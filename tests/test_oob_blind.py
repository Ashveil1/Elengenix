"""Tests for the local OOB callback server + blind-detection wiring.

Covers:
  - tools/oob_server.py        — token issue, hit recording, wait/poll, no cross-token FP
  - tools/ssrf_scanner.py      — blind SSRF confirmation via callback; silence when target ignores payload
  - tools/injection_tester.py  — blind SQLi + SSTI OOB paths against a simulated vulnerable target
  - tools/payload_db.py        — DB loading + inline fallback behavior

All tests are offline: a raw http.server "target" fetches the OOB callback
URL (simulating a blind-vulnerable app), and an "inert" target ignores it.
Total runtime budget < 10s.
"""

from __future__ import annotations

import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from tools.oob_server import OOBServer, get_oob_server, reset_oob_server_for_tests
from tools.payload_db import get_metadata, get_payload_values, get_payloads
from tools.ssrf_scanner import SSRFScanner
import tools.injection_tester as injection


# ─────────────────────────────────────────────────
# Fake targets
# ─────────────────────────────────────────────────


def _make_target(vulnerable: bool):
    """Return (url, server) — a one-shot fake target.

    vulnerable=True: GET /<path>?<param>=<url> fetches <url> (blind-SSRF/SQLi style).
    vulnerable=False: ignores all params, always returns 200 "ok".
    """

    class _Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            if vulnerable:
                from urllib.parse import parse_qs, urlparse

                for values in parse_qs(urlparse(self.path).query).values():
                    for value in values:
                        if value.startswith("http://"):
                            try:
                                urllib.request.urlopen(value, timeout=0.5)
                            except Exception:
                                pass
            self.send_response(200)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"ok")

        def log_message(self, *a):  # quiet
            pass

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    httpd.daemon_threads = True
    threading.Thread(target=httpd.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()
    return f"http://127.0.0.1:{httpd.server_address[1]}", httpd


@pytest.fixture
def oob():
    srv = OOBServer()
    assert srv.running
    yield srv
    srv.shutdown()


@pytest.fixture
def vulnerable_target():
    url, httpd = _make_target(vulnerable=True)
    yield url
    httpd.shutdown()
    httpd.server_close()


@pytest.fixture
def inert_target():
    url, httpd = _make_target(vulnerable=False)
    yield url
    httpd.shutdown()
    httpd.server_close()


# ─────────────────────────────────────────────────
# OOBServer core
# ─────────────────────────────────────────────────


class TestOOBServer:
    def test_issues_unique_tokens_and_urls(self, oob):
        t1, u1 = oob.new_url()
        t2, u2 = oob.new_url()
        assert t1 != t2
        assert u1 == f"http://127.0.0.1:{oob.port}/{t1}"
        assert t1 in u1 and t2 in u2

    def test_records_callback_keyed_by_token(self, oob):
        token, url = oob.new_url("/exfil")
        urllib.request.urlopen(url + "?x=1", timeout=3).read()
        hits = oob.poll(token)
        assert len(hits) == 1
        hit = hits[0]
        assert hit.token == token
        assert hit.method == "GET"
        assert hit.path.startswith(f"/{token}/exfil")
        assert hit.timestamp > 0
        assert hit.client == "127.0.0.1"

    def test_wait_for_returns_hit_within_timeout(self, oob):
        token, url = oob.new_url()

        def _fetch():
            time.sleep(0.15)
            urllib.request.urlopen(url, timeout=3)

        threading.Thread(target=_fetch, daemon=True).start()
        hit = oob.wait_for(token, timeout=3)
        assert hit is not None and hit.token == token

    def test_wait_for_times_out_cleanly(self, oob):
        token, _ = oob.new_url()
        start = time.monotonic()
        assert oob.wait_for(token, timeout=0.3) is None
        assert time.monotonic() - start < 2.0  # respected the short timeout

    def test_no_cross_token_leakage(self, oob):
        t1, u1 = oob.new_url()
        t2, _ = oob.new_url()
        urllib.request.urlopen(u1, timeout=3).read()
        assert oob.poll(t1) and not oob.poll(t2)

    def test_singleton_accessor(self):
        try:
            srv = get_oob_server()
            assert srv is not None and srv.running and srv.port > 0
            assert get_oob_server() is srv
        finally:
            reset_oob_server_for_tests()


# ─────────────────────────────────────────────────
# SSRF scanner blind pass
# ─────────────────────────────────────────────────


class TestSSRFBlindPass:
    def test_blind_confirmation_fires(self, vulnerable_target, monkeypatch):
        scanner = SSRFScanner(enable_oob=True, oob_timeout=3.0)
        monkeypatch.setattr(scanner, "_get_payloads", lambda: [])  # blind pass in isolation
        assert scanner._oob is not None
        result = scanner.scan(vulnerable_target, params={"url": ""})
        blind = [r for r in result.results if r.blind_confirmed]
        assert blind, "expected at least one blind_confirmed SSRF result"
        r = blind[0]
        assert r.vulnerable and r.provenance == "oob_callback"
        assert r.param == "url"
        assert "OOB callback" in r.evidence
        assert "url" in result.vulnerable_params

    def test_no_false_positive_when_target_ignores_payload(self, inert_target):
        scanner = SSRFScanner(enable_oob=True, oob_timeout=0.5)
        result = scanner.scan(inert_target, params={"url": ""})
        assert not [r for r in result.results if r.blind_confirmed]

    def test_oob_disabled_keeps_signature_behavior(self, vulnerable_target, monkeypatch):
        scanner = SSRFScanner(enable_oob=False)
        monkeypatch.setattr(scanner, "_get_payloads", lambda: [])
        assert scanner._oob is None
        result = scanner.scan(vulnerable_target, params={"url": ""})
        assert all(not r.blind_confirmed for r in result.results)


# ─────────────────────────────────────────────────
# Injection tester blind SQLi + SSTI
# ─────────────────────────────────────────────────


class TestInjectionBlindPass:
    def _patch_oob_payloads(self, monkeypatch, kinds):
        """Replace dialect exfil payloads with a direct callback GET."""

        def _builder(callback_base, scheme="http"):
            return [{"payload": f"{scheme}://{callback_base}", "type": "oob_probe"}]

        def _run(url, test_params, found, builder, kind, oob_timeout):
            return injection._run_oob_pass(url, test_params, found, _builder, kind, oob_timeout)

        for kind in kinds:
            monkeypatch.setattr(injection, f"_oob_{kind}_payloads", _builder)

    def test_blind_sqli_confirmed(self, vulnerable_target, monkeypatch):
        self._patch_oob_payloads(monkeypatch, ["sqli"])
        findings = injection.test_sqli(
            vulnerable_target + "/?id=1", params=["id"], oob_timeout=3.0
        )
        blind = [f for f in findings if f.get("blind_confirmed")]
        assert blind, "expected a blind SQLi OOB finding"
        assert blind[0]["type"] == "sqli"
        assert blind[0]["provenance"] == "oob_callback"
        assert blind[0]["severity"] == "critical"

    def test_blind_sqli_no_false_positive(self, inert_target, monkeypatch):
        self._patch_oob_payloads(monkeypatch, ["sqli"])
        findings = injection.test_sqli(
            inert_target + "/?id=1", params=["id"], oob_timeout=0.5
        )
        assert not [f for f in findings if f.get("blind_confirmed")]

    def test_blind_ssti_confirmed(self, vulnerable_target, monkeypatch):
        self._patch_oob_payloads(monkeypatch, ["ssti"])
        findings = injection.test_ssti(
            vulnerable_target + "/?name=x", params=["name"], oob_timeout=3.0
        )
        blind = [f for f in findings if f.get("blind_confirmed")]
        assert blind, "expected a blind SSTI OOB finding"
        assert blind[0]["type"] == "ssti"
        assert blind[0]["provenance"] == "oob_callback"

    def test_blind_ssti_no_false_positive(self, inert_target, monkeypatch):
        self._patch_oob_payloads(monkeypatch, ["ssti"])
        findings = injection.test_ssti(
            inert_target + "/?name=x", params=["name"], oob_timeout=0.5
        )
        assert not [f for f in findings if f.get("blind_confirmed")]

    def test_enable_oob_false_skips_pass(self, vulnerable_target, monkeypatch):
        self._patch_oob_payloads(monkeypatch, ["sqli", "ssti"])
        assert injection.test_sqli(
            vulnerable_target + "/?id=1", params=["id"], enable_oob=False
        ) == []

    def test_oob_validator_payloads_are_dialect_shaped(self):
        sqli = injection._oob_sqli_payloads("127.0.0.1:1/tok")
        assert any("LOAD_FILE" in p["payload"] for p in sqli)
        assert any("dblink" in p["payload"] for p in sqli)
        assert any("UTL_HTTP" in p["payload"] for p in sqli)
        ssti = injection._oob_ssti_payloads("127.0.0.1:1/tok")
        assert len(ssti) == 3


# ─────────────────────────────────────────────────
# Payload DB
# ─────────────────────────────────────────────────


class TestPayloadDB:
    @pytest.mark.parametrize("kind", ["sqli", "ssti", "xss", "ssrf", "lfi", "xxe"])
    def test_db_file_loads(self, kind):
        payloads = get_payloads(kind)
        assert len(payloads) >= 60
        assert all("value" in p and "context" in p and "target" in p for p in payloads)
        assert get_metadata(kind)["source"]

    def test_oob_context_present(self):
        assert get_payload_values("sqli", context="oob")
        assert get_payload_values("ssrf", context="oob")

    def test_missing_db_returns_empty(self):
        assert get_payloads("nonexistent_class") == []
