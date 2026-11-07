"""tests/test_webapp_hunter.py — Unit + integration tests for tools/webapp_hunter.py.

Fast unit tests (no network) cover the pure helpers. The integration tests
(spawn the deliberately-vulnerable local Flask target in stealth mode with a
random per-run flag) are marked ``@pytest.mark.integration`` so the default
hermetic CI suite skips them; run them explicitly to prove detection + impact:

    python3 -m pytest tests/test_webapp_hunter.py -m integration -v
"""
from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import time
import urllib.request
from pathlib import Path
from typing import Optional

import pytest

from tools.webapp_hunter import (
    FLAG_PATTERNS,
    Resp,
    WebAppHuntResult,
    WebAppHunter,
    _flag_present,
    _is_local_host,
    extract_flag,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
TARGET_APP = REPO_ROOT / "tests" / "vulnerable_target" / "app.py"


# ===================================================================
# Pure helpers (no network)
# ===================================================================


class TestExtractFlag:
    def test_olenigenix_flag(self):
        assert extract_flag("hello ELENGENIX-FLAG-abc123def456 world") == "ELENGENIX-FLAG-abc123def456"

    def test_flag_braces(self):
        assert extract_flag("got flag{deadbeef} here") == "flag{deadbeef}"

    def test_flag_colon_value(self):
        # "flag: X" style — capture the value token.
        out = extract_flag("flag: ABC123XYZ")
        assert out and "ABC123XYZ" in out

    def test_no_flag(self):
        assert extract_flag("nothing sensitive here") is None
        assert extract_flag("") is None

    def test_flag_present_helper(self):
        assert _flag_present("a ELENGENIX-FLAG-1234567890ab c") is True
        assert _flag_present("no flag") is False


class TestIsLocalHost:
    def test_loopback(self):
        assert _is_local_host("127.0.0.1") is True
        assert _is_local_host("localhost") is True
        assert _is_local_host("::1") is True

    def test_private_ranges(self):
        assert _is_local_host("10.0.0.5") is True
        assert _is_local_host("192.168.1.1") is True
        assert _is_local_host("172.16.0.1") is True
        assert _is_local_host("169.254.1.1") is True

    def test_public_is_not_local(self):
        assert _is_local_host("93.184.216.34") is False
        assert _is_local_host("8.8.8.8") is False

    def test_local_suffix(self):
        assert _is_local_host("app.local") is True
        assert _is_local_host("example.com") is False


class TestResp:
    def test_ok_range(self):
        assert Resp(status=200).ok is True
        assert Resp(status=301).ok is False
        assert Resp(status=404).ok is False

    def test_json(self):
        r = Resp(status=200, text='{"a": 1}')
        assert r.json() == {"a": 1}
        r2 = Resp(status=200, text="not json")
        assert r2.json() is None


class TestHostGuard:
    def test_blocks_off_host(self):
        h = WebAppHunter("http://127.0.0.1:59999")
        assert h._host_ok("http://127.0.0.1:59999/ok") is True
        assert h._host_ok("http://evil.com/other") is False

    def test_request_never_raises_off_host(self):
        h = WebAppHunter("http://127.0.0.1:59999")
        # _abs can't be forced off-host easily, but the guard path returns a
        # safe Resp with status 0 and a marker.
        r = h._request("GET", "http://attacker.example/x")
        assert r.status == 0
        assert "off-host" in r.text


class TestHuntResult:
    def test_summary_no_error(self):
        res = WebAppHuntResult(base_url="http://x")
        res.findings = [{"type": "xss", "endpoint": "/a"}, {"type": "xss", "endpoint": "/b"}]
        res.impact_proven = ["xss"]
        s = res.summary()
        assert "Findings: 2" in s
        assert "xss: 2" in s

    def test_by_type(self):
        res = WebAppHuntResult(base_url="http://x")
        res.findings = [
            {"type": "sqli", "endpoint": "/l"},
            {"type": "sqli", "endpoint": "/l2"},
            {"type": "xss", "endpoint": "/s"},
        ]
        by = res.by_type()
        assert len(by["sqli"]) == 2
        assert len(by["xss"]) == 1


# ===================================================================
# Local sink servers (hermetic, no external network)
# ===================================================================


@pytest.fixture()
def sink_server():
    """A tiny local web app with exactly two intentional sinks:

    - GET /fetch?url=...  -> the server fetches the URL (SSRF sink)
    - GET /go?next=...    -> 302 Location: next (open-redirect sink)

    Everything else 404s, so the hunter's SSRF / open-redirect detectors
    must fire on exactly those two endpoints and nowhere else.
    """
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    from urllib.parse import parse_qs, urlparse

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *a):  # silence
            pass

        def _send(self, code, body=b"", headers=None):
            self.send_response(code)
            for k, v in (headers or {}).items():
                self.send_header(k, v)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if body:
                self.wfile.write(body)

        def do_GET(self):
            p = urlparse(self.path)
            q = parse_qs(p.query or {})
            if p.path == "/":
                self._send(200, b'<html><body><a href="/fetch">f</a>'
                               b'<a href="/go">g</a></body></html>',
                           {"Content-Type": "text/html"})
            elif p.path == "/fetch":
                url = (q.get("url") or [""])[0]
                if url.startswith(("http://", "https://")):
                    # SSRF sink: server-side fetch of the supplied URL.
                    try:
                        urllib.request.urlopen(url, timeout=3)
                        self._send(200, b"fetched ok")
                    except Exception as e:
                        self._send(200, f"fetch failed: {e}".encode())
                else:
                    self._send(200, b"no url")
            elif p.path == "/go":
                nxt = (q.get("next") or [""])[0]
                if nxt:
                    self._send(302, b"", {"Location": nxt})  # open-redirect sink
                else:
                    self._send(200, b"nowhere to go")
            else:
                self._send(404, b"not found")

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    port = server.server_address[1]
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{port}"
    try:
        server.shutdown()
        server.server_close()
    except Exception:
        pass
    t.join(timeout=2)


class TestNewDetectors:
    """SSRF + open-redirect detectors against a real local sink app."""

    def test_ssrf_detected(self, sink_server):
        h = WebAppHunter(sink_server, timeout=3, max_words=0)
        res = h.hunt(classes=["ssrf"])
        ssrf = [f for f in res.findings if f["type"] == "ssrf"]
        assert ssrf, f"expected an SSRF finding, got: {[f['type'] for f in res.findings]}"
        f = ssrf[0]
        assert f["endpoint"] == "/fetch"
        assert f["parameter"] == "url"
        assert f["provenance"] == "deterministic" and f["verified"] is True

    def test_open_redirect_detected(self, sink_server):
        h = WebAppHunter(sink_server, timeout=3, max_words=0)
        res = h.hunt(classes=["open_redirect"])
        orr = [f for f in res.findings if f["type"] == "open_redirect"]
        assert orr, f"expected an open-redirect finding, got: {[f['type'] for f in res.findings]}"
        f = orr[0]
        assert f["endpoint"] == "/go"
        assert f["parameter"] == "next"

    def test_no_false_positives_on_sink_server(self, sink_server):
        """The sink app has no other vuln sinks: hunting only the two new
        classes must yield exactly one finding each, no extras."""
        h = WebAppHunter(sink_server, timeout=3, max_words=0)
        res = h.hunt(classes=["ssrf", "open_redirect"])
        by_type = {}
        for f in res.findings:
            by_type.setdefault(f["type"], []).append(f)
        assert {f["endpoint"] for f in by_type.get("ssrf", [])} == {"/fetch"}
        assert {f["endpoint"] for f in by_type.get("open_redirect", [])} == {"/go"}


# ===================================================================
# Integration: live vulnerable target (stealth + random flag)
# ===================================================================


@pytest.fixture()
def vuln_target():
    """Start the deliberately-vulnerable Flask app in stealth mode + random flag.

    Function-scoped on purpose: several endpoints are one-shot / stateful
    (the single-use coupon, stored XSS, registered users) and the app resets
    its DB on every start. A fresh app per test guarantees each test sees
    pristine state (e.g. an unspent coupon for the race detector).
    """
    if not TARGET_APP.exists():
        pytest.skip("vulnerable target app not present")
    flag = "ELENGENIX-FLAG-" + os.urandom(8).hex()

    def _free_port() -> int:
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        p = s.getsockname()[1]
        s.close()
        return p

    port = _free_port()
    base = f"http://127.0.0.1:{port}"

    # Clean stale per-run artifacts (the target only rewrites the flag file
    # if it does not exist).
    for stale in ("/tmp/elengenix_flag.txt", "/tmp/elengenix_vuln.db", "/tmp/elengenix_files"):
        try:
            if os.path.isdir(stale):
                import shutil

                shutil.rmtree(stale)
            elif os.path.exists(stale):
                os.remove(stale)
        except Exception:
            pass

    env = os.environ.copy()
    env.update({"PORT": str(port), "ELENGENIX_BENCH_STEALTH": "1", "FLAG": flag})
    proc = subprocess.Popen(
        [sys.executable, str(TARGET_APP)],
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    ready = False
    for _ in range(50):
        try:
            urllib.request.urlopen(base + "/", timeout=1)
            ready = True
            break
        except Exception:
            time.sleep(0.3)
    if not ready:
        proc.terminate()
        pytest.skip("vulnerable target did not start")

    yield {"base": base, "flag": flag}

    proc.terminate()
    try:
        proc.wait(timeout=5)
    except Exception:
        proc.kill()


@pytest.mark.integration
class TestLiveDetection:
    def test_discovers_key_endpoints(self, vuln_target):
        h = WebAppHunter(vuln_target["base"])
        eps = h.discover()
        paths = {p.lower() for p in eps}
        for needle in ("login", "search", "register", "render", "download"):
            assert any(needle in p for p in paths), f"expected an endpoint containing {needle!r}"

    def test_finds_all_ten_classes(self, vuln_target):
        h = WebAppHunter(vuln_target["base"], concurrent=8)
        res = h.hunt()
        types = {f["type"] for f in res.findings}
        expected = {
            "sqli", "xss", "mass_assignment", "idor", "ssti",
            "jwt_none", "prototype_pollution", "race_condition", "path_traversal",
        }
        missing = expected - types
        assert not missing, f"missed vuln classes: {missing} (found: {sorted(types)})"

    def test_proves_impact_on_flag_classes(self, vuln_target):
        flag = vuln_target["flag"]
        h = WebAppHunter(vuln_target["base"], concurrent=8)
        res = h.hunt()
        all_evidence = " ".join(str(f.get("evidence", "")) for f in res.findings)
        # At least the SQLi class must carry the exact per-run flag (UNION exfil).
        sqli_ev = " ".join(str(f.get("evidence", "")) for f in res.findings if f["type"] == "sqli")
        assert flag in sqli_ev, "SQLi finding should embed the extracted per-run flag"
        assert flag in all_evidence
        # SSTI should read the flag from the template context.
        ssti_ev = " ".join(str(f.get("evidence", "")) for f in res.findings if f["type"] == "ssti")
        assert flag in ssti_ev, "SSTI finding should embed the extracted per-run flag"

    def test_grades_100_percent(self, vuln_target):
        from benchmark.grading import BenchmarkGrader, GROUND_TRUTH

        flag = vuln_target["flag"]
        h = WebAppHunter(vuln_target["base"], concurrent=8)
        res = h.hunt()
        grader = BenchmarkGrader(GROUND_TRUTH)
        grade = grader.grade(res.findings, scan_duration_sec=res.duration, flag=flag)
        assert grade.recall() == 1.0, f"recall {grade.recall():.0%}; missed={grade.false_negatives}"
        assert grade.precision() == 1.0, f"precision {grade.precision():.0%}; fp={len(grade.false_positives)}"
        assert grade.impact_rate == 1.0, f"impact {grade.impact_rate:.0%} ({grade.impact_proven})"


# ===================================================================
# Integration: canonical agent loop end-to-end (weakest-LLM floor)
# ===================================================================


class _StubAIClient:
    """A do-nothing LLM: every chat() returns an immediate 'finish'.

    Proves the deterministic baseline carries the mission even when the AI
    contributes nothing (the 'weakest possible model' floor).
    """

    provider = "stub"
    model = "stub-finish"
    api_key = "stub-key-1234567890"

    def chat(self, messages, **kwargs):
        class _R:
            tool_calls = []
            content = json.dumps({"action": "finish", "summary": "stub finish"})

        return _R()

    call = chat


@pytest.mark.integration
class TestCanonicalLoop:
    def test_loop_reaches_full_recall_with_stub_llm(self, vuln_target):
        import asyncio

        from elengenix.scanning.decision_engine import DecisionEngine
        from elengenix.scanning.executor import execute_tool
        from elengenix.scanning.post_processor import PostExecutionProcessor
        from elengenix.scanning.prompt_builder import PromptBuilder
        from elengenix.scanning.scan_context import ScanContext
        from elengenix.scanning.scan_loop import ScanLoop
        from tools.governance import Governance
        from tools.tool_registry import ToolCategory, ToolResult

        base = vuln_target["base"]
        client = _StubAIClient()
        governance = Governance()
        ctx = ScanContext(
            target=base,
            base_url=base,
            objective=f"Find vulnerabilities in {base}",
            mission_key=f"test-{int(time.time())}",
            max_steps=5,
        )

        def _executor(action_data, ctx_):
            try:
                output = execute_tool(action_data, governance, callback=None)
                success = not (output.startswith("[FAIL]") or output.startswith("Error:"))
                result = ToolResult(
                    success=success,
                    tool_name=action_data.get("tool", action_data.get("action", "unknown")),
                    category=ToolCategory.SCANNER,
                    output=output,
                    findings=[],
                )
                return success, result, output
            except Exception as e:
                return False, None, str(e)

        loop = ScanLoop(
            decision_engine=DecisionEngine(ai_client=client, prompt_builder=PromptBuilder(base_prompt="x")),
            post_processor=PostExecutionProcessor(),
            executor=_executor,
            client=client,
        )
        result = asyncio.run(loop.run(ctx, f"Find vulnerabilities in {base}", interactive=False))

        from benchmark.grading import BenchmarkGrader, GROUND_TRUTH

        grade = BenchmarkGrader(GROUND_TRUTH).grade(
            result.findings, flag=vuln_target["flag"]
        )
        assert grade.recall() == 1.0, f"loop recall {grade.recall():.0%}; missed={grade.false_negatives}"
