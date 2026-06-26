"""tests/test_waf_detector.py — M9 verification tests."""

from __future__ import annotations

import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


# ── Mock WAF servers ──


class MockCloudflareHandler(BaseHTTPRequestHandler):
    """Mock that responds like Cloudflare when it sees malicious payloads."""

    MALICIOUS = ["'", "<script>", "../", "; ls", "ENTITY"]

    def do_GET(self):
        from urllib.parse import parse_qs, urlparse

        parsed = urlparse(self.path)
        qs = parse_qs(parsed.query)
        q = qs.get("q", [""])[0]

        if any(m in q for m in self.MALICIOUS):
            # Cloudflare-style block
            self.send_response(403)
            self.send_header("Server", "cloudflare")
            self.send_header("cf-ray", "12345abc-SJC")
            body = "<html>Attention Required! Cloudflare Ray ID: 12345abc</html>"
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body.encode())
        else:
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            body = "<html>welcome</html>"
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body.encode())

    def log_message(self, *args):
        pass


class MockModSecHandler(BaseHTTPRequestHandler):
    """Mock that responds like ModSecurity."""

    MALICIOUS = ["'", "<script>"]

    def do_GET(self):
        from urllib.parse import parse_qs, urlparse

        parsed = urlparse(self.path)
        qs = parse_qs(parsed.query)
        q = qs.get("q", [""])[0]

        if any(m in q for m in self.MALICIOUS):
            self.send_response(406)
            self.send_header("Server", "Apache/2.4")
            body = "Not Acceptable! ModSecurity detected attack pattern"
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body.encode())
        else:
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            body = "ok"
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body.encode())

    def log_message(self, *args):
        pass


class MockNoWAFHandler(BaseHTTPRequestHandler):
    """Mock that returns 200 for everything (no WAF)."""

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        body = "ok no waf here"
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body.encode())

    def log_message(self, *args):
        pass


class MockAWSWAFHandler(BaseHTTPRequestHandler):
    """Mock that responds like AWS WAF."""

    MALICIOUS = ["'", "<script>", "../"]

    def do_GET(self):
        from urllib.parse import parse_qs, urlparse

        parsed = urlparse(self.path)
        qs = parse_qs(parsed.query)
        q = qs.get("q", [""])[0]

        if any(m in q for m in self.MALICIOUS):
            self.send_response(403)
            self.send_header("x-amzn-RequestId", "abc-123-def")
            self.send_header("x-amz-cf-id", "xyz789")
            body = "AWS WAF blocked your request"
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body.encode())
        else:
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            body = "ok"
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body.encode())

    def log_message(self, *args):
        pass


@pytest.fixture(scope="module")
def cloudflare_server():
    server = HTTPServer(("127.0.0.1", 18802), MockCloudflareHandler)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    time.sleep(0.3)
    yield "http://127.0.0.1:18802"
    server.shutdown()


@pytest.fixture(scope="module")
def modsec_server():
    server = HTTPServer(("127.0.0.1", 18803), MockModSecHandler)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    time.sleep(0.3)
    yield "http://127.0.0.1:18803"
    server.shutdown()


@pytest.fixture(scope="module")
def nowaf_server():
    server = HTTPServer(("127.0.0.1", 18804), MockNoWAFHandler)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    time.sleep(0.3)
    yield "http://127.0.0.1:18804"
    server.shutdown()


@pytest.fixture(scope="module")
def aws_server():
    server = HTTPServer(("127.0.0.1", 18805), MockAWSWAFHandler)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    time.sleep(0.3)
    yield "http://127.0.0.1:18805"
    server.shutdown()


# ── Tests ──


def test_baseline_request(cloudflare_server):
    """Baseline request should succeed (200)."""
    from tools.waf_detector import SmartWAFDetector

    detector = SmartWAFDetector()
    resp = detector._send(cloudflare_server)
    assert resp["status"] == 200
    assert "welcome" in resp["body"]
    print(f"[BASELINE] status={resp['status']}, server={resp['headers'].get('server', '?')}")


def test_detect_cloudflare(cloudflare_server):
    """Probing should detect Cloudflare WAF."""
    from tools.waf_detector import SmartWAFDetector

    detector = SmartWAFDetector()
    result = detector.probe(cloudflare_server)
    assert result.waf_detected
    assert result.waf_name == "cloudflare"
    assert result.confidence >= 0.7
    assert len(result.blocked_payloads) >= 2  # sqli, xss blocked
    assert len(result.suggested_evasions) > 0
    print(
        f"[CLOUDFLARE] waf={result.waf_name}, conf={result.confidence}, blocked={result.blocked_payloads}"
    )
    print(f"[EVASIONS] first 3: {result.suggested_evasions[:3]}")


def test_detect_modsecurity(modsec_server):
    """Probing should detect ModSecurity WAF (406 status, Not Acceptable body)."""
    from tools.waf_detector import SmartWAFDetector

    detector = SmartWAFDetector()
    result = detector.probe(modsec_server)
    assert result.waf_detected
    assert result.waf_name == "modsecurity"
    assert result.confidence >= 0.6
    print(f"[MODSEC] waf={result.waf_name}, blocked={result.blocked_payloads}")


def test_detect_aws_waf(aws_server):
    """Probing should detect AWS WAF (x-amzn headers)."""
    from tools.waf_detector import SmartWAFDetector

    detector = SmartWAFDetector()
    result = detector.probe(aws_server)
    assert result.waf_detected
    assert result.waf_name == "aws_waf"
    assert "aws_waf" in result.signature_hits
    print(
        f"[AWS-WAF] waf={result.waf_name}, conf={result.confidence}, sigs={result.signature_hits}"
    )


def test_no_waf_detected(nowaf_server):
    """A non-WAF target should return waf_detected=False."""
    from tools.waf_detector import SmartWAFDetector

    detector = SmartWAFDetector()
    result = detector.probe(nowaf_server)
    assert not result.waf_detected
    assert result.waf_name == "none"
    assert len(result.blocked_payloads) == 0
    assert len(result.passed_payloads) == len(
        ["sqli", "xss", "traversal", "rce", "xxe", "benign_obvious"]
    )
    print(f"[NO-WAF] all {len(result.passed_payloads)} payloads passed")


def test_suggest_evasion_known_waf():
    """suggest_evasion should return specific techniques for known WAFs."""
    from tools.waf_detector import SmartWAFDetector

    detector = SmartWAFDetector()
    cf_evasions = detector.suggest_evasion("cloudflare")
    assert len(cf_evasions) >= 3
    assert any("case" in e.lower() or "url-encode" in e.lower() for e in cf_evasions)
    print(f"[CF-EVASION] {len(cf_evasions)} techniques")


def test_suggest_evasion_unknown_waf():
    """Unknown WAF should return generic evasions."""
    from tools.waf_detector import SmartWAFDetector

    detector = SmartWAFDetector()
    evasions = detector.suggest_evasion("nonexistent_waf")
    assert len(evasions) >= 1
    # Should fall back to generic_block
    print(f"[FALLBACK] {len(evasions)} generic evasions")


def test_waf_signatures_compile():
    """All signatures should have valid regex patterns."""
    from tools.waf_detector import WAF_SIGNATURES, SmartWAFDetector

    detector = SmartWAFDetector()
    assert len(detector._compiled_signatures) == len(WAF_SIGNATURES)
    for sig in detector._compiled_signatures:
        assert sig.name
        assert sig.confidence_threshold > 0
    print(f"[SIGS] {len(detector._compiled_signatures)} signatures loaded")


def test_probe_payloads_target_benign():
    """The 'benign_obvious' payload (AAAA) should never be blocked."""
    from tools.waf_detector import WAF_PROBE_PAYLOADS, SmartWAFDetector

    benign = [p for p in WAF_PROBE_PAYLOADS if p[0] == "benign_obvious"]
    assert len(benign) == 1
    assert benign[0][1] == "AAAA"
    print(f"[BENIGN] control payload: {benign[0]}")


def test_cloudflare_specific_signature_match(cloudflare_server):
    """Cloudflare response should match cf-ray header and Ray ID body."""
    from tools.waf_detector import SmartWAFDetector

    detector = SmartWAFDetector()
    # Send a malicious payload
    from urllib.parse import urlencode

    qs = urlencode({"q": "' OR 1=1--"})
    url = f"{cloudflare_server}/?{qs}"
    resp = detector._send(url)
    hits = detector._match_signatures(resp["status"], resp["body"], resp["headers"])
    assert "cloudflare" in hits
    print(f"[CF-MATCH] matched signatures: {hits}")
