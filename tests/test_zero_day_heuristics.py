"""tests/test_zero_day_heuristics.py

Tests for the Zero-Day Heuristics Engine.

These tests use a local in-memory mock HTTP server (BaseHTTPRequestHandler) so
that detection logic is exercised against real responses without touching the
network. The mock server is configurable per-route so each detector can be
tested in isolation against a synthetic but realistic target.

Run with::

    cd /mnt/data/Elengenix
    source venv/bin/activate
    python3 -m pytest tests/test_zero_day_heuristics.py -v
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import inspect
import json
import socket
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import parse_qs, urlparse

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


# ═══════════════════════════════════════════════════════════════════════════
#  MOCK HTTP SERVER
# ═══════════════════════════════════════════════════════════════════════════


# A single mutable router so tests can reconfigure behaviour on the fly.
_MOCK_ROUTES: Dict[Tuple[str, str], Callable[["BaseHTTPRequestHandler", Dict[str, Any]], None]] = {}
_MOCK_GLOBAL: Dict[str, Any] = {}


class _MockHandler(BaseHTTPRequestHandler):
    """Pluggable HTTP handler driven by the test's route table."""

    def log_message(self, *args, **kwargs):  # silence access log
        return

    def _route(self):
        key = (self.command, self.path.split("?", 1)[0])
        handler = _MOCK_ROUTES.get(key)
        if handler is None:
            # Fallback: try method="*" by re-keying.
            for (cmd, path), fn in _MOCK_ROUTES.items():
                if cmd == "*" and path == key[1]:
                    handler = fn
                    break
        return handler

    def _common(self) -> None:
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length > 0 else b""
        ctx: Dict[str, Any] = {
            "command": self.command,
            "path": self.path,
            "headers": dict(self.headers.items()),
            "body": body,
        }
        handler = self._route()
        if handler is None:
            self.send_response(404)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"not found")
            return
        try:
            handler(self, ctx)
        except Exception as exc:  # pragma: no cover - defensive
            self.send_response(500)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(str(exc).encode())

    def do_GET(self): self._common()
    def do_POST(self): self._common()
    def do_PUT(self): self._common()
    def do_PATCH(self): self._common()
    def do_DELETE(self): self._common()


def _start_mock_server() -> Tuple[HTTPServer, str, threading.Thread]:
    """Boot a mock server on an ephemeral port. Returns (server, base_url, thread)."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()

    server = HTTPServer(("127.0.0.1", port), _MockHandler)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    time.sleep(0.15)
    return server, f"http://127.0.0.1:{port}", t


def _register_route(method: str, path: str, handler: Callable[["BaseHTTPRequestHandler", Dict[str, Any]], None]) -> None:
    _MOCK_ROUTES[(method, path)] = handler


def _clear_routes() -> None:
    _MOCK_ROUTES.clear()


def _respond(handler: "BaseHTTPRequestHandler", status: int, body: bytes, headers: Optional[Dict[str, str]] = None) -> None:
    handler.send_response(status)
    handler.send_header("Content-Length", str(len(body)))
    handler.send_header("Content-Type", (headers or {}).get("Content-Type", "application/json"))
    for k, v in (headers or {}).items():
        if k.lower() in ("content-type", "content-length"):
            continue
        handler.send_header(k, v)
    handler.end_headers()
    handler.wfile.write(body)


# ═══════════════════════════════════════════════════════════════════════════
#  FIXTURES
# ═══════════════════════════════════════════════════════════════════════════


@pytest.fixture(scope="module")
def mock_server():
    server, base, thread = _start_mock_server()
    yield base
    server.shutdown()
    server.server_close()


@pytest.fixture(autouse=True)
def _reset_routes():
    _clear_routes()
    _MOCK_GLOBAL.clear()
    yield
    _clear_routes()
    _MOCK_GLOBAL.clear()


# ═══════════════════════════════════════════════════════════════════════════
#  TEST: SEVERITY + FINDING MODEL
# ═══════════════════════════════════════════════════════════════════════════


def test_finding_to_vuln_finding_minimal():
    """Finding.to_vuln_finding() should produce a valid VulnFinding."""
    from tools.zero_day_heuristics import Finding, SeverityLevel
    from tools.vuln_engine import VulnClass

    f = Finding(
        detector="unit_test",
        title="Demo",
        severity=SeverityLevel.HIGH,
        vuln_class=VulnClass.PROTOTYPE_POLLUTION,
        url="http://x.example",
        method="POST",
        payload='{"__proto__": {"isAdmin": true}}',
        evidence="canary reflected",
        description="desc",
        remediation="fix it",
        confidence=0.8,
    )
    vf = f.to_vuln_finding()
    assert vf.title == "Demo"
    assert vf.vuln_class == VulnClass.PROTOTYPE_POLLUTION
    assert vf.severity in ("High", "Critical")
    assert vf.cvss_score >= 7.5
    assert vf.cvss_vector.startswith("CVSS:3.1")
    assert vf.evidence == "canary reflected"
    assert vf.confidence == 0.8
    assert vf.metadata["detector"] == "unit_test"
    assert vf.metadata["heuristic_metadata"] == {}
    print("[OK] test_finding_to_vuln_finding_minimal")


def test_severity_cvss_floor_mapping():
    """Each severity bucket has a CVSS floor."""
    from tools.zero_day_heuristics import (
        SEVERITY_CVSS_FLOOR,
        SeverityLevel,
    )
    assert SEVERITY_CVSS_FLOOR[SeverityLevel.CRITICAL] >= 9.0
    assert SEVERITY_CVSS_FLOOR[SeverityLevel.HIGH] >= 7.0
    assert SEVERITY_CVSS_FLOOR[SeverityLevel.MEDIUM] >= 4.0
    print("[OK] test_severity_cvss_floor_mapping")


def test_default_vectors_per_vuln_class():
    """Every VulnClass used in findings has a default CVSS vector."""
    from tools.zero_day_heuristics import _default_vector_for
    from tools.vuln_engine import VulnClass

    classes = [
        VulnClass.PROTOTYPE_POLLUTION,
        VulnClass.DESERIALIZATION,
        VulnClass.RACE_CONDITION,
        VulnClass.TEMPLATE_INJECTION,
        VulnClass.GRAPHQL,
        VulnClass.JWT,
        VulnClass.HTTP_SMUGGLING,
    ]
    for cls in classes:
        v = _default_vector_for(cls)
        assert v.startswith("CVSS:3.1"), f"missing vector for {cls}"
    print("[OK] test_default_vectors_per_vuln_class")


# ═══════════════════════════════════════════════════════════════════════════
#  TEST: PROTOTYPE POLLUTION DETECTOR
# ═══════════════════════════════════════════════════════════════════════════


def test_prototype_pollution_canary_reflected(mock_server):
    """When the server reflects the canary, detector must report it."""
    from tools.zero_day_heuristics import PrototypePollutionDetector

    def handler(h: BaseHTTPRequestHandler, ctx: Dict[str, Any]) -> None:
        body = ctx["body"].decode("utf-8", errors="replace")
        if "elenheur-1337" in body:
            _respond(h, 200, b'{"echo":"elenheur-1337","status":"ok"}')
            return
        _respond(h, 200, b'{"status":"ok"}')

    _register_route("POST", "/proto", handler)
    det = PrototypePollutionDetector()
    findings = asyncio.run(det.detect(f"{mock_server}/proto"))
    assert findings, "expected at least one finding"
    titles = [f.title.lower() for f in findings]
    assert any("canary" in t or "stack" in t or "prototype" in t for t in titles)
    print(f"[OK] test_prototype_pollution_canary_reflected findings={len(findings)}")


def test_prototype_pollution_no_false_positive_on_clean(mock_server):
    """A clean response should not yield findings."""
    from tools.zero_day_heuristics import PrototypePollutionDetector

    def handler(h: BaseHTTPRequestHandler, ctx: Dict[str, Any]) -> None:
        _respond(h, 200, b'{"status":"ok","user":"alice"}')

    _register_route("POST", "/clean", handler)
    det = PrototypePollutionDetector()
    findings = asyncio.run(det.detect(f"{mock_server}/clean"))
    # No canary reflection, no stack trace, no entropy spike, no echo.
    # Filter: anomaly detector shouldn't fire on a small text body.
    high_or_crit = [f for f in findings if f.severity.value in ("high", "critical")]
    assert high_or_crit == []
    print(f"[OK] test_prototype_pollution_no_false_positive_on_clean findings={len(findings)}")


def test_prototype_pollution_stack_trace_detection(mock_server):
    """Server returning a stack trace with __proto__ should produce a finding."""
    from tools.zero_day_heuristics import PrototypePollutionDetector

    def handler(h: BaseHTTPRequestHandler, ctx: Dict[str, Any]) -> None:
        body = ctx["body"].decode("utf-8", errors="replace")
        if "__proto__" in body:
            _respond(h, 500, b"TypeError: Cannot set property 'x' of Object.prototype which has only a getter\n" * 4)
            return
        _respond(h, 200, b"ok")

    _register_route("POST", "/proto-error", handler)
    det = PrototypePollutionDetector()
    findings = asyncio.run(det.detect(f"{mock_server}/proto-error"))
    assert any("stack trace" in f.title.lower() or "error" in f.title.lower() for f in findings)
    print(f"[OK] test_prototype_pollution_stack_trace_detection findings={len(findings)}")


def test_prototype_pollution_gadget_mention_upgrades_severity(mock_server):
    """When a gadget is mentioned alongside the canary, severity rises to HIGH."""
    from tools.zero_day_heuristics import PrototypePollutionDetector, SeverityLevel

    def handler(h: BaseHTTPRequestHandler, ctx: Dict[str, Any]) -> None:
        _respond(h, 200, b'{"user":"elenheur-1337","gadget":"lodash.merge"}')

    _register_route("POST", "/gadget", handler)
    det = PrototypePollutionDetector()
    findings = asyncio.run(det.detect(f"{mock_server}/gadget"))
    relevant = [f for f in findings if "canary" in f.title.lower()]
    assert relevant
    assert relevant[0].severity == SeverityLevel.HIGH
    print(f"[OK] test_prototype_pollution_gadget_mention_upgrades_severity severity={relevant[0].severity.value}")


# ═══════════════════════════════════════════════════════════════════════════
#  TEST: MASS ASSIGNMENT DETECTOR
# ═══════════════════════════════════════════════════════════════════════════


def test_mass_assignment_reflects_isadmin(mock_server):
    """Server that echoes back isAdmin=true must be flagged."""
    from tools.zero_day_heuristics import MassAssignmentDetector

    def handler(h: BaseHTTPRequestHandler, ctx: Dict[str, Any]) -> None:
        try:
            payload = json.loads(ctx["body"] or b"{}")
        except json.JSONDecodeError:
            payload = {}
        body = {"username": payload.get("username", "anon"), "role": "user"}
        if "isAdmin" in payload:
            body["isAdmin"] = bool(payload["isAdmin"])
            body["role"] = "admin"
        _respond(h, 200, json.dumps(body).encode())

    _register_route("POST", "/users", handler)
    det = MassAssignmentDetector()
    findings = asyncio.run(det.detect(f"{mock_server}/users"))
    titles = [f.title for f in findings]
    assert any("isAdmin" in t for t in titles), f"no isAdmin finding: {titles}"
    sev_map = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
    crit_or_high = [f for f in findings if sev_map.get(f.severity.value, 0) >= 4]
    assert crit_or_high, "expected a critical/high finding for isAdmin"
    print(f"[OK] test_mass_assignment_reflects_isadmin findings={len(findings)}")


def test_mass_assignment_clean_response_no_findings(mock_server):
    """A well-behaved server should not produce findings."""
    from tools.zero_day_heuristics import MassAssignmentDetector

    def handler(h: BaseHTTPRequestHandler, ctx: Dict[str, Any]) -> None:
        try:
            payload = json.loads(ctx["body"] or b"{}")
        except json.JSONDecodeError:
            payload = {}
        body = {"username": payload.get("username", "anon"), "role": "user"}
        _respond(h, 200, json.dumps(body).encode())

    _register_route("POST", "/clean", handler)
    det = MassAssignmentDetector()
    findings = asyncio.run(det.detect(f"{mock_server}/clean"))
    high_or_crit = [f for f in findings if f.severity.value in ("high", "critical")]
    assert high_or_crit == []
    print(f"[OK] test_mass_assignment_clean_response_no_findings findings={len(findings)}")


def test_mass_assignment_response_growth(mock_server):
    """Server that adds content when extra field sent should produce a finding."""
    from tools.zero_day_heuristics import MassAssignmentDetector

    def handler(h: BaseHTTPRequestHandler, ctx: Dict[str, Any]) -> None:
        try:
            payload = json.loads(ctx["body"] or b"{}")
        except json.JSONDecodeError:
            payload = {}
        body = {"username": payload.get("username", "anon")}
        if "balance" in payload:
            body["balance"] = int(payload["balance"])
        _respond(h, 200, json.dumps(body).encode())

    _register_route("POST", "/profile", handler)
    det = MassAssignmentDetector()
    findings = asyncio.run(det.detect(f"{mock_server}/profile"))
    titles = [f.title for f in findings]
    assert any("balance" in t or "grew" in t for t in titles)
    print(f"[OK] test_mass_assignment_response_growth findings={len(findings)}")


# ═══════════════════════════════════════════════════════════════════════════
#  TEST: INSECURE DESERIALIZATION DETECTOR
# ═══════════════════════════════════════════════════════════════════════════


def test_deserialization_java_magic_bytes(mock_server):
    """Server returning Java serialization magic bytes must be flagged."""
    from tools.zero_day_heuristics import InsecureDeserializationDetector

    def handler(h: BaseHTTPRequestHandler, ctx: Dict[str, Any]) -> None:
        # Build a Java-style serialized payload that begins with ACED0005.
        body = b"\xac\xed\x00\x05" + b"\x74\x00\x08evilClass" + b"\x00" * 32
        _respond(h, 200, body, headers={"Content-Type": "application/octet-stream"})

    _register_route("GET", "/java-obj", handler)
    _register_route("POST", "/java-obj", handler)
    det = InsecureDeserializationDetector()
    findings = asyncio.run(det.detect(f"{mock_server}/java-obj"))
    langs = [f.metadata.get("language") for f in findings if f.metadata.get("language")]
    assert "java" in langs, f"no java finding: {[f.title for f in findings]}"
    print(f"[OK] test_deserialization_java_magic_bytes langs={set(langs)}")


def test_deserialization_python_pickle_reflection(mock_server):
    """Server reflecting a pickle-style base64 prefix should be flagged."""
    from tools.zero_day_heuristics import InsecureDeserializationDetector

    body = base64.b64encode(b"\x80\x04\x95\x00\x00\x00\x00\x00\x00\x00" + b"X" * 64).decode()

    def handler(h: BaseHTTPRequestHandler, ctx: Dict[str, Any]) -> None:
        _respond(h, 200, body.encode())

    _register_route("GET", "/pickle", handler)
    det = InsecureDeserializationDetector()
    findings = asyncio.run(det.detect(f"{mock_server}/pickle"))
    langs = [f.metadata.get("language") for f in findings if f.metadata.get("language")]
    assert "python" in langs
    print(f"[OK] test_deserialization_python_pickle_reflection langs={set(langs)}")


def test_deserialization_php_serialized_object(mock_server):
    """Server returning PHP serialized O:8:"stdClass" must be flagged."""
    from tools.zero_day_heuristics import InsecureDeserializationDetector

    def handler(h: BaseHTTPRequestHandler, ctx: Dict[str, Any]) -> None:
        _respond(h, 200, b'O:8:"stdClass":2:{s:4:"name";s:5:"alice";s:4:"role";s:5:"admin";}')

    _register_route("GET", "/php", handler)
    det = InsecureDeserializationDetector()
    findings = asyncio.run(det.detect(f"{mock_server}/php"))
    langs = [f.metadata.get("language") for f in findings if f.metadata.get("language")]
    assert "php" in langs
    print(f"[OK] test_deserialization_php_serialized_object langs={set(langs)}")


def test_deserialization_dotnet_viewstate(mock_server):
    """Server returning __VIEWSTATE must be flagged."""
    from tools.zero_day_heuristics import InsecureDeserializationDetector

    sample_viewstate = "__VIEWSTATE=" + base64.b64encode(b"X" * 128).decode()
    def handler(h: BaseHTTPRequestHandler, ctx: Dict[str, Any]) -> None:
        _respond(h, 200, sample_viewstate.encode())

    _register_route("GET", "/aspx", handler)
    det = InsecureDeserializationDetector()
    findings = asyncio.run(det.detect(f"{mock_server}/aspx"))
    langs = [f.metadata.get("language") for f in findings if f.metadata.get("language")]
    assert "dotnet" in langs
    print(f"[OK] test_deserialization_dotnet_viewstate langs={set(langs)}")


def test_deserialization_clean_response_no_findings(mock_server):
    """A normal JSON response should not produce deserialization findings."""
    from tools.zero_day_heuristics import InsecureDeserializationDetector

    def handler(h: BaseHTTPRequestHandler, ctx: Dict[str, Any]) -> None:
        _respond(h, 200, b'{"status":"ok"}')

    _register_route("GET", "/clean", handler)
    _register_route("POST", "/clean", handler)
    det = InsecureDeserializationDetector()
    findings = asyncio.run(det.detect(f"{mock_server}/clean"))
    assert findings == [], f"unexpected findings: {[f.title for f in findings]}"
    print("[OK] test_deserialization_clean_response_no_findings")


# ═══════════════════════════════════════════════════════════════════════════
#  TEST: HTTP REQUEST SMUGGLING DETECTOR
# ═══════════════════════════════════════════════════════════════════════════


def test_smuggling_clean_single_response_no_findings(mock_server):
    """A clean server should not yield smuggling findings via probe parsing."""
    from tools.zero_day_heuristics import HTTPSmugglingDetector

    def handler(h: BaseHTTPRequestHandler, ctx: Dict[str, Any]) -> None:
        _respond(h, 200, b"ok")

    # Register for ALL methods so any probe gets a sane response.
    for m in ("GET", "POST", "PUT", "DELETE", "PATCH"):
        _register_route(m, "/", handler)
    det = HTTPSmugglingDetector(timeout=2.0)
    findings = asyncio.run(det.detect(f"{mock_server}/"))
    # No multi-response, no 400 with ambiguity keyword. Should be empty.
    assert findings == [], f"unexpected findings: {[f.title for f in findings]}"
    print("[OK] test_smuggling_clean_single_response_no_findings")


def test_smuggling_ambiguous_error_response_flagged(mock_server):
    """A 400 'ambiguous' response should produce a smuggling indicator finding."""
    from tools.zero_day_heuristics import HTTPSmugglingDetector

    def handler(h: BaseHTTPRequestHandler, ctx: Dict[str, Any]) -> None:
        # Always 400 ambiguous — sufficient to trigger the pattern match
        # path if our probe happens to produce a single response.
        _respond(h, 400, b"400 Bad Request: ambiguous chunked encoding")

    for m in ("GET", "POST", "PUT", "DELETE", "PATCH"):
        _register_route(m, "/", handler)
    det = HTTPSmugglingDetector(timeout=2.0)
    findings = asyncio.run(det.detect(f"{mock_server}/"))
    # Either multi-response or single with the keyword should match.
    titles = [f.title.lower() for f in findings]
    assert any("smuggling" in t for t in titles), f"no smuggling finding: {titles}"
    print(f"[OK] test_smuggling_ambiguous_error_response_flagged findings={len(findings)}")


def test_smuggling_multi_response_flagged(mock_server):
    """Server replying with two HTTP messages is a classic smuggling signal."""
    from tools.zero_day_heuristics import HTTPSmugglingDetector

    def handler(h: BaseHTTPRequestHandler, ctx: Dict[str, Any]) -> None:
        # Reply with two HTTP/1.1 responses back-to-back. The second message
        # starts immediately after the first one ends (no extra CRLF between
        # them — this is exactly the smuggling signal a vulnerable server
        # produces when the front-end's framing is ambiguous).
        body = (
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK"
            b"\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nHI"
        )
        try:
            h.wfile.write(body)
            h.wfile.flush()
        except Exception:
            pass

    for m in ("GET", "POST", "PUT", "DELETE", "PATCH"):
        _register_route(m, "/", handler)
    det = HTTPSmugglingDetector(timeout=2.0)
    findings = asyncio.run(det.detect(f"{mock_server}/"))
    crit = [f for f in findings if f.severity.value == "critical"]
    assert crit, f"no critical finding: {[f.title for f in findings]}"
    print(f"[OK] test_smuggling_multi_response_flagged findings={len(findings)}")


# ═══════════════════════════════════════════════════════════════════════════
#  TEST: RACE CONDITION DETECTOR
# ═══════════════════════════════════════════════════════════════════════════


def test_race_condition_status_variation(mock_server):
    """Server that flips between 200 and 500 must produce a finding."""
    from tools.zero_day_heuristics import RaceConditionDetector

    counter = {"n": 0}

    def handler(h: BaseHTTPRequestHandler, ctx: Dict[str, Any]) -> None:
        counter["n"] += 1
        if counter["n"] % 2 == 0:
            _respond(h, 500, b"oops")
        else:
            _respond(h, 200, b"ok")

    _register_route("POST", "/race", handler)
    det = RaceConditionDetector()
    findings = asyncio.run(det.detect(f"{mock_server}/race", concurrency=10))
    assert any("status code" in f.title.lower() for f in findings), [f.title for f in findings]
    print(f"[OK] test_race_condition_status_variation findings={len(findings)}")


def test_race_condition_field_race(mock_server):
    """Non-monotonic 'balance' values across responses must be detected."""
    from tools.zero_day_heuristics import RaceConditionDetector

    counter = {"n": 0}

    def handler(h: BaseHTTPRequestHandler, ctx: Dict[str, Any]) -> None:
        counter["n"] += 1
        # Alternate increasing / decreasing
        balance = 100 - (counter["n"] % 4) * 10
        _respond(h, 200, json.dumps({"balance": balance}).encode())

    _register_route("POST", "/race-balance", handler)
    det = RaceConditionDetector()
    findings = asyncio.run(det.detect(f"{mock_server}/race-balance", concurrency=8))
    field_findings = [f for f in findings if "balance" in f.title.lower()]
    assert field_findings, [f.title for f in findings]
    print(f"[OK] test_race_condition_field_race findings={len(findings)}")


def test_race_condition_clean_no_findings(mock_server):
    """Deterministic identical responses must NOT be flagged."""
    from tools.zero_day_heuristics import RaceConditionDetector

    def handler(h: BaseHTTPRequestHandler, ctx: Dict[str, Any]) -> None:
        _respond(h, 200, b'{"balance":100,"status":"ok"}')

    _register_route("GET", "/race-clean", handler)
    det = RaceConditionDetector()
    findings = asyncio.run(det.detect(f"{mock_server}/race-clean", concurrency=8))
    high_or_crit = [f for f in findings if f.severity.value in ("high", "critical")]
    assert high_or_crit == []
    print(f"[OK] test_race_condition_clean_no_findings findings={len(findings)}")


# ═══════════════════════════════════════════════════════════════════════════
#  TEST: SSTI DETECTOR
# ═══════════════════════════════════════════════════════════════════════════


def test_ssti_jinja2_reflection(mock_server):
    """Server returning '49' from {{7*7}} must be flagged."""
    from tools.zero_day_heuristics import SSTIDetector

    def handler(h: BaseHTTPRequestHandler, ctx: Dict[str, Any]) -> None:
        path = ctx["path"]
        q = parse_qs(urlparse(path).query)
        marker = (q.get("q") or [""])[0]
        if marker == "{{7*7}}":
            _respond(h, 200, b"<html><body>Result: 49</body></html>", headers={"Content-Type": "text/html"})
            return
        _respond(h, 200, b"<html><body>Result: blank</body></html>", headers={"Content-Type": "text/html"})

    _register_route("GET", "/search", handler)
    det = SSTIDetector()
    findings = asyncio.run(det.detect(f"{mock_server}/search", context={"param": "q"}))
    titles = [f.title for f in findings]
    assert any("49" in t for t in titles), titles
    crit = [f for f in findings if f.severity.value == "critical"]
    assert crit, "expected a CRITICAL SSTI finding"
    print(f"[OK] test_ssti_jinja2_reflection findings={len(findings)}")


def test_ssti_stack_trace_signature(mock_server):
    """Server returning jinja2.TemplateSyntaxError must produce a finding."""
    from tools.zero_day_heuristics import SSTIDetector

    def handler(h: BaseHTTPRequestHandler, ctx: Dict[str, Any]) -> None:
        _respond(h, 500, b"jinja2.exceptions.TemplateSyntaxError: unexpected end of template", headers={"Content-Type": "text/plain"})

    _register_route("GET", "/render", handler)
    det = SSTIDetector()
    findings = asyncio.run(det.detect(f"{mock_server}/render", context={"param": "q"}))
    titles = [f.title.lower() for f in findings]
    assert any("jinja" in t or "template engine" in t or "stack trace" in t for t in titles)
    print(f"[OK] test_ssti_stack_trace_signature findings={len(findings)}")


def test_ssti_clean_no_findings(mock_server):
    """Server that never reflects 49 / 1337 / template errors must be clean."""
    from tools.zero_day_heuristics import SSTIDetector

    def handler(h: BaseHTTPRequestHandler, ctx: Dict[str, Any]) -> None:
        _respond(h, 200, b"<html><body>Search results page</body></html>", headers={"Content-Type": "text/html"})

    _register_route("GET", "/clean", handler)
    det = SSTIDetector()
    findings = asyncio.run(det.detect(f"{mock_server}/clean", context={"param": "q"}))
    high_or_crit = [f for f in findings if f.severity.value in ("high", "critical")]
    assert high_or_crit == []
    print(f"[OK] test_ssti_clean_no_findings findings={len(findings)}")


# ═══════════════════════════════════════════════════════════════════════════
#  TEST: GRAPHQL DETECTOR
# ═══════════════════════════════════════════════════════════════════════════


def test_graphql_introspection_enabled_flagged(mock_server):
    """A GraphQL endpoint that exposes introspection must be flagged."""
    from tools.zero_day_heuristics import GraphQLIntrospectionDetector

    schema = {
        "__schema": {
            "queryType": {"name": "Query"},
            "mutationType": {"name": "Mutation"},
            "subscriptionType": {"name": "Subscription"},
            "types": [
                {
                    "name": "User",
                    "kind": "OBJECT",
                    "fields": [
                        {"name": "password", "isDeprecated": False, "args": [], "deprecationReason": ""},
                        {"name": "email", "isDeprecated": False, "args": [], "deprecationReason": ""},
                        {"name": "apiKey", "isDeprecated": True, "args": [], "deprecationReason": "Use token instead"},
                    ],
                },
            ],
            "directives": [],
        }
    }

    def handler(h: BaseHTTPRequestHandler, ctx: Dict[str, Any]) -> None:
        try:
            payload = json.loads(ctx["body"] or b"{}")
        except json.JSONDecodeError:
            payload = {}
        # Allow arrays as a top-level body.
        if isinstance(payload, list):
            _respond(h, 200, json.dumps([{"data": {"__typename": "Query"}}] * len(payload)).encode())
            return
        if not isinstance(payload, dict):
            _respond(h, 200, b'{"data":null}')
            return
        query = payload.get("query", "")
        if "__typename" in query and "__schema" not in query:
            _respond(h, 200, b'{"data":{"__typename":"Query"}}')
            return
        if "__schema" in query:
            _respond(h, 200, json.dumps({"data": schema}).encode())
            return
        _respond(h, 200, b'{"data":null}')

    _register_route("POST", "/graphql", handler)
    det = GraphQLIntrospectionDetector()
    findings = asyncio.run(det.detect(mock_server, context={"endpoint": f"{mock_server}/graphql"}))
    titles = [f.title.lower() for f in findings]
    assert any("introspection" in t for t in titles)
    assert any("sensitive" in t for t in titles)
    assert any("batching" in t for t in titles)
    print(f"[OK] test_graphql_introspection_enabled_flagged findings={len(findings)}")


def test_graphql_introspection_disabled_no_high(mock_server):
    """GraphQL endpoint with introspection disabled yields no HIGH findings."""
    from tools.zero_day_heuristics import GraphQLIntrospectionDetector

    def handler(h: BaseHTTPRequestHandler, ctx: Dict[str, Any]) -> None:
        try:
            payload = json.loads(ctx["body"] or b"{}")
        except json.JSONDecodeError:
            payload = {}
        query = payload.get("query", "")
        if "__schema" in query:
            _respond(h, 200, b'{"errors":[{"message":"GraphQL introspection is not allowed"}]}')
            return
        if "__typename" in query:
            _respond(h, 200, b'{"data":{"__typename":"Query"}}')
            return
        _respond(h, 200, b'{"data":null}')

    _register_route("POST", "/graphql", handler)
    det = GraphQLIntrospectionDetector()
    findings = asyncio.run(det.detect(mock_server, context={"endpoint": f"{mock_server}/graphql"}))
    high = [f for f in findings if f.severity.value == "high"]
    assert high == [], [f.title for f in high]
    print(f"[OK] test_graphql_introspection_disabled_no_high findings={len(findings)}")


def test_graphql_endpoint_discovery(mock_server):
    """Detector must find /graphql endpoint via discovery."""
    from tools.zero_day_heuristics import GraphQLIntrospectionDetector

    def handler(h: BaseHTTPRequestHandler, ctx: Dict[str, Any]) -> None:
        _respond(h, 200, b'{"data":{"__typename":"Query"}}')

    _register_route("POST", "/graphql", handler)
    det = GraphQLIntrospectionDetector()
    findings = asyncio.run(det.detect(mock_server))
    # Even with introspection disabled-by-error, we should reach the endpoint.
    assert findings
    print(f"[OK] test_graphql_endpoint_discovery findings={len(findings)}")


# ═══════════════════════════════════════════════════════════════════════════
#  TEST: JWT ALGORITHM CONFUSION
# ═══════════════════════════════════════════════════════════════════════════


def test_jwt_forge_all_attacks_present():
    """forge_tokens must produce every expected attack variant."""
    from tools.zero_day_heuristics import JWTAlgorithmDetector, _is_jwt

    det = JWTAlgorithmDetector()
    attacks = det.forge_tokens()
    for name in (
        "alg_none", "alg_NONE", "alg_none_no_typ",
        "kid_path_traversal", "kid_sql_injection", "kid_blank",
        "jku_attack", "x5u_attack", "hs256_confusion",
    ):
        assert name in attacks, f"missing attack {name}"
        assert _is_jwt(attacks[name]), f"attack {name} produced invalid JWT"
    print(f"[OK] test_jwt_forge_all_attacks_present count={len(attacks)}")


def test_jwt_detect_static_emits_one_per_attack():
    """Static detect() should emit findings for every forged token."""
    from tools.zero_day_heuristics import JWTAlgorithmDetector

    det = JWTAlgorithmDetector()
    findings = det.detect()
    attack_titles = [f.metadata.get("attack") for f in findings]
    assert all(attack_titles), "every finding should have an attack tag"
    assert len(attack_titles) == len(set(attack_titles)), "duplicate findings"
    print(f"[OK] test_jwt_detect_static_emits_one_per_attack count={len(findings)}")


def test_jwt_detect_on_endpoint_accepts_alg_none(mock_server):
    """If the server accepts 'alg=none', we must produce a CRITICAL finding."""
    from tools.zero_day_heuristics import JWTAlgorithmDetector

    def handler(h: BaseHTTPRequestHandler, ctx: Dict[str, Any]) -> None:
        auth = ctx["headers"].get("Authorization", "")
        token = auth.replace("Bearer ", "").strip()
        parts = token.split(".")
        if len(parts) != 3:
            _respond(h, 401, b'{"err":"no token"}')
            return
        try:
            header_b64 = parts[0]
            pad = "=" * (-len(header_b64) % 4)
            header = json.loads(base64.urlsafe_b64decode(header_b64 + pad))
        except Exception:
            _respond(h, 401, b'{"err":"bad header"}')
            return
        if header.get("alg", "").lower() == "none":
            _respond(h, 200, b'{"user":"admin","role":"admin"}')
            return
        _respond(h, 401, b'{"err":"bad token"}')

    _register_route("GET", "/protected", handler)
    det = JWTAlgorithmDetector()
    findings = asyncio.run(det.detect_on_endpoint(f"{mock_server}/protected"))
    crit = [f for f in findings if f.severity.value == "critical"]
    assert crit, f"no critical finding: {[f.title for f in findings]}"
    print(f"[OK] test_jwt_detect_on_endpoint_accepts_alg_none findings={len(findings)}")


def test_jwt_detect_on_endpoint_rejects_attacks(mock_server):
    """A well-behaved endpoint should reject every forged token."""
    from tools.zero_day_heuristics import JWTAlgorithmDetector

    def handler(h: BaseHTTPRequestHandler, ctx: Dict[str, Any]) -> None:
        auth = ctx["headers"].get("Authorization", "")
        if not auth.startswith("Bearer "):
            _respond(h, 401, b'{"err":"no token"}')
            return
        _respond(h, 401, b'{"err":"rejected"}')

    _register_route("GET", "/strict", handler)
    det = JWTAlgorithmDetector()
    findings = asyncio.run(det.detect_on_endpoint(f"{mock_server}/strict"))
    assert findings == [], [f.title for f in findings]
    print("[OK] test_jwt_detect_on_endpoint_rejects_attacks")


# ═══════════════════════════════════════════════════════════════════════════
#  TEST: SMART ANOMALY DETECTOR
# ═══════════════════════════════════════════════════════════════════════════


def test_smart_anomaly_baseline_then_5xx_anomaly(mock_server):
    """Baseline 200s + a single 500 must produce a finding."""
    from tools.zero_day_heuristics import SmartAnomalyDetector

    counter = {"n": 0}

    def handler(h: BaseHTTPRequestHandler, ctx: Dict[str, Any]) -> None:
        counter["n"] += 1
        if counter["n"] > 5:
            _respond(h, 500, b"server crash " + b"X" * 400)
            return
        _respond(h, 200, b"OK body " + b"x" * 200)

    _register_route("GET", "/anom", handler)
    det = SmartAnomalyDetector()
    findings = asyncio.run(det.detect(f"{mock_server}/anom", baseline_count=4))
    assert any("500" in f.evidence or "server error" in f.evidence for f in findings), [f.evidence for f in findings]
    print(f"[OK] test_smart_anomaly_baseline_then_5xx_anomaly findings={len(findings)}")


def test_smart_anomaly_no_findings_on_uniform(mock_server):
    """A uniform endpoint should produce no anomaly findings on length/status."""
    from tools.zero_day_heuristics import SmartAnomalyDetector

    def handler(h: BaseHTTPRequestHandler, ctx: Dict[str, Any]) -> None:
        _respond(h, 200, b"OK body " + b"x" * 200)

    _register_route("GET", "/uniform", handler)
    det = SmartAnomalyDetector()
    # Use a slightly larger baseline so length/status z-scores are stable.
    findings = asyncio.run(det.detect(f"{mock_server}/uniform", baseline_count=5))
    # We accept timing-based noise under heavy CI load — only length/status
    # findings count for this negative test.
    length_or_status = [
        f for f in findings
        if "length" in f.evidence or "status" in f.evidence
    ]
    assert length_or_status == [], [f.evidence for f in length_or_status]
    print(f"[OK] test_smart_anomaly_no_findings_on_uniform findings={len(findings)}")


# ═══════════════════════════════════════════════════════════════════════════
#  TEST: FINDING GRAPH
# ═══════════════════════════════════════════════════════════════════════════


def test_finding_graph_chain_scoring():
    """Chain score should grow when findings are linked."""
    from tools.zero_day_heuristics import (
        Finding,
        FindingGraph,
        SeverityLevel,
    )
    from tools.vuln_engine import VulnClass

    g = FindingGraph()
    f1 = Finding(
        detector="d1", title="Auth missing", severity=SeverityLevel.HIGH,
        vuln_class=VulnClass.AUTH_BROKEN, url="http://x/a", method="GET",
    )
    f2 = Finding(
        detector="d2", title="IDOR user data", severity=SeverityLevel.HIGH,
        vuln_class=VulnClass.BROKEN_ACCESS, url="http://x/a", method="GET", parameter="id",
    )
    f3 = Finding(
        detector="d3", title="Mass assignment to admin", severity=SeverityLevel.CRITICAL,
        vuln_class=VulnClass.BROKEN_ACCESS, url="http://x/a", method="POST", parameter="role",
    )
    n1 = g.add_finding(f1)
    n2 = g.add_finding(f2)
    n3 = g.add_finding(f3)
    chain = [n1, n2, n3]
    score = g.chain_score(chain)
    # Score formula: sum(floor) * 1.5^(n-1), capped at 10.
    # HIGH floor=7.5, HIGH floor=7.5, CRITICAL floor=9.5 -> total=24.5 * 1.5^2 = 55.125 -> cap 10.
    assert 0 < score <= 10.0
    assert score >= 7.5  # at least one critical/high
    print(f"[OK] test_finding_graph_chain_scoring score={score}")


def test_finding_graph_chain_detection():
    """Three findings on same endpoint should be detected as a chain."""
    from tools.zero_day_heuristics import (
        Finding,
        FindingGraph,
        SeverityLevel,
    )
    from tools.vuln_engine import VulnClass

    g = FindingGraph()
    f1 = Finding(
        detector="d1", title="Auth missing on API", severity=SeverityLevel.HIGH,
        vuln_class=VulnClass.AUTH_BROKEN, url="http://x/api", method="GET",
    )
    f2 = Finding(
        detector="d2", title="IDOR on user endpoint", severity=SeverityLevel.HIGH,
        vuln_class=VulnClass.BROKEN_ACCESS, url="http://x/api", method="GET",
    )
    f3 = Finding(
        detector="d3", title="Admin via mass assignment", severity=SeverityLevel.CRITICAL,
        vuln_class=VulnClass.BROKEN_ACCESS, url="http://x/api", method="POST",
    )
    for f in (f1, f2, f3):
        g.add_finding(f)
    chains = g.detect_chains()
    assert chains, "no chains detected"
    summary = chains[0]["summary"]
    assert "Auth missing" in summary or "IDOR" in summary or "mass assignment" in summary.lower()
    assert chains[0]["score"] > 0
    print(f"[OK] test_finding_graph_chain_detection chains={len(chains)}")


def test_finding_graph_no_chains_when_only_one_finding():
    """A single finding is not a chain."""
    from tools.zero_day_heuristics import Finding, FindingGraph, SeverityLevel
    from tools.vuln_engine import VulnClass

    g = FindingGraph()
    g.add_finding(Finding(
        detector="d", title="Solo", severity=SeverityLevel.LOW,
        vuln_class=VulnClass.XSS, url="http://x/a", method="GET",
    ))
    chains = g.detect_chains()
    assert chains == []
    print("[OK] test_finding_graph_no_chains_when_only_one_finding")


def test_finding_graph_render_smoke():
    """render() must include all nodes and edges."""
    from tools.zero_day_heuristics import Finding, FindingGraph, SeverityLevel
    from tools.vuln_engine import VulnClass

    g = FindingGraph()
    g.add_endpoint("http://x/a", "GET")
    g.add_parameter("ep:GET:http://x/a", "id")
    g.add_finding(Finding(
        detector="d", title="IDOR", severity=SeverityLevel.HIGH,
        vuln_class=VulnClass.BROKEN_ACCESS, url="http://x/a", method="GET", parameter="id",
    ))
    rendered = g.render()
    assert "ep:GET:http://x/a" in rendered
    assert "param:ep:GET:http://x/a:id" in rendered
    assert "finding:" in rendered
    print("[OK] test_finding_graph_render_smoke")


# ═══════════════════════════════════════════════════════════════════════════
#  TEST: ZERO-DAY ENGINE END-TO-END
# ═══════════════════════════════════════════════════════════════════════════


def test_engine_imports_and_constructs():
    """ZeroDayEngine should construct with default config."""
    from tools.zero_day_heuristics import ZeroDayEngine, ScanConfig
    engine = ZeroDayEngine(config=ScanConfig(
        enable_prototype=True,
        enable_mass_assignment=True,
        enable_deserialization=False,
        enable_smuggling=True,
        enable_race=False,
        enable_ssti=False,
        enable_graphql=False,
        enable_jwt=False,
        enable_anomaly=False,
    ))
    try:
        assert "prototype" in engine._detectors
        assert "mass_assignment" in engine._detectors
        assert "smuggling" in engine._detectors
        assert "deserialization" not in engine._detectors
    finally:
        engine.close()
    print("[OK] test_engine_imports_and_constructs")


def test_engine_end_to_end(mock_server):
    """End-to-end run against a synthetic multi-detector target."""
    from tools.zero_day_heuristics import ZeroDayEngine, ScanConfig

    # Single endpoint that echoes payload back — exercises SSTI canary
    # and mass assignment reflection.
    def echo(h: BaseHTTPRequestHandler, ctx: Dict[str, Any]) -> None:
        body = ctx["body"] or b""
        path = ctx["path"]
        q = parse_qs(urlparse(path).query)
        marker = (q.get("q") or [""])[0]
        if marker == "{{7*7}}":
            _respond(h, 200, b"Result: 49", headers={"Content-Type": "text/html"})
            return
        # Mass assignment echo
        if b"isAdmin" in body:
            _respond(h, 200, b'{"user":"x","isAdmin":true,"role":"admin"}')
            return
        _respond(h, 200, body or b"ok")

    _register_route("GET", "/api", echo)
    _register_route("POST", "/api", echo)

    config = ScanConfig(
        enable_prototype=False,
        enable_mass_assignment=True,
        enable_deserialization=False,
        enable_smuggling=False,
        enable_race=False,
        enable_ssti=True,
        enable_graphql=False,
        enable_jwt=False,
        enable_anomaly=False,
        timeout=3.0,
    )
    engine = ZeroDayEngine(config=config)
    try:
        findings = asyncio.run(engine.scan(f"{mock_server}/api"))
    finally:
        engine.close()
    titles = [f.title for f in findings]
    assert any("49" in t or "SSTI" in t for t in titles), titles
    assert any("isAdmin" in t or "Mass assignment" in t for t in titles), titles
    print(f"[OK] test_engine_end_to_end findings={len(findings)}")


def test_engine_scan_as_vulns_returns_vulnfindings(mock_server):
    """scan_as_vulns must return VulnFinding-compatible objects."""
    from tools.zero_day_heuristics import ZeroDayEngine, ScanConfig
    from tools.vuln_engine import VulnFinding

    def handler(h: BaseHTTPRequestHandler, ctx: Dict[str, Any]) -> None:
        # Differentiate baseline (no marker) from probe (with `{{7*7}}`) so
        # the SSTI detector can spot the new "49" reflection.
        path = ctx["path"]
        q = parse_qs(urlparse(path).query)
        marker = (q.get("q") or [""])[0]
        if marker == "{{7*7}}":
            _respond(h, 200, b"Result: 49", headers={"Content-Type": "text/html"})
            return
        _respond(h, 200, b"Result: blank", headers={"Content-Type": "text/html"})

    _register_route("GET", "/ssti", handler)
    config = ScanConfig(
        enable_prototype=False, enable_mass_assignment=False,
        enable_deserialization=False, enable_smuggling=False,
        enable_race=False, enable_ssti=True, enable_graphql=False,
        enable_jwt=False, enable_anomaly=False, timeout=3.0,
    )
    engine = ZeroDayEngine(config=config)
    try:
        vulns = asyncio.run(engine.scan_as_vulns(f"{mock_server}/ssti"))
    finally:
        engine.close()
    assert vulns, "expected at least one VulnFinding"
    for v in vulns:
        assert isinstance(v, VulnFinding)
        assert v.cvss_vector.startswith("CVSS:3.1")
    print(f"[OK] test_engine_scan_as_vulns_returns_vulnfindings vulns={len(vulns)}")


def test_engine_deduplicates(mock_server):
    """Deduplication should remove duplicates introduced by overlapping detectors."""
    from tools.zero_day_heuristics import ZeroDayEngine, ScanConfig

    def handler(h: BaseHTTPRequestHandler, ctx: Dict[str, Any]) -> None:
        _respond(h, 200, b"Result: 49", headers={"Content-Type": "text/html"})

    _register_route("GET", "/dedup", handler)
    config = ScanConfig(
        enable_ssti=True, enable_prototype=False, enable_mass_assignment=False,
        enable_deserialization=False, enable_smuggling=False, enable_race=False,
        enable_graphql=False, enable_jwt=False, enable_anomaly=False, timeout=3.0,
    )
    engine = ZeroDayEngine(config=config)
    try:
        findings = asyncio.run(engine.scan(f"{mock_server}/dedup"))
    finally:
        engine.close()
    titles = [f.title for f in findings]
    assert len(titles) == len(set(titles)), "duplicate titles in findings"
    print(f"[OK] test_engine_deduplicates findings={len(findings)}")


def test_engine_severity_ordering(mock_server):
    """Findings should be sorted critical-first by default."""
    from tools.zero_day_heuristics import ZeroDayEngine, ScanConfig, SeverityLevel

    def handler(h: BaseHTTPRequestHandler, ctx: Dict[str, Any]) -> None:
        _respond(h, 200, b"Result: 49", headers={"Content-Type": "text/html"})

    _register_route("GET", "/order", handler)
    config = ScanConfig(
        enable_ssti=True, enable_prototype=False, enable_mass_assignment=False,
        enable_deserialization=False, enable_smuggling=False, enable_race=False,
        enable_graphql=False, enable_jwt=False, enable_anomaly=False, timeout=3.0,
    )
    engine = ZeroDayEngine(config=config)
    try:
        findings = asyncio.run(engine.scan(f"{mock_server}/order"))
    finally:
        engine.close()
    rank = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
    ranks = [rank.get(f.severity.value, 0) for f in findings]
    assert ranks == sorted(ranks, reverse=True), f"not sorted: {ranks}"
    print(f"[OK] test_engine_severity_ordering ranks={ranks}")


def test_engine_correlates_into_graph(mock_server):
    """Findings must be added to the engine's FindingGraph."""
    from tools.zero_day_heuristics import ZeroDayEngine, ScanConfig

    def handler(h: BaseHTTPRequestHandler, ctx: Dict[str, Any]) -> None:
        _respond(h, 200, b"Result: 49", headers={"Content-Type": "text/html"})

    _register_route("GET", "/graph", handler)
    config = ScanConfig(
        enable_ssti=True, enable_prototype=False, enable_mass_assignment=False,
        enable_deserialization=False, enable_smuggling=False, enable_race=False,
        enable_graphql=False, enable_jwt=False, enable_anomaly=False, timeout=3.0,
    )
    engine = ZeroDayEngine(config=config)
    try:
        findings = asyncio.run(engine.scan(f"{mock_server}/graph"))
    finally:
        engine.close()
    finding_nodes = [n for n in engine.graph.nodes.values() if n.kind == "finding"]
    assert len(finding_nodes) == len(findings), (
        f"graph has {len(finding_nodes)} findings but engine returned {len(findings)}"
    )
    print(f"[OK] test_engine_correlates_into_graph nodes={len(finding_nodes)}")


def test_engine_run_zero_day_scan_helper(mock_server):
    """Module-level run_zero_day_scan must produce VulnFindings."""
    from tools.zero_day_heuristics import run_zero_day_scan
    from tools.vuln_engine import VulnFinding

    def handler(h: BaseHTTPRequestHandler, ctx: Dict[str, Any]) -> None:
        path = ctx["path"]
        q = parse_qs(urlparse(path).query)
        marker = (q.get("q") or [""])[0]
        if marker == "{{7*7}}":
            _respond(h, 200, b"Result: 49", headers={"Content-Type": "text/html"})
            return
        _respond(h, 200, b"Result: blank", headers={"Content-Type": "text/html"})

    _register_route("GET", "/helper", handler)
    vulns = asyncio.run(run_zero_day_scan(
        f"{mock_server}/helper",
        enable_ssti=True,
        enable_prototype=False,
        enable_mass_assignment=False,
        enable_deserialization=False,
        enable_smuggling=False,
        enable_race=False,
        enable_graphql=False,
        enable_jwt=False,
        enable_anomaly=False,
        timeout=3.0,
    ))
    assert vulns
    assert all(isinstance(v, VulnFinding) for v in vulns)
    print(f"[OK] test_engine_run_zero_day_scan_helper vulns={len(vulns)}")


def test_engine_signature_includes_all_exports():
    """Public surface must be stable (no accidental renames)."""
    from tools import zero_day_heuristics as zd

    expected = {
        "SeverityLevel", "SEVERITY_CVSS_FLOOR", "Finding", "HTTPClient",
        "PrototypePollutionDetector", "MassAssignmentDetector",
        "InsecureDeserializationDetector", "HTTPSmugglingDetector",
        "RaceConditionDetector", "SSTIDetector", "GraphQLIntrospectionDetector",
        "JWTAlgorithmDetector", "SmartAnomalyDetector", "FindingGraph",
        "FindingNode", "FindingEdge", "ScanConfig", "ZeroDayEngine",
        "run_zero_day_scan",
    }
    actual = set(zd.__all__)
    missing = expected - actual
    assert not missing, f"missing exports: {missing}"
    extra = actual - expected
    assert not extra, f"unexpected exports: {extra}"
    print("[OK] test_engine_signature_includes_all_exports")


def test_engine_async_scan_signature():
    """ZeroDayEngine.scan must be a coroutine function."""
    from tools.zero_day_heuristics import ZeroDayEngine
    assert inspect.iscoroutinefunction(ZeroDayEngine.scan)
    assert inspect.iscoroutinefunction(ZeroDayEngine.scan_as_vulns)
    print("[OK] test_engine_async_scan_signature")


# ═══════════════════════════════════════════════════════════════════════════
# HONEST LABELING TESTS — verify static findings are not falsely labeled
# ═══════════════════════════════════════════════════════════════════════════

def test_jwt_static_findings_marked_as_candidates():
    """CRITICAL: Static JWT findings must be clearly marked as untested candidates."""
    from tools.zero_day_heuristics import JWTAlgorithmDetector
    det = JWTAlgorithmDetector()
    findings = det.detect()
    assert len(findings) > 0
    for f in findings:
        # Title must include CANDIDATE and (not tested)
        assert "CANDIDATE" in f.title
        assert "not tested" in f.title.lower()
        # Confidence must be 0 (untested)
        assert getattr(f, "confidence", -1) == 0.0
        # Metadata must mark it as static
        md = getattr(f, "metadata", {}) or {}
        assert md.get("static") is True
        assert md.get("tested") is False


def test_jwt_endpoint_discovery():
    """Auto-discovery must probe common auth paths and find JWT-bearing responses."""
    import asyncio
    from tools.zero_day_heuristics import ZeroDayEngine, ScanConfig
    async def go():
        e = ZeroDayEngine(config=ScanConfig())
        endpoints = await e._discover_jwt_endpoints("httpbin.org")
        # httpbin has no JWT endpoints; expect 0
        assert isinstance(endpoints, list)
        assert len(endpoints) == 0
    asyncio.run(go())


def test_jwt_looks_like_jwt_helper():
    """_looks_like_jwt must detect base64url.eyJ... patterns."""
    from tools.zero_day_heuristics import ZeroDayEngine
    valid = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    assert ZeroDayEngine._looks_like_jwt(f"Bearer {valid}") is True
    assert ZeroDayEngine._looks_like_jwt(f'{{"token": "{valid}"}}') is True
    assert ZeroDayEngine._looks_like_jwt("just a regular string") is False
    assert ZeroDayEngine._looks_like_jwt("") is False


def test_zero_day_findings_have_honest_labels():
    """ZeroDayEngine.scan output must include honest 'CANDIDATE' labels for static findings."""
    import asyncio
    from tools.zero_day_heuristics import ZeroDayEngine, ScanConfig
    async def go():
        e = ZeroDayEngine(config=ScanConfig())
        findings = await e.scan("httpbin.org")
        jwt_findings = [f for f in findings if "JWT" in (f.title or "")]
        if jwt_findings:
            for f in jwt_findings:
                # Every JWT finding on httpbin (no JWT endpoints) must be labeled as candidate
                assert "CANDIDATE" in f.title
    asyncio.run(go())


if __name__ == "__main__":
    # Allow running tests directly: `python3 tests/test_zero_day_heuristics.py`
    sys.exit(pytest.main([__file__, "-v"]))
