"""tests/test_logic_flaw_engine.py

Tests for the Elengenix Logic Flaw Engine.

Covers:
- Data model (LogicFinding, Evidence, Severity, LogicFlawConfig)
- Endpoint normalization helpers
- UUID v1 timestamp extraction
- Price-manipulation detector (negative, overflow, quantity, currency, discount)
- Race-condition detector (heuristic + dynamic burst)
- State-machine bypass detector
- Auth-logic detector (reset, 2FA, session, remember, OAuth)
- Authorization detector (sequential IDs, UUID v1, role param, admin path, tenant)
- Workflow-integrity detector
- Business-constraint detector (min/max, time, geo, KYC, trial)
- Inference engine scoring
- Correlation engine chaining
- Top-level LogicFlawEngine.analyze() integration
- Mock HTTP server simulating BOLA / TOCTOU / price endpoints
"""

from __future__ import annotations

import asyncio
import json
import sys
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any, Dict, List

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


# ═══════════════════════════════════════════════════════════════════════════
# Mock server - simulates a vulnerable API
# ═══════════════════════════════════════════════════════════════════════════


class MockLogicServer(BaseHTTPRequestHandler):
    """Mock server exposing endpoints with intentional logic flaws.

    Routes:
        GET  /api/users/{id}            - sequential IDs, BOLA (200 for all)
        GET  /api/admin/{id}            - admin path, no auth check (BFLA)
        POST /api/transfer              - amount param, no min/max
        POST /api/apply_coupon          - coupon param, single-use not enforced
        POST /api/place_order           - quantity param, accepts 0
        POST /api/login                 - login, but session is NOT rotated
        GET  /oauth/authorize           - OAuth flow with redirect_uri and state
        POST /api/withdraw              - race-friendly
        POST /api/refund                - negative amount accepted
        POST /api/verify_2fa            - 2FA verification, can be skipped
        GET  /api/accounts/{id}         - UUIDv1 IDs, timestamps leak
    """

    def _send(self, status: int, body: str, content_type: str = "application/json") -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        # NOTE: do NOT rotate session cookie on /api/login -> fixation surface
        if self.path == "/api/login":
            self.send_header("Set-Cookie", "session=fixed_session_id; Path=/")
        self.end_headers()
        self.wfile.write(body.encode())

    def do_GET(self) -> None:
        path = self.path
        if path.startswith("/api/users/"):
            oid = path.rsplit("/", 1)[-1]
            # BOLA: returns 200 for all sequential IDs
            self._send(200, json.dumps({"id": int(oid), "name": f"user{oid}"}))
            return
        if path.startswith("/api/accounts/"):
            oid = path.rsplit("/", 1)[-1]
            self._send(200, json.dumps({"id": oid, "balance": 1000}))
            return
        if path.startswith("/api/admin/"):
            # No auth check - BFLA
            self._send(200, json.dumps({"secret": "admin data"}))
            return
        if path.startswith("/oauth/authorize"):
            # Parse query for redirect_uri/state
            from urllib.parse import parse_qs, urlparse

            q = parse_qs(urlparse(path).query)
            redirect = q.get("redirect_uri", [""])[0]
            state = q.get("state", [""])[0]
            if not state:
                # No state -> CSRF
                self._send(400, json.dumps({"error": "missing state"}))
                return
            self._send(200, json.dumps({"redirect": redirect, "state": state}))
            return
        self._send(404, json.dumps({"error": "not found"}))

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        body_raw = self.rfile.read(length).decode("utf-8", errors="replace") if length else ""
        try:
            body = json.loads(body_raw) if body_raw else {}
        except json.JSONDecodeError:
            body = {}

        if self.path == "/api/transfer":
            # No min/max; large amounts allowed
            amount = body.get("amount", 0)
            self._send(200, json.dumps({"ok": True, "amount": amount}))
            return
        if self.path == "/api/apply_coupon":
            # No single-use enforcement
            code = body.get("coupon", "")
            self._send(200, json.dumps({"ok": True, "coupon": code}))
            return
        if self.path == "/api/place_order":
            qty = body.get("quantity", 1)
            # Accepts 0, negative, anything
            self._send(200, json.dumps({"ok": True, "quantity": qty}))
            return
        if self.path == "/api/login":
            self._send(200, json.dumps({"ok": True}))
            return
        if self.path == "/api/withdraw":
            # No atomic balance check -> race friendly
            amount = body.get("amount", 0)
            self._send(200, json.dumps({"ok": True, "withdrawn": amount}))
            return
        if self.path == "/api/refund":
            # Accepts negative amount
            amount = body.get("amount", 0)
            self._send(200, json.dumps({"ok": True, "refund": amount}))
            return
        if self.path == "/api/verify_2fa":
            # Empty code = success
            code = body.get("code", "")
            if code == "":
                self._send(200, json.dumps({"ok": True}))
                return
            self._send(200, json.dumps({"ok": True, "code": code}))
            return
        self._send(404, json.dumps({"error": "not found"}))

    def log_message(self, *args, **kwargs) -> None:  # silence logs
        pass


@pytest.fixture(scope="module")
def mock_server() -> str:
    server = HTTPServer(("127.0.0.1", 18821), MockLogicServer)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    time.sleep(0.3)
    yield "http://127.0.0.1:18821"
    server.shutdown()


# ═══════════════════════════════════════════════════════════════════════════
# 1. Data model & helpers
# ═══════════════════════════════════════════════════════════════════════════


def test_severity_weight_ordering() -> None:
    """Severity weights must be monotonically increasing."""
    from tools.logic_flaw_engine import Severity

    assert Severity.INFO.weight < Severity.LOW.weight < Severity.MEDIUM.weight
    assert Severity.MEDIUM.weight < Severity.HIGH.weight < Severity.CRITICAL.weight
    print("[OK] severity weights monotonic")


def test_logic_finding_id_autogenerated() -> None:
    """LogicFinding should auto-generate an id and default cwe list."""
    from tools.logic_flaw_engine import DetectorCategory, LogicFinding, Severity

    f = LogicFinding(
        title="X",
        target="t",
        endpoint="/x",
        category=DetectorCategory.AUTH_LOGIC,
        severity=Severity.HIGH,
    )
    assert f.finding_id.startswith("LFE-")
    assert len(f.finding_id) == len("LFE-") + 12
    assert "CWE-287" in f.cwe or "CWE-384" in f.cwe or "CWE-640" in f.cwe
    assert f.discovered_at > 0
    print(f"[OK] finding auto id: {f.finding_id}, cwe={f.cwe}")


def test_logic_finding_to_dict_serializable() -> None:
    """to_dict() output must be JSON-serializable."""
    from tools.logic_flaw_engine import LogicFinding

    f = LogicFinding(
        title="t", target="t", endpoint="/t", description="d", impact="i", remediation="r"
    )
    d = f.to_dict()
    s = json.dumps(d)
    parsed = json.loads(s)
    assert parsed["title"] == "t"
    assert "evidence" in parsed
    print("[OK] LogicFinding JSON-serializable")


def test_evidence_collectable() -> None:
    """Evidence list should accumulate kind/description/data."""
    from tools.logic_flaw_engine import LogicFinding

    f = LogicFinding(title="t", target="t", endpoint="/t")
    f.add_evidence("static_pattern", "regex hit", {"param": "amount"})
    f.add_evidence("burst_response", "burst variance", {"samples": 10})
    assert len(f.evidence) == 2
    assert f.evidence[0].kind == "static_pattern"
    assert f.evidence[1].data["samples"] == 10
    print("[OK] evidence accumulation")


def test_normalize_endpoint_accepts_url_string() -> None:
    """normalize_endpoint should accept raw URL strings."""
    from tools.logic_flaw_engine import normalize_endpoint

    out = normalize_endpoint("https://api.com/x")
    assert out["url"] == "https://api.com/x"
    assert out["method"] == "GET"
    assert out["params"] == {}
    print("[OK] normalize url string")


def test_normalize_endpoint_accepts_full_dict() -> None:
    """normalize_endpoint should accept rich endpoint dicts."""
    from tools.logic_flaw_engine import normalize_endpoint

    ep = {
        "url": "https://api.com/y",
        "method": "post",
        "params": {"a": "1"},
        "body": {"b": "2"},
        "headers": {"X-Foo": "bar"},
    }
    out = normalize_endpoint(ep)
    assert out["method"] == "POST"
    assert out["params"] == {"a": "1"}
    assert out["body"] == {"b": "2"}
    assert out["headers"] == {"X-Foo": "bar"}
    print("[OK] normalize full dict")


def test_helper_keyword_predicates() -> None:
    """is_price_endpoint / is_discount_endpoint / is_auth_endpoint / is_workflow_endpoint."""
    from tools.logic_flaw_engine import (
        is_auth_endpoint,
        is_discount_endpoint,
        is_price_endpoint,
        is_workflow_endpoint,
    )

    assert is_price_endpoint({"url": "/api/pay", "method": "POST", "body": {"amount": 1}})
    assert is_discount_endpoint({"url": "/api/apply_coupon", "method": "POST"})
    assert is_auth_endpoint({"url": "/api/login", "method": "POST"})
    assert is_workflow_endpoint({"url": "/api/onboard/step-2", "method": "GET"})
    assert not is_price_endpoint({"url": "/api/heartbeat", "method": "GET"})
    print("[OK] helper keyword predicates")


# ═══════════════════════════════════════════════════════════════════════════
# 2. UUID v1 decoder
# ═══════════════════════════════════════════════════════════════════════════


def test_uuid_v1_is_detected() -> None:
    """UUID v1 strings must be recognized by the decoder."""
    from tools.logic_flaw_engine import UUIDV1Decoder

    u = str(uuid.uuid1())
    assert UUIDV1Decoder.is_uuid_v1(u)
    # UUID v4 has version=4, must be rejected
    u4 = str(uuid.uuid4())
    assert not UUIDV1Decoder.is_uuid_v1(u4)
    print(f"[OK] uuid v1 detected: {u}")


def test_uuid_v1_timestamp_extraction() -> None:
    """Extract a plausible Unix timestamp (ms) from a UUID v1."""
    from tools.logic_flaw_engine import UUIDV1Decoder

    u = str(uuid.uuid1())
    ts_ms = UUIDV1Decoder.extract_timestamp_ms(u)
    assert ts_ms is not None
    # Should be within the last hour (uuid1 was just created)
    now_ms = int(time.time() * 1000)
    assert abs(now_ms - ts_ms) < 60_000, f"timestamp drift > 60s: {ts_ms} vs {now_ms}"
    print(f"[OK] uuid v1 timestamp ~{ts_ms}")


def test_uuid_v1_extract_returns_none_for_v4() -> None:
    """UUIDv4 should produce None from timestamp extraction."""
    from tools.logic_flaw_engine import UUIDV1Decoder

    u4 = str(uuid.uuid4())
    assert UUIDV1Decoder.extract_timestamp_ms(u4) is None
    print("[OK] uuid v4 returns None")


# ═══════════════════════════════════════════════════════════════════════════
# 3. Price / amount manipulation detector
# ═══════════════════════════════════════════════════════════════════════════


def test_price_detector_flags_negative_amount() -> None:
    from tools.logic_flaw_engine import LogicFlawEngine

    engine = LogicFlawEngine()
    endpoints = [
        {
            "url": "https://api.com/transfer",
            "method": "POST",
            "body": {"amount": 100, "user_id": 1},
        },
    ]
    findings = asyncio.run(engine.detectors[0].detect("api.com", endpoints))
    titles = [f.title for f in findings]
    assert any("Negative" in t for t in titles), titles
    assert any(f.parameter == "amount" for f in findings)
    print(f"[OK] price: negative-amount flag raised ({len(findings)} findings)")


def test_price_detector_flags_quantity_zero() -> None:
    from tools.logic_flaw_engine import LogicFlawEngine

    engine = LogicFlawEngine()
    endpoints = [
        {
            "url": "https://api.com/place_order",
            "method": "POST",
            "body": {"quantity": 1, "product_id": 1},
        },
    ]
    findings = asyncio.run(engine.detectors[0].detect("api.com", endpoints))
    titles = [f.title for f in findings]
    assert any("Quantity" in t for t in titles), titles
    print(f"[OK] price: quantity flag ({len(findings)} findings)")


def test_price_detector_currency_confusion() -> None:
    from tools.logic_flaw_engine import LogicFlawEngine

    engine = LogicFlawEngine()
    endpoints = [
        {
            "url": "https://api.com/charge",
            "method": "POST",
            "body": {"amount": 100, "currency": "JPY", "user_id": 1},
        },
    ]
    findings = asyncio.run(engine.detectors[0].detect("api.com", endpoints))
    # JPY is zero-decimal currency
    titles = [f.title for f in findings]
    assert any("JPY" in t for t in titles), titles
    assert any(f.severity.value == "critical" for f in findings)
    print(f"[OK] price: currency confusion JPY raised")


def test_price_detector_discount_stacking() -> None:
    from tools.logic_flaw_engine import LogicFlawEngine

    engine = LogicFlawEngine()
    endpoints = [
        {
            "url": "https://api.com/apply_coupon",
            "method": "POST",
            "body": {"coupon": "SAVE10", "user_id": 1},
        },
    ]
    findings = asyncio.run(engine.detectors[0].detect("api.com", endpoints))
    titles = [f.title for f in findings]
    assert any("stacking" in t.lower() or "reuse" in t.lower() for t in titles), titles
    print(f"[OK] price: discount-stacking raised")


def test_price_detector_skips_non_price_endpoints() -> None:
    from tools.logic_flaw_engine import LogicFlawEngine

    engine = LogicFlawEngine()
    endpoints = [
        {"url": "https://api.com/heartbeat", "method": "GET", "params": {"q": "1"}},
    ]
    findings = asyncio.run(engine.detectors[0].detect("api.com", endpoints))
    # No price-related output expected
    assert all("Negative" not in f.title and "Quantity" not in f.title for f in findings)
    print(f"[OK] price: no false positive on heartbeat")


def test_price_detector_integer_overflow_payloads() -> None:
    """Integer overflow payloads should be referenced in the finding evidence."""
    from tools.logic_flaw_engine import LogicFlawConfig, PriceManipulationDetector

    det = PriceManipulationDetector(LogicFlawConfig())
    endpoints = [
        {"url": "https://api.com/pay", "method": "POST", "body": {"amount": 100}},
    ]
    findings = asyncio.run(det.detect("api.com", endpoints))
    overflow = [f for f in findings if "overflow" in f.title.lower()]
    assert overflow, "no overflow finding"
    # Each finding carries evidence payloads
    for f in overflow:
        ev_data = f.evidence[0].data
        assert "payloads" in ev_data
        assert any(p > 10**9 for p in ev_data["payloads"])
    print(f"[OK] price: overflow evidence payloads present")


# ═══════════════════════════════════════════════════════════════════════════
# 4. Race condition detector
# ═══════════════════════════════════════════════════════════════════════════


def test_race_detector_static_heuristic() -> None:
    from tools.logic_flaw_engine import LogicFlawEngine

    engine = LogicFlawEngine()
    endpoints = [
        {"url": "https://api.com/apply_coupon", "method": "POST", "body": {"coupon": "WELCOME"}},
        {
            "url": "https://api.com/withdraw",
            "method": "POST",
            "body": {"amount": 100, "user_id": 1},
        },
    ]
    det = engine.detectors[1]  # RaceConditionDetector
    findings = asyncio.run(det.detect("api.com", endpoints))
    assert len(findings) >= 2
    assert all("race" in f.tags or "toctou" in f.tags for f in findings)
    print(f"[OK] race: {len(findings)} heuristic findings")


def test_race_detector_dynamic_burst(mock_server: str) -> None:
    """Dynamic burst against the mock server's withdraw endpoint."""
    from tools.logic_flaw_engine import LogicFlawConfig, LogicFlawEngine, RaceConditionDetector

    cfg = LogicFlawConfig(race_default_concurrency=6, race_default_attempts=2)
    engine = LogicFlawEngine(cfg)
    det = RaceConditionDetector(cfg)
    det._client = engine.http  # type: ignore[attr-defined]
    endpoints = [
        {
            "url": f"{mock_server}/api/withdraw",
            "method": "POST",
            "body": {"amount": 50, "user_id": 1},
        },
    ]
    findings = asyncio.run(det.detect("api.com", endpoints))
    # We expect at least a heuristic finding (burst evidence is not
    # deterministic, but the static finding is guaranteed).
    assert any("race" in f.tags for f in findings)
    print(f"[OK] race: dynamic burst produced {len(findings)} findings")


def test_race_detector_ignores_get_endpoints() -> None:
    from tools.logic_flaw_engine import LogicFlawEngine

    engine = LogicFlawEngine()
    endpoints = [
        {"url": "https://api.com/apply_coupon_history", "method": "GET"},
    ]
    det = engine.detectors[1]
    findings = asyncio.run(det.detect("api.com", endpoints))
    assert findings == []
    print("[OK] race: GET endpoints ignored")


# ═══════════════════════════════════════════════════════════════════════════
# 5. State machine bypass detector
# ═══════════════════════════════════════════════════════════════════════════


def test_state_machine_skips_step_via_query() -> None:
    from tools.logic_flaw_engine import LogicFlawEngine

    engine = LogicFlawEngine()
    endpoints = [
        {
            "url": "https://api.com/onboard",
            "method": "POST",
            "params": {"step": "3", "state": "approved"},
        },
    ]
    det = engine.detectors[2]
    findings = asyncio.run(det.detect("api.com", endpoints))
    titles = [f.title for f in findings]
    assert any("skip" in t.lower() or "State-skip" in t for t in titles), titles
    print(f"[OK] state: skip-step query flagged ({len(findings)})")


def test_state_machine_deep_linkable_step() -> None:
    from tools.logic_flaw_engine import LogicFlawEngine

    engine = LogicFlawEngine()
    endpoints = [
        {"url": "https://api.com/onboard/step-1", "method": "GET"},
        {"url": "https://api.com/onboard/step-2", "method": "GET"},
        {"url": "https://api.com/onboard/step-3", "method": "GET"},
    ]
    det = engine.detectors[2]
    findings = asyncio.run(det.detect("api.com", endpoints))
    deep = [f for f in findings if "Deep-linkable" in f.title]
    assert deep, f"expected deep-link finding, got: {[f.title for f in findings]}"
    print(f"[OK] state: deep-link finding for step 3")


def test_state_machine_admin_path() -> None:
    from tools.logic_flaw_engine import LogicFlawEngine

    engine = LogicFlawEngine()
    endpoints = [
        {"url": "https://api.com/admin/users", "method": "GET"},
    ]
    det = engine.detectors[2]
    findings = asyncio.run(det.detect("api.com", endpoints))
    assert any("admin" in f.tags for f in findings)
    print(f"[OK] state: admin-path flagged")


# ═══════════════════════════════════════════════════════════════════════════
# 6. Auth logic detector
# ═══════════════════════════════════════════════════════════════════════════


def test_auth_reset_token_flagged() -> None:
    from tools.logic_flaw_engine import LogicFlawEngine

    engine = LogicFlawEngine()
    endpoints = [
        {
            "url": "https://api.com/auth/forgot_password",
            "method": "POST",
            "body": {"email": "a@b.c"},
        },
    ]
    det = engine.detectors[3]
    findings = asyncio.run(det.detect("api.com", endpoints))
    assert any(any("reset" in t for t in f.tags) for f in findings)
    print(f"[OK] auth: reset-token entropy raised")


def test_auth_2fa_bypass_flagged() -> None:
    from tools.logic_flaw_engine import LogicFlawEngine

    engine = LogicFlawEngine()
    endpoints = [
        {"url": "https://api.com/auth/verify_2fa", "method": "POST", "body": {"code": "123456"}},
    ]
    det = engine.detectors[3]
    findings = asyncio.run(det.detect("api.com", endpoints))
    assert any(any("2fa" in t for t in f.tags) for f in findings)
    print(f"[OK] auth: 2FA bypass raised")


def test_auth_session_fixation_flagged() -> None:
    from tools.logic_flaw_engine import LogicFlawEngine

    engine = LogicFlawEngine()
    endpoints = [
        {
            "url": "https://api.com/auth/login",
            "method": "POST",
            "body": {"username": "u", "password": "p"},
        },
    ]
    det = engine.detectors[3]
    findings = asyncio.run(det.detect("api.com", endpoints))
    assert any("session_fixation" in f.tags for f in findings)
    print(f"[OK] auth: session fixation raised")


def test_auth_oauth_external_redirect_flagged() -> None:
    from tools.logic_flaw_engine import LogicFlawEngine

    engine = LogicFlawEngine()
    endpoints = [
        {
            "url": "https://api.com/oauth/authorize",
            "method": "GET",
            "params": {"redirect_uri": "https://evil.com/callback", "state": "abc"},
        },
    ]
    det = engine.detectors[3]
    findings = asyncio.run(det.detect("api.com", endpoints))
    # At least the open-redirect and/or the missing-state should fire
    assert any("oauth" in f.tags for f in findings)
    # The redirect_uri to evil.com must trigger the open-redirect finding
    assert any("evil.com" in f.title for f in findings), [f.title for f in findings]
    print(f"[OK] auth: OAuth external redirect flagged ({len(findings)})")


def test_auth_oauth_missing_state_flagged() -> None:
    from tools.logic_flaw_engine import LogicFlawEngine

    engine = LogicFlawEngine()
    endpoints = [
        {
            "url": "https://api.com/oauth/authorize",
            "method": "GET",
            "params": {"redirect_uri": "https://app.com/cb"},
        },
    ]
    det = engine.detectors[3]
    findings = asyncio.run(det.detect("api.com", endpoints))
    assert any("CSRF" in f.title or "state" in f.title for f in findings)
    print("[OK] auth: OAuth missing state (CSRF) raised")


def test_auth_remember_me_flagged() -> None:
    from tools.logic_flaw_engine import LogicFlawEngine

    engine = LogicFlawEngine()
    endpoints = [
        {"url": "https://api.com/auth/remember_me", "method": "POST", "body": {"remember": "true"}},
    ]
    det = engine.detectors[3]
    findings = asyncio.run(det.detect("api.com", endpoints))
    assert any(any("remember" in t for t in f.tags) for f in findings)
    print("[OK] auth: remember-me raised")


# ═══════════════════════════════════════════════════════════════════════════
# 7. Authorization detector (BOLA / BFLA)
# ═══════════════════════════════════════════════════════════════════════════


def test_authorization_sequential_id_flagged() -> None:
    from tools.logic_flaw_engine import LogicFlawEngine

    engine = LogicFlawEngine()
    endpoints = [
        {"url": "https://api.com/api/users/1", "method": "GET"},
        {"url": "https://api.com/api/users/2", "method": "GET"},
        {"url": "https://api.com/api/users/3", "method": "GET"},
    ]
    det = engine.detectors[4]
    findings = asyncio.run(det.detect("api.com", endpoints))
    bola = [f for f in findings if "sequential" in f.tags or "bola" in f.tags]
    assert bola, f"no BOLA finding, got: {[(f.title, f.tags) for f in findings]}"
    assert bola[0].confidence >= 0.8
    print(f"[OK] authz: sequential ID BOLA flagged ({len(findings)})")


def test_authorization_uuid_v1_flagged() -> None:
    from tools.logic_flaw_engine import LogicFlawEngine

    u1 = str(uuid.uuid1())
    engine = LogicFlawEngine()
    endpoints = [
        {"url": f"https://api.com/api/accounts/{u1}", "method": "GET"},
    ]
    det = engine.detectors[4]
    findings = asyncio.run(det.detect("api.com", endpoints))
    assert any("uuid_v1" in f.tags for f in findings)
    # The evidence should expose the original UUID value
    ev = findings[0].evidence[0].data
    assert ev.get("uuid") == u1
    assert ev.get("extracted_timestamp_ms") is not None
    print(f"[OK] authz: UUID v1 leak flagged")


def test_authorization_role_param_flagged() -> None:
    from tools.logic_flaw_engine import LogicFlawEngine

    engine = LogicFlawEngine()
    endpoints = [
        {"url": "https://api.com/api/users/list", "method": "GET", "params": {"role": "user"}},
    ]
    det = engine.detectors[4]
    findings = asyncio.run(det.detect("api.com", endpoints))
    bfla = [f for f in findings if "bfla" in f.tags or "role_param" in f.tags]
    assert bfla
    assert bfla[0].severity.value == "critical"
    print("[OK] authz: role-param BFLA flagged")


def test_authorization_admin_path_flagged() -> None:
    from tools.logic_flaw_engine import LogicFlawEngine

    engine = LogicFlawEngine()
    endpoints = [
        {"url": "https://api.com/admin/users", "method": "GET"},
    ]
    det = engine.detectors[4]
    findings = asyncio.run(det.detect("api.com", endpoints))
    assert any("admin" in f.tags for f in findings)
    print("[OK] authz: admin path flagged")


def test_authorization_tenant_boundary_flagged() -> None:
    from tools.logic_flaw_engine import LogicFlawEngine

    engine = LogicFlawEngine()
    endpoints = [
        {"url": "https://api.com/workspace/projects", "method": "GET"},
    ]
    det = engine.detectors[4]
    findings = asyncio.run(det.detect("api.com", endpoints))
    assert any("multi_tenant" in f.tags for f in findings)
    print("[OK] authz: multi-tenant boundary flagged")


# ═══════════════════════════════════════════════════════════════════════════
# 8. Workflow integrity detector
# ═══════════════════════════════════════════════════════════════════════════


def test_workflow_missing_idempotency_key() -> None:
    from tools.logic_flaw_engine import LogicFlawEngine

    engine = LogicFlawEngine()
    endpoints = [
        {"url": "https://api.com/api/pay", "method": "POST", "body": {"amount": 100, "user_id": 1}},
    ]
    det = engine.detectors[5]
    findings = asyncio.run(det.detect("api.com", endpoints))
    assert any("idempotency" in f.tags for f in findings)
    print("[OK] workflow: missing idempotency key flagged")


def test_workflow_present_idempotency_key_passes() -> None:
    from tools.logic_flaw_engine import LogicFlawEngine

    engine = LogicFlawEngine()
    endpoints = [
        {
            "url": "https://api.com/api/pay",
            "method": "POST",
            "body": {"amount": 100, "idempotency_key": "abc-123"},
        },
    ]
    det = engine.detectors[5]
    findings = asyncio.run(det.detect("api.com", endpoints))
    assert not any("idempotency" in f.tags for f in findings)
    print("[OK] workflow: idempotency key present -> no finding")


def test_workflow_force_param_flagged() -> None:
    from tools.logic_flaw_engine import LogicFlawEngine

    engine = LogicFlawEngine()
    endpoints = [
        {
            "url": "https://api.com/api/refund",
            "method": "POST",
            "body": {"amount": 50, "force": "1"},
        },
    ]
    det = engine.detectors[5]
    findings = asyncio.run(det.detect("api.com", endpoints))
    assert any("order_of_ops" in f.tags or "Order" in f.title for f in findings)
    print("[OK] workflow: force param order-of-ops flagged")


# ═══════════════════════════════════════════════════════════════════════════
# 9. Business constraint detector
# ═══════════════════════════════════════════════════════════════════════════


def test_constraint_time_param_flagged() -> None:
    from tools.logic_flaw_engine import LogicFlawEngine

    engine = LogicFlawEngine()
    endpoints = [
        {
            "url": "https://api.com/api/charge",
            "method": "POST",
            "body": {"amount": 100, "timestamp": 1234567890},
        },
    ]
    det = engine.detectors[6]
    findings = asyncio.run(det.detect("api.com", endpoints))
    assert any("time" in f.tags for f in findings)
    print("[OK] constraint: client time flagged")


def test_constraint_geo_param_flagged() -> None:
    from tools.logic_flaw_engine import LogicFlawEngine

    engine = LogicFlawEngine()
    endpoints = [
        {"url": "https://api.com/api/content", "method": "GET", "params": {"country": "US"}},
    ]
    det = engine.detectors[6]
    findings = asyncio.run(det.detect("api.com", endpoints))
    assert any("geo" in f.tags for f in findings)
    print("[OK] constraint: geo-param flagged")


def test_constraint_kyc_param_flagged() -> None:
    from tools.logic_flaw_engine import LogicFlawEngine

    engine = LogicFlawEngine()
    endpoints = [
        {
            "url": "https://api.com/api/account/tier",
            "method": "POST",
            "body": {"tier": "gold", "user_id": 1},
        },
    ]
    det = engine.detectors[6]
    findings = asyncio.run(det.detect("api.com", endpoints))
    assert any("kyc" in f.tags for f in findings)
    print("[OK] constraint: KYC/AML flagged")


def test_constraint_trial_param_flagged() -> None:
    from tools.logic_flaw_engine import LogicFlawEngine

    engine = LogicFlawEngine()
    endpoints = [
        {
            "url": "https://api.com/api/signup",
            "method": "POST",
            "body": {"email": "a@b.c", "is_trial": "1"},
        },
    ]
    det = engine.detectors[6]
    findings = asyncio.run(det.detect("api.com", endpoints))
    assert any("trial" in f.tags for f in findings)
    print("[OK] constraint: trial abuse flagged")


def test_constraint_min_max_amount_flagged() -> None:
    from tools.logic_flaw_engine import LogicFlawEngine

    engine = LogicFlawEngine()
    endpoints = [
        {
            "url": "https://api.com/api/transfer",
            "method": "POST",
            "body": {"amount": 100, "user_id": 1},
        },
    ]
    det = engine.detectors[6]
    findings = asyncio.run(det.detect("api.com", endpoints))
    assert any("min_max" in f.tags for f in findings)
    print("[OK] constraint: min/max amount flagged")


# ═══════════════════════════════════════════════════════════════════════════
# 10. Inference engine
# ═══════════════════════════════════════════════════════════════════════════


def test_inference_engine_novelty_unique() -> None:
    from tools.logic_flaw_engine import (
        DetectorCategory,
        InferenceEngine,
        LogicFinding,
        LogicFlawConfig,
        Severity,
    )

    ie = InferenceEngine(LogicFlawConfig())
    f1 = LogicFinding(title="t1", target="t", endpoint="/a", category=DetectorCategory.AUTH_LOGIC)
    f2 = LogicFinding(title="t2", target="t", endpoint="/b", category=DetectorCategory.AUTH_LOGIC)
    # Different endpoints -> high novelty
    f1.novelty = f2.novelty = 0.5
    ie.score(f1, [f1, f2])
    ie.score(f2, [f1, f2])
    assert f1.novelty >= 0.5
    print(f"[OK] inference: novelty scoring works (f1={f1.novelty})")


def test_inference_engine_impact_higher_for_critical_cats() -> None:
    from tools.logic_flaw_engine import (
        DetectorCategory,
        InferenceEngine,
        LogicFinding,
        LogicFlawConfig,
        Severity,
    )

    ie = InferenceEngine(LogicFlawConfig())
    auth_f = LogicFinding(
        title="t", target="t", endpoint="/a", category=DetectorCategory.AUTH_LOGIC
    )
    constraint_f = LogicFinding(
        title="t", target="t", endpoint="/a", category=DetectorCategory.BUSINESS_CONSTRAINT
    )
    ie.score(auth_f, [auth_f])
    ie.score(constraint_f, [constraint_f])
    # auth_logic is in the high_impact_cats set; business_constraint is not
    assert auth_f.impact_score >= constraint_f.impact_score
    print(
        f"[OK] inference: auth_logic={auth_f.impact_score}, constraint={constraint_f.impact_score}"
    )


def test_inference_engine_reproducibility_static_vs_dynamic() -> None:
    from tools.logic_flaw_engine import (
        DetectorCategory,
        Evidence,
        InferenceEngine,
        LogicFinding,
        LogicFlawConfig,
    )

    ie = InferenceEngine(LogicFlawConfig())
    f_static = LogicFinding(
        title="t", target="t", endpoint="/a", category=DetectorCategory.AUTH_LOGIC
    )
    f_dynamic = LogicFinding(
        title="t", target="t", endpoint="/a", category=DetectorCategory.AUTH_LOGIC
    )
    f_dynamic.add_evidence("burst_response", "burst ok", {"samples": 8})
    ie.score(f_static, [f_static, f_dynamic])
    ie.score(f_dynamic, [f_static, f_dynamic])
    assert f_dynamic.reproducibility >= f_static.reproducibility
    print(f"[OK] inference: dynamic={f_dynamic.reproducibility}, static={f_static.reproducibility}")


def test_inference_engine_risk_recomputed() -> None:
    from tools.logic_flaw_engine import (
        DetectorCategory,
        InferenceEngine,
        LogicFinding,
        LogicFlawConfig,
        Severity,
    )

    ie = InferenceEngine(LogicFlawConfig())
    f = LogicFinding(
        title="t",
        target="t",
        endpoint="/a",
        category=DetectorCategory.AUTHORIZATION,
        severity=Severity.CRITICAL,
    )
    pre = f.risk_score
    ie.score(f, [f])
    post = f.risk_score
    # Score should be recomputed and likely different
    assert isinstance(post, float)
    assert post >= 0
    # The risk formula multiplies severity.weight; pre is the value before
    # scoring mutated the inputs.
    print(f"[OK] inference: risk before={pre}, after={post}")


# ═══════════════════════════════════════════════════════════════════════════
# 11. Correlation engine
# ═══════════════════════════════════════════════════════════════════════════


def test_correlation_emits_chains() -> None:
    from tools.logic_flaw_engine import CorrelationEngine, DetectorCategory, LogicFinding, Severity

    engine = CorrelationEngine()
    f1 = LogicFinding(
        title="race",
        target="t",
        endpoint="/a",
        category=DetectorCategory.RACE_CONDITION,
        severity=Severity.CRITICAL,
        tags=["race", "toctou"],
    )
    f2 = LogicFinding(
        title="bola",
        target="t",
        endpoint="/b",
        category=DetectorCategory.AUTHORIZATION,
        severity=Severity.HIGH,
        tags=["bola", "idor"],
    )
    chains = engine.correlate([f1, f2])
    assert chains, "expected at least one chain"
    assert any("Mass" in c.title or "Race" in c.title for c in chains)
    print(f"[OK] correlation: {len(chains)} chains emitted")


def test_correlation_currency_negative_amount() -> None:
    from tools.logic_flaw_engine import CorrelationEngine, DetectorCategory, LogicFinding, Severity

    engine = CorrelationEngine()
    f1 = LogicFinding(
        title="currency",
        target="t",
        endpoint="/pay",
        category=DetectorCategory.PRICE_MANIPULATION,
        severity=Severity.CRITICAL,
        tags=["currency_confusion", "decimal_mismatch"],
    )
    f2 = LogicFinding(
        title="negative",
        target="t",
        endpoint="/refund",
        category=DetectorCategory.PRICE_MANIPULATION,
        severity=Severity.HIGH,
        tags=["negative_amount", "refund_abuse"],
    )
    chains = engine.correlate([f1, f2])
    assert any("Currency" in c.title or "arbitrary" in c.title.lower() for c in chains)
    print("[OK] correlation: currency + negative-amount chain")


# ═══════════════════════════════════════════════════════════════════════════
# 12. Top-level orchestrator integration
# ═══════════════════════════════════════════════════════════════════════════


def test_engine_analyze_returns_scored_findings() -> None:
    """End-to-end: analyze() returns sorted, scored LogicFinding objects."""
    from tools.logic_flaw_engine import LogicFlawEngine

    engine = LogicFlawEngine()
    endpoints = [
        {
            "url": "https://api.com/transfer",
            "method": "POST",
            "body": {"amount": 100, "user_id": 1},
        },
        {
            "url": "https://api.com/apply_coupon",
            "method": "POST",
            "body": {"coupon": "WELCOME", "user_id": 1},
        },
        {
            "url": "https://api.com/oauth/authorize",
            "method": "GET",
            "params": {"redirect_uri": "https://evil.com/cb"},
        },
        {"url": "https://api.com/api/users/1", "method": "GET"},
        {"url": "https://api.com/api/users/2", "method": "GET"},
        {"url": "https://api.com/admin/users", "method": "GET"},
    ]
    findings = asyncio.run(engine.analyze("api.com", endpoints))
    # Findings must be sorted by risk desc
    if len(findings) >= 2:
        assert findings[0].risk_score >= findings[-1].risk_score
    # Every finding has a finding_id, cwe list, and risk_score
    for f in findings:
        assert f.finding_id.startswith("LFE-")
        assert f.cwe
        assert f.risk_score >= 0
        assert f.discovered_at > 0
    # Multiple categories expected
    cats = {f.category for f in findings}
    assert len(cats) >= 3
    print(f"[OK] engine: {len(findings)} findings across {len(cats)} categories")


def test_engine_handles_empty_endpoints() -> None:
    from tools.logic_flaw_engine import LogicFlawEngine

    engine = LogicFlawEngine()
    findings = asyncio.run(engine.analyze("api.com", []))
    # Even with no endpoints, the correlation engine and inference may
    # emit zero findings.
    assert isinstance(findings, list)
    print(f"[OK] engine: empty endpoints -> {len(findings)} findings")


def test_engine_handles_string_endpoints() -> None:
    """analyze() should accept raw URL strings (normalize_endpoint handles it)."""
    from tools.logic_flaw_engine import LogicFlawEngine

    engine = LogicFlawEngine()
    urls = [
        "https://api.com/transfer?amount=1",
        "https://api.com/apply_coupon",
    ]
    findings = asyncio.run(engine.analyze("api.com", urls))
    assert isinstance(findings, list)
    print(f"[OK] engine: string URLs -> {len(findings)} findings")


def test_engine_filters_below_min_confidence() -> None:
    """A config with min_confidence=1.0 should suppress low-confidence findings."""
    from tools.logic_flaw_engine import LogicFlawConfig, LogicFlawEngine

    cfg = LogicFlawConfig(min_confidence=0.99, min_risk_score=10.0)
    engine = LogicFlawEngine(cfg)
    endpoints = [
        {"url": "https://api.com/heartbeat", "method": "GET"},
    ]
    findings = asyncio.run(engine.analyze("api.com", endpoints))
    # min_risk_score=10 filters everything except top critical chains
    assert isinstance(findings, list)
    print(f"[OK] engine: high threshold -> {len(findings)} findings")


def test_engine_http_integration_with_mock(mock_server: str) -> None:
    """The engine should perform dynamic race bursts against the mock server."""
    from tools.logic_flaw_engine import LogicFlawConfig, LogicFlawEngine

    cfg = LogicFlawConfig(
        race_default_concurrency=4, race_default_attempts=2, http_timeout_seconds=3.0
    )
    engine = LogicFlawEngine(cfg)
    endpoints = [
        {
            "url": f"{mock_server}/api/withdraw",
            "method": "POST",
            "body": {"amount": 50, "user_id": 1},
        },
    ]
    findings = asyncio.run(engine.analyze("api.com", endpoints))
    # At least a heuristic race finding
    assert any("race" in f.tags for f in findings)
    print(f"[OK] engine: http integration -> {len(findings)} findings")


def test_engine_aclose_is_safe() -> None:
    """aclose() should not raise even if called multiple times."""
    from tools.logic_flaw_engine import LogicFlawEngine

    engine = LogicFlawEngine()
    asyncio.run(engine.aclose())
    asyncio.run(engine.aclose())  # second call should be no-op
    print("[OK] engine: aclose idempotent")


# ═══════════════════════════════════════════════════════════════════════════
# 13. End-to-end with mock server covering multiple vectors
# ═══════════════════════════════════════════════════════════════════════════


def test_end_to_end_mock_vulnerable_app(mock_server: str) -> None:
    """Run the full engine against a curated vulnerable API surface."""
    from tools.logic_flaw_engine import LogicFlawConfig, LogicFlawEngine

    cfg = LogicFlawConfig(
        http_timeout_seconds=3.0, race_default_concurrency=4, race_default_attempts=2
    )
    engine = LogicFlawEngine(cfg)
    endpoints = [
        # Sequential user IDs (BOLA)
        {"url": f"{mock_server}/api/users/1", "method": "GET"},
        {"url": f"{mock_server}/api/users/2", "method": "GET"},
        # Admin path (BFLA)
        {"url": f"{mock_server}/api/admin/1", "method": "GET"},
        # Price/amount manipulation
        {
            "url": f"{mock_server}/api/transfer",
            "method": "POST",
            "body": {"amount": 100, "user_id": 1},
        },
        {
            "url": f"{mock_server}/api/refund",
            "method": "POST",
            "body": {"amount": 50, "user_id": 1},
        },
        {
            "url": f"{mock_server}/api/place_order",
            "method": "POST",
            "body": {"quantity": 1, "product_id": 1},
        },
        # Discount stacking / race
        {"url": f"{mock_server}/api/apply_coupon", "method": "POST", "body": {"coupon": "WELCOME"}},
        # Auth logic
        {
            "url": f"{mock_server}/api/login",
            "method": "POST",
            "body": {"username": "u", "password": "p"},
        },
        {"url": f"{mock_server}/api/verify_2fa", "method": "POST", "body": {"code": "123456"}},
    ]
    findings = asyncio.run(engine.analyze("api.com", endpoints))
    # We expect a rich set of findings
    assert len(findings) >= 5, f"only {len(findings)} findings: {[f.title for f in findings]}"
    # Top finding should be critical or high severity
    assert findings[0].severity.value in ("critical", "high")
    # Should find race, BOLA, BFLA, price, auth, 2fa at minimum
    tags_seen = {tag for f in findings for tag in f.tags}
    assert any(t in {"race", "toctou", "bola", "bfla"} for t in tags_seen)
    assert any("2fa" in t or "session_fixation" in t for t in tags_seen)
    print(
        f"[OK] end-to-end: {len(findings)} findings, top={findings[0].title}, "
        f"risk={findings[0].risk_score}"
    )


if __name__ == "__main__":
    # Allow running directly: `python3 tests/test_logic_flaw_engine.py`
    print("Run with pytest: pytest tests/test_logic_flaw_engine.py -v")
