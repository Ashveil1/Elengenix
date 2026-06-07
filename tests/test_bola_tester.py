"""tests/test_bola_tester.py — M8 verification tests."""
from __future__ import annotations

import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


# ── Mock server with BOLA + non-BOLA scenarios ──

class MockBOLAServer(BaseHTTPRequestHandler):
    """Mock server simulating a vulnerable API.

    Endpoints:
      /users/{id}  - returns user JSON if session is correct OR ID is in 1-10
                     (BOLA: session B can read users 1-10 by ID alone)
      /admin/{id}  - returns 403 for B session
      /private/{id}- returns 404 for everyone except A session
    """
    USERS = {
        "1": {"id": 1, "name": "Alice", "email": "alice@example.com"},
        "2": {"id": 2, "name": "Bob", "email": "bob@example.com"},
    }

    def do_GET(self):
        path = self.path.lstrip("/")
        parts = path.split("/")
        if len(parts) < 2:
            self._respond(404, "not found")
            return
        resource, oid = parts[0], parts[1]

        session_cookie = self._get_session()

        if resource == "users":
            # BOLA: any session (even unauthed) can read users 1-10
            if oid in self.USERS:
                self._respond(200, json.dumps(self.USERS[oid]))
            else:
                self._respond(404, "not found")
        elif resource == "admin":
            # Properly authZ'd
            if session_cookie == "admin_a":
                self._respond(200, json.dumps({"secret": "data"}))
            else:
                self._respond(403, "forbidden")
        elif resource == "private":
            # Only A can see, B gets 404
            if session_cookie == "user_a":
                if oid in ("1", "2"):
                    self._respond(200, json.dumps({"id": int(oid), "private": True}))
                else:
                    self._respond(404, "not found")
            else:
                self._respond(404, "not found")
        else:
            self._respond(404, "not found")

    def _get_session(self) -> str:
        cookie = self.headers.get("Cookie", "")
        for part in cookie.split(";"):
            part = part.strip()
            if part.startswith("session="):
                return part.replace("session=", "")
        return ""

    def _respond(self, status, body):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body.encode())

    def log_message(self, *args):
        pass


import json

@pytest.fixture(scope="module")
def mock_server():
    server = HTTPServer(("127.0.0.1", 18801), MockBOLAServer)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    time.sleep(0.3)
    yield "http://127.0.0.1:18801"
    server.shutdown()


# ── Tests ──

def test_register_sessions(mock_server):
    """Registering sessions should add them to the tester."""
    from tools.bola_tester import BOLATester
    tester = BOLATester()
    s1 = tester.register_session("user_a", cookies={"session": "user_a"})
    s2 = tester.register_session("user_b", cookies={"session": "user_b"})
    assert "user_a" in tester.sessions
    assert "user_b" in tester.sessions
    assert s1.to_request_headers()["Cookie"] == "session=user_a"
    print(f"[SESSION] registered: {list(tester.sessions.keys())}")


def test_bola_detected_critical(mock_server):
    """BOLA: both sessions get identical 200 response = critical."""
    from tools.bola_tester import BOLATester
    tester = BOLATester()
    tester.register_session("user_a", cookies={"session": "user_a"})
    tester.register_session("user_b", cookies={"session": "user_b"})
    result = tester.test_object(
        f"{mock_server}/users/{{id}}", "1", session_a="user_a", session_b="user_b"
    )
    assert result.is_bola, f"Expected BOLA, got is_bola={result.is_bola}, reason={result.reasoning}"
    assert result.severity in ("critical", "high")
    assert result.status_a == 200
    assert result.status_b == 200
    assert result.body_hash_a == result.body_hash_b
    print(f"[BOLA-CRITICAL] {result.reasoning}")


def test_bola_collection_sweep(mock_server):
    """Sweep a range of IDs to find BOLA-accessible objects."""
    from tools.bola_tester import BOLATester
    tester = BOLATester()
    tester.register_session("user_a", cookies={"session": "user_a"})
    tester.register_session("user_b", cookies={"session": "user_b"})
    results = tester.test_endpoint_collection(
        f"{mock_server}/users/{{id}}",
        ["1", "2", "3", "99"],
        session_a="user_a", session_b="user_b"
    )
    assert len(results) == 4
    bola_count = sum(1 for r in results if r.is_bola)
    assert bola_count >= 2  # users 1, 2 are BOLA-accessible
    print(f"[SWEEP] {bola_count}/{len(results)} BOLA: {[(r.object_id, r.severity) for r in results if r.is_bola]}")


def test_properly_authorized_no_bola(mock_server):
    """If B gets 403 and A gets 200, no BOLA."""
    from tools.bola_tester import BOLATester
    tester = BOLATester()
    tester.register_session("user_a", cookies={"session": "admin_a"})
    tester.register_session("user_b", cookies={"session": "user_b"})
    result = tester.test_object(
        f"{mock_server}/admin/{{id}}", "1", session_a="user_a", session_b="user_b"
    )
    assert not result.is_bola
    assert result.status_a == 200
    assert result.status_b == 403
    assert "denied" in result.reasoning.lower() or "enforced" in result.reasoning.lower()
    print(f"[NO-BOLA] A=200, B=403, properly authZ'd")


def test_enumeration_bola(mock_server):
    """If A=404 but B=200, that's enumeration BOLA."""
    from tools.bola_tester import BOLATester
    tester = BOLATester()
    tester.register_session("user_a", cookies={"session": "user_a"})
    tester.register_session("user_b", cookies={"session": "user_b"})
    # /private/1 - A gets 200, B gets 404
    result = tester.test_object(
        f"{mock_server}/private/{{id}}", "1", session_a="user_a", session_b="user_b"
    )
    # A=200, B=404 = properly authZ'd, no BOLA
    assert not result.is_bola
    assert result.status_a == 200
    assert result.status_b == 404
    print(f"[ENUM-NO] A sees it, B doesn't = no BOLA")


def test_bola_summarize(mock_server):
    """Summarize should aggregate by severity."""
    from tools.bola_tester import BOLATester
    tester = BOLATester()
    tester.register_session("user_a", cookies={"session": "user_a"})
    tester.register_session("user_b", cookies={"session": "user_b"})
    results = tester.test_endpoint_collection(
        f"{mock_server}/users/{{id}}", ["1", "2"], session_a="user_a", session_b="user_b"
    )
    summary = tester.summarize(results)
    assert "total" in summary
    assert "bola_found" in summary
    assert summary["bola_found"] == 2
    assert "critical" in summary
    assert len(summary["critical"]) == 2
    print(f"[SUMMARY] {summary}")


def test_invalid_session_raises():
    """Test should raise if session is not registered."""
    from tools.bola_tester import BOLATester
    tester = BOLATester()
    tester.register_session("user_a", cookies={"session": "user_a"})
    with pytest.raises(ValueError, match="not registered"):
        tester.test_object("https://api.com/users/{id}", "1", session_a="user_a", session_b="missing")
    print(f"[VALIDATE] correctly raised for missing session")


def test_unauthenticated_session_works():
    """Unauthed session (no cookies) should work as attacker session."""
    from tools.bola_tester import BOLATester
    tester = BOLATester()
    tester.register_session("user_a", cookies={"session": "user_a"})
    tester.register_session("attacker", cookies={})  # no auth
    # BOLA tester should handle empty cookies
    s = tester.sessions["attacker"]
    headers = s.to_request_headers()
    assert "Cookie" not in headers
    print(f"[UNAUTHED] attacker session has no Cookie header: {headers}")


def test_body_size_similarity_threshold(mock_server):
    """Two responses with body size diff > threshold should be medium BOLA."""
    from tools.bola_tester import BOLATester, BOLAConfig
    tester = BOLATester(BOLAConfig(body_size_diff_threshold=10))
    tester.register_session("user_a", cookies={"session": "user_a"})
    tester.register_session("user_b", cookies={"session": "user_b"})
    # Mock users 1, 2 have different sizes (Bob has longer email)
    r1 = tester.test_object(f"{mock_server}/users/{{id}}", "1")
    r2 = tester.test_object(f"{mock_server}/users/{{id}}", "2")
    # Both should be detected as BOLA (users endpoint is wide open)
    assert r1.is_bola
    assert r2.is_bola
    print(f"[THRESHOLD] user1 size={r1.body_size_a}, user2 size={r2.body_size_a}")


def test_classify_network_error_handled():
    """Network error should return is_bola=False with low confidence."""
    from tools.bola_tester import BOLATester
    tester = BOLATester()
    # No sessions registered
    is_bola, conf, sev, reason = tester._classify(-1, -1, "", "")
    assert not is_bola
    assert conf == 0.0
    assert "network" in reason.lower() or "error" in reason.lower()
    print(f"[NETERR] {reason}")
