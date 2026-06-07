"""tests/test_active_fuzzer.py — M5 verification tests.

Verifies ActiveFuzzer can:
  1. Capture baseline
  2. Send payloads to a mock server
  3. Score responses correctly (5xx = high, 4xx-where-baseline-was-2xx = high)
  4. Detect SQL error in body
  5. Detect reflection
  6. Back off on 429
  7. Summarize results
  8. Generate realistic timing deltas (time-based blind detection)
"""
from __future__ import annotations

import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


# ── Mock server that returns different responses based on payload ──

class MockVulnServer(BaseHTTPRequestHandler):
    """Mock server with multiple vuln scenarios.

    Endpoints:
      /normal            — always 200 with stable body
      /sqli              — returns 500 + SQL error if payload contains '
      /reflect           — echoes payload in body
      /timeblind         — sleeps 2s if payload contains SLEEP
      /auth              — 200 if no payload, 403 if payload contains 'admin'
      /ratelimit         — 429 if User-Agent is "tester"
    """
    SLEEP_TRIGGER = "SLEEP"

    def do_GET(self):
        path, _, query = self.path.partition("?")
        from urllib.parse import parse_qs
        params = parse_qs(query)
        payload = params.get("q", [""])[0]
        ua = self.headers.get("User-Agent", "")

        if path == "/normal":
            self._respond(200, "OK normal response body")
        elif path == "/sqli":
            if "'" in payload:
                self._respond(500, "You have an error in your SQL syntax near '...' at line 1")
            else:
                self._respond(200, "no results")
        elif path == "/reflect":
            self._respond(200, f"you searched for: {payload}")
        elif path == "/timeblind":
            if self.SLEEP_TRIGGER in payload:
                time.sleep(2.0)
            self._respond(200, "ok")
        elif path == "/auth":
            if "admin" in payload:
                self._respond(403, "Forbidden")
            else:
                self._respond(200, "welcome")
        elif path == "/ratelimit":
            if ua == "tester":
                self._respond(429, "Too Many Requests")
            else:
                self._respond(200, "ok")
        else:
            self._respond(404, "not found")

    def _respond(self, status, body):
        self.send_response(status)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body.encode())

    def log_message(self, *args):
        pass


@pytest.fixture(scope="module")
def mock_server():
    server = HTTPServer(("127.0.0.1", 18800), MockVulnServer)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    time.sleep(0.3)
    yield "http://127.0.0.1:18800"
    server.shutdown()


# ── Tests ──

def test_baseline_capture(mock_server):
    from tools.active_fuzzer import BaselineCapture
    cap = BaselineCapture()
    bl = cap.capture(f"{mock_server}/normal")
    assert bl.status == 200
    assert "OK normal" in bl.body
    assert bl.length > 0
    assert bl.body_hash
    print(f"[BASELINE] status={bl.status} len={bl.length} time={bl.elapsed_ms:.1f}ms hash={bl.body_hash[:12]}")


def test_active_fuzzer_detects_5xx_error(mock_server):
    """5xx response to a payload should score as interesting."""
    from tools.active_fuzzer import ActiveFuzzer, FuzzerConfig
    fuzzer = ActiveFuzzer(FuzzerConfig(timeout_seconds=5, interesting_threshold=0.3))
    results = fuzzer.fuzz_parameter(
        f"{mock_server}/sqli", "q", ["normal", "admin' OR '1'='1", "x'y"]
    )
    assert len(results) == 3
    sqli_results = [r for r in results if r.is_interesting]
    assert len(sqli_results) >= 1, f"Expected at least 1 interesting, got {len(sqli_results)}"
    top = max(results, key=lambda r: r.score)
    assert "5xx" in top.reasoning or "sql" in top.reasoning.lower()
    print(f"[5xx] top: payload='{top.payload[:30]}' score={top.score} reason='{top.reasoning}'")


def test_active_fuzzer_detects_sql_error_signature(mock_server):
    """SQL error pattern in body should bump score."""
    from tools.active_fuzzer import ActiveFuzzer
    fuzzer = ActiveFuzzer()
    results = fuzzer.fuzz_parameter(
        f"{mock_server}/sqli", "q", ["'", "x", "y"]
    )
    sql_err_results = [r for r in results if r.delta.sql_error_in_body]
    assert len(sql_err_results) >= 1, f"Expected SQL error detection, got {len(sql_err_results)}"
    top = sql_err_results[0]
    assert top.delta.sql_error_in_body
    assert top.score > 0.0
    print(f"[SQL] detected error, score={top.score}")


def test_active_fuzzer_detects_reflection(mock_server):
    """Payload echoed in response should be marked as reflected."""
    from tools.active_fuzzer import ActiveFuzzer
    fuzzer = ActiveFuzzer()
    results = fuzzer.fuzz_parameter(
        f"{mock_server}/reflect", "q", ["hello world", "<script>alert(1)</script>", "test"]
    )
    reflected = [r for r in results if r.delta.reflection_indicator]
    assert len(reflected) >= 2, f"Expected reflection on 2+ payloads, got {len(reflected)}"
    print(f"[REFLECT] detected {len(reflected)}/{len(results)} reflections")


def test_active_fuzzer_detects_auth_bypass(mock_server):
    """4xx where baseline was 2xx = broken access control indicator."""
    from tools.active_fuzzer import ActiveFuzzer
    fuzzer = ActiveFuzzer()
    results = fuzzer.fuzz_parameter(
        f"{mock_server}/auth", "q", ["user1", "admin", "admin' OR 1=1--"]
    )
    auth_results = [r for r in results if r.delta.auth_indicator]
    assert len(auth_results) >= 1, f"Expected auth indicator, got {len(auth_results)}"
    top = auth_results[0]
    assert top.score > 0.0
    print(f"[AUTH] detected 4xx on baseline 2xx, score={top.score}, payload='{top.payload}'")


def test_active_fuzzer_detects_time_based(mock_server):
    """Slow response (>2x baseline, >500ms slower) should be flagged."""
    from tools.active_fuzzer import ActiveFuzzer
    fuzzer = ActiveFuzzer()
    results = fuzzer.fuzz_parameter(
        f"{mock_server}/timeblind", "q", ["normal", "1' AND SLEEP(2)--", "x"]
    )
    slow_results = [r for r in results if r.delta.time_ratio > 2.0 and r.delta.time_diff_ms > 500]
    assert len(slow_results) >= 1, f"Expected time-based detection, got {len(slow_results)}"
    top = slow_results[0]
    assert top.score > 0.0
    print(f"[TIME] detected slow response: ratio={top.delta.time_ratio:.1f}x, diff={top.delta.time_diff_ms:.0f}ms")


def test_active_fuzzer_handles_429_backoff(mock_server):
    """Rate-limited requests should trigger backoff (no crash)."""
    from tools.active_fuzzer import ActiveFuzzer
    fuzzer = ActiveFuzzer()
    # Override user agent to trigger 429
    fuzzer.config.user_agent = "tester"
    results = fuzzer.fuzz_parameter(
        f"{mock_server}/ratelimit", "q", ["a", "b", "c"]
    )
    # Should not crash; all should be 429
    assert all(r.status == 429 for r in results)
    print(f"[429] all {len(results)} requests returned 429, backoff handled")


def test_active_fuzzer_summary(mock_server):
    """Summary should aggregate findings by category."""
    from tools.active_fuzzer import ActiveFuzzer
    fuzzer = ActiveFuzzer()
    results = fuzzer.fuzz_parameter(
        f"{mock_server}/sqli", "q", ["normal", "x'y", "z'w"]
    )
    summary = fuzzer.summarize(results)
    assert "total" in summary
    assert "interesting" in summary
    assert "categories" in summary
    assert summary["total"] == 3
    print(f"[SUMMARY] {summary}")


def test_fuzz_path(mock_server):
    """Path fuzzing should send each payload as a path segment."""
    from tools.active_fuzzer import ActiveFuzzer
    fuzzer = ActiveFuzzer()
    results = fuzzer.fuzz_path(
        f"{mock_server}/normal", ["admin", "test", "<script>"]
    )
    assert len(results) == 3
    assert all(r.injection_point == "path" for r in results)
    print(f"[PATH] fuzzed {len(results)} paths, top score={max(r.score for r in results)}")


def test_fuzz_header(mock_server):
    """Header fuzzing should send each payload as header value."""
    from tools.active_fuzzer import ActiveFuzzer
    fuzzer = ActiveFuzzer()
    # Use the ratelimit endpoint to verify header reaches server
    results = fuzzer.fuzz_header(
        f"{mock_server}/ratelimit", "User-Agent", ["tester", "normal", "evil-bot"]
    )
    assert len(results) == 3
    assert all(r.injection_point.startswith("header:") for r in results)
    # 'tester' UA should trigger 429
    rate_limited = [r for r in results if r.status == 429]
    assert len(rate_limited) >= 1
    print(f"[HEADER] fuzzed User-Agent, {len(rate_limited)}/3 got 429")


def test_scoring_is_deterministic():
    """score_delta should give the same result for the same delta."""
    from tools.active_fuzzer import score_delta, ResponseDelta
    delta = ResponseDelta(
        status_changed=True, status_before=200, status_after=500,
        length_diff=50, length_diff_pct=0.1, time_diff_ms=100, time_ratio=1.5,
        body_hash_changed=True, error_indicator=True, auth_indicator=False,
        sql_error_in_body=False, reflection_indicator=False,
    )
    s1, r1 = score_delta(delta)
    s2, r2 = score_delta(delta)
    assert s1 == s2
    assert r1 == r2
    assert s1 > 0.4  # 5xx alone gives 0.4
    print(f"[SCORE] deterministic: score={s1}, reason='{r1}'")


def test_scoring_high_for_sql_error():
    """SQL error + 5xx = high score (>= 0.5)."""
    from tools.active_fuzzer import score_delta, ResponseDelta
    delta = ResponseDelta(
        status_changed=True, status_before=200, status_after=500,
        length_diff=200, length_diff_pct=0.8, time_diff_ms=200, time_ratio=1.5,
        body_hash_changed=True, error_indicator=True, auth_indicator=False,
        sql_error_in_body=True, reflection_indicator=False,
    )
    score, reasoning = score_delta(delta)
    assert score >= 0.5
    assert "SQL" in reasoning
    print(f"[SCORE-HIGH] score={score}, reason='{reasoning}'")
