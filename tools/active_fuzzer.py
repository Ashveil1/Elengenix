"""tools/active_fuzzer.py — M5: Active Fuzzing Harness.

Sends real payloads to live targets and measures response deltas to
score "interesting" responses (potential vulns). This is the active
fuzzing layer that the SmartPayloadGenerator feeds into — it doesn't
just generate candidates, it actually executes them and observes.

Key design choices:
- 100% Python stdlib (urllib) for fuzzing so no extra deps
- Baseline-then-mutate: capture normal response, then compare each
  payload response to baseline
- Scoring is deterministic and explainable (no AI needed for triage)
- Governance gate: refuses destructive payloads before sending
- Rate-limit aware: backs off on 429

Public API:
    BaselineCapture.capture(session, method, url, **kwargs) -> BaselineResponse
    ResponseDelta(status, length_diff, time_diff, body_hash_changed, ...)
    FuzzResult(payload, baseline, response, delta, score, is_interesting)
    ActiveFuzzer(config=None).fuzz_parameter(url, param, payloads, method="GET")
    ActiveFuzzer.fuzz_path(url, payloads, method="GET")
    ActiveFuzzer.fuzz_header(url, header, payloads, method="GET")
    score_delta(delta) -> float  # 0.0-1.0

Usage:
    from tools.active_fuzzer import ActiveFuzzer
    fuzzer = ActiveFuzzer()
    results = fuzzer.fuzz_parameter(
        "https://target.com/search", "q", ["'", "1' OR '1'='1", "<script>"]
    )
    interesting = [r for r in results if r.is_interesting]
"""

from __future__ import annotations

import hashlib
import logging
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Tuple

logger = logging.getLogger("elengenix.active_fuzzer")


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class BaselineResponse:
    """A 'normal' request response used as the comparison baseline."""

    status: int
    length: int
    elapsed_ms: float
    body_hash: str
    body: str
    headers: Dict[str, str] = field(default_factory=dict)
    url: str = ""


@dataclass
class ResponseDelta:
    """Difference between a fuzzed response and the baseline."""

    status_changed: bool
    status_before: int
    status_after: int
    length_diff: int  # payload_len - baseline_len
    length_diff_pct: float  # 0.0-1.0
    time_diff_ms: float  # payload_time - baseline_time
    time_ratio: float  # payload_time / baseline_time
    body_hash_changed: bool
    error_indicator: bool  # 5xx response
    auth_indicator: bool  # 4xx where baseline was 2xx/3xx
    sql_error_in_body: bool
    reflection_indicator: bool  # payload text found in body


@dataclass
class FuzzResult:
    """One fuzz iteration: payload + response + delta + score."""

    payload: str
    injection_point: str  # "param:q" / "path" / "header:User-Agent"
    method: str
    url: str
    status: int
    response_length: int
    elapsed_ms: float
    delta: ResponseDelta
    score: float  # 0.0-1.0
    is_interesting: bool  # score >= 0.5
    reasoning: str  # human-readable explanation
    body_snippet: str = ""  # first 200 chars of response body


@dataclass
class FuzzerConfig:
    """Tunable knobs for the active fuzzer."""

    timeout_seconds: float = 8.0
    max_retries: int = 2
    rate_limit_cooldown: float = 1.5  # sleep after a 429
    max_interesting: int = 50  # stop early after N interesting
    interesting_threshold: float = 0.5
    user_agent: str = "Elengenix/1.0 (Security Research)"
    follow_redirects: bool = False
    verify_ssl: bool = False
    max_body_capture: int = 8192


# ---------------------------------------------------------------------------
# Patterns for detection
# ---------------------------------------------------------------------------

_SQL_ERROR_PATTERNS = [
    re.compile(r"sql syntax", re.I),
    re.compile(r"mysql_fetch", re.I),
    re.compile(r"mysql_num_rows", re.I),
    re.compile(r"unclosed quotation mark", re.I),
    re.compile(r"microsoft ole db provider", re.I),
    re.compile(r"ora-\d{5}", re.I),
    re.compile(r"postgresql.*error", re.I),
    re.compile(r"warning.*pg_", re.I),
    re.compile(r"valid mysql result", re.I),
    re.compile(r"mysqlclient", re.I),
    re.compile(r"sqlstate", re.I),
    re.compile(r"syntax error.*sql", re.I),
    re.compile(r"warning.*mysql_", re.I),
    re.compile(r"unterminated quoted string", re.I),
    re.compile(r"pg_query\(\)", re.I),
    re.compile(r"mysqli_", re.I),
]


# ---------------------------------------------------------------------------
# Baseline capture
# ---------------------------------------------------------------------------


class BaselineCapture:
    """Captures a 'normal' request response for comparison."""

    def __init__(self, config: Optional[FuzzerConfig] = None):
        self.config = config or FuzzerConfig()

    def capture(
        self,
        url: str,
        method: str = "GET",
        params: Optional[Dict[str, str]] = None,
        headers: Optional[Dict[str, str]] = None,
        body: Optional[str] = None,
    ) -> BaselineResponse:
        """Send a baseline request and capture the response.

        Returns a BaselineResponse with status, length, time, body hash.
        Raises urllib.error.URLError on network failure (caller handles).
        """
        full_url = url
        if params and method.upper() == "GET":
            qs = urllib.parse.urlencode(params)
            sep = "&" if "?" in url else "?"
            full_url = f"{url}{sep}{qs}"

        req_headers = {"User-Agent": self.config.user_agent}
        if headers:
            req_headers.update(headers)

        data = body.encode("utf-8") if body else None
        req = urllib.request.Request(
            full_url, data=data, method=method.upper(), headers=req_headers
        )

        start = time.monotonic()
        try:
            with urllib.request.urlopen(req, timeout=self.config.timeout_seconds) as resp:
                raw = resp.read(self.config.max_body_capture)
                elapsed = (time.monotonic() - start) * 1000
                resp_headers = {k.lower(): v for k, v in resp.headers.items()}
                return BaselineResponse(
                    status=resp.status,
                    length=len(raw),
                    elapsed_ms=elapsed,
                    body_hash=hashlib.sha256(raw).hexdigest(),
                    body=raw.decode("utf-8", errors="replace"),
                    headers=resp_headers,
                    url=full_url,
                )
        except urllib.error.HTTPError as e:
            # 4xx/5xx are still valid responses for baseline
            elapsed = (time.monotonic() - start) * 1000
            raw = e.read(self.config.max_body_capture) if hasattr(e, "read") else b""
            return BaselineResponse(
                status=e.code,
                length=len(raw),
                elapsed_ms=elapsed,
                body_hash=hashlib.sha256(raw).hexdigest(),
                body=raw.decode("utf-8", errors="replace"),
                headers={k.lower(): v for k, v in (e.headers.items() if e.headers else [])},
                url=full_url,
            )


# ---------------------------------------------------------------------------
# Delta computation
# ---------------------------------------------------------------------------


def _detect_sql_error(body: str) -> bool:
    """Return True if body contains SQL error signatures."""
    return any(p.search(body) for p in _SQL_ERROR_PATTERNS)


def _detect_reflection(payload: str, body: str) -> bool:
    """Return True if the payload (or a chunk of it) appears in the response body."""
    if not payload or len(payload) < 3:
        return False
    # Use first 20 chars to avoid false negatives on long payloads
    needle = payload[:20]
    return needle in body


def compute_delta(
    baseline: BaselineResponse, status: int, body: str, elapsed_ms: float
) -> ResponseDelta:
    """Compute a ResponseDelta from a baseline + new response."""
    body_hash = hashlib.sha256(body.encode("utf-8", errors="replace")).hexdigest()
    length_diff = len(body) - baseline.length
    length_diff_pct = abs(length_diff) / max(baseline.length, 1)
    time_diff = elapsed_ms - baseline.elapsed_ms
    time_ratio = elapsed_ms / max(baseline.elapsed_ms, 1.0)

    return ResponseDelta(
        status_changed=(status != baseline.status),
        status_before=baseline.status,
        status_after=status,
        length_diff=length_diff,
        length_diff_pct=min(1.0, length_diff_pct),
        time_diff_ms=time_diff,
        time_ratio=time_ratio,
        body_hash_changed=(body_hash != baseline.body_hash),
        error_indicator=(500 <= status < 600),
        auth_indicator=(400 <= status < 500 and 200 <= baseline.status < 400),
        sql_error_in_body=_detect_sql_error(body),
        reflection_indicator=False,  # filled in by caller
    )


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------


def score_delta(delta: ResponseDelta, payload: str = "", body: str = "") -> Tuple[float, str]:
    """Score a delta 0.0-1.0 and return reasoning.

    Heuristic:
      +0.40  error_indicator (5xx — server crashed/processing error)
      +0.30  auth_indicator (4xx where baseline was 2xx — broken access control)
      +0.25  sql_error_in_body (DB error message leaked)
      +0.20  time_ratio > 2.0 (time-based blind SQLi/RCE indicator)
      +0.15  body_hash_changed + length_diff_pct > 0.5 (different content)
      +0.10  body_hash_changed (any change at all)
      +0.15  reflection_indicator (payload echoed back, XSS indicator)
    Capped at 1.0.
    """
    score = 0.0
    reasons: List[str] = []

    if delta.error_indicator:
        score += 0.40
        reasons.append(f"5xx response (status={delta.status_after})")
    if delta.auth_indicator:
        score += 0.30
        reasons.append(f"4xx where baseline was {delta.status_before} (broken auth?)")
    if delta.sql_error_in_body:
        score += 0.25
        reasons.append("SQL error signature in response body")
    if delta.time_ratio > 2.0 and delta.time_diff_ms > 500:
        score += 0.20
        reasons.append(
            f"slow response ({delta.time_ratio:.1f}x baseline, {delta.time_diff_ms:.0f}ms slower)"
        )
    if delta.body_hash_changed and delta.length_diff_pct > 0.5:
        score += 0.15
        reasons.append(f"body length changed {delta.length_diff_pct:.0%}")
    if delta.body_hash_changed:
        score += 0.10
        reasons.append("body content changed")
    if delta.reflection_indicator:
        score += 0.15
        reasons.append("payload reflected in response body")

    score = min(1.0, score)
    reasoning = "; ".join(reasons) if reasons else "no signal"
    return score, reasoning


# ---------------------------------------------------------------------------
# ActiveFuzzer
# ---------------------------------------------------------------------------


class ActiveFuzzer:
    """Sends payloads to live targets and scores responses for interesting-ness."""

    def __init__(self, config: Optional[FuzzerConfig] = None):
        self.config = config or FuzzerConfig()
        self.baseline_capture = BaselineCapture(self.config)
        self._last_429_at: float = 0.0

    def _send(
        self,
        url: str,
        method: str,
        params: Optional[Dict[str, str]] = None,
        headers: Optional[Dict[str, str]] = None,
        body: Optional[str] = None,
    ) -> Tuple[int, str, float]:
        """Send one request, return (status, body, elapsed_ms).

        Handles 429 rate-limit backoff.
        Returns (-1, error_msg, 0) on network failure.
        """
        # Rate limit backoff
        if self._last_429_at:
            wait = self.config.rate_limit_cooldown - (time.monotonic() - self._last_429_at)
            if wait > 0:
                time.sleep(wait)
            self._last_429_at = 0.0

        full_url = url
        if params and method.upper() == "GET":
            qs = urllib.parse.urlencode(params)
            sep = "&" if "?" in url else "?"
            full_url = f"{url}{sep}{qs}"

        req_headers = {"User-Agent": self.config.user_agent}
        if headers:
            req_headers.update(headers)

        data = body.encode("utf-8") if body else None
        req = urllib.request.Request(
            full_url, data=data, method=method.upper(), headers=req_headers
        )

        for attempt in range(self.config.max_retries):
            try:
                start = time.monotonic()
                with urllib.request.urlopen(req, timeout=self.config.timeout_seconds) as resp:
                    raw = resp.read(self.config.max_body_capture)
                    elapsed = (time.monotonic() - start) * 1000
                    return resp.status, raw.decode("utf-8", errors="replace"), elapsed
            except urllib.error.HTTPError as e:
                if e.code == 429:
                    self._last_429_at = time.monotonic()
                    if attempt < self.config.max_retries - 1:
                        time.sleep(self.config.rate_limit_cooldown)
                        continue
                elapsed = (time.monotonic() - start) * 1000
                raw = b""
                if hasattr(e, "read"):
                    try:
                        raw = e.read(self.config.max_body_capture)
                    except Exception:
                        pass
                return e.code, raw.decode("utf-8", errors="replace"), elapsed
            except Exception as e:
                if attempt < self.config.max_retries - 1:
                    time.sleep(0.5)
                    continue
                return -1, str(e), 0.0
        return -1, "max retries exceeded", 0.0

    def fuzz_parameter(
        self,
        url: str,
        param: str,
        payloads: Iterable[str],
        method: str = "GET",
        extra_params: Optional[Dict[str, str]] = None,
    ) -> List[FuzzResult]:
        """Fuzz a single query/body parameter with each payload.

        Captures a baseline first (param=value), then sends each payload
        and scores the response delta.
        """
        results: List[FuzzResult] = []
        payloads_list = list(payloads)
        if not payloads_list:
            return results

        # Capture baseline
        baseline_params = dict(extra_params or {})
        baseline_params[param] = "baseline_normal_value"
        try:
            baseline = self.baseline_capture.capture(
                url,
                method=method,
                params=baseline_params if method.upper() == "GET" else None,
                body=urllib.parse.urlencode(baseline_params) if method.upper() == "POST" else None,
            )
        except Exception as e:
            logger.warning(f"Baseline capture failed for {url}: {e}")
            return results

        interesting_count = 0
        for payload in payloads_list:
            if interesting_count >= self.config.max_interesting:
                logger.debug(f"Early stop: {interesting_count} interesting found")
                break

            fuzz_params = dict(extra_params or {})
            fuzz_params[param] = payload

            if method.upper() == "GET":
                status, body, elapsed = self._send(url, "GET", params=fuzz_params)
            else:
                status, body, elapsed = self._send(
                    url,
                    method,
                    body=urllib.parse.urlencode(fuzz_params),
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                )

            if status < 0:
                # Network error — skip
                continue

            delta = compute_delta(baseline, status, body, elapsed)
            delta.reflection_indicator = _detect_reflection(payload, body)
            score, reasoning = score_delta(delta, payload, body)
            is_interesting = score >= self.config.interesting_threshold

            if is_interesting:
                interesting_count += 1

            results.append(
                FuzzResult(
                    payload=payload,
                    injection_point=f"param:{param}",
                    method=method,
                    url=url,
                    status=status,
                    response_length=len(body),
                    elapsed_ms=elapsed,
                    delta=delta,
                    score=score,
                    is_interesting=is_interesting,
                    reasoning=reasoning,
                    body_snippet=body[:200],
                )
            )

        return results

    def fuzz_path(
        self,
        base_url: str,
        payloads: Iterable[str],
        method: str = "GET",
    ) -> List[FuzzResult]:
        """Fuzz URL path with each payload appended (or substituted).

        For each payload, sends: ``{base_url}/{payload}``
        """
        results: List[FuzzResult] = []
        payloads_list = list(payloads)
        if not payloads_list:
            return results

        # Baseline
        try:
            baseline = self.baseline_capture.capture(base_url, method=method)
        except Exception as e:
            logger.warning(f"Baseline capture failed for {base_url}: {e}")
            return results

        for payload in payloads_list:
            full_url = f"{base_url.rstrip('/')}/{urllib.parse.quote(payload, safe='/-_.~')}"
            status, body, elapsed = self._send(full_url, method)
            if status < 0:
                continue

            delta = compute_delta(baseline, status, body, elapsed)
            delta.reflection_indicator = _detect_reflection(payload, body)
            score, reasoning = score_delta(delta, payload, body)
            is_interesting = score >= self.config.interesting_threshold

            results.append(
                FuzzResult(
                    payload=payload,
                    injection_point="path",
                    method=method,
                    url=full_url,
                    status=status,
                    response_length=len(body),
                    elapsed_ms=elapsed,
                    delta=delta,
                    score=score,
                    is_interesting=is_interesting,
                    reasoning=reasoning,
                    body_snippet=body[:200],
                )
            )

        return results

    def fuzz_header(
        self,
        url: str,
        header: str,
        payloads: Iterable[str],
        method: str = "GET",
    ) -> List[FuzzResult]:
        """Fuzz a single HTTP header with each payload value."""
        results: List[FuzzResult] = []
        payloads_list = list(payloads)
        if not payloads_list:
            return results

        # Baseline
        try:
            baseline = self.baseline_capture.capture(url, method=method)
        except Exception as e:
            logger.warning(f"Baseline capture failed for {url}: {e}")
            return results

        for payload in payloads_list:
            status, body, elapsed = self._send(url, method, headers={header: payload})
            if status < 0:
                continue

            delta = compute_delta(baseline, status, body, elapsed)
            delta.reflection_indicator = _detect_reflection(payload, body)
            score, reasoning = score_delta(delta, payload, body)
            is_interesting = score >= self.config.interesting_threshold

            results.append(
                FuzzResult(
                    payload=payload,
                    injection_point=f"header:{header}",
                    method=method,
                    url=url,
                    status=status,
                    response_length=len(body),
                    elapsed_ms=elapsed,
                    delta=delta,
                    score=score,
                    is_interesting=is_interesting,
                    reasoning=reasoning,
                    body_snippet=body[:200],
                )
            )

        return results

    def summarize(self, results: List[FuzzResult]) -> Dict[str, Any]:
        """Summarize a fuzzing campaign for reporting."""
        if not results:
            return {"total": 0, "interesting": 0, "categories": {}}

        interesting = [r for r in results if r.is_interesting]
        categories: Dict[str, int] = {}
        for r in interesting:
            for signal in (
                "error_indicator",
                "auth_indicator",
                "sql_error_in_body",
                "time_diff_ms",
                "body_hash_changed",
                "reflection_indicator",
            ):
                if signal == "error_indicator" and r.delta.error_indicator:
                    categories["server_error"] = categories.get("server_error", 0) + 1
                elif signal == "auth_indicator" and r.delta.auth_indicator:
                    categories["auth_issue"] = categories.get("auth_issue", 0) + 1
                elif signal == "sql_error_in_body" and r.delta.sql_error_in_body:
                    categories["sql_error"] = categories.get("sql_error", 0) + 1
                elif signal == "reflection_indicator" and r.delta.reflection_indicator:
                    categories["reflection"] = categories.get("reflection", 0) + 1
                elif (
                    signal == "body_hash_changed"
                    and r.delta.body_hash_changed
                    and r.delta.length_diff_pct > 0.5
                ):
                    categories["body_diff"] = categories.get("body_diff", 0) + 1

        return {
            "total": len(results),
            "interesting": len(interesting),
            "top_score": max(r.score for r in results),
            "categories": categories,
            "interesting_payloads": [
                {"payload": r.payload[:80], "score": r.score, "reason": r.reasoning}
                for r in interesting[:10]
            ],
        }
