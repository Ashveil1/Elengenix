"""tools/bola_tester.py — M8: BOLA / IDOR Tester.

Real request replay with two user sessions. Detects Broken Object
Level Authorization (BOLA/IDOR) by:
  1. Using session A to fetch a known object
  2. Using session B (different user) to fetch the same object ID
  3. If both return 200 with similar body size = BOLA (object-level
     authorization missing)

Unlike static analyzers that only flag endpoint patterns, this
actually replays the requests and measures the access delta.

Public API:
    Session  - one user session (cookies, headers, base URL)
    BOLATestResult - one BOLA test: status_A, status_B, body_diff, is_bola
    BOLATester:
        register_session(name, cookies, headers)
        test_object(url_template, object_id, session_a="user_a", session_b="user_b")
        test_endpoint_collection(endpoints, session_a, session_b) -> List[BOLATestResult]
"""

from __future__ import annotations

import hashlib
import logging
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("elengenix.bola_tester")


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class Session:
    """One user session (cookies, headers, base URL)."""

    name: str
    cookies: Dict[str, str] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)
    base_url: str = ""
    user_agent: str = "Elengenix-BOLA/1.0"

    def to_request_headers(self) -> Dict[str, str]:
        """Build headers for this session, including cookie string."""
        h = {"User-Agent": self.user_agent}
        h.update(self.headers)
        if self.cookies:
            cookie_str = "; ".join(f"{k}={v}" for k, v in self.cookies.items())
            h["Cookie"] = cookie_str
        return h


@dataclass
class BOLATestResult:
    """One BOLA test against one object."""

    url: str
    object_id: str
    session_a: str
    session_b: str
    status_a: int
    status_b: int
    body_size_a: int
    body_size_b: int
    body_hash_a: str
    body_hash_b: str
    is_bola: bool
    confidence: float  # 0.0-1.0
    severity: str  # "critical", "high", "medium", "low"
    reasoning: str
    body_a_snippet: str = ""
    body_b_snippet: str = ""


@dataclass
class BOLAConfig:
    """Tuning knobs for BOLA tester."""

    timeout_seconds: float = 8.0
    body_size_diff_threshold: int = 100  # bodies within this size = similar
    body_hash_match_threshold: float = 0.8  # hash similarity for "same"
    min_confidence_to_flag: float = 0.7
    sample_body_bytes: int = 4096


# ---------------------------------------------------------------------------
# BOLA tester
# ---------------------------------------------------------------------------


class BOLATester:
    """Tests for BOLA / IDOR by replaying requests with different sessions."""

    def __init__(self, config: Optional[BOLAConfig] = None):
        self.config = config or BOLAConfig()
        self.sessions: Dict[str, Session] = {}

    def register_session(
        self,
        name: str,
        cookies: Optional[Dict[str, str]] = None,
        headers: Optional[Dict[str, str]] = None,
        base_url: str = "",
    ) -> Session:
        """Register a user session for BOLA tests."""
        sess = Session(
            name=name,
            cookies=cookies or {},
            headers=headers or {},
            base_url=base_url,
        )
        self.sessions[name] = sess
        return sess

    def _send(self, url: str, session: Session) -> Tuple[int, str, float]:
        """Send a GET request as the given session.

        Returns (status, body, elapsed_ms). Returns (-1, error_msg, 0) on
        network failure.
        """
        req = urllib.request.Request(url, method="GET", headers=session.to_request_headers())
        start = time.monotonic()
        try:
            with urllib.request.urlopen(req, timeout=self.config.timeout_seconds) as resp:
                raw = resp.read(self.config.sample_body_bytes)
                elapsed = (time.monotonic() - start) * 1000
                return resp.status, raw.decode("utf-8", errors="replace"), elapsed
        except urllib.error.HTTPError as e:
            elapsed = (time.monotonic() - start) * 1000
            raw = b""
            if hasattr(e, "read"):
                try:
                    raw = e.read(self.config.sample_body_bytes)
                except Exception:
                    pass
            return e.code, raw.decode("utf-8", errors="replace"), elapsed
        except Exception as e:
            return -1, str(e), 0.0

    def _hash_body(self, body: str) -> str:
        return hashlib.sha256(body.encode("utf-8", errors="replace")).hexdigest()

    def test_object(
        self,
        url_template: str,
        object_id: str,
        session_a: str = "user_a",
        session_b: str = "user_b",
    ) -> BOLATestResult:
        """Test a single object ID with two sessions.

        Args:
            url_template: URL with {id} placeholder, e.g. "https://api.com/users/{id}"
            object_id: The object ID to test
            session_a: Name of the first session (usually victim)
            session_b: Name of the second session (usually attacker)
        """
        if session_a not in self.sessions:
            raise ValueError(f"Session '{session_a}' not registered")
        if session_b not in self.sessions:
            raise ValueError(f"Session '{session_b}' not registered")

        url = url_template.replace("{id}", str(object_id))
        sess_a = self.sessions[session_a]
        sess_b = self.sessions[session_b]

        status_a, body_a, _ = self._send(url, sess_a)
        status_b, body_b, _ = self._send(url, sess_b)

        is_bola, confidence, severity, reasoning = self._classify(
            status_a, status_b, body_a, body_b
        )

        return BOLATestResult(
            url=url,
            object_id=object_id,
            session_a=session_a,
            session_b=session_b,
            status_a=status_a,
            status_b=status_b,
            body_size_a=len(body_a),
            body_size_b=len(body_b),
            body_hash_a=self._hash_body(body_a),
            body_hash_b=self._hash_body(body_b),
            is_bola=is_bola,
            confidence=confidence,
            severity=severity,
            reasoning=reasoning,
            body_a_snippet=body_a[:200],
            body_b_snippet=body_b[:200],
        )

    def _classify(
        self,
        status_a: int,
        status_b: int,
        body_a: str,
        body_b: str,
    ) -> Tuple[bool, float, str, str]:
        """Classify whether the access pattern is a BOLA.

        Rules (ordered by severity):
          1. A=200, B=200, similar body -> CRITICAL BOLA (read access)
          2. A=200, B=403/401, A=403/401 -> broken authZ (B confirmed denied)
          3. A=404, B=200 -> ENUM BOLA (B can see hidden objects)
          4. A=200, B=200, very different body -> MEDIUM (partial access)
        """
        if status_a == -1 or status_b == -1:
            return False, 0.0, "low", "network error during test"

        # Rule 1: A=200, B=200, similar body = critical
        if status_a == 200 and status_b == 200:
            size_diff = abs(len(body_a) - len(body_b))
            same_hash = self._hash_body(body_a) == self._hash_body(body_b)
            if same_hash:
                return (
                    True,
                    0.99,
                    "critical",
                    f"B session got identical 200 response (size={len(body_a)}, hash matches A)",
                )
            elif size_diff <= self.config.body_size_diff_threshold:
                return (
                    True,
                    0.95,
                    "critical",
                    f"B session got 200 with body size diff {size_diff} bytes (within threshold)",
                )
            else:
                return (
                    True,
                    0.6,
                    "medium",
                    f"B session got 200 but body size differs by {size_diff} bytes (partial access?)",
                )

        # Rule 2: A=200, B=403/401 = properly authZ'd, no BOLA
        if status_a == 200 and status_b in (401, 403):
            return (
                False,
                0.0,
                "low",
                f"B session correctly denied ({status_b}) while A got 200 — authZ enforced",
            )

        # Rule 3: A=404, B=200 = enumeration BOLA
        if status_a == 404 and status_b == 200:
            return (
                True,
                0.9,
                "high",
                "B session got 200 for object A can't see (404) — enumeration + read BOLA",
            )

        # Rule 4: A=200, B=500 = server error on B's request
        if status_a == 200 and status_b == 500:
            return False, 0.3, "low", "B session caused 500 — possible authZ bypass attempt logged"

        # Default: inconclusive
        return False, 0.0, "low", f"A={status_a}, B={status_b} — no BOLA pattern detected"

    def test_endpoint_collection(
        self,
        endpoint_template: str,
        object_ids: List[str],
        session_a: str = "user_a",
        session_b: str = "user_b",
    ) -> List[BOLATestResult]:
        """Test a collection of object IDs against one endpoint.

        Useful for sweeping a range of IDs to find which ones are
        accessible to attacker session B.
        """
        results = []
        for oid in object_ids:
            try:
                result = self.test_object(endpoint_template, oid, session_a, session_b)
                results.append(result)
            except Exception as e:
                logger.debug(f"BOLA test failed for {oid}: {e}")
        return results

    def summarize(self, results: List[BOLATestResult]) -> Dict[str, Any]:
        """Summarize a BOLA test campaign."""
        if not results:
            return {"total": 0, "bola_found": 0}

        bola_results = [r for r in results if r.is_bola]
        by_severity: Dict[str, int] = {}
        for r in bola_results:
            by_severity[r.severity] = by_severity.get(r.severity, 0) + 1

        return {
            "total": len(results),
            "bola_found": len(bola_results),
            "bola_rate": round(len(bola_results) / len(results), 3),
            "by_severity": by_severity,
            "critical": [
                {
                    "url": r.url,
                    "object_id": r.object_id,
                    "status_a": r.status_a,
                    "status_b": r.status_b,
                    "body_match": r.body_hash_a == r.body_hash_b,
                    "reason": r.reasoning,
                }
                for r in bola_results
                if r.severity == "critical"
            ][:10],
        }
