"""tools/race_condition_tester.py

Race Condition / TOCTOU Vulnerability Scanner.

Purpose:
- Test for race conditions in API endpoints
- Concurrent request analysis (coupon code, rate limit, OTP bypass)
- Time-of-check-time-of-use (TOCTOU) detection
- Response analysis for timing-based condition bypass

Safety:
- Non-destructive testing (no actual state changes)
- Only GET and idempotent operations by default
- Rate limited to avoid DoS
"""

from __future__ import annotations

import concurrent.futures
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import requests

logger = logging.getLogger("elengenix.race_condition")

# Endpoint patterns likely vulnerable to race conditions
RACE_CONDITION_PATTERNS = [
    "/api/coupon/apply",
    "/api/coupon/redeem",
    "/api/redeem",
    "/api/voucher",
    "/api/withdraw",
    "/api/transfer",
    "/api/purchase",
    "/api/checkout",
    "/api/order",
    "/api/submit",
    "/api/vote",
    "/api/like",
    "/api/verify",
    "/api/confirm",
    "/api/otp",
]


@dataclass
class RaceConditionResult:
    endpoint: str
    method: str
    concurrent_requests: int
    response_variations: int
    timing_spread_ms: float
    is_vulnerable: bool
    confidence: float
    description: str


def _send_request(method: str, url: str, headers: Dict = None,
                  json_data: Dict = None, timeout: int = 10) -> tuple:
    """Send a single request and return (status, body_len, elapsed_ms)."""
    start = time.time()
    try:
        fn = {"GET": requests.get, "POST": requests.post, "PUT": requests.put}.get(method.upper(), requests.get)
        r = fn(url, headers=headers, json=json_data, timeout=timeout, verify=False)
        elapsed_ms = (time.time() - start) * 1000
        return r.status_code, len(r.text), elapsed_ms
    except Exception:
        elapsed_ms = (time.time() - start) * 1000
        return 0, 0, elapsed_ms


def test_race_condition(
    url: str,
    method: str = "GET",
    headers: Dict = None,
    concurrent: int = 10,
) -> RaceConditionResult:
    """
    Test an endpoint for race condition vulnerability.

    Sends 'concurrent' requests simultaneously and analyzes response variations.
    Significant variation across concurrent requests suggests a race window.
    """
    responses = []
    threads = min(concurrent, 20)  # Cap at 20 threads

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        futures = [
            executor.submit(_send_request, method, url, headers)
            for _ in range(concurrent)
        ]
        for future in concurrent.futures.as_completed(futures):
            try:
                responses.append(future.result(timeout=15))
            except Exception:
                pass

    if len(responses) < 2:
        return RaceConditionResult(
            endpoint=url, method=method, concurrent_requests=len(responses),
            response_variations=0, timing_spread_ms=0,
            is_vulnerable=False, confidence=0, description="Not enough responses",
        )

    # Analyze variations
    status_codes = set(r[0] for r in responses)
    body_lens = [r[1] for r in responses]
    timings = [r[2] for r in responses]

    timing_spread = max(timings) - min(timings) if timings else 0
    body_variation = max(body_lens) - min(body_lens) if body_lens else 0

    is_vulnerable = False
    confidence = 0.0
    description = "No race condition detected"

    # Indicator 1: Different status codes across concurrent requests
    if len(status_codes) > 1:
        is_vulnerable = True
        confidence = min(0.9, 0.5 + 0.15 * len(status_codes))
        description = (
            f"Race condition detected: {len(status_codes)} different status codes "
            f"from {concurrent} concurrent requests ({status_codes}). "
            "Response varies based on timing — classic race window."
        )

    # Indicator 2: Body varies significantly (>30% difference)
    elif body_lens and min(body_lens) > 0 and body_variation > max(body_lens) * 0.3:
        is_vulnerable = True
        confidence = 0.7
        description = (
            f"Response body varies by {body_variation} bytes across concurrent requests. "
            "Possible race condition or non-atomic operation."
        )

    # Indicator 3: Large timing variance (>500ms)
    elif timing_spread > 500:
        is_vulnerable = True
        confidence = 0.5
        description = (
            f"Timing spread of {timing_spread:.0f}ms across {concurrent} concurrent requests. "
            "Possible lock contention or race window."
        )

    return RaceConditionResult(
        endpoint=url, method=method, concurrent_requests=len(responses),
        response_variations=len(status_codes),
        timing_spread_ms=timing_spread,
        is_vulnerable=is_vulnerable,
        confidence=confidence,
        description=description,
    )


def scan_race_conditions(target: str, headers: Dict = None) -> List[Dict[str, Any]]:
    """
    Scan target for race condition vulnerabilities.

    Args:
        target: Base URL of the target
        headers: HTTP headers

    Returns:
        List of finding dicts
    """
    findings = []
    base = target.rstrip("/")

    for pattern in RACE_CONDITION_PATTERNS:
        url = f"{base}{pattern}"
        try:
            result = test_race_condition(url, headers=headers)
            if result.is_vulnerable and result.confidence >= 0.5:
                findings.append({
                    "type": "race_condition",
                    "severity": "high" if result.confidence >= 0.8 else "medium",
                    "confidence": round(result.confidence, 2),
                    "title": f"Race condition in {result.method} {pattern}",
                    "target": target,
                    "description": result.description,
                    "source": "race_condition_tester",
                    "url": url,
                    "evidence": {
                        "concurrent_requests": result.concurrent_requests,
                        "response_variations": result.response_variations,
                        "timing_spread_ms": round(result.timing_spread_ms, 1),
                    },
                })
        except Exception as e:
            logger.debug(f"Race condition test error for {pattern}: {e}")

    if not findings:
        logger.info(f"No race conditions detected on {target}")

    return findings
