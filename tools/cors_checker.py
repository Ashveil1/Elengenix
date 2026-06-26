"""tools/cors_checker.py — CORS Misconfiguration Tester.

Detects CORS (Cross-Origin Resource Sharing) vulnerabilities:
- Wildcard origin reflection
- Null origin bypass
- Subdomain takeover potential
- Trusted domain bypass
- Credential inclusion issues

Public API:
    CORSChecker - Main checker class
    CORSResult - Result of a single test
    CORSScanResult - Full scan results
"""

from __future__ import annotations

import logging
import re
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

logger = logging.getLogger("elengenix.cors_checker")


@dataclass
class CORSResult:
    """Result of a single CORS test."""

    test_type: str
    origin: str
    vulnerable: bool
    response_headers: Dict[str, str] = field(default_factory=dict)
    evidence: str = ""
    severity: str = "Medium"
    confidence: float = 0.0


@dataclass
class CORSScanResult:
    """Full CORS scan results."""

    target: str
    results: List[CORSResult] = field(default_factory=list)
    total_tests: int = 0
    duration: float = 0.0

    @property
    def is_vulnerable(self) -> bool:
        return any(r.vulnerable for r in self.results)

    def summary(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "is_vulnerable": self.is_vulnerable,
            "total_findings": len([r for r in self.results if r.vulnerable]),
            "total_tests": self.total_tests,
            "duration": self.duration,
        }


# Common CORS misconfiguration patterns
CORS_MISCONFIGURATIONS = {
    "wildcard": {
        "pattern": r"\*",
        "severity": "High",
        "description": "Wildcard origin allows any domain",
    },
    "null_origin": {
        "pattern": r"null",
        "severity": "High",
        "description": "Null origin accepted (potential bypass via sandboxed iframe)",
    },
    "http_reflect": {
        "pattern": r"http://",
        "severity": "Medium",
        "description": "HTTP origin reflected (not HTTPS)",
    },
    "subdomain": {
        "pattern": r"\*\.[a-zA-Z0-9-]+\.[a-zA-Z]{2,}",
        "severity": "Low",
        "description": "Wildcard subdomain pattern",
    },
}


class CORSChecker:
    """CORS misconfiguration tester.

    Tests for CORS vulnerabilities by sending requests with various
    Origin headers and analyzing the response headers.

    Example:
        checker = CORSChecker()
        result = checker.check("https://example.com")
        if result.is_vulnerable:
            print("CORS misconfiguration detected!")
    """

    def __init__(
        self,
        timeout: float = 10.0,
        verify_ssl: bool = False,
    ):
        """Initialize the CORS checker.

        Args:
            timeout: Request timeout in seconds.
            verify_ssl: Whether to verify SSL certificates.
        """
        self.timeout = timeout
        self.verify_ssl = verify_ssl

    def check(
        self,
        target_url: str,
        test_origins: Optional[List[str]] = None,
    ) -> CORSScanResult:
        """Check a URL for CORS misconfigurations.

        Args:
            target_url: The URL to test.
            test_origins: List of origins to test. If None, uses default test origins.

        Returns:
            CORSScanResult with test results.
        """
        import requests

        start_time = time.time()
        result = CORSScanResult(target=target_url)

        # Parse the target URL to get the domain
        parsed = urlparse(target_url)
        target_domain = parsed.netloc

        # Default test origins
        if not test_origins:
            test_origins = [
                # Null origin (sandboxed iframe)
                "null",
                # Attacker's domain
                "https://evil.com",
                # HTTP version of target
                f"http://{target_domain}",
                # Subdomain
                f"https://sub.{target_domain}",
                # Double subdomain
                f"https://a.b.{target_domain}",
                # Similar domain (typosquatting)
                f"https://{target_domain.replace('.', '')}.com",
                # Regex bypass attempt
                f"https://{target_domain}.evil.com",
                # Prefix/suffix bypass
                f"https://evil{target_domain}",
                f"https://{target_domain}evil.com",
            ]

        # Test each origin
        for origin in test_origins:
            result.total_tests += 1
            self._test_origin(target_url, origin, result)

        result.duration = time.time() - start_time
        return result

    def _test_origin(
        self,
        url: str,
        origin: str,
        result: CORSScanResult,
    ) -> None:
        """Test a specific origin for CORS misconfiguration."""
        import requests

        try:
            # Send preflight request
            headers = {
                "Origin": origin,
                "Access-Control-Request-Method": "GET",
                "Access-Control-Request-Headers": "Content-Type",
            }

            response = requests.options(
                url,
                headers=headers,
                timeout=self.timeout,
                verify=self.verify_ssl,
            )

            # Get CORS headers
            acao = response.headers.get("Access-Control-Allow-Origin", "")
            acac = response.headers.get("Access-Control-Allow-Credentials", "")
            acam = response.headers.get("Access-Control-Allow-Methods", "")
            acah = response.headers.get("Access-Control-Allow-Headers", "")

            cors_headers = {
                "Access-Control-Allow-Origin": acao,
                "Access-Control-Allow-Credentials": acac,
                "Access-Control-Allow-Methods": acam,
                "Access-Control-Allow-Headers": acah,
            }

            # Analyze the response
            if acao:
                # Check for wildcard
                if acao == "*":
                    result.results.append(
                        CORSResult(
                            test_type="wildcard_origin",
                            origin=origin,
                            vulnerable=True,
                            response_headers=cors_headers,
                            evidence="Wildcard origin (*) accepted",
                            severity="High",
                            confidence=0.95,
                        )
                    )
                    logger.info(f"CORS wildcard origin detected: {origin}")

                # Check for null origin
                elif origin == "null" and acao == "null":
                    result.results.append(
                        CORSResult(
                            test_type="null_origin",
                            origin=origin,
                            vulnerable=True,
                            response_headers=cors_headers,
                            evidence="Null origin accepted",
                            severity="High",
                            confidence=0.9,
                        )
                    )
                    logger.info("CORS null origin accepted")

                # Check for reflected origin
                elif acao == origin:
                    # Check if credentials are allowed
                    if acac.lower() == "true":
                        result.results.append(
                            CORSResult(
                                test_type="reflected_origin_with_credentials",
                                origin=origin,
                                vulnerable=True,
                                response_headers=cors_headers,
                                evidence=f"Origin reflected with credentials: {origin}",
                                severity="Critical",
                                confidence=0.95,
                            )
                        )
                        logger.info(f"CORS reflected origin with credentials: {origin}")
                    else:
                        result.results.append(
                            CORSResult(
                                test_type="reflected_origin",
                                origin=origin,
                                vulnerable=True,
                                response_headers=cors_headers,
                                evidence=f"Origin reflected: {origin}",
                                severity="Medium",
                                confidence=0.7,
                            )
                        )
                        logger.info(f"CORS origin reflected: {origin}")

                # Check for subdomain wildcard
                elif re.match(r"https://\*\.[a-zA-Z0-9-]+\.[a-zA-Z]{2,}", acao):
                    result.results.append(
                        CORSResult(
                            test_type="subdomain_wildcard",
                            origin=origin,
                            vulnerable=True,
                            response_headers=cors_headers,
                            evidence=f"Subdomain wildcard pattern: {acao}",
                            severity="Low",
                            confidence=0.6,
                        )
                    )
                    logger.info(f"CORS subdomain wildcard: {acao}")

        except Exception as e:
            logger.debug(f"CORS test failed for {origin}: {e}")

    def check_with_credentials(
        self,
        target_url: str,
    ) -> CORSScanResult:
        """Check if CORS allows credentials with dangerous origins.

        Args:
            target_url: The URL to test.

        Returns:
            CORSScanResult with test results.
        """
        import requests

        start_time = time.time()
        result = CORSScanResult(target=target_url)

        # Test with various dangerous origins
        dangerous_origins = [
            "null",
            "https://evil.com",
            "http://localhost",
            "http://127.0.0.1",
        ]

        for origin in dangerous_origins:
            result.total_tests += 1

            try:
                headers = {
                    "Origin": origin,
                    "Cookie": "test=123",
                }

                response = requests.get(
                    target_url,
                    headers=headers,
                    timeout=self.timeout,
                    verify=self.verify_ssl,
                )

                acao = response.headers.get("Access-Control-Allow-Origin", "")
                acac = response.headers.get("Access-Control-Allow-Credentials", "")

                if acao and acac.lower() == "true":
                    result.results.append(
                        CORSResult(
                            test_type="credentials_with_dangerous_origin",
                            origin=origin,
                            vulnerable=True,
                            response_headers={
                                "Access-Control-Allow-Origin": acao,
                                "Access-Control-Allow-Credentials": acac,
                            },
                            evidence=f"Credentials allowed with dangerous origin: {origin}",
                            severity="Critical",
                            confidence=0.95,
                        )
                    )
                    logger.info(f"CORS credentials with dangerous origin: {origin}")

            except Exception as e:
                logger.debug(f"CORS credential test failed: {e}")

        result.duration = time.time() - start_time
        return result
