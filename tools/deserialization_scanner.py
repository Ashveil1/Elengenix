"""tools/deserialization_scanner.py — Insecure Deserialization Scanner.

Detects deserialization vulnerabilities in various formats:
- Java serialized objects
- PHP serialized data
- Python pickle
- .NET BinaryFormatter
- YAML unsafe load
- JSON with custom deserializers

Public API:
    DeserializationScanner - Main scanner class
    DeserResult - Result of a single test
    DeserScanResult - Full scan results
"""

from __future__ import annotations

import base64
import logging
import re
import time
import urllib.parse
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("elengenix.deserialization_scanner")


@dataclass
class DeserResult:
    """Result of a single deserialization test."""
    url: str
    param: str
    format_type: str
    payload: str
    vulnerable: bool
    evidence: str = ""
    severity: str = "Critical"
    confidence: float = 0.0


@dataclass
class DeserScanResult:
    """Full deserialization scan results."""
    target: str
    results: List[DeserResult] = field(default_factory=list)
    vulnerable_params: List[str] = field(default_factory=list)
    formats_detected: List[str] = field(default_factory=list)
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
            "formats_detected": self.formats_detected,
            "total_findings": len([r for r in self.results if r.vulnerable]),
            "total_tests": self.total_tests,
            "duration": self.duration,
        }


# Deserialization detection patterns
DESER_PATTERNS = [
    # Java serialized objects
    (r"ac ed 00 05", "java_serialized"),
    (r"rO0AB", "java_serialized_base64"),
    
    # PHP serialized data
    (r"[a-z]:\d+:\{", "php_serialized"),
    (r"O:\d+:", "php_object"),
    
    # Python pickle
    (r"\\x80\\x04\\x95", "python_pickle"),
    (r"cos\\nsystem\\n", "python_pickle_exec"),
    
    # .NET BinaryFormatter
    (r"\\x00\\x01\\x00\\x00\\x00", "dotnet_binary"),
    
    # YAML
    (r"!!python/", "yaml_python"),
    (r"!!javax/script", "yaml_java"),
    
    # Base64 encoded payloads
    (r"eyJ", "base64_json"),
]

# Dangerous deserialization gadgets
GADGET_PATTERNS = [
    # Java gadgets
    (r"Runtime\.getRuntime\(\)\.exec", "java_rce"),
    (r"ProcessBuilder", "java_rce"),
    (r"Transformer", "java_transformer"),
    (r"AnnotationInvocationHandler", "java_invocation"),
    
    # PHP gadgets
    (r"__wakeup", "php_wakeup"),
    (r"__destruct", "php_destruct"),
    (r"unserialize", "php_unserialize"),
    
    # Python gadgets
    (r"__reduce__", "python_reduce"),
    (r"__import__", "python_import"),
]


class DeserializationScanner:
    """Insecure deserialization scanner.
    
    Tests input parameters for insecure deserialization by analyzing
    response patterns and injecting test payloads.
    
    Example:
        scanner = DeserializationScanner()
        result = scanner.scan("https://example.com/api/data")
        if result.is_vulnerable:
            print(f"Deserialization vulnerability in: {result.vulnerable_params}")
    """
    
    def __init__(
        self,
        timeout: float = 10.0,
        verify_ssl: bool = False,
    ):
        """Initialize the deserialization scanner.
        
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
    ) -> DeserScanResult:
        """Scan a URL for deserialization vulnerabilities.
        
        Args:
            target_url: The URL to test.
            params: URL parameters to test.
            method: HTTP method to use.
            
        Returns:
            DeserScanResult with all test results.
        """
        import requests
        
        start_time = time.time()
        result = DeserScanResult(target=target_url)
        
        # First, analyze responses for deserialization patterns
        self._analyze_responses(target_url, result)
        
        # Parse the URL to get existing parameters
        parsed = urllib.parse.urlparse(target_url)
        existing_params = dict(urllib.parse.parse_qsl(parsed.query))
        
        # Merge with provided params
        test_params = {**existing_params, **(params or {})}
        
        # If no parameters, test common ones
        if not test_params:
            test_params = {
                "data": "",
                "payload": "",
                "token": "",
                "session": "",
                "object": "",
                "serialized": "",
                "state": "",
                "cache": "",
            }
        
        # Test each parameter
        for param_name, original_value in test_params.items():
            self._test_parameter(target_url, param_name, result)
        
        result.duration = time.time() - start_time
        return result
    
    def _analyze_responses(self, target_url: str, result: DeserScanResult) -> None:
        """Analyze responses for deserialization patterns."""
        import requests
        
        try:
            response = requests.get(
                target_url,
                timeout=self.timeout,
                verify=self.verify_ssl,
            )
            
            response_text = response.text[:50000]
            response_headers = dict(response.headers)
            
            # Check for deserialization patterns
            for pattern, format_type in DESER_PATTERNS:
                if re.search(pattern, response_text, re.IGNORECASE):
                    if format_type not in result.formats_detected:
                        result.formats_detected.append(format_type)
                    logger.info(f"Deserialization format detected: {format_type}")
            
            # Check for gadget patterns
            for pattern, gadget_type in GADGET_PATTERNS:
                if re.search(pattern, response_text, re.IGNORECASE):
                    logger.info(f"Deserialization gadget detected: {gadget_type}")
            
            # Check cookies for serialized data
            for cookie_name, cookie_value in response.cookies.items():
                for pattern, format_type in DESER_PATTERNS:
                    if re.search(pattern, cookie_value, re.IGNORECASE):
                        logger.info(f"Serialized data in cookie: {cookie_name}")
        
        except Exception as e:
            logger.debug(f"Error analyzing responses: {e}")
    
    def _test_parameter(
        self,
        target_url: str,
        param_name: str,
        result: DeserScanResult,
    ) -> None:
        """Test a specific parameter for deserialization."""
        import requests
        
        # Test payloads for different formats
        test_payloads = [
            # Java serialized (base64)
            ("java", "rO0AB", "java_serialized"),
            
            # PHP serialized
            ("php", 'O:8:"stdClass":0:{}', "php_serialized"),
            
            # Python pickle (base64)
            ("python", "gANjYmFzZQpzdHJpbmcKcQRLAX10Lg==", "python_pickle"),
            
            # YAML
            ("yaml", "!!python/object/apply:os.system ['id']", "yaml_python"),
            
            # Generic test
            ("generic", "test", "generic"),
        ]
        
        for format_name, payload, format_type in test_payloads:
            result.total_tests += 1
            
            try:
                # Test via URL parameter
                parsed = urllib.parse.urlparse(target_url)
                test_params = {param_name: payload}
                test_url = urllib.parse.urlunparse(
                    parsed._replace(query=urllib.parse.urlencode(test_params))
                )
                
                response = requests.get(
                    test_url,
                    timeout=self.timeout,
                    verify=self.verify_ssl,
                )
                
                response_text = response.text[:10000]
                
                # Check for error-based detection
                error_patterns = [
                    r"serialization",
                    r"deserialization",
                    r"unserialize",
                    r"pickle",
                    r"yaml.*error",
                    r"invalid.*token",
                    r"malformed",
                ]
                
                for pattern in error_patterns:
                    if re.search(pattern, response_text, re.IGNORECASE):
                        deser_result = DeserResult(
                            url=test_url,
                            param=param_name,
                            format_type=format_type,
                            payload=payload,
                            vulnerable=True,
                            evidence=f"Error pattern detected: {pattern}",
                            severity="Critical",
                            confidence=0.7,
                        )
                        result.results.append(deser_result)
                        if param_name not in result.vulnerable_params:
                            result.vulnerable_params.append(param_name)
                        if format_type not in result.formats_detected:
                            result.formats_detected.append(format_type)
                        logger.info(f"Deserialization vulnerability found: {format_type}")
                        break
            
            except Exception as e:
                logger.debug(f"Error testing {param_name}: {e}")
    
    def scan_cookies(
        self,
        target_url: str,
    ) -> DeserScanResult:
        """Scan cookies for deserialization vulnerabilities.
        
        Args:
            target_url: The URL to test.
            
        Returns:
            DeserScanResult with all test results.
        """
        import requests
        
        start_time = time.time()
        result = DeserScanResult(target=target_url)
        
        try:
            response = requests.get(
                target_url,
                timeout=self.timeout,
                verify=self.verify_ssl,
            )
            
            # Analyze each cookie
            for cookie_name, cookie_value in response.cookies.items():
                result.total_tests += 1
                
                # Check for deserialization patterns
                for pattern, format_type in DESER_PATTERNS:
                    if re.search(pattern, cookie_value, re.IGNORECASE):
                        deser_result = DeserResult(
                            url=target_url,
                            param=f"cookie:{cookie_name}",
                            format_type=format_type,
                            payload=cookie_value[:100],
                            vulnerable=True,
                            evidence=f"Cookie contains {format_type} data",
                            severity="Critical",
                            confidence=0.8,
                        )
                        result.results.append(deser_result)
                        if f"cookie:{cookie_name}" not in result.vulnerable_params:
                            result.vulnerable_params.append(f"cookie:{cookie_name}")
                        if format_type not in result.formats_detected:
                            result.formats_detected.append(format_type)
                        logger.info(f"Deserialization in cookie: {cookie_name}")
                        break
        
        except Exception as e:
            logger.debug(f"Error scanning cookies: {e}")
        
        result.duration = time.time() - start_time
        return result
