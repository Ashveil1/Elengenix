"""tools/race_condition_tester.py — Race Condition Vulnerability Tester.

Detects race condition vulnerabilities by sending concurrent requests
and analyzing response patterns. Tests:
- TOCTOU (Time-of-Check to Time-of-Use) vulnerabilities
- Double-spend/double-redemption
- Concurrent resource modification
- File lock bypass

Public API:
    RaceConditionTester - Main tester class
    RaceConditionResult - Result of a single test
    RaceConditionScanResult - Full test results
"""

from __future__ import annotations

import asyncio
import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

logger = logging.getLogger("elengenix.race_condition_tester")


@dataclass
class RaceConditionResult:
    """Result of a single race condition test."""
    test_type: str
    endpoint: str
    vulnerable: bool
    evidence: str = ""
    response_codes: List[int] = field(default_factory=list)
    response_times: List[float] = field(default_factory=list)
    severity: str = "High"
    confidence: float = 0.0


@dataclass
class RaceConditionScanResult:
    """Full race condition test results."""
    target: str
    results: List[RaceConditionResult] = field(default_factory=list)
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


class RaceConditionTester:
    """Race condition vulnerability tester.
    
    Tests for race condition vulnerabilities by sending concurrent
    requests and analyzing response patterns.
    
    Example:
        tester = RaceConditionTester()
        result = tester.test_endpoint(
            "https://example.com/api/transfer",
            method="POST",
            data={"amount": 100, "to": "attacker"},
            concurrent_requests=10,
        )
        if result.is_vulnerable:
            print("Race condition vulnerability found!")
    """
    
    def __init__(
        self,
        timeout: float = 10.0,
        verify_ssl: bool = False,
        max_workers: int = 10,
    ):
        """Initialize the race condition tester.
        
        Args:
            timeout: Request timeout in seconds.
            verify_ssl: Whether to verify SSL certificates.
            max_workers: Maximum concurrent workers.
        """
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.max_workers = max_workers
    
    def test_endpoint(
        self,
        url: str,
        method: str = "POST",
        data: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        concurrent_requests: int = 10,
        expected_success_count: int = 1,
    ) -> RaceConditionScanResult:
        """Test an endpoint for race condition vulnerabilities.
        
        Args:
            url: The endpoint URL to test.
            method: HTTP method to use.
            data: Request data/payload.
            headers: Additional headers.
            concurrent_requests: Number of concurrent requests to send.
            expected_success_count: Expected number of successful responses.
            
        Returns:
            RaceConditionScanResult with test results.
        """
        import requests
        
        start_time = time.time()
        result = RaceConditionScanResult(target=url)
        
        default_headers = {
            "User-Agent": "Elengenix-Race-Tester/1.0",
        }
        if headers:
            default_headers.update(headers)
        
        # Test 1: Concurrent requests to same endpoint
        result.total_tests += 1
        response_codes = []
        response_times = []
        
        def make_request():
            try:
                req_start = time.time()
                if method.upper() == "POST":
                    response = requests.post(
                        url,
                        json=data,
                        headers=default_headers,
                        timeout=self.timeout,
                        verify=self.verify_ssl,
                    )
                else:
                    response = requests.get(
                        url,
                        headers=default_headers,
                        timeout=self.timeout,
                        verify=self.verify_ssl,
                    )
                req_time = time.time() - req_start
                return response.status_code, req_time
            except Exception as e:
                logger.debug(f"Request failed: {e}")
                return 0, 0
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = [executor.submit(make_request) for _ in range(concurrent_requests)]
            for future in as_completed(futures):
                code, req_time = future.result()
                if code > 0:
                    response_codes.append(code)
                    response_times.append(req_time)
        
        # Analyze results
        success_count = sum(1 for code in response_codes if 200 <= code < 300)
        
        if success_count > expected_success_count:
            # Race condition detected: more successes than expected
            race_result = RaceConditionResult(
                test_type="concurrent_requests",
                endpoint=url,
                vulnerable=True,
                evidence=f"Got {success_count} successful responses (expected {expected_success_count})",
                response_codes=response_codes,
                response_times=response_times,
                severity="High",
                confidence=0.8,
            )
            result.results.append(race_result)
            logger.info(f"Race condition detected: {success_count} successes")
        
        # Test 2: Timing analysis
        result.total_tests += 1
        if response_times:
            avg_time = sum(response_times) / len(response_times)
            max_time = max(response_times)
            min_time = min(response_times)
            
            # If responses are very fast and consistent, might indicate caching
            # If responses vary widely, might indicate race condition
            if max_time > avg_time * 3 and len(response_times) > 5:
                race_result = RaceConditionResult(
                    test_type="timing_analysis",
                    endpoint=url,
                    vulnerable=True,
                    evidence=f"Response times vary widely: min={min_time:.3f}s, avg={avg_time:.3f}s, max={max_time:.3f}s",
                    response_codes=response_codes,
                    response_times=response_times,
                    severity="Medium",
                    confidence=0.6,
                )
                result.results.append(race_result)
                logger.info("Timing variation detected")
        
        result.duration = time.time() - start_time
        return result
    
    def test_double_spend(
        self,
        url: str,
        data: Dict[str, Any],
        resource_field: str = "amount",
        headers: Optional[Dict[str, str]] = None,
        concurrent_requests: int = 5,
    ) -> RaceConditionScanResult:
        """Test for double-spend/double-redemption vulnerabilities.
        
        Args:
            url: The endpoint URL to test.
            data: Request data containing the resource field.
            resource_field: Field name containing the resource/amount.
            headers: Additional headers.
            concurrent_requests: Number of concurrent requests.
            
        Returns:
            RaceConditionScanResult with test results.
        """
        import requests
        
        start_time = time.time()
        result = RaceConditionScanResult(target=url)
        
        default_headers = {
            "Content-Type": "application/json",
            "User-Agent": "Elengenix-Race-Tester/1.0",
        }
        if headers:
            default_headers.update(headers)
        
        # Send concurrent requests with same resource
        result.total_tests += 1
        response_codes = []
        response_times = []
        
        def make_request():
            try:
                req_start = time.time()
                response = requests.post(
                    url,
                    json=data,
                    headers=default_headers,
                    timeout=self.timeout,
                    verify=self.verify_ssl,
                )
                req_time = time.time() - req_start
                return response.status_code, req_time, response.text[:500]
            except Exception as e:
                logger.debug(f"Request failed: {e}")
                return 0, 0, str(e)
        
        responses = []
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = [executor.submit(make_request) for _ in range(concurrent_requests)]
            for future in as_completed(futures):
                code, req_time, text = future.result()
                if code > 0:
                    response_codes.append(code)
                    response_times.append(req_time)
                    responses.append((code, text))
        
        # Analyze for double-spend
        success_count = sum(1 for code in response_codes if 200 <= code < 300)
        
        if success_count > 1:
            # Check if responses indicate successful double-spend
            success_responses = [text for code, text in responses if 200 <= code < 300]
            
            race_result = RaceConditionResult(
                test_type="double_spend",
                endpoint=url,
                vulnerable=True,
                evidence=f"Got {success_count} successful responses for same resource",
                response_codes=response_codes,
                response_times=response_times,
                severity="Critical",
                confidence=0.85,
            )
            result.results.append(race_result)
            logger.info(f"Double-spend detected: {success_count} successes")
        
        result.duration = time.time() - start_time
        return result
    
    def test_file_lock(
        self,
        url: str,
        data: Dict[str, Any],
        file_field: str = "filename",
        headers: Optional[Dict[str, str]] = None,
        concurrent_requests: int = 10,
    ) -> RaceConditionScanResult:
        """Test for file lock bypass vulnerabilities.
        
        Args:
            url: The endpoint URL to test.
            data: Request data containing the file field.
            file_field: Field name containing the filename.
            headers: Additional headers.
            concurrent_requests: Number of concurrent requests.
            
        Returns:
            RaceConditionScanResult with test results.
        """
        import requests
        
        start_time = time.time()
        result = RaceConditionScanResult(target=url)
        
        default_headers = {
            "Content-Type": "application/json",
            "User-Agent": "Elengenix-Race-Tester/1.0",
        }
        if headers:
            default_headers.update(headers)
        
        # Send concurrent requests to same file
        result.total_tests += 1
        response_codes = []
        response_times = []
        
        def make_request():
            try:
                req_start = time.time()
                response = requests.post(
                    url,
                    json=data,
                    headers=default_headers,
                    timeout=self.timeout,
                    verify=self.verify_ssl,
                )
                req_time = time.time() - req_start
                return response.status_code, req_time
            except Exception as e:
                logger.debug(f"Request failed: {e}")
                return 0, 0
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = [executor.submit(make_request) for _ in range(concurrent_requests)]
            for future in as_completed(futures):
                code, req_time = future.result()
                if code > 0:
                    response_codes.append(code)
                    response_times.append(req_time)
        
        # Analyze results
        success_count = sum(1 for code in response_codes if 200 <= code < 300)
        
        if success_count > 1:
            race_result = RaceConditionResult(
                test_type="file_lock_bypass",
                endpoint=url,
                vulnerable=True,
                evidence=f"Got {success_count} successful responses for same file",
                response_codes=response_codes,
                response_times=response_times,
                severity="High",
                confidence=0.75,
            )
            result.results.append(race_result)
            logger.info(f"File lock bypass detected: {success_count} successes")
        
        result.duration = time.time() - start_time
        return result
    
    def test_concurrent_modification(
        self,
        url: str,
        data: Dict[str, Any],
        modify_field: str,
        modify_values: List[Any],
        method: str = "PUT",
        headers: Optional[Dict[str, str]] = None,
    ) -> RaceConditionScanResult:
        """Test for concurrent modification vulnerabilities.
        
        Args:
            url: The endpoint URL to test.
            method: HTTP method to use.
            data: Request data.
            modify_field: Field to modify concurrently.
            modify_values: List of values to use concurrently.
            headers: Additional headers.
            
        Returns:
            RaceConditionScanResult with test results.
        """
        import requests
        
        start_time = time.time()
        result = RaceConditionScanResult(target=url)
        
        default_headers = {
            "Content-Type": "application/json",
            "User-Agent": "Elengenix-Race-Tester/1.0",
        }
        if headers:
            default_headers.update(headers)
        
        # Send concurrent requests with different values for same field
        result.total_tests += 1
        response_codes = []
        response_times = []
        
        def make_request(value):
            try:
                test_data = dict(data)
                test_data[modify_field] = value
                
                req_start = time.time()
                if method.upper() == "POST":
                    response = requests.post(url, json=test_data, headers=default_headers,
                                           timeout=self.timeout, verify=self.verify_ssl)
                elif method.upper() == "PUT":
                    response = requests.put(url, json=test_data, headers=default_headers,
                                          timeout=self.timeout, verify=self.verify_ssl)
                else:
                    response = requests.patch(url, json=test_data, headers=default_headers,
                                            timeout=self.timeout, verify=self.verify_ssl)
                req_time = time.time() - req_start
                return response.status_code, req_time, value
            except Exception as e:
                logger.debug(f"Request failed: {e}")
                return 0, 0, value
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = [executor.submit(make_request, v) for v in modify_values]
            for future in as_completed(futures):
                code, req_time, value = future.result()
                if code > 0:
                    response_codes.append(code)
                    response_times.append(req_time)
        
        # Analyze results
        success_count = sum(1 for code in response_codes if 200 <= code < 300)
        
        if success_count > 1:
            race_result = RaceConditionResult(
                test_type="concurrent_modification",
                endpoint=url,
                vulnerable=True,
                evidence=f"Got {success_count} successful modifications for same resource",
                response_codes=response_codes,
                response_times=response_times,
                severity="High",
                confidence=0.7,
            )
            result.results.append(race_result)
            logger.info(f"Concurrent modification detected: {success_count} successes")
        
        result.duration = time.time() - start_time
        return result
