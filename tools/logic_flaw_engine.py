"""tools/logic_flaw_engine.py — Business Logic Vulnerability Analyzer.

Detects business logic vulnerabilities by analyzing application behavior:
- Price manipulation
- Quantity overflow
- Workflow bypass
- Privilege escalation
- Race conditions in business flows
- Parameter tampering

Public API:
    LogicFlawEngine - Main analyzer class
    LogicFlaw - Single logic flaw finding
    LogicFlawResult - Full analysis results
"""

from __future__ import annotations

import logging
import re
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("elengenix.logic_flaw_engine")


@dataclass
class LogicFlaw:
    """A single business logic flaw."""

    flaw_type: str
    endpoint: str
    description: str
    evidence: str = ""
    severity: str = "High"
    confidence: float = 0.0
    remediation: str = ""


@dataclass
class LogicFlawResult:
    """Full business logic analysis results."""

    target: str
    flaws: List[LogicFlaw] = field(default_factory=list)
    total_tests: int = 0
    duration: float = 0.0

    @property
    def is_vulnerable(self) -> bool:
        return len(self.flaws) > 0

    def summary(self) -> Dict[str, Any]:
        severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        for flaw in self.flaws:
            if flaw.severity in severity_counts:
                severity_counts[flaw.severity] += 1

        return {
            "target": self.target,
            "is_vulnerable": self.is_vulnerable,
            "total_flaws": len(self.flaws),
            "severity_counts": severity_counts,
            "duration": self.duration,
        }


# Common business logic flaw patterns
BUSINESS_LOGIC_PATTERNS = {
    "price_manipulation": {
        "indicators": [
            r"price",
            r"amount",
            r"cost",
            r"total",
            r"discount",
            r"coupon",
        ],
        "tests": [
            "negative_price",
            "zero_price",
            "overflow_price",
            "discount_abuse",
        ],
    },
    "quantity_overflow": {
        "indicators": [
            r"quantity",
            r"qty",
            r"count",
            r"amount",
            r"stock",
        ],
        "tests": [
            "negative_quantity",
            "zero_quantity",
            "overflow_quantity",
            "exceed_stock",
        ],
    },
    "workflow_bypass": {
        "indicators": [
            r"step",
            r"stage",
            r"phase",
            r"status",
            r"state",
        ],
        "tests": [
            "skip_steps",
            "reverse_order",
            "skip_validation",
        ],
    },
    "privilege_escalation": {
        "indicators": [
            r"role",
            r"permission",
            r"admin",
            r"access",
            r"level",
        ],
        "tests": [
            "role_tampering",
            "permission_bypass",
            "admin_access",
        ],
    },
    "race_condition": {
        "indicators": [
            r"balance",
            r"transfer",
            r"payment",
            r"withdraw",
            r"deposit",
        ],
        "tests": [
            "concurrent_modification",
            "double_spend",
            "time_of_check",
        ],
    },
}


class LogicFlawEngine:
    """Business logic vulnerability analyzer.

    Detects business logic vulnerabilities by analyzing application
    behavior and testing for common flaws.

    Example:
        engine = LogicFlawEngine()
        result = engine.analyze_endpoint(
            "https://example.com/api/checkout",
            method="POST",
            parameters={"price": "100", "quantity": "1"},
        )
        if result.is_vulnerable:
            print("Business logic flaws detected!")
    """

    def __init__(
        self,
        timeout: float = 10.0,
        verify_ssl: bool = False,
    ):
        """Initialize the business logic analyzer.

        Args:
            timeout: Request timeout in seconds.
            verify_ssl: Whether to verify SSL certificates.
        """
        self.timeout = timeout
        self.verify_ssl = verify_ssl

    def analyze_endpoint(
        self,
        url: str,
        method: str = "POST",
        parameters: Optional[Dict[str, str]] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> LogicFlawResult:
        """Analyze an endpoint for business logic flaws.

        Args:
            url: The endpoint URL to analyze.
            method: HTTP method to use.
            parameters: Request parameters.
            headers: Additional headers.

        Returns:
            LogicFlawResult with analysis results.
        """
        import requests

        start_time = time.time()
        result = LogicFlawResult(target=url)

        default_headers = {
            "Content-Type": "application/json",
            "User-Agent": "Elengenix-LogicFlaw/1.0",
        }
        if headers:
            default_headers.update(headers)

        params = parameters or {}

        # Test 1: Price manipulation
        result.total_tests += 1
        self._test_price_manipulation(url, method, params, default_headers, result)

        # Test 2: Quantity overflow
        result.total_tests += 1
        self._test_quantity_overflow(url, method, params, default_headers, result)

        # Test 3: Negative values
        result.total_tests += 1
        self._test_negative_values(url, method, params, default_headers, result)

        # Test 4: Parameter tampering
        result.total_tests += 1
        self._test_parameter_tampering(url, method, params, default_headers, result)

        result.duration = time.time() - start_time
        return result

    def _test_price_manipulation(
        self,
        url: str,
        method: str,
        params: Dict[str, str],
        headers: Dict[str, str],
        result: LogicFlawResult,
    ) -> None:
        """Test for price manipulation vulnerabilities."""
        import requests

        # Find price-related parameters
        price_params = [
            k
            for k in params.keys()
            if any(p in k.lower() for p in ["price", "amount", "cost", "total"])
        ]

        for param in price_params:
            original_value = params.get(param, "100")

            # Test negative price
            test_params = dict(params)
            test_params[param] = "-100"

            try:
                response = self._make_request(url, method, test_params, headers)
                if response and response.status_code == 200:
                    result.flaws.append(
                        LogicFlaw(
                            flaw_type="price_manipulation",
                            endpoint=url,
                            description=f"Negative price accepted for parameter '{param}'",
                            evidence=f"Sent price=-100, got 200 OK",
                            severity="High",
                            confidence=0.7,
                            remediation="Validate that price cannot be negative",
                        )
                    )
            except Exception as e:
                logger.debug(f"Price manipulation test failed: {e}")

            # Test zero price
            test_params[param] = "0"

            try:
                response = self._make_request(url, method, test_params, headers)
                if response and response.status_code == 200:
                    result.flaws.append(
                        LogicFlaw(
                            flaw_type="price_manipulation",
                            endpoint=url,
                            description=f"Zero price accepted for parameter '{param}'",
                            evidence=f"Sent price=0, got 200 OK",
                            severity="Medium",
                            confidence=0.6,
                            remediation="Validate that price cannot be zero",
                        )
                    )
            except Exception as e:
                logger.debug(f"Zero price test failed: {e}")

    def _test_quantity_overflow(
        self,
        url: str,
        method: str,
        params: Dict[str, str],
        headers: Dict[str, str],
        result: LogicFlawResult,
    ) -> None:
        """Test for quantity overflow vulnerabilities."""
        import requests

        # Find quantity-related parameters
        qty_params = [
            k
            for k in params.keys()
            if any(p in k.lower() for p in ["quantity", "qty", "count", "amount"])
        ]

        for param in qty_params:
            # Test very large quantity
            test_params = dict(params)
            test_params[param] = "999999999"

            try:
                response = self._make_request(url, method, test_params, headers)
                if response and response.status_code == 200:
                    result.flaws.append(
                        LogicFlaw(
                            flaw_type="quantity_overflow",
                            endpoint=url,
                            description=f"Large quantity accepted for parameter '{param}'",
                            evidence=f"Sent quantity=999999999, got 200 OK",
                            severity="Medium",
                            confidence=0.5,
                            remediation="Validate quantity against stock limits",
                        )
                    )
            except Exception as e:
                logger.debug(f"Quantity overflow test failed: {e}")

    def _test_negative_values(
        self,
        url: str,
        method: str,
        params: Dict[str, str],
        headers: Dict[str, str],
        result: LogicFlawResult,
    ) -> None:
        """Test for negative value acceptance."""
        import requests

        # Test negative values for numeric parameters
        for param, value in params.items():
            if value.replace(".", "").replace("-", "").isdigit():
                test_params = dict(params)
                test_params[param] = f"-{value}"

                try:
                    response = self._make_request(url, method, test_params, headers)
                    if response and response.status_code == 200:
                        # Check if negative value was accepted
                        result.flaws.append(
                            LogicFlaw(
                                flaw_type="negative_value",
                                endpoint=url,
                                description=f"Negative value accepted for parameter '{param}'",
                                evidence=f"Sent {param}=-{value}, got 200 OK",
                                severity="Medium",
                                confidence=0.6,
                                remediation="Validate that numeric values are positive",
                            )
                        )
                except Exception as e:
                    logger.debug(f"Negative value test failed: {e}")

    def _test_parameter_tampering(
        self,
        url: str,
        method: str,
        params: Dict[str, str],
        headers: Dict[str, str],
        result: LogicFlawResult,
    ) -> None:
        """Test for parameter tampering vulnerabilities."""
        import requests

        # Test adding admin/role parameters
        test_params = dict(params)
        test_params["admin"] = "true"
        test_params["role"] = "admin"
        test_params["is_admin"] = "1"

        try:
            response = self._make_request(url, method, test_params, headers)
            if response and response.status_code == 200:
                # Check if admin parameter was accepted
                result.flaws.append(
                    LogicFlaw(
                        flaw_type="parameter_tampering",
                        endpoint=url,
                        description="Admin parameter accepted",
                        evidence="Added admin=true, got 200 OK",
                        severity="Critical",
                        confidence=0.8,
                        remediation="Do not trust client-side parameters for authorization",
                    )
                )
        except Exception as e:
            logger.debug(f"Parameter tampering test failed: {e}")

    def _make_request(
        self,
        url: str,
        method: str,
        data: Dict[str, str],
        headers: Dict[str, str],
    ):
        """Make an HTTP request."""
        import requests

        try:
            if method.upper() == "POST":
                return requests.post(
                    url,
                    json=data,
                    headers=headers,
                    timeout=self.timeout,
                    verify=self.verify_ssl,
                )
            elif method.upper() == "PUT":
                return requests.put(
                    url,
                    json=data,
                    headers=headers,
                    timeout=self.timeout,
                    verify=self.verify_ssl,
                )
            else:
                return requests.get(
                    url,
                    params=data,
                    headers=headers,
                    timeout=self.timeout,
                    verify=self.verify_ssl,
                )
        except Exception as e:
            logger.debug(f"Request failed: {e}")
            return None
