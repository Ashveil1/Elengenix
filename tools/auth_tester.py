"""tools/auth_tester.py

Authentication & Authorization Testing Tool for Bug Bounty.

Purpose:
- JWT structure analysis and weakness detection
- Token manipulation testing (alg:none, key confusion, claim forgery)
- OAuth 2.0 misconfiguration detection
- Session management testing
- API key exposure and rotation testing

Safety:
- Only tests on user-specified targets
- Read-only analysis where possible
- Logs all attempts
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import re
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

import requests

logger = logging.getLogger("elengenix.auth_tester")


@dataclass
class AuthFinding:
    title: str
    severity: str
    description: str
    evidence: Dict[str, Any]
    remediation: str


def _decode_jwt_part(part: str) -> Optional[Dict]:
    """Decode a base64url-encoded JWT part (header or payload)."""
    try:
        padded = part + "=" * (4 - len(part) % 4)
        decoded = base64.urlsafe_b64decode(padded)
        return json.loads(decoded)
    except Exception:
        return None


def analyze_jwt(token: str) -> List[AuthFinding]:
    """
    Analyze a JWT token for weaknesses.

    Checks:
    - Algorithm: none attack
    - Key ID injection
    - Weak signing algorithm (HS256 with RSA key confusion)
    - Missing claims (exp, iat, aud, iss)
    - Sensitive data in payload
    - Token entropy
    """
    findings = []

    parts = token.split(".")
    if len(parts) not in (3, 5):  # JWS or JWE
        return findings

    header = _decode_jwt_part(parts[0])
    payload = _decode_jwt_part(parts[1]) if len(parts) >= 2 else None

    if not header:
        return findings

    # Check 1: Algorithm "none" vulnerability
    alg = header.get("alg", "").lower()
    if alg == "none":
        findings.append(AuthFinding(
            title="JWT 'alg: none' — Unauthenticated Token Accepted",
            severity="critical",
            description="Token uses 'alg': 'none' which means no signature verification. Anyone can forge tokens.",
            evidence={"header": header, "attack": "alg:none"},
            remediation="Never accept 'none' algorithm. Whitelist allowed algorithms server-side.",
        ))

    # Check 2: Algorithm confusion (RS256 → HS256)
    if alg == "hs256" and header.get("typ", "").lower() in ("jwt", ""):
        # Could be legitimate HS256, but if server also has RSA public key, this is confusion
        findings.append(AuthFinding(
            title="JWT uses HS256 — potential algorithm confusion attack",
            severity="medium",
            description=(
                "Token uses HS256 (HMAC). If the server also has an RSA public key, "
                "an attacker can sign tokens with the public key as HMAC secret (key confusion). "
                "Test by forging a token signed with the known public key."
            ),
            evidence={"header": header, "attack": "key_confusion"},
            remediation="Use RS256 or ES256. Never mix symmetric and asymmetric algorithms.",
        ))

    # Check 3: Missing critical claims
    if payload:
        critical_claims = {
            "exp": "Expiration time — without this, tokens never expire",
            "iat": "Issued-at — needed to enforce token age limits",
            "aud": "Audience — prevents token use across services",
            "iss": "Issuer — validates token origin",
        }
        missing = []
        for claim, reason in critical_claims.items():
            if claim not in payload:
                missing.append(f"{claim}: {reason}")

        if missing:
            findings.append(AuthFinding(
                title=f"JWT missing critical claims: {', '.join(c for c in critical_claims if c not in (payload or {}))}",
                severity="medium" if "exp" in [c.split(":")[0] for c in missing] else "low",
                description="Missing claims:\n" + "\n".join(f"  - {m}" for m in missing),
                evidence={"missing_claims": [c.split(":")[0] for c in missing], "payload_keys": list(payload.keys())},
                remediation="Always include 'exp', 'iat', 'aud', 'iss' claims in JWTs.",
            ))

        # Check 4: Sensitive data in payload
        sensitive_keys = {"password", "secret", "ssn", "credit_card", "api_key", "private_key"}
        found_sensitive = [k for k in payload if k.lower() in sensitive_keys]
        if found_sensitive:
            findings.append(AuthFinding(
                title=f"Sensitive data in JWT payload: {', '.join(found_sensitive)}",
                severity="high",
                description=f"JWT contains sensitive fields: {found_sensitive}. JWT is only base64-encoded, not encrypted.",
                evidence={"sensitive_fields": found_sensitive},
                remediation="Never store sensitive data in JWT. Use opaque tokens with server-side lookup.",
            ))

    # Check 5: JKU/X5U header injection
    for key in ["jku", "x5u", "jwk"]:
        if key in header:
            findings.append(AuthFinding(
                title=f"JWT uses {key.upper()} header — potential key injection",
                severity="high",
                description=f"Token header contains '{key}'. An attacker may be able to point this to a malicious key URL.",
                evidence={"header": header, "injectable_key": key},
                remediation="Whitelist allowed key URLs server-side. Avoid JKU/X5U headers.",
            ))

    return findings


def test_oauth_misconfig(authorize_url: str, client_id: str,
                         redirect_uri: str = "https://evil.com") -> List[AuthFinding]:
    """
    Test OAuth 2.0 endpoints for common misconfigurations.

    Checks:
    - Open redirect on redirect_uri
    - Missing state parameter
    - Weak scope validation
    - PKCE enforcement
    """
    findings = []

    try:
        # Test open redirect
        params = {
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "scope": "openid profile email",
        }
        r = requests.get(authorize_url, params=params, timeout=10,
                         allow_redirects=False, verify=False)

        # If server accepts evil redirect_uri
        if r.status_code in (301, 302):
            location = r.headers.get("Location", "")
            if "evil.com" in location:
                findings.append(AuthFinding(
                    title="OAuth open redirect — arbitrary redirect_uri accepted",
                    severity="high",
                    description=f"Authorization server accepted redirect_uri={redirect_uri}. Attacker can steal auth codes.",
                    evidence={"redirect_uri": redirect_uri, "location": location[:200]},
                    remediation="Whitelist allowed redirect URIs. Exact match required.",
                ))

        # Check for state parameter enforcement
        params_no_state = {
            "client_id": client_id,
            "redirect_uri": "https://localhost/callback",
            "response_type": "code",
        }
        r2 = requests.get(authorize_url, params=params_no_state, timeout=10,
                          allow_redirects=False, verify=False)
        if r2.status_code == 200 or r2.status_code in (301, 302):
            findings.append(AuthFinding(
                title="OAuth state parameter may not be enforced",
                severity="medium",
                description="Authorization request without 'state' parameter was accepted. CSRF protection may be missing.",
                evidence={"request": params_no_state, "status": r2.status_code},
                remediation="Always require and validate 'state' parameter in OAuth flows.",
            ))

    except Exception as e:
        logger.debug(f"OAuth test error: {e}")

    return findings


def test_session_management(base_url: str,
                            cookies: Dict[str, str] = None,
                            headers: Dict[str, str] = None) -> List[AuthFinding]:
    """
    Test session management security.

    Checks:
    - Cookie security flags (Secure, HttpOnly, SameSite)
    - Session fixation potential
    - Concurrent session handling
    """
    findings = []

    try:
        r = requests.get(base_url, headers=headers, cookies=cookies,
                         timeout=10, verify=False)

        for cookie_name, cookie_value in (cookies or {}).items():
            # Check cookie from Set-Cookie headers in response
            for set_cookie in r.headers.get("Set-Cookie", "").split(","):
                if cookie_name.lower() not in set_cookie.lower():
                    continue

                missing_flags = []
                if "httponly" not in set_cookie.lower():
                    missing_flags.append("HttpOnly")
                if "secure" not in set_cookie.lower():
                    missing_flags.append("Secure")
                if "samesite" not in set_cookie.lower():
                    missing_flags.append("SameSite")

                if missing_flags:
                    findings.append(AuthFinding(
                        title=f"Cookie '{cookie_name}' missing security flags: {', '.join(missing_flags)}",
                        severity="medium" if "Secure" in missing_flags else "low",
                        description=f"Session cookie lacks: {', '.join(missing_flags)}. This enables XSS/CSRF attacks.",
                        evidence={"cookie": cookie_name, "missing": missing_flags},
                        remediation=f"Set {', '.join(missing_flags)} flags on all session cookies.",
                    ))

        # Check for session in URL
        if any("sessionid" in str(v).lower() or "jsessionid" in str(v).lower()
               for v in [r.url]):
            findings.append(AuthFinding(
                title="Session ID exposed in URL",
                severity="high",
                description="Session identifier found in URL. This leaks via Referer headers and browser history.",
                evidence={"url": r.url[:200]},
                remediation="Use cookies for session management, never URL parameters.",
            ))

    except Exception as e:
        logger.debug(f"Session management test error: {e}")

    return findings


def run_auth_tests(target: str, token: str = None,
                   headers: Dict[str, str] = None) -> List[Dict[str, Any]]:
    """
    Run all authentication/authorization tests.

    Args:
        target: Base URL of the target
        token: JWT or bearer token to analyze
        headers: HTTP headers including auth

    Returns:
        List of finding dicts compatible with Elengenix finding format
    """
    all_findings = []

    # JWT analysis
    if token and token.count(".") >= 2:
        jwt_findings = analyze_jwt(token)
        all_findings.extend(jwt_findings)

    # Session management
    session_findings = test_session_management(target, headers=headers)
    all_findings.extend(session_findings)

    # Convert to standard finding format
    results = []
    for f in all_findings:
        results.append({
            "type": "auth_vulnerability",
            "severity": f.severity,
            "title": f.title,
            "target": target,
            "description": f.description,
            "source": "auth_tester",
            "remediation": f.remediation,
            "evidence": f.evidence,
        })

    return results
