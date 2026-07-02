"""tools/auth_session.py

Authenticated testing support for the hunt engine.

Capabilities:
    1. Auto-detect login endpoints
    2. Attempt login with common credential pairs
    3. Capture session cookies / JWT tokens
    4. Replay authenticated requests with credentials
    5. Multi-user BOLA testing (login as 2 users, attempt cross-access)

This unlocks detection of:
    - Authenticated-only endpoints (admin panels, user settings)
    - BOLA / IDOR (compare user1 vs user2 access)
    - Broken function-level authorization (BFLA)
    - JWT issuance/validation flaws
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

try:
    import aiohttp
except ImportError:
    aiohttp = None  # type: ignore[assignment]

logger = logging.getLogger("elengenix.auth")


# ═══════════════════════════════════════════════════════════════════════════
# CREDENTIALS
# ═══════════════════════════════════════════════════════════════════════════

# Common credential pairs to try (low-noise, top targets)
COMMON_CREDENTIALS = [
    ("admin", "admin"),
    ("admin", "admin123"),
    ("admin", "password"),
    ("admin", "changeme"),
    ("administrator", "administrator"),
    ("root", "root"),
    ("root", "toor"),
    ("test", "test"),
    ("guest", "guest"),
    ("user", "user"),
    ("user", "password"),
    ("demo", "demo"),
    ("alice", "alice"),
    ("alice", "alice123"),
    ("bob", "bob"),
    ("bob", "bob123"),
]


# ═══════════════════════════════════════════════════════════════════════════
# SESSION DATA
# ═══════════════════════════════════════════════════════════════════════════


@dataclass
class AuthSession:
    """Authenticated session — cookies + headers."""

    username: str
    cookies: Dict[str, str] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)
    jwt_token: str = ""
    api_key: str = ""
    user_id: int = 0  # User ID from login response
    role: str = ""  # User role (admin/user/etc)
    authenticated_via: str = ""  # login endpoint URL
    evidence: str = ""  # what we got (token, session id)

    def auth_headers(self) -> Dict[str, str]:
        """Return all auth-related headers for use in requests."""
        h = dict(self.headers)
        if self.jwt_token:
            h["Authorization"] = f"Bearer {self.jwt_token}"
        return h


# ═══════════════════════════════════════════════════════════════════════════
# LOGIN FLOW
# ═══════════════════════════════════════════════════════════════════════════

# Endpoint patterns that look like login
LOGIN_PATH_HINTS = [
    "login",
    "signin",
    "auth",
    "authenticate",
    "session",
    "token",
    "api/auth",
    "/auth/",
    "api/login",
]


async def try_login(
    session: aiohttp.ClientSession,
    base_url: str,
    login_url: str,
    username: str,
    password: str,
) -> Optional[AuthSession]:
    """Attempt login with given credentials. Returns AuthSession if successful."""
    auth_session = AuthSession(username=username)

    # Try multiple login payload shapes
    payload_variants = [
        # JSON
        {"username": username, "password": password},
        {"user": username, "password": password},
        {"email": username, "password": password},
        {"login": username, "password": password},
        # Form-encoded (typical for HTML login)
        {"username": username, "password": password},
    ]
    content_types = ["application/json", "application/x-www-form-urlencoded"]

    for payload in payload_variants:
        for ct in content_types:
            try:
                if ct == "application/json":
                    async with session.post(login_url, json=payload) as r:
                        status = r.status
                        body = await r.text()
                        # Capture cookies
                        for c in r.cookies.values():
                            if c.value:
                                auth_session.cookies[c.key] = c.value
                        # Capture Set-Cookie headers
                        for h_name, h_val in r.headers.items():
                            if h_name.lower() == "set-cookie":
                                # Parse cookie
                                cookie_part = h_val.split(";")[0]
                                if "=" in cookie_part:
                                    k, v = cookie_part.split("=", 1)
                                    auth_session.cookies[k.strip()] = v.strip()
                else:
                    async with session.post(login_url, data=payload) as r:
                        status = r.status
                        body = await r.text()
                        for c in r.cookies.values():
                            if c.value:
                                auth_session.cookies[c.key] = c.value

                # Check for tokens in response
                try:
                    j = json.loads(body)
                    # Look for tokens/keys in common fields
                    for key in (
                        "token",
                        "access_token",
                        "jwt",
                        "session",
                        "session_token",
                        "sessionId",
                        "auth_token",
                        "api_key",
                        "apikey",
                    ):
                        if key in j and isinstance(j[key], str) and len(j[key]) >= 4:
                            token = j[key]
                            if token.count(".") == 2 and "." in token:
                                # JWT-like (three base64 segments)
                                auth_session.jwt_token = token
                                auth_session.evidence = f"JWT in '{key}' field"
                            else:
                                # Opaque token / session id — use as cookie
                                auth_session.cookies["session_id"] = token
                                auth_session.evidence = f"session token in '{key}' field"
                    # Or check user object for token, id, role
                    user = j.get("user", {})
                    if isinstance(user, dict):
                        for key in ("token", "session_token", "sessionId"):
                            if key in user and isinstance(user[key], str):
                                auth_session.cookies["session_id"] = str(user[key])
                                auth_session.evidence = f"session token in user.{key}"
                        # Capture user ID and role for BOLA testing
                        if "id" in user:
                            try:
                                auth_session.user_id = int(user["id"])
                            except (TypeError, ValueError):
                                pass
                        if "role" in user:
                            auth_session.role = str(user["role"])
                except Exception:
                    pass

                # Success indicators
                if status == 200 and (auth_session.cookies or auth_session.jwt_token):
                    auth_session.authenticated_via = login_url
                    return auth_session
                elif status == 302:
                    auth_session.authenticated_via = login_url
                    return auth_session
                # Status 200 with "ok" status in body
                elif (
                    status == 200 and body and ('"status":"ok"' in body or '"success":true' in body)
                ):
                    # Even without token, mark as authenticated if status indicates it
                    if auth_session.cookies or auth_session.jwt_token:
                        auth_session.authenticated_via = login_url
                        return auth_session

            except Exception as e:
                logger.debug("login attempt %s/%s failed: %s", username, ct, e)
                continue

    return None


async def discover_and_login(
    session: aiohttp.ClientSession,
    base_url: str,
    endpoints: List[Any],  # List[Endpoint] — avoid circular import
    credentials: List[Tuple[str, str]] = None,
) -> List[AuthSession]:
    """Try to authenticate against any discovered login endpoint.

    Returns list of successful AuthSession objects (one per valid credential).
    """
    credentials = credentials or COMMON_CREDENTIALS
    sessions: List[AuthSession] = []
    seen_users: Set[str] = set()

    # Find candidate login endpoints
    login_urls: List[str] = []
    for ep in endpoints:
        for hint in LOGIN_PATH_HINTS:
            if hint in ep.url and ep.url not in login_urls:
                login_urls.append(ep.url)
                break

    # Also try common paths
    for hint in (
        "/login",
        "/api/login",
        "/auth/login",
        "/api/auth/login",
        "/api/auth",
        "/api/token",
        "/oauth/token",
    ):
        url = base_url.rstrip("/") + hint
        if url not in login_urls:
            login_urls.append(url)

    # Try each login endpoint with each credential pair
    for login_url in login_urls:
        for username, password in credentials:
            if username in seen_users:
                continue
            try:
                auth = await try_login(session, base_url, login_url, username, password)
                if auth and (auth.cookies or auth.jwt_token or auth.api_key):
                    sessions.append(auth)
                    seen_users.add(username)
                    logger.info("[OK] Authenticated as '%s' via %s", username, login_url)
            except Exception as e:
                logger.debug("auth attempt %s @ %s: %s", username, login_url, e)

    return sessions


# ═══════════════════════════════════════════════════════════════════════════
# AUTHENTICATED REQUEST HELPER
# ═══════════════════════════════════════════════════════════════════════════


async def authenticated_get(
    session: aiohttp.ClientSession,
    url: str,
    auth: AuthSession,
) -> Tuple[int, str, Dict[str, str]]:
    """Make an authenticated GET. Returns (status, body, headers)."""
    headers = auth.auth_headers()
    async with session.get(url, headers=headers, cookies=auth.cookies) as r:
        body = await r.text()
        return r.status, body, dict(r.headers)


async def authenticated_post(
    session: aiohttp.ClientSession,
    url: str,
    data: Any,
    auth: AuthSession,
    json_data: bool = True,
) -> Tuple[int, str, Dict[str, str]]:
    """Make an authenticated POST."""
    headers = auth.auth_headers()
    if json_data:
        async with session.post(url, json=data, headers=headers, cookies=auth.cookies) as r:
            body = await r.text()
            return r.status, body, dict(r.headers)
    else:
        async with session.post(url, data=data, headers=headers, cookies=auth.cookies) as r:
            body = await r.text()
            return r.status, body, dict(r.headers)


# ═══════════════════════════════════════════════════════════════════════════
# BOLA / IDOR WITH TWO SESSIONS
# ═══════════════════════════════════════════════════════════════════════════


async def test_bola_with_sessions(
    session: aiohttp.ClientSession,
    endpoint_url: str,
    auth_a: AuthSession,
    auth_b: AuthSession,
) -> Optional[Dict[str, Any]]:
    """Test BOLA: does user A see user B's data?

    Returns evidence dict if BOLA found.
    """
    # User A accesses their own resource
    # User B accesses user A's resource by manipulating the ID
    try:
        # Extract ID from URL
        m = re.search(r"/(\d+)/?$", endpoint_url)
        if not m:
            return None
        victim_id = m.group(1)
        # As attacker (auth_b), access victim (auth_a)'s resource
        attacker_url = re.sub(r"/\d+/?$", f"/{victim_id}", endpoint_url)
        status_b, body_b, _ = await authenticated_get(session, attacker_url, auth_b)
        # If attacker can see victim's data, BOLA
        if status_b == 200 and body_b:
            # Try to access as victim for comparison
            status_a, body_a, _ = await authenticated_get(session, endpoint_url, auth_a)
            if status_a == 200 and body_a != body_b:
                # Different responses mean attacker sees different data
                # Check if body contains fields that look like victim's data
                if any(s in body_b.lower() for s in ("user", "id", "email", "name")):
                    return {
                        "victim_url": endpoint_url,
                        "attacker_url": attacker_url,
                        "victim_session": auth_a.username,
                        "attacker_session": auth_b.username,
                        "victim_response_excerpt": body_a[:300],
                        "attacker_response_excerpt": body_b[:300],
                    }
    except Exception as e:
        logger.debug("BOLA test failed: %s", e)
    return None
