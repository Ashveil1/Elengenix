"""elengenix.auth.sessions — Signed-cookie sessions.

This module ports PentAGI's cookie-store session logic (Gin
``sessions.Default`` + ``gorilla/securecookie``) to Python using
``itsdangerous.URLSafeTimedSerializer`` for the signed-cookie primitive.

Session fields mirror the keys set in
``backend/pkg/server/services/auth.go``::

    session.Set("uid",    user.ID)
    session.Set("uhash",  user.Hash)
    session.Set("rid",    user.RoleID)
    session.Set("tid",    userType.String())   // "local" | "oauth" | "api"
    session.Set("prm",    privileges)
    session.Set("gtm",    time.Now().Unix())    // issued-at
    session.Set("exp",    now + ttl)            // expiration (Unix seconds)
    session.Set("uuid",   userUuid)
    session.Set("uname",  user.Name)

Sliding-window refresh: after ``SESSION_REFRESH_THRESHOLD_SECONDS``
(default 5 minutes), a new cookie with the full TTL is reissued.
Matches the Go middleware in ``auth.go::Info``::

    if now >= gtm + 5*60 && c.Query("refresh_cookie") != "false" {
        s.refreshCookie(c, &resp, privs)
    }

Cookie attributes:

* ``HttpOnly=True``        — JavaScript cannot read the cookie.
* ``SameSite=Lax`` (default) — works for GitHub OAuth GET callback.
* ``SameSite=None``        — required for Google OAuth ``form_post``
  callback (set ``force_samesite_none=True`` on the relevant response).
* ``Secure``               — derived from the request's
  ``X-Forwarded-Proto: https`` header or the underlying TLS state.

Design constraints:

* Python 3.10+, 4-space indent, line-length 100.
* Lazy import of ``itsdangerous`` so the module is importable for
  AST inspection in CLI-only environments.
"""

from __future__ import annotations

import logging
import time
from typing import Any, Callable, Optional, Protocol, TypedDict

logger = logging.getLogger("elengenix.auth.sessions")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_SESSION_TTL_SECONDS: int = 14_400  # 4 hours (matches PentAGI default)

# After this many seconds since issuance, the cookie is eligible for a
# sliding refresh (matches PentAGI's 5-minute threshold in auth.go::Info).
SESSION_REFRESH_THRESHOLD_SECONDS: int = 300

# Cookie name (matches PentAGI's gorilla/securecookie default).
DEFAULT_COOKIE_NAME: str = "session"

# Cookie path — defaults to the API base URL prefix.
DEFAULT_COOKIE_PATH: str = "/"

# Signer salt — must NOT change (cross-language interop with gorilla).
# NOTE: gorilla/securecookie uses a different wire format than
# itsdangerous, so cross-language cookie interop is **not** achievable
# without re-implementing the gorilla format. The signer salt below is
# used purely within the Python stack.
_SIGNER_SALT: str = "pentagi.cookie.auth"


class SessionData(TypedDict, total=False):
    """Typed view of the cookie session payload.

    All fields mirror the keys set by PentAGI's Go middleware.
    """

    uid: int           # User ID
    uhash: str         # User hash (installation binding)
    rid: int           # Role ID
    tid: str           # Token/session type: "local" | "oauth" | "api"
    prm: list[str]     # Privileges
    gtm: int           # Issued-at (Unix seconds)
    exp: int           # Expiration (Unix seconds)
    uuid: str          # Stable user UUID (derived from uhash)
    uname: str         # User display name


class UserHashProvider(Protocol):
    """Protocol for the user-hash lookup callback.

    A callable that returns ``(hash, status)`` for a given user ID, or
    raises ``KeyError`` if the user does not exist. ``status`` is one of
    ``"created"``, ``"active"``, ``"blocked"`` (see ``models.py``).
    """

    def __call__(self, user_id: int) -> tuple[str, str]: ...


# ---------------------------------------------------------------------------
# Lazy itsdangerous import + serializer factory
# ---------------------------------------------------------------------------

_serializer_cache: dict[str, Any] = {}


def _get_serializer(secret_key: str) -> Any:
    """Return a cached ``URLSafeTimedSerializer`` for the given key."""
    try:
        from itsdangerous import URLSafeTimedSerializer
    except ImportError as exc:  # pragma: no cover
        raise ImportError(
            "elengenix.auth.sessions requires itsdangerous — install with "
            "'pip install itsdangerous'"
        ) from exc

    cache_key = f"{secret_key}:{_SIGNER_SALT}"
    if cache_key in _serializer_cache:
        return _serializer_cache[cache_key]

    serializer = URLSafeTimedSerializer(secret_key, salt=_SIGNER_SALT)
    _serializer_cache[cache_key] = serializer
    return serializer


# ---------------------------------------------------------------------------
# Session cookie creation / validation
# ---------------------------------------------------------------------------

def create_session_cookie(
    user: Any,
    secret_key: str,
    ttl_seconds: int = DEFAULT_SESSION_TTL_SECONDS,
    *,
    privileges: Optional[list[str]] = None,
    tid: str = "local",
    uuid: str = "",
) -> str:
    """Create a signed session cookie for the given user.

    Args:
        user: User-like object exposing ``id``, ``hash``, ``role_id``,
            ``name``, and (optionally) ``email`` attributes. Also
            accepts a ``dict`` with the same keys (camelCase or
            snake_case).
        secret_key: Server-wide secret used to sign the cookie.
        ttl_seconds: Cookie/session lifetime in seconds (default 4h).
        privileges: Privilege strings to embed in the session.
        tid: Token/session type — ``"local"`` (default) or ``"oauth"``.
        uuid: Stable user UUID (derived from the user hash externally).

    Returns:
        Signed cookie value string suitable for ``Set-Cookie``.
    """
    if not secret_key:
        raise ValueError("secret_key must be a non-empty string")

    uid = _attr(user, "id")
    uhash = _attr(user, "hash")
    rid = _attr(user, "role_id", default=0)
    uname = _attr(user, "name", default="")

    now = int(time.time())
    data: SessionData = {
        "uid": int(uid),
        "uhash": str(uhash),
        "rid": int(rid),
        "tid": tid,
        "prm": list(privileges or []),
        "gtm": now,
        "exp": now + int(ttl_seconds),
        "uuid": uuid,
        "uname": str(uname),
    }

    serializer = _get_serializer(secret_key)
    cookie_value = serializer.dumps(data)
    logger.debug(
        "created session cookie uid=%d tid=%s exp=%d ttl=%d",
        data["uid"], data["tid"], data["exp"], ttl_seconds,
    )
    return cookie_value


def validate_session_cookie(
    cookie: str,
    secret_key: str,
    user_hash_provider: Optional[Callable[[int], tuple[str, str]]] = None,
    *,
    max_age_seconds: Optional[int] = None,
) -> Optional[dict]:
    """Validate a signed session cookie and return its payload.

    Mirrors PentAGI's ``tryUserCookieAuthentication`` middleware:

    1. Verify the cookie signature (``itsdangerous`` HMAC + timestamp).
    2. Check the session ``exp`` field hasn't passed.
    3. If a ``user_hash_provider`` callback is supplied, fetch the
       current ``(hash, status)`` and verify the user is still
       ``active`` and that the hash matches the cookie's ``uhash``
       (blocks session reuse after password change / block).
    4. Return the decoded session dict on success, ``None`` otherwise.

    Args:
        cookie: Raw cookie value from the ``Cookie`` header.
        secret_key: Server-wide secret used to sign the cookie.
        user_hash_provider: Optional callback ``(uid) -> (hash, status)``
            used to verify the user is still active and the hash matches.
            Raises ``KeyError`` if the user does not exist.
        max_age_seconds: Optional override for the cookie freshness
            window (defaults to no itsdangerous-side max_age check —
            the session ``exp`` field is authoritative).

    Returns:
        Decoded session dict on success, ``None`` on any failure.
    """
    if not cookie or not secret_key:
        return None

    try:
        from itsdangerous import BadSignature, SignatureExpired
    except ImportError as exc:  # pragma: no cover
        raise ImportError(
            "elengenix.auth.sessions requires itsdangerous — install with "
            "'pip install itsdangerous'"
        ) from exc

    serializer = _get_serializer(secret_key)
    try:
        if max_age_seconds is not None:
            data = serializer.loads(cookie, max_age=max_age_seconds)
        else:
            data = serializer.loads(cookie)
    except SignatureExpired:
        logger.debug("session cookie signature expired")
        return None
    except BadSignature:
        logger.debug("session cookie signature invalid")
        return None

    if not isinstance(data, dict):
        return None

    # Required fields check (matches the Go middleware's nil-check loop).
    required = ("uid", "uhash", "rid", "tid", "prm", "exp", "gtm", "uname")
    for field in required:
        if data.get(field) is None:
            logger.debug("session cookie missing field %s", field)
            return None

    # Verify session expiration.
    exp = int(data["exp"])
    if time.time() > exp:
        logger.debug("session expired (exp=%d)", exp)
        return None

    # Verify user hash + status via the callback (when supplied).
    if user_hash_provider is not None:
        uid = int(data["uid"])
        try:
            db_hash, status = user_hash_provider(uid)
        except KeyError:
            logger.info("session user uid=%d not found", uid)
            return None
        except Exception:  # pragma: no cover — defensive
            logger.exception("user_hash_provider raised")
            return None

        if status == "blocked":
            logger.info("session user uid=%d blocked", uid)
            return None
        if status == "created":
            logger.info("session user uid=%d not ready (status=created)", uid)
            return None
        if db_hash != data["uhash"]:
            logger.info(
                "session hash mismatch for uid=%d — installation binding revoked",
                uid,
            )
            return None

    return data


# ---------------------------------------------------------------------------
# Sliding refresh
# ---------------------------------------------------------------------------

def should_refresh(session: dict) -> bool:
    """Return True when the session is eligible for a sliding refresh.

    Matches the Go condition::

        now >= gtm + 5*60
    """
    gtm = int(session.get("gtm", 0))
    return time.time() >= gtm + SESSION_REFRESH_THRESHOLD_SECONDS


def refresh_session_cookie(
    session: dict,
    secret_key: str,
    ttl_seconds: int = DEFAULT_SESSION_TTL_SECONDS,
) -> str:
    """Reissue a session cookie with the full TTL (sliding refresh).

    Preserves ``uid``, ``uhash``, ``rid``, ``tid``, ``prm``, ``uname``,
    ``uuid`` from the existing session. Updates ``gtm`` to ``now`` and
    ``exp`` to ``now + ttl_seconds``.

    Args:
        session: Validated session dict from :func:`validate_session_cookie`.
        secret_key: Server-wide secret.
        ttl_seconds: New TTL (default 4h).

    Returns:
        New signed cookie value.
    """
    now = int(time.time())
    refreshed: SessionData = {
        "uid": int(session["uid"]),
        "uhash": str(session["uhash"]),
        "rid": int(session["rid"]),
        "tid": str(session["tid"]),
        "prm": list(session.get("prm", [])),
        "gtm": now,
        "exp": now + int(ttl_seconds),
        "uuid": str(session.get("uuid", "")),
        "uname": str(session.get("uname", "")),
    }
    serializer = _get_serializer(secret_key)
    return serializer.dumps(refreshed)


# ---------------------------------------------------------------------------
# Cookie attribute helpers
# ---------------------------------------------------------------------------

def cookie_attributes(
    *,
    secure: bool,
    samesite: str = "lax",
    path: str = DEFAULT_COOKIE_PATH,
    ttl_seconds: int = DEFAULT_SESSION_TTL_SECONDS,
    httponly: bool = True,
) -> dict:
    """Build the ``Set-Cookie`` attribute dict for FastAPI responses.

    Args:
        secure: ``True`` if the request was HTTPS (set ``Secure`` flag).
        samesite: ``"lax"`` (default) or ``"none"`` (Google OAuth).
        path: Cookie path (defaults to the API base URL).
        ttl_seconds: Cookie lifetime in seconds.
        httponly: Whether to set ``HttpOnly`` (default ``True``).

    Returns:
        Dict suitable for ``response.set_cookie(**attrs)``.
    """
    samesite = samesite.lower()
    if samesite not in {"lax", "strict", "none"}:
        raise ValueError(f"invalid samesite={samesite!r}")

    return {
        "key": DEFAULT_COOKIE_NAME,
        "httponly": httponly,
        "secure": secure,
        "samesite": samesite,  # FastAPI accepts "none"/"lax"/"strict"
        "path": path,
        "max_age": ttl_seconds,
    }


def is_https_request(request: Any) -> bool:
    """Detect HTTPS on a Starlette/FastAPI request.

    Considers both the underlying ``url.scheme`` and the
    ``X-Forwarded-Proto`` header (matches PentAGI's
    ``setCallbackCookie`` logic).
    """
    if request is None:
        return False
    # Starlette Request exposes .url.scheme
    try:
        scheme = request.url.scheme  # type: ignore[attr-defined]
        if scheme == "https":
            return True
    except AttributeError:
        pass
    # X-Forwarded-Proto (reverse proxy)
    try:
        forwarded = request.headers.get("x-forwarded-proto", "")  # type: ignore[attr-defined]
        if forwarded.split(",")[0].strip().lower() == "https":
            return True
    except AttributeError:
        pass
    return False


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _attr(obj: Any, name: str, default: Any = None) -> Any:
    """Read an attribute from either an object or a dict (snake/camel)."""
    if isinstance(obj, dict):
        # Try snake_case first, then camelCase.
        if name in obj:
            return obj[name]
        camel = "".join(
            word.capitalize() if i else word
            for i, word in enumerate(name.split("_"))
        )
        return obj.get(camel, default)
    return getattr(obj, name, default)


__all__ = [
    "SessionData",
    "UserHashProvider",
    "DEFAULT_SESSION_TTL_SECONDS",
    "SESSION_REFRESH_THRESHOLD_SECONDS",
    "DEFAULT_COOKIE_NAME",
    "DEFAULT_COOKIE_PATH",
    "create_session_cookie",
    "validate_session_cookie",
    "should_refresh",
    "refresh_session_cookie",
    "cookie_attributes",
    "is_https_request",
]
