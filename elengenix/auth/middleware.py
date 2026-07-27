"""elengenix.auth.middleware — FastAPI auth dependencies.

This module exposes FastAPI dependencies / callables that mirror
PentAGI's three auth-middleware variants plus the privilege-check
helper:

* :func:`try_auth`             — auth optional: attach identity if a
  valid Bearer token or session cookie is present (ports ``TryAuth``).
* :func:`auth_token_required`  — auth mandatory: 401 if neither a
  valid Bearer token nor a session cookie is present (ports
  ``AuthTokenRequired`` — accepts API tokens).
* :func:`auth_user_required`   — auth mandatory: 401 if no interactive
  session (API tokens rejected) (ports ``AuthUserRequired`` — needed
  for password change, role/user management).
* :func:`local_user_required`  — rejects ``tid != "local"`` (ports
  ``localUserRequired`` — for password change only).
* :func:`privileges_required`  — dependency factory: 403 if any of the
  given privilege strings is not present in ``request.state.prm``
  (ports ``PrivilegesRequired``).

Permission enforcement is a simple ``in`` check on the privilege list
(``slices.Contains`` in Go), matching the PentAGI convention of dotted
namespaces like ``users.*``, ``roles.*``, ``settings.user.*``,
``settings.tokens.*``, ``pentagi.automation``. API tokens automatically
receive the ``pentagi.automation`` privilege.

The dependency functions store the resolved identity on
``request.state`` for downstream handlers:

* ``request.state.uid``    — user ID (int)
* ``request.state.uhash``  — user hash (str)
* ``request.state.rid``    — role ID (int)
* ``request.state.tid``    — token/session type ("local"|"oauth"|"api")
* ``request.state.prm``    — list[str] of privileges
* ``request.state.gtm``    — issued-at Unix timestamp
* ``request.state.exp``    — expiration Unix timestamp
* ``request.state.uuid``   — stable user UUID (str, may be "")
* ``request.state.uname``  — user display name (str)
* ``request.state.cpt``    — "automation" when pentagi.automation is in prm

Design constraints:

* Python 3.10+, 4-space indent, line-length 100.
* Lazy import of ``fastapi``, ``starlette`` so this module is importable
  for AST inspection in CLI-only environments.
* All dependencies are async — FastAPI supports both sync and async
  deps, but the PentAGI middleware performs DB I/O so async is the
  natural choice.
"""

from __future__ import annotations

import logging
from typing import Any, Awaitable, Callable, Optional

from elengenix.auth.models import (
    TOKEN_STATUS_ACTIVE,
    USER_STATUS_ACTIVE,
    USER_STATUS_BLOCKED,
    USER_TYPE_API,
)
from elengenix.auth.sessions import (
    DEFAULT_COOKIE_NAME,
    validate_session_cookie,
)
from elengenix.auth.tokens import (
    token_status_cache,
    validate_token,
)

logger = logging.getLogger("elengenix.auth.middleware")

# Re-export the privilege string at module scope for callers that want
# ``from elengenix.auth.middleware import PRIVILEGE_AUTOMATION``.
# Matches PentAGI's ``const PrivilegeAutomation = "pentagi.automation"``
# from backend/pkg/server/auth/auth_middleware.go.
PRIVILEGE_AUTOMATION: str = "pentagi.automation"

# Privilege namespaces that API tokens are filtered out from (matches
# the Go middleware in services/auth.go::Info).
_API_TOKEN_FORBIDDEN_PREFIXES: tuple[str, ...] = (
    "users.",
    "roles.",
    "settings.user.",
    "settings.tokens.",
)


# ---------------------------------------------------------------------------
# Configuration — registered by the FastAPI app at startup
# ---------------------------------------------------------------------------

class AuthMiddlewareConfig:
    """Process-wide auth configuration.

    Set once at app startup via :func:`configure_auth_middleware`.
    """

    def __init__(self) -> None:
        self.global_salt: str = ""
        self.session_secret_key: str = ""
        self.user_hash_provider: Optional[Callable[[int], tuple[str, str]]] = None

    @property
    def is_configured(self) -> bool:
        return bool(self.global_salt) and bool(self.session_secret_key)


_config: AuthMiddlewareConfig = AuthMiddlewareConfig()


def configure_auth_middleware(
    *,
    global_salt: str,
    session_secret_key: str,
    user_hash_provider: Optional[Callable[[int], tuple[str, str]]] = None,
) -> None:
    """Register global auth configuration.

    Args:
        global_salt: Server-wide salt for JWT key derivation.
        session_secret_key: Secret key for signing session cookies.
        user_hash_provider: Optional callback ``(uid) -> (hash, status)``
            used to verify users are still active. Raises ``KeyError``
            if the user does not exist.
    """
    _config.global_salt = global_salt
    _config.session_secret_key = session_secret_key
    _config.user_hash_provider = user_hash_provider
    logger.debug(
        "auth middleware configured (salt_len=%d, has_user_hash_provider=%s)",
        len(global_salt), user_hash_provider is not None,
    )


def get_auth_config() -> AuthMiddlewareConfig:
    """Return the process-wide :class:`AuthMiddlewareConfig`."""
    return _config


# ---------------------------------------------------------------------------
# Identity attachment
# ---------------------------------------------------------------------------

class AuthIdentity:
    """Resolved identity attached to ``request.state.identity``.

    Plain-Python container (no Pydantic dependency) so it can be
    constructed in middleware without importing Pydantic.
    """

    __slots__ = (
        "uid", "uhash", "rid", "tid", "prm", "gtm", "exp",
        "uuid", "uname", "cpt",
    )

    def __init__(
        self,
        *,
        uid: int,
        uhash: str,
        rid: int,
        tid: str,
        prm: list[str],
        gtm: int,
        exp: int,
        uuid: str = "",
        uname: str = "",
        cpt: Optional[str] = None,
    ) -> None:
        self.uid = uid
        self.uhash = uhash
        self.rid = rid
        self.tid = tid
        self.prm = list(prm)
        self.gtm = gtm
        self.exp = exp
        self.uuid = uuid
        self.uname = uname
        self.cpt = cpt

    def to_request_state(self, request: Any) -> None:
        """Copy all fields onto ``request.state`` for downstream use."""
        state = request.state
        state.uid = self.uid
        state.uhash = self.uhash
        state.rid = self.rid
        state.tid = self.tid
        state.prm = self.prm
        state.gtm = self.gtm
        state.exp = self.exp
        state.uuid = self.uuid
        state.uname = self.uname
        state.cpt = self.cpt or ""
        state.identity = self

    def __repr__(self) -> str:  # pragma: no cover
        return (
            f"AuthIdentity(uid={self.uid!r}, tid={self.tid!r}, "
            f"rid={self.rid!r}, prm_count={len(self.prm)})"
        )


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _extract_bearer_token(request: Any) -> Optional[str]:
    """Pull the Bearer token from the ``Authorization`` header.

    Returns ``None`` if the header is missing or doesn't use the
    ``Bearer`` scheme (mirrors the Go ``tryProtoTokenAuthentication``).
    """
    try:
        header = request.headers.get("authorization", "")  # type: ignore[attr-defined]
    except AttributeError:
        return None
    if not header:
        return None
    if not header.lower().startswith("bearer "):
        return None
    token = header[7:].strip()
    return token or None


def _extract_session_cookie(request: Any) -> Optional[str]:
    """Pull the session cookie from the ``Cookie`` header."""
    try:
        cookie_value = request.cookies.get(DEFAULT_COOKIE_NAME)  # type: ignore[attr-defined]
    except AttributeError:
        return None
    return cookie_value or None


def _attach_token_identity(
    request: Any,
    claims: Any,
) -> AuthIdentity:
    """Build an :class:`AuthIdentity` from validated JWT claims.

    Applies the PentAGI rule: API tokens automatically receive the
    ``pentagi.automation`` privilege and have their privileges filtered
    to remove ``users.*``, ``roles.*``, ``settings.user.*``,
    ``settings.tokens.*`` (cannot self-manage).
    """
    # Look up the token's privileges via the shared token-status cache.
    cached = token_status_cache.get(claims.tid)
    base_privs: list[str] = []
    if cached and cached.get("status") == TOKEN_STATUS_ACTIVE:
        base_privs = list(cached.get("privileges", []))

    # Always append the automation privilege (matches Go behaviour).
    if PRIVILEGE_AUTOMATION not in base_privs:
        base_privs.append(PRIVILEGE_AUTOMATION)

    # Filter out self-management privileges for API tokens.
    prm = [
        p for p in base_privs
        if not any(p.startswith(prefix) for prefix in _API_TOKEN_FORBIDDEN_PREFIXES)
    ]

    identity = AuthIdentity(
        uid=int(claims.uid),
        uhash=str(claims.uhash),
        rid=int(claims.rid),
        tid=USER_TYPE_API,
        prm=prm,
        gtm=int(__import__("time").time()),
        exp=int(claims.exp),
        uuid="",
        uname="",
        cpt="automation" if PRIVILEGE_AUTOMATION in prm else None,
    )
    identity.to_request_state(request)
    return identity


def _attach_session_identity(
    request: Any,
    session: dict,
) -> AuthIdentity:
    """Build an :class:`AuthIdentity` from a validated session dict."""
    prm = list(session.get("prm", []))
    identity = AuthIdentity(
        uid=int(session["uid"]),
        uhash=str(session["uhash"]),
        rid=int(session["rid"]),
        tid=str(session["tid"]),
        prm=prm,
        gtm=int(session["gtm"]),
        exp=int(session["exp"]),
        uuid=str(session.get("uuid", "")),
        uname=str(session.get("uname", "")),
        cpt="automation" if PRIVILEGE_AUTOMATION in prm else None,
    )
    identity.to_request_state(request)
    return identity


def _clear_identity(request: Any) -> None:
    """Mark the request as unauthenticated (no identity attached)."""
    state = request.state
    state.identity = None
    state.uid = 0
    state.uhash = ""
    state.rid = 0
    state.tid = ""
    state.prm = []
    state.gtm = 0
    state.exp = 0
    state.uuid = ""
    state.uname = ""
    state.cpt = ""


# ---------------------------------------------------------------------------
# 401 / 403 helpers (lazy FastAPI import)
# ---------------------------------------------------------------------------

def _raise_http_error(status_code: int, detail: str) -> None:
    """Raise an HTTPException with the given status and detail.

    Lazy-imports ``fastapi`` so this module is importable without it.
    """
    try:
        from fastapi import HTTPException
    except ImportError as exc:  # pragma: no cover
        raise ImportError(
            "elengenix.auth.middleware requires fastapi — install with "
            "'pip install fastapi'"
        ) from exc
    raise HTTPException(status_code=status_code, detail=detail)


# ---------------------------------------------------------------------------
# Auth middleware variants
# ---------------------------------------------------------------------------

async def try_auth(request: Any) -> Optional[AuthIdentity]:
    """Best-effort auth: attach identity if a token/cookie is valid.

    Equivalent to PentAGI's ``TryAuth``. Does **not** raise 401 when
    no credentials are present — just attaches no identity.
    """
    return await _resolve_identity(request, mandatory=False)


async def auth_token_required(request: Any) -> AuthIdentity:
    """Mandatory auth: 401 if neither a Bearer token nor a session is valid.

    Equivalent to PentAGI's ``AuthTokenRequired`` — accepts both API
    tokens (Bearer) and interactive sessions (cookie).
    """
    return await _resolve_identity(request, mandatory=True)


async def auth_user_required(request: Any) -> AuthIdentity:
    """Mandatory interactive auth: 401 if no valid session (API tokens rejected).

    Equivalent to PentAGI's ``AuthUserRequired``. Used for endpoints
    that manage users, roles, or tokens — API tokens cannot self-
    manage (matches the Go filter in ``services/auth.go::Info``).
    """
    identity = await _resolve_identity(request, mandatory=True)
    if identity.tid == USER_TYPE_API:
        logger.info(
            "auth_user_required rejected API token for uid=%d", identity.uid
        )
        _raise_http_error(401, "interactive session required (API tokens rejected)")
    return identity


async def local_user_required(request: Any) -> AuthIdentity:
    """Reject ``tid != "local"`` (for password change only).

    Equivalent to PentAGI's ``localUserRequired`` middleware. The
    request must have already passed through :func:`auth_user_required`.
    """
    identity = await _resolve_identity(request, mandatory=True)
    if identity.tid == USER_TYPE_API:
        _raise_http_error(401, "interactive session required (API tokens rejected)")
    if identity.tid != "local":
        logger.info(
            "local_user_required rejected tid=%s for uid=%d",
            identity.tid, identity.uid,
        )
        _raise_http_error(
            403, "local user required (password change unavailable for OAuth users)"
        )
    return identity


async def _resolve_identity(
    request: Any,
    *,
    mandatory: bool,
) -> Optional[AuthIdentity]:
    """Resolve the identity from Bearer token first, then cookie.

    Mirrors the ordering in PentAGI's ``AuthTokenRequired``:

        tryAuth(c, mandatory, tryProtoTokenAuthentication, tryUserCookieAuthentication)

    For ``TryAuth`` (mandatory=False), no 401 is raised — the request
    simply has no identity attached.
    """
    if not _config.is_configured:
        # Dev bypass — no identity attached (matches the Go default-salt
        # behaviour where token validation is disabled).
        _clear_identity(request)
        if mandatory:
            _raise_http_error(
                401, "auth middleware not configured — set global_salt and "
                     "session_secret_key at startup"
            )
        return None

    # 1. Bearer token (JWT).
    bearer = _extract_bearer_token(request)
    if bearer:
        claims = validate_token(bearer, _config.global_salt)
        if claims is not None:
            # Verify the user is still active and the hash matches
            # (mirrors the Go user-cache check).
            if _config.user_hash_provider is not None:
                try:
                    db_hash, status = _config.user_hash_provider(int(claims.uid))
                except KeyError:
                    logger.info(
                        "token uid=%d rejected: user deleted", claims.uid
                    )
                    db_hash, status = None, USER_STATUS_BLOCKED
                except Exception:  # pragma: no cover — defensive
                    logger.exception("user_hash_provider raised")
                    db_hash, status = None, USER_STATUS_BLOCKED

                if status == USER_STATUS_BLOCKED:
                    if mandatory:
                        _raise_http_error(401, "user has been blocked")
                    _clear_identity(request)
                    return None
                if db_hash != claims.uhash:
                    logger.info(
                        "token uid=%d rejected: hash mismatch", claims.uid
                    )
                    if mandatory:
                        _raise_http_error(
                            401,
                            "user hash mismatch — token invalid for this "
                            "installation"
                        )
                    _clear_identity(request)
                    return None

            return _attach_token_identity(request, claims)
        # Token present but invalid — fall through to cookie if non-mandatory,
        # but raise 401 if mandatory (matches Go: tryProtoToken returns
        # authResultFail, the loop breaks on first non-skip result).
        if mandatory:
            # Try cookie before raising — matches Go's chained tryAuth.
            pass

    # 2. Session cookie.
    cookie = _extract_session_cookie(request)
    if cookie:
        session = validate_session_cookie(
            cookie,
            _config.session_secret_key,
            _config.user_hash_provider,
        )
        if session is not None:
            return _attach_session_identity(request, session)

    # No valid identity.
    _clear_identity(request)
    if mandatory:
        _raise_http_error(401, "authentication required")
    return None


# ---------------------------------------------------------------------------
# Privilege enforcement — dependency factory
# ---------------------------------------------------------------------------

def privileges_required(
    *privs: str,
) -> Callable[[Any], Awaitable[None]]:
    """Build a FastAPI dependency that enforces the given privileges.

    Equivalent to PentAGI's ``PrivilegesRequired(privs...)`` factory.
    The returned dependency:

    * Reads ``request.state.prm`` (populated by :func:`try_auth` /
      :func:`auth_token_required` / :func:`auth_user_required`).
    * Raises 401 if no identity is attached.
    * Raises 403 if any of ``privs`` is not present in ``prm``.

    Permission enforcement is a simple ``in`` check on the privilege
    list (matches Go's ``slices.Contains``). Dotted namespaces
    (``users.*``, ``roles.*``, ``settings.user.*``, ``settings.tokens.*``,
    ``pentagi.automation``) are checked literally — wildcards must be
    listed explicitly in the role's privilege set.

    Usage::

        @router.delete(
            "/tokens/{token_id}",
            dependencies=[
                Depends(auth_user_required),
                Depends(privileges_required("settings.tokens.admin")),
            ],
        )
        async def delete_token(token_id: str): ...
    """

    if not privs:
        raise ValueError("privileges_required() requires at least one privilege")

    required = list(privs)

    async def _dependency(request: Any) -> None:
        state = request.state
        prm: list[str] = getattr(state, "prm", []) or []
        if not prm:
            _raise_http_error(401, "authentication required")
        for priv in required:
            if priv not in prm:
                logger.info(
                    "privilege check failed: missing %r in prm=%r",
                    priv, prm,
                )
                _raise_http_error(403, f"privilege '{priv}' is not set")
        # All good — no return value.

    _dependency.__name__ = f"privileges_required[{','.join(required)}]"
    _dependency.__qualname__ = _dependency.__name__
    return _dependency


def lookup_permission(prm: list[str], perm: str) -> bool:
    """Return True if ``perm`` is in ``prm`` (ports ``LookupPerm``)."""
    return perm in prm


__all__ = [
    "AuthIdentity",
    "AuthMiddlewareConfig",
    "PRIVILEGE_AUTOMATION",
    "auth_token_required",
    "auth_user_required",
    "configure_auth_middleware",
    "get_auth_config",
    "local_user_required",
    "lookup_permission",
    "privileges_required",
    "try_auth",
]
