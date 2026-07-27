"""elengenix.api.routes.auth — Authentication endpoints.

Ports PentAGI's ``backend/pkg/server/services/auth.go`` to FastAPI.

Routes
------
* ``POST /auth/login``    — login with username/password. Sets a signed
                            ``elengenix_session`` cookie (HttpOnly,
                            SameSite=Lax by default; SameSite=None +
                            Secure for Google OAuth callback).
* ``POST /auth/logout``   — clear the session cookie.
* ``GET  /auth/me``       — return the current user's public profile
                            (``UserPublic``).
* ``POST /auth/refresh``  — refresh the session token (sliding window).
                            PentAGI's ``/info?refresh_cookie=true`` does
                            this implicitly; Elengenix exposes an
                            explicit endpoint.

All routes are session-based. API tokens (Bearer) are accepted by
``/auth/me`` (read-only) but rejected by ``/auth/refresh`` and
``/auth/logout`` (which require an interactive session).

OAuth2 (``GET /auth/authorize``, ``GET|POST /auth/login-callback``) is
implemented separately in ``elengenix.api.routes.oauth`` (Task 6-c).
"""

from __future__ import annotations

import logging
from typing import Any, Optional

from fastapi import APIRouter, Depends, Request, Response
from fastapi.responses import JSONResponse

from .._auth import (
    AuthError,
    Identity,
    auth_token_required,
    auth_user_required,
    try_auth,
)
from .._models import (
    LoginRequest,
    LoginResponse,
    RefreshResponse,
    UserPublic,
    error_response,
    success_response,
)

logger = logging.getLogger("elengenix.api.routes.auth")

router = APIRouter(prefix="/auth", tags=["auth"])

# Default session TTL — PentAGI uses 4 hours.
SESSION_TTL_SECONDS = 4 * 60 * 60
SESSION_COOKIE_NAME = "elengenix_session"


# ---------------------------------------------------------------------------
# POST /auth/login
# ---------------------------------------------------------------------------


@router.post("/login", summary="Login with username and password")
async def login(body: LoginRequest, request: Request) -> JSONResponse:
    """Authenticate the user with username/password.

    On success: sets an HttpOnly ``elengenix_session`` cookie and
    returns ``LoginResponse``. On failure: 401 with
    ``code="unauthorized"``.

    The actual password verification goes through ``app.state.auth``
    (an ``AuthProvider`` protocol) so the route layer stays decoupled
    from the user store (SQLite, Postgres, or external IdP).
    """
    auth_provider = getattr(request.app.state, "auth", None)
    if auth_provider is None:
        # No auth provider wired — refuse logins. PentAGI has the same
        # behaviour when ``localUserRequired`` is unset.
        return JSONResponse(
            status_code=503,
            content=error_response(
                "service_unavailable",
                "Authentication subsystem not configured",
                develop=bool(getattr(request.app.state, "develop", False)),
            ),
        )

    try:
        identity: Identity = await auth_provider.login(
            username=body.username,
            password=body.password,
            ttl_seconds=SESSION_TTL_SECONDS,
        )
    except AuthError as exc:
        return JSONResponse(
            status_code=401,
            content=error_response(
                exc.code,
                exc.msg,
                develop=bool(getattr(request.app.state, "develop", False)),
            ),
        )
    except Exception as exc:
        logger.exception("login failed for user %r", body.username)
        return JSONResponse(
            status_code=500,
            content=error_response(
                "internal",
                "Login failed",
                error=str(exc),
                develop=bool(getattr(request.app.state, "develop", False)),
            ),
        )

    # Build the signed session cookie via the auth provider.
    cookie_value: str = await auth_provider.issue_session_cookie(
        identity, ttl_seconds=SESSION_TTL_SECONDS
    )

    response = JSONResponse(
        status_code=200,
        content=success_response(
            LoginResponse(
                user_id=identity.user_id,
                username=identity.username or body.username,
                role=str(identity.role_id),
                token_type="session",
                expires_at=identity.expires_at or 0,
            ).model_dump()
        ),
    )
    _set_session_cookie(
        response,
        cookie_value,
        max_age=SESSION_TTL_SECONDS,
        secure=bool(getattr(request.app.state, "cookie_secure", False)),
        samesite=str(getattr(request.app.state, "cookie_samesite", "lax")),
    )
    return response


# ---------------------------------------------------------------------------
# POST /auth/logout
# ---------------------------------------------------------------------------


@router.post("/logout", summary="Logout (clear session cookie)")
async def logout(request: Request) -> JSONResponse:
    """Clear the session cookie.

    PentAGI also invalidates the server-side session row; Elengenix
    session cookies are stateless (signed JWTs), so logout is purely
    client-side. We DO revoke any server-tracked session ID via
    ``auth_provider.revoke_session`` if it's present.
    """
    identity = await try_auth(request)
    if identity is not None:
        auth_provider = getattr(request.app.state, "auth", None)
        if auth_provider is not None:
            try:
                await auth_provider.revoke_session(identity)
            except Exception:
                logger.exception("revoke_session failed")

    response = JSONResponse(
        status_code=200,
        content=success_response({"logged_out": True}),
    )
    # Expire the cookie immediately.
    _set_session_cookie(
        response,
        cookie_value="",
        max_age=0,
        secure=bool(getattr(request.app.state, "cookie_secure", False)),
        samesite=str(getattr(request.app.state, "cookie_samesite", "lax")),
    )
    return response


# ---------------------------------------------------------------------------
# GET /auth/me
# ---------------------------------------------------------------------------


@router.get("/me", summary="Get the current user's profile")
async def get_me(
    request: Request,
    identity: Identity = Depends(auth_token_required),
) -> dict[str, Any]:
    """Return the current user's public profile.

    Accepts both API tokens (Bearer) and sessions. If the user is
    blocked/deleted in the DB, returns 401 (mirrors PentAGI's
    ``userCache.GetUserHash`` check).
    """
    auth_provider = getattr(request.app.state, "auth", None)
    user: Optional[UserPublic] = None
    if auth_provider is not None:
        try:
            user = await auth_provider.get_user_public(identity.user_id)
        except Exception:
            logger.exception("get_user_public failed")
    if user is None:
        # Fallback: synthesise from the identity.
        user = UserPublic(
            id=identity.user_id,
            username=identity.username or f"user-{identity.user_id}",
            role=str(identity.role_id),
            privileges=list(identity.privileges),
            type=identity.token_id,
            active=True,
        )
    return success_response(user.model_dump())


# ---------------------------------------------------------------------------
# POST /auth/refresh
# ---------------------------------------------------------------------------


@router.post("/refresh", summary="Refresh the session token (sliding window)")
async def refresh_session(
    request: Request,
    identity: Identity = Depends(auth_user_required),
) -> JSONResponse:
    """Refresh the session cookie with a fresh full TTL.

    PentAGI does this implicitly inside ``GET /info`` after 5 minutes;
    Elengenix exposes an explicit endpoint so SPAs can refresh on
    demand. API tokens are rejected (``auth_user_required``) — token
    refresh has its own ``/tokens`` flow.
    """
    auth_provider = getattr(request.app.state, "auth", None)
    if auth_provider is None:
        return JSONResponse(
            status_code=503,
            content=error_response(
                "service_unavailable",
                "Authentication subsystem not configured",
                develop=bool(getattr(request.app.state, "develop", False)),
            ),
        )

    try:
        new_cookie: str = await auth_provider.issue_session_cookie(
            identity, ttl_seconds=SESSION_TTL_SECONDS
        )
    except Exception as exc:
        logger.exception("session refresh failed")
        return JSONResponse(
            status_code=500,
            content=error_response(
                "internal",
                "Session refresh failed",
                error=str(exc),
                develop=bool(getattr(request.app.state, "develop", False)),
            ),
        )

    response = JSONResponse(
        status_code=200,
        content=success_response(
            RefreshResponse(
                token_type="session",
                expires_at=(identity.expires_at or 0),
            ).model_dump()
        ),
    )
    _set_session_cookie(
        response,
        new_cookie,
        max_age=SESSION_TTL_SECONDS,
        secure=bool(getattr(request.app.state, "cookie_secure", False)),
        samesite=str(getattr(request.app.state, "cookie_samesite", "lax")),
    )
    return response


# ---------------------------------------------------------------------------
# Cookie helper
# ---------------------------------------------------------------------------


def _set_session_cookie(
    response: JSONResponse,
    cookie_value: str,
    *,
    max_age: int,
    secure: bool,
    samesite: str,
) -> None:
    """Set the ``elengenix_session`` cookie on the response.

    The ``samesite`` parameter accepts ``"lax"``, ``"none"``, or
    ``"strict"`` (case-insensitive). When ``samesite="none"`` we force
    ``secure=True`` (browser requirement, mirror of PentAGI's Google
    OAuth callback path).
    """
    samesite_norm = (samesite or "lax").lower()
    if samesite_norm == "none" and not secure:
        # Browsers reject SameSite=None without Secure.
        secure = True
    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=cookie_value,
        max_age=max_age,
        httponly=True,
        secure=secure,
        samesite=samesite_norm,  # type: ignore[arg-type]
        path="/api/v1",
    )


__all__ = ["router"]
