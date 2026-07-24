"""elengenix.api.routes.tokens — API token management.

Ports PentAGI's ``backend/pkg/server/services/api_tokens.go`` to
FastAPI. These routes are **session-protected** (``auth_user_required``)
— API tokens cannot self-manage (PentAGI filters out
``settings.tokens.*`` privileges from token claims).

Routes
------
* ``POST   /tokens``      — create a new API token. Returns the JWT
                            **exactly once**.
* ``GET    /tokens``      — list the current user's tokens (without the
                            JWT).
* ``DELETE /tokens/{id}`` — revoke (soft-delete) a token. Idempotent.

JWT details (HS256, PBKDF2-derived key, 10-char base62 ``token_id``)
live in ``elengenix.api._auth``. This router layer is responsible for:

* Validating the request body (``CreateAPITokenRequest``).
* Looking up the caller's ``user_hash`` + ``role_id`` via the auth
  provider.
* Calling ``_auth.sign_api_token`` to mint the JWT.
* Persisting the token row via ``app.state.tokens`` (a
  ``TokenStore`` protocol implementation).
* Invalidating the token-cache negative entry (so the new token
  validates immediately).
"""

from __future__ import annotations

import logging
import time
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse

from .._auth import (
    AuthError,
    Identity,
    auth_user_required,
    generate_token_id,
    sign_api_token,
    token_cache,
)
from .._models import (
    APITokenPublic,
    CreateAPITokenRequest,
    CreateAPITokenResponse,
    MAX_TOKEN_TTL_SECONDS,
    MIN_TOKEN_TTL_SECONDS,
    TOKEN_NAME_MAX_LENGTH,
    error_response,
    success_response,
)

logger = logging.getLogger("elengenix.api.routes.tokens")

router = APIRouter(prefix="/tokens", tags=["tokens"])


# ---------------------------------------------------------------------------
# POST /tokens — create
# ---------------------------------------------------------------------------


@router.post("", summary="Create a new API token (returns JWT once)")
async def create_token(
    body: CreateAPITokenRequest,
    request: Request,
    identity: Identity = Depends(auth_user_required),
) -> JSONResponse:
    """Issue a new API token for the current user.

    Returns the signed JWT in the ``token`` field of the response —
    this is the ONLY time the JWT is exposed. Store it client-side; it
    cannot be retrieved again.
    """
    global_salt = str(getattr(request.app.state, "global_salt", "salt"))
    develop = bool(getattr(request.app.state, "develop", False))

    # Refuse to issue while the global salt is the dev default — PentAGI
    # behaviour (blocks token creation in dev until ops sets a real salt).
    if global_salt in ("", "salt"):
        return JSONResponse(
            status_code=409,
            content=error_response(
                "conflict",
                "Refusing to issue API token: global_salt is the default. "
                "Set a unique server salt before issuing tokens.",
                develop=develop,
            ),
        )

    # Look up the user's current password hash (for uhash binding) and
    # role ID via the auth provider.
    auth_provider = getattr(request.app.state, "auth", None)
    if auth_provider is None:
        return JSONResponse(
            status_code=503,
            content=error_response(
                "service_unavailable",
                "Auth subsystem not configured",
                develop=develop,
            ),
        )

    try:
        user_info: dict[str, Any] = await auth_provider.get_user_for_token(
            identity.user_id
        )
    except Exception as exc:
        logger.exception("get_user_for_token failed")
        return JSONResponse(
            status_code=500,
            content=error_response(
                "internal",
                "Failed to load user info for token issuance",
                error=str(exc),
                develop=develop,
            ),
        )

    # Generate the public token_id (10-char base62).
    token_id = generate_token_id()

    # Sign the JWT.
    try:
        jwt_str = sign_api_token(
            token_id=token_id,
            role_id=int(user_info.get("role_id", identity.role_id)),
            user_id=identity.user_id,
            user_hash=str(user_info.get("user_hash", identity.user_hash)),
            ttl_seconds=body.ttl_seconds,
            global_salt=global_salt,
        )
    except ValueError as exc:
        return JSONResponse(
            status_code=400,
            content=error_response("bad_request", str(exc), develop=develop),
        )
    except Exception as exc:
        logger.exception("JWT signing failed")
        return JSONResponse(
            status_code=500,
            content=error_response(
                "internal",
                "Failed to sign API token",
                error=str(exc),
                develop=develop,
            ),
        )

    # Persist the token row via the token store.
    token_store = getattr(request.app.state, "tokens", None)
    if token_store is None:
        return JSONResponse(
            status_code=503,
            content=error_response(
                "service_unavailable",
                "Token store not configured",
                develop=develop,
            ),
        )

    now = int(time.time())
    expires_at = now + body.ttl_seconds
    try:
        row_id: int = await token_store.create_token(
            user_id=identity.user_id,
            token_id=token_id,
            name=body.name,
            expires_at=expires_at,
        )
    except Exception as exc:
        logger.exception("token_store.create_token failed")
        return JSONResponse(
            status_code=500,
            content=error_response(
                "internal",
                "Failed to persist API token",
                error=str(exc),
                develop=develop,
            ),
        )

    # Invalidate the negative cache for this token_id so the next
    # request that uses it doesn't short-circuit to 401.
    token_cache.invalidate(token_id)

    response = CreateAPITokenResponse(
        id=row_id,
        token_id=token_id,
        name=body.name,
        status="active",
        created_at=now,
        expires_at=expires_at,
        last_used_at=None,
        token=jwt_str,
    )
    return JSONResponse(
        status_code=201,
        content=success_response(response.model_dump()),
    )


# ---------------------------------------------------------------------------
# GET /tokens — list
# ---------------------------------------------------------------------------


@router.get("", summary="List the current user's API tokens (without JWTs)")
async def list_tokens(
    request: Request,
    identity: Identity = Depends(auth_user_required),
) -> dict[str, Any]:
    """Return all API tokens owned by the current user.

    The JWT is NEVER returned here — only the metadata (name, status,
    expiry, last_used_at). PentAGI has the same constraint.
    """
    token_store = getattr(request.app.state, "tokens", None)
    if token_store is None:
        return success_response([])
    try:
        rows: list[dict[str, Any]] = await token_store.list_tokens(
            identity.user_id
        )
    except Exception as exc:
        logger.exception("token_store.list_tokens failed")
        return success_response([])  # Fail open for listing.
    items = [
        APITokenPublic(
            id=int(r.get("id", 0)),
            token_id=str(r.get("token_id", "")),
            name=str(r.get("name", "")),
            status=str(r.get("status", "active")),
            created_at=int(r.get("created_at", 0)),
            expires_at=int(r.get("expires_at", 0)),
            last_used_at=(
                int(r["last_used_at"]) if r.get("last_used_at") else None
            ),
        )
        for r in rows
    ]
    return success_response([t.model_dump() for t in items])


# ---------------------------------------------------------------------------
# DELETE /tokens/{id} — revoke
# ---------------------------------------------------------------------------


@router.delete("/{token_id}", summary="Revoke (soft-delete) an API token")
async def revoke_token(
    token_id: str,
    request: Request,
    identity: Identity = Depends(auth_user_required),
) -> JSONResponse:
    """Revoke an API token. Soft-delete (sets ``status="revoked"``).

    Idempotent — revoking an already-revoked token returns 200. The
    token cache is invalidated immediately so the next request using
    that token is rejected at the auth layer (no DB lookup required).
    """
    develop = bool(getattr(request.app.state, "develop", False))
    token_store = getattr(request.app.state, "tokens", None)
    if token_store is None:
        return JSONResponse(
            status_code=503,
            content=error_response(
                "service_unavailable",
                "Token store not configured",
                develop=develop,
            ),
        )

    try:
        deleted: bool = await token_store.revoke_token(
            token_id=token_id, user_id=identity.user_id
        )
    except Exception as exc:
        logger.exception("token_store.revoke_token failed")
        return JSONResponse(
            status_code=500,
            content=error_response(
                "internal",
                "Failed to revoke token",
                error=str(exc),
                develop=develop,
            ),
        )

    # Invalidate the cache regardless — a 404 reply still means "no
    # future requests with this token should succeed".
    token_cache.invalidate(token_id)

    if not deleted:
        return JSONResponse(
            status_code=404,
            content=error_response(
                "token_not_found",
                f"API token not found: {token_id}",
                develop=develop,
            ),
        )

    return JSONResponse(
        status_code=200,
        content=success_response({"revoked": True, "token_id": token_id}),
    )


__all__ = ["router"]
