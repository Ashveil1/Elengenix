"""elengenix.api.routes.providers — LLM provider introspection & testing.

Ports PentAGI's ``GET /providers``, ``POST /providers/test``,
``GET /providers/{name}/models`` (originally GraphQL queries — Task 1-c
recommendation §2 calls for REST-ifying them).

Routes
------
* ``GET  /providers``                 — list available providers + their
                                        configured models.
* ``POST /providers/test``            — probe a provider's connectivity
                                        with a 1-token completion.
* ``GET  /providers/{name}/models``   — list models for a specific
                                        provider (lazy-fetched from the
                                        provider's API where possible).

All routes are ``auth_token_required`` — both API tokens and sessions
are accepted.
"""

from __future__ import annotations

import logging
import time
from typing import Any, Optional

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse

from .._auth import Identity, auth_token_required
from .._models import (
    ProviderInfo,
    TestProviderRequest,
    TestProviderResponse,
    error_response,
    success_response,
)

logger = logging.getLogger("elengenix.api.routes.providers")

router = APIRouter(prefix="/providers", tags=["providers"])


# ---------------------------------------------------------------------------
# GET /providers — list
# ---------------------------------------------------------------------------


@router.get("", summary="List available LLM providers")
async def list_providers(
    request: Request,
    identity: Identity = Depends(auth_token_required),
) -> dict[str, Any]:
    """Return the list of LLM providers configured on this server.

    Each entry includes ``available`` (true if the provider's API key
    is configured + a recent health probe succeeded) and ``models``
    (the static configured list — ``GET /providers/{name}/models``
    returns the live list).
    """
    raw = getattr(request.app.state, "llm_providers", None) or []
    out: list[dict[str, Any]] = []
    for entry in raw:
        try:
            out.append(
                ProviderInfo(
                    name=str(entry.get("name", "")),
                    display_name=str(
                        entry.get("display_name", entry.get("name", ""))
                    ),
                    type=str(entry.get("type", "openai")),
                    available=bool(entry.get("available", True)),
                    models=list(entry.get("models", []) or []),
                ).model_dump()
            )
        except Exception:
            logger.exception("failed to parse provider entry: %r", entry)
    return success_response(out)


# ---------------------------------------------------------------------------
# POST /providers/test
# ---------------------------------------------------------------------------


@router.post("/test", summary="Test connectivity to a provider")
async def test_provider(
    body: TestProviderRequest,
    request: Request,
    identity: Identity = Depends(auth_token_required),
) -> JSONResponse:
    """Send a 1-token completion request to verify the provider config.

    Used by the settings UI's "Test connection" button. Returns
    ``{"ok": true, "latency_ms": 234, "model": "gpt-4o-mini"}`` on
    success, or ``{"ok": false, "message": "..."}`` on failure.
    """
    develop = bool(getattr(request.app.state, "develop", False))
    provider_pool = getattr(request.app.state, "llm_pool", None)
    if provider_pool is None:
        return JSONResponse(
            status_code=503,
            content=error_response(
                "service_unavailable",
                "LLM provider pool not configured",
                develop=develop,
            ),
        )

    t0 = time.time()
    try:
        result = await provider_pool.test_provider(
            provider=body.provider,
            api_key=body.api_key,
            base_url=body.base_url,
            model=body.model,
        )
    except Exception as exc:
        logger.exception("provider test failed for %r", body.provider)
        return JSONResponse(
            status_code=200,
            content=success_response(
                TestProviderResponse(
                    ok=False,
                    latency_ms=None,
                    message=f"Provider test raised: {exc!s}",
                    model=body.model,
                ).model_dump()
            ),
        )

    latency_ms = int((time.time() - t0) * 1000)
    response = TestProviderResponse(
        ok=bool(result.get("ok", False)),
        latency_ms=latency_ms,
        message=str(result.get("message", "")),
        model=str(result.get("model", body.model or "")),
    )
    return JSONResponse(
        status_code=200,
        content=success_response(response.model_dump()),
    )


# ---------------------------------------------------------------------------
# GET /providers/{name}/models — list models
# ---------------------------------------------------------------------------


@router.get("/{name}/models", summary="List models for a specific provider")
async def list_provider_models(
    name: str,
    request: Request,
    identity: Identity = Depends(auth_token_required),
) -> JSONResponse:
    """Return the list of models supported by ``name``.

    First checks the static configuration (``app.state.llm_providers``);
    if the provider implements ``list_models()`` (e.g. OpenAI's
    ``/v1/models`` endpoint), live-fetches the list and merges.
    """
    develop = bool(getattr(request.app.state, "develop", False))
    raw = getattr(request.app.state, "llm_providers", None) or []
    static_models: list[str] = []
    provider_type: Optional[str] = None
    for entry in raw:
        if str(entry.get("name", "")) == name:
            static_models = list(entry.get("models", []) or [])
            provider_type = str(entry.get("type", "openai"))
            break

    provider_pool = getattr(request.app.state, "llm_pool", None)
    if provider_pool is None or not hasattr(provider_pool, "list_models"):
        # No live-fetch capability — return the static list.
        return JSONResponse(
            status_code=200,
            content=success_response(
                {
                    "provider": name,
                    "type": provider_type or "unknown",
                    "models": static_models,
                    "source": "static",
                }
            ),
        )

    try:
        live_models: list[str] = await provider_pool.list_models(name)
    except Exception as exc:
        logger.exception("list_models failed for %r", name)
        return JSONResponse(
            status_code=200,
            content=success_response(
                {
                    "provider": name,
                    "type": provider_type or "unknown",
                    "models": static_models,
                    "source": "static",
                    "error": str(exc) if develop else None,
                }
            ),
        )

    # Merge static + live (dedupe, preserve order).
    seen: set[str] = set()
    merged: list[str] = []
    for m in static_models + live_models:
        if m not in seen:
            seen.add(m)
            merged.append(m)

    return JSONResponse(
        status_code=200,
        content=success_response(
            {
                "provider": name,
                "type": provider_type or "unknown",
                "models": merged,
                "source": "live" if live_models else "static",
            }
        ),
    )


__all__ = ["router"]
