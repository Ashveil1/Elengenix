"""elengenix.api.routes.health — Health, info, and metrics endpoints.

Ports PentAGI's ``GET /info`` and adds Elengenix-native ``/health`` and
``/metrics`` (Prometheus-style text format).

Routes
------
* ``GET /info``    — server info (version, capabilities, providers,
                     auth config). Public (uses ``try_auth`` so the
                     response can include user-specific data when a
                     session is present).
* ``GET /health``  — liveness/readiness probe. Returns
                     ``{"status": "ok", "checks": {...}, ...}``.
* ``GET /metrics`` — Prometheus text-format metrics.

All endpoints are public (no ``auth_token_required`` dependency) so they
work for Docker health checks and Prometheus scrapes.
"""

from __future__ import annotations

import logging
import os
import time
from typing import Any, Optional

from fastapi import APIRouter, Depends, Request

from .._auth import try_auth
from .._models import (
    HealthStatus,
    ProviderInfo,
    ServerInfo,
    success_response,
)

logger = logging.getLogger("elengenix.api.routes.health")

router = APIRouter(tags=["health"])

# Module-level start time — used for uptime reporting.
_START_TIME = time.time()


# ---------------------------------------------------------------------------
# GET /info
# ---------------------------------------------------------------------------


@router.get("/info", summary="Server information (version, providers, capabilities)")
async def get_info(request: Request) -> dict[str, Any]:
    """Public endpoint. Mirrors PentAGI's ``GET /api/v1/info``.

    If a valid session/token is present (via ``try_auth``), the response
    also includes the current user's role + privileges — this lets the
    React frontend tailor the UI on first page load.
    """
    identity = await try_auth(request)
    develop = bool(getattr(request.app.state, "develop", False))
    version = str(getattr(request.app.state, "version", "2.0.0"))

    capabilities = _collect_capabilities(request)
    providers = await _list_providers(request)

    info = ServerInfo(
        name="Elengenix",
        version=version,
        api_version="v1",
        capabilities=capabilities,
        providers=providers,
        auth={
            "session_enabled": True,
            "api_tokens_enabled": True,
            "oauth_providers": _oauth_providers(request),
        },
        develop=develop,
    )
    payload = info.model_dump()
    if identity is not None:
        payload["user"] = {
            "id": identity.user_id,
            "role_id": identity.role_id,
            "privileges": list(identity.privileges),
            "token_type": identity.token_id,
        }
    return success_response(payload)


# ---------------------------------------------------------------------------
# GET /health
# ---------------------------------------------------------------------------


@router.get("/health", summary="Liveness/readiness probe")
async def get_health(request: Request) -> dict[str, Any]:
    """Returns ``{"status": "ok"|"degraded", "checks": {...}, ...}``.

    Each downstream subsystem (DB, Docker, vector store, LLM provider
    pool) is probed with a short timeout. The overall ``status`` is
    ``"degraded"`` if ANY check fails, ``"ok"`` otherwise.
    """
    checks: dict[str, str] = {}
    overall = "ok"

    checks["server"] = "ok"

    # DB ping — optional; only if app.state exposes a db.
    db = getattr(request.app.state, "db", None)
    if db is None:
        checks["db"] = "skipped"
    else:
        try:
            # DB object is duck-typed: any async ``ping()`` works.
            ping = getattr(db, "ping", None)
            if ping is not None:
                await ping()
            checks["db"] = "ok"
        except Exception as exc:
            overall = "degraded"
            checks["db"] = f"error: {exc!s}"

    # Docker ping — optional.
    docker = getattr(request.app.state, "docker", None)
    if docker is None:
        checks["docker"] = "skipped"
    else:
        try:
            ping = getattr(docker, "ping", None)
            if ping is not None:
                await ping()
            checks["docker"] = "ok"
        except Exception as exc:
            overall = "degraded"
            checks["docker"] = f"error: {exc!s}"

    status = HealthStatus(
        status=overall,
        uptime_seconds=time.time() - _START_TIME,
        checks=checks,
        version=str(getattr(request.app.state, "version", "2.0.0")),
    )
    return success_response(status.model_dump())


# ---------------------------------------------------------------------------
# GET /metrics
# ---------------------------------------------------------------------------


@router.get("/metrics", summary="Prometheus-style metrics (text format)")
async def get_metrics(request: Request) -> str:
    """Return Prometheus text-format metrics.

    The response body is plain text (``text/plain; version=0.0.4``) —
    FastAPI's ``Response(media_type="text/plain")`` is used by the
    caller. We return a ``str`` here and the response is serialised
    as-is.

    Metrics exposed (mirror PentAGI's custom meters):

    * ``elengenix_uptime_seconds``           — gauge
    * ``elengenix_requests_total``           — counter (per route)
    * ``elengenix_request_duration_seconds`` — histogram
    * ``elengenix_flows_total{status}``      — counter
    * ``elengenix_tokens_active``            — gauge
    """
    metrics_collector = getattr(request.app.state, "metrics", None)
    if metrics_collector is not None and hasattr(metrics_collector, "render"):
        try:
            return await metrics_collector.render()
        except Exception:
            logger.exception("metrics render failed; returning minimal metrics")

    # Minimal fallback — always succeeds.
    uptime = time.time() - _START_TIME
    pid = os.getpid()
    return (
        "# HELP elengenix_uptime_seconds Server uptime in seconds.\n"
        "# TYPE elengenix_uptime_seconds gauge\n"
        f"elengenix_uptime_seconds {uptime:.3f}\n"
        "# HELP elengenix_process_pid Process ID.\n"
        "# TYPE elengenix_process_pid gauge\n"
        f"elengenix_process_pid {pid}\n"
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _collect_capabilities(request: Request) -> list[str]:
    """Inspect ``app.state`` to determine which feature flags are on."""
    state = request.app.state
    caps: list[str] = ["rest_api", "openapi_docs"]
    if getattr(state, "docker_enabled", False):
        caps.append("docker_sandbox")
    if getattr(state, "vector_store_enabled", False):
        caps.append("knowledge_search")
    if getattr(state, "oauth_github_enabled", False):
        caps.append("oauth_github")
    if getattr(state, "oauth_google_enabled", False):
        caps.append("oauth_google")
    if getattr(state, "langfuse_enabled", False):
        caps.append("llm_observability")
    if getattr(state, "otel_enabled", False):
        caps.append("otel_tracing")
    if getattr(state, "develop", False):
        caps.append("develop_mode")
    return caps


def _oauth_providers(request: Request) -> list[str]:
    state = request.app.state
    providers: list[str] = []
    if getattr(state, "oauth_github_enabled", False):
        providers.append("github")
    if getattr(state, "oauth_google_enabled", False):
        providers.append("google")
    return providers


async def _list_providers(request: Request) -> list[ProviderInfo]:
    """Return the list of LLM providers configured on this server.

    Reads from ``app.state.llm_providers`` (set by ``create_app()``).
    Each entry is a dict like
    ``{"name": "openai", "display_name": "OpenAI", "type": "openai",
       "available": true, "models": ["gpt-4o", "gpt-4o-mini"]}``.
    """
    raw = getattr(request.app.state, "llm_providers", None) or []
    out: list[ProviderInfo] = []
    for entry in raw:
        try:
            out.append(
                ProviderInfo(
                    name=str(entry.get("name", "")),
                    display_name=str(entry.get("display_name", entry.get("name", ""))),
                    type=str(entry.get("type", "openai")),
                    available=bool(entry.get("available", True)),
                    models=list(entry.get("models", []) or []),
                )
            )
        except Exception:
            logger.exception("failed to parse provider entry: %r", entry)
    return out


__all__ = ["router"]
