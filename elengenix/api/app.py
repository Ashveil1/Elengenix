"""elengenix.api.app — FastAPI application factory.

Ports PentAGI's ``router.go`` (Gin) to FastAPI. The ``create_app()``
factory builds the FastAPI application, wires middleware (CORS,
TrustedHost, GZip), registers custom exception handlers for the
PentAGI error catalog, mounts all routers under ``/api/v1``, and sets
up the lifespan hooks (startup: DB init + Docker cleanup; shutdown:
graceful close).

Design constraints (per Task 6-a):

* **Lazy import** of FastAPI inside the factory — so the CLI works
  without ``fastapi`` installed.
* **OpenAPI at ``/api/v1/docs``** (replaces PentAGI's Swagger).
* **CORS middleware** with configurable ``allowed_origins`` (default
  ``["*"]``; auto-add ``https://accounts.google.com`` when Google OAuth
  is enabled — Task 1-c recommendation §11).
* **TrustedHostMiddleware** with configurable allowed hosts.
* **GZipMiddleware** for response compression.
* **Custom exception handlers** for 400, 401, 403, 404, 409, 422, 500 —
  each returns the PentAGI envelope shape
  ``{"status": "error", "code": ..., "msg": ..., "error"?: ...}``.
* **Response envelope**: ``success_response(data)`` /
  ``error_response(code, msg)`` from ``_models``.
* **Lifespan**: startup hook (DB init, Docker cleanup),
  shutdown hook (graceful close).
* **Mount all routers** under the ``/api/v1`` prefix.
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from typing import Any, AsyncIterator, Optional

logger = logging.getLogger("elengenix.api.app")


# ---------------------------------------------------------------------------
# create_app() — factory
# ---------------------------------------------------------------------------


def create_app(
    *,
    version: str = "2.0.0",
    allowed_origins: Optional[list[str]] = None,
    allowed_hosts: Optional[list[str]] = None,
    global_salt: str = "salt",
    develop: bool = False,
    cookie_secure: bool = False,
    cookie_samesite: str = "lax",
    llm_providers: Optional[list[dict[str, Any]]] = None,
    auth: Any = None,
    tokens: Any = None,
    flows: Any = None,
    knowledge: Any = None,
    orchestrator: Any = None,
    llm_pool: Any = None,
    db: Any = None,
    docker: Any = None,
    metrics: Any = None,
    enable_docs: bool = True,
    oauth_google_enabled: bool = False,
    oauth_github_enabled: bool = False,
    vector_store_enabled: bool = False,
    docker_enabled: bool = False,
    langfuse_enabled: bool = False,
    otel_enabled: bool = False,
) -> Any:
    """Build and return the FastAPI application.

    All arguments are optional — sensible defaults are used. The
    ``*_enabled`` flags populate ``app.state`` and are surfaced via
    ``GET /info`` (see ``routes/health.py``).

    Args:
        version: API version string. Surfaced in ``GET /info`` and the
            OpenAPI spec title.
        allowed_origins: CORS allow-list. Defaults to ``["*"]``. If
            Google OAuth is enabled, ``https://accounts.google.com``
            is appended automatically (mirror of PentAGI's CORS wiring).
        allowed_hosts: TrustedHostMiddleware allow-list. Defaults to
            ``["*"]`` (all hosts). In production, set this to the
            server's hostname(s).
        global_salt: Server-wide salt used for JWT signing key
            derivation. MUST be set to a unique value (not ``"salt"``)
            before issuing API tokens — see ``_auth.sign_api_token``.
        develop: When True, error responses include the raw exception
            text in the ``error`` field (mirror of PentAGI's
            ``develop`` flag). Also surfaces in ``GET /info``.
        cookie_secure: When True, the ``elengenix_session`` cookie is
            marked ``Secure`` (HTTPS-only). Set based on
            ``X-Forwarded-Proto`` in production.
        cookie_samesite: ``"lax"`` (default), ``"strict"``, or ``"none"``.
            ``"none"`` requires ``cookie_secure=True`` (browser
            requirement). Google OAuth callback requires ``"none"``.
        llm_providers: List of provider dicts (see
            ``routes/health._list_providers`` for the shape).
        auth: ``AuthProvider`` instance (or any object implementing the
            duck-typed protocol used by ``routes/auth.py``). May be
            ``None`` if the server is running in read-only mode.
        tokens: ``TokenStore`` instance for ``/tokens`` routes.
        flows: ``FlowStore`` instance for ``/flows`` routes.
        knowledge: ``KnowledgeStore`` instance for ``/knowledge`` routes.
        orchestrator: Flow orchestrator (drives ``start_flow``,
            ``stop_flow``, ``cleanup_flow``).
        llm_pool: LLM provider pool (``test_provider``, ``list_models``).
        db: Database connection (any async object with a ``ping()``
            method).
        docker: Docker client (any async object with a ``ping()``
            method).
        metrics: Metrics collector (any object with an async
            ``render()`` method).
        enable_docs: When True (default), mount the OpenAPI docs UI at
            ``/api/v1/docs``. Disable in production if you don't want
            to expose the spec.
        oauth_google_enabled: Feature flag — surfaced in ``GET /info``.
        oauth_github_enabled: Feature flag — surfaced in ``GET /info``.
        vector_store_enabled: Feature flag — surfaced in ``GET /info``.
        docker_enabled: Feature flag — surfaced in ``GET /info``.
        langfuse_enabled: Feature flag — surfaced in ``GET /info``.
        otel_enabled: Feature flag — surfaced in ``GET /info``.

    Returns:
        The configured ``FastAPI`` application instance. Call
        ``uvicorn.run(app, host=..., port=...)`` to serve it.

    Raises:
        ImportError: if ``fastapi`` is not installed.
    """
    # --- Lazy import of FastAPI + Starlette middleware -------------------
    try:
        from fastapi import FastAPI, Request
        from fastapi.exceptions import RequestValidationError
        from fastapi.middleware.cors import CORSMiddleware
        from fastapi.middleware.gzip import GZipMiddleware
        from fastapi.responses import JSONResponse
        from starlette.exceptions import HTTPException as StarletteHTTPException
        from starlette.middleware.trustedhost import TrustedHostMiddleware
    except ImportError as exc:  # pragma: no cover
        raise ImportError(
            "elengenix.api requires fastapi: pip install 'fastapi>=0.100'"
        ) from exc

    # Local imports (these require pydantic but the package is already
    # opted-in by the time create_app is called).
    from . import _models as models  # noqa: WPS433  (local import OK)
    from ._auth import AuthError  # noqa: WPS433
    from .routes import all_routers  # noqa: WPS433

    # --- CORS allow-list construction ------------------------------------
    cors_origins = list(allowed_origins) if allowed_origins is not None else ["*"]
    if oauth_google_enabled:
        # PentAGI auto-adds accounts.google.com when Google OAuth is on
        # (see Task 1-c recommendation §11).
        if "https://accounts.google.com" not in cors_origins:
            cors_origins.append("https://accounts.google.com")

    trusted_hosts = list(allowed_hosts) if allowed_hosts is not None else ["*"]

    # --- Lifespan --------------------------------------------------------
    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        """Startup + shutdown hooks.

        Startup:
        * Initialise the DB (if ``db`` was provided and has
          ``init()`` / ``connect()`` methods).
        * Run Docker container cleanup (if ``docker`` was provided).
        * Mark the app as ready (sets ``app.state.ready = True``).

        Shutdown:
        * Gracefully close the DB + Docker pools.
        * Stop the orchestrator's background tasks.
        """
        # --- Startup ---
        logger.info("elengenix.api lifespan: starting up (v=%s)", version)
        app.state.ready = False

        if db is not None:
            for method_name in ("init", "connect", "setup"):
                method = getattr(db, method_name, None)
                if method is None:
                    continue
                try:
                    result = method()
                    if hasattr(result, "__await__"):
                        await result
                except Exception:
                    logger.exception("db.%s failed", method_name)
                break

        # Docker cleanup — best-effort. Mirror of PentAGI's
        # ``dockerClient.Cleanup()`` at startup.
        if docker is not None and hasattr(docker, "cleanup"):
            try:
                result = docker.cleanup()
                if hasattr(result, "__await__"):
                    await result
            except Exception:
                logger.exception("docker.cleanup failed at startup")

        app.state.ready = True
        logger.info("elengenix.api lifespan: ready")

        try:
            yield
        finally:
            # --- Shutdown ---
            logger.info("elengenix.api lifespan: shutting down")
            app.state.ready = False

            if orchestrator is not None and hasattr(orchestrator, "shutdown"):
                try:
                    result = orchestrator.shutdown()
                    if hasattr(result, "__await__"):
                        await result
                except Exception:
                    logger.exception("orchestrator.shutdown failed")

            if db is not None:
                for method_name in ("close", "shutdown", "disconnect"):
                    method = getattr(db, method_name, None)
                    if method is None:
                        continue
                    try:
                        result = method()
                        if hasattr(result, "__await__"):
                            await result
                    except Exception:
                        logger.exception("db.%s failed", method_name)
                    break

            if docker is not None and hasattr(docker, "close"):
                try:
                    result = docker.close()
                    if hasattr(result, "__await__"):
                        await result
                except Exception:
                    logger.exception("docker.close failed")

            logger.info("elengenix.api lifespan: shutdown complete")

    # --- App construction ------------------------------------------------
    app = FastAPI(
        title="Elengenix API",
        version=version,
        description=(
            "Elengenix REST API — FastAPI port of PentAGI's REST surface "
            "(/api/v1/*). All responses use the envelope "
            '{"status": "success", "data": <any>} or '
            '{"status": "error", "code": ..., "msg": ...}.'
        ),
        docs_url="/api/v1/docs" if enable_docs else None,
        redoc_url="/api/v1/redoc" if enable_docs else None,
        openapi_url="/api/v1/openapi.json" if enable_docs else None,
        lifespan=lifespan,
    )

    # --- Middleware (order matters: outermost last) ---------------------
    # GZip first (innermost) so compressed bodies flow through CORS.
    app.add_middleware(GZipMiddleware, minimum_size=1024)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
        expose_headers=[
            "X-Request-ID",
            "X-RateLimit-Limit",
            "X-RateLimit-Remaining",
            "X-RateLimit-Reset",
        ],
    )
    if trusted_hosts and trusted_hosts != ["*"]:
        app.add_middleware(
            TrustedHostMiddleware,
            allowed_hosts=trusted_hosts,
        )

    # --- App state (read by routers via ``request.app.state``) ----------
    app.state.version = version
    app.state.global_salt = global_salt
    app.state.develop = develop
    app.state.cookie_secure = cookie_secure
    app.state.cookie_samesite = cookie_samesite
    app.state.llm_providers = list(llm_providers) if llm_providers else []
    app.state.auth = auth
    app.state.tokens = tokens
    app.state.flows = flows
    app.state.knowledge = knowledge
    app.state.orchestrator = orchestrator
    app.state.llm_pool = llm_pool
    app.state.db = db
    app.state.docker = docker
    app.state.metrics = metrics
    app.state.oauth_google_enabled = oauth_google_enabled
    app.state.oauth_github_enabled = oauth_github_enabled
    app.state.vector_store_enabled = vector_store_enabled
    app.state.docker_enabled = docker_enabled
    app.state.langfuse_enabled = langfuse_enabled
    app.state.otel_enabled = otel_enabled
    app.state.ready = False

    # --- Exception handlers ---------------------------------------------
    develop_flag = develop

    def _envelope_error(
        code: models.APIError,
        msg: Optional[str] = None,
        status: Optional[int] = None,
        error: Optional[str] = None,
    ) -> JSONResponse:
        """Build a JSONResponse with the PentAGI error envelope."""
        actual_status = status or models.error_http_status(code)
        actual_msg = msg or models.error_default_msg(code)
        return JSONResponse(
            status_code=actual_status,
            content=models.error_response(
                code.value,
                actual_msg,
                error=error,
                develop=develop_flag,
            ),
        )

    @app.exception_handler(AuthError)
    async def _auth_error_handler(request: Request, exc: AuthError) -> JSONResponse:
        # Map AuthError codes back to APIError enum values.
        try:
            code_enum = models.APIError(exc.code)
        except ValueError:
            code_enum = models.APIError.UNAUTHORIZED
        return _envelope_error(code_enum, msg=exc.msg)

    @app.exception_handler(StarletteHTTPException)
    async def _http_exc_handler(
        request: Request, exc: StarletteHTTPException
    ) -> JSONResponse:
        code_map = {
            400: models.APIError.BAD_REQUEST,
            401: models.APIError.UNAUTHORIZED,
            403: models.APIError.FORBIDDEN,
            404: models.APIError.NOT_FOUND,
            405: models.APIError.BAD_REQUEST,
            409: models.APIError.CONFLICT,
            413: models.APIError.BAD_REQUEST,
            422: models.APIError.VALIDATION,
            429: models.APIError.RATE_LIMITED,
            500: models.APIError.INTERNAL,
            503: models.APIError.SERVICE_UNAVAILABLE,
        }
        code = code_map.get(exc.status_code, models.APIError.INTERNAL)
        msg = str(exc.detail) if exc.detail else models.error_default_msg(code)
        return _envelope_error(code, msg=msg, status=exc.status_code)

    @app.exception_handler(RequestValidationError)
    async def _validation_handler(
        request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        # FastAPI raises this for Pydantic schema violations (422).
        errors = []
        for err in exc.errors():
            loc = ".".join(str(p) for p in err.get("loc", []) if p != "body")
            errors.append(
                {
                    "field": loc or "body",
                    "message": err.get("msg", ""),
                    "type": err.get("type", ""),
                }
            )
        body = models.error_response(
            models.APIError.VALIDATION.value,
            "Validation failed",
            error=str(errors) if develop_flag else None,
            develop=develop_flag,
        )
        body["details"] = errors
        return JSONResponse(status_code=422, content=body)

    @app.exception_handler(ValueError)
    async def _value_error_handler(
        request: Request, exc: ValueError
    ) -> JSONResponse:
        logger.warning("ValueError in %s %s: %s", request.method, request.url, exc)
        return _envelope_error(
            models.APIError.BAD_REQUEST,
            msg=str(exc) or "Bad request",
        )

    @app.exception_handler(Exception)
    async def _generic_handler(request: Request, exc: Exception) -> JSONResponse:
        logger.exception(
            "unhandled exception in %s %s", request.method, request.url
        )
        return _envelope_error(
            models.APIError.INTERNAL,
            msg="Internal server error",
            error=str(exc) if develop_flag else None,
        )

    # --- Mount routers --------------------------------------------------
    for name, router in all_routers():
        app.include_router(router, prefix="/api/v1")
        logger.debug("mounted router %r under /api/v1", name)

    # --- Root route (informational) ------------------------------------
    @app.get("/", include_in_schema=False)
    async def _root() -> dict[str, Any]:
        """Root info — points users at the docs URL."""
        return {
            "name": "Elengenix API",
            "version": version,
            "docs": "/api/v1/docs" if enable_docs else None,
            "openapi": "/api/v1/openapi.json" if enable_docs else None,
            "health": "/api/v1/health",
            "info": "/api/v1/info",
        }

    logger.info(
        "elengenix.api app created: version=%s, develop=%s, routers=%d, "
        "docs=%s",
        version,
        develop,
        len(list(all_routers())),
        enable_docs,
    )
    return app


__all__ = ["create_app"]
