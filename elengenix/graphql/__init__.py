"""
elengenix.graphql — Strawberry GraphQL schema assembly.

This package ports PentAGI's GraphQL surface (1115-line SDL) to Elengenix
using ``strawberry-graphql`` (FastAPI-native, async, supports subscriptions
via the ``graphql-transport-ws`` WebSocket protocol).

Modules
-------
* :mod:`elengenix.graphql.schema`        — 19 enums + schema config knobs.
* :mod:`elengenix.graphql.types`         — All Strawberry types/inputs (Pydantic-compatible).
* :mod:`elengenix.graphql.queries`       — 43 read resolvers (async).
* :mod:`elengenix.graphql.mutations`     — 31 write resolvers (async).
* :mod:`elengenix.graphql.subscriptions` — 38 WebSocket subscriptions +
                                           ``OriginValidator`` +
                                           ``RedisSubscriptionsController``.

Schema assembly
---------------
The actual ``strawberry.Schema`` instance is built lazily via
:func:`get_schema`. Calling it triggers the imports of the Query, Mutation
and Subscription root types — which in turn import Strawberry — so the rest
of the package can be inspected (e.g. for static analysis) without paying
the schema-build cost.

FastAPI integration
-------------------
Mount the schema via ``strawberry.fastapi.GraphQLRouter`` in
:mod:`elengenix.api.v1.graphql`::

    from elengenix.graphql import get_schema, OriginValidator

    router = GraphQLRouter(
        schema=get_schema(),
        keep_alive_interval_seconds=10,
        origin_validator=OriginValidator(allowed_origins).validate_origin,
    )

References:
    * PentAGI: backend/pkg/server/services/graphql.go (FixedComplexityLimit + APQ + WS)
    * PentAGI: backend/pkg/graph/schema.graphqls (1115-line SDL)
"""
from __future__ import annotations

import logging
from typing import Any, Optional

from .schema import (
    APQ_CACHE_SIZE,
    COMPLEXITY_LIMIT,
    INTROSPECTION_ENABLED,
    KEEPALIVE_PING_INTERVAL_SECONDS,
    MULTIPART_MAX_MEMORY_BYTES,
    get_schema_config,
    get_schema_extensions,
    # 19 enums
    AgentConfigType,
    AgentType,
    KnowledgeAnswerType,
    KnowledgeDocType,
    KnowledgeGuideType,
    MessageLogType,
    PromptType,
    PromptValidationErrorType,
    ProviderType,
    ReasoningEffort,
    ResultFormat,
    ResultType,
    StatusType,
    TerminalLogType,
    TerminalType,
    TokenStatus,
    ToolCallStatus,
    UsageStatsPeriod,
    VectorStoreAction,
)

logger = logging.getLogger("elengenix.graphql")

# ─── Lazy schema singleton ────────────────────────────────────────────────
# We don't import the root types (Query/Mutation/Subscription) at module load
# so that introspecting this package for enums / config doesn't require
# strawberry to be installed. ``get_schema()`` performs the lazy import + build.

_schema_singleton: Any = None


def get_schema() -> Any:
    """Return the process-wide ``strawberry.Schema`` instance (lazy).

    The schema is configured with:
        * ``complexity_limit = 20000`` (PentAGI's ``FixedComplexityLimit``).
        * Strawberry extensions via :func:`get_schema_extensions` (incl.
          ``PydanticIntegration`` when available, so resolvers may return
          Pydantic models directly).
        * Query/Mutation/Subscription roots from the sibling modules.

    Automatic Persisted Queries (APQ) are handled at the HTTP router level
    (FastAPI ``GraphQLRouter`` accepts a ``persisted_queries`` store); the
    APQ cache size is exposed via :data:`APQ_CACHE_SIZE`.
    """
    global _schema_singleton
    if _schema_singleton is not None:
        return _schema_singleton

    import strawberry  # local import — heavy dependency, deferred

    from .queries import Query
    from .mutations import Mutation
    from .subscriptions import Subscription

    config = get_schema_config()
    extensions = config.get("extensions") or []
    kwargs: dict = {
        "query": Query,
        "mutation": Mutation,
        "subscription": Subscription,
    }
    if extensions:
        kwargs["extensions"] = [
            ext() if isinstance(ext, type) else ext for ext in extensions
        ]
    # Strawberry 0.323 dropped the ``complexity_limit=`` kwarg on Schema(); the
    # limit is enforced by the ComplexityLimitExtension registered above. We
    # still try the kwarg defensively for forward-compatibility with future
    # Strawberry versions that may re-introduce it.
    try:
        _schema_singleton = strawberry.Schema(**kwargs)
    except TypeError as exc:
        if "complexity_limit" in str(exc):
            logger.warning(
                "strawberry.Schema does not accept complexity_limit; relying on "
                "ComplexityLimitExtension (limit=%d).", COMPLEXITY_LIMIT
            )
            _schema_singleton = strawberry.Schema(**{
                k: v for k, v in kwargs.items() if k != "complexity_limit"
            })
        else:
            raise
    logger.info(
        "Strawberry schema assembled (complexity_limit=%d, extensions=%d, apq_cache=%d)",
        COMPLEXITY_LIMIT,
        len(extensions),
        APQ_CACHE_SIZE,
    )
    return _schema_singleton


def reset_schema() -> None:
    """Force :func:`get_schema` to rebuild the schema on the next call.

    Mainly useful in tests that swap resolvers or extensions.
    """
    global _schema_singleton
    _schema_singleton = None


def build_origin_validator(allowed_origins: list) -> Any:
    """Convenience factory used by the FastAPI router to build an
    :class:`OriginValidator` from the CORS allowlist."""
    from .subscriptions import OriginValidator

    return OriginValidator(allowed_origins)


def get_subscriptions_controller(
    redis_url: Optional[str] = None,
) -> Any:
    """Return (and lazily create) a :class:`RedisSubscriptionsController`.

    When ``redis_url`` is provided the controller is registered as the
    process-wide singleton via :func:`set_controller`; otherwise the existing
    singleton is returned untouched.
    """
    from .subscriptions import RedisSubscriptionsController, get_controller, set_controller

    if redis_url is None:
        return get_controller()
    controller = RedisSubscriptionsController(redis_url=redis_url)
    set_controller(controller)
    return controller


# ─── Public re-exports ─────────────────────────────────────────────────────

# Re-export the subscriptions helpers at the package root for convenience —
# these are the symbols the FastAPI router imports most often.
from .subscriptions import (  # noqa: E402
    OriginValidator,
    RedisSubscriptionsController,
    get_controller as _get_controller,
    set_controller as _set_controller,
)

# Re-export the Strawberry root types lazily via __getattr__ so that
# `from elengenix.graphql import Query` works but does not trigger an import
# storm when only enums are needed.
_LAZY_ROOTS = ("Query", "Mutation", "Subscription")


def __getattr__(name: str) -> Any:
    if name in _LAZY_ROOTS:
        if name == "Query":
            from .queries import Query

            return Query
        if name == "Mutation":
            from .mutations import Mutation

            return Mutation
        if name == "Subscription":
            from .subscriptions import Subscription

            return Subscription
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def __dir__() -> list:
    return sorted(
        list(globals().keys()) + list(_LAZY_ROOTS) + ["get_schema", "reset_schema"]
    )


__all__ = [
    # Schema config
    "COMPLEXITY_LIMIT",
    "APQ_CACHE_SIZE",
    "KEEPALIVE_PING_INTERVAL_SECONDS",
    "MULTIPART_MAX_MEMORY_BYTES",
    "INTROSPECTION_ENABLED",
    # Schema assembly
    "get_schema",
    "reset_schema",
    "get_schema_config",
    "get_schema_extensions",
    "build_origin_validator",
    "get_subscriptions_controller",
    # Subscriptions controller (re-exported)
    "OriginValidator",
    "RedisSubscriptionsController",
    # Lazy root types
    "Query",
    "Mutation",
    "Subscription",
    # Enums (19)
    "AgentConfigType",
    "AgentType",
    "KnowledgeAnswerType",
    "KnowledgeDocType",
    "KnowledgeGuideType",
    "MessageLogType",
    "PromptType",
    "PromptValidationErrorType",
    "ProviderType",
    "ReasoningEffort",
    "ResultFormat",
    "ResultType",
    "StatusType",
    "TerminalLogType",
    "TerminalType",
    "TokenStatus",
    "ToolCallStatus",
    "UsageStatsPeriod",
    "VectorStoreAction",
]
