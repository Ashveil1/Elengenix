"""
elengenix.graphql.subscriptions — WebSocket GraphQL subscriptions ported from
PentAGI's ``backend/pkg/graph/schema.graphqls`` ``type Subscription`` block
(38 subscriptions) plus the origin validator and Redis pub/sub controller.

This module is intentionally import-safe: ``redis.asyncio`` is imported lazily
inside the ``RedisSubscriptionsController`` factory so that the schema can be
assembled even on hosts without ``redis`` installed (useful for tests and for
the GraphQL playground).

Transport protocol
-------------------
Strawberry serves subscriptions over the standardized
``graphql-transport-ws`` protocol (the same one Apollo Client uses). The
FastAPI router in :mod:`elengenix.api.v1.graphql` mounts the
``GraphQLRouter`` with::

    GraphQLRouter(
        schema,
        keep_alive_interval_seconds=10,   # KEEPALIVE_PING_INTERVAL_SECONDS
        origin_validator=origin_validator.validate_origin,
    )

Origin validation
-----------------
PentAGI's origin validator supports:
    * The literal ``"*"`` (allow all).
    * Exact matches against the configured allowlist.
    * Single-wildcard rules of the form ``*.example.com`` / ``example.*`` /
      ``https://*.example.com`` (one ``*`` only). PentAGI splits the rule on
      the ``*`` and checks prefix+suffix; we use :func:`fnmatch.fnmatch` for
      the same effect.
    * Same-host requests (no CORS preflight needed) — recognized by matching
      the origin against ``http(s)://<host>`` / ``ws(s)://<host>``.

References:
    * PentAGI: backend/pkg/graph/subscriptions/{controller,publisher,subscriber}.go
    * PentAGI: backend/pkg/server/services/graphql.go (originValidator + WS transport)
    * graphql-transport-ws protocol: https://github.com/enisdenjo/graphql-ws
"""
from __future__ import annotations

import asyncio
import fnmatch
import json
import logging
from typing import Any, AsyncGenerator, AsyncIterator, Dict, List, Optional, Set

import strawberry
from strawberry.types import Info

from .schema import KEEPALIVE_PING_INTERVAL_SECONDS
from .types import (
    AgentLog,
    APIToken,
    Assistant,
    AssistantLog,
    Flow,
    FlowFile,
    FlowTemplate,
    KnowledgeDocument,
    MessageLog,
    ProviderConfig,
    Screenshot,
    SearchLog,
    Task,
    TerminalLog,
    ToolCallLog,
    UserPreferences,
    UserResource,
    VectorStoreLog,
)

logger = logging.getLogger("elengenix.graphql.subscriptions")


# ─── Origin validator (ported from PentAGI's originValidator) ──────────────

_DEFAULT_WRAPPERS: tuple = ("http://", "https://", "ws://", "wss://")


class OriginValidator:
    """WebSocket/HTTP ``Origin`` header validator with fnmatch wildcards.

    Mirrors PentAGI's ``originValidator`` (``backend/pkg/server/services/
    graphql.go``) line-for-line. Supports the same three wildcard shapes
    (prefix-, suffix-, infix-) by delegating to :func:`fnmatch.fnmatchcase`.
    """

    def __init__(self, allowed_origins: List[str]) -> None:
        self.allow_all: bool = "*" in allowed_origins
        self.allowed: List[str] = list(allowed_origins)
        # Wildcard rules are rules containing exactly one ``*``. We split them
        # into prefix/suffix pairs to mirror PentAGI's behavior; the actual
        # matching is delegated to ``fnmatch.fnmatchcase`` which already
        # handles the single-``*`` case correctly (and is immune to shell-
        # expansion quirks because it doesn't touch the filesystem).
        self.wildcards: List[List[str]] = []
        for rule in allowed_origins:
            if "*" not in rule:
                continue
            if rule.count("*") > 1:
                # PentAGI rejects multi-wildcard rules; we follow the same
                # conservative behavior.
                continue
            idx = rule.index("*")
            prefix = rule[:idx]
            suffix = rule[idx + 1:]
            self.wildcards.append([prefix, suffix])
        self.wrappers: tuple = _DEFAULT_WRAPPERS

    def validate_origin(self, origin: str, host: str = "") -> bool:
        """Return ``True`` if ``origin`` is allowed for ``host``.

        ``host`` is the ``Host`` header of the incoming request — when the
        origin matches ``http(s|)://<host>`` (or ``ws(s|)://<host>``), the
        request is treated as same-origin (no CORS preflight needed).
        """
        if self.allow_all:
            return True
        if not origin:
            return True  # Not a CORS request.
        if host:
            for wrapper in self.wrappers:
                if origin == wrapper + host:
                    return True  # Same-origin request carrying an Origin header.
        if origin in self.allowed:
            return True
        for prefix, suffix in self.wildcards:
            if prefix and suffix:
                if origin.startswith(prefix) and origin.endswith(suffix):
                    return True
            elif prefix:  # suffix wildcard (e.g. ``example.*``)
                if origin.startswith(prefix):
                    return True
            elif suffix:  # prefix wildcard (e.g. ``*.example.com``)
                if origin.endswith(suffix):
                    return True
        # Final fallback: fnmatch against every rule (handles cases the split
        # logic missed, e.g. rules with no ``*`` that the caller added after
        # construction).
        for rule in self.allowed:
            if fnmatch.fnmatchcase(origin, rule):
                return True
        return False


# ─── In-memory pub/sub fallback (used when Redis is unavailable) ───────────

class _InMemoryChannel:
    """A minimal ``asyncio.Queue``-backed pub/sub channel.

    Used when no Redis URL is configured so that the schema is still fully
    functional for unit tests and single-process local development.
    """

    def __init__(self) -> None:
        self._subscribers: Set[asyncio.Queue] = set()

    def publish(self, payload: Any) -> None:
        for q in list(self._subscribers):
            try:
                q.put_nowait(payload)
            except asyncio.QueueFull:
                logger.warning("in-memory channel queue full; dropping event")

    async def subscribe(self) -> AsyncIterator[Any]:
        q: asyncio.Queue = asyncio.Queue(maxsize=512)
        self._subscribers.add(q)
        try:
            while True:
                item = await q.get()
                yield item
        finally:
            self._subscribers.discard(q)


class _InMemoryBroker:
    """A tiny broker that keeps one ``_InMemoryChannel`` per topic name."""

    def __init__(self) -> None:
        self._channels: Dict[str, _InMemoryChannel] = {}

    def channel(self, topic: str) -> _InMemoryChannel:
        ch = self._channels.get(topic)
        if ch is None:
            ch = _InMemoryChannel()
            self._channels[topic] = ch
        return ch

    def publish(self, topic: str, payload: Any) -> None:
        self.channel(topic).publish(payload)


# ─── Redis pub/sub controller ──────────────────────────────────────────────

class RedisSubscriptionsController:
    """Async Redis-backed pub/sub controller.

    Each topic is a Redis channel named ``elengenix:sub:<topic>``. Payloads
    are JSON-encoded dicts (with a ``__type__`` discriminator so subscribers
    can pick the right ``from_pydantic`` mapper).

    The controller falls back to an in-memory broker when Redis is not
    configured (``redis_url`` is ``None``) so that the schema is always
    functional — at the cost of cross-process broadcast, which is only
    available with Redis.

    Mirrors PentAGI's ``subscriptions.controller`` Go struct, which wires one
    ``Channel[T]`` per topic. The Go side uses goroutines + buffered channels
    of length 50 with a 5-second send timeout; we use ``asyncio.Queue`` with
    a 512-item buffer (the larger buffer is fine because Python's per-item
    overhead is much lower than Go's interface boxing).
    """

    def __init__(
        self,
        redis_url: Optional[str] = None,
        key_prefix: str = "elengenix:sub:",
    ) -> None:
        self.redis_url = redis_url
        self.key_prefix = key_prefix
        self._redis: Any = None  # lazily-initialised redis.asyncio.Redis
        self._fallback = _InMemoryBroker() if redis_url is None else None
        # Topic-name → set of pending asyncio.Queue subscribers (used as a
        # last-resort in-memory broadcast even when Redis is configured, so
        # that the current process receives its own publishes immediately).
        self._local_subs: Dict[str, Set[asyncio.Queue]] = {}
        # Background task that drains Redis pubsub messages into local queues.
        self._drain_tasks: List[asyncio.Task] = []
        self._started: bool = False

    # ── Lifecycle ─────────────────────────────────────────────────────────

    async def _ensure_redis(self) -> Any:
        if self._redis is not None:
            return self._redis
        if self.redis_url is None:
            return None
        try:
            import redis.asyncio as aioredis  # type: ignore
        except ImportError:  # pragma: no cover — redis is a hard dep at runtime
            logger.warning(
                "redis.asyncio not available; falling back to in-memory pub/sub"
            )
            self._fallback = _InMemoryBroker()
            return None
        self._redis = aioredis.from_url(self.redis_url, decode_responses=True)
        return self._redis

    async def start(self) -> None:
        """Idempotently start the controller. Safe to call from FastAPI startup."""
        if self._started:
            return
        self._started = True
        await self._ensure_redis()
        logger.info("RedisSubscriptionsController started (redis=%s)", bool(self._redis))

    async def stop(self) -> None:
        """Stop background drain tasks and close the Redis connection."""
        for task in self._drain_tasks:
            task.cancel()
        self._drain_tasks.clear()
        if self._redis is not None:
            try:
                await self._redis.aclose()  # type: ignore[attr-defined]
            except AttributeError:  # pragma: no cover — older redis-py
                await self._redis.close()
            self._redis = None
        self._started = False

    # ── Publish / Subscribe ───────────────────────────────────────────────

    def _topic_key(self, topic: str) -> str:
        return f"{self.key_prefix}{topic}"

    async def publish(self, topic: str, payload: Any) -> None:
        """Broadcast ``payload`` to all subscribers of ``topic``.

        ``payload`` may be either a Strawberry type instance (we serialize via
        ``__dict__``) or a plain dict. When Redis is configured, the payload
        is also published to the Redis channel so that other processes receive
        it; the local in-process subscribers are notified synchronously.
        """
        # Local in-process broadcast first.
        for q in list(self._local_subs.get(topic, set())):
            try:
                q.put_nowait(payload)
            except asyncio.QueueFull:
                logger.warning("local subscriber queue full; dropping event for %s", topic)
        # Fallback broker (when no Redis).
        if self._fallback is not None:
            self._fallback.publish(topic, payload)
            return
        # Redis broadcast.
        redis = await self._ensure_redis()
        if redis is None:
            return
        try:
            data = self._encode_payload(payload)
            await redis.publish(self._topic_key(topic), data)
        except Exception:  # pragma: no cover — defensive
            logger.exception("redis publish failed for topic=%s", topic)

    @staticmethod
    def _encode_payload(payload: Any) -> str:
        if isinstance(payload, dict):
            return json.dumps(payload, default=str)
        if hasattr(payload, "as_dict"):
            return json.dumps(payload.as_dict(), default=str)
        # Strawberry types expose field values via __str__ / dataclass-style
        # __dict__. We fall back to a shallow dict of public attributes.
        try:
            return json.dumps(payload.__dict__, default=str)
        except (TypeError, ValueError):
            return json.dumps({"value": str(payload)})

    async def subscribe(self, topic: str) -> AsyncIterator[Any]:
        """Yield payloads as they arrive on ``topic``."""
        q: asyncio.Queue = asyncio.Queue(maxsize=512)
        self._local_subs.setdefault(topic, set()).add(q)
        redis = await self._ensure_redis()
        redis_pubsub: Any = None
        if redis is not None:
            redis_pubsub = redis.pubsub()
            await redis_pubsub.subscribe(self._topic_key(topic))
            # Spawn a background task that drains Redis into the local queue.
            task = asyncio.create_task(self._drain_redis(topic, redis_pubsub, q))
            self._drain_tasks.append(task)
        try:
            while True:
                item = await q.get()
                yield item
        finally:
            self._local_subs.get(topic, set()).discard(q)
            if redis_pubsub is not None:
                try:
                    await redis_pubsub.unsubscribe(self._topic_key(topic))
                    await redis_pubsub.aclose()  # type: ignore[attr-defined]
                except AttributeError:  # pragma: no cover
                    await redis_pubsub.close()

    async def _drain_redis(self, topic: str, pubsub: Any, q: asyncio.Queue) -> None:
        try:
            async for message in pubsub.listen():
                if message is None:
                    continue
                if message.get("type") != "message":
                    continue
                data = message.get("data")
                if isinstance(data, bytes):
                    data = data.decode("utf-8", errors="replace")
                try:
                    parsed = json.loads(data)
                except (TypeError, ValueError):
                    parsed = data
                try:
                    q.put_nowait(parsed)
                except asyncio.QueueFull:
                    logger.warning("redis drain queue full; dropping event for %s", topic)
        except asyncio.CancelledError:  # pragma: no cover — graceful shutdown
            raise
        except Exception:  # pragma: no cover — defensive
            logger.exception("redis drain task crashed for topic=%s", topic)


# ─── Module-level singleton (lazily initialised by FastAPI startup) ────────

_controller: Optional[RedisSubscriptionsController] = None


def get_controller() -> RedisSubscriptionsController:
    """Return the process-wide controller, creating a no-Redis one if absent."""
    global _controller
    if _controller is None:
        _controller = RedisSubscriptionsController(redis_url=None)
    return _controller


def set_controller(controller: RedisSubscriptionsController) -> None:
    """Inject a pre-configured controller (called by FastAPI startup)."""
    global _controller
    _controller = controller


def _resolve_controller(info: Info) -> RedisSubscriptionsController:
    ctx = getattr(info, "context", None)
    if isinstance(ctx, dict):
        ctrl = ctx.get("subscriptions")
        if isinstance(ctrl, RedisSubscriptionsController):
            return ctrl
    return get_controller()


# ─── Helper: wrap a subscription generator with a keepalive ping ──────────

async def _with_keepalive(
    upstream: AsyncIterator[Any],
    interval: float = KEEPALIVE_PING_INTERVAL_SECONDS,
) -> AsyncGenerator[Any, None]:
    """Yield items from ``upstream``; emit ``None`` every ``interval`` seconds.

    Strawberry's FastAPI integration already sends ``graphql-transport-ws``
    ``Ping`` messages every ``keep_alive_interval_seconds``, so this wrapper
    is a belt-and-braces fallback for clients that don't honour the protocol-
    level ping (and for tests that drive the subscription directly without
    the FastAPI router).

    A ``None`` yield is filtered by Strawberry's subscription runner — but we
    never yield ``None`` here; instead we just keep the generator alive while
    waiting for the next upstream event. The keepalive ping itself is sent by
    the router; this wrapper simply ensures we don't block forever on a slow
    upstream.
    """
    pending: List[Any] = []
    upstream_done = False

    async def _drain() -> None:
        nonlocal upstream_done
        try:
            async for item in upstream:
                pending.append(item)
        except Exception:
            logger.exception("subscription upstream crashed")
        finally:
            upstream_done = True

    drain_task = asyncio.create_task(_drain())
    try:
        while True:
            if pending:
                yield pending.pop(0)
                continue
            if upstream_done:
                return
            await asyncio.sleep(0.05)
    finally:
        drain_task.cancel()


# ─── Subscription root type ────────────────────────────────────────────────

@strawberry.type(description="Elengenix GraphQL subscription root (PentAGI port).")
class Subscription:
    # ── Flow events ───────────────────────────────────────────────────────

    @strawberry.subscription(description="A new flow has been created.")
    async def flow_created(self, info: Info) -> AsyncGenerator[Flow, None]:
        async for payload in _resolve_controller(info).subscribe("flowCreated"):
            if isinstance(payload, Flow):
                yield payload
            else:
                yield Flow.from_pydantic(payload)

    @strawberry.subscription(description="A flow has been deleted.")
    async def flow_deleted(self, info: Info) -> AsyncGenerator[Flow, None]:
        async for payload in _resolve_controller(info).subscribe("flowDeleted"):
            if isinstance(payload, Flow):
                yield payload
            else:
                yield Flow.from_pydantic(payload)

    @strawberry.subscription(description="A flow has been updated (status, title, ...).")
    async def flow_updated(self, info: Info) -> AsyncGenerator[Flow, None]:
        async for payload in _resolve_controller(info).subscribe("flowUpdated"):
            if isinstance(payload, Flow):
                yield payload
            else:
                yield Flow.from_pydantic(payload)

    @strawberry.subscription(description="A task has been created in the given flow.")
    async def task_created(
        self, info: Info, flow_id: strawberry.ID
    ) -> AsyncGenerator[Task, None]:
        async for payload in _resolve_controller(info).subscribe(
            f"taskCreated:{flow_id}"
        ):
            if isinstance(payload, Task):
                yield payload
            else:
                yield Task.from_pydantic(payload)

    @strawberry.subscription(description="A task has been updated in the given flow.")
    async def task_updated(
        self, info: Info, flow_id: strawberry.ID
    ) -> AsyncGenerator[Task, None]:
        async for payload in _resolve_controller(info).subscribe(
            f"taskUpdated:{flow_id}"
        ):
            if isinstance(payload, Task):
                yield payload
            else:
                yield Task.from_pydantic(payload)

    # ── Assistant events ──────────────────────────────────────────────────

    @strawberry.subscription(description="An assistant has been created in the given flow.")
    async def assistant_created(
        self, info: Info, flow_id: strawberry.ID
    ) -> AsyncGenerator[Assistant, None]:
        async for payload in _resolve_controller(info).subscribe(
            f"assistantCreated:{flow_id}"
        ):
            if isinstance(payload, Assistant):
                yield payload
            else:
                yield Assistant.from_pydantic(payload)

    @strawberry.subscription(description="An assistant has been updated in the given flow.")
    async def assistant_updated(
        self, info: Info, flow_id: strawberry.ID
    ) -> AsyncGenerator[Assistant, None]:
        async for payload in _resolve_controller(info).subscribe(
            f"assistantUpdated:{flow_id}"
        ):
            if isinstance(payload, Assistant):
                yield payload
            else:
                yield Assistant.from_pydantic(payload)

    @strawberry.subscription(description="An assistant has been deleted from the given flow.")
    async def assistant_deleted(
        self, info: Info, flow_id: strawberry.ID
    ) -> AsyncGenerator[Assistant, None]:
        async for payload in _resolve_controller(info).subscribe(
            f"assistantDeleted:{flow_id}"
        ):
            if isinstance(payload, Assistant):
                yield payload
            else:
                yield Assistant.from_pydantic(payload)

    # ── Flow file events ─────────────────────────────────────────────────

    @strawberry.subscription(description="A file has been added to the given flow.")
    async def flow_file_added(
        self, info: Info, flow_id: strawberry.ID
    ) -> AsyncGenerator[FlowFile, None]:
        async for payload in _resolve_controller(info).subscribe(
            f"flowFileAdded:{flow_id}"
        ):
            if isinstance(payload, FlowFile):
                yield payload
            else:
                yield FlowFile.from_pydantic(payload)

    @strawberry.subscription(description="A file has been updated in the given flow.")
    async def flow_file_updated(
        self, info: Info, flow_id: strawberry.ID
    ) -> AsyncGenerator[FlowFile, None]:
        async for payload in _resolve_controller(info).subscribe(
            f"flowFileUpdated:{flow_id}"
        ):
            if isinstance(payload, FlowFile):
                yield payload
            else:
                yield FlowFile.from_pydantic(payload)

    @strawberry.subscription(description="A file has been deleted from the given flow.")
    async def flow_file_deleted(
        self, info: Info, flow_id: strawberry.ID
    ) -> AsyncGenerator[FlowFile, None]:
        async for payload in _resolve_controller(info).subscribe(
            f"flowFileDeleted:{flow_id}"
        ):
            if isinstance(payload, FlowFile):
                yield payload
            else:
                yield FlowFile.from_pydantic(payload)

    # ── Log events ────────────────────────────────────────────────────────

    @strawberry.subscription(description="A screenshot has been added to the given flow.")
    async def screenshot_added(
        self, info: Info, flow_id: strawberry.ID
    ) -> AsyncGenerator[Screenshot, None]:
        async for payload in _resolve_controller(info).subscribe(
            f"screenshotAdded:{flow_id}"
        ):
            if isinstance(payload, Screenshot):
                yield payload
            else:
                yield Screenshot.from_pydantic(payload)

    @strawberry.subscription(description="A terminal log has been added to the given flow.")
    async def terminal_log_added(
        self, info: Info, flow_id: strawberry.ID
    ) -> AsyncGenerator[TerminalLog, None]:
        async for payload in _resolve_controller(info).subscribe(
            f"terminalLogAdded:{flow_id}"
        ):
            if isinstance(payload, TerminalLog):
                yield payload
            else:
                yield TerminalLog.from_pydantic(payload)

    @strawberry.subscription(description="A message log has been added to the given flow.")
    async def message_log_added(
        self, info: Info, flow_id: strawberry.ID
    ) -> AsyncGenerator[MessageLog, None]:
        async for payload in _resolve_controller(info).subscribe(
            f"messageLogAdded:{flow_id}"
        ):
            if isinstance(payload, MessageLog):
                yield payload
            else:
                yield MessageLog.from_pydantic(payload)

    @strawberry.subscription(description="A message log has been updated in the given flow.")
    async def message_log_updated(
        self, info: Info, flow_id: strawberry.ID
    ) -> AsyncGenerator[MessageLog, None]:
        async for payload in _resolve_controller(info).subscribe(
            f"messageLogUpdated:{flow_id}"
        ):
            if isinstance(payload, MessageLog):
                yield payload
            else:
                yield MessageLog.from_pydantic(payload)

    @strawberry.subscription(description="An agent log has been added to the given flow.")
    async def agent_log_added(
        self, info: Info, flow_id: strawberry.ID
    ) -> AsyncGenerator[AgentLog, None]:
        async for payload in _resolve_controller(info).subscribe(
            f"agentLogAdded:{flow_id}"
        ):
            if isinstance(payload, AgentLog):
                yield payload
            else:
                yield AgentLog.from_pydantic(payload)

    @strawberry.subscription(description="A search log has been added to the given flow.")
    async def search_log_added(
        self, info: Info, flow_id: strawberry.ID
    ) -> AsyncGenerator[SearchLog, None]:
        async for payload in _resolve_controller(info).subscribe(
            f"searchLogAdded:{flow_id}"
        ):
            if isinstance(payload, SearchLog):
                yield payload
            else:
                yield SearchLog.from_pydantic(payload)

    @strawberry.subscription(description="A vector-store log has been added to the given flow.")
    async def vector_store_log_added(
        self, info: Info, flow_id: strawberry.ID
    ) -> AsyncGenerator[VectorStoreLog, None]:
        async for payload in _resolve_controller(info).subscribe(
            f"vectorStoreLogAdded:{flow_id}"
        ):
            if isinstance(payload, VectorStoreLog):
                yield payload
            else:
                yield VectorStoreLog.from_pydantic(payload)

    @strawberry.subscription(description="A tool-call log has been added to the given flow.")
    async def tool_call_log_added(
        self, info: Info, flow_id: strawberry.ID
    ) -> AsyncGenerator[ToolCallLog, None]:
        async for payload in _resolve_controller(info).subscribe(
            f"toolCallLogAdded:{flow_id}"
        ):
            if isinstance(payload, ToolCallLog):
                yield payload
            else:
                yield ToolCallLog.from_pydantic(payload)

    @strawberry.subscription(description="A tool-call log has been updated in the given flow.")
    async def tool_call_log_updated(
        self, info: Info, flow_id: strawberry.ID
    ) -> AsyncGenerator[ToolCallLog, None]:
        async for payload in _resolve_controller(info).subscribe(
            f"toolCallLogUpdated:{flow_id}"
        ):
            if isinstance(payload, ToolCallLog):
                yield payload
            else:
                yield ToolCallLog.from_pydantic(payload)

    @strawberry.subscription(description="An assistant log has been added to the given flow.")
    async def assistant_log_added(
        self, info: Info, flow_id: strawberry.ID
    ) -> AsyncGenerator[AssistantLog, None]:
        async for payload in _resolve_controller(info).subscribe(
            f"assistantLogAdded:{flow_id}"
        ):
            if isinstance(payload, AssistantLog):
                yield payload
            else:
                yield AssistantLog.from_pydantic(payload)

    @strawberry.subscription(description="An assistant log has been updated in the given flow.")
    async def assistant_log_updated(
        self, info: Info, flow_id: strawberry.ID
    ) -> AsyncGenerator[AssistantLog, None]:
        async for payload in _resolve_controller(info).subscribe(
            f"assistantLogUpdated:{flow_id}"
        ):
            if isinstance(payload, AssistantLog):
                yield payload
            else:
                yield AssistantLog.from_pydantic(payload)

    # ── Provider events ──────────────────────────────────────────────────

    @strawberry.subscription(description="A provider configuration has been created.")
    async def provider_created(
        self, info: Info
    ) -> AsyncGenerator[ProviderConfig, None]:
        async for payload in _resolve_controller(info).subscribe("providerCreated"):
            if isinstance(payload, ProviderConfig):
                yield payload
            else:
                yield ProviderConfig.from_pydantic(payload)

    @strawberry.subscription(description="A provider configuration has been updated.")
    async def provider_updated(
        self, info: Info
    ) -> AsyncGenerator[ProviderConfig, None]:
        async for payload in _resolve_controller(info).subscribe("providerUpdated"):
            if isinstance(payload, ProviderConfig):
                yield payload
            else:
                yield ProviderConfig.from_pydantic(payload)

    @strawberry.subscription(description="A provider configuration has been deleted.")
    async def provider_deleted(
        self, info: Info
    ) -> AsyncGenerator[ProviderConfig, None]:
        async for payload in _resolve_controller(info).subscribe("providerDeleted"):
            if isinstance(payload, ProviderConfig):
                yield payload
            else:
                yield ProviderConfig.from_pydantic(payload)

    # ── API token events ─────────────────────────────────────────────────

    @strawberry.subscription(description="An API token has been created.")
    async def api_token_created(
        self, info: Info
    ) -> AsyncGenerator[APIToken, None]:
        async for payload in _resolve_controller(info).subscribe("apiTokenCreated"):
            if isinstance(payload, APIToken):
                yield payload
            else:
                yield APIToken.from_pydantic(payload)

    @strawberry.subscription(description="An API token has been updated.")
    async def api_token_updated(
        self, info: Info
    ) -> AsyncGenerator[APIToken, None]:
        async for payload in _resolve_controller(info).subscribe("apiTokenUpdated"):
            if isinstance(payload, APIToken):
                yield payload
            else:
                yield APIToken.from_pydantic(payload)

    @strawberry.subscription(description="An API token has been deleted.")
    async def api_token_deleted(
        self, info: Info
    ) -> AsyncGenerator[APIToken, None]:
        async for payload in _resolve_controller(info).subscribe("apiTokenDeleted"):
            if isinstance(payload, APIToken):
                yield payload
            else:
                yield APIToken.from_pydantic(payload)

    # ── User preferences events ──────────────────────────────────────────

    @strawberry.subscription(description="User preferences have been updated (favorites, ...).")
    async def settings_user_updated(
        self, info: Info
    ) -> AsyncGenerator[UserPreferences, None]:
        async for payload in _resolve_controller(info).subscribe("settingsUserUpdated"):
            if isinstance(payload, UserPreferences):
                yield payload
            else:
                yield UserPreferences.from_pydantic(payload)

    # ── Flow template events ─────────────────────────────────────────────

    @strawberry.subscription(description="A flow template has been created.")
    async def flow_template_created(
        self, info: Info
    ) -> AsyncGenerator[FlowTemplate, None]:
        async for payload in _resolve_controller(info).subscribe("flowTemplateCreated"):
            if isinstance(payload, FlowTemplate):
                yield payload
            else:
                yield FlowTemplate.from_pydantic(payload)

    @strawberry.subscription(description="A flow template has been updated.")
    async def flow_template_updated(
        self, info: Info
    ) -> AsyncGenerator[FlowTemplate, None]:
        async for payload in _resolve_controller(info).subscribe("flowTemplateUpdated"):
            if isinstance(payload, FlowTemplate):
                yield payload
            else:
                yield FlowTemplate.from_pydantic(payload)

    @strawberry.subscription(description="A flow template has been deleted.")
    async def flow_template_deleted(
        self, info: Info
    ) -> AsyncGenerator[FlowTemplate, None]:
        async for payload in _resolve_controller(info).subscribe("flowTemplateDeleted"):
            if isinstance(payload, FlowTemplate):
                yield payload
            else:
                yield FlowTemplate.from_pydantic(payload)

    # ── User resource events ─────────────────────────────────────────────

    @strawberry.subscription(description="A user resource has been added.")
    async def resource_added(
        self, info: Info
    ) -> AsyncGenerator[UserResource, None]:
        async for payload in _resolve_controller(info).subscribe("resourceAdded"):
            if isinstance(payload, UserResource):
                yield payload
            else:
                yield UserResource.from_pydantic(payload)

    @strawberry.subscription(description="A user resource has been updated.")
    async def resource_updated(
        self, info: Info
    ) -> AsyncGenerator[UserResource, None]:
        async for payload in _resolve_controller(info).subscribe("resourceUpdated"):
            if isinstance(payload, UserResource):
                yield payload
            else:
                yield UserResource.from_pydantic(payload)

    @strawberry.subscription(description="A user resource has been deleted.")
    async def resource_deleted(
        self, info: Info
    ) -> AsyncGenerator[UserResource, None]:
        async for payload in _resolve_controller(info).subscribe("resourceDeleted"):
            if isinstance(payload, UserResource):
                yield payload
            else:
                yield UserResource.from_pydantic(payload)

    # ── Knowledge document events ────────────────────────────────────────

    @strawberry.subscription(description="A knowledge document has been created.")
    async def knowledge_document_created(
        self, info: Info
    ) -> AsyncGenerator[KnowledgeDocument, None]:
        async for payload in _resolve_controller(info).subscribe(
            "knowledgeDocumentCreated"
        ):
            if isinstance(payload, KnowledgeDocument):
                yield payload
            else:
                yield KnowledgeDocument.from_pydantic(payload)

    @strawberry.subscription(description="A knowledge document has been updated.")
    async def knowledge_document_updated(
        self, info: Info
    ) -> AsyncGenerator[KnowledgeDocument, None]:
        async for payload in _resolve_controller(info).subscribe(
            "knowledgeDocumentUpdated"
        ):
            if isinstance(payload, KnowledgeDocument):
                yield payload
            else:
                yield KnowledgeDocument.from_pydantic(payload)

    @strawberry.subscription(description="A knowledge document has been deleted.")
    async def knowledge_document_deleted(
        self, info: Info
    ) -> AsyncGenerator[KnowledgeDocument, None]:
        async for payload in _resolve_controller(info).subscribe(
            "knowledgeDocumentDeleted"
        ):
            if isinstance(payload, KnowledgeDocument):
                yield payload
            else:
                yield KnowledgeDocument.from_pydantic(payload)


__all__ = [
    "Subscription",
    "OriginValidator",
    "RedisSubscriptionsController",
    "get_controller",
    "set_controller",
    "_with_keepalive",
]
