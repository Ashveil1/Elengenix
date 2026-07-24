"""Langfuse LLM observability integration for Elengenix.

Ports PentAGI's ``backend/pkg/observability/lfclient.go`` and
``backend/pkg/observability/langfuse/observation.go`` to the official
Langfuse Python SDK. PentAGI's Go upstream implements its own Langfuse
REST client because no Go SDK existed; in Python we can lean on the
official ``langfuse`` package which natively supports:

* asynchronous batching + background flush,
* the ``@observe()`` decorator for automatic span creation,
* the W3C ``traceparent`` propagator for OpenTelemetry bridge mode.

Mapping of PentAGI observation types to Langfuse Python SDK ``@observe``
calls (all carry ``TraceID + ParentObservationID`` so the trace tree is
preserved):

    Agent      → @observe(name="agent",      type="agent")
    Tool       → @observe(name="tool",       type="tool")
    Chain      → @observe(name="chain",      type="chain")
    Generation → @observe(name="generation", type="generation")
    Retriever  → @observe(name="retriever",  type="retriever")
    Evaluator  → @observe(name="evaluator",  type="evaluator")
    Embedding  → @observe(name="embedding",  type="embedding")
    Guardrail  → @observe(name="guardrail",  type="guardrail")
    Score      → @observe(name="score",      type="score")
    Log        → @observe(name="log",        type="log")

OTel bridge: set ``LANGFUSE_OTEL_EXPORTER_OTLP_ENDPOINT`` to the OTel
collector's OTLP endpoint so Langfuse traces flow through the same
pipeline as the rest of Elengenix's spans — unifying the Jaeger view
(matching PentAGI's ``Opentelemetry.Exporttraces`` sub-client).

All imports of ``langfuse`` are **lazy** so this module degrades to
no-op decorators when the SDK is not installed.
"""

from __future__ import annotations

import asyncio
import functools
import inspect
import logging
import os
import threading
from typing import Any, Awaitable, Callable, Optional, TypeVar, overload

logger = logging.getLogger("elengenix.observability.langfuse")

F = TypeVar("F", bound=Callable[..., Any])
AsyncF = TypeVar("AsyncF", bound=Callable[..., Awaitable[Any]])


# ---------------------------------------------------------------------------
# Langfuse observation type registry (mirrors PentAGI's Observation interface)
# ---------------------------------------------------------------------------
OBSERVATION_TYPES: dict[str, str] = {
    "agent": "agent",
    "tool": "tool",
    "chain": "chain",
    "generation": "generation",
    "retriever": "retriever",
    "evaluator": "evaluator",
    "embedding": "embedding",
    "guardrail": "guardrail",
    "score": "score",
    "log": "log",
}


class LangfuseClient:
    """Process-wide singleton Langfuse client.

    Initialised lazily from ``LANGFUSE_HOST``, ``LANGFUSE_PUBLIC_KEY`` and
    ``LANGFUSE_SECRET_KEY`` (matches PentAGI's ``cfg.LangfuseBaseURL`` /
    ``cfg.LangfusePublicKey`` / ``cfg.LangfuseSecretKey``).

    When the Langfuse SDK is not installed — or when the env vars are
    missing — the client operates in *degraded* mode: ``get_client``
    returns ``None`` and ``@observe`` decorators become pass-throughs.
    """

    _instance: Optional["LangfuseClient"] = None
    _lock = threading.Lock()

    def __new__(cls) -> "LangfuseClient":
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance._client = None  # type: ignore[attr-defined]
                cls._instance._initialized = False  # type: ignore[attr-defined]
        return cls._instance

    def __init__(self) -> None:
        if getattr(self, "_initialized", False):
            return
        self._client: Any = None
        self._initialized = False
        self._init_client()

    # -- initialisation ----------------------------------------------------
    def _init_client(self) -> None:
        host = os.environ.get("LANGFUSE_HOST")
        public_key = os.environ.get("LANGFUSE_PUBLIC_KEY")
        secret_key = os.environ.get("LANGFUSE_SECRET_KEY")

        if not (host and public_key and secret_key):
            logger.debug(
                "Langfuse env vars missing (LANGFUSE_HOST/PUBLIC_KEY/SECRET_KEY); "
                "running in degraded mode (observability disabled)."
            )
            self._client = None
            self._initialized = True
            return

        try:
            from langfuse import Langfuse  # type: ignore[import-not-found]
        except ImportError as exc:
            logger.warning(
                "Langfuse SDK not installed (%s); LLM observability disabled. "
                "Install with `pip install langfuse` to enable.",
                exc,
            )
            self._client = None
            self._initialized = True
            return

        # Bridge Langfuse traces through the same OTel collector pipeline —
        # matches PentAGI's ``Opentelemetry.Exporttraces`` sub-client.
        kwargs: dict[str, Any] = {
            "host": host,
            "public_key": public_key,
            "secret_key": secret_key,
        }
        # The Langfuse Python SDK reads ``LANGFUSE_OTEL_EXPORTER_OTLP_ENDPOINT``
        # from env directly when set, so we only forward the explicit arg if
        # the caller pre-set it.
        otel_endpoint = os.environ.get("LANGFUSE_OTEL_EXPORTER_OTLP_ENDPOINT")
        if otel_endpoint:
            kwargs["otel_endpoint"] = otel_endpoint

        try:
            self._client = Langfuse(**kwargs)
            logger.info("Langfuse client connected to %s", host)
        except Exception as exc:  # pragma: no cover — defensive
            logger.warning("Failed to initialise Langfuse client: %s", exc)
            self._client = None
        self._initialized = True

    # -- accessors ---------------------------------------------------------
    @property
    def client(self) -> Any:
        """Underlying ``langfuse.Langfuse`` instance or ``None`` if degraded."""
        return self._client

    @property
    def enabled(self) -> bool:
        """``True`` when Langfuse SDK is installed and configured."""
        return self._client is not None

    # -- lifecycle ---------------------------------------------------------
    def flush(self) -> None:
        """Flush any pending events synchronously.

        Safe to call from any thread. When degraded, this is a no-op.
        """
        if self._client is None:
            return
        try:
            self._client.flush()
        except Exception as exc:  # pragma: no cover — defensive
            logger.debug("Langfuse flush failed: %s", exc)

    async def flush_async(self) -> None:
        """Async flush — bridges the SDK's synchronous flush to the event loop."""
        if self._client is None:
            return
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, self.flush)

    def shutdown(self) -> None:
        """Gracefully close the client and flush pending events."""
        if self._client is None:
            return
        try:
            self._client.flush()
        except Exception as exc:  # pragma: no cover
            logger.debug("Langfuse pre-shutdown flush failed: %s", exc)
        # The official SDK exposes no explicit ``close`` method beyond flush;
        # subsequent calls become no-ops.
        self._client = None
        self._initialized = False
        logger.info("Langfuse client shut down")

    # -- trace context (mirror PentAGI TraceID + ParentObservationID) ------
    def get_current_trace_id(self) -> Optional[str]:
        """Return the active Langfuse trace id (or ``None`` when degraded)."""
        if self._client is None:
            return None
        try:
            from langfuse.debug import get_current_trace_id  # type: ignore[import-not-found]
        except ImportError:
            try:
                # Older SDK versions expose this on the client itself.
                return getattr(self._client, "get_current_trace_id", lambda: None)()
            except Exception:  # pragma: no cover
                return None
        try:
            return get_current_trace_id()
        except Exception:  # pragma: no cover
            return None

    def get_current_observation_id(self) -> Optional[str]:
        """Return the active Langfuse observation id (parent for nested spans)."""
        if self._client is None:
            return None
        try:
            from langfuse.debug import get_current_observation_id  # type: ignore[import-not-found]
        except ImportError:
            return None
        try:
            return get_current_observation_id()
        except Exception:  # pragma: no cover
            return None


# ---------------------------------------------------------------------------
# Singleton accessor
# ---------------------------------------------------------------------------
def get_client() -> LangfuseClient:
    """Return the process-wide :class:`LangfuseClient` (singleton)."""
    return LangfuseClient()


# ---------------------------------------------------------------------------
# @observe decorator factory (mirrors PentAGI's per-type observation factories)
# ---------------------------------------------------------------------------
def _passthrough_decorator(
    func: Callable[..., Any], name: str, obs_type: str
) -> Callable[..., Any]:
    """No-op decorator returned when Langfuse is unavailable.

    Preserves the original function's signature and return type so callers
    cannot tell the difference between instrumented and non-instrumented runs.
    """
    if inspect.iscoroutinefunction(func):

        @functools.wraps(func)
        async def _async_wrapper(*args: Any, **kwargs: Any) -> Any:
            return await func(*args, **kwargs)

        return _async_wrapper

    @functools.wraps(func)
    def _sync_wrapper(*args: Any, **kwargs: Any) -> Any:
        return func(*args, **kwargs)

    return _sync_wrapper


def observe(
    name: Optional[str] = None,
    *,
    type: Optional[str] = None,
    **observe_kwargs: Any,
) -> Callable[[F], F]:
    """Wrap a function in a Langfuse observation span.

    Parameters
    ----------
    name:
        Display name of the observation. Defaults to the function name.
    type:
        One of :data:`OBSERVATION_TYPES` (``agent``, ``tool``, ``chain``,
        ``generation``, ``retriever``, ``evaluator``, ``embedding``,
        ``guardrail``, ``score``, ``log``). When provided, the Langfuse SDK
        records the observation under this type — the same set PentAGI's
        ``Observation`` interface exposes.
    **observe_kwargs:
        Extra kwargs forwarded to the SDK's ``@observe`` decorator (e.g.
        ``capture_input=True``, ``capture_output=False``).

    When Langfuse is degraded, this returns a pass-through decorator so the
    wrapped function still works unchanged.
    """
    obs_type = type.lower() if isinstance(type, str) else None
    if obs_type is not None and obs_type not in OBSERVATION_TYPES:
        logger.warning(
            "Unknown Langfuse observation type %r — expected one of %s",
            obs_type,
            sorted(OBSERVATION_TYPES),
        )

    client = get_client()
    sdk_observe: Optional[Callable[..., Any]] = None
    if client.enabled:
        try:
            from langfuse import observe as _sdk_observe  # type: ignore[import-not-found]
        except ImportError:
            sdk_observe = None
        else:
            sdk_observe = _sdk_observe

    def decorator(func: F) -> F:
        if sdk_observe is None:
            return _passthrough_decorator(func, name or func.__name__, obs_type or "log")  # type: ignore[return-value]
        # The SDK's ``@observe`` accepts ``name`` and (in newer versions)
        # ``as_type``. We translate our ``type`` kwarg to ``as_type`` for the
        # newer API while staying compatible with the older signature.
        sdk_kwargs: dict[str, Any] = dict(observe_kwargs)
        if name is not None:
            sdk_kwargs["name"] = name
        if obs_type is not None:
            # ``as_type`` was added in langfuse >= 2.40; fall back gracefully.
            sdk_kwargs.setdefault("as_type", obs_type)
        try:
            return sdk_observe(**sdk_kwargs)(func)  # type: ignore[return-value]
        except TypeError:
            # Older SDKs do not accept ``as_type`` — retry without it.
            sdk_kwargs.pop("as_type", None)
            return sdk_observe(**sdk_kwargs)(func)  # type: ignore[return-value]

    return decorator


# ---------------------------------------------------------------------------
# Convenience aliases — mirror PentAGI's Observation interface factories.
# ---------------------------------------------------------------------------
@overload
def agent(func: AsyncF) -> AsyncF: ...


@overload
def agent(func: F) -> F: ...


def agent(func: Any) -> Any:
    """``@observe(type="agent")`` — wraps an agent flow handler."""
    return observe(name=func.__name__, type="agent")(func)


@overload
def tool(func: AsyncF) -> AsyncF: ...


@overload
def tool(func: F) -> F: ...


def tool(func: Any) -> Any:
    """``@observe(type="tool")`` — wraps a tool-call handler."""
    return observe(name=func.__name__, type="tool")(func)


@overload
def chain(func: AsyncF) -> AsyncF: ...


@overload
def chain(func: F) -> F: ...


def chain(func: Any) -> Any:
    """``@observe(type="chain")`` — wraps a chain summariser / chain handler."""
    return observe(name=func.__name__, type="chain")(func)


@overload
def generation(func: AsyncF) -> AsyncF: ...


@overload
def generation(func: F) -> F: ...


def generation(func: Any) -> Any:
    """``@observe(type="generation")`` — wraps an LLM generation call."""
    return observe(name=func.__name__, type="generation")(func)


@overload
def retriever(func: AsyncF) -> AsyncF: ...


@overload
def retriever(func: F) -> F: ...


def retriever(func: Any) -> Any:
    """``@observe(type="retriever")`` — wraps a retrieval handler."""
    return observe(name=func.__name__, type="retriever")(func)


@overload
def evaluator(func: AsyncF) -> AsyncF: ...


@overload
def evaluator(func: F) -> F: ...


def evaluator(func: Any) -> Any:
    """``@observe(type="evaluator")`` — wraps an evaluator."""
    return observe(name=func.__name__, type="evaluator")(func)


@overload
def embedding(func: AsyncF) -> AsyncF: ...


@overload
def embedding(func: F) -> F: ...


def embedding(func: Any) -> Any:
    """``@observe(type="embedding")`` — wraps an embedding call."""
    return observe(name=func.__name__, type="embedding")(func)


@overload
def guardrail(func: AsyncF) -> AsyncF: ...


@overload
def guardrail(func: F) -> F: ...


def guardrail(func: Any) -> Any:
    """``@observe(type="guardrail")`` — wraps a guardrail check."""
    return observe(name=func.__name__, type="guardrail")(func)


@overload
def score(func: AsyncF) -> AsyncF: ...


@overload
def score(func: F) -> F: ...


def score(func: Any) -> Any:
    """``@observe(type="score")`` — wraps a scorer."""
    return observe(name=func.__name__, type="score")(func)


@overload
def log(func: AsyncF) -> AsyncF: ...


@overload
def log(func: F) -> F: ...


def log(func: Any) -> Any:
    """``@observe(type="log")`` — wraps a structured-log emission."""
    return observe(name=func.__name__, type="log")(func)


# ---------------------------------------------------------------------------
# Module-level lifecycle helpers
# ---------------------------------------------------------------------------
def flush() -> None:
    """Async-friendly alias — flushes the singleton client."""
    get_client().flush()


async def flush_async() -> None:
    """Awaitable flush — wraps the synchronous flush in ``run_in_executor``."""
    await get_client().flush_async()


def shutdown() -> None:
    """Shut down the singleton client (flushes pending events)."""
    get_client().shutdown()


__all__ = [
    "OBSERVATION_TYPES",
    "LangfuseClient",
    "get_client",
    "observe",
    "agent",
    "tool",
    "chain",
    "generation",
    "retriever",
    "evaluator",
    "embedding",
    "guardrail",
    "score",
    "log",
    "flush",
    "flush_async",
    "shutdown",
]
