"""Structured logging for Elengenix — ``structlog`` + OTel logs bridge.

Mirrors PentAGI's ``Observability`` logrus hook behaviour
(``backend/pkg/observability/obs.go``): every structured-log record is
auto-injected with the active OpenTelemetry trace context and (when
Langfuse is enabled) the active Langfuse trace / observation ids, then
forwarded to the OTel logs pipeline so it lands in Loki alongside spans
landing in Jaeger.

Configuration:

* ``setup_logging(level="INFO", json_logs=False)`` — call once at process
  start. When ``json_logs=True`` (production), records are JSON-encoded;
  when ``False`` (dev), they pretty-print with colours.
* ``get_logger(name)`` — returns a ``structlog.BoundLogger`` bound to
  ``name``. The logger carries ``trace_id``, ``span_id``,
  ``langfuse_trace_id`` and ``langfuse_observation_id`` keys automatically
  (no-op when no active span / Langfuse session).

The Python ``logging`` package is bridged into the OTel logs pipeline via
``opentelemetry-instrumentation-logging`` (registered by ``setup_otel``)
so any module using ``logging.getLogger`` automatically gets the same
treatment — equivalent to PentAGI's logrus hook.
"""

from __future__ import annotations

import logging
import sys
import threading
from typing import Any, Optional

logger = logging.getLogger("elengenix.observability.logging")

# Standard Python level names → numeric values (used to bridge to structlog).
_LOG_LEVELS: dict[str, int] = {
    "DEBUG": logging.DEBUG,
    "INFO": logging.INFO,
    "WARNING": logging.WARNING,
    "ERROR": logging.ERROR,
    "CRITICAL": logging.CRITICAL,
}

_setup_lock = threading.Lock()
_setup_done: bool = False


class _TraceContextProcessor:
    """structlog processor — inject OTel + Langfuse trace context into each record.

    Adds four keys to every log event:

    * ``trace_id`` — W3C trace id of the active OTel span (hex) or ``None``.
    * ``span_id`` — W3C span id of the active OTel span (hex) or ``None``.
    * ``langfuse_trace_id`` — active Langfuse trace id or ``None``.
    * ``langfuse_observation_id`` — active Langfuse observation id or ``None``.

    The Langfuse ids are pulled lazily so importing this module does not
    require the Langfuse SDK.
    """

    def __init__(self) -> None:
        self._langfuse_getters: Optional[tuple[Any, Any]] = None
        self._langfuse_checked = False

    def __call__(
        self,
        logger: Any,
        method_name: str,
        event_dict: dict[str, Any],
    ) -> dict[str, Any]:
        # --- OpenTelemetry trace context ---
        trace_id: Optional[str] = None
        span_id: Optional[str] = None
        try:
            from opentelemetry import trace

            span = trace.get_current_span()
            ctx = span.get_span_context() if span is not None else None
            if ctx is not None and ctx.is_valid:
                trace_id = f"{ctx.trace_id:032x}"
                span_id = f"{ctx.span_id:016x}"
        except Exception:  # pragma: no cover — defensive
            pass

        event_dict.setdefault("trace_id", trace_id)
        event_dict.setdefault("span_id", span_id)

        # --- Langfuse trace context ---
        lf_trace: Optional[str] = None
        lf_obs: Optional[str] = None
        if not self._langfuse_checked:
            self._langfuse_checked = True
            try:
                from langfuse.debug import (  # type: ignore[import-not-found]
                    get_current_observation_id,
                    get_current_trace_id,
                )

                self._langfuse_getters = (get_current_trace_id, get_current_observation_id)
            except ImportError:
                self._langfuse_getters = None

        if self._langfuse_getters is not None:
            try:
                lf_trace = self._langfuse_getters[0]()
                lf_obs = self._langfuse_getters[1]()
            except Exception:  # pragma: no cover — defensive
                pass

        event_dict.setdefault("langfuse_trace_id", lf_trace)
        event_dict.setdefault("langfuse_observation_id", lf_obs)
        return event_dict


def _build_processors(json_logs: bool) -> list[Any]:
    """Construct the structlog processor chain.

    Pipeline order (left-to-right):

    1. ``merge_contextvars`` — propagates ``contextvars``-bound keys.
    2. ``add_log_level`` — adds ``level`` key (matches PentAGI's logrus
       ``level`` field).
    3. ``TimeStamper(fmt="iso", utc=True)`` — ISO-8601 UTC timestamps
       (matches Loki ingestion expectations).
    4. :class:`_TraceContextProcessor` — trace ids (OTel + Langfuse).
    5. ``StackInfoRenderer`` — adds ``stack_info`` when present.
    6. ``format_exc_info`` — renders ``exc_info`` into ``exception``.
    7. Renderer — ``JSONRenderer`` (prod) or ``ConsoleRenderer`` (dev).
    """
    try:
        import structlog  # type: ignore[import-not-found]
    except ImportError:  # pragma: no cover — defensive
        return []

    processors: list[Any] = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_log_level,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        _TraceContextProcessor(),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
    ]
    if json_logs:
        processors.append(structlog.processors.JSONRenderer())
    else:
        processors.append(structlog.dev.ConsoleRenderer(colors=sys.stderr.isatty()))
    return processors


def setup_logging(level: str = "INFO", json_logs: bool = False) -> None:
    """Configure structlog + Python ``logging`` for the whole process.

    Parameters
    ----------
    level:
        Root log level (case-insensitive). One of ``DEBUG``, ``INFO``,
        ``WARNING``, ``ERROR``, ``CRITICAL``.
    json_logs:
        ``True`` for JSON-encoded output (production); ``False`` for
        pretty-printed coloured output (dev).
    """
    global _setup_done
    with _setup_lock:
        if _setup_done:
            logger.debug("setup_logging already called — re-applying level only")
            _apply_level(level)
            return

        try:
            import structlog  # type: ignore[import-not-found]
        except ImportError as exc:
            # Fall back to plain ``logging`` — still useful for CLI runs.
            logging.basicConfig(
                level=_LOG_LEVELS.get(level.upper(), logging.INFO),
                format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
                stream=sys.stderr,
                force=True,
            )
            logger.warning(
                "structlog not installed (%s); falling back to stdlib logging.", exc
            )
            _setup_done = True
            return

        structlog.configure(
            processors=_build_processors(json_logs),
            wrapper_class=structlog.make_filtering_bound_logger(
                _LOG_LEVELS.get(level.upper(), logging.INFO)
            ),
            logger_factory=structlog.PrintLoggerFactory(file=sys.stderr),
            cache_logger_on_first_use=True,
        )

        # Bridge stdlib ``logging`` into structlog so any module using
        # ``logging.getLogger`` gets the same renderer + trace context.
        formatter = structlog.stdlib.ProcessorFormatter(
            processor=structlog.stdlib.ProcessorFormatter.remove_processors_meta,
            foreign_pre_chain=[
                structlog.stdlib.add_log_level,
                structlog.processors.TimeStamper(fmt="iso", utc=True),
                _TraceContextProcessor(),
            ],
        )
        handler = logging.StreamHandler(sys.stderr)
        handler.setFormatter(formatter)
        root = logging.getLogger()
        root.handlers.clear()
        root.addHandler(handler)
        root.setLevel(_LOG_LEVELS.get(level.upper(), logging.INFO))

        # The OTel logging instrumentor (registered in otel.py) also installs
        # a handler — make sure we don't double-emit. The handler we just
        # installed is the canonical sink.
        _apply_level(level)
        _setup_done = True
        logger.info("Structured logging initialised (level=%s, json=%s)", level, json_logs)


def _apply_level(level: str) -> None:
    """Apply the requested level to the root Python logger."""
    logging.getLogger().setLevel(_LOG_LEVELS.get(level.upper(), logging.INFO))


def get_logger(name: str) -> Any:
    """Return a ``structlog.BoundLogger`` bound to ``name``.

    Falls back to a plain ``logging.Logger`` when structlog is unavailable
    so callers can use the same API either way.
    """
    try:
        import structlog  # type: ignore[import-not-found]
    except ImportError:
        return logging.getLogger(name)
    return structlog.get_logger(name)


def bind_context(**kwargs: Any) -> None:
    """Bind keys to the current contextvar context (propagates to all logs)."""
    try:
        import structlog  # type: ignore[import-not-found]
    except ImportError:
        return
    structlog.contextvars.bind_contextvars(**kwargs)


def clear_context() -> None:
    """Clear all contextvar-bound keys."""
    try:
        import structlog  # type: ignore[import-not-found]
    except ImportError:
        return
    structlog.contextvars.clear_contextvars()


__all__ = [
    "setup_logging",
    "get_logger",
    "bind_context",
    "clear_context",
]
