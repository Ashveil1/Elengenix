"""OpenTelemetry setup for Elengenix (mirrors PentAGI's otelclient.go).

Ports the observability contract documented under Task 1-c of the worklog:

* Single OTLP exporter to the OTel Collector on ``:4318`` (HTTP) / ``:4317``
  (gRPC). PentAGI's Go upstream connects to ``:8148`` gRPC; the Python stack
  uses ``:4318`` HTTP because that's what the same Collector image exposes
  for the ``otlphttp`` receiver (gRPC would also work — pick the endpoint
  via ``otlp_endpoint``).
* Three SDK providers — Tracer, Meter, Logger — each with a 30-second
  export interval and 10-second export timeout (matches PentAGI's
  ``sdktrace.NewBatchSpanProcessor`` / ``sdkmetric.NewPeriodicReader`` /
  ``sdklog.NewBatchProcessor``).
* Resource attributes: ``service.name``, ``service.version``,
  ``deployment.environment``.
* W3C ``traceparent`` propagator (composite ``TraceContext + Baggage`` —
  identical to PentAGI's `` newTextMapPropagator(tracecontext.Baggage{})``).
* Auto-instruments FastAPI, httpx, asyncpg and redis (the same set the Go
  upstream instruments via otelhttp / otelpgx / otelredis).

All third-party imports are **lazy** so the module imports cleanly even when
the OpenTelemetry SDK is not installed (CLI runs without observability).
In that case ``setup_otel`` returns no-op implementations and metrics / log
bridges degrade to no-ops.
"""

from __future__ import annotations

import logging
import os
from typing import Any, Optional

logger = logging.getLogger("elengenix.observability.otel")

# 30 s export interval — matches PentAGI's BatchSpanProcessor / PeriodicReader.
EXPORT_INTERVAL_SECONDS: float = 30.0
# 10 s export timeout — matches PentAGI's batch export timeout.
EXPORT_TIMEOUT_SECONDS: float = 10.0

# Module-level state — populated by ``setup_otel``, drained by ``shutdown_otel``.
_tracer_provider: Any = None
_meter_provider: Any = None
_logger_provider: Any = None
_tracer: Any = None
_meter: Any = None
_otel_logger: Any = None
_instrumentors: list[Any] = []
_initialized: bool = False


class _NoOpTracer:
    """Fallback tracer returned when the OTel SDK is unavailable."""

    def start_span(self, *args: Any, **kwargs: Any) -> Any:
        from contextlib import nullcontext  # local import

        return nullcontext()

    # ``use_span`` is used by some helpers — provide a no-op version too.
    def use_span(self, *args: Any, **kwargs: Any) -> Any:
        from contextlib import nullcontext

        return nullcontext()


class _NoOpMeter:
    """Fallback meter — every counter/histogram/gauge is a silent no-op."""

    def create_counter(self, *args: Any, **kwargs: Any) -> Any:
        return _NoOpInstrument()

    def create_histogram(self, *args: Any, **kwargs: Any) -> Any:
        return _NoOpInstrument()

    def create_up_down_counter(self, *args: Any, **kwargs: Any) -> Any:
        return _NoOpInstrument()

    def create_observable_counter(self, *args: Any, **kwargs: Any) -> Any:
        return _NoOpInstrument()

    def create_observable_gauge(self, *args: Any, **kwargs: Any) -> Any:
        return _NoOpInstrument()

    def create_observable_up_down_counter(self, *args: Any, **kwargs: Any) -> Any:
        return _NoOpInstrument()

    def create_gauge(self, *args: Any, **kwargs: Any) -> Any:
        return _NoOpInstrument()


class _NoOpInstrument:
    """No-op Counter / Histogram / Gauge returned by :class:`_NoOpMeter`."""

    def add(self, *args: Any, **kwargs: Any) -> None:
        return None

    def record(self, *args: Any, **kwargs: Any) -> None:
        return None

    def set(self, *args: Any, **kwargs: Any) -> None:
        return None


class _NoOpLogger:
    """Fallback OTel logger."""

    def emit(self, *args: Any, **kwargs: Any) -> None:
        return None


def _is_otlp_grpc_endpoint(endpoint: str) -> bool:
    """Heuristic — gRPC endpoints typically use ``:4317`` or ``grpc://``."""
    if not endpoint:
        return False
    if endpoint.startswith("grpc://"):
        return True
    return ":4317" in endpoint or ":8148" in endpoint


def setup_otel(
    service_name: str = "elengenix",
    service_version: str = "2.0.0",
    environment: Optional[str] = None,
    otlp_endpoint: str = "http://localhost:4318",
) -> dict[str, Any]:
    """Initialise the OTel tracer / meter / logger providers.

    Parameters
    ----------
    service_name:
        ``service.name`` resource attribute.
    service_version:
        ``service.version`` resource attribute.
    environment:
        ``deployment.environment`` resource attribute. Defaults to the
        ``ENVIRONMENT`` env var, or ``"production"`` when unset.
    otlp_endpoint:
        OTLP collector endpoint. HTTP (``http://host:4318``) by default;
        switch to gRPC (``http://host:4317``) by passing a ``:4317`` /
        ``:8148`` URL. Override at runtime via ``OTEL_EXPORTER_OTLP_ENDPOINT``.

    Returns
    -------
    dict
        ``{"tracer", "meter", "logger"}`` — bound tracer / meter / logger
        instances. When the OTel SDK is unavailable, no-op stand-ins are
        returned so callers may use them without try/except.
    """
    global _tracer_provider, _meter_provider, _logger_provider
    global _tracer, _meter, _otel_logger, _instrumentors, _initialized

    if _initialized:
        logger.debug("setup_otel already called — returning cached handles")
        return {"tracer": _tracer, "meter": _meter, "logger": _otel_logger}

    env = environment or os.environ.get("ENVIRONMENT") or "production"
    endpoint = os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT") or otlp_endpoint

    try:
        from opentelemetry import metrics, trace
        from opentelemetry._logs import set_logger_provider
        from opentelemetry.sdk._logs import LoggerProvider, LoggingHandler
        from opentelemetry.sdk._logs.export import BatchLogRecordProcessor
        from opentelemetry.sdk.metrics import MeterProvider
        from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor
        from opentelemetry.trace import set_tracer_provider
        from opentelemetry.propagate import set_global_textmap
    except ImportError as exc:  # pragma: no cover — depends on env
        logger.warning(
            "OpenTelemetry SDK not installed (%s); observability disabled. "
            "Install `opentelemetry-distro opentelemetry-exporter-otlp` to enable.",
            exc,
        )
        _tracer, _meter, _otel_logger = _NoOpTracer(), _NoOpMeter(), _NoOpLogger()
        _initialized = True
        return {"tracer": _tracer, "meter": _meter, "logger": _otel_logger}

    resource = Resource.create(
        {
            "service.name": service_name,
            "service.version": service_version,
            "deployment.environment": env,
        }
    )

    # ---- Tracer provider -------------------------------------------------
    _tracer_provider = TracerProvider(resource=resource)

    try:
        if _is_otlp_grpc_endpoint(endpoint):
            from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import (
                OTLPSpanExporter,
            )
        else:
            from opentelemetry.exporter.otlp.proto.http.trace_exporter import (
                OTLPSpanExporter,
            )
        span_exporter = OTLPSpanExporter(endpoint=endpoint, timeout=EXPORT_TIMEOUT_SECONDS)
    except ImportError as exc:  # pragma: no cover
        logger.warning("OTLP span exporter unavailable: %s", exc)
        span_exporter = None

    if span_exporter is not None:
        _tracer_provider.add_span_processor(
            BatchSpanProcessor(
                span_exporter,
                export_timeout_millis=int(EXPORT_TIMEOUT_SECONDS * 1000),
                # The default schedule delay is 5 s; align to 30 s to match
                # PentAGI's batch processor configuration.
                schedule_delay_millis=int(EXPORT_INTERVAL_SECONDS * 1000),
            )
        )
    set_tracer_provider(_tracer_provider)
    _tracer = trace.get_tracer(service_name, service_version)

    # ---- Meter provider --------------------------------------------------
    metric_reader = None
    try:
        if _is_otlp_grpc_endpoint(endpoint):
            from opentelemetry.exporter.otlp.proto.grpc.metric_exporter import (
                OTLPMetricExporter,
            )
        else:
            from opentelemetry.exporter.otlp.proto.http.metric_exporter import (
                OTLPMetricExporter,
            )
        metric_exporter = OTLPMetricExporter(
            endpoint=endpoint,
            timeout=EXPORT_TIMEOUT_SECONDS,
        )
        metric_reader = PeriodicExportingMetricReader(
            metric_exporter,
            export_interval_millis=int(EXPORT_INTERVAL_SECONDS * 1000),
            export_timeout_millis=int(EXPORT_TIMEOUT_SECONDS * 1000),
        )
    except ImportError as exc:  # pragma: no cover
        logger.warning("OTLP metric exporter unavailable: %s", exc)

    _meter_provider = MeterProvider(resource=resource, metric_readers=[metric_reader] if metric_reader else [])
    metrics.set_meter_provider(_meter_provider)
    _meter = metrics.get_meter(service_name, service_version)

    # ---- Logger provider -------------------------------------------------
    _logger_provider = LoggerProvider(resource=resource)
    try:
        if _is_otlp_grpc_endpoint(endpoint):
            from opentelemetry.exporter.otlp.proto.grpc._logs_exporter import (
                OTLPLogExporter,
            )
        else:
            from opentelemetry.exporter.otlp.proto.http._logs_exporter import (
                OTLPLogExporter,
            )
        log_exporter = OTLPLogExporter(endpoint=endpoint, timeout=EXPORT_TIMEOUT_SECONDS)
        _logger_provider.add_log_record_processor(
            BatchLogRecordProcessor(
                log_exporter,
                export_timeout_millis=int(EXPORT_TIMEOUT_SECONDS * 1000),
                schedule_delay_millis=int(EXPORT_INTERVAL_SECONDS * 1000),
            )
        )
    except ImportError as exc:  # pragma: no cover
        logger.warning("OTLP log exporter unavailable: %s", exc)
    set_logger_provider(_logger_provider)
    _otel_logger = _logger_provider.get_logger(service_name)

    # ---- Propagator (W3C traceparent + baggage) --------------------------
    set_global_textmap(_composite_propagator())

    # ---- Auto-instrumentation -------------------------------------------
    _instrumentors = _auto_instrument()
    _initialized = True
    logger.info(
        "OpenTelemetry initialised: service=%s version=%s env=%s endpoint=%s",
        service_name,
        service_version,
        env,
        endpoint,
    )
    return {"tracer": _tracer, "meter": _meter, "logger": _otel_logger}


def _composite_propagator() -> Any:
    """Build the composite W3C ``tracecontext + baggage`` propagator."""
    from opentelemetry.baggage.propagation import W3CBaggagePropagator
    from opentelemetry.propagators.composite import CompositePropagator
    from opentelemetry.trace.propagation.tracecontext import (
        TraceContextTextMapPropagator,
    )

    return CompositePropagator(
        [TraceContextTextMapPropagator(), W3CBaggagePropagator()]
    )


def _auto_instrument() -> list[Any]:
    """Register FastAPI / httpx / asyncpg / redis auto-instrumentors.

    Each instrumentor is imported lazily and skipped silently when its
    dependency is not installed — this lets the observability package work
    across minimal CLI installs and full FastAPI deployments.
    """
    instrumentors: list[Any] = []
    instrumentor_specs: list[tuple[str, str]] = [
        # (module path, instrumentor class name)
        ("opentelemetry.instrumentation.fastapi", "FastAPIInstrumentor"),
        ("opentelemetry.instrumentation.httpx", "HTTPXClientInstrumentor"),
        ("opentelemetry.instrumentation.asyncpg", "AsyncPGInstrumentor"),
        ("opentelemetry.instrumentation.redis", "RedisInstrumentor"),
        # Logging bridge — wires Python ``logging`` into the OTel logs pipeline.
        ("opentelemetry.instrumentation.logging", "LoggingInstrumentor"),
    ]
    for module_path, class_name in instrumentor_specs:
        try:
            mod = __import__(module_path, fromlist=[class_name])
            instrumentor = getattr(mod, class_name)
            if instrumentor.is_instrumented_by_opentelemetry():
                continue
            instrumentor.instrument()
            instrumentors.append(instrumentor)
            logger.debug("Instrumented %s.%s", module_path, class_name)
        except ImportError as exc:
            logger.debug("Skipping %s (not installed: %s)", module_path, exc.name)
        except Exception as exc:  # pragma: no cover — defensive
            logger.warning("Failed to instrument %s.%s: %s", module_path, class_name, exc)
    return instrumentors


def get_tracer() -> Any:
    """Return the currently-configured tracer (or a no-op fallback)."""
    global _tracer
    if _tracer is None:
        return _NoOpTracer()
    return _tracer


def get_meter() -> Any:
    """Return the currently-configured meter (or a no-op fallback)."""
    global _meter
    if _meter is None:
        return _NoOpMeter()
    return _meter


def get_logger_provider() -> Any:
    """Return the OTel logger provider (or ``None`` when uninitialised)."""
    return _logger_provider


def shutdown_otel() -> None:
    """Gracefully flush all exporters and shut down the providers."""
    global _tracer_provider, _meter_provider, _logger_provider
    global _tracer, _meter, _otel_logger, _instrumentors, _initialized

    if not _initialized:
        return

    errors: list[str] = []

    # Uninstrument in reverse order.
    for instrumentor in reversed(_instrumentors):
        try:
            uninstrument = getattr(instrumentor, "uninstrument", None)
            if callable(uninstrument):
                uninstrument()
        except Exception as exc:  # pragma: no cover — defensive
            errors.append(f"uninstrument: {exc}")

    if _tracer_provider is not None:
        try:
            _tracer_provider.shutdown()
        except Exception as exc:  # pragma: no cover
            errors.append(f"tracer: {exc}")
    if _meter_provider is not None:
        try:
            _meter_provider.shutdown()
        except Exception as exc:  # pragma: no cover
            errors.append(f"meter: {exc}")
    if _logger_provider is not None:
        try:
            _logger_provider.shutdown()
        except Exception as exc:  # pragma: no cover
            errors.append(f"logger: {exc}")

    _tracer_provider = None
    _meter_provider = None
    _logger_provider = None
    _tracer = None
    _meter = None
    _otel_logger = None
    _instrumentors = []
    _initialized = False

    if errors:
        logger.warning("OTel shutdown completed with errors: %s", "; ".join(errors))
    else:
        logger.info("OTel shutdown complete")


__all__ = [
    "EXPORT_INTERVAL_SECONDS",
    "EXPORT_TIMEOUT_SECONDS",
    "setup_otel",
    "shutdown_otel",
    "get_tracer",
    "get_meter",
    "get_logger_provider",
]
