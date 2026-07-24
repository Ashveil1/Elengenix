"""Custom Elengenix metrics — mirrors PentAGI's Grafana dashboard contract.

PentAGI exposes a fixed set of custom metrics under the
``backend/pkg/observability/obs.go`` ``Meter`` interface; the existing
Grafana dashboards (``pentagi_service.json`` etc.) query Prometheus for
exactly these names. To keep those dashboards working unchanged after the
Python port, we mirror the same names + label cardinalities here.

Metric inventory
----------------

* ``elengenix_token_usage_counter`` — ``Int64Counter``
  Labels: ``provider``, ``model``, ``agent_type``, ``direction`` ∈ {``in``,
  ``out``}. Tracks tokens consumed per LLM call.

* ``elengenix_toolcalls_duration_histogram`` — ``Histogram``
  Labels: ``tool_name``, ``agent_type``, ``status``. Records wall-clock
  duration of each tool execution (seconds).

* ``elengenix_flows_count_gauge`` — ``UpDownCounter`` (gauge-like)
  Labels: ``status`` ∈ {``created``, ``running``, ``waiting``,
  ``finished``, ``failed``}. Active flow count per state.

* ``elengenix_agent_iterations_histogram`` — ``Histogram``
  Labels: ``agent_type``. Number of iterations performed by an agent run
  before terminating.

* ``elengenix_docker_container_count_gauge`` — ``UpDownCounter``
  Labels: ``status`` ∈ {``created``, ``running``, ``stopped``, ``failed``}.

* ``elengenix_search_provider_counter`` — ``Int64Counter``
  Labels: ``provider``, ``status`` ∈ {``success``, ``failure``}.

* ``elengenix_knowledge_graph_nodes_gauge`` — ``UpDownCounter``
  Labels: ``group_id``.

All metric operations are **no-op safe**: if ``setup_otel`` has not been
called (or the OTel SDK is missing), every record call silently succeeds
against a no-op meter.
"""

from __future__ import annotations

import logging
import threading
from typing import Any, Optional

logger = logging.getLogger("elengenix.observability.metrics")

# Histogram bucket boundaries (seconds for durations, count for iterations).
# Matches VictoriaMetrics' default Prometheus-style aggregation.
_DURATION_BUCKETS: tuple[float, ...] = (
    0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0,
    10.0, 30.0, 60.0, 120.0, 300.0, 600.0,
)
_ITERATION_BUCKETS: tuple[float, ...] = (
    1, 2, 3, 5, 8, 13, 21, 34, 55, 89, 144,
)

_TOKEN_COST_BUCKETS: tuple[float, ...] = (
    0.0001, 0.001, 0.01, 0.1, 0.5, 1.0, 5.0, 10.0, 50.0, 100.0,
)

# Metric name constants — exported so callers can reference them.
TOKEN_USAGE_COUNTER = "elengenix_token_usage_counter"
TOOLCALLS_DURATION_HISTOGRAM = "elengenix_toolcalls_duration_histogram"
FLOWS_COUNT_GAUGE = "elengenix_flows_count_gauge"
AGENT_ITERATIONS_HISTOGRAM = "elengenix_agent_iterations_histogram"
DOCKER_CONTAINER_COUNT_GAUGE = "elengenix_docker_container_count_gauge"
SEARCH_PROVIDER_COUNTER = "elengenix_search_provider_counter"
KNOWLEDGE_GRAPH_NODES_GAUGE = "elengenix_knowledge_graph_nodes_gauge"


class _NoOpInstrument:
    """No-op Counter / Histogram / UpDownCounter."""

    def add(self, *args: Any, **kwargs: Any) -> None:
        return None

    def record(self, *args: Any, **kwargs: Any) -> None:
        return None


class _Metrics:
    """Holder for all custom metric instruments.

    Lazy-initialised on first access via :func:`_get_metrics` so the OTel
    SDK is only imported when a metric is actually recorded.
    """

    def __init__(self) -> None:
        self.token_usage: Any = _NoOpInstrument()
        self.toolcalls_duration: Any = _NoOpInstrument()
        self.flows_count: Any = _NoOpInstrument()
        self.agent_iterations: Any = _NoOpInstrument()
        self.docker_container_count: Any = _NoOpInstrument()
        self.search_provider: Any = _NoOpInstrument()
        self.kg_nodes: Any = _NoOpInstrument()
        self._initialised = False

    def initialise(self, meter: Any) -> None:
        """Bind the instruments to ``meter`` (an OTel ``Meter``)."""
        if self._initialised:
            return
        try:
            self.token_usage = meter.create_counter(
                name=TOKEN_USAGE_COUNTER,
                unit="tokens",
                description="LLM token usage per provider/model/agent_type/direction.",
            )
            self.toolcalls_duration = meter.create_histogram(
                name=TOOLCALLS_DURATION_HISTOGRAM,
                unit="s",
                description="Wall-clock duration of tool executions.",
                explicit_bucket_boundaries_advisory=_DURATION_BUCKETS,
            )
            self.flows_count = meter.create_up_down_counter(
                name=FLOWS_COUNT_GAUGE,
                unit="flows",
                description="Active flow count by status.",
            )
            self.agent_iterations = meter.create_histogram(
                name=AGENT_ITERATIONS_HISTOGRAM,
                unit="iterations",
                description="Number of iterations per agent run.",
                explicit_bucket_boundaries_advisory=_ITERATION_BUCKETS,
            )
            self.docker_container_count = meter.create_up_down_counter(
                name=DOCKER_CONTAINER_COUNT_GAUGE,
                unit="containers",
                description="Active Docker container count by status.",
            )
            self.search_provider = meter.create_counter(
                name=SEARCH_PROVIDER_COUNTER,
                unit="searches",
                description="Search provider call count by status.",
            )
            self.kg_nodes = meter.create_up_down_counter(
                name=KNOWLEDGE_GRAPH_NODES_GAUGE,
                unit="nodes",
                description="Knowledge-graph node count by group_id.",
            )
            self._initialised = True
            logger.debug("Custom metrics bound to OTel meter")
        except Exception as exc:  # pragma: no cover — defensive
            logger.warning("Failed to initialise custom metrics: %s", exc)
            # Stays as no-op instruments.


_metrics: _Metrics = _Metrics()
_metrics_lock = threading.Lock()


def _get_metrics() -> _Metrics:
    """Return the singleton metrics holder, initialising it lazily.

    On first call, attempts to bind the instruments to the OTel meter
    registered by ``setup_otel``. If the meter is missing / a no-op, the
    instruments remain no-op and all ``record_*`` calls succeed silently.
    """
    if _metrics._initialised:
        return _metrics
    with _metrics_lock:
        if _metrics._initialised:
            return _metrics
        try:
            from .otel import get_meter

            meter = get_meter()
            _metrics.initialise(meter)
        except Exception as exc:  # pragma: no cover — defensive
            logger.debug("Metrics not bound (%s) — operating in no-op mode", exc)
    return _metrics


def _coerce_attrs(**kwargs: Any) -> dict[str, str]:
    """Coerce metric attribute values to strings (OTel requirement)."""
    return {k: str(v) for k, v in kwargs.items() if v is not None}


# ---------------------------------------------------------------------------
# Public recording API — every function is no-op safe.
# ---------------------------------------------------------------------------
def record_token_usage(
    provider: str,
    model: str,
    agent_type: str,
    direction: str,
    tokens: int,
    cost: Optional[float] = None,
) -> None:
    """Increment the token usage counter.

    Parameters
    ----------
    provider:
        LLM provider name (e.g. ``"openai"``, ``"anthropic"``).
    model:
        Model identifier (e.g. ``"gpt-4o"``, ``"claude-3-7-sonnet"``).
    agent_type:
        Agent type that triggered the call (e.g. ``"primary_agent"``).
    direction:
        ``"in"`` for prompt tokens, ``"out"`` for completion tokens.
    tokens:
        Number of tokens consumed.
    cost:
        Optional USD cost — currently logged at debug level only (the
        Langfuse SDK tracks costs in its own score API).
    """
    if tokens <= 0:
        return
    m = _get_metrics()
    attrs = _coerce_attrs(
        provider=provider,
        model=model,
        agent_type=agent_type,
        direction=direction,
    )
    try:
        m.token_usage.add(tokens, attributes=attrs)
    except Exception as exc:  # pragma: no cover — defensive
        logger.debug("record_token_usage failed: %s", exc)
    if cost is not None and cost > 0:
        logger.debug(
            "token_usage cost provider=%s model=%s direction=%s cost=%.6f",
            provider,
            model,
            direction,
            cost,
        )


def record_toolcall(
    tool_name: str,
    agent_type: str,
    duration_seconds: float,
    status: str = "success",
) -> None:
    """Record a tool execution duration.

    Parameters
    ----------
    tool_name:
        Tool name (e.g. ``"terminal"``, ``"browser"``, ``"search"``).
    agent_type:
        Agent type that invoked the tool.
    duration_seconds:
        Wall-clock duration in seconds.
    status:
        ``"success"`` or ``"failure"`` — recorded as a label so the
        Grafana panel can split by outcome.
    """
    if duration_seconds < 0:
        return
    m = _get_metrics()
    attrs = _coerce_attrs(tool_name=tool_name, agent_type=agent_type, status=status)
    try:
        m.toolcalls_duration.record(duration_seconds, attributes=attrs)
    except Exception as exc:  # pragma: no cover
        logger.debug("record_toolcall failed: %s", exc)


def record_agent_iteration(agent_type: str, iterations: int) -> None:
    """Record how many iterations an agent run took before terminating.

    Parameters
    ----------
    agent_type:
        Agent type (e.g. ``"primary_agent"``, ``"searcher"``).
    iterations:
        Number of iterations actually performed.
    """
    if iterations < 0:
        return
    m = _get_metrics()
    attrs = _coerce_attrs(agent_type=agent_type)
    try:
        m.agent_iterations.record(iterations, attributes=attrs)
    except Exception as exc:  # pragma: no cover
        logger.debug("record_agent_iteration failed: %s", exc)


def update_flow_count(status: str, delta: int = 1) -> None:
    """Increment / decrement the active flow gauge.

    Parameters
    ----------
    status:
        Flow state (``"created"``, ``"running"``, ``"waiting"``,
        ``"finished"``, ``"failed"``).
    delta:
        ``+1`` to increment, ``-1`` to decrement.
    """
    if delta == 0:
        return
    m = _get_metrics()
    attrs = _coerce_attrs(status=status)
    try:
        m.flows_count.add(delta, attributes=attrs)
    except Exception as exc:  # pragma: no cover
        logger.debug("update_flow_count failed: %s", exc)


def update_docker_container_count(status: str, delta: int = 1) -> None:
    """Increment / decrement the Docker container gauge.

    Parameters
    ----------
    status:
        Container state (``"created"``, ``"running"``, ``"stopped"``,
        ``"failed"``).
    delta:
        ``+1`` to increment, ``-1`` to decrement.
    """
    if delta == 0:
        return
    m = _get_metrics()
    attrs = _coerce_attrs(status=status)
    try:
        m.docker_container_count.add(delta, attributes=attrs)
    except Exception as exc:  # pragma: no cover
        logger.debug("update_docker_container_count failed: %s", exc)


def record_search_provider(provider: str, status: str = "success") -> None:
    """Increment the search provider counter.

    Parameters
    ----------
    provider:
        Search provider name (e.g. ``"duckduckgo"``, ``"tavily"``).
    status:
        ``"success"`` or ``"failure"``.
    """
    m = _get_metrics()
    attrs = _coerce_attrs(provider=provider, status=status)
    try:
        m.search_provider.add(1, attributes=attrs)
    except Exception as exc:  # pragma: no cover
        logger.debug("record_search_provider failed: %s", exc)


def update_knowledge_graph_nodes(group_id: str, delta: int = 1) -> None:
    """Increment / decrement the knowledge-graph node gauge.

    Parameters
    ----------
    group_id:
        Tenant / scope group id for the graph.
    delta:
        ``+1`` to add, ``-1`` to remove.
    """
    if delta == 0:
        return
    m = _get_metrics()
    attrs = _coerce_attrs(group_id=group_id)
    try:
        m.kg_nodes.add(delta, attributes=attrs)
    except Exception as exc:  # pragma: no cover
        logger.debug("update_knowledge_graph_nodes failed: %s", exc)


def reset_for_tests() -> None:
    """Reset the singleton (test-only — never call in production code)."""
    global _metrics
    with _metrics_lock:
        _metrics = _Metrics()


__all__ = [
    "TOKEN_USAGE_COUNTER",
    "TOOLCALLS_DURATION_HISTOGRAM",
    "FLOWS_COUNT_GAUGE",
    "AGENT_ITERATIONS_HISTOGRAM",
    "DOCKER_CONTAINER_COUNT_GAUGE",
    "SEARCH_PROVIDER_COUNTER",
    "KNOWLEDGE_GRAPH_NODES_GAUGE",
    "record_token_usage",
    "record_toolcall",
    "record_agent_iteration",
    "update_flow_count",
    "update_docker_container_count",
    "record_search_provider",
    "update_knowledge_graph_nodes",
    "reset_for_tests",
]
