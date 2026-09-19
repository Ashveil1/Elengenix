"""Elengenix observability package.

Re-exports the public API of the four observability sub-modules:

* :mod:`elengenix.observability.otel` — OpenTelemetry tracer / meter /
  logger setup + auto-instrumentation of FastAPI / httpx / asyncpg / redis.
* :mod:`elengenix.observability.langfuse` — Langfuse LLM observability
  singleton + ``@observe()`` decorators mapped to PentAGI's observation
  types (agent / tool / chain / generation / retriever / evaluator /
  embedding / guardrail / score / log).
* :mod:`elengenix.observability.logging` — ``structlog`` configuration
  with trace-context injection (``trace_id``, ``span_id``,
  ``langfuse_trace_id``, ``langfuse_observation_id``) and OTel logs
  pipeline bridge.
* :mod:`elengenix.observability.metrics` — custom metrics mirroring
  PentAGI's Grafana dashboard contract (token usage, toolcalls duration,
  flows count, agent iterations, docker containers, search providers,
  knowledge-graph nodes).
* :mod:`elengenix.observability.chains` — chain summarisation helpers
  re-exported from :mod:`elengenix.agent.crew.summarizer`.

Typical usage::

    from elengenix.observability import setup_otel, setup_logging, get_logger

    setup_logging(level="INFO", json_logs=True)
    setup_otel(service_name="elengenix", otlp_endpoint="http://otel:4318")
    log = get_logger("elengenix.api")

All third-party imports (``opentelemetry``, ``langfuse``, ``structlog``)
are lazy — the package degrades to no-op observability when any of them is
missing, so a minimal CLI install runs without the full observability
stack installed.
"""

from __future__ import annotations

import logging

logger = logging.getLogger("elengenix.observability")

# --- OpenTelemetry ---------------------------------------------------------
from .otel import (  # noqa: F401
    EXPORT_INTERVAL_SECONDS,
    EXPORT_TIMEOUT_SECONDS,
    get_logger_provider,
    get_meter,
    get_tracer,
    setup_otel,
    shutdown_otel,
)

# --- Langfuse --------------------------------------------------------------
from .langfuse import (  # noqa: F401
    OBSERVATION_TYPES,
    LangfuseClient,
    agent,
    chain,
    embedding,
    evaluator,
    flush as flush_langfuse,
    flush_async as flush_async_langfuse,
    generation,
    get_client,
    guardrail,
    log,
    observe,
    retriever,
    score,
    shutdown as shutdown_langfuse,
    tool,
)

# --- Structured logging ----------------------------------------------------
from .logging import (  # noqa: F401
    bind_context,
    clear_context,
    get_logger,
    setup_logging,
)

# --- Custom metrics --------------------------------------------------------
from .metrics import (  # noqa: F401
    AGENT_ITERATIONS_HISTOGRAM,
    DOCKER_CONTAINER_COUNT_GAUGE,
    FLOWS_COUNT_GAUGE,
    KNOWLEDGE_GRAPH_NODES_GAUGE,
    SEARCH_PROVIDER_COUNTER,
    TOKEN_USAGE_COUNTER,
    TOOLCALLS_DURATION_HISTOGRAM,
    record_agent_iteration,
    record_search_provider,
    record_token_usage,
    record_toolcall,
    reset_for_tests,
    update_docker_container_count,
    update_flow_count,
    update_knowledge_graph_nodes,
)

# --- Chain summarisation helpers ------------------------------------------
from .chains import (  # noqa: F401
    GEMINI_FAKE_THOUGHT_SIGNATURE,
    SUMMARY_TOOL_NAME,
    SUMMARIZED_CONTENT_PREFIX,
    SUMMARIZER_SYSTEM_PROMPT,
    AsyncLLMProvider,
    BodyPair,
    BodyPairType,
    ChainAST,
    ChainSection,
    SectionHeader,
    Summarizer,
    SummarizerConfig,
    build_chain_ast,
    clear_reasoning,
    contains_summarized_content,
    contains_tool_call_reasoning,
    extract_reasoning_message,
    get_default_summarizer,
    normalize_tool_call_ids,
    serialize_chain,
    summarize_chain,
)


def setup_all(
    *,
    service_name: str = "elengenix",
    service_version: str = "2.0.0",
    environment: str | None = None,
    otlp_endpoint: str = "http://localhost:4318",
    log_level: str = "INFO",
    json_logs: bool = False,
) -> dict[str, object]:
    """Convenience entrypoint — initialise logging, OTel and Langfuse together.

    Returns the dict from :func:`setup_otel` (``{"tracer", "meter", "logger"}``).
    Safe to call multiple times — subsequent calls are no-ops for OTel and
    only adjust the log level for logging.
    """
    setup_logging(level=log_level, json_logs=json_logs)
    handles = setup_otel(
        service_name=service_name,
        service_version=service_version,
        environment=environment,
        otlp_endpoint=otlp_endpoint,
    )
    # Langfuse is lazy — calling ``get_client`` triggers env-var-driven init.
    client = get_client()
    if client.enabled:
        logger.info("Langfuse observability enabled")
    else:
        logger.debug("Langfuse observability disabled (env vars missing or SDK absent)")
    return handles


def shutdown_all() -> None:
    """Flush and shut down every observability subsystem in reverse order."""
    shutdown_langfuse()
    shutdown_otel()


__all__ = [
    # OTel
    "EXPORT_INTERVAL_SECONDS",
    "EXPORT_TIMEOUT_SECONDS",
    "setup_otel",
    "shutdown_otel",
    "get_tracer",
    "get_meter",
    "get_logger_provider",
    # Langfuse
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
    "flush_langfuse",
    "flush_async_langfuse",
    "shutdown_langfuse",
    # Logging
    "setup_logging",
    "get_logger",
    "bind_context",
    "clear_context",
    # Metrics
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
    # Chains
    "GEMINI_FAKE_THOUGHT_SIGNATURE",
    "SUMMARY_TOOL_NAME",
    "SUMMARIZED_CONTENT_PREFIX",
    "SUMMARIZER_SYSTEM_PROMPT",
    "AsyncLLMProvider",
    "BodyPair",
    "BodyPairType",
    "ChainAST",
    "ChainSection",
    "SectionHeader",
    "Summarizer",
    "SummarizerConfig",
    "build_chain_ast",
    "serialize_chain",
    "contains_summarized_content",
    "get_default_summarizer",
    "summarize_chain",
    "normalize_tool_call_ids",
    "clear_reasoning",
    "contains_tool_call_reasoning",
    "extract_reasoning_message",
    # Convenience
    "setup_all",
    "shutdown_all",
]
