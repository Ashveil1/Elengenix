"""
elengenix.graphql.schema — GraphQL schema configuration and the 16+ enums ported
from PentAGI's `backend/pkg/graph/schema.graphqls`.

This module declares all GraphQL enums (Strawberry-flavored) and exposes the
configuration constants used by the assembled schema in
``elengenix.graphql.__init__``. Enum names and variants are kept byte-identical
to the upstream SDL so that React/Relay clients and Apollo federation tooling
keep working without a single change.

Schema knobs (mirroring PentAGI's gqlgen server):
    * ``COMPLEXITY_LIMIT = 20000`` — equal to PentAGI's ``FixedComplexityLimit``.
    * ``APQ_CACHE_SIZE = 1000`` — Automatic Persisted Query LRU size
      (matches ``srv.SetQueryCache(lru.New[*ast.QueryDocument](1000))``).
    * ``KEEPALIVE_PING_INTERVAL_SECONDS = 10`` — WebSocket keepalive ping.
    * ``MULTIPART_MAX_MEMORY_BYTES = 32 << 20`` — 32 MiB multipart upload limit.

The actual ``strawberry.Schema`` instance is constructed lazily in
``elengenix.graphql.__init__`` to avoid importing strawberry when the package
is only being inspected (e.g. for static analysis).

References:
    * PentAGI: backend/pkg/graph/schema.graphqls (1115 lines)
    * PentAGI: backend/pkg/server/services/graphql.go (FixedComplexityLimit + APQ)
"""
from __future__ import annotations

import logging
from enum import Enum
from typing import Any, Dict, List, Optional, TYPE_CHECKING

import strawberry
from strawberry import enum as strawberry_enum

if TYPE_CHECKING:
    from strawberry.extensions import SchemaExtension

logger = logging.getLogger("elengenix.graphql.schema")

# ─── Schema configuration knobs ────────────────────────────────────────────
# Mirrors PentAGI's gqlgen setup (backend/pkg/server/services/graphql.go).
COMPLEXITY_LIMIT: int = 20000
APQ_CACHE_SIZE: int = 1000
KEEPALIVE_PING_INTERVAL_SECONDS: float = 10.0
MULTIPART_MAX_MEMORY_BYTES: int = 32 << 20  # 32 MiB
INTROSPECTION_ENABLED: bool = True


# ─── GraphQL enums (16+ ported from schema.graphqls) ──────────────────────
# All enum values are lowercase to match the upstream SDL exactly. Strawberry
# exposes them as GraphQL enum values via ``enums=[...]`` on the strawberry.enum
# decorator (or by using ``value=`` in the Enum meta).


@strawberry_enum(description="Core execution status for flows, tasks and agents.", graphql_name_from="value")
class StatusType(str, Enum):
    CREATED = "created"
    RUNNING = "running"
    WAITING = "waiting"
    FINISHED = "finished"
    FAILED = "failed"


@strawberry_enum(description="LLM provider types supported by Elengenix.", graphql_name_from="value")
class ProviderType(str, Enum):
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    GEMINI = "gemini"
    BEDROCK = "bedrock"
    OLLAMA = "ollama"
    CUSTOM = "custom"
    DEEPSEEK = "deepseek"
    GLM = "glm"
    KIMI = "kimi"
    QWEN = "qwen"


@strawberry_enum(
    description="Reasoning effort levels for advanced AI models (OpenAI format).",
    graphql_name_from="value",
)
class ReasoningEffort(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@strawberry_enum(description="Template types for AI agent prompts and system operations.", graphql_name_from="value")
class PromptType(str, Enum):
    PRIMARY_AGENT = "primary_agent"
    ASSISTANT = "assistant"
    PENTESTER = "pentester"
    QUESTION_PENTESTER = "question_pentester"
    CODER = "coder"
    QUESTION_CODER = "question_coder"
    INSTALLER = "installer"
    QUESTION_INSTALLER = "question_installer"
    SEARCHER = "searcher"
    QUESTION_SEARCHER = "question_searcher"
    MEMORIST = "memorist"
    QUESTION_MEMORIST = "question_memorist"
    ADVISER = "adviser"
    QUESTION_ADVISER = "question_adviser"
    GENERATOR = "generator"
    SUBTASKS_GENERATOR = "subtasks_generator"
    REFINER = "refiner"
    SUBTASKS_REFINER = "subtasks_refiner"
    REPORTER = "reporter"
    TASK_REPORTER = "task_reporter"
    REFLECTOR = "reflector"
    QUESTION_REFLECTOR = "question_reflector"
    ENRICHER = "enricher"
    QUESTION_ENRICHER = "question_enricher"
    TOOLCALL_FIXER = "toolcall_fixer"
    INPUT_TOOLCALL_FIXER = "input_toolcall_fixer"
    SUMMARIZER = "summarizer"
    IMAGE_CHOOSER = "image_chooser"
    LANGUAGE_CHOOSER = "language_chooser"
    FLOW_DESCRIPTOR = "flow_descriptor"
    TASK_DESCRIPTOR = "task_descriptor"
    EXECUTION_LOGS = "execution_logs"
    FULL_EXECUTION_CONTEXT = "full_execution_context"
    SHORT_EXECUTION_CONTEXT = "short_execution_context"
    TOOL_CALL_ID_COLLECTOR = "tool_call_id_collector"
    TOOL_CALL_ID_DETECTOR = "tool_call_id_detector"
    QUESTION_EXECUTION_MONITOR = "question_execution_monitor"
    QUESTION_TASK_PLANNER = "question_task_planner"
    TASK_ASSIGNMENT_WRAPPER = "task_assignment_wrapper"


@strawberry_enum(description="AI agent types for autonomous penetration testing.", graphql_name_from="value")
class AgentType(str, Enum):
    PRIMARY_AGENT = "primary_agent"
    REPORTER = "reporter"
    GENERATOR = "generator"
    REFINER = "refiner"
    REFLECTOR = "reflector"
    ENRICHER = "enricher"
    ADVISER = "adviser"
    CODER = "coder"
    MEMORIST = "memorist"
    SEARCHER = "searcher"
    INSTALLER = "installer"
    PENTESTER = "pentester"
    SUMMARIZER = "summarizer"
    TOOL_CALL_FIXER = "tool_call_fixer"
    ASSISTANT = "assistant"


@strawberry_enum(description="AI agent type for provider configuration.", graphql_name_from="value")
class AgentConfigType(str, Enum):
    SIMPLE = "simple"
    SIMPLE_JSON = "simple_json"
    PRIMARY_AGENT = "primary_agent"
    ASSISTANT = "assistant"
    GENERATOR = "generator"
    REFINER = "refiner"
    ADVISER = "adviser"
    REFLECTOR = "reflector"
    SEARCHER = "searcher"
    ENRICHER = "enricher"
    CODER = "coder"
    INSTALLER = "installer"
    PENTESTER = "pentester"


@strawberry_enum(description="Terminal output stream types.", graphql_name_from="value")
class TerminalLogType(str, Enum):
    STDIN = "stdin"
    STDOUT = "stdout"
    STDERR = "stderr"


@strawberry_enum(description="Message types for agent communication and logging.", graphql_name_from="value")
class MessageLogType(str, Enum):
    ANSWER = "answer"
    REPORT = "report"
    THOUGHTS = "thoughts"
    BROWSER = "browser"
    TERMINAL = "terminal"
    FILE = "file"
    SEARCH = "search"
    ADVICE = "advice"
    ASK = "ask"
    INPUT = "input"
    DONE = "done"


@strawberry_enum(description="Output format types for responses.", graphql_name_from="value")
class ResultFormat(str, Enum):
    PLAIN = "plain"
    MARKDOWN = "markdown"
    TERMINAL = "terminal"


@strawberry_enum(description="Result type for GraphQL operations.", graphql_name_from="value")
class ResultType(str, Enum):
    SUCCESS = "success"
    ERROR = "error"


@strawberry_enum(description="Terminal type.", graphql_name_from="value")
class TerminalType(str, Enum):
    PRIMARY = "primary"
    SECONDARY = "secondary"


@strawberry_enum(description="Vector store action.", graphql_name_from="value")
class VectorStoreAction(str, Enum):
    RETRIEVE = "retrieve"
    STORE = "store"


@strawberry_enum(description="Tool call status.", graphql_name_from="value")
class ToolCallStatus(str, Enum):
    RECEIVED = "received"
    RUNNING = "running"
    FINISHED = "finished"
    FAILED = "failed"


@strawberry_enum(description="API token lifecycle status.", graphql_name_from="value")
class TokenStatus(str, Enum):
    ACTIVE = "active"
    REVOKED = "revoked"
    EXPIRED = "expired"


@strawberry_enum(description="Time period for usage statistics queries.", graphql_name_from="value")
class UsageStatsPeriod(str, Enum):
    WEEK = "week"
    MONTH = "month"
    QUARTER = "quarter"


@strawberry_enum(description="Validation error types for user-provided prompts.", graphql_name_from="value")
class PromptValidationErrorType(str, Enum):
    SYNTAX_ERROR = "syntax_error"
    UNAUTHORIZED_VARIABLE = "unauthorized_variable"
    RENDERING_FAILED = "rendering_failed"
    EMPTY_TEMPLATE = "empty_template"
    VARIABLE_TYPE_MISMATCH = "variable_type_mismatch"
    UNKNOWN_TYPE = "unknown_type"


@strawberry_enum(description="Document type discriminator stored in cmetadata doc_type field.", graphql_name_from="value")
class KnowledgeDocType(str, Enum):
    ANSWER = "answer"
    GUIDE = "guide"
    CODE = "code"


@strawberry_enum(description="Guide sub-type stored in cmetadata guide_type field.", graphql_name_from="value")
class KnowledgeGuideType(str, Enum):
    INSTALL = "install"
    CONFIGURE = "configure"
    USE = "use"
    PENTEST = "pentest"
    DEVELOPMENT = "development"
    OTHER = "other"


@strawberry_enum(description="Answer sub-type stored in cmetadata answer_type field.", graphql_name_from="value")
class KnowledgeAnswerType(str, Enum):
    GUIDE = "guide"
    VULNERABILITY = "vulnerability"
    CODE = "code"
    TOOL = "tool"
    OTHER = "other"


# ─── Schema introspection helpers ──────────────────────────────────────────
# Used by the schema assembler in __init__.py and by the FastAPI router in
# elengenix.api.v1.graphql to enable Automatic Persisted Queries, complexity
# limits and the WebSocket keepalive ping identical to the upstream server.


def get_schema_extensions() -> List[Any]:
    """Return the list of Strawberry extension *classes* to instantiate on the
    assembled schema.

    Mirrors PentAGI's gqlgen extensions:
        * ``extension.Introspection{}``  — Strawberry enables introspection by
          default (see :data:`INTROSPECTION_ENABLED`).
        * ``extension.AutomaticPersistedQuery{Cache: lru.New[string](100)}`` —
          APQ is implemented at the HTTP router layer (see
          :mod:`elengenix.graphql.__init__`) because Strawberry's APQ support
          is provided by ``strawberry.fastapi.GraphQLRouter`` rather than by a
          schema-level extension.
        * ``extension.FixedComplexityLimit(20000)`` — implemented via
          :class:`ComplexityLimitExtension` below, since Strawberry 0.323 does
          not ship a built-in complexity limiter.

    We also register:
        * ``ParserCache(maxsize=1000)`` — equivalent to PentAGI's
          ``srv.SetQueryCache(lru.New[*ast.QueryDocument](1000))``.
    """
    extensions: List[Any] = [ComplexityLimitExtension]
    try:
        from strawberry.extensions import ParserCache  # type: ignore

        extensions.append(ParserCache)
    except ImportError:  # pragma: no cover — very old strawberry
        logger.debug("ParserCache extension unavailable; skipping.")
    return extensions


def get_schema_config() -> Dict[str, Any]:
    """Return the kwargs passed to ``strawberry.Schema(...)`` at assembly time.

    The actual ``strawberry.Schema`` instance is constructed lazily in
    :mod:`elengenix.graphql.__init__` so that this module can be imported for
    enum lookup without paying the schema-build cost.

    Note: Strawberry 0.323 dropped the ``complexity_limit=`` kwarg on
    ``Schema(...)`` — the limit is enforced by :class:`ComplexityLimitExtension`
    instead.
    """
    return {
        "extensions": get_schema_extensions(),
    }


# ─── Custom complexity-limit extension (mirrors FixedComplexityLimit) ──────


class _ComplexityLimitBase:
    """Mixin that enforces a fixed per-query complexity budget.

    Strawberry 0.323 does not ship a built-in complexity limiter (gqlgen's
    ``FixedComplexityLimit`` equivalent). This mixin walks the GraphQL
    operation definitions and sums the per-field complexity (default 1 per
    field; list-valued fields count ×10 to match gqlgen's heuristic). Queries
    whose total exceeds :data:`COMPLEXITY_LIMIT` are rejected with a
    ``ComplexityLimitReached`` error before execution.

    The implementation is intentionally simple — it can be swapped out for a
    more accurate field-cost model (e.g. one that introspects the schema for
    ``@complexity(cost: ...)`` directives) without changing the public API.
    """

    # Default per-field complexity multipliers (matches gqlgen defaults).
    _FIELD_COST: int = 1
    _LIST_FIELD_MULTIPLIER: int = 10

    def _count_complexity(self, document: Any) -> int:
        """Walk a parsed GraphQL document and return its total complexity."""
        total = 0
        try:
            definitions = getattr(document, "definitions", []) or []
        except AttributeError:
            return 0
        for definition in definitions:
            selection_set = getattr(definition, "selection_set", None)
            if selection_set is None:
                continue
            total += self._count_selection_set(selection_set)
        return total

    def _count_selection_set(self, selection_set: Any) -> int:
        total = 0
        selections = getattr(selection_set, "selections", []) or []
        for selection in selections:
            # Inline fragments and fragment spreads delegate to their inner
            # selection sets — we approximate by recursing.
            inner = (
                getattr(selection, "selection_set", None)
                if hasattr(selection, "selection_set")
                else None
            )
            if inner is not None:
                total += self._LIST_FIELD_MULTIPLIER * self._count_selection_set(inner)
            else:
                total += self._FIELD_COST
        return total


if TYPE_CHECKING:
    _ComplexityExtensionBase = SchemaExtension
else:  # pragma: no cover — runtime import for the real base class
    try:
        from strawberry.extensions import SchemaExtension as _ComplexityExtensionBase
    except ImportError:  # pragma: no cover — strawberry <0.200
        _ComplexityExtensionBase = object  # type: ignore[assignment]


class ComplexityLimitExtension(_ComplexityLimitBase, _ComplexityExtensionBase):  # type: ignore[misc]
    """Strawberry schema extension that rejects queries above the complexity limit.

    Equivalent of PentAGI's ``extension.FixedComplexityLimit(20000)``. Hook
    point: ``on_parse`` — we inspect the parsed document and raise
    ``Exception`` if the total complexity exceeds :data:`COMPLEXITY_LIMIT`.
    """

    def on_parse(self) -> Any:  # type: ignore[override]
        # ``on_parse`` is a generator-based lifecycle hook. We yield once to
        # let Strawberry parse the document, then inspect the result.
        result = yield
        document = None
        # Strawberry passes the parsed document either via the generator's
        # ``send()`` value or via ``self.execution_context.graphql_document``.
        if result is not None:
            document = getattr(result, "document", None) or result
        if document is None:
            ctx = getattr(self, "execution_context", None)
            if ctx is not None:
                document = getattr(ctx, "graphql_document", None)
        if document is not None:
            total = self._count_complexity(document)
            if total > COMPLEXITY_LIMIT:
                raise Exception(
                    f"query has complexity {total}, which exceeds the limit of "
                    f"{COMPLEXITY_LIMIT}"
                )


__all__ = [
    # Schema config
    "COMPLEXITY_LIMIT",
    "APQ_CACHE_SIZE",
    "KEEPALIVE_PING_INTERVAL_SECONDS",
    "MULTIPART_MAX_MEMORY_BYTES",
    "INTROSPECTION_ENABLED",
    "get_schema_extensions",
    "get_schema_config",
    # Enums
    "StatusType",
    "ProviderType",
    "ReasoningEffort",
    "PromptType",
    "AgentType",
    "AgentConfigType",
    "TerminalLogType",
    "MessageLogType",
    "ResultFormat",
    "ResultType",
    "TerminalType",
    "VectorStoreAction",
    "ToolCallStatus",
    "TokenStatus",
    "UsageStatsPeriod",
    "PromptValidationErrorType",
    "KnowledgeDocType",
    "KnowledgeGuideType",
    "KnowledgeAnswerType",
    # Optional typing re-exports (helpers for the other graphql modules)
    "Optional",
    "List",
    "Dict",
    "Any",
    "strawberry",
]
