"""elengenix/flows/models.py — Pydantic v2 data models for the Flow management system.

This module ports PentAGI's four-tier data hierarchy (Flow → Task → SubTask →
Action/tool-call) to Python. Each entity carries a 5-state machine
(created → running → waiting ⇄ running → finished | failed) and the
``Msgchain`` model mirrors PentAGI's ``database.Msgchain`` so persisted agent
chains stay wire-compatible across the Go and Python implementations.

Models
------
* :class:`FlowStatus` / :class:`TaskStatus` / :class:`SubtaskStatus` —
  shared 5-state enums.
* :class:`MsgchainType` — 15 enum values mirroring PentAGI's
  ``database.MsgchainType``.
* :class:`MsglogType`, :class:`MsglogResultFormat`, :class:`ToolcallStatus`,
  :class:`TermlogType`, :class:`VecstoreActionType`, :class:`SearchengineType`,
  :class:`ProviderType`, :class:`ContainerStatus`, :class:`ContainerType` —
  supporting enums for log tables.
* :class:`Flow`, :class:`Task`, :class:`Subtask` — core hierarchy entities.
* :class:`SubtaskInfo` — planning-agent output (Generator / Refiner).
* :class:`SubtaskPatchOp` — Refiner delta-patch operation.
* :class:`Msgchain` — JSON-serialized agent message chain.
* :class:`Msglog`, :class:`Agentlog`, :class:`Toolcall`, :class:`Searchlog`,
  :class:`Termlog`, :class:`Vecstorelog`, :class:`Screenshot`,
  :class:`Container`, :class:`Prompt` — supporting log / record tables.

The Pydantic v2 ``ConfigDict(frozen=False)`` is used so models remain mutable
in place (the state machine updates ``status`` / ``updated_at`` in place
during back-propagation). ``model_config = ConfigDict(extra='allow')`` so
extra DB columns added in future migrations don't break deserialization.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


def _utcnow() -> datetime:
    """Return a timezone-aware UTC ``datetime`` (Pydantic-friendly)."""
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# 5-state enums — shared by Flow / Task / Subtask (mirrors PentAGI's
# ``FlowStatus`` / ``TaskStatus`` / ``SubtaskStatus``).
# ---------------------------------------------------------------------------


class FlowStatus(str, Enum):
    """Lifecycle state of a Flow.

    Mirrors PentAGI's ``database.FlowStatus``:
    ``created → running → waiting ⇄ running → finished | failed``.
    """

    CREATED = "created"
    RUNNING = "running"
    WAITING = "waiting"
    FINISHED = "finished"
    FAILED = "failed"


class TaskStatus(str, Enum):
    """Lifecycle state of a Task within a Flow.

    Mirrors PentAGI's ``database.TaskStatus``:
    ``created → running → waiting ⇄ running → finished | failed``.
    """

    CREATED = "created"
    RUNNING = "running"
    WAITING = "waiting"
    FINISHED = "finished"
    FAILED = "failed"


class SubtaskStatus(str, Enum):
    """Lifecycle state of a Subtask within a Task.

    Mirrors PentAGI's ``database.SubtaskStatus``:
    ``created → running → waiting ⇄ running → finished | failed``.
    """

    CREATED = "created"
    RUNNING = "running"
    WAITING = "waiting"
    FINISHED = "finished"
    FAILED = "failed"


# ---------------------------------------------------------------------------
# MsgchainType — 15 enum values mirroring PentAGI's ``database.MsgchainType``.
# The string values MUST match the Go constants verbatim so persisted msg
# chains remain cross-compatible.
# ---------------------------------------------------------------------------


class MsgchainType(str, Enum):
    """Type of agent that produced a persisted message chain.

    The 15 string values mirror PentAGI's ``database.MsgchainType`` enum
    so persisted msg-chain JSON stays cross-compatible across the Go and
    Python implementations.
    """

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


# ---------------------------------------------------------------------------
# Supporting enums for log tables — mirror PentAGI's database models.go.
# ---------------------------------------------------------------------------


class MsglogType(str, Enum):
    """Categorisation of a single user-visible message log entry."""

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


class MsglogResultFormat(str, Enum):
    """Render format hint for a message-log entry's ``result`` payload."""

    PLAIN = "plain"
    MARKDOWN = "markdown"
    TERMINAL = "terminal"


class ToolcallStatus(str, Enum):
    """Lifecycle state of a single tool call."""

    RECEIVED = "received"
    RUNNING = "running"
    FINISHED = "finished"
    FAILED = "failed"


class TermlogType(str, Enum):
    """Stream source for a terminal-log entry."""

    STDIN = "stdin"
    STDOUT = "stdout"
    STDERR = "stderr"


class VecstoreActionType(str, Enum):
    """Vector-store action (retrieve vs store) for a vecstore-log entry."""

    RETRIEVE = "retrieve"
    STORE = "store"


class SearchengineType(str, Enum):
    """Search-engine identifier for a search-log entry.

    Mirrors PentAGI's ``database.SearchengineType``.
    """

    GOOGLE = "google"
    TAVILY = "tavily"
    TRAVERSAAL = "traversaal"
    BROWSER = "browser"
    DUCKDUCKGO = "duckduckgo"
    PERPLEXITY = "perplexity"
    SEARXNG = "searxng"
    SPLOITUS = "sploitus"


class ProviderType(str, Enum):
    """LLM provider type identifier."""

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


class ContainerStatus(str, Enum):
    """Lifecycle state of a Docker sandbox container."""

    STARTING = "starting"
    RUNNING = "running"
    STOPPED = "stopped"
    DELETED = "deleted"
    FAILED = "failed"


class ContainerType(str, Enum):
    """Role of a container within a flow."""

    PRIMARY = "primary"
    SECONDARY = "secondary"


# ---------------------------------------------------------------------------
# Core hierarchy models — Flow / Task / Subtask.
# ---------------------------------------------------------------------------


class _BaseRecord(BaseModel):
    """Common Pydantic config for all flow-system records.

    ``extra='allow'`` lets DB rows with new columns (added by future
    migrations) deserialize without raising — unknown fields are kept on
    the model under ``model_extra``.
    """

    model_config = ConfigDict(
        extra="allow",
        use_enum_values=False,
        validate_assignment=True,
        populate_by_name=True,
    )


class Flow(_BaseRecord):
    """A single user engagement — the root of the 4-tier hierarchy.

    Mirrors PentAGI's ``database.Flow`` struct. ``functions`` is the
    JSON-serialized tool registry (Pydantic stores it as a dict; the DB
    layer handles JSON ↔ TEXT conversion).
    """

    id: int = Field(..., description="Primary key (auto-increment).")
    status: FlowStatus = Field(
        default=FlowStatus.CREATED,
        description="Lifecycle state of the flow.",
    )
    title: str = Field(default="untitled", description="Human-readable title.")
    model: str = Field(default="unknown", description="LLM model identifier.")
    model_provider_name: str = Field(
        default="", description="Provider name (e.g. 'openai')."
    )
    model_provider_type: ProviderType = Field(
        default=ProviderType.OPENAI,
        description="Provider type enum value.",
    )
    language: str = Field(
        default="English", description="Engagement-log language."
    )
    functions: dict[str, Any] = Field(
        default_factory=dict,
        description="Serialized tool registry (JSON in DB).",
    )
    user_id: int = Field(..., description="Owning user ID.")
    trace_id: str | None = Field(
        default=None, description="Observability trace ID (langfuse)."
    )
    tool_call_id_template: str = Field(
        default="",
        description="Template for generating tool-call IDs (provider-specific).",
    )
    created_at: datetime = Field(default_factory=_utcnow)
    updated_at: datetime = Field(default_factory=_utcnow)
    deleted_at: datetime | None = Field(default=None)


class Task(_BaseRecord):
    """A single user input / task within a Flow.

    Mirrors PentAGI's ``database.Task`` struct. Created by the FlowWorker
    on each ``PutInput``; decomposed into Subtasks by the Generator agent.
    """

    id: int = Field(..., description="Primary key (auto-increment).")
    status: TaskStatus = Field(
        default=TaskStatus.CREATED,
        description="Lifecycle state of the task.",
    )
    title: str = Field(default="", description="Short task title.")
    input: str = Field(..., description="Original user input text.")
    result: str = Field(default="", description="Final report from the Reporter agent.")
    flow_id: int = Field(..., description="Parent flow ID.")
    created_at: datetime = Field(default_factory=_utcnow)
    updated_at: datetime = Field(default_factory=_utcnow)


class Subtask(_BaseRecord):
    """A single planning step within a Task.

    Mirrors PentAGI's ``database.Subtask`` struct. Generated by the
    Generator agent and refined by the Refiner agent after each subtask
    completes. Each subtask runs as a single PrimaryAgent chain.
    """

    id: int = Field(..., description="Primary key (auto-increment).")
    status: SubtaskStatus = Field(
        default=SubtaskStatus.CREATED,
        description="Lifecycle state of the subtask.",
    )
    title: str = Field(default="", description="Short subtask title.")
    description: str = Field(
        default="", description="Full subtask description / instructions."
    )
    result: str = Field(
        default="", description="Final subtask result (set on finish)."
    )
    task_id: int = Field(..., description="Parent task ID.")
    context: str = Field(
        default="",
        description="Cached execution-context XML (rendered by Summarizer).",
    )
    created_at: datetime = Field(default_factory=_utcnow)
    updated_at: datetime = Field(default_factory=_utcnow)


# ---------------------------------------------------------------------------
# Planning models — SubtaskInfo (Generator output) and SubtaskPatchOp (Refiner).
# ---------------------------------------------------------------------------


class SubtaskInfo(BaseModel):
    """A single planned subtask emitted by the Generator or Refiner.

    Both fields are *engagement-log plan entries* — they appear verbatim
    in the engagement record and MUST be written in the engagement
    language declared by the system prompt.
    """

    model_config = ConfigDict(extra="forbid")

    title: str = Field(
        ...,
        max_length=200,
        description="Short title capturing the subtask's main goal.",
    )
    description: str = Field(
        ...,
        max_length=2000,
        description="Full description: instructions, rules, success criteria.",
    )


class SubtaskPatchOp(BaseModel):
    """A single delta operation on the planned-subtask list (Refiner output).

    Operation semantics:

    * ``add``     — insert a new subtask. ``subtask`` MUST be set. ``index``
      is the position to insert at (0 = beginning); if ``None`` the subtask
      is appended.
    * ``remove``  — delete an existing subtask. ``index`` MUST identify it.
    * ``modify``  — update title and/or description of an existing subtask.
      ``index`` MUST be set; ``subtask`` carries the new fields.
    * ``reorder`` — move an existing subtask. ``index`` is the subtask to
      move; ``new_order`` lists the desired new ordering of the affected
      subtasks (caller resolves absolute positions).
    """

    model_config = ConfigDict(extra="forbid")

    op: Literal["add", "remove", "modify", "reorder"] = Field(
        ...,
        description="Operation type.",
    )
    index: int | None = Field(
        default=None,
        ge=0,
        description="Index of the existing subtask (for remove / modify / reorder).",
    )
    subtask: SubtaskInfo | None = Field(
        default=None,
        description="New subtask payload (for add / modify).",
    )
    new_order: list[int] | None = Field(
        default=None,
        description="New ordering (list of indices) for the reorder op.",
    )


# ---------------------------------------------------------------------------
# Msgchain — JSON-serialized agent message chain.
# ---------------------------------------------------------------------------


class Msgchain(_BaseRecord):
    """A persisted agent message chain.

    Mirrors PentAGI's ``database.Msgchain`` struct. The ``chain`` field
    is the JSON-serialized list of ``llms.MessageContent`` payloads for
    one (flow, task, subtask, agent_type) tuple. Persisting chains enables
    resumability: when a subtask is in ``waiting`` state and the user
    submits new input, the SubtaskWorker loads the chain and continues
    from where it left off.

    Token / cost usage fields mirror PentAGI's: ``usage_in`` /
    ``usage_out`` are prompt / completion token counts;
    ``usage_cache_in`` / ``usage_cache_out`` are cached-token counts
    (Anthropic prompt caching); ``usage_cost_in`` / ``usage_cost_out``
    are USD costs; ``duration_seconds`` is the wall-clock duration.
    """

    id: int = Field(..., description="Primary key (auto-increment).")
    type: MsgchainType = Field(
        ..., description="Agent type that produced this chain."
    )
    model: str = Field(default="", description="LLM model identifier.")
    model_provider: str = Field(
        default="", description="Provider name (e.g. 'openai')."
    )
    usage_in: int = Field(default=0, description="Prompt token count.")
    usage_out: int = Field(default=0, description="Completion token count.")
    chain: list[dict[str, Any]] | dict[str, Any] = Field(
        default_factory=list,
        description="JSON-serialized message chain ([]llms.MessageContent).",
    )
    flow_id: int = Field(..., description="Parent flow ID.")
    task_id: int | None = Field(default=None, description="Parent task ID (nullable).")
    subtask_id: int | None = Field(
        default=None, description="Parent subtask ID (nullable)."
    )
    created_at: datetime = Field(default_factory=_utcnow)
    updated_at: datetime = Field(default_factory=_utcnow)
    usage_cache_in: int = Field(default=0, description="Cached prompt token count.")
    usage_cache_out: int = Field(
        default=0, description="Cached completion token count."
    )
    usage_cost_in: float = Field(default=0.0, description="Prompt cost (USD).")
    usage_cost_out: float = Field(default=0.0, description="Completion cost (USD).")
    duration_seconds: float = Field(
        default=0.0, description="Wall-clock duration in seconds."
    )


# ---------------------------------------------------------------------------
# Log / record tables — mirrors PentAGI's database models.go.
# ---------------------------------------------------------------------------


class Msglog(_BaseRecord):
    """A single user-visible message-log entry (engagement log)."""

    id: int = Field(..., description="Primary key (auto-increment).")
    type: MsglogType = Field(..., description="Message category.")
    message: str = Field(default="", description="User-visible message body.")
    result: str = Field(default="", description="Result / response body.")
    flow_id: int = Field(..., description="Parent flow ID.")
    task_id: int | None = Field(default=None, description="Parent task ID (nullable).")
    subtask_id: int | None = Field(
        default=None, description="Parent subtask ID (nullable)."
    )
    created_at: datetime = Field(default_factory=_utcnow)
    result_format: MsglogResultFormat = Field(
        default=MsglogResultFormat.MARKDOWN,
        description="Render format hint for the result body.",
    )
    thinking: str | None = Field(
        default=None, description="Provider-exposed reasoning content (nullable)."
    )


class Agentlog(_BaseRecord):
    """Agent-delegation log entry (initiator → executor)."""

    id: int = Field(..., description="Primary key (auto-increment).")
    initiator: MsgchainType = Field(
        ..., description="Agent that initiated the delegation."
    )
    executor: MsgchainType = Field(
        ..., description="Agent that executed the delegated work."
    )
    task: str = Field(default="", description="Delegated task description.")
    result: str = Field(default="", description="Delegation result.")
    flow_id: int = Field(..., description="Parent flow ID.")
    task_id: int | None = Field(default=None, description="Parent task ID (nullable).")
    subtask_id: int | None = Field(
        default=None, description="Parent subtask ID (nullable)."
    )
    created_at: datetime = Field(default_factory=_utcnow)


class Toolcall(_BaseRecord):
    """A single tool-call record (action-tier of the 4-tier hierarchy)."""

    id: int = Field(..., description="Primary key (auto-increment).")
    call_id: str = Field(..., description="LLM-assigned tool-call ID.")
    status: ToolcallStatus = Field(
        default=ToolcallStatus.RECEIVED,
        description="Lifecycle state of the tool call.",
    )
    name: str = Field(..., description="Tool name.")
    args: dict[str, Any] = Field(
        default_factory=dict,
        description="JSON-decoded tool-call arguments.",
    )
    result: str = Field(default="", description="Tool-call result body.")
    flow_id: int = Field(..., description="Parent flow ID.")
    task_id: int | None = Field(default=None, description="Parent task ID (nullable).")
    subtask_id: int | None = Field(
        default=None, description="Parent subtask ID (nullable)."
    )
    created_at: datetime = Field(default_factory=_utcnow)
    updated_at: datetime = Field(default_factory=_utcnow)
    duration_seconds: float = Field(
        default=0.0, description="Tool-call wall-clock duration (seconds)."
    )


class Searchlog(_BaseRecord):
    """Search-engine query / result log entry."""

    id: int = Field(..., description="Primary key (auto-increment).")
    initiator: MsgchainType = Field(
        ..., description="Agent that initiated the search."
    )
    executor: MsgchainType = Field(
        ..., description="Agent that executed the search."
    )
    engine: SearchengineType = Field(
        ..., description="Search engine used for the query."
    )
    query: str = Field(..., description="Search query string.")
    result: str = Field(default="", description="Search result body.")
    flow_id: int = Field(..., description="Parent flow ID.")
    task_id: int | None = Field(default=None, description="Parent task ID (nullable).")
    subtask_id: int | None = Field(
        default=None, description="Parent subtask ID (nullable)."
    )
    created_at: datetime = Field(default_factory=_utcnow)


class Termlog(_BaseRecord):
    """Terminal-stream log entry (stdin / stdout / stderr)."""

    id: int = Field(..., description="Primary key (auto-increment).")
    type: TermlogType = Field(..., description="Stream source.")
    text: str = Field(default="", description="Stream chunk text.")
    container_id: int = Field(..., description="Container that produced this log.")
    created_at: datetime = Field(default_factory=_utcnow)
    flow_id: int = Field(..., description="Parent flow ID.")
    task_id: int | None = Field(default=None, description="Parent task ID (nullable).")
    subtask_id: int | None = Field(
        default=None, description="Parent subtask ID (nullable)."
    )


class Vecstorelog(_BaseRecord):
    """Vector-store retrieve / store action log entry."""

    id: int = Field(..., description="Primary key (auto-increment).")
    initiator: MsgchainType = Field(
        ..., description="Agent that initiated the action."
    )
    executor: MsgchainType = Field(
        ..., description="Agent that executed the action."
    )
    filter: dict[str, Any] = Field(
        default_factory=dict,
        description="JSON filter used to scope the action.",
    )
    query: str = Field(default="", description="Query string (retrieve only).")
    action: VecstoreActionType = Field(..., description="Action type.")
    result: str = Field(default="", description="Action result body.")
    flow_id: int = Field(..., description="Parent flow ID.")
    task_id: int | None = Field(default=None, description="Parent task ID (nullable).")
    subtask_id: int | None = Field(
        default=None, description="Parent subtask ID (nullable)."
    )
    created_at: datetime = Field(default_factory=_utcnow)


class Screenshot(_BaseRecord):
    """A captured screenshot (browser / tool output)."""

    id: int = Field(..., description="Primary key (auto-increment).")
    name: str = Field(default="", description="Screenshot file name.")
    url: str = Field(default="", description="Screenshot URL (file:// or https://).")
    flow_id: int = Field(..., description="Parent flow ID.")
    created_at: datetime = Field(default_factory=_utcnow)
    task_id: int | None = Field(default=None, description="Parent task ID (nullable).")
    subtask_id: int | None = Field(
        default=None, description="Parent subtask ID (nullable)."
    )


class Container(_BaseRecord):
    """A Docker sandbox container attached to a flow."""

    id: int = Field(..., description="Primary key (auto-increment).")
    type: ContainerType = Field(
        default=ContainerType.PRIMARY,
        description="Container role (primary / secondary).",
    )
    name: str = Field(default="", description="Container name (Docker).")
    image: str = Field(default="", description="Docker image reference.")
    status: ContainerStatus = Field(
        default=ContainerStatus.STARTING,
        description="Container lifecycle state.",
    )
    local_id: str | None = Field(
        default=None, description="Docker container ID (nullable)."
    )
    local_dir: str | None = Field(
        default=None,
        description="Local working-directory path (nullable).",
    )
    flow_id: int = Field(..., description="Parent flow ID.")
    created_at: datetime = Field(default_factory=_utcnow)
    updated_at: datetime = Field(default_factory=_utcnow)


class Prompt(_BaseRecord):
    """A user-overridable prompt template stored in the DB."""

    id: int = Field(..., description="Primary key (auto-increment).")
    type: str = Field(..., description="Prompt type identifier.")
    user_id: int = Field(..., description="Owning user ID.")
    prompt: str = Field(default="", description="Prompt template body.")
    created_at: datetime = Field(default_factory=_utcnow)
    updated_at: datetime = Field(default_factory=_utcnow)


__all__ = [
    # Enums
    "FlowStatus",
    "TaskStatus",
    "SubtaskStatus",
    "MsgchainType",
    "MsglogType",
    "MsglogResultFormat",
    "ToolcallStatus",
    "TermlogType",
    "VecstoreActionType",
    "SearchengineType",
    "ProviderType",
    "ContainerStatus",
    "ContainerType",
    # Core models
    "Flow",
    "Task",
    "Subtask",
    # Planning models
    "SubtaskInfo",
    "SubtaskPatchOp",
    # Msgchain + log/record models
    "Msgchain",
    "Msglog",
    "Agentlog",
    "Toolcall",
    "Searchlog",
    "Termlog",
    "Vecstorelog",
    "Screenshot",
    "Container",
    "Prompt",
]
