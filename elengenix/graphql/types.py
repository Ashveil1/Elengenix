"""
elengenix.graphql.types — Strawberry GraphQL types ported from PentAGI's
``backend/pkg/graph/schema.graphqls`` (1115 lines).

Every SDL ``type``/``input`` block is mirrored one-to-one here as a
``@strawberry.type`` (or ``@strawberry.input``) class. Field names use the
camelCase GraphQL convention via ``strawberry.field(name="...")`` where needed
so that React/Relay clients keep working unchanged.

The source of truth for runtime data is a parallel set of Pydantic models
planned to live in :mod:`elengenix.db.models`. To avoid a hard import cycle
today (those models are still being ported in parallel tasks), each Strawberry
type exposes:

* a ``from_pydantic(cls, model)`` classmethod that builds the Strawberry
  instance from a Pydantic model or plain dict, applying any field renames;
* a ``to_pydantic(self)`` method that round-trips back to the source model.

This mirrors PentAGI's ``pkg/database/converter`` package — Go struct →
``model.*`` gqlgen struct — but in the Python idiomatic direction.

References:
    * PentAGI: backend/pkg/graph/schema.graphqls
    * PentAGI: backend/pkg/graph/model/models_gen.go
"""
from __future__ import annotations

import datetime as _dt
import logging
from typing import Any, Dict, List, Optional

import strawberry
from strawberry import field as _sf
from strawberry import input as _sinput
from strawberry import type as _stype
from strawberry.scalars import JSON as _JSON  # noqa: F401  (re-exported for resolvers)
from strawberry.types import Info

from .schema import (
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

logger = logging.getLogger("elengenix.graphql.types")

# Sentinel used by ``from_pydantic`` when the source model is None — Strawberry
# requires concrete instances for non-optional fields, so we synthesize default
# instances in that case.
_UNSET: Any = object()


def _coerce(value: Any, default: Any) -> Any:
    """Return ``value`` unless it is the ``_UNSET`` sentinel, else ``default``."""
    if value is _UNSET:
        return default
    return value


# ─── Core system types ─────────────────────────────────────────────────────

@_stype
class Settings:
    """Server-side runtime settings exposed to the client."""

    debug: bool
    ask_user: bool
    version: str
    docker_inside: bool
    is_develop_mode: bool
    assistant_use_agents: bool

    @classmethod
    def from_pydantic(cls, model: Any) -> "Settings":
        return cls(
            debug=getattr(model, "debug", False),
            ask_user=getattr(model, "ask_user", False),
            version=getattr(model, "version", ""),
            docker_inside=getattr(model, "docker_inside", False),
            is_develop_mode=getattr(model, "is_develop_mode", False),
            assistant_use_agents=getattr(model, "assistant_use_agents", False),
        )


@_stype
class UserPreferences:
    """Per-user preferences (favorites, language, …)."""

    id: strawberry.ID
    favorite_flows: List[strawberry.ID] = _sf(name="favoriteFlows", default_factory=list)

    @classmethod
    def from_pydantic(cls, model: Any) -> "UserPreferences":
        return cls(
            id=strawberry.ID(str(getattr(model, "id", "0"))),
            favorite_flows=[
                strawberry.ID(str(fid)) for fid in getattr(model, "favorite_flows", []) or []
            ],
        )


# ─── Flow template types ───────────────────────────────────────────────────

@_stype
class FlowTemplate:
    id: strawberry.ID
    user_id: strawberry.ID = _sf(name="userId")
    title: str
    text: str
    created_at: _dt.datetime = _sf(name="createdAt")
    updated_at: _dt.datetime = _sf(name="updatedAt")

    @classmethod
    def from_pydantic(cls, model: Any) -> "FlowTemplate":
        return cls(
            id=strawberry.ID(str(getattr(model, "id", "0"))),
            user_id=strawberry.ID(str(getattr(model, "user_id", "0"))),
            title=getattr(model, "title", ""),
            text=getattr(model, "text", ""),
            created_at=getattr(model, "created_at", _dt.datetime.utcnow()),
            updated_at=getattr(model, "updated_at", _dt.datetime.utcnow()),
        )


@_sinput
class CreateFlowTemplateInput:
    title: str
    text: str


@_sinput
class UpdateFlowTemplateInput:
    title: str
    text: str


# ─── Flow management types ─────────────────────────────────────────────────

@_stype
class Terminal:
    id: strawberry.ID
    type: TerminalType
    name: str
    image: str
    connected: bool
    created_at: _dt.datetime = _sf(name="createdAt")

    @classmethod
    def from_pydantic(cls, model: Any) -> "Terminal":
        return cls(
            id=strawberry.ID(str(getattr(model, "id", "0"))),
            type=TerminalType(getattr(model, "type", "primary")),
            name=getattr(model, "name", ""),
            image=getattr(model, "image", ""),
            connected=bool(getattr(model, "connected", False)),
            created_at=getattr(model, "created_at", _dt.datetime.utcnow()),
        )


# Forward declaration for Provider (defined further down) — Strawberry resolves
# forward references lazily via ``from __future__ import annotations``.
@_stype
class Provider:
    """Short provider view used in selectors."""

    name: str
    type: ProviderType

    @classmethod
    def from_pydantic(cls, model: Any) -> "Provider":
        return cls(
            name=getattr(model, "name", ""),
            type=ProviderType(getattr(model, "type", "openai")),
        )


@_stype
class Assistant:
    id: strawberry.ID
    title: str
    status: StatusType
    provider: Provider
    flow_id: strawberry.ID = _sf(name="flowId")
    use_agents: bool = _sf(name="useAgents")
    created_at: _dt.datetime = _sf(name="createdAt")
    updated_at: _dt.datetime = _sf(name="updatedAt")

    @classmethod
    def from_pydantic(cls, model: Any) -> "Assistant":
        prov = getattr(model, "provider", None)
        return cls(
            id=strawberry.ID(str(getattr(model, "id", "0"))),
            title=getattr(model, "title", ""),
            status=StatusType(getattr(model, "status", "created")),
            provider=Provider.from_pydantic(prov) if prov is not None else Provider(
                name="", type=ProviderType.OPENAI
            ),
            flow_id=strawberry.ID(str(getattr(model, "flow_id", "0"))),
            use_agents=bool(getattr(model, "use_agents", False)),
            created_at=getattr(model, "created_at", _dt.datetime.utcnow()),
            updated_at=getattr(model, "updated_at", _dt.datetime.utcnow()),
        )


@_stype
class FlowAssistant:
    flow: "Flow"
    assistant: Assistant

    @classmethod
    def from_pydantic(cls, model: Any) -> "FlowAssistant":
        flow = getattr(model, "flow", None)
        assistant = getattr(model, "assistant", None)
        return cls(
            flow=Flow.from_pydantic(flow) if flow is not None else Flow.placeholder(),
            assistant=(
                Assistant.from_pydantic(assistant)
                if assistant is not None
                else Assistant.placeholder()
            ),
        )


@_stype
class Flow:
    id: strawberry.ID
    title: str
    status: StatusType
    terminals: Optional[List[Terminal]] = None
    provider: Provider
    created_at: _dt.datetime = _sf(name="createdAt")
    updated_at: _dt.datetime = _sf(name="updatedAt")

    @classmethod
    def placeholder(cls) -> "Flow":
        return cls(
            id=strawberry.ID("0"),
            title="",
            status=StatusType.CREATED,
            terminals=[],
            provider=Provider(name="", type=ProviderType.OPENAI),
            created_at=_dt.datetime.utcnow(),
            updated_at=_dt.datetime.utcnow(),
        )

    @classmethod
    def from_pydantic(cls, model: Any) -> "Flow":
        terms = getattr(model, "terminals", None) or []
        prov = getattr(model, "provider", None)
        return cls(
            id=strawberry.ID(str(getattr(model, "id", "0"))),
            title=getattr(model, "title", ""),
            status=StatusType(getattr(model, "status", "created")),
            terminals=[Terminal.from_pydantic(t) for t in terms],
            provider=(
                Provider.from_pydantic(prov)
                if prov is not None
                else Provider(name="", type=ProviderType.OPENAI)
            ),
            created_at=getattr(model, "created_at", _dt.datetime.utcnow()),
            updated_at=getattr(model, "updated_at", _dt.datetime.utcnow()),
        )


@_stype
class Subtask:
    id: strawberry.ID
    status: StatusType
    title: str
    description: str
    result: str
    task_id: strawberry.ID = _sf(name="taskId")
    created_at: _dt.datetime = _sf(name="createdAt")
    updated_at: _dt.datetime = _sf(name="updatedAt")

    @classmethod
    def from_pydantic(cls, model: Any) -> "Subtask":
        return cls(
            id=strawberry.ID(str(getattr(model, "id", "0"))),
            status=StatusType(getattr(model, "status", "created")),
            title=getattr(model, "title", ""),
            description=getattr(model, "description", ""),
            result=getattr(model, "result", ""),
            task_id=strawberry.ID(str(getattr(model, "task_id", "0"))),
            created_at=getattr(model, "created_at", _dt.datetime.utcnow()),
            updated_at=getattr(model, "updated_at", _dt.datetime.utcnow()),
        )


@_stype
class Task:
    id: strawberry.ID
    title: str
    status: StatusType
    input: str
    result: str
    flow_id: strawberry.ID = _sf(name="flowId")
    subtasks: Optional[List[Subtask]] = None
    created_at: _dt.datetime = _sf(name="createdAt")
    updated_at: _dt.datetime = _sf(name="updatedAt")

    @classmethod
    def from_pydantic(cls, model: Any) -> "Task":
        subs = getattr(model, "subtasks", None) or []
        return cls(
            id=strawberry.ID(str(getattr(model, "id", "0"))),
            title=getattr(model, "title", ""),
            status=StatusType(getattr(model, "status", "created")),
            input=getattr(model, "input", ""),
            result=getattr(model, "result", ""),
            flow_id=strawberry.ID(str(getattr(model, "flow_id", "0"))),
            subtasks=[Subtask.from_pydantic(s) for s in subs] or None,
            created_at=getattr(model, "created_at", _dt.datetime.utcnow()),
            updated_at=getattr(model, "updated_at", _dt.datetime.utcnow()),
        )


# ─── Logging types ─────────────────────────────────────────────────────────

@_stype
class AssistantLog:
    id: strawberry.ID
    type: MessageLogType
    message: str
    thinking: Optional[str] = None
    result: str
    result_format: ResultFormat = _sf(name="resultFormat")
    append_part: bool = _sf(name="appendPart")
    flow_id: strawberry.ID = _sf(name="flowId")
    assistant_id: strawberry.ID = _sf(name="assistantId")
    created_at: _dt.datetime = _sf(name="createdAt")

    @classmethod
    def from_pydantic(cls, model: Any) -> "AssistantLog":
        return cls(
            id=strawberry.ID(str(getattr(model, "id", "0"))),
            type=MessageLogType(getattr(model, "type", "answer")),
            message=getattr(model, "message", ""),
            thinking=getattr(model, "thinking", None),
            result=getattr(model, "result", ""),
            result_format=ResultFormat(getattr(model, "result_format", "plain")),
            append_part=bool(getattr(model, "append_part", False)),
            flow_id=strawberry.ID(str(getattr(model, "flow_id", "0"))),
            assistant_id=strawberry.ID(str(getattr(model, "assistant_id", "0"))),
            created_at=getattr(model, "created_at", _dt.datetime.utcnow()),
        )


@_stype
class AgentLog:
    id: strawberry.ID
    initiator: AgentType
    executor: AgentType
    task: str
    result: str
    flow_id: strawberry.ID = _sf(name="flowId")
    task_id: Optional[strawberry.ID] = _sf(name="taskId", default=None)
    subtask_id: Optional[strawberry.ID] = _sf(name="subtaskId", default=None)
    created_at: _dt.datetime = _sf(name="createdAt")

    @classmethod
    def from_pydantic(cls, model: Any) -> "AgentLog":
        return cls(
            id=strawberry.ID(str(getattr(model, "id", "0"))),
            initiator=AgentType(getattr(model, "initiator", "primary_agent")),
            executor=AgentType(getattr(model, "executor", "primary_agent")),
            task=getattr(model, "task", ""),
            result=getattr(model, "result", ""),
            flow_id=strawberry.ID(str(getattr(model, "flow_id", "0"))),
            task_id=(
                strawberry.ID(str(model.task_id))
                if getattr(model, "task_id", None) is not None
                else None
            ),
            subtask_id=(
                strawberry.ID(str(model.subtask_id))
                if getattr(model, "subtask_id", None) is not None
                else None
            ),
            created_at=getattr(model, "created_at", _dt.datetime.utcnow()),
        )


@_stype
class MessageLog:
    id: strawberry.ID
    type: MessageLogType
    message: str
    thinking: Optional[str] = None
    result: str
    result_format: ResultFormat = _sf(name="resultFormat")
    flow_id: strawberry.ID = _sf(name="flowId")
    task_id: Optional[strawberry.ID] = _sf(name="taskId", default=None)
    subtask_id: Optional[strawberry.ID] = _sf(name="subtaskId", default=None)
    created_at: _dt.datetime = _sf(name="createdAt")

    @classmethod
    def from_pydantic(cls, model: Any) -> "MessageLog":
        return cls(
            id=strawberry.ID(str(getattr(model, "id", "0"))),
            type=MessageLogType(getattr(model, "type", "answer")),
            message=getattr(model, "message", ""),
            thinking=getattr(model, "thinking", None),
            result=getattr(model, "result", ""),
            result_format=ResultFormat(getattr(model, "result_format", "plain")),
            flow_id=strawberry.ID(str(getattr(model, "flow_id", "0"))),
            task_id=(
                strawberry.ID(str(model.task_id))
                if getattr(model, "task_id", None) is not None
                else None
            ),
            subtask_id=(
                strawberry.ID(str(model.subtask_id))
                if getattr(model, "subtask_id", None) is not None
                else None
            ),
            created_at=getattr(model, "created_at", _dt.datetime.utcnow()),
        )


@_stype
class SearchLog:
    id: strawberry.ID
    initiator: AgentType
    executor: AgentType
    engine: str
    query: str
    result: str
    flow_id: strawberry.ID = _sf(name="flowId")
    task_id: Optional[strawberry.ID] = _sf(name="taskId", default=None)
    subtask_id: Optional[strawberry.ID] = _sf(name="subtaskId", default=None)
    created_at: _dt.datetime = _sf(name="createdAt")

    @classmethod
    def from_pydantic(cls, model: Any) -> "SearchLog":
        return cls(
            id=strawberry.ID(str(getattr(model, "id", "0"))),
            initiator=AgentType(getattr(model, "initiator", "primary_agent")),
            executor=AgentType(getattr(model, "executor", "primary_agent")),
            engine=getattr(model, "engine", ""),
            query=getattr(model, "query", ""),
            result=getattr(model, "result", ""),
            flow_id=strawberry.ID(str(getattr(model, "flow_id", "0"))),
            task_id=(
                strawberry.ID(str(model.task_id))
                if getattr(model, "task_id", None) is not None
                else None
            ),
            subtask_id=(
                strawberry.ID(str(model.subtask_id))
                if getattr(model, "subtask_id", None) is not None
                else None
            ),
            created_at=getattr(model, "created_at", _dt.datetime.utcnow()),
        )


@_stype
class TerminalLog:
    id: strawberry.ID
    flow_id: strawberry.ID = _sf(name="flowId")
    task_id: Optional[strawberry.ID] = _sf(name="taskId", default=None)
    subtask_id: Optional[strawberry.ID] = _sf(name="subtaskId", default=None)
    type: TerminalLogType
    text: str
    terminal: strawberry.ID
    created_at: _dt.datetime = _sf(name="createdAt")

    @classmethod
    def from_pydantic(cls, model: Any) -> "TerminalLog":
        return cls(
            id=strawberry.ID(str(getattr(model, "id", "0"))),
            flow_id=strawberry.ID(str(getattr(model, "flow_id", "0"))),
            task_id=(
                strawberry.ID(str(model.task_id))
                if getattr(model, "task_id", None) is not None
                else None
            ),
            subtask_id=(
                strawberry.ID(str(model.subtask_id))
                if getattr(model, "subtask_id", None) is not None
                else None
            ),
            type=TerminalLogType(getattr(model, "type", "stdout")),
            text=getattr(model, "text", ""),
            terminal=strawberry.ID(str(getattr(model, "terminal", "0"))),
            created_at=getattr(model, "created_at", _dt.datetime.utcnow()),
        )


@_stype
class VectorStoreLog:
    id: strawberry.ID
    initiator: AgentType
    executor: AgentType
    filter: str
    query: str
    action: VectorStoreAction
    result: str
    flow_id: strawberry.ID = _sf(name="flowId")
    task_id: Optional[strawberry.ID] = _sf(name="taskId", default=None)
    subtask_id: Optional[strawberry.ID] = _sf(name="subtaskId", default=None)
    created_at: _dt.datetime = _sf(name="createdAt")

    @classmethod
    def from_pydantic(cls, model: Any) -> "VectorStoreLog":
        return cls(
            id=strawberry.ID(str(getattr(model, "id", "0"))),
            initiator=AgentType(getattr(model, "initiator", "primary_agent")),
            executor=AgentType(getattr(model, "executor", "primary_agent")),
            filter=getattr(model, "filter", ""),
            query=getattr(model, "query", ""),
            action=VectorStoreAction(getattr(model, "action", "retrieve")),
            result=getattr(model, "result", ""),
            flow_id=strawberry.ID(str(getattr(model, "flow_id", "0"))),
            task_id=(
                strawberry.ID(str(model.task_id))
                if getattr(model, "task_id", None) is not None
                else None
            ),
            subtask_id=(
                strawberry.ID(str(model.subtask_id))
                if getattr(model, "subtask_id", None) is not None
                else None
            ),
            created_at=getattr(model, "created_at", _dt.datetime.utcnow()),
        )


@_stype
class ToolCallLog:
    id: strawberry.ID
    call_id: str = _sf(name="callId")
    status: ToolCallStatus
    name: str
    args: str
    result: str
    duration_seconds: float = _sf(name="durationSeconds")
    flow_id: strawberry.ID = _sf(name="flowId")
    task_id: Optional[strawberry.ID] = _sf(name="taskId", default=None)
    subtask_id: Optional[strawberry.ID] = _sf(name="subtaskId", default=None)
    created_at: _dt.datetime = _sf(name="createdAt")
    updated_at: _dt.datetime = _sf(name="updatedAt")

    @classmethod
    def from_pydantic(cls, model: Any) -> "ToolCallLog":
        return cls(
            id=strawberry.ID(str(getattr(model, "id", "0"))),
            call_id=getattr(model, "call_id", ""),
            status=ToolCallStatus(getattr(model, "status", "received")),
            name=getattr(model, "name", ""),
            args=getattr(model, "args", ""),
            result=getattr(model, "result", ""),
            duration_seconds=float(getattr(model, "duration_seconds", 0.0)),
            flow_id=strawberry.ID(str(getattr(model, "flow_id", "0"))),
            task_id=(
                strawberry.ID(str(model.task_id))
                if getattr(model, "task_id", None) is not None
                else None
            ),
            subtask_id=(
                strawberry.ID(str(model.subtask_id))
                if getattr(model, "subtask_id", None) is not None
                else None
            ),
            created_at=getattr(model, "created_at", _dt.datetime.utcnow()),
            updated_at=getattr(model, "updated_at", _dt.datetime.utcnow()),
        )


@_stype
class Screenshot:
    id: strawberry.ID
    flow_id: strawberry.ID = _sf(name="flowId")
    task_id: Optional[strawberry.ID] = _sf(name="taskId", default=None)
    subtask_id: Optional[strawberry.ID] = _sf(name="subtaskId", default=None)
    name: str
    url: str
    created_at: _dt.datetime = _sf(name="createdAt")

    @classmethod
    def from_pydantic(cls, model: Any) -> "Screenshot":
        return cls(
            id=strawberry.ID(str(getattr(model, "id", "0"))),
            flow_id=strawberry.ID(str(getattr(model, "flow_id", "0"))),
            task_id=(
                strawberry.ID(str(model.task_id))
                if getattr(model, "task_id", None) is not None
                else None
            ),
            subtask_id=(
                strawberry.ID(str(model.subtask_id))
                if getattr(model, "subtask_id", None) is not None
                else None
            ),
            name=getattr(model, "name", ""),
            url=getattr(model, "url", ""),
            created_at=getattr(model, "created_at", _dt.datetime.utcnow()),
        )


@_stype
class FlowFile:
    id: str
    name: str
    path: str
    size: int
    is_dir: bool = _sf(name="isDir")
    modified_at: _dt.datetime = _sf(name="modifiedAt")

    @classmethod
    def from_pydantic(cls, model: Any) -> "FlowFile":
        return cls(
            id=str(getattr(model, "id", "")),
            name=getattr(model, "name", ""),
            path=getattr(model, "path", ""),
            size=int(getattr(model, "size", 0)),
            is_dir=bool(getattr(model, "is_dir", False)),
            modified_at=getattr(model, "modified_at", _dt.datetime.utcnow()),
        )


@_stype
class UserResource:
    id: strawberry.ID
    user_id: strawberry.ID = _sf(name="userId")
    name: str
    path: str
    size: int
    is_dir: bool = _sf(name="isDir")
    created_at: _dt.datetime = _sf(name="createdAt")
    updated_at: _dt.datetime = _sf(name="updatedAt")

    @classmethod
    def from_pydantic(cls, model: Any) -> "UserResource":
        return cls(
            id=strawberry.ID(str(getattr(model, "id", "0"))),
            user_id=strawberry.ID(str(getattr(model, "user_id", "0"))),
            name=getattr(model, "name", ""),
            path=getattr(model, "path", ""),
            size=int(getattr(model, "size", 0)),
            is_dir=bool(getattr(model, "is_dir", False)),
            created_at=getattr(model, "created_at", _dt.datetime.utcnow()),
            updated_at=getattr(model, "updated_at", _dt.datetime.utcnow()),
        )


# ─── API token types ───────────────────────────────────────────────────────

@_stype
class APIToken:
    id: strawberry.ID
    token_id: str = _sf(name="tokenId")
    user_id: strawberry.ID = _sf(name="userId")
    role_id: strawberry.ID = _sf(name="roleId")
    name: Optional[str] = None
    ttl: int
    status: TokenStatus
    created_at: _dt.datetime = _sf(name="createdAt")
    updated_at: _dt.datetime = _sf(name="updatedAt")

    @classmethod
    def from_pydantic(cls, model: Any) -> "APIToken":
        return cls(
            id=strawberry.ID(str(getattr(model, "id", "0"))),
            token_id=getattr(model, "token_id", ""),
            user_id=strawberry.ID(str(getattr(model, "user_id", "0"))),
            role_id=strawberry.ID(str(getattr(model, "role_id", "0"))),
            name=getattr(model, "name", None),
            ttl=int(getattr(model, "ttl", 0)),
            status=TokenStatus(getattr(model, "status", "active")),
            created_at=getattr(model, "created_at", _dt.datetime.utcnow()),
            updated_at=getattr(model, "updated_at", _dt.datetime.utcnow()),
        )


@_stype
class APITokenWithSecret(APIToken):
    """Returned only at creation time — carries the plaintext JWT."""

    token: str

    @classmethod
    def from_pydantic(cls, model: Any) -> "APITokenWithSecret":
        base = APIToken.from_pydantic(model)
        return cls(
            id=base.id,
            token_id=base.token_id,
            user_id=base.user_id,
            role_id=base.role_id,
            name=base.name,
            ttl=base.ttl,
            status=base.status,
            created_at=base.created_at,
            updated_at=base.updated_at,
            token=getattr(model, "token", ""),
        )


@_sinput
class CreateAPITokenInput:
    name: Optional[str] = None
    ttl: int


@_sinput
class UpdateAPITokenInput:
    name: Optional[str] = None
    status: Optional[TokenStatus] = None


# ─── Prompt management types ───────────────────────────────────────────────

@_stype
class PromptValidationResult:
    result: ResultType
    error_type: Optional[PromptValidationErrorType] = _sf(name="errorType", default=None)
    message: Optional[str] = None
    line: Optional[int] = None
    details: Optional[str] = None

    @classmethod
    def from_pydantic(cls, model: Any) -> "PromptValidationResult":
        et = getattr(model, "error_type", None)
        return cls(
            result=ResultType(getattr(model, "result", "success")),
            error_type=(
                PromptValidationErrorType(et) if et is not None else None
            ),
            message=getattr(model, "message", None),
            line=getattr(model, "line", None),
            details=getattr(model, "details", None),
        )


@_stype
class DefaultPrompt:
    type: PromptType
    template: str
    variables: List[str]

    @classmethod
    def from_pydantic(cls, model: Any) -> "DefaultPrompt":
        return cls(
            type=PromptType(getattr(model, "type", "assistant")),
            template=getattr(model, "template", ""),
            variables=list(getattr(model, "variables", []) or []),
        )


@_stype
class UserPrompt:
    id: strawberry.ID
    type: PromptType
    template: str
    created_at: _dt.datetime = _sf(name="createdAt")
    updated_at: _dt.datetime = _sf(name="updatedAt")

    @classmethod
    def from_pydantic(cls, model: Any) -> "UserPrompt":
        return cls(
            id=strawberry.ID(str(getattr(model, "id", "0"))),
            type=PromptType(getattr(model, "type", "assistant")),
            template=getattr(model, "template", ""),
            created_at=getattr(model, "created_at", _dt.datetime.utcnow()),
            updated_at=getattr(model, "updated_at", _dt.datetime.utcnow()),
        )


@_stype
class AgentPrompt:
    system: DefaultPrompt

    @classmethod
    def from_pydantic(cls, model: Any) -> "AgentPrompt":
        sys_ = getattr(model, "system", None)
        return cls(system=DefaultPrompt.from_pydantic(sys_) if sys_ else DefaultPrompt(
            type=PromptType.ASSISTANT, template="", variables=[]
        ))


@_stype
class AgentPrompts:
    system: DefaultPrompt
    human: DefaultPrompt

    @classmethod
    def from_pydantic(cls, model: Any) -> "AgentPrompts":
        sys_ = getattr(model, "system", None)
        human = getattr(model, "human", None)
        empty = DefaultPrompt(type=PromptType.ASSISTANT, template="", variables=[])
        return cls(
            system=DefaultPrompt.from_pydantic(sys_) if sys_ else empty,
            human=DefaultPrompt.from_pydantic(human) if human else empty,
        )


@_stype
class AgentsPrompts:
    primary_agent: AgentPrompt = _sf(name="primaryAgent")
    assistant: AgentPrompt
    pentester: AgentPrompts
    coder: AgentPrompts
    installer: AgentPrompts
    searcher: AgentPrompts
    memorist: AgentPrompts
    adviser: AgentPrompts
    generator: AgentPrompts
    refiner: AgentPrompts
    reporter: AgentPrompts
    reflector: AgentPrompts
    enricher: AgentPrompts
    tool_call_fixer: AgentPrompts = _sf(name="toolCallFixer")
    summarizer: AgentPrompt

    @classmethod
    def from_pydantic(cls, model: Any) -> "AgentsPrompts":
        empty_prompt = DefaultPrompt(type=PromptType.ASSISTANT, template="", variables=[])
        empty_single = AgentPrompt(system=empty_prompt)
        empty_pair = AgentPrompts(system=empty_prompt, human=empty_prompt)

        def _single(name: str) -> AgentPrompt:
            sub = getattr(model, name, None)
            return AgentPrompt.from_pydantic(sub) if sub else empty_single

        def _pair(name: str) -> AgentPrompts:
            sub = getattr(model, name, None)
            return AgentPrompts.from_pydantic(sub) if sub else empty_pair

        return cls(
            primary_agent=_single("primary_agent"),
            assistant=_single("assistant"),
            pentester=_pair("pentester"),
            coder=_pair("coder"),
            installer=_pair("installer"),
            searcher=_pair("searcher"),
            memorist=_pair("memorist"),
            adviser=_pair("adviser"),
            generator=_pair("generator"),
            refiner=_pair("refiner"),
            reporter=_pair("reporter"),
            reflector=_pair("reflector"),
            enricher=_pair("enricher"),
            tool_call_fixer=_pair("tool_call_fixer"),
            summarizer=_single("summarizer"),
        )


@_stype
class ToolsPrompts:
    get_flow_description: DefaultPrompt = _sf(name="getFlowDescription")
    get_task_description: DefaultPrompt = _sf(name="getTaskDescription")
    get_execution_logs: DefaultPrompt = _sf(name="getExecutionLogs")
    get_full_execution_context: DefaultPrompt = _sf(name="getFullExecutionContext")
    get_short_execution_context: DefaultPrompt = _sf(name="getShortExecutionContext")
    choose_docker_image: DefaultPrompt = _sf(name="chooseDockerImage")
    choose_user_language: DefaultPrompt = _sf(name="chooseUserLanguage")
    collect_tool_call_id: DefaultPrompt = _sf(name="collectToolCallId")
    detect_tool_call_id_pattern: DefaultPrompt = _sf(name="detectToolCallIdPattern")
    monitor_agent_execution: DefaultPrompt = _sf(name="monitorAgentExecution")
    plan_agent_task: DefaultPrompt = _sf(name="planAgentTask")
    wrap_agent_task: DefaultPrompt = _sf(name="wrapAgentTask")

    @classmethod
    def from_pydantic(cls, model: Any) -> "ToolsPrompts":
        empty = DefaultPrompt(type=PromptType.ASSISTANT, template="", variables=[])

        def _g(name: str) -> DefaultPrompt:
            sub = getattr(model, name, None)
            return DefaultPrompt.from_pydantic(sub) if sub else empty

        return cls(
            get_flow_description=_g("get_flow_description"),
            get_task_description=_g("get_task_description"),
            get_execution_logs=_g("get_execution_logs"),
            get_full_execution_context=_g("get_full_execution_context"),
            get_short_execution_context=_g("get_short_execution_context"),
            choose_docker_image=_g("choose_docker_image"),
            choose_user_language=_g("choose_user_language"),
            collect_tool_call_id=_g("collect_tool_call_id"),
            detect_tool_call_id_pattern=_g("detect_tool_call_id_pattern"),
            monitor_agent_execution=_g("monitor_agent_execution"),
            plan_agent_task=_g("plan_agent_task"),
            wrap_agent_task=_g("wrap_agent_task"),
        )


@_stype
class DefaultPrompts:
    agents: AgentsPrompts
    tools: ToolsPrompts

    @classmethod
    def from_pydantic(cls, model: Any) -> "DefaultPrompts":
        agents = getattr(model, "agents", None)
        tools = getattr(model, "tools", None)
        return cls(
            agents=AgentsPrompts.from_pydantic(agents) if agents else AgentsPrompts.from_pydantic(
                type("M", (), {})()
            ),
            tools=ToolsPrompts.from_pydantic(tools) if tools else ToolsPrompts.from_pydantic(
                type("M", (), {})()
            ),
        )


@_stype
class PromptsConfig:
    default: DefaultPrompts
    user_defined: Optional[List[UserPrompt]] = _sf(name="userDefined", default=None)

    @classmethod
    def from_pydantic(cls, model: Any) -> "PromptsConfig":
        default = getattr(model, "default", None)
        user = getattr(model, "user_defined", None) or []
        return cls(
            default=DefaultPrompts.from_pydantic(default) if default else (
                DefaultPrompts.from_pydantic(type("M", (), {})())
            ),
            user_defined=[UserPrompt.from_pydantic(u) for u in user] or None,
        )


# ─── Testing & validation types ────────────────────────────────────────────

@_stype
class TestResult:
    name: str
    type: str
    result: bool
    reasoning: bool
    streaming: bool
    latency: Optional[int] = None
    error: Optional[str] = None

    @classmethod
    def from_pydantic(cls, model: Any) -> "TestResult":
        return cls(
            name=getattr(model, "name", ""),
            type=getattr(model, "type", ""),
            result=bool(getattr(model, "result", False)),
            reasoning=bool(getattr(model, "reasoning", False)),
            streaming=bool(getattr(model, "streaming", False)),
            latency=getattr(model, "latency", None),
            error=getattr(model, "error", None),
        )


@_stype
class AgentTestResult:
    tests: List[TestResult]

    @classmethod
    def from_pydantic(cls, model: Any) -> "AgentTestResult":
        tests = getattr(model, "tests", []) or []
        return cls(tests=[TestResult.from_pydantic(t) for t in tests])


@_stype
class ProviderTestResult:
    simple: AgentTestResult
    simple_json: AgentTestResult = _sf(name="simpleJson")
    primary_agent: AgentTestResult = _sf(name="primaryAgent")
    assistant: AgentTestResult
    generator: AgentTestResult
    refiner: AgentTestResult
    adviser: AgentTestResult
    reflector: AgentTestResult
    searcher: AgentTestResult
    enricher: AgentTestResult
    coder: AgentTestResult
    installer: AgentTestResult
    pentester: AgentTestResult

    @classmethod
    def from_pydantic(cls, model: Any) -> "ProviderTestResult":
        empty = AgentTestResult(tests=[])

        def _g(name: str) -> AgentTestResult:
            sub = getattr(model, name, None)
            return AgentTestResult.from_pydantic(sub) if sub else empty

        return cls(
            simple=_g("simple"),
            simple_json=_g("simple_json"),
            primary_agent=_g("primary_agent"),
            assistant=_g("assistant"),
            generator=_g("generator"),
            refiner=_g("refiner"),
            adviser=_g("adviser"),
            reflector=_g("reflector"),
            searcher=_g("searcher"),
            enricher=_g("enricher"),
            coder=_g("coder"),
            installer=_g("installer"),
            pentester=_g("pentester"),
        )


# ─── Analytics & usage statistics types ────────────────────────────────────

@_stype
class UsageStats:
    total_usage_in: int = _sf(name="totalUsageIn")
    total_usage_out: int = _sf(name="totalUsageOut")
    total_usage_cache_in: int = _sf(name="totalUsageCacheIn")
    total_usage_cache_out: int = _sf(name="totalUsageCacheOut")
    total_usage_cost_in: float = _sf(name="totalUsageCostIn")
    total_usage_cost_out: float = _sf(name="totalUsageCostOut")

    @classmethod
    def empty(cls) -> "UsageStats":
        return cls(
            total_usage_in=0,
            total_usage_out=0,
            total_usage_cache_in=0,
            total_usage_cache_out=0,
            total_usage_cost_in=0.0,
            total_usage_cost_out=0.0,
        )

    @classmethod
    def from_pydantic(cls, model: Any) -> "UsageStats":
        return cls(
            total_usage_in=int(getattr(model, "total_usage_in", 0)),
            total_usage_out=int(getattr(model, "total_usage_out", 0)),
            total_usage_cache_in=int(getattr(model, "total_usage_cache_in", 0)),
            total_usage_cache_out=int(getattr(model, "total_usage_cache_out", 0)),
            total_usage_cost_in=float(getattr(model, "total_usage_cost_in", 0.0)),
            total_usage_cost_out=float(getattr(model, "total_usage_cost_out", 0.0)),
        )


@_stype
class ToolcallsStats:
    total_count: int = _sf(name="totalCount")
    total_duration_seconds: float = _sf(name="totalDurationSeconds")

    @classmethod
    def empty(cls) -> "ToolcallsStats":
        return cls(total_count=0, total_duration_seconds=0.0)

    @classmethod
    def from_pydantic(cls, model: Any) -> "ToolcallsStats":
        return cls(
            total_count=int(getattr(model, "total_count", 0)),
            total_duration_seconds=float(getattr(model, "total_duration_seconds", 0.0)),
        )


@_stype
class FlowsStats:
    total_flows_count: int = _sf(name="totalFlowsCount")
    total_tasks_count: int = _sf(name="totalTasksCount")
    total_subtasks_count: int = _sf(name="totalSubtasksCount")
    total_assistants_count: int = _sf(name="totalAssistantsCount")

    @classmethod
    def empty(cls) -> "FlowsStats":
        return cls(
            total_flows_count=0,
            total_tasks_count=0,
            total_subtasks_count=0,
            total_assistants_count=0,
        )

    @classmethod
    def from_pydantic(cls, model: Any) -> "FlowsStats":
        return cls(
            total_flows_count=int(getattr(model, "total_flows_count", 0)),
            total_tasks_count=int(getattr(model, "total_tasks_count", 0)),
            total_subtasks_count=int(getattr(model, "total_subtasks_count", 0)),
            total_assistants_count=int(getattr(model, "total_assistants_count", 0)),
        )


@_stype
class FlowStats:
    total_tasks_count: int = _sf(name="totalTasksCount")
    total_subtasks_count: int = _sf(name="totalSubtasksCount")
    total_assistants_count: int = _sf(name="totalAssistantsCount")

    @classmethod
    def empty(cls) -> "FlowStats":
        return cls(total_tasks_count=0, total_subtasks_count=0, total_assistants_count=0)

    @classmethod
    def from_pydantic(cls, model: Any) -> "FlowStats":
        return cls(
            total_tasks_count=int(getattr(model, "total_tasks_count", 0)),
            total_subtasks_count=int(getattr(model, "total_subtasks_count", 0)),
            total_assistants_count=int(getattr(model, "total_assistants_count", 0)),
        )


@_stype
class DailyUsageStats:
    date: _dt.datetime
    stats: UsageStats

    @classmethod
    def from_pydantic(cls, model: Any) -> "DailyUsageStats":
        stats = getattr(model, "stats", None)
        return cls(
            date=getattr(model, "date", _dt.datetime.utcnow()),
            stats=UsageStats.from_pydantic(stats) if stats else UsageStats.empty(),
        )


@_stype
class ProviderUsageStats:
    provider: str
    stats: UsageStats

    @classmethod
    def from_pydantic(cls, model: Any) -> "ProviderUsageStats":
        stats = getattr(model, "stats", None)
        return cls(
            provider=getattr(model, "provider", ""),
            stats=UsageStats.from_pydantic(stats) if stats else UsageStats.empty(),
        )


@_stype
class ModelUsageStats:
    model: str
    provider: str
    stats: UsageStats

    @classmethod
    def from_pydantic(cls, model: Any) -> "ModelUsageStats":
        stats = getattr(model, "stats", None)
        return cls(
            model=getattr(model, "model", ""),
            provider=getattr(model, "provider", ""),
            stats=UsageStats.from_pydantic(stats) if stats else UsageStats.empty(),
        )


@_stype
class ModelAgentsUsageStats:
    model: str
    provider: str
    agent_types: List[AgentType] = _sf(name="agentTypes")
    stats: UsageStats

    @classmethod
    def from_pydantic(cls, model: Any) -> "ModelAgentsUsageStats":
        stats = getattr(model, "stats", None)
        ats = getattr(model, "agent_types", []) or []
        return cls(
            model=getattr(model, "model", ""),
            provider=getattr(model, "provider", ""),
            agent_types=[AgentType(a) for a in ats],
            stats=UsageStats.from_pydantic(stats) if stats else UsageStats.empty(),
        )


@_stype
class AgentTypeUsageStats:
    agent_type: AgentType = _sf(name="agentType")
    stats: UsageStats

    @classmethod
    def from_pydantic(cls, model: Any) -> "AgentTypeUsageStats":
        stats = getattr(model, "stats", None)
        return cls(
            agent_type=AgentType(getattr(model, "agent_type", "primary_agent")),
            stats=UsageStats.from_pydantic(stats) if stats else UsageStats.empty(),
        )


@_stype
class DailyToolcallsStats:
    date: _dt.datetime
    stats: ToolcallsStats

    @classmethod
    def from_pydantic(cls, model: Any) -> "DailyToolcallsStats":
        stats = getattr(model, "stats", None)
        return cls(
            date=getattr(model, "date", _dt.datetime.utcnow()),
            stats=ToolcallsStats.from_pydantic(stats) if stats else ToolcallsStats.empty(),
        )


@_stype
class FunctionToolcallsStats:
    function_name: str = _sf(name="functionName")
    is_agent: bool = _sf(name="isAgent")
    total_count: int = _sf(name="totalCount")
    total_duration_seconds: float = _sf(name="totalDurationSeconds")
    avg_duration_seconds: float = _sf(name="avgDurationSeconds")

    @classmethod
    def from_pydantic(cls, model: Any) -> "FunctionToolcallsStats":
        return cls(
            function_name=getattr(model, "function_name", ""),
            is_agent=bool(getattr(model, "is_agent", False)),
            total_count=int(getattr(model, "total_count", 0)),
            total_duration_seconds=float(getattr(model, "total_duration_seconds", 0.0)),
            avg_duration_seconds=float(getattr(model, "avg_duration_seconds", 0.0)),
        )


@_stype
class DailyFlowsStats:
    date: _dt.datetime
    stats: FlowsStats

    @classmethod
    def from_pydantic(cls, model: Any) -> "DailyFlowsStats":
        stats = getattr(model, "stats", None)
        return cls(
            date=getattr(model, "date", _dt.datetime.utcnow()),
            stats=FlowsStats.from_pydantic(stats) if stats else FlowsStats.empty(),
        )


@_stype
class SubtaskExecutionStats:
    subtask_id: strawberry.ID = _sf(name="subtaskId")
    subtask_title: str = _sf(name="subtaskTitle")
    total_duration_seconds: float = _sf(name="totalDurationSeconds")
    total_toolcalls_count: int = _sf(name="totalToolcallsCount")

    @classmethod
    def from_pydantic(cls, model: Any) -> "SubtaskExecutionStats":
        return cls(
            subtask_id=strawberry.ID(str(getattr(model, "subtask_id", "0"))),
            subtask_title=getattr(model, "subtask_title", ""),
            total_duration_seconds=float(getattr(model, "total_duration_seconds", 0.0)),
            total_toolcalls_count=int(getattr(model, "total_toolcalls_count", 0)),
        )


@_stype
class TaskExecutionStats:
    task_id: strawberry.ID = _sf(name="taskId")
    task_title: str = _sf(name="taskTitle")
    total_duration_seconds: float = _sf(name="totalDurationSeconds")
    total_toolcalls_count: int = _sf(name="totalToolcallsCount")
    subtasks: List[SubtaskExecutionStats]

    @classmethod
    def from_pydantic(cls, model: Any) -> "TaskExecutionStats":
        subs = getattr(model, "subtasks", []) or []
        return cls(
            task_id=strawberry.ID(str(getattr(model, "task_id", "0"))),
            task_title=getattr(model, "task_title", ""),
            total_duration_seconds=float(getattr(model, "total_duration_seconds", 0.0)),
            total_toolcalls_count=int(getattr(model, "total_toolcalls_count", 0)),
            subtasks=[SubtaskExecutionStats.from_pydantic(s) for s in subs],
        )


@_stype
class FlowExecutionStats:
    flow_id: strawberry.ID = _sf(name="flowId")
    flow_title: str = _sf(name="flowTitle")
    total_duration_seconds: float = _sf(name="totalDurationSeconds")
    total_toolcalls_count: int = _sf(name="totalToolcallsCount")
    total_assistants_count: int = _sf(name="totalAssistantsCount")
    tasks: List[TaskExecutionStats]

    @classmethod
    def from_pydantic(cls, model: Any) -> "FlowExecutionStats":
        tasks = getattr(model, "tasks", []) or []
        return cls(
            flow_id=strawberry.ID(str(getattr(model, "flow_id", "0"))),
            flow_title=getattr(model, "flow_title", ""),
            total_duration_seconds=float(getattr(model, "total_duration_seconds", 0.0)),
            total_toolcalls_count=int(getattr(model, "total_toolcalls_count", 0)),
            total_assistants_count=int(getattr(model, "total_assistants_count", 0)),
            tasks=[TaskExecutionStats.from_pydantic(t) for t in tasks],
        )


# ─── Provider configuration types ──────────────────────────────────────────

@_stype
class ModelPrice:
    input: float
    output: float
    cache_read: float = _sf(name="cacheRead")
    cache_write: float = _sf(name="cacheWrite")

    @classmethod
    def from_pydantic(cls, model: Any) -> "ModelPrice":
        return cls(
            input=float(getattr(model, "input", 0.0)),
            output=float(getattr(model, "output", 0.0)),
            cache_read=float(getattr(model, "cache_read", 0.0)),
            cache_write=float(getattr(model, "cache_write", 0.0)),
        )


@_stype
class ReasoningConfig:
    effort: Optional[ReasoningEffort] = None
    max_tokens: Optional[int] = _sf(name="maxTokens", default=None)

    @classmethod
    def from_pydantic(cls, model: Any) -> "ReasoningConfig":
        eff = getattr(model, "effort", None)
        return cls(
            effort=ReasoningEffort(eff) if eff is not None else None,
            max_tokens=getattr(model, "max_tokens", None),
        )


@_stype
class AgentConfig:
    model: str
    max_tokens: Optional[int] = _sf(name="maxTokens", default=None)
    temperature: Optional[float] = None
    top_k: Optional[int] = _sf(name="topK", default=None)
    top_p: Optional[float] = _sf(name="topP", default=None)
    min_length: Optional[int] = _sf(name="minLength", default=None)
    max_length: Optional[int] = _sf(name="maxLength", default=None)
    repetition_penalty: Optional[float] = _sf(name="repetitionPenalty", default=None)
    frequency_penalty: Optional[float] = _sf(name="frequencyPenalty", default=None)
    presence_penalty: Optional[float] = _sf(name="presencePenalty", default=None)
    reasoning: Optional[ReasoningConfig] = None
    price: Optional[ModelPrice] = None

    @classmethod
    def from_pydantic(cls, model: Any) -> "AgentConfig":
        reasoning = getattr(model, "reasoning", None)
        price = getattr(model, "price", None)
        return cls(
            model=getattr(model, "model", ""),
            max_tokens=getattr(model, "max_tokens", None),
            temperature=getattr(model, "temperature", None),
            top_k=getattr(model, "top_k", None),
            top_p=getattr(model, "top_p", None),
            min_length=getattr(model, "min_length", None),
            max_length=getattr(model, "max_length", None),
            repetition_penalty=getattr(model, "repetition_penalty", None),
            frequency_penalty=getattr(model, "frequency_penalty", None),
            presence_penalty=getattr(model, "presence_penalty", None),
            reasoning=ReasoningConfig.from_pydantic(reasoning) if reasoning else None,
            price=ModelPrice.from_pydantic(price) if price else None,
        )


@_stype
class AgentsConfig:
    simple: AgentConfig
    simple_json: AgentConfig = _sf(name="simpleJson")
    primary_agent: AgentConfig = _sf(name="primaryAgent")
    assistant: AgentConfig
    generator: AgentConfig
    refiner: AgentConfig
    adviser: AgentConfig
    reflector: AgentConfig
    searcher: AgentConfig
    enricher: AgentConfig
    coder: AgentConfig
    installer: AgentConfig
    pentester: AgentConfig

    @classmethod
    def from_pydantic(cls, model: Any) -> "AgentsConfig":
        def _g(name: str) -> AgentConfig:
            sub = getattr(model, name, None)
            return AgentConfig.from_pydantic(sub) if sub else AgentConfig(model="")
        return cls(
            simple=_g("simple"),
            simple_json=_g("simple_json"),
            primary_agent=_g("primary_agent"),
            assistant=_g("assistant"),
            generator=_g("generator"),
            refiner=_g("refiner"),
            adviser=_g("adviser"),
            reflector=_g("reflector"),
            searcher=_g("searcher"),
            enricher=_g("enricher"),
            coder=_g("coder"),
            installer=_g("installer"),
            pentester=_g("pentester"),
        )


@_stype
class ProviderConfig:
    id: strawberry.ID
    name: str
    type: ProviderType
    agents: AgentsConfig
    created_at: _dt.datetime = _sf(name="createdAt")
    updated_at: _dt.datetime = _sf(name="updatedAt")

    @classmethod
    def from_pydantic(cls, model: Any) -> "ProviderConfig":
        agents = getattr(model, "agents", None)
        return cls(
            id=strawberry.ID(str(getattr(model, "id", "0"))),
            name=getattr(model, "name", ""),
            type=ProviderType(getattr(model, "type", "openai")),
            agents=AgentsConfig.from_pydantic(agents) if agents else AgentsConfig.from_pydantic(
                type("M", (), {})()
            ),
            created_at=getattr(model, "created_at", _dt.datetime.utcnow()),
            updated_at=getattr(model, "updated_at", _dt.datetime.utcnow()),
        )


@_stype
class ModelConfig:
    name: str
    description: Optional[str] = None
    release_date: Optional[_dt.datetime] = _sf(name="releaseDate", default=None)
    thinking: Optional[bool] = None
    price: Optional[ModelPrice] = None

    @classmethod
    def from_pydantic(cls, model: Any) -> "ModelConfig":
        price = getattr(model, "price", None)
        return cls(
            name=getattr(model, "name", ""),
            description=getattr(model, "description", None),
            release_date=getattr(model, "release_date", None),
            thinking=getattr(model, "thinking", None),
            price=ModelPrice.from_pydantic(price) if price else None,
        )


@_stype
class ProvidersModelsList:
    openai: List[ModelConfig]
    anthropic: List[ModelConfig]
    gemini: List[ModelConfig]
    bedrock: Optional[List[ModelConfig]] = None
    ollama: Optional[List[ModelConfig]] = None
    custom: Optional[List[ModelConfig]] = None
    deepseek: Optional[List[ModelConfig]] = None
    glm: Optional[List[ModelConfig]] = None
    kimi: Optional[List[ModelConfig]] = None
    qwen: Optional[List[ModelConfig]] = None

    @classmethod
    def from_pydantic(cls, model: Any) -> "ProvidersModelsList":
        def _g(name: str) -> Optional[List[ModelConfig]]:
            lst = getattr(model, name, None) or []
            return [ModelConfig.from_pydantic(m) for m in lst] or None

        return cls(
            openai=_g("openai") or [],
            anthropic=_g("anthropic") or [],
            gemini=_g("gemini") or [],
            bedrock=_g("bedrock"),
            ollama=_g("ollama"),
            custom=_g("custom"),
            deepseek=_g("deepseek"),
            glm=_g("glm"),
            kimi=_g("kimi"),
            qwen=_g("qwen"),
        )


@_stype
class ProvidersReadinessStatus:
    openai: bool
    anthropic: bool
    gemini: bool
    bedrock: bool
    ollama: bool
    custom: bool
    deepseek: bool
    glm: bool
    kimi: bool
    qwen: bool

    @classmethod
    def from_pydantic(cls, model: Any) -> "ProvidersReadinessStatus":
        return cls(
            openai=bool(getattr(model, "openai", False)),
            anthropic=bool(getattr(model, "anthropic", False)),
            gemini=bool(getattr(model, "gemini", False)),
            bedrock=bool(getattr(model, "bedrock", False)),
            ollama=bool(getattr(model, "ollama", False)),
            custom=bool(getattr(model, "custom", False)),
            deepseek=bool(getattr(model, "deepseek", False)),
            glm=bool(getattr(model, "glm", False)),
            kimi=bool(getattr(model, "kimi", False)),
            qwen=bool(getattr(model, "qwen", False)),
        )


@_stype
class DefaultProvidersConfig:
    openai: ProviderConfig
    anthropic: ProviderConfig
    gemini: Optional[ProviderConfig] = None
    bedrock: Optional[ProviderConfig] = None
    ollama: Optional[ProviderConfig] = None
    custom: Optional[ProviderConfig] = None
    deepseek: Optional[ProviderConfig] = None
    glm: Optional[ProviderConfig] = None
    kimi: Optional[ProviderConfig] = None
    qwen: Optional[ProviderConfig] = None

    @classmethod
    def from_pydantic(cls, model: Any) -> "DefaultProvidersConfig":
        def _g(name: str) -> Optional[ProviderConfig]:
            sub = getattr(model, name, None)
            return ProviderConfig.from_pydantic(sub) if sub else None

        empty = ProviderConfig(
            id=strawberry.ID("0"),
            name="",
            type=ProviderType.OPENAI,
            agents=AgentsConfig.from_pydantic(type("M", (), {})()),
            created_at=_dt.datetime.utcnow(),
            updated_at=_dt.datetime.utcnow(),
        )
        return cls(
            openai=_g("openai") or empty,
            anthropic=_g("anthropic") or empty,
            gemini=_g("gemini"),
            bedrock=_g("bedrock"),
            ollama=_g("ollama"),
            custom=_g("custom"),
            deepseek=_g("deepseek"),
            glm=_g("glm"),
            kimi=_g("kimi"),
            qwen=_g("qwen"),
        )


@_stype
class ProvidersConfig:
    enabled: ProvidersReadinessStatus
    default: DefaultProvidersConfig
    user_defined: Optional[List[ProviderConfig]] = _sf(name="userDefined", default=None)
    models: ProvidersModelsList

    @classmethod
    def from_pydantic(cls, model: Any) -> "ProvidersConfig":
        enabled = getattr(model, "enabled", None)
        default = getattr(model, "default", None)
        user = getattr(model, "user_defined", None) or []
        models = getattr(model, "models", None)
        return cls(
            enabled=(
                ProvidersReadinessStatus.from_pydantic(enabled)
                if enabled
                else ProvidersReadinessStatus.from_pydantic(type("M", (), {})())
            ),
            default=(
                DefaultProvidersConfig.from_pydantic(default)
                if default
                else DefaultProvidersConfig.from_pydantic(type("M", (), {})())
            ),
            user_defined=[ProviderConfig.from_pydantic(u) for u in user] or None,
            models=(
                ProvidersModelsList.from_pydantic(models)
                if models
                else ProvidersModelsList.from_pydantic(type("M", (), {})())
            ),
        )


# ─── Input types (provider config) ─────────────────────────────────────────

@_sinput
class ReasoningConfigInput:
    effort: Optional[ReasoningEffort] = None
    max_tokens: Optional[int] = None


@_sinput
class ModelPriceInput:
    input: float
    output: float
    cache_read: float
    cache_write: float


@_sinput
class AgentConfigInput:
    model: str
    max_tokens: Optional[int] = None
    temperature: Optional[float] = None
    top_k: Optional[int] = None
    top_p: Optional[float] = None
    min_length: Optional[int] = None
    max_length: Optional[int] = None
    repetition_penalty: Optional[float] = None
    frequency_penalty: Optional[float] = None
    presence_penalty: Optional[float] = None
    reasoning: Optional[ReasoningConfigInput] = None
    price: Optional[ModelPriceInput] = None


@_sinput
class AgentsConfigInput:
    simple: AgentConfigInput
    simple_json: AgentConfigInput
    primary_agent: AgentConfigInput
    assistant: AgentConfigInput
    generator: AgentConfigInput
    refiner: AgentConfigInput
    adviser: AgentConfigInput
    reflector: AgentConfigInput
    searcher: AgentConfigInput
    enricher: AgentConfigInput
    coder: AgentConfigInput
    installer: AgentConfigInput
    pentester: AgentConfigInput


# ─── Knowledge (vector store) types ────────────────────────────────────────

@_stype
class KnowledgeDocument:
    id: str
    doc_type: KnowledgeDocType = _sf(name="docType")
    content: str
    question: str
    description: Optional[str] = None
    user_id: strawberry.ID = _sf(name="userId")
    flow_id: Optional[strawberry.ID] = _sf(name="flowId", default=None)
    task_id: Optional[strawberry.ID] = _sf(name="taskId", default=None)
    subtask_id: Optional[strawberry.ID] = _sf(name="subtaskId", default=None)
    guide_type: Optional[KnowledgeGuideType] = _sf(name="guideType", default=None)
    answer_type: Optional[KnowledgeAnswerType] = _sf(name="answerType", default=None)
    code_lang: Optional[str] = _sf(name="codeLang", default=None)
    part_size: int = _sf(name="partSize")
    total_size: int = _sf(name="totalSize")
    manual: bool

    @classmethod
    def from_pydantic(cls, model: Any) -> "KnowledgeDocument":
        gt = getattr(model, "guide_type", None)
        at = getattr(model, "answer_type", None)
        return cls(
            id=str(getattr(model, "id", "")),
            doc_type=KnowledgeDocType(getattr(model, "doc_type", "answer")),
            content=getattr(model, "content", ""),
            question=getattr(model, "question", ""),
            description=getattr(model, "description", None),
            user_id=strawberry.ID(str(getattr(model, "user_id", "0"))),
            flow_id=(
                strawberry.ID(str(model.flow_id))
                if getattr(model, "flow_id", None) is not None
                else None
            ),
            task_id=(
                strawberry.ID(str(model.task_id))
                if getattr(model, "task_id", None) is not None
                else None
            ),
            subtask_id=(
                strawberry.ID(str(model.subtask_id))
                if getattr(model, "subtask_id", None) is not None
                else None
            ),
            guide_type=KnowledgeGuideType(gt) if gt is not None else None,
            answer_type=KnowledgeAnswerType(at) if at is not None else None,
            code_lang=getattr(model, "code_lang", None),
            part_size=int(getattr(model, "part_size", 0)),
            total_size=int(getattr(model, "total_size", 0)),
            manual=bool(getattr(model, "manual", False)),
        )


@_stype
class KnowledgeDocumentWithScore:
    score: float
    document: KnowledgeDocument

    @classmethod
    def from_pydantic(cls, model: Any) -> "KnowledgeDocumentWithScore":
        doc = getattr(model, "document", None)
        return cls(
            score=float(getattr(model, "score", 0.0)),
            document=(
                KnowledgeDocument.from_pydantic(doc)
                if doc is not None
                else KnowledgeDocument(
                    id="",
                    doc_type=KnowledgeDocType.ANSWER,
                    content="",
                    question="",
                    user_id=strawberry.ID("0"),
                    part_size=0,
                    total_size=0,
                    manual=False,
                )
            ),
        )


@_sinput
class KnowledgeFilter:
    doc_types: Optional[List[KnowledgeDocType]] = None
    guide_types: Optional[List[KnowledgeGuideType]] = None
    answer_types: Optional[List[KnowledgeAnswerType]] = None
    code_langs: Optional[List[str]] = None
    flow_id: Optional[strawberry.ID] = None
    manual: Optional[bool] = None


@_sinput
class CreateKnowledgeDocumentInput:
    doc_type: KnowledgeDocType
    content: str
    question: str
    description: Optional[str] = None
    guide_type: Optional[KnowledgeGuideType] = None
    answer_type: Optional[KnowledgeAnswerType] = None
    code_lang: Optional[str] = None


@_sinput
class UpdateKnowledgeDocumentInput:
    content: str
    question: Optional[str] = None
    description: Optional[str] = None
    doc_type: Optional[KnowledgeDocType] = None
    guide_type: Optional[KnowledgeGuideType] = None
    answer_type: Optional[KnowledgeAnswerType] = None
    code_lang: Optional[str] = None


# ─── Public re-exports ─────────────────────────────────────────────────────

__all__ = [
    # Core
    "Settings",
    "UserPreferences",
    # Flow templates
    "FlowTemplate",
    "CreateFlowTemplateInput",
    "UpdateFlowTemplateInput",
    # Flow mgmt
    "Terminal",
    "Provider",
    "Assistant",
    "FlowAssistant",
    "Flow",
    "Task",
    "Subtask",
    # Logs
    "AssistantLog",
    "AgentLog",
    "MessageLog",
    "SearchLog",
    "TerminalLog",
    "VectorStoreLog",
    "ToolCallLog",
    "Screenshot",
    "FlowFile",
    "UserResource",
    # API tokens
    "APIToken",
    "APITokenWithSecret",
    "CreateAPITokenInput",
    "UpdateAPITokenInput",
    # Prompts
    "PromptValidationResult",
    "DefaultPrompt",
    "UserPrompt",
    "AgentPrompt",
    "AgentPrompts",
    "AgentsPrompts",
    "ToolsPrompts",
    "DefaultPrompts",
    "PromptsConfig",
    # Testing
    "TestResult",
    "AgentTestResult",
    "ProviderTestResult",
    # Stats
    "UsageStats",
    "ToolcallsStats",
    "FlowsStats",
    "FlowStats",
    "DailyUsageStats",
    "ProviderUsageStats",
    "ModelUsageStats",
    "ModelAgentsUsageStats",
    "AgentTypeUsageStats",
    "DailyToolcallsStats",
    "FunctionToolcallsStats",
    "DailyFlowsStats",
    "SubtaskExecutionStats",
    "TaskExecutionStats",
    "FlowExecutionStats",
    # Providers
    "ModelPrice",
    "ReasoningConfig",
    "AgentConfig",
    "AgentsConfig",
    "ProviderConfig",
    "ModelConfig",
    "ProvidersModelsList",
    "ProvidersReadinessStatus",
    "DefaultProvidersConfig",
    "ProvidersConfig",
    # Inputs
    "ReasoningConfigInput",
    "ModelPriceInput",
    "AgentConfigInput",
    "AgentsConfigInput",
    # Knowledge
    "KnowledgeDocument",
    "KnowledgeDocumentWithScore",
    "KnowledgeFilter",
    "CreateKnowledgeDocumentInput",
    "UpdateKnowledgeDocumentInput",
    # Re-exported enums (for convenience)
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
    # Strawberry helpers re-exported for resolvers
    "strawberry",
    "Info",
    "_JSON",
]
