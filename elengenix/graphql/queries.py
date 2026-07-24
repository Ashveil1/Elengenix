"""
elengenix.graphql.queries — Read-side GraphQL resolvers ported from PentAGI's
``backend/pkg/graph/schema.graphqls`` ``type Query`` block (43 queries).

All resolvers are ``async`` and look up their backing service from the
Strawberry request context. The context is a plain dict populated by the
FastAPI router in :mod:`elengenix.api.v1.graphql` with the following layout::

    {
        "request": starlette.requests.Request,
        "services": elengenix.services.ServiceContainer,
        "user_id": int,
        "user_type": str,        # "local" | "api" | "oauth"
        "permissions": list[str],
    }

If a service is missing (e.g. during static introspection or unit tests)
the resolver logs a warning and returns an empty default value rather than
raising — that way the schema is always introspectable.

References:
    * PentAGI: backend/pkg/graph/schema.graphqls (type Query block, 67 lines)
    * PentAGI: backend/pkg/graph/schema.resolvers.go (query resolvers)
"""
from __future__ import annotations

import logging
from typing import Any, List, Optional

import strawberry
from strawberry.types import Info

from .schema import (
    UsageStatsPeriod,
)
from .types import (
    AgentTypeUsageStats,
    APIToken,
    Assistant,
    AssistantLog,
    AgentLog,
    DailyFlowsStats,
    DailyToolcallsStats,
    DailyUsageStats,
    DefaultPrompts,
    Flow,
    FlowExecutionStats,
    FlowFile,
    FlowStats,
    FlowTemplate,
    FlowsStats,
    FunctionToolcallsStats,
    KnowledgeDocument,
    KnowledgeDocumentWithScore,
    KnowledgeFilter,
    MessageLog,
    ModelAgentsUsageStats,
    ModelConfig,
    ModelUsageStats,
    PromptsConfig,
    Provider,
    ProviderConfig,
    ProvidersConfig,
    ProviderUsageStats,
    Screenshot,
    SearchLog,
    Settings,
    SubtaskExecutionStats,
    Task,
    TaskExecutionStats,
    TerminalLog,
    ToolCallLog,
    ToolcallsStats,
    UsageStats,
    UserPreferences,
    UserPrompt,
    UserResource,
    VectorStoreLog,
)

logger = logging.getLogger("elengenix.graphql.queries")


# ─── Service-lookup helpers ────────────────────────────────────────────────

def _ctx(info: Info) -> dict:
    """Return the Strawberry request context as a dict (or empty dict)."""
    ctx = getattr(info, "context", None)
    if isinstance(ctx, dict):
        return ctx
    if hasattr(ctx, "__dict__"):
        return ctx.__dict__
    return {}


def _services(info: Info) -> Any:
    """Return the service container registered on the request context."""
    return _ctx(info).get("services")


def _user_id(info: Info) -> int:
    return int(_ctx(info).get("user_id", 0) or 0)


async def _call(info: Info, service_name: str, method: str, *args: Any, **kwargs: Any) -> Any:
    """Invoke ``service.method(*args, **kwargs)`` if registered, else None.

    Returns the awaitable result if the method itself is async — supports both
    sync and async service methods. When the service container or the named
    service is missing, returns ``None`` so the resolver can fall back to a
    sensible default.
    """
    services = _services(info)
    if services is None:
        logger.debug("no service container on context; skipping %s.%s", service_name, method)
        return None
    service = getattr(services, service_name, None)
    if service is None:
        logger.debug("service %s not registered; skipping .%s", service_name, method)
        return None
    fn = getattr(service, method, None)
    if fn is None:
        logger.debug("method %s.%s not implemented", service_name, method)
        return None
    result = fn(*args, **kwargs)
    if hasattr(result, "__await__"):
        result = await result
    return result


# ─── Query root type ───────────────────────────────────────────────────────

@strawberry.type(description="Elengenix GraphQL read root (PentAGI port).")
class Query:
    # ── Provider management ────────────────────────────────────────────────

    @strawberry.field(description="List all configured LLM providers (short view).")
    async def providers(self, info: Info) -> List[Provider]:
        rows = await _call(info, "providers", "list_providers") or []
        return [Provider.from_pydantic(r) for r in rows]

    @strawberry.field(description="List available models for a given provider type.")
    async def models(
        self, info: Info, provider: str  # noqa: A002 — matches SDL arg name
    ) -> List[ModelConfig]:
        # SDL exposes models via ``settingsProviders.models``; kept here as a
        # convenience shortcut for the upstream PentAGI ``models(provider)``
        # query described in the worklog (Task 1-c).
        rows = await _call(info, "providers", "list_models", provider) or []
        return [ModelConfig.from_pydantic(r) for r in rows]

    # ── Flow and assistant management ─────────────────────────────────────

    @strawberry.field(description="List all flows visible to the current user.")
    async def flows(self, info: Info) -> Optional[List[Flow]]:
        rows = await _call(info, "flows", "list_flows", _user_id(info)) or []
        return [Flow.from_pydantic(r) for r in rows]

    @strawberry.field(description="Fetch a single flow by ID.")
    async def flow(self, info: Info, flow_id: strawberry.ID) -> Flow:
        row = await _call(info, "flows", "get_flow", int(flow_id))
        if row is None:
            return Flow.placeholder()
        return Flow.from_pydantic(row)

    @strawberry.field(description="List assistants for a flow (or all if flowId is 0).")
    async def assistants(self, info: Info, flow_id: strawberry.ID) -> Optional[List[Assistant]]:
        rows = await _call(info, "assistants", "list_assistants", int(flow_id)) or []
        return [Assistant.from_pydantic(r) for r in rows]

    @strawberry.field(description="List tasks for a flow.")
    async def tasks(self, info: Info, flow_id: strawberry.ID) -> Optional[List[Task]]:
        rows = await _call(info, "flows", "list_tasks", int(flow_id)) or []
        return [Task.from_pydantic(r) for r in rows]

    @strawberry.field(description="List files attached to a flow.")
    async def flow_files(self, info: Info, flow_id: strawberry.ID) -> List[FlowFile]:
        rows = await _call(info, "flows", "list_files", int(flow_id)) or []
        return [FlowFile.from_pydantic(r) for r in rows]

    # ── Log types ──────────────────────────────────────────────────────────

    @strawberry.field(description="Screenshots captured during flow execution.")
    async def screenshots(self, info: Info, flow_id: strawberry.ID) -> Optional[List[Screenshot]]:
        rows = await _call(info, "logs", "list_screenshots", int(flow_id)) or []
        return [Screenshot.from_pydantic(r) for r in rows]

    @strawberry.field(description="Terminal logs (stdin/stdout/stderr).")
    async def terminal_logs(
        self, info: Info, flow_id: strawberry.ID
    ) -> Optional[List[TerminalLog]]:
        rows = await _call(info, "logs", "list_terminal_logs", int(flow_id)) or []
        return [TerminalLog.from_pydantic(r) for r in rows]

    @strawberry.field(description="Message logs (agent → user comms).")
    async def message_logs(
        self, info: Info, flow_id: strawberry.ID
    ) -> Optional[List[MessageLog]]:
        rows = await _call(info, "logs", "list_message_logs", int(flow_id)) or []
        return [MessageLog.from_pydantic(r) for r in rows]

    @strawberry.field(description="Agent logs (initiator/executor pairs).")
    async def agent_logs(self, info: Info, flow_id: strawberry.ID) -> Optional[List[AgentLog]]:
        rows = await _call(info, "logs", "list_agent_logs", int(flow_id)) or []
        return [AgentLog.from_pydantic(r) for r in rows]

    @strawberry.field(description="Search logs (web search invocations).")
    async def search_logs(self, info: Info, flow_id: strawberry.ID) -> Optional[List[SearchLog]]:
        rows = await _call(info, "logs", "list_search_logs", int(flow_id)) or []
        return [SearchLog.from_pydantic(r) for r in rows]

    @strawberry.field(description="Vector store logs (retrieve/store).")
    async def vector_store_logs(
        self, info: Info, flow_id: strawberry.ID
    ) -> Optional[List[VectorStoreLog]]:
        rows = await _call(info, "logs", "list_vector_store_logs", int(flow_id)) or []
        return [VectorStoreLog.from_pydantic(r) for r in rows]

    @strawberry.field(description="Tool call logs (function calls + responses).")
    async def tool_call_logs(
        self, info: Info, flow_id: strawberry.ID
    ) -> Optional[List[ToolCallLog]]:
        rows = await _call(info, "logs", "list_tool_call_logs", int(flow_id)) or []
        return [ToolCallLog.from_pydantic(r) for r in rows]

    @strawberry.field(description="Assistant logs (assistant → user comms).")
    async def assistant_logs(
        self, info: Info, flow_id: strawberry.ID, assistant_id: strawberry.ID
    ) -> Optional[List[AssistantLog]]:
        rows = (
            await _call(
                info,
                "logs",
                "list_assistant_logs",
                int(flow_id),
                int(assistant_id),
            )
            or []
        )
        return [AssistantLog.from_pydantic(r) for r in rows]

    # ── Usage statistics ──────────────────────────────────────────────────

    @strawberry.field(description="Aggregate token usage across all flows.")
    async def usage_stats_total(self, info: Info) -> UsageStats:
        row = await _call(info, "stats", "usage_stats_total", _user_id(info))
        return UsageStats.from_pydantic(row) if row is not None else UsageStats.empty()

    @strawberry.field(description="Daily token usage for the given period.")
    async def usage_stats_by_period(
        self, info: Info, period: UsageStatsPeriod
    ) -> List[DailyUsageStats]:
        rows = await _call(info, "stats", "usage_stats_by_period", _user_id(info), period.value)
        return [DailyUsageStats.from_pydantic(r) for r in (rows or [])]

    @strawberry.field(description="Token usage broken down by provider.")
    async def usage_stats_by_provider(self, info: Info) -> List[ProviderUsageStats]:
        rows = await _call(info, "stats", "usage_stats_by_provider", _user_id(info))
        return [ProviderUsageStats.from_pydantic(r) for r in (rows or [])]

    @strawberry.field(description="Token usage broken down by model.")
    async def usage_stats_by_model(self, info: Info) -> List[ModelUsageStats]:
        rows = await _call(info, "stats", "usage_stats_by_model", _user_id(info))
        return [ModelUsageStats.from_pydantic(r) for r in (rows or [])]

    @strawberry.field(description="Token usage broken down by agent type.")
    async def usage_stats_by_agent_type(self, info: Info) -> List[AgentTypeUsageStats]:
        rows = await _call(info, "stats", "usage_stats_by_agent_type", _user_id(info))
        return [AgentTypeUsageStats.from_pydantic(r) for r in (rows or [])]

    @strawberry.field(description="Aggregate token usage for a single flow.")
    async def usage_stats_by_flow(self, info: Info, flow_id: strawberry.ID) -> UsageStats:
        row = await _call(info, "stats", "usage_stats_by_flow", _user_id(info), int(flow_id))
        return UsageStats.from_pydantic(row) if row is not None else UsageStats.empty()

    @strawberry.field(description="Per-agent-type token usage for a single flow.")
    async def usage_stats_by_agent_type_for_flow(
        self, info: Info, flow_id: strawberry.ID
    ) -> List[AgentTypeUsageStats]:
        rows = await _call(
            info, "stats", "usage_stats_by_agent_type_for_flow", _user_id(info), int(flow_id)
        )
        return [AgentTypeUsageStats.from_pydantic(r) for r in (rows or [])]

    @strawberry.field(description="Per-(model, agent-types) token usage for a single flow.")
    async def usage_stats_by_model_agents_for_flow(
        self, info: Info, flow_id: strawberry.ID
    ) -> List[ModelAgentsUsageStats]:
        rows = await _call(
            info, "stats", "usage_stats_by_model_agents_for_flow", _user_id(info), int(flow_id)
        )
        return [ModelAgentsUsageStats.from_pydantic(r) for r in (rows or [])]

    # ── Toolcall statistics ───────────────────────────────────────────────

    @strawberry.field(description="Aggregate toolcall count + duration across all flows.")
    async def toolcalls_stats_total(self, info: Info) -> ToolcallsStats:
        row = await _call(info, "stats", "toolcalls_stats_total", _user_id(info))
        return (
            ToolcallsStats.from_pydantic(row)
            if row is not None
            else ToolcallsStats.empty()
        )

    @strawberry.field(description="Daily toolcall statistics for the given period.")
    async def toolcalls_stats_by_period(
        self, info: Info, period: UsageStatsPeriod
    ) -> List[DailyToolcallsStats]:
        rows = await _call(
            info, "stats", "toolcalls_stats_by_period", _user_id(info), period.value
        )
        return [DailyToolcallsStats.from_pydantic(r) for r in (rows or [])]

    @strawberry.field(description="Toolcall statistics broken down by function name.")
    async def toolcalls_stats_by_function(
        self, info: Info
    ) -> List[FunctionToolcallsStats]:
        rows = await _call(info, "stats", "toolcalls_stats_by_function", _user_id(info))
        return [FunctionToolcallsStats.from_pydantic(r) for r in (rows or [])]

    @strawberry.field(description="Aggregate toolcall statistics for a single flow.")
    async def toolcalls_stats_by_flow(
        self, info: Info, flow_id: strawberry.ID
    ) -> ToolcallsStats:
        row = await _call(
            info, "stats", "toolcalls_stats_by_flow", _user_id(info), int(flow_id)
        )
        return (
            ToolcallsStats.from_pydantic(row)
            if row is not None
            else ToolcallsStats.empty()
        )

    @strawberry.field(description="Per-function toolcall statistics for a single flow.")
    async def toolcalls_stats_by_function_for_flow(
        self, info: Info, flow_id: strawberry.ID
    ) -> List[FunctionToolcallsStats]:
        rows = await _call(
            info,
            "stats",
            "toolcalls_stats_by_function_for_flow",
            _user_id(info),
            int(flow_id),
        )
        return [FunctionToolcallsStats.from_pydantic(r) for r in (rows or [])]

    # ── Flow statistics ───────────────────────────────────────────────────

    @strawberry.field(description="Aggregate flows/tasks/subtasks/assistants counts.")
    async def flows_stats_total(self, info: Info) -> FlowsStats:
        row = await _call(info, "stats", "flows_stats_total", _user_id(info))
        return FlowsStats.from_pydantic(row) if row is not None else FlowsStats.empty()

    @strawberry.field(description="Daily flows statistics for the given period.")
    async def flows_stats_by_period(
        self, info: Info, period: UsageStatsPeriod
    ) -> List[DailyFlowsStats]:
        rows = await _call(info, "stats", "flows_stats_by_period", _user_id(info), period.value)
        return [DailyFlowsStats.from_pydantic(r) for r in (rows or [])]

    @strawberry.field(description="Flow statistics for a single flow.")
    async def flow_stats_by_flow(self, info: Info, flow_id: strawberry.ID) -> FlowStats:
        row = await _call(info, "stats", "flow_stats_by_flow", _user_id(info), int(flow_id))
        return FlowStats.from_pydantic(row) if row is not None else FlowStats.empty()

    # ── Execution time statistics ─────────────────────────────────────────

    @strawberry.field(description="Per-flow execution-time statistics for the given period.")
    async def flows_execution_stats_by_period(
        self, info: Info, period: UsageStatsPeriod
    ) -> List[FlowExecutionStats]:
        rows = await _call(
            info, "stats", "flows_execution_stats_by_period", _user_id(info), period.value
        )
        return [FlowExecutionStats.from_pydantic(r) for r in (rows or [])]

    # ── Settings ──────────────────────────────────────────────────────────

    @strawberry.field(description="Server-side runtime settings exposed to the client.")
    async def settings(self, info: Info) -> Settings:
        row = await _call(info, "settings", "get_settings")
        return Settings.from_pydantic(row) if row is not None else Settings(
            debug=False,
            ask_user=False,
            version="",
            docker_inside=False,
            is_develop_mode=False,
            assistant_use_agents=False,
        )

    @strawberry.field(description="All configured providers + default configs + model list.")
    async def settings_providers(self, info: Info) -> ProvidersConfig:
        row = await _call(info, "providers", "get_providers_config", _user_id(info))
        if row is None:
            return ProvidersConfig.from_pydantic(type("M", (), {})())
        return ProvidersConfig.from_pydantic(row)

    @strawberry.field(description="Default prompts + user-defined overrides.")
    async def settings_prompts(self, info: Info) -> PromptsConfig:
        row = await _call(info, "prompts", "get_prompts_config")
        if row is None:
            return PromptsConfig.from_pydantic(type("M", (), {})())
        return PromptsConfig.from_pydantic(row)

    @strawberry.field(description="Per-user preferences (favorites, language, ...).")
    async def settings_user(self, info: Info) -> UserPreferences:
        row = await _call(info, "users", "get_user_preferences", _user_id(info))
        if row is None:
            return UserPreferences(id=strawberry.ID("0"), favorite_flows=[])
        return UserPreferences.from_pydantic(row)

    # ── Prompts (singletons) ──────────────────────────────────────────────

    @strawberry.field(description="List all user-customized prompt templates.")
    async def prompts(self, info: Info) -> List[UserPrompt]:
        rows = await _call(info, "prompts", "list_prompts", _user_id(info))
        return [UserPrompt.from_pydantic(r) for r in (rows or [])]

    @strawberry.field(description="Fetch a single user prompt by ID.")
    async def prompt(
        self, info: Info, id: strawberry.ID  # noqa: A002 — SDL arg name
    ) -> Optional[UserPrompt]:
        row = await _call(info, "prompts", "get_prompt", int(id))
        if row is None:
            return None
        return UserPrompt.from_pydantic(row)

    # ── API tokens ────────────────────────────────────────────────────────

    @strawberry.field(description="Fetch a single API token by its 10-char token ID.")
    async def api_token(self, info: Info, token_id: str) -> Optional[APIToken]:
        row = await _call(info, "tokens", "get_api_token", _user_id(info), token_id)
        if row is None:
            return None
        return APIToken.from_pydantic(row)

    @strawberry.field(description="List all API tokens owned by the current user.")
    async def api_tokens(self, info: Info) -> List[APIToken]:
        rows = await _call(info, "tokens", "list_api_tokens", _user_id(info))
        return [APIToken.from_pydantic(r) for r in (rows or [])]

    # ── Flow templates ────────────────────────────────────────────────────

    @strawberry.field(description="Fetch a single flow template by ID.")
    async def flow_template(
        self, info: Info, template_id: strawberry.ID
    ) -> Optional[FlowTemplate]:
        row = await _call(info, "templates", "get_flow_template", _user_id(info), int(template_id))
        if row is None:
            return None
        return FlowTemplate.from_pydantic(row)

    @strawberry.field(description="List all flow templates owned by the current user.")
    async def flow_templates(self, info: Info) -> List[FlowTemplate]:
        rows = await _call(info, "templates", "list_flow_templates", _user_id(info))
        return [FlowTemplate.from_pydantic(r) for r in (rows or [])]

    # ── User resources ────────────────────────────────────────────────────

    @strawberry.field(description="List user resources (optionally under a path, recursively).")
    async def resources(
        self,
        info: Info,
        path: Optional[str] = None,
        recursive: Optional[bool] = None,
    ) -> List[UserResource]:
        rows = await _call(
            info,
            "resources",
            "list_resources",
            _user_id(info),
            path,
            bool(recursive) if recursive is not None else False,
        )
        return [UserResource.from_pydantic(r) for r in (rows or [])]

    # ── Knowledge documents ───────────────────────────────────────────────

    @strawberry.field(description="List knowledge documents matching the filter.")
    async def knowledge_documents(
        self,
        info: Info,
        filter: Optional[KnowledgeFilter] = None,  # noqa: A002 — SDL arg name
        with_content: bool = True,
    ) -> List[KnowledgeDocument]:
        rows = await _call(
            info,
            "knowledge",
            "list_documents",
            _user_id(info),
            filter,
            with_content,
        )
        return [KnowledgeDocument.from_pydantic(r) for r in (rows or [])]

    @strawberry.field(description="Fetch a single knowledge document by UUID.")
    async def knowledge_document(self, info: Info, id: str) -> KnowledgeDocument:  # noqa: A002
        row = await _call(info, "knowledge", "get_document", _user_id(info), id)
        if row is None:
            # SDL marks this field as non-null; return an empty placeholder.
            return KnowledgeDocument(
                id="",
                doc_type=__import__("elengenix.graphql.schema", fromlist=["KnowledgeDocType"]).KnowledgeDocType.ANSWER,
                content="",
                question="",
                user_id=strawberry.ID("0"),
                part_size=0,
                total_size=0,
                manual=False,
            )
        return KnowledgeDocument.from_pydantic(row)

    @strawberry.field(description="Semantic search over the knowledge base.")
    async def search_knowledge(
        self,
        info: Info,
        query: str,
        filter: Optional[KnowledgeFilter] = None,  # noqa: A002 — SDL arg name
        limit: Optional[int] = None,
    ) -> List[KnowledgeDocumentWithScore]:
        rows = await _call(
            info,
            "knowledge",
            "search_documents",
            _user_id(info),
            query,
            filter,
            limit,
        )
        return [KnowledgeDocumentWithScore.from_pydantic(r) for r in (rows or [])]


__all__ = [
    "Query",
    "FunctionToolcallsStats",
    "SubtaskExecutionStats",
    "TaskExecutionStats",
    "DefaultPrompts",
    "ProviderConfig",
    "ModelConfig",
    "UserPrompt",
]
