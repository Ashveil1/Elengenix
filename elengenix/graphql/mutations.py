"""
elengenix.graphql.mutations — Write-side GraphQL resolvers ported from
PentAGI's ``backend/pkg/graph/schema.graphqls`` ``type Mutation`` block
(31 mutations).

All resolvers are ``async`` and look up their backing service from the
Strawberry request context — same convention as
:mod:`elengenix.graphql.queries`. Each mutation is also expected to publish
the corresponding subscription event via the subscriptions controller (see
:mod:`elengenix.graphql.subscriptions`).

References:
    * PentAGI: backend/pkg/graph/schema.graphqls (type Mutation block, 48 lines)
    * PentAGI: backend/pkg/graph/schema.resolvers.go (mutation resolvers)
"""
from __future__ import annotations

import logging
from typing import Any, List, Optional

import strawberry
from strawberry.types import Info

from .schema import (
    AgentConfigType,
    PromptType,
    ProviderType,
    ResultType,
)
from .types import (
    AgentsConfigInput,
    AgentConfigInput,
    AgentTestResult,
    APIToken,
    APITokenWithSecret,
    Assistant,
    CreateAPITokenInput,
    CreateFlowTemplateInput,
    CreateKnowledgeDocumentInput,
    Flow,
    FlowAssistant,
    FlowTemplate,
    KnowledgeDocument,
    PromptValidationResult,
    ProviderConfig,
    ProviderTestResult,
    UpdateAPITokenInput,
    UpdateFlowTemplateInput,
    UpdateKnowledgeDocumentInput,
    UserPrompt,
)

logger = logging.getLogger("elengenix.graphql.mutations")


# ─── Service-lookup helpers (mirrors queries.py) ──────────────────────────

def _ctx(info: Info) -> dict:
    ctx = getattr(info, "context", None)
    if isinstance(ctx, dict):
        return ctx
    if hasattr(ctx, "__dict__"):
        return ctx.__dict__
    return {}


def _services(info: Info) -> Any:
    return _ctx(info).get("services")


def _user_id(info: Info) -> int:
    return int(_ctx(info).get("user_id", 0) or 0)


async def _call(info: Info, service_name: str, method: str, *args: Any, **kwargs: Any) -> Any:
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


async def _publish(info: Info, topic: str, payload: Any) -> None:
    """Broadcast a subscription event via the subscriptions controller.

    The controller is registered on the request context as
    ``"subscriptions"``. When absent (e.g. in unit tests), the call is a
    no-op. Topic names mirror the SDL subscription field names exactly
    (camelCase) so that clients subscribed via the regular WebSocket
    transport receive the event.
    """
    subs = _ctx(info).get("subscriptions")
    if subs is None:
        return
    publish = getattr(subs, "publish", None)
    if publish is None:
        return
    try:
        result = publish(topic, payload)
        if hasattr(result, "__await__"):
            await result
    except Exception:  # pragma: no cover — defensive, never break a mutation
        logger.exception("subscriptions.publish failed for topic=%s", topic)


# ─── Mutation root type ────────────────────────────────────────────────────

@strawberry.type(description="Elengenix GraphQL write root (PentAGI port).")
class Mutation:
    # ── Flow lifecycle ────────────────────────────────────────────────────

    @strawberry.mutation(description="Create a new flow and start its primary agent.")
    async def create_flow(
        self,
        info: Info,
        model_provider: str,
        input: str,  # noqa: A002 — SDL arg name
        resource_ids: Optional[List[strawberry.ID]] = None,
    ) -> Flow:
        row = await _call(
            info,
            "flows",
            "create_flow",
            _user_id(info),
            model_provider,
            input,
            [int(r) for r in (resource_ids or [])],
        )
        if row is None:
            return Flow.placeholder()
        flow = Flow.from_pydantic(row)
        await _publish(info, "flowCreated", flow)
        return flow

    @strawberry.mutation(description="Inject additional user input into a running flow.")
    async def put_user_input(
        self,
        info: Info,
        flow_id: strawberry.ID,
        input: str,  # noqa: A002 — SDL arg name
        model_provider: Optional[str] = None,
        resource_ids: Optional[List[strawberry.ID]] = None,
    ) -> ResultType:
        ok = await _call(
            info,
            "flows",
            "put_user_input",
            int(flow_id),
            input,
            model_provider,
            [int(r) for r in (resource_ids or [])],
        )
        return ResultType.SUCCESS if ok else ResultType.ERROR

    @strawberry.mutation(description="Stop a running flow gracefully.")
    async def stop_flow(self, info: Info, flow_id: strawberry.ID) -> ResultType:
        ok = await _call(info, "flows", "stop_flow", int(flow_id))
        return ResultType.SUCCESS if ok else ResultType.ERROR

    @strawberry.mutation(description="Mark a flow as finished (no more tasks accepted).")
    async def finish_flow(self, info: Info, flow_id: strawberry.ID) -> ResultType:
        ok = await _call(info, "flows", "finish_flow", int(flow_id))
        return ResultType.SUCCESS if ok else ResultType.ERROR

    @strawberry.mutation(description="Delete a flow and all of its tasks/subtasks/logs.")
    async def delete_flow(self, info: Info, flow_id: strawberry.ID) -> ResultType:
        ok = await _call(info, "flows", "delete_flow", int(flow_id))
        return ResultType.SUCCESS if ok else ResultType.ERROR

    @strawberry.mutation(description="Rename a flow in place.")
    async def rename_flow(
        self, info: Info, flow_id: strawberry.ID, title: str
    ) -> ResultType:
        ok = await _call(info, "flows", "rename_flow", int(flow_id), title)
        return ResultType.SUCCESS if ok else ResultType.ERROR

    # ── Assistant lifecycle ───────────────────────────────────────────────

    @strawberry.mutation(description="Create a new assistant within a flow.")
    async def create_assistant(
        self,
        info: Info,
        flow_id: strawberry.ID,
        model_provider: str,
        input: str,  # noqa: A002 — SDL arg name
        use_agents: bool,
        resource_ids: Optional[List[strawberry.ID]] = None,
    ) -> FlowAssistant:
        row = await _call(
            info,
            "assistants",
            "create_assistant",
            _user_id(info),
            int(flow_id),
            model_provider,
            input,
            use_agents,
            [int(r) for r in (resource_ids or [])],
        )
        if row is None:
            return FlowAssistant(
                flow=Flow.placeholder(),
                assistant=Assistant(
                    id=strawberry.ID("0"),
                    title="",
                    status=__import__(
                        "elengenix.graphql.schema", fromlist=["StatusType"]
                    ).StatusType.CREATED,
                    provider=__import__(
                        "elengenix.graphql.types", fromlist=["Provider"]
                    ).Provider(name="", type=ProviderType.OPENAI),
                    flow_id=flow_id,
                    use_agents=use_agents,
                    created_at=__import__("datetime").datetime.utcnow(),
                    updated_at=__import__("datetime").datetime.utcnow(),
                ),
            )
        result = FlowAssistant.from_pydantic(row)
        await _publish(info, "assistantCreated", result.assistant)
        return result

    @strawberry.mutation(description="Send a new message to an existing assistant.")
    async def call_assistant(
        self,
        info: Info,
        flow_id: strawberry.ID,
        assistant_id: strawberry.ID,
        input: str,  # noqa: A002 — SDL arg name
        use_agents: bool,
        resource_ids: Optional[List[strawberry.ID]] = None,
    ) -> ResultType:
        ok = await _call(
            info,
            "assistants",
            "call_assistant",
            int(flow_id),
            int(assistant_id),
            input,
            use_agents,
            [int(r) for r in (resource_ids or [])],
        )
        return ResultType.SUCCESS if ok else ResultType.ERROR

    @strawberry.mutation(description="Stop a running assistant gracefully.")
    async def stop_assistant(
        self, info: Info, flow_id: strawberry.ID, assistant_id: strawberry.ID
    ) -> Assistant:
        row = await _call(
            info, "assistants", "stop_assistant", int(flow_id), int(assistant_id)
        )
        if row is None:
            return Assistant(
                id=assistant_id,
                title="",
                status=__import__(
                    "elengenix.graphql.schema", fromlist=["StatusType"]
                ).StatusType.CREATED,
                provider=__import__(
                    "elengenix.graphql.types", fromlist=["Provider"]
                ).Provider(name="", type=ProviderType.OPENAI),
                flow_id=flow_id,
                use_agents=False,
                created_at=__import__("datetime").datetime.utcnow(),
                updated_at=__import__("datetime").datetime.utcnow(),
            )
        result = Assistant.from_pydantic(row)
        await _publish(info, "assistantUpdated", result)
        return result

    @strawberry.mutation(description="Delete an assistant and its logs.")
    async def delete_assistant(
        self, info: Info, flow_id: strawberry.ID, assistant_id: strawberry.ID
    ) -> ResultType:
        ok = await _call(
            info, "assistants", "delete_assistant", int(flow_id), int(assistant_id)
        )
        return ResultType.SUCCESS if ok else ResultType.ERROR

    # ── Provider testing & CRUD ───────────────────────────────────────────

    @strawberry.mutation(description="Run the agent test suite against a single AgentConfig.")
    async def test_agent(
        self,
        info: Info,
        type: ProviderType,  # noqa: A002 — SDL arg name
        agent_type: AgentConfigType,
        agent: AgentConfigInput,
    ) -> AgentTestResult:
        row = await _call(
            info, "providers", "test_agent", type.value, agent_type.value, agent
        )
        if row is None:
            return AgentTestResult(tests=[])
        return AgentTestResult.from_pydantic(row)

    @strawberry.mutation(description="Run the full provider test suite against all agent configs.")
    async def test_provider(
        self,
        info: Info,
        type: ProviderType,  # noqa: A002 — SDL arg name
        agents: AgentsConfigInput,
    ) -> ProviderTestResult:
        row = await _call(info, "providers", "test_provider", type.value, agents)
        if row is None:
            return ProviderTestResult.from_pydantic(type("M", (), {})())
        return ProviderTestResult.from_pydantic(row)

    @strawberry.mutation(description="Persist a new user-defined provider configuration.")
    async def create_provider(
        self,
        info: Info,
        name: str,
        type: ProviderType,  # noqa: A002 — SDL arg name
        agents: AgentsConfigInput,
    ) -> ProviderConfig:
        row = await _call(
            info, "providers", "create_provider", _user_id(info), name, type.value, agents
        )
        if row is None:
            return ProviderConfig.from_pydantic(type("M", (), {})())
        result = ProviderConfig.from_pydantic(row)
        await _publish(info, "providerCreated", result)
        return result

    @strawberry.mutation(description="Update an existing user-defined provider configuration.")
    async def update_provider(
        self,
        info: Info,
        provider_id: strawberry.ID,
        name: str,
        agents: AgentsConfigInput,
    ) -> ProviderConfig:
        row = await _call(
            info, "providers", "update_provider", _user_id(info), int(provider_id), name, agents
        )
        if row is None:
            return ProviderConfig.from_pydantic(type("M", (), {})())
        result = ProviderConfig.from_pydantic(row)
        await _publish(info, "providerUpdated", result)
        return result

    @strawberry.mutation(description="Delete a user-defined provider configuration.")
    async def delete_provider(self, info: Info, provider_id: strawberry.ID) -> ResultType:
        row = await _call(
            info, "providers", "delete_provider", _user_id(info), int(provider_id)
        )
        if row is not None:
            await _publish(
                info,
                "providerDeleted",
                ProviderConfig.from_pydantic(row) if not isinstance(row, ProviderConfig) else row,
            )
            return ResultType.SUCCESS
        return ResultType.ERROR

    # ── Prompt management ─────────────────────────────────────────────────

    @strawberry.mutation(description="Validate a user-supplied prompt template without saving.")
    async def validate_prompt(
        self, info: Info, type: PromptType, template: str  # noqa: A002
    ) -> PromptValidationResult:
        row = await _call(info, "prompts", "validate_prompt", type.value, template)
        if row is None:
            return PromptValidationResult(result=ResultType.SUCCESS)
        return PromptValidationResult.from_pydantic(row)

    @strawberry.mutation(description="Create a new user-customized prompt template.")
    async def create_prompt(
        self, info: Info, type: PromptType, template: str  # noqa: A002
    ) -> UserPrompt:
        row = await _call(
            info, "prompts", "create_prompt", _user_id(info), type.value, template
        )
        if row is None:
            return UserPrompt(
                id=strawberry.ID("0"),
                type=type,
                template=template,
                created_at=__import__("datetime").datetime.utcnow(),
                updated_at=__import__("datetime").datetime.utcnow(),
            )
        return UserPrompt.from_pydantic(row)

    @strawberry.mutation(description="Update an existing user-customized prompt template.")
    async def update_prompt(
        self, info: Info, prompt_id: strawberry.ID, template: str
    ) -> UserPrompt:
        row = await _call(
            info, "prompts", "update_prompt", _user_id(info), int(prompt_id), template
        )
        if row is None:
            return UserPrompt(
                id=prompt_id,
                type=PromptType.ASSISTANT,
                template=template,
                created_at=__import__("datetime").datetime.utcnow(),
                updated_at=__import__("datetime").datetime.utcnow(),
            )
        return UserPrompt.from_pydantic(row)

    @strawberry.mutation(description="Delete a user-customized prompt template.")
    async def delete_prompt(self, info: Info, prompt_id: strawberry.ID) -> ResultType:
        ok = await _call(info, "prompts", "delete_prompt", _user_id(info), int(prompt_id))
        return ResultType.SUCCESS if ok else ResultType.ERROR

    # ── API token CRUD ────────────────────────────────────────────────────

    @strawberry.mutation(
        description="Issue a new API token; plaintext JWT returned only here.",
        name="createAPIToken",
    )
    async def create_api_token(
        self, info: Info, input: CreateAPITokenInput  # noqa: A002
    ) -> APITokenWithSecret:
        row = await _call(
            info, "tokens", "create_api_token", _user_id(info), input
        )
        if row is None:
            return APITokenWithSecret(
                id=strawberry.ID("0"),
                token_id="",
                user_id=strawberry.ID("0"),
                role_id=strawberry.ID("0"),
                name=input.name,
                ttl=input.ttl,
                status=__import__(
                    "elengenix.graphql.schema", fromlist=["TokenStatus"]
                ).TokenStatus.ACTIVE,
                created_at=__import__("datetime").datetime.utcnow(),
                updated_at=__import__("datetime").datetime.utcnow(),
                token="",
            )
        result = APITokenWithSecret.from_pydantic(row)
        await _publish(info, "apiTokenCreated", APIToken.from_pydantic(row))
        return result

    @strawberry.mutation(
        description="Update an API token's name/status (does not reissue JWT).",
        name="updateAPIToken",
    )
    async def update_api_token(
        self,
        info: Info,
        token_id: str,  # noqa: A002 — actually this is the SDL arg name
        input: UpdateAPITokenInput,  # noqa: A002
    ) -> APIToken:
        row = await _call(
            info, "tokens", "update_api_token", _user_id(info), token_id, input
        )
        if row is None:
            return APIToken(
                id=strawberry.ID("0"),
                token_id=token_id,
                user_id=strawberry.ID("0"),
                role_id=strawberry.ID("0"),
                name=input.name,
                ttl=0,
                status=input.status or __import__(
                    "elengenix.graphql.schema", fromlist=["TokenStatus"]
                ).TokenStatus.ACTIVE,
                created_at=__import__("datetime").datetime.utcnow(),
                updated_at=__import__("datetime").datetime.utcnow(),
            )
        result = APIToken.from_pydantic(row)
        await _publish(info, "apiTokenUpdated", result)
        return result

    @strawberry.mutation(
        description="Revoke an API token (soft-delete).",
        name="deleteAPIToken",
    )
    async def delete_api_token(
        self, info: Info, token_id: str  # noqa: A002 — SDL arg name
    ) -> bool:
        row = await _call(info, "tokens", "delete_api_token", _user_id(info), token_id)
        if row is not None:
            await _publish(
                info,
                "apiTokenDeleted",
                APIToken.from_pydantic(row) if not isinstance(row, APIToken) else row,
            )
            return True
        return False

    # ── Favorites ─────────────────────────────────────────────────────────

    @strawberry.mutation(description="Mark a flow as a favorite for the current user.")
    async def add_favorite_flow(self, info: Info, flow_id: strawberry.ID) -> ResultType:
        ok = await _call(info, "users", "add_favorite_flow", _user_id(info), int(flow_id))
        if ok:
            await _publish(
                info,
                "settingsUserUpdated",
                __import__(
                    "elengenix.graphql.types", fromlist=["UserPreferences"]
                ).UserPreferences(id=strawberry.ID("0"), favorite_flows=[flow_id]),
            )
            return ResultType.SUCCESS
        return ResultType.ERROR

    @strawberry.mutation(description="Remove a flow from the current user's favorites.")
    async def delete_favorite_flow(self, info: Info, flow_id: strawberry.ID) -> ResultType:
        ok = await _call(info, "users", "delete_favorite_flow", _user_id(info), int(flow_id))
        if ok:
            await _publish(
                info,
                "settingsUserUpdated",
                __import__(
                    "elengenix.graphql.types", fromlist=["UserPreferences"]
                ).UserPreferences(id=strawberry.ID("0"), favorite_flows=[]),
            )
            return ResultType.SUCCESS
        return ResultType.ERROR

    # ── Flow templates ────────────────────────────────────────────────────

    @strawberry.mutation(description="Create a new flow template.")
    async def create_flow_template(
        self, info: Info, input: CreateFlowTemplateInput  # noqa: A002
    ) -> FlowTemplate:
        row = await _call(info, "templates", "create_flow_template", _user_id(info), input)
        if row is None:
            return FlowTemplate(
                id=strawberry.ID("0"),
                user_id=strawberry.ID("0"),
                title=input.title,
                text=input.text,
                created_at=__import__("datetime").datetime.utcnow(),
                updated_at=__import__("datetime").datetime.utcnow(),
            )
        result = FlowTemplate.from_pydantic(row)
        await _publish(info, "flowTemplateCreated", result)
        return result

    @strawberry.mutation(description="Update an existing flow template.")
    async def update_flow_template(
        self,
        info: Info,
        template_id: strawberry.ID,
        input: UpdateFlowTemplateInput,  # noqa: A002
    ) -> FlowTemplate:
        row = await _call(
            info, "templates", "update_flow_template", _user_id(info), int(template_id), input
        )
        if row is None:
            return FlowTemplate(
                id=template_id,
                user_id=strawberry.ID("0"),
                title=input.title,
                text=input.text,
                created_at=__import__("datetime").datetime.utcnow(),
                updated_at=__import__("datetime").datetime.utcnow(),
            )
        result = FlowTemplate.from_pydantic(row)
        await _publish(info, "flowTemplateUpdated", result)
        return result

    @strawberry.mutation(description="Delete a flow template.")
    async def delete_flow_template(
        self, info: Info, template_id: strawberry.ID
    ) -> ResultType:
        row = await _call(
            info, "templates", "delete_flow_template", _user_id(info), int(template_id)
        )
        if row is not None:
            await _publish(
                info,
                "flowTemplateDeleted",
                FlowTemplate.from_pydantic(row) if not isinstance(row, FlowTemplate) else row,
            )
            return ResultType.SUCCESS
        return ResultType.ERROR

    # ── Knowledge documents ───────────────────────────────────────────────

    @strawberry.mutation(description="Create a new knowledge document manually.")
    async def create_knowledge_document(
        self, info: Info, input: CreateKnowledgeDocumentInput  # noqa: A002
    ) -> KnowledgeDocument:
        row = await _call(info, "knowledge", "create_document", _user_id(info), input)
        if row is None:
            return KnowledgeDocument(
                id="",
                doc_type=input.doc_type,
                content=input.content,
                question=input.question,
                description=input.description,
                user_id=strawberry.ID("0"),
                guide_type=input.guide_type,
                answer_type=input.answer_type,
                code_lang=input.code_lang,
                part_size=len(input.content),
                total_size=len(input.content),
                manual=True,
            )
        result = KnowledgeDocument.from_pydantic(row)
        await _publish(info, "knowledgeDocumentCreated", result)
        return result

    @strawberry.mutation(description="Update an existing knowledge document; re-embeds if needed.")
    async def update_knowledge_document(
        self,
        info: Info,
        id: str,  # noqa: A002 — SDL arg name
        input: UpdateKnowledgeDocumentInput,  # noqa: A002
    ) -> KnowledgeDocument:
        row = await _call(info, "knowledge", "update_document", _user_id(info), id, input)
        if row is None:
            return KnowledgeDocument(
                id=id,
                doc_type=input.doc_type or __import__(
                    "elengenix.graphql.schema", fromlist=["KnowledgeDocType"]
                ).KnowledgeDocType.ANSWER,
                content=input.content,
                question=input.question or "",
                description=input.description,
                user_id=strawberry.ID("0"),
                guide_type=input.guide_type,
                answer_type=input.answer_type,
                code_lang=input.code_lang,
                part_size=len(input.content),
                total_size=len(input.content),
                manual=True,
            )
        result = KnowledgeDocument.from_pydantic(row)
        await _publish(info, "knowledgeDocumentUpdated", result)
        return result

    @strawberry.mutation(description="Delete a knowledge document by UUID.")
    async def delete_knowledge_document(
        self, info: Info, id: str  # noqa: A002 — SDL arg name
    ) -> ResultType:
        row = await _call(info, "knowledge", "delete_document", _user_id(info), id)
        if row is not None:
            await _publish(
                info,
                "knowledgeDocumentDeleted",
                KnowledgeDocument.from_pydantic(row)
                if not isinstance(row, KnowledgeDocument)
                else row,
            )
            return ResultType.SUCCESS
        return ResultType.ERROR

    # ── Anonymization ─────────────────────────────────────────────────────

    @strawberry.mutation(description="Anonymize sensitive tokens in a free-form text blob.")
    async def anonymize_text(self, info: Info, text: str) -> str:
        result = await _call(info, "anonymizer", "anonymize_text", text)
        if result is None:
            return text
        return str(result)


__all__ = [
    "Mutation",
]
