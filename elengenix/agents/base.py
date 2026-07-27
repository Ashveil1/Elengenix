"""elengenix/agents/base.py — Base agent infrastructure for the PentAGI port.

Provides the foundational primitives used by every agent in the Elengenix
multi-agent system:

* ``AgentType`` — string-valued enum of all 15 agent types (mirrors PentAGI's
  ``database.MsgchainType`` so persisted msg-chains stay wire-compatible).
* ``AgentContext`` — dataclass carrying ``parent_agent_type`` /
  ``current_agent_type``; propagated through asyncio tasks via
  ``contextvars.ContextVar`` (Python equivalent of Go's ``context.Value``).
* ``perform_agent_chain`` — the universal LLM -> tool -> reflector loop ported
  from PentAGI's ``flowProvider.performAgentChain``
  (``backend/pkg/providers/performer.go``).
* Protocol interfaces (``LLMClient``, ``ToolExecutor``, ``Reflector``,
  ``Summarizer``) so concrete implementations can be wired in by other
  subagents without hard dependencies on langchain / pydantic-ai / etc.
* ``PerformResult`` enum (DONE / WAITING / ERROR) mirroring PentAGI's
  ``PerformResult``.
* Iteration-cap constants ``MAX_GENERAL_ITERATIONS=100`` and
  ``MAX_LIMITED_ITERATIONS=20`` plus the helpers ``is_general_agent`` /
  ``is_limited_agent``.

The module is intentionally dependency-light: only stdlib ``asyncio``,
``contextvars``, ``dataclasses``, ``enum``, ``logging``, ``typing`` and
``uuid`` are imported at module load. Heavy LLM/observability SDKs are
expected to be supplied by callers via the Protocol interfaces.
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from contextvars import ContextVar, Token
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, ClassVar, Protocol, runtime_checkable

logger = logging.getLogger("elengenix.agents.base")

# ---------------------------------------------------------------------------
# Iteration caps — ported verbatim from PentAGI's performer.go:
#   maxGeneralAgentChainIterations = 100
#   maxLimitedAgentChainIterations  = 20
#   maxAgentShutdownIterations      = 3   (graceful-termination window)
#   maxReflectorCallsPerChain       = 3
# ---------------------------------------------------------------------------
MAX_GENERAL_ITERATIONS: int = 100
MAX_LIMITED_ITERATIONS: int = 20
MAX_AGENT_SHUTDOWN_ITERATIONS: int = 3
MAX_REFLECTOR_CALLS_PER_CHAIN: int = 3


class AgentType(str, Enum):
    """All 15 agent types in the Elengenix multi-agent system.

    String values mirror PentAGI's ``database.MsgchainType`` constants so any
    persisted msg-chain JSON remains wire-compatible across the Go and Python
    implementations.
    """

    PRIMARY = "primary_agent"
    SEARCHER = "searcher"
    PENTESTER = "pentester"
    CODER = "coder"
    INSTALLER = "installer"
    MEMORIST = "memorist"
    ADVISER = "adviser"
    ENRICHER = "enricher"
    GENERATOR = "generator"
    REFINER = "refiner"
    REPORTER = "reporter"
    REFLECTOR = "reflector"
    SUMMARIZER = "summarizer"
    TOOLCALL_FIXER = "tool_call_fixer"
    ASSISTANT = "assistant"


class PerformResult(str, Enum):
    """Outcome of an agent-chain execution.

    Mirrors PentAGI's ``PerformResult`` enum (``PerformResultError``,
    ``PerformResultWaiting``, ``PerformResultDone``). String values are used
    so the enum serialises cleanly to JSON / DB columns.
    """

    ERROR = "error"
    WAITING = "waiting"
    DONE = "done"


# ---------------------------------------------------------------------------
# Agent-type classification — ported from PentAGI's ``performAgentChain``
# switch that selects ``maxGeneralAgentChainIterations`` vs
# ``maxLimitedAgentChainIterations`` based on ``optAgentType``.
# ---------------------------------------------------------------------------
_GENERAL_AGENTS: frozenset[AgentType] = frozenset(
    {
        AgentType.PRIMARY,
        AgentType.PENTESTER,
        AgentType.CODER,
        AgentType.INSTALLER,
        AgentType.ASSISTANT,
    }
)

_LIMITED_AGENTS: frozenset[AgentType] = frozenset(
    {
        AgentType.ADVISER,
        AgentType.SEARCHER,
        AgentType.MEMORIST,
        AgentType.GENERATOR,
        AgentType.REFINER,
        AgentType.REPORTER,
        AgentType.ENRICHER,
        AgentType.REFLECTOR,
        AgentType.TOOLCALL_FIXER,
        AgentType.SUMMARIZER,
    }
)


def is_general_agent(agent_type: AgentType) -> bool:
    """Return True if ``agent_type`` is a general agent (100-iteration cap).

    General agents: PRIMARY, PENTESTER, CODER, INSTALLER, ASSISTANT.
    """
    return agent_type in _GENERAL_AGENTS


def is_limited_agent(agent_type: AgentType) -> bool:
    """Return True if ``agent_type`` is a limited agent (20-iteration cap).

    Limited agents: ADVISER, SEARCHER, MEMORIST, GENERATOR, REFINER,
    REPORTER, ENRICHER, REFLECTOR, TOOLCALL_FIXER, SUMMARIZER.
    """
    return agent_type in _LIMITED_AGENTS


def default_max_iterations(agent_type: AgentType) -> int:
    """Resolve the default iteration cap for ``agent_type``.

    Mirrors PentAGI's switch on ``optAgentType`` inside ``performAgentChain``:
    general agents get ``MAX_GENERAL_ITERATIONS`` (100); all other agents get
    ``MAX_LIMITED_ITERATIONS`` (20).
    """
    if is_general_agent(agent_type):
        return MAX_GENERAL_ITERATIONS
    return MAX_LIMITED_ITERATIONS


# ---------------------------------------------------------------------------
# Message / tool-call data containers.
# ---------------------------------------------------------------------------


@dataclass
class ToolCall:
    """A single LLM-emitted tool call.

    Mirrors the shape used by OpenAI's function-calling API and PentAGI's
    ``llms.ToolCall``. ``arguments`` is the raw JSON-encoded argument string
    (preserved verbatim so the tool-call fixer can repair malformed payloads).
    """

    id: str = field(default_factory=lambda: f"call_{uuid.uuid4().hex[:24]}")
    name: str = ""
    arguments: str = "{}"


@dataclass
class Message:
    """A single chat message in the agent chain.

    Mirrors PentAGI's ``llms.MessageContent`` with a flat role/content layout
    close to OpenAI's chat-completions schema so it can be serialised to JSON
    and round-tripped through any LLM provider.

    Attributes:
        role: One of ``"system"``, ``"user"``, ``"assistant"``, ``"tool"``.
        content: Textual content of the message (empty for pure tool-call
            assistant messages).
        tool_calls: Tool calls emitted by the assistant (only populated when
            ``role == "assistant"``).
        tool_call_id: ID of the tool call this message responds to (only
            populated when ``role == "tool"``).
        name: Tool name when ``role == "tool"``.
        reasoning: Provider-exposed thinking / reasoning content (kept
            separate from ``content`` so it can be redacted or logged
            independently).
        metadata: Free-form per-message metadata (usage info, langfuse trace
            IDs, etc.).
    """

    role: str
    content: str = ""
    tool_calls: list[ToolCall] = field(default_factory=list)
    tool_call_id: str | None = None
    name: str | None = None
    reasoning: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class LLMResponse:
    """Structured LLM response (mirrors PentAGI's ``callResult``).

    A response may carry ``content`` (text), ``tool_calls`` (structured
    actions), or both. ``reasoning`` holds provider-exposed thinking tokens.
    ``info`` carries provider-specific metadata (token usage, stop reason).
    """

    content: str = ""
    tool_calls: list[ToolCall] = field(default_factory=list)
    reasoning: str | None = None
    info: dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Protocol interfaces — concrete implementations are wired in by callers.
# ---------------------------------------------------------------------------


@runtime_checkable
class LLMClient(Protocol):
    """LLM client protocol.

    Implementations wrap a specific provider (OpenAI, Anthropic, Ollama,
    LiteLLM, langchain, pydantic-ai, …) and expose a single async ``call``
    method that returns the model's response for a chain.
    """

    async def call(
        self,
        chain: list[Message],
        tools: list[dict[str, Any]] | None = None,
        agent_type: AgentType | None = None,
    ) -> LLMResponse:
        """Call the LLM with ``chain`` and optional ``tools`` schema list."""
        ...


@runtime_checkable
class ToolExecutor(Protocol):
    """Tool dispatcher protocol (mirrors PentAGI's ``tools.ContextToolsExecutor``).

    Implementations are responsible for:
      * Routing ``execute(name, arguments)`` to the registered handler.
      * Declaring which tool names are *barriers* (terminate the chain).
      * Exposing JSON-schema tool definitions for the LLM via ``get_tools``.
    """

    async def execute(
        self,
        name: str,
        arguments: str,
        context: "AgentContext | None" = None,
    ) -> str:
        """Execute the named tool with JSON-encoded ``arguments``."""
        ...

    def is_barrier(self, name: str) -> bool:
        """Return True if ``name`` is a barrier tool (e.g. ``done``/``ask``)."""
        ...

    def get_tools(self) -> list[dict[str, Any]]:
        """Return JSON-schema tool definitions exposed to the LLM."""
        ...


@runtime_checkable
class Reflector(Protocol):
    """Reflector protocol — repairs responses that contain no tool calls.

    Ports PentAGI's ``flowProvider.performReflector``: when the LLM returns a
    content-only response (no tool calls), the reflector is invoked to nudge
    the model back into structured tool use.
    """

    async def reflect(
        self,
        agent_type: AgentType,
        chain: list[Message],
        content: str,
        execution_context: str = "",
    ) -> LLMResponse:
        """Inspect ``content`` and return a repaired ``LLMResponse``."""
        ...


@runtime_checkable
class Summarizer(Protocol):
    """Summarizer protocol — condenses long chains to fit context windows.

    Ports PentAGI's ``csum.Summarizer.SummarizeChain``: when the running chain
    grows too large, the summarizer replaces historical messages with a
    condensed summary to keep the chain within the model's context window.
    """

    async def summarize(
        self,
        chain: list[Message],
    ) -> list[Message]:
        """Return a (possibly shorter) replacement for ``chain``."""
        ...


# Type alias for the barrier callback — receives ``(tool_name, tool_args_json)``
# and returns the ``PerformResult`` the chain should terminate with. Used by
# ``perform_agent_chain`` so callers (e.g. ``PrimaryAgent``) can translate
# barrier hits into the correct result without hardcoding tool names in the
# universal loop.
BarrierCallback = Callable[[str, str], PerformResult]


# ---------------------------------------------------------------------------
# AgentContext — contextvars-based parent/current agent-type propagation.
# ---------------------------------------------------------------------------


@dataclass
class AgentContext:
    """Parent / current agent-type propagation for asyncio tasks.

    Ports PentAGI's ``tools/context.go`` (which uses Go's ``context.Value``)
    to Python ``contextvars.ContextVar``. The contextvar propagates
    automatically to asyncio tasks created after ``AgentContext.put()`` is
    called, mirroring Go's context propagation through goroutines.

    The dataclass carries two fields:

    * ``parent_agent_type`` — the agent that delegated to the current one
      (equal to ``current_agent_type`` on the first ``put``).
    * ``current_agent_type`` — the agent currently executing.
    """

    parent_agent_type: AgentType | None = None
    current_agent_type: AgentType | None = None

    # ClassVar so @dataclass skips it — the ContextVar is a single shared
    # instance per process, defaulting to None (no context set).
    _ctx_var: ClassVar[ContextVar["AgentContext | None"]] = ContextVar(
        "elengenix_agent_context",
        default=None,
    )

    @classmethod
    def put(cls, agent_type: AgentType) -> Token["AgentContext | None"]:
        """Set the contextvar with parent propagation.

        Mirrors PentAGI's ``PutAgentContext``: on the first call both
        ``parent_agent_type`` and ``current_agent_type`` are set to
        ``agent_type``; on subsequent calls the previous ``current`` becomes
        the new ``parent`` and ``agent_type`` becomes the new ``current``.

        Returns the ``contextvars.Token`` so callers can restore the previous
        context via ``AgentContext.reset(token)`` in a ``finally`` block.
        """
        prev = cls._ctx_var.get()
        if prev is None:
            new_ctx = cls(
                parent_agent_type=agent_type,
                current_agent_type=agent_type,
            )
        else:
            new_ctx = cls(
                parent_agent_type=prev.current_agent_type,
                current_agent_type=agent_type,
            )
        return cls._ctx_var.set(new_ctx)

    @classmethod
    def reset(cls, token: Token["AgentContext | None"]) -> None:
        """Reset the contextvar to its previous value (use with ``put``)."""
        cls._ctx_var.reset(token)

    @classmethod
    def get(cls) -> dict[str, str] | None:
        """Return the current context as a dict, or ``None`` if unset.

        The dict shape (``{"parent_agent_type": ..., "current_agent_type": ...}``)
        matches the JSON serialisation of PentAGI's ``agentContext`` struct
        so logs / DB rows / observability spans stay cross-compatible.
        """
        ctx = cls._ctx_var.get()
        if ctx is None:
            return None
        return {
            "parent_agent_type": (ctx.parent_agent_type.value if ctx.parent_agent_type else ""),
            "current_agent_type": (ctx.current_agent_type.value if ctx.current_agent_type else ""),
        }

    @classmethod
    def current(cls) -> "AgentContext | None":
        """Return the raw ``AgentContext`` dataclass, or ``None`` if unset."""
        return cls._ctx_var.get()


# ---------------------------------------------------------------------------
# perform_agent_chain — the universal loop.
# ---------------------------------------------------------------------------


async def perform_agent_chain(
    *,
    agent_type: AgentType,
    chain: list[Message],
    llm_client: LLMClient,
    executor: ToolExecutor,
    reflector: Reflector | None = None,
    summarizer: Summarizer | None = None,
    max_iterations: int | None = None,
    execution_context: str = "",
    on_barrier: BarrierCallback | None = None,
) -> PerformResult:
    """Universal agent-chain loop ported from PentAGI's ``performAgentChain``.

    Flow per iteration:

      1. If ``iteration >= max_iterations`` -> return ``PerformResult.ERROR``.
      2. If ``iteration >= max_iterations - MAX_AGENT_SHUTDOWN_ITERATIONS``,
         inject a graceful-termination message (skip the LLM call) so the
         Reflector can drive the chain to a clean close (mirrors PentAGI's
         ``maxAgentShutdownIterations`` branch).
      3. Otherwise call ``llm_client.call(chain, tools=executor.get_tools())``.
      4. If the response has no tool calls:
           - If ``reflector`` is configured, invoke ``reflector.reflect(...)``
             to repair. If the repaired response still has no tool calls,
             return ``PerformResult.ERROR``.
           - If ``reflector`` is ``None``, return ``PerformResult.ERROR``.
      5. Append the assistant ``Message`` (content + tool_calls) to ``chain``.
      6. For each tool call:
           - ``executor.execute(name, arguments)`` -> response string.
           - Append a tool ``Message`` with the response.
           - If ``executor.is_barrier(name)``: invoke ``on_barrier`` (if any)
             and return its ``PerformResult`` (default ``DONE``).
      7. If ``summarizer`` is configured, ``summarizer.summarize(chain)`` ->
         replace ``chain`` contents in place. Errors are swallowed (mirrors
         PentAGI's "log and continue" behaviour).

    Args:
        agent_type: Which agent is running (controls the default iteration
            cap via :func:`default_max_iterations`).
        chain: Mutable list of :class:`Message` objects; appended to in
            place so callers can inspect the full chain after the loop
            returns.
        llm_client: LLM client implementing the :class:`LLMClient` protocol.
        executor: Tool dispatcher implementing the :class:`ToolExecutor`
            protocol.
        reflector: Optional :class:`Reflector` for no-tool-call repair. If
            ``None``, any no-tool-call response terminates the chain with
            ``PerformResult.ERROR``.
        summarizer: Optional :class:`Summarizer` for context-window
            management. Invoked once per iteration after tool dispatch.
        max_iterations: Override the default iteration cap. If ``None``,
            resolved via :func:`default_max_iterations`.
        execution_context: XML execution-context string passed to the
            reflector (mirrors PentAGI's ``executionContext``).
        on_barrier: Callback invoked when a barrier tool is hit; receives
            ``(tool_name, tool_args_json)`` and returns the
            ``PerformResult`` the chain should terminate with. If ``None``,
            barrier hits default to ``PerformResult.DONE``.

    Returns:
        * ``PerformResult.DONE`` on a successful barrier hit (or whatever
          ``on_barrier`` returns for the barrier tool).
        * ``PerformResult.ERROR`` on iteration-limit exhaustion, unrecoverable
          LLM / tool / reflector errors, or a no-tool-call response when no
          reflector is configured.

    The ``chain`` list is mutated in place; callers can read the full
    conversation history from it after the function returns.
    """
    log = logger.getChild("perform_agent_chain")

    if max_iterations is None:
        max_iterations = default_max_iterations(agent_type)

    # Ensure max_iterations is at least 2x the shutdown window so the
    # graceful-termination path has room to work (mirrors PentAGI's
    # ``max(fp.maxGACallsLimit, maxAgentShutdownIterations*2)`` clamp).
    if max_iterations < MAX_AGENT_SHUTDOWN_ITERATIONS * 2:
        max_iterations = max(max_iterations, MAX_AGENT_SHUTDOWN_ITERATIONS * 2)

    # Propagate the agent context to any asyncio tasks spawned by specialists
    # / reflector / summarizer (mirrors PentAGI's ``ctx = tools.PutAgentContext``).
    token = AgentContext.put(agent_type)

    try:
        iteration = 0
        while True:
            if iteration >= max_iterations:
                log.error(
                    "agent_chain_exhausted agent=%s iterations=%d max=%d",
                    agent_type.value,
                    iteration,
                    max_iterations,
                )
                return PerformResult.ERROR

            # Graceful-termination window: skip the LLM call and synthesize a
            # content-only message so the Reflector can drive the chain to a
            # close (mirrors PentAGI's ``maxAgentShutdownIterations`` branch).
            if iteration >= max_iterations - MAX_AGENT_SHUTDOWN_ITERATIONS:
                log.warning(
                    "agent_chain_near_limit agent=%s iteration=%d max=%d -- "
                    "injecting graceful-termination message",
                    agent_type.value,
                    iteration,
                    max_iterations,
                )
                llm_resp = LLMResponse(
                    content=(
                        f"I can't continue this multi-turn chain because I'm "
                        f"too close to the AI agent iteration limit "
                        f"({max_iterations})."
                    ),
                    tool_calls=[],
                )
            else:
                try:
                    llm_resp = await llm_client.call(
                        chain=chain,
                        tools=executor.get_tools(),
                        agent_type=agent_type,
                    )
                except asyncio.CancelledError:
                    raise
                except Exception as exc:  # noqa: BLE001
                    log.error(
                        "llm_call_failed agent=%s err=%s",
                        agent_type.value,
                        exc,
                    )
                    return PerformResult.ERROR

            # No tool calls -> invoke Reflector to repair (unless this is the
            # Assistant agent, which is allowed to return content directly —
            # but we let the caller handle that special case by returning
            # ERROR here; Assistant flow is handled in primary_agent.py).
            if not llm_resp.tool_calls:
                if reflector is None:
                    log.error(
                        "no_tool_calls_no_reflector agent=%s content=%r",
                        agent_type.value,
                        (llm_resp.content or "")[:500],
                    )
                    return PerformResult.ERROR

                # Build a temporary chain that includes the no-tool-call AI
                # message so the Reflector sees what the LLM actually
                # produced (mirrors PentAGI's ``append(chain, reflectorMsg)``).
                reflector_chain = chain + [
                    Message(
                        role="assistant",
                        content=llm_resp.content,
                        reasoning=llm_resp.reasoning,
                    )
                ]

                try:
                    repaired = await reflector.reflect(
                        agent_type=agent_type,
                        chain=reflector_chain,
                        content=llm_resp.content,
                        execution_context=execution_context,
                    )
                except asyncio.CancelledError:
                    raise
                except Exception as exc:  # noqa: BLE001
                    log.error(
                        "reflector_failed agent=%s err=%s",
                        agent_type.value,
                        exc,
                    )
                    return PerformResult.ERROR

                if not repaired.tool_calls:
                    log.error(
                        "reflector_no_tool_calls agent=%s content=%r",
                        agent_type.value,
                        (repaired.content or "")[:500],
                    )
                    return PerformResult.ERROR

                # Use the repaired response going forward; the caller's
                # ``chain`` does NOT get the no-tool-call placeholder appended
                # (matches PentAGI's behaviour where ``append(chain,
                # reflectorMsg)`` is a temporary copy).
                llm_resp = repaired

            # Append the assistant Message (content + tool_calls) to chain.
            chain.append(
                Message(
                    role="assistant",
                    content=llm_resp.content,
                    tool_calls=list(llm_resp.tool_calls),
                    reasoning=llm_resp.reasoning,
                )
            )

            # Dispatch each tool call sequentially (mirrors PentAGI's loop).
            want_to_stop = False
            result = PerformResult.ERROR

            for tool_call in llm_resp.tool_calls:
                try:
                    response = await executor.execute(
                        name=tool_call.name,
                        arguments=tool_call.arguments,
                        context=AgentContext.current(),
                    )
                except asyncio.CancelledError:
                    raise
                except Exception as exc:  # noqa: BLE001
                    log.error(
                        "tool_exec_failed agent=%s tool=%s err=%s",
                        agent_type.value,
                        tool_call.name,
                        exc,
                    )
                    return PerformResult.ERROR

                chain.append(
                    Message(
                        role="tool",
                        content=response,
                        tool_call_id=tool_call.id,
                        name=tool_call.name,
                    )
                )

                if executor.is_barrier(tool_call.name):
                    want_to_stop = True
                    if on_barrier is not None:
                        try:
                            result = on_barrier(tool_call.name, tool_call.arguments)
                        except Exception as exc:  # noqa: BLE001
                            log.error(
                                "barrier_callback_failed agent=%s tool=%s err=%s",
                                agent_type.value,
                                tool_call.name,
                                exc,
                            )
                            result = PerformResult.DONE
                    else:
                        result = PerformResult.DONE
                    # Break out of the tool-call loop; we still want to
                    # return immediately after the loop body.
                    break

            if want_to_stop:
                log.info(
                    "agent_chain_done agent=%s iterations=%d result=%s",
                    agent_type.value,
                    iteration + 1,
                    result.value,
                )
                return result

            # Summarize the chain if a summarizer is configured. Errors are
            # swallowed (mirrors PentAGI's "log and continue" behaviour).
            if summarizer is not None:
                try:
                    summarized = await summarizer.summarize(chain)
                    if summarized is not None:
                        # Replace contents in place so callers' references
                        # remain valid.
                        chain[:] = summarized
                except asyncio.CancelledError:
                    raise
                except Exception as exc:  # noqa: BLE001
                    log.warning("summarizer_failed_swallowed err=%s", exc)

            iteration += 1
    finally:
        AgentContext.reset(token)


__all__ = [
    "AgentType",
    "PerformResult",
    "AgentContext",
    "ToolCall",
    "Message",
    "LLMResponse",
    "LLMClient",
    "ToolExecutor",
    "Reflector",
    "Summarizer",
    "BarrierCallback",
    "MAX_GENERAL_ITERATIONS",
    "MAX_LIMITED_ITERATIONS",
    "MAX_AGENT_SHUTDOWN_ITERATIONS",
    "MAX_REFLECTOR_CALLS_PER_CHAIN",
    "is_general_agent",
    "is_limited_agent",
    "default_max_iterations",
    "perform_agent_chain",
]
