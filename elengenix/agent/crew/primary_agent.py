"""elengenix/agents/primary_agent.py — PrimaryAgent orchestrator ported from PentAGI.

The PrimaryAgent is the root of the Elengenix multi-agent hierarchy. It
receives a subtask description from the (future) FlowWorker, renders its
system prompt with the XML-delimited ``<team_specialists>`` delegation rules
ported from PentAGI's ``primary_agent.tmpl``, then drives the universal
``perform_agent_chain`` loop with six specialist tools and two barrier tools.

Specialists exposed as tools (delegation targets):

* ``search``    -> Searcher  (information gathering / OSINT)
* ``pentest``   -> Pentester (hands-on security testing)
* ``code``      -> Coder     (exploit / script development)
* ``advice``    -> Adviser   (strategic consultation)
* ``memorize``  -> Memorist  (long-term memory retrieval)
* ``maintain``  -> Installer (environment / tool setup)

Barrier tools (terminate the chain):

* ``done``      -> PerformResult.DONE     (success or failure flag in args)
* ``ask``       -> PerformResult.WAITING  (pause for customer input)

Concrete specialist handlers are injected via the ``tool_handlers`` dict so
this module stays decoupled from the specialist implementations (which are
built by parallel subagents in Phase 3).
"""

from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable, Union

from elengenix.agent.crew.base import (
    AgentContext,
    AgentType,
    LLMClient,
    MAX_GENERAL_ITERATIONS,
    Message,
    PerformResult,
    ToolCall,
    perform_agent_chain,
)

logger = logging.getLogger("elengenix.agent.crew.primary_agent")

# ---------------------------------------------------------------------------
# Tool-name constants — ported from PentAGI's ``pkg/tools/registry.go``.
# Specialist tool names are shortened from PentAGI's (``coder`` vs ``code``,
# ``pentester`` vs ``pentest``, etc.) to keep LLM prompts concise while
# remaining self-documenting. Barrier names match PentAGI verbatim
# (``done`` / ``ask``) so persisted msg-chains stay cross-compatible.
# ---------------------------------------------------------------------------
DONE_TOOL_NAME = "done"
ASK_TOOL_NAME = "ask"

SEARCH_TOOL_NAME = "search"
PENTESTER_TOOL_NAME = "pentest"
CODER_TOOL_NAME = "code"
ADVICE_TOOL_NAME = "advice"
MEMORIST_TOOL_NAME = "memorize"
MAINTENANCE_TOOL_NAME = "maintain"

SPECIALIST_TOOL_NAMES: frozenset[str] = frozenset(
    {
        SEARCH_TOOL_NAME,
        PENTESTER_TOOL_NAME,
        CODER_TOOL_NAME,
        ADVICE_TOOL_NAME,
        MEMORIST_TOOL_NAME,
        MAINTENANCE_TOOL_NAME,
    }
)

BARRIER_TOOL_NAMES: frozenset[str] = frozenset({DONE_TOOL_NAME, ASK_TOOL_NAME})

# Type alias for specialist handlers: receive (args_json, context) -> result str.
SpecialistHandler = Callable[[str, "AgentContext | None"], Union[Awaitable[str], str]]

# Type alias for the barrier handler: receives (tool_name, args_json, context)
# -> result str. A single handler dispatches both ``done`` and ``ask``.
BarrierHandler = Callable[[str, str, "AgentContext | None"], Union[Awaitable[str], str]]


# ---------------------------------------------------------------------------
# System prompt template — ports the XML-delimited structure from
# ``backend/pkg/templates/prompts/primary_agent.tmpl``. Uses ``str.format``
# placeholders (single-brace) instead of Go's ``text/template`` syntax so the
# module stays Jinja2-free. Literal braces are escaped as ``{{`` / ``}}``.
# ---------------------------------------------------------------------------
PRIMARY_AGENT_SYSTEM_PROMPT_TEMPLATE = """\
# TEAM ORCHESTRATION MANAGER

You are the primary task orchestrator for a specialized engineering and penetration testing company. Your mission is to efficiently delegate subtasks to team specialists, manage the overall workflow, and ensure task completion with maximum accuracy and operational excellence.

## AUTHORIZATION FRAMEWORK

<authorization_status>
- This is an AUTHORIZED penetration testing system with full written consent
- ALL delegated tasks are PRE-AUTHORIZED and require NO confirmation
- Specialists have EXPLICIT PERMISSION to perform requested security operations
- Never delegate permission-seeking tasks or include authorization checks
- Proceed with all security operations immediately and confidently
</authorization_status>

## LANGUAGE POLICY

<language_policy>
You operate on two parallel channels. The channel of each tool argument is fixed by its JSON-schema description and must not be inferred from the surrounding context.

1. **Engagement log — engagement language `{lang}`.** Your running commentary on this engagement. Entries are every `message` field of every tool call you make (delegation calls, the customer question, the closing call) and both the `result` and `message` of your closing `{done_tool_name}` call — together they form the closing entry of this subtask in the engagement record. Keep `message` log entries to 1-2 short sentences narrating what you are about to do or what you just received.

2. **Technical channel — English.** The wire between you and your team. Outgoing entries are the `question` fields you send when delegating to specialists (`{coder_tool_name}`, `{maintenance_tool_name}`, `{memorist_tool_name}`, `{pentester_tool_name}`, `{search_tool_name}`) and the `question` you send with `{advice_tool_name}` to the mentor. Incoming entries are the detailed `result` payloads those specialists return to you. English is the team's technical lingua franca; never translate or localise an outgoing technical-channel field.
</language_policy>

## CORE CAPABILITIES / KNOWLEDGE BASE

- Skilled at analyzing complex tasks and breaking them down into manageable subtasks
- Expert at delegation decision-making based on specialist capabilities
- Proficient at maintaining task context and ensuring operational continuity
- Capable of verifying environment state and establishing operational readiness

## TOOL EXECUTION RULES

<tool_usage_rules>
- ALL actions MUST use structured tool calls - plain text simulations will not execute
- VERIFY tool call success/failure and adapt strategy accordingly
- AVOID redundant actions and unnecessary tool usage
- PRIORITIZE minimally invasive tools before more intensive operations
</tool_usage_rules>

## MEMORY SYSTEM INTEGRATION

<memory_protocol>
- Use {memorist_tool_name} ONLY when information in the current context is insufficient
- If the current execution context and conversation history contain all necessary information to solve the task - memorist call is NOT required
- Invoke {memorist_tool_name} when you need information about past tasks, solutions, or methodologies that are NOT available in the current context
- Leverage previously stored solutions to similar problems only when current context lacks relevant approaches
- Prioritize using available context before retrieving from long-term memory
</memory_protocol>

## TEAM COLLABORATION & DELEGATION

<team_specialists>
<specialist name="searcher">
<skills>Information gathering, technical research, troubleshooting, analysis</skills>
<use_cases>Find critical information, create technical guides, explain complex issues</use_cases>
<tools>OSINT frameworks, search engines, threat intelligence databases, browser</tools>
<tool_name>{search_tool_name}</tool_name>
</specialist>

<specialist name="pentester">
<skills>Security testing, vulnerability exploitation, reconnaissance, attack execution</skills>
<use_cases>Discover and exploit vulnerabilities, bypass security controls, demonstrate attack paths</use_cases>
<tools>Network scanners, exploitation frameworks, privilege escalation tools</tools>
<tool_name>{pentester_tool_name}</tool_name>
</specialist>

<specialist name="developer">
<skills>Code creation, exploit customization, tool development, automation</skills>
<use_cases>Create scripts, modify exploits, implement technical solutions</use_cases>
<tools>Programming languages, development frameworks, build systems</tools>
<tool_name>{coder_tool_name}</tool_name>
</specialist>

<specialist name="adviser">
<skills>Strategic consultation, expertise coordination, solution architecture</skills>
<use_cases>Solve complex obstacles, provide specialized expertise, recommend approaches</use_cases>
<tools>Knowledge bases, decision frameworks, expert systems</tools>
<tool_name>{advice_tool_name}</tool_name>
</specialist>

<specialist name="memorist">
<skills>Context retrieval, historical analysis, pattern recognition</skills>
<use_cases>Access task history, identify similar scenarios, leverage past solutions</use_cases>
<tools>Vector database, semantic search, knowledge retention systems</tools>
<tool_name>{memorist_tool_name}</tool_name>
</specialist>

<specialist name="installer">
<skills>Environment configuration, tool installation, system administration</skills>
<use_cases>Configure testing environments, deploy security tools, prepare platforms</use_cases>
<tools>Container management, package managers, configuration automation</tools>
<tool_name>{maintenance_tool_name}</tool_name>
</specialist>
</team_specialists>

<delegation_rules>
- Delegate ONLY when a specialist is demonstrably better equipped for the task
- Provide COMPREHENSIVE context with every delegation request including:
  - Background information and current objective
  - Relevant findings gathered so far
  - Specific expected output format and success criteria
  - Constraints and security considerations
- Verify and integrate specialist results back into the workflow
- Maintain overall task coherence across multiple delegations
</delegation_rules>

## PLANNING & REASONING PROTOCOL

- EXPLICITLY plan before acting: develop a clear step-by-step approach
- For complex operations, use chain-of-thought reasoning:
  1. Analyze the problem and break it into components
  2. Consider multiple approaches and their trade-offs
  3. Select the optimal approach with justification
  4. Validate results before proceeding
- PERSIST until task completion: drive the interaction forward autonomously
- If an approach fails after 3 attempts, pivot to a completely different strategy
- Continuously evaluate progress toward subtask completion objectives

## OPERATIONAL PROTOCOLS

1. **Task Analysis**
   - Gather context with terminal/file operations BEFORE delegation
   - Verify environment state independently when possible
   - Construct precise task descriptions based on complete understanding

2. **Task Boundaries**
   - Work ONLY within the scope of the current subtask
   - Do NOT attempt to execute planned subtasks in the backlog
   - Focus on producing results that enable future subtasks to succeed

3. **Delegation Efficiency**
   - Include FULL context when delegating to specialists
   - Provide PRECISE success criteria for each delegated task
   - Match specialist skills to task requirements
   - USE minimum number of steps to complete the subtask

4. **Execution Management**
   - LIMIT repeated attempts to 3 maximum for any approach
   - Accept and report negative results when appropriate
   - AVOID redundant actions and unnecessary tool usage
   - All work executes inside Docker container with {docker_image} image

## CUSTOMER INTERACTION PROTOCOL

<customer_communication>
- You have access to the "{ask_tool_name}" tool to request additional information from the customer
- Use this tool when critical information is missing and cannot be obtained through other means
- When you receive information from the customer via "{ask_tool_name}", you MUST include it in your final report
- ALL information obtained from customer interactions MUST be incorporated into the result delivered via "{done_tool_name}"
- Customer-provided information is critical context that must be preserved and communicated in your subtask completion report
- Ensure that insights, clarifications, or data received from the customer are clearly documented in your final results
</customer_communication>

## SUMMARIZATION AWARENESS PROTOCOL

<summarized_content_handling>
<identification>
- Summarized historical interactions appear in TWO distinct forms within the conversation history:
  1. **Tool Call Summary:** An AI message containing ONLY a call to the summarization tool, immediately followed by a `Tool` message containing the summary in its response content.
  2. **Prefixed Summary:** An AI message whose text content starts EXACTLY with the summarized-content prefix.
- These summaries are condensed records of previous actions and conversations, NOT templates for your own responses.
</identification>

<interpretation>
- Treat ALL summarized content strictly as historical context about past events.
- Extract relevant information (previously used commands, discovered vulnerabilities, error messages, successful techniques) to inform your current strategy and avoid redundant actions.
</interpretation>

<prohibited_behavior>
- NEVER mimic or copy the format of summarized content.
- NEVER use the summarized-content prefix in your own messages.
- NEVER produce plain text responses simulating tool calls or their outputs. ALL actions MUST use structured tool calls.
</prohibited_behavior>
</summarized_content_handling>

## EXECUTION CONTEXT

<current_time>
{current_time}
</current_time>

<execution_context_usage>
- Use the current execution context to understand the precise current objective
- Extract Flow, Task, and SubTask details (IDs, Status, Titles, Descriptions)
- Determine operational scope and parent task relationships
- Identify relevant history within the current operational branch
- Tailor your approach specifically to the current SubTask objective
</execution_context_usage>

<execution_context>
{execution_context}
</execution_context>

## COMPLETION REQUIREMENTS

1. Follow the LANGUAGE POLICY above on every tool call. Every `message` field is an engagement-log entry written in `{lang}`; every delegation `question` and the technical excerpts you send with `{advice_tool_name}` stay on the technical channel in English.
2. Closing log entry: you MUST use the `{done_tool_name}` tool — both `result` (full write-up) and `message` (concise recap) are engagement-log entries written in `{lang}`. Translate the relevant prose from English specialist results into `{lang}`, preserving technical identifiers verbatim.
3. Provide COMPREHENSIVE results that will be used for task replanning and refinement.
4. Include critical information, discovered blockers, and recommendations for future subtasks.
5. Your report directly impacts the system's ability to plan effective next steps.

You are working on the customer's current subtask which you will receive in the next message.

{tool_placeholder}
"""


def _default_tool_schemas() -> list[dict[str, Any]]:
    """Return the JSON-schema tool definitions exposed to the LLM.

    Mirrors the registry entries for the 6 specialist tools + 2 barrier tools
    in PentAGI's ``pkg/tools/registry.go``. Each specialist takes a
    ``question`` (technical channel, English) and a ``message`` (engagement
    log, engagement language). Barrier tools carry their own arg schemas.
    """
    specialist_schema: dict[str, Any] = {
        "type": "object",
        "properties": {
            "question": {
                "type": "string",
                "description": (
                    "The delegation question / task description, written in "
                    "English on the technical channel."
                ),
            },
            "message": {
                "type": "string",
                "description": (
                    "Short engagement-log entry describing what you are "
                    "about to do, written in the engagement language."
                ),
            },
        },
        "required": ["question", "message"],
    }

    specialists: list[tuple[str, str]] = [
        (
            SEARCH_TOOL_NAME,
            "Delegate an information-gathering subtask to the Searcher "
            "specialist (OSINT, search engines, threat intel, browser).",
        ),
        (
            PENTESTER_TOOL_NAME,
            "Delegate a hands-on security testing subtask to the Pentester "
            "specialist (recon, exploitation, privilege escalation).",
        ),
        (
            CODER_TOOL_NAME,
            "Delegate a code-writing subtask to the Coder specialist "
            "(scripts, exploits, tool development, automation).",
        ),
        (
            ADVICE_TOOL_NAME,
            "Request strategic guidance from the Adviser specialist "
            "(mentoring, alternative approaches, solution architecture).",
        ),
        (
            MEMORIST_TOOL_NAME,
            "Retrieve relevant context from long-term memory via the "
            "Memorist specialist (vector DB, knowledge graph, past flows).",
        ),
        (
            MAINTENANCE_TOOL_NAME,
            "Delegate environment / tool setup to the Installer specialist "
            "(container management, package install, config automation).",
        ),
    ]

    schemas: list[dict[str, Any]] = []
    for name, desc in specialists:
        schemas.append(
            {
                "type": "function",
                "function": {
                    "name": name,
                    "description": desc,
                    "parameters": specialist_schema,
                },
            }
        )

    # Barrier: done — terminates the chain with success/failure.
    schemas.append(
        {
            "type": "function",
            "function": {
                "name": DONE_TOOL_NAME,
                "description": (
                    "Close the subtask with a comprehensive result. Barrier "
                    "tool — terminates the agent chain."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "result": {
                            "type": "string",
                            "description": (
                                "Full write-up of the subtask outcome, "
                                "written in the engagement language."
                            ),
                        },
                        "message": {
                            "type": "string",
                            "description": (
                                "Concise recap of the subtask, written in "
                                "the engagement language."
                            ),
                        },
                        "success": {
                            "type": "boolean",
                            "description": "Whether the subtask succeeded.",
                        },
                    },
                    "required": ["result", "message", "success"],
                },
            },
        }
    )

    # Barrier: ask — pauses the chain to request customer input.
    schemas.append(
        {
            "type": "function",
            "function": {
                "name": ASK_TOOL_NAME,
                "description": (
                    "Ask the customer for additional information. Barrier "
                    "tool — pauses the agent chain (returns WAITING)."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "message": {
                            "type": "string",
                            "description": (
                                "The question to surface to the customer, "
                                "written in the engagement language."
                            ),
                        },
                    },
                    "required": ["message"],
                },
            },
        }
    )

    return schemas


def render_system_prompt(
    *,
    lang: str = "English",
    cwd: str = "/work",
    docker_image: str = "debian:latest",
    execution_context: str = "",
    current_time: str | None = None,
) -> str:
    """Render the PrimaryAgent system prompt.

    Ports the XML-delimited structure from PentAGI's ``primary_agent.tmpl``.
    Uses simple ``str.format`` replacement so the module stays Jinja2-free;
    a future iteration may swap to Jinja2 if user-overridable prompts become
    a requirement (lazy-imported inside this function).

    Args:
        lang: Engagement-log language (BCP-47 code or English name).
        cwd: Working-directory path inside the Docker container.
        docker_image: Docker image the agent operates inside.
        execution_context: Pre-rendered XML execution-context string.
        current_time: ISO-8601 timestamp; defaults to now (UTC).

    Returns:
        The fully-rendered system prompt string.
    """
    if current_time is None:
        current_time = datetime.now(timezone.utc).isoformat()

    tool_placeholder = (
        "Execute operations via function invocation - textual responses "
        "are not acceptable for task completion."
    )

    return PRIMARY_AGENT_SYSTEM_PROMPT_TEMPLATE.format(
        lang=lang,
        cwd=cwd,
        docker_image=docker_image,
        execution_context=execution_context,
        current_time=current_time,
        search_tool_name=SEARCH_TOOL_NAME,
        pentester_tool_name=PENTESTER_TOOL_NAME,
        coder_tool_name=CODER_TOOL_NAME,
        advice_tool_name=ADVICE_TOOL_NAME,
        memorist_tool_name=MEMORIST_TOOL_NAME,
        maintenance_tool_name=MAINTENANCE_TOOL_NAME,
        done_tool_name=DONE_TOOL_NAME,
        ask_tool_name=ASK_TOOL_NAME,
        tool_placeholder=tool_placeholder,
    )


# ---------------------------------------------------------------------------
# Internal ToolExecutor adapter — wraps the injected handlers dict.
# ---------------------------------------------------------------------------


class _PrimaryToolExecutor:
    """Adapter that exposes the 6 specialists + 1 barrier handler as a
    ``ToolExecutor``.

    The ``tool_handlers`` dict provided by the caller must include:

    * One key per specialist tool name (``search``, ``pentest``, ``code``,
      ``advice``, ``memorize``, ``maintain``) — each value is a
      ``SpecialistHandler`` ``(args_json, ctx) -> str``.
    * A single ``"barrier"`` key whose value is a ``BarrierHandler``
      ``(tool_name, args_json, ctx) -> str`` — the same handler dispatches
      both ``done`` and ``ask`` (mirrors PentAGI's single ``Barrier`` func
      in ``PrimaryExecutorConfig``).
    """

    def __init__(
        self,
        tool_handlers: dict[str, Any],
        tool_schemas: list[dict[str, Any]] | None = None,
    ) -> None:
        self._handlers = tool_handlers
        self._schemas = tool_schemas if tool_schemas is not None else _default_tool_schemas()

        # Validate that all required handlers are present.
        required_keys = set(SPECIALIST_TOOL_NAMES) | {"barrier"}
        missing = required_keys - set(tool_handlers.keys())
        if missing:
            raise ValueError(f"PrimaryAgent missing required tool handlers: {sorted(missing)}")

    async def execute(
        self,
        name: str,
        arguments: str,
        context: AgentContext | None = None,
    ) -> str:
        """Route the tool call to the appropriate handler."""
        if name in SPECIALIST_TOOL_NAMES:
            handler: SpecialistHandler = self._handlers[name]
            result = handler(arguments, context)
        elif name in BARRIER_TOOL_NAMES:
            barrier_handler: BarrierHandler = self._handlers["barrier"]
            result = barrier_handler(name, arguments, context)
        else:
            raise ValueError(f"PrimaryAgent: no handler registered for tool {name!r}")

        if asyncio.iscoroutine(result):
            result = await result
        return result

    def is_barrier(self, name: str) -> bool:
        """Return True for ``done`` / ``ask``."""
        return name in BARRIER_TOOL_NAMES

    def get_tools(self) -> list[dict[str, Any]]:
        """Return a shallow-copied list of the tool schemas."""
        return [dict(schema) for schema in self._schemas]


# ---------------------------------------------------------------------------
# Per-run bookkeeping.
# ---------------------------------------------------------------------------


@dataclass
class PrimaryAgentRunStats:
    """Bookkeeping for a single ``PrimaryAgent.run()`` invocation.

    Populated by ``PrimaryAgent.run()`` after the chain terminates; accessible
    via ``PrimaryAgent.stats``. Useful for telemetry, debugging, and
    asserting on test behaviour.
    """

    iterations: int = 0
    tool_calls_made: list[ToolCall] = field(default_factory=list)
    barrier_hit: str | None = None
    final_result: PerformResult = PerformResult.ERROR
    started_at: str = ""
    finished_at: str = ""


# ---------------------------------------------------------------------------
# PrimaryAgent — the root orchestrator.
# ---------------------------------------------------------------------------


class PrimaryAgent:
    """Root orchestrator ported from PentAGI's ``flowProvider.PerformAgentChain``.

    The PrimaryAgent renders its system prompt, seeds the message chain with
    ``[system, user(subtask_description)]``, then drives
    :func:`perform_agent_chain` with the 6 specialist tools + 2 barrier
    tools. When the LLM invokes ``done``, the chain terminates with
    ``PerformResult.DONE`` (or ``PerformResult.ERROR`` if ``success=False``);
    when it invokes ``ask``, with ``PerformResult.WAITING``.

    The 6 specialists and the barrier handler are injected via
    ``tool_handlers`` so this class stays decoupled from the concrete
    specialist implementations (built by parallel subagents).

    Example:
        >>> llm = MyLLMClient()
        >>> handlers = {
        ...     "search":   searcher.run,
        ...     "pentest":  pentester.run,
        ...     "code":     coder.run,
        ...     "advice":   adviser.run,
        ...     "memorize": memorist.run,
        ...     "maintain": installer.run,
        ...     "barrier":  barrier_handler,
        ... }
        >>> agent = PrimaryAgent(llm, handlers)
        >>> result = await agent.run("Enumerate subdomains of example.com")

    Note:
        ``PrimaryAgent`` instances are NOT concurrency-safe: ``run()``
        mutates ``self._chain`` and ``self._stats``. Callers must either use
        one instance per concurrent subtask or serialise ``run()`` calls with
        an ``asyncio.Lock``.
    """

    def __init__(
        self,
        llm_client: LLMClient,
        tool_handlers: dict[str, Any],
        *,
        max_iterations: int = MAX_GENERAL_ITERATIONS,
        governance: Any | None = None,
        memory: Any | None = None,
        reflector: Any | None = None,
        summarizer: Any | None = None,
        lang: str = "English",
        execution_context: str = "",
        system_prompt: str | None = None,
        tool_schemas: list[dict[str, Any]] | None = None,
        docker_image: str = "debian:latest",
        cwd: str = "/work",
    ) -> None:
        """Initialise the PrimaryAgent.

        Args:
            llm_client: LLM client implementing the :class:`LLMClient`
                protocol.
            tool_handlers: Dict mapping tool names to handlers. Must include
                the 6 specialist keys (``search``, ``pentest``, ``code``,
                ``advice``, ``memorize``, ``maintain``) and a ``barrier``
                key. Specialist handlers are ``(args_json, ctx) -> str``;
                the barrier handler is ``(tool_name, args_json, ctx) -> str``.
            max_iterations: Iteration cap for the chain (default 100, the
                PentAGI general-agent cap).
            governance: Optional governance gate (e.g. an
                ``elengenix.governance.GovernanceGate`` instance) — currently
                stored for downstream specialists to consult; not invoked
                directly here.
            memory: Optional memory manager (e.g. a
                ``CognitiveMemoryManager``) — passed through to specialists
                via the handlers dict if needed.
            reflector: Optional :class:`Reflector` for no-tool-call repair.
                If ``None``, any no-tool-call response terminates the chain
                with ``PerformResult.ERROR``.
            summarizer: Optional :class:`Summarizer` for context-window
                management.
            lang: Engagement-log language.
            execution_context: Pre-rendered XML execution-context string.
            system_prompt: Optional fully-rendered system prompt; if
                ``None``, rendered lazily on first ``run()`` via
                :func:`render_system_prompt`.
            tool_schemas: Optional override for the JSON-schema tool list.
            docker_image: Docker image name injected into the prompt.
            cwd: Working-directory path injected into the prompt.
        """
        self._llm_client = llm_client
        self._tool_handlers = tool_handlers
        self._max_iterations = max_iterations
        self._governance = governance
        self._memory = memory
        self._reflector = reflector
        self._summarizer = summarizer
        self._lang = lang
        self._execution_context = execution_context
        self._system_prompt_override = system_prompt
        self._tool_schemas = tool_schemas
        self._docker_image = docker_image
        self._cwd = cwd
        self._log = logger.getChild("PrimaryAgent")

        # Per-run state — reset at the start of each run() call.
        self._chain: list[Message] = []
        self._stats: PrimaryAgentRunStats = PrimaryAgentRunStats()

    # ------------------------------------------------------------------
    # Read-only views for callers / tests.
    # ------------------------------------------------------------------

    @property
    def chain(self) -> list[Message]:
        """Return a shallow copy of the current message chain."""
        return list(self._chain)

    @property
    def stats(self) -> PrimaryAgentRunStats:
        """Return the stats from the most recent ``run()``."""
        return self._stats

    @property
    def agent_type(self) -> AgentType:
        """Return the agent type (always ``AgentType.PRIMARY``)."""
        return AgentType.PRIMARY

    # ------------------------------------------------------------------
    # System-prompt rendering.
    # ------------------------------------------------------------------

    def _render_system_prompt(self) -> str:
        """Render (or return the override for) the system prompt."""
        if self._system_prompt_override is not None:
            return self._system_prompt_override
        return render_system_prompt(
            lang=self._lang,
            cwd=self._cwd,
            docker_image=self._docker_image,
            execution_context=self._execution_context,
        )

    # ------------------------------------------------------------------
    # Barrier callback — translates barrier hits into PerformResult.
    # ------------------------------------------------------------------

    def _make_barrier_callback(self) -> Callable[[str, str], PerformResult]:
        """Build the ``on_barrier`` callback used by ``perform_agent_chain``.

        - ``done`` with ``success=True``  -> ``PerformResult.DONE``
        - ``done`` with ``success=False`` -> ``PerformResult.ERROR``
        - ``ask``                         -> ``PerformResult.WAITING``
        - unknown barrier                 -> ``PerformResult.DONE`` (default)
        """

        def _on_barrier(name: str, args_json: str) -> PerformResult:
            self._stats.barrier_hit = name
            if name == DONE_TOOL_NAME:
                # Parse the ``success`` flag (default True on parse failure
                # to mirror PentAGI's optimistic default).
                try:
                    payload = json.loads(args_json) if args_json else {}
                except json.JSONDecodeError:
                    payload = {}
                if payload.get("success", True):
                    return PerformResult.DONE
                return PerformResult.ERROR
            if name == ASK_TOOL_NAME:
                return PerformResult.WAITING
            self._log.warning("unknown_barrier_tool name=%s -- defaulting to DONE", name)
            return PerformResult.DONE

        return _on_barrier

    # ------------------------------------------------------------------
    # Main entry point.
    # ------------------------------------------------------------------

    async def run(self, subtask_description: str) -> PerformResult:
        """Execute ``subtask_description`` via ``perform_agent_chain``.

        Renders the system prompt, seeds the chain with
        ``[system, user(subtask_description)]``, then drives the universal
        agent-chain loop with the 6 specialist tools + 2 barrier tools.

        Args:
            subtask_description: The subtask to execute (typically rendered
                from the Generator's subtask plan).

        Returns:
            * ``PerformResult.DONE`` if the LLM closed via ``done`` with
              ``success=True``.
            * ``PerformResult.WAITING`` if the LLM paused via ``ask``.
            * ``PerformResult.ERROR`` on iteration-limit exhaustion,
              unrecoverable errors, or ``done`` with ``success=False``.
        """
        # Reset per-run state.
        self._chain = []
        self._stats = PrimaryAgentRunStats(
            started_at=datetime.now(timezone.utc).isoformat(),
            final_result=PerformResult.ERROR,
        )

        # Render system prompt and seed the chain.
        system_prompt = self._render_system_prompt()
        self._chain.append(Message(role="system", content=system_prompt))
        self._chain.append(Message(role="user", content=subtask_description))

        # Build the executor and barrier callback.
        executor = _PrimaryToolExecutor(
            tool_handlers=self._tool_handlers,
            tool_schemas=self._tool_schemas,
        )
        barrier_callback = self._make_barrier_callback()

        self._log.info("primary_agent_run_start subtask=%r", subtask_description[:200])

        try:
            result = await perform_agent_chain(
                agent_type=AgentType.PRIMARY,
                chain=self._chain,
                llm_client=self._llm_client,
                executor=executor,
                reflector=self._reflector,
                summarizer=self._summarizer,
                max_iterations=self._max_iterations,
                execution_context=self._execution_context,
                on_barrier=barrier_callback,
            )
        except asyncio.CancelledError:
            self._log.warning("primary_agent_run_cancelled")
            self._stats.finished_at = datetime.now(timezone.utc).isoformat()
            self._stats.final_result = PerformResult.ERROR
            raise
        except Exception as exc:  # noqa: BLE001
            self._log.error("primary_agent_run_failed err=%s", exc)
            self._stats.finished_at = datetime.now(timezone.utc).isoformat()
            self._stats.final_result = PerformResult.ERROR
            return PerformResult.ERROR

        # Tally stats from the (mutated) chain.
        self._stats.iterations = sum(1 for m in self._chain if m.role == "assistant")
        self._stats.tool_calls_made = [
            tc for m in self._chain if m.role == "assistant" for tc in m.tool_calls
        ]
        self._stats.final_result = result
        self._stats.finished_at = datetime.now(timezone.utc).isoformat()

        self._log.info(
            "primary_agent_run_done result=%s iterations=%d tool_calls=%d " "barrier=%s",
            result.value,
            self._stats.iterations,
            len(self._stats.tool_calls_made),
            self._stats.barrier_hit,
        )
        return result


__all__ = [
    "PrimaryAgent",
    "PrimaryAgentRunStats",
    "render_system_prompt",
    "PRIMARY_AGENT_SYSTEM_PROMPT_TEMPLATE",
    "DONE_TOOL_NAME",
    "ASK_TOOL_NAME",
    "SEARCH_TOOL_NAME",
    "PENTESTER_TOOL_NAME",
    "CODER_TOOL_NAME",
    "ADVICE_TOOL_NAME",
    "MEMORIST_TOOL_NAME",
    "MAINTENANCE_TOOL_NAME",
    "SPECIALIST_TOOL_NAMES",
    "BARRIER_TOOL_NAMES",
    "SpecialistHandler",
    "BarrierHandler",
]
