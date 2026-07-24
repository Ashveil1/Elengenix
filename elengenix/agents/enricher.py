"""elengenix/agents/enricher.py — sub-agent of Adviser that gathers supplementary context.

Ports PentAGI's ``templates/prompts/enricher.tmpl`` system prompt and the
``enricherHandler`` closure from ``providers/handlers.go::getAskAdviceHandler``
into Elengenix. The Enricher is a *limited* agent
(``MAX_LIMITED_ITERATIONS`` = 20) that gathers SUPPLEMENTARY context the
Adviser doesn't already have — historical memory (vector store + Graphiti
temporal knowledge graph), filesystem artifacts, terminal-execution data,
and content from specific known URLs (via the Browser tool).

The Enricher is ALWAYS invoked by the
:class:`~elengenix.agents.adviser.Adviser` and NEVER directly by the
PrimaryAgent. Given the same ``(question, execution_context)`` payload the
Adviser is about to reason over, the Enricher retrieves ONLY supplementary
information and terminates by calling the ``enricher_result`` barrier tool.
Its ``result`` field becomes the Adviser's ``<enrichment_data>``.

Two-channel language policy (ported verbatim from PentAGI):
    * Engagement log (``message`` fields, closing ``message``) -> {{ lang }}
    * Technical channel (queries, stored content, closing ``result``) ->
      English

Implementation note: this module wires its tools into the universal
:func:`elengenix.agents.base.perform_agent_chain` loop via a small
``_EnricherToolExecutor`` adapter that implements the ``ToolExecutor``
protocol — exactly the pattern used by
:class:`elengenix.agents.primary_agent.PrimaryAgent` and
:class:`elengenix.agents.memorist.Memorist`.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
from datetime import datetime, timezone
from typing import Any, Callable, Optional

from pydantic import BaseModel, Field, ValidationError

from elengenix.agents.base import (
    AgentContext,
    AgentType,
    MAX_LIMITED_ITERATIONS,
    Message,
    PerformResult,
    perform_agent_chain,
)

logger = logging.getLogger("elengenix.agents.enricher")

# --- Tool-name constants (ported from pentagi/backend/pkg/tools/registry.go) --
ENRICHER_RESULT_TOOL_NAME = "enricher_result"
SEARCH_IN_MEMORY_TOOL_NAME = "search_in_memory"
GRAPHITI_SEARCH_TOOL_NAME = "graphiti_search"
BROWSER_TOOL_NAME = "browser"
FILE_TOOL_NAME = "file"

# --- Shared prompt constants (ported from cast/csum packages) ----------------
SUMMARIZATION_TOOL_NAME = "execute_task_and_return_summary"
SUMMARIZED_CONTENT_PREFIX = "**summarized content:**\\n"
TOOL_PLACEHOLDER = (
    "Execute operations via function invocation - textual responses are not "
    "acceptable for task completion."
)

CONTAINER_WORK_DIR = "/work"
DEFAULT_DOCKER_IMAGE = "debian:latest"

#: The 7 Graphiti search types advertised in the system prompt.
GRAPHITI_SEARCH_TYPES: tuple[str, ...] = (
    "recent_context",
    "episode_context",
    "temporal_window",
    "successful_tools",
    "entity_relationships",
    "entity_by_label",
    "diverse_results",
)


# --- Pydantic schema for the barrier-tool payload ----------------------------
class EnricherResult(BaseModel):
    """Completion-tool payload for the ``enricher_result`` barrier tool.

    Two-channel policy (mirrors PentAGI):

    - ``result``  — technical channel, English. The supplementary-context
      write-up consumed by the Adviser. May be empty when no additional
      relevant information exists.
    - ``message`` — engagement log, engagement language. A 1–2 sentence
      running commentary on what was retrieved / produced.
    """

    result: str = Field(
        default="",
        description=(
            "Technical-channel payload — supplementary-context write-up "
            "(or empty when no additional relevant information exists). "
            "Always written in English; never translated."
        ),
    )
    message: str = Field(
        default="",
        max_length=500,
        description=(
            "Engagement-log entry — a 1-2 short sentence running commentary "
            "on what was retrieved. Written in the engagement language."
        ),
    )


# --- System prompt template (Jinja2; ported from enricher.tmpl) ---------------
SYSTEM_PROMPT_TEMPLATE = """\
# CONTEXT ENRICHMENT SPECIALIST

You are a specialized information gathering agent that provides SUPPLEMENTARY context to enhance the adviser's ability to answer user questions. Your role is NOT to answer questions yourself, but to retrieve additional relevant information that the adviser doesn't already have.

## LANGUAGE POLICY

<language_policy>
You operate on two parallel channels. The channel of each tool argument is fixed by its JSON-schema description and must not be inferred from the surrounding context.

1. **Engagement log — engagement language `{{ lang }}`.** Your running commentary on this engagement. Entries are every `message` field of every tool call you make (file operations, browser navigation, vector-store searches{% if graphiti_enabled %}, knowledge-graph searches{% endif %}, the closing call) and the `message` of your closing `{{ enricher_result_tool_name }}` call. The engagement coordination team reads the log in `{{ lang }}`. Keep `message` log entries to 1-2 short sentences narrating what you are about to do or what you just produced.

2. **Technical channel — English.** The wire between you, the vector store{% if graphiti_enabled %}, the temporal knowledge graph,{% endif %} the web, and the runtime container. Outgoing entries are:
   - vector-store search queries: `{{ search_in_memory_tool_name }}.questions`{% if graphiti_enabled %}
   - knowledge-graph queries: `{{ graphiti_search_tool_name }}.query`{% endif %}
   - runtime payloads inside the Docker container: `{{ file_tool_name }}` `path`, `{{ browser_tool_name }}` `url`
   - the `result` field of your closing `{{ enricher_result_tool_name }}` call — the supplementary-context write-up consumed by the adviser agent for further reasoning

The vector store{% if graphiti_enabled %} and the temporal knowledge graph{% endif %} {{ "are" if graphiti_enabled else "is" }} indexed in English and shared across all engagements regardless of their working language: any non-English query retrieves nothing. Never translate or localise an outgoing technical-channel field — runtime commands, search queries, and the closing `{{ enricher_result_tool_name }}.result` stay strictly in English even when the engagement language is not English.
</language_policy>

## OPERATIONAL CAPABILITIES

<information_sources_available>
You can retrieve supplementary information from:

<historical_sources>
{% if graphiti_enabled %}
<knowledge_graph>
- What agents actually did and discovered during operations
- Episodic memory of tool executions and their results
- Historical context about this specific engagement
</knowledge_graph>
{% endif %}
<vector_database>
- Stored knowledge, guides, and past solutions
- Reusable information from previous tasks
- Technical documentation and references
</vector_database>
</historical_sources>

<environment_sources>
<filesystem>
- Artifacts generated during task execution
- Configuration files and logs
- Results stored in container
</filesystem>
<browser>
- Content retrieval from specific known URLs
- Verification of web resources when URL is provided
</browser>
</environment_sources>
</information_sources_available>

## WHAT ADVISER ALREADY RECEIVES

The adviser will automatically receive the following from the system:
- **User Question**: The original question being asked
- **Code Snippet**: Any code provided by the user (if present)
- **Command Output**: Any execution output provided by the user (if present)
- **Execution Context**: Complete Flow/Task/SubTask details, IDs, statuses, descriptions
- **Current Time**: Timestamp of execution

**Your enrichment result will be added as SUPPLEMENTARY information to help the adviser.**

## ENRICHMENT PROTOCOL

<enhancement_rules>
<primary_rule>Provide ONLY additional information that adviser doesn't already have</primary_rule>
<no_duplication>DO NOT repeat the user's question, code, output, or
execution context details</no_duplication>
<memory_first>Check memory sources first - they may contain directly
relevant past results</memory_first>
<efficiency>If no additional relevant information exists - keep response
minimal or empty</efficiency>
<factual_only>Provide facts, data, and context - NOT answers, opinions, or advice</factual_only>
<relevance>Include only information directly relevant to answering the question</relevance>
</enhancement_rules>

## YOUR ROLE BOUNDARIES

<what_you_provide>
- Historical findings from past similar tasks (from memory/knowledge graph)
- Relevant artifacts, logs, or file contents from filesystem
- Technical data from command execution results
- Verification of specific URLs or resources when needed
- Background context not available in execution context
</what_you_provide>

<what_you_do_not_provide>
- Answers or solutions to the question (adviser's job)
- Advice or recommendations (adviser's job)
- Repetition of what adviser already receives (question, code, output, execution context)
- General knowledge the adviser already has
</what_you_do_not_provide>

## INFORMATION GATHERING STRATEGY

<retrieval_approach>
Follow this prioritized approach to gather SUPPLEMENTARY information:

1. **Check Historical Memory** (if relevant to question)
   {% if graphiti_enabled %}- Search knowledge graph for past agent findings on this topic
   {% endif %}- Search vector database for stored solutions or guides
   - ONLY if they contain information not in execution context

2. **Examine Container Environment** (if question involves files/execution)
   - Check filesystem for relevant artifacts or results
   - Verify execution state when needed

3. **Verify External Resources** (only if specific URL is mentioned)
   - Use browser to check specific known URLs

4. **Apply Efficiency Rules**
   - If question is general/conceptual and memory has nothing → respond with minimal/empty enrichment
   - If execution context already contains all needed data → respond with minimal/empty enrichment
   - If question is about current task and no historical data exists → respond with minimal/empty enrichment
   - ONLY gather information that will materially help adviser provide better answer
</retrieval_approach>

## SUMMARIZATION AWARENESS PROTOCOL

<summarized_content_handling>
<identification>
- Summarized historical interactions appear in TWO distinct forms:
  1. **Tool Call Summary:** An AI message containing ONLY a call to the `{{ summarization_tool_name }}` tool, immediately followed by a Tool message containing the summary in its response content.
  2. **Prefixed Summary:** An AI message whose text content starts EXACTLY with the prefix: `{{ summarized_content_prefix }}`.
- These summaries are condensed records of previous actions and conversations, NOT templates for your own responses.
</identification>

<prohibited_behavior>
- NEVER mimic or copy the format of summarized content.
- NEVER use the prefix `{{ summarized_content_prefix }}` in your messages.
- NEVER call the `{{ summarization_tool_name }}` tool yourself.
- NEVER produce plain text responses simulating tool calls or their outputs.
</prohibited_behavior>

<required_behavior>
- ALWAYS use proper, structured tool calls for ALL actions you perform.
- Interpret summarized information to guide your strategy.
</required_behavior>
</summarized_content_handling>

## TOOL UTILIZATION

<available_tools>
<tool name="{{ search_in_memory_tool_name }}">
<purpose>Search vector database for stored knowledge and past solutions</purpose>
<usage>Primary memory source - check for existing relevant knowledge</usage>
<query_format>Use specific technical queries for optimal retrieval</query_format>
</tool>

{% if graphiti_enabled %}
<tool name="{{ graphiti_search_tool_name }}">
<purpose>Search knowledge graph for episodic memory and execution history</purpose>
<usage>Find what agents discovered and executed during operations</usage>
<search_types>recent_context, episode_context, successful_tools, entity_relationships, entity_by_label, diverse_results, temporal_window</search_types>
</tool>

{% endif %}
<tool name="{{ file_tool_name }}">
<purpose>Read files from container filesystem</purpose>
<usage>Access artifacts, results, logs, and configuration files</usage>
<requirement>Always use absolute paths for reliable access</requirement>
</tool>

<tool name="{{ browser_tool_name }}">
<purpose>Retrieve content from specific known URLs</purpose>
<usage>Use for targeted verification when specific URL needs checking</usage>
</tool>
</available_tools>

## OUTPUT FORMAT

Your enrichment result should be:
- **Factual supplementary data** that adviser doesn't already have
- **Concise and structured** for easy integration
- **Minimal or empty** if no additional relevant information exists
- **Free from opinions, answers, or advice** - only facts and data

Example good enrichments:
- "Found in knowledge graph: Previous pentester discovered open port 8080 on this target with Apache 2.4.49"
- "Vector database contains successful exploit for similar vulnerability: [details]"
- "File /workspace/results.txt contains: [relevant excerpt]"
- "" (empty - when no supplementary information is needed)

Example bad enrichments:
- "The answer to your question is..." (that's adviser's job)
- "I recommend you should..." (that's adviser's job)
- "The execution context shows Task #5..." (adviser already has this)
- "Your question asks about..." (adviser already has the question)

## EXECUTION CONTEXT

<current_time>
{{ current_time }}
</current_time>

<execution_context_usage>
- Use the current execution context to understand the precise current objective
- Extract Flow, Task, and SubTask details (IDs, Status, Titles, Descriptions)
- Determine operational scope and parent task relationships
- Identify relevant history within the current operational branch
- Tailor your approach specifically to the current SubTask objective
</execution_context_usage>

<execution_context>
{{ execution_context }}
</execution_context>
{% if user_files %}

## TASK MATERIALS

<task_materials_protocol>
The following files are attached to this flow and available READ-ONLY in the container:
- `{{ cwd }}/uploads` — files delivered specifically for this flow
- `{{ cwd }}/resources` — reference materials for this engagement

If the question relates to these files, read their contents using `{{ file_tool_name }}` with the full path `<base>/<relative_path>` and include relevant excerpts in the enrichment result. These directories are READ-ONLY.
</task_materials_protocol>

{{ user_files }}
{% endif %}

## COMPLETION REQUIREMENTS

1. Gather ONLY supplementary information not already available to adviser
2. Provide factual data and context, NOT answers or advice
3. Keep response minimal if no additional relevant information exists
4. Follow the LANGUAGE POLICY above on every tool call. Every `message` is an engagement-log entry written in `{{ lang }}`; every search query, runtime command, and the closing `{{ enricher_result_tool_name }}.result` stay on the technical channel in English
5. Closing entries: you MUST use the `{{ enricher_result_tool_name }}` tool — `result` is the technical-channel supplementary-context write-up consumed by the adviser (English), `message` is the engagement-log closing summary (`{{ lang }}`)

{{ tool_placeholder }}

The user's question (and optional code/output) will be presented in the next message. Remember: your job is to provide SUPPLEMENTARY facts and data that will help the adviser answer this question, NOT to answer it yourself.
"""


USER_PROMPT_TEMPLATE = """\
<question_enricher_context>
  <instruction>Gather supplementary context that will help the adviser answer the user's question. Do NOT answer the question yourself.</instruction>

  <user_question>
  {{ question }}
  </user_question>
</question_enricher_context>
"""


# --- Jinja2 rendering helper (with str.format fallback) -----------------------
def _render(template: str, **context: Any) -> str:
    """Render a Jinja2 template string with the given context.

    Falls back to a tolerant ``str.format``-style substitution when Jinja2 is
    not installed; in that case ``{% if %}`` / ``{% endif %}`` blocks are
    stripped (treated as always-false) so the template still renders cleanly.
    """
    try:  # pragma: no cover - import guarded for minimal envs
        from jinja2 import Template

        return Template(template).render(**context)
    except ImportError:  # pragma: no cover
        stripped = re.sub(r"{%\s*if .*?%}.*?{%\s*endif\s*%}", "", template, flags=re.S)
        return stripped.format_map(_DefaultDict(context))


class _DefaultDict(dict):
    """``dict`` subclass returning empty string for missing keys (format fallback)."""

    def __missing__(self, key: str) -> str:  # noqa: D401
        return ""


# --- Tool-argument parsing helper --------------------------------------------
def _parse_args(arguments: str | dict[str, Any] | None) -> dict[str, Any]:
    """Parse a JSON-encoded tool-arguments string into a dict (tolerant)."""
    if isinstance(arguments, dict):
        return arguments
    if not arguments:
        return {}
    try:
        parsed = json.loads(arguments)
    except (json.JSONDecodeError, TypeError):
        return {}
    return parsed if isinstance(parsed, dict) else {}


# --- Default JSON-Schema tool definitions ------------------------------------
def _default_tool_schemas(graphiti_enabled: bool) -> list[dict[str, Any]]:
    """Return the JSON-schema tool definitions exposed to the LLM.

    Mirrors the registry entries for the Enricher's retrieval tools
    (``search_in_memory`` / ``graphiti_search`` / ``file`` / ``browser``)
    plus the ``enricher_result`` barrier.
    """
    schemas: list[dict[str, Any]] = []

    schemas.append({
        "type": "function",
        "function": {
            "name": SEARCH_IN_MEMORY_TOOL_NAME,
            "description": (
                "Search the long-term vector store for stored knowledge, "
                "guides, and past solutions from previous engagements. Use "
                "specific technical English queries for optimal retrieval."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "questions": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "1-5 precise English semantic queries.",
                    },
                    "message": {
                        "type": "string",
                        "description": "Short engagement-log entry (engagement language).",
                    },
                },
                "required": ["questions", "message"],
            },
        },
    })

    if graphiti_enabled:
        schemas.append({
            "type": "function",
            "function": {
                "name": GRAPHITI_SEARCH_TOOL_NAME,
                "description": (
                    "Search the Graphiti temporal knowledge graph for "
                    "episodic memory and execution history. 7 search types: "
                    + ", ".join(GRAPHITI_SEARCH_TYPES)
                    + "."
                ),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "query": {
                            "type": "string",
                            "description": "English search query (specific & contextual).",
                        },
                        "search_type": {
                            "type": "string",
                            "enum": list(GRAPHITI_SEARCH_TYPES),
                            "description": "One of the 7 Graphiti search types.",
                        },
                        "message": {
                            "type": "string",
                            "description": "Short engagement-log entry (engagement language).",
                        },
                    },
                    "required": ["query", "search_type", "message"],
                },
            },
        })

    schemas.append({
        "type": "function",
        "function": {
            "name": FILE_TOOL_NAME,
            "description": (
                "Read a file from the container filesystem (read-only). "
                "Always use absolute paths for reliable access."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Absolute path to the file inside the container.",
                    },
                    "message": {
                        "type": "string",
                        "description": "Short engagement-log entry (engagement language).",
                    },
                },
                "required": ["path", "message"],
            },
        },
    })

    schemas.append({
        "type": "function",
        "function": {
            "name": BROWSER_TOOL_NAME,
            "description": (
                "Retrieve content from a specific known URL. Use for "
                "targeted verification when a specific URL needs checking "
                "(not for general browsing)."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "The fully-qualified URL to fetch.",
                    },
                    "message": {
                        "type": "string",
                        "description": "Short engagement-log entry (engagement language).",
                    },
                },
                "required": ["url", "message"],
            },
        },
    })

    schemas.append({
        "type": "function",
        "function": {
            "name": ENRICHER_RESULT_TOOL_NAME,
            "description": (
                "Close the Enricher turn with the supplementary-context "
                "write-up. Barrier tool — terminates the agent chain. May "
                "be empty when no additional relevant information exists."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "result": {
                        "type": "string",
                        "description": (
                            "Technical-channel supplementary-context write-up "
                            "consumed by the adviser (English). May be empty."
                        ),
                    },
                    "message": {
                        "type": "string",
                        "description": (
                            "Engagement-log closing summary (engagement "
                            "language), 1-2 short sentences."
                        ),
                    },
                },
                "required": ["result", "message"],
            },
        },
    })

    return schemas


# --- ToolExecutor adapter ----------------------------------------------------
class _EnricherToolExecutor:
    """Adapter that exposes retrieval tools + the ``enricher_result`` barrier.

    Implements the :class:`elengenix.agents.base.ToolExecutor` protocol so
    the universal ``perform_agent_chain`` loop can dispatch tool calls. The
    completion tool (``enricher_result``) is a *barrier* — when invoked the
    executor captures the parsed :class:`EnricherResult` into ``captured``
    and returns an ack string; the loop's ``on_barrier`` callback then
    terminates the chain with :data:`PerformResult.DONE`.
    """

    def __init__(
        self,
        tool_handlers: dict[str, Callable[..., Any]],
        captured: dict[str, Any],
        tool_schemas: list[dict[str, Any]] | None = None,
    ) -> None:
        self._handlers = tool_handlers
        self._captured = captured
        self._schemas = tool_schemas if tool_schemas is not None else _default_tool_schemas(
            graphiti_enabled=False
        )

    async def execute(
        self,
        name: str,
        arguments: str,
        context: AgentContext | None = None,
    ) -> str:
        """Route the tool call to the appropriate handler (or capture barrier)."""
        if name == ENRICHER_RESULT_TOOL_NAME:
            args = _parse_args(arguments)
            try:
                parsed = EnricherResult.model_validate(args)
            except ValidationError as exc:
                logger.error("enricher_result payload failed validation: %s", exc)
                raise
            self._captured["result"] = parsed
            return "enricher result successfully processed"

        handler = self._handlers.get(name)
        if handler is None:
            logger.warning("enricher.tool_unknown name=%s", name)
            return (
                f"Error: tool '{name}' is not available in the Enricher chain. "
                f"Available tools: {sorted(self._handlers.keys())} "
                f"plus the '{ENRICHER_RESULT_TOOL_NAME}' completion tool."
            )

        try:
            result = (
                handler(arguments, context) if context is not None else handler(arguments)
            )
            if asyncio.iscoroutine(result):
                result = await result
        except Exception as exc:  # noqa: BLE001
            logger.warning("enricher.tool_failed name=%s err=%s", name, exc)
            return f"Error: tool '{name}' raised: {exc}"

        if not isinstance(result, str):
            try:
                result = json.dumps(result, ensure_ascii=False, default=str)
            except (TypeError, ValueError):
                result = str(result)
        return result or ""

    def is_barrier(self, name: str) -> bool:
        """Return True for the ``enricher_result`` completion tool."""
        return name == ENRICHER_RESULT_TOOL_NAME

    def get_tools(self) -> list[dict[str, Any]]:
        """Return a shallow-copied list of the tool schemas."""
        return [dict(schema) for schema in self._schemas]


# --- Enricher agent class ----------------------------------------------------
class Enricher:
    """Sub-agent of the Adviser that gathers supplementary context.

    Mirrors PentAGI's ``enricherHandler`` closure in ``handlers.go`` — runs
    an LLM tool-calling chain with a hard cap of ``MAX_LIMITED_ITERATIONS``
    iterations and the ``enricher_result`` barrier tool as the only exit.
    The vector store, Graphiti knowledge graph (when enabled), filesystem,
    and browser are exposed to the chain via the ``memory`` /
    ``docker_executor`` dependencies injected at construction time.

    The Enricher is NEVER invoked directly by the PrimaryAgent; it is always
    spawned by the :class:`~elengenix.agents.adviser.Adviser` as a sub-chain.
    """

    AGENT_TYPE = AgentType.ENRICHER
    COMPLETION_TOOL = ENRICHER_RESULT_TOOL_NAME
    LANG_DEFAULT = "en"
    DEFAULT_DOCKER_IMAGE = DEFAULT_DOCKER_IMAGE

    def __init__(
        self,
        llm_client: Any,
        docker_executor: Any = None,
        memory: Any = None,
        governance: Any = None,
        search_providers: Any = None,
        tool_handlers: dict[str, Callable[..., Any]] | None = None,
        max_iterations: int = MAX_LIMITED_ITERATIONS,
    ) -> None:
        self.llm_client = llm_client
        self.docker_executor = docker_executor
        self.memory = memory
        self.governance = governance
        self.search_providers = search_providers
        # Caller-supplied handlers override the auto-wired ones.
        self.tool_handlers: dict[str, Callable[..., Any]] = dict(tool_handlers or {})
        self.max_iterations = max_iterations or MAX_LIMITED_ITERATIONS

        # Engagement-log language — override on the instance if a non-default
        # language was negotiated at flow-creation time.
        self.lang: str = self.LANG_DEFAULT

        # Docker image is informational only — the Enricher doesn't spawn
        # containers itself; the adviser's container is used.
        self.docker_image: str = self.DEFAULT_DOCKER_IMAGE

        # Graphiti temporal-knowledge-graph toggle (cf. PentAGI
        # ``flowProvider.graphitiClient``).
        self.graphiti_enabled: bool = bool(getattr(memory, "graphiti_enabled", False))

    # ------------------------------------------------------------------ helpers

    def _now(self) -> str:
        """Return current UTC time as an ISO-8601 string for the prompt."""
        return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    def _user_files_listing(self) -> str:
        """Return a newline-separated listing of user-uploaded files (or empty)."""
        listing: Optional[list[str]] = None
        if self.docker_executor is not None:
            listing = getattr(self.docker_executor, "list_user_files", lambda: None)()
        return "\n".join(listing) if listing else ""

    def _build_system_context(
        self, execution_context: str, **extras: Any
    ) -> dict[str, Any]:
        """Build the Jinja2 context dict for the system-prompt template."""
        ctx: dict[str, Any] = {
            "lang": self.lang,
            "current_time": self._now(),
            "execution_context": execution_context or "",
            "cwd": CONTAINER_WORK_DIR,
            "user_files": self._user_files_listing(),
            "tool_placeholder": TOOL_PLACEHOLDER,
            "summarization_tool_name": SUMMARIZATION_TOOL_NAME,
            "summarized_content_prefix": SUMMARIZED_CONTENT_PREFIX,
            "docker_image": self.docker_image,
            "graphiti_enabled": self.graphiti_enabled,
            # Enricher-specific tool names
            "enricher_result_tool_name": ENRICHER_RESULT_TOOL_NAME,
            "search_in_memory_tool_name": SEARCH_IN_MEMORY_TOOL_NAME,
            "graphiti_search_tool_name": GRAPHITI_SEARCH_TOOL_NAME,
            "file_tool_name": FILE_TOOL_NAME,
            "browser_tool_name": BROWSER_TOOL_NAME,
        }
        ctx.update(extras)
        return ctx

    def _render_prompts(
        self, question: str, execution_context: str
    ) -> tuple[str, str]:
        """Render (system_prompt, user_prompt) for this run."""
        system_prompt = _render(
            SYSTEM_PROMPT_TEMPLATE,
            **self._build_system_context(execution_context),
        )
        user_prompt = _render(
            USER_PROMPT_TEMPLATE,
            question=question,
        )
        return system_prompt, user_prompt

    def _build_tool_handlers(self) -> dict[str, Callable[..., Any]]:
        """Wire the memory + docker_executor tools into a handler dict.

        Each handler is an ``async (args_json: str, ctx) -> str`` callable
        that parses the JSON args, calls the underlying method, and returns
        the string result. Caller-supplied ``self.tool_handlers`` override
        the auto-wired ones.
        """
        handlers: dict[str, Callable[..., Any]] = {}

        mem = self.memory
        if mem is not None:
            # search_in_memory
            fn = (
                getattr(mem, "search_in_memory", None)
                or getattr(mem, "search_answers", None)
            )
            if callable(fn):

                async def _search_in_memory(
                    args_json: str, ctx: AgentContext | None = None
                ) -> str:
                    args = _parse_args(args_json)
                    questions = args.get("questions") or []
                    if isinstance(questions, str):
                        questions = [questions]
                    result = fn(questions)
                    if asyncio.iscoroutine(result):
                        result = await result
                    return result if isinstance(result, str) else json.dumps(
                        result, ensure_ascii=False, default=str
                    )

                handlers[SEARCH_IN_MEMORY_TOOL_NAME] = _search_in_memory

            # graphiti_search — only when enabled.
            if self.graphiti_enabled:
                fn = (
                    getattr(mem, "graphiti_search", None)
                    or getattr(mem, "search_graphiti", None)
                )
                if callable(fn):

                    async def _graphiti_search(
                        args_json: str, ctx: AgentContext | None = None
                    ) -> str:
                        args = _parse_args(args_json)
                        wire_args = {
                            k: v for k, v in args.items() if k != "message"
                        }
                        result = fn(**wire_args)
                        if asyncio.iscoroutine(result):
                            result = await result
                        return result if isinstance(result, str) else json.dumps(
                            result, ensure_ascii=False, default=str
                        )

                    handlers[GRAPHITI_SEARCH_TOOL_NAME] = _graphiti_search

        # File (read-only) + Browser tools — wired from docker_executor.
        dock = self.docker_executor
        if dock is not None:
            # file — prefer a dedicated `read_file` method, else fall back
            # to the generic `exec_command` (cat the path).
            fn = getattr(dock, "read_file", None)
            if callable(fn):

                async def _file_read(
                    args_json: str, ctx: AgentContext | None = None
                ) -> str:
                    args = _parse_args(args_json)
                    path = args.get("path", "")
                    result = fn(path)
                    if asyncio.iscoroutine(result):
                        result = await result
                    return result if isinstance(result, str) else json.dumps(
                        result, ensure_ascii=False, default=str
                    )

                handlers[FILE_TOOL_NAME] = _file_read

            # browser — prefer a dedicated `fetch_url` / `browse` method.
            fn = (
                getattr(dock, "fetch_url", None)
                or getattr(dock, "browse", None)
                or getattr(dock, "browser", None)
            )
            if callable(fn):

                async def _browser(
                    args_json: str, ctx: AgentContext | None = None
                ) -> str:
                    args = _parse_args(args_json)
                    url = args.get("url", "")
                    result = fn(url)
                    if asyncio.iscoroutine(result):
                        result = await result
                    return result if isinstance(result, str) else json.dumps(
                        result, ensure_ascii=False, default=str
                    )

                handlers[BROWSER_TOOL_NAME] = _browser

        # Caller-supplied handlers override the auto-wired ones.
        if self.tool_handlers:
            handlers.update(self.tool_handlers)
        return handlers

    # ------------------------------------------------------------------- public

    async def run(self, question: str, execution_context: str = "") -> str:
        """Run the Enricher agent chain and return the supplementary-context string.

        Seeds the universal ``perform_agent_chain`` loop with
        ``[system, user]`` messages, drives it with the ``ENRICHER`` agent
        type, and terminates when the model emits the ``enricher_result``
        barrier tool. The barrier's parsed ``result`` field (technical
        channel, English) is this method's return value (may be empty when
        no additional relevant information exists).

        Args:
            question: The same question the Adviser is about to reason over.
                Written to the technical channel (English) inside the user
                prompt's ``<user_question>`` element.
            execution_context: Free-form execution-context blob rendered
                into the system prompt's ``<execution_context>`` section.

        Returns:
            The supplementary-context write-up (technical channel, English,
            possibly empty) captured from the ``enricher_result`` completion
            tool.

        Raises:
            ValueError: If ``question`` is empty.
            RuntimeError: If the chain terminates without invoking the
                ``enricher_result`` barrier tool.
            ValidationError: If the completion-tool payload does not conform
                to :class:`EnricherResult`.
        """
        if not question:
            raise ValueError("Enricher.run requires a non-empty question")

        logger.info(
            "Enricher starting run (question_len=%d, ctx_len=%d, lang=%s, graphiti=%s)",
            len(question),
            len(execution_context),
            self.lang,
            self.graphiti_enabled,
        )
        system_prompt, user_prompt = self._render_prompts(question, execution_context)

        chain: list[Message] = [
            Message(role="system", content=system_prompt),
            Message(role="user", content=user_prompt),
        ]

        tool_handlers = self._build_tool_handlers()
        captured: dict[str, Any] = {"result": None}
        tool_schemas = _default_tool_schemas(self.graphiti_enabled)
        executor = _EnricherToolExecutor(
            tool_handlers=tool_handlers,
            captured=captured,
            tool_schemas=tool_schemas,
        )

        def _on_barrier(name: str, args_json: str) -> PerformResult:
            """Enricher has exactly one barrier tool — always DONE."""
            return PerformResult.DONE

        result_state = await perform_agent_chain(
            agent_type=self.AGENT_TYPE,
            chain=chain,
            llm_client=self.llm_client,
            executor=executor,
            reflector=None,
            summarizer=None,
            max_iterations=self.max_iterations,
            execution_context=execution_context,
            on_barrier=_on_barrier,
        )

        result: EnricherResult | None = captured["result"]
        if result is None:
            raise RuntimeError(
                f"Enricher agent chain terminated without calling the "
                f"'{ENRICHER_RESULT_TOOL_NAME}' barrier tool "
                f"(final_state={result_state.value})"
            )

        logger.info(
            "Enricher run complete (result_len=%d, state=%s)",
            len(result.result or ""),
            result_state.value,
        )
        return result.result or ""


__all__ = [
    "Enricher",
    "EnricherResult",
    "ENRICHER_RESULT_TOOL_NAME",
    "SEARCH_IN_MEMORY_TOOL_NAME",
    "GRAPHITI_SEARCH_TOOL_NAME",
    "BROWSER_TOOL_NAME",
    "FILE_TOOL_NAME",
    "GRAPHITI_SEARCH_TYPES",
    "SYSTEM_PROMPT_TEMPLATE",
    "USER_PROMPT_TEMPLATE",
]
