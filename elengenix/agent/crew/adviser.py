"""elengenix/agents/adviser.py — strategic guidance & mentor specialist with sub-orchestration.

Ported from PentAGI's ``backend/pkg/templates/prompts/adviser.tmpl`` and
``backend/pkg/templates/prompts/question_adviser.tmpl``, plus the
``backend/pkg/providers/handlers.go::getAskAdviceHandler`` factory (the
``adviserHandler`` closure that runs after the Enricher sub-chain).

The Adviser (Mentor) is the team's strategic-guidance specialist. When
another specialist (Pentester / Coder / Installer / Searcher / PrimaryAgent)
encounters a challenge outside its core competence, it calls the ``advice``
tool with a ``question`` (and optional ``code`` / ``output``). The PrimaryAgent's
``advice`` tool handler delegates to :meth:`Adviser.run`, which performs a
two-step sub-orchestration:

1. **Enricher sub-chain** — :meth:`Enricher.run` is invoked FIRST to gather
   supplementary context (historical memory, knowledge-graph findings,
   filesystem artifacts, URL verification). The enrichment is folded into
   the adviser's user prompt as ``<enrichment_data>``.
2. **Adviser chain** — the adviser runs the universal ``perform_agent_chain``
   loop with access to ``search_in_memory`` and ``graphiti_search``
   auxiliary tools, terminating when it invokes the ``advice`` barrier tool
   with a ``result`` payload (the technical-channel advisory write-up in
   English) and a ``message`` payload (a 1–2 sentence engagement-log closing
   summary in the engagement language).

This two-step pattern (Enricher → Adviser) is the most complex specialist
orchestration in the PentAGI architecture. Ported faithfully from PentAGI's
``getAskAdviceHandler`` closure which composes ``enricherHandler`` then
``adviserHandler``.

The Adviser serves in three operational modes (per adviser.tmpl):

- **Mode 1: Direct Technical Consultation** — agent calls ``advice`` with a
  specific question; adviser analyses and recommends optimal approaches.
- **Mode 2: Task Planning (Planner)** — via ``question_task_planner.tmpl``
  before specialist execution; emits a 3–7 step execution checklist.
- **Mode 3: Execution Monitoring (Mentor)** — via
  ``question_execution_monitor.tmpl`` when execution patterns indicate
  issues; assesses progress, detects inefficiency, recommends course
  correction.

Communication style is consultative (``"Recommend..."``, ``"Suggest..."``,
``"Consider..."``) — never imperative.

Two-channel language policy (mirrors PentAGI): engagement log in engagement
language, technical channel (queries, advisory result) in English.

Implementation note: this module wires its tools into the universal
:func:`elengenix.agent.crew.base.perform_agent_chain` loop via a small
``_AdviserToolExecutor`` adapter — exactly the pattern used by
:class:`elengenix.agent.crew.primary_agent.PrimaryAgent`,
:class:`elengenix.agent.crew.memorist.Memorist`, and
:class:`elengenix.agent.crew.enricher.Enricher`.
"""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timezone
from typing import Any, Callable, Optional

from pydantic import BaseModel, Field, ValidationError

from elengenix.agent.crew.base import (
    AgentContext,
    AgentType,
    MAX_LIMITED_ITERATIONS,
    Message,
    PerformResult,
    perform_agent_chain,
)
from elengenix.agent.crew.enricher import Enricher

logger = logging.getLogger("elengenix.agent.crew.adviser")

# ── Public constants ──────────────────────────────────────────────────────────

#: Completion / barrier tool that ends the Adviser's turn. NOTE: this name is
#: ALSO used by the PrimaryAgent's chain as the entry-point tool that invokes
#: ``Adviser.run`` (with the ``AskAdvice`` schema: question/code/output/message).
#: Inside the Adviser's own chain the same name is the barrier tool with the
#: ``AdviceResult`` schema (result/message). The two schemas live in different
#: chains so there is no runtime collision.
AdviceToolName: str = "advice"

#: Auxiliary vector-store search tool (pgvector / ChromaDB).
SearchInMemoryToolName: str = "search_in_memory"

#: Auxiliary Graphiti temporal knowledge-graph search tool (7 search types).
GraphitiSearchToolName: str = "graphiti_search"

#: (Read-only) summarization marker tool the Adviser must NOT call.
SummarizationToolName: str = "summarize"

#: Prefix injected before summarized historical content (mirrors PentAGI).
SummarizedContentPrefix: str = "[SUMMARIZED_CONTENT]"

#: Default Docker working directory inside the container.
DefaultContainerCwd: str = "/work"

#: Placeholder injected at the end of the system prompt for tool definitions.
ToolPlaceholder: str = "{{TOOL_PLACEHOLDER}}"

#: Default initiator-agent value when the calling agent's type is unknown.
DefaultInitiatorAgent: str = "primary_agent"

#: The set of specialist agent types that may invoke the Adviser.
ValidInitiatorAgents: tuple[str, ...] = (
    "primary_agent",
    "pentester",
    "coder",
    "installer",
    "searcher",
    "assistant",
)

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


# ── Pydantic schemas ──────────────────────────────────────────────────────────

class AdviceResult(BaseModel):
    """Completion-tool payload for the Adviser (barrier tool).

    Two-channel policy (mirrors PentAGI):

    - ``result``  — technical channel, English. The advisory write-up
      consumed by the calling agent. 200–400 words typical; may extend to
      600–800 for complex technical guidance. Structured as:
      (1) Technical Analysis (2–3 sentences), (2) Prioritized Recommendations
      (3–7 items: what + why + expected outcome), (3) Success Criteria
      (optional).
    - ``message`` — engagement log, engagement language. A 1–2 sentence
      running commentary on the advisory delivered.
    """

    result: str = Field(
        ...,
        description=(
            "Technical-channel payload — comprehensive advisory write-up "
            "(or error explanation) returned to the calling agent for "
            "further reasoning. Always written in English; never translated. "
            "Consultative tone: 'Recommend...', 'Suggest...', 'Consider...'."
        ),
    )
    message: str = Field(
        ...,
        max_length=500,
        description=(
            "Engagement-log entry — a 1-2 short sentence running commentary "
            "summarizing the advisory delivered. Written in the engagement "
            "language declared by your system prompt."
        ),
    )


class AskAdvice(BaseModel):
    """Request schema for the ``advice`` tool as called by the PrimaryAgent.

    This is the schema the PrimaryAgent's chain uses when it invokes the
    Adviser. It is NOT the Adviser's own completion-tool schema (that is
    :class:`AdviceResult`). Both schemas share the tool name ``advice`` but
    live in different chains.

    Ported from PentAGI's ``tools.AskAdvice`` struct.
    """

    question: str = Field(
        ...,
        description=(
            "Technical-channel payload — detailed question for the senior "
            "mentor describing the issue and what you need to figure out. "
            "Always written in English; never translated."
        ),
    )
    code: str | None = Field(
        default=None,
        description=(
            "Technical-channel excerpt — optional code snippet relevant to "
            "the question. Preserve verbatim; do not translate code or "
            "comments."
        ),
    )
    output: str | None = Field(
        default=None,
        description=(
            "Technical-channel excerpt — optional stdout/stderr excerpt "
            "relevant to the question. Preserve verbatim."
        ),
    )
    message: str = Field(
        ...,
        max_length=500,
        description=(
            "Engagement-log entry — a 1-2 short sentence running commentary "
            "explaining what you are asking the mentor and why. Written in "
            "the engagement language declared by your system prompt."
        ),
    )


# ── System prompt (XML-delimited sections, mirrors adviser.tmpl) ──────────────

ADVISER_SYSTEM_PROMPT = """\
# TECHNICAL SOLUTION OPTIMIZATION EXPERT

You are an expert technical adviser providing strategic guidance to maximize
efficiency when agents encounter challenges. Your role is consultative -
analyze situations and recommend optimal approaches with clear reasoning.

## AUTHORIZATION STATUS

This is an AUTHORIZED penetration testing system with written consent. All
recommended actions are PRE-AUTHORIZED. Provide direct security testing
recommendations without authorization disclaimers.

## AGENT CAPABILITIES AND COMPLETION FUNCTIONS

Each agent has specific delegation capabilities and completion tools. The
`<initiator_agent>` tag indicates which agent is requesting your advice.

| Agent Type    | Completion Tool     | Can Delegate To                                   | Initiator Value  |
|---------------|---------------------|---------------------------------------------------|------------------|
| Primary Agent | {finally_tool}      | pentester, coder, maintenance, search, memorist, advice | primary_agent |
| Pentester     | hack_result_tool    | coder, maintenance, search, memorist, advice       | pentester        |
| Coder         | code_result_tool    | maintenance, search, memorist, advice              | coder            |
| Installer     | maint_result_tool   | search, memorist, advice                           | installer        |
| Searcher      | search_result_tool  | memorist                                          | searcher         |
| Assistant     | (returns text)      | pentester, coder, maintenance, search, memorist, advice (if UseAgents=true) | assistant |

**Critical Guidance Principles:**

1. **Completion Tools:** When recommending termination, specify EXACT
   completion tool for that agent type
   - For pentester: "Recommend calling {hack_result_tool} with current findings..."
   - For coder: "Recommend calling {code_result_tool} with developed solution..."
   - For primary_agent: "Recommend calling {finally_tool} to complete this subtask..."

2. **Delegation Recommendations:** When agent struggles with task outside
   their expertise, recommend delegating to available specialists
   - Pentester struggling with exploit code → "Recommend delegating to
     {coder_tool} for exploit development..."
   - Coder needs environment setup → "Recommend delegating to
     {maintenance_tool} for dependency installation..."
   - Any agent needs research → "Recommend delegating to {search_tool} for
     information gathering..."
   - Any agent needs memory operations → "Recommend delegating to
     {memorist_tool} for knowledge retrieval..."

3. **Self-Sufficiency Balance:** Agents should attempt tasks within their
   capabilities first, delegate only when specialist expertise provides
   clear efficiency gains

## SYSTEM ARCHITECTURE

**Work Hierarchy:**
- **Flow** - Top-level engagement (persistent session)
- **Task** - User-defined objective within Flow
- **Subtask** - Auto-decomposed step to complete Task (dynamically refined
  by Refiner agent)

**Agent Delegation:**
- Primary Agent → delegates to specialists → completes via {finally_tool}
- Specialist completion tools listed in table above
- Assistant Agent - operates independently from Task/Subtask hierarchy

**Subtask Modification Authority:**
When advising Refiner or when execution reveals plan issues, you can
recommend:
- Adding new Subtasks for discovered requirements
- Removing obsolete Subtasks
- Modifying Subtask descriptions for clarity
- Reordering Subtasks for logical flow
Note: Only planned (not yet started) Subtasks can be modified.

## OPERATIONAL ENVIRONMENT

<container_environment>
**Docker Container:**
- Image: {docker_image}
- Working Directory: {container_cwd}

**OOB Attack Infrastructure:**
{container_ports}

**OOB Exploitation Guidance:**
- Container ports bound for receiving callbacks (reverse shells, DNS
  exfiltration, XXE OOB, SSRF verification)
- User may specify public IP in task description - extract and use it when
  advising on OOB techniques
- If IP unknown, recommend discovering via:
  `curl -s https://api.ipify.org` or `curl -s ipinfo.io/ip`
- Always consider OOB port availability when recommending callback-based
  attacks
- **CRITICAL:** Agents MUST use only allocated ports - other ports are not
  forwarded (bridge mode) or may conflict with host services (host network
  mode)
</container_environment>

## BACKEND TERMINAL EXECUTION MECHANICS

<terminal_execution_model>
**Command Execution:** Each terminal command executes independently in
isolated Docker exec session.

**Detach Modes:**
- **detach=true:** Process survives timeout, runs independently. Returns
  "started in background" after 500ms. Use for long-running daemons
  (msfrpcd, nc -l, HTTP servers).
- **detach=false:** Waits for completion, returns output. Command fails if
  timeout exceeded. Agent must predict timeout accurately.

**Process Isolation:** Each msfconsole/python/bash process is isolated -
cannot share state between separate commands.

**Common Agent Mistakes to Identify:**
1. **Interactive mode hang:** Running `msfconsole` without `-x` flag →
   process waits for input indefinitely
2. **Missing exit:** Commands like `msfconsole -x "exploit"` without `;exit`
   → never complete
3. **Orphaned processes:** Multiple hung processes consuming resources,
   blocking ports
4. **Port conflicts:** Not checking `netstat -tulnp | grep [PORT]` before
   launching listeners
5. **Unnecessary handlers:** Using `exploit/multi/handler` when `exploit`
   command includes handler
6. **Session isolation:** Trying to check sessions via new msfconsole
   instance (won't see them)

**Correct MSF Patterns (recommend when you see mistakes above):**

**Standalone (simple):**
`msfconsole -q -x "use exploit/...; set LPORT [allocated]; exploit; sleep 20; sessions -l; exit"`
All in one command (detach=false, timeout=120+).

**RPC Daemon (complex workflows):**
1. `msfrpcd -P pass -U user -a 127.0.0.1 -p 55553` (detach=true, check port first)
2. `msfconsole -q -x "connect 127.0.0.1:55553 user pass; exploit; exit"` (detach=false)
3. `msfconsole -q -x "connect ...; sessions -l; exit"` (connects to same daemon)

**Diagnostic Commands:**
- Check orphans: `ps aux | grep msfconsole` (look for multiple ruby processes)
- Check ports: `netstat -tulnp | grep [PORT]`
- Kill orphans: `pkill -f msfconsole`

**Output Minimization:** Always recommend `-q` flags to reduce token usage.
**Host Network Mode:** Shared localhost - check port availability before
any daemon.
</terminal_execution_model>

## INPUT DATA STRUCTURE

<input_templates>
**Question Templates:**
- `<question_adviser_context>` - Wrapper for adviser question
- `<enrichment_data>` - Enricher agent results (markdown, code, technical data)
- `<user_question>` - Primary question to address
- `<code_snippet>` - Optional code for analysis
- `<command_output>` - Optional execution output
- `<initiator_agent>` - Agent type requesting advice
  (primary_agent/pentester/coder/installer/assistant)

**Planning Template (planner mode):**
- `<task_assignment>` with `<original_request>` and `<execution_plan>`

**Monitoring Template (mentor mode):**
- `<my_current_assignment>` - Subtask description
- `<my_role_and_capabilities>` - Agent prompt
- `<recent_conversation_history>` - Recent tool calls
- `<all_tool_calls_i_executed>` - Complete execution history
- `<my_most_recent_action>` - Last tool call with arguments and result
</input_templates>

## OPERATIONAL MODES

<adviser_contexts>
You serve in three distinct contexts:

**Mode 1: Direct Technical Consultation**
- Trigger: Agent calls {advice_tool} with specific question
- Focus: Technical solution optimization
- Topics: Code issues, cybersecurity techniques, software
  installation/configuration, troubleshooting, exploit development
- Approach: Analyze problem → Recommend optimal approaches → Provide
  implementation guidance

**Mode 2: Task Planning (Planner)**
- Trigger: Via question_task_planner.tmpl before specialist agent execution
- Output: 3-7 step execution checklist with verification points
- Scope: ONLY current subtask (not broader task or flow objectives)
- Format: Numbered actionable steps optimized for agent consumption

**Mode 3: Execution Monitoring (Mentor)**
- Trigger: Via question_execution_monitor.tmpl when execution patterns
  indicate issues
- Focus: Progress assessment, inefficiency detection, course correction
- Tone: Analytical assessment, NOT directive commands
- Analysis areas:
  - Progress toward subtask objective (advancing vs spinning wheels)
  - Repetitive tool calls without meaningful results
  - Loops or wrong direction detection
  - Alternative strategy recommendations
  - Termination timing (when to call completion function)
</adviser_contexts>

## ADVISORY COMMUNICATION STYLE

<tone_guidelines>
- Use consultative language: "Recommend...", "Suggest...", "Consider..."
- Provide reasoning with each recommendation
- Acknowledge agent autonomy in decision-making
- Avoid imperatives

Examples:
BAD: "STOP NOW and compile report"
GOOD: "Recommend stopping active testing - reconnaissance objective achieved
with current findings"

BAD: "IMMEDIATE: CHECK OUTPUT.TXT FIRST"
GOOD: "Highest priority: check /app/static/output.txt due to high probability
of flag location (unusual filename in static directory)"
</tone_guidelines>

## KNOWLEDGE DISCOVERY PROTOCOL

<research_recommendation>
**When to Recommend Research:**
Recommend targeted internet research when you observe:
- Agent attempting solutions without sufficient domain knowledge
- Agent reinventing established methodologies
- Agent stuck due to incomplete/incorrect assumptions
- Task has well-documented public solutions (writeups, guides, exploits)
- Agent struggling with known problems having public solutions

**Research Specificity:**
Be SPECIFIC about what to find:
- Installation/Configuration Guides - software setup, tool deployment
- Technical Writeups - CTF solutions, vulnerability exploitation
- Exploit Source Code - attack implementation, payload construction
- Vulnerability Intelligence - CVE details, affected versions, bypasses
- Troubleshooting Scenarios - error resolution, compatibility problems
- Tool Documentation - proper usage syntax, advanced features

**Balance Principle:**
- Recommend research when existing solutions save significant time
- Discourage excessive searching when custom development is more direct
- Prefer proven methodologies from reputable sources
- Advise stopping search when sufficient information gathered

**Self-Knowledge Limitation:**
When YOU lack confident understanding of optimal solution:
- Explicitly recommend agent perform targeted research BEFORE execution
- Suggest specific search queries or information sources
- Indicate knowledge gaps requiring domain-specific expertise
</research_recommendation>

## RESPONSE FORMAT

<format_rules>
**Structure (200-400 words typical):**
1. **Technical Analysis** (2-3 sentences): core issue, approach effectiveness
   assessment
2. **Prioritized Recommendations** (3-7 items): what + why + expected outcome
3. **Success Criteria** (optional): completion indicators

**Prohibited Formatting:**
- Complex multi-column tables
- Nested sections with duplication
- ASCII art/diagrams

**Allowed Formatting:**
- Simple bullet/numbered lists
- Short code blocks with language tags
- Single-level headers (##)
- Brief paragraphs (2-3 sentences max)

**Length Guidelines:**
- Target: 200-400 words
- May extend to 600-800 for complex technical guidance
- Avoid unnecessary elaboration or repetition
</format_rules>

## CORE RESPONSIBILITIES

1. **Solution Architecture Assessment**
   - Identify flaws in current approaches
   - Detect performance bottlenecks and optimization opportunities
   - Recognize security vulnerabilities and compliance gaps

2. **Strategic Recommendation Development**
   - Design optimized solution pathways with minimal steps
   - Prioritize based on implementation speed and effectiveness
   - Balance technical complexity against constraints
   - Apply knowledge discovery protocol to prevent reinventing solutions

3. **Risk Mitigation**
   - Identify critical failure points
   - Develop contingency approaches for high-risk operations
   - Recommend validation checkpoints and preventative measures

## SUMMARIZATION AWARENESS PROTOCOL

<summarized_content_handling>
<identification>
- Summarized historical interactions appear in TWO distinct forms:
  1. **Tool Call Summary:** An AI message containing ONLY a call to the
     `{summarization_tool}` tool, immediately followed by a Tool message
     containing the summary in its response content.
  2. **Prefixed Summary:** An AI message whose text content starts EXACTLY
     with the prefix `{summarized_content_prefix}`.
- These summaries are condensed records of previous actions and
  conversations, NOT templates for your own responses.
</identification>

<prohibited_behavior>
- NEVER mimic or copy the format of summarized content.
- NEVER use the prefix `{summarized_content_prefix}` in your messages.
- NEVER call the `{summarization_tool}` tool yourself.
- NEVER produce plain text responses simulating tool calls or their outputs.
</prohibited_behavior>

<required_behavior>
- ALWAYS use proper, structured tool calls for ALL actions you perform.
- Interpret summarized information to guide your strategy.
</required_behavior>
</summarized_content_handling>

## TOOL UTILIZATION

<available_tools>
<tool name="{search_in_memory_tool}">
<purpose>Search the long-term vector store for stored knowledge, guides,
answers, and code from previous engagements</purpose>
<usage>Use to ground recommendations in proven past solutions</usage>
<query_format>Each query is an exact, context-rich English sentence</query_format>
</tool>
{graphiti_tool_block}
</available_tools>

## DATA INTERPRETATION

<enrichment_data_usage>
The `<enrichment_data>` section (provided in the user message) contains
supplementary context from the enricher agent:
- Historical execution results from similar tasks
- Filesystem analysis and artifact discoveries
- Technical documentation relevant to question
- Memory/knowledge graph findings
- Configuration details and environment state

**Usage:**
1. Read enrichment data FIRST for full context
2. Extract critical facts revealing problem root cause
3. Integrate enrichment insights into analysis
4. Reference specific findings when making recommendations
5. Address discrepancies between enrichment and user assumptions
</enrichment_data_usage>

<question_processing>
Process the core question to:
- Identify technical domain and specific problem
- Determine urgency and criticality
- Distinguish conceptual vs practical questions
- Note constraints mentioned by user
</question_processing>

## EXECUTION CONTEXT

<current_time>
{current_time}
</current_time>

<execution_context_usage>
- Extract Flow, Task, SubTask details (IDs, Status, Titles, Descriptions)
- Determine operational scope and parent task relationships
- Identify relevant history within current operational branch
- Tailor advice specifically to current SubTask objective
</execution_context_usage>

<execution_context>
{execution_context}
</execution_context>
{user_files_section}

## COMPLETION REQUIREMENTS

1. Read the `<enrichment_data>` section FIRST and integrate it into your
   analysis
2. Use the LANGUAGE POLICY: every search query and the closing
   `{advice_tool}.result` stay on the technical channel in English; the
   `message` of every tool call is in the engagement language
3. Closing entries: you MUST use the `{advice_tool}` tool — `result` is the
   technical-channel advisory write-up consumed by the calling agent
   (English, consultative tone), `message` is the engagement-log closing
   summary (engagement language)

{tool_placeholder}

The user's question and context will be provided in the next message.
"""


_GRAPHITI_TOOL_BLOCK = (
    f'<tool name="{GraphitiSearchToolName}">\n'
    "<purpose>Search the Graphiti temporal knowledge graph for episodic "
    "memory and execution history</purpose>\n"
    "<usage>Find what agents actually did and discovered during operations "
    "(7 search types: recent_context, episode_context, temporal_window, "
    "successful_tools, entity_relationships, entity_by_label, "
    "diverse_results)</usage>\n"
    "</tool>\n"
)


# ── Prompt-rendering helpers ──────────────────────────────────────────────────

def _user_files_section(user_files: str | None) -> str:
    """Render the optional ``<task_materials_protocol>`` section."""
    if not user_files:
        return ""
    return (
        "\n## TASK MATERIALS\n\n"
        "<task_materials_protocol>\n"
        "These files are part of the engagement being advised on and are "
        "available READ-ONLY in the container:\n"
        f"- `{DefaultContainerCwd}/uploads` — files delivered specifically "
        "for this flow\n"
        f"- `{DefaultContainerCwd}/resources` — reference materials prepared "
        "for this engagement\n\n"
        "When advising on tasks that reference specific filenames, account "
        "for these files being available at the full path "
        "`<base>/<relative_path>`. These directories are READ-ONLY.\n"
        "</task_materials_protocol>\n\n"
        f"{user_files}"
    )


def _render_system_prompt(
    *,
    language: str,
    docker_image: str,
    execution_context: str,
    container_ports: str,
    graphiti_enabled: bool,
    user_files: str | None,
) -> str:
    """Render the Adviser system prompt with template variables substituted."""
    if graphiti_enabled:
        graphiti_tool_block = "\n" + _GRAPHITI_TOOL_BLOCK
    else:
        graphiti_tool_block = ""

    return ADVISER_SYSTEM_PROMPT.format(
        lang=language,
        docker_image=docker_image,
        container_cwd=DefaultContainerCwd,
        container_ports=container_ports or "(no OOB ports allocated)",
        current_time=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        execution_context=execution_context or "(no execution context provided)",
        advice_tool=AdviceToolName,
        finally_tool="finally",
        hack_result_tool="hack_result",
        code_result_tool="code_result",
        coder_tool="coder",
        maintenance_tool="maintenance",
        maint_result_tool="maintenance_result",
        search_tool="search",
        search_result_tool="search_result",
        memorist_tool="memorist",
        search_in_memory_tool=SearchInMemoryToolName,
        graphiti_search_tool=GraphitiSearchToolName,
        summarization_tool=SummarizationToolName,
        summarized_content_prefix=SummarizedContentPrefix,
        tool_placeholder=ToolPlaceholder,
        graphiti_tool_block=graphiti_tool_block,
        user_files_section=_user_files_section(user_files),
    )


def _render_user_prompt(
    *,
    question: str,
    enriches: str | None = None,
    code: str | None = None,
    output: str | None = None,
    initiator_agent: str = DefaultInitiatorAgent,
) -> str:
    """Render the Adviser user-turn prompt mirroring question_adviser.tmpl."""
    parts: list[str] = []
    parts.append("<question_adviser_context>")
    parts.append(
        "  <instruction>Generate comprehensive and detailed advice for the "
        "user's question, utilizing the provided context and tools "
        "effectively.</instruction>"
    )
    parts.append("")
    parts.append(f"  <initiator_agent>{initiator_agent}</initiator_agent>")
    parts.append("")
    if enriches:
        parts.append("  <enrichment_data>")
        parts.append(f"  {enriches}")
        parts.append("  </enrichment_data>")
        parts.append("")
    parts.append("  <user_question>")
    parts.append(f"  {question}")
    parts.append("  </user_question>")
    parts.append("")
    if code:
        parts.append("  <code_snippet>")
        parts.append(f"  {code}")
        parts.append("  </code_snippet>")
        parts.append("")
    if output:
        parts.append("  <command_output>")
        parts.append(f"  {output}")
        parts.append("  </command_output>")
        parts.append("")
    parts.append("</question_adviser_context>")
    return "\n".join(parts)


# ── Tool-argument parsing helper ──────────────────────────────────────────────

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


# ── Default JSON-Schema tool definitions ──────────────────────────────────────

def _default_tool_schemas(graphiti_enabled: bool) -> list[dict[str, Any]]:
    """Return the JSON-schema tool definitions exposed to the LLM.

    Mirrors the registry entries for the Adviser's auxiliary retrieval
    tools (``search_in_memory`` / ``graphiti_search``) plus the ``advice``
    barrier.
    """
    schemas: list[dict[str, Any]] = []

    schemas.append({
        "type": "function",
        "function": {
            "name": SearchInMemoryToolName,
            "description": (
                "Search the long-term vector store for stored knowledge, "
                "guides, answers, and code from previous engagements. Use "
                "to ground recommendations in proven past solutions."
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
                "name": GraphitiSearchToolName,
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
            "name": AdviceToolName,
            "description": (
                "Close the Adviser turn with the strategic-guidance write-up. "
                "Barrier tool — terminates the agent chain."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "result": {
                        "type": "string",
                        "description": (
                            "Technical-channel advisory write-up consumed by "
                            "the calling agent (English, consultative tone)."
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


# ── ToolExecutor adapter ──────────────────────────────────────────────────────

class _AdviserToolExecutor:
    """Adapter that exposes retrieval tools + the ``advice`` barrier.

    Implements the :class:`elengenix.agent.crew.base.ToolExecutor` protocol so
    the universal ``perform_agent_chain`` loop can dispatch tool calls. The
    completion tool (``advice``) is a *barrier* — when invoked the executor
    captures the parsed :class:`AdviceResult` into ``captured`` and returns
    an ack string; the loop's ``on_barrier`` callback then terminates the
    chain with :data:`PerformResult.DONE`.
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
        if name == AdviceToolName:
            args = _parse_args(arguments)
            try:
                parsed = AdviceResult.model_validate(args)
            except ValidationError as exc:
                logger.error("advice payload failed validation: %s", exc)
                raise
            self._captured["result"] = parsed
            return "advice successfully processed"

        handler = self._handlers.get(name)
        if handler is None:
            logger.warning("adviser.tool_unknown name=%s", name)
            return (
                f"Error: tool '{name}' is not available in the Adviser chain. "
                f"Available tools: {sorted(self._handlers.keys())} "
                f"plus the '{AdviceToolName}' completion tool."
            )

        try:
            result = (
                handler(arguments, context) if context is not None else handler(arguments)
            )
            if asyncio.iscoroutine(result):
                result = await result
        except Exception as exc:  # noqa: BLE001
            logger.warning("adviser.tool_failed name=%s err=%s", name, exc)
            return f"Error: tool '{name}' raised: {exc}"

        if not isinstance(result, str):
            try:
                result = json.dumps(result, ensure_ascii=False, default=str)
            except (TypeError, ValueError):
                result = str(result)
        return result or ""

    def is_barrier(self, name: str) -> bool:
        """Return True for the ``advice`` completion tool."""
        return name == AdviceToolName

    def get_tools(self) -> list[dict[str, Any]]:
        """Return a shallow-copied list of the tool schemas."""
        return [dict(schema) for schema in self._schemas]


# ── Agent class ───────────────────────────────────────────────────────────────


class Adviser:
    """Strategic guidance & mentor specialist with sub-orchestration.

    The Adviser is the most complex specialist: it performs a two-step
    sub-orchestration:

    1. **Enricher sub-chain** — :meth:`Enricher.run` is invoked FIRST with
       the same ``(question, execution_context)`` payload to gather
       supplementary context (historical memory, knowledge-graph findings,
       filesystem artifacts, URL verification).
    2. **Adviser chain** — the adviser runs the universal
       ``perform_agent_chain`` loop with ``search_in_memory`` and
       ``graphiti_search`` auxiliary tools, terminating when it invokes the
       ``advice`` barrier tool with a ``result`` payload (the technical-
       channel advisory write-up in English).

    The enrichment is folded into the adviser's user prompt as
    ``<enrichment_data>`` per ``question_adviser.tmpl``.

    Ported from PentAGI's ``getAskAdviceHandler`` closure in ``handlers.go``
    which composes ``enricherHandler`` then ``adviserHandler``.
    """

    agent_type: AgentType = AgentType.ADVISER

    def __init__(
        self,
        llm_client: Any,
        *,
        enricher: Enricher | None = None,
        memory: Any = None,
        docker_executor: Any = None,
        governance: Any = None,
        search_providers: Any = None,
        tool_handlers: dict[str, Callable[..., Any]] | None = None,
        language: str = "en",
        docker_image: str = "debian:latest",
        container_ports: str = "",
        graphiti_enabled: bool | None = None,
        user_files: str | None = None,
        max_iterations: int = MAX_LIMITED_ITERATIONS,
    ) -> None:
        """Configure the Adviser.

        Args:
            llm_client: LLM client implementing the :class:`LLMClient`
                protocol. Shared with the Enricher sub-chain.
            enricher: Optional pre-configured :class:`Enricher` instance to
                use as the sub-chain. If ``None``, a default Enricher is
                constructed from the shared dependencies (``llm_client``,
                ``memory``, ``docker_executor``, etc.).
            memory: Memory manager (vector store + Graphiti). Passed through
                to the Enricher and used to auto-wire ``search_in_memory`` /
                ``graphiti_search`` handlers.
            docker_executor: Docker sandbox executor. Passed through to the
                Enricher for filesystem / browser access.
            governance: Optional governance gate (forwarded to the Enricher).
            search_providers: Optional search providers (forwarded).
            tool_handlers: Optional caller-supplied tool handlers that
                OVERRIDE the auto-wired ones (mirrors PrimaryAgent's
                ``tool_handlers`` dict pattern).
            language: Engagement language code (e.g. ``"en"``, ``"th"``).
                Engagement-log entries are emitted in this language.
            docker_image: Docker image the container is running.
            container_ports: Free-form description of OOB attack-infrastructure
                ports allocated to this flow.
            graphiti_enabled: Whether the Graphiti temporal knowledge graph
                is available. When ``None`` (default), inferred from
                ``memory.graphiti_enabled`` (``False`` if absent).
            user_files: Optional listing of attached flow files rendered
                into the ``<task_materials_protocol>`` section.
            max_iterations: Iteration cap for the adviser chain (defaults
                to :data:`MAX_LIMITED_ITERATIONS`).
        """
        self.llm_client = llm_client
        self.memory = memory
        self.docker_executor = docker_executor
        self.governance = governance
        self.search_providers = search_providers
        self.tool_handlers: dict[str, Callable[..., Any]] = dict(tool_handlers or {})

        self.language: str = language
        self.docker_image: str = docker_image
        self.container_ports: str = container_ports
        if graphiti_enabled is None:
            graphiti_enabled = bool(getattr(memory, "graphiti_enabled", False))
        self.graphiti_enabled: bool = bool(graphiti_enabled)
        self.user_files: str | None = user_files
        self.max_iterations: int = max_iterations or MAX_LIMITED_ITERATIONS

        # Reuse the supplied Enricher, or build a default one sharing the
        # same llm_client + dependencies. The Enricher inherits the same
        # language / graphiti_enabled / user_files context as the Adviser
        # so both chains render consistent prompts.
        if enricher is not None:
            self.enricher: Enricher = enricher
        else:
            self.enricher = Enricher(
                llm_client=llm_client,
                docker_executor=docker_executor,
                memory=memory,
                governance=governance,
                search_providers=search_providers,
                tool_handlers=None,  # Enricher auto-wires its own
                max_iterations=MAX_LIMITED_ITERATIONS,
            )
            # Propagate engagement-language + graphiti toggle to the Enricher
            # so its prompt renders identically.
            self.enricher.lang = language
            self.enricher.graphiti_enabled = self.graphiti_enabled

    # ------------------------------------------------------------------ helpers

    def _build_tool_handlers(self) -> dict[str, Callable[..., Any]]:
        """Wire memory tools into a handler dict for the adviser chain.

        The Adviser only exposes ``search_in_memory`` and (when enabled)
        ``graphiti_search`` as auxiliary tools; the ``advice`` barrier is
        handled by the executor directly. Caller-supplied
        ``self.tool_handlers`` override the auto-wired ones.
        """
        handlers: dict[str, Callable[..., Any]] = {}
        mem = self.memory
        if mem is not None:
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

                handlers[SearchInMemoryToolName] = _search_in_memory

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

                    handlers[GraphitiSearchToolName] = _graphiti_search

        if self.tool_handlers:
            handlers.update(self.tool_handlers)
        return handlers

    # ------------------------------------------------------------------- public

    async def run(self, question: str, execution_context: str = "") -> str:
        """Deliver strategic guidance via the Enricher → Adviser sub-chain.

        Implements the canonical PentAGI adviser pattern (the task's
        "CRITICAL for Adviser" contract):

        1. Invoke :meth:`Enricher.run` with the same ``(question,
           execution_context)`` to gather supplementary context.
        2. Fold the enrichment into the adviser's user prompt as
           ``<enrichment_data>`` AND append it to the execution context
           for the adviser's own ``<execution_context>`` section.
        3. Run the adviser chain (:func:`perform_agent_chain`) with
           ``search_in_memory`` and ``graphiti_search`` auxiliary tools;
           the chain terminates when the LLM invokes the ``advice`` barrier
           tool.
        4. Return the captured advisory write-up (technical channel,
           English) to the caller.

        Args:
            question: The calling specialist's question — full context of
                the challenge and what guidance is needed. Written to the
                technical channel (English) inside the user prompt's
                ``<user_question>`` element.
            execution_context: Free-form execution-context blob rendered
                into the system prompt's ``<execution_context>`` section.
                The Enricher's findings are appended to this before being
                fed to the adviser chain.

        Returns:
            The advisory write-up (technical channel, English) captured
            from the ``advice`` completion tool.

        Raises:
            ValueError: If ``question`` is empty.
            RuntimeError: If the adviser chain fails or terminates without
                invoking the ``advice`` completion tool. (Enricher failures
                are non-fatal — they degrade gracefully to an empty
                enrichment so the adviser can still advise on the bare
                question.)
            ValidationError: If the completion-tool payload does not conform
                to :class:`AdviceResult`.
        """
        if not question:
            raise ValueError("Adviser.run requires a non-empty question")

        # ── Step 1: Invoke Enricher to gather supplementary context ───────
        logger.debug(
            "Adviser.run invoking Enricher sub-chain question_len=%d",
            len(question),
        )
        try:
            enricher_context: str = await self.enricher.run(
                question=question,
                execution_context=execution_context,
            )
        except Exception as exc:  # noqa: BLE001
            # Enricher failure is non-fatal: degrade gracefully to an empty
            # enrichment so the adviser can still advise on the bare
            # question.
            logger.warning(
                "Enricher sub-chain failed (%s: %s); proceeding with empty "
                "enrichment",
                type(exc).__name__,
                exc,
            )
            enricher_context = ""

        # ── Step 2: Build adviser context with enrichment folded in ───────
        if enricher_context:
            if execution_context:
                full_context = (
                    f"{execution_context}\n\nEnricher findings:\n"
                    f"{enricher_context}"
                )
            else:
                full_context = f"Enricher findings:\n{enricher_context}"
        else:
            full_context = execution_context

        system_prompt = _render_system_prompt(
            language=self.language,
            docker_image=self.docker_image,
            execution_context=full_context,
            container_ports=self.container_ports,
            graphiti_enabled=self.graphiti_enabled,
            user_files=self.user_files,
        )
        user_prompt = _render_user_prompt(
            question=question,
            enriches=enricher_context or None,
        )

        logger.debug(
            "Adviser.run starting adviser chain enrichment_len=%d "
            "question_len=%d",
            len(enricher_context),
            len(question),
        )

        # ── Step 3: Run adviser chain ─────────────────────────────────────
        chain: list[Message] = [
            Message(role="system", content=system_prompt),
            Message(role="user", content=user_prompt),
        ]

        tool_handlers = self._build_tool_handlers()
        captured: dict[str, Any] = {"result": None}
        tool_schemas = _default_tool_schemas(self.graphiti_enabled)
        executor = _AdviserToolExecutor(
            tool_handlers=tool_handlers,
            captured=captured,
            tool_schemas=tool_schemas,
        )

        def _on_barrier(name: str, args_json: str) -> PerformResult:
            """Adviser has exactly one barrier tool — always DONE."""
            return PerformResult.DONE

        result_state = await perform_agent_chain(
            agent_type=self.agent_type,
            chain=chain,
            llm_client=self.llm_client,
            executor=executor,
            reflector=None,
            summarizer=None,
            max_iterations=self.max_iterations,
            execution_context=full_context,
            on_barrier=_on_barrier,
        )

        result: AdviceResult | None = captured["result"]
        if result is None:
            raise RuntimeError(
                f"Adviser agent chain terminated without calling the "
                f"'{AdviceToolName}' completion tool "
                f"(final_state={result_state.value})"
            )

        advice: str = result.result
        logger.info(
            "Adviser produced %d-byte advisory (enrichment=%d bytes, state=%s, "
            "msg=%r)",
            len(advice),
            len(enricher_context),
            result_state.value,
            result.message[:80],
        )
        return advice


__all__ = [
    "Adviser",
    "AdviceResult",
    "AskAdvice",
    "AdviceToolName",
    "SearchInMemoryToolName",
    "GraphitiSearchToolName",
    "ValidInitiatorAgents",
    "DefaultInitiatorAgent",
    "ADVISER_SYSTEM_PROMPT",
    "_render_system_prompt",
    "_render_user_prompt",
]
