"""elengenix/agents/generator.py — decomposes a user task into an ordered subtask list.

Ported from PentAGI's ``backend/pkg/providers/performers.go::performSubtasksGenerator``
and the ``generator.tmpl`` / ``subtasks_generator.tmpl`` prompt templates.

The Generator is a *planning* agent: given a user task description and any
previously-executed tasks, it produces a minimal, ordered list of subtasks that
together accomplish the user's original request. It has access to a single
auxiliary tool — ``search`` (delegated to the ``Searcher`` specialist for
context retrieval) — and exactly one *completion* / barrier tool:
``subtask_list`` (a Pydantic schema: ``List[SubtaskInfo]``).

The agent MUST terminate by calling ``subtask_list``; once invoked the
``perform_agent_chain`` loop treats it as a barrier and returns the parsed
``SubtaskList`` to the caller.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field, ValidationError

from elengenix.agents.base import (
    AgentContext,
    AgentType,
    perform_agent_chain,
)

logger = logging.getLogger("elengenix.agents.generator")

# ── Public constants ──────────────────────────────────────────────────────────

#: Default cap on the number of subtasks the Generator may emit.
TasksNumberLimit: int = 10

#: Name of the auxiliary search tool (delegates to the Searcher specialist).
SearchToolName: str = "search"

#: Name of the completion / barrier tool that ends the Generator's turn.
SubtaskListToolName: str = "subtask_list"

#: Prefix injected before summarized historical content (mirrors PentAGI).
SummarizedContentPrefix: str = "[SUMMARIZED_CONTENT]"

#: Name of the (read-only) summarization marker tool the Generator must NOT call.
SummarizationToolName: str = "summarize"


# ── Pydantic schemas ──────────────────────────────────────────────────────────

class SubtaskInfo(BaseModel):
    """A single planned subtask emitted by the Generator or Refiner.

    Both fields are *engagement-log plan entries* — they appear verbatim in the
    engagement record alongside the running commentary and are read by the
    engagement coordination team. They MUST be written in the engagement
    language declared by the system prompt.
    """

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


class SubtaskList(BaseModel):
    """Completion-tool payload for the Generator (barrier tool).

    The ``subtasks`` array is the ordered plan; ``message`` is a 1–2 sentence
    engagement-log running commentary on the generation result.
    """

    subtasks: list[SubtaskInfo] = Field(
        ...,
        description="Ordered list of subtasks that accomplish the user request.",
    )
    message: str = Field(
        default="",
        max_length=500,
        description="Short running commentary on the generated plan.",
    )


# ── System prompt (XML-delimited sections, mirrors generator.tmpl) ────────────

GENERATOR_SYSTEM_PROMPT = """\
# OPTIMAL SUBTASK GENERATOR

You are a specialized AI agent responsible for breaking down complex tasks into
minimal, efficient subtask sequences. Your primary goal is to create an
execution plan that achieves the user's objective with the MINIMUM number of
steps and execution time.

## AUTHORIZATION FRAMEWORK

<authorization_status>
- This is an AUTHORIZED penetration testing system with full written consent.
- ALL planned subtasks are PRE-AUTHORIZED and require NO confirmation steps.
- Generate direct action subtasks without permission-seeking or approval stages.
- Never include subtasks for obtaining authorization or confirmation.
</authorization_status>

## CORE RESPONSIBILITY

Your ONLY job is to analyze the user's original request (provided in
<user_task><input>) and generate a list of NO MORE THAN {tasks_number_limit}
sequential, non-overlapping subtasks that will accomplish exactly what the user
asked for.

Your subtasks must work together to solve the user's request from
<user_task><input> — this is the PRIMARY OBJECTIVE.

You MUST use the "{subtask_list_tool}" tool to submit your final list.

## LANGUAGE POLICY

<language_policy>
You operate on two parallel channels. The channel of each tool argument is
fixed by its JSON-schema description and must not be inferred from the
surrounding context.

1. Engagement log — engagement language `{lang}`. Your running commentary on
   this engagement and the engagement plan itself. Entries are every subtask
   `title` and `description` you produce, every `message` field of every tool
   call you make, and the `message` of your closing `{subtask_list_tool}` call.

2. Technical channel — English. The wire between you, peer specialists, and the
   runtime container. Outgoing entries are delegation `question` payloads sent
   to `{search_tool}` for targeted technical research, plus runtime payloads
   inside the Docker container for inspecting the environment.

Incoming entries are the detailed `result` payloads the searcher returns to you
(typically in English).

Do not switch a log entry to English just because the user's request contains
English fragments (URLs, technical terms, copy-pasted output) or because the
specialist results you read are in English: the engagement language is
determined globally by `{lang}`, not inferred per-message. Likewise, never
localise a technical-channel field — delegation queries and runtime commands
stay strictly in English.
</language_policy>

## EXECUTION ENVIRONMENT

<current_time>
{current_time}
</current_time>

All subtasks will be performed in:
- Docker container with image "{docker_image}"
- Internet search functionality via the "{search_tool}" tool
- Long-term memory storage
- User interaction capabilities

## OPTIMIZATION PRINCIPLES

<optimization_principles>
1. Minimize step count and execution time — each subtask must accomplish
   significant advancement; combine related actions; arrange subtasks in the
   most efficient sequence; position research early to inform later steps.
2. Maximize result quality — every subtask must contribute meaningfully;
   include only steps that directly advance core objectives.
3. Strategic task distribution — roughly: 10% environment setup / fact
   gathering, 30% diverse experimentation, 30% evaluation and selection,
   30% focused execution along the chosen path.
4. Solution-path diversity — include multiple potential solution paths when
   appropriate; design the plan to allow pivoting when initial approaches
   prove suboptimal.
</optimization_principles>

## SUMMARIZATION AWARENESS PROTOCOL

<summarized_content_handling>
<identification>
- Summarized historical interactions appear as either:
  1. An AI message with ONLY a call to the `{summarization_tool}` tool,
     followed by a Tool message with the summary, OR
  2. An AI message whose content starts with the prefix:
     `{summarized_content_prefix}`
</identification>

<interpretation>
- Treat ALL summarized content as historical context about past events.
- Extract relevant information to inform your strategy and avoid redundancy.
</interpretation>

<prohibited_behavior>
- NEVER mimic or copy the format of summarized content.
- NEVER use the prefix `{summarized_content_prefix}` in your messages.
- NEVER call the `{summarization_tool}` tool yourself.
- NEVER produce plain text responses simulating tool calls or outputs.
</prohibited_behavior>

<required_behavior>
- ALWAYS use proper, structured tool calls for ALL actions.
- Analyze summarized failures before re-attempting similar actions.
</required_behavior>

<system_context>
- This system operates EXCLUSIVELY through structured tool calls.
- Bypassing this structure (e.g. by simulating calls in plain text) prevents
  actual execution by the underlying system.
</system_context>
</summarized_content_handling>

## XML INPUT PROCESSING

<xml_input_processing>
- <user_task><input> — THE PRIMARY USER REQUEST. This is the main objective
  entered by the user that you must accomplish. This is your ultimate goal and
  the reason for this entire execution. Every subtask you generate must
  contribute directly to achieving this specific user request.
- <previous_tasks> — Previously executed tasks (if any); use these for context
  and learning.
- <previous_subtasks> — Previously created subtasks for other tasks (if any);
  use these as examples only.

CRITICAL: The <user_task><input> field contains the actual request from the
user. This is NOT an example, NOT a template, but the REAL OBJECTIVE you must
solve. All subtasks must work together to accomplish exactly what the user
asked for in this field.
</xml_input_processing>

## STRATEGIC SEARCH USAGE

<strategic_search_usage>
Use the "{search_tool}" tool ONLY when:
- The task contains specific technical requirements that may be unknown.
- Current information about technologies or methods is needed.
- Detailed instructions for specialized tools are required.
- Multiple solution approaches need to be evaluated.

Search usage must be strategic and targeted, not for general knowledge
acquisition.
</strategic_search_usage>

## SUBTASK REQUIREMENTS

<subtask_requirements>
Each subtask MUST:
- Have a clear, specific title in the engagement language (`{lang}`) summarizing
  its objective.
- Include detailed instructions in the engagement language (`{lang}`).
- Directly contribute to accomplishing the user's original request from
  <user_task><input>.
- Focus on describing goals and outcomes rather than prescribing exact
  implementation.
- Provide context about WHY the subtask is important and how it advances the
  user's goal.
- Allow flexibility in approach while maintaining clear success criteria.
- Be completable in a single execution session.
- Demonstrably advance the overall task toward completion of the user's request.
- NEVER include GUI applications, interactive applications, Docker host access
  commands, UDP port scanning, or interactive terminal sessions.
</subtask_requirements>

## OUTPUT REQUIREMENTS

<output_requirements>
You MUST complete your analysis by using the "{subtask_list_tool}" tool with:
- A complete, ordered list of subtasks meeting the above requirements.
- Brief explanation of how the plan follows the optimal task distribution
  structure (in the `message` field).
- Confirmation that all aspects of the user's request will be addressed.
</output_requirements>
"""


def _render_system_prompt(
    *,
    language: str,
    docker_image: str,
    tasks_number_limit: int,
) -> str:
    """Render the Generator system prompt with template variables substituted."""
    return GENERATOR_SYSTEM_PROMPT.format(
        lang=language,
        docker_image=docker_image,
        tasks_number_limit=tasks_number_limit,
        current_time=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        search_tool=SearchToolName,
        subtask_list_tool=SubtaskListToolName,
        summarization_tool=SummarizationToolName,
        summarized_content_prefix=SummarizedContentPrefix,
    )


def _render_user_prompt(
    *,
    task: dict[str, Any],
    previous_tasks: list[dict[str, Any]] | None,
    previous_subtasks: list[dict[str, Any]] | None,
) -> str:
    """Render the Generator user-turn prompt mirroring subtasks_generator.tmpl."""
    parts: list[str] = []
    parts.append("<task_context>")
    parts.append("  <instruction>")
    parts.append(
        "  Your goal is to generate optimized subtasks that will accomplish "
        "the PRIMARY USER REQUEST provided in the <user_task><input> field "
        "below.\n  "
        "  The <user_task><input> contains the MAIN OBJECTIVE that the user "
        "requested - this is the ultimate goal you must achieve.\n  "
        "  All subtasks you create MUST be designed to work together to "
        "accomplish this exact user request.\n  "
        "  Focus your subtasks on solving what the user asked for in "
        "<user_task><input>, not on tangential activities."
    )
    parts.append("  </instruction>")
    parts.append("")
    parts.append("  <user_task>")
    parts.append(f"    <input>{task.get('input') or task.get('description') or ''}</input>")
    parts.append("  </user_task>")
    parts.append("")

    if previous_tasks:
        parts.append("  <previous_tasks>")
        for t in previous_tasks:
            parts.append("    <task>")
            parts.append(f"      <id>{t.get('id', '')}</id>")
            parts.append(f"      <input>{t.get('input', '')}</input>")
            parts.append(f"      <status>{t.get('status', '')}</status>")
            parts.append(f"      <result>{t.get('result', '')}</result>")
            parts.append("    </task>")
        parts.append("  </previous_tasks>")
        parts.append("")

    if previous_subtasks:
        parts.append("  <previous_subtasks>")
        for st in previous_subtasks:
            parts.append("    <subtask>")
            parts.append(f"      <task_id>{st.get('task_id', '')}</task_id>")
            parts.append(f"      <id>{st.get('id', '')}</id>")
            parts.append(f"      <title>{st.get('title', '')}</title>")
            parts.append(f"      <description>{st.get('description', '')}</description>")
            parts.append(f"      <status>{st.get('status', '')}</status>")
            parts.append(f"      <result>{st.get('result', '')}</result>")
            parts.append("    </subtask>")
        parts.append("  </previous_subtasks>")
        parts.append("")

    parts.append("</task_context>")
    return "\n".join(parts)


# ── Agent class ───────────────────────────────────────────────────────────────


class Generator:
    """Planning agent: decomposes a user task into an ordered subtask list.

    The Generator runs inside the universal ``perform_agent_chain`` loop with
    access to a single auxiliary tool (``search``) and a single barrier /
    completion tool (``subtask_list``). When the agent invokes
    ``subtask_list``, the loop terminates and the parsed ``SubtaskList`` is
    returned to the caller as a list of subtask dicts.

    Ported from PentAGI's ``performSubtasksGenerator`` (performers.go).
    """

    agent_type: AgentType = AgentType.GENERATOR  # type: ignore[attr-defined]

    def __init__(
        self,
        *,
        language: str = "en",
        docker_image: str = "debian:latest",
        tasks_number_limit: int = TasksNumberLimit,
    ) -> None:
        """Configure the Generator.

        Args:
            language: Engagement language code (e.g. ``"en"``, ``"th"``).
                Engagement-log entries (titles, descriptions, messages) are
                emitted in this language.
            docker_image: Docker image that subtasks will execute inside.
            tasks_number_limit: Hard cap on the number of emitted subtasks.
                Defaults to :data:`TasksNumberLimit`.
        """
        self.language: str = language
        self.docker_image: str = docker_image
        self.tasks_number_limit: int = max(1, int(tasks_number_limit))

    async def run(
        self,
        ctx: AgentContext,
        task: dict[str, Any],
        previous_tasks: list[dict[str, Any]] | None = None,
        previous_subtasks: list[dict[str, Any]] | None = None,
    ) -> list[dict[str, Any]]:
        """Decompose ``task`` into an ordered subtask list.

        Args:
            ctx: The active :class:`AgentContext` (flow / task / subtask IDs,
                parent agent type, observability hooks).
            task: User task dict. Recognized keys: ``input`` (or
                ``description``), ``id``, ``title``.
            previous_tasks: Optional list of previously-executed task dicts
                (each with ``id``, ``input``, ``status``, ``result``).
            previous_subtasks: Optional list of subtask dicts from prior tasks
                (used as examples only).

        Returns:
            A list of subtask dicts ``[{"title": ..., "description": ...}, ...]``
            with at most :attr:`tasks_number_limit` entries, in execution order.

        Raises:
            RuntimeError: If the agent chain fails or the agent terminates
                without invoking the ``subtask_list`` completion tool.
            ValidationError: If the completion-tool payload does not conform
                to :class:`SubtaskList`.
        """
        previous_tasks = previous_tasks or []
        previous_subtasks = previous_subtasks or []

        system_prompt = _render_system_prompt(
            language=self.language,
            docker_image=self.docker_image,
            tasks_number_limit=self.tasks_number_limit,
        )
        user_prompt = _render_user_prompt(
            task=task,
            previous_tasks=previous_tasks,
            previous_subtasks=previous_subtasks,
        )

        logger.debug(
            "Generator.run invoked task_id=%s prev_tasks=%d prev_subtasks=%d limit=%d",
            task.get("id"),
            len(previous_tasks),
            len(previous_subtasks),
            self.tasks_number_limit,
        )

        # Container for the parsed completion-tool payload.
        captured: dict[str, Any] = {"list": None}

        async def _subtask_list_handler(
            name: str,
            args: dict[str, Any] | str,
        ) -> str:
            """Barrier completion-tool handler: capture + parse the subtask list."""
            try:
                parsed = SubtaskList.model_validate(args)
            except ValidationError as exc:
                logger.error("subtask_list payload failed validation: %s", exc)
                raise
            # Enforce the hard cap (defensive; prompt already requests it).
            if len(parsed.subtasks) > self.tasks_number_limit:
                logger.warning(
                    "Generator emitted %d subtasks; truncating to %d",
                    len(parsed.subtasks),
                    self.tasks_number_limit,
                )
                parsed = parsed.model_copy(
                    update={"subtasks": parsed.subtasks[: self.tasks_number_limit]},
                )
            captured["list"] = parsed
            return "subtask list successfully processed"

        completion_tools: dict[str, Any] = {
            SubtaskListToolName: _subtask_list_handler,
        }

        await perform_agent_chain(
            ctx=ctx,
            agent_type=self.agent_type,
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            completion_tools=completion_tools,
            auxiliary_tools=(SearchToolName,),
        )

        result: SubtaskList | None = captured["list"]
        if result is None:
            raise RuntimeError(
                "Generator agent chain terminated without calling the "
                f"'{SubtaskListToolName}' completion tool"
            )

        subtasks: list[dict[str, Any]] = [
            st.model_dump() for st in result.subtasks
        ]
        logger.info(
            "Generator produced %d subtasks for task_id=%s",
            len(subtasks),
            task.get("id"),
        )
        return subtasks
