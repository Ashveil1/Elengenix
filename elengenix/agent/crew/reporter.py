"""elengenix/agents/reporter.py — synthesizes the final task success/failure report.

Ported from PentAGI's
``backend/pkg/providers/performers.go::performTaskResultReporter`` and the
``reporter.tmpl`` / ``task_reporter.tmpl`` prompt templates.

The Reporter is a *reporting* agent invoked once at the end of a task. Given
the user task, the previously-executed tasks, the completed subtasks (with
results and statuses), any still-planned subtasks, the execution state
snapshot, and the execution logs, it produces a final assessment: a boolean
``success`` flag, a detailed write-up (``result``, ≤4000 chars), and a concise
recap (``message``, ≤500 chars).

The Reporter has access to ONE tool — ``search_in_memory`` (vector-store
retrieval for relevant context from the engagement memory) — and exactly one
completion / barrier tool: ``report_result`` (a Pydantic schema:
:class:`TaskResult`).

CRITICAL: ``report_result`` is a *barrier* tool. Once the agent invokes it,
the universal ``perform_agent_chain`` loop MUST terminate — the agent cannot
continue past it. This module enforces that by returning the parsed
:class:`TaskResult` to the caller immediately after the barrier is hit.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field, ValidationError

from elengenix.agent.crew.base import (
    AgentContext,
    AgentType,
    perform_agent_chain,
)

logger = logging.getLogger("elengenix.agent.crew.reporter")

# ── Public constants ──────────────────────────────────────────────────────────

#: Hard cap on the total length of the ``result`` write-up (characters).
ReportResultLengthLimit: int = 4000

#: Hard cap on the total length of the ``message`` recap (characters).
ReportMessageLengthLimit: int = 500

#: Name of the auxiliary in-memory search tool (vector-store retrieval).
SearchInMemoryToolName: str = "search_in_memory"

#: Name of the completion / barrier tool that ends the Reporter's turn.
ReportResultToolName: str = "report_result"

#: Prefix injected before summarized historical content (mirrors PentAGI).
SummarizedContentPrefix: str = "[SUMMARIZED_CONTENT]"

#: Name of the (read-only) summarization marker tool the Reporter must NOT call.
SummarizationToolName: str = "summarize"


# ── Pydantic schemas ──────────────────────────────────────────────────────────

class TaskResult(BaseModel):
    """Completion-tool payload for the Reporter (barrier tool).

    All three fields are *engagement-log closing entries*: the engagement
    coordination team reads them in the engagement language declared by the
    system prompt. Technical identifiers (CVEs, CLI tool names, IPs, ports,
    file paths, code identifiers) must be preserved verbatim — they are not
    translatable.
    """

    success: bool = Field(
        ...,
        description=(
            "True if the task was executed successfully and its objective "
            "was reached. Form your own independent judgment regardless of "
            "individual subtask status claims."
        ),
    )
    result: str = Field(
        ...,
        max_length=4000,
        description=(
            "Engagement-log closing entry — fully detailed write-up of the "
            "task outcome (what was achieved or why it failed), grounded in "
            "concrete evidence from execution logs. ≤4000 chars."
        ),
    )
    message: str = Field(
        ...,
        max_length=500,
        description=(
            "Engagement-log closing summary — a concise 1–2 sentence recap "
            "of the outcome and the path taken to reach the goal. ≤500 chars."
        ),
    )


# ── System prompt (XML-delimited sections, mirrors reporter.tmpl) ─────────────

REPORTER_SYSTEM_PROMPT = """\
# TASK EXECUTION EVALUATOR AND REPORTER

You are a specialized AI agent responsible for performing critical analysis of
task execution results and delivering concise, accurate assessment reports.
Your expertise lies in determining whether the executed work truly addresses
the user's original requirements.

## CORE RESPONSIBILITY

Your ONLY job is to thoroughly evaluate task execution results against the
original user requirements, determining if the objectives were genuinely
achieved. You MUST use the "{report_result_tool}" tool to deliver your final
assessment report of no more than {result_length_limit} characters.

## LANGUAGE POLICY

<language_policy>
You are the closing scribe of the engagement: your sole output is the
engagement-log closing entry. Unlike other agents, you do not call any tool on
the technical channel — you only consume technical-channel material that was
produced earlier in the engagement (specialist `result` payloads, terminal
output, search excerpts, code excerpts, stored knowledge), all of which is in
English by design.

1. Engagement log — engagement language `{lang}` (your only output channel).
   Both fields of your closing `{report_result_tool}` call are engagement-log
   entries: `result` is the full assessment write-up, `message` is the concise
   recap. The engagement coordination team reads the engagement record in
   `{lang}`, fixed for the whole engagement.

2. Technical channel — English (incoming context only). The execution logs you
   analyse arrive on this channel: specialist agents emit detailed `result`
   payloads in English by design, and runtime commands, code, and stored
   knowledge are likewise English. Your job is to translate the relevant prose
   into `{lang}` for the engagement record while preserving technical
   identifiers (CVEs, CLI tool names, IPs, ports, file paths, code
   identifiers) literally — those are not translatable.

Do not switch the closing entry to English just because the execution logs you
analyse are in English: the engagement language is determined globally by
`{lang}` and is the language of the engagement record.
</language_policy>

## EVALUATION METHODOLOGY

<evaluation_methodology>
1. Comprehensive understanding — analyze the original user task to identify
   explicit and implicit requirements; review all completed subtasks, their
   descriptions, and execution results; examine execution logs to understand
   the actual implementation approach; identify any remaining planned
   subtasks that indicate incomplete work.

2. Results validation — critically assess whether each subtask's claimed
   "success" truly addressed its objectives; look for evidence of proper
   implementation rather than just claims of completion; identify any
   technical or logical gaps between what was requested and what was
   delivered; evaluate if failed subtasks were critical to overall task
   success.

3. Independent judgment — form your own conclusion about task success
   regardless of subtask status claims; consider the actual functional
   requirements rather than just technical completion; determine if the core
   user need was genuinely addressed, even if implementation differs;
   identify key information the user should know about the execution outcomes.
</evaluation_methodology>

## SUMMARIZATION AWARENESS PROTOCOL

<summarized_content_handling>
<identification>
- Summarized historical interactions appear in TWO distinct forms:
  1. Tool Call Summary: an AI message containing ONLY a call to the
     `{summarization_tool}` tool, immediately followed by a Tool message with
     the summary.
  2. Prefixed Summary: an AI message whose text content starts EXACTLY with
     the prefix `{summarized_content_prefix}`.
</identification>

<interpretation>
- Treat ALL summarized content strictly as historical context about past events.
- Extract relevant information to inform your current strategy.
</interpretation>

<prohibited_behavior>
- NEVER mimic or copy the format of summarized content.
- NEVER use the prefix `{summarized_content_prefix}` in your own messages.
- NEVER call the `{summarization_tool}` tool yourself.
- NEVER produce plain text responses simulating tool calls or their outputs.
</prohibited_behavior>

<required_behavior>
- ALWAYS use proper, structured tool calls for ALL actions you perform.
- Interpret the information derived from summaries to guide your strategy.
- Analyze summarized failures before re-attempting similar actions.
</required_behavior>

<system_context>
- This system operates EXCLUSIVELY through structured tool calls.
- Bypassing this structure prevents actual execution by the underlying system.
</system_context>
</summarized_content_handling>

## XML INPUT PROCESSING

<xml_input_processing>
The task report context is provided in XML format with the following
structure:
- <user_task> — the original task request from the user.
- <previous_tasks> — context from prior related tasks (if available).
- <completed_subtasks> — executed subtasks with their results and statuses.
- <planned_subtasks> — remaining subtasks if any (absence indicates
  completion).
- <execution_state> — current execution state snapshot (if provided).
- <execution_logs> — detailed logs of actions performed during execution.

Analyze all elements to form a complete picture of what was accomplished
versus what was required.
</xml_input_processing>

## REPORT FORMULATION CRITERIA

<report_criteria>
Your final report MUST:
- Start with a clear SUCCESS or FAILURE assessment of the overall task.
- Provide a concise (1-2 sentence) summary of the key accomplishment or
  shortfall.
- Include only the most critical details about what was/wasn't completed.
- Highlight any unexpected or particularly valuable outcomes.
- Indicate any remaining steps if the task is incomplete.
- Be written in the engagement language (`{lang}`) — both `result` and
  `message` are engagement-log closing entries; translate any English content
  from execution logs into `{lang}` while preserving technical identifiers
  (CVEs, CLI tool names, IPs, ports, file paths, code identifiers) verbatim.
- Never exceed {result_length_limit} characters in total length of `result`.
</report_criteria>

## CRITICAL EVALUATION PRINCIPLES

<evaluation_principles>
1. Actual results over process — focus on what was actually achieved, not just
   what steps were taken.
2. User intent over technical details — prioritize meeting the user's actual
   need over technical correctness.
3. Functional over formal completion — a task is only successful if it
   produces the required functional outcome.
4. Evidence-based assessment — base your judgment on concrete evidence in the
   execution logs.
5. Objective identification of gaps — clearly identify what remains unfinished
   or problematic.
</evaluation_principles>

## OUTPUT REQUIREMENTS

<output_requirements>
You MUST complete your evaluation by using the `{report_result_tool}` tool
with:
- The `success` field — boolean true/false reflecting your independent
  judgment of overall task outcome.
- The `result` field — detailed assessment grounded in concrete evidence from
  execution logs; engagement-log closing entry written in the engagement
  language (`{lang}`), translated from English source material while
  preserving technical identifiers verbatim.
- The `message` field — concise recap of the key outcome; engagement-log
  closing summary written in the engagement language (`{lang}`).

This is a BARRIER tool: once you call `{report_result_tool}` your turn ends
immediately — you cannot continue past it. Make sure your assessment is
complete before calling it.
</output_requirements>
"""


def _render_system_prompt(
    *,
    language: str,
    result_length_limit: int,
) -> str:
    """Render the Reporter system prompt with template variables substituted."""
    return REPORTER_SYSTEM_PROMPT.format(
        lang=language,
        result_length_limit=result_length_limit,
        current_time=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        report_result_tool=ReportResultToolName,
        search_in_memory_tool=SearchInMemoryToolName,
        summarization_tool=SummarizationToolName,
        summarized_content_prefix=SummarizedContentPrefix,
    )


def _render_user_prompt(
    *,
    task: dict[str, Any],
    previous_tasks: list[dict[str, Any]] | None,
    completed_subtasks: list[dict[str, Any]] | None,
    planned_subtasks: list[dict[str, Any]] | None,
    execution_state: str | None,
    execution_logs: str | None,
) -> str:
    """Render the Reporter user-turn prompt mirroring task_reporter.tmpl."""
    parts: list[str] = []
    parts.append("<task_report_context>")
    parts.append(
        "  <instruction>Generate a comprehensive evaluation report for the "
        "user's task</instruction>"
    )
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

    if completed_subtasks:
        parts.append("  <completed_subtasks>")
        for st in completed_subtasks:
            parts.append("    <subtask>")
            parts.append(f"      <id>{st.get('id', '')}</id>")
            parts.append(f"      <title>{st.get('title', '')}</title>")
            parts.append(f"      <description>{st.get('description', '')}</description>")
            parts.append(f"      <status>{st.get('status', '')}</status>")
            parts.append(f"      <result>{st.get('result', '')}</result>")
            parts.append("    </subtask>")
        parts.append("  </completed_subtasks>")
        parts.append("")

    if planned_subtasks:
        parts.append("  <planned_subtasks>")
        for st in planned_subtasks:
            parts.append("    <subtask>")
            parts.append(f"      <id>{st.get('id', '')}</id>")
            parts.append(f"      <title>{st.get('title', '')}</title>")
            parts.append(f"      <description>{st.get('description', '')}</description>")
            parts.append("    </subtask>")
        parts.append("  </planned_subtasks>")
    else:
        parts.append('  <planned_subtasks status="empty">')
        parts.append(
            "    <message>All subtasks have been completed. Review their "
            "statuses and results to prepare your report.</message>"
        )
        parts.append("  </planned_subtasks>")
    parts.append("")

    if execution_state:
        parts.append("  <execution_state>")
        parts.append(f"  {execution_state}")
        parts.append("  </execution_state>")
        parts.append("")

    if execution_logs:
        parts.append("  <execution_logs>")
        parts.append(f"  {execution_logs}")
        parts.append("  </execution_logs>")
        parts.append("")

    parts.append("</task_report_context>")
    return "\n".join(parts)


# ── Agent class ───────────────────────────────────────────────────────────────


class Reporter:
    """Reporting agent: synthesizes the final task success/failure report.

    The Reporter runs inside the universal ``perform_agent_chain`` loop with
    access to a single auxiliary tool (``search_in_memory``) and a single
    BARRIER / completion tool (``report_result``). When the agent invokes
    ``report_result``, the loop MUST terminate immediately — the agent cannot
    continue past it. The parsed :class:`TaskResult` is returned to the caller
    as a dict.

    Ported from PentAGI's ``performTaskResultReporter`` (performers.go).
    """

    agent_type: AgentType = AgentType.REPORTER  # type: ignore[attr-defined]

    def __init__(
        self,
        *,
        language: str = "en",
        result_length_limit: int = ReportResultLengthLimit,
    ) -> None:
        """Configure the Reporter.

        Args:
            language: Engagement language code.
            result_length_limit: Hard cap on the ``result`` write-up length
                (characters). Defaults to :data:`ReportResultLengthLimit`.
        """
        self.language: str = language
        self.result_length_limit: int = max(1, int(result_length_limit))

    async def run(
        self,
        ctx: AgentContext,
        task: dict[str, Any],
        previous_tasks: list[dict[str, Any]] | None = None,
        completed_subtasks: list[dict[str, Any]] | None = None,
        planned_subtasks: list[dict[str, Any]] | None = None,
        execution_state: str | None = None,
        execution_logs: str | None = None,
    ) -> dict[str, Any]:
        """Synthesize the final task report (barrier termination).

        Args:
            ctx: The active :class:`AgentContext`.
            task: User task dict (``input`` or ``description``, ``id``).
            previous_tasks: Optional previously-executed task dicts.
            completed_subtasks: Subtasks already executed, each with ``id``,
                ``title``, ``description``, ``status``, ``result``.
            planned_subtasks: Subtasks still pending (indicates incomplete
                work). ``None`` or empty means all subtasks completed.
            execution_state: Optional free-form execution-state snapshot
                rendered verbatim into ``<execution_state>``.
            execution_logs: Optional free-form execution-log blob rendered
                verbatim into ``<execution_logs>``.

        Returns:
            A dict with the shape ``{"success": bool, "result": str,
            "message": str}`` conforming to :class:`TaskResult`.

        Raises:
            RuntimeError: If the agent chain fails or terminates without
                invoking the ``report_result`` barrier tool (the Reporter
                MUST end its turn by calling ``report_result``).
            ValidationError: If the completion-tool payload does not conform
                to :class:`TaskResult`.
        """
        previous_tasks = previous_tasks or []
        completed_subtasks = completed_subtasks or []
        planned_subtasks = planned_subtasks or []

        system_prompt = _render_system_prompt(
            language=self.language,
            result_length_limit=self.result_length_limit,
        )
        user_prompt = _render_user_prompt(
            task=task,
            previous_tasks=previous_tasks,
            completed_subtasks=completed_subtasks,
            planned_subtasks=planned_subtasks,
            execution_state=execution_state,
            execution_logs=execution_logs,
        )

        logger.debug(
            "Reporter.run invoked task_id=%s prev=%d completed=%d planned=%d",
            task.get("id"),
            len(previous_tasks),
            len(completed_subtasks),
            len(planned_subtasks),
        )

        captured: dict[str, Any] = {"result": None}

        async def _report_result_handler(
            name: str,
            args: dict[str, Any] | str,
        ) -> str:
            """Barrier completion-tool handler: capture + parse the TaskResult.

            This is a BARRIER tool — once invoked, the agent chain MUST
            terminate. We return the acknowledgment string and let the
            outer :func:`perform_agent_chain` exit; the parsed result is
            then retrieved from ``captured``.
            """
            try:
                parsed = TaskResult.model_validate(args)
            except ValidationError as exc:
                logger.error("report_result payload failed validation: %s", exc)
                raise
            captured["result"] = parsed
            return "report result successfully processed"

        completion_tools: dict[str, Any] = {
            ReportResultToolName: _report_result_handler,
        }

        await perform_agent_chain(
            ctx=ctx,
            agent_type=self.agent_type,
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            completion_tools=completion_tools,
            auxiliary_tools=(SearchInMemoryToolName,),
            barrier_tools=(ReportResultToolName,),
        )

        result: TaskResult | None = captured["result"]
        if result is None:
            raise RuntimeError(
                "Reporter agent chain terminated without calling the "
                f"'{ReportResultToolName}' barrier tool"
            )

        logger.info(
            "Reporter produced result task_id=%s success=%s result_len=%d",
            task.get("id"),
            result.success,
            len(result.result),
        )
        return result.model_dump()
