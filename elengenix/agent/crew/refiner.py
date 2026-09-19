"""elengenix/agents/refiner.py — delta-patches the planned subtask list.

Ported from PentAGI's ``backend/pkg/providers/performers.go::performSubtasksRefiner``
and the ``refiner.tmpl`` / ``subtasks_refiner.tmpl`` prompt templates.

The Refiner is a *planning* agent invoked after each subtask completes. Given
the original user task, the list of completed subtasks (with their results and
statuses), the still-pending planned subtasks, and the current execution state
/ logs, it emits a delta-patch of operations (``add`` / ``remove`` / ``modify``
/ ``reorder``) that adapts the remaining plan to maximise efficiency and
minimise completion time.

It has access to one auxiliary tool — ``search`` (delegated to the
``Searcher`` specialist for context retrieval) — and exactly one completion /
barrier tool: ``subtask_patch`` (a Pydantic schema:
``SubtaskPatch`` containing a list of :class:`SubtaskPatchOp`).

When the agent invokes ``subtask_patch`` the universal
``perform_agent_chain`` loop terminates and the parsed patch is returned to
the caller. The caller is then responsible for applying the patch to the
in-memory planned-subtask list (mirrors PentAGI's ``applySubtaskOperations``).
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Literal

from pydantic import BaseModel, Field, ValidationError, model_validator

from elengenix.agent.crew.base import (
    AgentContext,
    AgentType,
    perform_agent_chain,
)
from elengenix.agent.crew.generator import SubtaskInfo

logger = logging.getLogger("elengenix.agent.crew.refiner")

# ── Public constants ──────────────────────────────────────────────────────────

#: Default cap on the number of subtasks after refinement.
TasksNumberLimit: int = 10

#: Name of the auxiliary search tool (delegates to the Searcher specialist).
SearchToolName: str = "search"

#: Name of the completion / barrier tool that ends the Refiner's turn.
SubtaskPatchToolName: str = "subtask_patch"

#: Prefix injected before summarized historical content (mirrors PentAGI).
SummarizedContentPrefix: str = "[SUMMARIZED_CONTENT]"

#: Name of the (read-only) summarization marker tool the Refiner must NOT call.
SummarizationToolName: str = "summarize"


# ── Pydantic schemas ──────────────────────────────────────────────────────────

class SubtaskPatchOp(BaseModel):
    """A single delta operation on the planned-subtask list.

    Operation semantics:

    - ``add``     : insert a new subtask. ``subtask`` MUST be set.
                    ``index`` is the position to insert at (0 = beginning);
                    if ``None`` the subtask is appended.
    - ``remove``  : delete an existing subtask. ``index`` MUST identify it.
    - ``modify``  : update title and/or description of an existing subtask.
                    ``index`` MUST be set; ``subtask`` carries the new fields
                    (only the non-``None`` fields are applied).
    - ``reorder`` : move an existing subtask to a new position.
                    ``index`` is the subtask to move; ``new_order`` is a list
                    of indices describing the desired new ordering of the
                    *affected* subtasks (caller resolves absolute positions).
    """

    op: Literal["add", "remove", "modify", "reorder"] = Field(
        ...,
        description=(
            "Operation type: 'add' creates a new subtask, 'remove' deletes a "
            "subtask by index, 'modify' updates title/description of an "
            "existing subtask, 'reorder' moves a subtask to a different "
            "position."
        ),
    )
    index: int | None = Field(
        default=None,
        ge=0,
        description=(
            "Index of the existing subtask to operate on (required for "
            "remove / modify / reorder; ignored for add when new_order is "
            "provided)."
        ),
    )
    subtask: SubtaskInfo | None = Field(
        default=None,
        description=(
            "New subtask payload (required for add, optional for modify)."
        ),
    )
    new_order: list[int] | None = Field(
        default=None,
        description=(
            "For 'reorder': list of indices describing the desired new "
            "ordering of the affected subtasks."
        ),
    )

    @model_validator(mode="after")
    def _validate_op_fields(self) -> "SubtaskPatchOp":
        """Enforce per-op required-field constraints."""
        if self.op == "add" and self.subtask is None:
            raise ValueError("'add' operation requires 'subtask' to be set")
        if self.op == "remove" and self.index is None:
            raise ValueError("'remove' operation requires 'index' to be set")
        if self.op == "modify" and self.index is None:
            raise ValueError("'modify' operation requires 'index' to be set")
        if self.op == "reorder":
            if self.index is None and not self.new_order:
                raise ValueError(
                    "'reorder' operation requires either 'index' (single move) "
                    "or 'new_order' (full re-ordering)"
                )
        return self


class SubtaskPatch(BaseModel):
    """Completion-tool payload for the Refiner (barrier tool).

    An empty ``operations`` array means "no changes needed — the current plan
    is optimal". A non-empty array is applied in order to the planned-subtask
    list by the caller.
    """

    operations: list[SubtaskPatchOp] = Field(
        default_factory=list,
        description=(
            "Ordered list of delta operations. Empty array means no changes "
            "needed."
        ),
    )
    message: str = Field(
        default="",
        max_length=500,
        description=(
            "1–2 sentence engagement-log running commentary on the changes "
            "made and the justification."
        ),
    )


# ── System prompt (XML-delimited sections, mirrors refiner.tmpl) ──────────────

REFINER_SYSTEM_PROMPT = """\
# SUBTASK PLAN OPTIMIZER

You are a specialized AI agent responsible for dynamically refining and
optimizing task execution plans. Your primary goal is to analyze execution
results and adapt the remaining subtasks to achieve maximum efficiency and
minimal completion time.

## AUTHORIZATION FRAMEWORK

<authorization_status>
- This is an AUTHORIZED penetration testing system with full written consent.
- ALL planned and refined subtasks are PRE-AUTHORIZED.
- Generate direct action subtasks without permission-seeking or approval stages.
- Never include subtasks for obtaining authorization or confirmation.
</authorization_status>

## CORE RESPONSIBILITY

Your ONLY job is to analyze the results of completed subtasks and the current
plan, then submit OPERATIONS to modify the remaining subtask list to better
accomplish the user's original request (provided in <user_task><input>).

Your refinements must optimize the plan to solve the user's request from
<user_task><input> — this is the PRIMARY OBJECTIVE.

Maximum {tasks_number_limit} planned subtasks after modifications. You MUST use
the "{subtask_patch_tool}" tool to submit your refinement operations.

## LANGUAGE POLICY

<language_policy>
You operate on two parallel channels. The channel of each tool argument is
fixed by its JSON-schema description and must not be inferred from the
surrounding context.

1. Engagement log — engagement language `{lang}`. Your running commentary on
   this engagement and the engagement plan delta itself. Entries are every
   operation `title` and `description` you emit in add/modify ops, every
   `message` field of every tool call you make, and the `message` of your
   closing `{subtask_patch_tool}` call.

2. Technical channel — English. Outgoing entries are delegation `question`
   payloads sent to `{search_tool}` for targeted technical research and to the
   memorist for historical-context retrieval, plus runtime payloads inside the
   Docker container for verifying state or extracting details.

Incoming entries are the detailed `result` payloads the searcher and memorist
return to you, plus the completed-subtask `result` fields you read from
execution history (typically in English from coder, pentester, searcher,
memorist).

Do not switch a log entry to English just because the completed subtask
results you read happen to be in English: the engagement language is
determined globally by `{lang}`, not inferred per-message.
</language_policy>

## EXECUTION ENVIRONMENT

<current_time>
{current_time}
</current_time>

All subtasks are performed in:
- Docker container with image "{docker_image}"
- Internet search functionality via the "{search_tool}" tool
- Long-term memory storage
- User interaction capabilities

## OPTIMIZATION PRINCIPLES

<optimization_principles>
1. Results-based adaptation — analyze completed subtask results; assess progress
   toward the user's original request; identify new information that impacts the
   remaining plan; maintain convergence toward the user's goal.
2. Subtask reduction & consolidation — remove subtasks rendered unnecessary by
   previous results; combine related subtasks; eliminate redundant actions.
3. Strategic gap filling — add new subtasks to address newly discovered
   problems or obstacles; include targeted information gathering ONLY when
   critical for next steps; create recovery paths for partial failures.
4. Overall step minimization — continually reduce the total number of remaining
   subtasks; prioritize the highest-impact work; seek the shortest viable path
   to accomplishing the user's goal.
5. Solution diversity & experimentation — avoid repeating failed approaches
   with minor variations; generate diverse alternatives when initial attempts
   fail; balance exploration with exploitation of proven techniques.
</optimization_principles>

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
- Extract relevant information to inform your current strategy and avoid
  redundant actions.
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
The refinement context is provided in XML format:
- <user_task><input> — THE PRIMARY USER REQUEST. Use completed subtask results
  to optimize the remaining plan to achieve this request more efficiently.
- <completed_subtasks> — Subtasks that have been executed with results and
  status. Analyze these to understand what worked and what didn't.
- <planned_subtasks> — Subtasks remaining to be executed. Optimize these.
- <previous_tasks> — Prior tasks that may provide context (use for learning
  only).
- <execution_state> — Current execution state snapshot (if provided).
- <execution_logs> — Detailed execution logs (if provided).

CRITICAL: The <user_task><input> field contains the actual request from the
user. All refinement operations must optimize the plan to accomplish exactly
what the user asked for.
</xml_input_processing>

## REFINEMENT RULES

<refinement_rules>
1. Failed subtask handling — conduct thorough failure analysis; distinguish
   between failures solvable by reformulation versus fundamental blockers;
   after 2 failed attempts with similar approaches, explore completely
   different solution paths.

2. Failure analysis framework — categorize failures as Technical, Environmental,
   Conceptual, or External:
   - Technical/environmental → replan with specific adjustments.
   - Conceptual → pivot to entirely different approaches.
   - External → acknowledge limitations and plan alternative objectives.

3. Subtask count management — total planned subtasks must not exceed
   {tasks_number_limit}. When approaching the limit, prioritize the most
   critical remaining work; consolidate lower-priority subtasks when necessary.

4. Task completion detection — if the user's original request has been achieved
   or all essential subtasks completed successfully, remove all remaining
   planned subtasks (empty result). If further progress is impossible due to
   insurmountable obstacles, also remove all remaining subtasks.

5. Progressive convergence planning — each subtask must bring the solution
   measurably closer to completion; structure the plan to follow the optimal
   distribution: ~10% setup, ~30% experimentation, ~30% evaluation, ~30%
   focused execution.
</refinement_rules>

## STRATEGIC SEARCH USAGE

<strategic_search_usage>
Use the "{search_tool}" tool ONLY when:
- Previous subtask results revealed new technical requirements.
- Specific information is needed to adjust the plan effectively.
- Unexpected complications require additional knowledge to address.
- A fundamentally different approach needs to be explored after failures.
</strategic_search_usage>

## REFINED SUBTASK REQUIREMENTS

<refined_subtask_requirements>
Each refined subtask MUST:
- Have a clear, specific title in the engagement language (`{lang}`).
- Include detailed instructions in the engagement language (`{lang}`).
- Directly contribute to accomplishing the user's original request from
  <user_task><input>.
- Specify outcomes and success criteria rather than rigid implementation
  details.
- Allow sufficient flexibility in approach while maintaining clear goals.
- Contain enough detail for execution without further clarification.
- Be completable in a single execution session.
- NEVER include GUI applications, web UIs, or interactive applications.
- NEVER include commands requiring Docker host access, UDP port scanning, or
  software installation via Docker images.
- NEVER include tools requiring interactive terminal sessions that cannot be
  automated.
</refined_subtask_requirements>

## OUTPUT FORMAT: DELTA OPERATIONS

<delta_operations>
Instead of regenerating all subtasks, submit ONLY the changes needed using
the "{subtask_patch_tool}" tool.

Available operations:
- add     : create a new subtask. Requires subtask.title and subtask.description.
            Optional: index (insert position; null/absent = append).
- remove  : delete a subtask by index. Requires index.
- modify  : update title and/or description of an existing subtask. Requires
            index; subtask carries the new fields (only non-null fields are
            applied).
- reorder : move a subtask to a different position. Either index (single move)
            or new_order (full re-ordering) must be provided.

Task completion: to signal that the task is complete, remove all remaining
planned subtasks.

Examples:
- Remove completed subtask at index 0, add a new one at index 1:
  operations=[{{"op": "remove", "index": 0}},
              {{"op": "add", "index": 1,
                "subtask": {{"title": "...", "description": "..."}}}}]
- Modify subtask at index 2's description:
  operations=[{{"op": "modify", "index": 2,
                "subtask": {{"title": "...", "description": "Updated ..."}}}}]
- No changes needed (current plan is optimal):
  operations=[]
- Task complete (remove all remaining planned subtasks):
  operations=[{{"op": "remove", "index": 0}},
              {{"op": "remove", "index": 0}},
              {{"op": "remove", "index": 0}}]
</delta_operations>

## OUTPUT REQUIREMENTS

<output_requirements>
You MUST complete your refinement by using the "{subtask_patch_tool}" tool with:
- A list of operations to apply to the current subtask list (or empty array if
  no changes needed).
- A clear explanatory message summarizing progress and changes made.
- Justification for any significant modifications.
- Brief analysis of completed tasks' outcomes and how they inform the refined
  plan.
</output_requirements>
"""


def _render_system_prompt(
    *,
    language: str,
    docker_image: str,
    tasks_number_limit: int,
) -> str:
    """Render the Refiner system prompt with template variables substituted."""
    return REFINER_SYSTEM_PROMPT.format(
        lang=language,
        docker_image=docker_image,
        tasks_number_limit=tasks_number_limit,
        current_time=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        search_tool=SearchToolName,
        subtask_patch_tool=SubtaskPatchToolName,
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
    """Render the Refiner user-turn prompt mirroring subtasks_refiner.tmpl."""
    parts: list[str] = []
    parts.append("<refinement_context>")
    parts.append("  <instruction>")
    parts.append(
        "  Your goal is to optimize the remaining subtasks to accomplish the "
        "PRIMARY USER REQUEST provided in the <user_task><input> field below."
    )
    parts.append(
        "  The <user_task><input> contains the MAIN OBJECTIVE that the user "
        "requested - this is the ultimate goal you must achieve."
    )
    parts.append(
        "  Based on completed subtask results, refine the remaining plan to "
        "accomplish this exact user request more efficiently."
    )
    parts.append(
        "  All modifications (add/remove/modify/reorder) must be focused on "
        "achieving what the user asked for in <user_task><input>."
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
        parts.append("  <planned_subtasks>")
        parts.append("    <status>empty</status>")
        parts.append(
            "    <message>All subtasks have been completed. Review their "
            "statuses and results.</message>"
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

    parts.append("</refinement_context>")
    return "\n".join(parts)


# ── Agent class ───────────────────────────────────────────────────────────────


class Refiner:
    """Planning agent: delta-patches the planned subtask list after each step.

    The Refiner runs inside the universal ``perform_agent_chain`` loop with
    access to a single auxiliary tool (``search``) and a single barrier /
    completion tool (``subtask_patch``). When the agent invokes
    ``subtask_patch``, the loop terminates and the parsed
    :class:`SubtaskPatch` is returned to the caller as a list of operation
    dicts. The caller is responsible for applying the patch to the in-memory
    planned-subtask list.

    Ported from PentAGI's ``performSubtasksRefiner`` (performers.go).
    """

    agent_type: AgentType = AgentType.REFINER  # type: ignore[attr-defined]

    def __init__(
        self,
        *,
        language: str = "en",
        docker_image: str = "debian:latest",
        tasks_number_limit: int = TasksNumberLimit,
    ) -> None:
        """Configure the Refiner.

        Args:
            language: Engagement language code.
            docker_image: Docker image that subtasks execute inside.
            tasks_number_limit: Hard cap on the number of planned subtasks
                after refinement. Defaults to :data:`TasksNumberLimit`.
        """
        self.language: str = language
        self.docker_image: str = docker_image
        self.tasks_number_limit: int = max(1, int(tasks_number_limit))

    async def run(
        self,
        ctx: AgentContext,
        task: dict[str, Any],
        completed_subtasks: list[dict[str, Any]] | None = None,
        planned_subtasks: list[dict[str, Any]] | None = None,
        previous_tasks: list[dict[str, Any]] | None = None,
        execution_state: str | None = None,
        execution_logs: str | None = None,
    ) -> list[dict[str, Any]]:
        """Produce a delta-patch of operations adapting the planned subtasks.

        Args:
            ctx: The active :class:`AgentContext`.
            task: User task dict (``input`` or ``description``, ``id``).
            completed_subtasks: Subtasks already executed, each with ``id``,
                ``title``, ``description``, ``status``, ``result``.
            planned_subtasks: Subtasks still pending execution, each with
                ``id``, ``title``, ``description``.
            previous_tasks: Optional previously-executed task dicts (for
                learning context only).
            execution_state: Optional free-form execution-state snapshot
                rendered verbatim into ``<execution_state>``.
            execution_logs: Optional free-form execution-log blob rendered
                verbatim into ``<execution_logs>``.

        Returns:
            A list of operation dicts. Each dict has the shape
            ``{"op": "add"|"remove"|"modify"|"reorder", "index": int|None,
            "subtask": {"title":..., "description":...}|None,
            "new_order": [int, ...]|None}``. An empty list means "no changes
            needed — current plan is optimal".

        Raises:
            RuntimeError: If the agent chain fails or terminates without
                invoking the ``subtask_patch`` completion tool.
            ValidationError: If the completion-tool payload does not conform
                to :class:`SubtaskPatch`.
        """
        completed_subtasks = completed_subtasks or []
        planned_subtasks = planned_subtasks or []
        previous_tasks = previous_tasks or []

        system_prompt = _render_system_prompt(
            language=self.language,
            docker_image=self.docker_image,
            tasks_number_limit=self.tasks_number_limit,
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
            "Refiner.run invoked task_id=%s completed=%d planned=%d limit=%d",
            task.get("id"),
            len(completed_subtasks),
            len(planned_subtasks),
            self.tasks_number_limit,
        )

        captured: dict[str, Any] = {"patch": None}

        async def _subtask_patch_handler(
            name: str,
            args: dict[str, Any] | str,
        ) -> str:
            """Barrier completion-tool handler: capture + parse the patch."""
            try:
                parsed = SubtaskPatch.model_validate(args)
            except ValidationError as exc:
                logger.error("subtask_patch payload failed validation: %s", exc)
                raise
            captured["patch"] = parsed
            return "subtask patch successfully processed"

        completion_tools: dict[str, Any] = {
            SubtaskPatchToolName: _subtask_patch_handler,
        }

        await perform_agent_chain(
            ctx=ctx,
            agent_type=self.agent_type,
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            completion_tools=completion_tools,
            auxiliary_tools=(SearchToolName,),
        )

        result: SubtaskPatch | None = captured["patch"]
        if result is None:
            raise RuntimeError(
                "Refiner agent chain terminated without calling the "
                f"'{SubtaskPatchToolName}' completion tool"
            )

        operations: list[dict[str, Any]] = [
            op.model_dump(exclude_none=True) for op in result.operations
        ]
        logger.info(
            "Refiner produced %d operations for task_id=%s (msg=%r)",
            len(operations),
            task.get("id"),
            result.message[:80],
        )
        return operations
