"""elengenix/flows/task_worker.py — TaskWorker asyncio port of PentAGI's task.go.

This module ports PentAGI's ``backend/pkg/controller/task.go::TaskWorker``
to Python. The TaskWorker is the middle tier of the 4-tier hierarchy
(Flow → Task → SubTask → Action). It owns a single Task row, runs the
Generator agent to produce the initial subtask plan, then loops:

    PopSubtask (FIFO) → SubtaskWorker.Run → RefineSubtasks → repeat

…until either the subtask queue is exhausted or the
:class:`TasksNumberLimit` cap is reached. Finally it calls the Reporter
agent to produce the task's final report (success / failure flag +
write-up) and transitions the Task to ``FINISHED`` or ``FAILED``.

Architecture (ported from PentAGI)
---------------------------------
* :meth:`TaskWorker.create` — classmethod that calls
  ``provider.get_task_title(input)`` to derive the title, inserts a Task
  row in ``CREATED`` status, runs the Generator to populate the
  subtask plan, then returns the TaskWorker.
* :meth:`run` — the main loop. Pops subtasks FIFO, runs each via a
  :class:`SubtaskWorker`, then calls the Refiner after each completion.
  Respects :data:`TasksNumberLimit` (default 10).
* :meth:`put_input` — feeds user input to the currently WAITING subtask
  (called by :class:`FlowWorker` when resuming a paused task).
* :meth:`finish` — marks all incomplete subtasks as FINISHED + sets the
  task to FINISHED (called by :class:`FlowWorker.finish`).

Concurrency
-----------
* An :class:`asyncio.Lock` (``_mx``) guards the ``completed`` / ``waiting``
  in-memory flags (replaces PentAGI's ``mx sync.RWMutex``).
* Back-propagation: on each status transition, the
  :class:`TaskStateMachine` calls :func:`back_propagate_status` to
  propagate the change up to the parent Flow.

Agent context propagation uses :class:`contextvars.ContextVar` via
:func:`AgentContext.put` (mirrors PentAGI's
``tools.PutAgentContext(ctx, MsgchainTypePrimaryAgent)``).
"""

from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING, Any

from elengenix.agent.crew.base import AgentContext, AgentType
from elengenix.flows.db import FlowDB
from elengenix.flows.flow_worker import (
    FlowContext,
    FlowProvider,
    TaskContext,
    TaskResult,
)
from elengenix.flows.models import (
    MsgchainType,
    Subtask,
    SubtaskInfo,
    SubtaskStatus,
    Task,
    TaskStatus,
)
from elengenix.flows.state_machine import (
    TaskStateMachine,
    build_task_state_machine,
)

if TYPE_CHECKING:
    from elengenix.flows.flow_worker import FlowWorker
    from elengenix.flows.subtask_worker import SubtaskWorker

logger = logging.getLogger("elengenix.flows.task_worker")

# Hard cap on the total number of subtasks (planned + completed) before
# the task loop terminates and the Reporter is invoked. Mirrors
# PentAGI's ``providers.TasksNumberLimit`` (default 10). The +3 buffer
# matches PentAGI's ``len(subtasks) < TasksNumberLimit+3`` loop guard.
TASKS_NUMBER_LIMIT: int = 10
_TASK_LOOP_BUFFER: int = 3


class TaskWorker:
    """Per-task asyncio worker.

    Owns a single :class:`Task` row + its planned/completed subtask
    lists. Runs the Generator → SubtaskWorker.Run → Refiner loop until
    the plan is exhausted or :data:`TASKS_NUMBER_LIMIT` is reached,
    then calls the Reporter for the final report.

    The worker is driven by its parent :class:`FlowWorker` — the
    FlowWorker creates one TaskWorker per user input and calls
    :meth:`run` on it.
    """

    def __init__(
        self,
        *,
        task: Task,
        task_ctx: TaskContext,
        flow_worker: "FlowWorker | None" = None,
    ) -> None:
        """Initialize the TaskWorker.

        Args:
            task: The :class:`Task` DB row.
            task_ctx: The :class:`TaskContext` (DB + provider + IDs).
            flow_worker: Optional reference to the parent
                :class:`FlowWorker` (used to check cancellation).
        """
        self.task: Task = task
        self.task_ctx: TaskContext = task_ctx
        self.flow_worker: "FlowWorker | None" = flow_worker

        # In-memory cache of subtask workers (subtask_id → SubtaskWorker).
        self._subtask_workers: dict[int, "SubtaskWorker"] = {}

        # In-memory flags mirroring PentAGI's `completed` / `waiting`.
        self._completed: bool = task.status in (
            TaskStatus.FINISHED,
            TaskStatus.FAILED,
        )
        self._waiting: bool = task.status == TaskStatus.WAITING
        self._mx: asyncio.Lock = asyncio.Lock()

        # State machine (lazily initialized).
        self._state_machine: TaskStateMachine | None = None

        logger.debug(
            "TaskWorker initialized task_id=%d flow_id=%d status=%s",
            task.id,
            task.flow_id,
            task.status.value,
        )

    # ── properties ─────────────────────────────────────────────────────

    @property
    def task_id(self) -> int:
        """The task's primary key."""
        return self.task.id

    @property
    def flow_id(self) -> int:
        """The parent flow's primary key."""
        return self.task.flow_id

    @property
    def user_id(self) -> int:
        """The owning user's ID."""
        return self.task_ctx.user_id

    @property
    def title(self) -> str:
        """The task's title."""
        return self.task.title

    def is_completed(self) -> bool:
        """Return ``True`` if the task is FINISHED or FAILED."""
        return self._completed

    def is_waiting(self) -> bool:
        """Return ``True`` if the task is WAITING for user input."""
        return self._waiting

    # ── state machine ──────────────────────────────────────────────────

    async def get_state_machine(self) -> TaskStateMachine:
        """Return the cached :class:`TaskStateMachine`, building it if needed."""
        if self._state_machine is None:
            self._state_machine = await build_task_state_machine(
                self.task_ctx.db, self.task_id
            )
            self._state_machine._flow_sm = (  # noqa: SLF001
                await self.task_ctx.flow_ctx.get_state_machine()
            )
        return self._state_machine

    async def set_status(self, status: TaskStatus) -> None:
        """Transition the task to ``status`` (validated + persisted).

        Also updates the in-memory ``completed`` / ``waiting`` flags and
        back-propagates to the parent Flow via the state machine.
        """
        sm = await self.get_state_machine()
        from elengenix.flows.state_machine import is_valid_transition

        async with self._mx:
            if is_valid_transition(sm.current_status, status):
                await sm.transition(status)
            else:
                logger.debug(
                    "TaskWorker.set_status_skip task_id=%d %s -> %s (invalid)",
                    self.task_id,
                    sm.current_status.value,
                    status.value,
                )

            # Update in-memory flags to mirror PentAGI's taskWorker.SetStatus switch.
            if status == TaskStatus.RUNNING:
                self._completed = False
                self._waiting = False
            elif status == TaskStatus.WAITING:
                self._completed = False
                self._waiting = True
            elif status in (TaskStatus.FINISHED, TaskStatus.FAILED):
                self._completed = True
                self._waiting = False
            # CREATED is not settable via this method (mirrors PentAGI).

    async def get_status(self) -> TaskStatus:
        """Return the task's current status (re-read from the DB)."""
        task = await self.task_ctx.db.get_task(self.task_id)
        if task is None:
            return TaskStatus.FAILED
        return task.status

    async def get_result(self) -> str:
        """Return the task's current ``result`` column value."""
        task = await self.task_ctx.db.get_task(self.task_id)
        return task.result if task is not None else ""

    async def set_result(self, result: str) -> None:
        """Update the task's ``result`` column."""
        await self.task_ctx.db.update_task_result(self.task_id, result)
        self.task.result = result

    # ── factory ────────────────────────────────────────────────────────

    @classmethod
    async def create(
        cls,
        *,
        flow_ctx: FlowContext,
        input: str,
        flow_worker: "FlowWorker | None" = None,
    ) -> "TaskWorker":
        """Create a new Task + run the Generator to populate the subtask plan.

        Mirrors PentAGI's ``NewTaskWorker``. Flow:
            1. ``provider.get_task_title(input)`` → derive title.
            2. Insert Task row in ``CREATED`` status.
            3. Log the input as a ``MsglogType.INPUT`` message-log entry.
            4. ``provider.generate_subtasks(task_id)`` → Generator output.
            5. Insert one Subtask row per planned subtask (in ``CREATED``).
            6. Return the TaskWorker.
        """
        # Put the primary-agent context for the duration of task creation.
        token = AgentContext.put(AgentType.PRIMARY)
        try:
            title = await flow_ctx.provider.get_task_title(input)
            task = await flow_ctx.db.create_task(
                flow_id=flow_ctx.flow_id,
                input=input,
                title=title,
                status=TaskStatus.CREATED,
            )

            # Log the user's input as an engagement-log entry.
            from elengenix.flows.models import MsglogType

            await flow_ctx.db.create_msglog(
                type=MsglogType.INPUT,
                flow_id=flow_ctx.flow_id,
                task_id=task.id,
                message=input,
                result="",
            )

            task_ctx = TaskContext(
                flow_ctx=flow_ctx,
                task_id=task.id,
                task_title=title,
                task_input=input,
            )
            tw = cls(task=task, task_ctx=task_ctx, flow_worker=flow_worker)

            # Run the Generator to populate the subtask plan.
            await tw._generate_subtasks()  # noqa: SLF001

            return tw
        finally:
            AgentContext.reset(token)

    # ── subtask controller (mirrors PentAGI's subtasks.go) ─────────────

    async def _generate_subtasks(self) -> None:
        """Call the Generator agent + insert the planned subtasks in DB."""
        plan = await self.task_ctx.provider.generate_subtasks(self.task_id)
        if not plan:
            logger.warning(
                "TaskWorker._generate_subtasks empty_plan task_id=%d", self.task_id
            )
            return
        for info in plan:
            await self.task_ctx.db.create_subtask(
                task_id=self.task_id,
                title=info.title,
                description=info.description,
                status=SubtaskStatus.CREATED,
            )
        logger.info(
            "TaskWorker._generate_subtasks generated task_id=%d count=%d",
            self.task_id,
            len(plan),
        )

    async def _refine_subtasks(self) -> None:
        """Call the Refiner agent + apply the patched plan to the DB.

        Mirrors PentAGI's ``subtaskController.RefineSubtasks``. The
        Refiner returns a fresh full plan; the caller deletes all
        ``CREATED`` subtasks and inserts the new ones.
        """
        plan = await self.task_ctx.provider.refine_subtasks(self.task_id)
        if not plan:
            logger.debug(
                "TaskWorker._refine_subtasks empty_plan task_id=%d", self.task_id
            )
            return

        # Delete all CREATED subtasks (the Refiner replaces them).
        existing = await self.task_ctx.db.list_subtasks(self.task_id)
        created_ids = [s.id for s in existing if s.status == SubtaskStatus.CREATED]
        if created_ids:
            await self.task_ctx.db.delete_subtasks(created_ids)
            # Drop cached workers for deleted subtasks.
            for sid in created_ids:
                self._subtask_workers.pop(sid, None)

        # Insert the refined plan.
        for info in plan:
            await self.task_ctx.db.create_subtask(
                task_id=self.task_id,
                title=info.title,
                description=info.description,
                status=SubtaskStatus.CREATED,
            )
        logger.info(
            "TaskWorker._refine_subtasks refined task_id=%d new_count=%d deleted=%d",
            self.task_id,
            len(plan),
            len(created_ids),
        )

    async def _pop_subtask(self) -> "SubtaskWorker | None":
        """Pop the next planned (CREATED) subtask from the DB, FIFO.

        Mirrors PentAGI's ``subtaskController.PopSubtask``. Returns
        ``None`` when the queue is empty.
        """
        planned = await self.task_ctx.db.list_planned_subtasks(self.task_id)
        if not planned:
            return None
        subtask_db = planned[0]
        # Reuse a cached worker if present (the worker may have been
        # pre-built during a previous run that was interrupted).
        if subtask_db.id in self._subtask_workers:
            return self._subtask_workers[subtask_db.id]

        # Lazy import to avoid circular import (subtask_worker imports
        # from this module for TaskContext).
        from elengenix.flows.subtask_worker import SubtaskWorker

        sw = await SubtaskWorker.create(
            task_ctx=self.task_ctx,
            subtask_id=subtask_db.id,
            title=subtask_db.title,
            description=subtask_db.description,
            task_worker=self,
        )
        self._subtask_workers[subtask_db.id] = sw
        return sw

    async def list_subtasks(self) -> list[Subtask]:
        """Return all subtasks for this task, ordered by ``id`` ascending."""
        return await self.task_ctx.db.list_subtasks(self.task_id)

    async def get_subtask_worker(self, subtask_id: int) -> "SubtaskWorker | None":
        """Return the cached :class:`SubtaskWorker` for ``subtask_id`` (or ``None``)."""
        return self._subtask_workers.get(subtask_id)

    # ── public API ─────────────────────────────────────────────────────

    async def put_input(self, input: str) -> None:
        """Feed user input to the currently WAITING subtask.

        Mirrors PentAGI's ``taskWorker.PutInput``. Iterates over the
        in-memory subtask workers, finds the first one that is WAITING,
        and calls ``put_input`` on it. Raises ``RuntimeError`` if the
        task isn't WAITING.
        """
        if not self.is_waiting():
            raise RuntimeError(
                f"task {self.task_id} is not waiting (status={self.task.status.value})"
            )

        # Find the WAITING subtask worker.
        for sw in self._subtask_workers.values():
            if not sw.is_completed() and sw.is_waiting():
                await sw.put_input(input)
                return

        # No waiting subtask in cache — fall back to scanning the DB.
        subtasks = await self.task_ctx.db.list_subtasks(self.task_id)
        for st in subtasks:
            if st.status == SubtaskStatus.WAITING:
                from elengenix.flows.subtask_worker import SubtaskWorker

                sw = await SubtaskWorker.load(
                    subtask=st,
                    task_ctx=self.task_ctx,
                    task_worker=self,
                )
                self._subtask_workers[st.id] = sw
                await sw.put_input(input)
                return

        logger.warning(
            "TaskWorker.put_input no_waiting_subtask task_id=%d", self.task_id
        )

    async def run(self) -> None:
        """Main task loop: PopSubtask → SubtaskWorker.Run → RefineSubtasks → repeat.

        Mirrors PentAGI's ``taskWorker.Run``. The loop continues until
        either the planned-subtask queue is empty OR the
        :data:`TASKS_NUMBER_LIMIT` cap is reached. Then it calls the
        Reporter for the final report and transitions the task to
        ``FINISHED`` (on success) or ``FAILED`` (on failure).
        """
        # Put the primary-agent context for the duration of the run.
        token = AgentContext.put(AgentType.PRIMARY)
        try:
            await self.set_status(TaskStatus.RUNNING)

            iterations = 0
            max_iterations = TASKS_NUMBER_LIMIT + _TASK_LOOP_BUFFER

            while iterations < max_iterations:
                # Check for cancellation between iterations (mirrors
                # PentAGI's per-iteration ctx.Done() check).
                if self.flow_worker is not None and self.flow_worker.is_task_cancelled():
                    logger.info(
                        "TaskWorker.run cancelled task_id=%d iteration=%d",
                        self.task_id,
                        iterations,
                    )
                    await self._handle_interrupting()
                    return

                # Pop the next planned subtask (FIFO).
                sw = await self._pop_subtask()
                if sw is None:
                    # Empty queue — task is done.
                    logger.info(
                        "TaskWorker.run queue_empty task_id=%d iteration=%d",
                        self.task_id,
                        iterations,
                    )
                    break

                # Run the subtask.
                try:
                    await sw.run()
                except asyncio.CancelledError:
                    await self._handle_interrupting()
                    raise
                except Exception as exc:  # noqa: BLE001
                    logger.error(
                        "TaskWorker.run subtask_failed task_id=%d subtask_id=%d err=%s",
                        self.task_id,
                        sw.subtask_id,
                        exc,
                    )
                    await self._handle_interrupting()
                    raise RuntimeError(
                        f"subtask {sw.subtask_id} failed: {exc}"
                    ) from exc

                # If the subtask went WAITING, the task is paused — return
                # without refining (the FlowWorker will resume on next input).
                if self.is_waiting():
                    logger.info(
                        "TaskWorker.run waiting task_id=%d subtask_id=%d",
                        self.task_id,
                        sw.subtask_id,
                    )
                    return

                # Refine the plan after each subtask completes.
                try:
                    await self._refine_subtasks()
                except asyncio.CancelledError:
                    await self._handle_interrupting()
                    raise
                except Exception as exc:  # noqa: BLE001
                    logger.error(
                        "TaskWorker.run refine_failed task_id=%d err=%s",
                        self.task_id,
                        exc,
                    )
                    await self.set_status(TaskStatus.WAITING)
                    raise RuntimeError(
                        f"failed to refine subtasks for task {self.task_id}: {exc}"
                    ) from exc

                iterations += 1

            # All subtasks done (or cap reached) — call the Reporter.
            await self._finalize_with_reporter()
        finally:
            AgentContext.reset(token)

    async def _finalize_with_reporter(self) -> None:
        """Call the Reporter agent + transition the task to FINISHED/FAILED.

        Mirrors PentAGI's ``taskWorker.Run`` final block. Calls
        ``provider.get_task_result(task_id)``, stores the result, and
        transitions the task status.
        """
        job_result: TaskResult = await self.task_ctx.provider.get_task_result(
            self.task_id
        )
        await self.set_result(job_result.result)

        if job_result.success:
            await self.set_status(TaskStatus.FINISHED)
        else:
            await self.set_status(TaskStatus.FAILED)

        # Log the report as a message-log entry (mirrors PentAGI's
        # ``PutTaskMsgResult`` with type=REPORT, format=MARKDOWN).
        from elengenix.flows.models import MsglogResultFormat, MsglogType

        await self.task_ctx.db.create_msglog(
            type=MsglogType.REPORT,
            flow_id=self.flow_id,
            task_id=self.task_id,
            message=self.task.title,
            result=job_result.result,
            result_format=MsglogResultFormat.MARKDOWN,
        )

        logger.info(
            "TaskWorker._finalize_with_reporter task_id=%d success=%s",
            self.task_id,
            job_result.success,
        )

    async def _handle_interrupting(self) -> None:
        """Set the task to WAITING on cancellation / deadline (best-effort).

        Mirrors PentAGI's ``taskWorker.handleInterrupting``. Skips if
        the task is already FINISHED/FAILED.
        """
        if self.is_completed():
            return
        try:
            await self.set_status(TaskStatus.WAITING)
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "TaskWorker._handle_interrupting set_waiting_failed task_id=%d err=%s",
                self.task_id,
                exc,
            )

    async def finish(self) -> None:
        """Finish the task: mark all incomplete subtasks FINISHED + set FINISHED.

        Mirrors PentAGI's ``taskWorker.Finish``. Called by
        :class:`FlowWorker.finish` during graceful shutdown.
        """
        if self.is_completed():
            return

        # Finish all incomplete subtasks.
        from elengenix.flows.subtask_worker import SubtaskWorker

        subtasks = await self.task_ctx.db.list_subtasks(self.task_id)
        for st in subtasks:
            if st.status in (
                SubtaskStatus.CREATED,
                SubtaskStatus.RUNNING,
                SubtaskStatus.WAITING,
            ):
                sw = self._subtask_workers.get(st.id)
                if sw is None:
                    sw = await SubtaskWorker.load(
                        subtask=st,
                        task_ctx=self.task_ctx,
                        task_worker=self,
                    )
                    self._subtask_workers[st.id] = sw
                try:
                    await sw.finish()
                except Exception as exc:  # noqa: BLE001
                    logger.warning(
                        "TaskWorker.finish subtask_finish_failed "
                        "task_id=%d subtask_id=%d err=%s",
                        self.task_id,
                        st.id,
                        exc,
                    )

        await self.set_status(TaskStatus.FINISHED)


__all__ = ["TaskWorker", "TASKS_NUMBER_LIMIT"]
