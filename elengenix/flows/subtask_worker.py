"""elengenix/flows/subtask_worker.py — SubtaskWorker asyncio port of PentAGI's subtask.go.

This module ports PentAGI's ``backend/pkg/controller/subtask.go::SubtaskWorker``
to Python. The SubtaskWorker is the leaf-tier worker in the 4-tier
hierarchy (Flow → Task → SubTask → Action). It owns a single Subtask
row + its primary-agent :class:`Msgchain` ID, and runs one iteration
of the universal :func:`perform_agent_chain` loop via the
:class:`FlowProvider`.

Architecture (ported from PentAGI)
---------------------------------
* :meth:`SubtaskWorker.create` — classmethod that calls
  ``provider.prepare_agent_chain(task_id, subtask_id)`` to allocate a
  fresh primary-agent msgchain, then returns the SubtaskWorker.
* :meth:`SubtaskWorker.load` — classmethod that loads an existing
  SubtaskWorker from the DB (used on resume after a WAITING subtask
  receives new user input). Loads the most recent primary-agent
  msgchain for the subtask.
* :meth:`run` — calls ``provider.ensure_chain_consistency(msg_chain_id)``
  to fix stale chain IDs, then ``provider.perform_agent_chain(...)``.
  Translates the :class:`PerformResult` into a status transition:
    - ``DONE``    → SubtaskStatus.FINISHED
    - ``WAITING`` → SubtaskStatus.WAITING
    - ``ERROR``   → SubtaskStatus.FAILED
* :meth:`put_input` — appends user input to the WAITING msgchain via
  ``provider.put_input_to_agent_chain(msg_chain_id, input)`` (called by
  :class:`TaskWorker.put_input`).
* :meth:`finish` — marks the subtask FINISHED (called by
  :class:`TaskWorker.finish`).

Back-propagation
----------------
On each status transition, the :class:`SubtaskStateMachine` calls
:func:`back_propagate_status` to propagate the change up to the parent
Task (and transitively to the Flow). ``RUNNING`` and ``WAITING``
propagate; ``FINISHED`` / ``FAILED`` do NOT propagate (the Task's
status is driven by the TaskWorker's outer loop, not by individual
subtask completions — mirrors PentAGI's
``subtaskWorker.SetStatus`` comment).

Agent context propagation uses :class:`contextvars.ContextVar` via
:func:`AgentContext.put` (mirrors PentAGI's
``tools.PutAgentContext(ctx, MsgchainTypePrimaryAgent)``).
"""

from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING

from elengenix.agent.crew.base import AgentContext, AgentType, PerformResult
from elengenix.flows.flow_worker import (
    SubtaskContext,
    TaskContext,
)
from elengenix.flows.models import (
    MsgchainType,
    Subtask,
    SubtaskStatus,
)
from elengenix.flows.state_machine import (
    SubtaskStateMachine,
    build_subtask_state_machine,
)

if TYPE_CHECKING:
    from elengenix.flows.task_worker import TaskWorker

logger = logging.getLogger("elengenix.flows.subtask_worker")


class SubtaskWorker:
    """Per-subtask asyncio worker.

    Owns a single :class:`Subtask` row + the primary-agent
    :class:`Msgchain` ID for it. Runs one iteration of the universal
    agent chain via :meth:`FlowProvider.perform_agent_chain`.

    The worker is driven by its parent :class:`TaskWorker` — the
    TaskWorker pops one SubtaskWorker at a time from the planned queue
    and calls :meth:`run` on it.
    """

    def __init__(
        self,
        *,
        subtask: Subtask,
        subtask_ctx: SubtaskContext,
        task_worker: "TaskWorker | None" = None,
    ) -> None:
        """Initialize the SubtaskWorker.

        Args:
            subtask: The :class:`Subtask` DB row.
            subtask_ctx: The :class:`SubtaskContext` (DB + provider +
                msg_chain_id + IDs).
            task_worker: Optional reference to the parent
                :class:`TaskWorker` (used for state-machine wiring).
        """
        self.subtask: Subtask = subtask
        self.subtask_ctx: SubtaskContext = subtask_ctx
        self.task_worker: "TaskWorker | None" = task_worker

        # In-memory flags mirroring PentAGI's `completed` / `waiting`.
        self._completed: bool = subtask.status in (
            SubtaskStatus.FINISHED,
            SubtaskStatus.FAILED,
        )
        self._waiting: bool = subtask.status == SubtaskStatus.WAITING
        self._mx: asyncio.Lock = asyncio.Lock()

        # State machine (lazily initialized).
        self._state_machine: SubtaskStateMachine | None = None

        logger.debug(
            "SubtaskWorker initialized subtask_id=%d task_id=%d status=%s msg_chain_id=%d",
            subtask.id,
            subtask.task_id,
            subtask.status.value,
            subtask_ctx.msg_chain_id,
        )

    # ── properties ─────────────────────────────────────────────────────

    @property
    def subtask_id(self) -> int:
        """The subtask's primary key."""
        return self.subtask.id

    @property
    def task_id(self) -> int:
        """The parent task's primary key."""
        return self.subtask.task_id

    @property
    def flow_id(self) -> int:
        """The parent flow's primary key."""
        return self.subtask_ctx.flow_id

    @property
    def user_id(self) -> int:
        """The owning user's ID."""
        return self.subtask_ctx.user_id

    @property
    def msg_chain_id(self) -> int:
        """The primary-agent Msgchain ID for this subtask."""
        return self.subtask_ctx.msg_chain_id

    @property
    def title(self) -> str:
        """The subtask's title."""
        return self.subtask.title

    @property
    def description(self) -> str:
        """The subtask's description."""
        return self.subtask.description

    def is_completed(self) -> bool:
        """Return ``True`` if the subtask is FINISHED or FAILED."""
        return self._completed

    def is_waiting(self) -> bool:
        """Return ``True`` if the subtask is WAITING for user input."""
        return self._waiting

    # ── state machine ──────────────────────────────────────────────────

    async def get_state_machine(self) -> SubtaskStateMachine:
        """Return the cached :class:`SubtaskStateMachine`, building it if needed."""
        if self._state_machine is None:
            self._state_machine = await build_subtask_state_machine(
                self.subtask_ctx.db, self.subtask_id
            )
            # Wire the parent task state machine if available (avoids
            # re-reading the task row on each back-propagation).
            if self.task_worker is not None:
                self._state_machine._task_sm = (  # noqa: SLF001
                    await self.task_worker.get_state_machine()
                )
        return self._state_machine

    async def set_status(self, status: SubtaskStatus) -> None:
        """Transition the subtask to ``status`` (validated + persisted).

        Also updates the in-memory ``completed`` / ``waiting`` flags and
        back-propagates to the parent Task (and transitively to the
        Flow) via the state machine.

        Back-propagation rules (Subtask → Task → Flow):
            * Subtask ``running`` → Task ``running``, Flow ``running``.
            * Subtask ``waiting`` → Task ``waiting``, Flow ``waiting``.
            * Subtask ``finished`` / ``failed`` → no propagation (the
              task's status is driven by the TaskWorker's outer loop).
        """
        sm = await self.get_state_machine()
        from elengenix.flows.state_machine import is_valid_transition

        async with self._mx:
            if is_valid_transition(sm.current_status, status):
                await sm.transition(status)
            else:
                logger.debug(
                    "SubtaskWorker.set_status_skip subtask_id=%d %s -> %s (invalid)",
                    self.subtask_id,
                    sm.current_status.value,
                    status.value,
                )

            # Update in-memory flags to mirror PentAGI's subtaskWorker.SetStatus switch.
            if status == SubtaskStatus.RUNNING:
                self._completed = False
                self._waiting = False
            elif status == SubtaskStatus.WAITING:
                self._completed = False
                self._waiting = True
            elif status in (SubtaskStatus.FINISHED, SubtaskStatus.FAILED):
                self._completed = True
                self._waiting = False
            # CREATED is not settable via this method.

    async def get_status(self) -> SubtaskStatus:
        """Return the subtask's current status (re-read from the DB)."""
        subtask = await self.subtask_ctx.db.get_subtask(self.subtask_id)
        if subtask is None:
            return SubtaskStatus.FAILED
        return subtask.status

    async def get_result(self) -> str:
        """Return the subtask's current ``result`` column value."""
        subtask = await self.subtask_ctx.db.get_subtask(self.subtask_id)
        return subtask.result if subtask is not None else ""

    async def set_result(self, result: str) -> None:
        """Update the subtask's ``result`` column."""
        await self.subtask_ctx.db.update_subtask_result(self.subtask_id, result)
        self.subtask.result = result

    # ── factories ──────────────────────────────────────────────────────

    @classmethod
    async def create(
        cls,
        *,
        task_ctx: TaskContext,
        subtask_id: int,
        title: str,
        description: str,
        task_worker: "TaskWorker | None" = None,
    ) -> "SubtaskWorker":
        """Create a fresh primary-agent msgchain + return the SubtaskWorker.

        Mirrors PentAGI's ``NewSubtaskWorker``. Calls
        ``provider.prepare_agent_chain(task_id, subtask_id)`` to
        allocate a new msgchain row, then constructs the SubtaskWorker.
        """
        # Put the primary-agent context for the duration of subtask creation.
        token = AgentContext.put(AgentType.PRIMARY)
        try:
            msg_chain_id = await task_ctx.provider.prepare_agent_chain(
                task_ctx.task_id, subtask_id
            )

            subtask = await task_ctx.db.get_subtask(subtask_id)
            if subtask is None:
                raise ValueError(f"subtask {subtask_id} not found")

            subtask_ctx = SubtaskContext(
                task_ctx=task_ctx,
                subtask_id=subtask_id,
                subtask_title=title,
                subtask_description=description,
                msg_chain_id=msg_chain_id,
            )
            return cls(
                subtask=subtask,
                subtask_ctx=subtask_ctx,
                task_worker=task_worker,
            )
        finally:
            AgentContext.reset(token)

    @classmethod
    async def load(
        cls,
        *,
        subtask: Subtask,
        task_ctx: TaskContext,
        task_worker: "TaskWorker | None" = None,
    ) -> "SubtaskWorker":
        """Load an existing SubtaskWorker from the DB (used on resume).

        Mirrors PentAGI's ``LoadSubtaskWorker``. Loads the most recent
        primary-agent msgchain for the subtask; if the subtask is in
        ``RUNNING`` status (i.e. interrupted mid-run), it's reset to
        ``CREATED`` so the run loop starts fresh on resume.
        """
        token = AgentContext.put(AgentType.PRIMARY)
        try:
            # If the subtask is RUNNING, it was interrupted mid-run —
            # reset to CREATED so the loop restarts cleanly.
            if subtask.status == SubtaskStatus.RUNNING:
                updated = await task_ctx.db.update_subtask_status(
                    subtask.id, SubtaskStatus.CREATED
                )
                if updated is not None:
                    subtask = updated

            # Load the primary-agent msgchains for this subtask.
            msg_chains = await task_ctx.db.get_subtask_primary_msgchains(subtask.id)
            if not msg_chains:
                raise ValueError(
                    f"subtask {subtask.id} has no primary-agent msgchains"
                )
            msg_chain_id = msg_chains[0].id

            subtask_ctx = SubtaskContext(
                task_ctx=task_ctx,
                subtask_id=subtask.id,
                subtask_title=subtask.title,
                subtask_description=subtask.description,
                msg_chain_id=msg_chain_id,
            )
            return cls(
                subtask=subtask,
                subtask_ctx=subtask_ctx,
                task_worker=task_worker,
            )
        finally:
            AgentContext.reset(token)

    # ── public API ─────────────────────────────────────────────────────

    async def put_input(self, input: str) -> None:
        """Append user input to the WAITING agent chain (for resume).

        Mirrors PentAGI's ``subtaskWorker.PutInput``. Calls
        ``provider.put_input_to_agent_chain(msg_chain_id, input)`` to
        append the user's input as a new ``user`` message in the
        existing chain, logs the input as a message-log entry, and
        clears the in-memory ``waiting`` flag.

        Raises:
            RuntimeError: If the subtask is already completed or not
                currently WAITING.
        """
        if self.is_completed():
            raise RuntimeError(f"subtask {self.subtask_id} has already completed")
        if not self.is_waiting():
            raise RuntimeError(
                f"subtask {self.subtask_id} is not waiting, run first"
            )

        await self.subtask_ctx.provider.put_input_to_agent_chain(
            self.msg_chain_id, input
        )

        # Log the user's input as an engagement-log entry.
        from elengenix.flows.models import MsglogType

        await self.subtask_ctx.db.create_msglog(
            type=MsglogType.INPUT,
            flow_id=self.flow_id,
            task_id=self.task_id,
            subtask_id=self.subtask_id,
            message=input,
            result="",
        )

        async with self._mx:
            self._waiting = False

    async def run(self) -> None:
        """Run one iteration of the universal agent chain for this subtask.

        Mirrors PentAGI's ``subtaskWorker.Run``. Flow:

            1. ``set_status(RUNNING)`` (validates the state-machine
               transition + back-propagates to Task/Flow).
            2. ``provider.ensure_chain_consistency(msg_chain_id)`` —
               rewrites stale tool-call IDs so a resumed subtask doesn't
               replay IDs the LLM has forgotten.
            3. ``provider.perform_agent_chain(task_id, subtask_id,
               msg_chain_id)`` — drives the PrimaryAgent chain.
            4. Translate the :class:`PerformResult`:
                - ``DONE``    → SubtaskStatus.FINISHED
                - ``WAITING`` → SubtaskStatus.WAITING
                - ``ERROR``   → SubtaskStatus.FAILED

        On ``asyncio.CancelledError`` or unexpected errors, sets the
        subtask to ``WAITING`` (best-effort) so it can be resumed later
        (mirrors PentAGI's ``handleInterrupting``).
        """
        if self.is_completed():
            raise RuntimeError(
                f"subtask {self.subtask_id} has already completed"
            )
        if self.is_waiting():
            raise RuntimeError(
                f"subtask {self.subtask_id} is waiting, put input first"
            )

        # Put the primary-agent context for the duration of the run.
        token = AgentContext.put(AgentType.PRIMARY)
        try:
            await self.set_status(SubtaskStatus.RUNNING)

            # Ensure chain consistency on resume (mirrors PentAGI's
            # EnsureChainConsistency call before PerformAgentChain).
            try:
                await self.subtask_ctx.provider.ensure_chain_consistency(
                    self.msg_chain_id
                )
            except asyncio.CancelledError:
                await self._handle_interrupting()
                raise
            except Exception as exc:  # noqa: BLE001
                logger.error(
                    "SubtaskWorker.run ensure_consistency_failed "
                    "subtask_id=%d msg_chain_id=%d err=%s",
                    self.subtask_id,
                    self.msg_chain_id,
                    exc,
                )
                await self._handle_interrupting()
                raise RuntimeError(
                    f"failed to ensure chain consistency for subtask "
                    f"{self.subtask_id}: {exc}"
                ) from exc

            # Drive the universal agent chain.
            try:
                perform_result = await self.subtask_ctx.provider.perform_agent_chain(
                    self.task_id, self.subtask_id, self.msg_chain_id
                )
            except asyncio.CancelledError:
                # Try to ensure consistency before re-raising.
                try:
                    await self.subtask_ctx.provider.ensure_chain_consistency(
                        self.msg_chain_id
                    )
                except Exception as exc:  # noqa: BLE001
                    logger.warning(
                        "SubtaskWorker.run post_cancel_ensure_failed "
                        "subtask_id=%d err=%s",
                        self.subtask_id,
                        exc,
                    )
                await self._handle_interrupting()
                raise
            except Exception as exc:  # noqa: BLE001
                logger.error(
                    "SubtaskWorker.run perform_failed subtask_id=%d err=%s",
                    self.subtask_id,
                    exc,
                )
                # Best-effort chain-consistency repair + set WAITING.
                try:
                    await self.subtask_ctx.provider.ensure_chain_consistency(
                        self.msg_chain_id
                    )
                except Exception:  # noqa: BLE001
                    pass
                await self._handle_interrupting()
                raise RuntimeError(
                    f"failed to perform agent chain for subtask "
                    f"{self.subtask_id}: {exc}"
                ) from exc

            # Translate PerformResult → SubtaskStatus.
            if perform_result == PerformResult.DONE:
                await self.set_status(SubtaskStatus.FINISHED)
            elif perform_result == PerformResult.WAITING:
                await self.set_status(SubtaskStatus.WAITING)
            elif perform_result == PerformResult.ERROR:
                await self.set_status(SubtaskStatus.FAILED)
            else:
                logger.error(
                    "SubtaskWorker.run unknown_perform_result subtask_id=%d result=%s",
                    self.subtask_id,
                    perform_result,
                )
                await self.set_status(SubtaskStatus.FAILED)

            logger.info(
                "SubtaskWorker.run complete subtask_id=%d result=%s final_status=%s",
                self.subtask_id,
                perform_result.value,
                (await self.get_status()).value,
            )
        finally:
            AgentContext.reset(token)

    async def _handle_interrupting(self) -> None:
        """Set the subtask to WAITING on cancellation / deadline (best-effort).

        Mirrors PentAGI's ``subtaskWorker.handleInterrupting``. Skips if
        the subtask is already FINISHED/FAILED.
        """
        if self.is_completed():
            return
        try:
            await self.set_status(SubtaskStatus.WAITING)
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "SubtaskWorker._handle_interrupting set_waiting_failed "
                "subtask_id=%d err=%s",
                self.subtask_id,
                exc,
            )

    async def finish(self) -> None:
        """Mark the subtask FINISHED (called by TaskWorker.finish).

        Mirrors PentAGI's ``subtaskWorker.Finish``. Raises ``RuntimeError``
        if the subtask has already completed.
        """
        if self.is_completed():
            raise RuntimeError(
                f"subtask {self.subtask_id} has already completed"
            )
        await self.set_status(SubtaskStatus.FINISHED)


__all__ = ["SubtaskWorker"]
