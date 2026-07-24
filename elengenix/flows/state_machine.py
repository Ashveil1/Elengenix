"""elengenix/flows/state_machine.py — 5-state machine + back-propagation.

This module ports PentAGI's status-management logic to Python. PentAGI
uses a shared 5-state machine (``created → running → waiting ⇄ running
→ finished | failed``) for all three of Flow / Task / Subtask, with
back-propagation: when a subtask transitions to ``running`` / ``waiting``
/ ``finished`` / ``failed``, the change is propagated up to its parent
task, and from the task up to its parent flow.

Classes
-------
* :class:`InvalidStateTransitionError` — raised on illegal transitions.
* :class:`BaseStateMachine` — shared base class implementing the
  transition table + validator.
* :class:`FlowStateMachine` — wraps a :class:`FlowStatus` enum and the
  DB updaters needed to persist transitions.
* :class:`TaskStateMachine` — wraps a :class:`TaskStatus` enum; on
  ``running`` / ``waiting`` / ``finished`` / ``failed`` it back-propagates
  to the parent Flow via :func:`back_propagate_status`.
* :class:`SubtaskStateMachine` — wraps a :class:`SubtaskStatus` enum; on
  ``running`` / ``waiting`` / ``finished`` / ``failed`` it back-propagates
  to the parent Task (which then back-propagates to the Flow).

The transition table is identical across all three machines (mirrors
PentAGI's Go state machine):

    created  → running                       ✓
    running  → waiting                       ✓
    waiting  → running                       ✓
    running  → finished                      ✓
    running  → failed                        ✓
    waiting  → failed                        ✓  (cancellation)
    *        → failed                        ✓  (error)

All other transitions raise :class:`InvalidStateTransitionError`.

Back-propagation rules (ported from PentAGI's
``subtaskWorker.SetStatus`` / ``taskWorker.SetStatus``):

* Subtask ``running`` → Task ``running``, Flow ``running``.
* Subtask ``waiting`` → Task ``waiting``, Flow ``waiting``.
* Subtask ``finished`` / ``failed`` → Task unchanged (the task's status
  is driven by the TaskWorker's outer loop, not by individual subtask
  completions — mirrors PentAGI's comment "statuses Finished and Failed
  will be produced by stack from Run function call").
* Task ``running`` → Flow ``running``.
* Task ``waiting`` → Flow ``waiting``.
* Task ``finished`` / ``failed`` → Flow ``waiting`` (the flow returns to
  ``waiting`` for new user input — mirrors PentAGI's ``taskWorker.SetStatus``).
"""

from __future__ import annotations

import asyncio
import logging
from typing import Awaitable, Callable

from elengenix.flows.db import FlowDB
from elengenix.flows.models import (
    FlowStatus,
    SubtaskStatus,
    TaskStatus,
)

logger = logging.getLogger("elengenix.flows.state_machine")

# Type alias for the DB-write coroutine returned by the state-machine
# transitions. Each machine calls ``await self._db.<updater>(...)`` to
# persist the new status.
_StatusEnum = FlowStatus | TaskStatus | SubtaskStatus


# ---------------------------------------------------------------------------
# InvalidStateTransitionError.
# ---------------------------------------------------------------------------


class InvalidStateTransitionError(Exception):
    """Raised when a state-machine transition is not in the valid table.

    Attributes:
        from_status: The source status (or ``None`` if the entity is new).
        to_status:   The target status.
        entity_type: ``"flow"`` / ``"task"`` / ``"subtask"`` (for logging).
        entity_id:   The entity's primary key (for logging).
    """

    def __init__(
        self,
        from_status: _StatusEnum | None,
        to_status: _StatusEnum,
        *,
        entity_type: str = "entity",
        entity_id: int | None = None,
    ) -> None:
        self.from_status: _StatusEnum | None = from_status
        self.to_status: _StatusEnum = to_status
        self.entity_type: str = entity_type
        self.entity_id: int | None = entity_id
        from_val = from_status.value if from_status is not None else "<none>"
        ident = f"{entity_type}#{entity_id}" if entity_id is not None else entity_type
        super().__init__(
            f"Invalid state transition for {ident}: "
            f"{from_val} -> {to_status.value}"
        )


# ---------------------------------------------------------------------------
# Valid-transition table — shared by Flow / Task / Subtask machines.
#
# The string values are used as dict keys so the same table works for all
# three enum types (they all share the same 5 string values).
# ---------------------------------------------------------------------------

_VALID_TRANSITIONS: dict[str, frozenset[str]] = {
    FlowStatus.CREATED.value: frozenset(
        {FlowStatus.RUNNING.value, FlowStatus.FAILED.value}
    ),
    FlowStatus.RUNNING.value: frozenset(
        {
            FlowStatus.WAITING.value,
            FlowStatus.FINISHED.value,
            FlowStatus.FAILED.value,
        }
    ),
    FlowStatus.WAITING.value: frozenset(
        {FlowStatus.RUNNING.value, FlowStatus.FAILED.value}
    ),
    FlowStatus.FINISHED.value: frozenset(),  # terminal
    FlowStatus.FAILED.value: frozenset(),  # terminal
}


def is_valid_transition(
    from_status: _StatusEnum | None,
    to_status: _StatusEnum,
) -> bool:
    """Return ``True`` if ``from_status → to_status`` is in the valid table.

    ``from_status=None`` is treated as ``created`` (i.e. only transitions
    to ``running`` or ``failed`` are allowed). The ``failed`` target is
    always allowed from any non-terminal source (mirrors PentAGI's "Any
    → failed ✓ (error)" rule).
    """
    if to_status.value == FlowStatus.FAILED.value and from_status is not None:
        # `failed` is the universal error sink — allowed from any non-terminal
        # source. (Both `finished` and `failed` are terminal so this branch is
        # only reached for non-terminal sources, which is correct.)
        if from_status.value in (FlowStatus.FINISHED.value, FlowStatus.FAILED.value):
            return False
        return True
    src = (
        from_status.value
        if from_status is not None
        else FlowStatus.CREATED.value
    )
    return to_status.value in _VALID_TRANSITIONS.get(src, frozenset())


# ---------------------------------------------------------------------------
# BaseStateMachine — shared base class.
# ---------------------------------------------------------------------------


class BaseStateMachine:
    """Shared base class for the three state machines.

    Subclasses must set :attr:`_entity_type` (``"flow"`` / ``"task"`` /
    ``"subtask"``) and override :meth:`_persist` to write the new status
    to the DB. The base class handles transition validation and logging.

    The class is async-only: :meth:`transition` is a coroutine that
    awaits the subclass's :meth:`_persist` implementation.
    """

    _entity_type: str = "entity"

    def __init__(
        self,
        entity_id: int,
        current_status: _StatusEnum,
        db: FlowDB,
    ) -> None:
        self.entity_id: int = entity_id
        self.current_status: _StatusEnum = current_status
        self._db: FlowDB = db
        self._lock: asyncio.Lock = asyncio.Lock()

    async def transition(self, to_status: _StatusEnum) -> _StatusEnum:
        """Validate + persist a transition to ``to_status``.

        Args:
            to_status: The target status. Must be a valid transition
                from :attr:`current_status` (see :data:`_VALID_TRANSITIONS`).

        Returns:
            The new current status (== ``to_status``).

        Raises:
            InvalidStateTransitionError: If the transition is not in the
                valid table.
        """
        async with self._lock:
            if not is_valid_transition(self.current_status, to_status):
                raise InvalidStateTransitionError(
                    self.current_status,
                    to_status,
                    entity_type=self._entity_type,
                    entity_id=self.entity_id,
                )
            prev = self.current_status
            await self._persist(to_status)
            self.current_status = to_status
            logger.info(
                "state_transition entity=%s id=%d %s -> %s",
                self._entity_type,
                self.entity_id,
                prev.value,
                to_status.value,
            )
            return self.current_status

    async def _persist(self, to_status: _StatusEnum) -> None:
        """Persist the new status to the DB. Subclasses must override."""
        raise NotImplementedError


# ---------------------------------------------------------------------------
# FlowStateMachine.
# ---------------------------------------------------------------------------


class FlowStateMachine(BaseStateMachine):
    """State machine for a Flow entity.

    Wraps a :class:`FlowStatus` enum and the
    :meth:`FlowDB.update_flow_status` DB updater.
    """

    _entity_type: str = "flow"

    def __init__(
        self,
        flow_id: int,
        current_status: FlowStatus,
        db: FlowDB,
    ) -> None:
        super().__init__(flow_id, current_status, db)

    @property
    def flow_id(self) -> int:
        """The flow's primary key."""
        return self.entity_id

    async def _persist(self, to_status: _StatusEnum) -> None:
        # mypy: to_status is FlowStatus when constructed via FlowStateMachine.
        await self._db.update_flow_status(self.entity_id, to_status)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# TaskStateMachine — back-propagates to Flow on running / waiting / finished / failed.
# ---------------------------------------------------------------------------


class TaskStateMachine(BaseStateMachine):
    """State machine for a Task entity.

    On ``running`` / ``waiting`` / ``finished`` / ``failed`` transitions,
    back-propagates to the parent Flow via :func:`back_propagate_status`.
    Mirrors PentAGI's ``taskWorker.SetStatus``.

    Back-propagation rules (Task → Flow):
        * Task ``running``  → Flow ``running``.
        * Task ``waiting``  → Flow ``waiting``.
        * Task ``finished`` → Flow ``waiting`` (flow awaits next user input).
        * Task ``failed``   → Flow ``waiting`` (flow awaits next user input).
    """

    _entity_type: str = "task"

    def __init__(
        self,
        task_id: int,
        current_status: TaskStatus,
        flow_id: int,
        db: FlowDB,
        flow_state_machine: FlowStateMachine | None = None,
    ) -> None:
        super().__init__(task_id, current_status, db)
        self._flow_id: int = flow_id
        self._flow_sm: FlowStateMachine | None = flow_state_machine

    @property
    def task_id(self) -> int:
        """The task's primary key."""
        return self.entity_id

    @property
    def flow_id(self) -> int:
        """The parent flow's primary key."""
        return self._flow_id

    async def _persist(self, to_status: _StatusEnum) -> None:
        task_status: TaskStatus = to_status  # type: ignore[assignment]
        await self._db.update_task_status(self.entity_id, task_status)
        # Back-propagate to the parent flow.
        await back_propagate_status(
            db=self._db,
            child_status=task_status,
            child_entity="task",
            flow_id=self._flow_id,
            flow_state_machine=self._flow_sm,
        )


# ---------------------------------------------------------------------------
# SubtaskStateMachine — back-propagates to Task (and transitively to Flow).
# ---------------------------------------------------------------------------


class SubtaskStateMachine(BaseStateMachine):
    """State machine for a Subtask entity.

    On ``running`` / ``waiting`` transitions, back-propagates to the
    parent Task via :func:`back_propagate_status`. ``finished`` and
    ``failed`` do NOT back-propagate (the Task's status is driven by the
    TaskWorker's outer loop, not by individual subtask completions —
    mirrors PentAGI's ``subtaskWorker.SetStatus`` comment).

    Back-propagation rules (Subtask → Task):
        * Subtask ``running`` → Task ``running`` (which then propagates
          to Flow ``running``).
        * Subtask ``waiting`` → Task ``waiting`` (which then propagates
          to Flow ``waiting``).
        * Subtask ``finished`` / ``failed`` → no propagation.
    """

    _entity_type: str = "subtask"

    def __init__(
        self,
        subtask_id: int,
        current_status: SubtaskStatus,
        task_id: int,
        flow_id: int,
        db: FlowDB,
        task_state_machine: TaskStateMachine | None = None,
    ) -> None:
        super().__init__(subtask_id, current_status, db)
        self._task_id: int = task_id
        self._flow_id: int = flow_id
        self._task_sm: TaskStateMachine | None = task_state_machine

    @property
    def subtask_id(self) -> int:
        """The subtask's primary key."""
        return self.entity_id

    @property
    def task_id(self) -> int:
        """The parent task's primary key."""
        return self._task_id

    @property
    def flow_id(self) -> int:
        """The parent flow's primary key."""
        return self._flow_id

    async def _persist(self, to_status: _StatusEnum) -> None:
        subtask_status: SubtaskStatus = to_status  # type: ignore[assignment]
        await self._db.update_subtask_status(self.entity_id, subtask_status)
        # Back-propagate to the parent task (and transitively to the flow).
        await back_propagate_status(
            db=self._db,
            child_status=subtask_status,
            child_entity="subtask",
            task_id=self._task_id,
            flow_id=self._flow_id,
            task_state_machine=self._task_sm,
        )


# ---------------------------------------------------------------------------
# back_propagate_status — the shared propagation helper.
# ---------------------------------------------------------------------------


# Type alias for the optional parent state-machine arguments.
_ParentSM = TaskStateMachine | FlowStateMachine | None


async def back_propagate_status(
    *,
    db: FlowDB,
    child_status: _StatusEnum,
    child_entity: str,
    flow_id: int | None = None,
    task_id: int | None = None,
    flow_state_machine: FlowStateMachine | None = None,
    task_state_machine: TaskStateMachine | None = None,
) -> None:
    """Propagate a child status change up to the parent entity.

    This is the shared back-propagation helper used by both
    :class:`TaskStateMachine` and :class:`SubtaskStateMachine`. It
    translates a child's status into the parent's status according to
    the rules above.

    Args:
        db: The :class:`FlowDB` instance (used to read the parent's
            current status if a state-machine object isn't supplied).
        child_status: The new status of the child entity.
        child_entity: ``"task"`` (propagates to Flow) or ``"subtask"``
            (propagates to Task, which then propagates to Flow).
        flow_id: Required when ``child_entity == "task"``.
        task_id: Required when ``child_entity == "subtask"``.
        flow_state_machine: Optional :class:`FlowStateMachine` to use for
            the flow transition. If ``None``, a fresh one is built from
            the DB row.
        task_state_machine: Optional :class:`TaskStateMachine` to use for
            the task transition. If ``None``, a fresh one is built from
            the DB row.

    The propagation is "best-effort": errors are logged and swallowed so
    a single subtask's status change can never deadlock the worker loop.
    This mirrors PentAGI's behaviour where the parent status update is
    fire-and-forget within ``SetStatus`` (errors are wrapped and returned
    but the child status is already persisted).
    """
    child_val = child_status.value
    try:
        if child_entity == "subtask":
            # Subtask → Task propagation. `finished` / `failed` do NOT propagate.
            if child_val in (
                SubtaskStatus.FINISHED.value,
                SubtaskStatus.FAILED.value,
            ):
                return
            if task_id is None:
                logger.warning(
                    "back_propagate_skip subtask_status=%s missing task_id",
                    child_val,
                )
                return
            # Translate subtask status to task status (1:1 for running/waiting).
            target_task_status: TaskStatus
            if child_val == SubtaskStatus.RUNNING.value:
                target_task_status = TaskStatus.RUNNING
            elif child_val == SubtaskStatus.WAITING.value:
                target_task_status = TaskStatus.WAITING
            else:
                return  # CREATED does not propagate.

            tsm = task_state_machine
            if tsm is None:
                task = await db.get_task(task_id)
                if task is None:
                    logger.warning(
                        "back_propagate_skip task_id=%d not found", task_id
                    )
                    return
                tsm = TaskStateMachine(
                    task_id=task.id,
                    current_status=task.status,
                    flow_id=task.flow_id,
                    db=db,
                )
            # Only transition if it's a valid transition (avoids InvalidStateTransitionError
            # when the task is already in the target state).
            if is_valid_transition(tsm.current_status, target_task_status):
                await tsm.transition(target_task_status)
            return

        if child_entity == "task":
            # Task → Flow propagation.
            if flow_id is None:
                logger.warning(
                    "back_propagate_skip task_status=%s missing flow_id",
                    child_val,
                )
                return
            target_flow_status: FlowStatus
            if child_val == TaskStatus.RUNNING.value:
                target_flow_status = FlowStatus.RUNNING
            elif child_val == TaskStatus.WAITING.value:
                target_flow_status = FlowStatus.WAITING
            elif child_val in (
                TaskStatus.FINISHED.value,
                TaskStatus.FAILED.value,
            ):
                # The last task was done — flow returns to WAITING for new
                # user input (mirrors PentAGI's taskWorker.SetStatus).
                target_flow_status = FlowStatus.WAITING
            else:
                return  # CREATED does not propagate.

            fsm = flow_state_machine
            if fsm is None:
                flow = await db.get_flow(flow_id)
                if flow is None:
                    logger.warning(
                        "back_propagate_skip flow_id=%d not found", flow_id
                    )
                    return
                fsm = FlowStateMachine(
                    flow_id=flow.id,
                    current_status=flow.status,
                    db=db,
                )
            if is_valid_transition(fsm.current_status, target_flow_status):
                await fsm.transition(target_flow_status)
            return

        logger.warning(
            "back_propagate_skip unknown_child_entity=%s", child_entity
        )
    except InvalidStateTransitionError as exc:
        logger.warning(
            "back_propagate_invalid_transition err=%s", exc
        )
    except Exception as exc:  # noqa: BLE001 — best-effort propagation.
        logger.error(
            "back_propagate_failed child_entity=%s child_status=%s err=%s",
            child_entity,
            child_val,
            exc,
        )


# ---------------------------------------------------------------------------
# Convenience builders.
# ---------------------------------------------------------------------------


async def build_flow_state_machine(db: FlowDB, flow_id: int) -> FlowStateMachine:
    """Build a :class:`FlowStateMachine` from the DB row for ``flow_id``."""
    flow = await db.get_flow(flow_id)
    if flow is None:
        raise ValueError(f"flow {flow_id} not found")
    return FlowStateMachine(
        flow_id=flow.id,
        current_status=flow.status,
        db=db,
    )


async def build_task_state_machine(db: FlowDB, task_id: int) -> TaskStateMachine:
    """Build a :class:`TaskStateMachine` from the DB row for ``task_id``."""
    task = await db.get_task(task_id)
    if task is None:
        raise ValueError(f"task {task_id} not found")
    return TaskStateMachine(
        task_id=task.id,
        current_status=task.status,
        flow_id=task.flow_id,
        db=db,
    )


async def build_subtask_state_machine(
    db: FlowDB, subtask_id: int
) -> SubtaskStateMachine:
    """Build a :class:`SubtaskStateMachine` from the DB row for ``subtask_id``."""
    subtask = await db.get_subtask(subtask_id)
    if subtask is None:
        raise ValueError(f"subtask {subtask_id} not found")
    task = await db.get_task(subtask.task_id)
    if task is None:
        raise ValueError(f"task {subtask.task_id} not found for subtask {subtask_id}")
    return SubtaskStateMachine(
        subtask_id=subtask.id,
        current_status=subtask.status,
        task_id=subtask.task_id,
        flow_id=task.flow_id,
        db=db,
    )


__all__ = [
    "InvalidStateTransitionError",
    "is_valid_transition",
    "BaseStateMachine",
    "FlowStateMachine",
    "TaskStateMachine",
    "SubtaskStateMachine",
    "back_propagate_status",
    "build_flow_state_machine",
    "build_task_state_machine",
    "build_subtask_state_machine",
]
