"""elengenix.flows — Flow management system (Flow → Task → SubTask → Action).

This package ports PentAGI's 4-tier orchestrator hierarchy
(``backend/pkg/controller/{flow,task,subtask,subtasks}.go``) to Python.
Each tier owns a 5-state machine
(created → running → waiting ⇄ running → finished | failed) with
back-propagation: when a subtask transitions, the change propagates up
to its parent task and from the task up to its parent flow.

Modules
-------
* :mod:`elengenix.flows.models`        — Pydantic v2 data models +
  enums (FlowStatus / TaskStatus / SubtaskStatus / MsgchainType +
  supporting log enums).
* :mod:`elengenix.flows.db`            — async SQLite persistence
  (aiosqlite) with full schema mirroring PentAGI's
  ``database/models.go``.
* :mod:`elengenix.flows.state_machine` — 5-state machine +
  :func:`back_propagate_status` helper.
* :mod:`elengenix.flows.flow_worker`   — :class:`FlowWorker` (topmost
  worker) + :class:`FlowProvider` Protocol + FlowContext /
  TaskContext / SubtaskContext dataclasses.
* :mod:`elengenix.flows.task_worker`   — :class:`TaskWorker` (middle
  tier; runs the Generator → SubtaskWorker.Run → Refiner loop).
* :mod:`elengenix.flows.subtask_worker`— :class:`SubtaskWorker` (leaf
  tier; runs one iteration of :func:`perform_agent_chain`).
* :mod:`elengenix.flows.manager`       — :class:`FlowManager` high-level
  orchestrator (the public API used by the CLI / REST API / tests).

Concurrency model
-----------------
* ``asyncio.Lock`` replaces Go's ``sync.Mutex`` / ``sync.RWMutex``.
* ``asyncio.Queue`` replaces Go's ``chan flowInput``.
* ``asyncio.Event`` replaces Go's ``chan struct{}`` for completion signaling.
* ``asyncio.create_task`` replaces Go's ``go func()``.
* ``contextvars.ContextVar`` replaces Go's ``context.Value`` for
  propagating the active :class:`AgentContext` (parent / current agent
  type) through spawned asyncio tasks.

Default DB path
---------------
``~/.elengenix/data/flows.db`` (overridable via the
``ELENGENIX_FLOWS_DB`` environment variable or the ``db_path`` argument
to :class:`FlowDB` / :class:`FlowManager`).
"""

from __future__ import annotations

from elengenix.flows.db import FlowDB
from elengenix.flows.flow_worker import (
    FLOW_INPUT_TIMEOUT,
    STOP_TASK_TIMEOUT,
    FlowContext,
    FlowProvider,
    FlowWorker,
    SubtaskContext,
    TaskContext,
    TaskResult,
)
from elengenix.flows.manager import FlowManager, ProviderFactory
from elengenix.flows.models import (
    Agentlog,
    Container,
    ContainerStatus,
    ContainerType,
    Flow,
    FlowStatus,
    Msgchain,
    MsgchainType,
    Msglog,
    MsglogResultFormat,
    MsglogType,
    Prompt,
    ProviderType,
    Screenshot,
    SearchengineType,
    Searchlog,
    Subtask,
    SubtaskInfo,
    SubtaskPatchOp,
    SubtaskStatus,
    Task,
    TaskStatus,
    Termlog,
    TermlogType,
    Toolcall,
    ToolcallStatus,
    VecstoreActionType,
    Vecstorelog,
)
from elengenix.flows.state_machine import (
    BaseStateMachine,
    FlowStateMachine,
    InvalidStateTransitionError,
    SubtaskStateMachine,
    TaskStateMachine,
    back_propagate_status,
    build_flow_state_machine,
    build_subtask_state_machine,
    build_task_state_machine,
    is_valid_transition,
)
from elengenix.flows.subtask_worker import SubtaskWorker
from elengenix.flows.task_worker import TASKS_NUMBER_LIMIT, TaskWorker

__all__ = [
    # DB
    "FlowDB",
    # Models
    "Flow",
    "Task",
    "Subtask",
    "FlowStatus",
    "TaskStatus",
    "SubtaskStatus",
    "MsgchainType",
    "Msgchain",
    "Msglog",
    "MsglogType",
    "MsglogResultFormat",
    "Agentlog",
    "Toolcall",
    "ToolcallStatus",
    "Searchlog",
    "SearchengineType",
    "Termlog",
    "TermlogType",
    "Vecstorelog",
    "VecstoreActionType",
    "Screenshot",
    "Container",
    "ContainerStatus",
    "ContainerType",
    "Prompt",
    "ProviderType",
    "SubtaskInfo",
    "SubtaskPatchOp",
    # State machine
    "BaseStateMachine",
    "FlowStateMachine",
    "TaskStateMachine",
    "SubtaskStateMachine",
    "InvalidStateTransitionError",
    "is_valid_transition",
    "back_propagate_status",
    "build_flow_state_machine",
    "build_task_state_machine",
    "build_subtask_state_machine",
    # Workers
    "FlowProvider",
    "FlowContext",
    "TaskContext",
    "SubtaskContext",
    "TaskResult",
    "FlowWorker",
    "TaskWorker",
    "SubtaskWorker",
    "TASKS_NUMBER_LIMIT",
    "FLOW_INPUT_TIMEOUT",
    "STOP_TASK_TIMEOUT",
    # Manager
    "FlowManager",
    "ProviderFactory",
]
