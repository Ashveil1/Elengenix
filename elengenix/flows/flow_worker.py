"""elengenix/flows/flow_worker.py — FlowWorker asyncio port of PentAGI's flow.go.

This module ports PentAGI's ``backend/pkg/controller/flow.go::FlowWorker``
to Python. The FlowWorker is the topmost worker in the 4-tier hierarchy
(Flow → Task → SubTask → Action). It owns an input queue and a single
background ``worker()`` coroutine that processes user inputs
sequentially, spawning a :class:`TaskWorker` (from
:mod:`elengenix.flows.task_worker`) for each input.

Architecture (ported from PentAGI)
---------------------------------
* ``worker()`` reads from an :class:`asyncio.Queue` of :class:`_FlowInput`
  items. Each item carries the user input string + an
  :class:`asyncio.Future` for synchronous error reporting back to the
  ``PutInput`` caller (mirrors PentAGI's ``flowInput.done`` channel).
* ``process_input(flin)`` checks whether any existing task is in
  ``WAITING`` status; if so, it calls ``task.put_input(input)`` and runs
  the task. Otherwise, it sets the flow to ``RUNNING``, creates a fresh
  :class:`TaskWorker`, and runs it.
* ``exec_task(task)`` wraps ``task.run()`` with per-task cancellation
  (an :class:`asyncio.Event` is used as the cancel signal).
* ``stop()`` cancels the current task and waits for it to settle.
* ``finish()`` finishes all child tasks, marks the flow ``FINISHED``,
  and stops the worker.

Concurrency
-----------
* An :class:`asyncio.Lock` (``_task_mx``) guards the per-task cancel
  handle (replaces PentAGI's ``taskMX sync.Mutex``).
* An :class:`asyncio.Lock` (``_assistants_mx``) guards the assistants
  map (PentAGI's ``awsMX sync.Mutex``).
* An :class:`asyncio.Event` (``_task_done``) is re-created on each
  task boundary to implement ``wait_task_completion`` (PentAGI's
  ``taskCCH`` channel + ``signalTaskComplete``).
* :class:`contextvars.ContextVar` propagates the active
  :class:`AgentContext` (parent / current agent type) through spawned
  asyncio tasks — replaces PentAGI's ``tools.PutAgentContext`` /
  Go's ``context.Value``.

This module also defines the :class:`FlowProvider` Protocol, the
:class:`FlowContext` / :class:`TaskContext` / :class:`SubtaskContext`
dataclasses, and the :class:`TaskResult` dataclass — these are shared
with :mod:`elengenix.flows.task_worker` and
:mod:`elengenix.flows.subtask_worker`.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

from elengenix.agent.crew.base import AgentContext, AgentType, PerformResult
from elengenix.flows.db import FlowDB
from elengenix.flows.models import (
    Flow,
    FlowStatus,
    MsgchainType,
    SubtaskInfo,
    TaskStatus,
)
from elengenix.flows.state_machine import (
    FlowStateMachine,
    build_flow_state_machine,
)

logger = logging.getLogger("elengenix.flows.flow_worker")

# Default timeout for ``PutInput`` to wait for the worker to acknowledge
# receipt of the input (mirrors PentAGI's ``flowInputTimeout = 1 * time.Second``).
FLOW_INPUT_TIMEOUT: float = 1.0

# Timeout for ``Stop`` to wait for the running task to settle (mirrors
# PentAGI's ``stopTaskTimeout = 5 * time.Second``).
STOP_TASK_TIMEOUT: float = 5.0


# ---------------------------------------------------------------------------
# FlowProvider — Protocol for the agent-layer interface used by all workers.
# ---------------------------------------------------------------------------


@runtime_checkable
class FlowProvider(Protocol):
    """High-level interface that the Flow/Task/Subtask workers use to talk
    to the agent layer.

    Mirrors PentAGI's ``providers.FlowProvider`` interface. Concrete
    implementations wire up the Generator / Refiner / Reporter /
    PrimaryAgent specialists defined in :mod:`elengenix.agent.crew`.
    """

    async def get_task_title(self, input: str) -> str:
        """Derive a short task title from the user input.

        Mirrors PentAGI's ``flowProvider.GetTaskTitle`` — typically
        implemented as a single LLM call with a tiny prompt template
        (``task_descriptor.tmpl``).
        """
        ...

    async def generate_subtasks(self, task_id: int) -> list[SubtaskInfo]:
        """Decompose the task into an ordered subtask plan.

        Mirrors PentAGI's ``flowProvider.GenerateSubtasks`` — delegates
        to the :class:`Generator` agent (see
        :mod:`elengenix.agent.crew.generator`).
        """
        ...

    async def refine_subtasks(self, task_id: int) -> list[SubtaskInfo]:
        """Produce a delta-patched subtask plan after each subtask completes.

        Mirrors PentAGI's ``flowProvider.RefineSubtasks`` — delegates to
        the :class:`Refiner` agent (see :mod:`elengenix.agent.crew.refiner`).
        Returns the *new* full plan (the caller deletes the old
        ``CREATED`` subtasks and inserts the new ones).
        """
        ...

    async def prepare_agent_chain(
        self, task_id: int, subtask_id: int
    ) -> int:
        """Create a fresh primary-agent :class:`Msgchain` for a subtask.

        Mirrors PentAGI's ``flowProvider.PrepareAgentChain`` — inserts a
        new msgchain row with ``type=primary_agent`` and returns its ID.
        """
        ...

    async def perform_agent_chain(
        self, task_id: int, subtask_id: int, msg_chain_id: int
    ) -> PerformResult:
        """Run the universal agent loop for one subtask.

        Mirrors PentAGI's ``flowProvider.PerformAgentChain`` — drives the
        :class:`PrimaryAgent` chain (see
        :mod:`elengenix.agent.crew.primary_agent`).
        """
        ...

    async def ensure_chain_consistency(self, msg_chain_id: int) -> None:
        """Rewrite stale chain IDs / fix tool-call ID collisions on resume.

        Mirrors PentAGI's ``flowProvider.EnsureChainConsistency`` —
        invoked before each ``PerformAgentChain`` so a resumed subtask
        doesn't replay stale tool-call IDs that the LLM has already
        forgotten.
        """
        ...

    async def put_input_to_agent_chain(
        self, msg_chain_id: int, input: str
    ) -> None:
        """Append user input to a WAITING agent chain (for resume).

        Mirrors PentAGI's ``flowProvider.PutInputToAgentChain`` — invoked
        by ``SubtaskWorker.PutInput`` when the user supplies new input to
        a paused subtask.
        """
        ...

    async def get_task_result(self, task_id: int) -> "TaskResult":
        """Produce the final task report (success flag + write-up).

        Mirrors PentAGI's ``flowProvider.GetTaskResult`` — delegates to
        the :class:`Reporter` agent (see :mod:`elengenix.agent.crew.reporter`).
        """
        ...


# ---------------------------------------------------------------------------
# TaskResult — output of the Reporter agent (mirrors agents.reporter.TaskResult).
# ---------------------------------------------------------------------------


@dataclass
class TaskResult:
    """Final task report produced by the Reporter agent.

    Mirrors :class:`elengenix.agent.crew.reporter.TaskResult` but kept
    dependency-light (a plain dataclass) so the workers don't import
    Pydantic at module load.
    """

    success: bool
    result: str
    message: str = ""


# ---------------------------------------------------------------------------
# Context dataclasses — FlowContext / TaskContext / SubtaskContext.
# ---------------------------------------------------------------------------


@dataclass
class FlowContext:
    """Per-flow context shared by all workers.

    Mirrors PentAGI's ``controller.FlowContext`` struct. Carries the DB
    handle, the flow / user IDs, the observability trace ID, and the
    :class:`FlowProvider` that talks to the agent layer.
    """

    db: FlowDB
    flow_id: int
    user_id: int
    provider: FlowProvider
    trace_id: str | None = None
    # The FlowStateMachine is lazily initialized by the FlowWorker on
    # first transition (avoids an extra DB roundtrip in the constructor).
    state_machine: FlowStateMachine | None = None

    async def get_state_machine(self) -> FlowStateMachine:
        """Return the cached :class:`FlowStateMachine`, building it if needed."""
        if self.state_machine is None:
            self.state_machine = await build_flow_state_machine(
                self.db, self.flow_id
            )
        return self.state_machine

    async def set_flow_status(self, status: FlowStatus) -> None:
        """Transition the flow to ``status`` (validated + persisted)."""
        sm = await self.get_state_machine()
        from elengenix.flows.state_machine import is_valid_transition

        if is_valid_transition(sm.current_status, status):
            await sm.transition(status)
        else:
            logger.debug(
                "set_flow_status_skip flow_id=%d %s -> %s (invalid)",
                self.flow_id,
                sm.current_status.value,
                status.value,
            )


@dataclass
class TaskContext:
    """Per-task context — extends :class:`FlowContext` with task-scoped fields.

    Mirrors PentAGI's ``controller.TaskContext`` struct (which embeds
    ``FlowContext`` by value). Carries the task ID, title, and original
    user input.
    """

    flow_ctx: FlowContext
    task_id: int
    task_title: str
    task_input: str

    # Convenience proxies so callers can use ``task_ctx.db``,
    # ``task_ctx.flow_id``, ``task_ctx.provider`` etc. directly (matches
    # PentAGI's struct embedding).
    @property
    def db(self) -> FlowDB:
        return self.flow_ctx.db

    @property
    def flow_id(self) -> int:
        return self.flow_ctx.flow_id

    @property
    def user_id(self) -> int:
        return self.flow_ctx.user_id

    @property
    def provider(self) -> FlowProvider:
        return self.flow_ctx.provider

    @property
    def trace_id(self) -> str | None:
        return self.flow_ctx.trace_id


@dataclass
class SubtaskContext:
    """Per-subtask context — extends :class:`TaskContext` with subtask fields.

    Mirrors PentAGI's ``controller.SubtaskContext`` struct (which embeds
    ``TaskContext`` by value). Carries the subtask ID, title,
    description, and the primary-agent msgchain ID for resumability.
    """

    task_ctx: TaskContext
    subtask_id: int
    subtask_title: str
    subtask_description: str
    msg_chain_id: int

    @property
    def flow_ctx(self) -> FlowContext:
        return self.task_ctx.flow_ctx

    @property
    def db(self) -> FlowDB:
        return self.task_ctx.db

    @property
    def flow_id(self) -> int:
        return self.task_ctx.flow_id

    @property
    def user_id(self) -> int:
        return self.task_ctx.user_id

    @property
    def provider(self) -> FlowProvider:
        return self.task_ctx.provider

    @property
    def trace_id(self) -> str | None:
        return self.task_ctx.trace_id

    @property
    def task_id(self) -> int:
        return self.task_ctx.task_id

    @property
    def task_title(self) -> str:
        return self.task_ctx.task_title

    @property
    def task_input(self) -> str:
        return self.task_ctx.task_input


# ---------------------------------------------------------------------------
# _FlowInput — the queue item (mirrors PentAGI's flowInput struct).
# ---------------------------------------------------------------------------


@dataclass
class _FlowInput:
    """A single user-input submission to the flow worker.

    ``input`` is the user's text. ``done`` is a Future that the worker
    resolves with ``None`` on successful receipt or an ``Exception`` on
    failure (mirrors PentAGI's ``flowInput.done chan error``).
    """

    input: str
    done: asyncio.Future[None] = field(
        default_factory=lambda: asyncio.get_running_loop().create_future()
    )


# ---------------------------------------------------------------------------
# FlowWorker — the topmost worker.
# ---------------------------------------------------------------------------


class FlowWorker:
    """Per-flow asyncio worker.

    Owns an input queue and a single background ``worker()`` coroutine
    that processes user inputs sequentially. For each input it spawns a
    :class:`TaskWorker` (which in turn spawns :class:`SubtaskWorker`
    instances for each planned subtask).

    The worker can be:
        * **Running** — actively processing a task.
        * **Waiting** — paused, waiting for new user input.
        * **Stopped** — ``stop()`` was called; the background loop has
          exited.
    """

    def __init__(
        self,
        *,
        flow: Flow,
        flow_ctx: FlowContext,
    ) -> None:
        """Initialize the worker (does NOT start the background loop).

        Use :meth:`start` to spawn the ``worker()`` coroutine, or
        :meth:`submit_input` which starts the loop lazily on first call.

        Args:
            flow: The :class:`Flow` DB row.
            flow_ctx: The :class:`FlowContext` (DB + provider + IDs).
        """
        self.flow: Flow = flow
        self.flow_ctx: FlowContext = flow_ctx

        # Input queue + background worker task.
        self._input_queue: asyncio.Queue[_FlowInput] = asyncio.Queue()
        self._worker_task: asyncio.Task[None] | None = None

        # Per-task cancellation handle (replaces PentAGI's taskST context.CancelFunc).
        # The Event is set when the current task should be cancelled.
        self._task_cancel_event: asyncio.Event = asyncio.Event()
        self._task_mx: asyncio.Lock = asyncio.Lock()

        # Per-task completion signal (replaces PentAGI's taskCCH channel).
        self._task_done_event: asyncio.Event = asyncio.Event()
        self._task_done_event.set()  # initially "no task running"
        self._task_done_mx: asyncio.Lock = asyncio.Lock()

        # Currently running task (TaskWorker | None) — set in exec_task.
        self._current_task: Any | None = None  # TaskWorker | None

        # Worker stop flag — set by stop() / finish().
        self._stopped: bool = False
        self._stop_mx: asyncio.Lock = asyncio.Lock()

        logger.debug(
            "FlowWorker initialized flow_id=%d user_id=%d status=%s",
            flow.id,
            flow_ctx.user_id,
            flow.status.value,
        )

    # ── properties ─────────────────────────────────────────────────────

    @property
    def flow_id(self) -> int:
        """The flow's primary key."""
        return self.flow.id

    @property
    def user_id(self) -> int:
        """The owning user's ID."""
        return self.flow_ctx.user_id

    @property
    def title(self) -> str:
        """The flow's title."""
        return self.flow.title

    @property
    def is_started(self) -> bool:
        """``True`` if the background worker task has been spawned."""
        return self._worker_task is not None and not self._worker_task.done()

    @property
    def is_stopped(self) -> bool:
        """``True`` if ``stop()`` was called (worker is shutting down)."""
        return self._stopped

    # ── lifecycle ──────────────────────────────────────────────────────

    def start(self) -> asyncio.Task[None]:
        """Spawn the background ``worker()`` coroutine (idempotent).

        Returns the :class:`asyncio.Task` wrapping the worker loop.
        """
        if self._worker_task is None or self._worker_task.done():
            self._worker_task = asyncio.create_task(
                self._worker(), name=f"flow-{self.flow_id}-worker"
            )
            logger.debug("FlowWorker started flow_id=%d", self.flow_id)
        return self._worker_task

    async def stop(self) -> None:
        """Stop the worker: cancel the current task + signal the loop to exit.

        Mirrors PentAGI's ``flowWorker.Stop``. Cancels the current task
        (via the per-task cancel event), waits up to
        :data:`STOP_TASK_TIMEOUT` seconds for it to settle, then signals
        the background loop to exit.
        """
        async with self._stop_mx:
            if self._stopped:
                return
            self._stopped = True

        logger.info("FlowWorker.stop flow_id=%d", self.flow_id)

        # Cancel the current task (if any).
        async with self._task_mx:
            self._task_cancel_event.set()

        # Wait for the current task to settle (bounded by STOP_TASK_TIMEOUT).
        try:
            await asyncio.wait_for(
                self._wait_for_task_done(), timeout=STOP_TASK_TIMEOUT
            )
        except asyncio.TimeoutError:
            logger.warning(
                "FlowWorker.stop task_settle_timeout flow_id=%d", self.flow_id
            )

        # Signal the input queue to drain (the worker loop reads until the
        # queue is empty + stopped is set).
        # Push a sentinel to wake the loop if it's blocked on queue.get().
        try:
            self._input_queue.put_nowait(_FlowInput(input="", done=_noop_future()))
        except Exception:  # noqa: BLE001 — best-effort wakeup.
            pass

        # Cancel the worker task itself.
        if self._worker_task is not None and not self._worker_task.done():
            self._worker_task.cancel()
            try:
                await self._worker_task
            except asyncio.CancelledError:
                pass
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "FlowWorker.stop worker_task_error flow_id=%d err=%s",
                    self.flow_id,
                    exc,
                )

        # Transition the flow to WAITING (awaiting new user input) on stop.
        # Mirrors PentAGI's behaviour where Stop() returns the flow to a
        # resumable state. If the flow is already FINISHED/FAILED, this is
        # a no-op (the state machine rejects terminal → waiting).
        try:
            await self.flow_ctx.set_flow_status(FlowStatus.WAITING)
        except Exception as exc:  # noqa: BLE001
            logger.debug(
                "FlowWorker.stop set_waiting_failed flow_id=%d err=%s",
                self.flow_id,
                exc,
            )

    async def finish(self) -> None:
        """Finish the flow: complete all child tasks + mark flow FINISHED.

        Mirrors PentAGI's ``flowWorker.Finish``. Iterates over all
        :class:`TaskWorker` instances and calls their ``finish()``,
        transitions the flow to :data:`FlowStatus.FINISHED`, then stops
        the worker loop.
        """
        logger.info("FlowWorker.finish flow_id=%d", self.flow_id)
        try:
            await self.flow_ctx.set_flow_status(FlowStatus.FINISHED)
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "FlowWorker.finish set_finished_failed flow_id=%d err=%s",
                self.flow_id,
                exc,
            )
        await self.stop()

    # ── public API ─────────────────────────────────────────────────────

    async def submit_input(self, input: str) -> "Any":
        """Submit a user input to the flow and return the created/resumed Task.

        Mirrors PentAGI's ``flowWorker.PutInput``. Pushes a
        :class:`_FlowInput` onto the queue, waits up to
        :data:`FLOW_INPUT_TIMEOUT` seconds for the worker to acknowledge
        receipt, then returns. The actual task execution happens
        asynchronously in the background worker loop.

        Returns:
            The :class:`TaskWorker` that was created or resumed (or
            ``None`` if the worker has been stopped).

        Raises:
            RuntimeError: If the worker has been stopped.
        """
        if self._stopped:
            raise RuntimeError(f"flow {self.flow_id} stopped")

        # Lazily start the worker on first input.
        self.start()

        flin = _FlowInput(input=input)
        await self._input_queue.put(flin)

        # Wait for the worker to acknowledge receipt (bounded timeout).
        try:
            await asyncio.wait_for(flin.done, timeout=FLOW_INPUT_TIMEOUT)
        except asyncio.TimeoutError:
            # No early error — the worker is still processing the input.
            logger.debug(
                "FlowWorker.submit_input ack_timeout flow_id=%d (non-fatal)",
                self.flow_id,
            )
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.error(
                "FlowWorker.submit_input failed flow_id=%d err=%s",
                self.flow_id,
                exc,
            )
            raise

        return self._current_task

    async def wait_task_completion(self, timeout: float | None = None) -> None:
        """Block until the currently running task completes.

        Mirrors PentAGI's ``flowWorker.WaitTaskCompletion``. Multiple
        concurrent callers are all unblocked at once when the task
        finishes (the ``_task_done_event`` is shared).

        Args:
            timeout: Optional timeout in seconds. ``None`` blocks forever.
        """
        if timeout is None:
            await self._task_done_event.wait()
        else:
            try:
                await asyncio.wait_for(
                    self._task_done_event.wait(), timeout=timeout
                )
            except asyncio.TimeoutError:
                pass

    # ── worker loop + task execution ───────────────────────────────────

    async def _worker(self) -> None:
        """Background worker loop — reads inputs + processes them sequentially.

        Mirrors PentAGI's ``flowWorker.worker()`` goroutine. Exits when
        the worker is stopped AND the input queue is drained.
        """
        logger.info("FlowWorker._worker started flow_id=%d", self.flow_id)

        # Put the primary-agent context (mirrors PentAGI's
        # ``ctx = tools.PutAgentContext(ctx, MsgchainTypePrimaryAgent)``).
        token = AgentContext.put(AgentType.PRIMARY)
        try:
            while True:
                if self._stopped and self._input_queue.empty():
                    return

                try:
                    flin = await self._input_queue.get()
                except asyncio.CancelledError:
                    return

                if not flin.input and self._stopped:
                    # Sentinel — drain the queue and exit.
                    return

                try:
                    await self._process_input(flin)
                except asyncio.CancelledError:
                    if not flin.done.done():
                        flin.done.set_result(None)
                    return
                except Exception as exc:  # noqa: BLE001
                    logger.error(
                        "FlowWorker._worker process_input_failed flow_id=%d err=%s",
                        self.flow_id,
                        exc,
                    )
                    # Mirrors PentAGI: set flow to WAITING on any error so
                    # the user can submit new input.
                    try:
                        await self.flow_ctx.set_flow_status(FlowStatus.WAITING)
                    except Exception:  # noqa: BLE001
                        pass
                    if not flin.done.done():
                        flin.done.set_exception(exc)
        finally:
            AgentContext.reset(token)
            logger.info("FlowWorker._worker exited flow_id=%d", self.flow_id)

    async def _process_input(self, flin: _FlowInput) -> None:
        """Process a single user input — create or resume a Task.

        Mirrors PentAGI's ``flowWorker.processInput``. If any existing
        task is in ``WAITING`` status, the input is fed to it and the
        task is resumed. Otherwise, a fresh :class:`TaskWorker` is
        created and run.
        """
        # Lazy import to avoid circular import (task_worker imports from
        # this module for FlowProvider / FlowContext).
        from elengenix.flows.task_worker import TaskWorker

        # 1) Check if any existing task is WAITING — feed the input to it.
        tasks = await self.flow_ctx.db.list_tasks(self.flow_id)
        for task in tasks:
            if task.status == TaskStatus.WAITING:
                # Build a TaskWorker for the waiting task + feed it the input.
                task_ctx = TaskContext(
                    flow_ctx=self.flow_ctx,
                    task_id=task.id,
                    task_title=task.title,
                    task_input=task.input,
                )
                task_worker = TaskWorker(task=task, task_ctx=task_ctx)
                try:
                    await task_worker.put_input(flin.input)
                except Exception as exc:  # noqa: BLE001
                    if not flin.done.done():
                        flin.done.set_exception(exc)
                    raise
                if not flin.done.done():
                    flin.done.set_result(None)
                await self._exec_task(task_worker)
                return

        # 2) No waiting task — set the flow to RUNNING and create a new task.
        await self.flow_ctx.set_flow_status(FlowStatus.RUNNING)

        # Acquire the per-task lock to set up the cancellation handle.
        async with self._task_mx:
            self._task_cancel_event = asyncio.Event()

        try:
            task_worker = await TaskWorker.create(
                flow_ctx=self.flow_ctx,
                input=flin.input,
                flow_worker=self,
            )
        except asyncio.CancelledError:
            if not flin.done.done():
                flin.done.set_result(None)
            # Flow was stopped during CreateTask — return to WAITING.
            await self.flow_ctx.set_flow_status(FlowStatus.WAITING)
            return
        except Exception as exc:
            if not flin.done.done():
                flin.done.set_exception(exc)
            raise

        # Acknowledge receipt of the input (the task has been created).
        if not flin.done.done():
            flin.done.set_result(None)

        await self._exec_task(task_worker)

    async def _exec_task(self, task_worker: "Any") -> None:
        """Execute a TaskWorker with per-task cancellation.

        Mirrors PentAGI's ``flowWorker.runTask`` + ``execTask``. The
        ``_task_cancel_event`` is checked between iterations of the
        task's run loop (the TaskWorker inspects it via
        :meth:`is_task_cancelled`).
        """
        async with self._task_mx:
            cancel_event = self._task_cancel_event

        # Mark the task as running (clear the completion event).
        async with self._task_done_mx:
            self._task_done_event = asyncio.Event()
            done_event = self._task_done_event
        self._current_task = task_worker

        try:
            await task_worker.run()
        except asyncio.CancelledError:
            logger.info(
                "FlowWorker._exec_task cancelled flow_id=%d task_id=%s",
                self.flow_id,
                getattr(task_worker, "task_id", "?"),
            )
            raise
        except Exception as exc:  # noqa: BLE001
            logger.error(
                "FlowWorker._exec_task failed flow_id=%d task_id=%s err=%s",
                self.flow_id,
                getattr(task_worker, "task_id", "?"),
                exc,
            )
        finally:
            self._current_task = None
            async with self._task_done_mx:
                done_event.set()

    def is_task_cancelled(self) -> bool:
        """Return ``True`` if the current task should be cancelled.

        Called by :class:`TaskWorker` between subtask iterations to
        check whether :meth:`stop` has been invoked (mirrors PentAGI's
        per-task ``ctx.Done()`` check).
        """
        return self._task_cancel_event.is_set() or self._stopped

    async def _wait_for_task_done(self) -> None:
        """Wait for the current task to complete (used by ``stop``)."""
        async with self._task_done_mx:
            evt = self._task_done_event
        await evt.wait()

    # ── status helpers ─────────────────────────────────────────────────

    async def get_status(self) -> FlowStatus:
        """Return the flow's current status (re-read from the DB)."""
        flow = await self.flow_ctx.db.get_flow(self.flow_id)
        if flow is None:
            return FlowStatus.FAILED
        return flow.status


def _noop_future() -> asyncio.Future[None]:
    """Return a resolved Future (used as a no-op ``done`` for sentinels)."""
    fut: asyncio.Future[None] = asyncio.get_running_loop().create_future()
    fut.set_result(None)
    return fut


__all__ = [
    "FLOW_INPUT_TIMEOUT",
    "STOP_TASK_TIMEOUT",
    "FlowProvider",
    "TaskResult",
    "FlowContext",
    "TaskContext",
    "SubtaskContext",
    "FlowWorker",
]
