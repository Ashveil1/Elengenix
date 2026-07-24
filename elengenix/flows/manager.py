"""elengenix/flows/manager.py — FlowManager high-level orchestrator.

This module ties together the Flow / Task / Subtask workers into a
single high-level API that callers (CLI, REST API, tests) use to manage
flows. It owns a :class:`FlowDB` instance, a factory for
:class:`FlowProvider` instances, and a dict of active
:class:`FlowWorker` instances keyed by flow ID.

Public API
----------
* :meth:`FlowManager.create_flow` — insert a new Flow row + spawn its
  :class:`FlowWorker`, then submit the initial user input.
* :meth:`FlowManager.submit_input` — feed new input to a running (or
  waiting) flow.
* :meth:`FlowManager.stop_flow` — stop a running flow (cancels the
  current task + transitions the flow to WAITING).
* :meth:`FlowManager.get_flow_status` — re-read the flow's status from
  the DB.
* :meth:`FlowManager.get_flow_report` — assemble a Markdown report
  from the flow's task / subtask / msglog rows.
* :meth:`FlowManager.list_flows` — paginated flow listing.
* :meth:`FlowManager.delete_flow` — soft-delete a flow + stop its
  worker.

The :class:`FlowManager` is async-only and thread-safe via
:class:`asyncio.Lock` (one lock guards the ``_workers`` dict).

The FlowProvider factory is supplied by the caller via the
``provider_factory`` constructor argument — this lets the manager stay
decoupled from any specific LLM / agent implementation. The factory is
an async callable that takes a :class:`FlowContext` and returns a
:class:`FlowProvider`.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Awaitable, Callable, Optional

from elengenix.flows.db import FlowDB
from elengenix.flows.flow_worker import (
    FlowContext,
    FlowProvider,
    FlowWorker,
)
from elengenix.flows.models import (
    Flow,
    FlowStatus,
    MsglogResultFormat,
    MsglogType,
    ProviderType,
    TaskStatus,
)

logger = logging.getLogger("elengenix.flows.manager")

# Type alias for the FlowProvider factory — an async callable that takes
# a FlowContext and returns a FlowProvider. The factory is called once
# per create_flow() to wire up the agent layer (Generator / Refiner /
# Reporter / PrimaryAgent specialists) for the new flow.
ProviderFactory = Callable[[FlowContext], Awaitable[FlowProvider]]


# Default provider factory — raises NotImplementedError. Callers must
# supply their own factory (typically wired up by the FastAPI app
# startup or the CLI bootstrap).
async def _default_provider_factory(_ctx: FlowContext) -> FlowProvider:
    """Default provider factory — raises ``NotImplementedError``.

    Callers must supply their own ``provider_factory`` to the
    :class:`FlowManager` constructor. The default exists so that
    ``FlowManager()`` can be instantiated in tests without an agent
    layer.
    """

    raise NotImplementedError(
        "no FlowProvider factory configured — pass `provider_factory` "
        "to FlowManager()"
    )


class FlowManager:
    """High-level orchestrator for the Flow management system.

    Owns a :class:`FlowDB` and a dict of active :class:`FlowWorker`
    instances. Each ``create_flow`` call spawns a new worker in an
    :class:`asyncio.create_task`; each ``stop_flow`` / ``delete_flow``
    call stops + removes the worker.

    Usage::

        manager = FlowManager(provider_factory=my_factory)
        await manager.start()
        try:
            flow = await manager.create_flow(
                user_id=1, title="pentest", input="scan example.com",
                model="gpt-4o", language="English",
            )
            # ... interact with the flow ...
            await manager.submit_input(flow.id, "now do X")
            report = await manager.get_flow_report(flow.id)
        finally:
            await manager.shutdown()
    """

    def __init__(
        self,
        *,
        provider_factory: ProviderFactory = _default_provider_factory,
        db: FlowDB | None = None,
        db_path: str | None = None,
    ) -> None:
        """Initialize the FlowManager.

        Args:
            provider_factory: Async callable that builds a
                :class:`FlowProvider` for a given :class:`FlowContext`.
                Called once per :meth:`create_flow`.
            db: Optional pre-configured :class:`FlowDB` instance. If
                ``None``, a new one is built from ``db_path`` (or the
                default ``~/.elengenix/data/flows.db``).
            db_path: Optional DB path override (used only when ``db``
                is ``None``).
        """
        self._db: FlowDB = db if db is not None else FlowDB(db_path=db_path)
        self._provider_factory: ProviderFactory = provider_factory
        self._workers: dict[int, FlowWorker] = {}
        self._workers_mx: asyncio.Lock = asyncio.Lock()
        self._started: bool = False
        self._start_mx: asyncio.Lock = asyncio.Lock()

    # ── lifecycle ──────────────────────────────────────────────────────

    async def start(self) -> None:
        """Open the DB connection (idempotent)."""
        async with self._start_mx:
            if self._started:
                return
            await self._db.connect()
            self._started = True
            logger.info("FlowManager started")

    async def shutdown(self) -> None:
        """Stop all workers + close the DB connection (idempotent)."""
        async with self._start_mx:
            if not self._started:
                return
            # Stop all active workers.
            async with self._workers_mx:
                workers = list(self._workers.values())
                self._workers.clear()
            for w in workers:
                try:
                    await w.stop()
                except Exception as exc:  # noqa: BLE001
                    logger.warning(
                        "FlowManager.shutdown worker_stop_failed flow_id=%d err=%s",
                        w.flow_id,
                        exc,
                    )
            await self._db.close()
            self._started = False
            logger.info("FlowManager shut down")

    @property
    def db(self) -> FlowDB:
        """The underlying :class:`FlowDB` instance."""
        return self._db

    @property
    def is_started(self) -> bool:
        """``True`` if :meth:`start` has been called."""
        return self._started

    # ── core API ───────────────────────────────────────────────────────

    async def create_flow(
        self,
        *,
        user_id: int,
        title: str,
        input: str,
        model: str,
        language: str = "English",
        image: str | None = None,
        model_provider_name: str = "",
        model_provider_type: ProviderType | str = ProviderType.OPENAI,
        functions: dict[str, Any] | None = None,
        tool_call_id_template: str = "",
    ) -> Flow:
        """Create a new Flow + spawn its FlowWorker + submit the initial input.

        Mirrors PentAGI's ``NewFlowWorker``. Flow:
            1. Insert a Flow row (status=CREATED).
            2. Build a :class:`FlowContext` (DB + provider + IDs).
            3. Build the :class:`FlowProvider` via the factory.
            4. Construct the :class:`FlowWorker`.
            5. Submit the initial user input via ``worker.submit_input``.
            6. Cache the worker in ``_workers``.

        Args:
            user_id: Owning user ID.
            title: Flow title (used as the initial title; the Generator
                may override it via ``get_task_title``).
            input: Initial user input text.
            model: LLM model identifier (e.g. ``"gpt-4o"``).
            language: Engagement-log language (default ``"English"``).
            image: Optional Docker image override for the sandbox
                container (``None`` uses the provider default).
            model_provider_name: Provider name (e.g. ``"openai"``).
            model_provider_type: Provider type enum value.
            functions: Serialized tool registry (default empty dict).
            tool_call_id_template: Template for generating tool-call IDs.

        Returns:
            The created :class:`Flow` (with the assigned ID).
        """
        await self.start()

        # Resolve the provider-type enum (accept either enum or string).
        if isinstance(model_provider_type, ProviderType):
            mpt = model_provider_type
        else:
            mpt = ProviderType(model_provider_type)

        flow = await self._db.create_flow(
            user_id=user_id,
            title=title,
            input=input,
            model=model,
            model_provider_name=model_provider_name,
            model_provider_type=mpt,
            language=language,
            functions=functions or {},
            tool_call_id_template=tool_call_id_template,
        )
        logger.info(
            "FlowManager.create_flow created flow_id=%d user_id=%d title=%r",
            flow.id,
            user_id,
            title,
        )

        # Build the FlowContext + provider.
        flow_ctx = FlowContext(
            db=self._db,
            flow_id=flow.id,
            user_id=user_id,
            provider=None,  # type: ignore[arg-type]
            trace_id=flow.trace_id,
        )
        provider = await self._provider_factory(flow_ctx)
        flow_ctx.provider = provider

        # Construct + cache the FlowWorker.
        worker = FlowWorker(flow=flow, flow_ctx=flow_ctx)
        async with self._workers_mx:
            self._workers[flow.id] = worker

        # Submit the initial input (starts the background worker loop).
        try:
            await worker.submit_input(input)
        except Exception as exc:  # noqa: BLE001
            logger.error(
                "FlowManager.create_flow submit_input_failed flow_id=%d err=%s",
                flow.id,
                exc,
            )
            # Don't remove the worker — the user can retry via submit_input.
            raise

        return flow

    async def submit_input(self, flow_id: int, input: str) -> "Any":
        """Submit new input to a running / waiting flow.

        Returns the :class:`TaskWorker` that was created or resumed (or
        ``None`` if the worker has been stopped).

        Raises:
            KeyError: If the flow has no active worker.
            RuntimeError: If the worker has been stopped.
        """
        await self.start()
        worker = await self._get_worker(flow_id)
        if worker is None:
            raise KeyError(f"flow {flow_id} has no active worker")
        return await worker.submit_input(input)

    async def stop_flow(self, flow_id: int) -> None:
        """Stop a running flow (cancels the current task).

        Mirrors PentAGI's ``stopFlow`` mutation. Calls ``worker.stop()``
        which cancels the current task + transitions the flow to
        WAITING. The worker remains cached so subsequent ``submit_input``
        calls can resume processing.
        """
        worker = await self._get_worker(flow_id)
        if worker is None:
            logger.warning(
                "FlowManager.stop_flow no_worker flow_id=%d", flow_id
            )
            return
        await worker.stop()

    async def get_flow_status(self, flow_id: int) -> FlowStatus:
        """Return the flow's current status (re-read from the DB)."""
        await self.start()
        flow = await self._db.get_flow(flow_id)
        if flow is None:
            return FlowStatus.FAILED
        return flow.status

    async def get_flow_report(self, flow_id: int) -> str:
        """Assemble a Markdown report for the flow.

        Iterates over the flow's tasks (in creation order) and emits
        one section per task with its title, status, and result. The
        report ends with an aggregate usage summary (token counts +
        cost) from :meth:`FlowDB.get_flow_usage`.
        """
        await self.start()
        flow = await self._db.get_flow(flow_id)
        if flow is None:
            return f"# Flow {flow_id} not found\n"

        tasks = await self._db.list_tasks(flow_id)
        lines: list[str] = []
        lines.append(f"# {flow.title}")
        lines.append("")
        lines.append(
            f"- **Flow ID**: {flow.id}  "
            f"- **Status**: `{flow.status.value}`  "
            f"- **Model**: `{flow.model}`"
        )
        lines.append(
            f"- **Language**: {flow.language}  "
            f"- **Tasks**: {len(tasks)}"
        )
        lines.append("")

        if not tasks:
            lines.append("_(no tasks yet)_")
            lines.append("")
        else:
            for task in tasks:
                lines.append(f"## Task #{task.id}: {task.title}")
                lines.append("")
                lines.append(f"- **Status**: `{task.status.value}`")
                lines.append("")
                lines.append("**Input:**")
                lines.append("```")
                lines.append(task.input)
                lines.append("```")
                lines.append("")
                if task.result:
                    lines.append("**Result:**")
                    lines.append("")
                    lines.append(task.result)
                    lines.append("")
                # Subtasks summary.
                subtasks = await self._db.list_subtasks(task.id)
                if subtasks:
                    lines.append("**Subtasks:**")
                    lines.append("")
                    lines.append("| # | Status | Title |")
                    lines.append("|---|--------|-------|")
                    for st in subtasks:
                        lines.append(
                            f"| {st.id} | `{st.status.value}` | {st.title} |"
                        )
                    lines.append("")

        # Aggregate usage.
        usage = await self._db.get_flow_usage(flow_id)
        if usage["usage_in"] or usage["usage_out"]:
            lines.append("## Usage")
            lines.append("")
            lines.append(
                f"- Prompt tokens: {usage['usage_in']} "
                f"(cached: {usage['usage_cache_in']})"
            )
            lines.append(
                f"- Completion tokens: {usage['usage_out']} "
                f"(cached: {usage['usage_cache_out']})"
            )
            lines.append(
                f"- Cost: ${usage['usage_cost_in'] + usage['usage_cost_out']:.4f} "
                f"(duration: {usage['duration_seconds']:.1f}s)"
            )
            lines.append("")

        return "\n".join(lines)

    async def list_flows(
        self,
        *,
        user_id: int | None = None,
        status: FlowStatus | str | None = None,
        offset: int = 0,
        limit: int = 100,
    ) -> list[Flow]:
        """List flows, optionally filtered by user / status (paginated)."""
        await self.start()
        return await self._db.list_flows(
            user_id=user_id,
            status=status,
            offset=offset,
            limit=limit,
        )

    async def delete_flow(self, flow_id: int) -> bool:
        """Soft-delete a flow + stop its worker.

        Returns ``True`` if the flow was deleted, ``False`` if it was
        already deleted or didn't exist.
        """
        await self.start()
        # Stop + remove the worker.
        async with self._workers_mx:
            worker = self._workers.pop(flow_id, None)
        if worker is not None:
            try:
                await worker.stop()
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "FlowManager.delete_flow worker_stop_failed flow_id=%d err=%s",
                    flow_id,
                    exc,
                )
        # Soft-delete the flow row.
        deleted = await self._db.delete_flow(flow_id)
        if deleted:
            logger.info("FlowManager.delete_flow deleted flow_id=%d", flow_id)
        return deleted

    # ── internal helpers ───────────────────────────────────────────────

    async def _get_worker(self, flow_id: int) -> FlowWorker | None:
        """Return the cached :class:`FlowWorker` for ``flow_id`` (or ``None``)."""
        async with self._workers_mx:
            return self._workers.get(flow_id)

    async def get_worker(self, flow_id: int) -> FlowWorker | None:
        """Public accessor for the cached :class:`FlowWorker` (or ``None``)."""
        return await self._get_worker(flow_id)

    async def wait_task_completion(
        self, flow_id: int, timeout: float | None = None
    ) -> None:
        """Block until the currently running task in ``flow_id`` completes.

        Thin wrapper around :meth:`FlowWorker.wait_task_completion`.
        """
        worker = await self._get_worker(flow_id)
        if worker is None:
            return
        await worker.wait_task_completion(timeout=timeout)


__all__ = ["FlowManager", "ProviderFactory"]
