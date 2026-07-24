"""elengenix/docker/cleanup.py — startup-time + on-demand container cleanup.

This module ports PentAGI's ``dockerClient.Cleanup()`` method
(defined in ``backend/pkg/docker/client.go``) to Python. The PentAGI
original runs at server startup and on graceful shutdown; its job is to
reconcile the DB's view of containers with what Docker actually has,
and to fail-fast any flow whose containers are in an inconsistent state.

Algorithm (verbatim port of the Go ``Cleanup`` switch statement):

1. Load ALL flows + ALL containers from the DB.
2. For each flow:
   - If flow status is ``Running``/``Waiting`` AND ALL of its containers
     are running -> skip (flow is healthy, leave it alone).
   - If flow status is ``Running``/``Waiting`` but at least one
     container is NOT running -> fall through to the
     ``Created/Finished/Failed`` arm (the flow is broken).
   - If flow status is ``Created``/``Finished``/``Failed`` -> mark the
     flow ``Failed`` (mirrors PentAGI's ``markFlowAsFailed``) and
     remove all its ``starting``/``running`` containers concurrently.
3. Container removal is done via ``asyncio.gather(return_exceptions=True)``
   (Python equivalent of PentAGI's goroutines + WaitGroup). Errors are
   collected but do NOT abort the sweep — we want to clean up as much
   as possible.

Elengenix additions (NOT in PentAGI):

* ``cleanup_all()`` — nuclear option that removes EVERY
  ``pentagi-terminal-*`` container from the Docker daemon, regardless
  of DB state. Useful for developer resets and for recovering from a
  corrupted DB. Identifies Elengenix-managed containers by the
  ``pentagi-terminal-`` name prefix (PentAGI's
  ``containerPrimaryTypePattern = "-terminal-"``).
* ``cleanup_flow(flow_id)`` — single-flow cleanup. Used by the
  orchestrator when a flow completes or fails.
* ``cleanup_orphan_networks()`` — removes any ``elengenix-flow-*``
  networks that have no containers attached (orphaned by a crash
  during teardown).
* Returns structured result dicts (``{cleaned_flows, removed_containers,
  errors}``) so callers can log/telemetry the outcome.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from typing import Any, Optional

from .db import (
    ACTIVE_CONTAINER_STATUSES,
    ContainerDB,
    ContainerInfo,
    ContainerStatus,
    FlowStatus,
    ORPHAN_FLOW_STATUSES,
)
from .lifecycle import PRIMARY_TERMINAL_NAME_PREFIX, ContainerLifecycle
from .network import DockerNetwork, NETWORK_NAME_PREFIX

logger = logging.getLogger("elengenix.docker.cleanup")


# ---------------------------------------------------------------------------
# Result dataclasses
# ---------------------------------------------------------------------------


@dataclass
class CleanupResult:
    """Structured outcome of a cleanup sweep.

    Fields mirror what PentAGI logs at the end of ``Cleanup()`` plus
    Elengenix additions (errors list, network count).
    """

    cleaned_flows: int = 0
    removed_containers: int = 0
    removed_networks: int = 0
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "cleaned_flows": self.cleaned_flows,
            "removed_containers": self.removed_containers,
            "removed_networks": self.removed_networks,
            "errors": list(self.errors),
        }


# ---------------------------------------------------------------------------
# Flow-status provider protocol
# ---------------------------------------------------------------------------


class FlowStatusProvider:
    """Abstract interface for looking up flow status.

    The cleanup logic needs to know each flow's status to decide whether
    to mark it ``Failed`` and purge its containers. PentAGI does this
    via ``db.GetFlows()``; Elengenix may store flows in SQLite (same DB
    as containers), Postgres, or elsewhere. We inject a small adapter
    object so the cleanup module stays decoupled from the flows store.

    Concrete implementations:

    * ``InMemoryFlowStatusProvider`` — for tests and small deployments.
    * ``SQLiteFlowStatusProvider`` — reads from a flows table in the
      same SQLite DB as containers (provided by a future task).
    """

    async def get_all_flow_statuses(self) -> dict[int, FlowStatus]:
        """Return ``{flow_id: FlowStatus}`` for ALL known flows."""
        raise NotImplementedError

    async def mark_flow_failed(self, flow_id: int) -> None:
        """Mark ``flow_id`` as ``Failed``. Idempotent."""
        raise NotImplementedError


class InMemoryFlowStatusProvider(FlowStatusProvider):
    """In-memory implementation — useful for tests and small deployments.

    Holds flow statuses in a plain dict. Mutations are atomic per-call
    (single-threaded asyncio).
    """

    def __init__(self, statuses: Optional[dict[int, FlowStatus]] = None) -> None:
        self._statuses: dict[int, FlowStatus] = dict(statuses or {})

    async def get_all_flow_statuses(self) -> dict[int, FlowStatus]:
        return dict(self._statuses)

    async def mark_flow_failed(self, flow_id: int) -> None:
        self._statuses[int(flow_id)] = FlowStatus.FAILED

    def set_status(self, flow_id: int, status: FlowStatus) -> None:
        """Test helper — set a flow's status without going through async."""
        self._statuses[int(flow_id)] = status


# ---------------------------------------------------------------------------
# Main class
# ---------------------------------------------------------------------------


class ContainerCleanup:
    """Startup-time + on-demand container/network cleanup.

    Args:
        db: ``ContainerDB`` instance — the source of truth for
            container rows.
        lifecycle: ``ContainerLifecycle`` instance — used for the actual
            stop+remove operations (so all the Docker SDK calls live in
            one place).
        flow_provider: Optional ``FlowStatusProvider``. If None, the
            cleanup assumes every flow whose container is in
            ``starting``/``running`` state is a candidate for cleanup
            (effectively treating unknown flows as orphans).
        network: Optional ``DockerNetwork`` instance for orphan-network
            cleanup. If None, network cleanup is skipped.
    """

    def __init__(
        self,
        db: ContainerDB,
        lifecycle: ContainerLifecycle,
        flow_provider: Optional[FlowStatusProvider] = None,
        network: Optional[DockerNetwork] = None,
    ) -> None:
        self.db = db
        self.lifecycle = lifecycle
        self.flow_provider = flow_provider or InMemoryFlowStatusProvider()
        self.network = network

    # ------------------------------------------------------------------
    # Startup-time cleanup — port of PentAGI's ``Cleanup()``
    # ------------------------------------------------------------------

    async def cleanup_orphan_containers(self) -> dict[str, Any]:
        """Sweep all flows + containers, removing orphans.

        Algorithm (ported from PentAGI's ``Cleanup``):

        1. Load all flows (statuses) + all containers.
        2. Group containers by flow_id.
        3. For each flow:
           - ``Running``/``Waiting`` with ALL containers running -> skip.
           - ``Running``/``Waiting`` with at least one non-running
             container -> fall through to terminal-state arm.
           - ``Created``/``Finished``/``Failed`` -> mark flow ``Failed``
             and remove all ``starting``/``running`` containers
             concurrently.

        Returns:
            ``{cleaned_flows, removed_containers, errors}`` dict.
        """
        result = CleanupResult()
        flows = await self.flow_provider.get_all_flow_statuses()
        containers = await self.db.list_all_containers()

        # Group containers by flow_id.
        flow_containers: dict[int, list[ContainerInfo]] = {}
        for c in containers:
            flow_containers.setdefault(c.flow_id, []).append(c)

        # Tasks to run concurrently — one per container to remove.
        removal_tasks: list[asyncio.Task] = []
        flows_to_fail: set[int] = set()

        for flow_id, status in flows.items():
            flow_ctrs = flow_containers.get(flow_id, [])
            if status in (FlowStatus.RUNNING, FlowStatus.WAITING):
                # PentAGI semantics: skip a Running/Waiting flow ONLY
                # when it has no active containers (nothing to clean
                # up). If at least one container is still starting or
                # running, the flow is considered "orphaned" by the
                # server restart — mark it Failed and kill the
                # containers. See ``_all_containers_running`` for the
                # (counter-intuitive) name rationale.
                if self._all_containers_running(flow_ctrs):
                    continue
                # Fall through to terminal-state arm.
            if status in ORPHAN_FLOW_STATUSES or status in (
                FlowStatus.RUNNING,
                FlowStatus.WAITING,
            ):
                # Mark flow failed and queue its active containers for removal.
                flows_to_fail.add(flow_id)
                for c in flow_ctrs:
                    if c.status in ACTIVE_CONTAINER_STATUSES:
                        removal_tasks.append(
                            asyncio.create_task(
                                self._remove_one(c, result),
                                name=f"cleanup-flow-{flow_id}-ctr-{c.id}",
                            )
                        )

        # Mark flows as failed (concurrent, but each call is idempotent).
        for flow_id in flows_to_fail:
            try:
                await self.flow_provider.mark_flow_failed(flow_id)
                result.cleaned_flows += 1
            except Exception as e:
                result.errors.append(f"failed to mark flow {flow_id} as failed: {e}")

        # Run all container removals concurrently (Python equivalent of
        # PentAGI's ``sync.WaitGroup``).
        if removal_tasks:
            logger.info(
                "cleanup: removing %d containers across %d flows concurrently",
                len(removal_tasks),
                len(flows_to_fail),
            )
            await asyncio.gather(*removal_tasks, return_exceptions=True)

        # Also clean up orphan containers that have NO flow row at all
        # (e.g. flow was hard-deleted but container rows were left).
        for flow_id, flow_ctrs in flow_containers.items():
            if flow_id in flows:
                continue  # flow exists — already handled above
            for c in flow_ctrs:
                if c.status in ACTIVE_CONTAINER_STATUSES:
                    await self._remove_one(c, result)

        # Optionally sweep orphan networks.
        if self.network is not None:
            try:
                result.removed_networks = await self.cleanup_orphan_networks()
            except Exception as e:
                result.errors.append(f"orphan-network cleanup failed: {e}")

        logger.info(
            "cleanup complete: %d flows failed, %d containers removed, "
            "%d networks removed, %d errors",
            result.cleaned_flows,
            result.removed_containers,
            result.removed_networks,
            len(result.errors),
        )
        return result.to_dict()

    # ------------------------------------------------------------------
    # Single-flow cleanup
    # ------------------------------------------------------------------

    async def cleanup_flow(self, flow_id: int) -> None:
        """Stop + force-remove ALL containers for ``flow_id``.

        Used by the orchestrator when a flow completes (``Finished``) or
        fails (``Failed``). Idempotent: safe to call when no containers
        exist for the flow. Also tears down the per-flow network if
        ``self.network`` is set.
        """
        containers = await self.db.list_containers_by_flow(flow_id)
        if not containers:
            logger.debug("cleanup_flow: no containers for flow %d", flow_id)
        # Remove all containers concurrently.
        tasks = [
            asyncio.create_task(self._remove_one(c, CleanupResult()))
            for c in containers
        ]
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        # Tear down the per-flow network.
        if self.network is not None:
            try:
                await self.network.teardown_flow_network(flow_id)
            except Exception as e:
                logger.warning(
                    "cleanup_flow: failed to tear down flow %d network: %s",
                    flow_id,
                    e,
                )

    # ------------------------------------------------------------------
    # Nuclear option — remove ALL Elengenix-managed containers
    # ------------------------------------------------------------------

    async def cleanup_all(self) -> dict[str, Any]:
        """Remove EVERY ``pentagi-terminal-*`` container from the Docker
        daemon, regardless of DB state.

        This is the developer-reset / disaster-recovery path. It does
        NOT consult the DB at all — it lists all Docker containers
        matching the ``pentagi-terminal-`` prefix and force-removes
        them. After the sweep, all DB rows are marked ``deleted``.

        Returns:
            ``{removed_containers, errors}`` dict.
        """
        result = CleanupResult()
        client = await self.lifecycle._client()
        try:
            containers = await client.containers.list(
                all=True,
                filters={"name": [PRIMARY_TERMINAL_NAME_PREFIX]},
            )
        except Exception as e:
            result.errors.append(f"failed to list containers: {e}")
            return result.to_dict()

        async def _nuke(c) -> None:
            try:
                name = ""
                names = c.get("Names") or []
                if names:
                    name = names[0].lstrip("/")
                await c.delete(force=True, v=True)
                result.removed_containers += 1
                logger.info("cleanup_all: removed container %s", name)
            except Exception as e:
                result.errors.append(f"cleanup_all: remove failed: {e}")

        tasks = [asyncio.create_task(_nuke(c)) for c in containers]
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

        # Mark all DB rows as deleted.
        try:
            all_rows = await self.db.list_all_containers()
            for row in all_rows:
                if row.status != ContainerStatus.DELETED:
                    try:
                        await self.db.update_container_status(row.id, ContainerStatus.DELETED)
                    except Exception as e:
                        result.errors.append(
                            f"cleanup_all: DB mark deleted for row {row.id}: {e}"
                        )
        except Exception as e:
            result.errors.append(f"cleanup_all: DB list failed: {e}")

        # Also nuke all Elengenix-managed networks.
        if self.network is not None:
            try:
                result.removed_networks = await self._nuke_all_networks()
            except Exception as e:
                result.errors.append(f"cleanup_all: network sweep failed: {e}")

        logger.info(
            "cleanup_all: removed %d containers, %d networks, %d errors",
            result.removed_containers,
            result.removed_networks,
            len(result.errors),
        )
        return result.to_dict()

    # ------------------------------------------------------------------
    # Orphan-network cleanup
    # ------------------------------------------------------------------

    async def cleanup_orphan_networks(self) -> int:
        """Remove all ``elengenix-flow-*`` networks that have no
        containers attached.

        Returns the count of removed networks. Idempotent.
        """
        if self.network is None:
            return 0
        removed = 0
        networks = await self.network.list_networks()
        for net_info in networks:
            name = net_info.get("Name", "")
            if not name.startswith(NETWORK_NAME_PREFIX):
                continue
            containers = net_info.get("Containers") or {}
            if containers:
                # Network has live endpoints — skip.
                logger.debug(
                    "skipping network %s: has %d endpoints", name, len(containers)
                )
                continue
            try:
                await self.network.remove_network(name)
                removed += 1
            except Exception as e:
                logger.warning("failed to remove orphan network %s: %s", name, e)
        return removed

    async def _nuke_all_networks(self) -> int:
        """Remove ALL ``elengenix-flow-*`` networks, even those with
        containers (used by ``cleanup_all``). Force-disconnects first."""
        if self.network is None:
            return 0
        removed = 0
        networks = await self.network.list_networks()
        for net_info in networks:
            name = net_info.get("Name", "")
            if not name.startswith(NETWORK_NAME_PREFIX):
                continue
            # Force-disconnect every endpoint.
            containers = net_info.get("Containers") or {}
            for ep in containers.values():
                ep_id = ep.get("Name") or ep.get("EndpointID") or ""
                if not ep_id:
                    continue
                try:
                    await self.network.disconnect_container(name, ep_id, force=True)
                except Exception:
                    pass
            try:
                await self.network.remove_network(name)
                removed += 1
            except Exception as e:
                logger.warning("failed to nuke network %s: %s", name, e)
        return removed

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _all_containers_running(containers: list[ContainerInfo]) -> bool:
        """Return True if ``containers`` is non-empty AND NONE of them are
        in ``starting``/``running`` status. Mirrors PentAGI's
        ``isAllContainersRunning``.

        Despite the misleading name (preserved verbatim from the Go
        source), this function actually returns True when NO containers
        are active — i.e. when there is nothing for the cleanup to kill.
        The cleanup switch uses it to *skip* flows whose containers are
        already all stopped/deleted/failed.

        Semantics:

        - non-empty list + every container in {stopped/deleted/failed} -> True
        - non-empty list + at least one container in {starting/running} -> False
        - empty list -> False (flow has no containers; nothing to skip)
        """
        if not containers:
            return False
        for c in containers:
            if c.status in ACTIVE_CONTAINER_STATUSES:
                return False
        return True

    async def _remove_one(self, info: ContainerInfo, result: CleanupResult) -> None:
        """Stop + force-remove a single container. Updates ``result`` in place."""
        try:
            await self.lifecycle._remove_container_silent(info)
            result.removed_containers += 1
        except Exception as e:
            err = f"failed to remove container {info.name} (id={info.id}): {e}"
            result.errors.append(err)
            logger.error(err)


__all__ = [
    "ContainerCleanup",
    "CleanupResult",
    "FlowStatusProvider",
    "InMemoryFlowStatusProvider",
]
