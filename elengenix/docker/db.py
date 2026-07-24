"""elengenix/docker/db.py — SQLite-backed persistence for container state.

This module ports PentAGI's ``containers`` SQL table
(``backend/pkg/database/models.go``) to a Python ``aiosqlite`` store. It
provides:

* ``ContainerType`` — ``primary`` (terminal sandbox) / ``secondary`` (future)
* ``ContainerStatus`` — five-state machine:
  ``starting -> running -> stopped -> deleted`` (with ``failed`` as a
  terminal escape hatch). Mirrors PentAGI's ``ContainerStatus`` enum.
* ``FlowStatus`` — ``created / running / waiting / finished / failed``.
  Used by ``ContainerDB.list_orphan_containers`` to identify stale
  containers whose parent flows are no longer live.
* ``ContainerInfo`` — dataclass mapping one row of the ``containers``
  table; the field set matches PentAGI verbatim:
  ``{id, type, name, image, status, local_id, local_dir, flow_id,
  created_at, updated_at}``.
* ``ContainerDB`` — async wrapper over an ``aiosqlite`` connection. All
  public methods are coroutines and never block the event loop.

The ``aiosqlite`` dependency is imported lazily inside ``connect()`` so
the module imports cleanly even when the optional dependency is absent
(this matters for AST-level test discovery and for environments where
Docker is not used).

The schema is created idempotently on first ``connect()`` via
``CREATE TABLE IF NOT EXISTS``; indexes on ``flow_id`` and ``status``
are added for the same access patterns PentAGI uses
(``GetFlowPrimaryContainer`` / ``GetContainers`` by status).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Optional

logger = logging.getLogger("elengenix.docker.db")


# ---------------------------------------------------------------------------
# Enums — string-valued for direct SQL serialization (mirrors PentAGI).
# ---------------------------------------------------------------------------


class ContainerType(str, Enum):
    """Mirror of PentAGI's ``database.ContainerType``."""

    PRIMARY = "primary"
    SECONDARY = "secondary"


class ContainerStatus(str, Enum):
    """Mirror of PentAGI's ``database.ContainerStatus`` state machine.

    Lifecycle: ``starting -> running -> stopped -> deleted``; any state
    can transition to ``failed`` on irrecoverable error.
    """

    STARTING = "starting"
    RUNNING = "running"
    STOPPED = "stopped"
    DELETED = "deleted"
    FAILED = "failed"


class FlowStatus(str, Enum):
    """Mirror of PentAGI's ``database.FlowStatus``.

    The cleanup logic in ``ContainerCleanup.cleanup_orphan_containers``
    treats ``FINISHED`` / ``FAILED`` / ``CREATED`` as terminal-or-stale
    flow states whose containers must be purged.
    """

    CREATED = "created"
    RUNNING = "running"
    WAITING = "waiting"
    FINISHED = "finished"
    FAILED = "failed"


# Flow states whose containers are considered orphans at startup. Matches
# PentAGI's ``Cleanup()`` switch (Finished/Failed/Created always; plus
# Running/Waiting only when at least one container is NOT running).
ORPHAN_FLOW_STATUSES: frozenset[FlowStatus] = frozenset(
    {FlowStatus.CREATED, FlowStatus.FINISHED, FlowStatus.FAILED}
)

# Container statuses that are still "live" and therefore candidates for
# force-removal during cleanup. Matches PentAGI's
# ``ContainerStatusStarting / ContainerStatusRunning`` switch arms.
ACTIVE_CONTAINER_STATUSES: frozenset[ContainerStatus] = frozenset(
    {ContainerStatus.STARTING, ContainerStatus.RUNNING}
)


# ---------------------------------------------------------------------------
# Row dataclass — one-to-one with PentAGI's ``Container`` struct.
# ---------------------------------------------------------------------------


@dataclass
class ContainerInfo:
    """Persistent record of a Docker container managed by Elengenix.

    Field names match PentAGI's ``database.Container`` struct so the
    serialized JSON remains wire-compatible across the Go and Python
    implementations.
    """

    id: int = 0
    type: ContainerType = ContainerType.PRIMARY
    name: str = ""
    image: str = ""
    status: ContainerStatus = ContainerStatus.STARTING
    local_id: str = ""
    local_dir: str = ""
    flow_id: int = 0
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    # Extra metadata bag — NOT persisted to SQL (kept for in-memory
    # annotations such as the parent flow's status when joined).
    extra: dict = field(default_factory=dict, repr=False, compare=False)


# ---------------------------------------------------------------------------
# Schema DDL — single source of truth.
# ---------------------------------------------------------------------------

_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS containers (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    type       TEXT    NOT NULL DEFAULT 'primary',
    name       TEXT    NOT NULL,
    image      TEXT    NOT NULL DEFAULT '',
    status     TEXT    NOT NULL DEFAULT 'starting',
    local_id   TEXT    NOT NULL DEFAULT '',
    local_dir  TEXT    NOT NULL DEFAULT '',
    flow_id    INTEGER NOT NULL DEFAULT 0,
    created_at TEXT,
    updated_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_containers_flow_id ON containers(flow_id);
CREATE INDEX IF NOT EXISTS idx_containers_status  ON containers(status);
CREATE INDEX IF NOT EXISTS idx_containers_name    ON containers(name);
"""


class ContainerDB:
    """Async SQLite persistence for container state.

    The DB is the single source of truth for which containers Elengenix
    thinks it has spawned. The Docker daemon itself may have additional
    orphan containers (left over from a crash) — those are reconciled
    by ``ContainerCleanup`` at startup.

    Usage::

        db = ContainerDB("/path/to/containers.db")
        await db.connect()
        info = await db.create_container(ContainerInfo(name="pentagi-terminal-1", ...))
        await db.close()
    """

    def __init__(self, db_path: str | Path) -> None:
        self.db_path: Path = Path(db_path)
        self._conn = None  # type: ignore[assignment]
        # Race-condition guard: ``connect`` is idempotent even if two
        # coroutines call it concurrently.
        self._connect_lock = None  # type: ignore[assignment]

    # ------------------------------------------------------------------
    # Connection lifecycle
    # ------------------------------------------------------------------

    async def connect(self) -> None:
        """Open (or reuse) the SQLite connection and ensure schema exists.

        ``aiosqlite`` is imported lazily here so the module can be
        imported in environments where the optional dependency is not
        installed (e.g. CI test discovery that only does AST parsing).
        """
        import asyncio

        if self._conn is not None:
            return
        if self._connect_lock is None:
            self._connect_lock = asyncio.Lock()
        async with self._connect_lock:
            if self._conn is not None:
                return
            import aiosqlite

            self.db_path.parent.mkdir(parents=True, exist_ok=True)
            logger.debug("opening container db at %s", self.db_path)
            self._conn = await aiosqlite.connect(str(self.db_path))
            # ``sqlite3.Row`` (re-exported as ``aiosqlite.Row``) lets us
            # access columns by name in ``_row_to_info``. We set it on
            # the connection so all subsequent cursors inherit it.
            import sqlite3

            self._conn.row_factory = sqlite3.Row
            # Allow concurrent reads from the same connection.
            await self._conn.execute("PRAGMA journal_mode=WAL")
            await self._conn.execute("PRAGMA foreign_keys=ON")
            await self._conn.executescript(_SCHEMA_SQL)
            await self._conn.commit()

    async def close(self) -> None:
        if self._conn is None:
            return
        await self._conn.close()
        self._conn = None

    async def __aenter__(self) -> "ContainerDB":
        await self.connect()
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        await self.close()

    # ------------------------------------------------------------------
    # Row mapping
    # ------------------------------------------------------------------

    @staticmethod
    def _row_to_info(row) -> ContainerInfo:
        """Convert a ``sqlite3.Row`` (or compatible) into a ``ContainerInfo`` dataclass.

        Accepts any object that supports string-key subscript
        (``row["col"]``); the standard ``sqlite3.Row`` factory set in
        ``connect()`` satisfies this contract.
        """
        return ContainerInfo(
            id=int(row["id"]),
            type=ContainerType(row["type"]) if row["type"] else ContainerType.PRIMARY,
            name=row["name"],
            image=row["image"] or "",
            status=ContainerStatus(row["status"]) if row["status"] else ContainerStatus.STARTING,
            local_id=row["local_id"] or "",
            local_dir=row["local_dir"] or "",
            flow_id=int(row["flow_id"]),
            created_at=_parse_dt(row["created_at"]),
            updated_at=_parse_dt(row["updated_at"]),
        )

    # ------------------------------------------------------------------
    # CRUD
    # ------------------------------------------------------------------

    async def create_container(self, info: ContainerInfo) -> int:
        """Insert a new container row; return the assigned primary key.

        The ``status`` defaults to ``starting`` (mirroring PentAGI's
        ``RunContainer`` which inserts the row before ``ContainerCreate``
        is even called).
        """
        await self.connect()
        assert self._conn is not None
        now = datetime.utcnow().isoformat(timespec="seconds")
        cursor = await self._conn.execute(
            """
            INSERT INTO containers
                (type, name, image, status, local_id, local_dir,
                 flow_id, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                info.type.value,
                info.name,
                info.image,
                info.status.value,
                info.local_id,
                info.local_dir,
                int(info.flow_id),
                now,
                now,
            ),
        )
        await self._conn.commit()
        new_id = int(cursor.lastrowid) if cursor.lastrowid else 0
        info.id = new_id
        info.created_at = info.updated_at = datetime.utcnow()
        logger.debug("created container row id=%d name=%s flow=%d", new_id, info.name, info.flow_id)
        return new_id

    async def get_container(self, id: int) -> Optional[ContainerInfo]:
        await self.connect()
        assert self._conn is not None
        cursor = await self._conn.execute("SELECT * FROM containers WHERE id = ?", (int(id),))
        row = await cursor.fetchone()
        return self._row_to_info(row) if row else None

    async def get_container_by_flow(self, flow_id: int) -> Optional[ContainerInfo]:
        """Return the PRIMARY container for ``flow_id`` (mirrors PentAGI's
        ``GetFlowPrimaryContainer``). Returns ``None`` if no such row
        exists.
        """
        await self.connect()
        assert self._conn is not None
        cursor = await self._conn.execute(
            """
            SELECT * FROM containers
            WHERE flow_id = ? AND type = ?
            ORDER BY id DESC
            LIMIT 1
            """,
            (int(flow_id), ContainerType.PRIMARY.value),
        )
        row = await cursor.fetchone()
        return self._row_to_info(row) if row else None

    async def update_container_status(self, id: int, status: ContainerStatus) -> None:
        await self.connect()
        assert self._conn is not None
        now = datetime.utcnow().isoformat(timespec="seconds")
        await self._conn.execute(
            "UPDATE containers SET status = ?, updated_at = ? WHERE id = ?",
            (status.value, now, int(id)),
        )
        await self._conn.commit()
        logger.debug("container id=%d -> status=%s", id, status.value)

    async def update_container_local_id(
        self, id: int, local_id: str, status: ContainerStatus
    ) -> None:
        """Update both ``local_id`` and ``status`` atomically.

        Ported from PentAGI's ``UpdateContainerStatusLocalID`` — used
        after ``ContainerCreate`` returns the real Docker container ID
        and after ``ContainerStart`` flips the status to ``running``.
        """
        await self.connect()
        assert self._conn is not None
        now = datetime.utcnow().isoformat(timespec="seconds")
        await self._conn.execute(
            "UPDATE containers SET status = ?, local_id = ?, updated_at = ? WHERE id = ?",
            (status.value, local_id, now, int(id)),
        )
        await self._conn.commit()

    async def update_container_image(self, id: int, image: str) -> None:
        """Persist a fallback-image swap (mirrors PentAGI's
        ``UpdateContainerImage`` used when the requested image fails to
        pull/create and we fall back to ``debian:latest``)."""
        await self.connect()
        assert self._conn is not None
        now = datetime.utcnow().isoformat(timespec="seconds")
        await self._conn.execute(
            "UPDATE containers SET image = ?, updated_at = ? WHERE id = ?",
            (image, now, int(id)),
        )
        await self._conn.commit()

    async def list_containers(
        self, status: Optional[ContainerStatus] = None
    ) -> list[ContainerInfo]:
        await self.connect()
        assert self._conn is not None
        if status is None:
            cursor = await self._conn.execute("SELECT * FROM containers ORDER BY id ASC")
        else:
            cursor = await self._conn.execute(
                "SELECT * FROM containers WHERE status = ? ORDER BY id ASC",
                (status.value,),
            )
        rows = await cursor.fetchall()
        return [self._row_to_info(r) for r in rows]

    async def list_containers_by_flow(self, flow_id: int) -> list[ContainerInfo]:
        await self.connect()
        assert self._conn is not None
        cursor = await self._conn.execute(
            "SELECT * FROM containers WHERE flow_id = ? ORDER BY id ASC",
            (int(flow_id),),
        )
        rows = await cursor.fetchall()
        return [self._row_to_info(r) for r in rows]

    async def delete_container(self, id: int) -> None:
        """Hard-delete a row from the DB (mirrors PentAGI's
        ``DeleteContainer``). Most callers should use
        ``update_container_status(id, DELETED)`` instead so history is
        preserved."""
        await self.connect()
        assert self._conn is not None
        await self._conn.execute("DELETE FROM containers WHERE id = ?", (int(id),))
        await self._conn.commit()
        logger.debug("deleted container row id=%d", id)

    async def list_orphan_containers(self) -> list[ContainerInfo]:
        """Containers whose parent flows are in a terminal-or-stale state.

        Because Elengenix's flow table may live in a separate SQLite DB
        (or a different store entirely), this method accepts the
        caller's notion of which flow IDs are orphans. The default
        implementation returns all containers in
        ``starting``/``running`` status — the caller (typically
        ``ContainerCleanup``) is then expected to filter by flow status.
        """
        # We deliberately do not join against a flows table here: the
        # flow-status filter is the cleanup layer's responsibility
        # (it owns the flows DB). What we CAN do cheaply is return only
        # "live" containers, since terminal-state ones don't need
        # cleanup.
        return await self.list_containers_in_active_state()

    async def list_containers_in_active_state(self) -> list[ContainerInfo]:
        """All containers in ``starting`` or ``running`` status.

        Used by ``ContainerCleanup.cleanup_orphan_containers`` to find
        candidates for force-removal (after filtering by flow status).
        """
        out: list[ContainerInfo] = []
        for status in ACTIVE_CONTAINER_STATUSES:
            out.extend(await self.list_containers(status=status))
        return out

    async def list_all_containers(self) -> list[ContainerInfo]:
        """Return every row (regardless of status). Mirrors PentAGI's
        ``GetContainers`` which is used by the ``Cleanup()`` startup
        sweep."""
        return await self.list_containers(status=None)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _parse_dt(s) -> Optional[datetime]:
    """Parse an ISO-8601 timestamp stored as TEXT; return None on failure."""
    if not s:
        return None
    try:
        return datetime.fromisoformat(str(s))
    except (ValueError, TypeError):
        return None




__all__ = [
    "ContainerType",
    "ContainerStatus",
    "FlowStatus",
    "ContainerInfo",
    "ContainerDB",
    "ORPHAN_FLOW_STATUSES",
    "ACTIVE_CONTAINER_STATUSES",
]
