"""elengenix/flows/db.py — SQLite persistence for the Flow management system.

This module ports PentAGI's PostgreSQL-backed ``database`` package
(``backend/pkg/database/models.go`` + the sqlc-generated query files) to
async SQLite via :mod:`aiosqlite`. The schema mirrors PentAGI's table
layout one-to-one so persisted data remains structurally compatible.

Tables
------
* ``flows``         — Flow records (root of the 4-tier hierarchy).
* ``tasks``         — Task records (children of flows).
* ``subtasks``      — Subtask records (children of tasks).
* ``msgchains``     — JSON-serialized agent message chains.
* ``msglogs``       — User-visible message-log entries (engagement log).
* ``agentlogs``     — Agent-delegation log entries.
* ``toolcalls``     — Tool-call records (action tier).
* ``searchlogs``    — Search-engine query/result log entries.
* ``termlogs``      — Terminal-stream log entries.
* ``vecstorelogs``  — Vector-store action log entries.
* ``screenshots``   — Screenshot records.
* ``prompts``       — User-overridable prompt templates.
* ``containers``    — Docker sandbox container records.

Concurrency
-----------
The :class:`FlowDB` class is async and uses a single ``aiosqlite.Connection``
guarded by an :class:`asyncio.Lock` for write serialization (SQLite only
supports one writer at a time anyway). All public methods are coroutines
and type-hinted.

Path
----
Default DB path is ``~/.elengenix/data/flows.db`` (resolved via
:mod:`elengenix.paths`). Override via the ``db_path`` constructor argument
or the ``ELENGENIX_FLOWS_DB`` environment variable.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
from datetime import datetime
from pathlib import Path
from typing import Any

import aiosqlite

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

logger = logging.getLogger("elengenix.flows.db")

# Default DB path — overridden by ELENGENIX_FLOWS_DB env var or constructor.
_DEFAULT_DB_PATH: Path = Path("~/.elengenix/data/flows.db").expanduser()


def _resolve_db_path(override: str | os.PathLike[str] | Path | None = None) -> Path:
    """Resolve the DB path from override arg, env var, or default.

    Priority:
      1. Explicit ``override`` argument.
      2. ``ELENGENIX_FLOWS_DB`` environment variable.
      3. ``~/.elengenix/data/flows.db``.
    """
    if override is not None:
        p = Path(override).expanduser()
    else:
        env_val = os.environ.get("ELENGENIX_FLOWS_DB")
        if env_val:
            p = Path(env_val).expanduser()
        else:
            p = _DEFAULT_DB_PATH
    p.parent.mkdir(parents=True, exist_ok=True)
    return p


# ---------------------------------------------------------------------------
# Schema — mirror PentAGI's migrations/*.sql (1:1 table layout).
# ---------------------------------------------------------------------------

_SCHEMA_SQL: str = """
-- Flow management system schema (ports PentAGI's backend/migrations).

CREATE TABLE IF NOT EXISTS flows (
    id                   INTEGER PRIMARY KEY AUTOINCREMENT,
    status               TEXT    NOT NULL DEFAULT 'created',
    title                TEXT    NOT NULL DEFAULT 'untitled',
    model                TEXT    NOT NULL DEFAULT 'unknown',
    model_provider_name  TEXT    NOT NULL DEFAULT '',
    model_provider_type  TEXT    NOT NULL DEFAULT 'openai',
    language             TEXT    NOT NULL DEFAULT 'English',
    functions            TEXT    NOT NULL DEFAULT '{}',
    user_id              INTEGER NOT NULL,
    trace_id             TEXT,
    tool_call_id_template TEXT   NOT NULL DEFAULT '',
    created_at           TEXT    NOT NULL,
    updated_at           TEXT    NOT NULL,
    deleted_at           TEXT
);

CREATE TABLE IF NOT EXISTS tasks (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    status      TEXT    NOT NULL DEFAULT 'created',
    title       TEXT    NOT NULL DEFAULT '',
    input       TEXT    NOT NULL,
    result      TEXT    NOT NULL DEFAULT '',
    flow_id     INTEGER NOT NULL,
    created_at  TEXT    NOT NULL,
    updated_at  TEXT    NOT NULL,
    FOREIGN KEY (flow_id) REFERENCES flows(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS subtasks (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    status      TEXT    NOT NULL DEFAULT 'created',
    title       TEXT    NOT NULL DEFAULT '',
    description TEXT    NOT NULL DEFAULT '',
    result      TEXT    NOT NULL DEFAULT '',
    task_id     INTEGER NOT NULL,
    context     TEXT    NOT NULL DEFAULT '',
    created_at  TEXT    NOT NULL,
    updated_at  TEXT    NOT NULL,
    FOREIGN KEY (task_id) REFERENCES tasks(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS msgchains (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    type              TEXT    NOT NULL,
    model             TEXT    NOT NULL DEFAULT '',
    model_provider    TEXT    NOT NULL DEFAULT '',
    usage_in          INTEGER NOT NULL DEFAULT 0,
    usage_out         INTEGER NOT NULL DEFAULT 0,
    chain             TEXT    NOT NULL DEFAULT '[]',
    flow_id           INTEGER NOT NULL,
    task_id           INTEGER,
    subtask_id        INTEGER,
    created_at        TEXT    NOT NULL,
    updated_at        TEXT    NOT NULL,
    usage_cache_in    INTEGER NOT NULL DEFAULT 0,
    usage_cache_out   INTEGER NOT NULL DEFAULT 0,
    usage_cost_in     REAL    NOT NULL DEFAULT 0.0,
    usage_cost_out    REAL    NOT NULL DEFAULT 0.0,
    duration_seconds  REAL    NOT NULL DEFAULT 0.0,
    FOREIGN KEY (flow_id)    REFERENCES flows(id)    ON DELETE CASCADE,
    FOREIGN KEY (task_id)    REFERENCES tasks(id)    ON DELETE CASCADE,
    FOREIGN KEY (subtask_id) REFERENCES subtasks(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS msglogs (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    type          TEXT    NOT NULL,
    message       TEXT    NOT NULL DEFAULT '',
    result        TEXT    NOT NULL DEFAULT '',
    flow_id       INTEGER NOT NULL,
    task_id       INTEGER,
    subtask_id    INTEGER,
    created_at    TEXT    NOT NULL,
    result_format TEXT    NOT NULL DEFAULT 'markdown',
    thinking      TEXT,
    FOREIGN KEY (flow_id)    REFERENCES flows(id)    ON DELETE CASCADE,
    FOREIGN KEY (task_id)    REFERENCES tasks(id)    ON DELETE CASCADE,
    FOREIGN KEY (subtask_id) REFERENCES subtasks(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS agentlogs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    initiator   TEXT    NOT NULL,
    executor    TEXT    NOT NULL,
    task        TEXT    NOT NULL DEFAULT '',
    result      TEXT    NOT NULL DEFAULT '',
    flow_id     INTEGER NOT NULL,
    task_id     INTEGER,
    subtask_id  INTEGER,
    created_at  TEXT    NOT NULL,
    FOREIGN KEY (flow_id)    REFERENCES flows(id)    ON DELETE CASCADE,
    FOREIGN KEY (task_id)    REFERENCES tasks(id)    ON DELETE CASCADE,
    FOREIGN KEY (subtask_id) REFERENCES subtasks(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS toolcalls (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    call_id          TEXT    NOT NULL,
    status           TEXT    NOT NULL DEFAULT 'received',
    name             TEXT    NOT NULL,
    args             TEXT    NOT NULL DEFAULT '{}',
    result           TEXT    NOT NULL DEFAULT '',
    flow_id          INTEGER NOT NULL,
    task_id          INTEGER,
    subtask_id       INTEGER,
    created_at       TEXT    NOT NULL,
    updated_at       TEXT    NOT NULL,
    duration_seconds REAL    NOT NULL DEFAULT 0.0,
    FOREIGN KEY (flow_id)    REFERENCES flows(id)    ON DELETE CASCADE,
    FOREIGN KEY (task_id)    REFERENCES tasks(id)    ON DELETE CASCADE,
    FOREIGN KEY (subtask_id) REFERENCES subtasks(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS searchlogs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    initiator   TEXT    NOT NULL,
    executor    TEXT    NOT NULL,
    engine      TEXT    NOT NULL,
    query       TEXT    NOT NULL,
    result      TEXT    NOT NULL DEFAULT '',
    flow_id     INTEGER NOT NULL,
    task_id     INTEGER,
    subtask_id  INTEGER,
    created_at  TEXT    NOT NULL,
    FOREIGN KEY (flow_id)    REFERENCES flows(id)    ON DELETE CASCADE,
    FOREIGN KEY (task_id)    REFERENCES tasks(id)    ON DELETE CASCADE,
    FOREIGN KEY (subtask_id) REFERENCES subtasks(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS termlogs (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    type         TEXT    NOT NULL,
    text         TEXT    NOT NULL DEFAULT '',
    container_id INTEGER NOT NULL,
    created_at   TEXT    NOT NULL,
    flow_id      INTEGER NOT NULL,
    task_id      INTEGER,
    subtask_id   INTEGER,
    FOREIGN KEY (flow_id)    REFERENCES flows(id)    ON DELETE CASCADE,
    FOREIGN KEY (task_id)    REFERENCES tasks(id)    ON DELETE CASCADE,
    FOREIGN KEY (subtask_id) REFERENCES subtasks(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS vecstorelogs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    initiator   TEXT    NOT NULL,
    executor    TEXT    NOT NULL,
    filter      TEXT    NOT NULL DEFAULT '{}',
    query       TEXT    NOT NULL DEFAULT '',
    action      TEXT    NOT NULL,
    result      TEXT    NOT NULL DEFAULT '',
    flow_id     INTEGER NOT NULL,
    task_id     INTEGER,
    subtask_id  INTEGER,
    created_at  TEXT    NOT NULL,
    FOREIGN KEY (flow_id)    REFERENCES flows(id)    ON DELETE CASCADE,
    FOREIGN KEY (task_id)    REFERENCES tasks(id)    ON DELETE CASCADE,
    FOREIGN KEY (subtask_id) REFERENCES subtasks(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS screenshots (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT    NOT NULL DEFAULT '',
    url         TEXT    NOT NULL DEFAULT '',
    flow_id     INTEGER NOT NULL,
    created_at  TEXT    NOT NULL,
    task_id     INTEGER,
    subtask_id  INTEGER,
    FOREIGN KEY (flow_id)    REFERENCES flows(id)    ON DELETE CASCADE,
    FOREIGN KEY (task_id)    REFERENCES tasks(id)    ON DELETE CASCADE,
    FOREIGN KEY (subtask_id) REFERENCES subtasks(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS prompts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    type        TEXT    NOT NULL,
    user_id     INTEGER NOT NULL,
    prompt      TEXT    NOT NULL DEFAULT '',
    created_at  TEXT    NOT NULL,
    updated_at  TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS containers (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    type        TEXT    NOT NULL DEFAULT 'primary',
    name        TEXT    NOT NULL DEFAULT '',
    image       TEXT    NOT NULL DEFAULT '',
    status      TEXT    NOT NULL DEFAULT 'starting',
    local_id    TEXT,
    local_dir   TEXT,
    flow_id     INTEGER NOT NULL,
    created_at  TEXT    NOT NULL,
    updated_at  TEXT    NOT NULL,
    FOREIGN KEY (flow_id) REFERENCES flows(id) ON DELETE CASCADE
);

-- Helpful indexes mirroring PentAGI's query patterns.

CREATE INDEX IF NOT EXISTS idx_flows_user_id        ON flows(user_id);
CREATE INDEX IF NOT EXISTS idx_flows_status         ON flows(status);
CREATE INDEX IF NOT EXISTS idx_tasks_flow_id        ON tasks(flow_id);
CREATE INDEX IF NOT EXISTS idx_tasks_status         ON tasks(status);
CREATE INDEX IF NOT EXISTS idx_subtasks_task_id     ON subtasks(task_id);
CREATE INDEX IF NOT EXISTS idx_subtasks_status      ON subtasks(status);
CREATE INDEX IF NOT EXISTS idx_msgchains_flow_id    ON msgchains(flow_id);
CREATE INDEX IF NOT EXISTS idx_msgchains_task_id    ON msgchains(task_id);
CREATE INDEX IF NOT EXISTS idx_msgchains_subtask_id ON msgchains(subtask_id);
CREATE INDEX IF NOT EXISTS idx_msgchains_type       ON msgchains(type);
CREATE INDEX IF NOT EXISTS idx_msglogs_flow_id      ON msglogs(flow_id);
CREATE INDEX IF NOT EXISTS idx_agentlogs_flow_id    ON agentlogs(flow_id);
CREATE INDEX IF NOT EXISTS idx_toolcalls_flow_id    ON toolcalls(flow_id);
CREATE INDEX IF NOT EXISTS idx_searchlogs_flow_id   ON searchlogs(flow_id);
CREATE INDEX IF NOT EXISTS idx_termlogs_flow_id     ON termlogs(flow_id);
CREATE INDEX IF NOT EXISTS idx_vecstorelogs_flow_id ON vecstorelogs(flow_id);
CREATE INDEX IF NOT EXISTS idx_screenshots_flow_id  ON screenshots(flow_id);
CREATE INDEX IF NOT EXISTS idx_containers_flow_id   ON containers(flow_id);
"""


# ---------------------------------------------------------------------------
# Helpers — datetime ↔ TEXT serialization (ISO 8601 UTC).
# ---------------------------------------------------------------------------


def _dt_to_text(dt: datetime | None) -> str | None:
    """Convert a ``datetime`` to ISO-8601 TEXT (or ``None``)."""
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=None)
    return dt.isoformat()


def _text_to_dt(text: str | None) -> datetime | None:
    """Convert ISO-8601 TEXT back to a ``datetime`` (or ``None``)."""
    if not text:
        return None
    try:
        return datetime.fromisoformat(text)
    except (ValueError, TypeError):
        return None


def _json_dumps(value: Any) -> str:
    """Serialize ``value`` to a compact JSON string."""
    return json.dumps(value, ensure_ascii=False, default=str)


def _json_loads(value: str | None, default: Any = None) -> Any:
    """Deserialize ``value`` from JSON, returning ``default`` on failure."""
    if not value:
        return default if default is not None else {}
    try:
        return json.loads(value)
    except (ValueError, TypeError):
        return default if default is not None else {}


# ---------------------------------------------------------------------------
# Row → Pydantic model converters.
# ---------------------------------------------------------------------------


def _flow_from_row(row: aiosqlite.Row) -> Flow:
    return Flow(
        id=row["id"],
        status=FlowStatus(row["status"]),
        title=row["title"],
        model=row["model"],
        model_provider_name=row["model_provider_name"],
        model_provider_type=ProviderType(row["model_provider_type"]),
        language=row["language"],
        functions=_json_loads(row["functions"], default={}),
        user_id=row["user_id"],
        trace_id=row["trace_id"],
        tool_call_id_template=row["tool_call_id_template"],
        created_at=_text_to_dt(row["created_at"]) or datetime.utcnow(),
        updated_at=_text_to_dt(row["updated_at"]) or datetime.utcnow(),
        deleted_at=_text_to_dt(row["deleted_at"]),
    )


def _task_from_row(row: aiosqlite.Row) -> Task:
    return Task(
        id=row["id"],
        status=TaskStatus(row["status"]),
        title=row["title"],
        input=row["input"],
        result=row["result"],
        flow_id=row["flow_id"],
        created_at=_text_to_dt(row["created_at"]) or datetime.utcnow(),
        updated_at=_text_to_dt(row["updated_at"]) or datetime.utcnow(),
    )


def _subtask_from_row(row: aiosqlite.Row) -> Subtask:
    return Subtask(
        id=row["id"],
        status=SubtaskStatus(row["status"]),
        title=row["title"],
        description=row["description"],
        result=row["result"],
        task_id=row["task_id"],
        context=row["context"] if "context" in row.keys() else "",
        created_at=_text_to_dt(row["created_at"]) or datetime.utcnow(),
        updated_at=_text_to_dt(row["updated_at"]) or datetime.utcnow(),
    )


def _msgchain_from_row(row: aiosqlite.Row) -> Msgchain:
    return Msgchain(
        id=row["id"],
        type=MsgchainType(row["type"]),
        model=row["model"],
        model_provider=row["model_provider"],
        usage_in=row["usage_in"],
        usage_out=row["usage_out"],
        chain=_json_loads(row["chain"], default=[]),
        flow_id=row["flow_id"],
        task_id=row["task_id"],
        subtask_id=row["subtask_id"],
        created_at=_text_to_dt(row["created_at"]) or datetime.utcnow(),
        updated_at=_text_to_dt(row["updated_at"]) or datetime.utcnow(),
        usage_cache_in=row["usage_cache_in"],
        usage_cache_out=row["usage_cache_out"],
        usage_cost_in=row["usage_cost_in"],
        usage_cost_out=row["usage_cost_out"],
        duration_seconds=row["duration_seconds"],
    )


def _msglog_from_row(row: aiosqlite.Row) -> Msglog:
    return Msglog(
        id=row["id"],
        type=MsglogType(row["type"]),
        message=row["message"],
        result=row["result"],
        flow_id=row["flow_id"],
        task_id=row["task_id"],
        subtask_id=row["subtask_id"],
        created_at=_text_to_dt(row["created_at"]) or datetime.utcnow(),
        result_format=MsglogResultFormat(row["result_format"]),
        thinking=row["thinking"],
    )


def _agentlog_from_row(row: aiosqlite.Row) -> Agentlog:
    return Agentlog(
        id=row["id"],
        initiator=MsgchainType(row["initiator"]),
        executor=MsgchainType(row["executor"]),
        task=row["task"],
        result=row["result"],
        flow_id=row["flow_id"],
        task_id=row["task_id"],
        subtask_id=row["subtask_id"],
        created_at=_text_to_dt(row["created_at"]) or datetime.utcnow(),
    )


def _toolcall_from_row(row: aiosqlite.Row) -> Toolcall:
    return Toolcall(
        id=row["id"],
        call_id=row["call_id"],
        status=ToolcallStatus(row["status"]),
        name=row["name"],
        args=_json_loads(row["args"], default={}),
        result=row["result"],
        flow_id=row["flow_id"],
        task_id=row["task_id"],
        subtask_id=row["subtask_id"],
        created_at=_text_to_dt(row["created_at"]) or datetime.utcnow(),
        updated_at=_text_to_dt(row["updated_at"]) or datetime.utcnow(),
        duration_seconds=row["duration_seconds"],
    )


def _searchlog_from_row(row: aiosqlite.Row) -> Searchlog:
    return Searchlog(
        id=row["id"],
        initiator=MsgchainType(row["initiator"]),
        executor=MsgchainType(row["executor"]),
        engine=SearchengineType(row["engine"]),
        query=row["query"],
        result=row["result"],
        flow_id=row["flow_id"],
        task_id=row["task_id"],
        subtask_id=row["subtask_id"],
        created_at=_text_to_dt(row["created_at"]) or datetime.utcnow(),
    )


def _termlog_from_row(row: aiosqlite.Row) -> Termlog:
    return Termlog(
        id=row["id"],
        type=TermlogType(row["type"]),
        text=row["text"],
        container_id=row["container_id"],
        created_at=_text_to_dt(row["created_at"]) or datetime.utcnow(),
        flow_id=row["flow_id"],
        task_id=row["task_id"],
        subtask_id=row["subtask_id"],
    )


def _vecstorelog_from_row(row: aiosqlite.Row) -> Vecstorelog:
    return Vecstorelog(
        id=row["id"],
        initiator=MsgchainType(row["initiator"]),
        executor=MsgchainType(row["executor"]),
        filter=_json_loads(row["filter"], default={}),
        query=row["query"],
        action=VecstoreActionType(row["action"]),
        result=row["result"],
        flow_id=row["flow_id"],
        task_id=row["task_id"],
        subtask_id=row["subtask_id"],
        created_at=_text_to_dt(row["created_at"]) or datetime.utcnow(),
    )


def _screenshot_from_row(row: aiosqlite.Row) -> Screenshot:
    return Screenshot(
        id=row["id"],
        name=row["name"],
        url=row["url"],
        flow_id=row["flow_id"],
        created_at=_text_to_dt(row["created_at"]) or datetime.utcnow(),
        task_id=row["task_id"],
        subtask_id=row["subtask_id"],
    )


def _container_from_row(row: aiosqlite.Row) -> Container:
    return Container(
        id=row["id"],
        type=ContainerType(row["type"]),
        name=row["name"],
        image=row["image"],
        status=ContainerStatus(row["status"]),
        local_id=row["local_id"],
        local_dir=row["local_dir"],
        flow_id=row["flow_id"],
        created_at=_text_to_dt(row["created_at"]) or datetime.utcnow(),
        updated_at=_text_to_dt(row["updated_at"]) or datetime.utcnow(),
    )


def _prompt_from_row(row: aiosqlite.Row) -> Prompt:
    return Prompt(
        id=row["id"],
        type=row["type"],
        user_id=row["user_id"],
        prompt=row["prompt"],
        created_at=_text_to_dt(row["created_at"]) or datetime.utcnow(),
        updated_at=_text_to_dt(row["updated_at"]) or datetime.utcnow(),
    )


# ---------------------------------------------------------------------------
# FlowDB — the main persistence class.
# ---------------------------------------------------------------------------


class FlowDB:
    """Async SQLite persistence for the Flow management system.

    All public methods are coroutines and type-hinted. A single
    :class:`aiosqlite.Connection` is opened lazily on first use and
    guarded by an :class:`asyncio.Lock` for write serialization.

    Usage::

        db = FlowDB()
        await db.connect()
        try:
            flow = await db.create_flow(user_id=1, title="my flow", input="hi",
                                        model="gpt-4o", language="English")
        finally:
            await db.close()
    """

    def __init__(
        self,
        db_path: str | os.PathLike[str] | Path | None = None,
    ) -> None:
        """Configure the FlowDB.

        Args:
            db_path: Optional override for the DB file path. If ``None``,
                falls back to ``ELENGENIX_FLOWS_DB`` env var or
                ``~/.elengenix/data/flows.db``.
        """
        self.db_path: Path = _resolve_db_path(db_path)
        self._conn: aiosqlite.Connection | None = None
        self._lock: asyncio.Lock = asyncio.Lock()
        self._connected: bool = False
        logger.debug("FlowDB configured db_path=%s", self.db_path)

    # ── lifecycle ──────────────────────────────────────────────────────

    async def connect(self) -> None:
        """Open the DB connection and apply the schema (idempotent)."""
        if self._connected and self._conn is not None:
            return
        async with self._lock:
            if self._connected and self._conn is not None:
                return
            self._conn = await aiosqlite.connect(str(self.db_path))
            # Row factory so we can access columns by name.
            self._conn.row_factory = aiosqlite.Row
            # Enable foreign-key enforcement (off by default in SQLite).
            await self._conn.execute("PRAGMA foreign_keys = ON")
            await self._conn.execute("PRAGMA journal_mode = WAL")
            await self._conn.executescript(_SCHEMA_SQL)
            await self._conn.commit()
            self._connected = True
            logger.info("FlowDB connected db_path=%s", self.db_path)

    async def close(self) -> None:
        """Close the DB connection (safe to call multiple times)."""
        async with self._lock:
            if self._conn is not None:
                await self._conn.close()
                self._conn = None
            self._connected = False
            logger.info("FlowDB closed db_path=%s", self.db_path)

    @property
    def is_connected(self) -> bool:
        """Return ``True`` if the DB connection is open."""
        return self._connected and self._conn is not None

    async def _execute(
        self,
        sql: str,
        params: tuple[Any, ...] | list[Any] = (),
    ) -> aiosqlite.Cursor:
        """Execute a single SQL statement and return the cursor.

        Raises ``RuntimeError`` if :meth:`connect` has not been called.
        """
        if self._conn is None:
            await self.connect()
        assert self._conn is not None  # noqa: S101 — narrow type for mypy
        return await self._conn.execute(sql, tuple(params))

    async def _executemany(
        self,
        sql: str,
        params_seq: list[tuple[Any, ...]] | list[list[Any]],
    ) -> aiosqlite.Cursor:
        """Execute ``sql`` once per row in ``params_seq``."""
        if self._conn is None:
            await self.connect()
        assert self._conn is not None  # noqa: S101
        return await self._conn.executemany(sql, [tuple(p) for p in params_seq])

    async def _commit(self) -> None:
        """Commit the current transaction (no-op if not connected)."""
        if self._conn is not None:
            await self._conn.commit()

    # ── Flow CRUD ──────────────────────────────────────────────────────

    async def create_flow(
        self,
        *,
        user_id: int,
        title: str = "untitled",
        input: str = "",
        model: str = "unknown",
        model_provider_name: str = "",
        model_provider_type: ProviderType | str = ProviderType.OPENAI,
        language: str = "English",
        functions: dict[str, Any] | None = None,
        trace_id: str | None = None,
        tool_call_id_template: str = "",
    ) -> Flow:
        """Insert a new Flow row and return the populated :class:`Flow`."""
        if isinstance(model_provider_type, ProviderType):
            mpt = model_provider_type
        else:
            mpt = ProviderType(model_provider_type)
        now = _dt_to_text(datetime.utcnow())  # type: ignore[arg-type]
        async with self._lock:
            cur = await self._execute(
                """
                INSERT INTO flows
                    (status, title, model, model_provider_name, model_provider_type,
                     language, functions, user_id, trace_id, tool_call_id_template,
                     created_at, updated_at)
                VALUES
                    (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    FlowStatus.CREATED.value,
                    title,
                    model,
                    model_provider_name,
                    mpt.value,
                    language,
                    _json_dumps(functions or {}),
                    user_id,
                    trace_id,
                    tool_call_id_template,
                    now,
                    now,
                ),
            )
            flow_id = cur.lastrowid
            await self._commit()
        assert flow_id is not None  # noqa: S101
        return await self.get_flow(flow_id)  # type: ignore[return-value]

    async def get_flow(self, flow_id: int) -> Flow | None:
        """Return a single Flow by ID (or ``None`` if not found)."""
        cur = await self._execute(
            "SELECT * FROM flows WHERE id = ? AND deleted_at IS NULL",
            (flow_id,),
        )
        row = await cur.fetchone()
        return _flow_from_row(row) if row is not None else None

    async def list_flows(
        self,
        *,
        user_id: int | None = None,
        status: FlowStatus | str | None = None,
        offset: int = 0,
        limit: int = 100,
    ) -> list[Flow]:
        """List flows, optionally filtered by user / status.

        Args:
            user_id: Optional filter by owning user.
            status: Optional filter by status (enum or string value).
            offset: SQL OFFSET (default 0).
            limit: SQL LIMIT (default 100).

        Returns:
            List of :class:`Flow` objects sorted by ``id`` descending.
        """
        sql = "SELECT * FROM flows WHERE deleted_at IS NULL"
        params: list[Any] = []
        if user_id is not None:
            sql += " AND user_id = ?"
            params.append(user_id)
        if status is not None:
            status_val = status.value if isinstance(status, FlowStatus) else str(status)
            sql += " AND status = ?"
            params.append(status_val)
        sql += " ORDER BY id DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        cur = await self._execute(sql, tuple(params))
        rows = await cur.fetchall()
        return [_flow_from_row(r) for r in rows]

    async def count_flows(
        self,
        *,
        user_id: int | None = None,
        status: FlowStatus | str | None = None,
    ) -> int:
        """Count flows matching the given filters."""
        sql = "SELECT COUNT(*) FROM flows WHERE deleted_at IS NULL"
        params: list[Any] = []
        if user_id is not None:
            sql += " AND user_id = ?"
            params.append(user_id)
        if status is not None:
            status_val = status.value if isinstance(status, FlowStatus) else str(status)
            sql += " AND status = ?"
            params.append(status_val)
        cur = await self._execute(sql, tuple(params))
        row = await cur.fetchone()
        return int(row[0]) if row is not None else 0

    async def update_flow_status(self, flow_id: int, status: FlowStatus) -> Flow | None:
        """Update a flow's status (used by the state-machine back-propagation)."""
        now = _dt_to_text(datetime.utcnow())  # type: ignore[arg-type]
        async with self._lock:
            await self._execute(
                "UPDATE flows SET status = ?, updated_at = ? WHERE id = ?",
                (status.value, now, flow_id),
            )
            await self._commit()
        return await self.get_flow(flow_id)

    async def update_flow(
        self,
        flow_id: int,
        *,
        title: str | None = None,
        model: str | None = None,
        language: str | None = None,
        model_provider_name: str | None = None,
        model_provider_type: ProviderType | str | None = None,
        functions: dict[str, Any] | None = None,
        trace_id: str | None = None,
        tool_call_id_template: str | None = None,
    ) -> Flow | None:
        """Update one or more Flow columns (only non-``None`` fields are written)."""
        sets: list[str] = []
        params: list[Any] = []
        if title is not None:
            sets.append("title = ?")
            params.append(title)
        if model is not None:
            sets.append("model = ?")
            params.append(model)
        if language is not None:
            sets.append("language = ?")
            params.append(language)
        if model_provider_name is not None:
            sets.append("model_provider_name = ?")
            params.append(model_provider_name)
        if model_provider_type is not None:
            mpt = (
                model_provider_type
                if isinstance(model_provider_type, ProviderType)
                else ProviderType(model_provider_type)
            )
            sets.append("model_provider_type = ?")
            params.append(mpt.value)
        if functions is not None:
            sets.append("functions = ?")
            params.append(_json_dumps(functions))
        if trace_id is not None:
            sets.append("trace_id = ?")
            params.append(trace_id)
        if tool_call_id_template is not None:
            sets.append("tool_call_id_template = ?")
            params.append(tool_call_id_template)
        if not sets:
            return await self.get_flow(flow_id)
        sets.append("updated_at = ?")
        params.append(_dt_to_text(datetime.utcnow()))  # type: ignore[arg-type]
        params.append(flow_id)
        sql = f"UPDATE flows SET {', '.join(sets)} WHERE id = ?"  # noqa: S608
        async with self._lock:
            await self._execute(sql, tuple(params))
            await self._commit()
        return await self.get_flow(flow_id)

    async def delete_flow(self, flow_id: int) -> bool:
        """Soft-delete a flow (sets ``deleted_at``). Returns ``True`` if updated."""
        now = _dt_to_text(datetime.utcnow())  # type: ignore[arg-type]
        async with self._lock:
            cur = await self._execute(
                (
                    "UPDATE flows SET deleted_at = ?, updated_at = ? "
                    "WHERE id = ? AND deleted_at IS NULL"
                ),
                (now, now, flow_id),
            )
            await self._commit()
            return cur.rowcount > 0

    # ── Task CRUD ──────────────────────────────────────────────────────

    async def create_task(
        self,
        *,
        flow_id: int,
        input: str,
        title: str = "",
        status: TaskStatus = TaskStatus.CREATED,
    ) -> Task:
        """Insert a new Task row and return the populated :class:`Task`."""
        now = _dt_to_text(datetime.utcnow())  # type: ignore[arg-type]
        async with self._lock:
            cur = await self._execute(
                """
                INSERT INTO tasks (status, title, input, result, flow_id, created_at, updated_at)
                VALUES (?, ?, ?, '', ?, ?, ?)
                """,
                (status.value, title, input, flow_id, now, now),
            )
            task_id = cur.lastrowid
            await self._commit()
        assert task_id is not None  # noqa: S101
        cur = await self._execute("SELECT * FROM tasks WHERE id = ?", (task_id,))
        row = await cur.fetchone()
        assert row is not None  # noqa: S101
        return _task_from_row(row)

    async def get_task(self, task_id: int) -> Task | None:
        """Return a single Task by ID (or ``None`` if not found)."""
        cur = await self._execute("SELECT * FROM tasks WHERE id = ?", (task_id,))
        row = await cur.fetchone()
        return _task_from_row(row) if row is not None else None

    async def list_tasks(self, flow_id: int) -> list[Task]:
        """List all tasks for a flow, ordered by ``id`` ascending."""
        cur = await self._execute(
            "SELECT * FROM tasks WHERE flow_id = ? ORDER BY id ASC", (flow_id,)
        )
        rows = await cur.fetchall()
        return [_task_from_row(r) for r in rows]

    async def update_task_status(self, task_id: int, status: TaskStatus) -> Task | None:
        """Update a task's status (used by the state machine)."""
        now = _dt_to_text(datetime.utcnow())  # type: ignore[arg-type]
        async with self._lock:
            await self._execute(
                "UPDATE tasks SET status = ?, updated_at = ? WHERE id = ?",
                (status.value, now, task_id),
            )
            await self._commit()
        return await self.get_task(task_id)

    async def update_task_result(self, task_id: int, result: str) -> Task | None:
        """Update a task's ``result`` column (set on Reporter completion)."""
        now = _dt_to_text(datetime.utcnow())  # type: ignore[arg-type]
        async with self._lock:
            await self._execute(
                "UPDATE tasks SET result = ?, updated_at = ? WHERE id = ?",
                (result, now, task_id),
            )
            await self._commit()
        return await self.get_task(task_id)

    # ── Subtask CRUD ───────────────────────────────────────────────────

    async def create_subtask(
        self,
        *,
        task_id: int,
        title: str,
        description: str,
        status: SubtaskStatus = SubtaskStatus.CREATED,
    ) -> Subtask:
        """Insert a new Subtask row and return the populated :class:`Subtask`."""
        now = _dt_to_text(datetime.utcnow())  # type: ignore[arg-type]
        async with self._lock:
            cur = await self._execute(
                """
                INSERT INTO subtasks
                    (status, title, description, result, task_id, context, created_at, updated_at)
                VALUES
                    (?, ?, ?, '', ?, '', ?, ?)
                """,
                (status.value, title, description, task_id, now, now),
            )
            subtask_id = cur.lastrowid
            await self._commit()
        assert subtask_id is not None  # noqa: S101
        cur = await self._execute("SELECT * FROM subtasks WHERE id = ?", (subtask_id,))
        row = await cur.fetchone()
        assert row is not None  # noqa: S101
        return _subtask_from_row(row)

    async def get_subtask(self, subtask_id: int) -> Subtask | None:
        """Return a single Subtask by ID (or ``None`` if not found)."""
        cur = await self._execute(
            "SELECT * FROM subtasks WHERE id = ?", (subtask_id,)
        )
        row = await cur.fetchone()
        return _subtask_from_row(row) if row is not None else None

    async def list_subtasks(self, task_id: int) -> list[Subtask]:
        """List all subtasks for a task, ordered by ``id`` ascending."""
        cur = await self._execute(
            "SELECT * FROM subtasks WHERE task_id = ? ORDER BY id ASC", (task_id,)
        )
        rows = await cur.fetchall()
        return [_subtask_from_row(r) for r in rows]

    async def list_planned_subtasks(self, task_id: int) -> list[Subtask]:
        """List all subtasks for a task that are still in ``CREATED`` status.

        Mirrors PentAGI's ``GetTaskPlannedSubtasks`` — used by the
        subtask controller's ``PopSubtask`` to find the next subtask to run.
        """
        cur = await self._execute(
            "SELECT * FROM subtasks WHERE task_id = ? AND status = ? ORDER BY id ASC",
            (task_id, SubtaskStatus.CREATED.value),
        )
        rows = await cur.fetchall()
        return [_subtask_from_row(r) for r in rows]

    async def update_subtask_status(
        self, subtask_id: int, status: SubtaskStatus
    ) -> Subtask | None:
        """Update a subtask's status (used by the state machine)."""
        now = _dt_to_text(datetime.utcnow())  # type: ignore[arg-type]
        async with self._lock:
            await self._execute(
                "UPDATE subtasks SET status = ?, updated_at = ? WHERE id = ?",
                (status.value, now, subtask_id),
            )
            await self._commit()
        return await self.get_subtask(subtask_id)

    async def update_subtask_result(
        self, subtask_id: int, result: str
    ) -> Subtask | None:
        """Update a subtask's ``result`` column."""
        now = _dt_to_text(datetime.utcnow())  # type: ignore[arg-type]
        async with self._lock:
            await self._execute(
                "UPDATE subtasks SET result = ?, updated_at = ? WHERE id = ?",
                (result, now, subtask_id),
            )
            await self._commit()
        return await self.get_subtask(subtask_id)

    async def update_subtask_context(
        self, subtask_id: int, context: str
    ) -> Subtask | None:
        """Update a subtask's cached execution-context XML."""
        now = _dt_to_text(datetime.utcnow())  # type: ignore[arg-type]
        async with self._lock:
            await self._execute(
                "UPDATE subtasks SET context = ?, updated_at = ? WHERE id = ?",
                (context, now, subtask_id),
            )
            await self._commit()
        return await self.get_subtask(subtask_id)

    async def delete_subtasks(self, subtask_ids: list[int]) -> int:
        """Delete subtasks by ID list. Returns the number of rows deleted.

        Used by the Refiner to clear the planned subtask list before
        re-inserting the refined plan (mirrors PentAGI's
        ``DeleteSubtasks`` + ``CreateSubtask`` sequence).
        """
        if not subtask_ids:
            return 0
        placeholders = ", ".join("?" * len(subtask_ids))
        sql = f"DELETE FROM subtasks WHERE id IN ({placeholders})"  # noqa: S608
        async with self._lock:
            cur = await self._execute(sql, tuple(subtask_ids))
            await self._commit()
            return cur.rowcount

    # ── Msgchain CRUD ──────────────────────────────────────────────────

    async def create_msgchain(
        self,
        *,
        type: MsgchainType,
        flow_id: int,
        task_id: int | None = None,
        subtask_id: int | None = None,
        model: str = "",
        model_provider: str = "",
        chain: list[dict[str, Any]] | dict[str, Any] | None = None,
        usage_in: int = 0,
        usage_out: int = 0,
        usage_cache_in: int = 0,
        usage_cache_out: int = 0,
        usage_cost_in: float = 0.0,
        usage_cost_out: float = 0.0,
        duration_seconds: float = 0.0,
    ) -> Msgchain:
        """Insert a new Msgchain row and return the populated :class:`Msgchain`."""
        now = _dt_to_text(datetime.utcnow())  # type: ignore[arg-type]
        async with self._lock:
            cur = await self._execute(
                """
                INSERT INTO msgchains
                    (type, model, model_provider, usage_in, usage_out, chain,
                     flow_id, task_id, subtask_id, created_at, updated_at,
                     usage_cache_in, usage_cache_out, usage_cost_in, usage_cost_out,
                     duration_seconds)
                VALUES
                    (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    type.value,
                    model,
                    model_provider,
                    usage_in,
                    usage_out,
                    _json_dumps(chain if chain is not None else []),
                    flow_id,
                    task_id,
                    subtask_id,
                    now,
                    now,
                    usage_cache_in,
                    usage_cache_out,
                    usage_cost_in,
                    usage_cost_out,
                    duration_seconds,
                ),
            )
            mc_id = cur.lastrowid
            await self._commit()
        assert mc_id is not None  # noqa: S101
        cur = await self._execute("SELECT * FROM msgchains WHERE id = ?", (mc_id,))
        row = await cur.fetchone()
        assert row is not None  # noqa: S101
        return _msgchain_from_row(row)

    async def get_msgchain(self, msgchain_id: int) -> Msgchain | None:
        """Return a single Msgchain by ID (or ``None`` if not found)."""
        cur = await self._execute(
            "SELECT * FROM msgchains WHERE id = ?", (msgchain_id,)
        )
        row = await cur.fetchone()
        return _msgchain_from_row(row) if row is not None else None

    async def list_msgchains(
        self,
        *,
        flow_id: int | None = None,
        task_id: int | None = None,
        subtask_id: int | None = None,
        type: MsgchainType | None = None,
        limit: int = 100,
    ) -> list[Msgchain]:
        """List msgchains, optionally filtered by flow / task / subtask / type."""
        sql = "SELECT * FROM msgchains WHERE 1=1"
        params: list[Any] = []
        if flow_id is not None:
            sql += " AND flow_id = ?"
            params.append(flow_id)
        if task_id is not None:
            sql += " AND task_id = ?"
            params.append(task_id)
        if subtask_id is not None:
            sql += " AND subtask_id = ?"
            params.append(subtask_id)
        if type is not None:
            sql += " AND type = ?"
            params.append(type.value)
        sql += " ORDER BY id ASC LIMIT ?"
        params.append(limit)
        cur = await self._execute(sql, tuple(params))
        rows = await cur.fetchall()
        return [_msgchain_from_row(r) for r in rows]

    async def get_subtask_primary_msgchains(self, subtask_id: int) -> list[Msgchain]:
        """Return primary-agent msgchains for a subtask (used on resume)."""
        cur = await self._execute(
            """
            SELECT * FROM msgchains
            WHERE subtask_id = ? AND type = ?
            ORDER BY id ASC
            """,
            (subtask_id, MsgchainType.PRIMARY_AGENT.value),
        )
        rows = await cur.fetchall()
        return [_msgchain_from_row(r) for r in rows]

    async def update_msgchain(
        self,
        msgchain_id: int,
        *,
        chain: list[dict[str, Any]] | dict[str, Any] | None = None,
        usage_in: int | None = None,
        usage_out: int | None = None,
        usage_cache_in: int | None = None,
        usage_cache_out: int | None = None,
        usage_cost_in: float | None = None,
        usage_cost_out: float | None = None,
        duration_seconds: float | None = None,
    ) -> Msgchain | None:
        """Update one or more Msgchain columns (only non-``None`` fields)."""
        sets: list[str] = []
        params: list[Any] = []
        if chain is not None:
            sets.append("chain = ?")
            params.append(_json_dumps(chain))
        for field_name, value in (
            ("usage_in", usage_in),
            ("usage_out", usage_out),
            ("usage_cache_in", usage_cache_in),
            ("usage_cache_out", usage_cache_out),
            ("usage_cost_in", usage_cost_in),
            ("usage_cost_out", usage_cost_out),
            ("duration_seconds", duration_seconds),
        ):
            if value is not None:
                sets.append(f"{field_name} = ?")
                params.append(value)
        if not sets:
            return await self.get_msgchain(msgchain_id)
        sets.append("updated_at = ?")
        params.append(_dt_to_text(datetime.utcnow()))  # type: ignore[arg-type]
        params.append(msgchain_id)
        sql = f"UPDATE msgchains SET {', '.join(sets)} WHERE id = ?"  # noqa: S608
        async with self._lock:
            await self._execute(sql, tuple(params))
            await self._commit()
        return await self.get_msgchain(msgchain_id)

    # ── Msglog CRUD ────────────────────────────────────────────────────

    async def create_msglog(
        self,
        *,
        type: MsglogType,
        flow_id: int,
        message: str = "",
        result: str = "",
        task_id: int | None = None,
        subtask_id: int | None = None,
        result_format: MsglogResultFormat = MsglogResultFormat.MARKDOWN,
        thinking: str | None = None,
    ) -> Msglog:
        """Insert a new Msglog row and return the populated :class:`Msglog`."""
        now = _dt_to_text(datetime.utcnow())  # type: ignore[arg-type]
        async with self._lock:
            cur = await self._execute(
                """
                INSERT INTO msglogs
                    (type, message, result, flow_id, task_id, subtask_id,
                     created_at, result_format, thinking)
                VALUES
                    (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    type.value,
                    message,
                    result,
                    flow_id,
                    task_id,
                    subtask_id,
                    now,
                    result_format.value,
                    thinking,
                ),
            )
            mc_id = cur.lastrowid
            await self._commit()
        assert mc_id is not None  # noqa: S101
        cur = await self._execute("SELECT * FROM msglogs WHERE id = ?", (mc_id,))
        row = await cur.fetchone()
        assert row is not None  # noqa: S101
        return _msglog_from_row(row)

    async def list_msglogs(
        self,
        *,
        flow_id: int | None = None,
        task_id: int | None = None,
        subtask_id: int | None = None,
        limit: int = 100,
    ) -> list[Msglog]:
        """List msglogs, optionally filtered by flow / task / subtask."""
        sql = "SELECT * FROM msglogs WHERE 1=1"
        params: list[Any] = []
        if flow_id is not None:
            sql += " AND flow_id = ?"
            params.append(flow_id)
        if task_id is not None:
            sql += " AND task_id = ?"
            params.append(task_id)
        if subtask_id is not None:
            sql += " AND subtask_id = ?"
            params.append(subtask_id)
        sql += " ORDER BY id ASC LIMIT ?"
        params.append(limit)
        cur = await self._execute(sql, tuple(params))
        rows = await cur.fetchall()
        return [_msglog_from_row(r) for r in rows]

    # ── Agentlog CRUD ──────────────────────────────────────────────────

    async def create_agentlog(
        self,
        *,
        initiator: MsgchainType,
        executor: MsgchainType,
        flow_id: int,
        task: str = "",
        result: str = "",
        task_id: int | None = None,
        subtask_id: int | None = None,
    ) -> Agentlog:
        """Insert a new Agentlog row and return the populated :class:`Agentlog`."""
        now = _dt_to_text(datetime.utcnow())  # type: ignore[arg-type]
        async with self._lock:
            cur = await self._execute(
                """
                INSERT INTO agentlogs
                    (initiator, executor, task, result, flow_id, task_id, subtask_id, created_at)
                VALUES
                    (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    initiator.value,
                    executor.value,
                    task,
                    result,
                    flow_id,
                    task_id,
                    subtask_id,
                    now,
                ),
            )
            row_id = cur.lastrowid
            await self._commit()
        assert row_id is not None  # noqa: S101
        cur = await self._execute("SELECT * FROM agentlogs WHERE id = ?", (row_id,))
        row = await cur.fetchone()
        assert row is not None  # noqa: S101
        return _agentlog_from_row(row)

    async def list_agentlogs(
        self,
        *,
        flow_id: int | None = None,
        task_id: int | None = None,
        subtask_id: int | None = None,
        limit: int = 100,
    ) -> list[Agentlog]:
        """List agentlogs, optionally filtered."""
        sql = "SELECT * FROM agentlogs WHERE 1=1"
        params: list[Any] = []
        if flow_id is not None:
            sql += " AND flow_id = ?"
            params.append(flow_id)
        if task_id is not None:
            sql += " AND task_id = ?"
            params.append(task_id)
        if subtask_id is not None:
            sql += " AND subtask_id = ?"
            params.append(subtask_id)
        sql += " ORDER BY id ASC LIMIT ?"
        params.append(limit)
        cur = await self._execute(sql, tuple(params))
        rows = await cur.fetchall()
        return [_agentlog_from_row(r) for r in rows]

    # ── Toolcall CRUD ──────────────────────────────────────────────────

    async def create_toolcall(
        self,
        *,
        call_id: str,
        name: str,
        flow_id: int,
        args: dict[str, Any] | None = None,
        result: str = "",
        status: ToolcallStatus = ToolcallStatus.RECEIVED,
        task_id: int | None = None,
        subtask_id: int | None = None,
        duration_seconds: float = 0.0,
    ) -> Toolcall:
        """Insert a new Toolcall row and return the populated :class:`Toolcall`."""
        now = _dt_to_text(datetime.utcnow())  # type: ignore[arg-type]
        async with self._lock:
            cur = await self._execute(
                """
                INSERT INTO toolcalls
                    (call_id, status, name, args, result, flow_id, task_id, subtask_id,
                     created_at, updated_at, duration_seconds)
                VALUES
                    (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    call_id,
                    status.value,
                    name,
                    _json_dumps(args or {}),
                    result,
                    flow_id,
                    task_id,
                    subtask_id,
                    now,
                    now,
                    duration_seconds,
                ),
            )
            row_id = cur.lastrowid
            await self._commit()
        assert row_id is not None  # noqa: S101
        cur = await self._execute("SELECT * FROM toolcalls WHERE id = ?", (row_id,))
        row = await cur.fetchone()
        assert row is not None  # noqa: S101
        return _toolcall_from_row(row)

    async def update_toolcall_status(
        self, toolcall_id: int, status: ToolcallStatus, result: str = ""
    ) -> Toolcall | None:
        """Update a toolcall's status (and optionally its result)."""
        now = _dt_to_text(datetime.utcnow())  # type: ignore[arg-type]
        async with self._lock:
            await self._execute(
                "UPDATE toolcalls SET status = ?, result = ?, updated_at = ? WHERE id = ?",
                (status.value, result, now, toolcall_id),
            )
            await self._commit()
        cur = await self._execute("SELECT * FROM toolcalls WHERE id = ?", (toolcall_id,))
        row = await cur.fetchone()
        return _toolcall_from_row(row) if row is not None else None

    async def list_toolcalls(
        self,
        *,
        flow_id: int | None = None,
        task_id: int | None = None,
        subtask_id: int | None = None,
        limit: int = 100,
    ) -> list[Toolcall]:
        """List toolcalls, optionally filtered."""
        sql = "SELECT * FROM toolcalls WHERE 1=1"
        params: list[Any] = []
        if flow_id is not None:
            sql += " AND flow_id = ?"
            params.append(flow_id)
        if task_id is not None:
            sql += " AND task_id = ?"
            params.append(task_id)
        if subtask_id is not None:
            sql += " AND subtask_id = ?"
            params.append(subtask_id)
        sql += " ORDER BY id ASC LIMIT ?"
        params.append(limit)
        cur = await self._execute(sql, tuple(params))
        rows = await cur.fetchall()
        return [_toolcall_from_row(r) for r in rows]

    # ── Searchlog CRUD ─────────────────────────────────────────────────

    async def create_searchlog(
        self,
        *,
        initiator: MsgchainType,
        executor: MsgchainType,
        engine: SearchengineType,
        query: str,
        flow_id: int,
        result: str = "",
        task_id: int | None = None,
        subtask_id: int | None = None,
    ) -> Searchlog:
        """Insert a new Searchlog row and return the populated :class:`Searchlog`."""
        now = _dt_to_text(datetime.utcnow())  # type: ignore[arg-type]
        async with self._lock:
            cur = await self._execute(
                """
                INSERT INTO searchlogs
                    (initiator, executor, engine, query, result,
                     flow_id, task_id, subtask_id, created_at)
                VALUES
                    (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    initiator.value,
                    executor.value,
                    engine.value,
                    query,
                    result,
                    flow_id,
                    task_id,
                    subtask_id,
                    now,
                ),
            )
            row_id = cur.lastrowid
            await self._commit()
        assert row_id is not None  # noqa: S101
        cur = await self._execute("SELECT * FROM searchlogs WHERE id = ?", (row_id,))
        row = await cur.fetchone()
        assert row is not None  # noqa: S101
        return _searchlog_from_row(row)

    async def list_searchlogs(
        self,
        *,
        flow_id: int | None = None,
        task_id: int | None = None,
        subtask_id: int | None = None,
        limit: int = 100,
    ) -> list[Searchlog]:
        """List searchlogs, optionally filtered."""
        sql = "SELECT * FROM searchlogs WHERE 1=1"
        params: list[Any] = []
        if flow_id is not None:
            sql += " AND flow_id = ?"
            params.append(flow_id)
        if task_id is not None:
            sql += " AND task_id = ?"
            params.append(task_id)
        if subtask_id is not None:
            sql += " AND subtask_id = ?"
            params.append(subtask_id)
        sql += " ORDER BY id ASC LIMIT ?"
        params.append(limit)
        cur = await self._execute(sql, tuple(params))
        rows = await cur.fetchall()
        return [_searchlog_from_row(r) for r in rows]

    # ── Termlog CRUD ───────────────────────────────────────────────────

    async def create_termlog(
        self,
        *,
        type: TermlogType,
        container_id: int,
        flow_id: int,
        text: str = "",
        task_id: int | None = None,
        subtask_id: int | None = None,
    ) -> Termlog:
        """Insert a new Termlog row and return the populated :class:`Termlog`."""
        now = _dt_to_text(datetime.utcnow())  # type: ignore[arg-type]
        async with self._lock:
            cur = await self._execute(
                """
                INSERT INTO termlogs
                    (type, text, container_id, created_at, flow_id, task_id, subtask_id)
                VALUES
                    (?, ?, ?, ?, ?, ?, ?)
                """,
                (type.value, text, container_id, now, flow_id, task_id, subtask_id),
            )
            row_id = cur.lastrowid
            await self._commit()
        assert row_id is not None  # noqa: S101
        cur = await self._execute("SELECT * FROM termlogs WHERE id = ?", (row_id,))
        row = await cur.fetchone()
        assert row is not None  # noqa: S101
        return _termlog_from_row(row)

    async def list_termlogs(
        self,
        *,
        flow_id: int | None = None,
        task_id: int | None = None,
        subtask_id: int | None = None,
        limit: int = 100,
    ) -> list[Termlog]:
        """List termlogs, optionally filtered."""
        sql = "SELECT * FROM termlogs WHERE 1=1"
        params: list[Any] = []
        if flow_id is not None:
            sql += " AND flow_id = ?"
            params.append(flow_id)
        if task_id is not None:
            sql += " AND task_id = ?"
            params.append(task_id)
        if subtask_id is not None:
            sql += " AND subtask_id = ?"
            params.append(subtask_id)
        sql += " ORDER BY id ASC LIMIT ?"
        params.append(limit)
        cur = await self._execute(sql, tuple(params))
        rows = await cur.fetchall()
        return [_termlog_from_row(r) for r in rows]

    # ── Vecstorelog CRUD ───────────────────────────────────────────────

    async def create_vecstorelog(
        self,
        *,
        initiator: MsgchainType,
        executor: MsgchainType,
        action: VecstoreActionType,
        flow_id: int,
        query: str = "",
        result: str = "",
        filter: dict[str, Any] | None = None,
        task_id: int | None = None,
        subtask_id: int | None = None,
    ) -> Vecstorelog:
        """Insert a new Vecstorelog row and return the populated :class:`Vecstorelog`."""
        now = _dt_to_text(datetime.utcnow())  # type: ignore[arg-type]
        async with self._lock:
            cur = await self._execute(
                """
                INSERT INTO vecstorelogs
                    (initiator, executor, filter, query, action, result,
                     flow_id, task_id, subtask_id, created_at)
                VALUES
                    (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    initiator.value,
                    executor.value,
                    _json_dumps(filter or {}),
                    query,
                    action.value,
                    result,
                    flow_id,
                    task_id,
                    subtask_id,
                    now,
                ),
            )
            row_id = cur.lastrowid
            await self._commit()
        assert row_id is not None  # noqa: S101
        cur = await self._execute("SELECT * FROM vecstorelogs WHERE id = ?", (row_id,))
        row = await cur.fetchone()
        assert row is not None  # noqa: S101
        return _vecstorelog_from_row(row)

    async def list_vecstorelogs(
        self,
        *,
        flow_id: int | None = None,
        task_id: int | None = None,
        subtask_id: int | None = None,
        limit: int = 100,
    ) -> list[Vecstorelog]:
        """List vecstorelogs, optionally filtered."""
        sql = "SELECT * FROM vecstorelogs WHERE 1=1"
        params: list[Any] = []
        if flow_id is not None:
            sql += " AND flow_id = ?"
            params.append(flow_id)
        if task_id is not None:
            sql += " AND task_id = ?"
            params.append(task_id)
        if subtask_id is not None:
            sql += " AND subtask_id = ?"
            params.append(subtask_id)
        sql += " ORDER BY id ASC LIMIT ?"
        params.append(limit)
        cur = await self._execute(sql, tuple(params))
        rows = await cur.fetchall()
        return [_vecstorelog_from_row(r) for r in rows]

    # ── Screenshot CRUD ────────────────────────────────────────────────

    async def create_screenshot(
        self,
        *,
        flow_id: int,
        name: str = "",
        url: str = "",
        task_id: int | None = None,
        subtask_id: int | None = None,
    ) -> Screenshot:
        """Insert a new Screenshot row and return the populated :class:`Screenshot`."""
        now = _dt_to_text(datetime.utcnow())  # type: ignore[arg-type]
        async with self._lock:
            cur = await self._execute(
                """
                INSERT INTO screenshots
                    (name, url, flow_id, created_at, task_id, subtask_id)
                VALUES
                    (?, ?, ?, ?, ?, ?)
                """,
                (name, url, flow_id, now, task_id, subtask_id),
            )
            row_id = cur.lastrowid
            await self._commit()
        assert row_id is not None  # noqa: S101
        cur = await self._execute("SELECT * FROM screenshots WHERE id = ?", (row_id,))
        row = await cur.fetchone()
        assert row is not None  # noqa: S101
        return _screenshot_from_row(row)

    async def list_screenshots(
        self,
        *,
        flow_id: int | None = None,
        task_id: int | None = None,
        subtask_id: int | None = None,
        limit: int = 100,
    ) -> list[Screenshot]:
        """List screenshots, optionally filtered."""
        sql = "SELECT * FROM screenshots WHERE 1=1"
        params: list[Any] = []
        if flow_id is not None:
            sql += " AND flow_id = ?"
            params.append(flow_id)
        if task_id is not None:
            sql += " AND task_id = ?"
            params.append(task_id)
        if subtask_id is not None:
            sql += " AND subtask_id = ?"
            params.append(subtask_id)
        sql += " ORDER BY id ASC LIMIT ?"
        params.append(limit)
        cur = await self._execute(sql, tuple(params))
        rows = await cur.fetchall()
        return [_screenshot_from_row(r) for r in rows]

    # ── Prompt CRUD ────────────────────────────────────────────────────

    async def upsert_prompt(
        self,
        *,
        type: str,
        user_id: int,
        prompt: str,
    ) -> Prompt:
        """Insert or update a user-overridable prompt template.

        Mirrors PentAGI's ``UpsertPrompt`` query: if a row exists for
        ``(type, user_id)``, its ``prompt`` and ``updated_at`` are updated;
        otherwise a new row is inserted.
        """
        now = _dt_to_text(datetime.utcnow())  # type: ignore[arg-type]
        async with self._lock:
            cur = await self._execute(
                "SELECT id FROM prompts WHERE type = ? AND user_id = ?",
                (type, user_id),
            )
            existing = await cur.fetchone()
            if existing is not None:
                row_id = existing["id"]
                await self._execute(
                    "UPDATE prompts SET prompt = ?, updated_at = ? WHERE id = ?",
                    (prompt, now, row_id),
                )
            else:
                cur = await self._execute(
                    """
                    INSERT INTO prompts (type, user_id, prompt, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (type, user_id, prompt, now, now),
                )
                row_id = cur.lastrowid
            await self._commit()
        assert row_id is not None  # noqa: S101
        cur = await self._execute("SELECT * FROM prompts WHERE id = ?", (row_id,))
        row = await cur.fetchone()
        assert row is not None  # noqa: S101
        return _prompt_from_row(row)

    async def get_prompt(self, type: str, user_id: int) -> Prompt | None:
        """Return the user's override for a prompt type (or ``None``)."""
        cur = await self._execute(
            "SELECT * FROM prompts WHERE type = ? AND user_id = ?",
            (type, user_id),
        )
        row = await cur.fetchone()
        return _prompt_from_row(row) if row is not None else None

    # ── Container CRUD ─────────────────────────────────────────────────

    async def create_container(
        self,
        *,
        flow_id: int,
        name: str,
        image: str,
        type: ContainerType = ContainerType.PRIMARY,
        status: ContainerStatus = ContainerStatus.STARTING,
        local_id: str | None = None,
        local_dir: str | None = None,
    ) -> Container:
        """Insert a new Container row and return the populated :class:`Container`."""
        now = _dt_to_text(datetime.utcnow())  # type: ignore[arg-type]
        async with self._lock:
            cur = await self._execute(
                """
                INSERT INTO containers
                    (type, name, image, status, local_id, local_dir, flow_id,
                     created_at, updated_at)
                VALUES
                    (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    type.value,
                    name,
                    image,
                    status.value,
                    local_id,
                    local_dir,
                    flow_id,
                    now,
                    now,
                ),
            )
            row_id = cur.lastrowid
            await self._commit()
        assert row_id is not None  # noqa: S101
        cur = await self._execute("SELECT * FROM containers WHERE id = ?", (row_id,))
        row = await cur.fetchone()
        assert row is not None  # noqa: S101
        return _container_from_row(row)

    async def list_containers(self, flow_id: int) -> list[Container]:
        """List all containers attached to a flow."""
        cur = await self._execute(
            "SELECT * FROM containers WHERE flow_id = ? ORDER BY id ASC",
            (flow_id,),
        )
        rows = await cur.fetchall()
        return [_container_from_row(r) for r in rows]

    async def update_container_status(
        self, container_id: int, status: ContainerStatus
    ) -> Container | None:
        """Update a container's status."""
        now = _dt_to_text(datetime.utcnow())  # type: ignore[arg-type]
        async with self._lock:
            await self._execute(
                "UPDATE containers SET status = ?, updated_at = ? WHERE id = ?",
                (status.value, now, container_id),
            )
            await self._commit()
        cur = await self._execute(
            "SELECT * FROM containers WHERE id = ?", (container_id,)
        )
        row = await cur.fetchone()
        return _container_from_row(row) if row is not None else None

    # ── Aggregate helpers ──────────────────────────────────────────────

    async def get_flow_usage(self, flow_id: int) -> dict[str, Any]:
        """Return aggregated token / cost usage for a flow.

        Mirrors PentAGI's ``GetFlowUsage`` query: sums
        ``usage_in`` / ``usage_out`` / ``usage_cache_in`` /
        ``usage_cache_out`` / ``usage_cost_in`` / ``usage_cost_out`` /
        ``duration_seconds`` over all msgchains in the flow.
        """
        cur = await self._execute(
            """
            SELECT
                COALESCE(SUM(usage_in), 0)         AS usage_in,
                COALESCE(SUM(usage_out), 0)        AS usage_out,
                COALESCE(SUM(usage_cache_in), 0)   AS usage_cache_in,
                COALESCE(SUM(usage_cache_out), 0)  AS usage_cache_out,
                COALESCE(SUM(usage_cost_in), 0.0)  AS usage_cost_in,
                COALESCE(SUM(usage_cost_out), 0.0) AS usage_cost_out,
                COALESCE(SUM(duration_seconds), 0.0) AS duration_seconds
            FROM msgchains WHERE flow_id = ?
            """,
            (flow_id,),
        )
        row = await cur.fetchone()
        if row is None:
            return {
                "usage_in": 0,
                "usage_out": 0,
                "usage_cache_in": 0,
                "usage_cache_out": 0,
                "usage_cost_in": 0.0,
                "usage_cost_out": 0.0,
                "duration_seconds": 0.0,
            }
        return {
            "usage_in": int(row["usage_in"]),
            "usage_out": int(row["usage_out"]),
            "usage_cache_in": int(row["usage_cache_in"]),
            "usage_cache_out": int(row["usage_cache_out"]),
            "usage_cost_in": float(row["usage_cost_in"]),
            "usage_cost_out": float(row["usage_cost_out"]),
            "duration_seconds": float(row["duration_seconds"]),
        }


__all__ = ["FlowDB"]
