"""elengenix/docker/sandbox.py — Docker sandbox for isolated tool execution (ported from PentAGI).

This module is a Python port of PentAGI's `backend/pkg/docker/client.go` (856 lines,
15-method interface). It provides a fully-async Docker sandbox that:

  * Allocates a deterministic port pair per flow (ports 28000–30000).
  * Persists container state in SQLite at ``~/.elengenix/data/containers.db``.
  * Falls back to ``debian:latest`` when a requested image cannot be pulled.
  * Performs TAR-based file copies to/from containers via the Docker API.
  * Cleans up orphan containers concurrently on startup.

Native-async ``aiodocker`` is preferred. If it is unavailable, the synchronous
``docker`` SDK is wrapped with ``asyncio.to_thread`` so the public surface stays
fully async. Both libraries are imported lazily inside ``__init__`` so that this
module remains importable in environments without Docker installed (e.g. unit
tests, CI, lint).
"""

from __future__ import annotations

import asyncio
import io
import logging
import os
import sqlite3
import tarfile
import time
import zlib
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger("elengenix.docker.sandbox")

# ─── Constants (ported verbatim from PentAGI's client.go) ─────────────────────

WORK_FOLDER_PATH_IN_CONTAINER = "/work"
BASE_CONTAINER_PORTS_NUMBER = 28000
CONTAINER_PORTS_NUMBER = 2
LIMIT_CONTAINER_PORTS_NUMBER = 2000  # port range 28000–30000
CONTAINER_LIST_WORKERS = 20
DEFAULT_IMAGE = "debian:latest"
PENTEST_DOCKER_IMAGE = "vxcontrol/kali-linux"

DEFAULT_DOCKER_SOCKET_PATH = "/var/run/docker.sock"
CONTAINER_PRIMARY_TYPE_PATTERN = "-terminal-"
CONTAINER_LOCAL_CWD_TEMPLATE = "flow-{flow_id}"

# TAR/file guards (ported from terminal.go ReadFile/WriteFile)
MAX_FILE_SIZE_BYTES = 100 * 1024 * 1024  # 100 MB per file

# Container lifecycle defaults
CONTAINER_ENTRYPOINT = ["tail", "-f", "/dev/null"]
RESTART_POLICY_NAME = "on-failure"
RESTART_POLICY_MAX_RETRIES = 5
LOG_CONFIG_TYPE = "json-file"
LOG_CONFIG_MAX_SIZE = "10m"
LOG_CONFIG_MAX_FILE = "5"

# Default SQLite path (mirrors paths.py: ~/.elengenix/data/containers.db)
DEFAULT_DB_PATH = Path("~/.elengenix/data/containers.db").expanduser()


# ─── Enums & dataclasses ──────────────────────────────────────────────────────


class ContainerStatus(str, Enum):
    """Container lifecycle states (mirrors PentAGI ``database.ContainerStatus``)."""

    STARTING = "starting"
    RUNNING = "running"
    STOPPED = "stopped"
    DELETED = "deleted"
    FAILED = "failed"


class ContainerType(str, Enum):
    """Container role (mirrors PentAGI ``database.ContainerType``)."""

    PRIMARY = "primary"  # terminal sandbox
    SECONDARY = "secondary"  # reserved for future use


@dataclass
class ContainerInfo:
    """Persisted container record (ports the PentAGI ``containers`` table schema)."""

    id: Optional[int] = None
    type: ContainerType = ContainerType.PRIMARY
    name: str = ""
    image: str = ""
    status: ContainerStatus = ContainerStatus.STARTING
    local_id: str = ""  # Docker container ID
    local_dir: str = ""  # host path bound to /work
    flow_id: int = 0
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)

    def to_row(self) -> tuple:
        return (
            self.type.value,
            self.name,
            self.image,
            self.status.value,
            self.local_id,
            self.local_dir,
            self.flow_id,
            self.created_at,
            self.updated_at,
        )


# ─── Helpers ──────────────────────────────────────────────────────────────────


def _allocate_ports(flow_id: int) -> list[int]:
    """Deterministic port allocation — ported verbatim from PentAGI's
    ``GetPrimaryContainerPorts``.

    Formula: ``28000 + (flow_id * 2 + i) % 2000`` for i in [0, 2).
    """
    return [
        BASE_CONTAINER_PORTS_NUMBER
        + (flow_id * CONTAINER_PORTS_NUMBER + i) % LIMIT_CONTAINER_PORTS_NUMBER
        for i in range(CONTAINER_PORTS_NUMBER)
    ]


def _hostname_from_name(container_name: str) -> str:
    """Hostname = 8-hex-char crc32 of container name (ports Go's
    ``crc32.ChecksumIEEE``)."""
    return f"{zlib.crc32(container_name.encode('utf-8')) & 0xFFFFFFFF:08x}"


# ─── SQLite persistence layer ─────────────────────────────────────────────────


class _ContainerStore:
    """Tiny SQLite DAO mirroring PentAGI's ``containers`` table schema.

    Schema (from PentAGI ``backend/pkg/database/models.go``):
        {id, type, name, image, status, local_id, local_dir, flow_id,
         created_at, updated_at}
    """

    def __init__(self, db_path: Path | str = DEFAULT_DB_PATH) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def _init_db(self) -> None:
        with self._conn() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS containers (
                    id         INTEGER PRIMARY KEY AUTOINCREMENT,
                    type       TEXT    NOT NULL,
                    name       TEXT    NOT NULL,
                    image      TEXT    NOT NULL,
                    status     TEXT    NOT NULL,
                    local_id   TEXT    NOT NULL DEFAULT '',
                    local_dir  TEXT    NOT NULL DEFAULT '',
                    flow_id    INTEGER NOT NULL,
                    created_at REAL    NOT NULL,
                    updated_at REAL    NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_containers_flow_id ON containers(flow_id);
                CREATE INDEX IF NOT EXISTS idx_containers_status  ON containers(status);
                CREATE INDEX IF NOT EXISTS idx_containers_local_id ON containers(local_id);
                """
            )

    @staticmethod
    def _row_to_info(row: sqlite3.Row) -> ContainerInfo:
        return ContainerInfo(
            id=row["id"],
            type=ContainerType(row["type"]),
            name=row["name"],
            image=row["image"],
            status=ContainerStatus(row["status"]),
            local_id=row["local_id"],
            local_dir=row["local_dir"],
            flow_id=row["flow_id"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )

    # ── CRUD ──────────────────────────────────────────────────────────────
    def create(self, info: ContainerInfo) -> ContainerInfo:
        now = time.time()
        info.created_at = now
        info.updated_at = now
        with self._conn() as conn:
            cur = conn.execute(
                """
                INSERT INTO containers
                    (type, name, image, status, local_id, local_dir, flow_id,
                     created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                info.to_row(),
            )
            info.id = cur.lastrowid
            conn.commit()
        return info

    def update_status(
        self,
        db_id: int,
        status: ContainerStatus,
        local_id: Optional[str] = None,
    ) -> Optional[ContainerInfo]:
        now = time.time()
        with self._conn() as conn:
            if local_id is not None:
                conn.execute(
                    "UPDATE containers SET status=?, local_id=?, updated_at=? WHERE id=?",
                    (status.value, local_id, now, db_id),
                )
            else:
                conn.execute(
                    "UPDATE containers SET status=?, updated_at=? WHERE id=?",
                    (status.value, now, db_id),
                )
            conn.commit()
            row = conn.execute(
                "SELECT * FROM containers WHERE id=?", (db_id,)
            ).fetchone()
        return self._row_to_info(row) if row else None

    def update_image(self, db_id: int, image: str) -> Optional[ContainerInfo]:
        now = time.time()
        with self._conn() as conn:
            conn.execute(
                "UPDATE containers SET image=?, updated_at=? WHERE id=?",
                (image, now, db_id),
            )
            conn.commit()
            row = conn.execute(
                "SELECT * FROM containers WHERE id=?", (db_id,)
            ).fetchone()
        return self._row_to_info(row) if row else None

    def get(self, db_id: int) -> Optional[ContainerInfo]:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM containers WHERE id=?", (db_id,)
            ).fetchone()
        return self._row_to_info(row) if row else None

    def get_by_flow(self, flow_id: int) -> list[ContainerInfo]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM containers WHERE flow_id=?", (flow_id,)
            ).fetchall()
        return [self._row_to_info(r) for r in rows]

    def get_primary_for_flow(self, flow_id: int) -> Optional[ContainerInfo]:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM containers WHERE flow_id=? AND type=? "
                "ORDER BY id DESC LIMIT 1",
                (flow_id, ContainerType.PRIMARY.value),
            ).fetchone()
        return self._row_to_info(row) if row else None

    def list_all(self) -> list[ContainerInfo]:
        with self._conn() as conn:
            rows = conn.execute("SELECT * FROM containers").fetchall()
        return [self._row_to_info(r) for r in rows]


# ─── Flow status enum (mirror PentAGI FlowStatus for cleanup) ─────────────────


class _FlowStatus(str, Enum):
    CREATED = "created"
    RUNNING = "running"
    WAITING = "waiting"
    FINISHED = "finished"
    FAILED = "failed"


# ─── Main DockerSandbox class ─────────────────────────────────────────────────


class DockerSandbox:
    """Async Docker sandbox wrapper.

    Ports PentAGI's 15-method ``DockerClient`` Go interface plus the
    ``Prepare`` / ``Release`` high-level helpers from ``tools.go``.

    The underlying client is ``aiodocker`` (preferred). When unavailable, the
    synchronous ``docker`` SDK is wrapped via ``asyncio.to_thread``.
    """

    def __init__(
        self,
        data_dir: Optional[str | Path] = None,
        host_dir: Optional[str] = None,
        default_image: str = DEFAULT_IMAGE,
        docker_socket: str = DEFAULT_DOCKER_SOCKET_PATH,
        network: str = "",
        public_ip: str = "0.0.0.0",
        docker_inside: bool = False,
        docker_net_admin: bool = False,
        db_path: Path | str = DEFAULT_DB_PATH,
    ) -> None:
        self.data_dir = Path(data_dir).expanduser() if data_dir else (
            Path("~/.elengenix/data").expanduser()
        )
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.host_dir = host_dir or ""
        self.def_image = (default_image or DEFAULT_IMAGE).lower()
        self.socket = docker_socket
        self.network = network or ""
        self.public_ip = public_ip
        self.inside = bool(docker_inside)
        self.net_admin = bool(docker_net_admin)
        self.store = _ContainerStore(db_path)

        # Lazy-import the Docker client libraries. We prefer aiodocker; if it's
        # unavailable, we fall back to the synchronous docker SDK and wrap all
        # blocking calls with ``asyncio.to_thread``. Both libs are imported
        # lazily so this module remains importable in Docker-less environments.
        self._aiodocker: Any = None
        self._docker_sync: Any = None
        self._use_aiodocker: bool = False
        try:
            import aiodocker  # type: ignore

            self._aiodocker = aiodocker
            self._use_aiodocker = True
            logger.debug("aiodocker available — using native async Docker client")
        except ImportError:
            try:
                import docker  # type: ignore

                self._docker_sync = docker
                logger.debug(
                    "aiodocker missing — falling back to docker SDK + asyncio.to_thread"
                )
            except ImportError:
                logger.warning(
                    "Neither aiodocker nor docker SDK installed — DockerSandbox "
                    "will raise on first use; module remains importable for tests"
                )

        # Client handles are created lazily so __init__ never needs a running
        # event loop and never opens a socket until a method is actually used.
        self._client: Any = None

    # ─── Client lifecycle ─────────────────────────────────────────────────

    async def _get_client(self) -> Any:
        """Return an aiodocker.Docker() or a docker.from_env() client (cached)."""
        if self._client is not None:
            return self._client

        if self._use_aiodocker:
            self._client = self._aiodocker.Docker()
        elif self._docker_sync is not None:
            self._client = await asyncio.to_thread(self._docker_sync.from_env)
        else:
            raise RuntimeError(
                "No Docker client available. Install aiodocker (preferred) or docker."
            )
        return self._client

    async def close(self) -> None:
        """Release the underlying Docker client (aiodocker only)."""
        if self._client is None:
            return
        if self._use_aiodocker:
            try:
                await self._client.close()
            except Exception as exc:  # noqa: BLE001
                logger.debug("error closing aiodocker client: %s", exc)
        self._client = None

    # ─── Port allocation ──────────────────────────────────────────────────

    def _allocate_ports(self, flow_id: int) -> list[int]:
        """Deterministic port allocation per flow (ports 28000–30000)."""
        return _allocate_ports(flow_id)

    async def get_default_image(self) -> str:
        """Return the default image used as a fallback."""
        return self.def_image

    # ─── Image pull ───────────────────────────────────────────────────────

    async def _pull_image(self, image_name: str) -> None:
        """Pull ``image_name`` if not cached locally (ports ``pullImage``)."""
        client = await self._get_client()
        if self._use_aiodocker:
            # Check local cache first
            filters = {"reference": [image_name]}
            images = await client.images.list(filter=filters)
            if images:
                return
            logger.info("initiating image download from registry: %s", image_name)
            stream = await client.images.pull(image_name)
            # aiodocker returns a DockerImage object; pull is already complete
            # by the time it resolves. We touch .id to ensure availability.
            _ = getattr(stream, "id", None) or stream
        else:
            def _sync_pull() -> None:
                images = client.images.list(filters={"reference": image_name})
                if images:
                    return
                logger.info("initiating image download from registry: %s", image_name)
                client.images.pull(image_name)

            await asyncio.to_thread(_sync_pull)

    # ─── Network ensure ───────────────────────────────────────────────────

    async def _ensure_network(self) -> None:
        """Idempotently create the configured network (skipped for host mode)."""
        name = self.network
        if not name or name == "host":
            return
        client = await self._get_client()
        if self._use_aiodocker:
            try:
                await client.networks.get(name)
                return
            except Exception:  # noqa: BLE001
                pass  # not found → create
            try:
                await client.networks.create(
                    {"Name": name, "Driver": "bridge"},
                )
            except Exception as exc:  # noqa: BLE001
                logger.warning("failed to create network %s: %s", name, exc)
        else:
            def _sync_ensure() -> None:
                try:
                    client.networks.get(name)
                except Exception:  # noqa: BLE001
                    try:
                        client.networks.create(name, driver="bridge")
                    except Exception as exc:  # noqa: BLE001
                        logger.warning("failed to create network %s: %s", name, exc)

            await asyncio.to_thread(_sync_ensure)

    # ─── Container name conventions ───────────────────────────────────────

    @staticmethod
    def _primary_container_name(flow_id: int) -> str:
        return f"elengenix{CONTAINER_PRIMARY_TYPE_PATTERN}{flow_id}"

    # ─── 1) Run container ─────────────────────────────────────────────────

    async def run_container(
        self,
        flow_id: int,
        image: str,
        ports: Optional[list[int]] = None,
        env: Optional[dict[str, str]] = None,
        volumes: Optional[list[str]] = None,
        network: str = "bridge",
        capabilities: Optional[list[str]] = None,
    ) -> ContainerInfo:
        """Create + start a container.

        Ports PentAGI's ``RunContainer`` flow:
          1. Create ``{data_dir}/flow-{flow_id}/`` directory.
          2. Insert DB row with STARTING + tmp local_id.
          3. Pull image (fallback to DEFAULT_IMAGE on failure).
          4. Configure container (hostname, working dir, restart policy, logs).
          5. Create + start container; update DB to RUNNING.
          6. On any unrecoverable failure mark DB row as FAILED.
        """
        if not image:
            image = self.def_image
        image = image.lower()

        container_name = self._primary_container_name(flow_id)
        work_dir = self.data_dir / CONTAINER_LOCAL_CWD_TEMPLATE.format(flow_id=flow_id)
        work_dir.mkdir(parents=True, exist_ok=True)

        host_dir = self.host_dir
        if host_dir:
            host_dir = os.path.join(host_dir, CONTAINER_LOCAL_CWD_TEMPLATE.format(flow_id=flow_id))

        logger.info(
            "running container flow_id=%s image=%s name=%s work_dir=%s host_dir=%s",
            flow_id,
            image,
            container_name,
            work_dir,
            host_dir,
        )

        # Step 2: DB insert
        info = self.store.create(
            ContainerInfo(
                type=ContainerType.PRIMARY,
                name=container_name,
                image=image,
                status=ContainerStatus.STARTING,
                local_id=f"tmp-id-{flow_id}",
                local_dir=host_dir or "",
                flow_id=flow_id,
            )
        )

        async def _fallback_to_default() -> bool:
            nonlocal image
            logger.warning("try to use default image: %s", self.def_image)
            image = self.def_image
            self.store.update_image(info.id, image)  # type: ignore[arg-type]
            try:
                await self._pull_image(image)
                return True
            except Exception as exc:  # noqa: BLE001
                logger.error("failed to pull default image '%s': %s", image, exc)
                return False

        # Step 3: image pull (with fallback)
        try:
            await self._pull_image(image)
        except Exception as exc:  # noqa: BLE001
            logger.warning("failed to pull image '%s', falling back: %s", image, exc)
            if image == self.def_image or not await _fallback_to_default():
                self.store.update_status(info.id, ContainerStatus.FAILED, "")
                raise RuntimeError(
                    f"failed to pull image '{image}' and default image also unavailable"
                ) from exc

        # Step 4: configure container
        flow_ports = ports if ports is not None else self._allocate_ports(flow_id)
        cap_add = list(capabilities or [])
        if "NET_RAW" not in cap_add and "NET_RAW" not in [c.upper() for c in cap_add]:
            cap_add.append("NET_RAW")
        if self.net_admin and "NET_ADMIN" not in [c.upper() for c in cap_add]:
            cap_add.append("NET_ADMIN")

        bind_src = host_dir or str(work_dir)
        binds = [f"{bind_src}:{WORK_FOLDER_PATH_IN_CONTAINER}"]
        if volumes:
            binds.extend(volumes)
        if self.inside:
            binds.append(f"{self.socket}:{DEFAULT_DOCKER_SOCKET_PATH}")

        hostname = _hostname_from_name(container_name)
        exposed_ports: dict[str, dict] = {}
        port_bindings: dict[str, list[dict[str, str]]] = {}
        net_mode = ""
        if network == "host" or self.network == "host":
            net_mode = "host"
        else:
            for p in flow_ports:
                key = f"{p}/tcp"
                exposed_ports[key] = {}
                port_bindings[key] = [{"HostIp": self.public_ip, "HostPort": str(p)}]

        container_config: dict[str, Any] = {
            "Hostname": hostname,
            "Image": image,
            "WorkingDir": WORK_FOLDER_PATH_IN_CONTAINER,
            "Entrypoint": CONTAINER_ENTRYPOINT,
            "Env": [f"{k}={v}" for k, v in (env or {}).items()],
            "ExposedPorts": exposed_ports,
            "Tty": True,
            "OpenStdin": True,
        }
        host_config: dict[str, Any] = {
            "RestartPolicy": {
                "Name": RESTART_POLICY_NAME,
                "MaximumRetryCount": RESTART_POLICY_MAX_RETRIES,
            },
            "Binds": binds,
            "CapAdd": cap_add,
            "LogConfig": {
                "Type": LOG_CONFIG_TYPE,
                "Config": {
                    "max-size": LOG_CONFIG_MAX_SIZE,
                    "max-file": LOG_CONFIG_MAX_FILE,
                },
            },
        }
        if net_mode:
            host_config["NetworkMode"] = net_mode
        elif port_bindings:
            host_config["PortBindings"] = port_bindings

        networking_config: dict[str, Any] = {}
        if not net_mode and self.network:
            networking_config = {
                "EndpointsConfig": {self.network: {}}
            }

        await self._ensure_network()
        client = await self._get_client()

        # Step 5: container create (with fallback on failure)
        container_id: Optional[str] = None
        try:
            container_id = await self._create_container(
                container_config, host_config, networking_config, container_name
            )
        except Exception as exc:  # noqa: BLE001
            if image == self.def_image:
                self.store.update_status(info.id, ContainerStatus.FAILED, "")
                raise RuntimeError(
                    f"failed to create container with default image: {exc}"
                ) from exc
            logger.warning("failed to create container, try default image: %s", exc)
            if not await _fallback_to_default():
                self.store.update_status(info.id, ContainerStatus.FAILED, "")
                raise RuntimeError(
                    f"failed to create container and default image unavailable: {exc}"
                ) from exc
            # Cleanup any stale container with same name
            await self._remove_existing_named_container(container_name)
            container_config["Image"] = image
            try:
                container_id = await self._create_container(
                    container_config, host_config, networking_config, container_name
                )
            except Exception as exc2:  # noqa: BLE001
                self.store.update_status(info.id, ContainerStatus.FAILED, "")
                raise RuntimeError(
                    f"failed to create container '{image}': {exc2}"
                ) from exc2

        # Step 6: start container
        try:
            await self._start_container(container_id)  # type: ignore[arg-type]
        except Exception as exc:  # noqa: BLE001
            self.store.update_status(info.id, ContainerStatus.FAILED, container_id)
            raise RuntimeError(f"failed to start container: {exc}") from exc

        self.store.update_status(info.id, ContainerStatus.RUNNING, container_id)
        info.local_id = container_id  # type: ignore[assignment]
        info.status = ContainerStatus.RUNNING
        info.image = image
        logger.info("container started local_id=%s", container_id)
        return info

    async def _create_container(
        self,
        config: dict[str, Any],
        host_config: dict[str, Any],
        networking_config: dict[str, Any],
        name: str,
    ) -> str:
        client = await self._get_client()
        if self._use_aiodocker:
            container = await client.containers.create(
                config,
                name=name,
            )
            return container.id if hasattr(container, "id") else container["Id"]
        else:
            def _sync() -> str:
                c = client.containers.create(
                    config,
                    host_config=host_config,
                    networking_config=networking_config,
                    name=name,
                )
                return c.id

            return await asyncio.to_thread(_sync)

    async def _start_container(self, container_id: str) -> None:
        client = await self._get_client()
        if self._use_aiodocker:
            container = client.containers.container(container_id)
            await container.start()
        else:
            await asyncio.to_thread(client.containers.get(container_id).start)

    async def _remove_existing_named_container(self, name: str) -> None:
        """Force-remove any Docker container with the given name (best effort)."""
        client = await self._get_client()
        try:
            if self._use_aiodocker:
                containers = await client.containers.list(all=True)
                for c in containers:
                    c_names = c.get("Names", []) if isinstance(c, dict) else []
                    if any(n.lstrip("/") == name for n in c_names):
                        try:
                            await c.delete(force=True, v=True)
                        except Exception:  # noqa: BLE001
                            pass
            else:
                def _sync() -> None:
                    for c in client.containers.list(all=True):
                        if c.name.lstrip("/") == name:
                            try:
                                c.remove(force=True, v=True)
                            except Exception:  # noqa: BLE001
                                pass

                await asyncio.to_thread(_sync)
        except Exception as exc:  # noqa: BLE001
            logger.debug("remove_existing_named_container failed: %s", exc)

    # ─── 2) Stop container ────────────────────────────────────────────────

    async def stop_container(self, container_id: str) -> None:
        """Stop a running container (ports PentAGI ``StopContainer``).

        Missing containers are logged but not treated as errors.
        """
        logger.info("initiating container shutdown sequence: %s", container_id)
        client = await self._get_client()
        try:
            if self._use_aiodocker:
                container = client.containers.container(container_id)
                await container.stop()
            else:
                await asyncio.to_thread(client.containers.get(container_id).stop)
        except Exception as exc:  # noqa: BLE001
            msg = str(exc).lower()
            if "not found" in msg or "no such" in msg:
                logger.warning("target container already removed or never existed")
            else:
                raise RuntimeError(f"container shutdown failed: {exc}") from exc

        # Update DB status to STOPPED for any rows matching this local_id.
        for row in self.store.list_all():
            if row.local_id == container_id:
                self.store.update_status(row.id, ContainerStatus.STOPPED)  # type: ignore[arg-type]
        logger.info("container shutdown completed: %s", container_id)

    # ─── 3) Remove container ──────────────────────────────────────────────

    async def remove_container(
        self,
        container_id: str,
        force: bool = False,
        remove_volumes: bool = True,
    ) -> None:
        """Stop + remove a container (ports PentAGI ``RemoveContainer``)."""
        logger.info("removing container and associated resources: %s", container_id)
        try:
            await self.stop_container(container_id)
        except Exception as exc:  # noqa: BLE001
            raise RuntimeError(f"failed to stop container: {exc}") from exc

        client = await self._get_client()
        try:
            if self._use_aiodocker:
                container = client.containers.container(container_id)
                await container.delete(force=force, v=remove_volumes)
            else:
                await asyncio.to_thread(
                    client.containers.get(container_id).remove,
                    force=force,
                    v=remove_volumes,
                )
        except Exception as exc:  # noqa: BLE001
            msg = str(exc).lower()
            if "not found" in msg or "no such" in msg:
                logger.warning("container not found: %s", container_id)
            else:
                raise RuntimeError(f"failed to remove container: {exc}") from exc

        # Update DB rows to DELETED.
        for row in self.store.list_all():
            if row.local_id == container_id:
                self.store.update_status(row.id, ContainerStatus.DELETED)  # type: ignore[arg-type]
        logger.info("container removed: %s", container_id)

    # ─── 4) Is container running ──────────────────────────────────────────

    async def is_container_running(self, container_id: str) -> bool:
        """Return True iff the container is running AND (if it has a healthcheck)
        not ``unhealthy``. Ports PentAGI ``IsContainerRunning``.
        """
        client = await self._get_client()
        try:
            if self._use_aiodocker:
                container = client.containers.container(container_id)
                data = await container.show()
            else:
                data = await asyncio.to_thread(client.containers.get(container_id).inspect)
        except Exception as exc:  # noqa: BLE001
            raise RuntimeError(f"container inspection failed: {exc}") from exc

        state = data.get("State", {}) if isinstance(data, dict) else {}
        is_operational = bool(state.get("Running", False))
        health = state.get("Health") or {}
        health_status = health.get("Status", "") if isinstance(health, dict) else ""
        if health_status:
            is_operational = is_operational and health_status != "unhealthy"
        return is_operational

    # ─── 5) Exec create ───────────────────────────────────────────────────

    async def container_exec_create(
        self,
        container_id: str,
        cmd: list[str] | str,
        working_dir: Optional[str] = None,
        env: Optional[dict[str, str]] = None,
    ) -> str:
        """Create an exec instance inside the container. Returns the exec ID."""
        if isinstance(cmd, str):
            cmd = ["sh", "-c", cmd]
        config: dict[str, Any] = {
            "Cmd": cmd,
            "AttachStdout": True,
            "AttachStderr": True,
            "Tty": True,
        }
        if working_dir:
            config["WorkingDir"] = working_dir
        if env:
            config["Env"] = [f"{k}={v}" for k, v in env.items()]

        client = await self._get_client()
        if self._use_aiodocker:
            container = client.containers.container(container_id)
            exec_obj = await container.exec(config)
            return exec_obj.id if hasattr(exec_obj, "id") else exec_obj["Id"]
        else:
            def _sync() -> str:
                return client.containers.get(container_id).client.api.exec_create(
                    container_id, **config
                )["Id"]

            return await asyncio.to_thread(_sync)

    # ─── 6) Exec attach ───────────────────────────────────────────────────

    async def container_exec_attach(self, exec_id: str, tty: bool = True) -> str:
        """Start + attach to an exec instance; return the captured output as text."""
        client = await self._get_client()
        if self._use_aiodocker:
            exec_obj = client.containers.exec(exec_id)
            stream = await exec_obj.start(tty=tty, stream=False, demux=False)
            if isinstance(stream, bytes):
                return stream.decode("utf-8", errors="replace")
            if isinstance(stream, str):
                return stream
            # Some aiodocker versions return an async iterator
            chunks: list[bytes] = []
            try:
                async for chunk in stream:  # type: ignore[union-attr]
                    if isinstance(chunk, tuple):
                        chunks.append(b"".join(chunk))
                    else:
                        chunks.append(chunk)  # type: ignore[arg-type]
            except Exception as exc:  # noqa: BLE001
                logger.debug("exec stream ended: %s", exc)
            return b"".join(chunks).decode("utf-8", errors="replace")
        else:
            def _sync() -> str:
                api = client.api
                sock = api.exec_start(exec_id, tty=tty, stream=False, demux=False)
                if isinstance(sock, (bytes, bytearray)):
                    return sock.decode("utf-8", errors="replace")
                # Generator/iterator case
                chunks = []
                for chunk in sock:
                    if isinstance(chunk, tuple):
                        chunks.append(b"".join(chunk))
                    else:
                        chunks.append(chunk)
                return b"".join(chunks).decode("utf-8", errors="replace")

            return await asyncio.to_thread(_sync)

    # ─── 7) Exec inspect ──────────────────────────────────────────────────

    async def container_exec_inspect(self, exec_id: str) -> dict:
        """Inspect an exec instance; returns the raw Docker inspect dict."""
        client = await self._get_client()
        if self._use_aiodocker:
            exec_obj = client.containers.exec(exec_id)
            return await exec_obj.inspect()
        else:
            return await asyncio.to_thread(client.api.exec_inspect, exec_id)

    # ─── 8) Stat path ─────────────────────────────────────────────────────

    async def container_stat_path(self, container_id: str, path: str) -> dict:
        """Stat a path inside the container. Returns the ``PathStat`` dict
        (Docker places a JSON header named ``X-Docker-Container-Path-Stat``)."""
        client = await self._get_client()
        if self._use_aiodocker:
            container = client.containers.container(container_id)
            stream = await container.get_archive(path)
            # aiodocker returns a (stream, stat) tuple.
            stat: dict = {}
            if isinstance(stream, tuple) and len(stream) >= 2:
                stat = stream[1] or {}
            elif isinstance(stream, dict):
                stat = stream.get("stat", {})
            return stat
        else:
            def _sync() -> dict:
                _stream, stat = client.containers.get(container_id).get_archive(path)
                if hasattr(stat, "get"):
                    return dict(stat)
                return stat if isinstance(stat, dict) else {}

            return await asyncio.to_thread(_sync)

    # ─── 9) List container dir ────────────────────────────────────────────

    async def list_container_dir(self, container_id: str, path: str) -> list[str]:
        """Return the list of entry names in ``path`` inside the container.

        Ports PentAGI ``ListContainerDir`` but returns a flat list of names
        instead of full ``PathStat`` dicts (sufficient for tool execution).
        """
        if not path or not path.strip():
            path = WORK_FOLDER_PATH_IN_CONTAINER

        # Verify it is a directory
        stat = await self.container_stat_path(container_id, path)
        mode = stat.get("mode", 0) if isinstance(stat, dict) else 0
        if mode and not (mode & 0o040000):  # S_IFDIR
            raise RuntimeError(f"container path '{path}' is not a directory")

        exec_id = await self.container_exec_create(
            container_id,
            cmd=["ls", "-1", "--", path],
        )
        output = await self.container_exec_attach(exec_id, tty=True)
        inspect = await self.container_exec_inspect(exec_id)
        exit_code = inspect.get("ExitCode", -1) if isinstance(inspect, dict) else -1
        if exit_code != 0:
            raise RuntimeError(
                f"ls command failed for '{path}' with exit code {exit_code}: {output}"
            )

        names: list[str] = []
        for line in output.split("\n"):
            name = line.strip()
            if name:
                names.append(name)
        return names

    # ─── 10) Copy to container ────────────────────────────────────────────

    async def copy_to_container(
        self,
        container_id: str,
        path: str,
        data: bytes,
    ) -> None:
        """Copy ``data`` (file contents) into ``path`` inside the container.

        ``path`` is interpreted as the *destination directory*; the file name
        is derived from the basename of ``path`` if it has no slashes, otherwise
        ``data`` is written to ``path`` itself with basename ``path``.

        Ports PentAGI ``CopyToContainer`` semantics. We always pack the data as
        a single-entry TAR (mode 0600) and stream it to the Docker API.
        """
        if len(data) > MAX_FILE_SIZE_BYTES:
            raise RuntimeError(
                f"file too large: {len(data)} bytes (max {MAX_FILE_SIZE_BYTES})"
            )

        # Determine destination directory and filename.
        # Docker's put_archive API takes a directory path and the TAR entries
        # are written relative to it. We use the parent of `path` and put the
        # file at basename(path) inside the TAR.
        if path.endswith("/"):
            dst_dir = path.rstrip("/") or "/"
            filename = "data"
        elif "/" in path:
            dst_dir = path.rsplit("/", 1)[0] or "/"
            filename = path.rsplit("/", 1)[1]
        else:
            dst_dir = WORK_FOLDER_PATH_IN_CONTAINER
            filename = path

        tar_buf = io.BytesIO()
        with tarfile.open(fileobj=tar_buf, mode="w") as tar:
            ti = tarfile.TarInfo(name=filename)
            ti.size = len(data)
            ti.mode = 0o600
            ti.mtime = int(time.time())
            tar.addfile(ti, io.BytesIO(data))
        tar_bytes = tar_buf.getvalue()

        client = await self._get_client()
        if self._use_aiodocker:
            container = client.containers.container(container_id)
            # aiodocker's put_archive expects raw bytes for the data stream.
            await container.put_archive(dst_dir, tar_bytes)
        else:
            def _sync() -> None:
                client.containers.get(container_id).put_archive(dst_dir, tar_bytes)

            await asyncio.to_thread(_sync)

    # ─── 11) Copy from container ──────────────────────────────────────────

    async def copy_from_container(self, container_id: str, path: str) -> bytes:
        """Copy a file (or single entry of a directory) out of the container.

        Returns the raw file contents as bytes. For directories, the first
        regular file entry is returned. Ports PentAGI ``CopyFromContainer``.
        """
        client = await self._get_client()
        if self._use_aiodocker:
            container = client.containers.container(container_id)
            stream = await container.get_archive(path)
            # aiodocker returns (stream, stat) — stream is a generator of bytes
            tar_bytes = b""
            stat = None
            if isinstance(stream, tuple) and len(stream) >= 2:
                stat = stream[1]
                stream = stream[0]
            if isinstance(stream, bytes):
                tar_bytes = stream
            else:
                async for chunk in stream:  # type: ignore[union-attr]
                    if isinstance(chunk, tuple):
                        tar_bytes += b"".join(chunk)
                    else:
                        tar_bytes += chunk  # type: ignore[arg-type]
        else:
            def _sync() -> bytes:
                stream, _stat = client.containers.get(container_id).get_archive(path)
                buf = b""
                for chunk in stream:
                    if isinstance(chunk, tuple):
                        buf += b"".join(chunk)
                    else:
                        buf += chunk
                return buf

            tar_bytes = await asyncio.to_thread(_sync)

        # Parse the TAR stream
        bio = io.BytesIO(tar_bytes)
        with tarfile.open(fileobj=bio, mode="r|*") as tar:
            for member in tar:
                if not member.isfile():
                    continue
                f = tar.extractfile(member)
                if f is None:
                    continue
                data = f.read()
                if len(data) > MAX_FILE_SIZE_BYTES:
                    raise RuntimeError(
                        f"file too large: {len(data)} bytes (max {MAX_FILE_SIZE_BYTES})"
                    )
                return data
        raise RuntimeError(f"no regular file found in container path '{path}'")

    # ─── 12) Cleanup ──────────────────────────────────────────────────────

    async def cleanup(self) -> None:
        """Concurrent orphan-container cleanup.

        Ports PentAGI's ``Cleanup`` method:
          * For each flow in status ``Finished/Failed/Created`` (or
            ``Running/Waiting`` with non-running containers), mark the flow
            ``Failed`` and remove all ``Starting/Running`` containers
            concurrently via ``asyncio.gather(return_exceptions=True)``.

        Flow status is read from the SQLite store via optional flow records in
        the same DB. If no flow records exist, this method gracefully no-ops
        on the flow-status side but still cleans orphan containers in
        ``Starting``/``Running`` state.
        """
        logger.info("cleaning up containers and marking orphan flows failed...")

        # Load all containers from the store.
        containers = self.store.list_all()
        if not containers:
            logger.info("cleanup finished — no containers tracked")
            return

        # Group containers by flow_id
        flow_containers: dict[int, list[ContainerInfo]] = {}
        for c in containers:
            flow_containers.setdefault(c.flow_id, []).append(c)

        # Optional: load flow statuses if a flows table exists
        flow_status: dict[int, _FlowStatus] = {}
        try:
            with sqlite3.connect(self.store.db_path) as conn:
                conn.row_factory = sqlite3.Row
                rows = conn.execute(
                    "SELECT id, status FROM flows"
                ).fetchall()
                for row in rows:
                    try:
                        flow_status[row["id"]] = _FlowStatus(row["status"])
                    except ValueError:
                        continue
        except sqlite3.Error:
            # No flows table — treat all flows as needing cleanup
            pass

        def _is_all_containers_not_running(flow_id: int) -> bool:
            cs = flow_containers.get(flow_id, [])
            if not cs:
                return False
            for c in cs:
                if c.status in (ContainerStatus.STARTING, ContainerStatus.RUNNING):
                    return False
            return True

        tasks: list[asyncio.Task] = []

        async def _remove_one(container: ContainerInfo) -> None:
            logger.info("cleanup: removing container %s (flow_id=%s)",
                        container.local_id, container.flow_id)
            try:
                await self.remove_container(container.local_id, force=True, remove_volumes=True)
            except Exception as exc:  # noqa: BLE001
                logger.error("failed to remove container %s: %s", container.local_id, exc)
            try:
                if container.id is not None:
                    self.store.update_status(container.id, ContainerStatus.DELETED)
            except Exception as exc:  # noqa: BLE001
                logger.error("failed to update container status: %s", exc)

        for flow_id, cs in flow_containers.items():
            status = flow_status.get(flow_id)
            needs_cleanup = False

            if status in (_FlowStatus.RUNNING, _FlowStatus.WAITING):
                if _is_all_containers_not_running(flow_id):
                    needs_cleanup = True
                # else: healthy running flow — skip
            elif status == _FlowStatus.CREATED:
                needs_cleanup = True
            elif status in (_FlowStatus.FINISHED, _FlowStatus.FAILED):
                needs_cleanup = True
            elif status is None:
                # Unknown flow status — be conservative and cleanup active containers.
                needs_cleanup = any(
                    c.status in (ContainerStatus.STARTING, ContainerStatus.RUNNING) for c in cs
                )

            if not needs_cleanup:
                continue

            # Mark flow failed (best effort)
            if status is not None:
                try:
                    with sqlite3.connect(self.store.db_path) as conn:
                        conn.execute(
                            "UPDATE flows SET status=? WHERE id=?",
                            (_FlowStatus.FAILED.value, flow_id),
                        )
                        conn.commit()
                except sqlite3.Error as exc:
                    logger.error("failed to mark flow %s as failed: %s", flow_id, exc)

            for c in cs:
                if c.status in (ContainerStatus.STARTING, ContainerStatus.RUNNING):
                    tasks.append(asyncio.create_task(_remove_one(c)))

        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

        logger.info("cleanup finished")

    # ─── 13) Get default image ────────────────────────────────────────────

    # (already defined above as async get_default_image)

    # ─── 14) Prepare (high-level) ─────────────────────────────────────────

    async def prepare(
        self,
        flow_id: int,
        image: str,
        uploads: Optional[dict[str, bytes]] = None,
    ) -> str:
        """High-level Prepare flow (ports ``flowToolsExecutor.Prepare``).

        1. If a PRIMARY container exists for ``flow_id`` and is RUNNING,
           reuse it and sync any missing uploads.
        2. Otherwise, remove any stale container record and create a fresh
           one with image + capabilities + entrypoint ``tail -f /dev/null``.
        3. Copy any ``uploads`` into ``/work``.

        Returns the Docker container ID (``local_id``).
        """
        image = (image or self.def_image).lower()

        existing = self.store.get_primary_for_flow(flow_id)
        if existing and existing.status == ContainerStatus.RUNNING and existing.local_id:
            try:
                if await self.is_container_running(existing.local_id):
                    logger.info(
                        "prepare: reusing running container %s for flow %s",
                        existing.local_id,
                        flow_id,
                    )
                    if uploads:
                        await self._sync_uploads(existing.local_id, uploads)
                    return existing.local_id
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "prepare: existing container unusable (%s); recreating", exc
                )

        # Remove stale container record + actual container if any
        if existing and existing.local_id:
            try:
                await self.remove_container(existing.local_id, force=True, remove_volumes=True)
            except Exception as exc:  # noqa: BLE001
                logger.debug("prepare: stale container cleanup failed: %s", exc)

        info = await self.run_container(
            flow_id=flow_id,
            image=image,
        )
        if not info.local_id:
            raise RuntimeError(f"prepare: container created but no local_id for flow {flow_id}")

        if uploads:
            await self._sync_uploads(info.local_id, uploads)

        return info.local_id

    async def _sync_uploads(self, container_id: str, uploads: dict[str, bytes]) -> None:
        """Copy each (filename → bytes) into the container's ``/work`` dir."""
        for filename, data in uploads.items():
            try:
                await self.copy_to_container(container_id, f"/work/{filename}", data)
            except Exception as exc:  # noqa: BLE001
                logger.warning("failed to sync upload '%s': %s", filename, exc)

    # ─── 15) Release (high-level) ─────────────────────────────────────────

    async def release(self, flow_id: int) -> None:
        """High-level release: stop + remove the primary container for ``flow_id``.

        Ports PentAGI ``Release``: ``RemoveContainer(primaryLID, primaryID)``
        with ``force=True`` and ``remove_volumes=True``.
        """
        primary = self.store.get_primary_for_flow(flow_id)
        if not primary:
            logger.info("release: no primary container for flow %s", flow_id)
            return
        if primary.local_id:
            try:
                await self.remove_container(
                    primary.local_id, force=True, remove_volumes=True
                )
            except Exception as exc:  # noqa: BLE001
                logger.error(
                    "release: failed to remove container %s: %s",
                    primary.local_id,
                    exc,
                )
        else:
            # No Docker container ever created — just mark DB row DELETED.
            if primary.id is not None:
                self.store.update_status(primary.id, ContainerStatus.DELETED)

    # ─── Context manager helpers ──────────────────────────────────────────

    async def __aenter__(self) -> "DockerSandbox":
        await self._get_client()
        return self

    async def __aexit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        await self.close()
