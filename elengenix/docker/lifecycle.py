"""elengenix/docker/lifecycle.py — high-level container lifecycle: prepare → run → release.

This module ports PentAGI's ``flowToolsExecutor.Prepare`` / ``Release``
helpers (defined in ``backend/pkg/tools/tools.go``) to Python. The
high-level contract is:

* ``prepare(flow_id, image, uploads=None) -> ContainerInfo`` — get a
  running container for the flow, reusing an existing one if it's
  healthy, else recreating from scratch. Idempotent: safe to call
  repeatedly with the same arguments.
* ``release(flow_id) -> None`` — stop + force-remove the flow's
  container (with ``RemoveVolumes=True``), then mark the DB row
  ``deleted``.
* ``get_or_create(flow_id, image) -> ContainerInfo`` — the lower-level
  helper that ``prepare`` builds on. Does NOT do file sync.
* ``health_check(container_id) -> dict`` — return
  ``{running, status, started_at, restart_count}`` for a Docker
  container. Used by the orchestrator to decide whether to reuse or
  recreate.

Key PentAGI behaviors preserved verbatim:

* **Container-name pattern**: ``pentagi-terminal-{flow_id}`` (constant
  ``PrimaryTerminalNamePrefix``). We keep the PentAGI prefix so the
  existing ``containerPrimaryTypePattern = "-terminal-"`` filter in
  ``Cleanup()`` works unchanged. The DB row's ``name`` column carries
  this string.
* **Reuse logic**: check DB for an active (``running``) container row
  for ``flow_id``. If found AND the Docker daemon confirms it's
  actually running (``IsContainerRunning``), reuse it. Otherwise remove
  the stale row/container and recreate.
* **Image fallback chain**: requested image → ``debian:latest``
  (matches PentAGI's ``defaultImage``). Both pull failure and create
  failure trigger the fallback.
* **Entrypoint**: ``["tail", "-f", "/dev/null"]`` — keeps the container
  alive indefinitely; the terminal tool runs commands via ``exec``.
* **RestartPolicy**: ``on-failure(5)`` — prevents the container from
  auto-restarting after a host reboot (which would create a
  ``docker.sock`` directory for DinD).
* **LogConfig**: ``json-file`` with ``max-size:10m, max-file:5`` — caps
  log disk usage at 50 MB per container.
* **syncMissingFiles**: walk local
  ``{data_dir}/flow-{id}-data/{uploads,resources}``, run ONE shell exec
  inside the container to find which files are missing, then send ALL
  missing files as a SINGLE tar stream via ``CopyToContainer``. Highly
  optimized — typically one exec + one copy per prepare.

Elengenix additions (NOT in PentAGI):

* ``ResourceLimits`` enforcement — cgroup limits, ulimits, read-only
  rootfs, network mode. Applied via
  ``resource_limits.apply_to_container_config``.
* Optional per-flow isolated network via ``DockerNetwork`` — used when
  ``--network-internal`` or ``--network-host`` flags are set.
"""

from __future__ import annotations

import asyncio
import io
import logging
import os
import shlex
import tarfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from .db import ContainerDB, ContainerInfo, ContainerStatus, ContainerType
from .resource_limits import ResourceLimits, apply_to_container_config, validate_limits

logger = logging.getLogger("elengenix.docker.lifecycle")

# ---------------------------------------------------------------------------
# Constants — ported verbatim from PentAGI's ``docker/client.go`` and
# ``tools/terminal.go``.
# ---------------------------------------------------------------------------

#: In-container working directory. All file syncs land here. Bind mount
#: target for the per-flow data directory.
WORK_FOLDER_PATH_IN_CONTAINER: str = "/work"

#: PentAGI-compatible primary container name prefix. The full name is
#: ``pentagi-terminal-{flow_id}``. We keep the PentAGI prefix so the
#: cleanup layer's ``-terminal-`` substring filter keeps working.
PRIMARY_TERMINAL_NAME_PREFIX: str = "pentagi-terminal-"

#: Default image used as the fallback when the requested image fails to
#: pull or create. Matches PentAGI's ``defaultImage`` constant.
DEFAULT_IMAGE: str = "debian:latest"

#: Default entrypoint — keeps the container alive indefinitely. The
#: terminal tool runs commands via ``docker exec``.
DEFAULT_ENTRYPOINT: list[str] = ["tail", "-f", "/dev/null"]

#: Default working directory inside the container. PentAGI sets this via
#: ``config.WorkingDir = WorkFolderPathInContainer`` in ``RunContainer``.
DEFAULT_WORKING_DIR: str = WORK_FOLDER_PATH_IN_CONTAINER

#: Subdirectories under ``{data_dir}/flow-{flow_id}-data/`` that are
#: scanned by ``sync_missing_files``. Mirrors PentAGI's
#: ``flowfiles.UploadsDirName`` / ``ResourcesDirName``.
UPLOADS_DIR_NAME: str = "uploads"
RESOURCES_DIR_NAME: str = "resources"

#: Per-flow data directory template. The local on-disk path is
#: ``{data_dir}/flow-{flow_id}-data/`` (the ``-data`` suffix matches
#: PentAGI's ``flow-{flowID}-data`` convention).
FLOW_DATA_DIR_TEMPLATE: str = "flow-{flow_id}-data"


# ---------------------------------------------------------------------------
# Public dataclass for health-check results
# ---------------------------------------------------------------------------


@dataclass
class HealthStatus:
    """Result of ``ContainerLifecycle.health_check``.

    Fields mirror the subset of Docker's ``ContainerInspect`` State
    object that the orchestrator needs to decide reuse-vs-recreate.
    """

    running: bool
    status: str = "unknown"            # e.g. "running", "exited", "paused"
    started_at: Optional[str] = None   # ISO-8601 timestamp from Docker
    restart_count: int = 0
    healthy: Optional[bool] = None     # None = no healthcheck defined
    error: Optional[str] = None        # populated only if the inspect failed

    def to_dict(self) -> dict[str, Any]:
        return {
            "running": self.running,
            "status": self.status,
            "started_at": self.started_at,
            "restart_count": self.restart_count,
            "healthy": self.healthy,
            "error": self.error,
        }


# ---------------------------------------------------------------------------
# File-sync entry — internal dataclass used by ``_sync_missing_files``.
# ---------------------------------------------------------------------------


@dataclass
class _FileSyncEntry:
    """One file to potentially sync from host to container.

    ``host_path`` is the absolute path on the host filesystem.
    ``container_path`` is the absolute path INSIDE the container
    (always under ``/work/{uploads,resources}/...``).
    """

    host_path: Path
    container_path: str
    rel_path: str  # path relative to {flow_data_dir}, used as tar entry name


# ---------------------------------------------------------------------------
# Main class
# ---------------------------------------------------------------------------


class ContainerLifecycle:
    """High-level prepare/run/release lifecycle for flow sandboxes.

    The class is the Python equivalent of PentAGI's
    ``flowToolsExecutor`` (the subset of its API that deals with
    container bring-up/teardown — NOT the tool-execution methods, which
    live in a separate module).

    Args:
        db: ``ContainerDB`` instance — the single source of truth for
            container state. Required.
        data_dir: Root directory for per-flow data folders. Each flow
            gets a ``flow-{id}-data/`` subdir with ``uploads/`` and
            ``resources/`` children. Mirrors PentAGI's ``dataDir``.
        default_image: Fallback image when the requested image fails.
            Defaults to ``debian:latest`` (matches PentAGI).
        docker_url: Optional aiodocker connection URL. If None, uses
            ``DOCKER_HOST`` env var (or the default unix socket).
        network: Optional ``DockerNetwork`` instance for per-flow
            isolated networks. If None, the lifecycle uses the
            container's default network (set via ``ResourceLimits``).
        inside: If True, bind-mount the host's Docker socket into the
            container (for DinD scenarios). Mirrors PentAGI's
            ``cfg.DockerInside``. Default False.
        docker_socket: Host path to the Docker socket. Used when
            ``inside=True``. Defaults to ``/var/run/docker.sock``.
    """

    def __init__(
        self,
        db: ContainerDB,
        data_dir: str | Path,
        default_image: str = DEFAULT_IMAGE,
        docker_url: Optional[str] = None,
        network: Optional[Any] = None,
        inside: bool = False,
        docker_socket: str = "/var/run/docker.sock",
    ) -> None:
        self.db = db
        self.data_dir = Path(data_dir).expanduser().resolve()
        self.default_image = default_image.lower() or DEFAULT_IMAGE
        self.docker_url = docker_url
        self.network = network
        self.inside = bool(inside)
        self.docker_socket = docker_socket
        self._client = None  # type: ignore[assignment]

    # ------------------------------------------------------------------
    # Lazy aiodocker client
    # ------------------------------------------------------------------

    async def _client(self):
        if self._client is not None:
            return self._client
        import aiodocker

        kwargs: dict[str, Any] = {}
        if self.docker_url:
            kwargs["url"] = self.docker_url
        self._client = aiodocker.Docker(**kwargs)
        return self._client

    async def close(self) -> None:
        if self._client is not None:
            await self._client.close()
            self._client = None

    # ------------------------------------------------------------------
    # Naming helpers (static, ported from PentAGI's ``PrimaryTerminalName``)
    # ------------------------------------------------------------------

    @staticmethod
    def container_name(flow_id: int) -> str:
        """Return the canonical container name for ``flow_id``.

        Format: ``pentagi-terminal-{flow_id}``. The prefix is kept
        PentAGI-compatible so the cleanup layer's
        ``containerPrimaryTypePattern = "-terminal-"`` filter keeps
        working unchanged.
        """
        return f"{PRIMARY_TERMINAL_NAME_PREFIX}{int(flow_id)}"

    @staticmethod
    def flow_data_dir(data_dir: Path, flow_id: int) -> Path:
        """Return ``{data_dir}/flow-{flow_id}-data/`` (does NOT create it)."""
        return data_dir / FLOW_DATA_DIR_TEMPLATE.format(flow_id=int(flow_id))

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def prepare(
        self,
        flow_id: int,
        image: str,
        uploads: Optional[dict[str, bytes]] = None,
        resources: Optional[dict[str, bytes]] = None,
        limits: Optional[ResourceLimits] = None,
    ) -> ContainerInfo:
        """Get a running container for ``flow_id``, creating or reusing as needed.

        Algorithm (ported from PentAGI's ``flowToolsExecutor.Prepare``):

        1. Look up the flow's primary container in the DB.
           - If status == ``running`` AND Docker confirms it's actually
             running -> reuse it and call ``_sync_missing_files``.
           - Otherwise -> remove the stale container/row and recreate.
        2. Apply ``ResourceLimits`` (default = ``ResourceLimits.default()``)
           to the container config. Validate first.
        3. Create the container with the requested image, falling back
           to ``self.default_image`` on pull/create failure.
        4. Sync missing files from the host's ``flow-{id}-data/`` folder
           to the container's ``/work`` directory.

        Args:
            flow_id: Flow ID.
            image: Docker image (e.g. ``"debian:latest"``,
                ``"vxcontrol/kali-linux"``).
            uploads: Optional dict mapping filename -> bytes for files
                to ensure exist in ``/work/uploads/``. These are written
                to the host data dir before the sync step.
            resources: Optional dict mapping filename -> bytes for
                ``/work/resources/``.
            limits: Optional ``ResourceLimits``. If None, uses
                ``ResourceLimits.default()``.

        Returns:
            The (possibly newly created) ``ContainerInfo`` row.
        """
        limits = limits or ResourceLimits.default()
        errors = validate_limits(limits)
        if errors:
            raise ValueError(
                f"invalid ResourceLimits for flow {flow_id}: "
                + "; ".join(errors)
            )

        # 1. Materialize the upload/resource bytes on disk so the sync
        #    step can find them. This is idempotent.
        if uploads or resources:
            await asyncio.to_thread(self._write_uploads, flow_id, uploads, resources)

        # 2. Try reuse.
        existing = await self.db.get_container_by_flow(flow_id)
        if existing is not None and existing.status == ContainerStatus.RUNNING:
            actually_running = await self._is_container_running(existing.local_id)
            if actually_running:
                logger.info(
                    "reusing running container %s (id=%d, local_id=%s) for flow %d",
                    existing.name,
                    existing.id,
                    existing.local_id,
                    flow_id,
                )
                await asyncio.to_thread(self._sync_missing_files, flow_id, existing.local_id)
                return existing
            # Stale row — purge before recreating.
            logger.info(
                "container %s marked running in DB but not actually running; recreating",
                existing.name,
            )
            await self._remove_container_silent(existing)

        # 3. Create new container.
        info = await self.get_or_create(flow_id, image=image, limits=limits)

        # 4. Sync files.
        await asyncio.to_thread(self._sync_missing_files, flow_id, info.local_id)
        return info

    async def get_or_create(
        self,
        flow_id: int,
        image: Optional[str] = None,
        limits: Optional[ResourceLimits] = None,
    ) -> ContainerInfo:
        """Lower-level create-or-reuse helper. Does NOT do file sync.

        Used by ``prepare`` and by callers that want to skip the sync
        step (e.g. when bootstrapping a brand-new flow with no files).
        """
        img = (image or self.default_image).lower()
        limits = limits or ResourceLimits.default()

        # Insert DB row with status=starting + a placeholder local_id.
        # This matches PentAGI's pattern of inserting the row BEFORE
        # ContainerCreate so we can track "starting" state even if the
        # daemon is unreachable.
        container_name = self.container_name(flow_id)
        flow_dir = self.flow_data_dir(self.data_dir, flow_id)
        await asyncio.to_thread(flow_dir.mkdir, parents=True, exist_ok=True)

        info = ContainerInfo(
            type=ContainerType.PRIMARY,
            name=container_name,
            image=img,
            status=ContainerStatus.STARTING,
            local_id=f"tmp-id-{flow_id}",
            local_dir=str(flow_dir),
            flow_id=int(flow_id),
        )
        info.id = await self.db.create_container(info)

        try:
            local_id = await self._create_and_start_container(
                flow_id, container_name, img, limits
            )
        except Exception as e:
            logger.warning(
                "failed to create container with image %s: %s; falling back to %s",
                img,
                e,
                self.default_image,
            )
            if img == self.default_image:
                await self.db.update_container_status(info.id, ContainerStatus.FAILED)
                raise
            # Update the DB row's image to the fallback, then retry.
            await self.db.update_container_image(info.id, self.default_image)
            await self._pull_image(self.default_image)
            # Remove any half-created container with the same name.
            await self._remove_docker_container_by_name(container_name)
            try:
                local_id = await self._create_and_start_container(
                    flow_id, container_name, self.default_image, limits
                )
                info.image = self.default_image
            except Exception as e2:
                await self.db.update_container_status(info.id, ContainerStatus.FAILED)
                raise RuntimeError(
                    f"failed to create container {container_name} even with "
                    f"default image {self.default_image}: {e2}"
                ) from e2

        await self.db.update_container_local_id(info.id, local_id, ContainerStatus.RUNNING)
        info.local_id = local_id
        info.status = ContainerStatus.RUNNING
        logger.info(
            "container %s (id=%d, local_id=%s) running for flow %d",
            info.name,
            info.id,
            info.local_id,
            flow_id,
        )
        return info

    async def release(self, flow_id: int) -> None:
        """Stop + force-remove the flow's container (RemoveVolumes=True).

        Idempotent: safe to call when no container exists. After this
        returns, the DB row is marked ``deleted`` (NOT removed from the
        DB — history is preserved for diagnostics).
        """
        info = await self.db.get_container_by_flow(flow_id)
        if info is None:
            logger.debug("release: no container row for flow %d", flow_id)
            return
        await self._remove_container_silent(info)
        # Also tear down the per-flow network if we own one.
        if self.network is not None:
            try:
                await self.network.teardown_flow_network(flow_id)
            except Exception as e:
                logger.warning(
                    "failed to tear down flow %d network: %s", flow_id, e
                )

    async def health_check(self, container_id: int) -> dict[str, Any]:
        """Return ``{running, status, started_at, restart_count}`` for a
        container DB row.

        ``container_id`` is the DB primary key (NOT the Docker container
        ID). The method looks up the row to get the Docker ID, then
        inspects the live container.
        """
        info = await self.db.get_container(container_id)
        if info is None:
            return HealthStatus(
                running=False, status="unknown", error="no DB row for id"
            ).to_dict()

        client = await self._client()
        try:
            data = await client.containers.get(info.local_id)
            state = data.get("State", {}) or {}
            health = state.get("Health") or {}
            healthy: Optional[bool] = None
            if health:
                # Docker health statuses: "starting", "healthy", "unhealthy", "none"
                healthy = state["Health"].get("Status") == "healthy"
            return HealthStatus(
                running=bool(state.get("Running", False)),
                status=str(state.get("Status", "unknown")),
                started_at=state.get("StartedAt"),
                restart_count=int(state.get("RestartCount", 0)),
                healthy=healthy,
            ).to_dict()
        except Exception as e:
            return HealthStatus(
                running=False, status="error", error=str(e)
            ).to_dict()

    # ------------------------------------------------------------------
    # Internal: container creation / startup
    # ------------------------------------------------------------------

    async def _create_and_start_container(
        self,
        flow_id: int,
        container_name: str,
        image: str,
        limits: ResourceLimits,
    ) -> str:
        """Pull, create, and start the container. Returns Docker container ID."""
        client = await self._client()

        # Pull (idempotent — checks local cache first).
        await self._pull_image(image)

        # Build config dict.
        flow_dir = self.flow_data_dir(self.data_dir, flow_id)
        config: dict[str, Any] = {
            "Image": image,
            "Hostname": self._hostname(container_name),
            "WorkingDir": DEFAULT_WORKING_DIR,
            "Entrypoint": list(DEFAULT_ENTRYPOINT),
            "Tty": True,
            "OpenStdin": True,
            "AttachStdout": False,
            "AttachStderr": False,
            "HostConfig": {
                # Bind-mount the per-flow data dir as /work.
                "Binds": [f"{flow_dir}:{WORK_FOLDER_PATH_IN_CONTAINER}"],
                # Prevent auto-restart after host reboot (PentAGI quirk:
                # the docker.sock dir would otherwise be recreated for
                # DinD containers).
                "RestartPolicy": {"Name": "on-failure", "MaximumRetryCount": 5},
                # Log rotation: 5 x 10 MB = 50 MB max per container.
                "LogConfig": {
                    "Type": "json-file",
                    "Config": {"max-size": "10m", "max-file": "5"},
                },
            },
        }

        # Bind-mount the Docker socket for DinD if requested.
        if self.inside:
            config["HostConfig"]["Binds"].append(
                f"{self.docker_socket}:/var/run/docker.sock"
            )

        # Apply cgroup/ulimit/network limits.
        apply_to_container_config(config, limits)

        # Optional per-flow isolated network.
        if self.network is not None and limits.network_mode not in ("host", "none"):
            try:
                net_name = await self.network.create_isolated_network(
                    flow_id, internal=(limits.network_mode != "bridge")
                )
                # Attach via EndpointsConfig so the container joins on start.
                net_cfg = config.setdefault("NetworkingConfig", {})
                net_cfg["EndpointsConfig"] = {
                    net_name: {"Aliases": ["sandbox", "terminal"]}
                }
            except Exception as e:
                logger.warning(
                    "failed to create isolated network for flow %d: %s", flow_id, e
                )

        # Create.
        try:
            container = await client.containers.create_or_replace(
                name=container_name, config=config
            )
        except Exception as e:
            raise RuntimeError(f"ContainerCreate failed for {container_name}: {e}") from e

        docker_id = str(container.id)
        # Start.
        try:
            await container.start()
        except Exception as e:
            # Best-effort cleanup before re-raising.
            try:
                await container.delete(force=True)
            except Exception:
                pass
            raise RuntimeError(f"ContainerStart failed for {container_name}: {e}") from e

        return docker_id

    async def _pull_image(self, image: str) -> None:
        """Pull ``image`` if not already present locally. Mirrors PentAGI's
        ``pullImage`` — checks local cache via ``images.list(reference=...)``,
        falls back to ``images.pull`` + drain stream.
        """
        client = await self._client()
        # Check local cache.
        try:
            local_images = await client.images.list(filter=image)
            if local_images:
                logger.debug("image %s already present locally", image)
                return
        except Exception:
            pass  # be lenient — fall through to pull
        logger.info("pulling image %s", image)
        try:
            await client.images.pull(image)
        except Exception as e:
            raise RuntimeError(f"failed to pull image {image}: {e}") from e

    # ------------------------------------------------------------------
    # Internal: file sync (ported from PentAGI's syncMissingFiles)
    # ------------------------------------------------------------------

    def _write_uploads(
        self,
        flow_id: int,
        uploads: Optional[dict[str, bytes]],
        resources: Optional[dict[str, bytes]],
    ) -> None:
        """Write the supplied ``uploads`` / ``resources`` dicts to the
        host's ``flow-{id}-data/{uploads,resources}/`` directories.

        Existing files are overwritten. Missing parent dirs are created.
        Called from ``prepare`` BEFORE the sync step so the new files
        are picked up.
        """
        flow_dir = self.flow_data_dir(self.data_dir, flow_id)
        for sub, payload in ((UPLOADS_DIR_NAME, uploads), (RESOURCES_DIR_NAME, resources)):
            if not payload:
                continue
            sub_dir = flow_dir / sub
            sub_dir.mkdir(parents=True, exist_ok=True)
            for name, data in payload.items():
                # Sanitize: no path traversal.
                safe_name = Path(name).name
                if not safe_name or safe_name.startswith(".."):
                    logger.warning("skipping unsafe upload name: %r", name)
                    continue
                target = sub_dir / safe_name
                target.write_bytes(data)
                logger.debug("wrote %d bytes to %s", len(data), target)

    def _collect_sync_entries(self, flow_id: int) -> list[_FileSyncEntry]:
        """Walk ``{flow_data_dir}/{uploads,resources}/`` and build a list
        of files to consider for syncing. Mirrors PentAGI's
        ``collectSyncEntries``.
        """
        flow_dir = self.flow_data_dir(self.data_dir, flow_id)
        entries: list[_FileSyncEntry] = []
        for sub in (UPLOADS_DIR_NAME, RESOURCES_DIR_NAME):
            sub_dir = flow_dir / sub
            if not sub_dir.exists():
                continue
            for root, _dirs, files in os.walk(sub_dir):
                for fname in files:
                    host_path = Path(root) / fname
                    rel = host_path.relative_to(flow_dir)
                    # In-container path: /work/<uploads|resources>/...
                    container_path = f"{WORK_FOLDER_PATH_IN_CONTAINER}/{rel.as_posix()}"
                    entries.append(
                        _FileSyncEntry(
                            host_path=host_path,
                            container_path=container_path,
                            rel_path=rel.as_posix(),
                        )
                    )
        return entries

    def _sync_missing_files(self, flow_id: int, local_id: str) -> None:
        """One-shot diff-and-copy. Syncs only the files that are missing
        in the container, using a SINGLE exec + SINGLE tar stream.

        This is a SYNCHRONOUS method that performs blocking I/O (tar
        build, docker exec via ``aiodocker`` is async-only — so the
        async parts are scheduled via ``asyncio.run_coroutine_threadsafe``
        against the running loop). Callers should invoke it via
        ``asyncio.to_thread``.
        """
        entries = self._collect_sync_entries(flow_id)
        if not entries:
            return

        loop = asyncio.get_event_loop()
        # Step 1: find which files are missing inside the container.
        missing = asyncio.run_coroutine_threadsafe(
            self._find_missing_in_container(local_id, entries), loop
        ).result()
        if not missing:
            logger.debug("all %d files already present in container %s", len(entries), local_id)
            return

        # Step 2: build a single tar stream containing all missing files.
        tar_bytes = self._build_tar(missing)
        logger.info(
            "syncing %d/%d missing files (%d bytes) to container %s",
            len(missing),
            len(entries),
            len(tar_bytes),
            local_id,
        )
        asyncio.run_coroutine_threadsafe(
            self._copy_tar_to_container(local_id, tar_bytes), loop
        ).result()

    async def _find_missing_in_container(
        self, local_id: str, entries: list[_FileSyncEntry]
    ) -> list[_FileSyncEntry]:
        """Run ONE shell exec inside the container to find which files
        are missing. Mirrors PentAGI's ``findMissingInContainer``.

        The shell command is::

            sh -c 'for f in "$@"; do [ -f "$f" ] || printf "%s\\n" "$f"; done' -- /path1 /path2 ...

        Each missing path is printed on its own line; we then intersect
        with the input entries to build the final missing list.
        """
        client = await self._client()
        # Build the command. We pass container paths as positional args
        # to avoid shell-injection (the paths come from local filenames
        # but defense-in-depth is cheap).
        paths = [e.container_path for e in entries]
        cmd = [
            "sh",
            "-c",
            "for f in \"$@\"; do [ -f \"$f\" ] || printf '%s\\n' \"$f\"; done",
            "--",
            *paths,
        ]
        exec_obj = await client.containers.exec(
            local_id, cmd=cmd, stdout=True, stderr=True, tty=False
        )
        # Stream the output.
        stream = exec_obj.start()
        output = b""
        async for chunk in stream:
            if isinstance(chunk, bytes):
                output += chunk
            else:
                output += chunk.encode("utf-8", errors="replace")
        # Inspect for exit code.
        inspect = await exec_obj.inspect()
        exit_code = int(inspect.get("ExitCode", 0) or 0)
        if exit_code != 0:
            logger.warning(
                "file-check exec exited %d; assuming all files missing. Output: %s",
                exit_code,
                output[:512],
            )
            return list(entries)
        # Parse output lines.
        missing_paths = set()
        for line in output.decode("utf-8", errors="replace").splitlines():
            line = line.strip()
            if line:
                missing_paths.add(line)
        return [e for e in entries if e.container_path in missing_paths]

    def _build_tar(self, entries: list[_FileSyncEntry]) -> bytes:
        """Build an in-memory tar archive containing all ``entries``.

        The tar uses POSIX format (``tarfile.PAX_FORMAT``) for full
        Unicode filename support. File mode is 0600 (matches PentAGI).
        Paths inside the tar are RELATIVE to ``/work`` so the
        ``CopyToContainer`` destination of ``/work`` reconstructs them
        correctly.
        """
        buf = io.BytesIO()
        # PAX_FORMAT is the safest for long filenames and Unicode.
        with tarfile.open(fileobj=buf, mode="w", format=tarfile.PAX_FORMAT) as tar:
            for entry in entries:
                data = entry.host_path.read_bytes()
                # The tar entry name must be relative to /work (the
                # CopyToContainer dst_path). PentAGI uses the same trick.
                tarinfo = tarfile.TarInfo(name=entry.rel_path)
                tarinfo.size = len(data)
                tarinfo.mtime = int(entry.host_path.stat().st_mtime)
                tarinfo.mode = 0o600
                tarinfo.type = tarfile.REGTYPE
                tar.addfile(tarinfo, io.BytesIO(data))
        return buf.getvalue()

    async def _copy_tar_to_container(self, local_id: str, tar_bytes: bytes) -> None:
        """Send a tar stream to the container at ``/work``. Mirrors
        PentAGI's ``copyEntriesToContainer`` (which calls
        ``CopyToContainer`` with ``AllowOverwriteDirWithFile: true``).
        """
        client = await self._client()
        container = client.containers.container(local_id)
        # aiodocker's put_archive takes a path + bytes payload.
        await container.put_archive(WORK_FOLDER_PATH_IN_CONTAINER, tar_bytes)

    # ------------------------------------------------------------------
    # Internal: container removal + health
    # ------------------------------------------------------------------

    async def _is_container_running(self, local_id: str) -> bool:
        """Check via the Docker daemon whether ``local_id`` is actually
        running. Mirrors PentAGI's ``IsContainerRunning`` — also
        considers the health-check status (``unhealthy`` = not running).
        """
        if not local_id or local_id.startswith("tmp-id-"):
            return False
        client = await self._client()
        try:
            data = await client.containers.get(local_id)
        except Exception as e:
            logger.debug("container %s inspect failed: %s", local_id, e)
            return False
        state = data.get("State", {}) or {}
        running = bool(state.get("Running", False))
        health = state.get("Health") or {}
        if health and health.get("Status") == "unhealthy":
            return False
        return running

    async def _remove_container_silent(self, info: ContainerInfo) -> None:
        """Stop + force-remove a container, swallowing errors. Updates
        the DB row to ``deleted`` regardless of daemon errors."""
        client = await self._client()
        if info.local_id and not info.local_id.startswith("tmp-id-"):
            try:
                container = client.containers.container(info.local_id)
                # Stop with a short grace period (matches PentAGI's
                # default 10s + Docker's SIGTERM).
                try:
                    await container.stop(timeout=10)
                except Exception as e:
                    msg = str(e).lower()
                    if "not found" not in msg and "no such" not in msg:
                        logger.debug("stop container %s: %s", info.local_id, e)
                # Force-remove with volumes.
                try:
                    await container.delete(force=True, v=True)
                except Exception as e:
                    msg = str(e).lower()
                    if "not found" not in msg and "no such" not in msg:
                        logger.warning("remove container %s: %s", info.local_id, e)
            except Exception as e:
                logger.warning("failed to purge container %s: %s", info.local_id, e)
        try:
            await self.db.update_container_status(info.id, ContainerStatus.DELETED)
        except Exception as e:
            logger.warning("failed to mark container %d deleted: %s", info.id, e)

    async def _remove_docker_container_by_name(self, name: str) -> None:
        """Look up a container by name and force-remove it. Used during
        the image-fallback path to clean up a half-created container
        before retrying with the default image. Mirrors PentAGI's
        same-named inline logic in ``RunContainer``."""
        client = await self._client()
        try:
            containers = await client.containers.list(all=True, filters={"name": [name]})
        except Exception:
            return
        for c in containers:
            try:
                await c.delete(force=True, v=True)
            except Exception as e:
                logger.debug("failed to remove stale container %s: %s", name, e)

    # ------------------------------------------------------------------
    # Misc helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _hostname(container_name: str) -> str:
        """8-hex-char hostname derived from the container name (matches
        PentAGI's ``crc32.ChecksumIEEE``). We use Python's built-in
        ``zlib.crc32`` which is bit-identical to Go's implementation."""
        import zlib

        return f"{zlib.crc32(container_name.encode('utf-8')) & 0xFFFFFFFF:08x}"

    @staticmethod
    def _shlex_quote(s: str) -> str:
        """Wrapper around ``shlex.quote`` — exposed for testability and
        to make the import-explicit lint happy."""
        return shlex.quote(s)


__all__ = [
    "ContainerLifecycle",
    "HealthStatus",
    "PRIMARY_TERMINAL_NAME_PREFIX",
    "WORK_FOLDER_PATH_IN_CONTAINER",
    "DEFAULT_IMAGE",
    "DEFAULT_ENTRYPOINT",
    "UPLOADS_DIR_NAME",
    "RESOURCES_DIR_NAME",
    "FLOW_DATA_DIR_TEMPLATE",
]
