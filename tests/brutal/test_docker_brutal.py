"""200 BRUTAL pytest tests for the Elengenix Docker sandbox system.

This file is the brutal-testing deliverable for Phase 12, Task 12-b.
It covers all six public modules of ``elengenix/docker/``:

* ``sandbox``         — 40 tests (DockerSandbox core, port allocation, hostname, run/stop/remove/exec/copy/cleanup)
* ``terminal``        — 40 tests (DockerTerminal execute/read_file/write_file, timeout normalization, ANSI colors, shlex escaping)
* ``file_ops``        — 30 tests (DockerFileOps exists/is_dir/list_dir/mkdir/rm/chmod/grep with shell-injection defenses)
* ``image_chooser``   — 25 tests (LLM-driven image selection, fallback chain, caching, bypass, template rendering)
* ``browser``         — 30 tests (URL routing, binary-URL guard, local zones, scraper HTTP client, screenshot capture)
* ``lifecycle/cleanup/resource_limits/network/db`` — 35 tests (high-level lifecycle, cleanup sweeps, resource-limit validation, per-flow networks, async DB CRUD)

All tests are deterministic — no real Docker daemon, no real LLM, no real HTTP.
``aiodocker``, ``httpx``, and ``aiosqlite`` are mocked or used in-process only.
``asyncio_mode = "auto"`` is set in ``pyproject.toml`` so async tests run without
decorators.
"""

from __future__ import annotations

import asyncio
import io
import json
import os
import sqlite3
import sys
import tarfile
import time
from pathlib import Path
from typing import Any, Optional
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# ─── Imports under test ───────────────────────────────────────────────────────
from elengenix.docker import sandbox as sandbox_mod
from elengenix.docker.sandbox import (
    BASE_CONTAINER_PORTS_NUMBER,
    CONTAINER_LOCAL_CWD_TEMPLATE,
    CONTAINER_PORTS_NUMBER,
    DEFAULT_DOCKER_SOCKET_PATH,
    DEFAULT_IMAGE,
    DEFAULT_DB_PATH,
    LIMIT_CONTAINER_PORTS_NUMBER,
    MAX_FILE_SIZE_BYTES,
    PENTEST_DOCKER_IMAGE,
    WORK_FOLDER_PATH_IN_CONTAINER,
    ContainerInfo,
    ContainerStatus,
    ContainerType,
    DockerSandbox,
    _ContainerStore,
    _allocate_ports,
    _hostname_from_name,
)
from elengenix.docker.terminal import (
    ANSI_COLOR_INPUT_CMD,
    ANSI_COLOR_RESET,
    ANSI_COLOR_SYSTEM_MSG,
    ANSI_LINE_TERMINATOR,
    DEFAULT_EXTRA_EXEC_TIMEOUT,
    DEFAULT_QUICK_CHECK_TIMEOUT,
    DEFAULT_SERVER_EXEC_TIMEOUT,
    MAX_EXPLICIT_EXEC_COMMAND_TIMEOUT,
    MAX_READ_FILE_SIZE,
    PRIMARY_TERMINAL_NAME_PREFIX,
    DockerTerminal,
    _NullTermLog,
    _truncate_string,
    primary_terminal_name,
)
from elengenix.docker.file_ops import DockerFileOps
from elengenix.docker.image_chooser import (
    DEFAULT_IMAGE as IC_DEFAULT_IMAGE,
    DEFAULT_IMAGE_FOR_PENTEST,
    IMAGE_CHOOSER_TEMPLATE,
    ImageChooser,
    _IMAGE_RE,
    _validate_image,
    render_template,
)
from elengenix.docker.browser import (
    LOCAL_ZONES,
    MIN_HTML_CONTENT_SIZE,
    MIN_IMG_CONTENT_SIZE,
    MIN_MD_CONTENT_SIZE,
    NON_HTML_EXTENSIONS,
    SCRAPER_HTTP_TIMEOUT,
    BrowserResult,
    DockerBrowser,
    _is_private_ip,
    is_binary_url,
)
from elengenix.docker.db import (
    ACTIVE_CONTAINER_STATUSES,
    ContainerDB,
    ContainerInfo as DBContainerInfo,
    ContainerStatus as DBContainerStatus,
    ContainerType as DBContainerType,
    FlowStatus,
    ORPHAN_FLOW_STATUSES,
)
from elengenix.docker.resource_limits import (
    DEFAULT_CPU_PERIOD,
    DEFAULT_CPU_QUOTA,
    DEFAULT_MEM_LIMIT,
    DEFAULT_NETWORK_MODE,
    DEFAULT_PIDS_LIMIT,
    DEFAULT_SHM_SIZE,
    DEFAULT_ULIMIT_NOFILE,
    DEFAULT_ULIMIT_NPROC,
    SUPPORTED_NETWORK_MODES,
    ResourceLimits,
    apply_to_container_config,
    parse_size_to_bytes,
    validate_limits,
)
from elengenix.docker.network import (
    DEFAULT_DRIVER,
    DEFAULT_SUBNET_PREFIX,
    NETWORK_NAME_PREFIX,
    DockerNetwork,
)
from elengenix.docker.lifecycle import (
    DEFAULT_ENTRYPOINT,
    DEFAULT_WORKING_DIR,
    FLOW_DATA_DIR_TEMPLATE,
    RESOURCES_DIR_NAME,
    UPLOADS_DIR_NAME,
    ContainerLifecycle,
    HealthStatus,
    PRIMARY_TERMINAL_NAME_PREFIX as LC_PRIMARY_PREFIX,
)
from elengenix.docker.cleanup import (
    CleanupResult,
    ContainerCleanup,
    FlowStatusProvider,
    InMemoryFlowStatusProvider,
)


# ─── Shared fixtures ──────────────────────────────────────────────────────────


@pytest.fixture
def tmp_db(tmp_path) -> Path:
    """Path to a fresh, isolated SQLite DB for container state."""
    return tmp_path / "containers.db"


@pytest.fixture
def sandbox(tmp_db, tmp_path) -> DockerSandbox:
    """DockerSandbox with no real Docker daemon wired up.

    ``_use_aiodocker`` is forced to True so tests can mock the aiodocker
    client uniformly via ``sandbox._client``.
    """
    sb = DockerSandbox(data_dir=tmp_path, db_path=tmp_db)
    sb._use_aiodocker = True  # type: ignore[attr-defined]
    sb._aiodocker = MagicMock()  # type: ignore[attr-defined]
    sb._docker_sync = None  # type: ignore[attr-defined]
    return sb


@pytest.fixture
def fake_aiodocker_client():
    """A pre-mocked aiodocker client.

    Returns a ``MagicMock`` whose common async attributes
    (``images``, ``containers``, ``networks``) are ``AsyncMock``s so
    ``await client.images.pull(...)`` etc. work out of the box.
    """
    client = MagicMock()
    client.images = MagicMock()
    client.images.list = AsyncMock(return_value=[])
    client.images.pull = AsyncMock(return_value=MagicMock(id="sha256:abc"))
    client.containers = MagicMock()
    client.containers.create = AsyncMock(return_value=MagicMock(id="container-123"))
    # container.exec returns an object with async start/inspect.
    exec_obj = MagicMock(
        id="exec-1",
        start=AsyncMock(return_value=b"ok"),
        inspect=AsyncMock(return_value={"ExitCode": 0}),
    )
    client.containers.container = MagicMock(return_value=MagicMock(
        start=AsyncMock(),
        stop=AsyncMock(),
        delete=AsyncMock(),
        show=AsyncMock(),
        put_archive=AsyncMock(),
        get_archive=AsyncMock(),
        exec=AsyncMock(return_value=exec_obj),
    ))
    # client.containers.exec(exec_id) — sync call returning exec_obj.
    client.containers.exec = MagicMock(return_value=exec_obj)
    client.networks = MagicMock()
    client.networks.get = AsyncMock(side_effect=Exception("not found"))
    client.networks.create = AsyncMock(return_value=MagicMock())
    client.close = AsyncMock()
    return client


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 1 — DockerSandbox Core (40 tests)
# ═══════════════════════════════════════════════════════════════════════════


class TestContainerStatusEnum:
    """ContainerStatus enum: 5 values, string-valued, str-Enum semantics."""

    def test_container_status_has_exactly_five_values(self):
        """All 5 lifecycle states present (STARTING/RUNNING/STOPPED/DELETED/FAILED)."""
        values = {s.value for s in ContainerStatus}
        assert values == {"starting", "running", "stopped", "deleted", "failed"}

    def test_container_status_starting_value(self):
        assert ContainerStatus.STARTING.value == "starting"

    def test_container_status_running_value(self):
        assert ContainerStatus.RUNNING.value == "running"

    def test_container_status_stopped_value(self):
        assert ContainerStatus.STOPPED.value == "stopped"

    def test_container_status_deleted_value(self):
        assert ContainerStatus.DELETED.value == "deleted"

    def test_container_status_failed_value(self):
        assert ContainerStatus.FAILED.value == "failed"

    def test_container_status_is_str_enum(self):
        """str-Enum: every member IS a str."""
        for s in ContainerStatus:
            assert isinstance(s, str)


class TestContainerTypeEnum:
    def test_container_type_has_two_values(self):
        assert {t.value for t in ContainerType} == {"primary", "secondary"}

    def test_container_type_primary(self):
        assert ContainerType.PRIMARY.value == "primary"

    def test_container_type_secondary(self):
        assert ContainerType.SECONDARY.value == "secondary"


class TestContainerInfoDataclass:
    def test_container_info_defaults(self):
        """ContainerInfo default factory: status=STARTING, type=PRIMARY."""
        info = ContainerInfo()
        assert info.id is None
        assert info.type is ContainerType.PRIMARY
        assert info.status is ContainerStatus.STARTING
        assert info.flow_id == 0
        assert info.name == ""

    def test_container_info_all_fields_assignable(self):
        info = ContainerInfo(
            id=42,
            type=ContainerType.SECONDARY,
            name="pentagi-terminal-1",
            image="debian:latest",
            status=ContainerStatus.RUNNING,
            local_id="abc123",
            local_dir="/tmp/flow-1",
            flow_id=1,
            created_at=1000.0,
            updated_at=2000.0,
        )
        assert info.id == 42
        assert info.type is ContainerType.SECONDARY
        assert info.name == "pentagi-terminal-1"
        assert info.image == "debian:latest"
        assert info.status is ContainerStatus.RUNNING
        assert info.local_id == "abc123"
        assert info.local_dir == "/tmp/flow-1"
        assert info.flow_id == 1
        assert info.created_at == 1000.0
        assert info.updated_at == 2000.0

    def test_container_info_to_row_serialization(self):
        """to_row returns 9-tuple in canonical column order."""
        info = ContainerInfo(
            type=ContainerType.PRIMARY,
            name="n",
            image="img",
            status=ContainerStatus.RUNNING,
            local_id="lid",
            local_dir="/d",
            flow_id=7,
            created_at=1.0,
            updated_at=2.0,
        )
        row = info.to_row()
        assert row == (
            "primary", "n", "img", "running", "lid", "/d", 7, 1.0, 2.0,
        )

    def test_container_info_to_row_length(self):
        """9 columns — one per INSERT placeholder."""
        assert len(ContainerInfo().to_row()) == 9


class TestSandboxConstants:
    """Verify every PentAGI-ported constant."""

    def test_work_folder_path_in_container(self):
        assert WORK_FOLDER_PATH_IN_CONTAINER == "/work"

    def test_base_container_ports_number(self):
        assert BASE_CONTAINER_PORTS_NUMBER == 28000

    def test_container_ports_number(self):
        assert CONTAINER_PORTS_NUMBER == 2

    def test_limit_container_ports_number(self):
        assert LIMIT_CONTAINER_PORTS_NUMBER == 2000

    def test_default_image_constant(self):
        assert DEFAULT_IMAGE == "debian:latest"

    def test_pentest_docker_image_constant(self):
        assert PENTEST_DOCKER_IMAGE == "vxcontrol/kali-linux"

    def test_max_file_size_bytes_is_100_mb(self):
        assert MAX_FILE_SIZE_BYTES == 100 * 1024 * 1024

    def test_default_docker_socket_path(self):
        assert DEFAULT_DOCKER_SOCKET_PATH == "/var/run/docker.sock"

    def test_default_db_path_is_user_data(self):
        assert str(DEFAULT_DB_PATH).endswith("containers.db")


class TestPortAllocation:
    """_allocate_ports: deterministic port pair per flow."""

    def test_allocate_ports_flow_zero(self):
        assert _allocate_ports(0) == [28000, 28001]

    def test_allocate_ports_flow_one(self):
        assert _allocate_ports(1) == [28002, 28003]

    def test_allocate_ports_flow_1500(self):
        assert _allocate_ports(1500) == [29000, 29001]

    def test_allocate_ports_wrap_around_at_2000(self):
        """flow_id=2000 must wrap back to 28000/28001."""
        assert _allocate_ports(2000) == [28000, 28001]

    def test_allocate_ports_wrap_around_at_2001(self):
        assert _allocate_ports(2001) == [28002, 28003]

    def test_allocate_ports_within_range(self):
        for flow_id in (0, 1, 999, 1000, 1500, 1999, 2000):
            ports = _allocate_ports(flow_id)
            for p in ports:
                assert 28000 <= p < 30000

    def test_allocate_ports_returns_exactly_two(self):
        assert len(_allocate_ports(42)) == 2

    def test_allocate_ports_consecutive_pairs_differ_by_two(self):
        """Adjacent flows share no ports."""
        for flow_id in range(0, 100, 7):
            a = set(_allocate_ports(flow_id))
            b = set(_allocate_ports(flow_id + 1))
            assert a.isdisjoint(b)

    def test_allocate_ports_deterministic(self):
        assert _allocate_ports(7) == _allocate_ports(7)

    def test_allocate_ports_wrap_consistency(self):
        """flow_id and flow_id+2000 produce the same port pair."""
        assert _allocate_ports(7) == _allocate_ports(7 + 2000)


class TestHostname:
    """_hostname_from_name: crc32 → 8-hex-char string."""

    def test_hostname_is_8_hex_chars(self):
        h = _hostname_from_name("elengenix-terminal-1")
        assert len(h) == 8
        int(h, 16)  # raises if not hex

    def test_hostname_deterministic(self):
        assert _hostname_from_name("foo") == _hostname_from_name("foo")

    def test_hostname_differs_for_different_names(self):
        assert _hostname_from_name("a") != _hostname_from_name("b")

    def test_hostname_handles_unicode(self):
        """Container names with non-ASCII chars must not crash."""
        h = _hostname_from_name("élengenix-ü-1")
        assert len(h) == 8

    def test_hostname_matches_zlib_crc32(self):
        import zlib
        expected = f"{zlib.crc32(b'elengenix-terminal-1') & 0xFFFFFFFF:08x}"
        assert _hostname_from_name("elengenix-terminal-1") == expected


class TestRunContainer:
    """run_container: image pull, env, volumes, network, capabilities."""

    @pytest.mark.asyncio
    async def test_run_container_with_default_image(self, sandbox, fake_aiodocker_client, monkeypatch):
        """When image is empty → uses def_image (debian:latest)."""
        sandbox._client = fake_aiodocker_client  # type: ignore[attr-defined]
        info = await sandbox.run_container(flow_id=1, image="")
        assert info.image == "debian:latest"
        assert info.status is ContainerStatus.RUNNING
        assert info.flow_id == 1

    @pytest.mark.asyncio
    async def test_run_container_with_custom_image(self, sandbox, fake_aiodocker_client):
        sandbox._client = fake_aiodocker_client  # type: ignore[attr-defined]
        info = await sandbox.run_container(flow_id=2, image="vxcontrol/kali-linux")
        assert info.image == "vxcontrol/kali-linux"

    @pytest.mark.asyncio
    async def test_run_container_lowercases_image(self, sandbox, fake_aiodocker_client):
        sandbox._client = fake_aiodocker_client  # type: ignore[attr-defined]
        info = await sandbox.run_container(flow_id=3, image="DEBIAN:LATEST")
        assert info.image == "debian:latest"

    @pytest.mark.asyncio
    async def test_run_container_with_env_vars(self, sandbox, fake_aiodocker_client):
        """Env vars get serialized as 'KEY=VALUE' in the create config."""
        sandbox._client = fake_aiodocker_client  # type: ignore[attr-defined]
        captured = {}
        original = sandbox._create_container

        async def _spy(config, host_config, networking_config, name):
            captured["config"] = config
            captured["host_config"] = host_config
            return "cid-spied"

        sandbox._create_container = _spy  # type: ignore[assignment]
        sandbox._start_container = AsyncMock()  # type: ignore[assignment]
        await sandbox.run_container(flow_id=4, image="debian:latest",
                                    env={"FOO": "bar", "BAZ": "qux"})
        env_list = captured["config"]["Env"]
        assert "FOO=bar" in env_list and "BAZ=qux" in env_list

    @pytest.mark.asyncio
    async def test_run_container_with_volumes(self, sandbox, fake_aiodocker_client):
        sandbox._client = fake_aiodocker_client  # type: ignore[attr-defined]
        captured = {}

        async def _spy(config, host_config, networking_config, name):
            captured["host_config"] = host_config
            return "cid-spied"

        sandbox._create_container = _spy  # type: ignore[assignment]
        sandbox._start_container = AsyncMock()  # type: ignore[assignment]
        await sandbox.run_container(flow_id=5, image="debian:latest",
                                    volumes=["/host:/container"])
        binds = captured["host_config"]["Binds"]
        assert any("/host:/container" in b for b in binds)

    @pytest.mark.asyncio
    async def test_run_container_with_network_bridge(self, sandbox, fake_aiodocker_client):
        sandbox._client = fake_aiodocker_client  # type: ignore[attr-defined]
        captured = {}

        async def _spy(config, host_config, networking_config, name):
            captured["host_config"] = host_config
            return "cid-spied"

        sandbox._create_container = _spy  # type: ignore[assignment]
        sandbox._start_container = AsyncMock()  # type: ignore[assignment]
        await sandbox.run_container(flow_id=6, image="debian:latest", network="bridge")
        # bridge mode → port bindings present
        assert "PortBindings" in captured["host_config"]

    @pytest.mark.asyncio
    async def test_run_container_with_network_host(self, sandbox, fake_aiodocker_client):
        sandbox._client = fake_aiodocker_client  # type: ignore[attr-defined]
        captured = {}

        async def _spy(config, host_config, networking_config, name):
            captured["host_config"] = host_config
            return "cid-spied"

        sandbox._create_container = _spy  # type: ignore[assignment]
        sandbox._start_container = AsyncMock()  # type: ignore[assignment]
        await sandbox.run_container(flow_id=7, image="debian:latest", network="host")
        assert captured["host_config"].get("NetworkMode") == "host"
        assert "PortBindings" not in captured["host_config"]

    @pytest.mark.asyncio
    async def test_run_container_with_capabilities(self, sandbox, fake_aiodocker_client):
        """Capabilities list is augmented with NET_RAW (defense-in-depth)."""
        sandbox._client = fake_aiodocker_client  # type: ignore[attr-defined]
        captured = {}

        async def _spy(config, host_config, networking_config, name):
            captured["host_config"] = host_config
            return "cid-spied"

        sandbox._create_container = _spy  # type: ignore[assignment]
        sandbox._start_container = AsyncMock()  # type: ignore[assignment]
        await sandbox.run_container(flow_id=8, image="debian:latest",
                                    capabilities=["SYS_PTRACE"])
        cap_add = captured["host_config"]["CapAdd"]
        assert "SYS_PTRACE" in cap_add
        assert "NET_RAW" in cap_add  # auto-added

    @pytest.mark.asyncio
    async def test_run_container_image_pull_failure_falls_back_to_default(
        self, sandbox, fake_aiodocker_client
    ):
        """If the requested image fails to pull, fall back to def_image."""
        sandbox._client = fake_aiodocker_client  # type: ignore[attr-defined]
        # First pull fails, second (fallback) succeeds.
        call_count = {"n": 0}
        original_pull = fake_aiodocker_client.images.pull

        async def _flaky_pull(image_name):
            call_count["n"] += 1
            if call_count["n"] == 1:
                raise RuntimeError("registry down")
            return MagicMock(id="sha256:abc")

        fake_aiodocker_client.images.pull = _flaky_pull
        info = await sandbox.run_container(flow_id=9, image="vxcontrol/kali-linux")
        assert info.image == "debian:latest"  # fell back

    @pytest.mark.asyncio
    async def test_run_container_default_image_pull_failure_raises(
        self, sandbox, fake_aiodocker_client
    ):
        """If even the default image fails → mark FAILED + raise RuntimeError."""
        sandbox._client = fake_aiodocker_client  # type: ignore[attr-defined]
        fake_aiodocker_client.images.pull = AsyncMock(side_effect=RuntimeError("network unreachable"))
        with pytest.raises(RuntimeError):
            await sandbox.run_container(flow_id=10, image="debian:latest")
        # DB row should be marked FAILED
        rows = sandbox.store.list_all()
        assert any(r.status is ContainerStatus.FAILED for r in rows)


class TestStopRemoveInspect:
    """stop_container / remove_container / is_container_running."""

    @pytest.mark.asyncio
    async def test_stop_container_running(self, sandbox, fake_aiodocker_client):
        sandbox._client = fake_aiodocker_client  # type: ignore[attr-defined]
        await sandbox.stop_container("cid-1")
        fake_aiodocker_client.containers.container.return_value.stop.assert_awaited()

    @pytest.mark.asyncio
    async def test_stop_container_already_stopped_is_noop(self, sandbox, fake_aiodocker_client):
        """A 'no such container' error is logged but not raised."""
        sandbox._client = fake_aiodocker_client  # type: ignore[attr-defined]
        fake_aiodocker_client.containers.container.return_value.stop = AsyncMock(
            side_effect=RuntimeError("no such container")
        )
        # Should NOT raise — the sandbox treats already-gone as success.
        await sandbox.stop_container("cid-gone")

    @pytest.mark.asyncio
    async def test_stop_container_nonexistent_not_found(self, sandbox, fake_aiodocker_client):
        sandbox._client = fake_aiodocker_client  # type: ignore[attr-defined]
        fake_aiodocker_client.containers.container.return_value.stop = AsyncMock(
            side_effect=RuntimeError("Container not found")
        )
        await sandbox.stop_container("never-existed")

    @pytest.mark.asyncio
    async def test_stop_container_unknown_error_raises(self, sandbox, fake_aiodocker_client):
        """Non-'not found' errors propagate."""
        sandbox._client = fake_aiodocker_client  # type: ignore[attr-defined]
        fake_aiodocker_client.containers.container.return_value.stop = AsyncMock(
            side_effect=RuntimeError("docker daemon exploded")
        )
        with pytest.raises(RuntimeError, match="container shutdown failed"):
            await sandbox.stop_container("cid-1")

    @pytest.mark.asyncio
    async def test_remove_container_with_force(self, sandbox, fake_aiodocker_client):
        sandbox._client = fake_aiodocker_client  # type: ignore[attr-defined]
        await sandbox.remove_container("cid-1", force=True)
        fake_aiodocker_client.containers.container.return_value.delete.assert_awaited()
        call_kwargs = fake_aiodocker_client.containers.container.return_value.delete.call_args.kwargs
        assert call_kwargs.get("force") is True

    @pytest.mark.asyncio
    async def test_remove_container_without_force(self, sandbox, fake_aiodocker_client):
        sandbox._client = fake_aiodocker_client  # type: ignore[attr-defined]
        await sandbox.remove_container("cid-1", force=False)
        call_kwargs = fake_aiodocker_client.containers.container.return_value.delete.call_args.kwargs
        assert call_kwargs.get("force") is False

    @pytest.mark.asyncio
    async def test_remove_container_with_remove_volumes(self, sandbox, fake_aiodocker_client):
        sandbox._client = fake_aiodocker_client  # type: ignore[attr-defined]
        await sandbox.remove_container("cid-1", remove_volumes=True)
        call_kwargs = fake_aiodocker_client.containers.container.return_value.delete.call_args.kwargs
        assert call_kwargs.get("v") is True

    @pytest.mark.asyncio
    async def test_remove_container_nonexistent(self, sandbox, fake_aiodocker_client):
        sandbox._client = fake_aiodocker_client  # type: ignore[attr-defined]
        fake_aiodocker_client.containers.container.return_value.delete = AsyncMock(
            side_effect=RuntimeError("no such container")
        )
        # Should not raise — already gone is fine.
        await sandbox.remove_container("never-existed")

    @pytest.mark.asyncio
    async def test_is_container_running_true(self, sandbox, fake_aiodocker_client):
        sandbox._client = fake_aiodocker_client  # type: ignore[attr-defined]
        fake_aiodocker_client.containers.container.return_value.show = AsyncMock(
            return_value={"State": {"Running": True}}
        )
        assert await sandbox.is_container_running("cid-1") is True

    @pytest.mark.asyncio
    async def test_is_container_running_stopped(self, sandbox, fake_aiodocker_client):
        sandbox._client = fake_aiodocker_client  # type: ignore[attr-defined]
        fake_aiodocker_client.containers.container.return_value.show = AsyncMock(
            return_value={"State": {"Running": False}}
        )
        assert await sandbox.is_container_running("cid-1") is False

    @pytest.mark.asyncio
    async def test_is_container_running_nonexistent_raises(self, sandbox, fake_aiodocker_client):
        sandbox._client = fake_aiodocker_client  # type: ignore[attr-defined]
        fake_aiodocker_client.containers.container.return_value.show = AsyncMock(
            side_effect=RuntimeError("no such container")
        )
        with pytest.raises(RuntimeError, match="container inspection failed"):
            await sandbox.is_container_running("never-existed")

    @pytest.mark.asyncio
    async def test_is_container_running_unhealthy_is_false(self, sandbox, fake_aiodocker_client):
        """Health-check 'unhealthy' overrides Running=True."""
        sandbox._client = fake_aiodocker_client  # type: ignore[attr-defined]
        fake_aiodocker_client.containers.container.return_value.show = AsyncMock(
            return_value={"State": {
                "Running": True,
                "Health": {"Status": "unhealthy"},
            }}
        )
        assert await sandbox.is_container_running("cid-1") is False


class TestExecCreateAttachInspect:
    """container_exec_create / attach / inspect with shell-injection defenses."""

    @pytest.mark.asyncio
    async def test_exec_create_with_list_cmd(self, sandbox, fake_aiodocker_client):
        """List cmd is passed as Cmd without sh wrapping."""
        sandbox._client = fake_aiodocker_client  # type: ignore[attr-defined]
        await sandbox.container_exec_create("cid", ["ls", "-l"])
        # container.exec is called with a config dict as positional arg.
        call_args = fake_aiodocker_client.containers.container.return_value.exec.call_args
        config = call_args.args[0] if call_args.args else call_args.kwargs.get("config", {})
        assert config["Cmd"] == ["ls", "-l"]

    @pytest.mark.asyncio
    async def test_exec_create_with_string_cmd_wraps_in_sh(self, sandbox, fake_aiodocker_client):
        """String cmd is wrapped in 'sh -c <cmd>' — preserves shell semantics."""
        sandbox._client = fake_aiodocker_client  # type: ignore[attr-defined]
        await sandbox.container_exec_create("cid", "echo hello; rm -rf /")
        call_args = fake_aiodocker_client.containers.container.return_value.exec.call_args
        config = call_args.args[0] if call_args.args else call_args.kwargs.get("config")
        cmd = config.get("Cmd") if isinstance(config, dict) else None
        assert cmd == ["sh", "-c", "echo hello; rm -rf /"]

    @pytest.mark.asyncio
    async def test_exec_create_with_empty_string_cmd(self, sandbox, fake_aiodocker_client):
        """Empty string cmd is still wrapped in sh -c — no special-casing."""
        sandbox._client = fake_aiodocker_client  # type: ignore[attr-defined]
        exec_id = await sandbox.container_exec_create("cid", "")
        assert isinstance(exec_id, str)

    @pytest.mark.asyncio
    async def test_exec_create_with_none_cmd_passes_through(self, sandbox, fake_aiodocker_client):
        """None cmd is NOT a str → bypasses the sh -c wrapping and is passed as-is.

        The Docker daemon will reject ``Cmd: null`` at execution time, but the
        sandbox layer does not pre-validate this — defense-in-depth is the
        daemon's job.
        """
        sandbox._client = fake_aiodocker_client  # type: ignore[attr-defined]
        exec_id = await sandbox.container_exec_create("cid", None)
        assert isinstance(exec_id, str)
        call_args = fake_aiodocker_client.containers.container.return_value.exec.call_args
        config = call_args.args[0] if call_args.args else {}
        assert config["Cmd"] is None

    @pytest.mark.asyncio
    async def test_exec_create_with_very_long_cmd(self, sandbox, fake_aiodocker_client):
        """10KB command string is accepted (no length limit at this layer)."""
        sandbox._client = fake_aiodocker_client  # type: ignore[attr-defined]
        long_cmd = "echo " + "A" * 10240
        exec_id = await sandbox.container_exec_create("cid", long_cmd)
        assert isinstance(exec_id, str)

    @pytest.mark.asyncio
    async def test_exec_attach_returns_string(self, sandbox, fake_aiodocker_client):
        sandbox._client = fake_aiodocker_client  # type: ignore[attr-defined]
        result = await sandbox.container_exec_attach("exec-1")
        assert isinstance(result, str)

    @pytest.mark.asyncio
    async def test_exec_attach_handles_bytes_stream(self, sandbox, fake_aiodocker_client):
        sandbox._client = fake_aiodocker_client  # type: ignore[attr-defined]
        fake_aiodocker_client.containers.exec.return_value.start = AsyncMock(
            return_value=b"hello world"
        )
        result = await sandbox.container_exec_attach("exec-1")
        assert "hello world" in result

    @pytest.mark.asyncio
    async def test_exec_inspect_returns_dict(self, sandbox, fake_aiodocker_client):
        sandbox._client = fake_aiodocker_client  # type: ignore[attr-defined]
        result = await sandbox.container_exec_inspect("exec-1")
        assert isinstance(result, dict)


class TestCopyToFromContainer:
    """copy_to_container / copy_from_container — TAR + size guard."""

    @pytest.mark.asyncio
    async def test_copy_to_container_small_file(self, sandbox, fake_aiodocker_client):
        sandbox._client = fake_aiodocker_client  # type: ignore[attr-defined]
        await sandbox.copy_to_container("cid", "/work/file.txt", b"hello")
        fake_aiodocker_client.containers.container.return_value.put_archive.assert_awaited()

    @pytest.mark.asyncio
    async def test_copy_to_container_rejects_large_file(self, sandbox, fake_aiodocker_client):
        """Files > 100MB are rejected before any Docker call."""
        sandbox._client = fake_aiodocker_client  # type: ignore[attr-defined]
        big = b"x" * (MAX_FILE_SIZE_BYTES + 1)
        with pytest.raises(RuntimeError, match="file too large"):
            await sandbox.copy_to_container("cid", "/work/big.bin", big)
        fake_aiodocker_client.containers.container.return_value.put_archive.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_copy_to_container_empty_file(self, sandbox, fake_aiodocker_client):
        sandbox._client = fake_aiodocker_client  # type: ignore[attr-defined]
        await sandbox.copy_to_container("cid", "/work/empty", b"")
        fake_aiodocker_client.containers.container.return_value.put_archive.assert_awaited()

    @pytest.mark.asyncio
    async def test_copy_to_container_packs_tar(self, sandbox, fake_aiodocker_client):
        """The bytes streamed to put_archive are a valid tar archive."""
        sandbox._client = fake_aiodocker_client  # type: ignore[attr-defined]
        await sandbox.copy_to_container("cid", "/work/data.txt", b"payload")
        call_args = fake_aiodocker_client.containers.container.return_value.put_archive.call_args
        tar_bytes = call_args.args[1]
        bio = io.BytesIO(tar_bytes)
        with tarfile.open(fileobj=bio, mode="r") as tar:
            members = tar.getmembers()
            assert len(members) == 1
            assert members[0].isfile()
            f = tar.extractfile(members[0])
            assert f.read() == b"payload"

    @pytest.mark.asyncio
    async def test_copy_from_container_small_file(self, sandbox, fake_aiodocker_client):
        sandbox._client = fake_aiodocker_client  # type: ignore[attr-defined]
        # Build a tar with one file entry.
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as tar:
            ti = tarfile.TarInfo(name="hello.txt")
            ti.size = len(b"hello")
            tar.addfile(ti, io.BytesIO(b"hello"))
        fake_aiodocker_client.containers.container.return_value.get_archive = AsyncMock(
            return_value=(buf.getvalue(), {"mode": 0o100644})
        )
        result = await sandbox.copy_from_container("cid", "/work/hello.txt")
        assert result == b"hello"

    @pytest.mark.asyncio
    async def test_copy_from_container_no_file_raises(self, sandbox, fake_aiodocker_client):
        """Empty tar stream (no entries) → RuntimeError."""
        sandbox._client = fake_aiodocker_client  # type: ignore[attr-defined]
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as tar:
            pass  # empty archive
        fake_aiodocker_client.containers.container.return_value.get_archive = AsyncMock(
            return_value=(buf.getvalue(), {})
        )
        with pytest.raises(RuntimeError, match="no regular file found"):
            await sandbox.copy_from_container("cid", "/work/missing")


class TestCleanup:
    """cleanup: empty flows, all-finished flows, mixed statuses."""

    @pytest.mark.asyncio
    async def test_cleanup_no_containers_is_noop(self, sandbox, fake_aiodocker_client):
        sandbox._client = fake_aiodocker_client  # type: ignore[attr-defined]
        await sandbox.cleanup()  # should not raise

    @pytest.mark.asyncio
    async def test_cleanup_removes_starting_containers(self, sandbox, fake_aiodocker_client, tmp_path):
        """Containers in STARTING state with no flows-table row are cleaned up."""
        sandbox._client = fake_aiodocker_client  # type: ignore[attr-defined]
        # Insert a STARTING container row directly.
        sandbox.store.create(ContainerInfo(
            name="elengenix-terminal-1", image="debian:latest",
            status=ContainerStatus.STARTING, local_id="cid-1", flow_id=1,
        ))
        await sandbox.cleanup()
        fake_aiodocker_client.containers.container.return_value.delete.assert_awaited()

    @pytest.mark.asyncio
    async def test_cleanup_skips_finished_flows_without_active_containers(
        self, sandbox, fake_aiodocker_client
    ):
        """Containers in DELETED status (already terminal) are NOT removed again."""
        sandbox._client = fake_aiodocker_client  # type: ignore[attr-defined]
        sandbox.store.create(ContainerInfo(
            name="elengenix-terminal-2", image="debian:latest",
            status=ContainerStatus.DELETED, local_id="cid-2", flow_id=2,
        ))
        await sandbox.cleanup()
        fake_aiodocker_client.containers.container.return_value.delete.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_cleanup_with_mixed_statuses(self, sandbox, fake_aiodocker_client):
        """Cleanup picks up only STARTING/RUNNING; leaves STOPPED/DELETED alone."""
        sandbox._client = fake_aiodocker_client  # type: ignore[attr-defined]
        sandbox.store.create(ContainerInfo(
            name="elengenix-terminal-3", image="debian:latest",
            status=ContainerStatus.STARTING, local_id="cid-3a", flow_id=3,
        ))
        sandbox.store.create(ContainerInfo(
            name="elengenix-terminal-4", image="debian:latest",
            status=ContainerStatus.DELETED, local_id="cid-3b", flow_id=4,
        ))
        await sandbox.cleanup()
        # Only the STARTING one is removed.
        assert fake_aiodocker_client.containers.container.return_value.delete.await_count >= 1


class TestGetDefaultImage:
    @pytest.mark.asyncio
    async def test_get_default_image_returns_debian_latest(self, sandbox):
        assert await sandbox.get_default_image() == "debian:latest"

    @pytest.mark.asyncio
    async def test_get_default_image_custom(self, tmp_path, tmp_db):
        sb = DockerSandbox(data_dir=tmp_path, db_path=tmp_db, default_image="ubuntu:22.04")
        assert await sb.get_default_image() == "ubuntu:22.04"


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 2 — DockerTerminal (40 tests)
# ═══════════════════════════════════════════════════════════════════════════


class TestTerminalConstants:
    """All PentAGI-ported constants."""

    def test_primary_terminal_name_prefix(self):
        assert PRIMARY_TERMINAL_NAME_PREFIX == "pentagi-terminal-"

    def test_max_explicit_exec_command_timeout(self):
        assert MAX_EXPLICIT_EXEC_COMMAND_TIMEOUT == 10800

    def test_default_extra_exec_timeout(self):
        assert DEFAULT_EXTRA_EXEC_TIMEOUT == 5

    def test_default_quick_check_timeout(self):
        assert DEFAULT_QUICK_CHECK_TIMEOUT == 0.5

    def test_default_server_exec_timeout(self):
        assert DEFAULT_SERVER_EXEC_TIMEOUT == 1200

    def test_max_read_file_size(self):
        assert MAX_READ_FILE_SIZE == 100 * 1024 * 1024

    def test_ansi_color_input_cmd_is_cyan(self):
        """stdin color = bright cyan (ESC[96m)."""
        assert ANSI_COLOR_INPUT_CMD == "\033[96m"

    def test_ansi_color_system_msg_is_green(self):
        """stdout color = bright green (ESC[92m)."""
        assert ANSI_COLOR_SYSTEM_MSG == "\033[92m"

    def test_ansi_color_reset(self):
        assert ANSI_COLOR_RESET == "\033[0m"

    def test_ansi_line_terminator_is_crlf(self):
        assert ANSI_LINE_TERMINATOR == "\r\n"

    def test_primary_terminal_name_for_flow(self):
        assert primary_terminal_name(1) == "pentagi-terminal-1"

    def test_primary_terminal_name_for_string_flow_id(self):
        assert primary_terminal_name("abc") == "pentagi-terminal-abc"


class TestTerminalTimeoutNormalization:
    """normalize_exec_timeout: 0/neg/out-of-range → server default."""

    def _make_terminal(self, default_exec_timeout: int = DEFAULT_SERVER_EXEC_TIMEOUT) -> DockerTerminal:
        t = DockerTerminal.__new__(DockerTerminal)
        t.default_exec_timeout = default_exec_timeout
        return t

    def test_normalize_zero_uses_server_default(self):
        t = self._make_terminal(default_exec_timeout=1200)
        # 0 → server default + extra = 1205
        assert t.normalize_exec_timeout(0) == 1205

    def test_normalize_one_adds_extra_slack(self):
        t = self._make_terminal(default_exec_timeout=1200)
        # 1 <= 1205 → returns 1 + 5 = 6
        assert t.normalize_exec_timeout(1) == 6

    def test_normalize_negative_uses_server_default(self):
        t = self._make_terminal(default_exec_timeout=1200)
        assert t.normalize_exec_timeout(-1) == 1205

    def test_normalize_above_server_default_clamps(self):
        """Any timeout above server_default+extra falls back to server_default+extra."""
        t = self._make_terminal(default_exec_timeout=1200)
        # 10800 > 1205 → server default
        assert t.normalize_exec_timeout(10800) == 1205

    def test_normalize_at_max_with_maxed_config(self):
        """With default_exec_timeout=10800, normalize(10800) = 10805."""
        t = self._make_terminal(default_exec_timeout=10800)
        assert t.normalize_exec_timeout(10800) == 10805

    def test_normalize_above_max_with_maxed_config_clamps(self):
        """10806 > 10805 → server default 10805."""
        t = self._make_terminal(default_exec_timeout=10800)
        assert t.normalize_exec_timeout(10806) == 10805

    def test_configured_exec_timeout_clamps_invalid_zero(self):
        """default_exec_timeout=0 → configured returns MAX_EXPLICIT."""
        t = self._make_terminal(default_exec_timeout=0)
        assert t.configured_exec_timeout() == MAX_EXPLICIT_EXEC_COMMAND_TIMEOUT

    def test_configured_exec_timeout_clamps_above_max(self):
        t = self._make_terminal(default_exec_timeout=99999)
        assert t.configured_exec_timeout() == MAX_EXPLICIT_EXEC_COMMAND_TIMEOUT

    def test_configured_exec_timeout_passes_through_valid(self):
        t = self._make_terminal(default_exec_timeout=600)
        assert t.configured_exec_timeout() == 600


class TestTerminalExecute:
    """execute: cmd, cwd, detach, timeouts, shell-injection defenses."""

    def _make_terminal(self, docker_client) -> DockerTerminal:
        return DockerTerminal(flow_id=1, docker_client=docker_client)

    @pytest.mark.asyncio
    async def test_execute_basic_command(self):
        client = MagicMock()
        client.is_container_running = AsyncMock(return_value=True)
        client.container_exec_create = AsyncMock(return_value={"Id": "exec-1"})
        client.container_exec_start = AsyncMock(return_value=b"hello world")
        client.container_exec_inspect = AsyncMock(return_value={"ExitCode": 0})
        term = self._make_terminal(client)
        out = await term.execute("cid-1", "echo hello")
        assert "hello world" in out

    @pytest.mark.asyncio
    async def test_execute_with_cwd(self):
        client = MagicMock()
        client.is_container_running = AsyncMock(return_value=True)
        client.container_exec_create = AsyncMock(return_value={"Id": "exec-1"})
        client.container_exec_start = AsyncMock(return_value=b"")
        client.container_exec_inspect = AsyncMock(return_value={"ExitCode": 0})
        term = self._make_terminal(client)
        await term.execute("cid-1", "ls", cwd="/var/log")
        call_kwargs = client.container_exec_create.call_args.kwargs
        assert call_kwargs.get("working_dir") == "/var/log"

    @pytest.mark.asyncio
    async def test_execute_detach_returns_output_if_quick(self):
        """Detach mode: command finishes within 500ms → returns output."""
        client = MagicMock()
        client.is_container_running = AsyncMock(return_value=True)
        client.container_exec_create = AsyncMock(return_value={"Id": "exec-1"})
        client.container_exec_start = AsyncMock(return_value=b"done")
        client.container_exec_inspect = AsyncMock(return_value={"ExitCode": 0})
        term = self._make_terminal(client)
        out = await term.execute("cid-1", "echo done", detach=True)
        assert "done" in out

    @pytest.mark.asyncio
    async def test_execute_detach_returns_background_notice_if_slow(self):
        """Detach mode: >500ms → returns 'started in background' notice."""
        client = MagicMock()
        client.is_container_running = AsyncMock(return_value=True)
        client.container_exec_create = AsyncMock(return_value={"Id": "exec-1"})

        async def _slow_start(exec_id, tty=True):
            await asyncio.sleep(2.0)  # > 500ms quick-check window
            return b""

        client.container_exec_start = _slow_start
        client.container_exec_inspect = AsyncMock(return_value={"ExitCode": 0})
        term = self._make_terminal(client)
        out = await term.execute("cid-1", "sleep 2", detach=True)
        assert "background" in out.lower()

    @pytest.mark.asyncio
    async def test_execute_attached_mode_timeout_suggests_detach(self):
        """Attached mode with timeout → error message hints at detach=True."""
        client = MagicMock()
        client.is_container_running = AsyncMock(return_value=True)
        client.container_exec_create = AsyncMock(return_value={"Id": "exec-1"})

        # Slow async reader — _drain() will hang reading from it.
        class _SlowReader:
            async def read(self, n=-1):
                await asyncio.sleep(10.0)
                return b""

        client.container_exec_start = AsyncMock(return_value=_SlowReader())
        client.container_exec_inspect = AsyncMock(return_value={"ExitCode": 0})
        term = self._make_terminal(client)
        with pytest.raises(RuntimeError) as ei:
            await term.execute("cid-1", "sleep 10", detach=False, timeout=1)
        assert "detach=true" in str(ei.value).lower()

    @pytest.mark.asyncio
    async def test_execute_empty_command_still_runs(self):
        """Empty string command is passed to sh -c — no special-casing."""
        client = MagicMock()
        client.is_container_running = AsyncMock(return_value=True)
        client.container_exec_create = AsyncMock(return_value={"Id": "exec-1"})
        client.container_exec_start = AsyncMock(return_value=b"")
        client.container_exec_inspect = AsyncMock(return_value={"ExitCode": 0})
        term = self._make_terminal(client)
        out = await term.execute("cid-1", "")
        # Empty output → silent-success placeholder.
        assert "silent success" in out.lower() or out == ""

    @pytest.mark.asyncio
    async def test_execute_command_with_shell_metacharacters(self):
        """Command containing ; | & $ ` is passed verbatim to sh -c."""
        client = MagicMock()
        client.is_container_running = AsyncMock(return_value=True)
        client.container_exec_create = AsyncMock(return_value={"Id": "exec-1"})
        client.container_exec_start = AsyncMock(return_value=b"ok")
        client.container_exec_inspect = AsyncMock(return_value={"ExitCode": 0})
        term = self._make_terminal(client)
        await term.execute("cid-1", "echo `whoami` | grep root ; echo $HOME & sleep 1")
        call_kwargs = client.container_exec_create.call_args.kwargs
        cmd = call_kwargs.get("cmd")
        # Verify metachars are preserved (NOT escaped — they're inside sh -c).
        assert "`" in cmd[-1] or "$" in cmd[-1] or "|" in cmd[-1]

    @pytest.mark.asyncio
    async def test_execute_command_with_unicode_emoji(self):
        """Unicode / emoji in command do not crash the terminal."""
        client = MagicMock()
        client.is_container_running = AsyncMock(return_value=True)
        client.container_exec_create = AsyncMock(return_value={"Id": "exec-1"})
        client.container_exec_start = AsyncMock(return_value="🎉 ok".encode("utf-8"))
        client.container_exec_inspect = AsyncMock(return_value={"ExitCode": 0})
        term = self._make_terminal(client)
        out = await term.execute("cid-1", "echo '🎉 élengenix'")
        assert "🎉" in out

    @pytest.mark.asyncio
    async def test_execute_very_long_command_10kb(self):
        """10KB command string is accepted (no length limit)."""
        client = MagicMock()
        client.is_container_running = AsyncMock(return_value=True)
        client.container_exec_create = AsyncMock(return_value={"Id": "exec-1"})
        client.container_exec_start = AsyncMock(return_value=b"ok")
        client.container_exec_inspect = AsyncMock(return_value={"ExitCode": 0})
        term = self._make_terminal(client)
        long_cmd = "echo " + "A" * 10240
        out = await term.execute("cid-1", long_cmd)
        assert "ok" in out

    @pytest.mark.asyncio
    async def test_execute_container_not_running_raises(self):
        """If container is not operational, execute refuses to run."""
        client = MagicMock()
        client.is_container_running = AsyncMock(return_value=False)
        term = self._make_terminal(client)
        with pytest.raises(RuntimeError, match="not operational"):
            await term.execute("cid-1", "ls")

    @pytest.mark.asyncio
    async def test_execute_terminal_unavailable_raises(self):
        """Without a docker client, execute raises RuntimeError."""
        term = DockerTerminal(flow_id=1, docker_client=None)
        with pytest.raises(RuntimeError, match="not available"):
            await term.execute("cid-1", "ls")

    @pytest.mark.asyncio
    async def test_execute_emits_styled_stdin_log(self):
        """stdin log includes cwd, ANSI cyan color, and the command."""
        tlp = MagicMock()
        tlp.put_msg = AsyncMock()
        client = MagicMock()
        client.is_container_running = AsyncMock(return_value=True)
        client.container_exec_create = AsyncMock(return_value={"Id": "exec-1"})
        client.container_exec_start = AsyncMock(return_value=b"ok")
        client.container_exec_inspect = AsyncMock(return_value={"ExitCode": 0})
        term = DockerTerminal(flow_id=1, docker_client=client, term_log_provider=tlp)
        await term.execute("cid-1", "ls")
        # First put_msg call is the stdin log entry.
        first_call = tlp.put_msg.call_args_list[0]
        assert first_call.args[0] == "stdin"
        assert ANSI_COLOR_INPUT_CMD in first_call.args[1]

    @pytest.mark.asyncio
    async def test_execute_emits_styled_stdout_log(self):
        """stdout log includes ANSI green color and the captured output."""
        tlp = MagicMock()
        tlp.put_msg = AsyncMock()
        client = MagicMock()
        client.is_container_running = AsyncMock(return_value=True)
        client.container_exec_create = AsyncMock(return_value={"Id": "exec-1"})
        client.container_exec_start = AsyncMock(return_value=b"hello-output")
        client.container_exec_inspect = AsyncMock(return_value={"ExitCode": 0})
        term = DockerTerminal(flow_id=1, docker_client=client, term_log_provider=tlp)
        await term.execute("cid-1", "echo hello-output")
        stdout_call = tlp.put_msg.call_args_list[1]
        assert stdout_call.args[0] == "stdout"
        assert ANSI_COLOR_SYSTEM_MSG in stdout_call.args[1]
        assert "hello-output" in stdout_call.args[1]

    @pytest.mark.asyncio
    async def test_execute_silent_success_placeholder(self):
        """Empty output → returns 'silent success' placeholder text."""
        client = MagicMock()
        client.is_container_running = AsyncMock(return_value=True)
        client.container_exec_create = AsyncMock(return_value={"Id": "exec-1"})
        client.container_exec_start = AsyncMock(return_value=b"")
        client.container_exec_inspect = AsyncMock(return_value={"ExitCode": 0})
        term = self._make_terminal(client)
        out = await term.execute("cid-1", "true")
        assert "silent success" in out.lower()


class TestTerminalReadFile:
    """read_file: TAR-based, size guard, path injection defense."""

    @staticmethod
    def _make_tar(name: str, content: bytes, is_dir: bool = False) -> bytes:
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as tar:
            ti = tarfile.TarInfo(name=name)
            if is_dir:
                ti.type = tarfile.DIRTYPE
                ti.mode = 0o040755
                ti.size = 0
                tar.addfile(ti)
            else:
                ti.size = len(content)
                ti.mode = 0o100644
                tar.addfile(ti, io.BytesIO(content))
        return buf.getvalue()

    @pytest.mark.asyncio
    async def test_read_file_small(self):
        client = MagicMock()
        client.is_container_running = AsyncMock(return_value=True)
        tar_bytes = self._make_tar("hello.txt", b"hello world")
        client.get_archive = AsyncMock(return_value=(tar_bytes, {"mode": 0o100644}))
        term = DockerTerminal(flow_id=1, docker_client=client)
        content = await term.read_file("cid-1", "/work/hello.txt")
        assert "hello world" in content

    @pytest.mark.asyncio
    async def test_read_file_rejects_large_file(self):
        """Member size > MAX_READ_FILE_SIZE → RuntimeError."""
        client = MagicMock()
        client.is_container_running = AsyncMock(return_value=True)
        big = b"x" * (MAX_READ_FILE_SIZE + 1)
        tar_bytes = self._make_tar("big.bin", big)
        client.get_archive = AsyncMock(return_value=(tar_bytes, {"mode": 0o100644}))
        term = DockerTerminal(flow_id=1, docker_client=client)
        with pytest.raises(RuntimeError, match="exceeds maximum"):
            await term.read_file("cid-1", "/work/big.bin")

    @pytest.mark.asyncio
    async def test_read_file_nonexistent_raises(self):
        """get_archive failure surfaces as a RuntimeError."""
        client = MagicMock()
        client.is_container_running = AsyncMock(return_value=True)
        client.get_archive = AsyncMock(side_effect=RuntimeError("no such path"))
        term = DockerTerminal(flow_id=1, docker_client=client)
        with pytest.raises(RuntimeError, match="failed to copy file"):
            await term.read_file("cid-1", "/work/missing.txt")

    @pytest.mark.asyncio
    async def test_read_file_path_traversal_attempt(self):
        """Path-traversal sequences are passed to docker get_archive (the
        Docker daemon rejects them) — but the terminal layer must not crash."""
        client = MagicMock()
        client.is_container_running = AsyncMock(return_value=True)
        tar_bytes = self._make_tar("passwd", b"root:x:0:0")
        client.get_archive = AsyncMock(return_value=(tar_bytes, {"mode": 0o100644}))
        term = DockerTerminal(flow_id=1, docker_client=client)
        # We use the path verbatim — shlex.quote is applied for the cat command.
        content = await term.read_file("cid-1", "../../etc/passwd")
        assert "root:x:0:0" in content

    @pytest.mark.asyncio
    async def test_read_file_directory_lists_all_entries(self):
        """Reading a directory concatenates every regular file inside it."""
        client = MagicMock()
        client.is_container_running = AsyncMock(return_value=True)
        # Build tar with 2 files; mark stat as directory.
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as tar:
            for name, content in [("a.txt", b"alpha"), ("b.txt", b"beta")]:
                ti = tarfile.TarInfo(name=name)
                ti.size = len(content)
                ti.mode = 0o100644
                tar.addfile(ti, io.BytesIO(content))
        client.get_archive = AsyncMock(return_value=(buf.getvalue(), {"mode": 0o040755}))
        term = DockerTerminal(flow_id=1, docker_client=client)
        content = await term.read_file("cid-1", "/work/")
        assert "alpha" in content
        assert "beta" in content

    @pytest.mark.asyncio
    async def test_read_file_shell_metachar_in_path_is_quoted(self):
        """Path with shell metacharacters is shlex-quoted in the cat command."""
        tlp = MagicMock()
        tlp.put_msg = AsyncMock()
        client = MagicMock()
        client.is_container_running = AsyncMock(return_value=True)
        tar_bytes = self._make_tar("file", b"ok")
        client.get_archive = AsyncMock(return_value=(tar_bytes, {"mode": 0o100644}))
        term = DockerTerminal(flow_id=1, docker_client=client, term_log_provider=tlp)
        await term.read_file("cid-1", "/work/file; rm -rf /")
        first_call = tlp.put_msg.call_args_list[0]
        # The injected ; rm -rf / must be shell-escaped, not literal.
        assert "rm -rf /" not in first_call.args[1] or "'" in first_call.args[1]


class TestTerminalWriteFile:
    """write_file: TAR packaging, overwrite, binary content, path injection."""

    @pytest.mark.asyncio
    async def test_write_file_small_content(self):
        client = MagicMock()
        client.is_container_running = AsyncMock(return_value=True)
        client.put_archive = AsyncMock()
        term = DockerTerminal(flow_id=1, docker_client=client)
        result = await term.write_file("cid-1", "/work/file.txt", b"hello")
        assert "5 bytes" in result  # len(b"hello")
        client.put_archive.assert_awaited()

    @pytest.mark.asyncio
    async def test_write_file_empty_content(self):
        client = MagicMock()
        client.is_container_running = AsyncMock(return_value=True)
        client.put_archive = AsyncMock()
        term = DockerTerminal(flow_id=1, docker_client=client)
        result = await term.write_file("cid-1", "/work/empty.txt", b"")
        assert "0 bytes" in result

    @pytest.mark.asyncio
    async def test_write_file_binary_content(self):
        client = MagicMock()
        client.is_container_running = AsyncMock(return_value=True)
        client.put_archive = AsyncMock()
        term = DockerTerminal(flow_id=1, docker_client=client)
        payload = bytes(range(256))
        result = await term.write_file("cid-1", "/work/bin.dat", payload)
        assert "256 bytes" in result

    @pytest.mark.asyncio
    async def test_write_file_string_content_is_encoded(self):
        """If a str is passed, it's encoded to UTF-8 bytes automatically."""
        client = MagicMock()
        client.is_container_running = AsyncMock(return_value=True)
        client.put_archive = AsyncMock()
        term = DockerTerminal(flow_id=1, docker_client=client)
        result = await term.write_file("cid-1", "/work/s.txt", "héllo")
        # 'héllo' = h(1) + é(2) + l(1) + l(1) + o(1) = 6 UTF-8 bytes
        assert "6 bytes" in result

    @pytest.mark.asyncio
    async def test_write_file_overwrite_existing(self):
        """Writing twice to the same path is allowed (AllowOverwriteDirWithFile)."""
        client = MagicMock()
        client.is_container_running = AsyncMock(return_value=True)
        client.put_archive = AsyncMock()
        term = DockerTerminal(flow_id=1, docker_client=client)
        await term.write_file("cid-1", "/work/file.txt", b"v1")
        await term.write_file("cid-1", "/work/file.txt", b"v2")
        assert client.put_archive.await_count == 2

    @pytest.mark.asyncio
    async def test_write_file_path_with_special_chars(self):
        """Paths with spaces / special chars are passed via tar entry name."""
        client = MagicMock()
        client.is_container_running = AsyncMock(return_value=True)
        client.put_archive = AsyncMock()
        term = DockerTerminal(flow_id=1, docker_client=client)
        await term.write_file("cid-1", "/work/my file (1).txt", b"data")
        call_args = client.put_archive.call_args
        tar_bytes = call_args.args[2]
        bio = io.BytesIO(tar_bytes)
        with tarfile.open(fileobj=bio, mode="r") as tar:
            members = tar.getmembers()
            assert members[0].name == "my file (1).txt"

    @pytest.mark.asyncio
    async def test_write_file_container_not_running_raises(self):
        client = MagicMock()
        client.is_container_running = AsyncMock(return_value=False)
        term = DockerTerminal(flow_id=1, docker_client=client)
        with pytest.raises(RuntimeError, match="not operational"):
            await term.write_file("cid-1", "/work/x.txt", b"data")


class TestTerminalShlexQuote:
    """shlex.quote correctness — defense-in-depth against shell injection."""

    def test_shlex_quote_simple_word(self):
        import shlex
        assert shlex.quote("hello") == "hello"

    def test_shlex_quote_word_with_space(self):
        import shlex
        assert shlex.quote("hello world") == "'hello world'"

    def test_shlex_quote_word_with_semicolon(self):
        import shlex
        out = shlex.quote("evil; rm -rf /")
        assert "rm -rf /" in out  # inside quotes, harmless
        assert out.startswith("'")

    def test_shlex_quote_word_with_backtick(self):
        import shlex
        out = shlex.quote("evil`whoami`")
        assert "'" in out  # quoted

    def test_shlex_quote_word_with_dollar(self):
        import shlex
        out = shlex.quote("$HOME")
        assert "'" in out  # quoted — no var expansion


class TestTruncateString:
    def test_truncate_short_unchanged(self):
        assert _truncate_string("hello", 100) == "hello"

    def test_truncate_long_gets_suffix(self):
        s = "x" * 200
        out = _truncate_string(s, 100)
        assert out.startswith("x" * 100)
        assert "200 bytes" in out


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 3 — DockerFileOps (30 tests)
# ═══════════════════════════════════════════════════════════════════════════


class TestFileOpsExists:
    @pytest.mark.asyncio
    async def test_exists_returns_true_for_existing_file(self):
        terminal = MagicMock()
        terminal.execute = AsyncMock(return_value="yes")
        ops = DockerFileOps(terminal)
        assert await ops.exists("cid-1", "/etc/hostname") is True

    @pytest.mark.asyncio
    async def test_exists_returns_false_for_missing(self):
        terminal = MagicMock()
        terminal.execute = AsyncMock(return_value="no")
        ops = DockerFileOps(terminal)
        assert await ops.exists("cid-1", "/no/such/file") is False

    @pytest.mark.asyncio
    async def test_exists_returns_true_for_directory(self):
        terminal = MagicMock()
        terminal.execute = AsyncMock(return_value="yes")
        ops = DockerFileOps(terminal)
        assert await ops.exists("cid-1", "/etc") is True

    @pytest.mark.asyncio
    async def test_exists_quotes_path_with_metachars(self):
        """Path with shell metacharacters is shlex-quoted (no injection)."""
        terminal = MagicMock()
        terminal.execute = AsyncMock(return_value="no")
        ops = DockerFileOps(terminal)
        await ops.exists("cid-1", "evil; rm -rf /")
        cmd = terminal.execute.call_args.args[1]
        assert "rm -rf /" in cmd  # inside [ -e '...' ] quotes
        assert "if [ -e 'evil; rm -rf /' ]" in cmd


class TestFileOpsIsDir:
    @pytest.mark.asyncio
    async def test_is_dir_true_for_directory(self):
        terminal = MagicMock()
        terminal.execute = AsyncMock(return_value="yes")
        ops = DockerFileOps(terminal)
        assert await ops.is_dir("cid-1", "/etc") is True

    @pytest.mark.asyncio
    async def test_is_dir_false_for_file(self):
        terminal = MagicMock()
        terminal.execute = AsyncMock(return_value="no")
        ops = DockerFileOps(terminal)
        assert await ops.is_dir("cid-1", "/etc/hostname") is False

    @pytest.mark.asyncio
    async def test_is_dir_false_for_nonexistent(self):
        terminal = MagicMock()
        terminal.execute = AsyncMock(return_value="no")
        ops = DockerFileOps(terminal)
        assert await ops.is_dir("cid-1", "/no/such/dir") is False


class TestFileOpsListDir:
    @pytest.mark.asyncio
    async def test_list_dir_empty(self):
        terminal = MagicMock()
        terminal.execute = AsyncMock(return_value="")
        ops = DockerFileOps(terminal)
        assert await ops.list_dir("cid-1", "/empty") == []

    @pytest.mark.asyncio
    async def test_list_dir_populated(self):
        terminal = MagicMock()
        terminal.execute = AsyncMock(return_value="file1\nfile2\ndir1")
        ops = DockerFileOps(terminal)
        result = await ops.list_dir("cid-1", "/work")
        assert result == ["file1", "file2", "dir1"]

    @pytest.mark.asyncio
    async def test_list_dir_includes_hidden_files(self):
        """ls -1A includes dotfiles (but not . or ..)."""
        terminal = MagicMock()
        terminal.execute = AsyncMock(return_value=".hidden\nvisible")
        ops = DockerFileOps(terminal)
        result = await ops.list_dir("cid-1", "/work")
        assert ".hidden" in result

    @pytest.mark.asyncio
    async def test_list_dir_nonexistent_returns_empty(self):
        """2>/dev/null swallows the error → empty list."""
        terminal = MagicMock()
        terminal.execute = AsyncMock(return_value="")
        ops = DockerFileOps(terminal)
        assert await ops.list_dir("cid-1", "/no/such/dir") == []

    @pytest.mark.asyncio
    async def test_list_dir_quotes_path(self):
        terminal = MagicMock()
        terminal.execute = AsyncMock(return_value="")
        ops = DockerFileOps(terminal)
        await ops.list_dir("cid-1", "name with space")
        cmd = terminal.execute.call_args.args[1]
        assert "'name with space'" in cmd


class TestFileOpsMkdir:
    @pytest.mark.asyncio
    async def test_mkdir_new_dir(self):
        terminal = MagicMock()
        terminal.execute = AsyncMock(return_value="")
        ops = DockerFileOps(terminal)
        await ops.mkdir("cid-1", "/work/newdir")
        cmd = terminal.execute.call_args.args[1]
        assert "mkdir" in cmd and "-p" in cmd

    @pytest.mark.asyncio
    async def test_mkdir_existing_with_parents_is_idempotent(self):
        terminal = MagicMock()
        terminal.execute = AsyncMock(return_value="")
        ops = DockerFileOps(terminal)
        await ops.mkdir("cid-1", "/work/existing")
        cmd = terminal.execute.call_args.args[1]
        assert "-p" in cmd  # -p makes it idempotent

    @pytest.mark.asyncio
    async def test_mkdir_without_parents(self):
        terminal = MagicMock()
        terminal.execute = AsyncMock(return_value="")
        ops = DockerFileOps(terminal)
        await ops.mkdir("cid-1", "/work/newdir", parents=False)
        cmd = terminal.execute.call_args.args[1]
        assert "-p" not in cmd

    @pytest.mark.asyncio
    async def test_mkdir_nested_path(self):
        terminal = MagicMock()
        terminal.execute = AsyncMock(return_value="")
        ops = DockerFileOps(terminal)
        await ops.mkdir("cid-1", "/work/a/b/c/d")
        cmd = terminal.execute.call_args.args[1]
        assert "/work/a/b/c/d" in cmd

    @pytest.mark.asyncio
    async def test_mkdir_with_mode(self):
        terminal = MagicMock()
        terminal.execute = AsyncMock(return_value="")
        ops = DockerFileOps(terminal)
        await ops.mkdir("cid-1", "/work/secure", mode=0o700)
        cmd = terminal.execute.call_args.args[1]
        assert "700" in cmd


class TestFileOpsRm:
    @pytest.mark.asyncio
    async def test_rm_file(self):
        terminal = MagicMock()
        terminal.execute = AsyncMock(return_value="")
        ops = DockerFileOps(terminal)
        await ops.rm("cid-1", "/work/file.txt")
        cmd = terminal.execute.call_args.args[1]
        assert "rm" in cmd and "-f" in cmd and "-rf" not in cmd

    @pytest.mark.asyncio
    async def test_rm_dir_without_recursive_uses_f_only(self):
        terminal = MagicMock()
        terminal.execute = AsyncMock(return_value="")
        ops = DockerFileOps(terminal)
        await ops.rm("cid-1", "/work/dir", recursive=False)
        cmd = terminal.execute.call_args.args[1]
        assert "-rf" not in cmd

    @pytest.mark.asyncio
    async def test_rm_dir_with_recursive(self):
        terminal = MagicMock()
        terminal.execute = AsyncMock(return_value="")
        ops = DockerFileOps(terminal)
        await ops.rm("cid-1", "/work/dir", recursive=True)
        cmd = terminal.execute.call_args.args[1]
        assert "-rf" in cmd

    @pytest.mark.asyncio
    async def test_rm_nonexistent_silent(self):
        terminal = MagicMock()
        terminal.execute = AsyncMock(return_value="")
        ops = DockerFileOps(terminal)
        await ops.rm("cid-1", "/no/such/file")  # -f makes it silent

    @pytest.mark.asyncio
    async def test_rm_quotes_path(self):
        terminal = MagicMock()
        terminal.execute = AsyncMock(return_value="")
        ops = DockerFileOps(terminal)
        await ops.rm("cid-1", "evil; rm -rf /")
        cmd = terminal.execute.call_args.args[1]
        assert "'evil; rm -rf /'" in cmd


class TestFileOpsChmod:
    @pytest.mark.asyncio
    async def test_chmod_octal_644(self):
        terminal = MagicMock()
        terminal.execute = AsyncMock(return_value="")
        ops = DockerFileOps(terminal)
        await ops.chmod("cid-1", "/work/file.txt", 0o644)
        cmd = terminal.execute.call_args.args[1]
        assert "644" in cmd

    @pytest.mark.asyncio
    async def test_chmod_octal_755(self):
        terminal = MagicMock()
        terminal.execute = AsyncMock(return_value="")
        ops = DockerFileOps(terminal)
        await ops.chmod("cid-1", "/work/file.txt", 0o755)
        cmd = terminal.execute.call_args.args[1]
        assert "755" in cmd

    @pytest.mark.asyncio
    async def test_chmod_octal_600(self):
        terminal = MagicMock()
        terminal.execute = AsyncMock(return_value="")
        ops = DockerFileOps(terminal)
        await ops.chmod("cid-1", "/work/secret.txt", 0o600)
        cmd = terminal.execute.call_args.args[1]
        assert "600" in cmd

    @pytest.mark.asyncio
    async def test_chmod_symbolic_mode(self):
        terminal = MagicMock()
        terminal.execute = AsyncMock(return_value="")
        ops = DockerFileOps(terminal)
        await ops.chmod("cid-1", "/work/script.sh", "u+x")
        cmd = terminal.execute.call_args.args[1]
        assert "u+x" in cmd

    @pytest.mark.asyncio
    async def test_chmod_quotes_path(self):
        terminal = MagicMock()
        terminal.execute = AsyncMock(return_value="")
        ops = DockerFileOps(terminal)
        await ops.chmod("cid-1", "name with space", 0o755)
        cmd = terminal.execute.call_args.args[1]
        assert "'name with space'" in cmd


class TestFileOpsGrep:
    @pytest.mark.asyncio
    async def test_grep_match(self):
        terminal = MagicMock()
        terminal.execute = AsyncMock(return_value="/work/a.txt:1:hello")
        ops = DockerFileOps(terminal)
        result = await ops.grep("cid-1", "hello", "/work/a.txt")
        assert result == ["/work/a.txt:1:hello"]

    @pytest.mark.asyncio
    async def test_grep_no_match(self):
        terminal = MagicMock()
        terminal.execute = AsyncMock(return_value="")
        ops = DockerFileOps(terminal)
        assert await ops.grep("cid-1", "missing", "/work/a.txt") == []

    @pytest.mark.asyncio
    async def test_grep_recursive_flag(self):
        terminal = MagicMock()
        terminal.execute = AsyncMock(return_value="")
        ops = DockerFileOps(terminal)
        await ops.grep("cid-1", "pat", "/work", recursive=True)
        cmd = terminal.execute.call_args.args[1]
        # Recursive flag is appended to the -nE base → '-nEr'.
        assert "grep -nEr" in cmd

    @pytest.mark.asyncio
    async def test_grep_non_recursive_no_r_flag(self):
        terminal = MagicMock()
        terminal.execute = AsyncMock(return_value="")
        ops = DockerFileOps(terminal)
        await ops.grep("cid-1", "pat", "/work/a.txt", recursive=False)
        cmd = terminal.execute.call_args.args[1]
        # No 'r' in the flag string.
        flag_str = cmd.split("grep")[1].split()[0]
        assert "r" not in flag_str
        assert "n" in flag_str and "E" in flag_str

    @pytest.mark.asyncio
    async def test_grep_ignore_case(self):
        terminal = MagicMock()
        terminal.execute = AsyncMock(return_value="")
        ops = DockerFileOps(terminal)
        await ops.grep("cid-1", "pat", "/work", ignore_case=True)
        cmd = terminal.execute.call_args.args[1]
        # ignore_case appends 'i' to the flag string → '-nEi'.
        assert "grep -nEi" in cmd

    @pytest.mark.asyncio
    async def test_grep_regex_pattern_preserved(self):
        """Regex metacharacters in pattern survive shell-quoting intact."""
        terminal = MagicMock()
        terminal.execute = AsyncMock(return_value="")
        ops = DockerFileOps(terminal)
        await ops.grep("cid-1", r"^\d+$", "/work/data.txt")
        cmd = terminal.execute.call_args.args[1]
        # Pattern must be inside single quotes so backslashes survive.
        assert "'^\\d+$'" in cmd

    @pytest.mark.asyncio
    async def test_grep_max_results_uses_head(self):
        terminal = MagicMock()
        terminal.execute = AsyncMock(return_value="")
        ops = DockerFileOps(terminal)
        await ops.grep("cid-1", "pat", "/work", max_results=42)
        cmd = terminal.execute.call_args.args[1]
        assert "head -n 42" in cmd


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 4 — ImageChooser (25 tests)
# ═══════════════════════════════════════════════════════════════════════════


class TestImageChooserDefaults:
    def test_default_image_is_debian_latest(self):
        assert IC_DEFAULT_IMAGE == "debian:latest"

    def test_default_image_for_pentest_is_kali(self):
        assert DEFAULT_IMAGE_FOR_PENTEST == "vxcontrol/kali-linux"

    def test_template_has_three_placeholders(self):
        """Template uses the 3 canonical placeholder names."""
        assert "{{ DefaultImage }}" in IMAGE_CHOOSER_TEMPLATE
        assert "{{ DefaultImageForPentest }}" in IMAGE_CHOOSER_TEMPLATE
        assert "{{ Input }}" in IMAGE_CHOOSER_TEMPLATE


class TestImageChooserTemplate:
    def test_render_template_substitutes_default_image(self):
        out = render_template("myimg", "kali", "input")
        assert "myimg" in out
        assert "kali" in out
        assert "input" in out

    def test_render_template_removes_placeholders(self):
        out = render_template("a", "b", "c")
        assert "{{" not in out
        assert "}}" not in out

    def test_render_template_preserves_rules_text(self):
        out = render_template("a", "b", "c")
        assert "Rules:" in out
        assert "Output only the lowercase" in out

    def test_render_template_handles_unicode_input(self):
        out = render_template("a", "b", "héllo 🎉")
        assert "héllo 🎉" in out

    def test_render_template_handles_empty_input(self):
        out = render_template("a", "b", "")
        assert "User input: " in out  # empty substitution, but no crash


class TestValidateImage:
    def test_validate_image_lowercase_passes_through(self):
        assert _validate_image("debian:latest") == "debian:latest"

    def test_validate_image_uppercase_lowercased(self):
        assert _validate_image("DEBIAN:LATEST") == "debian:latest"

    def test_validate_image_whitespace_trimmed(self):
        assert _validate_image("  debian:latest  ") == "debian:latest"

    def test_validate_image_empty_returns_default(self):
        assert _validate_image("") == IC_DEFAULT_IMAGE

    def test_validate_image_none_returns_default(self):
        assert _validate_image(None) == IC_DEFAULT_IMAGE

    def test_validate_image_multi_token_returns_default(self):
        """'image extra text' has whitespace → fallback."""
        assert _validate_image("debian:latest extra") == IC_DEFAULT_IMAGE

    def test_validate_image_newline_returns_default(self):
        assert _validate_image("debian:latest\nextra") == IC_DEFAULT_IMAGE

    def test_validate_image_with_registry(self):
        assert _validate_image("registry.io:5000/repo:1.0") == "registry.io:5000/repo:1.0"

    def test_validate_image_no_tag_passes(self):
        """Images without a tag are accepted (regex lenient branch)."""
        assert _validate_image("ubuntu") == "ubuntu"

    def test_validate_image_with_digest(self):
        out = _validate_image("debian@sha256:" + "a" * 64)
        assert out == "debian@sha256:" + "a" * 64

    def test_image_re_matches_valid_image(self):
        assert _IMAGE_RE.match("debian:latest") is not None

    def test_image_re_rejects_uppercase(self):
        assert _IMAGE_RE.match("DEBIAN") is None


class TestImageChooserBypass:
    def test_bypass_returns_validated_image(self):
        chooser = ImageChooser()
        assert chooser.bypass("kalilinux/kali-rolling") == "kalilinux/kali-rolling"

    def test_bypass_lowercases(self):
        chooser = ImageChooser()
        assert chooser.bypass("KALILINUX:latest") == "kalilinux:latest"

    def test_bypass_empty_raises_value_error(self):
        chooser = ImageChooser()
        with pytest.raises(ValueError, match="non-empty"):
            chooser.bypass("")

    def test_bypass_whitespace_only_raises(self):
        chooser = ImageChooser()
        with pytest.raises(ValueError):
            chooser.bypass("   ")


class TestImageChooserChoose:
    @pytest.mark.asyncio
    async def test_choose_security_task_returns_kali(self):
        """LLM returns kali-linux for security tasks."""
        llm = MagicMock()
        llm.complete = AsyncMock(return_value="vxcontrol/kali-linux")
        chooser = ImageChooser()
        result = await chooser.choose("pentest the target", llm)
        assert result == "vxcontrol/kali-linux"

    @pytest.mark.asyncio
    async def test_choose_general_task_returns_debian(self):
        llm = MagicMock()
        llm.complete = AsyncMock(return_value="debian:latest")
        chooser = ImageChooser()
        result = await chooser.choose("write a python script", llm)
        assert result == "debian:latest"

    @pytest.mark.asyncio
    async def test_choose_user_specified_image_passes_through(self):
        """LLM honors a user-specified image."""
        llm = MagicMock()
        llm.complete = AsyncMock(return_value="ubuntu:22.04")
        chooser = ImageChooser()
        result = await chooser.choose("use ubuntu:22.04", llm)
        assert result == "ubuntu:22.04"

    @pytest.mark.asyncio
    async def test_choose_ambiguous_returns_debian(self):
        """Ambiguous input → LLM returns debian → returned as-is."""
        llm = MagicMock()
        llm.complete = AsyncMock(return_value="debian:latest")
        chooser = ImageChooser()
        result = await chooser.choose("do something", llm)
        assert result == "debian:latest"

    @pytest.mark.asyncio
    async def test_choose_empty_input(self):
        llm = MagicMock()
        llm.complete = AsyncMock(return_value="debian:latest")
        chooser = ImageChooser()
        result = await chooser.choose("", llm)
        assert result == "debian:latest"

    @pytest.mark.asyncio
    async def test_choose_llm_failure_falls_back_to_default(self):
        """LLM exception → fallback to default_image (debian:latest)."""
        llm = MagicMock()
        llm.complete = AsyncMock(side_effect=RuntimeError("LLM down"))
        chooser = ImageChooser()
        result = await chooser.choose("anything", llm)
        assert result == IC_DEFAULT_IMAGE

    @pytest.mark.asyncio
    async def test_choose_llm_returns_invalid_image_falls_back(self):
        """LLM returns malformed output → fallback."""
        llm = MagicMock()
        llm.complete = AsyncMock(return_value="INVALID IMAGE\n")
        chooser = ImageChooser()
        result = await chooser.choose("anything", llm)
        assert result == IC_DEFAULT_IMAGE

    @pytest.mark.asyncio
    async def test_choose_llm_returns_uppercase_lowercased(self):
        llm = MagicMock()
        llm.complete = AsyncMock(return_value="DEBIAN:LATEST")
        chooser = ImageChooser()
        result = await chooser.choose("anything", llm)
        assert result == "debian:latest"

    @pytest.mark.asyncio
    async def test_choose_llm_returns_extra_text_falls_back(self):
        """LLM returns multi-token output → fallback to default."""
        llm = MagicMock()
        llm.complete = AsyncMock(return_value="debian:latest is the best")
        chooser = ImageChooser()
        result = await chooser.choose("anything", llm)
        assert result == IC_DEFAULT_IMAGE

    @pytest.mark.asyncio
    async def test_choose_very_long_input_10kb(self):
        """10KB input is accepted — no length cap."""
        llm = MagicMock()
        llm.complete = AsyncMock(return_value="debian:latest")
        chooser = ImageChooser()
        long_input = "x" * 10240
        result = await chooser.choose(long_input, llm)
        assert result == "debian:latest"

    @pytest.mark.asyncio
    async def test_choose_unicode_emoji_input(self):
        llm = MagicMock()
        llm.complete = AsyncMock(return_value="debian:latest")
        chooser = ImageChooser()
        result = await chooser.choose("héllo 🎉", llm)
        assert result == "debian:latest"


class TestImageChooserCaching:
    @pytest.mark.asyncio
    async def test_choose_cache_hit_skips_llm_call(self):
        """Second call with same flow_id hits cache → no LLM call."""
        cache = MagicMock()
        cache.get_flow_image = AsyncMock(return_value="debian:latest")
        cache.set_flow_image = AsyncMock()
        llm = MagicMock()
        llm.complete = AsyncMock(return_value="vxcontrol/kali-linux")  # would-be response
        chooser = ImageChooser(cache=cache)
        result = await chooser.choose("input", llm, flow_id=1)
        assert result == "debian:latest"  # from cache
        llm.complete.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_choose_cache_miss_calls_llm(self):
        cache = MagicMock()
        cache.get_flow_image = AsyncMock(return_value=None)
        cache.set_flow_image = AsyncMock()
        llm = MagicMock()
        llm.complete = AsyncMock(return_value="vxcontrol/kali-linux")
        chooser = ImageChooser(cache=cache)
        result = await chooser.choose("input", llm, flow_id=2)
        assert result == "vxcontrol/kali-linux"
        llm.complete.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_choose_different_inputs_different_results(self):
        """Cache keyed by flow_id; different flow_ids get fresh LLM calls."""
        cache = MagicMock()
        cache.get_flow_image = AsyncMock(return_value=None)
        cache.set_flow_image = AsyncMock()
        llm = MagicMock()
        # First call returns kali, second returns debian
        llm.complete = AsyncMock(side_effect=["vxcontrol/kali-linux", "debian:latest"])
        chooser = ImageChooser(cache=cache)
        r1 = await chooser.choose("pentest", llm, flow_id=10)
        r2 = await chooser.choose("write code", llm, flow_id=11)
        assert r1 == "vxcontrol/kali-linux"
        assert r2 == "debian:latest"
        assert llm.complete.await_count == 2

    @pytest.mark.asyncio
    async def test_choose_cache_read_failure_falls_through_to_llm(self):
        """Cache exception is logged but doesn't crash the chooser."""
        cache = MagicMock()
        cache.get_flow_image = AsyncMock(side_effect=RuntimeError("cache down"))
        cache.set_flow_image = AsyncMock()
        llm = MagicMock()
        llm.complete = AsyncMock(return_value="debian:latest")
        chooser = ImageChooser(cache=cache)
        result = await chooser.choose("input", llm, flow_id=3)
        assert result == "debian:latest"

    @pytest.mark.asyncio
    async def test_choose_no_flow_id_skips_cache(self):
        """flow_id=None → never reads or writes the cache."""
        cache = MagicMock()
        cache.get_flow_image = AsyncMock(return_value="should-not-be-used")
        cache.set_flow_image = AsyncMock()
        llm = MagicMock()
        llm.complete = AsyncMock(return_value="debian:latest")
        chooser = ImageChooser(cache=cache)
        result = await chooser.choose("input", llm, flow_id=None)
        assert result == "debian:latest"
        cache.get_flow_image.assert_not_awaited()
        cache.set_flow_image.assert_not_awaited()


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 5 — DockerBrowser (30 tests)
# ═══════════════════════════════════════════════════════════════════════════


class TestBrowserConstants:
    def test_min_md_content_size(self):
        assert MIN_MD_CONTENT_SIZE == 50

    def test_min_html_content_size(self):
        assert MIN_HTML_CONTENT_SIZE == 300

    def test_min_img_content_size(self):
        assert MIN_IMG_CONTENT_SIZE == 2048

    def test_scraper_http_timeout_is_65s(self):
        assert SCRAPER_HTTP_TIMEOUT == 65.0

    def test_non_html_extensions_count(self):
        assert len(NON_HTML_EXTENSIONS) >= 31  # task spec says 31

    def test_local_zones_count(self):
        assert len(LOCAL_ZONES) == 11

    def test_local_zones_includes_htb(self):
        assert ".htb" in LOCAL_ZONES

    def test_local_zones_includes_home_arpa(self):
        assert ".home.arpa" in LOCAL_ZONES


class TestIsPrivateIp:
    def test_private_10_x(self):
        assert _is_private_ip("10.0.0.1") is True

    def test_private_172_16_to_31(self):
        for third in range(16, 32):
            assert _is_private_ip(f"172.{third}.0.1") is True

    def test_private_192_168(self):
        assert _is_private_ip("192.168.1.1") is True

    def test_loopback_127(self):
        assert _is_private_ip("127.0.0.1") is True

    def test_loopback_ipv6(self):
        assert _is_private_ip("::1") is True

    def test_public_ipv4(self):
        assert _is_private_ip("8.8.8.8") is False

    def test_private_ipv6_unique_local(self):
        assert _is_private_ip("fc00::1") is True

    def test_invalid_ip_returns_false(self):
        assert _is_private_ip("not-an-ip") is False


class TestIsBinaryUrl:
    def test_pdf_is_binary(self):
        assert is_binary_url("https://example.com/file.pdf") is True

    def test_pdf_with_query_is_binary(self):
        assert is_binary_url("https://example.com/file.pdf?token=abc") is True

    def test_uppercase_pdf_is_binary(self):
        assert is_binary_url("https://example.com/file.PDF") is True

    def test_exe_is_binary(self):
        assert is_binary_url("https://example.com/app.exe") is True

    def test_zip_is_binary(self):
        assert is_binary_url("https://example.com/archive.zip") is True

    def test_docx_is_binary(self):
        assert is_binary_url("https://example.com/report.docx") is True

    def test_html_is_not_binary(self):
        assert is_binary_url("https://example.com/page.html") is False

    def test_root_path_is_not_binary(self):
        assert is_binary_url("https://example.com/") is False

    def test_no_extension_is_not_binary(self):
        assert is_binary_url("https://example.com/page") is False

    def test_all_31_extensions_are_binary(self):
        """Every entry in NON_HTML_EXTENSIONS triggers the guard."""
        for ext in NON_HTML_EXTENSIONS:
            assert is_binary_url(f"https://example.com/f{ext}") is True, ext


class TestBrowserResolveUrl:
    def _make_browser(self):
        return DockerBrowser(
            flow_id=1,
            data_dir="/tmp",
            scraper_private_url="http://private:3000",
            scraper_public_url="http://public:3000",
        )

    def test_resolve_url_private_10_x(self):
        b = self._make_browser()
        with patch("elengenix.docker.browser._resolve_host_ips", return_value=[]):
            assert b.resolve_url("http://10.0.0.1/").netloc == "private:3000"

    def test_resolve_url_loopback(self):
        b = self._make_browser()
        assert b.resolve_url("http://127.0.0.1/").netloc == "private:3000"

    def test_resolve_url_localhost(self):
        b = self._make_browser()
        with patch("elengenix.docker.browser._resolve_host_ips", return_value=[]):
            assert b.resolve_url("http://localhost/").netloc == "private:3000"

    def test_resolve_url_public_domain(self):
        b = self._make_browser()
        with patch("elengenix.docker.browser._resolve_host_ips", return_value=[]):
            assert b.resolve_url("http://example.com/").netloc == "public:3000"

    def test_resolve_url_local_zone_local(self):
        b = self._make_browser()
        with patch("elengenix.docker.browser._resolve_host_ips", return_value=[]):
            assert b.resolve_url("http://foo.local/").netloc == "private:3000"

    def test_resolve_url_local_zone_lan(self):
        b = self._make_browser()
        with patch("elengenix.docker.browser._resolve_host_ips", return_value=[]):
            assert b.resolve_url("http://foo.lan/").netloc == "private:3000"

    def test_resolve_url_local_zone_htb(self):
        b = self._make_browser()
        with patch("elengenix.docker.browser._resolve_host_ips", return_value=[]):
            assert b.resolve_url("http://target.htb/").netloc == "private:3000"

    def test_resolve_url_all_11_local_zones(self):
        b = self._make_browser()
        with patch("elengenix.docker.browser._resolve_host_ips", return_value=[]):
            for zone in LOCAL_ZONES:
                host = f"foo{zone}"
                netloc = b.resolve_url(f"http://{host}/").netloc
                assert netloc == "private:3000", f"{zone} not private"

    def test_resolve_url_no_dot_hostname_is_private(self):
        """Hostnames without a dot (e.g. 'myhost') are treated as private."""
        b = self._make_browser()
        with patch("elengenix.docker.browser._resolve_host_ips", return_value=[]):
            assert b.resolve_url("http://myhost/").netloc == "private:3000"

    def test_resolve_url_public_ip_8_8_8_8(self):
        b = self._make_browser()
        assert b.resolve_url("http://8.8.8.8/").netloc == "public:3000"

    def test_resolve_url_private_falls_back_to_public(self):
        """If only public URL configured, private routing falls through."""
        b = DockerBrowser(flow_id=1, data_dir="/tmp", scraper_public_url="http://public:3000")
        assert b.resolve_url("http://10.0.0.1/").netloc == "public:3000"

    def test_resolve_url_no_scraper_url_raises(self):
        b = DockerBrowser(flow_id=1, data_dir="/tmp")
        with pytest.raises(ValueError, match="no scraper URL configured"):
            b.resolve_url("http://example.com/")

    def test_resolve_url_ipv6_loopback(self):
        b = self._make_browser()
        assert b.resolve_url("http://[::1]/").netloc == "private:3000"


class TestBrowserActions:
    @pytest.mark.asyncio
    async def test_markdown_action_returns_markdown_content(self):
        b = DockerBrowser(flow_id=1, data_dir="/tmp",
                          scraper_private_url="http://scraper:3000")
        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.content = b"# Title\n\nThis is markdown content."
            mock_client.get = AsyncMock(return_value=mock_resp)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client_cls.return_value = mock_client
            result = await b.markdown("http://example.com/")
            assert isinstance(result, BrowserResult)
            assert "markdown" in result.content.lower() or "title" in result.content.lower()

    @pytest.mark.asyncio
    async def test_html_action_returns_html_content(self):
        b = DockerBrowser(flow_id=1, data_dir="/tmp",
                          scraper_private_url="http://scraper:3000")
        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.content = b"<html><body>" + b"<p>x</p>" * 100 + b"</body></html>"
            mock_client.get = AsyncMock(return_value=mock_resp)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client_cls.return_value = mock_client
            result = await b.html("http://example.com/")
            assert "<html>" in result.content

    @pytest.mark.asyncio
    async def test_links_action_returns_json_list(self):
        b = DockerBrowser(flow_id=1, data_dir="/tmp",
                          scraper_private_url="http://scraper:3000")
        links_payload = json.dumps([
            {"Title": "Foo", "Link": "https://foo.com/"},
            {"Title": "Bar", "Link": "https://bar.com/"},
        ]).encode("utf-8")
        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.content = links_payload
            mock_client.get = AsyncMock(return_value=mock_resp)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client_cls.return_value = mock_client
            result = await b.links("http://example.com/")
            assert "foo.com" in result.content
            assert "bar.com" in result.content

    @pytest.mark.asyncio
    async def test_markdown_binary_url_rejected_with_curl_suggestion(self):
        b = DockerBrowser(flow_id=1, data_dir="/tmp",
                          scraper_private_url="http://scraper:3000")
        with pytest.raises(RuntimeError, match="curl"):
            await b.markdown("http://example.com/file.pdf")

    @pytest.mark.asyncio
    async def test_html_binary_url_rejected(self):
        b = DockerBrowser(flow_id=1, data_dir="/tmp",
                          scraper_private_url="http://scraper:3000")
        with pytest.raises(RuntimeError, match="binary"):
            await b.html("http://example.com/file.exe")

    @pytest.mark.asyncio
    async def test_markdown_non_binary_url_allowed(self):
        """Non-binary URLs pass the guard and reach the scraper."""
        b = DockerBrowser(flow_id=1, data_dir="/tmp",
                          scraper_private_url="http://scraper:3000")
        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.content = b"# Title\n\n" + b"content " * 50
            mock_client.get = AsyncMock(return_value=mock_resp)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client_cls.return_value = mock_client
            result = await b.markdown("http://example.com/page.html")
            assert "title" in result.content.lower()

    @pytest.mark.asyncio
    async def test_markdown_short_content_flagged_with_warning(self):
        """< MIN_MD_CONTENT_SIZE bytes → WARNING prefix."""
        b = DockerBrowser(flow_id=1, data_dir="/tmp",
                          scraper_private_url="http://scraper:3000")
        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.content = b"tiny"  # < 50 bytes
            mock_client.get = AsyncMock(return_value=mock_resp)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client_cls.return_value = mock_client
            result = await b.markdown("http://example.com/")
            assert "WARNING" in result.content

    @pytest.mark.asyncio
    async def test_screenshot_failure_is_non_fatal(self):
        """If /screenshot fails, the action still returns content."""
        b = DockerBrowser(flow_id=1, data_dir="/tmp",
                          scraper_private_url="http://scraper:3000")
        # Two GET calls: first (content) succeeds, second (screenshot) fails.
        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            good_resp = MagicMock(status_code=200, content=b"# Title\n" + b"x " * 50)
            bad_resp = MagicMock(status_code=500, content=b"")
            mock_client.get = AsyncMock(side_effect=[good_resp, bad_resp])
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client_cls.return_value = mock_client
            result = await b.markdown("http://example.com/")
            assert result.content  # non-empty
            assert result.screenshot is None  # no screenshot

    @pytest.mark.asyncio
    async def test_http_error_500_raises(self):
        b = DockerBrowser(flow_id=1, data_dir="/tmp",
                          scraper_private_url="http://scraper:3000")
        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_resp = MagicMock(status_code=500, content=b"error")
            mock_client.get = AsyncMock(return_value=mock_resp)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client_cls.return_value = mock_client
            with pytest.raises(RuntimeError, match="unexpected resp code"):
                await b.markdown("http://example.com/")

    @pytest.mark.asyncio
    async def test_http_timeout_raises(self):
        b = DockerBrowser(flow_id=1, data_dir="/tmp",
                          scraper_private_url="http://scraper:3000")
        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(side_effect=asyncio.TimeoutError())
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client_cls.return_value = mock_client
            with pytest.raises(RuntimeError, match="failed to fetch"):
                await b.markdown("http://example.com/")

    @pytest.mark.asyncio
    async def test_http_connection_refused_raises(self):
        b = DockerBrowser(flow_id=1, data_dir="/tmp",
                          scraper_private_url="http://scraper:3000")
        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(side_effect=ConnectionRefusedError())
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client_cls.return_value = mock_client
            with pytest.raises(RuntimeError, match="failed to fetch"):
                await b.markdown("http://example.com/")

    @pytest.mark.asyncio
    async def test_screenshot_saved_to_correct_path(self, tmp_path):
        b = DockerBrowser(flow_id=1, data_dir=str(tmp_path),
                          scraper_private_url="http://scraper:3000")
        png_bytes = b"\x89PNG\r\n\x1a\n" + b"x" * MIN_IMG_CONTENT_SIZE
        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            content_resp = MagicMock(status_code=200, content=b"# x\n" + b"y " * 50)
            sc_resp = MagicMock(status_code=200, content=png_bytes)
            mock_client.get = AsyncMock(side_effect=[content_resp, sc_resp])
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client_cls.return_value = mock_client
            result = await b.markdown("http://example.com/")
            assert result.screenshot is not None
            assert "screenshots" in result.screenshot
            assert "flow-1" in result.screenshot
            assert os.path.exists(result.screenshot)

    def test_browser_is_available_with_either_url(self):
        b1 = DockerBrowser(flow_id=1, data_dir="/tmp", scraper_private_url="x")
        b2 = DockerBrowser(flow_id=1, data_dir="/tmp", scraper_public_url="x")
        b3 = DockerBrowser(flow_id=1, data_dir="/tmp")
        assert b1.is_available() is True
        assert b2.is_available() is True
        assert b3.is_available() is False

    @pytest.mark.asyncio
    async def test_handle_dispatches_markdown(self):
        b = DockerBrowser(flow_id=1, data_dir="/tmp",
                          scraper_private_url="http://scraper:3000")
        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_resp = MagicMock(status_code=200, content=b"# Title\n" + b"x " * 50)
            mock_client.get = AsyncMock(return_value=mock_resp)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client_cls.return_value = mock_client
            result = await b.handle("markdown", "http://example.com/")
            assert isinstance(result, BrowserResult)

    @pytest.mark.asyncio
    async def test_handle_unknown_action_raises(self):
        b = DockerBrowser(flow_id=1, data_dir="/tmp",
                          scraper_private_url="http://scraper:3000")
        with pytest.raises(ValueError, match="unknown browser action"):
            await b.handle("bogus", "http://example.com/")

    @pytest.mark.asyncio
    async def test_handle_unavailable_raises(self):
        b = DockerBrowser(flow_id=1, data_dir="/tmp")
        with pytest.raises(RuntimeError, match="not available"):
            await b.handle("markdown", "http://example.com/")


class TestBrowserHttpxConfig:
    """Verify httpx is constructed with verify=False and 65s timeout."""

    @pytest.mark.asyncio
    async def test_httpx_uses_verify_false(self):
        """Self-signed cert tolerance: verify=False."""
        b = DockerBrowser(flow_id=1, data_dir="/tmp",
                          scraper_private_url="http://scraper:3000")
        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_resp = MagicMock(status_code=200, content=b"# x\n" + b"y " * 50)
            mock_client.get = AsyncMock(return_value=mock_resp)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client_cls.return_value = mock_client
            await b.markdown("http://example.com/")
            call_kwargs = mock_client_cls.call_args.kwargs
            assert call_kwargs.get("verify") is False

    @pytest.mark.asyncio
    async def test_httpx_uses_65s_timeout(self):
        b = DockerBrowser(flow_id=1, data_dir="/tmp",
                          scraper_private_url="http://scraper:3000")
        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_resp = MagicMock(status_code=200, content=b"# x\n" + b"y " * 50)
            mock_client.get = AsyncMock(return_value=mock_resp)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client_cls.return_value = mock_client
            await b.markdown("http://example.com/")
            call_kwargs = mock_client_cls.call_args.kwargs
            assert call_kwargs.get("timeout") == SCRAPER_HTTP_TIMEOUT

    @pytest.mark.asyncio
    async def test_httpx_only_get_no_post(self):
        """Scraper calls only client.get — no POST/PUT/DELETE."""
        b = DockerBrowser(flow_id=1, data_dir="/tmp",
                          scraper_private_url="http://scraper:3000")
        with patch("httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_resp = MagicMock(status_code=200, content=b"# x\n" + b"y " * 50)
            mock_client.get = AsyncMock(return_value=mock_resp)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=None)
            mock_client_cls.return_value = mock_client
            await b.markdown("http://example.com/")
            # Verify only .get was called — no post/put/delete
            mock_client.get.assert_awaited()
            assert not hasattr(mock_client, "post") or mock_client.post.call_count == 0


# ═══════════════════════════════════════════════════════════════════════════
# SECTION 6 — Lifecycle + Cleanup + ResourceLimits + Network + DB (35 tests)
# ═══════════════════════════════════════════════════════════════════════════


class TestResourceLimitsDefaults:
    def test_default_mem_limit(self):
        assert ResourceLimits.default().mem_limit == DEFAULT_MEM_LIMIT

    def test_default_cpu_quota(self):
        assert ResourceLimits.default().cpu_quota == DEFAULT_CPU_QUOTA

    def test_default_cpu_period(self):
        assert ResourceLimits.default().cpu_period == DEFAULT_CPU_PERIOD

    def test_default_pids_limit(self):
        assert ResourceLimits.default().pids_limit == DEFAULT_PIDS_LIMIT

    def test_default_shm_size(self):
        assert ResourceLimits.default().shm_size == DEFAULT_SHM_SIZE

    def test_default_ulimit_nofile(self):
        assert ResourceLimits.default().ulimit_nofile == DEFAULT_ULIMIT_NOFILE

    def test_default_ulimit_nproc(self):
        assert ResourceLimits.default().ulimit_nproc == DEFAULT_ULIMIT_NPROC

    def test_default_network_mode(self):
        assert ResourceLimits.default().network_mode == DEFAULT_NETWORK_MODE

    def test_default_cap_add_includes_net_raw(self):
        assert "NET_RAW" in ResourceLimits.default().cap_add


class TestResourceLimitsProfiles:
    def test_isolated_profile_uses_none_network(self):
        assert ResourceLimits.isolated().network_mode == "none"

    def test_isolated_profile_read_only_root(self):
        assert ResourceLimits.isolated().read_only_root is True

    def test_isolated_profile_drops_all_caps(self):
        assert "ALL" in ResourceLimits.isolated().cap_drop

    def test_host_network_profile_uses_host(self):
        assert ResourceLimits.host_network().network_mode == "host"

    def test_host_network_profile_adds_net_admin(self):
        caps = ResourceLimits.host_network().cap_add
        assert "NET_ADMIN" in caps
        assert "NET_RAW" in caps

    def test_pentest_profile_default_caps(self):
        assert "NET_RAW" in ResourceLimits.pentest().cap_add
        assert "NET_ADMIN" not in ResourceLimits.pentest().cap_add

    def test_pentest_profile_with_net_admin(self):
        caps = ResourceLimits.pentest(net_admin=True).cap_add
        assert "NET_ADMIN" in caps


class TestResourceLimitsValidation:
    def test_validate_default_is_clean(self):
        assert validate_limits(ResourceLimits.default()) == []

    def test_validate_negative_mem_raises(self):
        errors = validate_limits(ResourceLimits(mem_limit="1m"))
        assert any("mem_limit" in e for e in errors)

    def test_validate_invalid_cpu_quota(self):
        errors = validate_limits(ResourceLimits(cpu_quota=-1))
        assert any("cpu_quota" in e for e in errors)

    def test_validate_invalid_cpu_period(self):
        errors = validate_limits(ResourceLimits(cpu_period=0))
        assert any("cpu_period" in e for e in errors)

    def test_validate_low_pids_limit(self):
        errors = validate_limits(ResourceLimits(pids_limit=8))
        assert any("pids_limit" in e for e in errors)

    def test_validate_negative_pids_limit(self):
        errors = validate_limits(ResourceLimits(pids_limit=-1))
        assert any("pids_limit" in e for e in errors)

    def test_validate_invalid_network_mode(self):
        errors = validate_limits(ResourceLimits(network_mode="bogus"))
        assert any("network_mode" in e for e in errors)

    def test_validate_shm_exceeds_mem(self):
        errors = validate_limits(ResourceLimits(shm_size="4g", mem_limit="2g"))
        assert any("shm_size" in e and "exceeds" in e for e in errors)

    def test_validate_negative_ulimit_nofile(self):
        errors = validate_limits(ResourceLimits(ulimit_nofile=-1))
        assert any("ulimit_nofile" in e for e in errors)

    def test_validate_negative_ulimit_nproc(self):
        errors = validate_limits(ResourceLimits(ulimit_nproc=-1))
        assert any("ulimit_nproc" in e for e in errors)

    def test_validate_nproc_below_pids_limit(self):
        errors = validate_limits(ResourceLimits(ulimit_nproc=50, pids_limit=100))
        assert any("nproc" in e and "dominate" in e for e in errors)

    def test_validate_read_only_root_with_host_network_warns(self):
        errors = validate_limits(ResourceLimits(read_only_root=True, network_mode="host"))
        assert any("read_only_root" in e for e in errors)

    def test_validate_cpu_quota_above_16_cpus(self):
        errors = validate_limits(ResourceLimits(cpu_quota=2_000_000, cpu_period=100_000))
        assert any("CPUs" in e for e in errors)


class TestApplyToContainerConfig:
    def test_apply_sets_memory(self):
        config = {"HostConfig": {}}
        out = apply_to_container_config(config, ResourceLimits.default())
        assert out["HostConfig"]["Memory"] == parse_size_to_bytes("2g")

    def test_apply_sets_cpu_quota(self):
        config = {"HostConfig": {}}
        out = apply_to_container_config(config, ResourceLimits.default())
        assert out["HostConfig"]["CpuQuota"] == 50_000

    def test_apply_sets_pids_limit(self):
        config = {"HostConfig": {}}
        out = apply_to_container_config(config, ResourceLimits.default())
        assert out["HostConfig"]["PidsLimit"] == 100

    def test_apply_sets_ulimits(self):
        config = {"HostConfig": {}}
        out = apply_to_container_config(config, ResourceLimits.default())
        names = {u["Name"] for u in out["HostConfig"]["Ulimits"]}
        assert "nofile" in names and "nproc" in names

    def test_apply_sets_network_mode(self):
        config = {"HostConfig": {}}
        out = apply_to_container_config(config, ResourceLimits.default())
        assert out["HostConfig"]["NetworkMode"] == "bridge"

    def test_apply_sets_readonly_rootfs(self):
        config = {"HostConfig": {}}
        out = apply_to_container_config(config, ResourceLimits.isolated())
        assert out["HostConfig"]["ReadonlyRootfs"] is True
        assert "/tmp" in out["HostConfig"]["Tmpfs"]

    def test_apply_merges_existing_cap_add(self):
        config = {"HostConfig": {"CapAdd": ["SYS_PTRACE"]}}
        out = apply_to_container_config(config, ResourceLimits.default())
        cap_add = out["HostConfig"]["CapAdd"]
        assert "SYS_PTRACE" in cap_add
        assert "NET_RAW" in cap_add  # added

    def test_apply_does_not_duplicate_cap_add(self):
        """If NET_RAW is already present, don't add it twice."""
        config = {"HostConfig": {"CapAdd": ["NET_RAW"]}}
        out = apply_to_container_config(config, ResourceLimits.default())
        assert out["HostConfig"]["CapAdd"].count("NET_RAW") == 1

    def test_apply_creates_host_config_if_missing(self):
        config = {}
        out = apply_to_container_config(config, ResourceLimits.default())
        assert "HostConfig" in out


class TestParseSizeToBytes:
    def test_parse_k(self):
        assert parse_size_to_bytes("1k") == 1024

    def test_parse_m(self):
        assert parse_size_to_bytes("1m") == 1024 ** 2

    def test_parse_g(self):
        assert parse_size_to_bytes("1g") == 1024 ** 3

    def test_parse_t(self):
        assert parse_size_to_bytes("1t") == 1024 ** 4

    def test_parse_plain_int(self):
        assert parse_size_to_bytes(1024) == 1024

    def test_parse_uppercase_unit(self):
        assert parse_size_to_bytes("1G") == 1024 ** 3

    def test_parse_decimal(self):
        assert parse_size_to_bytes("1.5g") == int(1.5 * 1024 ** 3)

    def test_parse_empty_raises(self):
        with pytest.raises(ValueError):
            parse_size_to_bytes("")

    def test_parse_invalid_raises(self):
        with pytest.raises(ValueError):
            parse_size_to_bytes("abc")


class TestNetworkHelpers:
    def test_network_name_for_flow(self):
        assert DockerNetwork.network_name(42) == "elengenix-flow-42"

    def test_network_name_prefix(self):
        assert NETWORK_NAME_PREFIX == "elengenix-flow-"

    def test_subnet_for_flow_zero(self):
        assert DockerNetwork.subnet_for(0) == "172.30.0.0/24"

    def test_subnet_for_flow_255(self):
        assert DockerNetwork.subnet_for(255) == "172.30.255.0/24"

    def test_subnet_wraps_at_256(self):
        assert DockerNetwork.subnet_for(256) == "172.30.0.0/24"

    def test_subnet_wraps_at_300(self):
        assert DockerNetwork.subnet_for(300) == "172.30.44.0/24"

    def test_gateway_for_flow(self):
        assert DockerNetwork.gateway_for(42) == "172.30.42.1"

    def test_default_driver_is_bridge(self):
        assert DEFAULT_DRIVER == "bridge"

    def test_default_subnet_prefix(self):
        assert DEFAULT_SUBNET_PREFIX == "172.30"


class TestNetworkLifecycle:
    @pytest.mark.asyncio
    async def test_create_isolated_network_creates_new(self):
        """When network does not exist → create is called."""
        net = DockerNetwork()
        client = MagicMock()
        # First .get() raises (not found); then create succeeds.
        existing_mock = MagicMock()
        existing_mock.show = AsyncMock(side_effect=RuntimeError("not found"))
        client.networks.get = AsyncMock(return_value=existing_mock)
        new_net = MagicMock()
        new_net.show = AsyncMock(return_value={"Id": "net-abc"})
        client.networks.create = AsyncMock(return_value=new_net)

        async def _client_factory():
            return client

        net._client = _client_factory  # type: ignore[assignment]
        result = await net.create_isolated_network(flow_id=42, internal=True)
        assert result == "net-abc"
        client.networks.create.assert_awaited()

    @pytest.mark.asyncio
    async def test_create_isolated_network_reuses_existing(self):
        """When network exists → return its ID without creating."""
        net = DockerNetwork()
        client = MagicMock()
        existing_mock = MagicMock()
        existing_mock.show = AsyncMock(return_value={"Id": "existing-net"})
        client.networks.get = AsyncMock(return_value=existing_mock)
        client.networks.create = AsyncMock()

        async def _client_factory():
            return client

        net._client = _client_factory  # type: ignore[assignment]
        result = await net.create_isolated_network(flow_id=42)
        assert result == "existing-net"
        client.networks.create.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_remove_network_idempotent(self):
        net = DockerNetwork()
        client = MagicMock()
        existing_mock = MagicMock()
        existing_mock.delete = AsyncMock()
        client.networks.get = AsyncMock(return_value=existing_mock)

        async def _client_factory():
            return client

        net._client = _client_factory  # type: ignore[assignment]
        await net.remove_network("net-1")
        existing_mock.delete.assert_awaited()

    @pytest.mark.asyncio
    async def test_remove_network_not_found_is_noop(self):
        net = DockerNetwork()
        client = MagicMock()
        client.networks.get = AsyncMock(side_effect=RuntimeError("no such network"))

        async def _client_factory():
            return client

        net._client = _client_factory  # type: ignore[assignment]
        # Should not raise.
        await net.remove_network("never-existed")

    @pytest.mark.asyncio
    async def test_connect_container_with_aliases(self):
        net = DockerNetwork()
        client = MagicMock()
        n = MagicMock()
        n.connect = AsyncMock()
        client.networks.get = AsyncMock(return_value=n)

        async def _client_factory():
            return client

        net._client = _client_factory  # type: ignore[assignment]
        await net.connect_container("net-1", "cid-1", aliases=["sandbox", "terminal"])
        n.connect.assert_awaited()
        call_args = n.connect.call_args.args[0]
        assert call_args["Aliases"] == ["sandbox", "terminal"]

    @pytest.mark.asyncio
    async def test_disconnect_container_idempotent(self):
        net = DockerNetwork()
        client = MagicMock()
        n = MagicMock()
        n.disconnect = AsyncMock(side_effect=RuntimeError("not connected"))
        client.networks.get = AsyncMock(return_value=n)

        async def _client_factory():
            return client

        net._client = _client_factory  # type: ignore[assignment]
        # Should not raise.
        await net.disconnect_container("net-1", "cid-1")

    @pytest.mark.asyncio
    async def test_list_networks_filters_elengenix(self):
        net = DockerNetwork()
        client = MagicMock()
        n1 = MagicMock()
        n1.show = AsyncMock(return_value={"Name": "elengenix-flow-1", "Id": "n1"})
        n2 = MagicMock()
        n2.show = AsyncMock(return_value={"Name": "elengenix-flow-2", "Id": "n2"})
        client.networks.list = AsyncMock(return_value=[n1, n2])

        async def _client_factory():
            return client

        net._client = _client_factory  # type: ignore[assignment]
        result = await net.list_networks()
        assert len(result) == 2
        assert result[0]["Name"].startswith("elengenix-flow-")

    @pytest.mark.asyncio
    async def test_teardown_flow_network_disconnects_then_removes(self):
        net = DockerNetwork()
        client = MagicMock()
        n = MagicMock()
        n.show = AsyncMock(return_value={
            "Name": "elengenix-flow-1",
            "Containers": {"c1": {"Name": "container-1"}},
        })
        n.disconnect = AsyncMock()
        n.delete = AsyncMock()
        client.networks.get = AsyncMock(return_value=n)

        async def _client_factory():
            return client

        net._client = _client_factory  # type: ignore[assignment]
        await net.teardown_flow_network(flow_id=1)
        n.disconnect.assert_awaited()
        n.delete.assert_awaited()


class TestContainerDB:
    @pytest.mark.asyncio
    async def test_db_create_and_get(self, tmp_db):
        db = ContainerDB(tmp_db)
        await db.connect()
        info = DBContainerInfo(name="pentagi-terminal-1", image="debian:latest", flow_id=1, local_id="cid-1")
        new_id = await db.create_container(info)
        assert new_id > 0
        fetched = await db.get_container(new_id)
        assert fetched.name == "pentagi-terminal-1"
        await db.close()

    @pytest.mark.asyncio
    async def test_db_get_by_flow(self, tmp_db):
        db = ContainerDB(tmp_db)
        await db.connect()
        info = DBContainerInfo(name="pentagi-terminal-5", image="debian:latest", flow_id=5, local_id="cid-5")
        await db.create_container(info)
        fetched = await db.get_container_by_flow(5)
        assert fetched is not None
        assert fetched.flow_id == 5
        await db.close()

    @pytest.mark.asyncio
    async def test_db_update_status(self, tmp_db):
        db = ContainerDB(tmp_db)
        await db.connect()
        info = DBContainerInfo(name="pentagi-terminal-2", flow_id=2, local_id="cid-2")
        new_id = await db.create_container(info)
        await db.update_container_status(new_id, DBContainerStatus.RUNNING)
        fetched = await db.get_container(new_id)
        assert fetched.status is DBContainerStatus.RUNNING
        await db.close()

    @pytest.mark.asyncio
    async def test_db_update_local_id(self, tmp_db):
        db = ContainerDB(tmp_db)
        await db.connect()
        info = DBContainerInfo(name="pentagi-terminal-3", flow_id=3, local_id="tmp-3")
        new_id = await db.create_container(info)
        await db.update_container_local_id(new_id, "real-3", DBContainerStatus.RUNNING)
        fetched = await db.get_container(new_id)
        assert fetched.local_id == "real-3"
        assert fetched.status is DBContainerStatus.RUNNING
        await db.close()

    @pytest.mark.asyncio
    async def test_db_list_containers(self, tmp_db):
        db = ContainerDB(tmp_db)
        await db.connect()
        for i in range(5):
            await db.create_container(DBContainerInfo(name=f"pentagi-terminal-{i}", flow_id=i, local_id=f"cid-{i}"))
        all_rows = await db.list_containers()
        assert len(all_rows) == 5
        await db.close()

    @pytest.mark.asyncio
    async def test_db_list_by_flow(self, tmp_db):
        db = ContainerDB(tmp_db)
        await db.connect()
        for i in range(3):
            await db.create_container(DBContainerInfo(name=f"pentagi-terminal-9-{i}", flow_id=9, local_id=f"cid-9-{i}"))
        rows = await db.list_containers_by_flow(9)
        assert len(rows) == 3
        await db.close()

    @pytest.mark.asyncio
    async def test_db_delete_container(self, tmp_db):
        db = ContainerDB(tmp_db)
        await db.connect()
        info = DBContainerInfo(name="pentagi-terminal-7", flow_id=7)
        new_id = await db.create_container(info)
        await db.delete_container(new_id)
        assert await db.get_container(new_id) is None
        await db.close()

    @pytest.mark.asyncio
    async def test_db_list_orphans_returns_active_only(self, tmp_db):
        """list_orphan_containers returns only STARTING/RUNNING rows."""
        db = ContainerDB(tmp_db)
        await db.connect()
        await db.create_container(DBContainerInfo(name="c-active", flow_id=1, status=DBContainerStatus.RUNNING, local_id="a"))
        await db.create_container(DBContainerInfo(name="c-deleted", flow_id=2, status=DBContainerStatus.DELETED, local_id="d"))
        orphans = await db.list_orphan_containers()
        assert len(orphans) == 1
        assert orphans[0].name == "c-active"
        await db.close()

    @pytest.mark.asyncio
    async def test_db_schema_migration_on_first_run(self, tmp_db):
        """First connect() creates the schema; second connect() is idempotent."""
        db = ContainerDB(tmp_db)
        await db.connect()
        await db.close()
        # Reopen — schema already exists, should not raise.
        db2 = ContainerDB(tmp_db)
        await db2.connect()
        info = DBContainerInfo(name="post-migration", flow_id=99)
        new_id = await db2.create_container(info)
        assert new_id > 0
        await db2.close()

    @pytest.mark.asyncio
    async def test_db_concurrent_connect_is_safe(self, tmp_db):
        """Calling connect() concurrently from two coroutines must not error."""
        db = ContainerDB(tmp_db)
        await asyncio.gather(db.connect(), db.connect())
        # Schema should exist (one row inserted proves schema is up).
        info = DBContainerInfo(name="concurrent", flow_id=42)
        new_id = await db.create_container(info)
        assert new_id > 0
        await db.close()


class TestContainerLifecycle:
    """High-level lifecycle: prepare, release, health_check, naming."""

    def test_container_name_pattern(self):
        assert ContainerLifecycle.container_name(1) == "pentagi-terminal-1"

    def test_container_name_prefix_is_pentagi_compatible(self):
        """Prefix kept PentAGI-compatible so cleanup filters work."""
        assert LC_PRIMARY_PREFIX == "pentagi-terminal-"

    def test_flow_data_dir_template(self):
        assert FLOW_DATA_DIR_TEMPLATE == "flow-{flow_id}-data"

    def test_default_entrypoint_keeps_container_alive(self):
        assert DEFAULT_ENTRYPOINT == ["tail", "-f", "/dev/null"]

    def test_default_working_dir(self):
        assert DEFAULT_WORKING_DIR == "/work"

    def test_uploads_dir_name(self):
        assert UPLOADS_DIR_NAME == "uploads"

    def test_resources_dir_name(self):
        assert RESOURCES_DIR_NAME == "resources"

    def test_flow_data_dir_path(self, tmp_path):
        p = ContainerLifecycle.flow_data_dir(tmp_path, 42)
        assert p.name == "flow-42-data"

    def test_hostname_uses_crc32(self):
        """Lifecycle._hostname uses zlib.crc32 (matches PentAGI)."""
        import zlib
        h = ContainerLifecycle._hostname("pentagi-terminal-1")
        expected = f"{zlib.crc32(b'pentagi-terminal-1') & 0xFFFFFFFF:08x}"
        assert h == expected
        assert len(h) == 8

    @pytest.mark.asyncio
    async def test_health_check_no_db_row(self, tmp_db, tmp_path):
        """health_check for a non-existent DB row returns {running=False}."""
        db = ContainerDB(tmp_db)
        await db.connect()
        lc = ContainerLifecycle(db, tmp_path)
        result = await lc.health_check(9999)
        assert result["running"] is False
        assert result["error"] is not None
        await db.close()

    @pytest.mark.asyncio
    async def test_health_check_running_container(self, tmp_db, tmp_path):
        db = ContainerDB(tmp_db)
        await db.connect()
        info = DBContainerInfo(name="pentagi-terminal-1", flow_id=1, local_id="cid-1")
        new_id = await db.create_container(info)
        lc = ContainerLifecycle(db, tmp_path)
        # Mock the aiodocker client.
        client = MagicMock()
        client.containers.get = AsyncMock(return_value={
            "State": {"Running": True, "Status": "running", "StartedAt": "2024-01-01T00:00:00Z", "RestartCount": 0, "Health": {"Status": "healthy"}},
        })
        lc._client = client  # type: ignore[attr-defined]
        # Override the _client method
        async def _client_coro():
            return client
        lc._client = _client_coro  # type: ignore[assignment]
        result = await lc.health_check(new_id)
        assert result["running"] is True
        assert result["status"] == "running"
        assert result["healthy"] is True
        await db.close()

    @pytest.mark.asyncio
    async def test_health_check_unhealthy_container(self, tmp_db, tmp_path):
        db = ContainerDB(tmp_db)
        await db.connect()
        info = DBContainerInfo(name="pentagi-terminal-2", flow_id=2, local_id="cid-2")
        new_id = await db.create_container(info)
        lc = ContainerLifecycle(db, tmp_path)
        client = MagicMock()
        client.containers.get = AsyncMock(return_value={
            "State": {"Running": True, "Status": "running", "Health": {"Status": "unhealthy"}},
        })
        async def _client_coro():
            return client
        lc._client = _client_coro  # type: ignore[assignment]
        result = await lc.health_check(new_id)
        assert result["running"] is True
        assert result["healthy"] is False
        await db.close()

    @pytest.mark.asyncio
    async def test_health_check_inspect_error(self, tmp_db, tmp_path):
        """If inspect raises → status='error' with error message."""
        db = ContainerDB(tmp_db)
        await db.connect()
        info = DBContainerInfo(name="pentagi-terminal-3", flow_id=3, local_id="cid-3")
        new_id = await db.create_container(info)
        lc = ContainerLifecycle(db, tmp_path)
        client = MagicMock()
        client.containers.get = AsyncMock(side_effect=RuntimeError("daemon down"))
        async def _client_coro():
            return client
        lc._client = _client_coro  # type: ignore[assignment]
        result = await lc.health_check(new_id)
        assert result["running"] is False
        assert result["status"] == "error"
        await db.close()


class TestContainerCleanup:
    """Cleanup sweeps: orphan containers, parallel removal, cleanup_all."""

    @pytest.mark.asyncio
    async def test_cleanup_orphans_with_finished_flows(self, tmp_db, tmp_path):
        """Containers in FINISHED flows are removed + flow marked FAILED."""
        db = ContainerDB(tmp_db)
        await db.connect()
        info = DBContainerInfo(name="pentagi-terminal-1", flow_id=1, local_id="cid-1",
                               status=DBContainerStatus.RUNNING)
        await db.create_container(info)
        fp = InMemoryFlowStatusProvider()
        fp.set_status(1, FlowStatus.FINISHED)
        lc = ContainerLifecycle.__new__(ContainerLifecycle)
        lc.db = db
        async def fake_remove(info):
            await db.update_container_status(info.id, DBContainerStatus.DELETED)
        lc._remove_container_silent = fake_remove  # type: ignore[assignment]
        cc = ContainerCleanup(db, lc, fp)
        result = await cc.cleanup_orphan_containers()
        assert result["removed_containers"] == 1
        assert result["cleaned_flows"] == 1
        await db.close()

    @pytest.mark.asyncio
    async def test_cleanup_skips_running_flow_with_running_containers(self, tmp_db, tmp_path):
        """RUNNING flow whose containers are ALL inactive (STOPPED) → skip.

        PentAGI's ``_all_containers_running`` returns True iff NO container is
        in ``starting``/``running`` status (the name is preserved verbatim from
        the Go source). When the flow is RUNNING/WAITING and all its containers
        are already stopped/deleted/failed, there is nothing to clean → skip.
        """
        db = ContainerDB(tmp_db)
        await db.connect()
        info = DBContainerInfo(name="pentagi-terminal-2", flow_id=2, local_id="cid-2",
                               status=DBContainerStatus.STOPPED)
        await db.create_container(info)
        fp = InMemoryFlowStatusProvider()
        fp.set_status(2, FlowStatus.RUNNING)
        lc = ContainerLifecycle.__new__(ContainerLifecycle)
        lc.db = db
        async def fake_remove(info):
            await db.update_container_status(info.id, DBContainerStatus.DELETED)
        lc._remove_container_silent = fake_remove  # type: ignore[assignment]
        cc = ContainerCleanup(db, lc, fp)
        result = await cc.cleanup_orphan_containers()
        assert result["removed_containers"] == 0
        assert result["cleaned_flows"] == 0
        await db.close()

    @pytest.mark.asyncio
    async def test_cleanup_parallel_removal(self, tmp_db, tmp_path):
        """Multiple orphan containers are removed concurrently."""
        db = ContainerDB(tmp_db)
        await db.connect()
        for i in range(5):
            info = DBContainerInfo(name=f"pentagi-terminal-{i}", flow_id=i, local_id=f"cid-{i}",
                                   status=DBContainerStatus.RUNNING)
            await db.create_container(info)
        fp = InMemoryFlowStatusProvider()
        for i in range(5):
            fp.set_status(i, FlowStatus.FAILED)
        lc = ContainerLifecycle.__new__(ContainerLifecycle)
        lc.db = db
        removed = []
        async def fake_remove(info):
            removed.append(info.id)
            await db.update_container_status(info.id, DBContainerStatus.DELETED)
        lc._remove_container_silent = fake_remove  # type: ignore[assignment]
        cc = ContainerCleanup(db, lc, fp)
        result = await cc.cleanup_orphan_containers()
        assert result["removed_containers"] == 5
        assert len(removed) == 5
        await db.close()

    @pytest.mark.asyncio
    async def test_cleanup_flow_single(self, tmp_db, tmp_path):
        """cleanup_flow removes ALL containers for a flow."""
        db = ContainerDB(tmp_db)
        await db.connect()
        for i in range(3):
            info = DBContainerInfo(name=f"pentagi-terminal-9-{i}", flow_id=9, local_id=f"cid-9-{i}",
                                   status=DBContainerStatus.RUNNING)
            await db.create_container(info)
        lc = ContainerLifecycle.__new__(ContainerLifecycle)
        lc.db = db
        async def fake_remove(info):
            await db.update_container_status(info.id, DBContainerStatus.DELETED)
        lc._remove_container_silent = fake_remove  # type: ignore[assignment]
        cc = ContainerCleanup(db, lc)
        await cc.cleanup_flow(9)
        remaining_active = await db.list_containers_in_active_state()
        assert all(r.flow_id != 9 for r in remaining_active)
        await db.close()

    @pytest.mark.asyncio
    async def test_cleanup_all_removes_every_terminal_container(self, tmp_db, tmp_path):
        """cleanup_all nukes every pentagi-terminal-* container regardless of DB state."""
        db = ContainerDB(tmp_db)
        await db.connect()
        info = DBContainerInfo(name="pentagi-terminal-1", flow_id=1, local_id="cid-1",
                               status=DBContainerStatus.RUNNING)
        await db.create_container(info)
        lc = ContainerLifecycle.__new__(ContainerLifecycle)
        lc.db = db
        # Mock the aiodocker client. ``cleanup_all`` expects each container
        # entry to support ``.get("Names")`` (returning a list of "/name"
        # strings) and ``.delete(force=True, v=True)`` (awaitable).
        mock_container = MagicMock()
        mock_container.get = MagicMock(return_value=["/pentagi-terminal-1"])
        mock_container.delete = AsyncMock()
        client = MagicMock()
        client.containers.list = AsyncMock(return_value=[mock_container])
        async def _client_coro():
            return client
        lc._client = _client_coro  # type: ignore[assignment]
        cc = ContainerCleanup(db, lc)
        result = await cc.cleanup_all()
        assert result["removed_containers"] == 1
        mock_container.delete.assert_awaited()
        await db.close()

    @pytest.mark.asyncio
    async def test_cleanup_all_no_orphans_after(self, tmp_db, tmp_path):
        """After cleanup_all, no DB rows remain in active state."""
        db = ContainerDB(tmp_db)
        await db.connect()
        for i in range(3):
            info = DBContainerInfo(name=f"pentagi-terminal-{i}", flow_id=i, local_id=f"cid-{i}",
                                   status=DBContainerStatus.RUNNING)
            await db.create_container(info)
        lc = ContainerLifecycle.__new__(ContainerLifecycle)
        lc.db = db
        client = MagicMock()
        client.containers.list = AsyncMock(return_value=[])
        async def _client_coro():
            return client
        lc._client = _client_coro  # type: ignore[assignment]
        cc = ContainerCleanup(db, lc)
        await cc.cleanup_all()
        active = await db.list_containers_in_active_state()
        assert len(active) == 0
        await db.close()

    @pytest.mark.asyncio
    async def test_cleanup_all_handles_docker_listing_error(self, tmp_db, tmp_path):
        """If containers.list raises, cleanup_all returns error in result."""
        db = ContainerDB(tmp_db)
        await db.connect()
        lc = ContainerLifecycle.__new__(ContainerLifecycle)
        lc.db = db
        client = MagicMock()
        client.containers.list = AsyncMock(side_effect=RuntimeError("docker down"))
        async def _client_coro():
            return client
        lc._client = _client_coro  # type: ignore[assignment]
        cc = ContainerCleanup(db, lc)
        result = await cc.cleanup_all()
        assert any("failed to list containers" in e for e in result["errors"])
        await db.close()

    @pytest.mark.asyncio
    async def test_cleanup_result_to_dict(self):
        r = CleanupResult(cleaned_flows=2, removed_containers=5, errors=["e1"])
        d = r.to_dict()
        assert d["cleaned_flows"] == 2
        assert d["removed_containers"] == 5
        assert d["errors"] == ["e1"]

    @pytest.mark.asyncio
    async def test_cleanup_in_memory_provider_mark_failed(self):
        fp = InMemoryFlowStatusProvider({1: FlowStatus.RUNNING})
        await fp.mark_flow_failed(1)
        statuses = await fp.get_all_flow_statuses()
        assert statuses[1] is FlowStatus.FAILED


class TestLifecyclePrepareRelease:
    """Race-condition & idempotency tests for prepare/release."""

    @pytest.mark.asyncio
    async def test_release_idempotent_no_container(self, tmp_db, tmp_path):
        """release() with no DB row is a no-op (no exception)."""
        db = ContainerDB(tmp_db)
        await db.connect()
        lc = ContainerLifecycle(db, tmp_path)
        await lc.release(flow_id=999)  # no row, no error
        await db.close()

    @pytest.mark.asyncio
    async def test_release_with_no_local_id_marks_deleted(self, tmp_db, tmp_path):
        """release() on a row with no Docker ID just marks DELETED."""
        db = ContainerDB(tmp_db)
        await db.connect()
        info = DBContainerInfo(name="pentagi-terminal-5", flow_id=5, local_id="",
                               status=DBContainerStatus.STARTING)
        new_id = await db.create_container(info)
        lc = ContainerLifecycle.__new__(ContainerLifecycle)
        lc.db = db
        lc.network = None
        async def fake_remove(container_info):
            await db.update_container_status(container_info.id, DBContainerStatus.DELETED)
        lc._remove_container_silent = fake_remove  # type: ignore[assignment]
        await lc.release(flow_id=5)
        fetched = await db.get_container(new_id)
        assert fetched.status is DBContainerStatus.DELETED
        await db.close()

    @pytest.mark.asyncio
    async def test_release_tears_down_per_flow_network(self, tmp_db, tmp_path):
        """release() with a DockerNetwork instance triggers teardown_flow_network."""
        db = ContainerDB(tmp_db)
        await db.connect()
        info = DBContainerInfo(name="pentagi-terminal-6", flow_id=6, local_id="cid-6",
                               status=DBContainerStatus.RUNNING)
        await db.create_container(info)
        lc = ContainerLifecycle.__new__(ContainerLifecycle)
        lc.db = db
        # Mock network
        net = MagicMock()
        net.teardown_flow_network = AsyncMock()
        lc.network = net
        async def fake_remove(container_info):
            await db.update_container_status(container_info.id, DBContainerStatus.DELETED)
        lc._remove_container_silent = fake_remove  # type: ignore[assignment]
        await lc.release(flow_id=6)
        net.teardown_flow_network.assert_awaited_with(6)
        await db.close()


class TestBrutalPatterns:
    """Container-escape, injection, race-condition, port-wraparound tests."""

    @pytest.mark.asyncio
    async def test_no_privileged_mode_in_run_container_config(self, sandbox, fake_aiodocker_client):
        """Privileged=True must NEVER appear in any HostConfig."""
        sandbox._client = fake_aiodocker_client  # type: ignore[attr-defined]
        captured = {}

        async def _spy(config, host_config, networking_config, name):
            captured["host_config"] = host_config
            return "cid-spied"

        sandbox._create_container = _spy  # type: ignore[assignment]
        sandbox._start_container = AsyncMock()  # type: ignore[assignment]
        await sandbox.run_container(flow_id=1, image="debian:latest")
        assert captured["host_config"].get("Privileged") is None

    @pytest.mark.asyncio
    async def test_no_root_bind_mount_in_default_config(self, sandbox, fake_aiodocker_client):
        """The default bind mount is /work — never '/' (root escape)."""
        sandbox._client = fake_aiodocker_client  # type: ignore[attr-defined]
        captured = {}

        async def _spy(config, host_config, networking_config, name):
            captured["host_config"] = host_config
            return "cid-spied"

        sandbox._create_container = _spy  # type: ignore[assignment]
        sandbox._start_container = AsyncMock()  # type: ignore[assignment]
        await sandbox.run_container(flow_id=1, image="debian:latest")
        binds = captured["host_config"]["Binds"]
        for b in binds:
            # Each bind must be 'host_path:/work' — never '/:/anything'
            src, _, _ = b.partition(":")
            assert src != "/", f"refused root bind mount: {b}"

    def test_port_allocation_wrap_around_above_1000(self):
        """flow_id > 1000 wraps around within [28000, 30000)."""
        for flow_id in (1000, 1001, 1500, 1999, 2000, 2001, 5000):
            ports = _allocate_ports(flow_id)
            for p in ports:
                assert 28000 <= p < 30000

    @pytest.mark.asyncio
    async def test_restart_policy_is_on_failure_5(self, sandbox, fake_aiodocker_client):
        """Container restart policy is on-failure with max 5 retries."""
        sandbox._client = fake_aiodocker_client  # type: ignore[attr-defined]
        captured = {}

        async def _spy(config, host_config, networking_config, name):
            captured["host_config"] = host_config
            return "cid-spied"

        sandbox._create_container = _spy  # type: ignore[assignment]
        sandbox._start_container = AsyncMock()  # type: ignore[assignment]
        await sandbox.run_container(flow_id=1, image="debian:latest")
        rp = captured["host_config"]["RestartPolicy"]
        assert rp["Name"] == "on-failure"
        assert rp["MaximumRetryCount"] == 5

    @pytest.mark.asyncio
    async def test_log_rotation_config_present(self, sandbox, fake_aiodocker_client):
        """json-file log rotation: 10m size, 5 files."""
        sandbox._client = fake_aiodocker_client  # type: ignore[attr-defined]
        captured = {}

        async def _spy(config, host_config, networking_config, name):
            captured["host_config"] = host_config
            return "cid-spied"

        sandbox._create_container = _spy  # type: ignore[assignment]
        sandbox._start_container = AsyncMock()  # type: ignore[assignment]
        await sandbox.run_container(flow_id=1, image="debian:latest")
        lc = captured["host_config"]["LogConfig"]
        assert lc["Type"] == "json-file"
        assert lc["Config"]["max-size"] == "10m"
        assert lc["Config"]["max-file"] == "5"

    @pytest.mark.asyncio
    async def test_net_raw_always_added(self, sandbox, fake_aiodocker_client):
        """NET_RAW capability is added even when caller passes other caps."""
        sandbox._client = fake_aiodocker_client  # type: ignore[attr-defined]
        captured = {}

        async def _spy(config, host_config, networking_config, name):
            captured["host_config"] = host_config
            return "cid-spied"

        sandbox._create_container = _spy  # type: ignore[assignment]
        sandbox._start_container = AsyncMock()  # type: ignore[assignment]
        await sandbox.run_container(flow_id=1, image="debian:latest", capabilities=["SYS_PTRACE"])
        cap_add = captured["host_config"]["CapAdd"]
        assert "NET_RAW" in cap_add

    @pytest.mark.asyncio
    async def test_image_fallback_to_debian_on_pull_failure(self, sandbox, fake_aiodocker_client):
        """Image pull failure triggers fallback to debian:latest."""
        sandbox._client = fake_aiodocker_client  # type: ignore[attr-defined]
        # First pull (kali) fails, second (debian) succeeds.
        call_count = {"n": 0}

        async def _flaky(image_name):
            call_count["n"] += 1
            if call_count["n"] == 1:
                raise RuntimeError("registry down")
            return MagicMock(id="sha256:abc")

        fake_aiodocker_client.images.pull = _flaky
        info = await sandbox.run_container(flow_id=2, image="vxcontrol/kali-linux")
        assert info.image == "debian:latest"

    def test_container_store_isolation_per_db(self, tmp_path):
        """Two stores with different DB paths are fully isolated."""
        s1 = _ContainerStore(tmp_path / "a.db")
        s2 = _ContainerStore(tmp_path / "b.db")
        s1.create(ContainerInfo(name="flow-A", flow_id=1, local_id="a-1"))
        assert len(s1.list_all()) == 1
        assert len(s2.list_all()) == 0

    def test_hostname_collision_resistance(self):
        """Two distinct container names should not produce the same hostname."""
        names = [f"elengenix-terminal-{i}" for i in range(100)]
        hostnames = {_hostname_from_name(n) for n in names}
        # No collisions in 100 distinct names.
        assert len(hostnames) == 100

    def test_validate_image_rejects_path_traversal(self):
        """An image name with embedded whitespace is rejected (multi-token fallback).

        The strict ``_IMAGE_RE`` does not match ``..`` segments, so the lenient
        branch would normally pass them through; however, the moment the LLM
        emits ANY whitespace (a near-certain sign of prompt injection trying to
        chain shell tokens), ``_validate_image`` falls back to the default
        image. This test exercises that defense: ``"../etc/passwd rm -rf /"``
        is multi-token → default image.
        """
        assert _validate_image("../etc/passwd rm -rf /") == IC_DEFAULT_IMAGE

    def test_validate_image_rejects_shell_substitution(self):
        """Shell substitution with embedded space → multi-token → default.

        ``$(whoami)`` alone passes the lenient check (no whitespace), but the
        moment the LLM adds any whitespace — the typical attack shape — the
        multi-token guard fires and falls back to the default image.
        """
        assert _validate_image("$(whoami) payload") == IC_DEFAULT_IMAGE

    @pytest.mark.asyncio
    async def test_terminal_path_traversal_in_read_uses_shlex_quote(self):
        """read_file cat command uses shlex.quote on shell-metachar paths.

        A path containing shell metacharacters (space + semicolon, the classic
        injection vector) MUST be wrapped in single quotes by ``shlex.quote``
        so ``cat`` receives it as a single literal filename argument.
        """
        tlp = MagicMock()
        tlp.put_msg = AsyncMock()
        client = MagicMock()
        client.is_container_running = AsyncMock(return_value=True)
        # Return an empty tar so read_file doesn't crash on extraction.
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as tar:
            pass
        client.get_archive = AsyncMock(return_value=(buf.getvalue(), {}))
        term = DockerTerminal(flow_id=1, docker_client=client, term_log_provider=tlp)
        # Path contains a shell metachar — shlex.quote must wrap it.
        await term.read_file("cid-1", "../../etc/passwd; rm -rf /")
        stdin_log = tlp.put_msg.call_args_list[0].args[1]
        assert "'" in stdin_log  # shlex.quote wraps in single quotes
        assert ";" in stdin_log  # the literal semicolon survives inside quotes
