"""elengenix/docker/terminal.py — Docker terminal & file tool ported from PentAGI.

Ports `backend/pkg/tools/terminal.go` (462 lines) to Python. Provides the
`DockerTerminal` class with `execute`, `read_file`, and `write_file` async
methods. All shell escaping uses `shlex.quote()` (replacing Go's
`strings.ReplaceAll(path, "'", "'\"'\"'")` pattern). ANSI colour codes are
preserved verbatim (cyan stdin, green stdout, CRLF line terminator).
"""

from __future__ import annotations

import asyncio
import io
import logging
import os
import shlex
import tarfile
from dataclasses import dataclass
from typing import Any, Optional, Protocol, runtime_checkable

logger = logging.getLogger("elengenix.docker.terminal")

# ── Public constants (ported verbatim from terminal.go) ──────────────────
PRIMARY_TERMINAL_NAME_PREFIX = "pentagi-terminal-"
MAX_EXPLICIT_EXEC_COMMAND_TIMEOUT = 10800  # 3 hours (seconds)
DEFAULT_EXTRA_EXEC_TIMEOUT = 5  # extra cleanup slack (seconds)
DEFAULT_QUICK_CHECK_TIMEOUT = 0.5  # 500 ms quick-check window for detach mode
DEFAULT_SERVER_EXEC_TIMEOUT = 1200  # 20 min server default (env override)
WORK_FOLDER_PATH_IN_CONTAINER = "/work"
MAX_READ_FILE_SIZE = 100 * 1024 * 1024  # 100 MB per file

# ── ANSI terminal colour codes (aligned with PentAGI UI palette) ─────────
ANSI_COLOR_INPUT_CMD = "\033[96m"  # Bright Cyan  — matches UI blue accents
ANSI_COLOR_SYSTEM_MSG = "\033[92m"  # Bright Green — universal success/info
ANSI_COLOR_RESET = "\033[0m"
ANSI_LINE_TERMINATOR = "\r\n"  # CRLF for terminal compatibility


def primary_terminal_name(flow_id: int | str) -> str:
    """Return the canonical container name for a given flow ID."""
    return f"{PRIMARY_TERMINAL_NAME_PREFIX}{flow_id}"


def _truncate_string(s: str, max_len: int) -> str:
    """Truncate a string to ``max_len`` bytes with a size hint suffix."""
    if len(s) <= max_len:
        return s
    return s[:max_len] + f"... [truncated full size is {len(s)} bytes]"


@dataclass
class _ExecResult:
    """Internal exec outcome used by the detach quick-check window."""

    output: str
    error: Optional[Exception] = None


# ── Protocols for dependency injection (zero hard deps at import time) ────
@runtime_checkable
class DockerClientProtocol(Protocol):
    """Async Docker client protocol (satisfied by aiodocker or a shim).

    Methods mirror the subset of the PentAGI ``DockerClient`` interface that
    the terminal tool exercises. Phase 4-a is expected to ship a concrete
    implementation; this Protocol keeps ``terminal.py`` importable in
    isolation.
    """

    async def is_container_running(self, container_lid: str) -> bool: ...

    async def container_exec_create(
        self, container: str, *, cmd: list[str], working_dir: str,
        tty: bool = True, attach_stdout: bool = True, attach_stderr: bool = True,
    ) -> dict[str, Any]: ...

    async def container_exec_start(self, exec_id: str, *, tty: bool = True) -> Any: ...

    async def container_exec_inspect(self, exec_id: str) -> dict[str, Any]: ...

    async def get_archive(self, container: str, path: str) -> tuple[Any, dict[str, Any]]: ...

    async def put_archive(
        self, container: str, path: str, data: bytes,
        *, allow_overwrite_dir_with_file: bool = True,
    ) -> None: ...


@runtime_checkable
class TermLogProviderProtocol(Protocol):
    """Optional terminal-log sink (port of Go ``TermLogProvider``)."""

    async def put_msg(
        self, log_type: str, message: str,
        container_id: Optional[int] = None,
        task_id: Optional[int] = None,
        subtask_id: Optional[int] = None,
    ) -> Any: ...


class _NullTermLog:
    """Default no-op log sink when none is supplied."""

    async def put_msg(self, log_type: str, message: str, *args: Any, **kw: Any) -> None:
        return None


class DockerTerminal:
    """Port of PentAGI ``terminal`` struct (terminal.go) to Python.

    The class wraps an async Docker client (Protocol-injected) and exposes
    three operations: ``execute`` (shell command, with detach/timeout
    semantics), ``read_file`` (TAR-based directory-aware read), and
    ``write_file`` (in-memory TAR + ``put_archive``).
    """

    def __init__(
        self,
        flow_id: int | str,
        docker_client: DockerClientProtocol,
        *,
        container_lid: Optional[str] = None,
        term_log_provider: Optional[TermLogProviderProtocol] = None,
        default_exec_timeout: int = DEFAULT_SERVER_EXEC_TIMEOUT,
        task_id: Optional[int] = None,
        subtask_id: Optional[int] = None,
        container_id: Optional[int] = None,
    ) -> None:
        self.flow_id = flow_id
        self.docker_client = docker_client
        self.container_lid = container_lid or primary_terminal_name(flow_id)
        self.tlp: TermLogProviderProtocol = term_log_provider or _NullTermLog()
        self.default_exec_timeout = default_exec_timeout
        self.task_id = task_id
        self.subtask_id = subtask_id
        self.container_id = container_id

    # ── Availability ────────────────────────────────────────────────────
    def is_available(self) -> bool:
        """Mirror Go ``IsAvailable`` — true when a docker client is wired."""
        return self.docker_client is not None

    # ── Timeout normalisation (verbatim port of terminal.go §75-92) ─────
    def configured_exec_timeout(self) -> int:
        """Server default clamped to ``MAX_EXPLICIT_EXEC_COMMAND_TIMEOUT``."""
        if self.default_exec_timeout <= 0 or self.default_exec_timeout > MAX_EXPLICIT_EXEC_COMMAND_TIMEOUT:
            return MAX_EXPLICIT_EXEC_COMMAND_TIMEOUT
        return self.default_exec_timeout

    def normalize_exec_timeout(self, timeout: int) -> int:
        """Normalise a caller-supplied timeout (0/neg/out-of-range → server default).

        Always adds ``DEFAULT_EXTRA_EXEC_TIMEOUT`` seconds of cleanup slack
        (matches Go ``defaultExtraExecTimeout``).
        """
        server_default = self.configured_exec_timeout() + DEFAULT_EXTRA_EXEC_TIMEOUT
        if 0 < timeout <= server_default:
            return timeout + DEFAULT_EXTRA_EXEC_TIMEOUT
        return server_default

    # ── Execute (port of ExecCommand + getExecResult) ───────────────────
    async def execute(
        self,
        container_id: str,
        command: str,
        cwd: str = WORK_FOLDER_PATH_IN_CONTAINER,
        detach: bool = False,
        timeout: int = 0,
    ) -> str:
        """Run ``command`` inside the container via ``docker exec``.

        Args:
            container_id: Container name or ID (usually
                ``primary_terminal_name(flow_id)``).
            command: Shell command (passed verbatim to ``sh -c``).
            cwd: Working directory (defaults to ``/work``).
            detach: When true, spawn as detached task with a 500 ms
                quick-check window — if it finishes within that window,
                return its output; otherwise return a "started in
                background" notice (port of Go ``context.WithoutCancel``).
            timeout: Seconds. 0/negative → server default; valid range
                1–10800 (3 h). Anything outside is clamped to the server
                default + 5 s cleanup slack.

        Returns:
            Captured stdout/stderr (may be empty for silent success).
        """
        if not self.is_available():
            raise RuntimeError("terminal is not available")

        # Verify container runtime status (Go: IsContainerRunning).
        try:
            is_running = await self.docker_client.is_container_running(self.container_lid)
        except Exception as exc:
            raise RuntimeError(f"runtime verification failed: {exc}") from exc
        if not is_running:
            raise RuntimeError("container runtime is not operational")

        if not cwd:
            cwd = WORK_FOLDER_PATH_IN_CONTAINER

        # Styled stdin log entry (Go: cyan prompt + CRLF).
        styled_command = (
            f"{cwd} $ {ANSI_COLOR_INPUT_CMD}{command}{ANSI_COLOR_RESET}{ANSI_LINE_TERMINATOR}"
        )
        try:
            await self.tlp.put_msg(
                "stdin", styled_command, self.container_id, self.task_id, self.subtask_id
            )
        except Exception as exc:
            logger.warning("failed to put terminal log (stdin): %s", exc)

        effective_timeout = self.normalize_exec_timeout(timeout)

        # Create exec process (Go: ContainerExecCreate with Tty=true).
        try:
            create_resp = await self.docker_client.container_exec_create(
                container_id,
                cmd=["sh", "-c", command],
                working_dir=cwd,
                tty=True,
                attach_stdout=True,
                attach_stderr=True,
            )
        except Exception as exc:
            raise RuntimeError(f"failed to create exec process: {exc}") from exc

        exec_id = create_resp.get("Id") if isinstance(create_resp, dict) else None
        if not exec_id:
            raise RuntimeError(f"exec create returned no Id: {create_resp!r}")

        if detach:
            return await self._execute_detached(exec_id, effective_timeout)

        return await self._get_exec_result(exec_id, effective_timeout)

    async def _execute_detached(self, exec_id: str, timeout: int) -> str:
        """Detach-mode quick-check window (port of terminal.go §216-237).

        Spawns the exec as an ``asyncio.Task`` that does NOT propagate
        cancellation from the parent (Python equivalent of Go's
        ``context.WithoutCancel``). If the task completes within
        ``DEFAULT_QUICK_CHECK_TIMEOUT`` (500 ms), return its output;
        otherwise return a "started in background" notice.
        """
        result_queue: asyncio.Queue[_ExecResult] = asyncio.Queue(maxsize=1)

        async def _runner() -> None:
            try:
                output = await self._get_exec_result(exec_id, timeout)
                await result_queue.put(_ExecResult(output=output, error=None))
            except Exception as exc:  # noqa: BLE001 — capture for parent
                await result_queue.put(_ExecResult(output="", error=exc))

        # Detached task: do NOT cancel on parent cancellation (best-effort).
        task = asyncio.create_task(_runner())
        try:
            result = await asyncio.wait_for(
                result_queue.get(), timeout=DEFAULT_QUICK_CHECK_TIMEOUT
            )
        except asyncio.TimeoutError:
            return (
                f"Command started in background with timeout {timeout}s (still running)"
            )

        if result.error is not None:
            raise RuntimeError(f"command failed: {result.error}: {result.output}")
        if not result.output:
            return "Command completed in background with exit code 0"
        return result.output

    async def _get_exec_result(self, exec_id: str, timeout: int) -> str:
        """Attach to the exec, stream output, enforce timeout (Go §242-308)."""
        try:
            resp = await self.docker_client.container_exec_start(exec_id, tty=True)
        except Exception as exc:
            raise RuntimeError(f"failed to attach to exec process: {exc}") from exc

        # Collect output bytes — caller's docker client may yield an async
        # stream (aiodocker) or a sync binary file (docker SDK); handle both.
        buf = io.BytesIO()

        async def _drain() -> Optional[Exception]:
            try:
                if hasattr(resp, "read"):
                    # Async stream-like reader.
                    read = resp.read
                    if asyncio.iscoroutinefunction(read):
                        while True:
                            chunk = await read(65536)
                            if not chunk:
                                break
                            buf.write(chunk)
                    else:
                        # Sync binary reader — offload to thread.
                        while True:
                            chunk = await asyncio.to_thread(read, 65536)
                            if not chunk:
                                break
                            buf.write(chunk)
                elif hasattr(resp, "__aiter__"):
                    async for chunk in resp:  # type: ignore[union-attr]
                        if chunk:
                            buf.write(chunk if isinstance(chunk, (bytes, bytearray)) else str(chunk).encode())
                else:
                    # Fall back to treating resp as raw bytes.
                    buf.write(resp if isinstance(resp, (bytes, bytearray)) else str(resp).encode())
            except Exception as exc:  # noqa: BLE001
                return exc
            return None

        try:
            if timeout > 0:
                copy_err = await asyncio.wait_for(_drain(), timeout=timeout)
            else:
                copy_err = await _drain()
        except asyncio.TimeoutError:
            suggested = max(int(timeout) - 10, 10)
            partial = _truncate_string(buf.getvalue().decode("utf-8", errors="replace"), 500)
            raise RuntimeError(
                f"command execution timeout (after {timeout}s). Partial output: {partial}. "
                f"HINT: If this is an interactive command (shell/REPL/listener), use detach=true. "
                f"For long batch commands, wrap with shell timeout utility: "
                f"'timeout {suggested} <command>' to ensure clean completion"
            )

        if copy_err is not None and not isinstance(copy_err, (EOFError,)):
            raise RuntimeError(f"failed to copy output: {copy_err}")

        # Wait for the exec process to finish (Go: ContainerExecInspect).
        try:
            await self.docker_client.container_exec_inspect(exec_id)
        except Exception as exc:
            logger.warning("failed to inspect exec process: %s", exc)

        results = buf.getvalue().decode("utf-8", errors="replace")

        # Styled stdout log entry (Go: green output + CRLF).
        styled_output = (
            f"{ANSI_COLOR_SYSTEM_MSG}{results}{ANSI_COLOR_RESET}{ANSI_LINE_TERMINATOR}"
        )
        try:
            await self.tlp.put_msg(
                "stdout", styled_output, self.container_id, self.task_id, self.subtask_id
            )
        except Exception as exc:
            logger.warning("failed to put terminal log (stdout): %s", exc)

        if not results:
            results = (
                "Command completed successfully with exit code 0. "
                "No output produced (silent success)"
            )
        return results

    # ── ReadFile (port of terminal.go §310-390) ─────────────────────────
    async def read_file(self, container_id: str, path: str) -> str:
        """Read a file (or every file in a directory) from the container.

        Uses ``get_archive`` (Docker's ``CopyFromContainer``), which returns
        a TAR stream. Multi-entry TARs are concatenated when the requested
        path is a directory. 100 MB per file hard cap.
        """
        if not self.is_available():
            raise RuntimeError("terminal is not available")

        try:
            is_running = await self.docker_client.is_container_running(self.container_lid)
        except Exception as exc:
            raise RuntimeError(f"runtime verification failed: {exc}") from exc
        if not is_running:
            raise RuntimeError("container runtime is not operational")

        cwd = WORK_FOLDER_PATH_IN_CONTAINER
        cat_command = f"cat {shlex.quote(path)}"
        styled_command = (
            f"{cwd} $ {ANSI_COLOR_INPUT_CMD}{cat_command}{ANSI_COLOR_RESET}{ANSI_LINE_TERMINATOR}"
        )
        try:
            await self.tlp.put_msg(
                "stdin", styled_command, self.container_id, self.task_id, self.subtask_id
            )
        except Exception as exc:
            logger.warning("failed to put terminal log (read file cmd): %s", exc)

        try:
            stream, stats = await self.docker_client.get_archive(container_id, path)
        except Exception as exc:
            raise RuntimeError(f"failed to copy file: {exc}") from exc

        is_dir_stats = isinstance(stats, dict) and isinstance(
            stats.get("mode"), int
        ) and bool(stats["mode"] & 0o040000) if isinstance(stats, dict) else False
        # Some clients return a pathlib.Path-like or os.stat_result — fall
        # back to a "name ends with /" heuristic when mode info is absent.
        if isinstance(stats, dict) and not is_dir_stats and "name" in stats:
            is_dir_stats = str(stats["name"]).endswith("/")

        # Normalise stream to bytes.
        if isinstance(stream, (bytes, bytearray)):
            raw = bytes(stream)
        elif hasattr(stream, "read") and not asyncio.iscoroutinefunction(getattr(stream, "read", None)):
            # Sync file-like object — read in a thread to avoid blocking.
            def _read_all() -> bytes:
                if hasattr(stream, "getvalue"):
                    return stream.getvalue()  # type: ignore[no-any-return]
                return stream.read()  # type: ignore[no-any-return]
            raw = await asyncio.to_thread(_read_all)
        elif hasattr(stream, "read") and asyncio.iscoroutinefunction(stream.read):
            chunks: list[bytes] = []
            while True:
                chunk = await stream.read(65536)
                if not chunk:
                    break
                chunks.append(chunk)
            raw = b"".join(chunks)
        else:
            raw = bytes(stream)  # last-resort coercion

        buffer = io.StringIO()
        tar_input = io.BytesIO(raw)
        try:
            with tarfile.open(fileobj=tar_input, mode="r:*") as tar_reader:
                for member in tar_reader.getmembers():
                    if member.isdir():
                        continue
                    if member.size > MAX_READ_FILE_SIZE:
                        raise RuntimeError(
                            f"file '{member.name}' size {member.size} exceeds "
                            f"maximum allowed size {MAX_READ_FILE_SIZE}"
                        )
                    if member.size < 0:
                        raise RuntimeError(
                            f"file '{member.name}' has invalid size {member.size}"
                        )
                    if is_dir_stats:
                        buffer.write(
                            "--------------------------------------------------\n"
                        )
                        buffer.write(
                            f"'{member.name}' file content (with size "
                            f"{member.size} bytes) shown below:\n"
                        )
                    f = tar_reader.extractfile(member)
                    if f is not None:
                        buffer.write(f.read().decode("utf-8", errors="replace"))
                    if is_dir_stats:
                        buffer.write("\n\n")
        except tarfile.TarError as exc:
            raise RuntimeError(f"failed to read tar header: {exc}") from exc

        content = buffer.getvalue()
        styled_content = (
            f"{ANSI_COLOR_SYSTEM_MSG}{content}{ANSI_COLOR_RESET}{ANSI_LINE_TERMINATOR}"
        )
        try:
            await self.tlp.put_msg(
                "stdout", styled_content, self.container_id, self.task_id, self.subtask_id
            )
        except Exception as exc:
            logger.warning("failed to put terminal log (read file content): %s", exc)

        return content

    # ── WriteFile (port of terminal.go §392-446) ────────────────────────
    async def write_file(self, container_id: str, path: str, content: bytes) -> str:
        """Write ``content`` bytes to ``path`` inside the container.

        Builds an in-memory TAR with a single ``0600`` entry and uploads
        via ``put_archive`` to the file's parent directory with
        ``AllowOverwriteDirWithFile=True``.
        """
        if not self.is_available():
            raise RuntimeError("terminal is not available")

        try:
            is_running = await self.docker_client.is_container_running(self.container_lid)
        except Exception as exc:
            raise RuntimeError(f"container runtime check failed: {exc}") from exc
        if not is_running:
            raise RuntimeError("target container is not operational")

        if isinstance(content, str):
            content = content.encode("utf-8")

        filename = os.path.basename(path.rstrip("/")) or path
        tar_buf = io.BytesIO()
        try:
            with tarfile.open(fileobj=tar_buf, mode="w") as archive:
                info = tarfile.TarInfo(name=filename)
                info.size = len(content)
                info.mode = 0o600
                info.mtime = 0
                archive.addfile(info, io.BytesIO(content))
        except tarfile.TarError as exc:
            raise RuntimeError(f"tar archive generation failed: {exc}") from exc

        dir_path = os.path.dirname(path.rstrip("/")) or "/"
        try:
            await self.docker_client.put_archive(
                container_id, dir_path, tar_buf.getvalue(),
                allow_overwrite_dir_with_file=True,
            )
        except Exception as exc:
            raise RuntimeError(f"container file transfer failed: {exc}") from exc

        success_msg = f"File successfully saved to {path}"
        styled_msg = (
            f"{ANSI_COLOR_SYSTEM_MSG}{success_msg}{ANSI_COLOR_RESET}{ANSI_LINE_TERMINATOR}"
        )
        try:
            await self.tlp.put_msg(
                "stdin", styled_msg, self.container_id, self.task_id, self.subtask_id
            )
        except Exception as exc:
            logger.warning("failed to put terminal log (write file cmd): %s", exc)

        return f"Successfully wrote {len(content)} bytes to {path}"


__all__ = [
    "PRIMARY_TERMINAL_NAME_PREFIX",
    "MAX_EXPLICIT_EXEC_COMMAND_TIMEOUT",
    "DEFAULT_EXTRA_EXEC_TIMEOUT",
    "DEFAULT_QUICK_CHECK_TIMEOUT",
    "DEFAULT_SERVER_EXEC_TIMEOUT",
    "WORK_FOLDER_PATH_IN_CONTAINER",
    "MAX_READ_FILE_SIZE",
    "ANSI_COLOR_INPUT_CMD",
    "ANSI_COLOR_SYSTEM_MSG",
    "ANSI_COLOR_RESET",
    "ANSI_LINE_TERMINATOR",
    "DockerTerminal",
    "DockerClientProtocol",
    "TermLogProviderProtocol",
    "primary_terminal_name",
]
