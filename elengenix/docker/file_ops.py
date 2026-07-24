"""elengenix/docker/file_ops.py — Higher-level file operations on top of DockerTerminal.

Provides ``DockerFileOps`` — a small async wrapper that builds common
filesystem primitives (``exists``, ``is_dir``, ``list_dir``, ``mkdir``,
``rm``, ``chmod``, ``grep``) on top of the ``DockerTerminal.execute``
shell-channel primitive. Each method emits a single ``sh -c`` command
with shell-escaped arguments via ``shlex.quote``.
"""

from __future__ import annotations

import logging
import shlex
from typing import TYPE_CHECKING, List, Optional

from .terminal import DockerTerminal, WORK_FOLDER_PATH_IN_CONTAINER

if TYPE_CHECKING:  # pragma: no cover — typing only
    pass

logger = logging.getLogger("elengenix.docker.file_ops")


class DockerFileOps:
    """High-level file operations layered over ``DockerTerminal.execute``.

    Each method issues one ``docker exec`` shell command. All path
    arguments are shell-quoted with ``shlex.quote`` to prevent command
    injection — mirroring the PentAGI convention of never interpolating
    untrusted paths into shell strings.
    """

    def __init__(
        self,
        terminal: DockerTerminal,
        *,
        default_cwd: str = WORK_FOLDER_PATH_IN_CONTAINER,
    ) -> None:
        self.terminal = terminal
        self.default_cwd = default_cwd

    # ── Private helpers ─────────────────────────────────────────────────
    async def _run(
        self,
        container_id: str,
        command: str,
        *,
        cwd: Optional[str] = None,
        timeout: int = 60,
    ) -> str:
        """Run ``command`` and return stripped stdout.

        Failures (non-zero exit / shell errors) surface as RuntimeError
        because the file-op helpers want crisp diagnostics rather than
        the silent-success string the terminal tool returns for empty
        output.
        """
        out = await self.terminal.execute(
            container_id,
            command,
            cwd=cwd or self.default_cwd,
            detach=False,
            timeout=timeout,
        )
        return out

    @staticmethod
    def _quote(path: str) -> str:
        return shlex.quote(path)

    # ── Public API ──────────────────────────────────────────────────────
    async def exists(self, container_id: str, path: str) -> bool:
        """Return True iff ``path`` exists in the container filesystem."""
        cmd = (
            f"if [ -e {self._quote(path)} ]; then echo yes; "
            f"else echo no; fi"
        )
        out = await self._run(container_id, cmd, timeout=10)
        return out.strip().lower().startswith("yes")

    async def is_dir(self, container_id: str, path: str) -> bool:
        """Return True iff ``path`` exists and is a directory."""
        cmd = (
            f"if [ -d {self._quote(path)} ]; then echo yes; "
            f"else echo no; fi"
        )
        out = await self._run(container_id, cmd, timeout=10)
        return out.strip().lower().startswith("yes")

    async def list_dir(self, container_id: str, path: str) -> List[str]:
        """List directory entries (one per line, names only).

        Uses ``ls -1A`` to include dotfiles but exclude ``.``/``..``.
        Returns an empty list for empty directories.
        """
        cmd = f"ls -1A {self._quote(path)} 2>/dev/null"
        out = await self._run(container_id, cmd, timeout=30)
        return [line for line in out.splitlines() if line.strip()]

    async def mkdir(
        self, container_id: str, path: str, *, parents: bool = True, mode: Optional[int] = None,
    ) -> None:
        """Create a directory (``-p`` by default; optional ``mode`` arg)."""
        flag = "-p" if parents else ""
        mode_arg = f"-m {oct(mode)[2:]}" if mode is not None else ""
        parts = [p for p in ("mkdir", flag, mode_arg, self._quote(path)) if p]
        cmd = " ".join(parts)
        await self._run(container_id, cmd, timeout=30)

    async def rm(self, container_id: str, path: str, *, recursive: bool = False) -> None:
        """Remove a file or directory. Use ``recursive=True`` for ``rm -rf``."""
        flag = "-rf" if recursive else "-f"
        cmd = f"rm {flag} {self._quote(path)}"
        await self._run(container_id, cmd, timeout=60)

    async def chmod(self, container_id: str, path: str, mode: int | str) -> None:
        """Change file mode bits. ``mode`` may be int (e.g. ``0o755``) or str (``'u+x'``)."""
        if isinstance(mode, int):
            mode_str = oct(mode)[2:]
        else:
            mode_str = str(mode)
        cmd = f"chmod {mode_str} {self._quote(path)}"
        await self._run(container_id, cmd, timeout=30)

    async def grep(
        self,
        container_id: str,
        pattern: str,
        path: str,
        *,
        recursive: bool = False,
        ignore_case: bool = False,
        max_results: int = 200,
    ) -> List[str]:
        """Run ``grep -n`` (or ``grep -rn``) inside the container.

        Args:
            pattern: Regex/substring to search for (passed as a single
                shell-quoted argument so regex metacharacters survive
                intact).
            path: File or directory to search.
            recursive: Use ``-r`` (recursive directory walk).
            ignore_case: Add ``-i``.
            max_results: Stop after this many matching lines (uses
                ``head -n`` to bound output).

        Returns:
            List of ``path:line_no:matching_line`` strings (matching
            ``grep -n`` default format).
        """
        flags = "-nE"
        if recursive:
            flags += "r"
        if ignore_case:
            flags += "i"
        cmd = (
            f"grep {flags} {self._quote(pattern)} {self._quote(path)} 2>/dev/null "
            f"| head -n {int(max_results)}"
        )
        out = await self._run(container_id, cmd, timeout=120)
        return [line for line in out.splitlines() if line.strip()]


__all__ = ["DockerFileOps"]
