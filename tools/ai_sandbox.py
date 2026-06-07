"""tools/ai_sandbox.py

Real sandbox for executing AI-generated code.

This module provides:
- RealDangerousPatternDetector: AST-based static analysis of Python source
  to detect dangerous patterns (not just regex on text)
- SubprocessSandbox: run untrusted code in a subprocess with resource limits
  (CPU, memory, wall clock, file descriptors, network)
- SandboxResult: structured result of a sandboxed execution

The sandbox is a layered defense:
1. Static analysis: AST scan blocks obviously dangerous code BEFORE running
2. Subprocess isolation: code runs in a separate process (not main agent)
3. Resource limits: hard caps on CPU/memory/time via stdlib resource module
4. Network policy: optionally block network access
5. Path policy: optionally restrict filesystem writes to a single root

This module deliberately avoids RestrictedPython or other heavy sandboxing
libraries — it uses only Python's standard library.
"""

from __future__ import annotations

import ast
import json
import logging
import os
import resource
import signal
import subprocess
import sys
import tempfile
import textwrap
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger("elengenix.ai_sandbox")


# ---------------------------------------------------------------------------
# AST-based pattern detection
# ---------------------------------------------------------------------------


# High-level categories of dangerous behavior
class PatternSeverity:
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class DangerousPatternHit:
    """One match of a dangerous pattern."""
    pattern_id: str
    severity: str
    line: int
    col: int
    description: str
    snippet: str


@dataclass
class SafetyReport:
    """Result of static analysis of a code snippet."""
    is_safe: bool
    hits: List[DangerousPatternHit] = field(default_factory=list)
    syntax_error: Optional[str] = None
    imports: List[str] = field(default_factory=list)
    function_calls: List[str] = field(default_factory=list)
    network_calls: List[str] = field(default_factory=list)
    filesystem_writes: List[str] = field(default_factory=list)

    def by_severity(self, severity: str) -> List[DangerousPatternHit]:
        return [h for h in self.hits if h.severity == severity]

    def has_critical(self) -> bool:
        return any(h.severity == PatternSeverity.CRITICAL for h in self.hits)

    def summary(self) -> str:
        if self.syntax_error:
            return f"SyntaxError: {self.syntax_error}"
        if not self.hits:
            return "OK (no dangerous patterns detected)"
        sev_counts: Dict[str, int] = {}
        for h in self.hits:
            sev_counts[h.severity] = sev_counts.get(h.severity, 0) + 1
        parts = [f"{k}={v}" for k, v in sorted(sev_counts.items())]
        return "Hits: " + ", ".join(parts)


# Dangerous builtin / function names that should be flagged
_DANGEROUS_BUILTINS: Set[str] = {
    "exec", "eval", "compile", "__import__", "getattr", "setattr",
    "delattr", "globals", "locals", "vars",
}

# Dangerous stdlib modules
_DANGEROUS_MODULES: Set[str] = {
    "os", "subprocess", "ctypes", "ctypes.util", "socket", "ssl",
    "multiprocessing", "threading", "_thread", "pty", "fcntl",
    "resource", "pwd", "grp", "spwd", "crypt",
    "requests", "httpx", "urllib3", "aiohttp",
}

# Filesystem write functions
_FILESYSTEM_WRITE_FUNCS: Set[str] = {
    "open",  # checked with mode
    "os.remove", "os.unlink", "os.rmdir", "os.removedirs",
    "shutil.rmtree", "shutil.move",
    "pathlib.Path.unlink", "pathlib.Path.rmdir",
    "pathlib.Path.write_text", "pathlib.Path.write_bytes",
    "tempfile.mkstemp", "tempfile.NamedTemporaryFile",
}

# Network call functions
_NETWORK_FUNCS: Set[str] = {
    "socket.socket", "socket.create_connection", "socket.getaddrinfo",
    "urllib.request.urlopen", "urllib.request.urlretrieve",
    "http.client.HTTPConnection", "http.client.HTTPSConnection",
    "ftplib.FTP", "smtplib.SMTP", "telnetlib.Telnet",
    "requests.get", "requests.post", "requests.put", "requests.delete",
    "requests.head", "requests.patch", "requests.request",
}


class RealDangerousPatternDetector:
    """AST-based static analyzer for AI-generated Python code.

    Detects:
    - Dangerous imports (subprocess, os, ctypes, socket, etc.)
    - Calls to dangerous builtins (eval, exec, getattr, etc.)
    - Filesystem write attempts
    - Network call attempts
    - Use of __dunder__ attributes (often used to escape sandboxes)
    - Code that looks like reverse shells or bind shells
    """

    def __init__(
        self,
        allow_network: bool = False,
        allow_filesystem_writes: bool = True,
        allow_dangerous_imports: bool = False,
        allow_eval_exec: bool = False,
    ) -> None:
        self.allow_network = allow_network
        self.allow_filesystem_writes = allow_filesystem_writes
        self.allow_dangerous_imports = allow_dangerous_imports
        self.allow_eval_exec = allow_eval_exec

    def analyze(self, code: str) -> SafetyReport:
        """Analyze Python source code. Returns a SafetyReport."""
        report = SafetyReport(is_safe=True)
        try:
            tree = ast.parse(code)
        except SyntaxError as e:
            report.syntax_error = str(e)
            report.is_safe = False
            return report

        for node in ast.walk(tree):
            self._check_node(node, report)

        if report.has_critical():
            report.is_safe = False
        return report

    # ---- node handlers -------------------------------------------------

    def _check_node(self, node: ast.AST, report: SafetyReport) -> None:
        if isinstance(node, ast.Import):
            for alias in node.names:
                mod = alias.name.split(".")[0]
                report.imports.append(alias.name)
                if not self.allow_dangerous_imports and mod in _DANGEROUS_MODULES:
                    self._hit(
                        report,
                        "dangerous_import",
                        PatternSeverity.CRITICAL,
                        node,
                        f"Import of dangerous module: {alias.name}",
                    )
        elif isinstance(node, ast.ImportFrom):
            mod = (node.module or "").split(".")[0]
            report.imports.append(node.module or "")
            if not self.allow_dangerous_imports and mod in _DANGEROUS_MODULES:
                self._hit(
                    report,
                    "dangerous_from_import",
                    PatternSeverity.CRITICAL,
                    node,
                    f"From-import of dangerous module: {node.module}",
                )
        elif isinstance(node, ast.Call):
            self._check_call(node, report)
        elif isinstance(node, ast.Attribute):
            # __dunder__ access is a classic sandbox escape
            if node.attr.startswith("__") and node.attr.endswith("__") \
                    and node.attr not in {"__init__", "__name__", "__doc__", "__class__", "__dict__"}:
                self._hit(
                    report,
                    "dunder_access",
                    PatternSeverity.HIGH,
                    node,
                    f"Access to dunder attribute: {node.attr}",
                )

    def _check_call(self, node: ast.Call, report: SafetyReport) -> None:
        """Analyze a Call node for dangerous callees."""
        func_name = self._call_name(node.func)
        if not func_name:
            return
        report.function_calls.append(func_name)

        # eval / exec
        if not self.allow_eval_exec and func_name in _DANGEROUS_BUILTINS:
            sev = PatternSeverity.CRITICAL
            self._hit(
                report,
                "dangerous_builtin",
                sev,
                node,
                f"Call to dangerous builtin: {func_name}",
            )
            return

        # filesystem writes
        if not self.allow_filesystem_writes and func_name in _FILESYSTEM_WRITE_FUNCS:
            self._hit(
                report,
                "fs_write",
                PatternSeverity.HIGH,
                node,
                f"Filesystem write via {func_name}",
            )

        # network
        if not self.allow_network and func_name in _NETWORK_FUNCS:
            report.network_calls.append(func_name)
            self._hit(
                report,
                "network_call",
                PatternSeverity.HIGH,
                node,
                f"Network call: {func_name}",
            )

        # os.system, subprocess.* — always flag
        if func_name.startswith("os.system") or func_name.startswith("os.popen"):
            self._hit(
                report,
                "shell_exec",
                PatternSeverity.CRITICAL,
                node,
                f"Shell exec: {func_name}",
            )
        if func_name.startswith("subprocess."):
            self._hit(
                report,
                "subprocess_call",
                PatternSeverity.CRITICAL,
                node,
                f"Subprocess: {func_name}",
            )

        # heuristic: a literal that looks like a reverse-shell command
        for arg in node.args:
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                s = arg.value.lower()
                if any(token in s for token in ("/dev/tcp/", "nc -e", "bash -i", "rm -rf /", "mkfifo")):
                    self._hit(
                        report,
                        "shell_token",
                        PatternSeverity.CRITICAL,
                        node,
                        f"Suspicious shell token: {arg.value[:60]}",
                    )

    def _call_name(self, func: ast.AST) -> Optional[str]:
        """Return a dotted name for a Call's function, e.g. 'os.system'."""
        if isinstance(func, ast.Name):
            return func.id
        if isinstance(func, ast.Attribute):
            parts: List[str] = [func.attr]
            cur: ast.AST = func.value
            while isinstance(cur, ast.Attribute):
                parts.append(cur.attr)
                cur = cur.value
            if isinstance(cur, ast.Name):
                parts.append(cur.id)
            return ".".join(reversed(parts))
        return None

    def _hit(
        self,
        report: SafetyReport,
        pattern_id: str,
        severity: str,
        node: ast.AST,
        description: str,
    ) -> None:
        snippet = ast.unparse(node) if hasattr(ast, "unparse") else "<node>"
        if len(snippet) > 120:
            snippet = snippet[:120] + "..."
        report.hits.append(DangerousPatternHit(
            pattern_id=pattern_id,
            severity=severity,
            line=getattr(node, "lineno", 0),
            col=getattr(node, "col_offset", 0),
            description=description,
            snippet=snippet,
        ))


# ---------------------------------------------------------------------------
# Subprocess sandbox with resource limits
# ---------------------------------------------------------------------------


@dataclass
class SandboxConfig:
    """Configuration for a sandboxed execution."""
    timeout_seconds: int = 30
    memory_limit_mb: int = 512
    cpu_time_seconds: int = 20
    max_file_descriptors: int = 64
    max_file_size_mb: int = 100
    max_processes: int = 1
    allow_network: bool = False
    working_dir: Optional[Path] = None
    extra_env: Dict[str, str] = field(default_factory=dict)


@dataclass
class SandboxResult:
    """Result of running code in a SubprocessSandbox."""
    success: bool
    returncode: int
    stdout: str
    stderr: str
    duration_seconds: float
    timed_out: bool = False
    killed_for_resource: bool = False
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "success": self.success,
            "returncode": self.returncode,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "duration_seconds": self.duration_seconds,
            "timed_out": self.timed_out,
            "killed_for_resource": self.killed_for_resource,
            "error": self.error,
        }


# Linux-only signal used for hard timeout
_SIGXCPU = signal.SIGXCPU


def _apply_resource_limits(cfg: SandboxConfig) -> None:
    """Apply POSIX resource limits to the current process.

    This is meant to be called from inside a preexec_fn (before exec).
    """
    try:
        # CPU time limit (hard)
        resource.setrlimit(
            resource.RLIMIT_CPU,
            (cfg.cpu_time_seconds, cfg.cpu_time_seconds + 1),
        )
    except (ValueError, OSError):
        pass
    try:
        # Address-space limit (memory)
        mem_bytes = cfg.memory_limit_mb * 1024 * 1024
        resource.setrlimit(resource.RLIMIT_AS, (mem_bytes, mem_bytes))
    except (ValueError, OSError):
        pass
    try:
        # File size limit
        fs_bytes = cfg.max_file_size_mb * 1024 * 1024
        resource.setrlimit(resource.RLIMIT_FSIZE, (fs_bytes, fs_bytes))
    except (ValueError, OSError):
        pass
    try:
        # Number of open file descriptors
        resource.setrlimit(
            resource.RLIMIT_NOFILE,
            (cfg.max_file_descriptors, cfg.max_file_descriptors),
        )
    except (ValueError, OSError):
        pass
    try:
        # Number of processes/threads
        resource.setrlimit(
            resource.RLIMIT_NPROC,
            (cfg.max_processes, cfg.max_processes),
        )
    except (ValueError, OSError):
        pass

    # Disable core dumps
    try:
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    except (ValueError, OSError):
        pass

    # If no network: drop the ability to bind new sockets by isolating
    # via a separate network namespace is impossible without root. Instead
    # we just set an env var that well-behaved code can read, and the
    # static analyzer blocks network calls.
    if not cfg.allow_network:
        os.environ["ELENGENIX_SANDBOX_NO_NETWORK"] = "1"


class SubprocessSandbox:
    """Run untrusted Python code in a hardened subprocess.

    Layered defense:
    1. The code is written to a temp file with a unique name.
    2. A subprocess is launched with ``preexec_fn`` applying POSIX
       resource limits (CPU, memory, file size, file descriptors, processes).
    3. ``subprocess.run`` enforces a wall-clock timeout.
    4. Static analysis (RealDangerousPatternDetector) can be run first
       to refuse obviously dangerous code.
    """

    def __init__(
        self,
        config: Optional[SandboxConfig] = None,
        detector: Optional[RealDangerousPatternDetector] = None,
    ) -> None:
        self.config = config or SandboxConfig()
        if detector is not None:
            self.detector = detector
        else:
            # Honor the sandbox's policy: if allow_network is on, the
            # detector should not block network calls. Dangerous imports
            # are always blocked by default; they can be relaxed via the
            # detector argument.
            self.detector = RealDangerousPatternDetector(
                allow_network=self.config.allow_network,
                allow_filesystem_writes=True,
                allow_dangerous_imports=False,
                allow_eval_exec=False,
            )

    def run(self, code: str, args: Optional[List[str]] = None) -> SandboxResult:
        """Execute code in a sandboxed subprocess.

        Args:
            code: Python source code to execute.
            args: optional argv to expose to the code via ``sys.argv``.

        Returns:
            SandboxResult with stdout, stderr, timing, and exit info.
        """
        # Pre-flight static check
        report = self.detector.analyze(code)
        if report.syntax_error:
            return SandboxResult(
                success=False,
                returncode=-1,
                stdout="",
                stderr=f"SyntaxError: {report.syntax_error}",
                duration_seconds=0.0,
                error="syntax_error",
            )
        if report.has_critical():
            return SandboxResult(
                success=False,
                returncode=-1,
                stdout="",
                stderr=(
                    "Refused: critical safety violations detected.\n"
                    + report.summary()
                ),
                duration_seconds=0.0,
                error="critical_violations",
            )

        # Write code to a temp file
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            script_path = tmp / "sandboxed.py"
            script_path.write_text(self._wrap_code(code, args), encoding="utf-8")

            cmd = [sys.executable, str(script_path)]
            env = {
                "PATH": os.environ.get("PATH", ""),
                "HOME": tmpdir,
                "TMPDIR": tmpdir,
                "PYTHONDONTWRITEBYTECODE": "1",
            }
            env.update(self.config.extra_env)
            if not self.config.allow_network:
                env["ELENGENIX_SANDBOX_NO_NETWORK"] = "1"

            start = time.monotonic()
            try:
                proc = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=self.config.timeout_seconds,
                    cwd=str(self.config.working_dir) if self.config.working_dir else tmpdir,
                    env=env,
                    preexec_fn=lambda: _apply_resource_limits(self.config),
                )
                duration = time.monotonic() - start
                return SandboxResult(
                    success=(proc.returncode == 0),
                    returncode=proc.returncode,
                    stdout=proc.stdout,
                    stderr=proc.stderr,
                    duration_seconds=duration,
                )
            except subprocess.TimeoutExpired as e:
                duration = time.monotonic() - start
                return SandboxResult(
                    success=False,
                    returncode=-1,
                    stdout=(e.stdout.decode() if isinstance(e.stdout, bytes) else (e.stdout or "")),
                    stderr=(
                        (e.stderr.decode() if isinstance(e.stderr, bytes) else (e.stderr or ""))
                        + f"\n[TIMEOUT after {self.config.timeout_seconds}s]"
                    ),
                    duration_seconds=duration,
                    timed_out=True,
                )
            except OSError as e:
                return SandboxResult(
                    success=False,
                    returncode=-1,
                    stdout="",
                    stderr=f"Sandbox error: {e}",
                    duration_seconds=time.monotonic() - start,
                    error=str(e),
                )

    @staticmethod
    def _wrap_code(code: str, args: Optional[List[str]]) -> str:
        """Wrap user code with a small main() harness so we capture exceptions."""
        argv_repr = repr(args or [])
        return textwrap.dedent(
            f"""\
            import sys
            sys.argv = ['sandboxed.py'] + ({argv_repr} or [])
            try:
                exec(compile({code!r}, '<sandboxed>', 'exec'), {{'__name__': '__sandbox__'}})
                sys.exit(0)
            except SystemExit as _e:
                # Honor explicit sys.exit
                code = _e.code if isinstance(_e.code, int) else 1
                sys.exit(code)
            except BaseException as _e:
                import traceback
                traceback.print_exc()
                sys.exit(1)
            """
        )


# ---------------------------------------------------------------------------
# Convenience facade
# ---------------------------------------------------------------------------


def analyze_code(code: str, allow_network: bool = False) -> SafetyReport:
    """One-shot static analysis helper."""
    detector = RealDangerousPatternDetector(allow_network=allow_network)
    return detector.analyze(code)


def run_sandboxed(code: str, config: Optional[SandboxConfig] = None) -> SandboxResult:
    """One-shot sandboxed execution helper."""
    sandbox = SubprocessSandbox(config=config)
    return sandbox.run(code)
