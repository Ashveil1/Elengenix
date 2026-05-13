"""
tools/safe_exec.py — Allowlisted Subprocess Executor (v2.0.0)
- No shell=True, metacharacter blocking
- Timeout & output size limits
- Structured return with stdout/stderr/exit_code
"""

from __future__ import annotations

import logging
import shlex
import subprocess
from typing import Dict, Union

logger = logging.getLogger("elengenix.safe_exec")

# Binary allowlist has been removed in favour of Governance-based classification.
# safe_exec now only enforces: shell=False, metacharacter blocking, timeout, output limits.
# Authorisation is handled by tools/governance.py (SAFE / PRIVILEGED / DESTRUCTIVE).
ALLOWED_BINARIES: frozenset = frozenset()  # kept as empty sentinel for backward compat

FORBIDDEN_CHARS: tuple = ("|", "&", ";", "`", "$(", ">", "<", "\\", "\n", "\r")
MAX_OUTPUT = 50_000  # chars


def execute_safely(
    command_str: str,
    timeout: int = 300,
    cwd: str | None = None,
) -> Dict[str, Union[str, int, bool]]:
    """
    Safely execute a shell command with metacharacter protection.

    Binary allowlisting has been removed.  Governance-based classification
    (tools/governance.py) handles authorisation upstream.

    Returns:
        {
          "success":   bool,
          "stdout":    str,
          "stderr":    str,
          "exit_code": int,
          "error":     str,   # non-empty on failure
        }
    """
    error_result = lambda msg: {
        "success": False, "stdout": "", "stderr": "", "exit_code": -1, "error": msg
    }

    if not command_str or not command_str.strip():
        return error_result("Empty command.")

    if any(c in command_str for c in FORBIDDEN_CHARS):
        logger.warning(f"Blocked dangerous command: {command_str!r}")
        return error_result("Command contains prohibited metacharacters.")

    try:
        args = shlex.split(command_str)
    except ValueError as e:
        return error_result(f"Parse error: {e}")

    logger.info(f"Executing: {command_str}")
    try:
        result = subprocess.run(
            args,
            shell=False,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=cwd,
        )
        return {
            "success":   result.returncode == 0,
            "stdout":    result.stdout[:MAX_OUTPUT],
            "stderr":    result.stderr[:MAX_OUTPUT],
            "exit_code": result.returncode,
            "error":     "",
        }
    except subprocess.TimeoutExpired:
        return error_result(f"Command timed out after {timeout}s.")
    except FileNotFoundError:
        return error_result(f"Binary not found on this system.")
    except Exception as e:
        logger.error(f"Execution error: {e}")
        return error_result(str(e))
