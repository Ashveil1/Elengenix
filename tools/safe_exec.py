"""
tools/safe_exec.py — Native Shell Executor
- shell=True enabled for full pipeline / redirect / chaining support
- Security handled by Governance (tools/governance.py) upstream
- Timeout & output size limits enforced
- Structured return with stdout/stderr/exit_code
"""

from __future__ import annotations

import logging
import subprocess
from typing import Dict, Union

logger = logging.getLogger("elengenix.safe_exec")

# Metacharacter blocking has been removed to preserve native shell workflows.
# This module is intentionally low-level: callers must run tools.governance
# first so DESTRUCTIVE commands are denied and PRIVILEGED commands are approved
# before reaching shell=True.

MAX_OUTPUT = 50_000  # chars


def execute_safely(
    command_str: str,
    timeout: int = 300,
    cwd: str | None = None,
) -> Dict[str, Union[str, int, bool]]:
    """
    Execute a shell command with full pipeline support.

    The command is run via ``shell=True`` so that pipes, redirects, and
    command chaining work natively. Security classification must happen
    upstream in ``tools.governance.py`` before calling this function.

    Args:
        command_str: Raw shell command string (may contain |, >, &, etc.).
        timeout: Maximum execution time in seconds.
        cwd: Optional working directory.

    Returns:
        {
          "success":   bool,
          "stdout":    str,
          "stderr":    str,
          "exit_code": int,
          "error":     str,   # non-empty on failure
        }
    """

    def error_result(msg):
        return {
            "success": False,
            "stdout": "",
            "stderr": "",
            "exit_code": -1,
            "error": msg,
        }

    if not command_str or not command_str.strip():
        return error_result("Empty command.")

    logger.info(f"Executing (shell): {command_str}")
    # Transparent execution markers for CLI
    if "sudo " in command_str or "apt " in command_str or "pip " in command_str:
        print("\n[THOUGHT] Agent is executing a system-level action")
        print(f"[COMMAND] {command_str}")
        if "sudo " in command_str:
            print(
                "[RUN]     Privileged action (sudo) requested. Please provide your password if prompted:\n"
            )
    try:
        result = subprocess.run(
            command_str,
            shell=True,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=cwd,
        )
        return {
            "success": result.returncode == 0,
            "stdout": result.stdout[:MAX_OUTPUT],
            "stderr": result.stderr[:MAX_OUTPUT],
            "exit_code": result.returncode,
            "error": "",
        }
    except subprocess.TimeoutExpired:
        return error_result(f"Command timed out after {timeout}s.")
    except FileNotFoundError:
        return error_result("Shell not found on this system.")
    except Exception as e:
        logger.error(f"Execution error: {e}")
        return error_result(str(e))
