"""
tools/safe_exec.py — Native Shell Executor (v99999 (god nine is the best))
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

# Metacharacter blocking has been removed to allow the AI full shell access.
# Pipes (|), redirects (>), background (&), and command chaining (;) are now
# permitted.  Authorisation is handled upstream by tools/governance.py which
# blocks DESTRUCTIVE commands (rm, dd, mkfs, etc.) before they ever reach here.

MAX_OUTPUT = 50_000  # chars


def execute_safely(
    command_str: str,
    timeout: int = 300,
    cwd: str | None = None,
) -> Dict[str, Union[str, int, bool]]:
    """
    Execute a shell command with full pipeline support.

    The command is run via ``shell=True`` so that pipes, redirects, and
    command chaining work natively.  Security classification is handled
    upstream by ``tools/governance.py`` (DESTRUCTIVE commands are denied
    before reaching this function).

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
    error_result = lambda msg: {
        "success": False, "stdout": "", "stderr": "", "exit_code": -1, "error": msg
    }

    if not command_str or not command_str.strip():
        return error_result("Empty command.")

    logger.info(f"Executing (shell): {command_str}")
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
            "success":   result.returncode == 0,
            "stdout":    result.stdout[:MAX_OUTPUT],
            "stderr":    result.stderr[:MAX_OUTPUT],
            "exit_code": result.returncode,
            "error":     "",
        }
    except subprocess.TimeoutExpired:
        return error_result(f"Command timed out after {timeout}s.")
    except FileNotFoundError:
        return error_result(f"Shell not found on this system.")
    except Exception as e:
        logger.error(f"Execution error: {e}")
        return error_result(str(e))
