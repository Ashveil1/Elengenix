"""
tools/safe_exec.py -- Native Shell Executor
- shell=True enabled for full pipeline / redirect / chaining support
- Security handled by Governance (tools/governance.py) upstream
- Timeout & output size limits enforced
- Structured return with stdout/stderr/exit_code
- Streaming support for interactive LLM
"""

from __future__ import annotations

import logging
import subprocess
from typing import Callable, Dict, Generator, Optional, Union

logger = logging.getLogger("elengenix.safe_exec")

# Metacharacter blocking has been removed to preserve native shell workflows.
# This module is intentionally low-level: callers must run tools.governance
# first so DESTRUCTIVE commands are denied and PRIVILEGED commands are approved
# before reaching shell=True.

MAX_OUTPUT = 100_000  # chars (increased for LLM to see full output)


def execute_safely(
    command_str: str,
    timeout: int = 300,
    cwd: str | None = None,
) -> Dict[str, Union[str, int, bool]]:
    """
    Execute a shell command with full pipeline support.

    The command is run via ``shell=True`` so that pipes, redirects, and
    command chaining work natively. Security classification must happen
    upstream in ``tools/governance.py`` before calling this function.

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


def execute_safely_streaming(
    command_str: str,
    timeout: int = 300,
    cwd: str | None = None,
    callback: Optional[Callable[[str], None]] = None,
) -> Generator[str, None, None]:
    """
    Execute a shell command with streaming output.

    This allows the LLM to see output in real-time as it's produced,
    similar to how a human watches a terminal.

    Args:
        command_str: Raw shell command string.
        timeout: Maximum execution time in seconds.
        cwd: Optional working directory.
        callback: Optional callback for each line of output.

    Yields:
        Each line of output as it's produced.

    Returns:
        Generator that yields output lines.
    """
    if not command_str or not command_str.strip():
        return

    logger.info(f"Executing (streaming): {command_str}")

    try:
        process = subprocess.Popen(
            command_str,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,  # Merge stderr into stdout
            text=True,
            cwd=cwd,
        )

        # Read output line by line
        for line in process.stdout:
            yield line
            if callback:
                callback(line)

        # Wait for process to complete
        process.wait(timeout=timeout)

        # Return exit code info
        if process.returncode != 0:
            yield f"\n[EXIT CODE: {process.returncode}]"

    except subprocess.TimeoutExpired:
        process.kill()
        yield f"\n[TIMEOUT: Command killed after {timeout}s]"
    except Exception as e:
        logger.error(f"Streaming execution error: {e}")
        yield f"\n[ERROR: {e}]"


def execute_safely_interactive(
    command_str: str,
    timeout: int = 300,
    cwd: str | None = None,
    line_callback: Optional[Callable[[str], None]] = None,
) -> Dict[str, Union[str, int, bool]]:
    """
    Execute a shell command with streaming output and return full result.

    This combines streaming (for real-time display) with structured result.
    The LLM can see output as it's produced AND get the full result.

    Args:
        command_str: Raw shell command string.
        timeout: Maximum execution time in seconds.
        cwd: Optional working directory.
        line_callback: Callback for each line of output.

    Returns:
        {
          "success":   bool,
          "stdout":    str (full output),
          "stderr":    str,
          "exit_code": int,
          "error":     str,
          "lines":     list (all output lines),
        }
    """
    lines = []
    stdout_chunks = []

    for line in execute_safely_streaming(command_str, timeout, cwd, line_callback):
        lines.append(line)
        stdout_chunks.append(line)

    # Get exit code from last output if available
    exit_code = 0
    error = ""

    # Check if process succeeded by looking at output
    full_output = "".join(stdout_chunks)
    if "[TIMEOUT:" in full_output:
        exit_code = -1
        error = "Command timed out"
    elif "[ERROR:" in full_output:
        exit_code = -1
        error = "Execution error"
    elif "[EXIT CODE:" in full_output:
        # Extract exit code
        try:
            exit_code = int(full_output.split("[EXIT CODE:")[1].split("]")[0].strip())
        except (IndexError, ValueError):
            exit_code = -1

    return {
        "success": exit_code == 0,
        "stdout": full_output[:MAX_OUTPUT],
        "stderr": "",
        "exit_code": exit_code,
        "error": error,
        "lines": lines,
    }
