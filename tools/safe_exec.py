"""
tools/safe_exec.py — Allowlisted Subprocess Executor (v2.0.0)
- Strict binary allowlist
- No shell=True, metacharacter blocking
- Timeout & output size limits
- Structured return with stdout/stderr/exit_code
"""

from __future__ import annotations

import logging
import os
import shlex
import subprocess
from typing import Dict, Union

logger = logging.getLogger("elengenix.safe_exec")

ALLOWED_BINARIES: frozenset = frozenset({
 "nmap", "curl", "wget",
 "subfinder", "nuclei", "httpx", "katana",
 "waybackurls", "ffuf", "gau", "amass",
 "hakrawler", "gospider", "assetfinder",
 "python3", "python",
})

FORBIDDEN_CHARS: tuple = ("|", "&", ";", "`", "$(", ">", "<", "\\", "\n", "\r")
MAX_OUTPUT = 50_000 # chars

def execute_safely(
 command_str: str,
 timeout: int = 300,
 cwd: str | None = None,
) -> Dict[str, Union[str, int, bool]]:
 """
 Safely execute an allowlisted shell command.

 Returns:
 {
 "success": bool,
 "stdout": str,
 "stderr": str,
 "exit_code": int,
 "error": str, # non-empty on failure
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

 binary = os.path.basename(args[0])
 if binary not in ALLOWED_BINARIES:
 return error_result(f"'{binary}' is not in the security allowlist.")

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
 "success": result.returncode == 0,
 "stdout": result.stdout[:MAX_OUTPUT],
 "stderr": result.stderr[:MAX_OUTPUT],
 "exit_code": result.returncode,
 "error": "",
 }
 except subprocess.TimeoutExpired:
 return error_result(f"Command timed out after {timeout}s.")
 except FileNotFoundError:
 return error_result(f"Binary '{binary}' not found on this system.")
 except Exception as e:
 logger.error(f"Execution error: {e}")
 return error_result(str(e))
