"""
dependency_manager.py — Elengenix Tool Install Request Flow
- The AI agent calls `request_install()` when it needs a tool the user does not have.
- The user is shown the request and explicitly approves/rejects.
- On approval, the install command runs once and we report success/failure.
- Elengenix does NOT bundle any third-party tool, and does NOT auto-install.
"""

import subprocess
import shutil
import questionary
import logging
import sys
import os
import time
from pathlib import Path
from typing import List, Optional, Tuple
from ui_components import console, print_success, print_error, print_warning

logger = logging.getLogger("elengenix.installer")

# Managers the AI can request. Maps friendly name → command prefix used to check
# the manager itself is available (e.g. apt, go, pip3).
SUPPORTED_MANAGERS = ("go", "pip", "pip3", "apt", "cargo", "npm", "gem", "brew")


def _manager_available(manager: str) -> bool:
    """Return True if the package manager binary is on PATH."""
    if manager in ("pip", "pip3"):
        return shutil.which(manager) is not None or shutil.which("python3") is not None
    return shutil.which(manager) is not None


def _build_install_cmd(name: str, manager: str, install_cmd: Optional[str]) -> Optional[List[str]]:
    """Build a list-form command. Returns None if we cannot build it."""
    if install_cmd:
        # Caller supplied the full command. Parse defensively (no shell).
        return install_cmd.split()

    if manager == "go":
        return ["go", "install", f"github.com/{name}@latest"]
    if manager in ("pip", "pip3"):
        return [manager, "install", name]
    if manager == "apt":
        return ["sudo", "apt-get", "install", "-y", name]
    if manager == "cargo":
        return ["cargo", "install", name]
    if manager == "npm":
        return ["npm", "install", "-g", name]
    if manager == "gem":
        return ["gem", "install", name]
    if manager == "brew":
        return ["brew", "install", name]
    return None


def request_install(
    name: str,
    purpose: str,
    manager: str = "go",
    install_cmd: Optional[str] = None,
    timeout: int = 600,
    auto_yes: bool = False,
) -> Tuple[bool, str]:
    """
    Ask the user for permission to install a tool, then run the install if approved.

    Args:
        name: The tool name (e.g. "ffuf"). Used in the prompt.
        purpose: Why the AI wants this tool. Shown to the user.
        manager: One of SUPPORTED_MANAGERS.
        install_cmd: Optional full command string (overrides name/manager heuristic).
        timeout: Max seconds for the install subprocess.
        auto_yes: If True, skip the prompt (used by tests/automation).

    Returns:
        (success: bool, message: str)
    """
    if manager not in SUPPORTED_MANAGERS:
        return False, f"Unsupported manager '{manager}'. Supported: {', '.join(SUPPORTED_MANAGERS)}"

    if shutil.which(name):
        return True, f"{name} is already installed."

    if not _manager_available(manager):
        return False, (
            f"Package manager '{manager}' is not available on this system. "
            f"Install it first, or ask the user to install '{name}' manually."
        )

    cmd = _build_install_cmd(name, manager, install_cmd)
    if not cmd:
        return False, f"Could not build install command for {name} via {manager}"

    # Show the request
    console.print(f"\n[bold red]Tool Install Request[/bold red]")
    console.print(f"  Tool:    [bold white]{name}[/bold white]")
    console.print(f"  Manager: {manager}")
    console.print(f"  Purpose: {purpose}")
    console.print(f"  Command: [dim]{' '.join(cmd)}[/dim]")

    if not auto_yes:
        try:
            choice = questionary.confirm("Approve installation?", default=False).ask()
        except (KeyboardInterrupt, EOFError):
            return False, "User cancelled install"
        if not choice:
            return False, "User declined install"

    # Run install with streaming
    try:
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
        for line in process.stdout:
            if "installing" in line.lower() or "downloading" in line.lower():
                console.print(f"    [dim]{line.strip()}[/dim]")
        process.wait(timeout=timeout)
        if process.returncode == 0 and shutil.which(name):
            return True, f"{name} installed successfully"
        return False, f"Install returned non-zero (rc={process.returncode})"
    except subprocess.TimeoutExpired:
        return False, f"Install timed out after {timeout}s"
    except Exception as e:
        return False, f"Install error: {e}"


def list_installable(tools: List[str]) -> List[Tuple[str, bool]]:
    """Return [(tool_name, is_installed), ...] for the given list."""
    return [(t, shutil.which(t) is not None) for t in tools]


if __name__ == "__main__":
    # Standalone CLI for the user to manually request a tool install.
    if len(sys.argv) < 2:
        console.print("[bold]Usage:[/bold] python dependency_manager.py <tool_name> [manager] [purpose]")
        sys.exit(1)
    tool_name = sys.argv[1]
    manager = sys.argv[2] if len(sys.argv) > 2 else "go"
    purpose = sys.argv[3] if len(sys.argv) > 3 else f"User requested install of {tool_name}"
    ok, msg = request_install(tool_name, purpose, manager=manager)
    if ok:
        print_success(msg)
    else:
        print_error(msg)
    sys.exit(0 if ok else 1)
