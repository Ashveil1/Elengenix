"""commands/mcp_runner.py — Auto-start MCP server when Elengenix boots.

Hooks into CLI startup so the MCP server is ready before any scan,
TUI, or vuln-hunt command runs. Starts silently in a background
thread (daemon) so it never blocks startup.
"""

from __future__ import annotations

import logging

logger = logging.getLogger("elengenix.commands.mcp_runner")

_MCP_STARTED = False


def start_mcp_if_enabled() -> bool:
    """Start MCP server in background if enabled in config.

    Safe to call multiple times — only starts once per process.
    Returns True if started, False if disabled or already running.
    """
    global _MCP_STARTED
    if _MCP_STARTED:
        return True

    try:
        from mcp.manager import start_mcp

        result = start_mcp()
        if result:
            logger.debug("MCP server auto-started")
            _MCP_STARTED = True
        return result
    except Exception:
        logger.debug("MCP server not available (optional component)")
        return False
