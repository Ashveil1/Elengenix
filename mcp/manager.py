"""
mcp/manager.py — MCP Server Manager

Manages MCP server lifecycle - auto-start when TUI/scan starts,
stop when they end. Runs in background thread.
"""

from __future__ import annotations

import asyncio
import logging
import threading
from typing import Optional

from mcp.config import get_config_manager, get_mcp_config
from mcp.server import MCPServer

logger = logging.getLogger("elengenix.mcp.manager")


class MCPManager:
    """Manages MCP server lifecycle.
    
    Auto-starts MCP server when TUI or scan starts.
    Runs in background thread to avoid blocking.
    
    Usage:
        manager = MCPManager()
        manager.start()  # Start in background
        # ... use Elengenix ...
        manager.stop()   # Stop server
    """
    
    def __init__(self):
        self.server: Optional[MCPServer] = None
        self._thread: Optional[threading.Thread] = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._running = False
    
    @property
    def is_running(self) -> bool:
        """Check if MCP server is running."""
        return self._running
    
    def start(self) -> bool:
        """Start MCP server in background.
        
        Returns:
            True if started, False if already running or config disabled.
        """
        if self._running:
            logger.debug("MCP server already running")
            return False
        
        # Check if MCP is enabled in config
        try:
            config = get_mcp_config()
            if not config.enabled:
                logger.debug("MCP disabled in config")
                return False
            
            enabled_servers = config.get_enabled_servers()
            if not enabled_servers:
                logger.debug("No MCP servers configured")
                return False
        except Exception as e:
            logger.debug(f"Could not load MCP config: {e}")
            return False
        
        # Start server in background thread
        self._running = True
        self._thread = threading.Thread(target=self._run_server, daemon=True)
        self._thread.start()
        
        logger.info("MCP server started in background")
        return True
    
    def stop(self) -> None:
        """Stop MCP server."""
        if not self._running:
            return
        
        self._running = False
        
        if self._loop and self._loop.is_running():
            self._loop.call_soon_threadsafe(self._loop.stop)
        
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2.0)
        
        self.server = None
        self._loop = None
        logger.info("MCP server stopped")
    
    def _run_server(self) -> None:
        """Run MCP server in background thread."""
        try:
            self._loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self._loop)
            
            self.server = MCPServer(load_config=True)
            
            # Run server with stdio in background
            # For background mode, we just keep the server ready
            # Actual stdio handling happens when AI agents connect
            logger.info("MCP server ready")
            
            # Keep loop running until stopped
            while self._running:
                self._loop.run_until_complete(asyncio.sleep(0.1))
                
        except Exception as e:
            logger.error(f"MCP server error: {e}")
        finally:
            self._running = False


# Global manager instance
_manager: Optional[MCPManager] = None


def get_mcp_manager() -> MCPManager:
    """Get the global MCP manager."""
    global _manager
    if _manager is None:
        _manager = MCPManager()
    return _manager


def start_mcp() -> bool:
    """Start MCP server if enabled."""
    return get_mcp_manager().start()


def stop_mcp() -> None:
    """Stop MCP server."""
    get_mcp_manager().stop()
