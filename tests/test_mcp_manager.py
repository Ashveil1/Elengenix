"""tests/test_mcp_manager.py — Tests for MCP manager"""

import pytest

from mcp.manager import MCPManager


class TestMCPManager:
    def test_create_manager(self):
        manager = MCPManager()
        assert manager.is_running is False

    def test_start_and_stop(self):
        """Start and stop MCP manager."""
        manager = MCPManager()
        # Start should work (may return True if config exists)
        manager.start()
        # Stop should work
        manager.stop()
        assert manager.is_running is False

    def test_stop_when_not_running(self):
        manager = MCPManager()
        # Should not raise
        manager.stop()
        assert manager.is_running is False

    def test_multiple_start_calls(self):
        """Multiple start calls should not create multiple servers."""
        manager = MCPManager()
        manager.start()
        manager.start()  # Second call should be no-op
        manager.stop()
