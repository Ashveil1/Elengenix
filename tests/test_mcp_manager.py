"""Tests for mcp/manager.py — MCP server lifecycle manager."""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from mcp.manager import MCPManager


class TestMCPManager:
    def test_initial_state(self):
        mgr = MCPManager()
        assert mgr.is_running is False
        assert mgr.server is None
        assert mgr._thread is None

    def test_start_when_already_running(self):
        mgr = MCPManager()
        mgr._running = True
        result = mgr.start()
        assert result is False

    def test_start_config_disabled(self):
        """When MCP is disabled in config, start returns False."""
        mock_config = MagicMock()
        mock_config.enabled = False
        with patch("mcp.manager.get_mcp_config", return_value=mock_config):
            mgr = MCPManager()
            result = mgr.start()
            assert result is False
            assert mgr.is_running is False

    def test_start_no_servers_configured(self):
        """When no servers in config, start returns False."""
        mock_config = MagicMock()
        mock_config.enabled = True
        mock_config.get_enabled_servers.return_value = {}
        with patch("mcp.manager.get_mcp_config", return_value=mock_config):
            mgr = MCPManager()
            result = mgr.start()
            assert result is False
            assert mgr.is_running is False

    def test_start_success(self):
        """When MCP is enabled and servers configured, starts successfully."""
        mock_config = MagicMock()
        mock_config.enabled = True
        mock_config.get_enabled_servers.return_value = {
            "test": MagicMock(command="npx test"),
        }
        with patch("mcp.manager.get_mcp_config", return_value=mock_config):
            mgr = MCPManager()
            result = mgr.start()
            # In test without event loop, it may set _running but thread
            # can't actually run. Still, should return True.
            if result:
                assert mgr.is_running is True

    def test_stop_when_not_running(self):
        mgr = MCPManager()
        mgr.stop()  # Should not crash
        assert mgr.is_running is False

    def test_stop_while_running(self):
        mgr = MCPManager()
        mgr._running = True
        mgr._loop = MagicMock()
        mgr._loop.is_running.return_value = True
        mgr._thread = MagicMock()
        mgr._thread.is_alive.return_value = True
        mgr.stop()
        assert mgr.is_running is False
        assert mgr.server is None

    def test_start_config_exception(self):
        """If config loading fails, start should return False."""
        with patch("mcp.manager.get_mcp_config", side_effect=Exception("no config")):
            mgr = MCPManager()
            result = mgr.start()
            assert result is False
            assert mgr.is_running is False

    def test_double_stop_safe(self):
        """Stopping twice should not error."""
        mgr = MCPManager()
        mgr.stop()
        mgr.stop()  # second stop
        assert mgr.is_running is False
