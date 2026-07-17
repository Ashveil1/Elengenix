"""Tests for commands/mcp_runner.py — MCP server auto-start."""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from commands.mcp_runner import start_mcp_if_enabled


class TestStartMCPIfEnabled:
    @pytest.fixture(autouse=True)
    def reset_mcp_state(self):
        """Reset the global _MCP_STARTED before each test."""
        import commands.mcp_runner
        commands.mcp_runner._MCP_STARTED = False
        yield

    def test_returns_true_when_mcp_enabled(self):
        with patch("mcp.manager.start_mcp", return_value=True):
            result = start_mcp_if_enabled()
            assert result is True

    def test_returns_false_when_mcp_disabled(self):
        with patch("mcp.manager.start_mcp", return_value=False):
            result = start_mcp_if_enabled()
            assert result is False

    def test_returns_true_on_subsequent_calls(self):
        with patch("mcp.manager.start_mcp", return_value=True):
            first = start_mcp_if_enabled()
            second = start_mcp_if_enabled()
            assert first is True
            assert second is True  # cached

    def test_handles_import_error_gracefully(self):
        with patch("mcp.manager.start_mcp", side_effect=ImportError("No module")):
            result = start_mcp_if_enabled()
            assert result is False

    def test_handles_general_exception(self):
        with patch("mcp.manager.start_mcp", side_effect=Exception("Boom")):
            result = start_mcp_if_enabled()
            assert result is False

    def test_returns_false_when_start_returns_false(self):
        with patch("mcp.manager.start_mcp", return_value=False):
            result = start_mcp_if_enabled()
            assert result is False
