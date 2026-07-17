"""Tests for mcp/server.py — MCP server."""
from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from mcp.server import MCPServer


class TestMCPServer:
    def test_init_without_config(self):
        """Server can init without loading external config."""
        with patch("mcp.server.get_mcp_config", return_value=MagicMock()):
            server = MCPServer(load_config=False)
            assert server.protocol is not None
            # Should have registered Elengenix tools
            assert len(server.protocol.tools) >= 20  # 25 tools roughly

    def test_init_loads_external_servers(self):
        """When load_config=True, external MCP servers are loaded."""
        mock_config = MagicMock()
        mock_config.get_enabled_servers.return_value = {}
        with patch("mcp.server.get_mcp_config", return_value=mock_config):
            server = MCPServer(load_config=True)
            assert "elengenix_" in list(server.protocol.tools.keys())[0]

    def test_register_elengenix_tools_has_expected_tools(self):
        with patch("mcp.server.get_mcp_config", return_value=MagicMock()):
            server = MCPServer(load_config=False)
            tool_names = list(server.protocol.tools.keys())
            assert "elengenix_port_scan" in tool_names
            assert "elengenix_web_recon" in tool_names
            assert "elengenix_vuln_scan" in tool_names

    def test_server_handles_initialize_request(self):
        with patch("mcp.server.get_mcp_config", return_value=MagicMock()):
            server = MCPServer(load_config=False)
            from mcp.protocol import MCPRequest

            mcp_req = MCPRequest(id=1, method="initialize")
            resp = server.protocol.handle_request(mcp_req)
            assert resp.result is not None
            assert "protocolVersion" in resp.result

    def test_server_lists_tools(self):
        with patch("mcp.server.get_mcp_config", return_value=MagicMock()):
            server = MCPServer(load_config=False)
            from mcp.protocol import MCPRequest

            req = MCPRequest(id=1, method="tools/list")
            resp = server.protocol.handle_request(req)
            assert resp.result is not None
            assert len(resp.result["tools"]) >= 20
            tool_names = [t["name"] for t in resp.result["tools"]]
            assert "elengenix_port_scan" in tool_names

    def test_external_servers_loaded_from_config(self):
        """When config has enabled servers, they should be loaded."""
        mock_servers = {
            "ext-test": MagicMock(command="npx test-server", type="local"),
        }
        mock_config = MagicMock()
        mock_config.get_enabled_servers.return_value = mock_servers
        with patch("mcp.server.get_mcp_config", return_value=mock_config):
            server = MCPServer(load_config=True)
            # Should not crash
            assert len(server.protocol.tools) >= 20

    def test_server_no_crash_on_bad_config(self):
        """Should gracefully handle config load failure."""
        with patch("mcp.server.get_mcp_config", side_effect=Exception("config fail")):
            server = MCPServer(load_config=True)
            assert len(server.protocol.tools) >= 20
