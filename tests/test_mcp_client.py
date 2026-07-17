"""Tests for mcp/client.py — MCP client."""
from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from mcp.client import MCPClient
from mcp.protocol import MCPResponse, MCPTool


class TestMCPClient:
    def test_init_stdio_defaults(self):
        client = MCPClient(transport="stdio", command=["echo", "test"])
        assert client.transport == "stdio"
        assert client.command == ["echo", "test"]
        assert client.connected is False

    def test_init_http(self):
        client = MCPClient(transport="http", url="http://localhost:8080")
        assert client.transport == "http"
        assert client.url == "http://localhost:8080"

    def test_list_tools_when_connected(self):
        """list_tools returns tools from server response."""
        client = MCPClient(transport="http", url="http://localhost:8080")
        client.connected = True
        client._send_request_sync = MagicMock(
            return_value=MCPResponse(
                id=1,
                result={
                    "tools": [
                        {"name": "test", "description": "t", "input_schema": {}},
                        {"name": "scan", "description": "s", "input_schema": {}},
                    ],
                },
            ),
        )
        tools = client.list_tools()
        assert len(tools) == 2
        assert tools[0].name == "test"
        assert tools[1].name == "scan"

    def test_list_tools_with_error_response(self):
        """list_tools raises RuntimeError when server returns error."""
        client = MCPClient(transport="http", url="http://localhost:8080")
        client.connected = True
        client._send_request_sync = MagicMock(
            return_value=MCPResponse(id=1, error={"code": -1, "message": "fail"}),
        )
        with pytest.raises(RuntimeError, match="fail"):
            client.list_tools()

    def test_list_tools_not_connected(self):
        client = MCPClient(transport="stdio", command=["echo", "test"])
        with pytest.raises(ConnectionError):
            client.list_tools()

    def test_call_tool_raises_when_not_connected(self):
        client = MCPClient(transport="stdio", command=["echo", "test"])
        with pytest.raises(ConnectionError):
            client.call_tool("nonexistent", {})

    def test_call_tool_connected_returns_result(self):
        """call_tool returns parsed result when connected."""
        client = MCPClient(transport="http", url="http://localhost:8080")
        client.connected = True
        client._send_request_sync = MagicMock(
            return_value=MCPResponse(
                id=1,
                result={
                    "content": [{"type": "text", "text": '{"ok": true}'}],
                },
            ),
        )
        result = client.call_tool("test", {})
        assert result == {"ok": True}

    def test_call_tool_string_content(self):
        """When content is not JSON, returns response.result."""
        client = MCPClient(transport="http", url="http://localhost:8080")
        client.connected = True
        client._send_request_sync = MagicMock(
            return_value=MCPResponse(
                id=1,
                result={"content": [{"type": "text", "text": '"plain text"'}], "extra": "data"},
            ),
        )
        result = client.call_tool("test", {})
        assert result == "plain text"

    def test_call_tool_no_content(self):
        client = MCPClient(transport="http", url="http://localhost:8080")
        client.connected = True
        client._send_request_sync = MagicMock(
            return_value=MCPResponse(id=1, result={"status": "ok"}),
        )
        result = client.call_tool("test", {})
        assert result == {"status": "ok"}

    def test_call_tool_error_response(self):
        client = MCPClient(transport="http", url="http://localhost:8080")
        client.connected = True
        client._send_request_sync = MagicMock(
            return_value=MCPResponse(id=1, error={"code": -1, "message": "tool error"}),
        )
        with pytest.raises(RuntimeError, match="tool error"):
            client.call_tool("test", {})

    def test_connect_http(self):
        """Http transport sets up correctly without crashing."""
        client = MCPClient(transport="http", url="http://localhost:8080")
        assert client.transport == "http"
        assert client.url == "http://localhost:8080"
        assert client.connected is False

    def test_disconnect_when_not_connected(self):
        client = MCPClient(transport="stdio", command=["echo", "test"])
        asyncio.run(client.disconnect())  # Should not crash

    def test_disconnect_http(self):
        """Disconnecting from http mode should clean up."""
        client = MCPClient(transport="http", url="http://localhost:8080")
        client.connected = True
        mock_proc = MagicMock()
        mock_proc.wait = AsyncMock()
        client.process = mock_proc
        asyncio.run(client.disconnect())
        assert client.connected is False
        assert client.process is None
