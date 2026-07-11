"""tests/test_mcp.py — Tests for MCP protocol and server"""

import json

import pytest

from mcp.protocol import MCPProtocol, MCPRequest, MCPResponse, MCPTool
from mcp.server import MCPServer


class TestMCPProtocol:
    def test_register_tool(self):
        protocol = MCPProtocol()
        tool = MCPTool(
            name="test_tool",
            description="A test tool",
            input_schema={"type": "object", "properties": {}},
        )
        protocol.register_tool(tool)
        assert "test_tool" in protocol.tools

    def test_handle_initialize(self):
        protocol = MCPProtocol()
        request = MCPRequest(method="initialize", params={})
        response = protocol.handle_request(request)
        assert response.result is not None
        assert response.result["serverInfo"]["name"] == "elengenix"

    def test_handle_tools_list(self):
        protocol = MCPProtocol()
        tool = MCPTool(name="test_tool", description="Test", input_schema={"type": "object"})
        protocol.register_tool(tool)

        request = MCPRequest(method="tools/list", params={})
        response = protocol.handle_request(request)
        assert len(response.result["tools"]) == 1
        assert response.result["tools"][0]["name"] == "test_tool"

    def test_handle_tools_call(self):
        protocol = MCPProtocol()
        tool = MCPTool(
            name="test_tool",
            description="Test",
            input_schema={"type": "object"},
            handler=lambda args: {"result": "ok"},
        )
        protocol.register_tool(tool)

        request = MCPRequest(method="tools/call", params={"name": "test_tool", "arguments": {}})
        response = protocol.handle_request(request)
        assert response.result is not None

    def test_handle_unknown_method(self):
        protocol = MCPProtocol()
        request = MCPRequest(method="unknown", params={})
        response = protocol.handle_request(request)
        assert response.error is not None

    def test_json_serialization(self):
        protocol = MCPProtocol()
        response = MCPResponse(id=1, result={"tools": []})
        json_str = protocol.to_json(response)
        assert json.loads(json_str)


class TestMCPServer:
    def test_create_server(self):
        server = MCPServer()
        assert "elengenix_scan" in server.protocol.tools
        assert "elengenix_recon" in server.protocol.tools

    def test_handle_scan_missing_target(self):
        server = MCPServer()
        result = server._handle_scan({})
        assert "error" in result

    def test_handle_recon_missing_target(self):
        server = MCPServer()
        result = server._handle_recon({})
        assert "error" in result
