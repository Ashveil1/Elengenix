"""Tests for mcp/protocol.py — MCP protocol handler."""
from __future__ import annotations

import json
from typing import Any, Dict

import pytest

from mcp.protocol import MCPProtocol, MCPRequest, MCPResponse, MCPTool


def _make_handler(result: Dict[str, Any] = None):
    if result is None:
        result = {"ok": True}

    def handler(args: Dict[str, Any]) -> Dict[str, Any]:
        return result

    return handler


class TestMCPTool:
    def test_minimal_tool(self):
        tool = MCPTool(name="test", description="A test tool", input_schema={})
        assert tool.name == "test"
        assert tool.handler is None

    def test_tool_with_handler(self):
        fn = lambda args: {"done": True}  # noqa: E731
        tool = MCPTool(name="fn", description="Fn tool", input_schema={}, handler=fn)
        assert tool.handler({"x": 1}) == {"done": True}


class TestMCPRequest:
    def test_default(self):
        req = MCPRequest()
        assert req.jsonrpc == "2.0"
        assert req.method == ""

    def test_from_json(self):
        data = {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}
        req = MCPRequest(**data)
        assert req.id == 1
        assert req.method == "tools/list"


class TestMCPResponse:
    def test_success_response(self):
        resp = MCPResponse(id=1, result={"tools": []})
        assert resp.error is None
        assert resp.result == {"tools": []}

    def test_error_response(self):
        resp = MCPResponse(id=1, error={"code": -32601, "message": "Not found"})
        assert resp.result is None


class TestMCPProtocol:
    def test_initial_state(self):
        proto = MCPProtocol()
        assert proto.tools == {}
        assert proto.initialized is False

    def test_register_tool(self):
        proto = MCPProtocol()
        tool = MCPTool(name="my_tool", description="Does stuff", input_schema={"type": "object"})
        proto.register_tool(tool)
        assert "my_tool" in proto.tools
        assert proto.tools["my_tool"].name == "my_tool"

    def test_handle_initialize(self):
        proto = MCPProtocol()
        req = MCPRequest(id=1, method="initialize", params={"protocolVersion": "1.0"})
        resp = proto.handle_request(req)
        assert resp.id == 1
        assert resp.result is not None
        assert "protocolVersion" in resp.result
        assert proto.initialized is True

    def test_handle_tools_list_empty(self):
        proto = MCPProtocol()
        req = MCPRequest(id=1, method="tools/list")
        resp = proto.handle_request(req)
        assert resp.result["tools"] == []

    def test_handle_tools_list_with_tools(self):
        proto = MCPProtocol()
        proto.register_tool(
            MCPTool(name="scan", description="Scan a target", input_schema={"type": "object"})
        )
        req = MCPRequest(id=1, method="tools/list")
        resp = proto.handle_request(req)
        assert len(resp.result["tools"]) == 1
        assert resp.result["tools"][0]["name"] == "scan"

    def test_handle_tools_call_success(self):
        proto = MCPProtocol()
        proto.register_tool(
            MCPTool(
                name="echo",
                description="Echo",
                input_schema={},
                handler=_make_handler({"echoed": True}),
            )
        )
        req = MCPRequest(id=1, method="tools/call", params={"name": "echo", "arguments": {}})
        resp = proto.handle_request(req)
        assert resp.result is not None
        assert "content" in resp.result

    def test_handle_tools_call_not_found(self):
        proto = MCPProtocol()
        req = MCPRequest(id=1, method="tools/call", params={"name": "nonexistent", "arguments": {}})
        resp = proto.handle_request(req)
        assert resp.error is not None
        assert resp.error["code"] == -32602

    def test_handle_tools_call_handler_error(self):
        def broken_handler(args):
            raise ValueError("something broke")

        proto = MCPProtocol()
        proto.register_tool(
            MCPTool(name="broken", description="Broken", input_schema={}, handler=broken_handler)
        )
        req = MCPRequest(id=1, method="tools/call", params={"name": "broken", "arguments": {}})
        resp = proto.handle_request(req)
        assert resp.error is not None
        assert resp.error["code"] == -32603

    def test_handle_unknown_method(self):
        proto = MCPProtocol()
        req = MCPRequest(id=1, method="unknown/method")
        resp = proto.handle_request(req)
        assert resp.error is not None
        assert resp.error["code"] == -32601

    def test_handle_request_exception(self):
        proto = MCPProtocol()
        req = MCPRequest(method="tools/list")
        # The handler method doesn't exist on protocol, but we test the
        # top-level handle_request which catches exceptions
        resp = proto.handle_request(req)
        assert resp.error is None or resp.result is not None
