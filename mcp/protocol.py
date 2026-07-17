"""
mcp/protocol.py — MCP Protocol Implementation

Implements the Model Context Protocol (MCP) for tool discovery and execution.
MCP allows AI agents to discover and use tools from external servers.

Protocol: JSON-RPC 2.0 over stdio or HTTP
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger("elengenix.mcp")


@dataclass
class MCPTool:
    """MCP tool definition."""

    name: str
    description: str
    input_schema: Dict[str, Any]
    handler: Optional[Callable] = None


@dataclass
class MCPRequest:
    """MCP JSON-RPC request."""

    jsonrpc: str = "2.0"
    id: Optional[int] = None
    method: str = ""
    params: Dict[str, Any] = field(default_factory=dict)


@dataclass
class MCPResponse:
    """MCP JSON-RPC response."""

    jsonrpc: str = "2.0"
    id: Optional[int] = None
    result: Optional[Dict[str, Any]] = None
    error: Optional[Dict[str, Any]] = None


class MCPProtocol:
    """MCP protocol handler for tool discovery and execution.

    Handles MCP methods:
    - initialize: Handshake with client
    - tools/list: List available tools
    - tools/call: Execute a tool
    """

    def __init__(self):
        self.tools: Dict[str, MCPTool] = {}
        self.initialized = False

    def register_tool(self, tool: MCPTool) -> None:
        """Register a tool with the MCP server."""
        self.tools[tool.name] = tool
        logger.debug(f"Registered MCP tool: {tool.name}")

    def handle_request(self, request: MCPRequest) -> MCPResponse:
        """Handle an MCP JSON-RPC request."""
        try:
            if request.method == "initialize":
                return self._handle_initialize(request)
            elif request.method == "tools/list":
                return self._handle_tools_list(request)
            elif request.method == "tools/call":
                return self._handle_tools_call(request)
            else:
                return MCPResponse(
                    id=request.id,
                    error={"code": -32601, "message": f"Method not found: {request.method}"},
                )
        except Exception as e:
            logger.error(f"MCP request error: {e}")
            return MCPResponse(id=request.id, error={"code": -32603, "message": str(e)})

    def _handle_initialize(self, request: MCPRequest) -> MCPResponse:
        """Handle initialize handshake."""
        self.initialized = True
        return MCPResponse(
            id=request.id,
            result={
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": "elengenix", "version": "1.0.0"},
            },
        )

    def _handle_tools_list(self, request: MCPRequest) -> MCPResponse:
        """Handle tools/list request."""
        tools_list = []
        for name, tool in self.tools.items():
            tools_list.append(
                {
                    "name": tool.name,
                    "description": tool.description,
                    "inputSchema": tool.input_schema,
                }
            )

        return MCPResponse(id=request.id, result={"tools": tools_list})

    def _handle_tools_call(self, request: MCPRequest) -> MCPResponse:
        """Handle tools/call request."""
        tool_name = request.params.get("name")
        arguments = request.params.get("arguments", {})

        if tool_name not in self.tools:
            return MCPResponse(
                id=request.id, error={"code": -32602, "message": f"Tool not found: {tool_name}"}
            )

        tool = self.tools[tool_name]
        if not tool.handler:
            return MCPResponse(
                id=request.id,
                error={"code": -32603, "message": f"Tool has no handler: {tool_name}"},
            )

        try:
            result = tool.handler(arguments)
            return MCPResponse(
                id=request.id, result={"content": [{"type": "text", "text": json.dumps(result)}]}
            )
        except Exception as e:
            return MCPResponse(id=request.id, error={"code": -32603, "message": str(e)})

    def to_json(self, obj) -> str:
        """Serialize MCP request or response to JSON."""
        data = {"jsonrpc": obj.jsonrpc}
        if obj.id is not None:
            data["id"] = obj.id
        if hasattr(obj, "method") and obj.method:
            data["method"] = obj.method
        if hasattr(obj, "params") and obj.params:
            data["params"] = obj.params
        if hasattr(obj, "result") and obj.result is not None:
            data["result"] = obj.result
        if hasattr(obj, "error") and obj.error is not None:
            data["error"] = obj.error
        return json.dumps(data)

    def from_json(self, json_str: str) -> MCPRequest:
        """Deserialize MCP request from JSON."""
        data = json.loads(json_str)
        return MCPRequest(
            jsonrpc=data.get("jsonrpc", "2.0"),
            id=data.get("id"),
            method=data.get("method", ""),
            params=data.get("params", {}),
        )
