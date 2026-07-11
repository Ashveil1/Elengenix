"""
mcp/client.py — MCP Client for Elengenix

Connects to external MCP servers to use their tools.
Allows Elengenix to leverage tools from other MCP servers.

Usage:
    from mcp.client import MCPClient
    client = MCPClient("stdio", command=["python3", "-m", "mcp.server"])
    client.connect()
    tools = client.list_tools()
    result = client.call_tool("tool_name", {"arg": "value"})
"""

from __future__ import annotations

import asyncio
import json
import logging
import subprocess
from typing import Any, Dict, List, Optional

from mcp.protocol import MCPProtocol, MCPRequest, MCPResponse, MCPTool

logger = logging.getLogger("elengenix.mcp.client")


class MCPClient:
    """MCP Client that connects to external MCP servers.

    Supports stdio transport for connecting to local MCP servers.
    """

    def __init__(
        self,
        transport: str = "stdio",
        command: Optional[List[str]] = None,
        url: Optional[str] = None,
    ):
        """Initialize MCP client.

        Args:
            transport: Transport type ("stdio" or "http").
            command: Command to start MCP server (for stdio).
            url: URL of MCP server (for http).
        """
        self.transport = transport
        self.command = command
        self.url = url
        self.protocol = MCPProtocol()
        self.process: Optional[asyncio.subprocess.Process] = None
        self.connected = False

    async def connect(self) -> None:
        """Connect to the MCP server."""
        if self.transport == "stdio":
            await self._connect_stdio()
        elif self.transport == "http":
            await self._connect_http()
        else:
            raise ValueError(f"Unknown transport: {self.transport}")

        # Initialize
        request = MCPRequest(method="initialize", params={})
        response = await self._send_request(request)
        if response.error:
            raise ConnectionError(f"Initialize failed: {response.error}")

        self.connected = True
        logger.info(f"Connected to MCP server")

    async def _connect_stdio(self) -> None:
        """Connect via stdio transport."""
        if not self.command:
            raise ValueError("Command is required for stdio transport")

        self.process = await asyncio.create_subprocess_exec(
            *self.command,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        logger.info(f"Started MCP server: {self.command}")

    async def _connect_http(self) -> None:
        """Connect via HTTP transport."""
        if not self.url:
            raise ValueError("URL is required for HTTP transport")
        # HTTP connection is stateless, just set the URL
        logger.info(f"HTTP MCP server: {self.url}")

    async def disconnect(self) -> None:
        """Disconnect from the MCP server."""
        if self.process:
            self.process.terminate()
            await self.process.wait()
            self.process = None
        self.connected = False
        logger.info("Disconnected from MCP server")

    def list_tools(self) -> List[MCPTool]:
        """List available tools from the server."""
        if not self.connected:
            raise ConnectionError("Not connected to MCP server")

        request = MCPRequest(method="tools/list", params={})
        response = self._send_request_sync(request)

        if response.error:
            raise RuntimeError(f"List tools failed: {response.error}")

        tools = []
        for tool_data in response.result.get("tools", []):
            tools.append(
                MCPTool(
                    name=tool_data["name"],
                    description=tool_data.get("description", ""),
                    input_schema=tool_data.get("inputSchema", {}),
                )
            )

        return tools

    def call_tool(self, name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Call a tool on the server."""
        if not self.connected:
            raise ConnectionError("Not connected to MCP server")

        request = MCPRequest(method="tools/call", params={"name": name, "arguments": arguments})
        response = self._send_request_sync(request)

        if response.error:
            raise RuntimeError(f"Tool call failed: {response.error}")

        # Parse content from result
        content = response.result.get("content", [])
        if content and content[0].get("type") == "text":
            return json.loads(content[0]["text"])

        return response.result

    async def _send_request(self, request: MCPRequest) -> MCPResponse:
        """Send request and wait for response."""
        if self.transport == "stdio":
            return await self._send_stdio(request)
        elif self.transport == "http":
            return await self._send_http(request)
        else:
            raise ValueError(f"Unknown transport: {self.transport}")

    def _send_request_sync(self, request: MCPRequest) -> MCPResponse:
        """Send request synchronously (blocking)."""
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            return loop.run_until_complete(self._send_request(request))
        finally:
            loop.close()

    async def _send_stdio(self, request: MCPRequest) -> MCPResponse:
        """Send request via stdio."""
        if not self.process or not self.process.stdin or not self.process.stdout:
            raise ConnectionError("Process not started")

        # Send request
        request_json = self.protocol.to_json(request)
        self.process.stdin.write(f"{request_json}\n".encode())
        await self.process.stdin.drain()

        # Read response
        response_line = await self.process.stdout.readline()
        if not response_line:
            raise ConnectionError("No response from server")

        return self.protocol.from_json(response_line.decode())

    async def _send_http(self, request: MCPRequest) -> MCPResponse:
        """Send request via HTTP."""
        import aiohttp

        async with aiohttp.ClientSession() as session:
            async with session.post(
                self.url,
                data=self.protocol.to_json(request),
                headers={"Content-Type": "application/json"},
            ) as resp:
                response_text = await resp.text()
                return self.protocol.from_json(response_text)
