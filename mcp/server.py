"""
mcp/server.py — MCP Server for Elengenix

Exposes Elengenix tools via MCP protocol so external AI agents
can discover and use them.

Usage:
    python3 -m mcp.server
    # or
    from mcp.server import MCPServer
    server = MCPServer()
    server.start_stdio()
"""

from __future__ import annotations

import asyncio
import json
import logging
import sys
from typing import Any, Callable, Dict, Optional

from mcp.config import get_config_manager, get_mcp_config
from mcp.protocol import MCPProtocol, MCPRequest, MCPResponse, MCPTool

logger = logging.getLogger("elengenix.mcp.server")


class MCPServer:
    """MCP Server that exposes Elengenix tools.

    Supports stdio transport for integration with AI agents.
    Loads configuration from .mcp.json and config.yaml.
    """

    def __init__(self, load_config: bool = True):
        self.protocol = MCPProtocol()
        self._register_elengenix_tools()

        if load_config:
            self._load_external_servers()

    def _load_external_servers(self) -> None:
        """Load external MCP servers from configuration."""
        try:
            config = get_mcp_config()
            for name, server_config in config.get_enabled_servers().items():
                if server_config.command:
                    logger.info(f"Loaded MCP server: {name} ({server_config.command})")
        except Exception as e:
            logger.debug(f"Could not load MCP config: {e}")

    def _register_elengenix_tools(self) -> None:
        """Register Elengenix tools with MCP."""
        # Register scan tool
        self.protocol.register_tool(
            MCPTool(
                name="elengenix_scan",
                description="Scan a target for vulnerabilities using Elengenix",
                input_schema={
                    "type": "object",
                    "properties": {
                        "target": {"type": "string", "description": "Target to scan"},
                        "phase": {
                            "type": "string",
                            "description": "Specific phase (recon, waf, fuzz, bola)",
                        },
                    },
                    "required": ["target"],
                },
                handler=self._handle_scan,
            )
        )

        # Register recon tool
        self.protocol.register_tool(
            MCPTool(
                name="elengenix_recon",
                description="Reconnaissance on a target",
                input_schema={
                    "type": "object",
                    "properties": {
                        "target": {"type": "string", "description": "Target to recon"},
                    },
                    "required": ["target"],
                },
                handler=self._handle_recon,
            )
        )

    def _handle_scan(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Handle scan tool call."""
        target = args.get("target", "")
        phase = args.get("phase")

        if not target:
            return {"error": "Target is required"}

        try:
            from pipeline.unified import UnifiedPipeline, ScanConfig

            pipeline = UnifiedPipeline()
            config = ScanConfig(target=target, phases=[phase] if phase else None)

            # Run scan in sync context
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                result = loop.run_until_complete(pipeline.run(config))
            finally:
                loop.close()

            return {
                "success": result.success,
                "findings_count": len(result.findings),
                "summary": result.summary,
                "report_dir": result.report_dir,
            }
        except Exception as e:
            return {"error": str(e)}

    def _handle_recon(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Handle recon tool call."""
        target = args.get("target", "")

        if not target:
            return {"error": "Target is required"}

        try:
            from tools.python_recon import PythonRecon

            recon = PythonRecon(timeout=1.0, max_concurrent=40)
            result = recon.full_recon(target, quick=True)

            return {
                "directories": len(result.get("directories", [])),
                "ports": len(result.get("ports", [])),
                "subdomains": len(result.get("subdomains", [])),
                "parameters": len(result.get("parameters", [])),
            }
        except Exception as e:
            return {"error": str(e)}

    def start_stdio(self) -> None:
        """Start MCP server using stdio transport."""
        logger.info("Starting MCP server (stdio mode)")

        try:
            for line in sys.stdin:
                line = line.strip()
                if not line:
                    continue

                try:
                    request = self.protocol.from_json(line)
                    response = self.protocol.handle_request(request)
                    print(self.protocol.to_json(response), flush=True)
                except json.JSONDecodeError as e:
                    logger.error(f"Invalid JSON: {e}")
                    error_response = MCPResponse(error={"code": -32700, "message": "Parse error"})
                    print(self.protocol.to_json(error_response), flush=True)
        except KeyboardInterrupt:
            logger.info("MCP server stopped")

    def start_http(self, host: str = "localhost", port: int = 8080) -> None:
        """Start MCP server using HTTP transport."""
        from http.server import HTTPServer, BaseHTTPRequestHandler

        server = self

        class MCPHandler(BaseHTTPRequestHandler):
            def do_POST(self):
                content_length = int(self.headers.get("Content-Length", 0))
                body = self.rfile.read(content_length)

                try:
                    request = server.protocol.from_json(body.decode())
                    response = server.protocol.handle_request(request)

                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(server.protocol.to_json(response).encode())
                except Exception as e:
                    self.send_response(500)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    error = {"jsonrpc": "2.0", "error": {"code": -32603, "message": str(e)}}
                    self.wfile.write(json.dumps(error).encode())

            def log_message(self, format, *args):
                logger.debug(f"HTTP: {format % args}")

        httpd = HTTPServer((host, port), MCPHandler)
        logger.info(f"MCP server started on {host}:{port}")
        httpd.serve_forever()


def main():
    """Main entry point for MCP server."""
    logging.basicConfig(level=logging.INFO)

    server = MCPServer()

    if "--stdio" in sys.argv:
        server.start_stdio()
    elif "--http" in sys.argv:
        port = 8080
        for i, arg in enumerate(sys.argv):
            if arg == "--port" and i + 1 < len(sys.argv):
                port = int(sys.argv[i + 1])
        server.start_http(port=port)
    else:
        print("Usage: python3 -m mcp.server [--stdio|--http [--port PORT]]")
        sys.exit(1)


if __name__ == "__main__":
    main()
