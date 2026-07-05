"""tests/test_mcp_config.py — Tests for MCP configuration"""

import json
import tempfile
from pathlib import Path

import pytest

from mcp.config import MCPConfig, MCPConfigManager, MCPServerConfig


class TestMCPConfig:
    def test_default_config(self):
        config = MCPConfig()
        assert config.servers == {}
        assert config.enabled is True
        assert config.transport == "stdio"

    def test_get_enabled_servers(self):
        config = MCPConfig()
        config.servers["server1"] = MCPServerConfig(name="server1", command="npx", enabled=True)
        config.servers["server2"] = MCPServerConfig(name="server2", command="uvx", enabled=False)

        enabled = config.get_enabled_servers()
        assert "server1" in enabled
        assert "server2" not in enabled


class TestMCPConfigManager:
    def test_load_from_json(self, tmp_path):
        mcp_json = tmp_path / "mcp.json"
        mcp_json.write_text(json.dumps({
            "mcpServers": {
                "memory": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-memory"]}
            }
        }))

        manager = MCPConfigManager(tmp_path)
        config = manager.load()

        assert "memory" in config.servers
        assert config.servers["memory"].command == "npx"

    def test_save_to_json(self, tmp_path):
        manager = MCPConfigManager(tmp_path)
        manager.add_server("test", "echo", ["hello"])

        mcp_json = tmp_path / "mcp.json"
        assert mcp_json.exists()

        with open(mcp_json) as f:
            data = json.load(f)
        assert "test" in data["mcpServers"]

    def test_add_remove_server(self, tmp_path):
        manager = MCPConfigManager(tmp_path)

        manager.add_server("server1", "npx", ["arg1"])
        assert "server1" in manager.config.servers

        manager.remove_server("server1")
        assert "server1" not in manager.config.servers

    def test_enable_disable_server(self, tmp_path):
        manager = MCPConfigManager(tmp_path)
        manager.add_server("server1", "npx")

        manager.enable_server("server1", False)
        assert manager.config.servers["server1"].enabled is False

        manager.enable_server("server1", True)
        assert manager.config.servers["server1"].enabled is True

    def test_get_server_command(self, tmp_path):
        manager = MCPConfigManager(tmp_path)
        manager.add_server("server1", "npx", ["-y", "package"])

        cmd = manager.get_server_command("server1")
        assert cmd == ["npx", "-y", "package"]

    def test_get_server_command_not_found(self, tmp_path):
        manager = MCPConfigManager(tmp_path)
        cmd = manager.get_server_command("nonexistent")
        assert cmd is None
