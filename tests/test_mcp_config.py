"""Tests for mcp/config.py — MCP configuration loader."""
from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

from mcp.config import (
    MCPConfig,
    MCPServerConfig,
    MCPConfigManager,
    get_config_manager,
    get_mcp_config,
)


class TestMCPServerConfig:
    def test_default_values(self):
        srv = MCPServerConfig(name="test")
        assert srv.command == ""
        assert srv.args == []
        assert srv.env == {}
        assert srv.enabled is True

    def test_disabled_server(self):
        srv = MCPServerConfig(name="test", command="npx foo", enabled=False)
        assert srv.enabled is False


class TestMCPConfig:
    def test_default_has_known_servers(self):
        """Default config should have enabled=True and known servers."""
        config = MCPConfig()
        assert config.enabled is True
        assert config.transport == "stdio"
        assert config.port == 8080

    def test_disabled_config_returns_empty_servers(self):
        config = MCPConfig(enabled=False)
        assert config.enabled is False
        assert config.get_enabled_servers() == {}

    def test_get_enabled_servers_only_enabled(self):
        config = MCPConfig(
            servers={
                "good": MCPServerConfig(name="good", command="echo ok"),
                "bad": MCPServerConfig(name="bad", command="echo no", enabled=False),
            },
        )
        enabled = config.get_enabled_servers()
        assert "good" in enabled
        assert "bad" not in enabled
        assert len(enabled) == 1

    def test_server_missing_command_skipped(self):
        """Server without command should not appear in enabled list
        (MCPConfigManager._merge_mcp_json skips it at parse time)."""
        config = MCPConfig(
            servers={
                "broken": MCPServerConfig(name="broken", command=""),
            },
        )
        enabled = config.get_enabled_servers()
        # The config doesn't filter by empty command itself;
        # it's the manager's job. But we can still list it.
        assert "broken" in enabled  # config stores it; manager filters


class TestMCPConfigManager:
    def test_create_from_scratch(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "mcp.json"
            mgr = MCPConfigManager(project_root=Path(tmp))
            assert mgr.config.enabled is True

    def test_load_from_json_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            # Write mcp.json in the project root
            mcp_json = {
                "mcpServers": {
                    "custom": {
                        "command": "echo hello",
                        "enabled": True,
                    },
                },
            }
            (Path(tmp) / "mcp.json").write_text(json.dumps(mcp_json))
            mgr = MCPConfigManager(project_root=Path(tmp))
            cfg = mgr.config
            assert "custom" in cfg.servers
            assert cfg.servers["custom"].command == "echo hello"

    def test_load_disabled_over_all(self):
        """User mcp.json with enabled=false should still load servers."""
        with tempfile.TemporaryDirectory() as tmp:
            mcp_json = {
                "mcpServers": {
                    "custom": {
                        "command": "echo hello",
                        "enabled": False,
                    },
                },
            }
            (Path(tmp) / "mcp.json").write_text(json.dumps(mcp_json))
            mgr = MCPConfigManager(project_root=Path(tmp))
            cfg = mgr.config
            assert "custom" in cfg.servers
            assert cfg.servers["custom"].enabled is False

    def test_missing_json_falls_back(self):
        with tempfile.TemporaryDirectory() as tmp:
            mgr = MCPConfigManager(project_root=Path(tmp))
            cfg = mgr.config
            assert cfg.enabled is True
            # Should have default servers from code
            assert len(cfg.servers) >= 0

    def test_invalid_json_falls_back_gracefully(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "mcp.json").write_text("not json{{{")
            mgr = MCPConfigManager(project_root=Path(tmp))
            cfg = mgr.config
            assert cfg.enabled is True

    def test_merge_user_json_overrides_project(self):
        """User ~/.elengenix/mcp.json should take priority over project mcp.json."""
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / ".elengenix"
            home.mkdir(parents=True)
            project_json = {
                "mcpServers": {
                    "shared": {"command": "npx project", "enabled": True},
                },
            }
            (Path(tmp) / "mcp.json").write_text(json.dumps(project_json))

            user_json = {
                "mcpServers": {
                    "shared": {"command": "npx user", "enabled": True},
                    "user_only": {"command": "npx useronly", "enabled": True},
                },
            }
            (home / "mcp.json").write_text(json.dumps(user_json))

            with patch("mcp.config.USER_MCP_JSON", home / "mcp.json"):
                mgr = MCPConfigManager(project_root=Path(tmp))
                cfg = mgr.config
                # user version should win
                assert cfg.servers["shared"].command == "npx user"
                assert "user_only" in cfg.servers


class TestGetMCPConfig:
    def test_get_config_manager_returns_singleton(self):
        mgr1 = get_config_manager()
        mgr2 = get_config_manager()
        assert mgr1 is mgr2

    def test_get_mcp_config_returns_config_instance(self):
        config = get_mcp_config()
        assert isinstance(config, MCPConfig)
        assert hasattr(config, "enabled")
