"""
mcp/config.py — MCP Configuration Management

Handles loading, saving, and managing MCP server configurations.
Supports multiple config sources: mcp.json, config.yaml, CLI wizard.

Config file: mcp.json (user-specific, gitignored)
Template: mcp.json.example (committed to git)
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional
from elengenix.paths import ELENGENIX_HOME

logger = logging.getLogger("elengenix.mcp.config")

# Config search order: ~/.elengenix/mcp.json > project/mcp.json > ~/.elengenix/config.yaml
DEFAULT_MCP_JSON = Path("mcp.json")  # Project-level fallback
USER_MCP_JSON = ELENGENIX_HOME / "mcp.json"  # User config (gitignored)
DEFAULT_MCP_EXAMPLE = Path("mcp.json.example")  # Template (committed)
DEFAULT_CONFIG_YAML = Path("config.yaml")


@dataclass
class MCPServerConfig:
    """Configuration for an MCP server."""

    name: str
    command: str = ""
    args: List[str] = field(default_factory=list)
    env: Dict[str, str] = field(default_factory=dict)
    enabled: bool = True


@dataclass
class MCPConfig:
    """MCP configuration."""

    servers: Dict[str, MCPServerConfig] = field(default_factory=dict)
    enabled: bool = True
    transport: str = "stdio"  # stdio or http
    port: int = 8080

    def get_enabled_servers(self) -> Dict[str, MCPServerConfig]:
        """Get only enabled servers."""
        return {k: v for k, v in self.servers.items() if v.enabled}


class MCPConfigManager:
    """Manages MCP configuration from multiple sources."""

    def __init__(self, project_root: Optional[Path] = None):
        self.project_root = project_root or Path.cwd()
        self._config: Optional[MCPConfig] = None

    @property
    def config(self) -> MCPConfig:
        """Get current configuration (lazy loaded)."""
        if self._config is None:
            self._config = self.load()
        return self._config

    def load(self) -> MCPConfig:
        """Load configuration from all sources.

        Priority: ~/.elengenix/mcp.json > project/mcp.json > config.yaml > defaults
        """
        config = MCPConfig()

        # Load from config.yaml (lowest priority)
        yaml_config = self._load_from_yaml()
        if yaml_config:
            for name, server in yaml_config.servers.items():
                if name not in config.servers:
                    config.servers[name] = server

        # Load from project mcp.json (second priority)
        mcp_json = self.project_root / DEFAULT_MCP_JSON
        if mcp_json.exists():
            self._merge_mcp_json(mcp_json, config)

        # Load from ~/.elengenix/mcp.json (user config, highest priority)
        if USER_MCP_JSON.exists():
            self._merge_mcp_json(USER_MCP_JSON, config, override=True)

        self._config = config
        return config

    def _merge_mcp_json(self, path: Path, config: MCPConfig, override: bool = False) -> None:
        """Merge server entries from an mcp.json file into config."""
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)

            for name, server_data in data.get("mcpServers", {}).items():
                if not override and name in config.servers:
                    continue
                command = server_data.get("command", "")
                args = server_data.get("args", [])

                # If command is a list, extract command and args
                if isinstance(command, list) and len(command) > 0:
                    command = command[0]
                    args = command[1:]

                config.servers[name] = MCPServerConfig(
                    name=name,
                    command=command,
                    args=args,
                    env=server_data.get("env", {}),
                    enabled=server_data.get("enabled", True),
                )
            logger.debug(f"Loaded MCP config from {path}")
        except Exception as e:
            logger.warning(f"Failed to load {path}: {e}")

    def _load_from_yaml(self) -> Optional[MCPConfig]:
        """Load MCP config from config.yaml."""
        try:
            import yaml
        except ImportError:
            return None

        config_path = self.project_root / "config.yaml"
        if not config_path.exists():
            return None

        try:
            with open(config_path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)

            mcp_data = data.get("mcp", {})
            if not mcp_data:
                return None

            config = MCPConfig(
                enabled=mcp_data.get("enabled", True),
                transport=mcp_data.get("transport", "stdio"),
                port=mcp_data.get("port", 8080),
            )

            for name, server_data in mcp_data.get("servers", {}).items():
                config.servers[name] = MCPServerConfig(
                    name=name,
                    command=server_data.get("command", ""),
                    args=server_data.get("args", []),
                    env=server_data.get("env", {}),
                    enabled=server_data.get("enabled", True),
                )

            return config
        except Exception as e:
            logger.warning(f"Failed to load MCP config from {config_path}: {e}")
            return None

    def save(self, config: Optional[MCPConfig] = None) -> None:
        """Save configuration to mcp.json."""
        config = config or self._config
        if config is None:
            return

        mcp_json = self.project_root / DEFAULT_MCP_JSON

        data = {"mcpServers": {}}

        for name, server in config.servers.items():
            server_data = {
                "command": server.command,
                "args": server.args,
            }
            if server.env:
                server_data["env"] = server.env
            if not server.enabled:
                server_data["enabled"] = False

            data["mcpServers"][name] = server_data

        try:
            with open(mcp_json, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
            logger.debug(f"Saved MCP config to {mcp_json}")
        except Exception as e:
            logger.error(f"Failed to save MCP config: {e}")

    def add_server(self, name: str, command: str, args: List[str] = None, **kwargs) -> None:
        """Add a server to configuration."""
        self.config.servers[name] = MCPServerConfig(
            name=name,
            command=command,
            args=args or [],
            **kwargs,
        )
        self.save()

    def remove_server(self, name: str) -> None:
        """Remove a server from configuration."""
        if name in self.config.servers:
            del self.config.servers[name]
            self.save()

    def enable_server(self, name: str, enabled: bool = True) -> None:
        """Enable or disable a server."""
        if name in self.config.servers:
            self.config.servers[name].enabled = enabled
            self.save()

    def get_server_command(self, name: str) -> Optional[List[str]]:
        """Get the full command for a server."""
        if name not in self.config.servers:
            return None

        server = self.config.servers[name]
        if not server.command:
            return None

        return [server.command] + server.args


# Global config manager
_config_manager: Optional[MCPConfigManager] = None


def get_config_manager() -> MCPConfigManager:
    """Get the global config manager."""
    global _config_manager
    if _config_manager is None:
        _config_manager = MCPConfigManager()
    return _config_manager


def get_mcp_config() -> MCPConfig:
    """Get the current MCP configuration."""
    return get_config_manager().config
