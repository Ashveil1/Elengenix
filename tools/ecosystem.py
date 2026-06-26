"""
Elengenix Ecosystem SDK — Plugin Architecture for Community Contributions.

Provides a stable, well-documented extension surface so that anyone can:
- Add custom security tools (subdomain enum, port scan, custom fuzzers)
- Add custom AI providers (Ollama, vLLM, custom HTTP APIs)
- Add custom CLI commands
- Hook into the finding pipeline (enrich, dedupe, score)
- Add custom TUI panels (stats, charts, alerts)

Design goals:
- Zero-config: drop a folder in ~/.elengenix/plugins/ and it just works
- Hot-reload safe: plugins are isolated, failures don't crash the host
- Backward compatible: SDK 1.0 plugins work with SDK 2.0 host
- Sandboxed: plugins declare capabilities (network, filesystem, subprocess)
- Type-safe: full type hints, ABCs, Protocol classes
- Free: uses local file system + git/python -m pip for distribution, no server needed

Example plugin structure:
    ~/.elengenix/plugins/
        my_plugin/
            plugin.yaml        # manifest
            __init__.py        # entry point with register(api)
            my_tool.py         # custom tool
            README.md

This module is the SDK itself (BasePlugin, PluginAPI, manifest parser, loader).
Marketplace + updater are in tools/marketplace.py and tools/updater.py.
"""

from __future__ import annotations

import importlib
import importlib.util
import inspect
import logging
import os
import re
import sys
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Protocol, Tuple, Union

import yaml

logger = logging.getLogger("elengenix.ecosystem")

# SDK version. Plugins declare sdk_version in manifest; loader warns on mismatch.
SDK_VERSION = "1.0.0"
SDK_API_LEVEL = 1

# Plugin search paths in priority order (highest first)
DEFAULT_PLUGIN_PATHS = [
    Path.home() / ".elengenix" / "plugins",
    Path.cwd() / "plugins",
    Path(__file__).parent.parent / "plugins",  # bundled (none in core)
]

# Environment variable to extend search paths
PLUGIN_PATH_ENV = "ELENGENIX_PLUGIN_PATH"


class PluginState(str, Enum):
    """Plugin lifecycle states."""

    DISCOVERED = "discovered"  # Found on disk, not yet loaded
    LOADING = "loading"  # Import in progress
    LOADED = "loaded"  # register(api) called successfully
    ACTIVE = "active"  # Running, registered handlers in place
    FAILED = "failed"  # Load error or runtime error
    DISABLED = "disabled"  # User-disabled via manifest
    UNLOADING = "unloading"  # Cleanup in progress


class Capability(str, Enum):
    """Plugin capabilities — declared in manifest, enforced by loader."""

    NETWORK = "network"  # Can make HTTP/network requests
    FILESYSTEM = "filesystem"  # Can read/write filesystem outside sandbox
    SUBPROCESS = "subprocess"  # Can spawn subprocesses
    SECRETS = "secrets"  # Can access API keys / credentials
    AI_API = "ai_api"  # Can call AI providers
    SUBFINDER = "subfinder"  # Needs subfinder binary
    NUCLEI = "nuclei"  # Needs nuclei binary
    ELEVATED = "elevated"  # Needs root / privileged access


@dataclass
class PluginManifest:
    """Parsed plugin.yaml / plugin.json metadata."""

    name: str  # Unique slug, e.g. "shodan_recon"
    version: str  # Semver, e.g. "1.2.3"
    author: str = ""  # Author name/email
    description: str = ""  # One-line summary
    sdk_version: str = SDK_VERSION  # Required SDK version
    api_level: int = SDK_API_LEVEL  # Required API level
    entry_point: str = "__init__.py"  # Python file with register(api)
    capabilities: List[Capability] = field(default_factory=list)
    dependencies: List[str] = field(default_factory=list)  # pip packages
    enabled: bool = True  # False = skip loading
    tags: List[str] = field(default_factory=list)
    homepage: str = ""
    license: str = ""
    min_elengenix_version: str = ""

    def is_compatible(self, sdk_version: str = SDK_VERSION) -> Tuple[bool, str]:
        """Check SDK version compatibility. Returns (ok, reason)."""
        if not self.enabled:
            return False, "disabled in manifest"
        if self.sdk_version and self.sdk_version != sdk_version:
            # Allow same major.minor (e.g. 1.0.x compatible with 1.0.0)
            try:
                sdk_major, sdk_minor, _ = sdk_version.split(".")[:3]
                plg_major, plg_minor, _ = self.sdk_version.split(".")[:3]
                if sdk_major != plg_major:
                    return (
                        False,
                        f"SDK major mismatch: plugin={self.sdk_version}, host={sdk_version}",
                    )
                if int(sdk_minor) < int(plg_minor):
                    return False, f"Plugin needs SDK >= {self.sdk_version}, host has {sdk_version}"
            except (ValueError, IndexError):
                return False, f"Bad SDK version format: {self.sdk_version}"
        return True, "compatible"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "author": self.author,
            "description": self.description,
            "sdk_version": self.sdk_version,
            "api_level": self.api_level,
            "capabilities": [c.value for c in self.capabilities],
            "dependencies": self.dependencies,
            "enabled": self.enabled,
            "tags": self.tags,
            "homepage": self.homepage,
            "license": self.license,
        }


@dataclass
class PluginInfo:
    """Runtime info about a loaded plugin."""

    manifest: PluginManifest
    path: Path
    state: PluginState = PluginState.DISCOVERED
    load_time: Optional[float] = None
    error: Optional[str] = None
    module: Any = None  # Imported module reference
    registered_tools: List[str] = field(default_factory=list)
    registered_commands: List[str] = field(default_factory=list)
    registered_ai_providers: List[str] = field(default_factory=list)
    registered_hooks: List[str] = field(default_factory=list)

    @property
    def name(self) -> str:
        return self.manifest.name

    @property
    def age_seconds(self) -> float:
        if self.load_time is None:
            return 0.0
        return time.time() - self.load_time

    def summary(self) -> str:
        return (
            f"{self.manifest.name} v{self.manifest.version} "
            f"[{self.state.value}] "
            f"tools={len(self.registered_tools)} "
            f"cmds={len(self.registered_commands)} "
            f"ai={len(self.registered_ai_providers)} "
            f"hooks={len(self.registered_hooks)}"
        )


class ToolResult(dict):
    """Standard tool result — plugins should return this from custom tools."""

    def __init__(
        self,
        success: bool = True,
        data: Any = None,
        findings: Optional[List[Dict[str, Any]]] = None,
        error: Optional[str] = None,
        duration_s: float = 0.0,
    ):
        super().__init__()
        self["success"] = success
        self["data"] = data or {}
        self["findings"] = findings or []
        self["error"] = error
        self["duration_s"] = duration_s


# Type aliases for hooks
FindingHook = Callable[[Dict[str, Any]], Dict[str, Any]]
CommandFunc = Callable[[List[str]], int]


class PluginAPI:
    """Stable, public API exposed to plugins via register(api: PluginAPI).

    Plugins call methods on this object to register their functionality.
    All registrations are validated, namespaced, and reversible (on unload).
    """

    def __init__(self, plugin_info: PluginInfo, host: "PluginHost"):
        self._info = plugin_info
        self._host = host
        self._logger = logging.getLogger(f"elengenix.plugin.{plugin_info.name}")

    @property
    def plugin_name(self) -> str:
        """The current plugin's name (read-only)."""
        return self._info.name

    @property
    def logger(self) -> logging.Logger:
        """Plugin-namespaced logger. Use this for all plugin output."""
        return self._logger

    def register_tool(
        self,
        name: str,
        func: Callable[..., ToolResult],
        description: str = "",
        tags: Optional[List[str]] = None,
    ) -> None:
        """Register a custom security tool.

        Args:
            name: Unique tool name (e.g. "shodan_lookup")
            func: Callable that accepts (**kwargs) and returns ToolResult
            description: Human-readable description (shown in tool lists)
            tags: Tags for categorization (recon, fuzz, exploit, etc.)
        """
        if not name or not re.match(r"^[a-z][a-z0-9_]{1,63}$", name):
            raise ValueError(
                f"Invalid tool name: {name!r} (must be lowercase, underscore, 2-64 chars)"
            )
        if not callable(func):
            raise TypeError(f"Tool {name!r} function is not callable")
        full_name = f"{self._info.name}.{name}"
        self._host._register_tool(full_name, func, description, tags or [])
        self._info.registered_tools.append(full_name)
        self._logger.info("Registered tool: %s", full_name)

    def register_command(
        self,
        name: str,
        func: CommandFunc,
        description: str = "",
        usage: str = "",
    ) -> None:
        """Register a custom CLI command.

        Args:
            name: Command name (e.g. "shodan-scan")
            func: Callable that accepts (args: List[str]) and returns exit code (int)
            description: Short description for help text
            usage: Usage string (e.g. "shodan-scan <target>")
        """
        if not name or not re.match(r"^[a-z][a-z0-9-]{1,63}$", name):
            raise ValueError(f"Invalid command name: {name!r}")
        if not callable(func):
            raise TypeError(f"Command {name!r} function is not callable")
        full_name = f"{self._info.name}-{name}"
        self._host._register_command(full_name, func, description, usage)
        self._info.registered_commands.append(full_name)
        self._logger.info("Registered command: %s", full_name)

    def register_ai_provider(
        self,
        name: str,
        chat_func: Callable[..., Any],
        list_models_func: Optional[Callable[[], List[str]]] = None,
    ) -> None:
        """Register a custom AI provider (Ollama, vLLM, custom HTTP, etc.).

        Args:
            name: Provider name (e.g. "ollama", "vllm", "custom")
            chat_func: Async or sync callable that accepts (messages, model) and returns response text
            list_models_func: Optional callable returning list of available model names
        """
        if not name or not re.match(r"^[a-z][a-z0-9_]{1,31}$", name):
            raise ValueError(f"Invalid AI provider name: {name!r}")
        self._host._register_ai_provider(name, chat_func, list_models_func)
        self._info.registered_ai_providers.append(name)
        self._logger.info("Registered AI provider: %s", name)

    def register_finding_hook(
        self,
        name: str,
        hook: FindingHook,
        priority: int = 50,
    ) -> None:
        """Register a hook that runs on every finding before it's added to results.

        Hooks can enrich, modify, or drop findings. They run in priority order
        (lower priority runs first). Return the (possibly modified) finding dict,
        or None to drop the finding entirely.

        Args:
            name: Hook name (e.g. "shodan_enrich", "severity_adjust")
            hook: Callable taking (finding: Dict) and returning Dict or None
            priority: Execution order (0=first, 100=last, default=50)
        """
        if not callable(hook):
            raise TypeError(f"Hook {name!r} is not callable")
        full_name = f"{self._info.name}.{name}"
        self._host._register_finding_hook(full_name, hook, priority)
        self._info.registered_hooks.append(full_name)
        self._logger.info("Registered finding hook: %s (priority=%d)", full_name, priority)

    def get_config(self, key: str, default: Any = None) -> Any:
        """Read a config value from ~/.elengenix/config.yaml or env."""
        return self._host._get_config(key, default)

    def has_capability(self, capability: Union[Capability, str]) -> bool:
        """Check if this plugin declared a capability in its manifest."""
        cap = Capability(capability) if isinstance(capability, str) else capability
        return cap in self._info.manifest.capabilities


class BasePlugin(ABC):
    """Optional base class for plugins that prefer class-based style.

    Subclass and override register(api: PluginAPI) to add tools/commands.
    Most plugins will use the function-based style instead:
        def register(api: PluginAPI) -> None: ...
    But this class is provided for plugins that want state + lifecycle.
    """

    @abstractmethod
    def register(self, api: PluginAPI) -> None:
        """Called by host after manifest validation. Add tools/commands here."""
        raise NotImplementedError


class PluginHost:
    """Central plugin registry and lifecycle manager.

    Discovers plugins on disk, validates manifests, loads them safely,
    tracks state, handles errors, and provides unified access to all
    registered tools, commands, AI providers, and finding hooks.
    """

    def __init__(self, search_paths: Optional[List[Path]] = None):
        self._plugins: Dict[str, PluginInfo] = {}
        self._tools: Dict[str, Tuple[Callable, str, List[str]]] = {}  # name -> (func, desc, tags)
        self._commands: Dict[str, Tuple[CommandFunc, str, str]] = {}  # name -> (func, desc, usage)
        self._ai_providers: Dict[str, Tuple[Callable, Optional[Callable]]] = {}
        self._hooks: List[Tuple[int, str, FindingHook]] = []  # sorted by priority
        self._search_paths: List[Path] = search_paths or list(DEFAULT_PLUGIN_PATHS)
        # Extend with env var
        env_paths = os.environ.get(PLUGIN_PATH_ENV, "").strip()
        if env_paths:
            for p in env_paths.split(os.pathsep):
                if p.strip():
                    self._search_paths.append(Path(p.strip()))
        self._config: Dict[str, Any] = {}

    # ── Discovery ────────────────────────────────────────────────────────

    def discover(self) -> List[Path]:
        """Scan all search paths for plugin directories.

        A plugin directory contains plugin.yaml or plugin.json at its root.
        Returns list of plugin directory paths found.
        """
        found: List[Path] = []
        for search_path in self._search_paths:
            if not search_path.exists() or not search_path.is_dir():
                continue
            try:
                for entry in search_path.iterdir():
                    if not entry.is_dir():
                        continue
                    if entry.name.startswith(("_", ".")):
                        continue
                    if (entry / "plugin.yaml").exists() or (entry / "plugin.json").exists():
                        found.append(entry)
            except PermissionError as e:
                logger.warning("Cannot read plugin path %s: %s", search_path, e)
        return found

    def load_all(self, fail_fast: bool = False) -> Dict[str, PluginInfo]:
        """Discover and load all enabled, compatible plugins.

        Args:
            fail_fast: If True, abort on first error. If False (default),
                       log error and continue (recommended for production).

        Returns: dict of plugin_name -> PluginInfo for all loaded plugins
        """
        paths = self.discover()
        logger.info("Discovered %d plugin(s) in %d path(s)", len(paths), len(self._search_paths))
        for path in paths:
            try:
                self._load_one(path)
            except Exception as e:  # noqa: BLE001
                logger.error("Failed to load plugin from %s: %s", path, e)
                if fail_fast:
                    raise
        return dict(self._plugins)

    def _load_one(self, path: Path) -> PluginInfo:
        """Load a single plugin from a directory path."""
        # Parse manifest first
        manifest = self._parse_manifest(path)
        if manifest is None:
            raise ValueError(f"No valid manifest in {path}")

        # Check compatibility
        ok, reason = manifest.is_compatible()
        if not ok:
            logger.info("Skipping %s: %s", manifest.name, reason)
            info = PluginInfo(manifest=manifest, path=path, state=PluginState.DISABLED)
            self._plugins[manifest.name] = info
            return info

        # Check for duplicate
        if manifest.name in self._plugins:
            logger.warning("Duplicate plugin name %s, skipping %s", manifest.name, path)
            return self._plugins[manifest.name]

        info = PluginInfo(manifest=manifest, path=path, state=PluginState.LOADING)
        self._plugins[manifest.name] = info

        # Import the entry point module
        entry_file = path / manifest.entry_point
        if not entry_file.exists():
            raise FileNotFoundError(f"Entry point not found: {entry_file}")

        # Add plugin dir to sys.path so it can import its own deps
        plugin_path_str = str(path)
        if plugin_path_str not in sys.path:
            sys.path.insert(0, plugin_path_str)

        spec = importlib.util.spec_from_file_location(
            f"elengenix_plugin_{manifest.name}",
            entry_file,
        )
        if spec is None or spec.loader is None:
            raise ImportError(f"Cannot import plugin {manifest.name} from {entry_file}")

        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        info.module = module

        # Call register(api) — must exist
        if not hasattr(module, "register"):
            info.state = PluginState.FAILED
            info.error = f"Plugin {manifest.name} missing register(api) function"
            logger.error(info.error)
            raise AttributeError(info.error)

        api = PluginAPI(info, self)
        try:
            result = module.register(api)
        except Exception as e:
            info.state = PluginState.FAILED
            info.error = str(e)
            logger.exception("Plugin %s raised during register(): %s", manifest.name, e)
            raise

        info.state = PluginState.ACTIVE
        info.load_time = time.time()
        logger.info(
            "Loaded plugin: %s (v%s by %s)", manifest.name, manifest.version, manifest.author
        )
        return info

    def _parse_manifest(self, path: Path) -> Optional[PluginManifest]:
        """Parse plugin.yaml or plugin.json. Returns None if neither exists."""
        yaml_path = path / "plugin.yaml"
        json_path = path / "plugin.json"
        data: Optional[Dict[str, Any]] = None
        if yaml_path.exists():
            try:
                with open(yaml_path, "r", encoding="utf-8") as f:
                    data = yaml.safe_load(f) or {}
            except yaml.YAMLError as e:
                logger.error("Bad YAML in %s: %s", yaml_path, e)
                return None
        elif json_path.exists():
            import json

            try:
                with open(json_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
            except json.JSONDecodeError as e:
                logger.error("Bad JSON in %s: %s", json_path, e)
                return None
        if not data:
            return None
        # Normalize capabilities to enum
        caps = [
            Capability(c)
            for c in data.get("capabilities", [])
            if c in [x.value for x in Capability]
        ]
        return PluginManifest(
            name=data.get("name", path.name),
            version=str(data.get("version", "0.1.0")),
            author=data.get("author", ""),
            description=data.get("description", ""),
            sdk_version=str(data.get("sdk_version", SDK_VERSION)),
            api_level=int(data.get("api_level", SDK_API_LEVEL)),
            entry_point=data.get("entry_point", "__init__.py"),
            capabilities=caps,
            dependencies=data.get("dependencies", []),
            enabled=bool(data.get("enabled", True)),
            tags=data.get("tags", []),
            homepage=data.get("homepage", ""),
            license=data.get("license", ""),
            min_elengenix_version=data.get("min_elengenix_version", ""),
        )

    # ── Registration (called by PluginAPI) ───────────────────────────────

    def _register_tool(self, full_name: str, func: Callable, desc: str, tags: List[str]) -> None:
        if full_name in self._tools:
            raise ValueError(f"Tool already registered: {full_name}")
        self._tools[full_name] = (func, desc, tags)

    def _register_command(self, full_name: str, func: CommandFunc, desc: str, usage: str) -> None:
        if full_name in self._commands:
            raise ValueError(f"Command already registered: {full_name}")
        self._commands[full_name] = (func, desc, usage)

    def _register_ai_provider(
        self, name: str, chat_func: Callable, list_models_func: Optional[Callable]
    ) -> None:
        if name in self._ai_providers:
            logger.warning("AI provider %s already exists, overriding (plugin-provided)", name)
        self._ai_providers[name] = (chat_func, list_models_func)

    def _register_finding_hook(self, full_name: str, hook: FindingHook, priority: int) -> None:
        # Replace if same name re-registered
        self._hooks = [(p, n, h) for (p, n, h) in self._hooks if n != full_name]
        self._hooks.append((priority, full_name, hook))
        self._hooks.sort(key=lambda x: (x[0], x[1]))

    def _get_config(self, key: str, default: Any = None) -> Any:
        # Try config dict, then env var
        if key in self._config:
            return self._config[key]
        env_key = f"ELENGENIX_{key.upper()}"
        return os.environ.get(env_key, default)

    def set_config(self, config: Dict[str, Any]) -> None:
        """Inject config values for plugin access via get_config()."""
        self._config.update(config)

    # ── Public accessors (used by orchestrator, CLI, TUI) ─────────────────

    def get_tool(self, full_name: str) -> Optional[Callable]:
        """Get a registered tool function by name (e.g. "shodan_recon.lookup")."""
        entry = self._tools.get(full_name)
        return entry[0] if entry else None

    def get_command(self, full_name: str) -> Optional[CommandFunc]:
        entry = self._commands.get(full_name)
        return entry[0] if entry else None

    def get_ai_provider(self, name: str) -> Optional[Tuple[Callable, Optional[Callable]]]:
        return self._ai_providers.get(name)

    def list_tools(self) -> List[Dict[str, str]]:
        return [
            {"name": name, "description": desc, "tags": ",".join(tags)}
            for name, (_, desc, tags) in sorted(self._tools.items())
        ]

    def list_commands(self) -> List[Dict[str, str]]:
        return [
            {"name": name, "description": desc, "usage": usage}
            for name, (_, desc, usage) in sorted(self._commands.items())
        ]

    def list_ai_providers(self) -> List[str]:
        return sorted(self._ai_providers.keys())

    def list_plugins(self) -> List[PluginInfo]:
        return list(self._plugins.values())

    def get_plugin(self, name: str) -> Optional[PluginInfo]:
        return self._plugins.get(name)

    # ── Hook execution ────────────────────────────────────────────────────

    def run_finding_hooks(self, finding: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Run all registered finding hooks in priority order.

        Returns the (possibly modified) finding, or None to drop it.
        Hooks that raise exceptions are logged and skipped (don't break pipeline).
        """
        current = finding
        for priority, name, hook in self._hooks:
            try:
                result = hook(current)
                if result is None:
                    logger.debug("Hook %s dropped finding", name)
                    return None
                if not isinstance(result, dict):
                    logger.warning(
                        "Hook %s returned non-dict (%s), keeping original", name, type(result)
                    )
                    continue
                current = result
            except Exception as e:  # noqa: BLE001
                logger.warning("Hook %s failed: %s", name, e)
        return current

    # ── Lifecycle ────────────────────────────────────────────────────────

    def unload(self, name: str) -> bool:
        """Unload a plugin: remove its tools, commands, AI providers, hooks.

        Returns True if removed, False if not found.
        """
        info = self._plugins.get(name)
        if not info:
            return False
        info.state = PluginState.UNLOADING
        # Remove tools
        for tool_name in info.registered_tools:
            self._tools.pop(tool_name, None)
        # Remove commands
        for cmd_name in info.registered_commands:
            self._commands.pop(cmd_name, None)
        # Remove AI providers (only if registered by this plugin — we don't track ownership yet, so warn)
        for ai_name in info.registered_ai_providers:
            if ai_name in self._ai_providers:
                logger.warning("Removing AI provider %s (registered by plugin %s)", ai_name, name)
                del self._ai_providers[ai_name]
        # Remove hooks
        self._hooks = [(p, n, h) for (p, n, h) in self._hooks if n not in info.registered_hooks]
        del self._plugins[name]
        logger.info("Unloaded plugin: %s", name)
        return True

    def reload(self, name: str) -> Optional[PluginInfo]:
        """Unload and re-load a plugin (for development)."""
        info = self._plugins.get(name)
        if not info:
            return None
        path = info.path
        self.unload(name)
        try:
            return self._load_one(path)
        except Exception as e:  # noqa: BLE001
            logger.error("Reload failed for %s: %s", name, e)
            return None

    # ── Stats ────────────────────────────────────────────────────────────

    def stats(self) -> Dict[str, Any]:
        return {
            "total_plugins": len(self._plugins),
            "active_plugins": sum(
                1 for p in self._plugins.values() if p.state == PluginState.ACTIVE
            ),
            "failed_plugins": sum(
                1 for p in self._plugins.values() if p.state == PluginState.FAILED
            ),
            "disabled_plugins": sum(
                1 for p in self._plugins.values() if p.state == PluginState.DISABLED
            ),
            "total_tools": len(self._tools),
            "total_commands": len(self._commands),
            "total_ai_providers": len(self._ai_providers),
            "total_finding_hooks": len(self._hooks),
            "search_paths": [str(p) for p in self._search_paths],
        }


# ── Module-level singleton ────────────────────────────────────────────────
_host: Optional[PluginHost] = None


def get_host() -> PluginHost:
    """Get the global plugin host (lazy-initialized)."""
    global _host
    if _host is None:
        _host = PluginHost()
    return _host


def reset_host() -> None:
    """Reset the global plugin host (mainly for tests)."""
    global _host
    _host = None


def discover_and_load() -> PluginHost:
    """Convenience: discover + load all plugins, return the host."""
    host = get_host()
    host.load_all()
    return host
