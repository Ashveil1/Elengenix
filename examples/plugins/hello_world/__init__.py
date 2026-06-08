"""
Hello World Plugin — Minimal example showing the Plugin API.

This plugin:
  - Registers a custom tool "greet" that returns a greeting
  - Registers a custom command "hello" that prints a message
  - Registers a finding hook that tags all findings

To use:
  1. Copy this folder to ~/.elengenix/plugins/hello_world/
  2. Run `python3 main.py` — the tool/command will be auto-discovered
"""

from __future__ import annotations

from typing import List

from tools.ecosystem import ToolResult

PLUGIN_NAME = "hello_world"
PLUGIN_VERSION = "1.0.0"


def register(api) -> None:
    """Called by PluginHost after manifest validation.

    Use the `api` object to register tools, commands, AI providers, and hooks.
    """
    api.logger.info("Hello from %s v%s!", api.plugin_name, PLUGIN_VERSION)

    # Register a custom tool
    api.register_tool(
        name="greet",
        func=_greet,
        description="Generate a greeting for the given name",
        tags=["demo", "utility"],
    )

    # Register a custom command
    api.register_command(
        name="hello",
        func=_hello_cmd,
        description="Print a friendly hello message",
        usage="hello [name]",
    )

    # Register a finding hook that adds a 'tagged_by_hello' marker
    api.register_finding_hook(
        name="tag",
        hook=_tag_hook,
        priority=10,  # Lower priority = runs first
    )


def _greet(name: str = "world") -> ToolResult:
    """Generate a friendly greeting.

    Args:
        name: Who to greet (default: "world")

    Returns:
        ToolResult with success=True and data={'message': '...'}
    """
    return ToolResult(
        success=True,
        data={"message": f"Hello, {name}! (from {PLUGIN_NAME})"},
    )


def _hello_cmd(args: List[str]) -> int:
    """CLI command that prints a hello message.

    Args:
        args: Command-line arguments (e.g. ["Alice"] for "hello Alice")

    Returns:
        Exit code (0 = success)
    """
    name = args[0] if args else "world"
    print(f"Hello, {name}! (from {PLUGIN_NAME} plugin)")
    return 0


def _tag_hook(finding: dict) -> dict:
    """Enrich every finding with a marker showing it went through this plugin.

    Args:
        finding: The finding dict (may be modified or returned as None to drop)

    Returns:
        Modified finding dict
    """
    finding["tagged_by_hello"] = True
    return finding
