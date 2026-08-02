"""
cli/provider_info.py — Provider pre-flight display for Elengenix.

Before any chat or scan runs, users should see exactly which AI provider
will be used, which model, where the API key is coming from, and whether
the endpoint is reachable. This module renders
``tools.ai_config.describe_provider_setup()`` using the shared Rich
console — no new dependencies, no hidden fallbacks.
"""

from __future__ import annotations

from typing import Any, Dict

from cli.ui_components import console


def render_provider_status_panel(info: Dict[str, Any] | None = None) -> bool:
    """Render the startup provider status panel.

    Args:
        info: Pre-fetched ``describe_provider_setup()`` result, or None to
            fetch it now.

    Returns:
        True when a usable provider is configured, False otherwise.
    """
    try:
        if info is None:
            from tools.ai_config import describe_provider_setup

            info = describe_provider_setup()
    except Exception as e:  # never break startup on a display issue
        console.print(f"[dim]Provider check unavailable: {e}[/dim]")
        return False

    active = info.get("active") or ""
    model = info.get("model") or "(default)"
    key_set = bool(info.get("key_set"))
    key_source = info.get("key_source", "none (not set)")
    ok = bool(info.get("ok"))

    reachable_txt = "[dim]not checked[/dim]"
    for p in info.get("providers", []):
        if p.get("name") == active:
            r = p.get("reachable")
            if r is True:
                reachable_txt = "[bold #ffffff]reachable[/bold #ffffff]"
            elif r is False:
                reachable_txt = "[bold #888888]unreachable[/bold #888888]"

    console.print("  [bold #ffffff]AI PROVIDER[/bold #ffffff]")
    if active:
        key_txt = (
            f"[bold #ffffff]set[/bold #ffffff] [dim]({key_source})[/dim]"
            if key_set
            else "[bold #888888]NOT SET[/bold #888888]"
        )
        console.print(
            f"  [dim]provider:[/dim] [bold #ffffff]{active}[/bold #ffffff]   "
            f"[dim]model:[/dim] [bold #ffffff]{model}[/bold #ffffff]"
        )
        console.print(
            f"  [dim]key:[/dim]     {key_txt}   "
            f"[dim]endpoint:[/dim] {reachable_txt}"
        )
    else:
        console.print("  [dim]provider:[/dim] [bold #888888]none selected[/bold #888888]")

    if not ok or not key_set:
        console.print(
            "  [bold #ffffff][WARN][/bold #ffffff] No usable AI provider key found.\n"
            "  [dim]Fix: set an env key (e.g. [/dim][bold]GEMINI_API_KEY[/bold][dim]) "
            "or run[/dim] [bold]elengenix configure[/bold]"
        )
    console.print(f"  [dim #737373]{'-' * 56}[/dim #737373]")
    return ok and (key_set or not active)
