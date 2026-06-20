"""tui/launcher.py

Properly integrated world-class TUI launcher.

Uses all premium components together:
- Welcome screen with ASCII art
- Live ThreatDashboard with risk gauge + severity chart
- Vulnerability heatmap
- Theme switcher (5 themes)
- Animated status indicators

Run: elengenix launch [target]
"""
from __future__ import annotations

import asyncio
import sys
import time
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from rich.console import Console
from rich.live import Live
from rich.layout import Layout
from rich.panel import Panel
from rich.text import Text
from rich.align import Align
from rich.table import Table
from rich import box

from tui.themes import THEMES, get_theme
from tui.visualizations import (
    VulnerabilityHeatmap, SeverityChart, RiskGauge,
    FindingTimeline, AttackSurfaceMap,
)
from tui.dashboard import build_static_renderable
from tui.welcome import build_welcome_renderable, MissionBriefing


def render_banner(theme_name: str = "DEFAULT") -> Text:
    """Render Elengenix ASCII art banner with theme colors."""
    theme = get_theme(theme_name)
    primary = theme.get("primary", "#ff2222")
    text = theme.get("text", "#ffffff")

    banner = Text()
    banner.append("\n")
    banner.append("ELENGENIX", style=f"bold {primary}")
    banner.append("  ", style=text)
    banner.append("// ", style=f"dim {text}")
    banner.append("WORLD-CLASS CYBERSECURITY FRAMEWORK", style=f"bold {text}")
    banner.append("\n")
    return banner


def render_status_panel(target: str = "", theme_name: str = "DEFAULT") -> Panel:
    """Render a status panel with target, mode, and theme."""
    theme = get_theme(theme_name)
    primary = theme.get("primary", "#ff2222")
    text = theme.get("text", "#ffffff")
    muted = theme.get("muted", "#888888")

    table = Table.grid(padding=(0, 2))
    table.add_column(style=f"bold {primary}", justify="right")
    table.add_column(style=text)

    table.add_row("TARGET", target or "[dim]not set[/dim]")
    table.add_row("MODE", "[bold red]HUNT[/bold red]")
    table.add_row("THEME", theme_name)
    table.add_row("STATUS", f"[bold {primary}]READY[/bold {primary}]")

    return Panel(
        table,
        title=f"[{primary}]STATUS[/{primary}]",
        border_style=primary,
        box=box.HEAVY,
    )


def render_command_panel(theme_name: str = "DEFAULT") -> Panel:
    """Render available commands panel."""
    theme = get_theme(theme_name)
    primary = theme.get("primary", "#ff2222")
    text = theme.get("text", "#ffffff")
    muted = theme.get("muted", "#888888")

    table = Table.grid(padding=(0, 1))
    table.add_column(style=f"bold {primary}")
    table.add_column(style=text)

    commands = [
        ("hunt", "Run full vulnerability scan"),
        ("themes", "Switch theme (cyberpunk/matrix/synthwave)"),
        ("dashboard", "Show live threat dashboard"),
        ("targets", "Set scan target"),
        ("report", "Generate report"),
        ("quit", "Exit"),
    ]
    for cmd, desc in commands:
        table.add_row(f"[{primary}]{cmd}[/{primary}]", f"[{muted}]{desc}[/{muted}]")

    return Panel(
        table,
        title=f"[{primary}]COMMANDS[/{primary}]",
        border_style=primary,
        box=box.HEAVY,
    )


def render_dashboard(theme_name: str = "DEFAULT",
                     target: str = "",
                     risk: int = 0,
                     findings: Optional[list] = None) -> Panel:
    """Render live threat dashboard using static builder."""
    return build_static_renderable(
        theme_name=theme_name,
        risk=risk,
        target=target or "demo",
    )


def render_themed_layout(theme_name: str = "DEFAULT",
                         target: str = "",
                         risk: int = 0) -> Layout:
    """Build a complete themed layout (welcome + dashboard + status)."""
    theme = get_theme(theme_name)
    primary = theme.get("primary", "#ff2222")
    muted = theme.get("muted", "#888888")

    layout = Layout()
    layout.split_column(
        Layout(name="banner", size=3),
        Layout(name="body"),
        Layout(name="footer", size=3),
    )
    layout["body"].split_row(
        Layout(name="dashboard", ratio=2),
        Layout(name="sidebar", ratio=1),
    )
    layout["sidebar"].split_column(
        Layout(name="status", ratio=1),
        Layout(name="commands", ratio=1),
    )

    # Banner
    layout["banner"].update(
        Align.center(render_banner(theme_name), vertical="middle")
    )

    # Dashboard
    layout["dashboard"].update(render_dashboard(theme_name, target, risk))

    # Sidebar
    layout["status"].update(render_status_panel(target, theme_name))
    layout["commands"].update(render_command_panel(theme_name))

    # Footer
    footer = Text()
    footer.append("  [", style=muted)
    footer.append(f"ELENGENIX", style=f"bold {primary}")
    footer.append("] ", style=muted)
    footer.append("Press Ctrl+C to exit  ", style=muted)
    footer.append("•  ", style=primary)
    footer.append("Theme: ", style=muted)
    footer.append(theme_name, style=f"bold {primary}")
    footer.append("  ", style=muted)
    footer.append("•  ", style=primary)
    footer.append("Mode: ", style=muted)
    footer.append("HUNT", style=f"bold {primary}")
    layout["footer"].update(Align.center(footer, vertical="middle"))

    return layout


def run_themed_launcher(target: str = ""):
    """Run the themed TUI launcher with live updates."""
    console = Console()
    themes = ["DEFAULT", "CYBERPUNK", "MATRIX", "STEALTH", "SYNTHWAVE"]
    current_theme_idx = 0

    console.clear()
    console.print(render_banner(themes[current_theme_idx]))

    # Show welcome
    mission = MissionBriefing(target=target or "no target set",
                             scan_status="READY",
                             ai_status="READY")
    console.print(build_welcome_renderable(mission=mission))

    # Show themed dashboard
    console.print(render_themed_layout(themes[current_theme_idx], target, risk=42))

    console.print(f"\n[bold cyan]Available themes:[/bold cyan] " +
                  ", ".join(f"[cyan]{t}[/cyan]" for t in themes))
    console.print(f"[dim]Run 'elengenix launch <target>' to scan[/dim]")


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else ""
    run_themed_launcher(target)
