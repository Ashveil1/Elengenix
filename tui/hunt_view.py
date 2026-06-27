"""tui/hunt_view.py

Hunt result visualization using the integrated TUI components.

Renders a full beautiful dashboard showing:
- Risk gauge with severity chart
- Vulnerability heatmap (endpoint x category)
- Finding timeline
- Top findings with proof-of-concept
- Theme switcher

Used by hunt command for final visualization.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Dict, List

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from rich import box
from rich.align import Align
from rich.console import Console
from rich.layout import Layout
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from tui.dashboard import build_static_renderable
from tui.themes import THEMES, get_theme
from tui.visualizations import RiskGauge, SeverityChart
from tui.welcome import MissionBriefing, build_welcome_renderable


def _category_for_vuln(finding: Any) -> str:
    """Map finding to heatmap category."""
    cat = getattr(finding, "category", "") or ""
    if isinstance(cat, str):
        return cat
    return str(cat.value if hasattr(cat, "value") else cat)


def render_hunt_dashboard(
    target: str,
    findings: List[Any],
    risk_score: float,
    risk_level: str,
    theme_name: str = "DEFAULT",
    width: int = 140,
) -> Layout:
    """Render a full hunt results dashboard using integrated TUI components."""
    theme = get_theme(theme_name)
    primary = theme.get("primary", "#ff2222")
    text = theme.get("text", "#ffffff")
    muted = theme.get("muted", "#888888")

    layout = Layout()
    layout.split_column(
        Layout(name="banner", size=3),
        Layout(name="metrics", size=8),
        Layout(name="body"),
        Layout(name="footer", size=3),
    )
    layout["body"].split_row(
        Layout(name="left", ratio=1),
        Layout(name="right", ratio=2),
    )

    # Banner
    banner = Text()
    banner.append("  ELENGENIX", style=f"bold {primary}")
    banner.append("  //  ", style=muted)
    banner.append("HUNT COMPLETE", style=f"bold {text}")
    banner.append("  //  ", style=muted)
    banner.append(f"TARGET: {target}", style=text)
    layout["banner"].update(Align.center(banner, vertical="middle"))

    # Metrics row: Risk gauge + Severity chart
    metrics_table = Table.grid(padding=(0, 2), expand=True)
    metrics_table.add_column(ratio=1)
    metrics_table.add_column(ratio=2)

    risk_int = int(risk_score) if isinstance(risk_score, (int, float)) else 0
    gauge = RiskGauge(value=risk_int, max_value=100, label="RISK SCORE").render()

    # Count by severity (live findings only)
    by_sev = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Informational": 0}
    for f in findings:
        sev = getattr(f, "severity", "Informational")
        if hasattr(sev, "value"):
            sev = sev.value
        if sev in by_sev:
            by_sev[sev] += 1
    sev_chart = SeverityChart(
        critical=by_sev["Critical"],
        high=by_sev["High"],
        medium=by_sev["Medium"],
        low=by_sev["Low"],
        info=by_sev["Informational"],
    ).render()

    metrics_table.add_row(gauge, sev_chart)
    layout["metrics"].update(
        Panel(
            metrics_table,
            border_style=primary,
            box=box.HEAVY,
        )
    )

    # LEFT: Findings list (top critical/high)
    layout["left"].update(_render_findings_panel(findings, theme_name))

    # RIGHT: Top findings + heatmap
    layout["right"].split_column(
        Layout(name="top", ratio=2),
        Layout(name="heatmap", ratio=1),
    )
    layout["top"].update(_render_top_findings(findings, theme_name))
    layout["heatmap"].update(_render_heatmap(findings, theme_name))

    # Footer
    footer = Text()
    footer.append("  [", style=muted)
    footer.append("ELENGENIX", style=f"bold {primary}")
    footer.append("] ", style=muted)
    footer.append("  Risk: ", style=muted)
    footer.append(f"{risk_score:.0f}/100 ({risk_level})", style=f"bold {primary}")
    footer.append("  ", style=muted)
    footer.append("•  ", style=primary)
    footer.append(f"{len(findings)} findings", style=muted)
    footer.append("  •  ", style=primary)
    footer.append("Theme: ", style=muted)
    footer.append(theme_name, style=f"bold {primary}")
    layout["footer"].update(Align.center(footer, vertical="middle"))

    return layout


def _render_findings_panel(findings: List[Any], theme_name: str) -> Panel:
    """Render left panel with top findings list."""
    theme = get_theme(theme_name)
    primary = theme.get("primary", "#ff2222")
    text = theme.get("text", "#ffffff")
    muted = theme.get("muted", "#888888")

    # Sort by severity
    sev_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Informational": 4}
    live = [
        f
        for f in findings
        if (getattr(f, "severity", "Info") not in ("Informational",))
        and "CANDIDATE" not in (getattr(f, "title", "") or "").upper()
    ]

    def sev_key(f):
        s = getattr(f, "severity", "Informational")
        if hasattr(s, "value"):
            s = s.value
        return sev_order.get(s, 5)

    sorted_f = sorted(live, key=sev_key)
    table = Table.grid(padding=(0, 1))
    table.add_column(width=10)
    table.add_column()

    for f in sorted_f[:15]:
        sev = getattr(f, "severity", "?")
        if hasattr(sev, "value"):
            sev = sev.value
        sev_color = {
            "Critical": primary,
            "High": "yellow",
            "Medium": "white",
            "Low": "dim",
        }.get(sev, "white")
        title = (getattr(f, "title", "") or "")[:80]
        table.add_row(
            f"[bold {sev_color}]{sev[:8]}[/bold {sev_color}]",
            f"[{text}]{title}[/{text}]",
        )

    return Panel(
        table,
        title=f"[{primary}]FINDINGS[/{primary}]",
        border_style=primary,
        box=box.HEAVY,
    )


def _render_top_findings(findings: List[Any], theme_name: str) -> Panel:
    """Render top critical/high findings with details."""
    theme = get_theme(theme_name)
    primary = theme.get("primary", "#ff2222")
    text = theme.get("text", "#ffffff")
    muted = theme.get("muted", "#888888")

    critical_high = [
        f
        for f in findings
        if (getattr(f, "severity", "") in ("Critical", "High"))
        and "CANDIDATE" not in (getattr(f, "title", "") or "").upper()
    ][:8]

    if not critical_high:
        return Panel(
            Text("No Critical/High findings.", style=muted),
            title=f"[{primary}]TOP FINDINGS[/{primary}]",
            border_style=primary,
        )

    table = Table.grid(padding=(0, 1))
    table.add_column(width=12)
    table.add_column(width=20)
    table.add_column()

    for f in critical_high:
        sev = getattr(f, "severity", "?")
        if hasattr(sev, "value"):
            sev = sev.value
        title = (getattr(f, "title", "") or "")[:60]
        url = (getattr(f, "url", "") or "")[:40]
        poc = ""
        ev = getattr(f, "evidence", {}) or {}
        if isinstance(ev, dict):
            poc_data = ev.get("proof_of_concept") or {}
            if isinstance(poc_data, dict):
                poc = (poc_data.get("impact", "") or "")[:80]
        sev_color = primary if sev == "Critical" else "yellow"
        table.add_row(
            f"[bold {sev_color}]{sev[:8]}[/bold {sev_color}]",
            f"[{text}]{title}[/{text}]",
            f"[{muted}]{poc or url}[/{muted}]",
        )

    return Panel(
        table,
        title=f"[{primary}]TOP CRITICAL/HIGH[/{primary}]",
        border_style=primary,
        box=box.HEAVY,
    )


def _render_heatmap(findings: List[Any], theme_name: str) -> Panel:
    """Render vulnerability heatmap."""
    theme = get_theme(theme_name)
    primary = theme.get("primary", "#ff2222")
    text = theme.get("text", "#ffffff")
    muted = theme.get("muted", "#888888")

    # Build endpoint x category matrix
    endpoints: List[str] = set()
    categories: List[str] = set()
    matrix: Dict[tuple, int] = {}

    for f in findings:
        url = (getattr(f, "url", "") or "").replace("http://", "").replace("https://", "")[:30]
        cat = _category_for_vuln(f)[:15]
        if not url or not cat:
            continue
        endpoints.add(url)
        categories.add(cat)
        key = (url, cat)
        sev = getattr(f, "severity", "Info")
        if hasattr(sev, "value"):
            sev = sev.value
        score = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}.get(sev, 0)
        matrix[key] = max(matrix.get(key, 0), score)

    if not endpoints:
        return Panel(
            Text("No data for heatmap", style=muted),
            title=f"[{primary}]VULNERABILITY HEATMAP[/{primary}]",
            border_style=primary,
        )

    endpoints_list = sorted(endpoints)[:8]
    categories_list = sorted(categories)[:6]

    table = Table.grid(padding=(0, 1))
    table.add_column(width=15)
    for cat in categories_list:
        table.add_column(width=8)

    # Header row
    header = [f"[{muted}]ENDPOINT[/{muted}]"]
    for cat in categories_list:
        header.append(f"[bold {text}]{cat[:6]}[/bold {text}]")
    table.add_row(*header)

    # Data rows
    color_map = {0: muted, 1: "green", 2: "yellow", 3: "red", 4: "bold red"}
    char_map = {0: ".", 1: "·", 2: "■", 3: "█", 4: "▓"}
    for ep in endpoints_list:
        row = [f"[{text}]{ep[:13]}[/{text}]"]
        for cat in categories_list:
            score = matrix.get((ep, cat), 0)
            color = color_map.get(score, muted)
            char = char_map.get(score, " ")
            row.append(f"[{color}]{char}[/{color}]")
        table.add_row(*row)

    return Panel(
        table,
        title=f"[{primary}]VULNERABILITY HEATMAP[/{primary}]",
        border_style=primary,
        box=box.HEAVY,
    )


def show_hunt_results(target: str, report: Any, theme_name: str = "DEFAULT"):
    """Show hunt results in beautiful TUI dashboard."""
    console = Console(width=140)
    console.clear()
    layout = render_hunt_dashboard(
        target=target,
        findings=report.findings if hasattr(report, "findings") else [],
        risk_score=report.risk_score if hasattr(report, "risk_score") else 0,
        risk_level=report.risk_level if hasattr(report, "risk_level") else "Unknown",
        theme_name=theme_name,
    )
    console.print(layout)


# ═══════════════════════════════════════════════════════════════════════════
# LAUNCHER (merged from launcher.py)
# ═══════════════════════════════════════════════════════════════════════════


def render_banner(theme_name="DEFAULT"):
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


def render_status_panel(target="", theme_name="DEFAULT"):
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


def render_command_panel(theme_name="DEFAULT"):
    """Render available commands panel."""
    theme = get_theme(theme_name)
    primary = theme.get("primary", "#ff2222")
    text = theme.get("text", "#ffffff")
    muted = theme.get("muted", "#888888")

    table = Table.grid(padding=(0, 1))
    table.add_column(style=f"bold {primary}")
    table.add_column(style=text)

    commands = [
        ("hunt <target>", "Run full vulnerability scan"),
        ("launch", "Show this TUI dashboard"),
        ("report", "View saved reports"),
        ("--theme X", "cyberpunk, matrix, synthwave, stealth"),
    ]
    for cmd, desc in commands:
        table.add_row(f"[{primary}]{cmd}[/{primary}]", f"[{muted}]{desc}[/{muted}]")

    return Panel(
        table,
        title=f"[{primary}]COMMANDS[/{primary}]",
        border_style=primary,
        box=box.HEAVY,
    )


def render_launcher_layout(theme_name="DEFAULT", target="", risk=0):
    """Build complete themed launcher layout (banner + dashboard + sidebar)."""
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

    layout["banner"].update(Align.center(render_banner(theme_name), vertical="middle"))
    layout["dashboard"].update(
        build_static_renderable(
            theme_name=theme_name,
            risk=risk,
            target=target or "demo",
        )
    )
    layout["status"].update(render_status_panel(target, theme_name))
    layout["commands"].update(render_command_panel(theme_name))

    footer = Text()
    footer.append("  [", style=muted)
    footer.append("ELENGENIX", style=f"bold {primary}")
    footer.append("] ", style=muted)
    footer.append("Theme: ", style=muted)
    footer.append(theme_name, style=f"bold {primary}")
    footer.append("  -  ", style=primary)
    footer.append("Mode: ", style=muted)
    footer.append("HUNT", style=f"bold {primary}")
    layout["footer"].update(Align.center(footer, vertical="middle"))

    return layout


def run_launcher(target="", theme_name="DEFAULT"):
    """Render themed launcher dashboard to console."""
    console = Console()
    console.clear()
    console.print(render_banner(theme_name))

    mission = MissionBriefing(
        target=target or "no target set", scan_status="READY", ai_status="READY"
    )
    console.print(build_welcome_renderable(mission=mission))
    console.print(render_launcher_layout(theme_name, target, risk=42))

    console.print(
        "\n[bold cyan]Available themes:[/bold cyan] "
        + ", ".join(f"[cyan]{t}[/cyan]" for t in THEMES.keys())
    )
    console.print("[dim]Run 'elengenix hunt <target>' to scan[/dim]")
