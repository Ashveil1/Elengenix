"""tui/visualizations.py - Reusable Rich renderables for security data.

All public classes here produce Rich ``Renderable`` objects that can be
embedded in any Rich container (Panel, Group, Table, Columns) or in
Textual widgets. They are self-contained: no Textual app required.

Provided:
    * :class:`VulnerabilityHeatmap` - endpoint x vulnerability-type matrix
    * :class:`FindingTimeline`      - chronological finding list
    * :class:`ExploitChainDiagram`  - ASCII attack chain visualisation
    * :class:`AttackSurfaceMap`     - tree of discovered endpoints
    * :class:`RiskGauge`            - radial speedometer
    * :class:`SeverityChart`        - horizontal bar chart of severities
"""

from __future__ import annotations

import logging
import math
from dataclasses import dataclass
from datetime import datetime
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from rich.align import Align
from rich.box import ROUNDED, SIMPLE
from rich.console import Group, RenderResult
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.tree import Tree

logger = logging.getLogger("elengenix.tui.visualizations")

# ---------------------------------------------------------------------------
# Severity helpers
# ---------------------------------------------------------------------------

SEVERITY_ORDER: Tuple[str, ...] = ("critical", "high", "medium", "low", "info")
SEVERITY_GLYPH: Dict[str, str] = {
    "critical": "#",
    "high": "X",
    "medium": "x",
    "low": ".",
    "info": "o",
}

# Default colours used when a theme manager is not provided.
DEFAULT_SEVERITY_COLORS: Dict[str, str] = {
    "critical": "#ff003c",
    "high": "#ff5500",
    "medium": "#ffb300",
    "low": "#81c784",
    "info": "#888888",
}


def _color_for(
    severity: str,
    severity_colors: Optional[Dict[str, str]] = None,
) -> str:
    palette = severity_colors or DEFAULT_SEVERITY_COLORS
    return palette.get(severity.lower(), "#888888")


# ---------------------------------------------------------------------------
# VulnerabilityHeatmap
# ---------------------------------------------------------------------------


@dataclass
class HeatmapCell:
    """A single cell in a :class:`VulnerabilityHeatmap`."""

    row: str
    col: str
    severity: str = "info"
    count: int = 1
    label: str = ""


class VulnerabilityHeatmap:
    """Endpoint x vulnerability-type matrix, colour-coded by severity.

    Usage:
        heat = VulnerabilityHeatmap(
            endpoints=["api.example.com", "admin.example.com"],
            vuln_types=["XSS", "IDOR", "SQLi", "SSRF", "Auth"],
        )
        heat.set("api.example.com", "XSS", "high", 3)
        console.print(heat.render())
    """

    def __init__(
        self,
        endpoints: Sequence[str],
        vuln_types: Sequence[str],
        severity_colors: Optional[Dict[str, str]] = None,
        width: int = 80,
        color_scale: Optional[Sequence[str]] = None,
    ) -> None:
        self.endpoints = list(endpoints)
        self.vuln_types = list(vuln_types)
        self.severity_colors = severity_colors or DEFAULT_SEVERITY_COLORS
        self.width = width
        self._cells: Dict[Tuple[str, str], HeatmapCell] = {}
        self.color_scale = color_scale or (
            "#0a0a0a",
            "#3a1a1a",
            "#7a1a1a",
            "#bb2a2a",
            "#ff3a3a",
            "#ff6666",
        )

    def set(
        self,
        endpoint: str,
        vuln_type: str,
        severity: str = "info",
        count: int = 1,
        label: str = "",
    ) -> None:
        """Set the value of a single cell."""
        self._cells[(endpoint, vuln_type)] = HeatmapCell(
            row=endpoint, col=vuln_type, severity=severity, count=count, label=label
        )

    def get(self, endpoint: str, vuln_type: str) -> Optional[HeatmapCell]:
        return self._cells.get((endpoint, vuln_type))

    def render(self) -> Panel:
        """Build the heatmap as a Rich ``Panel``."""
        n_cols = len(self.vuln_types)
        # Pick a column width that fits the requested width.
        col_w = max(3, min(10, (self.width - len(self.endpoints[0]) - 4) // max(1, n_cols)))
        table = Table(
            show_header=True,
            header_style="bold #ffffff",
            box=SIMPLE,
            border_style="#444444",
            padding=(0, 0),
            expand=False,
        )
        table.add_column("Endpoint", style="#ffffff", no_wrap=True)
        for vt in self.vuln_types:
            table.add_column(vt[:col_w], justify="center", width=col_w, style="#888888")

        for ep in self.endpoints:
            row_cells: List[Text] = []
            for vt in self.vuln_types:
                cell = self._cells.get((ep, vt))
                if cell is None or cell.count == 0:
                    row_cells.append(Text("\u00b7", style="#333333"))
                else:
                    color = _color_for(cell.severity, self.severity_colors)
                    intensity = min(len(self.color_scale) - 1, cell.count)
                    bg = self.color_scale[intensity]
                    glyph = SEVERITY_GLYPH.get(cell.severity.lower(), "?")
                    row_cells.append(Text(glyph, style=f"bold {color} on {bg}"))
            table.add_row(Text(ep, style="#ffffff"), *row_cells)

        # Build a tiny legend.
        legend = Text()
        for sev in SEVERITY_ORDER:
            color = _color_for(sev, self.severity_colors)
            legend.append(f" {SEVERITY_GLYPH[sev]} {sev.upper():8s}", style=color)
        legend.append("   (darker = fewer hits)", style="#666666")

        body = Group(table, Text(""), legend)
        return Panel(
            body,
            title="[bold]VULNERABILITY HEATMAP[/bold]",
            border_style="#888888",
            box=ROUNDED,
            padding=(0, 1),
        )


# ---------------------------------------------------------------------------
# FindingTimeline
# ---------------------------------------------------------------------------


@dataclass
class Finding:
    """Lightweight container for timeline items."""

    title: str
    severity: str = "info"
    location: str = ""
    timestamp: Optional[datetime] = None
    description: str = ""


class FindingTimeline:
    """Chronological list of security findings (newest first by default).

    Renders as a vertical column of cards, each with a timestamp, severity
    badge, and a short description. Use :meth:`add` to append and
    :meth:`render` to obtain the final Rich renderable.
    """

    def __init__(
        self,
        findings: Optional[Iterable[Finding]] = None,
        newest_first: bool = True,
        severity_colors: Optional[Dict[str, str]] = None,
        max_items: int = 50,
    ) -> None:
        self.findings: List[Finding] = list(findings or [])
        self.newest_first = newest_first
        self.severity_colors = severity_colors or DEFAULT_SEVERITY_COLORS
        self.max_items = max_items

    def add(
        self,
        title: str,
        severity: str = "info",
        location: str = "",
        timestamp: Optional[datetime] = None,
        description: str = "",
    ) -> None:
        """Append a new finding to the timeline."""
        self.findings.append(
            Finding(
                title=title,
                severity=severity,
                location=location,
                timestamp=timestamp or datetime.now(),
                description=description,
            )
        )
        # Trim the list if needed.
        if len(self.findings) > self.max_items * 2:
            self.findings = self.findings[-self.max_items :]

    def render(self) -> Panel:
        """Build the timeline as a Rich ``Panel``."""
        items = sorted(
            self.findings,
            key=lambda f: f.timestamp or datetime.min,
            reverse=self.newest_first,
        )[: self.max_items]

        rows: List[RenderResult] = []
        for f in items:
            color = _color_for(f.severity, self.severity_colors)
            ts = f.timestamp.strftime("%H:%M:%S") if f.timestamp else "--:--:--"
            line = Text()
            line.append(f" {ts} ", style="#888888")
            line.append(f"[{f.severity.upper():8s}] ", style=f"bold {color}")
            line.append(f.title, style="bold #ffffff")
            if f.location:
                line.append(f"  {f.location}", style="#888888")
            rows.append(line)
            if f.description:
                rows.append(Text(f"          {f.description[:80]}", style="#666666"))
            rows.append(Text(""))

        if not rows:
            rows = [Text("  (no findings yet)", style="#666666")]

        return Panel(
            Group(*rows),
            title="[bold]FINDING TIMELINE[/bold]",
            border_style="#888888",
            box=ROUNDED,
            padding=(0, 1),
        )


# ---------------------------------------------------------------------------
# ExploitChainDiagram
# ---------------------------------------------------------------------------


@dataclass
class ExploitStep:
    """A single step in an exploit chain."""

    title: str
    detail: str = ""
    severity: str = "medium"
    success: bool = True


class ExploitChainDiagram:
    """ASCII-art visualisation of a multi-step attack chain.

    Each step is rendered as a card; arrows connect them vertically. The
    final card is highlighted as the objective.
    """

    ARROW = "    |"
    ARROW_HEAD = "    v"

    def __init__(
        self,
        steps: Optional[Iterable[ExploitStep]] = None,
        title: str = "Exploit Chain",
        objective: str = "Objective reached",
        severity_colors: Optional[Dict[str, str]] = None,
    ) -> None:
        self.steps: List[ExploitStep] = list(steps or [])
        self.title = title
        self.objective = objective
        self.severity_colors = severity_colors or DEFAULT_SEVERITY_COLORS

    def add(
        self, title: str, detail: str = "", severity: str = "medium", success: bool = True
    ) -> None:
        self.steps.append(
            ExploitStep(title=title, detail=detail, severity=severity, success=success)
        )

    def render(self) -> Panel:
        """Build the chain as a Rich ``Panel``."""
        rows: List[RenderResult] = []
        for i, step in enumerate(self.steps):
            color = _color_for(step.severity, self.severity_colors)
            glyph = "[OK]" if step.success else "[FAIL]"
            box = Text()
            box.append("  +--", style=color)
            box.append(f" {glyph} ", style=f"bold {color}")
            box.append(f"Step {i + 1}: ", style="#888888")
            box.append(step.title, style="bold #ffffff")
            if step.detail:
                box.append(f"\n  |   {step.detail[:80]}", style="#888888")
            box.append("\n  +", style=color)
            rows.append(box)
            if i < len(self.steps) - 1:
                rows.append(Text(self.ARROW, style="#888888"))
                rows.append(Text(self.ARROW_HEAD, style="#888888"))

        # Final objective block.
        rows.append(Text("    |", style="#888888"))
        rows.append(Text("    v", style="#ff003c"))
        rows.append(Text("  +--[ OBJECTIVE ]-- " + self.objective, style="bold #ff003c"))

        return Panel(
            Group(*rows),
            title=f"[bold]{self.title}[/bold]",
            border_style="#ff003c",
            box=ROUNDED,
            padding=(0, 1),
        )


# ---------------------------------------------------------------------------
# AttackSurfaceMap
# ---------------------------------------------------------------------------


@dataclass
class Endpoint:
    """An endpoint discovered during recon."""

    path: str
    method: str = "GET"
    risk: str = "low"  # critical / high / medium / low / info
    notes: str = ""


class AttackSurfaceMap:
    """Tree of discovered endpoints with per-node risk scoring.

    Endpoints are organised under path prefixes; each leaf node shows the
    HTTP method, risk colour, and any captured notes.
    """

    def __init__(
        self,
        endpoints: Optional[Iterable[Endpoint]] = None,
        severity_colors: Optional[Dict[str, str]] = None,
    ) -> None:
        self.endpoints: List[Endpoint] = list(endpoints or [])
        self.severity_colors = severity_colors or DEFAULT_SEVERITY_COLORS

    def add(self, path: str, method: str = "GET", risk: str = "low", notes: str = "") -> None:
        self.endpoints.append(Endpoint(path=path, method=method, risk=risk, notes=notes))

    def render(self) -> Panel:
        """Build the attack surface as a Rich ``Panel`` containing a Tree."""
        root = Tree(
            Text("attack surface", style="bold #ffffff"),
            guide_style="#555555",
        )
        # Group endpoints by top-level segment.
        grouped: Dict[str, List[Endpoint]] = {}
        for ep in self.endpoints:
            parts = [p for p in ep.path.split("/") if p]
            head = parts[0] if parts else "/"
            grouped.setdefault(head, []).append(
                Endpoint(
                    path="/" + "/".join(parts[1:]) if len(parts) > 1 else "/",
                    method=ep.method,
                    risk=ep.risk,
                    notes=ep.notes,
                )
            )

        for head, items in sorted(grouped.items()):
            head_color = _color_for(
                max(
                    (i.risk for i in items),
                    key=lambda r: SEVERITY_ORDER.index(r) if r in SEVERITY_ORDER else 99,
                ),
                self.severity_colors,
            )
            branch = root.add(
                Text(f"/{head}", style=f"bold {head_color}"),
            )
            for ep in sorted(items, key=lambda e: e.path):
                color = _color_for(ep.risk, self.severity_colors)
                leaf = Text()
                leaf.append(f"{ep.method:<6s}", style="#888888")
                leaf.append(f" {ep.path:<32s}", style="#ffffff")
                leaf.append(f"  [{ep.risk.upper():7s}]", style=f"bold {color}")
                if ep.notes:
                    leaf.append(f"  {ep.notes[:40]}", style="#666666")
                branch.add(leaf)

        return Panel(
            root,
            title="[bold]ATTACK SURFACE[/bold]",
            border_style="#888888",
            box=ROUNDED,
            padding=(0, 1),
        )


# ---------------------------------------------------------------------------
# RiskGauge - radial speedometer
# ---------------------------------------------------------------------------


class RiskGauge:
    """Radial gauge (speedometer style) rendered with ASCII art.

    The arc is drawn with box-drawing characters, with a tick mark and
    label at major positions. The current value is highlighted, and a
    short caption is shown below the arc.

    Example:
        gauge = RiskGauge(value=73, max_value=100, label="RISK SCORE")
        console.print(gauge.render())
    """

    # Half-circle arc characters (top half), from -90 deg (left) to +90 deg (right).
    ARC = " \u2570\u256f\u256d\u256e\u2588"
    TICKS = "|----+----+----+----+----+"

    def __init__(
        self,
        value: float = 0.0,
        max_value: float = 100.0,
        label: str = "RISK",
        width: int = 32,
        height: int = 10,
        low_color: str = "#81c784",
        mid_color: str = "#ffb300",
        high_color: str = "#ff003c",
        unit: str = "",
    ) -> None:
        self.value = max(0.0, float(value))
        self.max_value = max(1.0, float(max_value))
        self.label = label
        self.width = max(16, width)
        self.height = max(6, height)
        self.low_color = low_color
        self.mid_color = mid_color
        self.high_color = high_color
        self.unit = unit

    def _arc_color(self, ratio: float) -> str:
        if ratio < 0.5:
            return self.low_color
        if ratio < 0.8:
            return self.mid_color
        return self.high_color

    def render(self) -> Panel:
        """Build the gauge as a Rich ``Panel``."""
        ratio = min(1.0, max(0.0, self.value / self.max_value))
        # Build the arc: a series of layers.
        lines: List[Text] = []
        cx = self.width // 2
        radius = min(self.width // 2 - 2, self.height * 2 - 1)
        # Vertical rows: 0 is top, height-1 is bottom (where the value sits).
        rows = self.height
        for r in range(rows):
            line = Text(" " * (cx - radius))
            for x in range(2 * radius + 1):
                # Compute distance from the centre of the arc.
                dx = x - radius
                dy = (rows - 1) - r
                dist = math.sqrt(dx * dx + (dy * 2) ** 2)
                # We're drawing the top half of a circle.
                in_arc = abs(dist - radius) < 1.0 and dy >= 0
                if in_arc:
                    # Map x to angle.
                    theta = math.atan2(dy, dx - 0) + math.pi  # 0..pi
                    fill = theta / math.pi  # 0..1
                    if fill <= ratio:
                        line.append(self.ARC[4], style=f"bold {self._arc_color(fill)}")
                    else:
                        line.append(self.ARC[1], style="#333333")
                else:
                    line.append(" ", style="")
            lines.append(line)

        # Value line below the arc.
        value_text = Text()
        value_text.append(" " * max(0, cx - 4))
        value_text.append(
            f"{int(round(self.value))}{self.unit}", style=f"bold {self._arc_color(ratio)}"
        )
        lines.append(value_text)

        # Caption (centred horizontally to the panel width).
        cap = Text(self.label, style="#888888", justify="center", end="")
        lines.append(Align.center(cap, width=self.width))

        return Panel(
            Group(*lines),
            title=f"[bold]{self.label}[/bold]",
            border_style="#888888",
            box=ROUNDED,
            padding=(0, 1),
            width=self.width + 2,
        )


# ---------------------------------------------------------------------------
# SeverityChart - horizontal bar chart
# ---------------------------------------------------------------------------


class SeverityChart:
    """Horizontal bar chart showing the count of each severity level.

    Renders as a small, dense panel suitable for dashboards.
    """

    def __init__(
        self,
        critical: int = 0,
        high: int = 0,
        medium: int = 0,
        low: int = 0,
        info: int = 0,
        severity_colors: Optional[Dict[str, str]] = None,
        max_bar_width: int = 24,
        title: str = "FINDINGS BY SEVERITY",
    ) -> None:
        self.counts: Dict[str, int] = {
            "critical": int(critical),
            "high": int(high),
            "medium": int(medium),
            "low": int(low),
            "info": int(info),
        }
        self.severity_colors = severity_colors or DEFAULT_SEVERITY_COLORS
        self.max_bar_width = max_bar_width
        self.title = title

    def set(self, severity: str, count: int) -> None:
        """Update the count for a single severity bucket."""
        severity = severity.lower()
        if severity in self.counts:
            self.counts[severity] = max(0, int(count))

    def render(self) -> Panel:
        """Build the chart as a Rich ``Panel``."""
        max_count = max(1, max(self.counts.values()))
        bar_w = self.max_bar_width
        rows: List[Text] = []
        for sev in SEVERITY_ORDER:
            count = self.counts.get(sev, 0)
            color = _color_for(sev, self.severity_colors)
            filled = int(round((count / max_count) * bar_w))
            row = Text()
            row.append(f" {sev.upper():8s} ", style=f"bold {color}")
            row.append("|", style="#444444")
            row.append("\u2588" * filled, style=f"bold {color}")
            row.append(" " * (bar_w - filled), style="")
            row.append("|", style="#444444")
            row.append(f" {count:>4d}", style="#ffffff")
            rows.append(row)

        return Panel(
            Group(*rows),
            title=f"[bold]{self.title}[/bold]",
            border_style="#888888",
            box=ROUNDED,
            padding=(0, 1),
        )


# ---------------------------------------------------------------------------
# Standalone helpers
# ---------------------------------------------------------------------------


def render_text_panel(
    text: str,
    title: str = "",
    border: str = "#888888",
    style: str = "#ffffff",
    width: Optional[int] = None,
) -> Panel:
    """Wrap a string in a styled Rich ``Panel``."""
    return Panel(
        Text(text, style=style),
        title=f"[bold]{title}[/bold]" if title else None,
        border_style=border,
        box=ROUNDED,
        padding=(0, 1),
        width=width,
    )


__all__ = [
    "SEVERITY_ORDER",
    "SEVERITY_GLYPH",
    "DEFAULT_SEVERITY_COLORS",
    "VulnerabilityHeatmap",
    "HeatmapCell",
    "FindingTimeline",
    "Finding",
    "ExploitChainDiagram",
    "ExploitStep",
    "AttackSurfaceMap",
    "Endpoint",
    "RiskGauge",
    "SeverityChart",
    "render_text_panel",
]
