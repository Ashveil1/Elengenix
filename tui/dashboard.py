"""tui/dashboard.py - Real-time threat & operations dashboard for Elengenix.

Provides :class:`ThreatDashboard`, a composite Textual widget that shows:

    * Header bar with current theme, target, and overall risk score
    * A radial :class:`~tui.visualizations.RiskGauge` for risk scoring
    * A "threat map" with animated markers showing live network events
    * Live CPU / memory / network statistics (updated by a worker)
    * An active-scans panel with per-scan ETA
    * A findings feed, newest first, severity-coloured
    * A topology view of discovered hosts

The dashboard is designed to be dropped into any Textual app::

    class MyApp(App):
        def compose(self):
            yield ThreatDashboard()
"""

from __future__ import annotations

import logging
import math
import random
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Tuple

from rich.align import Align
from rich.box import HEAVY, ROUNDED, SIMPLE
from rich.console import Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from textual.containers import Container, Horizontal, Vertical
from textual.reactive import reactive
from textual.widget import Widget
from textual.widgets import Static
from textual import work

from ui_components import console as shared_console
from .themes import ThemeManager, get_theme
from .visualizations import (
    FindingTimeline,
    RiskGauge,
    SeverityChart,
    render_text_panel,
)

logger = logging.getLogger("elengenix.tui.dashboard")


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------


@dataclass
class SystemStats:
    """Live system statistics (CPU, memory, network)."""

    cpu: float = 0.0
    memory: float = 0.0
    net_in: float = 0.0
    net_out: float = 0.0
    timestamp: float = 0.0


@dataclass
class Scan:
    """An active scan shown in the dashboard."""

    name: str
    target: str
    progress: float = 0.0
    started_at: float = 0.0
    eta: float = 0.0
    status: str = "running"


@dataclass
class Host:
    """A host in the topology graph."""

    ip: str
    hostname: str = ""
    role: str = "unknown"
    risk: str = "low"


@dataclass
class Finding:
    """A single security finding for the feed."""

    title: str
    severity: str = "info"
    location: str = ""
    timestamp: datetime = field(default_factory=datetime.now)
    description: str = ""


@dataclass
class ThreatMarker:
    """A pulsing marker on the threat map."""

    x: int
    y: int
    severity: str = "info"
    label: str = ""
    pulse: float = 0.0  # 0..1


# ---------------------------------------------------------------------------
# ThreatDashboard widget
# ---------------------------------------------------------------------------


class ThreatDashboard(Container):
    """Composite dashboard widget.

    The dashboard is a grid of Static sub-panels. A timer (set in
    :meth:`on_mount`) advances the simulation:

        * system stats drift via :meth:`_tick_system`
        * threat markers pulse and expire via :meth:`_tick_threats`
        * scans progress via :meth:`_tick_scans`

    Live data is provided by the parent app via the reactive properties
    (:attr:`risk_score`, :attr:`target`, :attr:`theme_name`, etc.) and
    the public :meth:`add_finding`, :meth:`add_threat`, :meth:`add_scan`
    methods.
    """

    DEFAULT_CSS = """
    ThreatDashboard {
        layout: vertical;
        width: 100%;
        height: 100%;
        background: #0d0d0d;
    }
    ThreatDashboard #dash-header {
        height: 3;
    }
    ThreatDashboard #dash-row-top {
        height: 1fr;
    }
    ThreatDashboard #dash-row-bottom {
        height: 1fr;
    }
    ThreatDashboard #gauge-panel,
    ThreatDashboard #threatmap-panel,
    ThreatDashboard #scans-panel,
    ThreatDashboard #findings-panel,
    ThreatDashboard #stats-panel,
    ThreatDashboard #topology-panel {
        width: 1fr;
        height: 1fr;
        border: round #444444;
    }
    """

    risk_score = reactive(0)
    target = reactive("no target")
    theme_name = reactive("DEFAULT")
    clock = reactive("00:00:00")

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self.findings: List[Finding] = []
        self.scans: List[Scan] = []
        self.hosts: List[Host] = []
        self.markers: List[ThreatMarker] = []
        self.stats = SystemStats(timestamp=time.time())
        self._threatmap_w = 40
        self._threatmap_h = 14
        self._topology_w = 30
        self._topology_h = 10
        self._tick_timer = None
        self._max_findings = 50
        self._max_markers = 16
        self._max_scans = 6

    # -- Compose ------------------------------------------------------------

    def compose(self):
        """Compose the dashboard layout."""
        yield Static(id="dash-header")
        with Horizontal(id="dash-row-top"):
            yield Static(id="gauge-panel")
            yield Static(id="threatmap-panel")
            yield Static(id="scans-panel")
        with Horizontal(id="dash-row-bottom"):
            yield Static(id="findings-panel")
            yield Static(id="stats-panel")
            yield Static(id="topology-panel")

    def on_mount(self) -> None:
        """Start the simulation timer and prime the panels."""
        self._seed_demo_data()
        self._refresh_all()
        # 4 FPS is enough for dashboard updates (15 FPS if you want smoother).
        self._tick_timer = self.set_interval(0.25, self._tick)

    def on_unmount(self) -> None:
        """Stop the simulation timer on removal."""
        if self._tick_timer is not None:
            self._tick_timer.stop()
            self._tick_timer = None

    # -- Public API --------------------------------------------------------

    def add_finding(
        self,
        title: str,
        severity: str = "info",
        location: str = "",
        description: str = "",
    ) -> None:
        """Append a new finding to the feed."""
        self.findings.append(
            Finding(
                title=title,
                severity=severity,
                location=location,
                description=description,
                timestamp=datetime.now(),
            )
        )
        if len(self.findings) > self._max_findings * 2:
            self.findings = self.findings[-self._max_findings:]
        self._refresh_findings()

    def add_threat(
        self,
        x: Optional[int] = None,
        y: Optional[int] = None,
        severity: str = "info",
        label: str = "",
    ) -> None:
        """Drop a new pulsing marker onto the threat map."""
        x = x if x is not None else random.randint(0, self._threatmap_w - 1)
        y = y if y is not None else random.randint(0, self._threatmap_h - 1)
        self.markers.append(
            ThreatMarker(x=x, y=y, severity=severity, label=label, pulse=0.0)
        )
        if len(self.markers) > self._max_markers:
            self.markers = self.markers[-self._max_markers:]
        self._refresh_threatmap()

    def add_scan(
        self,
        name: str,
        target: str = "",
        duration: float = 60.0,
    ) -> None:
        """Add a new active scan."""
        self.scans.append(
            Scan(
                name=name,
                target=target or self.target,
                progress=0.0,
                started_at=time.time(),
                eta=duration,
                status="running",
            )
        )
        if len(self.scans) > self._max_scans:
            self.scans = self.scans[-self._max_scans:]
        self._refresh_scans()

    def add_host(self, ip: str, hostname: str = "", role: str = "unknown", risk: str = "low") -> None:
        """Add a host to the topology view."""
        self.hosts.append(Host(ip=ip, hostname=hostname, role=role, risk=risk))
        self._refresh_topology()

    def update_stats(self, cpu: float, memory: float, net_in: float, net_out: float) -> None:
        """Update the system stats panel."""
        self.stats = SystemStats(
            cpu=max(0.0, min(100.0, cpu)),
            memory=max(0.0, min(100.0, memory)),
            net_in=max(0.0, net_in),
            net_out=max(0.0, net_out),
            timestamp=time.time(),
        )
        self._refresh_stats()

    def watch_risk_score(self, _) -> None:
        self._refresh_gauge()
        self._refresh_header()

    def watch_target(self, _) -> None:
        self._refresh_header()

    def watch_theme_name(self, _) -> None:
        self._refresh_all()

    # -- Internal: simulation ---------------------------------------------

    def _seed_demo_data(self) -> None:
        """Populate the dashboard with demo data so it looks alive."""
        if not self.findings:
            demo_findings = [
                ("Open admin port", "high", ":8080/admin", "Default credentials may be in use"),
                ("Reflected XSS in search", "medium", "/search?q=", "User input echoed without sanitisation"),
                ("TLS 1.0 enabled", "medium", ":443", "Deprecated protocol version supported"),
                ("Verbose error page", "low", "/api/items/0", "Stack trace returned in response body"),
                ("CORS wildcard", "info", "global", "Access-Control-Allow-Origin: *"),
            ]
            for title, sev, loc, desc in demo_findings:
                self.add_finding(title, sev, loc, desc)
        if not self.hosts:
            for ip, role, risk in [
                ("10.0.0.1",  "gateway",   "low"),
                ("10.0.0.5",  "web",       "medium"),
                ("10.0.0.12", "database",  "high"),
                ("10.0.0.20", "auth",      "critical"),
                ("10.0.0.30", "cache",     "low"),
            ]:
                self.add_host(ip, role=role, risk=risk)
        if not self.scans:
            self.add_scan("Recon", duration=120.0)
            self.add_scan("Vuln scan", duration=300.0)
        if not self.markers:
            for _ in range(4):
                self.add_threat(severity=random.choice(["info", "medium", "high"]))

    def _tick(self) -> None:
        """Per-frame simulation tick."""
        # Advance scan progress.
        now = time.time()
        for s in self.scans:
            if s.status != "running":
                continue
            elapsed = now - s.started_at
            s.progress = min(1.0, elapsed / max(1.0, s.eta))
            s.eta = max(0.0, s.eta - 0.25)
            if s.progress >= 1.0:
                s.status = "done"
        self._refresh_scans()

        # Advance marker pulse, expire old ones.
        for m in self.markers:
            m.pulse = (m.pulse + 0.08) % 1.0
        # Drop markers randomly over time to feel alive.
        if random.random() < 0.10 and len(self.markers) < self._max_markers:
            self.add_threat(severity=random.choice(["info", "info", "medium", "high", "critical"]))
        self._refresh_threatmap()

        # Drift system stats for a live feel.
        if self.stats.timestamp > 0:
            self.stats.cpu = max(5.0, min(95.0, self.stats.cpu + random.uniform(-4, 4)))
            self.stats.memory = max(10.0, min(95.0, self.stats.memory + random.uniform(-2, 2)))
            self.stats.net_in = max(0.0, self.stats.net_in + random.uniform(-50, 50))
            self.stats.net_out = max(0.0, self.stats.net_out + random.uniform(-50, 50))
        else:
            self.stats = SystemStats(
                cpu=random.uniform(20, 60),
                memory=random.uniform(40, 70),
                net_in=random.uniform(50, 200),
                net_out=random.uniform(30, 150),
                timestamp=now,
            )
        self._refresh_stats()

        # Update clock.
        self.clock = datetime.now().strftime("%H:%M:%S")
        self._refresh_header()

    # -- Internal: render helpers ----------------------------------------

    def _refresh_all(self) -> None:
        self._refresh_header()
        self._refresh_gauge()
        self._refresh_threatmap()
        self._refresh_scans()
        self._refresh_findings()
        self._refresh_stats()
        self._refresh_topology()

    def _refresh_header(self) -> None:
        widget = self.query_one("#dash-header", Static)
        theme = get_theme(self.theme_name)
        primary = theme.get("primary", "#ff2222")
        text = theme.get("text", "#ffffff")
        muted = theme.get("muted", "#888888")
        accent = theme.get("accent", "#ffffff")
        score = int(round(self.risk_score))
        score_color = (
            theme.get("critical") if score >= 80 else
            theme.get("high")     if score >= 60 else
            theme.get("medium")   if score >= 30 else
            theme.get("low")
        )

        line = Text()
        line.append(" ELENGENIX", style=f"bold {primary}")
        line.append("  /  ", style=muted)
        line.append("THREAT DASHBOARD", style=f"bold {text}")
        line.append("  /  ", style=muted)
        line.append(f"TARGET: {self.target}", style=accent)
        line.append("  /  ", style=muted)
        line.append(f"RISK: {score}", style=f"bold {score_color}")
        line.append("  /  ", style=muted)
        line.append(f"THEME: {self.theme_name}", style=text)
        line.append("  ", style="")
        line.append(self.clock, style=f"bold {primary}")

        widget.update(
            Panel(
                line,
                border_style=primary,
                box=HEAVY,
                padding=(0, 1),
            )
        )

    def _refresh_gauge(self) -> None:
        widget = self.query_one("#gauge-panel", Static)
        theme = get_theme(self.theme_name)
        gauge = RiskGauge(
            value=self.risk_score,
            max_value=100,
            label="RISK SCORE",
            low_color=theme.get("low", "#81c784"),
            mid_color=theme.get("medium", "#ffb300"),
            high_color=theme.get("critical", "#ff003c"),
        )
        widget.update(gauge.render())

    def _refresh_threatmap(self) -> None:
        widget = self.query_one("#threatmap-panel", Static)
        theme = get_theme(self.theme_name)
        primary = theme.get("primary", "#ff2222")
        text = theme.get("text", "#ffffff")
        muted = theme.get("muted", "#888888")
        sev_colors = {
            "critical": theme.get("critical", "#ff003c"),
            "high":     theme.get("high", "#ff5500"),
            "medium":   theme.get("medium", "#ffb300"),
            "low":      theme.get("low", "#81c784"),
            "info":     theme.get("info", "#888888"),
        }

        grid = [[" "] * self._threatmap_w for _ in range(self._threatmap_h)]
        for y, row in enumerate(grid):
            for x in range(self._threatmap_w):
                # Background latitude/longitude lines.
                if y == 0 or y == self._threatmap_h - 1:
                    row[x] = ("-", muted)
                elif x == 0 or x == self._threatmap_w - 1:
                    row[x] = ("|", muted)
                elif (x + y) % 8 == 0:
                    row[x] = (".", muted)
        for m in self.markers:
            if 0 <= m.x < self._threatmap_w and 0 <= m.y < self._threatmap_h:
                color = sev_colors.get(m.severity, primary)
                # Pulsing glyph: + at pulse=0, * at pulse=0.5, + at pulse=1.
                glyph = "*" if 0.3 < m.pulse < 0.7 else "+"
                grid[m.y][m.x] = (glyph, f"bold {color}")
                # 4-directional pulse ring (subtle).
                ring = "."
                for dx, dy in ((-1, 0), (1, 0), (0, -1), (0, 1)):
                    nx, ny = m.x + dx, m.y + dy
                    if 0 <= nx < self._threatmap_w and 0 <= ny < self._threatmap_h:
                        if grid[ny][nx][0] in (" ", "-", "|", "."):
                            grid[ny][nx] = (ring, color)

        text = Text()
        for y, row in enumerate(grid):
            for ch, style in row:
                if ch == " ":
                    text.append(" ")
                elif style:
                    text.append(ch, style=style)
                else:
                    text.append(ch)
            if y < len(grid) - 1:
                text.append("\n")
        title = Text("THREAT MAP", style=f"bold {text}")
        title.append(f"  markers: {len(self.markers)}", style=muted)
        widget.update(
            Panel(
                text,
                title=title,
                border_style=primary,
                box=ROUNDED,
                padding=(0, 0),
            )
        )

    def _refresh_scans(self) -> None:
        widget = self.query_one("#scans-panel", Static)
        theme = get_theme(self.theme_name)
        primary = theme.get("primary", "#ff2222")
        text = theme.get("text", "#ffffff")
        muted = theme.get("muted", "#888888")

        if not self.scans:
            body = Text("  (no active scans)", style=muted)
        else:
            table = Table(
                show_header=True,
                header_style=f"bold {primary}",
                box=SIMPLE,
                padding=(0, 0),
                expand=True,
            )
            table.add_column("Scan",     style=f"bold {text}",  no_wrap=True)
            table.add_column("Target",   style=muted,           no_wrap=True)
            table.add_column("Progress", width=14)
            table.add_column("ETA",      justify="right",       width=6)
            table.add_column("Status",   justify="center",      width=8)
            for s in self.scans:
                pct = int(round(s.progress * 100))
                bar_w = 8
                filled = int(round(s.progress * bar_w))
                bar = f"[{primary}]" + "\u2588" * filled + f"[{muted}]" + "\u2591" * (bar_w - filled)
                status_color = (
                    theme.get("success", "#ffffff") if s.status == "done" else
                    theme.get("warning", "#ffb300") if s.status == "paused" else
                    theme.get("primary", "#ff2222")
                )
                table.add_row(
                    s.name,
                    s.target[:18],
                    bar + f" {pct:3d}%",
                    f"{int(s.eta):d}s",
                    f"[bold {status_color}]{s.status.upper():8s}[/bold {status_color}]",
                )
            body = table

        widget.update(
            Panel(
                body,
                title=f"[bold {text}]ACTIVE SCANS[/bold {text}]",
                border_style=primary,
                box=ROUNDED,
                padding=(0, 1),
            )
        )

    def _refresh_findings(self) -> None:
        widget = self.query_one("#findings-panel", Static)
        theme = get_theme(self.theme_name)
        primary = theme.get("primary", "#ff2222")
        text = theme.get("text", "#ffffff")
        muted = theme.get("muted", "#888888")
        sev_colors = {
            "critical": theme.get("critical", "#ff003c"),
            "high":     theme.get("high", "#ff5500"),
            "medium":   theme.get("medium", "#ffb300"),
            "low":      theme.get("low", "#81c784"),
            "info":     theme.get("info", "#888888"),
        }
        items = sorted(self.findings, key=lambda f: f.timestamp, reverse=True)[: self._max_findings]
        if not items:
            body = Text("  (no findings yet)", style=muted)
        else:
            rows: List[Text] = []
            for f in items:
                color = sev_colors.get(f.severity, primary)
                line = Text()
                line.append(f" {f.timestamp.strftime('%H:%M:%S')} ", style=muted)
                line.append(f"[{f.severity.upper():8s}] ", style=f"bold {color}")
                line.append(f.title[:42], style=text)
                if f.location:
                    line.append(f"  {f.location[:24]}", style=muted)
                rows.append(line)
            body = Group(*rows)

        widget.update(
            Panel(
                body,
                title=f"[bold {text}]FINDINGS FEED[/bold {text}]",
                border_style=primary,
                box=ROUNDED,
                padding=(0, 1),
            )
        )

    def _refresh_stats(self) -> None:
        widget = self.query_one("#stats-panel", Static)
        theme = get_theme(self.theme_name)
        primary = theme.get("primary", "#ff2222")
        text = theme.get("text", "#ffffff")
        muted = theme.get("muted", "#888888")

        def _bar(value: float, width: int = 18) -> Text:
            filled = int(round((value / 100.0) * width))
            color = (
                theme.get("critical", "#ff003c") if value >= 80 else
                theme.get("high", "#ff5500")     if value >= 60 else
                theme.get("medium", "#ffb300")   if value >= 30 else
                theme.get("low", "#81c784")
            )
            return Text(
                "\u2588" * filled + "\u2591" * (width - filled) + f" {int(round(value)):3d}%",
                style=color,
            )

        body = Table(
            show_header=False,
            box=SIMPLE,
            padding=(0, 0),
            expand=True,
        )
        body.add_column("Label", style=muted, width=10)
        body.add_column("Bar", width=24)
        body.add_column("Value", style=text, justify="right", width=8)
        body.add_row("CPU",     _bar(self.stats.cpu),     f"{self.stats.cpu:.1f}%")
        body.add_row("MEMORY",  _bar(self.stats.memory),  f"{self.stats.memory:.1f}%")
        body.add_row("NET IN",  Text(f"{self.stats.net_in:7.1f} kbps",  style=text), "")
        body.add_row("NET OUT", Text(f"{self.stats.net_out:7.1f} kbps", style=text), "")

        widget.update(
            Panel(
                body,
                title=f"[bold {text}]SYSTEM STATS[/bold {text}]",
                border_style=primary,
                box=ROUNDED,
                padding=(0, 1),
            )
        )

    def _refresh_topology(self) -> None:
        widget = self.query_one("#topology-panel", Static)
        theme = get_theme(self.theme_name)
        primary = theme.get("primary", "#ff2222")
        text = theme.get("text", "#ffffff")
        muted = theme.get("muted", "#888888")
        sev_colors = {
            "critical": theme.get("critical", "#ff003c"),
            "high":     theme.get("high", "#ff5500"),
            "medium":   theme.get("medium", "#ffb300"),
            "low":      theme.get("low", "#81c784"),
            "info":     theme.get("info", "#888888"),
        }
        if not self.hosts:
            body = Text("  (no hosts discovered)", style=muted)
        else:
            rows: List[Text] = []
            # Fake "spine" connecting all hosts - the gateway is the root.
            for i, h in enumerate(self.hosts[: self._topology_h]):
                color = sev_colors.get(h.risk, primary)
                indent = "  " if i == 0 else "  |  "
                branch = "[ROOT]" if i == 0 else "+-- "
                rows.append(
                    Text.assemble(
                        (indent, muted),
                        (branch, color),
                        (h.ip, f"bold {text}"),
                        ("  ", ""),
                        (f"{h.role:<8s}", muted),
                        (f"  [{h.risk.upper():7s}]", f"bold {color}"),
                    )
                )
            body = Group(*rows)

        widget.update(
            Panel(
                body,
                title=f"[bold {text}]TOPOLOGY[/bold {text}]",
                border_style=primary,
                box=ROUNDED,
                padding=(0, 1),
            )
        )


# ---------------------------------------------------------------------------
# Demo launcher (manual)
# ---------------------------------------------------------------------------


def run_demo() -> None:
    """Print a one-shot render of the dashboard for manual inspection."""
    from rich.console import Console as _Console
    c = _Console(width=140, record=True)
    c.print(build_static_renderable("DEFAULT", risk=73, target="example.com"))


def build_static_renderable(
    theme_name: str = "DEFAULT",
    risk: int = 0,
    target: str = "demo",
) -> Group:
    """Build a single Rich ``Group`` rendering the dashboard.

    Useful for screenshot tests or one-off prints.
    """
    theme = get_theme(theme_name)
    primary = theme.get("primary", "#ff2222")
    text = theme.get("text", "#ffffff")
    muted = theme.get("muted", "#888888")

    gauge = RiskGauge(value=risk, max_value=100, label="RISK SCORE").render()
    chart = SeverityChart(critical=1, high=3, medium=5, low=8, info=12).render()
    body = Table(show_header=False, box=SIMPLE, padding=(0, 1), expand=True)
    body.add_column("Left")
    body.add_column("Right")
    body.add_row(gauge, chart)
    header = Panel(
        Text.assemble(
            (" ELENGENIX", f"bold {primary}"),
            ("  /  ", muted),
            ("THREAT DASHBOARD", f"bold {text}"),
            ("  /  ", muted),
            (f"TARGET: {target}", text),
            ("  /  ", muted),
            (f"RISK: {risk}", "bold #ff003c"),
        ),
        border_style=primary,
        box=HEAVY,
    )
    return Group(header, body)


__all__ = [
    "ThreatDashboard",
    "SystemStats",
    "Scan",
    "Host",
    "Finding",
    "ThreatMarker",
    "build_static_renderable",
    "run_demo",
]
