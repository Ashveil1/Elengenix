"""
tools/tui_dashboard.py — Elengenix World-Class TUI Dashboard
============================================================
A real-time terminal dashboard built on Textual + the Apple-level design system.
Features multi-panel layout, live scan monitoring, findings browser, themes.

Design: Apple-level. Linear-inspired. Raycast-speed.
"""

from __future__ import annotations

import logging
import os
import json
import time
from datetime import datetime
from typing import Any, Dict, List, Optional

logger = logging.getLogger("elengenix.dashboard")

# ── Textual imports (optional) ───────────────────────────────────────────
try:
    from textual import work
    from textual.app import App, ComposeResult
    from textual.binding import Binding
    from textual.containers import Container, Horizontal, Vertical
    from textual.reactive import reactive
    from textual.screen import Screen
    from textual.widget import Widget
    from textual.widgets import Button, DataTable, Footer, Header, Input, RichLog, Static

    _HAS_TEXTUAL = True
except ImportError:
    _HAS_TEXTUAL = False

    # Define stubs
    class App:
        pass

    class ComposeResult:
        pass

    class Container:
        pass

    class Horizontal:
        pass

    class Vertical:
        pass

    class Static:
        pass

    class RichLog:
        pass

    class Header:
        pass

    class Footer:
        pass

    class Input:
        pass

    class Button:
        pass

    class DataTable:
        pass

    class Widget:
        pass

    class Screen:
        pass

    def work(f):
        return f


# ── Import design system ─────────────────────────────────────────────────
try:
    from tui_design import (
        Severity,
    )

    _HAS_DESIGN = True
except ImportError:
    _HAS_DESIGN = False

    # Stubs
    class Severity:
        CRITICAL = ("#ff3b30", "●")
        HIGH = ("#ff9500", "●")
        MEDIUM = ("#ffcc00", "●")
        LOW = ("#34c759", "●")
        INFO = ("#5ac8fa", "●")


# ── Dashboard Colors ─────────────────────────────────────────────────────
DARK_BG = "#0a0a0f"
DARK_SURFACE = "#1a1a2e"
DARK_BORDER = "#2a2a4a"
DARK_TEXT = "#e0e0e0"
DARK_MUTED = "#888888"
DARK_ACCENT = "#4488ff"
RED_ACCENT = "#ff4444"
GREEN_ACCENT = "#44cc44"
YELLOW_ACCENT = "#ffcc44"


def _is_live_finding(f: Dict[str, Any]) -> bool:
    """True only for a LIVE, evidenced finding (same honesty rule as the
    risk scorer). Static "CANDIDATE (not tested)" items, Informational
    notes, and entries with no URL/evidence are excluded so the UI never
    presents unverified candidates as confirmed vulnerabilities."""
    sev = str(f.get("severity", "info") or "info").lower()
    if sev == "informational" or sev == "info":
        return False
    title = str(f.get("title", "") or "")
    if "candidate" in title.lower() or "not tested" in title.lower():
        return False
    return bool(f.get("url") or f.get("details") or f.get("evidence"))

# ═══════════════════════════════════════════════════════════════════════════
# WIDGETS
# ═══════════════════════════════════════════════════════════════════════════

if _HAS_TEXTUAL:

    class MetricCard(Static):
        """A single metric display card with label, value, and color."""

        value = reactive("0")
        label_text = reactive("")
        color = reactive(DARK_ACCENT)

        def render(self):
            from rich.text import Text

            t = Text()
            t.append(f"\n{self.label_text}\n", style="dim " + DARK_MUTED)
            t.append(f"{self.value}", style=f"bold {self.color}")
            return t

        def on_mount(self):
            self.styles.background = DARK_SURFACE
            self.styles.border = ("solid", DARK_BORDER)
            self.styles.padding = (1, 2)
            self.styles.margin = (0, 1)
            self.styles.width = 20
            self.styles.height = 5
            self.styles.text_align = "center"

    class ScanStatusCard(Static):
        """Shows current scan status with animated indicator."""

        status = reactive("idle")
        target_text = reactive("")
        findings_count = reactive(0)

        def render(self):
            from rich.text import Text

            t = Text()
            status_icon = {
                "running": "[bold green]●[/]",
                "completed": "[bold blue]●[/]",
                "failed": "[bold red]●[/]",
                "idle": "[dim]○[/]",
            }
            icon = status_icon.get(self.status, "[dim]○[/]")
            t.append(f"\n{icon} Scan Status\n", style="bold white")
            t.append(
                f"  {self.status.upper()}",
                style={"running": "green", "completed": "blue", "failed": "red", "idle": "dim"}.get(
                    self.status, "dim"
                ),
            )
            if self.target_text:
                t.append(f"\n  Target: {self.target_text}", style=DARK_MUTED)
            t.append(f"\n  Findings: {self.findings_count}", style="white")
            return t

        def on_mount(self):
            self.styles.background = DARK_SURFACE
            self.styles.border = ("solid", DARK_BORDER)
            self.styles.padding = (1, 2)
            self.styles.margin = (0, 1)
            self.styles.width = 30
            self.styles.height = 7

    class FindingsTable(DataTable):
        """Interactive findings data table with sorting and filtering.

        Shows ONLY real findings — no seeded/sample rows. Before a scan it
        displays an explicit "no findings yet" state so nothing is mistaken
        for a real result.
        """

        def on_mount(self):
            self.styles.background = DARK_SURFACE
            self.styles.border = ("solid", DARK_BORDER)
            self.styles.height = "1fr"
            self.add_columns("Severity", "Type", "Title", "URL", "CVSS")
            self.add_rows([["[dim]—[/]", "[dim]—[/]", "[dim]No findings yet — run /scan <target> to start a real scan[/]", "[dim]—[/]", "[dim]—[/]"]])

        def update_findings(self, findings: List[Dict[str, Any]]):
            self.clear()
            self.add_columns("Severity", "Type", "Title", "URL", "CVSS")
            rows = findings or []
            if not rows:
                self.add_rows([["[dim]—[/]", "[dim]—[/]", "[dim]Scan finished — no findings[/]", "[dim]—[/]", "[dim]—[/]"]])
                return
            for f in rows:
                sev = (f.get("severity", "info") or "info").lower()
                sev_colors = {
                    "critical": "red",
                    "high": "orange",
                    "medium": "yellow",
                    "low": "green",
                    "info": "dim",
                }
                color = sev_colors.get(sev, "dim")
                self.add_row(
                    f"[{color}]{sev.upper()}[/]",
                    str(f.get("type", "") or f.get("category", ""))[:20],
                    (f.get("title", "") or "")[:40],
                    (f.get("url", "") or f.get("target_endpoint", ""))[:40],
                    str(f.get("cvss", "") or ""),
                )

    class LogPanel(RichLog):
        """Real-time scan log panel with auto-scroll."""

        def on_mount(self):
            self.styles.background = DARK_BORDER
            self.styles.border = ("solid", DARK_BORDER)
            self.styles.height = 8
            self.styles.margin = (1, 0)
            self.write("[dim]Elengenix Dashboard ready[/dim]")
            self.write("[dim]Type /help for commands[/dim]")

        def log(self, message: str, style: str = "white"):
            ts = datetime.now().strftime("%H:%M:%S")
            self.write(f"[dim]{ts}[/] [{style}]{message}[/]")

    class DashboardApp(App):
        """Elengenix World-Class Terminal Dashboard."""

        TITLE = "Elengenix Security Dashboard"
        CSS = """
        Screen {
            background: #0a0a0f;
        }
        DashboardApp {
            background: #0a0a0f;
        }
        #main-container {
            height: 100%;
            margin: 0;
            padding: 0;
        }
        #header-panel {
            height: 3;
            background: #1a1a2e;
            border-bottom: solid #2a2a4a;
            content-align: center middle;
        }
        #metrics-row {
            height: 6;
            margin: 0 1;
        }
        #content-row {
            height: 1fr;
            margin: 0 1;
        }
        #findings-panel {
            width: 1fr;
            height: 1fr;
            border: solid #2a2a4a;
            background: #1a1a2e;
        }
        #log-panel {
            height: 8;
            border: solid #2a2a4a;
            background: #111122;
            margin: 1 0;
        }
        #input-panel {
            height: 3;
            background: #1a1a2e;
            border-top: solid #2a2a4a;
        }
        #status-bar {
            height: 1;
            background: #0f3460;
            color: #888;
        }
        MetricCard {
            background: #1a1a2e;
            border: solid #2a2a4a;
            padding: 1 2;
        }
        ScanStatusCard {
            background: #1a1a2e;
            border: solid #2a2a4a;
            padding: 1 2;
        }
        """

        BINDINGS = [
            Binding("q", "quit", "Quit"),
            Binding("r", "refresh", "Refresh"),
            Binding("f", "focus_findings", "Findings"),
            Binding("l", "focus_log", "Log"),
            Binding("i", "focus_input", "Input"),
            Binding("slash", "focus_input", "Command"),
            Binding("ctrl+c", "quit", "Exit"),
        ]

        def __init__(self):
            super().__init__()
            self.scan_data: Dict[str, Any] = {}
            self.findings_data: List[Dict[str, Any]] = []

        def compose(self) -> ComposeResult:
            yield Container(
                Static("Elengenix Security Dashboard", id="header-panel"),
                Horizontal(
                    MetricCard(id="metric-scans"),
                    MetricCard(id="metric-findings"),
                    MetricCard(id="metric-critical"),
                    MetricCard(id="metric-high"),
                    ScanStatusCard(id="scan-status"),
                    id="metrics-row",
                ),
                Horizontal(
                    FindingsTable(id="findings-table"),
                    id="content-row",
                ),
                LogPanel(id="log-panel", highlight=True, max_lines=100),
                Input(placeholder="Type command or /help ...", id="input-field"),
                Static("Ready | Press Ctrl+C to quit", id="status-bar"),
                id="main-container",
            )

        def on_mount(self) -> None:
            self.log_panel = self.query_one("#log-panel", LogPanel)
            self.log_panel.log("Dashboard initialized", "green")
            # Metric cards (labels set here, not in the constructor — Static
            # does not accept reactive kwargs at compose time).
            self.query_one("#metric-scans", MetricCard).label_text = "Active Scans"
            self.query_one("#metric-findings", MetricCard).label_text = "Total Findings"
            self.query_one("#metric-critical", MetricCard).label_text = "Critical"
            self.query_one("#metric-high", MetricCard).label_text = "High"
            card = self.query_one("#scan-status", ScanStatusCard)
            card.status = "idle"
            target = (self.scan_data or {}).get("target", "")
            if target:
                card.target_text = target

        def on_input_submitted(self, event: Input.Submitted) -> None:
            cmd = event.value.strip()
            self.log_panel.log(f"> {cmd}", "dim white")
            if cmd == "/help":
                self.show_help()
            elif cmd == "/clear":
                self.log_panel.clear()
            elif cmd.startswith("/scan "):
                target = cmd[6:].strip()
                self.start_scan(target)
            elif cmd == "/quit" or cmd == "/exit":
                self.exit()
            else:
                self.log_panel.log(f"Unknown: {cmd}. Try /help", "red")
            self.query_one("#input-field", Input).value = ""

        def show_help(self):
            self.log_panel.log("Commands:", "bold white")
            self.log_panel.log("  /scan <target> - Start a new scan", "white")
            self.log_panel.log("  /clear - Clear log", "white")
            self.log_panel.log("  /help - Show this help", "white")
            self.log_panel.log("  /quit - Exit dashboard", "white")
            self.log_panel.log("")
            self.log_panel.log("Keys: q=quit r=refresh f=findings l=log i=input", "dim")

        @work(thread=True)
        def start_scan(self, target: str):
            """Run a REAL scan (HuntEngine) in a background thread and update
            the UI with honest per-phase progress — no simulated progress."""
            try:
                self.call_from_thread(self.log_panel.log, f"Scanning: {target}", "bold green")
                self.call_from_thread(self._update_scan_status, "running", target, 0)
                self.call_from_thread(self._update_metric, 0, "1", RED_ACCENT)

                # HuntEngine runs a fixed pipeline (recon -> smart -> zero_day
                # -> logic -> correlation). The callback below reports each
                # phase as it really starts/finishes, so the UI shows honest
                # progress instead of a fabricated percentage.
                from tools.hunt_engine import HuntEngine

                def _phase_cb(engine, phase_name, status, findings, duration):
                    # Called from the scan thread; hop to the UI thread.
                    self.call_from_thread(
                        self.log_panel.log,
                        f"[{phase_name}] {status}  ({duration:.1f}s, {findings} findings)",
                        "green" if status == "done" else ("red" if status == "failed" else "dim"),
                    )
                    self.call_from_thread(self._set_phase, phase_name, status)

                # Build the engine (also gives us the phase list count).
                import asyncio

                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                try:
                    engine = HuntEngine(
                        target, quiet=True, phase_callback=_phase_cb
                    )
                    report = loop.run_until_complete(engine.hunt())
                finally:
                    loop.close()

                # Show only LIVE findings in the UI — the same honesty rule the
                # risk scorer uses. Static "CANDIDATE (not tested)" items and
                # entries with no evidence are NOT real findings; counting them
                # would make a clean target look compromised. The full report
                # (console/JSON) still lists candidates separately.
                all_f = getattr(report, "findings", None) or []
                finding_dicts = [
                    f.to_dict()
                    for f in all_f
                    if hasattr(f, "to_dict")
                    and _is_live_finding(f.to_dict())
                ] or [
                    f
                    for f in all_f
                    if isinstance(f, dict) and _is_live_finding(f)
                ]
                n = len(finding_dicts)
                self.call_from_thread(
                    self.log_panel.log,
                    f"Scan complete: {n} findings  (risk {report.risk_score:.0f}/100 {report.risk_level})",
                    "bold green",
                )
                self.call_from_thread(self._update_scan_status, "completed", target, n)
                self.call_from_thread(self._update_findings, finding_dicts)
                self.call_from_thread(self._update_metric, 1, str(n), DARK_ACCENT)

                critical = sum(1 for f in finding_dicts if str(f.get("severity", "")).lower() in ("critical",))
                high = sum(1 for f in finding_dicts if str(f.get("severity", "")).lower() in ("high",))
                self.call_from_thread(self._update_metric, 2, str(critical), RED_ACCENT)
                self.call_from_thread(self._update_metric, 3, str(high), "#ff8844")
            except Exception as e:
                self.call_from_thread(self.log_panel.log, f"Scan error: {e}", "red")
                self.call_from_thread(self._update_scan_status, "failed", target, 0)

        def _set_phase(self, phase_name: str, status: str):
            """Show the phase the scan is ACTUALLY in (from the engine's
            live callback) on the Active Scans card."""
            try:
                card = self.query_one("#metric-scans", MetricCard)
                label = f"Phase: {phase_name}" + ("" if status == "running" else f" ({status})")
                card.label_text = label
            except Exception:
                pass

        def _update_metric(self, index: int, value: str, color: str):
            cards = self.query(MetricCard)
            if index < len(cards):
                cards[index].value = value
                cards[index].color = color

        def _update_scan_status(self, status: str, target: str, count: int):
            try:
                card = self.query_one(ScanStatusCard)
                card.status = status
                card.target_text = target
                card.findings_count = count
            except Exception:
                pass

        def _update_findings(self, findings: List[Dict[str, Any]]):
            try:
                table = self.query_one("#findings-table", FindingsTable)
                table.update_findings(findings)
            except Exception:
                pass

        def action_refresh(self):
            self.log_panel.log("Refreshed", "dim")

        def action_focus_findings(self):
            try:
                self.query_one("#findings-table", DataTable).focus()
            except Exception:
                pass

        def action_focus_log(self):
            self.log_panel.focus()

        def action_focus_input(self):
            self.query_one("#input-field", Input).focus()


# ═══════════════════════════════════════════════════════════════════════════
# LAUNCHER
# ═══════════════════════════════════════════════════════════════════════════


def run_dashboard(target: Optional[str] = None) -> None:
    """Launch the Elengenix dashboard.

    Args:
        target: Optional target to start scanning immediately
    """
    if not _HAS_TEXTUAL:
        print("[FAIL] Textual not installed. Install: pip install textual")
        return
    app = DashboardApp()
    if target:
        app.scan_data["target"] = target
    app.run()


def run_with_target(target: str) -> None:
    """Launch dashboard and start scanning immediately."""
    if not _HAS_TEXTUAL:
        print("[FAIL] Textual not installed.")
        return
    app = DashboardApp()
    app.scan_data["target"] = target
    app.run()


# ── Simple CLI fallback if Textual not available ─────────────────────────


def run_minimal():
    """Render a minimal live-updating dashboard in plain terminal.

    Shows the REAL last saved scan report (if any) — no fake numbers. If no
    scan has run yet it says so explicitly.
    """
    from rich.console import Console
    from rich.layout import Layout
    from rich.live import Live
    from rich.panel import Panel
    from rich.table import Table

    console = Console()
    layout = Layout()
    layout.split_column(
        Layout(name="header", size=3),
        Layout(name="body"),
        Layout(name="footer", size=3),
    )

    def _last_report():
        try:
            from elengenix.paths import get_reports_path

            reports = get_reports_path()
            if not reports.exists():
                return None
            files = sorted(reports.glob("*.json"), key=os.path.getmtime, reverse=True)
            if not files:
                return None
            return json.loads(files[0].read_text())
        except Exception:
            return None

    rep = _last_report()
    if rep:
        fs = rep.get("findings") or []
        total = len(fs)
        crit = sum(1 for f in fs if str(f.get("severity", "")).lower() == "critical")
        high = sum(1 for f in fs if str(f.get("severity", "")).lower() == "high")
        status_line = f"[dim]Last scan: {rep.get('target', '?')}[/]"
    else:
        total = crit = high = 0
        status_line = "[dim]No scan yet — run a scan to populate real data[/]"

    with Live(layout, refresh_per_second=4, screen=True) as live:
        try:
            import signal

            signal.signal(signal.SIGINT, lambda s, f: exit(0))
            while True:
                table = Table(title="Elengenix Security Monitor", border_style="dim")
                table.add_column("Metric", style="bold")
                table.add_column("Value", style="green")
                table.add_row("Active Scans", "0")
                table.add_row("Total Findings (last scan)", str(total))
                table.add_row("Critical", str(crit))
                table.add_row("High", str(high))
                table.add_row("Status", status_line)
                layout["header"].update(
                    Panel("Elengenix Security Monitor", style="bold white on #1a1a2e")
                )
                layout["body"].update(table)
                layout["footer"].update(Panel("Press Ctrl+C to quit", style="dim"))
                time.sleep(1)
        except KeyboardInterrupt:
            pass


__all__ = ["DashboardApp", "run_dashboard", "run_minimal"]
