"""tui/welcome.py - Beautiful welcome screen for the Elengenix TUI.

Provides:

    * :func:`ascii_logo` - the "ELENGENIX" wordmark with gradient colour.
    * :class:`WelcomeScreen` - a full-screen Textual widget combining
      logo, mission briefing, quick-start tiles, recent activity, and a
      live clock in the status footer.
    * :func:`build_welcome_renderable` - a standalone Rich renderable
      version of the welcome screen (no Textual app required).
"""

from __future__ import annotations

import logging
import os
from datetime import datetime
from pathlib import Path
from elengenix.paths import get_reports_path
from prompt_toolkit

from rich.align import Align
from rich.box import HEAVY, ROUNDED, SIMPLE
from rich.console import Group, RenderResult
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from textual.containers import Container, Horizontal
from textual.reactive import reactive
from textual.widgets import Static

from .themes import get_theme

logger = logging.getLogger("elengenix.tui.welcome")


# ---------------------------------------------------------------------------
# ASCII logo - large "ELENGENIX" wordmark
# ---------------------------------------------------------------------------

LOGO_LINES: List[str] = [
    "  ███████╗██╗     ███████╗███╗   ██╗ ██████╗ ███████╗███╗   ██╗██╗██╗  ██╗",
    "  ██╔════╝██║     ██╔════╝████╗  ██║██╔════╝ ██╔════╝████╗  ██║██║╚██╗██╔╝",
    "  █████╗  ██║     █████╗  ██╔██╗ ██║██║  ███╗█████╗  ██╔██╗ ██║██║ ╚███╔╝ ",
    "  ██╔══╝  ██║     ██╔══╝  ██║╚██╗██║██║   ██║██╔══╝  ██║╚██╗██║██║ ██╔██╗ ",
    "  ███████╗███████╗███████╗██║ ╚████║╚██████╔╝███████╗██║ ╚████║██║██╔╝ ██╗",
    "  ╚══════╝╚══════╝╚══════╝╚═╝  ╚═══╝ ╚═════╝ ╚══════╝╚═╝  ╚═══╝╚═╝╚═╝  ╚═╝",
]


def get_system_status() -> Dict[str, Any]:
    """Get system status information for the welcome screen.

    Returns:
        Dictionary containing system status info.
    """
    status = {
        "cpu_percent": 0.0,
        "memory_percent": 0.0,
        "disk_percent": 0.0,
        "python_version": f"{os.sys.version_info.major}.{os.sys.version_info.minor}.{os.sys.version_info.micro}",
        "tools_installed": 0,
        "last_scan": "Never",
    }

    try:
        import psutil

        status["cpu_percent"] = psutil.cpu_percent(interval=0.1)
        mem = psutil.virtual_memory()
        status["memory_percent"] = mem.percent
        disk = psutil.disk_usage("/")
        status["disk_percent"] = disk.percent
    except ImportError:
        # psutil not installed, skip system stats
        pass
    except Exception:
        pass

    # Count installed tools
    tools_dir = Path(__file__).parent.parent / "tools"
    if tools_dir.exists():
        status["tools_installed"] = (
            len(list(tools_dir.glob("*.py"))) - 2
        )  # Exclude __init__.py and tool_registry.py

    # Check last scan
    reports_dir = get_reports_path()
    if reports_dir.exists():
        scan_files = sorted(reports_dir.glob("*.html"), key=os.path.getmtime, reverse=True)
        if scan_files:
            last_scan_time = os.path.getmtime(scan_files[0])
            status["last_scan"] = datetime.fromtimestamp(last_scan_time).strftime("%Y-%m-%d %H:%M")

    return status


def ascii_logo(
    color_a: str = "#ff2222",
    color_b: str = "#888888",
    color_c: str = "#ffffff",
    bold: bool = True,
) -> Text:
    """Return the ELENGENIX wordmark as a Rich ``Text`` with a 3-stop gradient.

    Args:
        color_a: Left-edge colour.
        color_b: Middle colour.
        color_c: Right-edge colour.
        bold: Apply bold weight.

    Returns:
        Rich ``Text`` ready to print.
    """
    n_lines = len(LOGO_LINES)
    line_w = max(len(line) for line in LOGO_LINES)
    out = Text()
    for li, line in enumerate(LOGO_LINES):
        # 3-stop gradient: left -> mid -> right.
        for ci, ch in enumerate(line):
            t = ci / max(1, line_w - 1)
            if t < 0.5:
                ratio = t * 2
                r = _mix(color_a, color_b, ratio)
            else:
                ratio = (t - 0.5) * 2
                r = _mix(color_b, color_c, ratio)
            out.append(ch, style=f"bold {r}" if bold else r)
        if li < n_lines - 1:
            out.append("\n")
    return out


def _mix(a: str, b: str, t: float) -> str:
    """Linearly interpolate two hex colours."""
    t = max(0.0, min(1.0, float(t)))
    a = a.lstrip("#")
    b = b.lstrip("#")
    if len(a) == 3:
        a = "".join(c * 2 for c in a)
    if len(b) == 3:
        b = "".join(c * 2 for c in b)
    ra, ga, ba = int(a[0:2], 16), int(a[2:4], 16), int(a[4:6], 16)
    rb, gb, bb = int(b[0:2], 16), int(b[2:4], 16), int(b[4:6], 16)
    r = int(ra + (rb - ra) * t)
    g = int(ga + (gb - ga) * t)
    bv = int(ba + (bb - ba) * t)
    return f"#{r:02x}{g:02x}{bv:02x}"


# ---------------------------------------------------------------------------
# Mission briefing data
# ---------------------------------------------------------------------------


class MissionBriefing:
    """Container for the current mission state shown in the welcome panel."""

    def __init__(
        self,
        target: str = "no target set",
        scan_status: str = "IDLE",
        ai_status: str = "READY",
        operators: int = 1,
        active_session: str = "default",
    ) -> None:
        self.target = target
        self.scan_status = scan_status
        self.ai_status = ai_status
        self.operators = operators
        self.active_session = active_session

    def render(self, primary: str = "#ff2222", text_color: str = "#ffffff") -> Panel:
        """Render the briefing as a Rich panel."""
        table = Table(
            show_header=False,
            box=SIMPLE,
            padding=(0, 1),
            expand=True,
        )
        table.add_column("Key", style="#888888", justify="right", width=14)
        table.add_column("Value", style=text_color)
        table.add_row("TARGET", self.target or "no target set")
        table.add_row("SCAN", f"[bold {primary}]{self.scan_status}[/bold {primary}]")
        table.add_row("AI", f"[bold #ffffff]{self.ai_status}[/bold #ffffff]")
        table.add_row("OPERATORS", str(self.operators))
        table.add_row("SESSION", self.active_session)
        return Panel(
            table,
            title="[bold]MISSION BRIEFING[/bold]",
            border_style=primary,
            box=ROUNDED,
            padding=(0, 1),
        )


# ---------------------------------------------------------------------------
# Quick-start tile
# ---------------------------------------------------------------------------


QUICK_START_TILES: List[Dict[str, str]] = [
    {
        "key": "S",
        "title": "START SCAN",
        "desc": "Launch a full pipeline scan",
        "action": "start_scan",
    },
    {
        "key": "D",
        "title": "OPEN DASHBOARD",
        "desc": "Live threat & metrics view",
        "action": "open_dashboard",
    },
    {
        "key": "R",
        "title": "VIEW REPORTS",
        "desc": "Browse past scan reports",
        "action": "view_reports",
    },
    {
        "key": "X",
        "title": "SETTINGS",
        "desc": "Theme, providers, integrations",
        "action": "open_settings",
    },
    {
        "key": "P",
        "title": "COMMAND PALETTE",
        "desc": "Ctrl+Shift+P - every command",
        "action": "command_palette",
    },
    {"key": "H", "title": "HELP", "desc": "Show help and shortcuts", "action": "show_help"},
]


def render_quick_start(
    highlight_index: int = 0,
    primary: str = "#ff2222",
    text_color: str = "#ffffff",
    muted: str = "#888888",
) -> Panel:
    """Render the quick-start tile grid as a Rich panel."""
    table = Table(
        show_header=False,
        box=SIMPLE,
        padding=(0, 1),
        expand=True,
    )
    # Two columns of three tiles each.
    table.add_column("Tile 1", ratio=1)
    table.add_column("Tile 2", ratio=1)
    rows: List[List[Text]] = []
    for i in range(0, len(QUICK_START_TILES), 2):
        cells: List[Text] = []
        for j in range(2):
            idx = i + j
            if idx >= len(QUICK_START_TILES):
                cells.append(Text(""))
                continue
            tile = QUICK_START_TILES[idx]
            cell = Text()
            color = primary if idx == highlight_index else text_color
            border_color = primary if idx == highlight_index else muted
            cell.append(f" [{tile['key']}] ", style=f"bold black on {border_color}")
            cell.append(f" {tile['title']}\n", style=f"bold {color}")
            cell.append(f"      {tile['desc']}", style=muted)
            cells.append(cell)
        rows.append(cells)
    for r in rows:
        table.add_row(*r)
    return Panel(
        table,
        title="[bold]QUICK START[/bold]",
        border_style=muted,
        box=ROUNDED,
        padding=(0, 1),
    )


def render_system_status(
    primary: str = "#ff2222",
    text_color: str = "#ffffff",
    muted: str = "#888888",
) -> Panel:
    """Render system status information as a Rich panel."""
    status = get_system_status()

    table = Table(
        show_header=False,
        box=SIMPLE,
        padding=(0, 1),
        expand=True,
    )
    table.add_column("Metric", style=muted, width=12)
    table.add_column("Value", style=text_color)

    # CPU status with color
    cpu = status["cpu_percent"]
    cpu_color = "#81C784" if cpu < 50 else "#ffb300" if cpu < 80 else "#ff5500"
    table.add_row("CPU", f"[{cpu_color}]{cpu:.1f}%[/{cpu_color}]")

    # Memory status with color
    mem = status["memory_percent"]
    mem_color = "#81C784" if mem < 50 else "#ffb300" if mem < 80 else "#ff5500"
    table.add_row("Memory", f"[{mem_color}]{mem:.1f}%[/{mem_color}]")

    # Disk status with color
    disk = status["disk_percent"]
    disk_color = "#81C784" if disk < 70 else "#ffb300" if disk < 90 else "#ff5500"
    table.add_row("Disk", f"[{disk_color}]{disk:.1f}%[/{disk_color}]")

    table.add_row("Python", status["python_version"])
    table.add_row("Tools", f"{status['tools_installed']} installed")
    table.add_row("Last Scan", status["last_scan"])

    return Panel(
        table,
        title="[bold]SYSTEM STATUS[/bold]",
        border_style=primary,
        box=ROUNDED,
        padding=(0, 1),
    )


# ---------------------------------------------------------------------------
# Recent activity timeline
# ---------------------------------------------------------------------------


class RecentActivity:
    """Small scrollable list of recent activities."""

    def __init__(self, max_items: int = 8) -> None:
        self.items: List[Dict[str, str]] = []
        self.max_items = max_items

    def add(self, when: str, kind: str, message: str) -> None:
        """Append a new activity entry."""
        self.items.append({"when": when, "kind": kind, "message": message})
        if len(self.items) > self.max_items * 2:
            self.items = self.items[-self.max_items :]

    def render(self, primary: str = "#ff2222", muted: str = "#888888") -> Panel:
        """Render the activity list as a Rich panel."""
        rows: List[Text] = []
        for it in self.items[-self.max_items :]:
            line = Text()
            line.append(f" {it['when']:>8s} ", style=muted)
            line.append(f"{it['kind']:<10s} ", style=f"bold {primary}")
            line.append(it["message"], style="#ffffff")
            rows.append(line)
        if not rows:
            rows = [Text("  (no recent activity)", style=muted)]
        return Panel(
            Group(*rows),
            title="[bold]RECENT ACTIVITY[/bold]",
            border_style=muted,
            box=ROUNDED,
            padding=(0, 1),
        )


# ---------------------------------------------------------------------------
# Standalone Rich renderable (no Textual app required)
# ---------------------------------------------------------------------------


def build_welcome_renderable(
    mission: Optional[MissionBriefing] = None,
    activity: Optional[RecentActivity] = None,
    theme_name: str = "DEFAULT",
    width: int = 100,
) -> RenderResult:
    """Build a single Rich renderable of the welcome screen.

    Args:
        mission: Optional mission briefing data. Defaults to a stub.
        activity: Optional recent activity list. Defaults to a stub.
        theme_name: Theme name to use for colouring.
        width: Target width in columns.

    Returns:
        Rich ``Group`` containing the welcome composition.
    """
    theme = get_theme(theme_name)
    primary = theme.get("primary", "#ff2222")
    text = theme.get("text", "#ffffff")
    muted = theme.get("muted", "#888888")
    bg = theme.get("bg_panel", "#0d0d0d")

    mission = mission or MissionBriefing()
    activity = activity or RecentActivity()

    logo = ascii_logo(
        color_a=theme.get("gradient_1", primary),
        color_b=theme.get("gradient_2", primary),
        color_c=theme.get("gradient_3", text),
    )
    subtitle = Text("Universal AI & Bug Bounty Agent", style=f"italic {muted}")

    header = Panel(
        Align.center(Group(logo, Text(" "), subtitle)),
        border_style=primary,
        box=HEAVY,
        padding=(0, 2),
        width=width,
    )

    body = Table(
        show_header=False,
        box=SIMPLE,
        padding=(0, 0),
        expand=True,
    )
    body.add_column("Left", ratio=1)
    body.add_column("Right", ratio=1)
    body.add_row(
        mission.render(primary=primary, text_color=text),
        render_quick_start(primary=primary, text_color=text, muted=muted),
    )
    body.add_row(
        activity.render(primary=primary, muted=muted),
        render_system_status(primary=primary, text_color=text, muted=muted),
    )

    return Group(header, body)


def _render_status_footer(
    theme_name: str = "DEFAULT",
    primary: str = "#ff2222",
    text_color: str = "#ffffff",
    muted: str = "#888888",
) -> Panel:
    """Render the bottom status bar with live clock and theme indicator."""
    now = datetime.now()
    line = Text()
    line.append(" THEME ", style=muted)
    line.append(theme_name, style=f"bold {primary}")
    line.append("   |   ", style=muted)
    line.append(now.strftime("%Y-%m-%d %H:%M:%S"), style=f"bold {text_color}")
    line.append("   |   ", style=muted)
    line.append("Elengenix v1.0.0", style=muted)
    line.append("   |   ", style=muted)
    line.append("Ctrl+Shift+P", style=f"bold {primary}")
    line.append(" palette", style=muted)
    return Panel(
        Align.center(line),
        border_style=muted,
        box=ROUNDED,
        padding=(0, 0),
    )


# ---------------------------------------------------------------------------
# Textual widget - WelcomeScreen
# ---------------------------------------------------------------------------


class WelcomeScreen(Container):
    """A Textual welcome screen widget.

    The screen is composed of:
        * The ELENGENIX logo (gradient ASCII)
        * A mission briefing panel
        * A quick-start tile grid
        * A recent activity list
        * A status footer with live clock

    All panels update in real time via the internal ``_tick`` timer.

    The widget exposes reactive properties for the mission data so an
    outer app can update the screen without poking individual sub-widgets.
    """

    DEFAULT_CSS = """
    WelcomeScreen {
        layout: vertical;
        background: #0d0d0d;
        width: 100%;
        height: 100%;
    }
    WelcomeScreen #welcome-header {
        height: auto;
    }
    WelcomeScreen #welcome-body {
        height: 1fr;
    }
    WelcomeScreen #welcome-footer {
        height: 3;
    }
    """

    target = reactive("no target set")
    scan_status = reactive("IDLE")
    ai_status = reactive("READY")
    operators = reactive(1)
    active_session = reactive("default")
    theme_name = reactive("DEFAULT")
    clock = reactive("00:00:00")

    def __init__(
        self,
        mission: Optional[MissionBriefing] = None,
        activity: Optional[RecentActivity] = None,
        **kwargs,
    ) -> None:
        super().__init__(**kwargs)
        self._mission = mission or MissionBriefing()
        self._activity = activity or RecentActivity()
        self._highlight_index = 0
        self._timer = None

    def compose(self):
        """Compose the welcome layout."""
        # Header (logo)
        yield Static(id="welcome-header")
        # Body (briefing + quick-start + activity)
        with Horizontal(id="welcome-body"):
            yield Static(id="welcome-briefing")
            yield Static(id="welcome-quickstart")
        # Footer (status)
        yield Static(id="welcome-footer")

    def on_mount(self) -> None:
        """Initial render + start clock timer."""
        self._refresh_all()
        self._timer = self.set_interval(1.0, self._tick_clock)

    def on_unmount(self) -> None:
        """Stop the timer when the widget is removed."""
        if self._timer is not None:
            self._timer.stop()
            self._timer = None

    # -- Reactive update hooks ---------------------------------------------

    def watch_target(self, _) -> None:
        self._refresh_mission()

    def watch_scan_status(self, _) -> None:
        self._refresh_mission()

    def watch_ai_status(self, _) -> None:
        self._refresh_mission()

    def watch_operators(self, _) -> None:
        self._refresh_mission()

    def watch_active_session(self, _) -> None:
        self._refresh_mission()

    def watch_theme_name(self, _) -> None:
        self._refresh_all()

    # -- Public API --------------------------------------------------------

    def add_activity(self, kind: str, message: str) -> None:
        """Append a new entry to the recent activity list."""
        ts = datetime.now().strftime("%H:%M:%S")
        self._activity.add(when=ts, kind=kind, message=message)
        self._refresh_activity()

    def highlight_tile(self, index: int) -> None:
        """Change which quick-start tile is highlighted."""
        self._highlight_index = index % len(QUICK_START_TILES)
        self._refresh_quickstart()

    # -- Internal render helpers -------------------------------------------

    def _tick_clock(self) -> None:
        """Update the clock once per second."""
        self.clock = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self._refresh_footer()

    def _refresh_all(self) -> None:
        """Re-render every section."""
        self._refresh_header()
        self._refresh_mission()
        self._refresh_quickstart()
        self._refresh_activity()
        self._refresh_footer()

    def _refresh_header(self) -> None:
        widget = self.query_one("#welcome-header", Static)
        theme = get_theme(self.theme_name)
        primary = theme.get("primary", "#ff2222")
        text = theme.get("text", "#ffffff")
        muted = theme.get("muted", "#888888")
        logo = ascii_logo(
            color_a=theme.get("gradient_1", primary),
            color_b=theme.get("gradient_2", primary),
            color_c=theme.get("gradient_3", text),
        )
        subtitle = Text("Universal AI & Bug Bounty Agent", style=f"italic {muted}")
        widget.update(
            Panel(
                Align.center(Group(logo, subtitle)),
                border_style=primary,
                box=HEAVY,
                padding=(0, 2),
            )
        )

    def _refresh_mission(self) -> None:
        widget = self.query_one("#welcome-briefing", Static)
        theme = get_theme(self.theme_name)
        primary = theme.get("primary", "#ff2222")
        text = theme.get("text", "#ffffff")
        mission = MissionBriefing(
            target=self.target,
            scan_status=self.scan_status,
            ai_status=self.ai_status,
            operators=self.operators,
            active_session=self.active_session,
        )
        widget.update(mission.render(primary=primary, text_color=text))

    def _refresh_quickstart(self) -> None:
        widget = self.query_one("#welcome-quickstart", Static)
        theme = get_theme(self.theme_name)
        primary = theme.get("primary", "#ff2222")
        text = theme.get("text", "#ffffff")
        muted = theme.get("muted", "#888888")
        widget.update(
            render_quick_start(
                highlight_index=self._highlight_index,
                primary=primary,
                text_color=text,
                muted=muted,
            )
        )

    def _refresh_activity(self) -> None:
        theme = get_theme(self.theme_name)
        primary = theme.get("primary", "#ff2222")
        muted = theme.get("muted", "#888888")
        widget = self._activity_panel()
        if widget is not None:
            widget.update(self._activity.render(primary=primary, muted=muted))

    def _activity_panel(self) -> Optional[Static]:
        # Activity is rendered inside the body - it lives in a separate panel
        # that we lazily create if missing.
        try:
            return self.query_one("#welcome-activity", Static)
        except Exception:
            return None

    def _refresh_footer(self) -> None:
        widget = self.query_one("#welcome-footer", Static)
        theme = get_theme(self.theme_name)
        primary = theme.get("primary", "#ff2222")
        text = theme.get("text", "#ffffff")
        muted = theme.get("muted", "#888888")
        widget.update(
            _render_status_footer(
                theme_name=self.theme_name,
                primary=primary,
                text_color=text,
                muted=muted,
            )
        )


__all__ = [
    "LOGO_LINES",
    "ascii_logo",
    "MissionBriefing",
    "RecentActivity",
    "QUICK_START_TILES",
    "render_quick_start",
    "render_system_status",
    "get_system_status",
    "build_welcome_renderable",
    "WelcomeScreen",
]
