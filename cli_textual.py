"""cli_textual.py — Elengenix AI Partner Mode (Textual TUI v99999)
Monochrome theme — Black & White minimalist hacker aesthetic.
"""

from __future__ import annotations

import math
import os
import random
import sys
import time
import logging
import warnings
from pathlib import Path

warnings.filterwarnings("ignore", category=FutureWarning)

from textual.app import App, ComposeResult
from textual.theme import Theme
from textual.geometry import Spacing
from textual.containers import Container, Horizontal, Vertical
from textual.widgets import Static, RichLog, Input
from textual.widget import Widget
from textual import work
from textual.binding import Binding

from rich.text import Text
from rich.panel import Panel
from rich.markdown import Markdown

from agent import get_agent
from agents.tui_game import ObbyGame

LOG_FILE = Path("data/elengenix_cli.log")
LOG_FILE.parent.mkdir(exist_ok=True)
logging.basicConfig(level=logging.WARNING, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger("elengenix.cli_textual")

# ── DUAL THEME: CHILL (white) ──────────────────────────────────────────
BASE    = "#000000"
MANTLE  = "#111111"
CRUST   = "#0d0d0d"
SURFACE = "#1a1a1a"
TEXT    = "#ffffff"
WHITE   = "#ffffff"
MUTED   = "#555555"
DIM     = "#444444"
GRAY    = "#888888"

# ── DUAL THEME: HUNT (red accent only — same background as CHILL) ────
H_BASE    = BASE
H_MANTLE  = MANTLE
H_CRUST   = CRUST
H_SURFACE = SURFACE
H_TEXT    = TEXT
H_MUTED   = MUTED
H_DIM     = DIM
H_GRAY    = GRAY
H_RED     = "#ff2222"
H_BRIGHT  = "#ff5555"

AGENT_NAMES  = {1: "Elengix 1", 2: "Elengix 2", 3: "Elengix 3"}
AGENT_COLORS = {1: WHITE, 2: GRAY, 3: MUTED}

CHILL_COLORS = {
    "BASE": BASE, "MANTLE": MANTLE, "CRUST": CRUST, "SURFACE": SURFACE,
    "TEXT": TEXT, "MUTED": MUTED, "DIM": DIM, "GRAY": GRAY,
    "WHITE": TEXT, "BORDER": DIM, "ACCENT": TEXT,
}
HUNT_COLORS = {
    "BASE": H_BASE, "MANTLE": H_MANTLE, "CRUST": H_CRUST, "SURFACE": H_SURFACE,
    "TEXT": H_TEXT, "MUTED": H_MUTED, "DIM": H_DIM, "GRAY": H_GRAY,
    "WHITE": H_RED, "BORDER": H_DIM, "ACCENT": H_BRIGHT,
}

ASCII_BANNER = """\
[{color}]███████╗██╗     ███████╗███╗   ██╗ ██████╗ ███████╗███╗   ██╗██╗██╗  ██╗
[{color}]██╔════╝██║     ██╔════╝████╗  ██║██╔════╝ ██╔════╝████╗  ██║██║╚██╗██╔╝
[{color}]█████╗  ██║     █████╗  ██╔██╗ ██║██║  ███╗█████╗  ██╔██╗ ██║██║ ╚███╔╝
[{color}]██╔══╝  ██║     ██╔══╝  ██║╚██╗██║██║   ██║██╔══╝  ██║╚██╗██║██║ ██╔██╗
[{color}]███████╗███████╗███████╗██║ ╚████║╚██████╔╝███████╗██║ ╚████║██║██╔╝ ██╗
[{color}]╚══════╝╚══════╝╚══════╝╚═╝  ╚═══╝ ╚═════╝ ╚══════╝╚═╝  ╚═══╝╚═╝╚═╝  ╚═╝[/]"""

HELP_TEXT = """\
[white]━━━ COMMANDS ━━━[/]
  [dim]/clear[/]       Clear chat
  [dim]/reset[/]       Reset session
  [dim]/quit[/]        Exit
  [dim]/mode chill[/]  CHILL — chat only (no scan)
  [dim]/mode hunt[/]   HUNT — chat + full scan
  [dim]/target <x>[/]  Set target domain
  [dim]/talk <n>[/]    Talk to agent 1,2,3 or all
  [dim]/session[/]     Session info
  [dim]/session new[/] New session
  [dim]/session list[/] List saved sessions
  [dim]/session load <id>[/] Load session
  [dim]/stats[/]       Memory stats
  [dim]/team[/]        Show team

[white]━━━ SHORTCUTS ━━━[/]
  [dim]Ctrl+R[/] Research  [dim]Ctrl+M[/] CHILL/HUNT
  [dim]Ctrl+T[/] Thinking  [dim]Ctrl+P[/] Model
  [dim]Ctrl+G[/] Help      [dim]Ctrl+S[/] Settings
  [dim]↑↓[/] History       [dim]/[/] Slash commands"""


# ── Sidebar ──────────────────────────────────────────────────────────────
class Sidebar(Container):
    """Right-hand panel — golden-ratio width, monochrome minimal."""

    DEFAULT_CSS = f"""
    Sidebar {{
        width: 38; height: 1fr;
        background: {MANTLE};
        border-left: solid {DIM};
        margin: 0; padding: 1 1;
        overflow-y: auto;
    }}
    """

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._data: dict = {}

    def compose(self) -> ComposeResult:
        yield Static("", id="sidebar_content")

    def refresh_data(self, **kw) -> None:
        self._data.update(kw)
        d = self._data
        status   = d.get("status", "ready")
        mode     = d.get("mode", "auto")
        models   = d.get("models", [])
        session  = d.get("session", "new")
        turns    = d.get("turns", 0)
        tokens   = d.get("tokens", 0)
        limit    = d.get("limit", 128000)
        thinking = d.get("thinking", False)
        target   = d.get("target", "")
        team     = d.get("team", 0)
        findings = d.get("findings", 0)
        tools_run = d.get("tools_run", 0)
        talk_to  = d.get("talk_to", "all")
        game_active = d.get("game_active", False)
        game_frame = d.get("game_frame", "")

        if game_active:
            sidebar_text = (
                f"[white]┌ {game_frame}[/]\n"
                f"[dim]─" + "─" * 28 + "[/]\n"
                f"[white]SHORTCUTS[/]\n"
                f"  [dim]SPACE[/] Jump / Restart\n"
                f"  [dim]Q / Esc[/] Quit Game\n"
                f"[dim]─" + "─" * 28 + "[/]\n"
                f"[white]DETAILS[/]\n"
                f"  Turns: [white]{turns}[/]  [dim]Tools:[/] {tools_run}\n"
                f"  [dim]Findings:[/] {findings}\n"
                f"  Target: [white]{target[:18] or 'none'}[/]\n"
            )
        else:
            dot = f"[white]●[/]" if status == "ready" else f"[dim]●[/]"
            slabel = "[white]READY[/]" if status == "ready" else "[dim]WORKING[/]"
            if os.environ.get("TEAM_STAGGERING") == "1":
                slabel = "[white]STAGGER[/]"
            mode_icon = "[white]❄ CHILL[/]" if mode == "CHILL" else "[white]⚔ HUNT[/]"
            think_tag = f"  [dim]THINK[/]" if thinking else ""
            team_tag = f"  [dim]TEAM {team}[/]" if team > 1 else ""
            talk_tag = ""
            if talk_to != "all" and team > 0:
                name = AGENT_NAMES.get(talk_to, f"#{talk_to}")
                talk_tag = f"\n  [dim]▶ {name}[/]"

            pct   = min(100, int((tokens / limit) * 100)) if limit > 0 else 0
            bar_w = 24
            filled = int((pct / 100) * bar_w)
            bar  = f"[white]{'█' * filled}[/][dim]{'█' * (bar_w - filled)}[/]"

            target_line = f"\n  [white]{target[:28]}[/]" if target else f"\n  [dim]none[/]"

            model_lines = []
            if models:
                for i, m in enumerate(models):
                    name = AGENT_NAMES.get(i + 1, f"#{i + 1}")
                    short = m.split("/")[-1] if "/" in m else m
                    color = AGENT_COLORS.get(i + 1, TEXT)
                    model_lines.append(f"  [{color}]{name}[/] [dim]{short[:20]}[/]")
            else:
                model_lines.append(f"  [dim]default[/]")

            sidebar_text = (
                f"[white]┌ ELENGENIX[/]\n"
                f"  {dot} {mode_icon}  {slabel}{think_tag}{team_tag}{talk_tag}\n"
                f"[dim]─" + "─" * 28 + "[/]\n"
                f"[white]TARGET[/]{target_line}\n"
                f"[dim]─" + "─" * 28 + "[/]\n"
                f"[white]SESSION[/]\n"
                f"  [dim]{session[:20]}[/]\n"
                f"  Mode: [white]{mode}[/] [dim]Turns: {turns}[/]\n"
                f"[dim]─" + "─" * 28 + "[/]\n"
                f"[white]SCAN[/]\n"
                f"  [dim]Tools:[/] {tools_run}  [dim]Findings:[/] {findings}\n"
                f"[dim]─" + "─" * 28 + "[/]\n"
                f"[white]MODELS[/]\n"
                + "\n".join(model_lines) + "\n"
                f"[dim]─" + "─" * 28 + "[/]\n"
                f"[white]CONTEXT[/]\n"
                f"  {bar}\n"
                f"  [dim]{tokens}[/dim]/[dim]{limit}[/]  {pct}%\n"
                f"[dim]─" + "─" * 28 + "[/]\n"
                f"[white]SHORTCUTS[/]\n"
                f"  [dim]Ctrl+R[/] Research [dim]Ctrl+M[/] CHILL/HUNT\n"
                f"  [dim]Ctrl+T[/] Think   [dim]Ctrl+P[/] Model\n"
                f"  [dim]Ctrl+G[/] Help    [dim]Ctrl+S[/] Settings\n"
            )
        try:
            self.query_one("#sidebar_content", Static).update(sidebar_text)
        except Exception:
            pass


# ── Thinking Animation ─────────────────────────────────────────────────
class ThinkingWidget(Static):
    """Animated thinking indicator — driven by 30fps master tick (no own timer)."""
    DEFAULT_CSS = f"""ThinkingWidget {{ height: 1; padding: 0 1 0 5; color: {WHITE}; display: none; }}
    ThinkingWidget.visible {{ display: block; }}"""

    def on_mount(self) -> None:
        self.frames = ["◐", "◓", "◑", "◒"]
        self.idx = 0
        # No timer — animated by app._animate_frame at 30fps

    def show(self) -> None:
        self.add_class("visible")

    def hide(self) -> None:
        self.remove_class("visible")


# ── Animation Overlay Widgets ──────────────────────────────────────────
class Scanline(Static):
    """Horizontal wipe bar — positioned via margin top."""
    DEFAULT_CSS = """
    Scanline { layer: overlay; width: 100%; height: 1; display: none; }
    """

class GlitchFlash(Static):
    """Full-screen flash overlay."""
    DEFAULT_CSS = """
    GlitchFlash { layer: overlay; width: 100%; height: 100%; display: none; }
    """

GLITCH_CHARS = "!@#$%^&*<>?╳░▒▓│┤╡╢╖╕╣║╗╝╜╛┐└┴┬├─┼╞╟╚╔╩╦╠═╬╧╨╤╥╙╘╒╓╫╪┘┌"

def _lerp(a: float, b: float, t: float) -> float:
    return a + (b - a) * max(0.0, min(1.0, t))

def _lerp_color(c1: str, c2: str, t: float) -> str:
    t = max(0.0, min(1.0, t))
    r1, g1, b1 = int(c1[1:3],16), int(c1[3:5],16), int(c1[5:7],16)
    r2, g2, b2 = int(c2[1:3],16), int(c2[3:5],16), int(c2[5:7],16)
    return f"#{int(_lerp(r1,r2,t)):02x}{int(_lerp(g1,g2,t)):02x}{int(_lerp(b2,b1,t)):02x}"

# ── Status & Progress Bars ─────────────────────────────────────────────
class StatusBar(Static):
    DEFAULT_CSS = f"""StatusBar {{ height: 1; padding: 0 1; background: {CRUST}; color: {MUTED}; }}"""

    def show_action(self, cmd: str, risk: str = "SAFE") -> None:
        tag = {"SAFE": "", "PRIVILEGED": "[dim]▶ PRIV[/]", "DESTRUCTIVE": "[white]▶ BLOCKED[/]"}.get(risk, "")
        self.update(f"{tag}  [dim]{cmd[:75]}[/]" if tag else f"[dim]{cmd[:80]}[/]")

    def show_message(self, msg: str) -> None:
        self.update(f"[dim]{msg[:80]}[/]")


class ProgressBar(Static):
    DEFAULT_CSS = f"""ProgressBar {{ height: 1; padding: 0 1; background: {MANTLE}; display: none; }}"""

    def show_scan(self, tool: str, cur: int, total: int, findings: int) -> None:
        self.update("")  # animated by smooth progress in _animate_frame
        self.show()

    def show(self) -> None: self.add_class("visible")
    def hide(self) -> None: self.remove_class("visible")


# ── Settings Overlay ────────────────────────────────────────────────────
CUSTOM_URL_INPUT_CSS = """
#custom_url_row { height: 3; display: none; margin: 0 1; background: #111111; border: solid #444444; }
#custom_url_row.visible { display: block; }
#custom_url_input { height: 3; border: none; background: #111111; color: #ffffff; padding: 0 1; }
"""

class SettingsOverlayWidget(Widget, can_focus=True):
    DEFAULT_CSS = f"""
    SettingsOverlayWidget {{ layer: overlay; align: center middle; width: 100%; height: 100%; display: none; }}
    SettingsOverlayWidget.visible {{ display: block; }}
    #settings_panel {{ width: 72; height: auto; max-height: 80%; min-height: 20; background: {BASE}; border: solid {DIM}; padding: 0; }}
    #settings_header {{ width: 1fr; height: 1; content-align: center middle; background: {BASE}; color: {WHITE}; text-style: bold; border-bottom: solid {DIM}; }}
    #settings_content {{ width: 1fr; height: auto; background: transparent; padding: 1 2; }}
    #settings_footer {{ width: 1fr; height: 1; content-align: center middle; color: {MUTED}; background: {CRUST}; }}
    {CUSTOM_URL_INPUT_CSS}
    """

    def compose(self) -> ComposeResult:
        with Vertical(id="settings_panel"):
            yield Static("  SETTINGS  ", id="settings_header")
            yield Static("", id="settings_content", markup=True)
            with Horizontal(id="custom_url_row"):
                yield Input(placeholder="Enter API base URL...", id="custom_url_input")
            yield Static("  ↑↓ Navigate  ⏎ Select  Esc Close  S Save", id="settings_footer")

    def on_mount(self) -> None:
        self._overlay = None
        self._reload()

    def _reload(self) -> None:
        try:
            from tools.overlay_menu import SettingsOverlay
            self._overlay = SettingsOverlay(getattr(self.app, "_agent", None), None, target=getattr(self.app, "target", ""))
        except Exception:
            self._overlay = None

    def _redraw(self) -> None:
        w = self.query_one("#settings_content", Static)
        if self._overlay:
            w.update(self._overlay.render())
        else:
            w.update(Panel("[dim]Unavailable. Esc to close.[/]", border_style=DIM))

    def show(self) -> None:
        self._reload(); self._redraw(); self.add_class("visible")
        try:
            self.app.query_one("#user_input", Input).disabled = True
        except: pass
        self.app.set_timer(0.0, lambda: self.focus())

    def hide(self) -> None:
        self.remove_class("visible")
        self.query_one("#custom_url_row").remove_class("visible")
        try:
            inp = self.app.query_one("#user_input", Input)
            inp.disabled = False; inp.focus()
        except: pass

    def on_key(self, event) -> None:
        if not self.has_class("visible"): return
        if self.query_one("#custom_url_row").has_class("visible"):
            if event.key == "escape": self.hide()
            return
        key = event.key
        cmap = {"escape": "\x1b", "enter": "\r", "up": "\x1b[A", "down": "\x1b[B", "left": "\x1b[D", "right": "\x1b[C"}
        char = cmap.get(key, event.character or "")
        if not char: return
        event.stop()
        r = self._overlay.handle_char(char) if self._overlay else "exit"
        if r == "exit": self.hide()
        elif r == "show_custom_url": self._show_custom_url()
        elif r and r.startswith("load_session:"):
            sid = r.split(":", 1)[1]
            self.hide()
            if hasattr(self.app, "_load_session_by_id"): self.app._load_session_by_id(sid)
        elif r == "saved":
            self.app._chat_write_system("[dim]Settings saved.[/]")
            if hasattr(self.app, "_agent") and self.app._agent:
                try:
                    from tools.governance import Governance
                    self.app._agent.governance = Governance()
                except: pass
            self.hide()
        elif r == "error":
            self.app._chat_write_system("[dim]Settings failed.[/]"); self.hide()
        else:
            self.query_one("#custom_url_row").remove_class("visible")
            self._redraw()

    def _show_custom_url(self) -> None:
        self.query_one("#settings_content", Static).update("")
        row = self.query_one("#custom_url_row")
        row.add_class("visible")
        inp = self.query_one("#custom_url_input", Input)
        inp.value = ""; inp.focus()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id != "custom_url_input": return
        val = event.value.strip()
        if not val or not self._overlay:
            self.query_one("#custom_url_row").remove_class("visible")
            self._redraw()
            self.app.set_timer(0.0, lambda: self.focus()); return
        step = getattr(self._overlay, "_custom_step", "")
        inp = self.query_one("#custom_url_input", Input)
        if step == "apikey":
            self._overlay.handle_custom_apikey(val)
            self.query_one("#custom_url_row").remove_class("visible")
            self._redraw()
            self.app.set_timer(0.0, lambda: self.focus())
        elif step == "model":
            url = getattr(self._overlay, "_custom_url", "")
            if url: os.environ["CUSTOM_API_BASE"] = url
            self._overlay._agent_config[self._overlay._agent_idx] = {"provider": "custom", "model": val}
            self._overlay._save_and_apply()
            self._overlay._custom_step = ""
            self.query_one("#custom_url_row").remove_class("visible")
            self._redraw()
            self.app.set_timer(0.0, lambda: self.focus())
        else:
            self._overlay.handle_custom_url(val)
            inp.value = ""
            inp.placeholder = "Enter API key (or Enter to skip)..."
            inp.focus()


# ── Help Overlay ────────────────────────────────────────────────────────
class HelpOverlayWidget(Widget, can_focus=True):
    """Modal overlay for displaying help — Esc to close."""

    DEFAULT_CSS = f"""
    HelpOverlayWidget {{ layer: overlay; align: center middle; width: 100%; height: 100%; display: none; }}
    HelpOverlayWidget.visible {{ display: block; }}
    #help_panel {{ width: 68; height: auto; max-height: 80%; min-height: 14; background: {BASE}; border: solid {DIM}; padding: 0; overflow-y: auto; }}
    #help_header {{ width: 1fr; height: 1; content-align: center middle; background: {BASE}; color: {WHITE}; text-style: bold; border-bottom: solid {DIM}; }}
    #help_body {{ width: 1fr; height: auto; background: transparent; padding: 1 2; }}
    #help_footer {{ width: 1fr; height: 1; content-align: center middle; color: {MUTED}; background: {CRUST}; }}
    """

    def compose(self) -> ComposeResult:
        with Vertical(id="help_panel"):
            yield Static("  HELP  ", id="help_header")
            yield Static("", id="help_body", markup=True)
            yield Static("  Esc Close", id="help_footer")

    def on_mount(self) -> None:
        self.query_one("#help_body", Static).update(Text.from_markup(HELP_TEXT))

    def show(self) -> None:
        self.add_class("visible")
        try:
            self.app.query_one("#user_input", Input).disabled = True
        except Exception:
            pass
        self.app.set_timer(0.0, lambda: self.focus())

    def hide(self) -> None:
        self.remove_class("visible")
        try:
            inp = self.app.query_one("#user_input", Input)
            inp.disabled = False
            inp.focus()
        except Exception:
            pass

    def on_key(self, event) -> None:
        if not self.has_class("visible"):
            return
        event.stop()
        if event.key == "escape":
            self.hide()


# ── Main App ───────────────────────────────────────────────────────────
class ElengenixTextualApp(App):
    # ── Golden ratio layout: φ ≈ 1.618 ───────────────────────────────────
    # chat : sidebar = 1.618 : 1  →  side = 100/2.618 ≈ 38
    # ── CSS with transitions, using Textual theme variables ──────────────
    CSS = """
Screen { background: $surface; layers: base overlay; transition: border 500ms; border: solid transparent; }
Screen.glow { border: heavy $accent; }
RichLog, Sidebar { scrollbar_color: $secondary; scrollbar_color_hover: $accent; scrollbar_color_active: $primary; }
Sidebar { width: 38; height: 1fr; background: $surface; border-left: solid $secondary; margin: 0; padding: 1 1; overflow-y: auto; }
ThinkingWidget { height: 1; padding: 0 1 0 5; color: $primary; display: none; }
ThinkingWidget.visible { display: block; }
StatusBar { height: 1; padding: 0 1; background: $panel; color: $secondary; }
ProgressBar { height: 1; padding: 0 1; background: $surface; display: none; }
#header { height: 1; background: $background; color: $text; content-align: center middle; border-bottom: solid $secondary; padding: 0 5; }
#main_row { height: 1fr; layer: base; }
#chat_col { width: 1fr; height: 1fr; background: $background; }
#chat_area { height: 1fr; background: $background; padding: 1 3 1 3; overflow-y: auto; }
#input_row { height: auto; margin: 0 3 1 3; background: $background; border-top: solid $secondary; border-bottom: solid $secondary; border-left: thick $primary; }
#user_input { height: 3; border: none; background: $surface; color: $text; padding: 0 3 0 3; }
#user_input:focus { border: none; }
#suggest_box { height: auto; max-height: 6; background: $surface; color: $text; min-height: 0; border: none; margin: 0 3 0 3; padding: 0 3; overflow-y: auto; display: none; }
#banner { height: auto; display: block; padding: 2 3 0 3; }
"""

    BINDINGS = [
        Binding("ctrl+r", "toggle_research", "Research", priority=True),
        Binding("ctrl+m", "toggle_mode", "CHILL/HUNT", priority=True),
        Binding("ctrl+t", "toggle_think", "Think", priority=True),
        Binding("ctrl+p", "show_model", "Model", priority=True),
        Binding("ctrl+g", "show_help", "Help", priority=True),
        Binding("ctrl+s", "show_settings", "Settings", priority=True),
        Binding("ctrl+c", "app_exit", "Exit", priority=True),
        Binding("ctrl+u", "scroll_up", "", show=False, priority=True),
        Binding("ctrl+d", "scroll_down", "", show=False, priority=True),
        Binding("up", "history_up", "", show=False),
        Binding("down", "history_down", "", show=False),
    ]

    def __init__(self, target: str = "", mode: str = "CHILL", session_id: str = "", **kwargs):
        super().__init__(**kwargs)
        self.target        = target
        self.mode          = mode
        self.thinking      = False
        self._load_sid     = session_id
        self.session_name  = session_id or ""
        self.turn_count    = 0
        self.tools_run     = 0
        self.findings      = 0
        self.history: list[str] = []
        self.history_idx   = -1
        self._processing   = False
        self._agent        = None
        self._talk_to      = "all"
        self._team_active  = False
        self._session_mgr  = None
        self._pending_session = None
        self._cached_chat: RichLog | None = None
        self._cached_sidebar: Sidebar | None = None
        self._last_sidebar_update: float = 0.0

        # ── Animation (30fps) ─────────────────────────────────────────
        self._anim_frame = 0
        self._header_pulse = 0
        self._scanline_y = 0
        self._smooth_progress = 0.0
        self._displayed_tools = 0
        self._displayed_findings = 0
        self._displayed_tokens = 0
        self._target_tools = 0
        self._target_findings = 0
        self._target_tokens = 0
        self._thinking_dots = 0
        self._theme_transition = 0.0

        # Autocomplete suggestion state
        self._suggest_idx = -1
        self._original_prefix = ""
        self._cycling_suggestions = False

        # Cinematic transition state
        self._trans = False
        self._trans_frame = 0
        self._trans_next = ""
        self._trans_total = 24  # 24 frames @ 30fps = 0.8s
        self._scanline_y = 0
        self._header_base_text = "  ELENGENIX  ❄[dim]CHILL[/]  ⚔[dim]HUNT[/]"
        self.game = ObbyGame(self, on_exit=self._stop_game)
        self._game_active = False
        self._current_game_frame = ""

    def compose(self) -> ComposeResult:
        yield Static(self._header_base_text + f"  {self.target or ''}  |  /help", id="header")
        with Horizontal(id="main_row"):
            with Vertical(id="chat_col"):
                yield Static("", id="banner", markup=True)
                yield RichLog(id="chat_area", highlight=True, markup=True, wrap=True, auto_scroll=True, max_lines=2000)
                yield ThinkingWidget(id="thinking_bar")
                yield ProgressBar(id="progress_bar")
                yield StatusBar(id="status_bar")
                with Vertical(id="input_row"):
                    yield Static("", id="suggest_box", markup=True)
                    yield Input(placeholder="  try it!", id="user_input")
            yield Sidebar(id="sidebar")
        yield Scanline(id="scanline")
        yield GlitchFlash(id="glitch")
        yield SettingsOverlayWidget(id="settings_overlay")
        yield HelpOverlayWidget(id="help_overlay")

    def on_mount(self) -> None:
        # Banner is blank at start, animated via boot sequence
        self.query_one("#banner", Static).update("")
        try:
            from tools.session_manager import SessionManager
            self._session_mgr = SessionManager()
            if self._load_sid:
                self._pending_session = self._session_mgr.resume_session(self._load_sid)
                if self._pending_session:
                    self.session_name = self._load_sid
                    self.target = self._pending_session.get("target", self.target)
                    self.mode = self._pending_session.get("mode", self.mode)
                    self.turn_count = self._pending_session.get("turns", 0)
                else:
                    self._chat_write_system(f"Session not found: {self._load_sid}")
                    self._load_sid = ""
        except: pass
        self._update_sidebar()
        self.set_focus(self.query_one("#user_input", Input))
        self._load_agent()
        self._run_boot_sequence()

        # Register custom themes and apply CHILL
        self.register_theme(Theme(
            name="chill", primary=WHITE, secondary=GRAY, accent=WHITE,
            background=BASE, surface=MANTLE, panel=CRUST, foreground=TEXT,
            error=WHITE, success=WHITE, warning=WHITE, dark=True,
        ))
        self.register_theme(Theme(
            name="hunt", primary=H_RED, secondary=H_RED, accent=H_BRIGHT,
            background=BASE, surface=MANTLE, panel=CRUST, foreground=H_RED,
            error=H_RED, success=H_RED, warning=H_BRIGHT, dark=True,
        ))
        self.theme = "chill"

        # ── 30fps animation timers ──────────────────────────────────────
        self.set_interval(1 / 30, self._animate_frame)

        # Counter animations (update every 60ms = ~16fps, smoother than jump)
        self.set_interval(1 / 16, self._animate_counters)

    @work(thread=True)
    def _load_agent(self) -> None:
        try:
            logging.getLogger().setLevel(logging.WARNING)
            self._agent = get_agent()
            if self._agent:
                _ = self._agent.governance
                if hasattr(self, "_pending_session") and self._pending_session:
                    from tools.session_manager import SessionManager
                    SessionManager().resume_session(self._load_sid, agent=self._agent)
                    self._pending_session = None
                    self.call_from_thread(self._replay_history)
                else:
                    self._agent.conversation_history = []
        except Exception as e:
            self.call_from_thread(self._chat_write_error, f"Agent load: {e}")
        finally:
            logging.getLogger().setLevel(logging.INFO)

    def _ensure_session(self) -> str:
        if self.session_name: return self.session_name
        from tools.session_manager import generate_session_id
        self.session_name = generate_session_id()
        try:
            if self._session_mgr:
                self._session_mgr.start_session(name=self.session_name, target=self.target, mode=self.mode)
        except: pass
        self._update_sidebar()
        return self.session_name

    # ── Animations (30fps) ────────────────────────────────────────────────

    def _animate_frame(self) -> None:
        """30fps master tick — transition, header, spinner, progress."""
        self._anim_frame += 1

        # Cinematic transition
        if self._trans:
            self._trans_frame += 1
            self._run_transition(self._trans_frame)
            if self._trans_frame >= self._trans_total:
                self._finish_transition()
            return

        # Game tick (30fps)
        if self._game_active and self.game.running:
            frame = self.game.tick()
            if frame:
                self._game_display(frame)
            elif self.game.game_over:
                self._game_display(self.game._render_death())
            return

        # Header pulse
        if self._anim_frame % 60 == 0:
            self._header_pulse = (self._header_pulse + 1) % 4
            shades = ["#ffffff", "#cccccc", "#999999", "#cccccc"]
            try:
                self.query_one("#header", Static).styles.color = shades[self._header_pulse]
            except Exception:
                pass

        # ThinkingWidget tick — 30fps smoothness
        if self._processing:
            tw = self.query_one("#thinking_bar", ThinkingWidget)
            try:
                frames = ["◐", "◓", "◑", "◒"]
                tw.idx = (self._anim_frame // 8) % 4
                tw.update(f"[white]{frames[tw.idx]} thinking[/]")
            except Exception:
                pass

        # Smooth progress bar tick
        if hasattr(self, "_progress_total") and self._progress_total > 0:
            self._smooth_progress += (self._progress_cur / max(self._progress_total, 1) - self._smooth_progress) * 0.3
            try:
                pb = self.query_one("#progress_bar", ProgressBar)
                w = 30
                filled = int(self._smooth_progress * w)
                bar = f"[white]{'█' * filled}[/][dim]{'█' * (w - filled)}[/]"
                pb.update(f"  {bar}  {self._progress_tool}  [dim]({self._progress_cur}/{self._progress_total})[/]  {self._progress_findings} findings")
            except Exception:
                pass

    def _animate_counters(self) -> None:
        """Smooth counter transitions (~16fps) for sidebar numbers."""
        changed = False

        # Tools run counter
        if self._displayed_tools < self._target_tools:
            self._displayed_tools = min(self._displayed_tools + 1, self._target_tools)
            changed = True
        elif self._displayed_tools > self._target_tools:
            self._displayed_tools = self._target_tools
            changed = True

        # Findings counter
        if self._displayed_findings < self._target_findings:
            self._displayed_findings = min(self._displayed_findings + 1, self._target_findings)
            changed = True
        elif self._displayed_findings > self._target_findings:
            self._displayed_findings = self._target_findings
            changed = True

        # Token counter (bigger jumps)
        if self._displayed_tokens < self._target_tokens:
            self._displayed_tokens = min(self._displayed_tokens + int((self._target_tokens - self._displayed_tokens) * 0.2) + 1, self._target_tokens)
            changed = True

        if changed:
            self._update_sidebar()

    # ── Transition Animation Methods ─────────────────────────────────────
    def _run_transition(self, f: int) -> None:
        """Premium pulse-crossfade transition between HUNT and CHILL modes."""
        if self._trans_next not in ("HUNT", "CHILL"):
            return
        going_hunt = self._trans_next == "HUNT"
        try:
            # Phase 1: Quick bright pulse flash (f 1-3)
            if f <= 3:
                flash = self.query_one("#glitch", GlitchFlash)
                flash.styles.display = "block"
                intensities = [0.5, 1.0, 0.3]
                v = intensities[f - 1]
                if going_hunt:
                    r = int(255 * v)
                    g = int(20 * v)
                    flash.styles.background = f"#{r:02x}{g:02x}00"
                else:
                    c = int(240 * v)
                    flash.styles.background = f"#{c:02x}{c:02x}{c:02x}"
                return

            # Phase 2: Smooth crossfade all UI elements (f 4-18)
            if f <= 18:
                if f == 4:
                    try:
                        self.query_one("#glitch", GlitchFlash).styles.display = "none"
                    except Exception:
                        pass
                t = (f - 3) / 15.0
                ease = t * t * (3 - 2 * t)  # smoothstep easing

                if going_hunt:
                    bg_r = int(ease * 10)
                    bg = f"#{bg_r:02x}0000"
                    txt_g = int(255 - ease * 51)
                    txt_b = int(255 - ease * 51)
                    txt = f"#ff{txt_g:02x}{txt_b:02x}"
                else:
                    bg_r = int(10 - ease * 10)
                    bg = f"#{bg_r:02x}0000"
                    txt_v = int(204 + ease * 51)
                    txt = f"#{txt_v:02x}{txt_v:02x}{txt_v:02x}"

                for sel in ("#header", "#chat_area", "#sidebar", "#input_row"):
                    try:
                        w = self.query_one(sel)
                        w.styles.background = bg
                        w.styles.color = txt
                    except Exception:
                        pass

                # Switch mode at midpoint for seamless feel
                if f == 11:
                    self.mode = self._trans_next
                    self.theme = "hunt" if going_hunt else "chill"
                    self._update_banner()
                return

            # Phase 3: Accent settle with header glow (f 19-24)
            if f <= 24:
                t = (f - 18) / 6.0
                ease = t * t
                try:
                    header = self.query_one("#header", Static)
                    if going_hunt:
                        g = int(34 * (1 - ease * 0.5))
                        header.styles.color = f"#ff{g:02x}{g:02x}"
                    else:
                        v = int(220 + ease * 35)
                        header.styles.color = f"#{v:02x}{v:02x}{v:02x}"
                except Exception:
                    pass
        except Exception:
            pass

    def _finish_transition(self) -> None:
        try:
            self.query_one("#scanline", Scanline).styles.display = "none"
            self.query_one("#glitch", GlitchFlash).styles.display = "none"
        except: pass
        self._trans = False
        self._trans_frame = 0
        self.mode = self._trans_next
        self.theme = "hunt" if self._trans_next == "HUNT" else "chill"
        self._update_banner()
        self._update_sidebar()


    def _chat(self) -> RichLog:
        if self._cached_chat is None:
            self._cached_chat = self.query_one("#chat_area", RichLog)
        return self._cached_chat

    def _sidebar(self) -> Sidebar:
        if self._cached_sidebar is None:
            self._cached_sidebar = self.query_one("#sidebar", Sidebar)
        return self._cached_sidebar

    def _update_banner_text(self, text: str) -> None:
        try:
            self.query_one("#banner", Static).update(Text.from_markup(text))
        except Exception:
            pass

    @work(thread=True)
    def _run_boot_sequence(self) -> None:
        """Typewriter ASCII banner boot-up line-by-line accompanied by system bell, then initialization logs."""
        color = "#ff2222" if self.mode == "HUNT" else "white"
        lines = ASCII_BANNER.strip().split("\n")
        current_lines = []
        bell_enabled = "--no-bell" not in sys.argv and os.environ.get("ELENGENIX_BELL") != "0"
        
        for line in lines:
            current_lines.append(line.format(color=color))
            self.call_from_thread(self._update_banner_text, "\n".join(current_lines))
            time.sleep(0.12)
            
        sys_logs = [
            "[INFO] Loading security knowledge base...",
            "[INFO] Registering 62 vulnerability detection skills...",
            "[INFO] Initializing Governance risk engine...",
            "[INFO] Establishing LLM client session...",
            "[OK] System initialized successfully. Ready to hunt.",
        ]
        for log in sys_logs:
            time.sleep(0.15)
            self.call_from_thread(self._chat_write_system, log)

        # Single friendly notification ring on complete boot
        if bell_enabled:
            sys.stdout.write("\a")
            sys.stdout.flush()

    def _trigger_border_glow(self) -> None:
        """Temporarily add the .glow class to the screen to trigger border pulse."""
        try:
            screen = self.screen
            screen.add_class("glow")
            self.set_timer(1.2, lambda: screen.remove_class("glow"))
        except Exception:
            pass

    def _update_banner(self) -> None:
        color = "#ff2222" if self.mode == "HUNT" else "white"
        raw = ASCII_BANNER.strip().format(color=color)
        self.query_one("#banner", Static).update(Text.from_markup(raw))

    def _chat_write_user(self, text: str) -> None:
        ts = time.strftime("%H:%M")
        self._chat().write(Text.from_markup(
            f"\n[white]┃[/] [dim]{ts}[/] [white]you[/]\n"
            f"  [white]{text}[/]"
        ))

    def _chat_write_agent(self, text: str) -> None:
        ts = time.strftime("%H:%M")
        self._chat().write(Text.from_markup(f"\n[white]┃[/] [dim]{ts}[/] [white]elengix[/]"))
        try:
            self._chat().write(Markdown(text))
        except Exception:
            self._chat().write(Text(f"  {text}", style=TEXT))

    def _chat_write_elengix(self, aid: int, text: str, t: str = "") -> None:
        name = AGENT_NAMES.get(aid, f"#{aid}")
        tag = f" [dim]{t}[/]" if t else ""
        ts = time.strftime("%H:%M")
        self._chat().write(Text.from_markup(
            f"\n[white]┃[/] [dim]{ts}[/] [white]{name}[/]{tag}\n"
            f"  [white]{text[:500]}[/]"
        ))

    def _chat_write_system(self, markup: str) -> None:
        self._chat().write(Text.from_markup(f"[dim]{markup}[/]"))

    def _chat_write_governance(self, cmd: str, risk: str) -> None:
        """Show governance action in status bar only (not in chat log)."""
        self.query_one("#status_bar", StatusBar).show_action(cmd, risk)

    def _chat_write_error(self, markup: str) -> None:
        self._chat().write(Text.from_markup(f"[white]error:[/] {markup}"))

    def _update_sidebar(self, force: bool = False) -> None:
        now = time.monotonic()
        if not force and (now - self._last_sidebar_update < 0.3): return
        self._last_sidebar_update = now
        tokens = 0; model = "default"; team = 0; models: list[str] = []
        try:
            if self._agent:
                from tools.token_counter import count_tokens
                if hasattr(self._agent, "conversation_history"):
                    tokens = sum(count_tokens(str(m.get("content", ""))) for m in self._agent.conversation_history)
        except: pass
        em = [m.strip() for m in os.environ.get("ACTIVE_MODELS", "").split(",") if m.strip()]
        if em: models = em[:3]; team = len(models)

        # Update target values for smooth counter animation
        self._target_tools = self.tools_run
        self._target_findings = self.findings
        self._target_tokens = tokens

        try:
            self._sidebar().refresh_data(
                status="thinking" if self._processing else "ready",
                mode=self.mode, model=model, models=models,
                session=self.session_name, turns=self.turn_count,
                tokens=self._displayed_tokens, limit=128000,
                target=self.target, thinking=self.thinking,
                team=team, tools_run=self._displayed_tools,
                findings=self._displayed_findings,
                talk_to=self._talk_to,
                game_active=self._game_active,
                game_frame=getattr(self, "_current_game_frame", ""),
            )
        except: pass

    @work(thread=True)
    def _send_to_agent(self, text: str, callback=None) -> None:
        if self._processing: return
        self._processing = True
        self.call_from_thread(self._update_sidebar)
        self.call_from_thread(lambda: self.query_one("#thinking_bar", ThinkingWidget).show())
        try:
            if self._agent is None: raise RuntimeError("Agent not ready.")
            if hasattr(self._agent, "_execute_tool"):
                orig = self._agent._execute_tool
                def wrap(ad, cb=None):
                    # CHILL mode blocks all tool/shell execution
                    if self.mode == "CHILL" and ad.get("action") in ("run_shell", "run_tool", "shell"):
                        self.call_from_thread(self._chat_write_system, "[dim]tool execution blocked in CHILL mode — Ctrl+M to switch to HUNT[/dim]")
                        return "__FINISH__"
                    
                    if ad.get("action") == "submit_findings":
                        findings_data = ad.get("findings", [])
                        if not isinstance(findings_data, list):
                            findings_data = [findings_data]
                        num_findings = len(findings_data)
                        if num_findings > 0:
                            self.findings += num_findings
                            self.call_from_thread(self._update_sidebar)
                            self.call_from_thread(self._trigger_border_glow)

                    cmd = ad.get("command", "")[:120]
                    risk = "SAFE"
                    try: risk = self._agent.governance.classify_risk(ad)
                    except: pass
                    self.call_from_thread(self._chat_write_governance, cmd, risk)
                    
                    if risk == "DESTRUCTIVE":
                        self.call_from_thread(
                            self._chat_write_system,
                            f"\n[bold #ff2222]🛡️ [GOVERNANCE] Action blocked: '{cmd}' violates safety/integrity rules.[/bold #ff2222]\n"
                        )
                    
                    if self.mode == "HUNT" and risk == "SAFE":
                        self.tools_run += 1
                        self.call_from_thread(self._update_sidebar)
                        self.call_from_thread(self._trigger_border_glow)
                        
                    # Wrapped callback to output tool progress directly to TUI chat as system updates
                    def tui_cb(msg):
                        if msg:
                            self.call_from_thread(self._chat_write_system, f"[dim]Progress: {msg}[/dim]")
                        if cb:
                            cb(msg)
                            
                    return orig(ad, tui_cb)
                self._agent._execute_tool = wrap
            if hasattr(self._agent, "process_universal"):
                agent_mode = "auto" if self.mode == "CHILL" else "bug_bounty"
                resp = self._agent.process_universal(text, target=self.target or "", mode=agent_mode)
            else:
                resp = self._agent.process_query(user_input=text, target=self.target or "")
            if resp: self.call_from_thread(self._chat_write_agent, str(resp))
            else: self.call_from_thread(self._chat_write_error, "No response.")
        except Exception as exc:
            logger.error(f"Agent: {exc}")
            self.call_from_thread(self._chat_write_error, str(exc))
        finally:
            self._processing = False
            self.call_from_thread(lambda: self.query_one("#thinking_bar", ThinkingWidget).hide())
            self.call_from_thread(self._update_sidebar)

    def on_key(self, event) -> None:
        ho = self.query_one("#help_overlay", HelpOverlayWidget)
        if ho.has_class("visible"):
            event.stop(); ho.on_key(event); return
        ov = self.query_one("#settings_overlay", SettingsOverlayWidget)
        if ov.has_class("visible"):
            if ov.query_one("#custom_url_row").has_class("visible"): return
            event.stop(); ov.on_key(event); return
        key = event.key
        if key not in ("tab", "shift+tab"):
            self._cycling_suggestions = False

        if key == "tab" or key == "shift+tab":
            inp = self.query_one("#user_input", Input)
            if inp.has_focus:
                text = inp.value
                if text.startswith("/"):
                    if not self._cycling_suggestions:
                        self._original_prefix = text
                        self._suggest_idx = -1
                        self._cycling_suggestions = True
                    
                    parts = self._original_prefix.split()
                    if len(parts) == 1:
                        prefix = parts[0].lower()
                        matches = [c for c in self.SLASH_COMMANDS if c.startswith(prefix)]
                    else:
                        matches = []
                    
                    if matches:
                        event.stop()
                        if key == "tab":
                            self._suggest_idx = (self._suggest_idx + 1) % len(matches)
                        else:
                            self._suggest_idx = (self._suggest_idx - 1) % len(matches)
                        
                        inp.value = matches[self._suggest_idx]
                        inp.cursor_position = len(inp.value)
                        self._update_suggestion_box(matches)
                        return
        if key == "ctrl+s": event.stop(); self.action_show_settings(); return
        if key == "ctrl+t": event.stop(); self.action_toggle_think(); return
        if key == "ctrl+r": event.stop(); self.action_toggle_research(); return
        if self._game_active:
            if key == "space":
                if self.game.game_over:
                    self.game.start()
                else:
                    self.game.jump()
                event.stop(); return
            if key == "q" or key == "escape":
                self._stop_game()
                event.stop(); return
        if key == "ctrl+m": event.stop(); self.action_toggle_mode(); return
        if key == "ctrl+p": event.stop(); self.action_show_model(); return
        if key == "ctrl+g": event.stop(); self.action_show_help(); return
        if key == "ctrl+c": event.stop(); self.action_app_exit(); return

    def on_resize(self, event) -> None:
        """Handle window resizing - auto-hide sidebar on compact layouts (< 95 width)."""
        try:
            sidebar = self.query_one("#sidebar")
            if event.size.width < 95:
                sidebar.display = False
            else:
                sidebar.display = True
        except Exception:
            pass

    def _start_game(self) -> None:
        self._game_active = True
        self._current_game_frame = ""
        self.game.start()
        self.query_one("#user_input", Input).disabled = True
        self._update_sidebar(force=True)
        self._chat_write_system("[dim]🎮 game — SPACE jump, Q quit[/dim]")

    def _stop_game(self) -> None:
        self._game_active = False
        self.game.running = False
        self.query_one("#user_input", Input).disabled = False
        self.set_focus(self.query_one("#user_input", Input))
        self._update_sidebar(force=True)

    def _game_display(self, frame: str) -> None:
        self._current_game_frame = frame
        self._update_sidebar(force=True)

    # ── Input ────────────────────────────────────────────────────────────
    SLASH_COMMANDS = [
        "/clear", "/reset", "/quit", "/exit",
        "/mode chill", "/mode hunt",
        "/target <domain>", "/talk 1", "/talk 2", "/talk 3", "/talk all",
        "/session", "/session new", "/session list", "/session load <id>",
        "/stats", "/team", "/game", "/help",
    ]

    def _update_suggestion_box(self, matches: list[str]) -> None:
        box = self.query_one("#suggest_box", Static)
        lines = []
        for idx, m in enumerate(matches[:12]):
            if idx == self._suggest_idx:
                lines.append(f"[bold reverse]{m}[/]")
            else:
                lines.append(f"[dim]{m}[/]")
        box.update("\n".join(lines))

    def on_input_changed(self, event: Input.Changed) -> None:
        text = event.value
        if not self._cycling_suggestions:
            self._original_prefix = text
            self._suggest_idx = -1
        
        box = self.query_one("#suggest_box", Static)
        if not text or not text.startswith("/"):
            box.styles.display = "none"
            self._cycling_suggestions = False
            return
            
        parts = self._original_prefix.split()
        if len(parts) == 1:
            prefix = parts[0].lower()
            matches = [c for c in self.SLASH_COMMANDS if c.startswith(prefix)]
        else:
            matches = []
            
        if matches:
            self._update_suggestion_box(matches)
            box.styles.display = "block"
        else:
            box.styles.display = "none"
            self._cycling_suggestions = False

    def on_input_submitted(self, event: Input.Submitted) -> None:
        text = event.value.strip()
        if not text: return
        event.input.value = ""
        self._cycling_suggestions = False
        if not self.history or self.history[-1] != text: self.history.append(text)
        self.history_idx = -1
        if self._handle_slash(text): return
        self._ensure_session()
        self._chat_write_user(text)
        # Hide banner on first message
        try:
            self.query_one("#banner", Static).display = False
        except: pass
        self.turn_count += 1
        self._update_sidebar()
        self._send_to_agent(text)

    def _handle_slash(self, text: str) -> bool:
        low = text.lower().strip()
        if low in ("/quit", "/exit", "quit", "exit"):
            self._save_session(); self.set_timer(0.3, self.exit); return True
        if low == "/clear": self._chat().clear(); return True
        if low == "/reset":
            self._chat().clear()
            try:
                self.query_one("#banner", Static).display = True
                self._update_banner()
            except: pass
            if self._agent and hasattr(self._agent, "clear_conversation_history"):
                self._agent.clear_conversation_history()
            self.turn_count = 0; self.tools_run = 0; self.findings = 0
            self._update_sidebar(); return True
        if low in ("/help", "?"): self.action_show_help(); return True
        if low == "/mode":
            self._chat_write_system("Modes: chill (chat only)  hunt (chat + scan)"); return True
        if low.startswith("/mode "):
            v = text.split(" ", 1)[1].strip().upper()
            if v in ("CHILL", "HUNT"):
                self.mode = v; self._update_sidebar(); self._chat_write_system(f"Mode: {v}")
            return True
        if low.startswith("/target"):
            p = text.split(" ", 1)
            self.target = p[1].strip() if len(p) > 1 else ""
            self._update_sidebar()
            self._chat_write_system(f"Target: {self.target or '(cleared)'}"); return True
        if low == "/stats":
            try:
                from tools.vector_memory import get_vector_memory
                vs = get_vector_memory().get_memory_stats()
                self._chat_write_system(f"Memory: {vs.get('total_memories',0)} entries, {vs.get('unique_targets',0)} targets")
            except Exception as e: self._chat_write_system(f"Stats: {e}")
            return True
        if low == "/team":
            active = [m.strip() for m in os.environ.get("ACTIVE_MODELS","").split(",") if m.strip()]
            if not active: self._chat_write_system("No team configured.")
            else:
                rs = ["Strategist","Recon Lead","Exploit Analyst"]
                lines = ["[bold]Team Aegis:[/bold]"]
                for i, m in enumerate(active[:3]): lines.append(f"  [{rs[i]} {m}]")
                self._chat().write(Text.from_markup("\n".join(lines)))
            return True
        if low.startswith("/talk"):
            parts = text.split()
            if len(parts) > 1:
                v = parts[1].strip()
                if v in ("1","2","3"): self._talk_to = int(v)
                elif v in ("all","*"): self._talk_to = "all"
                else: self._chat_write_system("Usage: /talk <1|2|3|all>")
            self._chat_write_system(f"Talk to: {self._talk_to if self._talk_to == 'all' else AGENT_NAMES[self._talk_to]}")
            self._update_sidebar(); return True
        if low.startswith("/session"):
            parts = text.split(maxsplit=2); sub = parts[1].strip() if len(parts) > 1 else ""
            if sub == "new":
                self._save_session()
                from tools.session_manager import generate_session_id
                self.session_name = generate_session_id()
                if self._session_mgr: self._session_mgr.start_session(name=self.session_name, target=self.target, mode=self.mode)
                if self._agent and hasattr(self._agent,"clear_conversation_history"): self._agent.clear_conversation_history()
                self.turn_count = 0; self.tools_run = 0; self.findings = 0; self._chat().clear()
                self._chat_write_system(f"New session: {self.session_name}")
                self._update_sidebar(); return True
            if sub == "list" and self._session_mgr:
                ss = self._session_mgr.list_sessions()
                if not ss: self._chat_write_system("No saved sessions.")
                else:
                    lines = ["[bold]Sessions:[/bold]"]
                    for s in ss[-10:]:
                        sid = s.name
                        marker = " >" if sid == self.session_name else "  "
                        lines.append(f"  {marker} [dim]{sid}[/]  turns={s.turn_count}  [dim]{s.target or '-'}[/]")
                    self._chat().write(Text.from_markup("\n".join(lines)))
                return True
            if sub == "load" and len(parts) > 2 and self._session_mgr:
                sid = parts[2].strip()
                info = self._session_mgr.resume_session(sid, agent=self._agent)
                if info:
                    self.session_name = sid; self.target = info.get("target", self.target)
                    self.mode = info.get("mode", self.mode); self.turn_count = info.get("turns", 0)
                    self._chat().clear()
                    self._chat_write_system(f"Loaded session: {sid}")
                    self._replay_history(); self._update_sidebar()
                else: self._chat_write_system(f"Session not found: {sid}")
                return True
            self._chat_write_system(f"Session: {self.session_name}  Turns: {self.turn_count}"); return True
        if low == "/game":
            if not self._game_active:
                self._start_game()
            else:
                self._stop_game()
            return True
        if low.startswith("/"): self._chat_write_system(f"Unknown: {low}  (/help)"); return True
        return False

    def _save_session(self) -> str:
        sid = self.session_name
        try:
            if self._session_mgr and sid:
                self._session_mgr.save_session(name=sid, agent=self._agent, target=self.target, mode=self.mode)
        except: pass
        return sid

    def _replay_history(self) -> None:
        if not self._agent or not hasattr(self._agent, "conversation_history"): return
        for msg in self._agent.conversation_history:
            role = msg.get("role", ""); content = msg.get("content", "")
            if not content: continue
            if role == "user": self._chat_write_user(content[:500])
            elif role == "assistant": self._chat_write_agent(content[:500])

    def _load_session_by_id(self, sid: str) -> None:
        if not sid or not self._session_mgr: return
        self._save_session()
        from tools.session_manager import SessionManager
        info = SessionManager().resume_session(sid, agent=self._agent)
        if info:
            self.session_name = sid; self.target = info.get("target", self.target)
            self.mode = info.get("mode", self.mode); self.turn_count = info.get("turns", 0)
            self._chat().clear()
            self._chat_write_system(f"Session loaded: {sid}  ({self.turn_count} turns)")
            self._replay_history(); self._update_sidebar()
        else: self._chat_write_system(f"Session not found: {sid}")

    def action_app_exit(self) -> None:
        sid = self._save_session()
        logger.info(f"Session {sid} saved on exit")
        from rich.console import Console
        Console().print(f"\n  thank you for using elengenix\n  session: {sid}\n", style="dim")
        self.exit()

    def action_toggle_research(self) -> None:
        self.mode = "research" if self.mode != "research" else "auto"
        self._update_sidebar()
        self._chat_write_system(f"[dim]Research: {'ON' if self.mode == 'research' else 'OFF'}[/]")

    def action_toggle_mode(self) -> None:
        if self._trans:
            return
        new_mode = "HUNT" if self.mode != "HUNT" else "CHILL"
        self._trans_next = new_mode
        self._trans = True
        self._trans_frame = 0

    def action_toggle_think(self) -> None:
        self.thinking = not self.thinking
        os.environ["NVIDIA_PARAM_MODE"] = "enable" if self.thinking else "disable"
        self._update_sidebar()
        self._chat_write_system(f"[dim]Thinking: {'ON' if self.thinking else 'OFF'}[/]")

    def action_show_model(self) -> None:
        models = os.environ.get("ACTIVE_MODELS", "default")
        self._chat_write_system(f"[dim]Active model(s): {models}[/]")

    def action_show_help(self) -> None:
        self.query_one("#help_overlay", HelpOverlayWidget).show()

    def action_show_settings(self) -> None:
        self.query_one("#settings_overlay", SettingsOverlayWidget).show()

    def action_scroll_up(self) -> None:
        try: self._chat().scroll_up(10)
        except: pass

    def action_scroll_down(self) -> None:
        try: self._chat().scroll_down(10)
        except: pass

    def action_history_up(self) -> None:
        inp = self.query_one("#user_input", Input)
        if inp.has_focus and self.history:
            if self.history_idx == -1: self.history_idx = len(self.history) - 1
            elif self.history_idx > 0: self.history_idx -= 1
            inp.value = self.history[self.history_idx]
            inp.cursor_position = len(inp.value)

    def action_history_down(self) -> None:
        inp = self.query_one("#user_input", Input)
        if inp.has_focus and self.history:
            if self.history_idx == -1: return
            self.history_idx += 1
            if self.history_idx >= len(self.history):
                self.history_idx = -1; inp.value = ""
            else:
                inp.value = self.history[self.history_idx]
                inp.cursor_position = len(inp.value)


def main(target: str = "", mode: str = "auto", session_id: str = "") -> None:
    app = ElengenixTextualApp(target=target, mode=mode, session_id=session_id)
    app.run()

if __name__ == "__main__":
    sid = ""
    if "-s" in sys.argv:
        idx = sys.argv.index("-s")
        if idx + 1 < len(sys.argv): sid = sys.argv[idx + 1]
    main(session_id=sid)
