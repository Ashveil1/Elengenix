"""
cli_textual.py — Elengenix AI Partner Mode (Textual TUI v5.0)
- RichLog widget with native mouse scroll + Rich markup
- Full sidebar: session, model, target, context usage, agent status
- Governance-aware: shows when AI is installing/running privileged commands
- Real-time scan progress bar
- Background thread agent calls (non-blocking UI)
- Slash commands (/help /clear /reset /mode /target /quit /stats /team)
- Input history with Up/Down + Ctrl+R/B/T/P/G/E shortcuts
- Token counter using tiktoken (optional, fallback built-in)
"""

from __future__ import annotations

import os
import sys
import time
import logging
import threading
import warnings
from pathlib import Path
from typing import Optional

warnings.filterwarnings("ignore", category=FutureWarning)

from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal, Vertical
from textual.widgets import Static, RichLog, Input, Button, Label
from textual.widget import Widget
from textual import work
from textual.binding import Binding

from rich.text import Text
from rich.panel import Panel
from rich.markdown import Markdown
from rich.table import Table
from rich.progress import Progress, BarColumn, TextColumn
from rich.layout import Layout

from agent import get_agent

LOG_FILE = Path("data/elengenix_cli.log")
LOG_FILE.parent.mkdir(exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler()],
)
logger = logging.getLogger("elengenix.cli_textual")

# ── Theme ──────────────────────────────────────────────────────────────────
C_RED    = "#ff4444"
C_DARK   = "#000000"
C_GRAY   = "#525252"
C_LGRAY  = "#a3a3a3"
C_WHITE  = "#ffffff"
C_MUTED  = "#737373"

ASCII_BANNER = """\
    [#ff6666] ███████╗██╗     ███████╗███╗   ██╗ ██████╗ ███████╗███╗   ██╗[/]
    [#ff4d4d] ██╔════╝██║     ██╔════╝████╗  ██║██╔════╝ ██╔════╝████╗  ██║[/]
    [#ff3333] █████╗  ██║     █████╗  ██╔██╗ ██║██║  ███╗█████╗  ██╔██╗ ██║[/]
    [#e61919] ██╔══╝  ██║     ██╔══╝  ██║╚██╗██║██║   ██║██╔══╝  ██║╚██╗██║[/]
    [#cc0000] ███████╗███████╗███████╗██║ ╚████║╚██████╔╝███████╗██║ ╚████║[/]
    [#b30000] ╚══════╝╚══════╝╚══════╝╚═╝  ╚═══╝ ╚═════╝ ╚══════╝╚═╝  ╚═══╝[/]"""

HELP_TEXT = """\
[bold #cc4444]Commands:[/bold #cc4444]
  /clear       Clear chat display
  /reset       Clear chat + reset history
  /quit        Exit
  /mode        Show mode options
  /mode <x>    Set mode: auto research security_chat scan casual
  /target <x>  Set target domain
    /stats       Memory stats
    /team        Show active team
    /talk <n>    Talk to specific agent: 1,2,3, or "all"
    /session     Show current session info
    /session new Start a new session (saves current automatically)
    /session list List saved sessions
    /session load <name> Load a saved session

[bold #cc4444]Shortcuts:[/bold #cc4444]
  Ctrl+R  Research ON/off
  Ctrl+B  Scan mode ON/off
  Ctrl+T  Toggle thinking
  Ctrl+P  Show active model
  Ctrl+G  This help
  Ctrl+E  Settings overlay
  Ctrl+U  Scroll up     Ctrl+D  Scroll down
  Up/Down Input history
  /       Slash commands"""

AGENT_NAMES = {1: "Elengix 1", 2: "Elengix 2", 3: "Elengix 3"}
AGENT_COLORS = {1: C_WHITE, 2: C_GRAY, 3: C_LGRAY}


# ── Sidebar ────────────────────────────────────────────────────────────────
class Sidebar(Container):
    """Right-hand sidebar with session info, target, and agent status."""

    DEFAULT_CSS = """
    Sidebar {
        width: 38;
        height: 1fr;
        background: #0d0d0d;
        border: solid #cc4444;
        margin: 1 1 1 0;
        padding: 0 1;
        overflow-y: auto;
    }
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
        model    = d.get("model", "default")
        models   = d.get("models", [])
        session  = d.get("session", "new-session")
        turns    = d.get("turns", 0)
        tokens   = d.get("tokens", 0)
        limit    = d.get("limit", 128000)
        thinking = d.get("thinking", False)
        target   = d.get("target", "")
        team     = d.get("team", 0)
        findings = d.get("findings", 0)
        tools_run = d.get("tools_run", 0)
        talk_to  = d.get("talk_to", "all")

        is_ready = (status == "ready")
        dot = f"[{C_WHITE}]\u25cf[/{C_WHITE}]" if is_ready else f"[{C_RED}]\u25cf[/{C_RED}]"
        slabel = "[bold white]READY[/bold white]" if is_ready else "[bold red]WORKING[/bold red]"
        think_tag = f"  [{C_RED}]THINK[/{C_RED}]" if thinking else ""
        team_tag = f"  [{C_RED}]TEAM {team}[/{C_RED}]" if team > 1 else ""
        talk_tag = ""
        if talk_to != "all" and team > 0:
            name = AGENT_NAMES.get(talk_to, f"#{talk_to}")
            talk_tag = f"\n  [{C_WHITE}]>> {name}[/{C_WHITE}]"

        # Build model list display
        model_lines = []
        if models:
            for i, m in enumerate(models):
                idx = i + 1
                name = AGENT_NAMES.get(idx, f"#{idx}")
                marker = "[bold white]\u25b6[/bold white]" if talk_to == idx else " "
                short = m.split("/")[-1] if "/" in m else m
                model_lines.append(f"  {marker} {name}: [{C_MUTED}]{short[:22]}[/{C_MUTED}]")
        else:
            model_lines.append(f"  {model[:28]}")

        pct = min(100, int((tokens / limit) * 100)) if limit > 0 else 0
        bar_w = 28
        filled = int((pct / 100) * bar_w)
        bar = (
            f"[{C_RED}]{'.' * filled}[/{C_RED}]"
            f"[{C_MUTED}]{'.' * (bar_w - filled)}[/{C_MUTED}]"
        )
        mc = C_RED if mode in ("research", "scan") else C_WHITE
        div = f"[{C_MUTED}]{chr(0x2500) * 28}[/{C_MUTED}]"

        target_line = ""
        if target:
            target_line = f"\n  [{C_RED}]{target[:32]}[/{C_RED}]"

        lines = "\n".join([
            f"[bold {C_RED}]ELENGENIX[/bold {C_RED}]",
            f"[{C_LGRAY}]Universal AI Agent[/{C_LGRAY}]",
            div,
            f"{dot}  {slabel}{think_tag}{team_tag}{talk_tag}",
            div,
            f"[bold {C_WHITE}]TARGET[/bold {C_WHITE}]{target_line}",
            div,
            f"[bold {C_WHITE}]SESSION[/bold {C_WHITE}]",
            f"  {session[:22]}",
            f"  Mode: [bold {mc}]{mode.upper()}[/bold {mc}]"
            f"  [{C_MUTED}]Turns: {turns}[/{C_MUTED}]",
            div,
            f"[bold {C_WHITE}]SCAN STATS[/bold {C_WHITE}]" if target else f"[{C_MUTED}]SCAN STATS[/{C_MUTED}]",
            f"  [{C_WHITE}]Tools run: {tools_run}[/{C_WHITE}]  [{C_WHITE}]Findings: {findings}[/{C_WHITE}]",
            div,
            f"[bold {C_WHITE}]ACTIVE MODELS[/bold {C_WHITE}]",
            "\n".join(model_lines),
            div,
            f"[bold {C_WHITE}]CONTEXT[/bold {C_WHITE}]",
            f"  {tokens} / {limit}",
            f"  {bar}",
            f"  [{C_MUTED}]{pct}% of window[/{C_MUTED}]",
            div,
            f"[bold {C_WHITE}][/bold {C_WHITE}]",
            f"  [{C_MUTED}]Ctrl+G Help   Ctrl+E Settings[/{C_MUTED}]",
            f"  [{C_MUTED}]Ctrl+R Research Ctrl+B Scan[/{C_MUTED}]",
            div,
            f"[{C_MUTED}]v5.0.0  Elengenix AI[/{C_MUTED}]",
        ])

        try:
            self.query_one("#sidebar_content", Static).update(lines)
        except Exception:
            pass


# ── Thinking Indicator ─────────────────────────────────────────────────────
class ThinkingWidget(Static):
    """Animated hacker-style thinking indicator."""

    DEFAULT_CSS = """
    ThinkingWidget {
        height: 1;
        content-align: left middle;
        padding: 0 1;
        color: #ff4444;
        display: none;
    }
    ThinkingWidget.visible {
        display: block;
    }
    """

    def on_mount(self) -> None:
        self.frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
        self.idx = 0
        self.anim_timer = self.set_interval(0.15, self.tick, pause=True)

    def tick(self) -> None:
        self.idx = (self.idx + 1) % len(self.frames)
        f = self.frames[self.idx]
        self.update(f"[bold #ff4444]{f} AGENT THINKING...[/bold #ff4444]")

    def show(self) -> None:
        self.add_class("visible")
        self.anim_timer.resume()

    def hide(self) -> None:
        self.remove_class("visible")
        self.anim_timer.pause()


# ── Governance Status Bar ─────────────────────────────────────────────────
class GovernanceBar(Static):
    """Shows the last AI action with governance classification."""

    DEFAULT_CSS = """
    GovernanceBar {
        height: 1;
        padding: 0 1;
        background: #0d0d0d;
        border-top: solid #333333;
        content-align: left middle;
    }
    """

    def show_action(self, label: str, risk: str = "SAFE") -> None:
        risk_colors = {"SAFE": C_WHITE, "PRIVILEGED": C_GRAY, "DESTRUCTIVE": C_RED}
        color = risk_colors.get(risk, C_WHITE)
        self.update(f"[{color}]{risk}[/{color}]  {label[:80]}")


class ProgressBar(Static):
    """Scan progress bar — shows tool execution live."""

    DEFAULT_CSS = """
    ProgressBar {
        height: 1;
        padding: 0 1;
        background: #0d0d0d;
        display: none;
        content-align: left middle;
    }
    ProgressBar.visible {
        display: block;
    }
    """

    def show_scan(self, tool: str, current: int, total: int, findings: int) -> None:
        w = 30
        pct = int((current / max(total, 1)) * w)
        bar = f"[{C_RED}]{'#' * pct}[/{C_RED}][{C_MUTED}]{'-' * (w - pct)}[/{C_MUTED}]"
        self.update(f"  Scan: {bar}  [{C_WHITE}]{tool}[/{C_WHITE}]  ({current}/{total})  [{C_WHITE}]{findings} findings[/{C_WHITE}]")

    def show(self) -> None:
        self.add_class("visible")

    def hide(self) -> None:
        self.remove_class("visible")


# ── Settings Overlay ─────────────────────────────────────────────────────
class SettingsOverlayWidget(Widget, can_focus=True):
    """Floating settings modal — dims the background, centres a panel."""

    DEFAULT_CSS = """
    SettingsOverlayWidget {
        layer: overlay;
        align: center middle;
        width: 100%;
        height: 100%;
        display: none;
        background: transparent;
    }
    SettingsOverlayWidget.visible {
        display: block;
    }
    #settings_panel {
        width: 74;
        height: auto;
        max-height: 80%;
        min-height: 22;
        background: #0d0d0d;
        border: wide #cc4444;
        padding: 1 2;
        overflow-y: auto;
    }
    #settings_title {
        width: 1fr;
        height: 1;
        content-align: center middle;
        background: #cc4444;
        color: #000000;
        text-style: bold;
        margin: 0 0 1 0;
    }
    #settings_content {
        width: 1fr;
        height: auto;
        background: transparent;
    }
    #settings_footer {
        width: 1fr;
        height: 1;
        content-align: center middle;
        color: #737373;
        margin: 1 0 0 0;
    }
    """

    def compose(self) -> ComposeResult:
        with Vertical(id="settings_panel"):
            yield Static("  ELENGENIX  SETTINGS  ", id="settings_title")
            yield Static("", id="settings_content", markup=True)
            yield Static("  \u2191\u2193 Navigate  \u23ce Select  Esc Close  S Save", id="settings_footer")

    def on_mount(self) -> None:
        self._overlay = None
        self._reload()

    def _reload(self) -> None:
        try:
            from tools.overlay_menu import SettingsOverlay
            agent = getattr(self.app, "_agent", None)
            target = getattr(self.app, "target", "")
            self._overlay = SettingsOverlay(agent, None, target=target)
        except Exception as exc:
            self._overlay = None
            logger.error(f"SettingsOverlay: {exc}")

    def _redraw(self) -> None:
        w = self.query_one("#settings_content", Static)
        if self._overlay:
            w.update(self._overlay.render())
        else:
            w.update(Panel(
                f"[{C_RED}]Settings unavailable.[/{C_RED}]\n\nPress [{C_WHITE}]Esc[/{C_WHITE}] to close.",
                border_style=C_MUTED,
            ))

    def show(self) -> None:
        self._reload()
        self._redraw()
        self.add_class("visible")
        self.focus()

    def hide(self) -> None:
        self.remove_class("visible")
        try:
            self.app.query_one("#user_input", Input).focus()
        except Exception:
            pass

    def on_key(self, event) -> None:
        if not self.has_class("visible"):
            return
        key = event.key
        char_map = {
            "escape": "\x1b", "enter": "\r",
            "up": "\x1b[A", "down": "\x1b[B",
            "left": "\x1b[D", "right": "\x1b[C",
        }
        char = char_map.get(key, event.character or "")
        if not char:
            return
        event.stop()
        result = self._overlay.handle_char(char) if self._overlay else "exit"
        if result == "exit":
            self.hide()
        elif result == "saved":
            self.app._chat_write_system("[OK] Settings saved. Agent reloaded.")
            if hasattr(self.app, "_agent") and self.app._agent:
                try:
                    from tools.governance import Governance
                    self.app._agent.governance = Governance()
                except Exception:
                    pass
            self.hide()
        elif result == "saved":
            self.app._chat_write_system("[OK] Settings saved. Agent reloaded.")
            # Re-init governance after settings change
            if hasattr(self.app, "_agent") and self.app._agent:
                try:
                    from tools.governance import Governance
                    self.app._agent.governance = Governance()
                except Exception:
                    pass
            self.hide()
        elif result == "error":
            self.app._chat_write_system("[FAIL] Settings save failed.")
            self.hide()
        else:
            self._redraw()


# ── Main App ───────────────────────────────────────────────────────────────
class ElengenixTextualApp(App):
    """Elengenix TUI v5.0 — full-featured chat with mouse-scrollable RichLog."""

    CSS = """
    Screen {
        background: #000000;
        layers: base overlay;
    }
    #main_row   { height: 1fr; layer: base; }
    #chat_col   { width: 1fr; height: 1fr; background: #000000; }
    #chat_area  {
        height: 1fr;
        background: #000000;
        border: none;
        padding: 0 1;
    }
    #tool_row  {
        height: auto;
        margin: 0 2 0 2;
        background: transparent;
    }
    #input_row  {
        height: auto;
        margin: 0 2 1 2;
        background: #0d0d0d;
        border: solid #333333;
        padding: 0;
    }
    #user_input {
        height: 3;
        border: none;
        border-left: thick #ff4444;
        background: #0d0d0d;
        color: #ffffff;
        padding: 0 1;
    }
    #user_input:focus { border-left: thick #ff6b6b; }
    """

    BINDINGS = [
        Binding("ctrl+r", "toggle_research", "Research", priority=True),
        Binding("ctrl+b", "toggle_scan", "Scan", priority=True),
        Binding("ctrl+t", "toggle_think", "Think", priority=True),
        Binding("ctrl+p", "show_model", "Model", priority=True),
        Binding("ctrl+g", "show_help", "Help", priority=True),
        Binding("ctrl+e", "show_settings", "Settings", priority=True),
        Binding("ctrl+c", "app_exit", "Exit", priority=True),
        Binding("ctrl+u", "scroll_up", "Scroll Up", show=False, priority=True),
        Binding("ctrl+d", "scroll_down", "Scroll Down", show=False, priority=True),
        Binding("up", "history_up", "History Up", show=False),
        Binding("down", "history_down", "History Down", show=False),
    ]

    def __init__(self, target: str = "", mode: str = "auto", **kwargs):
        super().__init__(**kwargs)
        self.target       = target
        self.mode         = mode
        self.thinking     = False
        self.session_name = f"session-{time.strftime('%Y%m%d-%H%M%S')}"
        self.turn_count   = 0
        self.tools_run    = 0
        self.findings     = 0
        self.history: list[str] = []
        self.history_idx  = -1
        self._processing  = False
        self._agent       = None
        self._talk_to     = "all"  # "all", 1, 2, 3
        self._team_active = False
        self._session_mgr = None
        self._session_name = ""
        self._cached_chat: RichLog | None = None
        self._cached_sidebar: Sidebar | None = None
        self._last_sidebar_update: float = 0.0

    def compose(self) -> ComposeResult:
        with Horizontal(id="main_row"):
            with Vertical(id="chat_col"):
                yield RichLog(
                    id="chat_area", highlight=False, markup=True, wrap=True,
                    auto_scroll=True, max_lines=1000,
                )
                yield ThinkingWidget(id="thinking_bar")
                yield ProgressBar(id="progress_bar")
                yield GovernanceBar(id="gov_bar")
                with Vertical(id="input_row"):
                    yield Input(placeholder="Elengenix ) ", id="user_input")
            yield Sidebar(id="sidebar")
        yield SettingsOverlayWidget(id="settings_overlay")

    def on_mount(self) -> None:
        chat = self.query_one("#chat_area", RichLog)
        chat.write(Text("\n\n", style="#000000"))
        chat.write(Text.from_markup(ASCII_BANNER))
        chat.write(Text.from_markup(
            f"           [{C_WHITE}]Universal AI & Bug Bounty Agent[/{C_WHITE}]\n"
            f"           [{C_MUTED}]Type /help for commands | Target: {self.target or '(none)'}[/{C_MUTED}]\n\n"
        ))
        # Init session manager
        try:
            from tools.session_manager import SessionManager
            self._session_mgr = SessionManager()
            self._session_name = self._session_mgr.start_session(target=self.target, mode=self.mode)
            self._chat_write_system(f"Session: {self._session_name}")
        except Exception as e:
            logger.debug(f"Session init: {e}")
        self._update_sidebar()
        self.set_focus(self.query_one("#user_input", Input))
        self._load_agent()

    @work(thread=True)
    def _load_agent(self) -> None:
        try:
            self._agent = get_agent()
            # Ensure governance is loaded
            if self._agent:
                _ = self._agent.governance  # warm up
        except Exception as e:
            self.call_from_thread(self._chat_write_system, f"[{C_RED}][FAIL] Agent load error: {e}[/{C_RED}]")

    # ── UI Helpers ─────────────────────────────────────────────────────────
    def _chat(self) -> RichLog:
        if self._cached_chat is None:
            self._cached_chat = self.query_one("#chat_area", RichLog)
        return self._cached_chat

    def _sidebar(self) -> Sidebar:
        if self._cached_sidebar is None:
            self._cached_sidebar = self.query_one("#sidebar", Sidebar)
        return self._cached_sidebar

    def _gov_bar(self) -> GovernanceBar:
        return self.query_one("#gov_bar", GovernanceBar)

    def _chat_write_user(self, text: str) -> None:
        ts = time.strftime("%H:%M:%S")
        self._chat().write(Text.from_markup(
            f"\n[{C_RED}]╭─[/{C_RED}] [{C_RED}]USER[/{C_RED}] [dim]{ts}[/dim]"
            f"\n[{C_RED}]╰─[/{C_RED}] [{C_WHITE}]{text}[/{C_WHITE}]"
        ))

    def _chat_write_agent(self, text: str) -> None:
        ts = time.strftime("%H:%M:%S")
        self._chat().write(Text.from_markup(
            f"\n[{C_RED}]╭─[/{C_RED}] [{C_RED}]ELENGIX[/{C_RED}] [dim]{ts}[/dim]"
        ))
        try:
            self._chat().write(Markdown(text))
        except Exception:
            self._chat().write(Text(text, style=C_LGRAY))

    def _chat_write_elengix(self, agent_id: int, text: str, msg_type: str = "discussion") -> None:
        """แสดงข้อความจาก Elengix agent ตัวใดตัวหนึ่ง"""
        name = AGENT_NAMES.get(agent_id, f"Elengix {agent_id}")
        color = AGENT_COLORS.get(agent_id, C_RED)
        tag = {"discussion": "", "finding": "FOUND", "tool": "RUN"}.get(msg_type, "")
        prefix = f"[{color}]{name}[/{color}]"
        if tag:
            prefix += f" [{C_RED}]{tag}[/{C_RED}]" if tag else ""
        ts = time.strftime("%H:%M:%S")
        self._chat().write(Text.from_markup(
            f"\n[{color}]╭─[/{color}] {prefix} [dim]{ts}[/dim]"
            f"\n[{color}]╰─[/{color}] {text[:500]}"
        ))

    def _chat_write_system(self, markup: str) -> None:
        self._chat().write(Text.from_markup(f"[{C_MUTED}]{markup}[/{C_MUTED}]"))

    def _chat_write_governance(self, command: str, risk: str) -> None:
        risk_color = {"SAFE": C_WHITE, "PRIVILEGED": C_GRAY, "DESTRUCTIVE": C_RED}.get(risk, C_MUTED)
        risk_tag = {"SAFE": "[GREEN]", "PRIVILEGED": "[YELLOW]", "DESTRUCTIVE": "[RED]"}.get(risk, "")
        self._chat().write(Text.from_markup(
            f"  [{risk_color}]\u25b6 {risk}[/{risk_color}] [dim]{command[:120]}[/dim]"
        ))
        self._gov_bar().show_action(command, risk)

    def _chat_write_error(self, markup: str) -> None:
        self._chat().write(Text.from_markup(f"[bold {C_RED}][FAIL] {markup}[/bold {C_RED}]"))

    def _update_sidebar(self) -> None:
        now = time.monotonic()
        if now - self._last_sidebar_update < 0.3:
            return
        self._last_sidebar_update = now

        tokens = 0
        model = "default"
        team = 0
        models: list[str] = []
        try:
            if self._agent:
                from tools.token_counter import count_tokens
                if hasattr(self._agent, "conversation_history"):
                    tokens = sum(
                        count_tokens(str(m.get("content", "")))
                        for m in self._agent.conversation_history
                    )
                if hasattr(self._agent, "client") and hasattr(self._agent.client, "active_client"):
                    model = getattr(self._agent.client.active_client, "model", "default")
        except Exception:
            pass

        env_models = [m.strip() for m in os.environ.get("ACTIVE_MODELS", "").split(",") if m.strip()]
        if env_models:
            models = env_models[:3]
            team = len(models)
            model = f"Team ({team} agents)"

        try:
            self._sidebar().refresh_data(
                status="thinking" if self._processing else "ready",
                mode=self.mode, model=model, models=models,
                session=self.session_name, turns=self.turn_count,
                tokens=tokens, limit=128000,
                target=self.target, thinking=self.thinking,
                team=team, tools_run=self.tools_run, findings=self.findings,
                talk_to=self._talk_to,
            )
        except Exception:
            pass

    # ── Slash Commands ───────────────────────────────────────────────────
    SLASH_COMMANDS = [
        "/clear", "/reset", "/quit", "/mode auto", "/mode research",
        "/mode scan", "/mode security_chat", "/mode casual",
        "/target <domain>", "/stats", "/team", "/help",
    ]

    def on_input_changed(self, event: Input.Changed) -> None:
        """Show slash command suggestions."""
        text = event.value
        if text.startswith("/") and len(text) > 1:
            # Could show suggestions in the future
            pass

    def on_input_submitted(self, event: Input.Submitted) -> None:
        text = event.value.strip()
        if not text:
            return
        event.input.value = ""

        if not self.history or self.history[-1] != text:
            self.history.append(text)
        self.history_idx = -1

        # Handle governance callback from agent
        if self._handle_slash(text):
            return

        self._chat_write_user(text)
        self.turn_count += 1
        self._update_sidebar()

        # Wrap the agent callback to catch governance events
        def agent_callback(msg: str) -> None:
            self.call_from_thread(self._chat_write_system, msg)

        self._send_to_agent(text, agent_callback)

    def _handle_slash(self, text: str) -> bool:
        low = text.lower().strip()

        if low in ("/quit", "/exit", "quit", "exit"):
            self._chat_write_system("Goodbye.")
            self.set_timer(0.3, self.exit)
            return True

        if low == "/clear":
            self._chat().clear()
            self._chat_write_system("Chat cleared.")
            return True

        if low == "/reset":
            self._chat().clear()
            if self._agent and hasattr(self._agent, "clear_conversation_history"):
                self._agent.clear_conversation_history()
            self.turn_count = 0
            self.tools_run = 0
            self.findings = 0
            self._update_sidebar()
            self._chat_write_system("Chat and history reset.")
            return True

        if low in ("/help", "?"):
            self.action_show_help()
            return True

        if low == "/mode":
            self._chat_write_system(
                "Modes: auto  research  security_chat  scan  casual\n"
                "Usage: /mode <name>"
            )
            return True

        if low.startswith("/mode "):
            val = text.split(" ", 1)[1].strip()
            valid = ["auto", "research", "security_chat", "scan", "casual"]
            if val in valid:
                self.mode = val
                self._update_sidebar()
                self._chat_write_system(f"Mode: {val}")
            else:
                self._chat_write_error(f"Unknown mode: {val}")
            return True

        if low.startswith("/target"):
            parts = text.split(" ", 1)
            self.target = parts[1].strip() if len(parts) > 1 else ""
            self._update_sidebar()
            self._chat_write_system(f"Target: {self.target or '(cleared)'}")
            return True

        if low == "/stats":
            self._show_stats()
            return True

        if low == "/team":
            self._show_team()
            return True

        if low.startswith("/talk"):
            parts = text.split()
            if len(parts) > 1:
                val = parts[1].strip()
                if val in ("1", "2", "3"):
                    self._talk_to = int(val)
                    self._chat_write_system(f"Now talking to {AGENT_NAMES[int(val)]}")
                elif val in ("all", "*"):
                    self._talk_to = "all"
                    self._chat_write_system("Now talking to all agents")
                else:
                    self._chat_write_system("Usage: /talk <1|2|3|all>")
            else:
                self._chat_write_system(f"Currently talking to: {self._talk_to if self._talk_to == 'all' else AGENT_NAMES[self._talk_to]}")
            return True

        if low.startswith("/session"):
            parts = text.split(maxsplit=2)
            sub = parts[1].strip() if len(parts) > 1 else ""
            if sub == "new":
                self._save_current_session()
                if self._agent and hasattr(self._agent, "clear_conversation_history"):
                    self._agent.clear_conversation_history()
                self.turn_count = 0
                self.tools_run = 0
                self.findings = 0
                if self._session_mgr:
                    self._session_name = self._session_mgr.start_session(target=self.target, mode=self.mode)
                self._chat().clear()
                self._chat_write_system(f"New session started: {self._session_name}")
                self._update_sidebar()
                return True
            if sub == "list":
                if not self._session_mgr:
                    self._chat_write_system("Session manager not available.")
                    return True
                sessions = self._session_mgr.list_sessions()
                if not sessions:
                    self._chat_write_system("No saved sessions.")
                else:
                    lines = ["[bold]Saved sessions:[/bold]"]
                    for s in sessions[-10:]:
                        lines.append(f"  [{C_MUTED}]{s.name}[/{C_MUTED}]  turns={s.turn_count}  {s.created_at[:19]}")
                    self._chat().write(Text.from_markup("\n".join(lines)))
                return True
            if sub == "load" and len(parts) > 2:
                name = parts[2].strip()
                if self._session_mgr:
                    self._save_current_session()
                    loaded = self._session_mgr.save_session(name=name, agent=self._agent, target=self.target, mode=self.mode)
                    if loaded:
                        self._chat_write_system(f"Session saved: {name}")
                    self._session_name = name
                return True
            # Show current session
            self._chat_write_system(f"Current session: {self._session_name}  |  Turns: {self.turn_count}")
            return True

        if low.startswith("/"):
            self._chat_write_system(f"Unknown command: {low}  (type /help)")
            return True

        return False

    def _save_current_session(self) -> None:
        """Save current session state before switching or exiting."""
        try:
            if self._session_mgr and self._session_name:
                self._session_mgr.save_session(
                    name=self._session_name,
                    agent=self._agent,
                    target=self.target,
                    mode=self.mode,
                )
        except Exception as e:
            logger.debug(f"Session save: {e}")

    def _show_stats(self) -> None:
        try:
            from tools.vector_memory import get_vector_memory
            vm = get_vector_memory()
            vs = vm.get_memory_stats()
            self._chat_write_system(
                f"[bold]Memory:[/bold] entries={vs.get('total_memories', 0)} "
                f"targets={vs.get('unique_targets', 0)}"
            )
        except Exception as e:
            self._chat_write_system(f"Stats unavailable: {e}")

    def _show_team(self) -> None:
        active = [m.strip() for m in os.environ.get("ACTIVE_MODELS", "").split(",") if m.strip()]
        if not active:
            self._chat_write_system("No team configured. Set ACTIVE_MODELS in env.")
        else:
            roles = ["Strategist", "Recon Lead", "Exploit Analyst"]
            lines = ["[bold]Team Aegis:[/bold]"]
            for i, m in enumerate(active[:3]):
                role = roles[i] if i < len(roles) else f"Agent {i+1}"
                lines.append(f"  [{role}] {m}")
            self._chat().write(Text.from_markup("\n".join(lines)))

    # ── Agent Call ────────────────────────────────────────────────────────
    @work(thread=True)
    def _send_to_agent(self, text: str, callback=None) -> None:
        if self._processing:
            self.call_from_thread(self._chat_write_system, "Agent is busy — please wait.")
            return

        self._processing = True
        self.call_from_thread(self._update_sidebar)

        def show_thinking():
            try:
                self.query_one("#thinking_bar", ThinkingWidget).show()
            except Exception:
                pass
        self.call_from_thread(show_thinking)

        try:
            if self._agent is None:
                raise RuntimeError("Agent not loaded yet. Please wait.")

            # Hook into governance: capture commands before execution
            original_exec = None
            if hasattr(self._agent, "_execute_tool"):
                original_exec = self._agent._execute_tool

                def _wrapped_execute(action_data, cb=None):
                    cmd = action_data.get("command", "")[:120]
                    # Check governance classification
                    risk = "SAFE"
                    try:
                        gate = self._agent.governance.classify_risk(action_data)
                        risk = gate
                    except Exception:
                        pass
                    self.call_from_thread(
                        self._chat_write_governance, cmd, risk
                    )
                    # Show progress in scan mode
                    if self.mode == "scan" and risk == "SAFE":
                        self.tools_run += 1
                        self.call_from_thread(self._update_sidebar)
                    return original_exec(action_data, cb) if original_exec else ""

                self._agent._execute_tool = _wrapped_execute

            # Handle findings from analysis pipeline
            original_pipeline = None
            if hasattr(self._agent, "_analysis_pipeline_run"):
                original_pipeline = self._agent._analysis_pipeline_run

            if hasattr(self._agent, "process_universal"):
                response = self._agent.process_universal(
                    text, target=self.target or "", mode=self.mode,
                )
            else:
                response = self._agent.process_query(
                    user_input=text, target=self.target or "",
                )

            if response:
                self.call_from_thread(self._chat_write_agent, str(response))
            else:
                self.call_from_thread(self._chat_write_error, "No response.")
        except Exception as exc:
            logger.error(f"Agent error: {exc}")
            self.call_from_thread(self._chat_write_error, str(exc))
        finally:
            self._processing = False

            def cleanup():
                try:
                    self.query_one("#thinking_bar", ThinkingWidget).hide()
                    self.query_one("#progress_bar", ProgressBar).hide()
                except Exception:
                    pass
            self.call_from_thread(cleanup)
            self.call_from_thread(self._update_sidebar)

    # ── Actions ───────────────────────────────────────────────────────────
    def action_toggle_research(self) -> None:
        self.mode = "research" if self.mode != "research" else "auto"
        self._update_sidebar()
        self._chat_write_system(f"Research mode: {'ON' if self.mode == 'research' else 'OFF'}")

    def action_toggle_scan(self) -> None:
        self.mode = "scan" if self.mode != "scan" else "auto"
        self._update_sidebar()
        self._chat_write_system(f"Scan mode: {'ON' if self.mode == 'scan' else 'OFF'}")

    def action_toggle_think(self) -> None:
        self.thinking = not self.thinking
        if self.thinking:
            os.environ["NVIDIA_PARAM_MODE"] = "enable"
        else:
            os.environ["NVIDIA_PARAM_MODE"] = "disable"
        self._update_sidebar()
        self._chat_write_system(f"Thinking: {'ON' if self.thinking else 'OFF'}")

    def action_show_model(self) -> None:
        env = os.environ.get("ACTIVE_MODELS", "")
        self._chat_write_system(f"Active model: {env or 'default'}")

    def action_show_help(self) -> None:
        self._chat().write(Text.from_markup(HELP_TEXT))

    def action_show_settings(self) -> None:
        self.query_one("#settings_overlay", SettingsOverlayWidget).show()

    def action_app_exit(self) -> None:
        self._save_current_session()
        self.exit()

    def action_scroll_up(self) -> None:
        try:
            self._chat().scroll_up(10)
        except Exception:
            pass

    def action_scroll_down(self) -> None:
        try:
            self._chat().scroll_down(10)
        except Exception:
            pass

    def action_history_up(self) -> None:
        inp = self.query_one("#user_input", Input)
        if inp.has_focus and self.history:
            if self.history_idx == -1:
                self.history_idx = len(self.history) - 1
            elif self.history_idx > 0:
                self.history_idx -= 1
            inp.value = self.history[self.history_idx]
            inp.cursor_position = len(inp.value)

    def action_history_down(self) -> None:
        inp = self.query_one("#user_input", Input)
        if inp.has_focus and self.history:
            if self.history_idx == -1:
                return
            self.history_idx += 1
            if self.history_idx >= len(self.history):
                self.history_idx = -1
                inp.value = ""
            else:
                inp.value = self.history[self.history_idx]
                inp.cursor_position = len(inp.value)


# ── Entry Point ────────────────────────────────────────────────────────────
def main(target: str = "", mode: str = "auto") -> None:
    app = ElengenixTextualApp(target=target, mode=mode)
    app.run()


if __name__ == "__main__":
    main()
