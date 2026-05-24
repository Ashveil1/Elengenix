"""cli_textual.py — Elengenix AI Partner Mode (Textual TUI v99999)
Monochrome theme — Black & White minimalist hacker aesthetic.
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
from textual.widgets import Static, RichLog, Input
from textual.widget import Widget
from textual import work
from textual.binding import Binding

from rich.text import Text
from rich.panel import Panel
from rich.markdown import Markdown
from rich.table import Table

from agent import get_agent

LOG_FILE = Path("data/elengenix_cli.log")
LOG_FILE.parent.mkdir(exist_ok=True)
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s", handlers=[logging.StreamHandler()])
logger = logging.getLogger("elengenix.cli_textual")

# ── MONOCHROME THEME: Black & White ────────────────────────────────────
BASE    = "#000000"
MANTLE  = "#111111"
CRUST   = "#0d0d0d"
SURFACE = "#1a1a1a"
TEXT    = "#ffffff"
SUBTEXT = "#cccccc"
MUTED   = "#555555"
DIM     = "#444444"
WHITE   = "#ffffff"
GRAY    = "#888888"

COLOR_OK    = WHITE
COLOR_WARN  = WHITE
COLOR_ERR   = WHITE
COLOR_INFO  = WHITE
COLOR_ACCENT= WHITE
COLOR_DIM   = GRAY
COLOR_MUTED = MUTED
COLOR_BORDER = "#333333"

AGENT_NAMES  = {1: "Elengix 1", 2: "Elengix 2", 3: "Elengix 3"}
AGENT_COLORS = {1: WHITE, 2: GRAY, 3: MUTED}

ASCII_BANNER = """
    [white]███████╗██╗     ███████╗███╗   ██╗ ██████╗ ███████╗███╗   ██╗██╗██╗  ██╗
    ██╔════╝██║     ██╔════╝████╗  ██║██╔════╝ ██╔════╝████╗  ██║██║╚██╗██╔╝
    █████╗  ██║     █████╗  ██╔██╗ ██║██║  ███╗█████╗  ██╔██╗ ██║██║ ╚███╔╝
    ██╔══╝  ██║     ██╔══╝  ██║╚██╗██║██║   ██║██╔══╝  ██║╚██╗██║██║ ██╔██╗
    ███████╗███████╗███████╗██║ ╚████║╚██████╔╝███████╗██║ ╚████║██║██╔╝ ██╗
    ╚══════╝╚══════╝╚══════╝╚═╝  ╚═══╝ ╚═════╝ ╚══════╝╚═╝  ╚═══╝╚═╝╚═╝  ╚═╝
                              [dim]v99999[/]"""

HELP_TEXT = """\
[white]━━━ COMMANDS ━━━[/]
  [dim]/clear[/]       Clear chat
  [dim]/reset[/]       Reset session
  [dim]/quit[/]        Exit
  [dim]/mode <x>[/]    Mode: auto research scan casual
  [dim]/target <x>[/]  Set target domain
  [dim]/talk <n>[/]    Talk to agent 1,2,3 or all
  [dim]/session[/]     Session info
  [dim]/session new[/] New session
  [dim]/session list[/] List saved sessions
  [dim]/session load <id>[/] Load session
  [dim]/stats[/]       Memory stats
  [dim]/team[/]        Show team

[white]━━━ SHORTCUTS ━━━[/]
  [dim]Ctrl+R[/] Research  [dim]Ctrl+B[/] Scan
  [dim]Ctrl+T[/] Thinking  [dim]Ctrl+P[/] Model
  [dim]Ctrl+G[/] Help      [dim]Ctrl+S[/] Settings
  [dim]↑↓[/] History       [dim]/[/] Slash commands"""


# ── Sidebar ──────────────────────────────────────────────────────────────
class Sidebar(Container):
    """Right-hand panel — monochrome minimal."""

    DEFAULT_CSS = f"""
    Sidebar {{
        width: 34; height: 1fr;
        background: {MANTLE};
        border-left: solid {DIM};
        margin: 0; padding: 0 1;
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

        dot = f"[white]●[/]" if status == "ready" else f"[dim]●[/]"
        slabel = "[white]READY[/]" if status == "ready" else "[dim]WORKING[/]"
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
            f"  {dot} {slabel}{think_tag}{team_tag}{talk_tag}\n"
            f"[dim]─" + "─" * 28 + "[/]\n"
            f"[white]TARGET[/]{target_line}\n"
            f"[dim]─" + "─" * 28 + "[/]\n"
            f"[white]SESSION[/]\n"
            f"  [dim]{session[:20]}[/]\n"
            f"  Mode: [white]{mode.upper()}[/] [dim]Turns: {turns}[/]\n"
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
        )
        try:
            self.query_one("#sidebar_content", Static).update(sidebar_text)
        except Exception:
            pass


# ── Thinking Animation ─────────────────────────────────────────────────
class ThinkingWidget(Static):
    DEFAULT_CSS = f"""ThinkingWidget {{ height: 1; padding: 0 1; color: {WHITE}; display: none; }}"""

    def on_mount(self) -> None:
        self.frames = ["◐", "◓", "◑", "◒"]
        self.idx = 0
        self.anim_timer = self.set_interval(0.3, self.tick, pause=True)

    def tick(self) -> None:
        self.idx = (self.idx + 1) % len(self.frames)
        self.update(f"[white]{self.frames[self.idx]} thinking[/]")

    def show(self) -> None:
        self.add_class("visible"); self.anim_timer.resume()

    def hide(self) -> None:
        self.remove_class("visible"); self.anim_timer.pause()


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
        w = 30; pct = int((cur / max(total, 1)) * w)
        bar = f"[white]{'█' * pct}[/][dim]{'█' * (w - pct)}[/]"
        self.update(f"  {bar}  {tool}  [dim]({cur}/{total})[/]  {findings} findings")

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


# ── Main App ───────────────────────────────────────────────────────────
class ElengenixTextualApp(App):
    CSS = f"""
    Screen {{ background: {BASE}; layers: base overlay; }}
    #header {{ height: 1; background: {BASE}; color: {TEXT}; content-align: center middle; border-bottom: solid {DIM}; }}
    #main_row {{ height: 1fr; layer: base; }}
    #chat_col {{ width: 1fr; height: 1fr; background: {BASE}; }}
    #chat_area {{ height: 1fr; background: {BASE}; padding: 0 1; }}
    #input_row {{ height: auto; margin: 0; background: {BASE}; border-top: solid {DIM}; border-bottom: solid {DIM}; }}
    #user_input {{ height: 3; border: none; border-left: thick {WHITE}; background: {MANTLE}; color: {TEXT}; padding: 0 1; }}
    #user_input:focus {{ border-left: thick {WHITE}; }}
    #suggest_box {{ height: auto; max-height: 8; background: {MANTLE}; color: {TEXT}; border: solid {DIM}; margin: 0 1; padding: 0 1; overflow-y: auto; display: none; }}
    """

    BINDINGS = [
        Binding("ctrl+r", "toggle_research", "Research", priority=True),
        Binding("ctrl+b", "toggle_scan", "Scan", priority=True),
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

    def __init__(self, target: str = "", mode: str = "auto", session_id: str = "", **kwargs):
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

    def compose(self) -> ComposeResult:
        yield Static(f"  ELENGENIX  [dim]{self.target or '(no target)'}[/]  |  /help", id="header")
        with Horizontal(id="main_row"):
            with Vertical(id="chat_col"):
                yield RichLog(id="chat_area", highlight=True, markup=True, wrap=True, auto_scroll=True, max_lines=2000)
                yield ThinkingWidget(id="thinking_bar")
                yield ProgressBar(id="progress_bar")
                yield StatusBar(id="status_bar")
                with Vertical(id="input_row"):
                    yield Static("", id="suggest_box", markup=True)
                    yield Input(placeholder="  try it!", id="user_input")
            yield Sidebar(id="sidebar")
        yield SettingsOverlayWidget(id="settings_overlay")

    def on_mount(self) -> None:
        self._chat_write_banner()
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

    # ── UI Helpers ───────────────────────────────────────────────────────
    def _chat(self) -> RichLog:
        if self._cached_chat is None:
            self._cached_chat = self.query_one("#chat_area", RichLog)
        return self._cached_chat

    def _sidebar(self) -> Sidebar:
        if self._cached_sidebar is None:
            self._cached_sidebar = self.query_one("#sidebar", Sidebar)
        return self._cached_sidebar

    def _chat_write_banner(self) -> None:
        self._chat().write(Text("\n"))
        for line in ASCII_BANNER.splitlines():
            self._chat().write(Text.from_markup(f"  {line}"))
        self._chat().write(Text("\n"))

    def _chat_write_user(self, text: str) -> None:
        ts = time.strftime("%H:%M")
        self._chat().write(Text.from_markup(
            f"\n[white]│[/] [dim]{ts}[/] [white]you[/]\n"
            f"  {text}"
        ))

    def _chat_write_agent(self, text: str) -> None:
        ts = time.strftime("%H:%M")
        self._chat().write(Text.from_markup(f"\n[white]│[/] [dim]{ts}[/] [white]elengix[/]"))
        try:
            self._chat().write(Markdown(text))
        except Exception:
            self._chat().write(Text(f"  {text}", style=TEXT))

    def _chat_write_elengix(self, aid: int, text: str, t: str = "") -> None:
        name = AGENT_NAMES.get(aid, f"#{aid}")
        tag = f" [dim]{t}[/]" if t else ""
        ts = time.strftime("%H:%M")
        self._chat().write(Text.from_markup(
            f"\n[white]│[/] [dim]{ts}[/] [white]{name}[/]{tag}\n"
            f"  [white]{text[:500]}[/]"
        ))

    def _chat_write_system(self, markup: str) -> None:
        self._chat().write(Text.from_markup(f"[dim]{markup}[/]"))

    def _chat_write_governance(self, cmd: str, risk: str) -> None:
        tag = {"SAFE": "", "PRIVILEGED": "[dim]▶ PRIV[/]", "DESTRUCTIVE": "[white]▶ BLOCKED[/]"}.get(risk, "[dim]▶ ?[/]")
        self._chat().write(Text.from_markup(f"  {tag} [dim]{cmd[:100]}[/]"))
        self.query_one("#status_bar", StatusBar).show_action(cmd, risk)

    def _chat_write_error(self, markup: str) -> None:
        self._chat().write(Text.from_markup(f"[white]error:[/] {markup}"))

    def _update_sidebar(self) -> None:
        now = time.monotonic()
        if now - self._last_sidebar_update < 0.3: return
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
                    cmd = ad.get("command", "")[:120]
                    risk = "SAFE"
                    try: risk = self._agent.governance.classify_risk(ad)
                    except: pass
                    self.call_from_thread(self._chat_write_governance, cmd, risk)
                    if self.mode == "scan" and risk == "SAFE":
                        self.tools_run += 1
                        self.call_from_thread(self._update_sidebar)
                    return orig(ad, cb)
                self._agent._execute_tool = wrap
            if hasattr(self._agent, "process_universal"):
                resp = self._agent.process_universal(text, target=self.target or "", mode=self.mode)
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
        ov = self.query_one("#settings_overlay", SettingsOverlayWidget)
        if ov.has_class("visible"):
            if ov.query_one("#custom_url_row").has_class("visible"): return
            event.stop(); ov.on_key(event); return
        key = event.key
        if key == "ctrl+s": event.stop(); self.action_show_settings(); return
        if key == "ctrl+t": event.stop(); self.action_toggle_think(); return
        if key == "ctrl+r": event.stop(); self.action_toggle_research(); return
        if key == "ctrl+b": event.stop(); self.action_toggle_scan(); return
        if key == "ctrl+p": event.stop(); self.action_show_model(); return
        if key == "ctrl+g": event.stop(); self.action_show_help(); return
        if key == "ctrl+c": event.stop(); self.action_app_exit(); return

    # ── Input ────────────────────────────────────────────────────────────
    SLASH_COMMANDS = [
        "/clear", "/reset", "/quit", "/exit",
        "/mode auto", "/mode research", "/mode scan", "/mode casual",
        "/target <domain>", "/talk 1", "/talk 2", "/talk 3", "/talk all",
        "/session", "/session new", "/session list", "/session load <id>",
        "/stats", "/team", "/help",
    ]

    def on_input_changed(self, event: Input.Changed) -> None:
        text = event.value
        box = self.query_one("#suggest_box", Static)
        if not text or not text.startswith("/"):
            box.styles.display = "none"
            return
        parts = text.split()
        if len(parts) == 1:
            prefix = parts[0].lower()
            matches = [c for c in self.SLASH_COMMANDS if c.startswith(prefix)]
        else:
            matches = []
        if matches:
            box.update("\n".join(f"  [dim]{m}[/]" for m in matches[:12]))
            box.styles.display = "block"
        else:
            box.styles.display = "none"

    def on_input_submitted(self, event: Input.Submitted) -> None:
        text = event.value.strip()
        if not text: return
        event.input.value = ""
        if not self.history or self.history[-1] != text: self.history.append(text)
        self.history_idx = -1
        if self._handle_slash(text): return
        self._ensure_session()
        self._chat_write_user(text)
        self.turn_count += 1
        self._update_sidebar()
        def cb(msg: str): self.call_from_thread(self._chat_write_system, msg)
        self._send_to_agent(text, cb)

    def _handle_slash(self, text: str) -> bool:
        low = text.lower().strip()
        if low in ("/quit", "/exit", "quit", "exit"):
            self._save_session(); self.set_timer(0.3, self.exit); return True
        if low == "/clear": self._chat().clear(); return True
        if low == "/reset":
            self._chat().clear()
            if self._agent and hasattr(self._agent, "clear_conversation_history"):
                self._agent.clear_conversation_history()
            self.turn_count = 0; self.tools_run = 0; self.findings = 0
            self._update_sidebar(); return True
        if low in ("/help", "?"): self.action_show_help(); return True
        if low == "/mode":
            self._chat_write_system("Modes: auto  research  security_chat  scan  casual"); return True
        if low.startswith("/mode "):
            v = text.split(" ", 1)[1].strip()
            if v in ("auto","research","security_chat","scan","casual"):
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

    def action_toggle_scan(self) -> None:
        self.mode = "scan" if self.mode != "scan" else "auto"
        self._update_sidebar()
        self._chat_write_system(f"[dim]Scan: {'ON' if self.mode == 'scan' else 'OFF'}[/]")

    def action_toggle_think(self) -> None:
        self.thinking = not self.thinking
        os.environ["NVIDIA_PARAM_MODE"] = "enable" if self.thinking else "disable"
        self._update_sidebar()
        self._chat_write_system(f"[dim]Thinking: {'ON' if self.thinking else 'OFF'}[/]")

    def action_show_model(self) -> None:
        models = os.environ.get("ACTIVE_MODELS", "default")
        self._chat_write_system(f"[dim]Active model(s): {models}[/]")

    def action_show_help(self) -> None:
        self._chat().write(Text.from_markup(HELP_TEXT))

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
