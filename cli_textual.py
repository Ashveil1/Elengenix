"""
cli_textual.py — Elengenix AI Partner Mode (Textual TUI v99999 (god nine is the best))
Catppuccin Mocha-inspired theme with proper layout management.
- Header bar with session info + keybinding hints
- Main chat area with RichLog (scrollable)
- Right sidebar: target, models, context, scan stats
- Footer: status line + governance bar
- Slash commands + settings overlay
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
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler()],
)
logger = logging.getLogger("elengenix.cli_textual")

# ── Theme: Black, Red, White, Gray, Orange ──────────────────────────────
BASE    = "#000000"
MANTLE  = "#111111"
CRUST   = "#0d0d0d"
SURFACE = "#444444"
TEXT    = "#ffffff"
SUBTEXT = "#cccccc"
MUTED   = "#777777"
RED     = "#ff4444"
ORANGE  = "#ff6b6b"
WHITE   = "#ffffff"
GRAY    = "#888888"

# ── Aliases ─────────────────────────────────────────────────────────────
COLOR_OK       = WHITE
COLOR_WARN     = ORANGE
COLOR_ERR      = RED
COLOR_INFO     = WHITE
COLOR_ACCENT   = RED
COLOR_DIM      = GRAY
COLOR_BG       = BASE
COLOR_SURFACE  = SURFACE
COLOR_TEXT     = TEXT
COLOR_MUTED    = MUTED
COLOR_BORDER   = SURFACE
COLOR_HIGHLIGHT= ORANGE

AGENT_NAMES  = {1: "Elengix 1", 2: "Elengix 2", 3: "Elengix 3"}
AGENT_COLORS = {1: WHITE, 2: GRAY, 3: MUTED}

ASCII_BANNER = f"""\
    [{RED}] ███████╗██╗     ███████╗███╗   ██╗ ██████╗ ███████╗███╗   ██╗
    ██╔════╝██║     ██╔════╝████╗  ██║██╔════╝ ██╔════╝████╗  ██║
    █████╗  ██║     █████╗  ██╔██╗ ██║██║  ███╗█████╗  ██╔██╗ ██║
    ██╔══╝  ██║     ██╔══╝  ██║╚██╗██║██║   ██║██╔══╝  ██║╚██╗██║
    ███████╗███████╗███████╗██║ ╚████║╚██████╔╝███████╗██║ ╚████║
    ╚══════╝╚══════╝╚══════╝╚═╝  ╚═══╝ ╚═════╝ ╚══════╝╚═╝  ╚═══╝[/]"""

HELP_TEXT = f"""\
[{COLOR_ACCENT}]━━━ COMMANDS ━━━[/{COLOR_ACCENT}]
  /clear       Clear chat
  /reset       Reset session
  /quit        Exit
  /mode <x>    Mode: auto research scan casual
  /target <x>  Set target domain
  /talk <n>    Talk to agent 1,2,3 or all
  /session     Session info
  /session new New session
  /session list List sessions
  /stats       Memory stats
  /team        Show team

[{COLOR_ACCENT}]━━━ SHORTCUTS ━━━[/{COLOR_ACCENT}]
  Ctrl+R Research  Ctrl+B Scan
  Ctrl+T Thinking  Ctrl+P Model
  Ctrl+G Help      Ctrl+E Settings
  Ctrl+U ↑10  Ctrl+D ↓10
  ↑↓ History       / Slash commands"""


# ── Sidebar ──────────────────────────────────────────────────────────────
class Sidebar(Container):
    """Right-hand panel — target, models, context, scan stats."""

    DEFAULT_CSS = f"""
    Sidebar {{
        width: 38;
        height: 1fr;
        background: {MANTLE};
        border: solid {RED};
        margin: 0 0 0 1;
        padding: 0 1;
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
        model    = d.get("model", "default")
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

        is_ready = (status == "ready")
        dot  = f"[{COLOR_OK}]\u25cf[/{COLOR_OK}]" if is_ready else f"[{COLOR_WARN}]\u25cf[/{COLOR_WARN}]"
        slabel = f"[bold {COLOR_OK}]READY[/]" if is_ready else f"[bold {COLOR_WARN}]WORKING[/]"
        think_tag = f"  [{COLOR_ACCENT}]THINK[/]" if thinking else ""
        team_tag = f"  [{COLOR_INFO}]TEAM {team}[/]" if team > 1 else ""
        talk_tag = ""
        if talk_to != "all" and team > 0:
            name = AGENT_NAMES.get(talk_to, f"#{talk_to}")
            talk_tag = f"\n  [{COLOR_ACCENT}]\u25b6 {name}[/]"

        pct   = min(100, int((tokens / limit) * 100)) if limit > 0 else 0
        bar_w = 28
        filled = int((pct / 100) * bar_w)
        bar  = f"[{COLOR_ACCENT}]{'.' * filled}[/][{COLOR_DIM}]{'.' * (bar_w - filled)}[/]"
        mode_color = COLOR_ACCENT if mode in ("research", "scan") else COLOR_TEXT
        div = f"[{COLOR_DIM}]\u2500" + "\u2500" * 28 + "[/]"

        target_line = ""
        if target:
            target_line = f"\n  [{COLOR_ACCENT}]{target[:32]}[/]"

        model_lines = []
        if models:
            for i, m in enumerate(models):
                idx = i + 1
                name = AGENT_NAMES.get(idx, f"#{idx}")
                marker = f"[bold {COLOR_ACCENT}]\u25b6[/]" if talk_to == idx else " "
                short = m.split("/")[-1] if "/" in m else m
                tag_color = AGENT_COLORS.get(idx, COLOR_TEXT)
                model_lines.append(f"  {marker} [{tag_color}]{name}[/] [{COLOR_DIM}]{short[:22]}[/]")
        else:
            model_lines.append(f"  [{COLOR_MUTED}]default[/]")

        lines = "\n".join([
            f"[bold {COLOR_ACCENT}]\u250c\u2500 ELENGENIX[/]",
            f"  {dot} {slabel}{think_tag}{team_tag}{talk_tag}",
            div,
            f"[bold {COLOR_TEXT}]TARGET[/]{target_line}",
            div,
            f"[bold {COLOR_TEXT}]SESSION[/]",
            f"  {session[:22]}",
            f"  Mode: [bold {mode_color}]{mode.upper()}[/] [{COLOR_DIM}]Turns: {turns}[/]",
            div,
            f"[bold {COLOR_TEXT}]SCAN[/]" if target else f"[{COLOR_DIM}]SCAN[/]",
            f"  [{COLOR_DIM}]Tools:[/] {tools_run}  [{COLOR_DIM}]Findings:[/] {findings}",
            div,
            f"[bold {COLOR_TEXT}]MODELS[/]",
            "\n".join(model_lines),
            div,
            f"[bold {COLOR_TEXT}]CONTEXT[/]",
            f"  {bar}",
            f"  {tokens}/{limit}  [{COLOR_DIM}]{pct}%[/]",
            div,
            f"[{COLOR_DIM}]\u2514\u2500 v99999 Elengix[/]",
        ])
        try:
            self.query_one("#sidebar_content", Static).update(lines)
        except Exception:
            pass


# ── Animated Thinking ────────────────────────────────────────────────────
class ThinkingWidget(Static):
    DEFAULT_CSS = f"""
    ThinkingWidget {{
        height: 1; padding: 0 1;
        color: {COLOR_ACCENT};
        display: none;
    }}
    ThinkingWidget.visible {{ display: block; }}
    """

    def on_mount(self) -> None:
        self.frames = ["\u25d0", "\u25d3", "\u25d1", "\u25d2"]
        self.idx = 0
        self.anim_timer = self.set_interval(0.2, self.tick, pause=True)

    def tick(self) -> None:
        self.idx = (self.idx + 1) % len(self.frames)
        self.update(f"[{COLOR_ACCENT}]{self.frames[self.idx]} Thinking...[/]")

    def show(self) -> None:
        self.add_class("visible"); self.anim_timer.resume()

    def hide(self) -> None:
        self.remove_class("visible"); self.anim_timer.pause()


# ── Governance / Status Bar ──────────────────────────────────────────────
class StatusBar(Static):
    DEFAULT_CSS = f"""
    StatusBar {{
        height: 1; padding: 0 1;
        background: {CRUST};
        color: {COLOR_MUTED};
    }}
    """

    def show_action(self, cmd: str, risk: str = "SAFE") -> None:
        c = {"SAFE": COLOR_OK, "PRIVILEGED": COLOR_WARN, "DESTRUCTIVE": COLOR_ERR}.get(risk, COLOR_MUTED)
        self.update(f"[{c}]\u25b6 {risk}[/]  [{COLOR_DIM}]{cmd[:80]}[/]")


class ProgressBar(Static):
    DEFAULT_CSS = f"""
    ProgressBar {{
        height: 1; padding: 0 1;
        background: {MANTLE};
        display: none;
    }}
    ProgressBar.visible {{ display: block; }}
    """

    def show_scan(self, tool: str, cur: int, total: int, findings: int) -> None:
        w = 30; pct = int((cur / max(total, 1)) * w)
        bar = f"[{COLOR_ACCENT}]{'#' * pct}[/][{COLOR_DIM}]{'-' * (w - pct)}[/]"
        self.update(f"  {bar}  [{COLOR_ACCENT}]{tool}[/]  ({cur}/{total})  [{COLOR_OK}]{findings} findings[/]")

    def show(self) -> None: self.add_class("visible")
    def hide(self) -> None: self.remove_class("visible")


# ── Settings Overlay ─────────────────────────────────────────────────────
class SettingsOverlayWidget(Widget, can_focus=True):
    DEFAULT_CSS = f"""
    SettingsOverlayWidget {{
        layer: overlay; align: center middle;
        width: 100%; height: 100%; display: none;
    }}
    SettingsOverlayWidget.visible {{ display: block; }}
    #settings_panel {{
        width: 76; height: auto; max-height: 80%; min-height: 22;
        background: {MANTLE}; border: wide {RED}; padding: 0;
    }}
    #settings_header {{
        width: 1fr; height: 1; content-align: center middle;
        background: {RED}; color: {WHITE};
        text-style: bold;
    }}
    #settings_content {{ width: 1fr; height: auto; background: transparent; padding: 1 2; }}
    #settings_footer {{
        width: 1fr; height: 1; content-align: center middle;
        color: {MUTED}; background: {CRUST};
    }}
    """

    def compose(self) -> ComposeResult:
        with Vertical(id="settings_panel"):
            yield Static("  SETTINGS  ", id="settings_header")
            yield Static("", id="settings_content", markup=True)
            yield Static("  \u2191\u2193 Navigate  \u23ce Select  Esc Close  S Save", id="settings_footer")

    def on_mount(self) -> None: self._overlay = None; self._reload()

    def _reload(self) -> None:
        try:
            from tools.overlay_menu import SettingsOverlay
            self._overlay = SettingsOverlay(getattr(self.app, "_agent", None), None, target=getattr(self.app, "target", ""))
        except Exception as exc:
            self._overlay = None; logger.error(f"Settings: {exc}")

    def _redraw(self) -> None:
        w = self.query_one("#settings_content", Static)
        if self._overlay:
            w.update(self._overlay.render())
        else:
            w.update(Panel(f"[{COLOR_ERR}]Unavailable. Esc to close.[/]", border_style=COLOR_DIM))

    def show(self) -> None: self._reload(); self._redraw(); self.add_class("visible"); self.focus()
    def hide(self) -> None:
        self.remove_class("visible")
        try: self.app.query_one("#user_input", Input).focus()
        except: pass

    def on_key(self, event) -> None:
        if not self.has_class("visible"): return
        key = event.key
        cmap = {"escape": "\x1b", "enter": "\r", "up": "\x1b[A", "down": "\x1b[B", "left": "\x1b[D", "right": "\x1b[C"}
        char = cmap.get(key, event.character or "")
        if not char: return
        event.stop()
        r = self._overlay.handle_char(char) if self._overlay else "exit"
        if r == "exit": self.hide()
        elif r == "saved":
            self.app._chat_write_system(f"[{COLOR_OK}]Settings saved.[/]")
            if hasattr(self.app, "_agent") and self.app._agent:
                try:
                    from tools.governance import Governance
                    self.app._agent.governance = Governance()
                except: pass
            self.hide()
        elif r == "error":
            self.app._chat_write_system(f"[{COLOR_ERR}]Settings failed.[/]"); self.hide()
        else: self._redraw()


# ── Main App ─────────────────────────────────────────────────────────────
class ElengenixTextualApp(App):
    CSS = f"""
    Screen {{
        background: {BASE};
        layers: base overlay;
    }}
    #header {{
        height: 1; background: {MANTLE};
        color: {TEXT}; content-align: center middle;
        border-bottom: solid {RED};
    }}
    #main_row {{ height: 1fr; layer: base; }}
    #chat_col {{ width: 1fr; height: 1fr; background: {BASE}; }}
    #chat_area {{
        height: 1fr; background: {BASE};
        padding: 0 1;
    }}
    #input_row {{
        height: auto; margin: 0 1;
        background: {MANTLE}; border: none; padding: 0;
    }}
    #user_input {{
        height: 3; border: none;
        border-left: thick {RED};
        background: {MANTLE}; color: {TEXT};
        padding: 0 1;
    }}
    #user_input:focus {{ border-left: thick {ORANGE}; }}
    """

    BINDINGS = [
        Binding("ctrl+r", "toggle_research", "Research", priority=True),
        Binding("ctrl+b", "toggle_scan", "Scan", priority=True),
        Binding("ctrl+t", "toggle_think", "Think", priority=True),
        Binding("ctrl+p", "show_model", "Model", priority=True),
        Binding("ctrl+g", "show_help", "Help", priority=True),
        Binding("ctrl+e", "show_settings", "Settings", priority=True),
        Binding("ctrl+c", "app_exit", "Exit", priority=True),
        Binding("ctrl+u", "scroll_up", "", show=False, priority=True),
        Binding("ctrl+d", "scroll_down", "", show=False, priority=True),
        Binding("up", "history_up", "", show=False),
        Binding("down", "history_down", "", show=False),
    ]

    def __init__(self, target: str = "", mode: str = "auto", **kwargs):
        super().__init__(**kwargs)
        self.target        = target
        self.mode          = mode
        self.thinking      = False
        self.session_name  = f"sess-{time.strftime('%m%d-%H%M%S')}"
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
        self._cached_chat: RichLog | None = None
        self._cached_sidebar: Sidebar | None = None
        self._last_sidebar_update: float = 0.0

    def compose(self) -> ComposeResult:
        yield Static(f" Elengenix AI  |  [{COLOR_DIM}]{self.target or '(no target)'}[/]  |  /help", id="header")
        with Horizontal(id="main_row"):
            with Vertical(id="chat_col"):
                yield RichLog(id="chat_area", highlight=False, markup=True, wrap=True, auto_scroll=True, max_lines=2000)
                yield ThinkingWidget(id="thinking_bar")
                yield ProgressBar(id="progress_bar")
                yield StatusBar(id="status_bar")
                with Vertical(id="input_row"):
                    yield Input(placeholder="try it!", id="user_input")
            yield Sidebar(id="sidebar")
        yield SettingsOverlayWidget(id="settings_overlay")

    def on_mount(self) -> None:
        self._chat().write(Text("\n"))
        self._chat().write(Text.from_markup(ASCII_BANNER))
        self._chat_write_system(f"[{COLOR_DIM}]Target: {self.target or '(none)'}  |  /help for commands[/]")
        try:
            from tools.session_manager import SessionManager
            self._session_mgr = SessionManager()
            self._session_mgr.start_session(name=self.session_name, target=self.target, mode=self.mode)
        except: pass
        self._update_sidebar()
        self.set_focus(self.query_one("#user_input", Input))
        self._load_agent()

    @work(thread=True)
    def _load_agent(self) -> None:
        try:
            self._agent = get_agent()
            if self._agent: _ = self._agent.governance
        except Exception as e:
            self.call_from_thread(self._chat_write_error, f"Agent load: {e}")

    # ── UI Helpers ───────────────────────────────────────────────────────
    def _chat(self) -> RichLog:
        if self._cached_chat is None:
            self._cached_chat = self.query_one("#chat_area", RichLog)
        return self._cached_chat

    def _sidebar(self) -> Sidebar:
        if self._cached_sidebar is None:
            self._cached_sidebar = self.query_one("#sidebar", Sidebar)
        return self._cached_sidebar

    def _chat_write_user(self, text: str) -> None:
        ts = time.strftime("%H:%M")
        self._chat().write(Text.from_markup(
            f"\n[{COLOR_ACCENT}]\u2570[/] [{COLOR_ACCENT}]USER[/] [{COLOR_DIM}]{ts}[/]"
            f"\n  [{COLOR_TEXT}]{text}[/]"
        ))

    def _chat_write_agent(self, text: str) -> None:
        ts = time.strftime("%H:%M")
        self._chat().write(Text.from_markup(f"\n[{COLOR_ACCENT}]\u2570[/] [{COLOR_ACCENT}]ELENGIX[/] [{COLOR_DIM}]{ts}[/]"))
        try: self._chat().write(Markdown(text))
        except: self._chat().write(Text(text, style=COLOR_TEXT))

    def _chat_write_elengix(self, aid: int, text: str, t: str = "") -> None:
        name = AGENT_NAMES.get(aid, f"#{aid}")
        color = AGENT_COLORS.get(aid, COLOR_TEXT)
        tag = f" [{COLOR_WARN}]{t}[/]" if t else ""
        ts = time.strftime("%H:%M")
        self._chat().write(Text.from_markup(
            f"\n[{color}]\u2570[/] [{color}]{name}[/]{tag} [{COLOR_DIM}]{ts}[/]"
            f"\n  [{color}]{text[:500]}[/]"
        ))

    def _chat_write_system(self, markup: str) -> None:
        self._chat().write(Text.from_markup(f"[{COLOR_DIM}]{markup}[/]"))

    def _chat_write_governance(self, cmd: str, risk: str) -> None:
        c = {"SAFE": COLOR_OK, "PRIVILEGED": COLOR_WARN, "DESTRUCTIVE": COLOR_ERR}.get(risk, COLOR_MUTED)
        self._chat().write(Text.from_markup(f"  [{c}]\u25b6 {risk}[/] [{COLOR_DIM}]{cmd[:120]}[/]"))
        self.query_one("#status_bar", StatusBar).show_action(cmd, risk)

    def _chat_write_error(self, markup: str) -> None:
        self._chat().write(Text.from_markup(f"[bold {COLOR_ERR}][FAIL] {markup}[/]"))

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

    # ── Input ────────────────────────────────────────────────────────────
    def on_input_submitted(self, event: Input.Submitted) -> None:
        text = event.value.strip()
        if not text: return
        event.input.value = ""
        if not self.history or self.history[-1] != text: self.history.append(text)
        self.history_idx = -1
        if self._handle_slash(text): return
        self._chat_write_user(text)
        self.turn_count += 1
        self._update_sidebar()

        def cb(msg: str):
            self.call_from_thread(self._chat_write_system, msg)
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
                lines = [f"[bold]Team Aegis:[/bold]"]
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
                if self._agent and hasattr(self._agent,"clear_conversation_history"): self._agent.clear_conversation_history()
                self.turn_count = 0; self.tools_run = 0; self.findings = 0
                self._chat().clear()
                self._chat_write_system("New session.")
                self._update_sidebar(); return True
            if sub == "list" and self._session_mgr:
                ss = self._session_mgr.list_sessions()
                if not ss: self._chat_write_system("No saved sessions.")
                else:
                    lines = ["[bold]Sessions:[/bold]"]
                    for s in ss[-10:]: lines.append(f"  [{COLOR_DIM}]{s.name}[/]  turns={s.turn_count}")
                    self._chat().write(Text.from_markup("\n".join(lines)))
                return True
            self._chat_write_system(f"Session: {self.session_name}  Turns: {self.turn_count}"); return True
        if low.startswith("/"): self._chat_write_system(f"Unknown: {low}  (/help)"); return True
        return False

    def _save_session(self) -> None:
        try:
            if self._session_mgr:
                self._session_mgr.save_session(name=self.session_name, agent=self._agent, target=self.target, mode=self.mode)
        except: pass

    # ── Agent ────────────────────────────────────────────────────────────
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
                    cmd = ad.get("command","")[:120]
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

    # ── Actions ──────────────────────────────────────────────────────────
    def action_toggle_research(self) -> None:
        self.mode = "research" if self.mode != "research" else "auto"
        self._update_sidebar(); self._chat_write_system(f"Research: {'ON' if self.mode=='research' else 'OFF'}")

    def action_toggle_scan(self) -> None:
        self.mode = "scan" if self.mode != "scan" else "auto"
        self._update_sidebar(); self._chat_write_system(f"Scan: {'ON' if self.mode=='scan' else 'OFF'}")

    def action_toggle_think(self) -> None:
        self.thinking = not self.thinking
        os.environ["NVIDIA_PARAM_MODE"] = "enable" if self.thinking else "disable"
        self._update_sidebar(); self._chat_write_system(f"Thinking: {'ON' if self.thinking else 'OFF'}")

    def action_show_model(self) -> None:
        self._chat_write_system(f"Model: {os.environ.get('ACTIVE_MODELS','default')}")

    def action_show_help(self) -> None:
        self._chat().write(Text.from_markup(HELP_TEXT))

    def action_show_settings(self) -> None:
        self.query_one("#settings_overlay", SettingsOverlayWidget).show()

    def action_app_exit(self) -> None:
        self._save_session(); self.exit()

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


def main(target: str = "", mode: str = "auto") -> None:
    ElengenixTextualApp(target=target, mode=mode).run()

if __name__ == "__main__":
    main()
