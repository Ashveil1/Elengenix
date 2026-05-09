"""
cli_textual.py — Elengenix AI Partner Mode (Textual TUI v4.0)
- RichLog widget: native mouse scroll + Rich markup support
- Full sidebar with session stats, mode, model, token usage
- Keyboard shortcuts matching cli.py (Ctrl+R/B/T/P/G/E)
- Background thread agent calls (non-blocking UI)
- Slash command support (/help /clear /reset /mode /target /quit)
- Input history with Up/Down arrows
"""

import os
import sys
import time
import logging
import threading
import warnings
warnings.filterwarnings("ignore", category=FutureWarning)
from pathlib import Path
from typing import Optional

from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal, Vertical, ScrollableContainer
from textual.widgets import Static, RichLog, Input, Button, Label
from textual.widget import Widget
from textual import work
from textual.binding import Binding
from textual.reactive import reactive

from rich.text import Text
from rich.panel import Panel
from rich.markdown import Markdown
from rich.box import ROUNDED, MINIMAL

from agent import get_agent

LOG_FILE = Path("data/elengenix_cli.log")
LOG_FILE.parent.mkdir(exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.FileHandler(LOG_FILE, encoding="utf-8")],
)
logger = logging.getLogger("elengenix.cli_textual")

# ── Theme ──────────────────────────────────────────────────────────────────
C_RED    = "#ff4444"
C_DARK   = "#000000"
C_GRAY   = "#525252"
C_LGRAY  = "#a3a3a3"
C_WHITE  = "#ffffff"
C_MUTED  = "#737373"
C_GREEN  = "#4ade80"
C_BLUE   = "#60a5fa"

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

[bold #cc4444]Shortcuts:[/bold #cc4444]
  Ctrl+R  Research ON/off
  Ctrl+B  Scan mode ON/off
  Ctrl+T  Toggle thinking
  Ctrl+P  Show active model
  Ctrl+G  This help
  Ctrl+E  Settings overlay
  Ctrl+C  Exit
  Up/Down Input history"""


# ── Sidebar ────────────────────────────────────────────────────────────────
class Sidebar(Container):
    """Right-hand sidebar showing session info."""

    DEFAULT_CSS = """
    Sidebar {
        width: 36;
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
        """Update sidebar with new values and re-render."""
        self._data.update(kw)
        d        = self._data
        status   = d.get("status", "ready")
        mode     = d.get("mode", "auto")
        model    = d.get("model", "default")
        session  = d.get("session", "new-session")
        turns    = d.get("turns", 0)
        tokens   = d.get("tokens", 0)
        limit    = d.get("limit", 128000)
        thinking = d.get("thinking", False)

        # Status
        is_ready = (status == "ready")
        dot   = f"[{C_RED}]\u25cf[/{C_RED}]" if is_ready else "[white]\u25c9[/white]"
        slabel = f"[bold {C_RED}]STANDBY[/bold {C_RED}]" if is_ready else "[bold white]PROCESSING[/bold white]"
        think_tag = f"  [{C_RED}]THINK[/{C_RED}]" if thinking else ""

        # Dotted context bar (image-1 style)
        pct    = min(100, int((tokens / limit) * 100)) if limit > 0 else 0
        bar_w  = 26
        filled = int((pct / 100) * bar_w)
        bar    = (
            f"[{C_RED}]{'.' * filled}[/{C_RED}]"
            f"[{C_MUTED}]{'.' * (bar_w - filled)}[/{C_MUTED}]"
        )

        mc  = C_RED if mode in ("scan", "research") else C_WHITE
        div = f"[{C_MUTED}]{chr(0x2500) * 26}[/{C_MUTED}]"

        lines = "\n".join([
            f"[bold {C_RED}]ELENGENIX[/bold {C_RED}]",
            f"[{C_LGRAY}]Universal AI Agent[/{C_LGRAY}]",
            div,
            f"{dot}  {slabel}{think_tag}",
            div,
            f"[bold {C_WHITE}]SESSION[/bold {C_WHITE}]",
            f"  {session[:24]}",
            f"  [{mc}]{mode.upper()}[/{mc}]  "
            f"[{C_MUTED}]Turns: {turns}[/{C_MUTED}]",
            div,
            f"[bold {C_WHITE}]ACTIVE MODEL[/bold {C_WHITE}]",
            f"  {model[:26]}",
            div,
            f"[bold {C_WHITE}]CONTEXT USAGE[/bold {C_WHITE}]",
            f"  {tokens} / {limit}",
            f"  {bar}",
            f"  [{C_MUTED}]{pct}% of window[/{C_MUTED}]",
            div,
            f"[bold {C_WHITE}]SHORTCUTS[/bold {C_WHITE}]",
            f"  [{C_MUTED}]Ctrl+R[/{C_MUTED}] Research  [{C_MUTED}]Ctrl+B[/{C_MUTED}] Mode",
            f"  [{C_MUTED}]Ctrl+T[/{C_MUTED}] Think     [{C_MUTED}]Ctrl+P[/{C_MUTED}] Models",
            f"  [{C_MUTED}]Ctrl+G[/{C_MUTED}] Help      [{C_MUTED}]Ti[/{C_MUTED}]    History",
            f"  [{C_MUTED}]Ctrl+E[/{C_MUTED}] Settings  (Overlay menu)",
            div,
            f"[{C_MUTED}]v3.0.0  Elengenix AI Agent Framework[/{C_MUTED}]",
        ])

        try:
            self.query_one("#sidebar_content", Static).update(lines)
        except Exception:
            pass


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


# ── Settings overlay widget (layer-based, avoids ModalScreen 8.x crash) ─────
class SettingsOverlayWidget(Widget, can_focus=True):
    """Floating settings widget on the 'overlay' layer.

    Uses SettingsOverlay from tools/overlay_menu.py for state and rendering.
    Shown/hidden via CSS class 'visible'. Avoids ModalScreen._render() bug
    in Textual 8.x where Screen._render() returns None causing a crash.
    """

    DEFAULT_CSS = """
    /* Semi-transparent backdrop — CLI visible behind */
    SettingsOverlayWidget {
        layer: overlay;
        align: center middle;
        width: 100%;
        height: 100%;
        display: none;
        background: #000000 65%;
    }
    SettingsOverlayWidget.visible {
        display: block;
    }
    /* Centered floating window — solid dark background */
    #settings_panel {
        width: 72;
        height: auto;
        min-height: 20;
        background: #0d0d0d;
        border: double #cc4444;
        padding: 1 2;
    }
    #settings_content {
        width: 1fr;
        height: auto;
        background: transparent;
    }
    """

    def compose(self) -> ComposeResult:
        with Vertical(id="settings_panel"):
            yield Static("", id="settings_content", markup=True)

    def on_mount(self) -> None:
        """Pre-build overlay object so first show is instant."""
        self._overlay = None
        self._build_overlay()

    def _build_overlay(self) -> None:
        """Instantiate SettingsOverlay (resets state on each show)."""
        try:
            from tools.overlay_menu import SettingsOverlay
            agent  = getattr(self.app, "_agent", None)
            target = getattr(self.app, "target", "")
            self._overlay = SettingsOverlay(agent, None, target=target)
        except Exception as exc:
            self._overlay = None
            logger.error(f"[FAIL] SettingsOverlay init: {exc}")

    def _redraw(self) -> None:
        """Re-render Rich Panel into the Static child."""
        w = self.query_one("#settings_content", Static)
        if self._overlay:
            w.update(self._overlay.render())
        else:
            w.update(Panel(
                f"[{C_RED}]Settings unavailable. Press q to close.[/{C_RED}]",
                title=f"[bold {C_RED}]SETTINGS[/bold {C_RED}]",
                border_style=C_RED,
            ))

    def show(self) -> None:
        """Reset overlay state, show widget, grab focus."""
        self._build_overlay()
        self._redraw()
        self.add_class("visible")
        self.focus()

    def hide(self) -> None:
        """Hide the overlay and return focus to the input."""
        self.remove_class("visible")
        try:
            self.app.query_one("#user_input", Input).focus()
        except Exception:
            pass

    def on_key(self, event) -> None:
        """Forward keys to SettingsOverlay.handle_char() and re-render."""
        if not self.has_class("visible"):
            return
        if self._overlay is None:
            self.hide()
            return

        key = event.key
        char_map = {
            "escape": "\x1b",
            "enter":  "\r",
            "up":     "\x1b[A",
            "down":   "\x1b[B",
            "left":   "\x1b[D",
            "right":  "\x1b[C",
        }
        char = char_map.get(key, event.character or "")
        if not char:
            return

        event.stop()
        result = self._overlay.handle_char(char)

        if result == "exit":
            self.hide()
        elif result == "saved":
            self.app._chat_write_system("[OK] Settings saved. Agent reloaded.")
            self.hide()
        elif result == "error":
            self.app._chat_write_system("[FAIL] Settings save failed.")
            self.hide()
        else:
            self._redraw()



# ── Main App ───────────────────────────────────────────────────────────────
class ElengenixTextualApp(App):
    """Elengenix TUI — full-featured chat with mouse-scrollable RichLog."""

    CSS = """
    Screen {
        background: #000000;
        layers: base overlay;
    }

    #main_row   { height: 1fr; layer: base; }
    #chat_col   { width: 1fr; height: 1fr; background: #000000; }

    /* Chat log fills all vertical space — no header bar */
    #chat_area  {
        height: 1fr;
        background: #000000;
        border: none;
        padding: 0 1;
    }

    /* Input row — floating box style */
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
        Binding("ctrl+r", "toggle_research", "Research",  priority=True),
        Binding("ctrl+b", "toggle_scan",     "Scan",      priority=True),
        Binding("ctrl+t", "toggle_think",    "Think",     priority=True),
        Binding("ctrl+p", "show_model",      "Model",     priority=True),
        Binding("ctrl+g", "show_help",       "Help",      priority=True),
        Binding("ctrl+e", "show_settings",   "Settings",  priority=True),
        Binding("ctrl+c", "app_exit",        "Exit",      priority=True),
        Binding("ctrl+u", "scroll_up",       "Scroll Up", show=False, priority=True),
        Binding("ctrl+d", "scroll_down",     "Scroll Down", show=False, priority=True),
        Binding("up",     "history_up",      "History Up",   show=False),
        Binding("down",   "history_down",    "History Down", show=False),
    ]

    def __init__(self, target: str = "", mode: str = "auto", **kwargs):
        super().__init__(**kwargs)
        self.target      = target
        self.mode        = mode
        self.thinking    = False
        self.session_name = f"session-{time.strftime('%Y%m%d-%H%M%S')}"
        self.turn_count  = 0
        self.history: list[str] = []
        self.history_idx = -1
        self._processing = False
        self._agent      = None
        self._cached_chat: RichLog | None = None
        self._cached_sidebar: Sidebar | None = None
        self._last_sidebar_update: float = 0.0

    # ── Layout ──────────────────────────────────────────────────────────────
    def compose(self) -> ComposeResult:
        with Horizontal(id="main_row"):
            with Vertical(id="chat_col"):
                yield RichLog(
                    id="chat_area",
                    highlight=False,
                    markup=True,
                    wrap=True,
                    auto_scroll=True,
                    max_lines=500,
                )
                yield ThinkingWidget(id="thinking_bar")
                with Vertical(id="input_row"):
                    yield Input(
                        placeholder="Elengenix ) ",
                        id="user_input",
                    )
            yield Sidebar(id="sidebar")
        # Settings overlay — always mounted on the 'overlay' layer, hidden by default
        yield SettingsOverlayWidget(id="settings_overlay")

    # ── Mount ────────────────────────────────────────────────────────────────
    def on_mount(self) -> None:
        """Focus input and show welcome banner."""
        chat = self.query_one("#chat_area", RichLog)
        # Push banner down slightly from the top edge
        chat.write(Text("\n\n", style=C_DARK))
        chat.write(Text.from_markup(ASCII_BANNER))
        chat.write(Text.from_markup(
            f"           [{C_BLUE}]Universal AI & Bug Bounty Agent[/{C_BLUE}]\n"
            f"           [{C_MUTED}]Type /help for commands[/{C_MUTED}]\n\n"
        ))
        self._update_sidebar()
        self.set_focus(self.query_one("#user_input", Input))
        # Load agent in background
        self._load_agent()

    @work(thread=True)
    def _load_agent(self) -> None:
        """Load agent in background so startup is fast."""
        try:
            self._agent = get_agent()
            # Do not log to UI on success per user request (start clean)
        except Exception as e:
            self.call_from_thread(
                self._chat_write_system,
                f"[{C_RED}][FAIL] Agent load error: {e}[/{C_RED}]"
            )

    # ── Helpers ──────────────────────────────────────────────────────────────
    def _chat(self) -> RichLog:
        if self._cached_chat is None:
            self._cached_chat = self.query_one("#chat_area", RichLog)
        return self._cached_chat

    def _sidebar(self) -> Sidebar:
        if self._cached_sidebar is None:
            self._cached_sidebar = self.query_one("#sidebar", Sidebar)
        return self._cached_sidebar

    def _chat_write_user(self, text: str) -> None:
        ts = time.strftime("%H:%M:%S")
        self._chat().write(Text.from_markup(f"\n[{C_BLUE}]╭─\u276f USER[/{C_BLUE}] [dim]{ts}[/dim]"))
        self._chat().write(Text.from_markup(f"[{C_BLUE}]╰─❯[/{C_BLUE}] [{C_WHITE}]{text}[/{C_WHITE}]"))

    def _chat_write_agent(self, text: str) -> None:
        ts = time.strftime("%H:%M:%S")
        self._chat().write(Text.from_markup(f"\n[{C_RED}]╭─❖ AEGIS PROTOCOL[/{C_RED}] [dim]{ts}[/dim]"))
        # Write markdown for agent responses
        try:
            self._chat().write(Markdown(text))
        except Exception:
            self._chat().write(Text(text, style=C_LGRAY))

    def _chat_write_system(self, markup: str) -> None:
        self._chat().write(Text.from_markup(f"[{C_MUTED}]{markup}[/{C_MUTED}]"))

    def _chat_write_error(self, markup: str) -> None:
        self._chat().write(Text.from_markup(f"[bold {C_RED}][FAIL] {markup}[/bold {C_RED}]"))


    def _update_sidebar(self) -> None:
        # Debounce: skip if called within 0.3s of last update
        now = time.monotonic()
        if now - self._last_sidebar_update < 0.3:
            return
        self._last_sidebar_update = now

        tokens = 0
        model  = "default"
        try:
            if self._agent:
                if hasattr(self._agent, "conversation_history"):
                    tokens = sum(
                        len(str(m.get("content", "")))
                        for m in self._agent.conversation_history
                    ) // 4
                if hasattr(self._agent, "client") and hasattr(self._agent.client, "active_client"):
                    model = getattr(self._agent.client.active_client, "model", "default")
        except Exception:
            pass

        # Check env for active model
        env_models = [m.strip() for m in os.environ.get("ACTIVE_MODELS", "").split(",") if m.strip()]
        if len(env_models) >= 2:
            model = f"Team ({len(env_models)} agents)"
        elif env_models:
            model = env_models[0].split("/")[-1] if "/" in env_models[0] else env_models[0]

        try:
            self._sidebar().refresh_data(
                status="thinking" if self._processing else "ready",
                mode=self.mode,
                model=model,
                session=self.session_name,
                turns=self.turn_count,
                tokens=tokens,
                limit=128000,
                target=self.target,
                thinking=self.thinking,
            )
        except Exception:
            pass

    # ── Input handler ─────────────────────────────────────────────────────
    def on_input_submitted(self, event: Input.Submitted) -> None:
        """Handle Enter key."""
        text = event.value.strip()
        if not text:
            return
        event.input.value = ""

        # History
        if not self.history or self.history[-1] != text:
            self.history.append(text)
        self.history_idx = -1

        # Slash commands
        if self._handle_slash(text):
            return

        # Echo + send to agent
        self._chat_write_user(text)
        self.turn_count += 1
        self._update_sidebar()
        self._send_to_agent(text)

    def _handle_slash(self, text: str) -> bool:
        """Handle slash commands. Returns True if handled."""
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

        if low.startswith("/"):
            self._chat_write_system(f"Unknown command: {low}  (type /help)")
            return True

        return False

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
            self._chat_write_system("No team configured. Use /team in cli.py or set ACTIVE_MODELS.")
        else:
            roles = ["Strategist", "Recon Lead", "Exploit Analyst"]
            lines = ["[bold]Team Aegis:[/bold]"]
            for i, m in enumerate(active):
                role = roles[i] if i < len(roles) else f"Agent {i+1}"
                lines.append(f"  [{role}] {m}")
            self._chat().write(Text.from_markup("\n".join(lines)))

    # ── Agent call (background thread) ───────────────────────────────────
    @work(thread=True)
    def _send_to_agent(self, text: str) -> None:
        """Call agent.process_universal in a background thread."""
        if self._processing:
            self.call_from_thread(
                self._chat_write_system, "Agent is busy — please wait."
            )
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
                raise RuntimeError("Agent not loaded yet. Please wait a moment.")

            # Use process_universal (handles all intents) if available
            if hasattr(self._agent, "process_universal"):
                response = self._agent.process_universal(
                    text,
                    target=self.target or "",
                    mode=self.mode,
                )
            else:
                response = self._agent.process_query(
                    user_input=text,
                    target=self.target or "",
                )

            if response:
                self.call_from_thread(self._chat_write_agent, str(response))
            else:
                self.call_from_thread(self._chat_write_error, "No response from agent.")
        except Exception as exc:
            logger.error(f"[FAIL] Agent error: {exc}")
            self.call_from_thread(self._chat_write_error, str(exc))
        finally:
            self._processing = False
            def hide_thinking():
                try:
                    self.query_one("#thinking_bar", ThinkingWidget).hide()
                except Exception:
                    pass
            self.call_from_thread(hide_thinking)
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
        cur = os.environ.get("NVIDIA_PARAM_MODE", "auto")
        if self.thinking:
            os.environ["NVIDIA_PARAM_MODE"] = "enable"
        else:
            os.environ["NVIDIA_PARAM_MODE"] = "disable"
        self._update_sidebar()
        self._chat_write_system(f"Thinking: {'ON' if self.thinking else 'OFF'}")

    def action_show_model(self) -> None:
        env = os.environ.get("ACTIVE_MODELS", "")
        model = env or "default (see /stats)"
        self._chat_write_system(f"Active model: {model}")

    def action_show_help(self) -> None:
        self._chat().write(Text.from_markup(HELP_TEXT))

    def action_show_settings(self) -> None:
        self.query_one("#settings_overlay", SettingsOverlayWidget).show()

    def action_app_exit(self) -> None:
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


# ── Entry point ────────────────────────────────────────────────────────────
def main(target: str = "", mode: str = "auto") -> None:
    """Launch the Textual TUI."""
    app = ElengenixTextualApp(target=target, mode=mode)
    app.run()


if __name__ == "__main__":
    main()
