"""tui/command_palette.py - VSCode-style command palette for Elengenix.

A modal overlay that:

    * Lists every command registered with the app.
    * Filters them via fuzzy search (as you type).
    * Groups commands by category.
    * Pins recent commands to the top.
    * Navigable with keyboard (Up/Down, Enter, Esc, Tab to switch modes).
    * Animates open/close via a small CSS-driven fade.

Usage (from a Textual app)::

    palette = CommandPalette(commands=my_commands)
    await self.mount(palette)
    palette.show()

The palette is also usable as a pure-Rich panel for embedding into
non-Textual contexts via :func:`render_palette`.
"""

from __future__ import annotations

import logging
import re
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Sequence, Tuple

from rich.box import HEAVY, ROUNDED, SIMPLE
from rich.console import Group
from rich.panel import Panel
from rich.text import Text

from textual.containers import Container, Vertical
from textual.reactive import reactive
from textual.screen import ModalScreen
from textual.widgets import Input, Static

from ui_components import console as shared_console

logger = logging.getLogger("elengenix.tui.command_palette")

# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class Command:
    """A single command in the palette."""

    id: str
    title: str
    category: str = "General"
    description: str = ""
    shortcut: str = ""
    keywords: Sequence[str] = field(default_factory=tuple)
    callback: Optional[Callable[[], None]] = None


DEFAULT_COMMANDS: List[Command] = [
    Command("scan.start",       "Start Scan",            "Scan",     "Launch a full pipeline scan",              "S", ("recon", "pipeline", "run")),
    Command("scan.recon",       "Recon",                 "Scan",     "Subdomain + asset discovery",              "",  ("recon", "subdomain")),
    Command("scan.omni",        "Omni-Scan",             "Scan",     "Recon -> Vuln -> Report",                  "",  ("omni", "full")),
    Command("scan.vuln",        "Vulnerability Scan",    "Scan",     "Nuclei CVE and misconfig scan",            "",  ("vuln", "nuclei")),
    Command("scan.bounty",      "Bounty Intel",          "Scan",     "Bug bounty program analysis",              "",  ("bounty", "intel")),
    Command("recon.api",        "API Hunter",            "Recon",    "Find Swagger, OpenAPI, hidden routes",     "",  ("api", "swagger")),
    Command("recon.js",         "JS Analyzer",           "Recon",    "Extract secrets & paths from JS files",    "",  ("js", "javascript")),
    Command("recon.params",     "Param Miner",           "Recon",    "Fuzz URL parameters for hidden vulns",     "",  ("params", "fuzz")),
    Command("recon.dork",       "Google Dorking",        "Recon",    "Search exposed files & logs via Google",   "",  ("dork", "google")),
    Command("exploit.bola",     "BOLA / IDOR",           "Exploit",  "Broken access control & IDOR tests",       "",  ("bola", "idor")),
    Command("exploit.waf",      "WAF / XSS",             "Exploit",  "WAF detection, bypass & XSS engine",       "",  ("waf", "xss")),
    Command("exploit.evasion",  "Evasion",               "Exploit",  "EDR/AV evasion framework",                 "",  ("evasion", "av")),
    Command("exploit.poc",      "Research / PoC",        "Exploit",  "CVE research + PoC generator",             "",  ("poc", "cve")),
    Command("analysis.sast",    "SAST",                  "Analysis", "Static analysis - Py/JS/Go/Java/PHP",      "",  ("sast", "static")),
    Command("analysis.cloud",   "Cloud",                 "Analysis", "Cloud / Terraform / IaC review",           "",  ("cloud", "terraform")),
    Command("analysis.mobile",  "Mobile / API",          "Analysis", "Mobile API traffic analysis & fuzzing",    "",  ("mobile", "api")),
    Command("analysis.soc",     "SOC Analyzer",          "Analysis", "Security log & threat intel",              "",  ("soc", "logs")),
    Command("reports.generate", "Generate Report",       "Reports",  "Build an HTML / PDF report",               "",  ("report", "pdf")),
    Command("reports.history",  "History",               "Reports",  "Browse past scan sessions",                "",  ("history", "sessions")),
    Command("reports.dashboard","Open Dashboard",        "Reports",  "Launch the web dashboard",                 "D", ("dashboard", "ui")),
    Command("settings.theme",   "Switch Theme",          "Settings", "Cycle through CYBERPUNK / MATRIX / ...",   "",  ("theme", "ui")),
    Command("settings.config",  "Configure",             "Settings", "AI providers, Telegram, HackerOne",        "",  ("config", "setup")),
    Command("settings.doctor",  "Doctor",                "Settings", "System health check",                      "",  ("doctor", "health")),
    Command("settings.update",  "Update",                "Settings", "Pull the latest version",                  "",  ("update", "git")),
    Command("nav.welcome",      "Welcome",               "Nav",      "Back to the welcome screen",               "W", ("welcome", "home")),
    Command("nav.help",         "Help",                  "Nav",      "Show keybindings & help",                  "?", ("help", "shortcuts")),
    Command("nav.quit",         "Quit",                  "Nav",      "Exit the application",                     "Q", ("quit", "exit")),
]


# ---------------------------------------------------------------------------
# Fuzzy matching
# ---------------------------------------------------------------------------


def fuzzy_score(query: str, candidate: str) -> int:
    """Return a fuzzy match score for ``query`` against ``candidate``.

    A score of 0 means no match. Higher scores indicate better matches.
    The algorithm is a classic subsequence match with bonuses for:

        * matching the start of a word
        * contiguous character runs
        * case-insensitive matches
        * shorter candidates
    """
    if not query:
        return 1
    q = query.lower()
    c = candidate.lower()
    qi = 0
    score = 0
    last_match = -2
    bonus = 0
    for i, ch in enumerate(c):
        if qi >= len(q):
            break
        if ch == q[qi]:
            qi += 1
            # Bonus for matches at word boundaries.
            if i == 0 or c[i - 1] in (" ", "/", "-", "_", ".", ":"):
                bonus += 8
            # Bonus for consecutive matches.
            if i == last_match + 1:
                bonus += 5
            last_match = i
            score += 1
    if qi < len(q):
        return 0
    # Penalty for length (shorter is better).
    length_penalty = max(0, len(candidate) - len(query))
    return 10 * (score + bonus) - length_penalty


def fuzzy_match(query: str, candidates: Sequence[str]) -> List[Tuple[int, int]]:
    """Return ``(score, index)`` pairs sorted by descending score.

    Indices refer to positions in ``candidates``.
    """
    results: List[Tuple[int, int]] = []
    for i, c in enumerate(candidates):
        s = fuzzy_score(query, c)
        if s > 0:
            results.append((s, i))
    results.sort(key=lambda x: -x[0])
    return results


# ---------------------------------------------------------------------------
# Palette state
# ---------------------------------------------------------------------------


@dataclass
class _PaletteState:
    """Mutable state for the palette (query, selection, recents)."""

    query: str = ""
    selected: int = 0
    recents: List[str] = field(default_factory=list)
    show_recents: bool = True


# ---------------------------------------------------------------------------
# Pure-Rich renderable
# ---------------------------------------------------------------------------


def render_palette(
    commands: Sequence[Command],
    state: _PaletteState,
    width: int = 80,
    primary: str = "#ff2222",
    text: str = "#ffffff",
    muted: str = "#888888",
    highlight: str = "#ff5555",
) -> Panel:
    """Build the command palette as a Rich ``Panel``."""
    # Group and order: recents first (when no query and show_recents),
    # then by category.
    visible: List[Tuple[Command, int]] = []
    if state.show_recents and not state.query:
        recent_cmds = [c for c in commands if c.id in state.recents]
        for c in recent_cmds:
            visible.append((c, 0))
        for c in commands:
            if c.id not in state.recents:
                visible.append((c, 1))
    else:
        scored: List[Tuple[int, Command]] = []
        for c in commands:
            haystack = " ".join([c.title, c.category, c.description, *c.keywords])
            s = fuzzy_score(state.query, haystack) + fuzzy_score(state.query, c.title)
            if s > 0:
                scored.append((s, c))
        scored.sort(key=lambda x: -x[0])
        visible = [(c, 2) for _, c in scored]

    # Clamp selection.
    if not visible:
        state.selected = 0
    else:
        state.selected = max(0, min(state.selected, len(visible) - 1))

    rows: List[Text] = []
    # Header: query line.
    header = Text()
    header.append(" > ", style=f"bold {primary}")
    header.append(state.query or "Type to search commands...", style=text if state.query else muted)
    header.append("\u2588", style=f"bold {primary}")  # caret
    rows.append(header)
    rows.append(Text(" " + "-" * (width - 4), style=muted))

    if not visible:
        rows.append(Text("  (no matches)", style=muted))
    else:
        last_section: Optional[int] = None
        for idx, (cmd, section) in enumerate(visible):
            # Section header.
            if section != last_section:
                if section == 0:
                    rows.append(Text(" RECENT", style=f"bold {primary}"))
                elif section == 1:
                    rows.append(Text(" ALL COMMANDS", style=f"bold {primary}"))
                elif section == 2:
                    rows.append(Text(f" RESULTS FOR '{state.query}'", style=f"bold {primary}"))
                last_section = section
            color = highlight if idx == state.selected else text
            row = Text()
            row.append("  ", style="")
            row.append("\u25b8" if idx == state.selected else " ", style=f"bold {primary}")
            row.append(f" {cmd.title:<28s}", style=f"bold {color}")
            row.append(f" {cmd.category:<10s}", style=muted)
            if cmd.shortcut:
                row.append(f" [{cmd.shortcut}]", style=f"bold {primary}")
            if cmd.description:
                row.append(f"  {cmd.description[:40]}", style=muted)
            rows.append(row)

    rows.append(Text(" " + "-" * (width - 4), style=muted))
    footer = Text()
    footer.append(" \u2191\u2193 ", style=f"bold {primary}")
    footer.append("navigate  ", style=muted)
    footer.append("Enter ", style=f"bold {primary}")
    footer.append("run  ", style=muted)
    footer.append("Esc ", style=f"bold {primary}")
    footer.append("close  ", style=muted)
    footer.append("Tab ", style=f"bold {primary}")
    footer.append("recents  ", style=muted)
    rows.append(footer)

    return Panel(
        Group(*rows),
        title="[bold]COMMAND PALETTE[/bold]",
        border_style=primary,
        box=HEAVY,
        padding=(0, 1),
        width=width,
    )


# ---------------------------------------------------------------------------
# Textual widget
# ---------------------------------------------------------------------------


class CommandPalette(ModalScreen):
    """Modal command palette with fuzzy search and recent-commands pinning.

    Bindings:
        * ``Esc``   - close
        * ``Enter`` - run selected command
        * ``Up``    - move selection up
        * ``Down``  - move selection down
        * ``Tab``   - toggle recents section
        * ``Ctrl+R``- clear query
    """

    BINDINGS = [
        ("escape",    "close_palette",  "Close"),
        ("enter",     "run_command",    "Run"),
        ("up",        "move_up",        "Up"),
        ("down",      "move_down",      "Down"),
        ("tab",       "toggle_recents", "Toggle recents"),
        ("ctrl+r",    "clear_query",    "Clear"),
    ]

    DEFAULT_CSS = """
    CommandPalette {
        align: center middle;
        background: rgba(0,0,0,180);
    }
    CommandPalette > #palette-container {
        width: 80;
        height: auto;
        max-height: 80%;
        border: heavy #ff2222;
        background: #0d0d0d;
        padding: 0 1;
    }
    CommandPalette Input {
        border: none;
        background: #0d0d0d;
        color: #ffffff;
        height: 3;
    }
    CommandPalette #palette-results {
        height: auto;
    }
    """

    query_text = reactive("")

    def __init__(
        self,
        commands: Optional[Sequence[Command]] = None,
        primary: str = "#ff2222",
        text: str = "#ffffff",
        muted: str = "#888888",
        highlight: str = "#ff5555",
        **kwargs,
    ) -> None:
        super().__init__(**kwargs)
        self.commands: List[Command] = list(commands or DEFAULT_COMMANDS)
        self.primary = primary
        self.text = text
        self.muted = muted
        self.highlight = highlight
        self.state = _PaletteState()

    # -- Compose ------------------------------------------------------------

    def compose(self):
        with Container(id="palette-container"):
            yield Input(placeholder="Type to search commands...", id="palette-input")
            yield Static(id="palette-results")

    def on_mount(self) -> None:
        """Focus the input and render the initial list."""
        self.query_one("#palette-input", Input).focus()
        self._refresh_results()

    # -- Watchers -----------------------------------------------------------

    def watch_query_text(self, _: str) -> None:
        """React to query changes from the input."""
        self.state.query = self.query_text
        self.state.selected = 0
        self._refresh_results()

    # -- Input handling ------------------------------------------------------

    def on_input_changed(self, event: Input.Changed) -> None:
        """Forward input changes to the reactive query."""
        self.query_text = event.value

    def on_input_submitted(self, event: Input.Submitted) -> None:
        """Run the selected command when the user hits Enter."""
        self.action_run_command()

    # -- Actions ------------------------------------------------------------

    def action_close_palette(self) -> None:
        """Dismiss the palette."""
        self.dismiss(None)

    def action_run_command(self) -> None:
        """Execute the currently selected command (if any)."""
        chosen = self._selected_command()
        if chosen is None:
            return
        # Promote to recents.
        if chosen.id in self.state.recents:
            self.state.recents.remove(chosen.id)
        self.state.recents.insert(0, chosen.id)
        self.state.recents = self.state.recents[:5]
        # Run callback if provided.
        if chosen.callback is not None:
            try:
                chosen.callback()
            except Exception as exc:  # pragma: no cover - defensive
                logger.warning("Command '%s' callback raised: %s", chosen.id, exc)
        self.dismiss(chosen)

    def action_move_up(self) -> None:
        """Move the selection up."""
        self.state.selected = max(0, self.state.selected - 1)
        self._refresh_results()

    def action_move_down(self) -> None:
        """Move the selection down."""
        # The list length changes; the render helper will clamp.
        self.state.selected += 1
        self._refresh_results()

    def action_toggle_recents(self) -> None:
        """Toggle the recents section visibility."""
        self.state.show_recents = not self.state.show_recents
        self._refresh_results()

    def action_clear_query(self) -> None:
        """Clear the search query."""
        self.query_one("#palette-input", Input).value = ""
        self.query_text = ""

    # -- Internal helpers ---------------------------------------------------

    def _selected_command(self) -> Optional[Command]:
        # We need to re-compute the visible list to know which one is selected.
        visible = self._visible_commands()
        if not visible:
            return None
        idx = min(self.state.selected, len(visible) - 1)
        return visible[idx]

    def _visible_commands(self) -> List[Command]:
        """Compute the current visible command list (in order)."""
        visible: List[Command] = []
        if self.state.show_recents and not self.state.query:
            for c in self.commands:
                if c.id in self.state.recents:
                    visible.append(c)
            for c in self.commands:
                if c.id not in self.state.recents:
                    visible.append(c)
        else:
            scored: List[Tuple[int, Command]] = []
            for c in self.commands:
                haystack = " ".join([c.title, c.category, c.description, *c.keywords])
                s = fuzzy_score(self.state.query, haystack) + fuzzy_score(self.state.query, c.title)
                if s > 0:
                    scored.append((s, c))
            scored.sort(key=lambda x: -x[0])
            visible = [c for _, c in scored]
        return visible

    def _refresh_results(self) -> None:
        widget = self.query_one("#palette-results", Static)
        widget.update(
            render_palette(
                self.commands,
                self.state,
                width=78,
                primary=self.primary,
                text=self.text,
                muted=self.muted,
                highlight=self.highlight,
            )
        )


# ---------------------------------------------------------------------------
# Convenience helpers
# ---------------------------------------------------------------------------


def build_palette(
    commands: Optional[Sequence[Command]] = None,
    primary: str = "#ff2222",
    text: str = "#ffffff",
    muted: str = "#888888",
) -> CommandPalette:
    """Construct a :class:`CommandPalette` populated with ``commands``.

    If ``commands`` is ``None``, the default catalogue is used.
    """
    return CommandPalette(
        commands=commands,
        primary=primary,
        text=text,
        muted=muted,
    )


__all__ = [
    "Command",
    "CommandPalette",
    "DEFAULT_COMMANDS",
    "fuzzy_match",
    "fuzzy_score",
    "render_palette",
    "build_palette",
]
