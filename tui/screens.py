"""tui/screens.py - Native Textual screens replacing questionary menus.

run_main_menu() previously cleared the screen and used questionary.select
in a while-True loop, losing scrollback context. These screens provide the
same navigation (scan/tools/settings/memory/recon/reports/help) as Textual
widgets with full keyboard support, while the questionary path is kept as a
non-TTY fallback.
"""

from __future__ import annotations

import sys
from typing import Callable, Dict, List, Optional

try:
    from textual.app import App, ComposeResult
    from textual.containers import Vertical
    from textual.screen import ModalScreen
    from textual.widgets import Footer, Header, Input, ListItem, ListView, Static

    _TEXTUAL = True
except ImportError:  # pragma: no cover - minimal envs
    _TEXTUAL = False
    from typing import Any

    App = Any  # type: ignore
    ComposeResult = Any  # type: ignore
    ModalScreen = Any  # type: ignore
    Vertical = Any  # type: ignore
    Footer = Any  # type: ignore
    ListItem = Any  # type: ignore
    ListView = Any  # type: ignore
    Static = Any  # type: ignore


def is_tty() -> bool:
    """True when a full-screen Textual menu is usable (real terminal)."""
    try:
        return bool(sys.stdin.isatty() and sys.stdout.isatty())
    except Exception:
        return False


MENU_ENTRIES: List[Dict[str, str]] = [
    {"key": "scan", "title": "Scan Target", "desc": "Run security scan on a target"},
    {"key": "recon", "title": "Reconnaissance", "desc": "DNS, HTTP, port discovery"},
    {"key": "tools", "title": "Security Tools", "desc": "Access individual scanners"},
    {"key": "reports", "title": "View Reports", "desc": "Browse past scan reports"},
    {"key": "memory", "title": "AI Memory", "desc": "Search and manage AI memory"},
    {"key": "settings", "title": "Settings", "desc": "Theme, providers, configuration"},
    {"key": "help", "title": "Help", "desc": "Commands and shortcuts"},
    {"key": "exit", "title": "Exit", "desc": "Exit Elengenix"},
]

SCAN_ENTRIES: List[Dict[str, str]] = [
    {"key": "quick", "title": "Quick Scan", "desc": "Fast vulnerability scan"},
    {"key": "full", "title": "Full Scan", "desc": "Comprehensive security assessment"},
    {"key": "custom", "title": "Custom Scan", "desc": "Choose specific scanners"},
    {"key": "back", "title": "Back", "desc": "Return to main menu"},
]


class MenuScreen(ModalScreen):  # type: ignore[valid-type,misc]
    """Generic single-level menu; returns the selected entry key or None."""

    def __init__(self, title: str, entries: List[Dict[str, str]]) -> None:
        super().__init__()
        self._title = title
        self._entries = entries

    def compose(self):  # type: ignore[no-untyped-def]
        yield Static(f"  {self._title}  (up/down navigate, Enter select, Esc back)")  # type: ignore[operator]
        with Vertical():  # type: ignore[operator]
            items = [
                ListItem(Static(f"{e['title']}  --  {e['desc']}"), id=f"m-{e['key']}")  # type: ignore[operator]
                for e in self._entries
            ]
            yield ListView(*items, id="menu-list")  # type: ignore[operator]
        yield Footer()  # type: ignore[operator]

    def on_mount(self) -> None:
        try:
            self.query_one("#menu-list", ListView).focus()  # type: ignore[arg-type]
        except Exception:
            pass

    def on_list_view_selected(self, event) -> None:
        try:
            selected_id = event.item.id or ""
            key = selected_id[2:] if selected_id.startswith("m-") else selected_id
        except Exception:
            key = ""
        self.dismiss(key or None)

    def on_key(self, event) -> None:
        if event.key == "escape":
            event.stop()
            self.dismiss(None)


class MenuApp(App):  # type: ignore
    """Minimal standalone menu app for `elengenix menu` on real terminals."""

    CSS = """
    MenuScreen { align: center middle; }
    MenuScreen Vertical { width: 72; height: auto; max-height: 80%; border: solid #444444; background: #0d0d0d; }
    MenuScreen ListView { height: auto; max-height: 20; }
    """

    def __init__(self, on_select: Optional[Callable[[str], None]] = None) -> None:
        super().__init__()
        self._on_select = on_select

    def on_mount(self) -> None:
        self.push_screen(MenuScreen("ELENGENIX MAIN MENU", MENU_ENTRIES), self._picked)

    def _picked(self, key: Optional[str]) -> None:
        if not key or key == "exit":
            self.exit()
            return
        if self._on_select is not None:
            try:
                self._on_select(key)
            except Exception:
                pass
        # Re-show the menu after the action completes.
        try:
            self.push_screen(MenuScreen("ELENGENIX MAIN MENU", MENU_ENTRIES), self._picked)
        except Exception:
            self.exit()


def run_textual_menu(on_select: Optional[Callable[[str], None]] = None) -> bool:
    """Run the native Textual menu. Returns True if it ran, False to fallback."""
    if not _TEXTUAL or not is_tty():
        return False
    try:
        MenuApp(on_select=on_select).run()
        return True
    except Exception:
        return False


__all__ = [
    "MENU_ENTRIES",
    "SCAN_ENTRIES",
    "MenuScreen",
    "MenuApp",
    "run_textual_menu",
    "is_tty",
]
