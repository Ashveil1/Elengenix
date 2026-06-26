"""tui/keyboard_shortcuts.py - Keyboard shortcuts system for Elengenix TUI.

Provides:
    * :class:`KeyboardShortcutManager` - Manages keyboard shortcuts
    * :class:`KeyboardShortcut` - Single shortcut definition
    * :func:`render_shortcuts_help` - Render shortcuts help panel

Features:
    - Global shortcuts (work everywhere)
    - Context-specific shortcuts (work in specific views)
    - Shortcut categories (navigation, actions, view)
    - Help overlay with all shortcuts
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Tuple

from rich.align import Align
from rich.box import HEAVY, ROUNDED, SIMPLE
from rich.console import Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

logger = logging.getLogger("elengenix.tui.keyboard_shortcuts")


class ShortcutCategory(Enum):
    """Categories for keyboard shortcuts."""

    NAVIGATION = "navigation"
    ACTION = "action"
    VIEW = "view"
    EDIT = "edit"
    SYSTEM = "system"


@dataclass
class KeyboardShortcut:
    """A single keyboard shortcut definition."""

    key: str
    description: str
    action: str
    category: ShortcutCategory = ShortcutCategory.ACTION
    context: Optional[str] = None  # None = global, otherwise view name
    enabled: bool = True

    def __str__(self) -> str:
        return f"{self.key}: {self.description}"


class KeyboardShortcutManager:
    """Manages keyboard shortcuts for the TUI.

    Features:
        - Global shortcuts (work everywhere)
        - Context-specific shortcuts (work in specific views)
        - Shortcut categories (navigation, actions, view)
        - Help overlay with all shortcuts

    Example:
        manager = KeyboardShortcutManager()
        manager.register("Ctrl+S", "Save", "save", ShortcutCategory.ACTION)
        manager.register("Ctrl+Q", "Quit", "quit", ShortcutCategory.SYSTEM)

        action = manager.get_action("Ctrl+S")
        # Returns "save"
    """

    def __init__(self):
        self.shortcuts: List[KeyboardShortcut] = []
        self._action_handlers: Dict[str, Callable] = {}
        self._current_context: Optional[str] = None

    def register(
        self,
        key: str,
        description: str,
        action: str,
        category: ShortcutCategory = ShortcutCategory.ACTION,
        context: Optional[str] = None,
    ) -> None:
        """Register a keyboard shortcut.

        Args:
            key: Key combination (e.g., "Ctrl+S", "F1", "a").
            description: Human-readable description.
            action: Action identifier to execute.
            category: Shortcut category.
            context: View context (None = global).
        """
        shortcut = KeyboardShortcut(
            key=key,
            description=description,
            action=action,
            category=category,
            context=context,
        )
        self.shortcuts.append(shortcut)

    def register_handler(self, action: str, handler: Callable) -> None:
        """Register a handler for an action.

        Args:
            action: Action identifier.
            handler: Callable to execute when action is triggered.
        """
        self._action_handlers[action] = handler

    def set_context(self, context: Optional[str]) -> None:
        """Set the current view context.

        Args:
            context: View name or None for global.
        """
        self._current_context = context

    def get_action(self, key: str) -> Optional[str]:
        """Get the action for a key combination.

        Args:
            key: Key combination to look up.

        Returns:
            Action identifier or None if not found.
        """
        # First check context-specific shortcuts
        if self._current_context:
            for shortcut in self.shortcuts:
                if (
                    shortcut.key == key
                    and shortcut.context == self._current_context
                    and shortcut.enabled
                ):
                    return shortcut.action

        # Then check global shortcuts
        for shortcut in self.shortcuts:
            if shortcut.key == key and shortcut.context is None and shortcut.enabled:
                return shortcut.action

        return None

    def execute(self, key: str) -> bool:
        """Execute the action for a key combination.

        Args:
            key: Key combination to execute.

        Returns:
            True if action was executed, False otherwise.
        """
        action = self.get_action(key)
        if action and action in self._action_handlers:
            try:
                self._action_handlers[action]()
                return True
            except Exception as e:
                logger.error(f"Error executing action {action}: {e}")
                return False
        return False

    def get_shortcuts(
        self,
        category: Optional[ShortcutCategory] = None,
        context: Optional[str] = None,
        include_global: bool = True,
    ) -> List[KeyboardShortcut]:
        """Get shortcuts filtered by category and context.

        Args:
            category: Filter by category (None = all).
            context: Filter by context (None = all).
            include_global: Include global shortcuts.

        Returns:
            List of matching shortcuts.
        """
        result = []
        for shortcut in self.shortcuts:
            if not shortcut.enabled:
                continue
            if category and shortcut.category != category:
                continue
            if context and shortcut.context is not None and shortcut.context != context:
                continue
            if not include_global and shortcut.context is None:
                continue
            result.append(shortcut)
        return result

    def render_help(
        self,
        primary: str = "#ff2222",
        text_color: str = "#ffffff",
        muted: str = "#888888",
        context: Optional[str] = None,
    ) -> Panel:
        """Render keyboard shortcuts help panel.

        Args:
            primary: Primary theme color.
            text_color: Main text color.
            muted: Muted text color.
            context: Current context to show context-specific shortcuts.

        Returns:
            Rich Panel with shortcuts help.
        """
        # Group shortcuts by category
        categories = {}
        for shortcut in self.get_shortcuts(context=context):
            cat = shortcut.category.value
            if cat not in categories:
                categories[cat] = []
            categories[cat].append(shortcut)

        # Build table
        table = Table(
            show_header=True,
            header_style=f"bold {primary}",
            box=SIMPLE,
            padding=(0, 1),
            expand=True,
        )
        table.add_column("Key", style=f"bold {text_color}", width=15)
        table.add_column("Action", style=text_color, width=25)
        table.add_column("Description", style=muted)

        # Add shortcuts by category
        category_order = [
            ShortcutCategory.NAVIGATION.value,
            ShortcutCategory.ACTION.value,
            ShortcutCategory.VIEW.value,
            ShortcutCategory.EDIT.value,
            ShortcutCategory.SYSTEM.value,
        ]

        for cat_name in category_order:
            if cat_name in categories:
                for shortcut in categories[cat_name]:
                    # Highlight key
                    key_text = Text(f" {shortcut.key} ", style=f"bold white on {primary}")
                    table.add_row(
                        key_text,
                        shortcut.action,
                        shortcut.description,
                    )

        return Panel(
            table,
            title=f"[bold {primary}]KEYBOARD SHORTCUTS[/bold {primary}]",
            border_style=primary,
            box=ROUNDED,
            padding=(0, 1),
        )


# Default shortcuts for Elengenix TUI
DEFAULT_SHORTCUTS = [
    # Navigation
    ("Ctrl+N", "Next item", "next", ShortcutCategory.NAVIGATION),
    ("Ctrl+P", "Previous item", "previous", ShortcutCategory.NAVIGATION),
    ("Tab", "Next field", "next_field", ShortcutCategory.NAVIGATION),
    ("Shift+Tab", "Previous field", "prev_field", ShortcutCategory.NAVIGATION),
    ("Up", "Move up", "move_up", ShortcutCategory.NAVIGATION),
    ("Down", "Move down", "move_down", ShortcutCategory.NAVIGATION),
    ("Left", "Move left", "move_left", ShortcutCategory.NAVIGATION),
    ("Right", "Move right", "move_right", ShortcutCategory.NAVIGATION),
    # Actions
    ("Enter", "Select/Confirm", "select", ShortcutCategory.ACTION),
    ("Escape", "Cancel/Back", "cancel", ShortcutCategory.ACTION),
    ("Ctrl+S", "Save", "save", ShortcutCategory.ACTION),
    ("Ctrl+Z", "Undo", "undo", ShortcutCategory.ACTION),
    ("Ctrl+Y", "Redo", "redo", ShortcutCategory.ACTION),
    ("Delete", "Delete item", "delete", ShortcutCategory.ACTION),
    # View
    ("F1", "Show help", "help", ShortcutCategory.VIEW),
    ("F5", "Refresh view", "refresh", ShortcutCategory.VIEW),
    ("F11", "Toggle fullscreen", "fullscreen", ShortcutCategory.VIEW),
    ("Ctrl+F", "Search/Filter", "search", ShortcutCategory.VIEW),
    ("Ctrl+G", "Go to", "goto", ShortcutCategory.VIEW),
    # System
    ("Ctrl+Q", "Quit", "quit", ShortcutCategory.SYSTEM),
    ("Ctrl+C", "Copy", "copy", ShortcutCategory.SYSTEM),
    ("Ctrl+V", "Paste", "paste", ShortcutCategory.SYSTEM),
    ("Ctrl+Shift+P", "Command palette", "command_palette", ShortcutCategory.SYSTEM),
]


def create_default_shortcut_manager() -> KeyboardShortcutManager:
    """Create a KeyboardShortcutManager with default shortcuts.

    Returns:
        KeyboardShortcutManager with default shortcuts registered.
    """
    manager = KeyboardShortcutManager()

    for key, desc, action, category in DEFAULT_SHORTCUTS:
        manager.register(key, desc, action, category)

    return manager


def render_shortcuts_help(
    primary: str = "#ff2222",
    text_color: str = "#ffffff",
    muted: str = "#888888",
    context: Optional[str] = None,
) -> Panel:
    """Render keyboard shortcuts help as a standalone Rich Panel.

    Args:
        primary: Primary theme color.
        text_color: Main text color.
        muted: Muted text color.
        context: Current context.

    Returns:
        Rich Panel with shortcuts help.
    """
    manager = create_default_shortcut_manager()
    return manager.render_help(
        primary=primary,
        text_color=text_color,
        muted=muted,
        context=context,
    )
