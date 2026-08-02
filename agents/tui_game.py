"""agents/tui_game.py — Mini 2D platformer (Obby) for Elengenix TUI (DEPRECATED).

This module now re-exports from elengenix.scanning.tui_game for backward
compatibility. New code should import from elengenix.scanning.tui_game
directly.

Deprecated import:  from agents.tui_game import ObbyGame
                    → from elengenix.scanning.tui_game import ObbyGame
"""

import warnings

from elengenix.scanning.tui_game import ObbyGame

warnings.warn(
    "agents.tui_game is deprecated; import from elengenix.scanning.tui_game instead",
    DeprecationWarning,
    stacklevel=2,
)

__all__ = [
    "ObbyGame",
]
