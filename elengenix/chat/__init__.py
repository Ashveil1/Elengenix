"""elengenix/chat/ — Conversational agent for the TUI / CLI / Telegram bot.

This package hosts the interactive "chat brain" (ElengenixAgent) that powers
``cli/textual.py``, ``cli/interactive.py`` and ``integrations/bot.py``.

It was relocated from the deprecated root-level ``core/brain.py`` during the
architecture consolidation. Reusable scanning/intent helpers live in
``elengenix.scanning`` — this package only contains glue specific to the
interactive chat experience.
"""

from elengenix.chat.agent import get_agent
from elengenix.chat.brain import ElengenixAgent

__all__ = [
    "ElengenixAgent",
    "get_agent",
]
