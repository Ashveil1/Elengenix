"""elengenix/chat/agent.py — Singleton factory for the chat agent.

Relocated from the deprecated root-level ``core/agent.py`` during the
architecture consolidation.
"""

import logging

from elengenix.chat.brain import ElengenixAgent

logger = logging.getLogger(__name__)

_agent_instance = None


def get_agent() -> ElengenixAgent:
    """Return the singleton ElengenixAgent instance.

    Used by ``cli/textual.py`` and ``cli/interactive.py``.
    """
    global _agent_instance
    if _agent_instance is None:
        logger.info("Initialising ElengenixAgent")
        _agent_instance = ElengenixAgent()
    return _agent_instance
