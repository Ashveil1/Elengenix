"""agents/critic_agent.py — CriticAgent for TeamAegis v2 (DEPRECATED).

This module now re-exports from elengenix.scanning.critic for backward
compatibility. New code should import from elengenix.scanning.critic directly.

Deprecated import:  from agents.critic_agent import CriticAgent
                    → from elengenix.scanning.critic import CriticAgent
"""

import warnings

from elengenix.scanning.critic import CriticAgent, ReportWorker, ValidatorWorker

warnings.warn(
    "agents.critic_agent is deprecated; import from elengenix.scanning.critic instead",
    DeprecationWarning,
    stacklevel=2,
)

__all__ = [
    "CriticAgent",
    "ReportWorker",
    "ValidatorWorker",
]
