"""agents/strategist_agent.py — StrategistAgent for TeamAegis v2 (DEPRECATED).

This module now re-exports from elengenix.scanning.strategist for backward
compatibility. New code should import from elengenix.scanning.strategist
directly.

Deprecated import:  from agents.strategist_agent import StrategistAgent
                    → from elengenix.scanning.strategist import StrategistAgent
"""

import warnings

from elengenix.scanning.strategist import OsintWorker, ReconWorker, StrategistAgent

warnings.warn(
    "agents.strategist_agent is deprecated; import from elengenix.scanning.strategist instead",
    DeprecationWarning,
    stacklevel=2,
)

__all__ = [
    "OsintWorker",
    "ReconWorker",
    "StrategistAgent",
]
