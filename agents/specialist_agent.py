"""agents/specialist_agent.py — SpecialistAgent for TeamAegis v2 (DEPRECATED).

This module now re-exports from elengenix.scanning.specialist for backward
compatibility. New code should import from elengenix.scanning.specialist
directly.

Deprecated import:  from agents.specialist_agent import SpecialistAgent
                    → from elengenix.scanning.specialist import SpecialistAgent
"""

import warnings

from elengenix.scanning.specialist import ExploitWorker, FuzzerWorker, SpecialistAgent

warnings.warn(
    "agents.specialist_agent is deprecated; import from elengenix.scanning.specialist instead",
    DeprecationWarning,
    stacklevel=2,
)

__all__ = [
    "ExploitWorker",
    "FuzzerWorker",
    "SpecialistAgent",
]
