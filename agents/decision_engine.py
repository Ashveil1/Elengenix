"""agents/decision_engine.py — AI Decision Engine (DEPRECATED).

This module now re-exports from elengenix.scanning.decision_engine for
backward compatibility. New code should import from
elengenix.scanning.decision_engine directly.

Deprecated import:  from agents.decision_engine import DecisionEngine
                    → from elengenix.scanning.decision_engine import DecisionEngine
"""

import warnings

from elengenix.scanning.decision_engine import Decision, DecisionEngine, Reflection

warnings.warn(
    "agents.decision_engine is deprecated; import from elengenix.scanning.decision_engine instead",
    DeprecationWarning,
    stacklevel=2,
)

__all__ = [
    "Decision",
    "DecisionEngine",
    "Reflection",
]
