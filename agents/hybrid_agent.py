"""agents/hybrid_agent.py — Elengenix hybrid agent module (DEPRECATED).

This module now re-exports from elengenix.scanning.hybrid_agent for backward
compatibility. New code should import from elengenix.scanning.hybrid_agent directly.

Deprecated import:  from agents.hybrid_agent import HybridAgent
                    → from elengenix.scanning.hybrid_agent import HybridAgent
"""

import warnings

from elengenix.scanning.hybrid_agent import HybridAgent

warnings.warn(
    "agents.hybrid_agent is deprecated; import from elengenix.scanning.hybrid_agent instead",
    DeprecationWarning,
    stacklevel=2,
)

__all__ = [
    "HybridAgent",
]
