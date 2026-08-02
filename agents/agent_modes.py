"""agents/agent_modes.py — Elengenix mode processing module (DEPRECATED).

This module now re-exports from elengenix.scanning.modes for backward
compatibility. New code should import from elengenix.scanning.modes directly.

Deprecated import:  from agents.agent_modes import ModeProcessor
                    → from elengenix.scanning.modes import ModeProcessor
"""

import warnings

from elengenix.scanning.modes import ModeProcessor

warnings.warn(
    "agents.agent_modes is deprecated; import from elengenix.scanning.modes instead",
    DeprecationWarning,
    stacklevel=2,
)

__all__ = [
    "ModeProcessor",
]
