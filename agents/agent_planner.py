"""agents/agent_planner.py — Strategic planning module (DEPRECATED).

This module now re-exports from elengenix.scanning.planner for backward
compatibility. New code should import from elengenix.scanning.planner directly.

Deprecated import:  from agents.agent_planner import StrategicPlanner, TargetFingerprinter
                    → from elengenix.scanning.planner import StrategicPlanner, TargetFingerprinter
"""

import warnings

from elengenix.scanning.planner import (
    AttackVectorDatabase,
    StrategicPlanner,
    TargetFingerprinter,
)

warnings.warn(
    "agents.agent_planner is deprecated; import from elengenix.scanning.planner instead",
    DeprecationWarning,
    stacklevel=2,
)

__all__ = [
    "AttackVectorDatabase",
    "StrategicPlanner",
    "TargetFingerprinter",
]
