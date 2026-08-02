"""agents/vuln_reasoning_phase.py — Autonomous vulnerability reasoning (DEPRECATED).

This module now re-exports from elengenix.scanning.vuln_reasoning_phase for
backward compatibility. New code should import from
elengenix.scanning.vuln_reasoning_phase directly.

Deprecated import:  from agents.vuln_reasoning_phase import run_reasoning_phase
                    → from elengenix.scanning.vuln_reasoning_phase import run_reasoning_phase
"""

import warnings

from elengenix.scanning.vuln_reasoning_phase import (
    DEFAULT_MIN_CONFIDENCE,
    _dataclass_to_dict,
    _get_reasoning_engine,
    _hypothesis_to_finding,
    run_reasoning_phase,
)

warnings.warn(
    "agents.vuln_reasoning_phase is deprecated; import from elengenix.scanning.vuln_reasoning_phase instead",
    DeprecationWarning,
    stacklevel=2,
)

__all__ = [
    "DEFAULT_MIN_CONFIDENCE",
    "_dataclass_to_dict",
    "_get_reasoning_engine",
    "_hypothesis_to_finding",
    "run_reasoning_phase",
]
