"""agents/hypothesis_boost.py — Hypothesis-driven boost for stuck scans (DEPRECATED).

This module now re-exports from elengenix.scanning.hypothesis_boost for
backward compatibility. New code should import from
elengenix.scanning.hypothesis_boost directly.

Deprecated import:  from agents.hypothesis_boost import HypothesisBoost
                    → from elengenix.scanning.hypothesis_boost import HypothesisBoost
"""

import warnings

from elengenix.scanning.hypothesis_boost import HypothesisBoost, build_stuck_guidance

warnings.warn(
    "agents.hypothesis_boost is deprecated; import from elengenix.scanning.hypothesis_boost instead",
    DeprecationWarning,
    stacklevel=2,
)

__all__ = [
    "HypothesisBoost",
    "build_stuck_guidance",
]
