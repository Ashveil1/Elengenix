"""agents/hybrid_prompts.py — Hybrid Agent prompts (DEPRECATED).

This module now re-exports from elengenix.scanning.hybrid_prompts for
backward compatibility. New code should import from
elengenix.scanning.hybrid_prompts directly.

Deprecated import:  from agents.hybrid_prompts import HYBRID_STRATEGIST_PROMPT
                    → from elengenix.scanning.hybrid_prompts import HYBRID_STRATEGIST_PROMPT
"""

import warnings

from elengenix.scanning.hybrid_prompts import (
    COUNCIL_DELIBERATION_PROMPT,
    CRITIC_PROMPT,
    HYBRID_GOVERNANCE_RULES,
    HYBRID_SPECIALIST_PROMPT,
    HYBRID_STRATEGIST_PROMPT,
    WORKER_EXPLOIT_PROMPT,
    WORKER_RECON_PROMPT,
)

warnings.warn(
    "agents.hybrid_prompts is deprecated; import from elengenix.scanning.hybrid_prompts instead",
    DeprecationWarning,
    stacklevel=2,
)

__all__ = [
    "COUNCIL_DELIBERATION_PROMPT",
    "CRITIC_PROMPT",
    "HYBRID_GOVERNANCE_RULES",
    "HYBRID_SPECIALIST_PROMPT",
    "HYBRID_STRATEGIST_PROMPT",
    "WORKER_EXPLOIT_PROMPT",
    "WORKER_RECON_PROMPT",
]
