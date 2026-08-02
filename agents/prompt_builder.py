"""agents/prompt_builder.py — AI Prompt Assembly (DEPRECATED).

This module now re-exports from elengenix.scanning.prompt_builder for
backward compatibility. New code should import from
elengenix.scanning.prompt_builder directly.

Deprecated import:  from agents.prompt_builder import PromptBuilder
                    → from elengenix.scanning.prompt_builder import PromptBuilder
"""

import warnings

from elengenix.scanning.prompt_builder import PromptBuilder

warnings.warn(
    "agents.prompt_builder is deprecated; import from elengenix.scanning.prompt_builder instead",
    DeprecationWarning,
    stacklevel=2,
)

__all__ = [
    "PromptBuilder",
]
