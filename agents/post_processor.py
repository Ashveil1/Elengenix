"""agents/post_processor.py — Post-Execution Processing (DEPRECATED).

This module now re-exports from elengenix.scanning.post_processor for
backward compatibility. New code should import from
elengenix.scanning.post_processor directly.

Deprecated import:  from agents.post_processor import PostExecutionProcessor
                    → from elengenix.scanning.post_processor import PostExecutionProcessor
"""

import warnings

from elengenix.scanning.post_processor import PostExecutionProcessor

warnings.warn(
    "agents.post_processor is deprecated; import from elengenix.scanning.post_processor instead",
    DeprecationWarning,
    stacklevel=2,
)

__all__ = [
    "PostExecutionProcessor",
]
