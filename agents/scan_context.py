"""agents/scan_context.py — Elengenix scan context module (DEPRECATED).

This module now re-exports from elengenix.scanning.scan_context for backward
compatibility. New code should import from elengenix.scanning.scan_context directly.

Deprecated import:  from agents.scan_context import ScanContext
                    → from elengenix.scanning.scan_context import ScanContext
"""

import warnings

from elengenix.scanning.scan_context import ScanContext

warnings.warn(
    "agents.scan_context is deprecated; import from elengenix.scanning.scan_context instead",
    DeprecationWarning,
    stacklevel=2,
)

__all__ = [
    "ScanContext",
]
