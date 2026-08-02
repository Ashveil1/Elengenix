"""agents/scan_loop.py — Main Scan Loop (DEPRECATED).

This module now re-exports from elengenix.scanning.scan_loop for backward
compatibility. New code should import from elengenix.scanning.scan_loop
directly.

Deprecated import:  from agents.scan_loop import ScanLoop, ScanResult
                    → from elengenix.scanning.scan_loop import ScanLoop, ScanResult
"""

import warnings

from elengenix.scanning.scan_loop import ScanLoop, ScanResult

warnings.warn(
    "agents.scan_loop is deprecated; import from elengenix.scanning.scan_loop instead",
    DeprecationWarning,
    stacklevel=2,
)

__all__ = [
    "ScanLoop",
    "ScanResult",
]
