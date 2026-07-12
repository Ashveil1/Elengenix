"""core/scan_engine.py — DEPRECATED: Stub module.

This module is no longer maintained. The SmartOrchestrator class and
related functionality have been superseded by elengix/scanner modules.
"""

import warnings

warnings.warn(
    "core.scan_engine is deprecated; use elengix/scanning instead.",
    DeprecationWarning,
    stacklevel=2,
)


class SmartOrchestrator:
    """Deprecated stub. No-op placeholder."""
    def __init__(self, *args, **kwargs):
        pass

    def __getattr__(self, name):
        return lambda *a, **kw: None
