"""agents/worker_base.py — Base class for TeamAegis sub-workers (DEPRECATED).

This module now re-exports from elengenix.scanning.worker for backward
compatibility. New code should import from elengenix.scanning.worker directly.

Deprecated import:  from agents.worker_base import BaseWorker, WorkerResult
                    → from elengenix.scanning.worker import BaseWorker, WorkerResult
"""

import warnings

from elengenix.scanning.worker import BaseWorker, WorkerResult

warnings.warn(
    "agents.worker_base is deprecated; import from elengenix.scanning.worker instead",
    DeprecationWarning,
    stacklevel=2,
)

__all__ = [
    "BaseWorker",
    "WorkerResult",
]
