"""agents/ — Elengenix agent modules package (DEPRECATED).

This package now re-exports from elengenix.scanning for backward compatibility.
New code should import from elengenix.scanning directly.

Deprecated import:  from agents.scan_loop import ScanLoop   → from elengenix.scanning.scan_loop import ScanLoop
                    from agents.decision_engine import ...   → from elengenix.scanning.decision_engine import ...
                    from agents.scan_context import ...      → from elengenix.scanning.scan_context import ...
                    from agents.post_processor import ...    → from elengenix.scanning.post_processor import ...
                    from agents.prompt_builder import ...    → from elengenix.scanning.prompt_builder import ...
"""

import warnings

from elengenix.scanning.decision_engine import Decision, DecisionEngine
from elengenix.scanning.post_processor import PostExecutionProcessor
from elengenix.scanning.prompt_builder import PromptBuilder
from elengenix.scanning.scan_context import ScanContext
from elengenix.scanning.scan_loop import ScanLoop, ScanResult

warnings.warn(
    "agents/ is deprecated; import from elengenix.scanning instead",
    DeprecationWarning,
    stacklevel=2,
)

__all__ = [
    "Decision",
    "DecisionEngine",
    "PostExecutionProcessor",
    "PromptBuilder",
    "ScanContext",
    "ScanLoop",
    "ScanResult",
]
