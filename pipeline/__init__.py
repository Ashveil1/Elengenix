"""pipeline/ — DEPRECATED: Legacy pipeline modules.

This package is retained for test compatibility. New code should use
elengix/ (cognitive loop) and elengix/scanning/ directly instead of
pipeline.phase_registry, pipeline.scope, or pipeline.unified.
"""

import warnings

warnings.warn(
    "pipeline is deprecated; use elengix/ and elengix/scanning/ instead.",
    DeprecationWarning,
    stacklevel=2,
)
