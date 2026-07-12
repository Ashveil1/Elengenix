"""redteam_agent — DEPRECATED: Legacy autonomous red-team agent.

This directory is no longer maintained. All functionality has been
superseded by elengix/ (core cognitive loop) and elengix/scanning/
(autonomous scanning pipeline). Kept only to prevent import errors
for any remaining references.
"""

import warnings

warnings.warn(
    "redteam_agent is deprecated and will be removed in a future release. "
    "Use elengix/ instead.",
    DeprecationWarning,
    stacklevel=2,
)
