"""elengenix/paths.py — Centralized path resolution for Elengenix.

All file-system paths used by Elengenix should go through this module.
This ensures pip-installed copies work correctly — user data always
lives under ~/.elengenix/, never in site-packages.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Optional

logger = logging.getLogger("elengenix.paths")

# ── User home directory (pip-safe) ───────────────────────────────
ELENGENIX_HOME = Path("~/.elengenix").expanduser()

# Subdirectory layout
ELENGENIX_DIRS = {
    "data": ELENGENIX_HOME / "data",
    "tools": ELENGENIX_HOME / "tools",
    "reports": ELENGENIX_HOME / "reports",
    "scripts": ELENGENIX_HOME / "scripts",
    "plugins": ELENGENIX_HOME / "plugins",
}


def get_data_path(name: str) -> Path:
    """Return ~/.elengenix/data/{name}, creating dirs as needed."""
    p = ELENGENIX_DIRS["data"] / name
    p.parent.mkdir(parents=True, exist_ok=True)
    return p


def get_reports_path(subdir: str = "") -> Path:
    """Return ~/.elengenix/reports[/{subdir}], creating dirs as needed."""
    p = ELENGENIX_DIRS["reports"] / subdir if subdir else ELENGENIX_DIRS["reports"]
    p.mkdir(parents=True, exist_ok=True)
    return p


def get_data_dir(subdir: str = "") -> Path:
    """Return ~/.elengenix/data[/{subdir}], creating dirs as needed."""
    p = ELENGENIX_DIRS["data"] / subdir if subdir else ELENGENIX_DIRS["data"]
    p.mkdir(parents=True, exist_ok=True)
    return p


def get_log_dir(subdir: str = "") -> Path:
    """Return ~/.elengenix/data/logs[/{subdir}], creating dirs as needed."""
    p = ELENGENIX_DIRS["data"] / "logs" / subdir if subdir else ELENGENIX_DIRS["data"] / "logs"
    p.mkdir(parents=True, exist_ok=True)
    return p


def get_tools_path(name: str) -> Path:
    """Return ~/.elengenix/tools/{name}, creating dirs as needed."""
    p = ELENGENIX_DIRS["tools"] / name
    p.parent.mkdir(parents=True, exist_ok=True)
    return p


def ensure_dirs() -> None:
    """Create all ~/.elengenix/ subdirectories on startup."""
    for d in ELENGENIX_DIRS.values():
        d.mkdir(parents=True, exist_ok=True)


# ── .env resolution (search order: env var > home > cwd) ────────
ENV_OVERRIDE = os.environ.get("ELENGENIX_ENV")


def find_env() -> Optional[Path]:
    """Locate .env using priority: ENV var → ~/.elengenix/ → cwd."""
    if ENV_OVERRIDE:
        p = Path(ENV_OVERRIDE).expanduser().resolve()
        if p.exists():
            return p
    for candidate in (ELENGENIX_HOME / ".env", Path(".env").resolve()):
        if candidate.exists():
            return candidate
    return None


# ── config.yaml resolution (search order: env var > home > cwd) ─
CONFIG_OVERRIDE = os.environ.get("ELENGENIX_CONFIG")


def find_config() -> Optional[Path]:
    """Locate config.yaml using priority: ENV var → ~/.elengenix/ → cwd."""
    if CONFIG_OVERRIDE:
        p = Path(CONFIG_OVERRIDE).expanduser().resolve()
        if p.exists():
            return p
    for candidate in (ELENGENIX_HOME / "config.yaml", Path("config.yaml").resolve()):
        if candidate.exists():
            return candidate
    return None
