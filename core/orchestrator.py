"""core/orchestrator.py — DEPRECATED: Re-exports from pipeline/scope and pipeline/unified.

This module is deprecated. New code should import directly from:
  - pipeline.scope for target validation/scope functions
  - pipeline.unified for pipeline functions
"""

import warnings

warnings.warn(
    "core.orchestrator is deprecated; use pipeline.scope / pipeline.unified instead.",
    DeprecationWarning,
    stacklevel=2,
)

# ── Re-export from pipeline/scope ──────────────────────────────────
from pipeline.scope import (
    is_in_scope,
    is_valid_target,
    load_allowed_domains,
    normalize_target,
    sanitize_path,
)

# ── Re-export from pipeline/unified ────────────────────────────────
from pipeline.unified import _recon_to_findings

# ── Stubs for functions not yet ported ──────────────────────────────

def reload_scope() -> None:
    """Deprecated. Use pipeline.scope.ScopeManager.reload() instead."""
    from pipeline.scope import ScopeManager
    ScopeManager().reload()


def normalize_targets(target: str):
    """Deprecated stub."""
    warnings.warn(
        "normalize_targets is deprecated and has no pipeline equivalent.",
        DeprecationWarning,
        stacklevel=2,
    )
    return [normalize_target(target)]


def are_targets_in_scope(targets: list[str]) -> bool:
    """Deprecated stub."""
    return all(is_in_scope(t) for t in targets)


def get_recommended_tool_chain(target_type: str = "web"):
    """Deprecated stub."""
    warnings.warn(
        "get_recommended_tool_chain is deprecated and has no pipeline equivalent.",
        DeprecationWarning,
        stacklevel=2,
    )
    return []


def _suggest_missing_tools(*args, **kwargs):
    """Deprecated stub."""
    return []


def _manual_cmd(tool_name: str) -> str:
    """Deprecated stub."""
    return ""


def calculate_cvss_for_results(*args, **kwargs):
    """Deprecated stub."""
    return []


def print_findings_summary(*args, **kwargs):
    """Deprecated stub."""
    pass


def http_get_cached(*args, **kwargs):
    """Deprecated stub."""
    return None


def _check_cves_for_tech(*args, **kwargs):
    """Deprecated stub."""
    return []


def _check_cves_for_tech_cached(*args, **kwargs):
    """Deprecated stub."""
    return []


def _prepare_scan_targets(*args, **kwargs):
    """Deprecated stub."""
    return [], 0


def _send_telegram_async(*args, **kwargs):
    """Deprecated stub."""
    pass


def _print_scan_banner(*args, **kwargs):
    """Deprecated stub."""
    pass


def _save_findings(*args, **kwargs):
    """Deprecated stub."""
    pass


def _handle_timeout(*args, **kwargs):
    """Deprecated stub."""
    return None


def _handle_interrupt(*args, **kwargs):
    """Deprecated stub."""
    return None


def _handle_error(*args, **kwargs):
    """Deprecated stub."""
    return None


async def run_standard_scan(
    target: str,
    report_dir,
    tools: list | None = None,
    **kwargs,
):
    """Deprecated stub. Core scanning is now handled by elengix.scanning."""
    warnings.warn(
        "run_standard_scan is deprecated; use elengix.scanning instead.",
        DeprecationWarning,
        stacklevel=2,
    )
    return None, None


async def run_elengenix_modules(*args, **kwargs):
    """Deprecated stub."""
    warnings.warn(
        "run_elengenix_modules is deprecated; use elengix.scanning instead.",
        DeprecationWarning,
        stacklevel=2,
    )
    return None


class Orchestrator:
    """Deprecated stub. No-op placeholder."""
    def __init__(self, *args, **kwargs):
        pass

    def __getattr__(self, name):
        return lambda *a, **kw: None


SmartOrchestrator = Orchestrator
