"""core/orchestrator.py — DEPRECATED: Re-exports from elengenix/scope.

This module is deprecated. New code should import directly from:
  - elengenix.scope for target validation/scope functions

Will be removed in a future release.
"""

import warnings
from pathlib import Path as _Path

warnings.warn(
    "core.orchestrator is deprecated; use elengenix.scope instead.",
    DeprecationWarning,
    stacklevel=2,
)

# ── Re-export from elengenix/scope ──────────────────────────────────
from elengenix.scope import (  # noqa: F401, E402
    is_in_scope,
    is_valid_target,
    load_allowed_domains,
    normalize_target,
    sanitize_path,
)
from elengenix.scope import ScopeManager  # noqa: F401, E402

def run_standard_scan(
    target: str,
    rate_limit: int = 5,
    timeout: int = 600,
    use_registry: bool = True,
    tool_filter: str | None = None,
    use_smart_scan: bool = False,
) -> str | None:
    """Run a standard scan via VulnAgent (replaces legacy pipeline).

    Note: This is a deprecated compat shim. New code should use
    VulnAgent directly.
    """
    try:
        from elengenix.agent import VulnAgent
        from elengenix.agent.memory import AgentMemory
        from tools.universal_ai_client import create_default_client

        memory = AgentMemory()
        client = create_default_client()
        agent = VulnAgent(target=target, client=client, memory=memory)
        report = agent.hunt()
        return report.render()
    except Exception as e:
        import logging
        logging.getLogger("elengenix.orchestrator").warning(
            "run_standard_scan failed: %s", e
        )
        return None


async def run_elengenix_modules(
    target: str,
    report_dir: _Path,
    timeout: int = 90,
) -> list[dict]:
    """Deprecated. Returns empty list."""
    return []


class Orchestrator:
    """DEPRECATED compat shim — delegates to VulnAgent.

    Old Orchestrator was a script-driven pipeline runner.
    Now it wraps VulnAgent for backward compatibility.
    """

    def __init__(self, target: str) -> None:
        self.target = target
        self._agent = None

    def _get_agent(self):
        if self._agent is None:
            from elengenix.agent import VulnAgent
            from elengenix.agent.memory import AgentMemory
            from tools.universal_ai_client import create_default_client

            self._agent = VulnAgent(
                target=self.target,
                client=create_default_client(),
                memory=AgentMemory(),
            )
        return self._agent

    async def run_quick_scan(self) -> list[dict]:
        agent = self._get_agent()
        report = agent.hunt()
        raw = getattr(report, "findings", None) or []
        return [dict(f) if not isinstance(f, dict) else f for f in raw]

    async def run_deep_scan(self) -> list[dict]:
        return await self.run_quick_scan()

    async def run_stealth_scan(self) -> list[dict]:
        return await self.run_quick_scan()

    async def run_scan_web(self) -> list[dict]:
        return await self.run_quick_scan()

    async def run_full_scan(self) -> list[dict]:
        return await self.run_quick_scan()

    async def run_auto_scan(self) -> list[dict]:
        return await self.run_quick_scan()


# ── Stubs for functions not yet ported ──────────────────────────────


def reload_scope() -> None:
    """Deprecated. Use elengenix.scope.ScopeManager.reload() instead."""
    from elengenix.scope import ScopeManager
    ScopeManager().reload()


def normalize_targets(target: str):
    """Deprecated stub."""
    warnings.warn(
        "normalize_targets is deprecated.",
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
        "get_recommended_tool_chain is deprecated.",
        DeprecationWarning,
        stacklevel=2,
    )
    return []
