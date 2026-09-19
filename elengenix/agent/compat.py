"""elengenix/agent/compat.py — Thin scan wrappers over VulnAgent.

Relocated from the deprecated root-level ``core/orchestrator.py`` during the
architecture consolidation. New code should use ``elengenix.agent.VulnAgent``
directly; these helpers exist for ``tools/omni_scan.py``,
``tools/smart_scanner.py``, ``tools/api_server.py``,
``tools/tui_dashboard.py`` and ``integrations/bot.py``.
"""

from __future__ import annotations

import logging
from typing import Optional

logger = logging.getLogger("elengenix.agent.compat")


def run_standard_scan(
    target: str,
    rate_limit: int = 5,
    timeout: int = 600,
    use_registry: bool = True,
    tool_filter: Optional[str] = None,
    use_smart_scan: bool = False,
) -> Optional[str]:
    """Run a standard scan via VulnAgent and return the rendered report.

    Kept for callers that only need a one-shot scan + report string.
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
        logger.warning("run_standard_scan failed: %s", e)
        return None


class Orchestrator:
    """Thin wrapper delegating to VulnAgent for legacy scan entrypoints."""

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
