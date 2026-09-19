"""elengenix/chat/smart_orchestrator.py — Smart scan orchestrator.

Replaces the deprecated no-op stub that used to live in
``core/scan_engine.py``. Wraps ``tools.smart_scanner.SmartScanner`` and
exposes the ``run_async(target, report_dir)`` coroutine interface that
``ElengenixAgent.run_smart_scan`` consumes.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("elengenix.chat.smart_orchestrator")


@dataclass
class SmartScanState:
    """Scan state surface expected by ``ElengenixAgent.run_smart_scan``."""

    target: str = ""
    duration: float = 0.0
    findings: List[Dict[str, Any]] = field(default_factory=list)
    results: List[Any] = field(default_factory=list)
    phase_results: Dict[str, Any] = field(default_factory=dict)
    status: str = "completed"


@dataclass
class SmartScanCorrelator:
    """Lightweight finding correlator reporting clustered findings."""

    findings: List[Dict[str, Any]] = field(default_factory=list)

    def get_clustered_report(self) -> List[Dict[str, Any]]:
        clusters: Dict[str, Dict[str, Any]] = {}
        for f in self.findings:
            key = str(f.get("type", "unknown"))
            cluster = clusters.setdefault(key, {"type": key, "count": 0, "items": []})
            cluster["count"] += 1
            cluster["items"].append(f)
        return list(clusters.values())


class SmartOrchestrator:
    """Run a phased smart scan on a shared event loop.

    The actual scanning work is delegated to
    ``tools.smart_scanner.SmartScanner``; this wrapper adapts its synchronous
    ``run()`` into the ``run_async`` coroutine interface the chat agent
    expects, and shapes the result into ``(SmartScanState, correlator)``.
    """

    def run_async(self, target: str, report_dir: Optional[Path] = None):
        return self._run_async(target, report_dir)

    async def _run_async(
        self, target: str, report_dir: Optional[Path] = None
    ) -> Tuple[SmartScanState, SmartScanCorrelator]:
        import time

        started = time.time()
        state = SmartScanState(target=target)
        correlator = SmartScanCorrelator()

        try:
            from tools.smart_scanner import SmartScanner

            scanner = SmartScanner(target=target)
            # SmartScanner.run() is blocking — keep the shared loop responsive.
            results: Dict[str, Any] = await asyncio.get_running_loop().run_in_executor(
                None, lambda: scanner.run()
            )
            state.findings = list(results.get("findings", []) or [])
            state.results = list(results.get("phases_completed", []) or [])
            state.phase_results = dict(results.get("phase_results", {}) or {})
            state.status = str(results.get("status", "completed"))
        except Exception as exc:
            logger.warning("Smart scan failed for %s: %s", target, exc)
            state.status = "failed"

        state.duration = max(0.0, time.time() - started)
        correlator.findings = state.findings
        return state, correlator
