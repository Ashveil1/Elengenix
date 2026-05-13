"""scan_engine_bridge.py — Bridge between legacy orchestrator and upgraded scan engine.

This module provides a thin compatibility layer so that existing code in
orchestrator.py can call into the SmartOrchestrator without changing the
public API.

Usage:
    from scan_engine_bridge import smart_scan
    results = smart_scan("example.com", report_dir, use_smart=True)
"""
from __future__ import annotations

import asyncio
import threading
from pathlib import Path
from typing import List, Tuple, Optional

from rich.console import Console

from scan_engine_upgrade import (
    SmartOrchestrator,
    ScanState,
    FindingCorrelator,
)
from tools.tool_registry import ToolResult

console = Console()

# ── Shared Persistent Event Loop ──────────────────────────
_SHARED_LOOP: Optional[asyncio.AbstractEventLoop] = None
_SHARED_LOOP_LOCK: threading.Lock = threading.Lock()
_SHARED_LOOP_THREAD: Optional[threading.Thread] = None


def _get_shared_loop() -> asyncio.AbstractEventLoop:
    """Get or create the module-level persistent event loop."""
    global _SHARED_LOOP, _SHARED_LOOP_THREAD
    with _SHARED_LOOP_LOCK:
        if _SHARED_LOOP is None:
            _SHARED_LOOP = asyncio.new_event_loop()

            def _run_forever(loop: asyncio.AbstractEventLoop) -> None:
                asyncio.set_event_loop(loop)
                loop.run_forever()

            _SHARED_LOOP_THREAD = threading.Thread(
                target=_run_forever,
                args=(_SHARED_LOOP,),
                daemon=True,
                name="bridge-event-loop",
            )
            _SHARED_LOOP_THREAD.start()
        return _SHARED_LOOP


def smart_scan(
    target: str,
    report_dir: Path,
    tools: List[str] = None,
    rate_limit: int = 5,
    correlate: bool = True,
    use_smart_chain: bool = True,
    build_file_graph: bool = True,
) -> Tuple[ScanState, Optional[FindingCorrelator]]:
    """Synchronous entry-point for the smart scan pipeline.

    Wraps the async :class:`SmartOrchestrator` so that legacy code can call
    it without an async context.

    Args:
        target: Target domain / IP to scan.
        report_dir: Directory where reports will be saved.
        tools: Optional list of specific tool names to run.  If ``None`` the
            orchestrator selects the chain automatically (or via file
            relationships when *use_smart_chain* is ``True``).
        rate_limit: Maximum number of concurrent tools.
        correlate: Whether to run the :class:`FindingCorrelator` after all
            tools finish.
        use_smart_chain: If ``True`` (default) the orchestrator asks
            :module:`file_relationship_mapper` which tools to run based on
            recently changed files.
        build_file_graph: If ``True`` (default) a
            :class:`FileRelationshipGraph` is built before the scan.  Set to
            ``False`` to skip when the graph is already cached.

    Returns:
        A two-tuple of ``(state, correlator)`` where *state* is a
        :class:`ScanState` containing all results and *correlator* is a
        :class:`FindingCorrelator` (or ``None`` when *correlate* is
        ``False``).
    """
    orchestrator = SmartOrchestrator(max_concurrency=rate_limit)

    if build_file_graph:
        try:
            orchestrator.build_file_graph()
            console.print("[dim][OK] Built FileRelationshipGraph[/dim]")
        except Exception:  # noqa: BLE001
            console.print("[dim][WARN] FileRelationshipGraph failed, continuing...[/dim]")

    async def _run():
        return await orchestrator.run_smart_scan(
            target=target,
            report_dir=report_dir,
            tools=tools,
            rate_limit=rate_limit,
            correlate=correlate,
            use_smart_chain=use_smart_chain,
        )

    loop = _get_shared_loop()
    future = asyncio.run_coroutine_threadsafe(_run(), loop)
    return future.result(timeout=600)


# ── Compatibility wrappers ─────────────────────────────────────────────

def run_registry_pipeline_smart(
    target: str,
    report_dir: Path,
    rate_limit: int = 5,
    tool_filter: List[str] = None,
) -> List[ToolResult]:
    """Drop-in replacement for ``orchestrator.run_registry_pipeline``.

    Runs the smart orchestrator and converts the final :class:`ScanState`
    back to a plain list of :class:`ToolResult` instances for callers that
    expect the legacy return type.
    """
    state, _ = smart_scan(
        target, report_dir,
        tools=tool_filter,
        rate_limit=rate_limit,
        correlate=False,
    )
    return list(state.results.values())


def calculate_cvss_for_results(results: list) -> list:
    """Stub retained for backward compatibility.

    The smart orchestrator already calculates CVSS internally; this
    function exists purely to satisfy legacy imports.
    """
    scored = []
    from tools.cvss_calculator import CVSSCalculator  # noqa: W0611
    calculator = CVSSCalculator(use_ai=False)
    for res in results:
        for finding in res.findings:
            score = calculator.calculate_from_tool_result(res.tool_name, finding, "unknown")
            scored.append({
                "tool": res.tool_name,
                "finding": finding,
                "cvss_score": score.base_score,
                "severity": (score.adjusted_severity or score.severity).value,
                "vector": score.vector_string,
            })
    return scored


if __name__ == "__main__":
    # Quick smoke-test
    print("scan_engine_bridge loaded successfully.")
    print("Use smart_scan(target, report_dir) to run the upgraded pipeline.")
