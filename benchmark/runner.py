"""benchmark/runner.py — Benchmark runner.

Spins up the local vulnerable Flask app (tests/vulnerable_target/app.py)
on an ephemeral port, runs Elengenix's canonical ScanLoop against it, and
collects the reported findings + timing metrics for grading.

This is the measurement half of the benchmark harness. The grading half
lives in benchmark/grading.py.

Public API
----------
    from benchmark.runner import run_elengenix_benchmark

    result = run_elengenix_benchmark(max_steps=30)
    print(result.summary())   # BenchmarkResult
"""

from __future__ import annotations

import asyncio
import logging
import os
import socket
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from benchmark.grading import BenchmarkGrader, BenchmarkResult, GROUND_TRUTH

logger = logging.getLogger("elengenix.benchmark.runner")

# Path to the deliberately-vulnerable Flask app fixture.
VULN_APP_PATH = Path(__file__).resolve().parent.parent / "tests" / "vulnerable_target" / "app.py"


# ---------------------------------------------------------------------------#
# Port management
# ---------------------------------------------------------------------------#


def _find_free_port() -> int:
    """Find an ephemeral free port for the vulnerable app."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


# ---------------------------------------------------------------------------#
# Vulnerable app lifecycle
# ---------------------------------------------------------------------------#


class VulnerableAppServer:
    """Context manager that starts/stops the vulnerable Flask app."""

    def __init__(self, port: Optional[int] = None):
        self.port = port or _find_free_port()
        self.base_url = f"http://127.0.0.1:{self.port}"
        self._proc: Optional[subprocess.Popen] = None

    def __enter__(self) -> "VulnerableAppServer":
        self.start()
        return self

    def __exit__(self, *exc) -> None:
        self.stop()

    def start(self) -> None:
        """Start the vulnerable Flask app in a subprocess."""
        if not VULN_APP_PATH.exists():
            raise FileNotFoundError(f"Vulnerable app not found at {VULN_APP_PATH}")

        env = os.environ.copy()
        env["PORT"] = str(self.port)
        # Use the project venv python if available
        python = sys.executable

        logger.info(f"Starting vulnerable app on port {self.port}...")
        self._proc = subprocess.Popen(
            [python, str(VULN_APP_PATH)],
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        # Wait for the app to come up
        if not self._wait_for_ready(timeout=15):
            self.stop()
            raise RuntimeError(f"Vulnerable app did not start on port {self.port}")
        logger.info(f"Vulnerable app ready at {self.base_url}")

    def stop(self) -> None:
        """Terminate the vulnerable Flask app."""
        if self._proc is not None:
            try:
                self._proc.terminate()
                self._proc.wait(timeout=5)
            except Exception:
                try:
                    self._proc.kill()
                except Exception:
                    pass
            self._proc = None

    def _wait_for_ready(self, timeout: float = 15.0) -> bool:
        """Poll the app until it responds or timeout."""
        import urllib.request

        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                urllib.request.urlopen(f"{self.base_url}/", timeout=1)
                return True
            except Exception:
                time.sleep(0.3)
        return False


# ---------------------------------------------------------------------------#
# Elengenix scan runner
# ---------------------------------------------------------------------------#


def run_elengenix_benchmark(
    target_url: Optional[str] = None,
    max_steps: int = 30,
    callback: Optional[Callable] = None,
    use_canonical_loop: bool = True,
) -> BenchmarkResult:
    """Run Elengenix against the vulnerable app and grade the results.

    Args:
        target_url: If provided, skip starting the local app and scan
            this URL instead. If None, a fresh vulnerable app is started.
        max_steps: Max agent reasoning steps.
        callback: Optional live-output callback.
        use_canonical_loop: If True, use the canonical ScanLoop (with all
            modern agent features). If False, use the legacy universal loop.

    Returns:
        BenchmarkResult with precision/recall/F1 + timing metrics.
    """
    server: Optional[VulnerableAppServer] = None
    if target_url is None:
        server = VulnerableAppServer()
        server.start()
        target_url = server.base_url

    scan_duration_start = time.time()
    time_to_first_finding: Optional[float] = None
    findings: List[Dict[str, Any]] = []
    steps_taken = 0

    try:
        if use_canonical_loop:
            findings, steps_taken, ttf = _run_canonical_scan(
                target_url, max_steps, callback
            )
            time_to_first_finding = ttf
        else:
            findings, steps_taken, ttf = _run_legacy_scan(
                target_url, max_steps, callback
            )
            time_to_first_finding = ttf
    finally:
        if server is not None:
            server.stop()

    scan_duration = time.time() - scan_duration_start
    grader = BenchmarkGrader(GROUND_TRUTH)
    return grader.grade(
        findings,
        scan_duration_sec=scan_duration,
        time_to_first_finding_sec=time_to_first_finding or scan_duration,
        steps_taken=steps_taken,
    )


def _run_canonical_scan(
    target_url: str,
    max_steps: int,
    callback: Optional[Callable],
) -> tuple:
    """Run the canonical ScanLoop against the target.

    Returns (findings, steps_taken, time_to_first_finding_sec).
    """
    try:
        from elengenix.scanning.decision_engine import DecisionEngine
        from elengenix.scanning.post_processor import PostExecutionProcessor
        from elengenix.scanning.prompt_builder import PromptBuilder
        from elengenix.scanning.scan_context import ScanContext
        from elengenix.scanning.scan_loop import ScanLoop
        from tools.governance import Governance
    except ImportError as e:
        logger.error(f"Elengenix modules unavailable: {e}")
        return [], 0, 0.0

    # Try to get an AI client; if none configured, we can't run the agent.
    try:
        from tools.universal_ai_client import UniversalAIClient
        client = UniversalAIClient()
    except Exception:
        client = None

    governance = Governance()

    ctx = ScanContext(
        target=target_url,
        base_url=target_url,
        objective=f"Find vulnerabilities in {target_url}",
        mission_key=f"benchmark-{int(time.time())}",
        max_steps=max_steps,
    )

    def _executor(action_data: Dict[str, Any], ctx: Any):
        from elengenix.scanning.executor import execute_tool
        try:
            output = execute_tool(action_data, governance, callback=callback)
            from tools.tool_registry import ToolResult, ToolCategory
            success = not (output.startswith("[FAIL]") or output.startswith("Error:"))
            result = ToolResult(
                success=success,
                tool_name=action_data.get("tool", action_data.get("action", "unknown")),
                category=ToolCategory.SCANNER,
                output=output,
                findings=[],
            )
            return success, result, output
        except Exception as e:
            logger.debug(f"benchmark executor failed: {e}")
            return False, None, str(e)

    prompt_builder = PromptBuilder(
        base_prompt="You are Elengenix, an autonomous security agent. Find vulnerabilities.",
    )
    decision_engine = DecisionEngine(ai_client=client, prompt_builder=prompt_builder)
    post_processor = PostExecutionProcessor(callback=callback)

    loop = ScanLoop(
        decision_engine=decision_engine,
        post_processor=post_processor,
        executor=_executor,
        callback=callback,
        client=client,
        replan_every=5,
    )

    t0 = time.time()
    ttf: Optional[float] = None

    # Wrap ctx.add_finding to capture time-to-first-finding
    _orig_add_finding = ctx.add_finding
    def _timed_add_finding(finding):
        nonlocal ttf
        if ttf is None:
            ttf = time.time() - t0
        _orig_add_finding(finding)
    ctx.add_finding = _timed_add_finding

    try:
        result = asyncio.run(loop.run(ctx, f"Find vulnerabilities in {target_url}", interactive=True))
        return result.findings, result.steps_taken, ttf or 0.0
    except Exception as e:
        logger.error(f"canonical scan failed: {e}")
        return [], 0, 0.0


def _run_legacy_scan(
    target_url: str,
    max_steps: int,
    callback: Optional[Callable],
) -> tuple:
    """Run the legacy universal loop against the target (fallback)."""
    try:
        from elengenix.scanning.universal import process_universal
        from tools.governance import Governance
        from tools.universal_ai_client import UniversalAIClient
    except ImportError as e:
        logger.error(f"Legacy modules unavailable: {e}")
        return [], 0, 0.0

    try:
        client = UniversalAIClient()
    except Exception:
        client = None

    governance = Governance()
    t0 = time.time()
    try:
        output = process_universal(
            user_input=f"Find vulnerabilities in {target_url}",
            client=client,
            conversation_history=[],
            base_prompt="You are Elengenix, an autonomous security agent.",
            governance=governance,
            target=target_url,
            callback=callback,
        )
        # The legacy loop returns a string summary; findings are embedded.
        # We can't easily extract structured findings from it, so return empty.
        return [], max_steps, time.time() - t0
    except Exception as e:
        logger.error(f"legacy scan failed: {e}")
        return [], 0, 0.0
