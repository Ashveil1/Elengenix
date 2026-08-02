"""benchmark/runner.py — Benchmark runner.

Spins up the local vulnerable Flask app (tests/vulnerable_target/app.py)
on an ephemeral port, runs Elengenix's canonical ScanLoop against it, and
collects the reported findings + timing metrics for grading.

Difficulty tiers: the target defaults to STEALTH (opaque index, no debug
echo) and can be switched back to loud mode. The runner also injects a
random per-run FLAG into the app so the grader can mark "impact proven"
findings when that exact string shows up in a finding's evidence.

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
import secrets
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


def _python_for_vuln_app() -> str:
    """Python interpreter that can run tests/vulnerable_target/app.py.

    The target needs flask + PyJWT. Dev containers often lack them (tests use
    importorskip), so check for a project venv at .venv-benchmark/ first,
    then fall back to sys.executable. A missing flask is caught later at app
    startup with a clear error.
    """
    venv_python = Path(__file__).resolve().parent.parent / ".venv-benchmark" / "bin" / "python"
    if venv_python.exists():
        return str(venv_python)
    return sys.executable


def generate_flag() -> str:
    """Generate a random per-run impact FLAG.

    A fresh value each run means the agent cannot hard-code it — finding the
    string is only possible by actually exploiting a flag-eligible vuln class.
    Prefixed so it is unambiguous in arbitrary evidence text.
    """
    return f"ELENGENIX-FLAG-{secrets.token_hex(8)}"


# ---------------------------------------------------------------------------#
# Vulnerable app lifecycle
# ---------------------------------------------------------------------------#


class VulnerableAppServer:
    """Context manager that starts/stops the vulnerable Flask app.

    Args:
        port: Optional explicit port (ephemeral chosen when None).
        stealth: When True (default) the app runs in opaque mode —
            no vuln hints on the index, no debug echo in error paths.
            Passed through as ELENGENIX_BENCH_STEALTH.
        flag: Optional per-run impact FLAG the app plants into reachable
            locations (flags DB table, traversal-only file, SSTI context).
    """

    def __init__(
        self,
        port: Optional[int] = None,
        stealth: bool = True,
        flag: Optional[str] = None,
    ):
        self.port = port or _find_free_port()
        self.base_url = f"http://127.0.0.1:{self.port}"
        self.stealth = stealth
        self.flag = flag
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
        # Difficulty tier + per-run impact flag. Stealth is the benchmark
        # default (the app only reads it at startup, so env is the switch).
        env["ELENGENIX_BENCH_STEALTH"] = "1" if self.stealth else "0"
        if self.flag:
            env["FLAG"] = self.flag
        logger.info(
            f"Starting vulnerable app on port {self.port} "
            f"(stealth={self.stealth}, flag={'set' if self.flag else 'none'})..."
        )
        python = _python_for_vuln_app()
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
    model: Optional[str] = None,
    provider: Optional[str] = None,
    stealth: bool = True,
    flag: Optional[str] = None,
    time_limit: Optional[int] = None,
) -> BenchmarkResult:
    """Run Elengenix against the vulnerable app and grade the results.

    Args:
        target_url: If provided, skip starting the local app and scan
            this URL instead. If None, a fresh vulnerable app is started.
        max_steps: Max agent reasoning steps.
        callback: Optional live-output callback.
        use_canonical_loop: If True, use the canonical ScanLoop (with all
            modern agent features). If False, use the legacy universal loop.
        model: If provided, override the AI model for this run (used by
            per-model sweeps; also recorded on the result for history).
        provider: If provided, override the AI provider for this run
            (uses the existing UniversalAIClient constructor param).
        stealth: Difficulty tier for a locally-started target. True (default)
            runs the app opaque (no vuln hints / debug echo); False restores
            the original loud mode. Ignored when target_url is given.
        flag: Per-run impact flag planted into the app and passed to the
            grader. When None a fresh random flag is generated for locally-
            started targets. Ignored when target_url is given (we do not
            control that app's planted flag, so impact is ungraded).
        time_limit: Hard timeout in seconds. None = derive from max_steps
            (default tiers: 10 steps→600s, 30→3600s, 120→28800s).

    Returns:
        BenchmarkResult with precision/recall/F1 + timing metrics. If the
        benchmark could not run (missing deps, no AI key, unsupported mode),
        ``result.error`` is set so callers can distinguish a broken run from
        a genuine zero-recall run.
    """
    scan_t0 = time.time()

    def _failed(reason: str) -> BenchmarkResult:
        return BenchmarkGrader(GROUND_TRUTH).grade(
            [],
            error=reason,
            scan_duration_sec=time.time() - scan_t0,
        )

    # Pre-flight: fail loudly with a real error instead of silently grading [].
    # The legacy mode is unsupported regardless of the environment, so check
    # it first (the AI-key pre-flight is irrelevant in that mode).
    if not use_canonical_loop:
        # Honest failure: the legacy loop returns a free-text summary with no
        # structured findings, so it cannot be graded.
        return _failed(
            "legacy loop (--legacy) is not supported by the benchmark: "
            "process_universal returns a text summary with no structured "
            "findings to grade. Run without --legacy to use the canonical "
            "ScanLoop."
        )

    error = _precheck_scan_environment(provider=provider, model=model)
    if error:
        logger.error(error)
        return _failed(error)

    # Derive a hard timeout from the step budget unless the caller overrode it.
    # Used by both the app-start wait and the outer scan harness.
    if time_limit is None:
        time_limit = {10: 600, 30: 3600, 120: 28800}.get(max_steps, 3600)

    logger.info(
        "Benchmark intensity: max_steps=%d, time_limit=%ds (%.1f min)",
        max_steps, time_limit, time_limit / 60,
    )

    # Generate the per-run impact flag only for locally-started targets, where
    # we actually control the planted value. For an external target_url we
    # cannot know its flag, so impact stays ungraded (flag=None).
    if target_url is None and flag is None:
        flag = generate_flag()

    server: Optional[VulnerableAppServer] = None
    if target_url is None:
        try:
            server = VulnerableAppServer(stealth=stealth, flag=flag)
            server.start()
        except Exception as e:
            return _failed(f"vulnerable target failed to start: {e}")
        target_url = server.base_url

    scan_duration_start = time.time()
    time_to_first_finding: Optional[float] = None
    findings: List[Dict[str, Any]] = []
    steps_taken = 0
    scan_error: Optional[str] = None

    try:
        findings, steps_taken, ttf, scan_error = _run_canonical_scan(
            target_url, max_steps, callback, model=model, provider=provider
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
        error=scan_error,
        flag=flag,
    )


def _precheck_scan_environment(
    provider: Optional[str] = None,
    model: Optional[str] = None,
) -> Optional[str]:
    """Fail-fast environment check. Returns an error string, or None if OK.

    Catches the two dominant silent-failure causes of the canonical path:
    missing Elengenix modules and a missing/placeholder AI provider key.

    ``provider``/``model`` are forwarded so a benchmark sweep can check the
    exact provider the run intends to use (not the ``auto``-detected default).
    """
    try:
        import elengenix.scanning.decision_engine  # noqa: F401
        import elengenix.scanning.post_processor  # noqa: F401
        import elengenix.scanning.prompt_builder  # noqa: F401
        import elengenix.scanning.scan_context  # noqa: F401
        import elengenix.scanning.scan_loop  # noqa: F401
        import tools.governance  # noqa: F401
    except ImportError as e:
        return f"required Elengenix scanning modules failed to import: {e}"

    try:
        from tools.universal_ai_client import UniversalAIClient

        kwargs: Dict[str, Any] = {}
        if provider:
            kwargs["provider"] = provider
        if model:
            kwargs["model"] = model
        client = UniversalAIClient(**kwargs)
    except Exception as e:
        return (
            f"no AI provider available for the canonical scan: {e}. "
            "Set a provider API key or start Ollama to run the benchmark."
        )
    if not getattr(client, "api_key", None) and getattr(client, "provider", "") not in ("ollama", "custom"):
        return (
            f"AI provider '{getattr(client, 'provider', '?')}' has no API key. "
            "Set the key to run the benchmark."
        )
    api_key = getattr(client, "api_key", "") or ""
    if api_key and len(api_key) < 10:
        # Tiny keys are placeholder values from a sample .env / config, not a
        # real credential — fail loudly rather than silently grading [].
        return (
            f"AI provider '{getattr(client, 'provider', '?')}' has what looks "
            f"like a placeholder API key (len={len(api_key)}). Set a real key "
            "to run the benchmark."
        )
    return None


def _run_canonical_scan(
    target_url: str,
    max_steps: int,
    callback: Optional[Callable],
    model: Optional[str] = None,
    provider: Optional[str] = None,
) -> tuple:
    """Run the canonical ScanLoop against the target.

    Returns (findings, steps_taken, time_to_first_finding_sec, error).

    ``model``/``provider`` are passed straight to UniversalAIClient's
    constructor (the existing config mechanism: param > config.yaml > env >
    default), letting a per-model sweep select the model for the run.

    Previously this returned ``([], 0, 0.0)`` on ANY import failure or
    exception — making a broken environment indistinguishable from "agent
    found nothing". It now captures the real error into the 4th return value
    so callers can surface it instead of silently grading an empty set.
    """
    error: Optional[str] = None
    try:
        from elengenix.scanning.decision_engine import DecisionEngine
        from elengenix.scanning.post_processor import PostExecutionProcessor
        from elengenix.scanning.prompt_builder import PromptBuilder
        from elengenix.scanning.scan_context import ScanContext
        from elengenix.scanning.scan_loop import ScanLoop
        from tools.governance import Governance
    except ImportError as e:
        error = f"Elengenix scanning modules unavailable: {e}"
        logger.error(error)
        return [], 0, 0.0, error

    # Get a real AI client; if none is configured we cannot run the agent.
    # model/provider come from the sweep; provider=None keeps the existing
    # default ("auto" detection) unchanged for plain single-run benchmarks.
    try:
        from tools.universal_ai_client import UniversalAIClient

        kwargs: Dict[str, Any] = {}
        if provider:
            kwargs["provider"] = provider
        if model:
            kwargs["model"] = model
        client = UniversalAIClient(**kwargs)
    except Exception as e:
        error = f"no AI client available: {e}"
        logger.error(error)
        return [], 0, 0.0, error

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
        return result.findings, result.steps_taken, ttf or 0.0, None
    except Exception as e:
        error = f"canonical scan failed: {type(e).__name__}: {e}"
        logger.error(error)
        return [], 0, 0.0, error
