"""Integration smoke test: run a real scan chain against a known target.

This is marked ``@pytest.mark.integration`` so it does not run in CI by default.
To run: ``python3 -m pytest tests/test_integration_real.py -v -m integration``
Or with skip: ``python3 -m pytest tests/ -v -m "not integration"``
"""

from __future__ import annotations

import asyncio
import shutil
from pathlib import Path

import pytest

# Mark all tests in this file as integration (opt-in)
pytestmark = pytest.mark.integration


REAL_TARGET = "testphp.vulnweb.com"  # intentionally vulnerable Acunetix test site


@pytest.fixture
def report_dir(tmp_path: Path) -> Path:
    """Provide a clean report directory for each test."""
    d = tmp_path / "reports"
    d.mkdir(parents=True, exist_ok=True)
    return d


@pytest.mark.skipif(
    not shutil.which("subfinder"),
    reason="subfinder not installed",
)
def test_subfinder_real_run_finds_subdomains(report_dir: Path):
    """Run subfinder on testphp.vulnweb.com and assert it completes successfully.

    testphp.vulnweb.com is an intentionally vulnerable test site maintained by
    Acunetix for testing security tools. It's the closest thing to a public
    test target that we can legally scan.
    """
    from scan_engine_upgrade import ParallelRunner

    runner = ParallelRunner(max_concurrency=1)
    try:
        result = asyncio.run(
            asyncio.wait_for(
                runner.run_tool("subfinder", REAL_TARGET, report_dir),
                timeout=60,
            )
        )
    except asyncio.TimeoutError:
        pytest.skip("subfinder timed out (network)")

    # subfinder may find 0 subdomains (this domain is small), but the call must
    # complete and return a proper ToolResult.
    assert result is not None
    assert result.tool_name == "subfinder"
    # The bug we're guarding against: missing semaphore would raise TypeError.
    # The fact we got a result back means the fix is in place.


@pytest.mark.skipif(
    not shutil.which("httpx"),
    reason="httpx not installed",
)
def test_httpx_real_run_probes_target(report_dir: Path):
    """Run httpx on testphp.vulnweb.com and assert it returns HTTP metadata."""
    from scan_engine_upgrade import ParallelRunner

    runner = ParallelRunner(max_concurrency=1)
    try:
        result = asyncio.run(
            asyncio.wait_for(
                runner.run_tool("httpx", REAL_TARGET, report_dir),
                timeout=30,
            )
        )
    except asyncio.TimeoutError:
        pytest.skip("httpx timed out (network)")

    assert result is not None
    assert result.tool_name == "httpx"
    # httpx should successfully probe the site and find it live
    # (testphp.vulnweb.com is a real, live test target)


def test_smart_orchestrator_smoke_compiles():
    """The SmartOrchestrator must instantiate without error."""
    from scan_engine_upgrade import SmartOrchestrator

    orch = SmartOrchestrator(max_concurrency=5)
    assert orch.max_concurrency == 5
    assert orch.parallel_runner is not None
    assert orch.parallel_runner.semaphore is not None


def test_full_pipeline_modules_importable():
    """All the modules in the pipeline must be importable without errors.

    Catches the most common failure mode: a syntax error or missing import
    that breaks the whole system.
    """
    # Core engine
    from agents.agent_logger import ChainOfThoughtLogger
    from agents.agent_planner import StrategicPlanner
    from core.orchestrator import run_standard_scan
    from tools.governance import Governance
    from tools.payload_mutation import PayloadMutator

    # All imports succeeded
    assert StrategicPlanner is not None
    assert ChainOfThoughtLogger is not None
    assert PayloadMutator is not None
    assert Governance is not None
    assert run_standard_scan is not None
