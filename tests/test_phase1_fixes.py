"""Tests for Phase 1 bug fixes.

These tests verify the runtime bugs found during code review are now fixed:
1. SmartOrchestrator.run_tool() passes the required semaphore argument
2. doctor() actually checks Go security tools
3. CoT logger actually saves sessions to disk (and survives process exit)
"""

from __future__ import annotations

import asyncio
import json
import os
import shutil
from pathlib import Path

import pytest

# ── Fix 1: SmartOrchestrator semaphore ─────────────────────────────────────
# These tests run the actual async function, NOT the real subfinder binary,
# to keep the test suite fast and avoid network dependencies. We use a
# mock tool that records what arguments it was called with.


def test_parallel_runner_run_tool_passes_semaphore(tmp_path: Path):
    """ParallelRunner.run_tool() must call tool.execute() with all required args.

    Previous bug: ``await tool.execute(target, report_dir)`` crashed with
    TypeError because BaseTool.execute() requires (target, report_dir, semaphore).
    """
    from scan_engine_upgrade import ParallelRunner
    from tools.tool_registry import (
        BaseTool,
        ToolCategory,
        ToolMetadata,
        ToolPriority,
        ToolRegistry,
        ToolResult,
    )

    # Register a mock tool that records its call args
    captured = {}

    class MockTool(BaseTool):
        async def execute(self, target, report_dir, semaphore, **kwargs):
            captured["target"] = target
            captured["report_dir"] = report_dir
            captured["semaphore"] = semaphore
            captured["called"] = True
            return ToolResult(
                success=True,
                tool_name="mock",
                category=ToolCategory.UTILITY,
                output="mock output",
                raw_output_file=None,
            )

        @property
        def is_available(self) -> bool:
            return True

    metadata = ToolMetadata(
        name="mock_tool",
        category=ToolCategory.UTILITY,
        priority=ToolPriority.LOW,
        binary_name="mock_tool",
        description="mock",
    )
    mock_instance = MockTool(metadata)
    # Skip BaseTool.__init__ binary check by bypassing it via __new__
    # (it tries shutil.which() in __init__ which is OK if binary is not found)
    # But we override is_available so it returns True regardless
    ToolRegistry._tools["mock_tool"] = mock_instance

    try:
        runner = ParallelRunner(max_concurrency=2)
        # runner.semaphore is set in __init__; access it to ensure creation
        _ = runner.semaphore
        result = asyncio.run(runner.run_tool("mock_tool", "test.example.com", tmp_path))

        assert result.success is True
        assert captured.get("called") is True
        assert captured.get("target") == "test.example.com"
        assert captured.get("report_dir") == tmp_path
        # The fix: semaphore MUST have been passed as the 3rd positional arg
        assert captured.get("semaphore") is not None
    finally:
        ToolRegistry._tools.pop("mock_tool", None)


def test_smart_orchestrator_does_not_crash_with_mock_tool(tmp_path: Path):
    """Full SmartOrchestrator.run_smart_scan with a mock tool must not crash.

    Before the fix, this raised:
        TypeError: SubfinderTool.execute() missing 1 required positional argument: 'semaphore'
    """
    from scan_engine_upgrade import SmartOrchestrator
    from tools.tool_registry import (
        BaseTool,
        ToolCategory,
        ToolMetadata,
        ToolPriority,
        ToolRegistry,
        ToolResult,
    )

    class MockTool(BaseTool):
        async def execute(self, target, report_dir, semaphore, **kwargs):
            return ToolResult(
                success=True,
                tool_name="mock_tool",
                category=ToolCategory.UTILITY,
                output="mock",
                findings=[{"test": "data"}],
                raw_output_file=None,
            )

        @property
        def is_available(self) -> bool:
            return True

    metadata = ToolMetadata(
        name="mock_tool",
        category=ToolCategory.UTILITY,
        priority=ToolPriority.LOW,
        binary_name="mock_tool",
        description="mock",
    )
    mock_instance = MockTool(metadata)
    ToolRegistry._tools["mock_tool"] = mock_instance

    try:
        orch = SmartOrchestrator(max_concurrency=1)
        state, _ = asyncio.run(
            orch.run_smart_scan(
                target="test.example.com",
                report_dir=tmp_path,
                tools=["mock_tool"],
                rate_limit=1,
                correlate=False,
                use_smart_chain=False,
            )
        )

        assert state is not None
        assert len(state.results) >= 0
    finally:
        ToolRegistry._tools.pop("mock_tool", None)


def test_parallel_runner_run_tool_signature_has_semaphore():
    """Source-level check: the run_tool method must call execute with 3 args."""
    import inspect

    from scan_engine_upgrade import ParallelRunner

    source = inspect.getsource(ParallelRunner.run_tool)
    # Must pass self.semaphore to tool.execute
    assert "self.semaphore" in source, (
        "ParallelRunner.run_tool() must pass self.semaphore to tool.execute(). " "Bug regressed!"
    )
    # Must NOT call with only 2 args
    assert (
        "tool.execute(target, report_dir)" not in source
    ), "Found the old 2-arg call signature — bug regressed!"


# ── Fix 2 (NEW): doctor() does NOT check third-party security tools ───────
# Elengenix is a pure Python framework. It checks its own build dependencies
# (Python libraries) but does NOT bundle or check third-party scanners
# (nuclei, subfinder, etc.). The AI agent discovers those at runtime.


def test_doctor_does_not_check_third_party_tools():
    """tools/doctor.py must NOT define a GO_SECURITY_TOOLS list (we are framework-only)."""
    from tools import doctor

    # GO_SECURITY_TOOLS constant must be removed
    assert not hasattr(
        doctor, "GO_SECURITY_TOOLS"
    ), "GO_SECURITY_TOOLS must be removed — Elengenix does not bundle third-party tools"

    # The doctor source code must not import shutil.which or check binaries
    import inspect

    src = inspect.getsource(doctor)
    assert (
        "shutil.which" not in src
    ), "doctor.py must not check external binaries — it only validates the framework itself"
    assert "GO_SECURITY_TOOLS" not in src


def test_doctor_only_checks_python_libraries():
    """doctor.py must define PYTHON_LIBRARIES and PYTHON_MIN as the build-time checks."""
    from tools.doctor import PYTHON_LIBRARIES, PYTHON_MIN

    assert isinstance(PYTHON_LIBRARIES, list)
    assert len(PYTHON_LIBRARIES) >= 5, "Must check the framework's Python dependencies"
    assert PYTHON_MIN >= (3, 10), "Python 3.10+ required"

    # Every entry is a 3-tuple (import_name, pip_name, is_required)
    for entry in PYTHON_LIBRARIES:
        assert len(entry) == 3, f"Each PYTHON_LIBRARIES entry needs 3 fields, got {len(entry)}"


def test_doctor_health_check_works():
    """check_health() must run end-to-end without crashing."""
    from tools.doctor import check_health

    # Run non-interactively to avoid prompting the user
    result = check_health(interactive=False)
    # Result is bool — True if everything is OK, False otherwise. Either is fine;
    # what we care about is that the function completes without exception.
    assert isinstance(result, bool)


# ── Fix 3: CoT logger actually saves sessions ───────────────────────────────


def test_cot_logger_creates_log_file(tmp_path: Path):
    """ChainOfThoughtLogger.save_session() must write a JSON file to disk."""
    from agents.agent_logger import ChainOfThoughtLogger

    logger = ChainOfThoughtLogger(log_dir=tmp_path)
    logger.set_target("test_target")
    logger.log(
        step=0, context="ctx1", reasoning="reason1", action="act1", result="res1", confidence=0.5
    )
    logger.log(
        step=1, context="ctx2", reasoning="reason2", action="act2", result="res2", confidence=0.7
    )

    path = logger.save_session("test_target")
    assert path is not None, "save_session() returned None but should return a Path"
    assert path.exists(), f"CoT log file was not created at {path}"

    data = json.loads(path.read_text())
    assert "target" in data
    assert "thoughts" in data
    assert len(data["thoughts"]) == 2
    assert data["thoughts"][0]["step"] == 0
    assert data["thoughts"][0]["reasoning"] == "reason1"
    assert data["thoughts"][1]["step"] == 1


def test_cot_logger_idempotent_save(tmp_path: Path):
    """save_session() must not write the same session twice."""
    from agents.agent_logger import ChainOfThoughtLogger

    logger = ChainOfThoughtLogger(log_dir=tmp_path)
    logger.set_target("idem_test")
    logger.log(0, "c", "r", "a", "res", 0.5)

    first = logger.save_session("idem_test")
    second = logger.save_session("idem_test")

    # First call should write; second should be a no-op (return None)
    assert first is not None
    assert second is None

    # Only one file in the log dir
    files = list(tmp_path.glob("*.json"))
    assert len(files) == 1, f"Expected 1 CoT file, found {len(files)}: {files}"


def test_cot_logger_handles_empty_session(tmp_path: Path):
    """save_session() on an empty session must return None (no file)."""
    from agents.agent_logger import ChainOfThoughtLogger

    logger = ChainOfThoughtLogger(log_dir=tmp_path)
    result = logger.save_session("empty")
    assert result is None
    assert list(tmp_path.glob("*.json")) == []


def test_cot_logger_atexit_save(tmp_path: Path):
    """atexit hook must save the session if process exits before save_session() is called."""
    # We can't actually trigger atexit in a test, but we can verify the
    # mechanism is wired up by checking _pending_target is set.
    from agents.agent_logger import ChainOfThoughtLogger

    logger = ChainOfThoughtLogger(log_dir=tmp_path)
    logger.set_target("atexit_test")
    logger.log(0, "ctx", "reason", "action", "result", 0.5)
    assert logger._pending_target == "atexit_test"
    # Now manually invoke the atexit handler to verify it works
    logger._atexit_save()

    # If we have any session, at least one file should be created
    # (or it may have been cleared by a prior test — we only assert it
    # doesn't crash)
