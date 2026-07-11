"""tests/test_scan_loop.py — Tests for agents.scan_loop.ScanLoop"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Tuple
from unittest.mock import MagicMock

import pytest

from agents.decision_engine import Decision
from agents.scan_context import ScanContext
from agents.scan_loop import ScanLoop, ScanResult


# ── Mock Objects ────────────────────────────────────────────────


class MockDecisionEngine:
    def __init__(self, decisions=None):
        self._decisions = decisions or []
        self._call_count = 0

    def decide(self, ctx, user_input, reflect_engine=None):
        if self._call_count < len(self._decisions):
            d = self._decisions[self._call_count]
            self._call_count += 1
            return d
        # No more decisions — return a non-finish action so the loop continues
        self._call_count += 1
        return Decision(
            action_data={"action": "run_shell", "command": "echo keep_going", "tool": "echo"},
            reasoning="continue",
            source="test",
        )


class MockPostProcessor:
    def __init__(self):
        self.processed = []

    async def process(self, ctx, result, tool_name, action_data, step):
        self.processed.append((ctx, result, tool_name, action_data, step))


class MockToolResult:
    def __init__(self, success=True, findings=None):
        self.success = success
        self.findings = findings or []
        self.tool_name = "test_tool"


# ── Helper ──────────────────────────────────────────────────────


def _make_ctx(**kwargs) -> ScanContext:
    defaults = {"target": "example.com", "objective": "Find vulns"}
    defaults.update(kwargs)
    return ScanContext(**defaults)


def _mock_executor(action_data, ctx) -> Tuple[bool, Any, str]:
    """Mock executor that returns success."""
    tool = action_data.get("tool", "test")
    result = MockToolResult(success=True, findings=[{"type": "xss", "url": "http://example.com"}])
    return True, result, f"{tool}: 1 findings"


def _mock_executor_fails(action_data, ctx) -> Tuple[bool, Any, str]:
    """Mock executor that fails."""
    return False, None, "Execution failed"


# ── Creation Tests ──────────────────────────────────────────────


class TestScanLoopCreation:
    def test_create_with_defaults(self):
        engine = MockDecisionEngine()
        processor = MockPostProcessor()
        loop = ScanLoop(engine, processor)
        assert loop.loop_threshold == 3

    def test_create_with_custom_threshold(self):
        engine = MockDecisionEngine()
        processor = MockPostProcessor()
        loop = ScanLoop(engine, processor, loop_threshold=5)
        assert loop.loop_threshold == 5


# ── Termination Tests ──────────────────────────────────────────


class TestTermination:
    async def test_finish_action_terminates(self):
        decisions = [
            Decision(
                action_data={"action": "finish", "summary": "Mission complete"},
                reasoning="done",
                source="test",
            ),
        ]
        engine = MockDecisionEngine(decisions)
        processor = MockPostProcessor()
        loop = ScanLoop(engine, processor)

        ctx = _make_ctx()
        result = await loop.run(ctx, "scan example.com")

        assert result.success is True
        assert "Mission complete" in result.summary
        assert result.steps_taken == 1

    async def test_max_steps_terminates(self):
        # No finish decision — should hit max_steps
        engine = MockDecisionEngine(decisions=[])
        processor = MockPostProcessor()
        loop = ScanLoop(engine, processor)

        ctx = _make_ctx(max_steps=3)
        result = await loop.run(ctx, "scan")

        assert result.success is False
        assert "halted" in result.summary.lower()
        assert result.steps_taken == 3

    async def test_returns_findings(self):
        decisions = [
            Decision(
                action_data={"action": "finish"},
                reasoning="done",
                source="test",
            ),
        ]
        engine = MockDecisionEngine(decisions)
        processor = MockPostProcessor()
        loop = ScanLoop(engine, processor)

        ctx = _make_ctx()
        ctx.add_finding({"type": "xss", "url": "http://example.com"})
        result = await loop.run(ctx, "scan")

        assert len(result.findings) == 1


# ── Loop Detection Tests ───────────────────────────────────────


class TestLoopDetection:
    async def test_detects_repeated_action(self):
        # Create decisions that repeat the same action
        same_action = Decision(
            action_data={"action": "run_shell", "command": "nmap target", "tool": "nmap"},
            reasoning="repeat",
            source="test",
        )
        decisions = [same_action] * 5  # Repeat 5 times
        engine = MockDecisionEngine(decisions)
        processor = MockPostProcessor()
        loop = ScanLoop(engine, processor, loop_threshold=3, executor=_mock_executor)

        ctx = _make_ctx()
        result = await loop.run(ctx, "scan")

        assert "DEADLOCK" in result.summary
        assert result.success is False

    async def test_different_actions_not_detected(self):
        decisions = [
            Decision(
                action_data={"action": "run_shell", "command": "nmap target"},
                reasoning="step 1",
                source="test",
            ),
            Decision(
                action_data={"action": "run_shell", "command": "dirb target"},
                reasoning="step 2",
                source="test",
            ),
            Decision(
                action_data={"action": "finish", "summary": "Done"},
                reasoning="done",
                source="test",
            ),
        ]
        engine = MockDecisionEngine(decisions)
        processor = MockPostProcessor()
        loop = ScanLoop(engine, processor, executor=_mock_executor)

        ctx = _make_ctx()
        result = await loop.run(ctx, "scan")

        assert result.success is True
        assert "DEADLOCK" not in result.summary


# ── Save Memory Tests ──────────────────────────────────────────


class TestSaveMemory:
    async def test_save_memory_continues_loop(self):
        decisions = [
            Decision(
                action_data={
                    "action": "save_memory",
                    "learning": "XSS found",
                    "target": "example.com",
                },
                reasoning="save",
                source="test",
            ),
            Decision(
                action_data={"action": "finish", "summary": "Done after save"},
                reasoning="done",
                source="test",
            ),
        ]
        engine = MockDecisionEngine(decisions)
        processor = MockPostProcessor()
        loop = ScanLoop(engine, processor)

        ctx = _make_ctx()
        result = await loop.run(ctx, "scan")

        assert result.success is True
        assert "Done after save" in result.summary
        # History should have the save_memory entries
        assert any("save_memory" in str(h) for h in ctx.history)


# ── History Tests ──────────────────────────────────────────────


class TestHistory:
    async def test_history_updated_after_action(self):
        decisions = [
            Decision(
                action_data={"action": "run_shell", "command": "nmap", "tool": "nmap"},
                reasoning="scan",
                source="test",
            ),
            Decision(
                action_data={"action": "finish", "summary": "Done"},
                reasoning="done",
                source="test",
            ),
        ]
        engine = MockDecisionEngine(decisions)
        processor = MockPostProcessor()
        loop = ScanLoop(engine, processor, executor=_mock_executor)

        ctx = _make_ctx()
        result = await loop.run(ctx, "scan")

        # Should have: assistant action + user observation (from step 1)
        # + assistant finish (from step 2 validation, no history update for finish)
        assert len(ctx.history) >= 2
        # Check that the action was recorded
        assert any("run_shell" in h["content"] for h in ctx.history)
        assert any("OBSERVATION" in h["content"] for h in ctx.history)

    async def test_thought_prepended_to_history(self):
        decisions = [
            Decision(
                action_data={
                    "action": "run_shell",
                    "command": "nmap",
                    "thought": "I think there's SQLi",
                },
                reasoning="scan",
                source="test",
            ),
            Decision(
                action_data={"action": "finish", "summary": "Done"},
                reasoning="done",
                source="test",
            ),
        ]
        engine = MockDecisionEngine(decisions)
        processor = MockPostProcessor()
        loop = ScanLoop(engine, processor, executor=_mock_executor)

        ctx = _make_ctx()
        await loop.run(ctx, "scan")

        # Find the assistant message with the thought
        assistant_msgs = [h for h in ctx.history if h["role"] == "assistant"]
        assert any("I think there's SQLi" in h["content"] for h in assistant_msgs)


# ── Execution Tests ────────────────────────────────────────────


class TestExecution:
    async def test_executor_called_with_action(self):
        decisions = [
            Decision(
                action_data={"action": "run_shell", "command": "nmap", "tool": "nmap"},
                reasoning="scan",
                source="test",
            ),
            Decision(
                action_data={"action": "finish", "summary": "Done"},
                reasoning="done",
                source="test",
            ),
        ]
        engine = MockDecisionEngine(decisions)
        processor = MockPostProcessor()
        executor = MagicMock(return_value=(True, MockToolResult(), "ok"))
        loop = ScanLoop(engine, processor, executor=executor)

        ctx = _make_ctx()
        await loop.run(ctx, "scan")

        executor.assert_called_once()

    async def test_post_processor_called_after_execution(self):
        decisions = [
            Decision(
                action_data={"action": "run_shell", "command": "nmap", "tool": "nmap"},
                reasoning="scan",
                source="test",
            ),
            Decision(
                action_data={"action": "finish", "summary": "Done"},
                reasoning="done",
                source="test",
            ),
        ]
        engine = MockDecisionEngine(decisions)
        processor = MockPostProcessor()
        loop = ScanLoop(engine, processor, executor=_mock_executor)

        ctx = _make_ctx()
        await loop.run(ctx, "scan")

        assert len(processor.processed) == 1

    async def test_executor_failure_continues_loop(self):
        decisions = [
            Decision(
                action_data={"action": "run_shell", "command": "nmap", "tool": "nmap"},
                reasoning="scan",
                source="test",
            ),
            Decision(
                action_data={"action": "finish", "summary": "Done"},
                reasoning="done",
                source="test",
            ),
        ]
        engine = MockDecisionEngine(decisions)
        processor = MockPostProcessor()
        loop = ScanLoop(engine, processor, executor=_mock_executor_fails)

        ctx = _make_ctx()
        result = await loop.run(ctx, "scan")

        # Should still complete (executor failure doesn't crash)
        assert result.success is True


# ── Submit Findings Tests ──────────────────────────────────────


class TestSubmitFindings:
    async def test_submit_findings_creates_result(self):
        findings = [{"type": "xss", "url": "http://example.com", "severity": "High"}]
        decisions = [
            Decision(
                action_data={"action": "submit_findings", "findings": findings},
                reasoning="report",
                source="test",
            ),
            Decision(
                action_data={"action": "finish", "summary": "Done"},
                reasoning="done",
                source="test",
            ),
        ]
        engine = MockDecisionEngine(decisions)
        processor = MockPostProcessor()
        loop = ScanLoop(engine, processor)

        ctx = _make_ctx()
        result = await loop.run(ctx, "scan")

        assert result.success is True
        # Post processor should have been called with the findings result
        assert len(processor.processed) == 1


# ── ScanResult Tests ──────────────────────────────────────────


class TestScanResult:
    def test_default_values(self):
        r = ScanResult()
        assert r.summary == ""
        assert r.findings == []
        assert r.steps_taken == 0
        assert r.success is False
        assert r.action_history == []

    def test_with_values(self):
        r = ScanResult(
            summary="Done",
            findings=[{"type": "xss"}],
            steps_taken=5,
            success=True,
            action_history=["run_shell:nmap", "finish:"],
        )
        assert r.summary == "Done"
        assert len(r.findings) == 1
        assert r.steps_taken == 5
        assert r.success is True
        assert len(r.action_history) == 2
