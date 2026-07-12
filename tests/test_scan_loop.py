"""
tests/test_scan_loop.py — Tests for agents.scan_loop.ScanLoop
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Tuple
from unittest.mock import MagicMock

import pytest

from elengenix.scanning.decision_engine import Decision
from elengenix.scanning.scan_context import ScanContext
from elengenix.scanning.scan_loop import ScanLoop, ScanResult


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
    """Shared mock executor that simulates a successful shell command."""
    tool_name = action_data.get("tool", "test_tool")
    command = action_data.get("command", "")
    return True, f"mock output for: {command}", tool_name


def _noop_client() -> MagicMock:
    """Return a mock AI client so ScanLoop doesn't try real provider init."""
    client = MagicMock()
    return client


def _make_loop(
    engine,
    processor,
    executor=_mock_executor,
    loop_threshold=3,
    **kwargs,
) -> ScanLoop:
    """Create a ScanLoop with a noop client to avoid AI provider timeouts."""
    return ScanLoop(
        engine,
        processor,
        executor=executor,
        loop_threshold=loop_threshold,
        client=_noop_client(),
        **kwargs,
    )


# ── Tests ────────────────────────────────────────────────────────


class TestScanLoopCreation:
    async def test_create_with_defaults(self):
        engine = MockDecisionEngine()
        processor = MockPostProcessor()
        loop = _make_loop(engine, processor)

        assert loop.decision_engine is engine
        assert loop.post_processor is processor
        assert loop.loop_threshold == 3

    async def test_create_with_custom_threshold(self):
        engine = MockDecisionEngine()
        processor = MockPostProcessor()
        loop = _make_loop(engine, processor, loop_threshold=5)

        assert loop.loop_threshold == 5


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
        loop = _make_loop(engine, processor)

        ctx = _make_ctx()
        result = await loop.run(ctx, "scan example.com")

        assert result.success is True
        assert "Mission complete" in result.summary
        assert result.steps_taken == 1

    async def test_max_steps_terminates(self):
        # No finish decision — should hit max_steps
        engine = MockDecisionEngine(decisions=[])
        processor = MockPostProcessor()
        loop = _make_loop(engine, processor)

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
        loop = _make_loop(engine, processor)

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
        loop = _make_loop(engine, processor, loop_threshold=3)

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
        loop = _make_loop(engine, processor)

        ctx = _make_ctx()
        result = await loop.run(ctx, "scan")

        assert result.success is True
        assert result.steps_taken == 3

    async def test_threshold_three(self):
        # 3 identical actions should trigger deadlock
        same_action = Decision(
            action_data={"action": "run_shell", "command": "ping target"},
            reasoning="ping",
            source="test",
        )
        decisions = [same_action] * 5
        engine = MockDecisionEngine(decisions)
        processor = MockPostProcessor()
        loop = _make_loop(engine, processor, loop_threshold=3)

        ctx = _make_ctx()
        result = await loop.run(ctx, "scan")

        assert "DEADLOCK" in result.summary

    async def test_threshold_not_met(self):
        # 2 identical < threshold 3 → should not deadlock before finish
        same_action = Decision(
            action_data={"action": "run_shell", "command": "nmap target"},
            reasoning="nmap",
            source="test",
        )
        finish = Decision(
            action_data={"action": "finish", "summary": "Done early"},
            reasoning="finish",
            source="test",
        )
        decisions = [same_action, same_action, finish]
        engine = MockDecisionEngine(decisions)
        processor = MockPostProcessor()
        loop = _make_loop(engine, processor, loop_threshold=3)

        ctx = _make_ctx()
        result = await loop.run(ctx, "scan")

        assert result.success is True
        assert result.steps_taken == 3


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
        loop = _make_loop(engine, processor)

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
        loop = _make_loop(engine, processor, executor=_mock_executor)

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
        loop = _make_loop(engine, processor, executor=_mock_executor)

        ctx = _make_ctx()
        result = await loop.run(ctx, "scan")

        # The thought should appear in history before the observation
        history_text = " ".join(h["content"] for h in ctx.history)
        assert "SQLi" in history_text or "thought" in history_text.lower()
        assert result.success is True
