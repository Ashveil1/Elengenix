"""Tests for elengenix/scanning/scan_loop.py — ScanLoop + ScanResult."""
from __future__ import annotations

import pytest
from types import SimpleNamespace
from unittest.mock import MagicMock, AsyncMock, patch

from elengenix.scanning.scan_loop import ScanLoop, ScanResult


def _decision(action_data, reasoning=""):
    """Helper: create a mock decision as returned by DecisionEngine.decide()."""
    return SimpleNamespace(action_data=action_data, reasoning=reasoning)


# ===================================================================
# ScanResult
# ===================================================================


class TestScanResult:
    def test_default(self):
        sr = ScanResult()
        assert sr.summary == ""
        assert sr.findings == []
        assert sr.steps_taken == 0
        assert sr.success is False
        assert sr.action_history == []

    def test_custom(self):
        sr = ScanResult("done", [{"k": "v"}], 5, True, ["step1"])
        assert sr.summary == "done"
        assert sr.findings == [{"k": "v"}]
        assert sr.steps_taken == 5
        assert sr.success is True

    def test_findings_mutable(self):
        sr = ScanResult()
        sr.findings.append({"a": 1})
        assert len(sr.findings) == 1


# ===================================================================
# ScanLoop
# ===================================================================


class TestScanLoop:
    @pytest.fixture
    def ctx(self):
        c = MagicMock()
        c.max_steps = 5
        c.findings = []
        c.steps_taken = 0
        c.action_history = []
        c.all_findings = []
        c.target = "example.com"
        c.append_history = MagicMock()
        return c

    @pytest.fixture
    def decision_engine(self):
        de = MagicMock()
        de.decide = MagicMock()
        return de

    @pytest.fixture
    def pp(self):
        p = MagicMock()
        p.process = AsyncMock(return_value=("continue", {}, "ok"))
        return p


    @pytest.fixture
    def executor(self):
        def fake_exec(action_data, ctx):
            return (True, {"output": "done"}, "executed")
        return fake_exec

    @pytest.fixture(autouse=True)
    def _mock_search_web(self):
        """Mock search_web globally to prevent real HTTP calls."""
        with patch("tools.research_tool.search_web", return_value="mocked search result"):
            yield

    @pytest.fixture
    def loop(self, decision_engine, pp, executor):
        loop = ScanLoop(
            decision_engine=decision_engine,
            post_processor=pp,
            executor=executor,
            loop_threshold=5,
        )
        loop._run_reasoning_phase = MagicMock(return_value=[])
        return loop

    # -- run() tests --

    @pytest.mark.asyncio
    async def test_finish_action_ends(self, loop, ctx, decision_engine):
        decision_engine.decide.return_value = _decision({"action": "finish"})
        result = await loop.run(ctx, "test")
        assert result.success is True
        assert isinstance(result, ScanResult)

    @pytest.mark.asyncio
    async def test_max_steps_respected(self, loop, ctx, decision_engine):
        decision_engine.decide.return_value = _decision({"action": "run_shell", "command": "echo hi"})
        result = await loop.run(ctx, "loop test")
        assert result.steps_taken <= ctx.max_steps

    @pytest.mark.asyncio
    async def test_no_executor(self, decision_engine, pp, ctx):
        decision_engine.decide.return_value = _decision({"action": "finish"})
        loop = ScanLoop(decision_engine=decision_engine, post_processor=pp)
        result = await loop.run(ctx, "test")
        assert isinstance(result, ScanResult)

    @pytest.mark.asyncio
    async def test_submit_findings(self, loop, ctx, decision_engine, pp):
        findings_data = [{"vuln": "xss", "severity": "high"}]
        decision_engine.decide.side_effect = [
            _decision({"action": "submit_findings", "findings": findings_data, "reasoning": "found"}),
            _decision({"action": "finish", "reasoning": "done"}),
        ]
        result = await loop.run(ctx, "test")
        assert isinstance(result, ScanResult)

    @pytest.mark.asyncio
    async def test_submit_findings_with_findings_calls_callback(self, ctx, decision_engine, pp, executor):
        cb = MagicMock()
        findings_data = [{"vuln": "xss", "severity": "high"}]
        decision_engine.decide.side_effect = [
            _decision({"action": "submit_findings", "findings": findings_data, "reasoning": "found"}),
            _decision({"action": "finish", "reasoning": "done"}),
        ]
        loop = ScanLoop(decision_engine=decision_engine, post_processor=pp,
                         executor=executor, callback=cb)
        loop._run_reasoning_phase = MagicMock(return_value=[])
        await loop.run(ctx, "test")
        cb.assert_called_once()

    @pytest.mark.asyncio
    async def test_save_memory(self, loop, ctx, decision_engine):
        decision_engine.decide.side_effect = [
            _decision({"action": "save_memory", "content": "test"}),
            _decision({"action": "finish"}),
        ]
        result = await loop.run(ctx, "test")
        assert isinstance(result, ScanResult)

    @pytest.mark.asyncio
    async def test_web_search(self, loop, ctx, decision_engine):
        decision_engine.decide.side_effect = [
            _decision({"action": "web_search", "query": "test"}),
            _decision({"action": "finish"}),
        ]
        result = await loop.run(ctx, "test")
        assert isinstance(result, ScanResult)

    @pytest.mark.asyncio
    async def test_deadlock_detected(self, loop, ctx, decision_engine):
        decision_engine.decide.return_value = _decision({"action": "web_search", "query": "x"})
        result = await loop.run(ctx, "test")
        assert isinstance(result, ScanResult)

    @pytest.mark.asyncio
    async def test_callback_invoked(self, ctx, decision_engine, pp, executor):
        cb = MagicMock()
        decision_engine.decide.side_effect = [
            _decision({"action": "submit_findings", "findings": [{"vuln": "xss"}]}),
            _decision({"action": "finish"}),
        ]
        loop = ScanLoop(decision_engine=decision_engine, post_processor=pp,
                         executor=executor, callback=cb)
        await loop.run(ctx, "test")
        cb.assert_called()

    # -- internal methods --

    def test_validate_action_finish(self, loop, ctx):
        d = _decision({"action": "finish"})
        result = loop._validate_action(ctx, d, "test", 0)
        assert isinstance(result, ScanResult)
        assert result.success is True

    def test_validate_action_continue(self, loop, ctx):
        d = _decision({"action": "run_shell"})
        result = loop._validate_action(ctx, d, "test", 0)
        assert result is None

    def test_is_save_memory_positive(self, loop):
        assert loop._is_save_memory(_decision({"action": "save_memory"})) is True

    def test_is_save_memory_negative(self, loop):
        assert loop._is_save_memory(_decision({"action": "run_shell"})) is False

    def test_action_signature(self, loop):
        d = _decision({"action": "run_shell", "command": "ls"})
        sig = loop._action_signature(d)
        assert "run_shell" in sig
        assert "ls" in sig

    def test_action_signature_empty(self, loop):
        d = _decision({})
        sig = loop._action_signature(d)
        assert sig == ":"
