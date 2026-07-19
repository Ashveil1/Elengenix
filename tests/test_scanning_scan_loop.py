"""Tests for elengenix/scanning/scan_loop.py — ScanLoop + ScanResult."""
from __future__ import annotations

import asyncio
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

    def test_finish_action_ends(self, loop, ctx, decision_engine):
        decision_engine.decide.return_value = _decision({"action": "finish"})
        result = asyncio.run(loop.run(ctx, "test"))
        assert result.success is True
        assert isinstance(result, ScanResult)

    def test_max_steps_respected(self, loop, ctx, decision_engine):
        decision_engine.decide.return_value = _decision({"action": "run_shell", "command": "echo hi"})
        result = asyncio.run(loop.run(ctx, "loop test"))
        assert result.steps_taken <= ctx.max_steps

    def test_no_executor(self, decision_engine, pp, ctx):
        decision_engine.decide.return_value = _decision({"action": "finish"})
        loop = ScanLoop(decision_engine=decision_engine, post_processor=pp)
        result = asyncio.run(loop.run(ctx, "test"))
        assert isinstance(result, ScanResult)

    def test_submit_findings(self, loop, ctx, decision_engine, pp):
        findings_data = [{"vuln": "xss", "severity": "high"}]
        decision_engine.decide.side_effect = [
            _decision({"action": "submit_findings", "findings": findings_data, "reasoning": "found"}),
            _decision({"action": "finish", "reasoning": "done"}),
        ]
        result = asyncio.run(loop.run(ctx, "test"))
        assert isinstance(result, ScanResult)

    def test_submit_findings_with_findings_calls_callback(self, ctx, decision_engine, pp, executor):
        cb = MagicMock()
        findings_data = [{"vuln": "xss", "severity": "high"}]
        decision_engine.decide.side_effect = [
            _decision({"action": "submit_findings", "findings": findings_data, "reasoning": "found"}),
            _decision({"action": "finish", "reasoning": "done"}),
        ]
        loop = ScanLoop(decision_engine=decision_engine, post_processor=pp,
                         executor=executor, callback=cb)
        loop._run_reasoning_phase = MagicMock(return_value=[])
        asyncio.run(loop.run(ctx, "test"))
        cb.assert_called_once()

    def test_save_memory(self, loop, ctx, decision_engine):
        decision_engine.decide.side_effect = [
            _decision({"action": "save_memory", "content": "test"}),
            _decision({"action": "finish"}),
        ]
        result = asyncio.run(loop.run(ctx, "test"))
        assert isinstance(result, ScanResult)

    def test_web_search(self, loop, ctx, decision_engine):
        decision_engine.decide.side_effect = [
            _decision({"action": "web_search", "query": "test"}),
            _decision({"action": "finish"}),
        ]
        result = asyncio.run(loop.run(ctx, "test"))
        assert isinstance(result, ScanResult)

    def test_deadlock_detected(self, loop, ctx, decision_engine):
        decision_engine.decide.return_value = _decision({"action": "web_search", "query": "x"})
        result = asyncio.run(loop.run(ctx, "test"))
        assert isinstance(result, ScanResult)

    def test_callback_invoked(self, ctx, decision_engine, pp, executor):
        cb = MagicMock()
        decision_engine.decide.side_effect = [
            _decision({"action": "submit_findings", "findings": [{"vuln": "xss"}]}),
            _decision({"action": "finish"}),
        ]
        loop = ScanLoop(decision_engine=decision_engine, post_processor=pp,
                         executor=executor, callback=cb)
        asyncio.run(loop.run(ctx, "test"))
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


# ===================================================================
# _maybe_replan (periodic re-planning)
# ===================================================================


class TestMaybeReplan:
    """Every N steps, the scan loop regenerates the attack tree from
    current findings so the strategy adapts to what the AI has learned
    — instead of being locked to the initial pre-scan plan."""

    @pytest.fixture
    def ctx(self):
        # Use a SimpleNamespace so attribute writes aren't shadowed by
        # MagicMock's auto-attribute behavior (MagicMock returns a mock
        # for ANY attribute access, which breaks our setattr-on-first-write logic).
        from types import SimpleNamespace
        ctx = SimpleNamespace(
            target="example.com",
            objective="find vulnerabilities",
            all_findings=[],
            attack_tree=MagicMock(),
            planner=MagicMock(),
        )
        return ctx

    @pytest.fixture
    def loop_with_replan(self):
        de = MagicMock()
        pp = MagicMock()
        exec_ = MagicMock(return_value=(True, MagicMock(output="ok"), "ok"))
        loop = ScanLoop(
            decision_engine=de,
            post_processor=pp,
            executor=exec_,
            loop_threshold=5,
            replan_every=3,
        )
        loop._run_reasoning_phase = MagicMock(return_value=[])
        return loop

    def test_no_replan_when_planner_missing(self, loop_with_replan, ctx):
        ctx.planner = None
        ctx.attack_tree = MagicMock()
        original_tree = ctx.attack_tree
        loop_with_replan._maybe_replan(ctx, "scan me", step=3)
        # Tree should be unchanged
        assert ctx.attack_tree is original_tree

    def test_replan_regenerates_attack_tree(self, loop_with_replan, ctx):
        mock_planner = MagicMock()
        new_tree = MagicMock()
        new_tree.steps = ["new_step_1", "new_step_2"]
        mock_planner.generate_attack_tree.return_value = new_tree
        ctx.planner = mock_planner
        ctx.target = "example.com"
        ctx.objective = "find vulnerabilities"
        ctx.all_findings = [{"type": "xss"}]
        old_tree = ctx.attack_tree

        loop_with_replan._maybe_replan(ctx, "scan me", step=3)

        assert ctx.attack_tree is new_tree
        assert mock_planner.generate_attack_tree.call_count == 1

    def test_replan_records_history_on_ctx(self, loop_with_replan, ctx):
        mock_planner = MagicMock()
        new_tree = MagicMock()
        new_tree.steps = [1, 2, 3]
        mock_planner.generate_attack_tree.return_value = new_tree
        ctx.planner = mock_planner
        ctx.target = "example.com"

        loop_with_replan._maybe_replan(ctx, "scan me", step=3)

        assert hasattr(ctx, "replan_history")
        assert len(ctx.replan_history) == 1
        assert ctx.replan_history[0]["step"] == 3
        assert ctx.replan_history[0]["new_steps"] == 3

    def test_replan_increments_count(self, loop_with_replan, ctx):
        mock_planner = MagicMock()
        new_tree = MagicMock(); new_tree.steps = []
        mock_planner.generate_attack_tree.return_value = new_tree
        ctx.planner = mock_planner
        ctx.target = "example.com"

        assert loop_with_replan._replan_count == 0
        loop_with_replan._maybe_replan(ctx, "scan me", step=3)
        assert loop_with_replan._replan_count == 1
        loop_with_replan._maybe_replan(ctx, "scan me", step=6)
        assert loop_with_replan._replan_count == 2

    def test_replan_exception_doesnt_break_loop(self, loop_with_replan, ctx):
        mock_planner = MagicMock()
        mock_planner.generate_attack_tree.side_effect = RuntimeError("api down")
        ctx.planner = mock_planner
        ctx.target = "example.com"
        original_tree = ctx.attack_tree

        # Should NOT raise
        loop_with_replan._maybe_replan(ctx, "scan me", step=3)
        # Tree unchanged
        assert ctx.attack_tree is original_tree

    def test_replan_calls_callback(self, loop_with_replan, ctx):
        mock_planner = MagicMock()
        new_tree = MagicMock(); new_tree.steps = [1, 2]
        mock_planner.generate_attack_tree.return_value = new_tree
        ctx.planner = mock_planner
        ctx.target = "example.com"
        loop_with_replan.callback = MagicMock()

        loop_with_replan._maybe_replan(ctx, "scan me", step=3)

        callback_msgs = [c.args[0] for c in loop_with_replan.callback.call_args_list if c.args]
        assert any("[RE-PLAN]" in m for m in callback_msgs)

    def test_replan_every_zero_disables_feature(self, ctx):
        de = MagicMock(); pp = MagicMock(); exec_ = MagicMock()
        loop = ScanLoop(
            decision_engine=de,
            post_processor=pp,
            executor=exec_,
            replan_every=0,
        )
        loop._run_reasoning_phase = MagicMock(return_value=[])
        # Even with a planner present, no re-plan should happen because
        # the run loop never calls _maybe_replan when replan_every=0.
        assert loop.replan_every == 0

