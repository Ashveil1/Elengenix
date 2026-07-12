"""tests/test_decision_engine.py — Tests for agents.decision_engine.DecisionEngine"""

from dataclasses import dataclass, field
from typing import Any, Dict
from unittest.mock import MagicMock, patch

import pytest

from elengenix.scanning.decision_engine import Decision, DecisionEngine, Reflection
from elengenix.scanning.scan_context import ScanContext


# ── Mock Objects ────────────────────────────────────────────────


class MockReflectEngine:
    def __init__(self, status="on_track", switch=False, recommendation="keep going"):
        self._status = status
        self._switch = switch
        self._recommendation = recommendation
        self.reflect = MagicMock(return_value=self._make_result())

    def _make_result(self):
        result = MagicMock()
        result.status = self._status
        result.switch_strategy = self._switch
        result.recommendation = self._recommendation
        return result


class MockCoverageMap:
    def get_gaps(self):
        return ["gap1", "gap2"]


class MockBeliefState:
    def get_active_beliefs(self):
        return ["belief1"]


class MockAttackTree:
    def __init__(self, steps=None):
        self.steps = steps or []
        self.reasoning = "test reasoning"


@dataclass
class MockAttackStep:
    tool_name: str = "nmap"
    purpose: str = "Port scan"
    completed: bool = False
    phase: str = "recon"  # Mock phase (string for simplicity)


class MockAIClient:
    def __init__(self, response=None):
        self._response = response
        self.call_count = 0

    def chat(self, messages, temperature=0.2, tools=None):
        self.call_count += 1
        return self._response


class MockToolCall:
    def __init__(self, name="run_shell", arguments=None):
        self.name = name
        self.arguments = arguments or {"command": "nmap target"}


class MockAIResponse:
    def __init__(self, content="", tool_calls=None):
        self.content = content
        self.tool_calls = tool_calls or []


# ── Helper ──────────────────────────────────────────────────────


def _make_ctx(**kwargs) -> ScanContext:
    defaults = {"target": "example.com", "objective": "Find vulns"}
    defaults.update(kwargs)
    return ScanContext(**defaults)


# ── Reflection Tests ────────────────────────────────────────────


class TestReflection:
    def test_reflect_returns_on_track_by_default(self):
        engine = DecisionEngine()
        ctx = _make_ctx()
        ctx.coverage_map = MockCoverageMap()
        ctx.belief_state = MockBeliefState()

        result = engine._reflect(ctx, None, 0, "scan example.com")
        assert result.status == "on_track"

    def test_reflect_uses_engine(self):
        reflect = MockReflectEngine(status="stuck", switch=True, recommendation="try XSS")
        engine = DecisionEngine()
        ctx = _make_ctx()
        ctx.coverage_map = MockCoverageMap()
        ctx.belief_state = MockBeliefState()

        result = engine._reflect(ctx, reflect, 0, "scan example.com")
        assert result.status == "stuck"
        assert result.switch_strategy is True
        assert result.recommendation == "try XSS"

    def test_reflect_counts_gaps_and_beliefs(self):
        reflect = MockReflectEngine()
        engine = DecisionEngine()
        ctx = _make_ctx()
        ctx.coverage_map = MockCoverageMap()
        ctx.belief_state = MockBeliefState()

        result = engine._reflect(ctx, reflect, 0, "scan example.com")
        assert result.coverage_gaps == 2
        assert result.active_beliefs == 1

    def test_reflect_handles_none_coverage_map(self):
        engine = DecisionEngine()
        ctx = _make_ctx()
        ctx.coverage_map = None
        ctx.belief_state = MockBeliefState()

        result = engine._reflect(ctx, MockReflectEngine(), 0, "scan")
        assert result.status == "on_track"

    def test_reflect_handles_exception(self):
        reflect = MockReflectEngine()
        reflect.reflect.side_effect = RuntimeError("boom")
        engine = DecisionEngine()
        ctx = _make_ctx()
        ctx.coverage_map = MockCoverageMap()
        ctx.belief_state = MockBeliefState()

        result = engine._reflect(ctx, reflect, 0, "scan")
        assert result.status == "on_track"  # Fallback on error


# ── Attack Tree Tests ──────────────────────────────────────────


class TestFollowAttackTree:
    def test_follow_tree_returns_correct_action(self):
        step = MockAttackStep(tool_name="nmap", purpose="Port scan")
        tree = MockAttackTree(steps=[step])
        ctx = _make_ctx()
        ctx.attack_tree = tree

        engine = DecisionEngine()
        decision = engine._follow_attack_tree(ctx, 0)

        assert decision.source == "attack_tree"
        assert decision.action_data["action"] == "run_shell"
        assert decision.action_data["tool"] == "nmap"
        assert "nmap" in decision.action_data["command"]
        assert "example.com" in decision.action_data["command"]
        assert decision.reasoning == "Port scan"

    def test_follow_tree_with_multiple_steps(self):
        steps = [
            MockAttackStep(tool_name="recon", purpose="Reconnaissance"),
            MockAttackStep(tool_name="fuzzer", purpose="Fuzzing"),
        ]
        tree = MockAttackTree(steps=steps)
        ctx = _make_ctx()
        ctx.attack_tree = tree

        engine = DecisionEngine()
        decision = engine._follow_attack_tree(ctx, 1)

        assert decision.action_data["tool"] == "fuzzer"
        assert decision.reasoning == "Fuzzing"


# ── AI Dynamic Planning Tests ─────────────────────────────────


class TestAIDynamicPlanning:
    def _make_engine(self, client=None, prompt_builder=None):
        """Helper to create engine with both client and prompt_builder."""
        if client is None:
            client = MockAIClient()
        if prompt_builder is None:
            pb = MagicMock()
            pb.build_scan_prompt.return_value = "test prompt"
            prompt_builder = pb
        return DecisionEngine(ai_client=client, prompt_builder=prompt_builder)

    def test_ai_planning_with_tool_calls(self):
        response = MockAIResponse(
            tool_calls=[
                MockToolCall(
                    "run_shell", {"command": "nmap -sV target", "purpose": "Service detection"}
                )
            ]
        )
        client = MockAIClient(response)
        engine = self._make_engine(client=client)

        ctx = _make_ctx()
        decision = engine._ai_dynamic_planning(ctx, "Find SQLi")

        assert decision.source == "ai_dynamic"
        assert decision.action_data["action"] == "run_shell"
        assert "nmap" in decision.action_data["command"]
        assert client.call_count == 1

    def test_ai_planning_with_json_fallback(self):
        response = MockAIResponse(
            content='{"action": "web_search", "query": "SQLi techniques", "purpose": "Research"}'
        )
        client = MockAIClient(response)
        engine = self._make_engine(client=client)

        ctx = _make_ctx()
        decision = engine._ai_dynamic_planning(ctx, "Find SQLi")

        assert decision.source == "ai_dynamic"
        assert decision.action_data["action"] == "web_search"

    def test_ai_planning_handles_no_client(self):
        engine = DecisionEngine(ai_client=None)
        ctx = _make_ctx()

        decision = engine._ai_dynamic_planning(ctx, "Find SQLi")
        assert decision.source == "fallback"
        assert decision.action_data["action"] == "finish"

    def test_ai_planning_handles_no_prompt_builder(self):
        engine = DecisionEngine(ai_client=MockAIClient(), prompt_builder=None)
        ctx = _make_ctx()

        decision = engine._ai_dynamic_planning(ctx, "Find SQLi")
        assert decision.source == "fallback"

    def test_ai_planning_handles_exception(self):
        client = MockAIClient()
        client.chat = MagicMock(side_effect=RuntimeError("API error"))
        engine = self._make_engine(client=client)

        ctx = _make_ctx()
        decision = engine._ai_dynamic_planning(ctx, "Find SQLi")

        assert decision.source == "fallback"
        assert "error" in decision.reasoning.lower()


# ── Main Decide Tests ─────────────────────────────────────────


class TestDecide:
    def _make_engine(self, client=None):
        """Helper to create engine with mock prompt_builder."""
        if client is None:
            client = MockAIClient()
        pb = MagicMock()
        pb.build_scan_prompt.return_value = "test prompt"
        return DecisionEngine(ai_client=client, prompt_builder=pb)

    def test_decide_always_uses_ai(self):
        """DecisionEngine now always asks AI, even with attack tree available."""
        step = MockAttackStep(tool_name="nmap", purpose="Port scan")
        tree = MockAttackTree(steps=[step])
        ctx = _make_ctx()
        ctx.attack_tree = tree
        ctx.coverage_map = MockCoverageMap()
        ctx.belief_state = MockBeliefState()

        response = MockAIResponse(
            tool_calls=[MockToolCall("run_shell", {"command": "nmap target", "purpose": "scan"})]
        )
        client = MockAIClient(response)
        engine = self._make_engine(client=client)
        decision = engine.decide(ctx, "scan example.com", reflect_engine=MockReflectEngine())

        # Now AI always decides, even with attack tree
        assert decision.source == "ai_dynamic"
        assert decision.reflection is not None

    def test_decide_switches_to_ai_when_tree_exhausted(self):
        tree = MockAttackTree(steps=[])  # Empty tree
        ctx = _make_ctx()
        ctx.attack_tree = tree
        ctx.coverage_map = MockCoverageMap()
        ctx.belief_state = MockBeliefState()

        response = MockAIResponse(
            tool_calls=[MockToolCall("run_shell", {"command": "dirb target"})]
        )
        client = MockAIClient(response)
        engine = self._make_engine(client=client)

        decision = engine.decide(ctx, "scan example.com", reflect_engine=MockReflectEngine())

        assert decision.source == "ai_dynamic"

    def test_decide_switches_to_ai_on_reflection(self):
        step = MockAttackStep()
        tree = MockAttackTree(steps=[step])
        ctx = _make_ctx()
        ctx.attack_tree = tree
        ctx.coverage_map = MockCoverageMap()
        ctx.belief_state = MockBeliefState()

        reflect = MockReflectEngine(switch=True, recommendation="try different approach")
        response = MockAIResponse(
            tool_calls=[MockToolCall("run_shell", {"command": "dirb target"})]
        )
        client = MockAIClient(response)
        engine = self._make_engine(client=client)

        decision = engine.decide(ctx, "scan example.com", reflect_engine=reflect)

        assert decision.source == "ai_dynamic"
        assert decision.reflection.switch_strategy is True

    def test_decide_stores_reflection(self):
        ctx = _make_ctx()
        ctx.coverage_map = MockCoverageMap()
        ctx.belief_state = MockBeliefState()

        reflect = MockReflectEngine(status="stuck")
        engine = self._make_engine()

        decision = engine.decide(ctx, "scan", reflect_engine=reflect)
        assert decision.reflection.status == "stuck"
        assert engine.last_reflection.status == "stuck"


# ── Extract JSON Tests ─────────────────────────────────────────


class TestExtractJSON:
    def test_extract_json_from_direct(self):
        engine = DecisionEngine()
        result = engine._extract_json('{"action": "run_shell", "command": "ls"}')
        assert result["action"] == "run_shell"

    def test_extract_json_from_code_block(self):
        engine = DecisionEngine()
        text = '```json\n{"action": "web_search", "query": "test"}\n```'
        result = engine._extract_json(text)
        assert result["action"] == "web_search"

    def test_extract_json_from_mixed_text(self):
        engine = DecisionEngine()
        text = 'Here is my plan: {"action": "finish", "summary": "done"} Hope this helps!'
        result = engine._extract_json(text)
        assert result["action"] == "finish"

    def test_extract_json_returns_none_for_invalid(self):
        engine = DecisionEngine()
        result = engine._extract_json("no json here")
        assert result is None

    def test_extract_json_returns_none_for_empty(self):
        engine = DecisionEngine()
        result = engine._extract_json("")
        assert result is None
