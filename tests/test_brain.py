"""Tests for elengenix/brain.py — Cognitive core dataclasses and synchronous methods."""

from __future__ import annotations

import asyncio
import pytest
from unittest.mock import MagicMock, Mock, patch
import time

from elengenix.brain import (
    CognitiveState,
    ReasoningResult,
    AttackPlan,
    PlanPhase,
    PerceptionModule,
    ReasoningEngine,
    DecisionEngine,
    TrueAIBrain,
)


class TestCognitiveState:
    def test_default_values(self):
        state = CognitiveState()
        assert state.current_goal == ""
        assert state.active_plan is None
        assert state.current_step == 0
        assert state.confidence == 0.5

    def test_with_values(self):
        state = CognitiveState(current_goal="scan target", confidence=0.8)
        assert state.current_goal == "scan target"
        assert state.confidence == 0.8


class TestReasoningResult:
    def test_default_values(self):
        result = ReasoningResult(reasoning_type="deductive", premise="p", conclusion="c", confidence=0.7)
        assert result.reasoning_type == "deductive"
        assert result.premise == "p"
        assert result.conclusion == "c"
        assert result.confidence == 0.7

    def test_with_all_fields(self):
        result = ReasoningResult(
            reasoning_type="abductive", premise="p", conclusion="c", confidence=0.9,
            evidence=[{"type": "obs"}], alternative_hypotheses=["a1"], reasoning_trace=["s1"],
        )
        assert len(result.evidence) == 1
        assert len(result.alternative_hypotheses) == 1


class TestAttackPlan:
    def test_default_values(self):
        plan = AttackPlan()
        assert plan.plan_id != ""
        assert plan.goal == ""
        assert plan.phases == []

    def test_plan_id_unique(self):
        assert AttackPlan().plan_id != AttackPlan().plan_id


class TestPlanPhase:
    def test_default_values(self):
        phase = PlanPhase()
        assert phase.name == ""
        assert phase.tools == []
        assert phase.risk_level == "medium"


class TestPerceptionModule:
    def test_init(self):
        mod = PerceptionModule(memory=Mock(), tools=Mock())
        assert mod.memory is not None

    def test_summarize_findings(self):
        assert PerceptionModule(memory=Mock(), tools=Mock())._summarize_findings() == {"total": 0, "by_severity": {}, "by_type": {}}

    def test_assess_resources(self):
        r = PerceptionModule(memory=Mock(), tools=Mock())._assess_resources()
        assert r["api_calls_remaining"] == 1000

    def test_assess_threat_level(self):
        assert PerceptionModule(memory=Mock(), tools=Mock())._assess_threat_level() == "low"

    def test_perceive(self):
        mod = PerceptionModule(memory=Mock(), tools=Mock())
        ctx = MagicMock()
        ctx.target = "example.com"
        p = asyncio.run(mod.perceive(ctx))
        assert "timestamp" in p
        assert "threat_level" in p

    def test_assess_target(self):
        mod = PerceptionModule(memory=Mock(), tools=Mock())
        r = asyncio.run(mod._assess_target("example.com"))
        assert r["target"] == "example.com"
        assert r["status"] == "active"

    def test_assess_threat_landscape(self):
        mod = PerceptionModule(memory=Mock(), tools=Mock())
        r = asyncio.run(mod._assess_threat_landscape())
        assert r["waf_detected"] is False


class TestReasoningEngine:
    def test_parse_reasoning(self):
        engine = ReasoningEngine(llm_client=Mock(), memory=Mock())
        result = engine._parse_reasoning("test response", "deductive")
        assert result.reasoning_type == "deductive"
        assert result.conclusion == "test response"
        assert result.confidence == 0.7

    def test_parse_reasoning_truncates(self):
        engine = ReasoningEngine(llm_client=Mock(), memory=Mock())
        result = engine._parse_reasoning("x" * 600, "abductive")
        assert len(result.conclusion) == 500
        assert len(result.reasoning_trace[0]) == 200

    def test_reason_calls_strategy(self):
        engine = ReasoningEngine(llm_client=Mock(), memory=Mock())
        engine.llm = MagicMock()
        engine.llm.chat.return_value = Mock(content='{"conclusion": "deductive result", "confidence": 0.8}')
        result = asyncio.run(engine.reason({"situation": "test"}, "goal", strategy="deductive"))
        assert result.reasoning_type == "deductive"
        assert result.conclusion == "deductive result"

    def test_reason_unknown_strategy(self):
        engine = ReasoningEngine(llm_client=Mock(), memory=Mock())
        engine.llm = MagicMock()
        engine.llm.chat.return_value = Mock(content='{"conclusion": "abductive result"}')
        result = asyncio.run(engine.reason({"situation": "test"}, "goal", strategy="unknown"))
        assert result.reasoning_type == "abductive"

    def test_all_strategies(self):
        engine = ReasoningEngine(llm_client=Mock(), memory=Mock())
        engine.llm = MagicMock()
        engine.llm.chat.return_value = Mock(content='{"conclusion": "result"}')
        for s in ["deductive", "inductive", "abductive", "analogical", "causal", "counterfactual"]:
            result = asyncio.run(engine.reason({"s": "t"}, "g", strategy=s))
            assert result.reasoning_type == s


class TestDecisionEngine:
    def test_init(self):
        engine = DecisionEngine(Mock(), Mock(), Mock(), Mock())
        assert engine.llm is not None

    def test_mission_alignment(self):
        engine = DecisionEngine(Mock(), Mock(), Mock(), Mock())
        ctx = MagicMock()
        ctx.target = "example.com"
        assert engine._mission_alignment({"tool": "nmap", "params": {"target": "example.com"}}, ctx) > 0.5
        assert engine._mission_alignment({"tool": "ls", "params": {}}, ctx) <= 0.5

    def test_expected_value(self):
        engine = DecisionEngine(Mock(), Mock(), Mock(), Mock())
        ctx = MagicMock()
        assert engine._expected_value({"tool": "nuclei", "params": {"endpoint": "/api"}}, ctx) > 0.3

    def test_risk_score(self):
        engine = DecisionEngine(Mock(), Mock(), Mock(), Mock())
        assert engine._risk_score({"tool": "rm", "risk_level": "high"}) > 0.5
        assert engine._risk_score({"tool": "ls", "risk_level": "safe"}) < 0.5

    def test_learning_value(self):
        engine = DecisionEngine(Mock(), Mock(), Mock(), Mock())
        assert engine._learning_value({"tool": "nmap"}) > 0.5

    def test_score_action(self):
        engine = DecisionEngine(Mock(), Mock(), Mock(), Mock())
        ctx = MagicMock()
        ctx.target = "example.com"
        score = asyncio.run(engine._score_action({"tool": "nmap", "risk_level": "safe"}, ctx))
        assert isinstance(score, float)
        assert 0.0 <= score <= 1.0

    def test_filter_by_governance_allows(self):
        engine = DecisionEngine(Mock(), Mock(), Mock(), Mock())
        gate = MagicMock()
        gate.decision = "allow"
        engine.governance.gate.return_value = gate
        ctx = MagicMock()
        ctx.target = "example.com"
        result = asyncio.run(engine._filter_by_governance([{"tool": "nmap"}], ctx))
        assert len(result) == 1

    def test_filter_by_governance_denies(self):
        engine = DecisionEngine(Mock(), Mock(), Mock(), Mock())
        gate = MagicMock()
        gate.decision = "deny"
        engine.governance.gate.return_value = gate
        ctx = MagicMock()
        ctx.target = "example.com"
        result = asyncio.run(engine._filter_by_governance([{"tool": "nmap"}], ctx))
        assert len(result) == 0

    def test_make_sovereign_decision(self):
        engine = DecisionEngine(Mock(), Mock(), Mock(), Mock())
        ctx = MagicMock()
        ctx.target = "nmap.example.com"
        decision = asyncio.run(engine._make_sovereign_decision(
            [{"tool": "nmap", "risk_level": "safe"}, {"tool": "ls", "risk_level": "safe"}], ctx
        ))
        assert decision.tool == "nmap"

    def test_create_action(self):
        engine = DecisionEngine(Mock(), Mock(), Mock(), Mock())
        action = engine._create_action({
            "action_type": "recon", "tool": "nmap", "target": "example.com",
            "parameters": {}, "description": "scan", "purpose": "recon", "risk_level": "safe",
        })
        from elengenix.types import AIAction
        assert isinstance(action, AIAction)
        assert action.tool == "nmap"

    def test_decide_no_allowed_actions(self):
        engine = DecisionEngine(Mock(), Mock(), Mock(), Mock())
        ctx = MagicMock()
        ctx.target = "example.com"
        gate = MagicMock()
        gate.decision = "deny"
        engine.governance.gate.return_value = gate
        result = asyncio.run(engine.decide({}, [{"tool": "nmap"}], ctx))
        assert result.action_type == "reporting"


class TestTrueAIBrain:
    def test_init(self):
        brain = TrueAIBrain(llm_client=Mock(), memory=Mock(), tools=Mock(), governance=Mock(), constitutional_engine=Mock())
        assert brain.perception is not None
        assert brain.reasoning is not None
        assert brain.planner is not None
        assert brain.decision_engine is not None

    def test_init_with_config(self):
        brain = TrueAIBrain(llm_client=Mock(), memory=Mock(), config={"k": "v"})
        assert brain.config == {"k": "v"}


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
