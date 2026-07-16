"""Tests for elengenix/brain.py — Cognitive core dataclasses and synchronous methods."""

from __future__ import annotations

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
    """Tests for CognitiveState dataclass."""

    def test_default_values(self):
        """Should have correct defaults."""
        state = CognitiveState()
        assert state.current_goal == ""
        assert state.active_plan is None
        assert state.current_step == 0
        assert state.situation_awareness == {}
        assert state.working_memory == {}
        assert state.confidence == 0.5
        assert state.stress_level == 0.0
        assert state.focus_area == ""
        assert state.last_reflection == 0

    def test_with_values(self):
        """Should accept custom values."""
        state = CognitiveState(
            current_goal="scan target",
            confidence=0.8,
            stress_level=0.3,
            focus_area="recon",
        )
        assert state.current_goal == "scan target"
        assert state.confidence == 0.8
        assert state.stress_level == 0.3
        assert state.focus_area == "recon"


class TestReasoningResult:
    """Tests for ReasoningResult dataclass."""

    def test_default_values(self):
        """Should have correct defaults."""
        result = ReasoningResult(
            reasoning_type="deductive",
            premise="test premise",
            conclusion="test conclusion",
            confidence=0.7,
        )
        assert result.reasoning_type == "deductive"
        assert result.premise == "test premise"
        assert result.conclusion == "test conclusion"
        assert result.confidence == 0.7
        assert result.evidence == []
        assert result.alternative_hypotheses == []
        assert result.reasoning_trace == []

    def test_with_all_fields(self):
        """Should accept all fields."""
        result = ReasoningResult(
            reasoning_type="abductive",
            premise="premise",
            conclusion="conclusion",
            confidence=0.9,
            evidence=[{"type": "observation", "data": "test"}],
            alternative_hypotheses=["alt1", "alt2"],
            reasoning_trace=["step1", "step2"],
        )
        assert len(result.evidence) == 1
        assert len(result.alternative_hypotheses) == 2
        assert len(result.reasoning_trace) == 2


class TestAttackPlan:
    """Tests for AttackPlan dataclass."""

    def test_default_values(self):
        """Should have correct defaults."""
        plan = AttackPlan()
        assert plan.plan_id != ""
        assert plan.goal == ""
        assert plan.target == ""
        assert plan.phases == []
        assert plan.risk_assessment == {}
        assert plan.resource_requirements == {}
        assert plan.success_criteria == []
        assert plan.contingencies == []
        assert plan.created_at > 0

    def test_with_values(self):
        """Should accept custom values."""
        plan = AttackPlan(
            goal="find vulns",
            target="example.com",
            risk_assessment={"overall": "medium"},
        )
        assert plan.goal == "find vulns"
        assert plan.target == "example.com"
        assert plan.risk_assessment == {"overall": "medium"}

    def test_plan_id_unique(self):
        """Each plan should have a unique ID."""
        p1 = AttackPlan()
        p2 = AttackPlan()
        assert p1.plan_id != p2.plan_id


class TestPlanPhase:
    """Tests for PlanPhase dataclass."""

    def test_default_values(self):
        """Should have correct defaults."""
        phase = PlanPhase()
        assert phase.phase_id != ""
        assert phase.name == ""
        assert phase.objective == ""
        assert phase.actions == []
        assert phase.dependencies == []
        assert phase.tools == []
        assert phase.estimated_duration == 0
        assert phase.risk_level == "medium"
        assert phase.success_criteria == []

    def test_with_values(self):
        """Should accept custom values."""
        phase = PlanPhase(
            name="recon",
            objective="enumerate targets",
            risk_level="low",
            tools=["nmap", "dig"],
            estimated_duration=300,
        )
        assert phase.name == "recon"
        assert phase.tools == ["nmap", "dig"]
        assert phase.estimated_duration == 300


class TestPerceptionModule:
    """Tests for PerceptionModule synchronous methods."""

    def test_init(self):
        """Init should set memory and tools."""
        mock_memory = Mock()
        mock_tools = Mock()
        mod = PerceptionModule(memory=mock_memory, tools=mock_tools)
        assert mod.memory is mock_memory
        assert mod.tools is mock_tools

    def test_summarize_findings(self):
        """_summarize_findings returns default."""
        mod = PerceptionModule(memory=Mock(), tools=Mock())
        result = mod._summarize_findings()
        assert result == {"total": 0, "by_severity": {}, "by_type": {}}

    def test_identify_coverage_gaps(self):
        """_identify_coverage_gaps returns empty list."""
        mod = PerceptionModule(memory=Mock(), tools=Mock())
        result = mod._identify_coverage_gaps()
        assert result == []

    def test_assess_resources(self):
        """_assess_resources returns defaults."""
        mod = PerceptionModule(memory=Mock(), tools=Mock())
        result = mod._assess_resources()
        assert result["api_calls_remaining"] == 1000
        assert result["time_remaining"] == 3600

    def test_assess_threat_level(self):
        """_assess_threat_level returns 'low'."""
        mod = PerceptionModule(memory=Mock(), tools=Mock())
        result = mod._assess_threat_level()
        assert result == "low"

    @pytest.mark.asyncio
    async def test_perceive(self):
        """perceive should return a perception dict."""
        mod = PerceptionModule(memory=Mock(), tools=Mock())
        context = MagicMock()
        context.target = "example.com"
        perception = await mod.perceive(context)
        assert "timestamp" in perception
        assert "target_status" in perception
        assert "findings_summary" in perception
        assert "threat_level" in perception

    @pytest.mark.asyncio
    async def test_assess_target(self):
        """_assess_target returns target info."""
        mod = PerceptionModule(memory=Mock(), tools=Mock())
        result = await mod._assess_target("example.com")
        assert result["target"] == "example.com"
        assert result["status"] == "active"

    @pytest.mark.asyncio
    async def test_assess_threat_landscape(self):
        """_assess_threat_landscape returns defaults."""
        mod = PerceptionModule(memory=Mock(), tools=Mock())
        result = await mod._assess_threat_landscape()
        assert result["waf_detected"] is False
        assert result["rate_limits"] == []


class TestReasoningEngine:
    """Tests for ReasoningEngine synchronous methods."""

    def test_parse_reasoning(self):
        """_parse_reasoning should return a ReasoningResult."""
        engine = ReasoningEngine(llm_client=Mock(), memory=Mock())
        result = engine._parse_reasoning("This is a test response", "deductive")
        assert result.reasoning_type == "deductive"
        assert result.conclusion == "This is a test response"
        assert result.confidence == 0.7

    def test_parse_reasoning_truncates_long_response(self):
        """Long response should be truncated."""
        engine = ReasoningEngine(llm_client=Mock(), memory=Mock())
        long_response = "x" * 600
        result = engine._parse_reasoning(long_response, "abductive")
        assert len(result.conclusion) == 500
        assert len(result.reasoning_trace[0]) == 200

    @pytest.mark.asyncio
    async def test_reason_calls_strategy(self):
        """reason() should dispatch to the correct strategy."""
        engine = ReasoningEngine(llm_client=Mock(), memory=Mock())
        engine.llm = MagicMock()
        engine.llm.chat.return_value = Mock(content='{"conclusion": "deductive result", "confidence": 0.8}')

        result = await engine.reason({"situation": "test"}, "goal", strategy="deductive")
        assert result.reasoning_type == "deductive"
        assert result.conclusion == "deductive result"

    @pytest.mark.asyncio
    async def test_reason_unknown_strategy_defaults_to_abductive(self):
        """Unknown strategy should default to abductive."""
        engine = ReasoningEngine(llm_client=Mock(), memory=Mock())
        engine.llm = MagicMock()
        engine.llm.chat.return_value = Mock(content='{"conclusion": "abductive result", "confidence": 0.7}')

        result = await engine.reason({"situation": "test"}, "goal", strategy="unknown")
        assert result.reasoning_type == "abductive"

    @pytest.mark.asyncio
    async def test_all_reasoning_strategies(self):
        """All 6 reasoning strategies should work."""
        engine = ReasoningEngine(llm_client=Mock(), memory=Mock())
        engine.llm = MagicMock()
        engine.llm.chat.return_value = Mock(content='{"conclusion": "strategy result", "confidence": 0.7}')

        for strategy in ["deductive", "inductive", "abductive", "analogical", "causal", "counterfactual"]:
            result = await engine.reason({"situation": "test"}, "goal", strategy=strategy)
            assert result.reasoning_type == strategy
            assert result.conclusion == "strategy result"


class TestDecisionEngine:
    """Tests for DecisionEngine synchronous methods."""

    def test_init(self):
        """Should set all attributes."""
        engine = DecisionEngine(
            llm_client=Mock(),
            reasoning=Mock(),
            constitutional_engine=Mock(),
            governance=Mock(),
        )
        assert engine.llm is not None
        assert engine.reasoning is not None
        assert engine.constitutional is not None
        assert engine.governance is not None

    def test_mission_alignment(self):
        """_mission_alignment should score based on tool relevance."""
        engine = DecisionEngine(Mock(), Mock(), Mock(), Mock())
        ctx = MagicMock()
        ctx.target = "example.com"
        # Security tool targeting the mission target
        result = engine._mission_alignment({"tool": "nmap", "params": {"target": "example.com"}}, ctx)
        assert result > 0.5
        # Non-security tool
        result = engine._mission_alignment({"tool": "ls", "params": {}}, ctx)
        assert result <= 0.5

    def test_expected_value(self):
        """_expected_value should score based on tool impact."""
        engine = DecisionEngine(Mock(), Mock(), Mock(), Mock())
        ctx = MagicMock()
        # High-value tool with endpoint
        result = engine._expected_value({"tool": "nuclei", "params": {"endpoint": "/api"}}, ctx)
        assert result > 0.3
        # Low-value tool
        result = engine._expected_value({"tool": "ls", "params": {}}, ctx)
        assert result <= 0.5

    def test_risk_score(self):
        """_risk_score should score based on tool risk."""
        engine = DecisionEngine(Mock(), Mock(), Mock(), Mock())
        # High risk
        result = engine._risk_score({"tool": "rm", "risk_level": "high"})
        assert result > 0.5
        # Low risk
        result = engine._risk_score({"tool": "ls", "risk_level": "safe"})
        assert result < 0.5

    def test_learning_value(self):
        """_learning_value should score based on exploration value."""
        engine = DecisionEngine(Mock(), Mock(), Mock(), Mock())
        # High learning value
        result = engine._learning_value({"tool": "nmap"})
        assert result > 0.5
        # Medium learning value
        result = engine._learning_value({"tool": "ffuf"})
        assert result >= 0.5
        # Default
        result = engine._learning_value({"tool": "unknown"})
        assert result <= 0.5

    @pytest.mark.asyncio
    async def test_score_action(self):
        """_score_action should compute a numeric score."""
        engine = DecisionEngine(Mock(), Mock(), Mock(), Mock())
        ctx = MagicMock()
        ctx.target = "example.com"
        score = await engine._score_action({"tool": "nmap", "risk_level": "safe"}, ctx)
        assert isinstance(score, float)
        assert 0.0 <= score <= 1.0

    @pytest.mark.asyncio
    async def test_filter_by_governance_allows(self):
        """Actions not denied by governance should pass."""
        engine = DecisionEngine(Mock(), Mock(), Mock(), Mock())
        gate = MagicMock()
        gate.decision = "allow"
        engine.governance.gate.return_value = gate
        context = MagicMock()
        context.target = "example.com"
        actions = [{"tool": "nmap"}]
        result = await engine._filter_by_governance(actions, context)
        assert len(result) == 1

    @pytest.mark.asyncio
    async def test_filter_by_governance_denies(self):
        """Actions denied by governance should be filtered out."""
        engine = DecisionEngine(Mock(), Mock(), Mock(), Mock())
        gate = MagicMock()
        gate.decision = "deny"
        engine.governance.gate.return_value = gate
        context = MagicMock()
        context.target = "example.com"
        actions = [{"tool": "nmap"}]
        result = await engine._filter_by_governance(actions, context)
        assert len(result) == 0

    @pytest.mark.asyncio
    async def test_make_sovereign_decision_picks_best(self):
        """Should pick the highest-scoring action."""
        engine = DecisionEngine(Mock(), Mock(), Mock(), Mock())
        context = MagicMock()
        context.target = "nmap.example.com"

        # nmap should score higher because target matches
        action1 = {"tool": "nmap", "risk_level": "safe"}
        action2 = {"tool": "ls", "risk_level": "safe"}
        actions = [action1, action2]

        decision = await engine._make_sovereign_decision(actions, context)
        assert decision.tool == "nmap"

    def test_create_action(self):
        """_create_action should create AIAction from dict."""
        engine = DecisionEngine(Mock(), Mock(), Mock(), Mock())
        action_dict = {
            "action_type": "recon",
            "tool": "nmap",
            "target": "example.com",
            "parameters": {"port": "80"},
            "description": "scan ports",
            "purpose": "reconnaissance",
            "risk_level": "safe",
        }
        from elengenix.types import AIAction
        action = engine._create_action(action_dict)
        assert isinstance(action, AIAction)
        assert action.tool == "nmap"
        assert action.target == "example.com"

    @pytest.mark.asyncio
    async def test_decide_no_allowed_actions(self):
        """decide with no allowed actions should return reporting action."""
        engine = DecisionEngine(Mock(), Mock(), Mock(), Mock())
        context = MagicMock()
        context.target = "example.com"

        gate = MagicMock()
        gate.decision = "deny"
        engine.governance.gate.return_value = gate

        result = await engine.decide({}, [{"tool": "nmap"}], context)
        assert result.action_type == "reporting"


class TestTrueAIBrain:
    """Tests for TrueAIBrain init."""

    def test_init_creates_submodules(self):
        """Init should create perception, reasoning, planner, decision_engine."""
        brain = TrueAIBrain(
            llm_client=Mock(),
            memory=Mock(),
            tools=Mock(),
            governance=Mock(),
            constitutional_engine=Mock(),
        )
        assert brain.perception is not None
        assert brain.reasoning is not None
        assert brain.planner is not None
        assert brain.decision_engine is not None

    def test_init_with_config(self):
        """Should accept custom config."""
        brain = TrueAIBrain(
            llm_client=Mock(),
            memory=Mock(),
            tools=Mock(),
            governance=Mock(),
            constitutional_engine=Mock(),
            config={"custom_key": "value"},
        )
        assert brain.config == {"custom_key": "value"}


if __name__ == "__main__":
    pytest.main([__file__, "-v"])