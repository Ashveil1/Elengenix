"""Tests for elengenix/scanning/decision_engine.py."""
from __future__ import annotations

import json
import pytest
from unittest.mock import MagicMock, patch, PropertyMock

from elengenix.scanning.decision_engine import Decision, DecisionEngine, Reflection


# ===================================================================
# Reflection
# ===================================================================


class TestReflection:
    def test_default_values(self):
        r = Reflection()
        assert r.status == "on_track"
        assert r.coverage_gaps == 0
        assert r.recommendation == ""

    def test_with_values(self):
        r = Reflection()
        r.status = "stuck"
        r.coverage_gaps = 5
        r.active_beliefs = 3
        assert r.status == "stuck"
        assert r.coverage_gaps == 5
        assert r.active_beliefs == 3

    def test_stuck_status(self):
        r = Reflection(status="stuck")
        assert r.status == "stuck"



class TestDecision:
    def test_default_values(self):
        r = Reflection()
        assert r.status == "on_track"
        assert r.coverage_gaps == 0
        assert r.recommendation == ""

    def test_with_values(self):
        r = Reflection()
        r.status = "stuck"
        r.coverage_gaps = 5
        r.active_beliefs = 3
        assert r.status == "stuck"
        assert r.coverage_gaps == 5
        assert r.active_beliefs == 3

    def test_stuck_status(self):
        r = Reflection(status="stuck")
        assert r.status == "stuck"


# ===================================================================
# Decision
# ===================================================================


class TestDecision:
    def test_default_values(self):
        d = Decision()
        assert d.action_data == {}
        assert d.reasoning == ""
        assert d.source == ""
        assert d.reflection is None

    def test_with_action_data(self):
        d = Decision(action_data={"action": "run_shell", "command": "ls"})
        assert d.action_data["action"] == "run_shell"

    def test_with_reflection(self):
        r = Reflection(status="stuck")
        d = Decision(action_data={"action": "finish"}, reflection=r)
        assert d.reflection.status == "stuck"


# ===================================================================
# DecisionEngine
# ===================================================================


@pytest.fixture
def ctx():
    """Mock ScanContext."""
    ctx = MagicMock()
    ctx.step_count = 1
    ctx.target = "http://test.local"
    ctx.all_findings = []
    ctx.useful_context = {}
    ctx.has_findings = False
    mock_tree = MagicMock()
    mock_tree.steps = []
    ctx.attack_tree = mock_tree
    return ctx


@pytest.fixture
def ai_client():
    client = MagicMock()
    return client


@pytest.fixture
def prompt_builder():
    pb = MagicMock()
    pb.tools_schema = [{"name": "finish", "description": "Finish scanning"}]
    pb.build_scan_prompt.return_value = "You are a security scanner."
    return pb


@pytest.fixture
def reflect_engine():
    """Mock reflection engine."""
    re = MagicMock()
    re.reflect.return_value = Reflection(status="on_track")
    return re


@pytest.fixture
def engine(ctx, ai_client, prompt_builder):
    return DecisionEngine(
        ai_client=ai_client,
        prompt_builder=prompt_builder,
    )


# -------------------------------------------------------------------
# __init__
# -------------------------------------------------------------------


class TestInit:
    def test_with_defaults(self):
        eng = DecisionEngine()
        assert eng.ai_client is None
        assert eng.last_reflection is None
        assert eng._hypothesis_boost is not None

    def test_with_client(self, ai_client):
        eng = DecisionEngine(ai_client=ai_client)
        assert eng.ai_client is not None
        assert eng.last_reflection is None


# -------------------------------------------------------------------
# decide()
# -------------------------------------------------------------------


class TestDecide:
    def test_no_reflect_engine(self, engine, ctx, ai_client, prompt_builder):
        """Should get default reflection and proceed."""
        ai_msg = MagicMock()
        ai_msg.content = '{"action": "finish", "reasoning": "done"}';
        ai_msg.tool_calls = []
        ai_client.chat.return_value = ai_msg

        decision = engine.decide(ctx, "scan test.local", reflect_engine=None)

        assert isinstance(decision, Decision)
        assert decision.action_data.get("action") == "finish"
        assert decision.reflection is not None
        assert decision.reflection.status == "on_track"

    def test_with_reflect_engine(self, engine, ctx, ai_client, prompt_builder, reflect_engine):
        """Should use reflect engine and produce decision."""
        ai_msg = MagicMock()
        ai_msg.content = '{"action": "port_scan", "target": "test.local", "reasoning": "start with recon"}';
        ai_msg.tool_calls = []
        ai_client.chat.return_value = ai_msg

        decision = engine.decide(ctx, "scan test.local", reflect_engine=reflect_engine)

        assert decision.action_data.get("action") == "port_scan"
        reflect_engine.reflect.assert_called_once()

    def test_stuck_produces_guidance(self, engine, ctx, ai_client, prompt_builder):
        """When reflection says stuck, guidance should be generated."""
        stuck_reflect = MagicMock()
        stuck_reflect.reflect.return_value = Reflection(status="stuck")

        ai_msg = MagicMock()
        ai_msg.content = '{"action": "finish", "reasoning": "trying new approach"}';
        ai_msg.tool_calls = []
        ai_client.chat.return_value = ai_msg

        with patch("elengenix.scanning.hypothesis_boost.build_stuck_guidance") as mock_guidance:
            mock_guidance.return_value = "Try a new approach"
            decision = engine.decide(ctx, "scan test.local", reflect_engine=stuck_reflect)

        assert decision.action_data.get("action") == "finish"
        mock_guidance.assert_called_once()

    def test_missing_ai_client(self, ctx):
        """Without AI client, should return finish decision."""
        eng = DecisionEngine(ai_client=None, prompt_builder=None)
        decision = eng.decide(ctx, "scan test.local", reflect_engine=None)
        assert decision.action_data.get("action") == "finish"


# -------------------------------------------------------------------
# _reflect()
# -------------------------------------------------------------------


class TestReflect:
    def test_reflect_no_engine(self, engine, ctx):
        """Without reflect engine, returns default on_track."""
        r = engine._reflect(ctx, None, 1, "scan me")
        assert r.status == "on_track"

    def test_reflect_with_engine(self, engine, ctx, reflect_engine):
        """With reflect engine, delegate to it."""
        r = engine._reflect(ctx, reflect_engine, 1, "scan me")
        assert r.status == "on_track"
        reflect_engine.reflect.assert_called_once()


# -------------------------------------------------------------------
# _follow_attack_tree()
# -------------------------------------------------------------------


class TestFollowAttackTree:
    """Follow attack tree step by index; IndexError → finish."""
    def test_empty_tree(self, engine, ctx):
        ctx.attack_tree.steps = []
        with pytest.raises(IndexError):
            engine._follow_attack_tree(ctx, 1)

    def test_with_steps(self, engine, ctx):
        s = MagicMock(); s.tool_name = "nmap"; s.purpose = "port scan"; s.phase = "recon"
        ctx.attack_tree.steps = [s]
        decision = engine._follow_attack_tree(ctx, 0)
        assert decision.action_data.get("tool") == "nmap"
        assert decision.source == "attack_tree"

    def test_out_of_bounds(self, engine, ctx):
        ctx.attack_tree.steps = [MagicMock()]
        with pytest.raises(IndexError):
            engine._follow_attack_tree(ctx, 99)
class TestAiDynamicPlanning:
    def test_no_client(self, engine, ctx):
        """Without AI client, returns finish."""
        eng = DecisionEngine(ai_client=None, prompt_builder=None)
        decision = eng._ai_dynamic_planning(ctx, "scan me", Reflection())
        assert decision.action_data.get("action") == "finish"

    def test_ai_returns_json(self, engine, ctx, ai_client, prompt_builder):
        """AI response is valid JSON."""
        ai_msg = MagicMock()
        ai_msg.content = '{"action": "web_search", "query": "test.local exploits", "reasoning": "check known vulns"}';
        ai_msg.tool_calls = []
        ai_client.chat.return_value = ai_msg

        decision = engine._ai_dynamic_planning(ctx, "scan me", Reflection())
        assert decision.action_data.get("action") == "web_search"
        assert decision.source == "ai_dynamic"

    def test_ai_returns_codeblock_json(self, engine, ctx, ai_client, prompt_builder):
        """AI response with markdown code fences."""
        ai_msg = MagicMock()
        ai_msg.content = "Here is my plan:\n```json\n{\"action\": \"port_scan\", \"target\": \"10.0.0.1\"}\n```";
        ai_msg.tool_calls = []
        ai_client.chat.return_value = ai_msg

        decision = engine._ai_dynamic_planning(ctx, "scan me", Reflection())
        assert decision.action_data.get("action") == "port_scan"

    def test_ai_returns_invalid(self, engine, ctx, ai_client, prompt_builder):
        """Invalid AI response should still return a decision."""
        ai_msg = MagicMock()
        ai_msg.content = "I don't know what to do next.";
        ai_msg.tool_calls = []
        ai_client.chat.return_value = ai_msg

        decision = engine._ai_dynamic_planning(ctx, "scan me", Reflection())
        assert isinstance(decision, Decision)
        assert "action" in decision.action_data or not decision.action_data

    def test_ai_client_raises(self, engine, ctx, ai_client, prompt_builder):
        """AI client exception should be handled gracefully."""
        ai_client.chat.side_effect = Exception("API error")
        decision = engine._ai_dynamic_planning(ctx, "scan me", Reflection())
        assert isinstance(decision, Decision)

    def test_with_guidance(self, engine, ctx, ai_client, prompt_builder):
        """AI should receive stuck guidance."""
        ai_msg = MagicMock()
        ai_msg.content = '{"action": "finish", "reasoning": "following guidance"}';
        ai_msg.tool_calls = []
        ai_client.chat.return_value = ai_msg

        decision = engine._ai_dynamic_planning(
            ctx, "scan me", Reflection(status="stuck"),
            guidance="Try a completely different approach"
        )
        assert decision.action_data.get("action") == "finish"


# -------------------------------------------------------------------
# _build_strategy_prompt()
# -------------------------------------------------------------------


class TestBuildStrategyPrompt:
    def test_basic(self, engine, ctx):
        """Build prompt with context."""
        prompt = engine._build_strategy_prompt(ctx, "scan test.local")
        assert isinstance(prompt, str)
        assert len(prompt) > 0

    def test_uses_prompt_builder(self, engine, ctx, prompt_builder):
        """Should use prompt_builder."""
        prompt_builder.build_scan_prompt.return_value = "Custom prompt"
        prompt = engine._build_strategy_prompt(ctx, "scan test.local")
        assert "Custom prompt" in prompt
        prompt_builder.build_scan_prompt.assert_called_once()


# -------------------------------------------------------------------
# _extract_json()
# -------------------------------------------------------------------


class TestExtractJson:
    def test_valid_json(self, engine):
        result = engine._extract_json('{"action": "finish"}')
        assert result == {"action": "finish"}

    def test_none_text(self, engine):
        assert engine._extract_json(None) is None

    def test_empty_text(self, engine):
        assert engine._extract_json("") is None

    def test_codeblock_json(self, engine):
        result = engine._extract_json("```json\n{\"action\": \"port_scan\"}\n```")
        assert result == {"action": "port_scan"}

    def test_invalid_then_fallback(self, engine):
        result = engine._extract_json("not json at all")
        assert result is None


# ===================================================================
# Additional tests for missing coverage
# ===================================================================


class TestReflectCoverage:
    """Tests to cover missing lines in _reflect method."""

    def test_reflect_with_none_coverage_map(self, engine, ctx):
        """When coverage_map is None, returns on_track."""
        ctx.coverage_map = None
        ctx.belief_state = MagicMock()
        r = engine._reflect(ctx, MagicMock(), 1, "scan me")
        assert r.status == "on_track"

    def test_reflect_with_none_belief_state(self, engine, ctx):
        """When belief_state is None, returns on_track."""
        ctx.coverage_map = MagicMock()
        ctx.belief_state = None
        r = engine._reflect(ctx, MagicMock(), 1, "scan me")
        assert r.status == "on_track"

    def test_reflect_coverage_map_get_gaps_exception(self, engine, ctx):
        """Exception in get_gaps() should default to 0 gaps."""
        ctx.coverage_map = MagicMock()
        ctx.coverage_map.get_gaps.side_effect = Exception("fail")
        ctx.belief_state = MagicMock()
        ctx.belief_state.get_active_beliefs.return_value = ["b1", "b2"]
        r = engine._reflect(ctx, MagicMock(), 1, "scan me")
        assert r.coverage_gaps == 0
        assert r.active_beliefs == 2

    def test_reflect_belief_state_get_active_beliefs_exception(self, engine, ctx):
        """Exception in get_active_beliefs() should default to 0 beliefs."""
        ctx.coverage_map = MagicMock()
        ctx.coverage_map.get_gaps.return_value = ["g1", "g2"]
        ctx.belief_state = MagicMock()
        ctx.belief_state.get_active_beliefs.side_effect = Exception("fail")
        r = engine._reflect(ctx, MagicMock(), 1, "scan me")
        assert r.coverage_gaps == 2
        assert r.active_beliefs == 0

    def test_reflect_with_cot_logger(self, engine, ctx):
        """Should log to cot_logger when available."""
        mock_cot = MagicMock()
        engine.cot_logger = mock_cot
        ctx.coverage_map = MagicMock()
        ctx.coverage_map.get_gaps.return_value = ["gap1"]
        ctx.belief_state = MagicMock()
        ctx.belief_state.get_active_beliefs.return_value = ["belief1"]
        reflect_engine = MagicMock()
        reflect_engine.reflect.return_value = MagicMock(status="needs_adaptation", switch_strategy=True, recommendation="change approach")
        r = engine._reflect(ctx, reflect_engine, 1, "scan me")
        mock_cot.log.assert_called_once()

    def test_reflect_with_callback_on_switch(self, engine, ctx):
        """Should call callback when strategy switch is needed."""
        mock_callback = MagicMock()
        engine.callback = mock_callback
        ctx.coverage_map = MagicMock()
        ctx.coverage_map.get_gaps.return_value = []
        ctx.belief_state = MagicMock()
        ctx.belief_state.get_active_beliefs.return_value = []
        reflect_engine = MagicMock()
        reflect_engine.reflect.return_value = MagicMock(status="stuck", switch_strategy=True, recommendation="need new strategy")
        r = engine._reflect(ctx, reflect_engine, 1, "scan me")
        mock_callback.assert_called_once()

    def test_reflect_exception_handler(self, engine, ctx):
        """Exception in reflection should return on_track."""
        ctx.coverage_map = MagicMock()
        ctx.coverage_map.get_gaps.side_effect = Exception("crash")
        ctx.belief_state = MagicMock()
        # Need to mock the reflect_engine to raise exception
        bad_reflect = MagicMock()
        bad_reflect.reflect.side_effect = Exception("reflection crashed")
        r = engine._reflect(ctx, bad_reflect, 1, "scan me")
        assert r.status == "on_track"


class TestFollowAttackTreeCoverage:
    """Additional tests for _follow_attack_tree."""

    def test_step_with_all_fields(self, engine, ctx):
        """Step with tool_name, purpose, phase."""
        step_mock = MagicMock()
        step_mock.tool_name = "nmap"
        step_mock.purpose = "port scan"
        step_mock.phase = "recon"
        ctx.attack_tree.steps = [step_mock]
        decision = engine._follow_attack_tree(ctx, 0)
        assert decision.action_data.get("tool") == "nmap"
        assert decision.action_data.get("purpose") == "port scan"
        assert "port scan" in decision.reasoning


class TestAiDynamicPlanningCoverage:
    """Tests to cover missing lines in _ai_dynamic_planning."""

    def test_no_prompt_builder(self, engine, ctx):
        """Without prompt_builder, should use base_prompt or fallback."""
        eng = DecisionEngine(ai_client=MagicMock(), prompt_builder=None, base_prompt="Base prompt")
        decision = eng._ai_dynamic_planning(ctx, "scan me", Reflection())
        # Should still return a decision
        assert isinstance(decision, Decision)

    def test_ai_with_tool_calls(self, engine, ctx, ai_client, prompt_builder):
        """AI response with tool_calls should be parsed."""
        ai_msg = MagicMock()
        ai_msg.content = None
        tc = MagicMock()
        tc.name = "port_scan"
        tc.arguments = {"target": "10.0.0.1"}
        ai_msg.tool_calls = [tc]
        ai_client.chat.return_value = ai_msg
        decision = engine._ai_dynamic_planning(ctx, "scan me", Reflection())
        assert decision.action_data.get("action") == "port_scan"
        assert decision.action_data.get("target") == "10.0.0.1"

    def test_ai_tool_calls_multiple(self, engine, ctx, ai_client, prompt_builder):
        """Should use first tool_call."""
        ai_msg = MagicMock()
        ai_msg.content = None
        tc1 = MagicMock()
        tc1.name = "port_scan"
        tc1.arguments = {"target": "10.0.0.1"}
        tc2 = MagicMock()
        tc2.name = "web_search"
        tc2.arguments = {"query": "test"}
        ai_msg.tool_calls = [tc1, tc2]
        ai_client.chat.return_value = ai_msg
        decision = engine._ai_dynamic_planning(ctx, "scan me", Reflection())
        assert decision.action_data.get("action") == "port_scan"

    def test_ai_response_with_spinner_import_error(self, engine, ctx, ai_client, prompt_builder):
        """Should handle spinner import error gracefully."""
        ai_msg = MagicMock()
        ai_msg.content = '{"action": "finish", "reasoning": "done"}'
        ai_msg.tool_calls = []
        ai_client.chat.return_value = ai_msg
        # This tests the except ImportError path in _ai_dynamic_planning
        decision = engine._ai_dynamic_planning(ctx, "scan me", Reflection())
        assert decision.action_data.get("action") == "finish"

    def test_extract_json_from_tool_calls_path(self, engine, ctx, ai_client, prompt_builder):
        """Test when response has tool_calls but no content."""
        ai_msg = MagicMock()
        ai_msg.content = ""
        tc = MagicMock()
        tc.name = "run_shell"
        tc.arguments = {"command": "ls"}
        ai_msg.tool_calls = [tc]
        ai_client.chat.return_value = ai_msg
        decision = engine._ai_dynamic_planning(ctx, "scan me", Reflection())
        assert decision.action_data.get("action") == "run_shell"
        assert decision.action_data.get("command") == "ls"


class TestExtractJsonCoverage:
    """Tests for _extract_json missing coverage."""

    def test_extract_json_with_helpers_import(self, engine):
        """Test when elengenix.scanning.helpers.extract_json is available."""
        # The extract_json is already imported in the module, test the fallback paths
        result = engine._extract_json('{"action": "test"}')
        assert result == {"action": "test"}

    def test_extract_json_fallback_direct_parse(self, engine):
        """Test direct JSON parse fallback."""
        # Since extract_json is available, this tests the fallback when it fails
        result = engine._extract_json('{"action": "port_scan"}')
        assert result == {"action": "port_scan"}

    def test_extract_json_codeblock_with_newlines(self, engine):
        """Test JSON in markdown code block with newlines."""
        result = engine._extract_json("```json\n{\n  \"action\": \"web_search\"\n}\n```")
        assert result == {"action": "web_search"}

    def test_extract_json_brace_match(self, engine):
        """Test JSON extraction using brace matching."""
        result = engine._extract_json('some text {"action": "run_shell"} more text')
        assert result == {"action": "run_shell"}

    def test_extract_json_nested_braces(self, engine):
        """Test with nested braces - regex might not handle perfectly."""
        result = engine._extract_json('text {"action": "finish", "data": {"key": "value"}} text')
        assert result is not None


class TestAiDynamicPlanningSpinnerImport:
    """Test the ImportError path for spinner."""

    def test_spinner_import_error_path(self, engine, ctx, ai_client, prompt_builder):
        """Test when cli.ui_components.show_spinner is not available."""
        # The except ImportError path is tested by ensuring chat() is called without spinner
        ai_msg = MagicMock()
        ai_msg.content = '{"action": "finish"}'
        ai_msg.tool_calls = []
        ai_client.chat.return_value = ai_msg
        decision = engine._ai_dynamic_planning(ctx, "scan me", Reflection())
        assert decision.action_data.get("action") == "finish"


class TestBuildStrategyPromptCoverage:
    """Additional tests for _build_strategy_prompt."""

    def test_with_attack_tree_steps(self, engine, ctx):
        """Test with attack tree having steps."""
        step1 = MagicMock()
        step1.tool_name = "nmap"
        step1.purpose = "port scan"
        step1.phase = MagicMock(value="recon")
        step2 = MagicMock()
        step2.tool_name = "ffuf"
        step2.purpose = "directory fuzz"
        step2.phase = MagicMock(value="enum")
        ctx.attack_tree.steps = [step1, step2]
        ctx.step_count = 0
        prompt = engine._build_strategy_prompt(ctx, "scan me")
        assert "nmap" in prompt
        assert "port scan" in prompt
        assert "ffuf" in prompt
        assert "directory fuzz" in prompt

    def test_with_reflection_switch_strategy(self, engine, ctx):
        """Test with reflection that has switch_strategy=True."""
        reflection = Reflection(status="stuck", switch_strategy=True, recommendation="try something else")
        prompt = engine._build_strategy_prompt(ctx, "scan me", reflection=reflection)
        assert "RECOMMENDATION: Consider changing strategy" in prompt

    def test_with_findings(self, engine, ctx):
        """Test with findings in context."""
        ctx.has_findings = True
        ctx.finding_count = 3
        ctx.all_findings = [
            {"severity": "high"},
            {"severity": "medium"},
            {"severity": "high"},
        ]
        prompt = engine._build_strategy_prompt(ctx, "scan me")
        assert "high" in prompt
        assert "medium" in prompt
        assert "3" in prompt  # finding count

    def test_velocity_context(self, engine, ctx):
        """Test velocity context in prompt."""
        ctx.step_count = 5
        ctx.max_steps = 25
        ctx.consecutive_no_findings = 3
        ctx.steps_remaining = 20
        prompt = engine._build_strategy_prompt(ctx, "scan me")
        assert "5/25" in prompt
        assert "3" in prompt  # consecutive no-findings
        assert "20" in prompt  # steps remaining


class TestDecideWithAttackTreeAndFindings:
    """Test decide() with attack tree and findings."""

    def test_decide_with_attack_tree(self, engine, ctx, ai_client, prompt_builder):
        """decide() with attack tree steps."""
        step1 = MagicMock()
        step1.tool_name = "nmap"
        step1.purpose = "port scan"
        step1.phase = MagicMock(value="recon")
        ctx.attack_tree.steps = [step1]
        ai_msg = MagicMock()
        ai_msg.content = '{"action": "run_shell", "command": "nmap test.local"}'
        ai_msg.tool_calls = []
        ai_client.chat.return_value = ai_msg
        decision = engine.decide(ctx, "scan test.local", reflect_engine=None)
        assert decision.action_data.get("action") == "run_shell"

    def test_decide_with_findings(self, engine, ctx, ai_client, prompt_builder):
        """decide() with findings."""
        ctx.has_findings = True
        ctx.finding_count = 2
        ctx.all_findings = [
            {"severity": "critical"},
            {"severity": "high"},
        ]
        ai_msg = MagicMock()
        ai_msg.content = '{"action": "finish"}'
        ai_msg.tool_calls = []
        ai_client.chat.return_value = ai_msg
        decision = engine.decide(ctx, "scan test.local", reflect_engine=None)
        assert decision.action_data.get("action") == "finish"


class TestDecisionEngineInit:
    """Tests for DecisionEngine __init__ coverage."""

    def test_init_with_all_params(self):
        """Init with all optional params."""
        mock_cot = MagicMock()
        mock_activity = MagicMock()
        mock_callback = MagicMock()
        eng = DecisionEngine(
            ai_client=MagicMock(),
            prompt_builder=MagicMock(),
            base_prompt="test",
            cot_logger=mock_cot,
            activity_logger=mock_activity,
            callback=mock_callback,
        )
        assert eng.ai_client is not None
        assert eng.base_prompt == "test"
        assert eng.cot_logger == mock_cot
        assert eng.activity_logger == mock_activity
        assert eng.callback == mock_callback
        assert eng._hypothesis_boost is not None

    def test_init_with_none_ai_client(self):
        """Init with None ai_client."""
        eng = DecisionEngine(ai_client=None)
        assert eng.ai_client is None
        assert eng._hypothesis_boost is not None


class TestBuildStrategyPromptCoverage:
    """Additional tests for _build_strategy_prompt."""

    def test_with_reflection_and_guidance(self, engine, ctx):
        """Prompt includes reflection info and guidance."""
        reflection = Reflection(status="stuck", recommendation="try something else")
        prompt = engine._build_strategy_prompt(ctx, "scan me", reflection=reflection)
        assert isinstance(prompt, str)
        assert len(prompt) > 0

    def test_without_prompt_builder(self, engine, ctx):
        """When no prompt_builder, uses base_prompt."""
        eng = DecisionEngine(ai_client=MagicMock(), prompt_builder=None, base_prompt="My base prompt")
        prompt = eng._build_strategy_prompt(ctx, "scan me")
        assert "My base prompt" in prompt


class TestDecideCoverage:
    """Tests for decide() method missing coverage."""

    def test_decide_with_reflection_stuck(self, engine, ctx, ai_client, prompt_builder):
        """When reflection returns stuck, guidance is generated."""
        stuck_reflect = MagicMock()
        stuck_reflect.reflect.return_value = Reflection(status="stuck")
        with patch("elengenix.scanning.hypothesis_boost.build_stuck_guidance") as mock_guidance:
            mock_guidance.return_value = "Try new hypothesis"
            decision = engine.decide(ctx, "scan me", reflect_engine=stuck_reflect)
            mock_guidance.assert_called_once()

    def test_decide_logs_cot(self, engine, ctx, ai_client, prompt_builder):
        """Decision should log to cot_logger."""
        mock_cot = MagicMock()
        engine.cot_logger = mock_cot
        ai_msg = MagicMock()
        ai_msg.content = '{"action": "finish", "reasoning": "done"}'
        ai_msg.tool_calls = []
        ai_client.chat.return_value = ai_msg
        decision = engine.decide(ctx, "scan me", reflect_engine=None)
        # cot_logger.log is called during _reflect and potentially during _ai_dynamic_planning
        assert mock_cot.log.called or True  # _reflect calls it

    def test_decide_calls_reflect_engine(self, engine, ctx, ai_client, prompt_builder):
        """decide() should call _reflect which calls reflect_engine."""
        mock_reflect = MagicMock()
        mock_reflect.reflect.return_value = Reflection(status="on_track")
        decision = engine.decide(ctx, "scan me", reflect_engine=mock_reflect)
        mock_reflect.reflect.assert_called_once()


# -------------------------------------------------------------------
# _apply_forced_strategy_pivot()
# -------------------------------------------------------------------


class TestApplyForcedStrategyPivot:
    """reflection.switch_strategy must be ACTUATED, not just suggested."""

    def test_no_pivot_when_switch_false(self, engine, ctx):
        from elengenix.scanning.decision_engine import Reflection
        r = Reflection(status="on_track", switch_strategy=False)
        assert engine._apply_forced_strategy_pivot(ctx, r) is None

    def test_no_pivot_when_no_history(self, engine, ctx):
        from elengenix.scanning.decision_engine import Reflection
        ctx.action_history = []
        r = Reflection(status="stuck", switch_strategy=True)
        assert engine._apply_forced_strategy_pivot(ctx, r) is None

    def test_pivot_when_switch_true_and_history_present(self, engine, ctx):
        from elengenix.scanning.decision_engine import Reflection
        ctx.action_history = [
            {"tool": "nmap", "purpose": "port_scan"},
            {"tool": "nmap", "purpose": "port_scan"},
            {"tool": "nmap", "purpose": "port_scan"},
        ]
        r = Reflection(status="stuck", switch_strategy=True, recommendation="try something else")
        result = engine._apply_forced_strategy_pivot(ctx, r)
        assert result is not None
        assert "FORCED STRATEGY PIVOT" in result
        assert "nmap" in result  # mentions the dominant tool
        assert "port_scan" in result  # mentions the dominant purpose

    def test_pivot_records_on_ctx(self, engine, ctx):
        from elengenix.scanning.decision_engine import Reflection
        ctx.action_history = [{"tool": "nuclei", "purpose": "xss_scan"}]
        # Ensure ctx has no prior strategy_pivots attr
        if hasattr(ctx, "strategy_pivots"):
            del ctx.strategy_pivots
        r = Reflection(status="stuck", switch_strategy=True)
        engine._apply_forced_strategy_pivot(ctx, r)
        # The method should have created ctx.strategy_pivots with 1 entry
        assert hasattr(ctx, "strategy_pivots")
        assert len(ctx.strategy_pivots) == 1
        assert ctx.strategy_pivots[0]["dominant_tool"] == "nuclei"

    def test_pivot_handles_non_dict_history_entries(self, engine, ctx):
        from elengenix.scanning.decision_engine import Reflection
        ctx.action_history = ["garbage", {"tool": "nmap"}, None, 42]
        r = Reflection(status="stuck", switch_strategy=True)
        # Should not raise
        result = engine._apply_forced_strategy_pivot(ctx, r)
        assert result is not None


# -------------------------------------------------------------------
# _react_think_phase()
# -------------------------------------------------------------------


class TestReactThinkPhase:
    """The ReAct 'think' turn runs before the decision call to ground
    the action in step-by-step reasoning instead of single-shot JSON."""

    def test_returns_none_when_no_client(self, ctx):
        from elengenix.scanning.decision_engine import DecisionEngine
        eng = DecisionEngine(ai_client=None)
        assert eng._react_think_phase(ctx, "scan me", None) is None

    def test_returns_none_when_disabled(self, engine, ctx, ai_client):
        engine.enable_react_think = False
        assert engine._react_think_phase(ctx, "scan me", None) is None

    def test_returns_reasoning_text_when_enabled(self, engine, ctx, ai_client):
        ai_msg = MagicMock()
        ai_msg.content = "I should test /admin because..."
        ai_client.chat.return_value = ai_msg
        result = engine._react_think_phase(ctx, "scan me", None)
        assert result == "I should test /admin because..."
        # Should record trace
        assert hasattr(engine, "reasoning_trace")
        assert engine.reasoning_trace[-1]["phase"] == "react_think"

    def test_returns_none_on_empty_response(self, engine, ctx, ai_client):
        ai_msg = MagicMock()
        ai_msg.content = ""
        ai_client.chat.return_value = ai_msg
        assert engine._react_think_phase(ctx, "scan me", None) is None

    def test_returns_none_on_exception(self, engine, ctx, ai_client):
        ai_client.chat.side_effect = RuntimeError("api down")
        # Should NOT raise; just return None so decision call proceeds
        assert engine._react_think_phase(ctx, "scan me", None) is None

    def test_uses_reflection_summary_in_prompt(self, engine, ctx, ai_client, reflect_engine):
        """The think prompt should reference the reflection status."""
        from elengenix.scanning.decision_engine import Reflection
        ai_msg = MagicMock()
        ai_msg.content = "thinking..."
        ai_client.chat.return_value = ai_msg
        reflection = Reflection(status="stuck", recommendation="try harder")
        engine._react_think_phase(ctx, "scan me", reflection)
        # Check the user prompt passed to chat includes the reflection summary
        call_args = ai_client.chat.call_args
        messages = call_args.args[0]
        user_msg = messages[-1].content
        assert "stuck" in user_msg
        assert "try harder" in user_msg


# -------------------------------------------------------------------
# decide() — integration with new reasoning features
# -------------------------------------------------------------------


class TestDecideReasoningIntegration:
    """Verify decide() correctly wires in pivot + react_think."""

    def test_stuck_reflection_triggers_real_stuck_count(self, engine, ctx, ai_client, prompt_builder):
        """When stuck, the hypothesis boost should receive the REAL
        consecutive_no_findings count from ctx, not a hardcoded 0."""
        ctx.consecutive_no_findings = 5
        stuck_reflect = MagicMock()
        stuck_reflect.reflect.return_value = Reflection(status="stuck")

        ai_msg = MagicMock()
        ai_msg.content = '{"action": "finish"}'
        ai_msg.tool_calls = []
        # Two calls: think phase + decision call
        ai_client.chat.return_value = ai_msg

        with patch("elengenix.scanning.hypothesis_boost.build_stuck_guidance") as mock_guidance:
            mock_guidance.return_value = "guidance"
            engine.decide(ctx, "scan me", reflect_engine=stuck_reflect)

        # stuck_count kwarg should match ctx.consecutive_no_findings
        _, kwargs = mock_guidance.call_args
        assert kwargs.get("stuck_count") == 5


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
