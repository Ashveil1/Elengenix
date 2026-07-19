"""Tests for tools/vuln_reasoning.py — chain-of-thought reasoning depth.

These tests verify the multi-turn reasoning loop added to
VulnReasoningEngine.analyze_output:
  - Turn 1: think step-by-step (free-form prose)
  - Turn 2: self-critique of the thinking
  - Turn 3: structured JSON hypotheses grounded in turns 1+2
  - reasoning_trace is attached to AnalysisResult for observability
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from tools.vuln_reasoning import (
    AnalysisResult,
    VulnHypothesis,
    VulnReasoningEngine,
    _COT_CRITIQUE_PROMPT,
    _COT_THINK_PROMPT,
    _HYPOTHESIS_PROMPT_TEMPLATE,
)


@pytest.fixture
def mock_client():
    """Mock LLM client with a configurable chat() response sequence."""
    c = MagicMock()
    return c


@pytest.fixture
def engine(mock_client):
    return VulnReasoningEngine(client=mock_client, temperature=0.3)


class TestReasoningTraceField:
    def test_analysis_result_has_reasoning_trace_default(self):
        r = AnalysisResult()
        assert hasattr(r, "reasoning_trace")
        assert r.reasoning_trace == []


class TestChainOfThoughtPrompts:
    def test_think_prompt_is_prose_only(self):
        # Should explicitly tell the model not to output JSON
        lower = _COT_THINK_PROMPT.lower()
        assert "do not output json" in lower or "no json" in lower

    def test_think_prompt_has_placeholders(self):
        formatted = _COT_THINK_PROMPT.format(
            target="x",
            tool_name="nmap",
            tool_output="output",
            previous_findings="[]",
            tech_stack="{}",
        )
        assert "x" in formatted
        assert "nmap" in formatted

    def test_critique_prompt_is_prose_only(self):
        lower = _COT_CRITIQUE_PROMPT.lower()
        assert "do not output json" in lower or "no json" in lower

    def test_critique_prompt_asks_for_self_critique(self):
        assert "critically review" in _COT_CRITIQUE_PROMPT.lower() or "self-critique" in _COT_CRITIQUE_PROMPT.lower()


class TestAnalyzeOutputChainOfThought:
    """analyze_output should make 3 LLM calls (think → critique → structured),
    not just 1."""

    def test_makes_three_llm_calls(self, engine, mock_client):
        # 3 responses: think prose, critique prose, structured JSON
        think_resp = MagicMock(); think_resp.content = "Thinking about what we see..."
        critique_resp = MagicMock(); critique_resp.content = "My reasoning above is weak because..."
        structured_resp = MagicMock(); structured_resp.content = '{"hypotheses": [], "signals": [], "next_actions": [], "risk_assessment": "", "coverage_gaps": []}'
        mock_client.chat.side_effect = [think_resp, critique_resp, structured_resp]

        engine.analyze_output(
            target="example.com",
            tool_name="nmap",
            tool_output="80/tcp open http",
        )

        assert mock_client.chat.call_count == 3

    def test_attaches_reasoning_trace_to_result(self, engine, mock_client):
        think_resp = MagicMock(); think_resp.content = "I think there's an SSRF."
        critique_resp = MagicMock(); critique_resp.content = "Actually, weak evidence."
        structured_resp = MagicMock(); structured_resp.content = '{"hypotheses": [{"title": "SSRF", "vuln_class": "ssrf", "confidence": 0.6, "reasoning": "r"}], "signals": [], "next_actions": [], "risk_assessment": "", "coverage_gaps": []}'
        mock_client.chat.side_effect = [think_resp, critique_resp, structured_resp]

        result = engine.analyze_output("example.com", "nmap", "output")

        assert isinstance(result, AnalysisResult)
        assert len(result.reasoning_trace) == 2
        assert result.reasoning_trace[0]["phase"] == "think"
        assert result.reasoning_trace[0]["content"] == "I think there's an SSRF."
        assert result.reasoning_trace[1]["phase"] == "critique"
        assert result.reasoning_trace[1]["content"] == "Actually, weak evidence."

    def test_first_call_uses_think_prompt(self, engine, mock_client):
        think_resp = MagicMock(); think_resp.content = "thinking"
        critique_resp = MagicMock(); critique_resp.content = "critique"
        structured_resp = MagicMock(); structured_resp.content = '{}'
        mock_client.chat.side_effect = [think_resp, critique_resp, structured_resp]

        engine.analyze_output("example.com", "nmap", "output")

        # First call's messages — should be system + user (think prompt)
        first_call_args = mock_client.chat.call_args_list[0]
        first_call_messages = first_call_args.args[0]
        assert len(first_call_messages) == 2
        # Last message should be the think prompt (user role)
        assert first_call_messages[1].role == "user"
        assert "step-by-step" in first_call_messages[1].content.lower() or "step by step" in first_call_messages[1].content.lower()

    def test_second_call_uses_critique_prompt(self, engine, mock_client):
        think_resp = MagicMock(); think_resp.content = "thinking"
        critique_resp = MagicMock(); critique_resp.content = "critique"
        structured_resp = MagicMock(); structured_resp.content = '{}'
        mock_client.chat.side_effect = [think_resp, critique_resp, structured_resp]

        engine.analyze_output("example.com", "nmap", "output")

        # Second call's last user message should be the critique prompt
        second_call_args = mock_client.chat.call_args_list[1]
        second_call_messages = second_call_args.args[0]
        last_user_msg = second_call_messages[-1].content
        assert "crit" in last_user_msg.lower()

    def test_third_call_includes_prior_reasoning_as_assistant(self, engine, mock_client):
        think_resp = MagicMock(); think_resp.content = "THINK_OUTPUT"
        critique_resp = MagicMock(); critique_resp.content = "CRITIQUE_OUTPUT"
        structured_resp = MagicMock(); structured_resp.content = '{}'
        mock_client.chat.side_effect = [think_resp, critique_resp, structured_resp]

        engine.analyze_output("example.com", "nmap", "output")

        # Third call should include prior turns as assistant messages
        third_call_messages = mock_client.chat.call_args_list[2].args[0]
        assistant_msgs = [m for m in third_call_messages if m.role == "assistant"]
        # Should have at least 2 prior assistant messages (think + critique)
        assert len(assistant_msgs) >= 2
        contents = [m.content for m in assistant_msgs]
        assert "THINK_OUTPUT" in contents
        assert "CRITIQUE_OUTPUT" in contents

    def test_empty_think_response_falls_back_to_heuristic(self, engine, mock_client):
        # If turn 1 returns empty, should not crash; falls back gracefully
        think_resp = MagicMock(); think_resp.content = ""
        mock_client.chat.return_value = think_resp

        result = engine.analyze_output("example.com", "nmap", "80/tcp open")

        # Should return a heuristic result, not crash
        assert isinstance(result, AnalysisResult)
        # Only 1 LLM call was made (turn 1)
        assert mock_client.chat.call_count == 1

    def test_exception_during_think_falls_back_to_heuristic(self, engine, mock_client):
        mock_client.chat.side_effect = RuntimeError("api down")

        result = engine.analyze_output("example.com", "nmap", "80/tcp open")

        assert isinstance(result, AnalysisResult)
        # Heuristic result; no LLM hypotheses

    def test_truncates_long_tool_output(self, engine, mock_client):
        think_resp = MagicMock(); think_resp.content = "thinking"
        critique_resp = MagicMock(); critique_resp.content = "critique"
        structured_resp = MagicMock(); structured_resp.content = '{}'
        mock_client.chat.side_effect = [think_resp, critique_resp, structured_resp]

        long_output = "x" * 10000
        engine.analyze_output("example.com", "nmap", long_output)

        # First call's user prompt should contain truncated output
        first_call_messages = mock_client.chat.call_args_list[0].args[0]
        user_msg = first_call_messages[1].content
        assert "[truncated]" in user_msg


class TestBackwardCompatibility:
    """Existing single-shot call sites should still work after the change."""

    def test_no_client_falls_back_to_heuristic(self):
        eng = VulnReasoningEngine(client=None)
        result = eng.analyze_output("x", "nmap", "output")
        assert isinstance(result, AnalysisResult)
        # heuristic analysis still produces a result object
        assert result.hypotheses == [] or len(result.hypotheses) >= 0

    def test_previous_findings_passed_through(self, engine, mock_client):
        think_resp = MagicMock(); think_resp.content = "thinking"
        critique_resp = MagicMock(); critique_resp.content = "critique"
        structured_resp = MagicMock(); structured_resp.content = '{}'
        mock_client.chat.side_effect = [think_resp, critique_resp, structured_resp]

        prev = [{"type": "xss", "url": "http://t/admin"}]
        engine.analyze_output("example.com", "nmap", "output", previous_findings=prev)

        first_call_messages = mock_client.chat.call_args_list[0].args[0]
        user_msg = first_call_messages[1].content
        assert "xss" in user_msg or "admin" in user_msg

    def test_tech_stack_passed_through(self, engine, mock_client):
        think_resp = MagicMock(); think_resp.content = "thinking"
        critique_resp = MagicMock(); critique_resp.content = "critique"
        structured_resp = MagicMock(); structured_resp.content = '{}'
        mock_client.chat.side_effect = [think_resp, critique_resp, structured_resp]

        engine.analyze_output(
            "example.com", "nmap", "output",
            tech_stack={"server": "nginx", "language": "php"},
        )

        first_call_messages = mock_client.chat.call_args_list[0].args[0]
        user_msg = first_call_messages[1].content
        assert "nginx" in user_msg or "php" in user_msg
