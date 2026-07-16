"""Tests for elengenix/scanning/universal.py — Universal Agent Mode."""

from __future__ import annotations

import pytest
from unittest.mock import MagicMock, Mock, patch
from elengenix.scanning.universal import (
    _format_preflight_context,
    process_universal,
    _build_chat_messages,
    _append_history,
    _build_research_prompt,
    _build_bug_bounty_prompt,
    _build_general_prompt,
)


class TestFormatPreflightContext:
    """Tests for _format_preflight_context function."""

    def test_empty_findings(self):
        """Should return empty string for empty findings."""
        result = _format_preflight_context([])
        assert result == ""

    def test_groups_by_type(self):
        """Should group findings by type."""
        findings = [
            {"type": "xss", "severity": "high", "title": "XSS 1"},
            {"type": "sqli", "severity": "medium", "title": "SQLi 1"},
            {"type": "xss", "severity": "critical", "title": "XSS 2"},
        ]
        result = _format_preflight_context(findings)
        assert "**xss** (2):" in result
        assert "**sqli** (1):" in result

    def test_severity_breakdown(self):
        """Should include severity breakdown."""
        findings = [
            {"severity": "Critical"},
            {"severity": "High"},
            {"severity": "High"},
            {"severity": "Medium"},
        ]
        result = _format_preflight_context(findings)
        assert "Critical=1" in result
        assert "High=2" in result
        assert "Medium=1" in result

    def test_highlights_critical_findings(self):
        """Should highlight critical and high findings."""
        findings = [
            {"severity": "Critical", "type": "rce", "title": "RCE found"},
            {"severity": "High", "type": "sqli", "title": "SQLi found", "url": "http://example.com"},
            {"severity": "Low", "type": "info", "title": "Info leak"},
        ]
        result = _format_preflight_context(findings)
        assert "HIGH-PRIORITY TARGETS" in result
        assert "RCE found" in result
        assert "SQLi found" in result
        assert "http://example.com" in result
        # Low severity findings ARE included in the grouped section
        assert "Info leak" in result

    def test_limits_per_category(self):
        """Should limit to 5 items per category."""
        findings = [
            {"type": "xss", "severity": "high", "title": f"XSS {i}", "url": f"http://xss{i}.com"}
            for i in range(8)
        ]
        result = _format_preflight_context(findings)
        # Should only show first 5
        assert "XSS 0" in result
        assert "XSS 4" in result
        assert "XSS 5" not in result
        assert "... +3 more" in result

    def test_includes_usage_instructions(self):
        """Should include usage instructions."""
        findings = [{"type": "xss", "severity": "high", "title": "XSS"}]
        result = _format_preflight_context(findings)
        assert "HOW TO USE THIS" in result
        assert "DO NOT re-discover" in result


class TestBuildChatMessages:
    """Tests for _build_chat_messages function."""

    def test_builds_messages_with_history(self):
        """Should build messages with system prompt, history, and user input."""
        history = [
            {"role": "user", "content": "hello"},
            {"role": "assistant", "content": "hi"},
        ]
        messages = _build_chat_messages(history, "System prompt", "user query")

        assert len(messages) == 4
        assert messages[0].role == "system"
        assert messages[0].content == "System prompt"
        assert messages[1].role == "user"
        assert messages[1].content == "hello"
        assert messages[2].role == "assistant"
        assert messages[2].content == "hi"
        assert messages[3].role == "user"
        assert messages[3].content == "user query"

    def test_limits_history_to_last_10(self):
        """Should limit history to last 10 messages."""
        history = [{"role": "user", "content": f"msg{i}"} for i in range(15)]
        messages = _build_chat_messages(history, "System", "query")

        # system + 10 history + 1 user = 12
        assert len(messages) == 12

    def test_empty_history(self):
        """Should work with empty history."""
        messages = _build_chat_messages([], "System", "query")

        assert len(messages) == 2
        assert messages[0].role == "system"
        assert messages[1].role == "user"


class TestAppendHistory:
    """Tests for _append_history function."""

    def test_appends_user_message(self):
        """Should append user message to history."""
        history = []
        _append_history(history, "user", "hello")

        assert len(history) == 1
        assert history[0] == {"role": "user", "content": "hello"}

    def test_appends_assistant_message(self):
        """Should append assistant message to history."""
        history = [{"role": "user", "content": "hello"}]
        _append_history(history, "assistant", "hi")

        assert len(history) == 2
        assert history[1] == {"role": "assistant", "content": "hi"}


class TestBuildResearchPrompt:
    """Tests for _build_research_prompt function."""

    def test_contains_user_query(self):
        """Should include user query in prompt."""
        prompt = _build_research_prompt("latest news", "Now: 2024")

        assert "latest news" in prompt
        assert "Now: 2024" in prompt

    def test_contains_anti_hallucination_rules(self):
        """Should include anti-hallucination rules."""
        prompt = _build_research_prompt("query", "context")

        assert "ANTI-HALLUCINATION RULES" in prompt
        assert "MUST call search_web" in prompt

    def test_contains_capabilities(self):
        """Should list capabilities."""
        prompt = _build_research_prompt("query", "context")

        assert "search_web" in prompt
        assert "finish" in prompt

    def test_response_format(self):
        """Should specify JSON response format."""
        prompt = _build_research_prompt("query", "context")

        assert "Always respond with valid JSON" in prompt
        assert '"thought"' in prompt
        assert '"action"' in prompt


class TestBuildBugBountyPrompt:
    """Tests for _build_bug_bounty_prompt function."""

    def test_contains_target(self):
        """Should include target in prompt."""
        mock_registry = Mock()
        mock_registry.list_available_tools.return_value = {}
        mock_skill_registry = Mock()
        mock_skill_registry.list_available_skills.return_value = []
        mock_skill_registry.get_missing_skills.return_value = []
        mock_governance = Mock()
        mock_client = Mock()

        prompt = _build_bug_bounty_prompt(
            "scan example.com", "Now: 2024", "example.com", mock_client, mock_governance, mock_skill_registry
        )

        assert "example.com" in prompt

    def test_contains_tools_list(self):
        """Should list available tools."""
        mock_skill_registry = Mock()
        mock_skill_registry.list_available_skills.return_value = []
        mock_skill_registry.get_missing_skills.return_value = []

        with patch("elengenix.scanning.universal.registry") as mock_reg:
            mock_reg.list_available_tools.return_value = {
                "dns_lookup": {"description": "DNS lookup", "available": True},
                "http_probe": {"description": "HTTP probe", "available": True},
            }
            prompt = _build_bug_bounty_prompt(
                "scan", "Now", "target", Mock(), Mock(), mock_skill_registry
            )

        assert "dns_lookup" in prompt
        assert "http_probe" in prompt
        assert "DNS lookup" in prompt

    def test_contains_phases(self):
        """Should contain all 5 phases."""
        mock_registry = Mock()
        mock_registry.list_available_tools.return_value = {}
        mock_skill_registry = Mock()
        mock_skill_registry.list_available_skills.return_value = []
        mock_skill_registry.get_missing_skills.return_value = []
        mock_governance = Mock()
        mock_client = Mock()

        prompt = _build_bug_bounty_prompt(
            "scan", "Now", "target", mock_client, mock_governance, mock_skill_registry
        )

        assert "PHASE 1: RECONNAISSANCE" in prompt
        assert "PHASE 2: CONTENT DISCOVERY" in prompt
        assert "PHASE 3: VULNERABILITY SCANNING" in prompt
        assert "PHASE 4: EXPLOITATION" in prompt
        assert "PHASE 5: REPORTING" in prompt

    def test_contains_full_capabilities(self):
        """Should list full capabilities."""
        mock_registry = Mock()
        mock_registry.list_available_tools.return_value = {}
        mock_skill_registry = Mock()
        mock_skill_registry.list_available_skills.return_value = []
        mock_skill_registry.get_missing_skills.return_value = []
        mock_governance = Mock()
        mock_client = Mock()

        prompt = _build_bug_bounty_prompt(
            "scan", "Now", "target", mock_client, mock_governance, mock_skill_registry
        )

        assert "Full shell access" in prompt
        assert "File editing" in prompt
        assert "Package installation" in prompt
        assert "Web search" in prompt
        assert "CVE database" in prompt
        assert "GitHub code search" in prompt
        assert "JS analysis" in prompt


class TestBuildGeneralPrompt:
    """Tests for _build_general_prompt function."""

    def test_contains_capabilities(self):
        """Should list general capabilities."""
        prompt = _build_general_prompt("test", "Now: 2024")

        assert "Universal AI Agent" in prompt
        assert "code" in prompt
        assert "security research" in prompt
        assert "OSINT" in prompt

    def test_contains_principles(self):
        """Should include principles."""
        prompt = _build_general_prompt("test", "Now: 2024")

        assert "PRINCIPLES" in prompt
        assert "If you are unsure" in prompt
        assert "If a command fails" in prompt
        assert "Prefer registered tools" in prompt


class TestProcessUniversal:
    """Tests for process_universal function."""

    def test_classifies_intent(self):
        """Should classify user intent."""
        mock_client = Mock()
        mock_client.chat.return_value = Mock(content="casual")

        with patch("elengenix.scanning.universal.analyze_intent") as mock_analyze:
            mock_analyze.return_value = "casual"
            result = process_universal(
                user_input="hello",
                client=mock_client,
                conversation_history=[],
                base_prompt="test",
                governance=Mock(),
            )

            mock_analyze.assert_called_once_with(mock_client, "hello")

    def test_returns_casual_response(self):
        """Should return casual response for casual intent."""
        with patch("elengenix.scanning.universal.analyze_intent", return_value="casual"):
            with patch("elengenix.scanning.universal.get_context_for_ai", return_value=""):
                with patch("elengenix.scanning.universal._get_memory_profile_context", return_value=""):
                    with patch("elengenix.scanning.universal._get_now_context", return_value="Now: 2024"):
                        with patch("elengenix.scanning.universal.registry") as mock_reg:
                            mock_reg.list_available_tools.return_value = {}
                            mock_client = Mock()
                            mock_client.chat.return_value = Mock(content="Hello! How can I help?")
                            result = process_universal(
                                user_input="hello",
                                client=mock_client,
                                conversation_history=[],
                                base_prompt="test",
                                governance=Mock(),
                            )

        assert "Hello" in result

    def test_calls_callback(self):
        """Should call callback with intent."""
        mock_callback = Mock()
        mock_client = Mock()
        mock_client.chat.return_value = Mock(content="response")

        with patch("elengenix.scanning.universal.analyze_intent", return_value="scan"):
            with patch("elengenix.scanning.universal.get_context_for_ai", return_value=""):
                with patch("elengenix.scanning.universal._get_memory_profile_context", return_value=""):
                    with patch("elengenix.scanning.universal._get_now_context", return_value="Now: 2024"):
                        with patch("elengenix.scanning.universal._build_bug_bounty_prompt", return_value="prompt"):
                            with patch("elengenix.scanning.universal.registry") as mock_registry:
                                mock_registry.list_available_tools.return_value = {}
                                process_universal(
                                    user_input="scan example.com",
                                    client=Mock(),
                                    conversation_history=[],
                                    base_prompt="test",
                                    governance=Mock(),
                                    callback=mock_callback,
                                    target="example.com",
                                )

        mock_callback.assert_called()
        assert any("SCAN" in str(c) for c in mock_callback.call_args_list)

    def test_research_mode_falls_through(self):
        """Research mode without target falls through to main loop."""
        with patch("elengenix.scanning.universal.analyze_intent", return_value="research"):
            with patch("elengenix.scanning.universal._get_now_context", return_value="Now: 2024"):
                with patch("elengenix.scanning.universal.registry") as mock_reg:
                    mock_reg.list_available_tools.return_value = {}
                    mock_client = Mock()
                    mock_client.chat.return_value = Mock(
                        content='{"thought": "test", "action": {"type": "search_web"}, "next_step": "done"}'
                    )
                    with patch("elengenix.scanning.universal.get_universal_executor") as mock_exec:
                        mock_exec.return_value.execute_action.return_value = Mock(success=True, output="search result")
                        result = process_universal(
                            user_input="today's news",
                            client=mock_client,
                            conversation_history=[],
                            base_prompt="test",
                            governance=Mock(),
                        )

        assert isinstance(result, str)
        assert len(result) > 0

    def test_shell_action_governance_deny(self):
        """Shell commands blocked by governance should be skipped."""
        with patch("elengenix.scanning.universal.analyze_intent", return_value="scan"):
            with patch("elengenix.scanning.universal.registry") as mock_reg:
                mock_reg.list_available_tools.return_value = {}
                mock_governance = Mock()
                mock_gate = Mock()
                mock_gate.decision = "deny"
                mock_gate.rationale = "blocked"
                mock_governance.gate.return_value = mock_gate
                mock_client = Mock()
                mock_client.chat.return_value = Mock(
                    content='{"thought": "run cmd", "action": {"type": "run_shell", "params": {"command": "rm -rf /"}}}'
                )
                with patch("elengenix.scanning.universal.get_universal_executor") as mock_exec:
                    result = process_universal(
                        user_input="scan example.com",
                        client=mock_client,
                        conversation_history=[],
                        base_prompt="test",
                        governance=mock_governance,
                        target="example.com",
                    )

        assert isinstance(result, str)

    def test_shell_action_needs_approval_rejected(self):
        """Shell commands needing approval that get rejected should be skipped."""
        with patch("elengenix.scanning.universal.analyze_intent", return_value="scan"):
            with patch("elengenix.scanning.universal.registry") as mock_reg:
                mock_reg.list_available_tools.return_value = {}
                mock_governance = Mock()
                mock_gate = Mock()
                mock_gate.decision = "needs_approval"
                mock_governance.gate.return_value = mock_gate
                mock_client = Mock()
                mock_client.chat.return_value = Mock(
                    content='{"thought": "run cmd", "action": {"type": "run_shell", "params": {"command": "ls"}}}'
                )
                with patch("elengenix.scanning.universal.get_universal_executor"):
                    with patch("cli.ui_components.confirm", return_value=False):
                        result = process_universal(
                            user_input="scan example.com",
                            client=mock_client,
                            conversation_history=[],
                            base_prompt="test",
                            governance=mock_governance,
                            target="example.com",
                        )

        assert isinstance(result, str)

    def test_finish_action_breaks_loop(self):
        """finish action should break the main loop."""
        with patch("elengenix.scanning.universal.analyze_intent", return_value="scan"):
            with patch("elengenix.scanning.universal.registry") as mock_reg:
                mock_reg.list_available_tools.return_value = {}
                mock_client = Mock()
                mock_client.chat.return_value = Mock(
                    content='{"thought": "done", "action": {"type": "finish"}}'
                )
                with patch("elengenix.scanning.universal.get_universal_executor") as mock_exec:
                    mock_exec.return_value.execute_action.return_value = Mock(success=True, output="ok")
                    result = process_universal(
                        user_input="scan example.com",
                        client=mock_client,
                        conversation_history=[],
                        base_prompt="test",
                        governance=Mock(),
                        target="example.com",
                    )

        assert isinstance(result, str)

    def test_two_consecutive_ai_failures_returns_unavailable(self):
        """Two consecutive AI failures should return unavailable message."""
        with patch("elengenix.scanning.universal.analyze_intent", return_value="scan"):
            with patch("elengenix.scanning.universal.registry") as mock_reg:
                mock_reg.list_available_tools.return_value = {}
                mock_client = Mock()
                mock_client.chat.side_effect = Exception("API down")
                with patch("elengenix.scanning.universal.get_universal_executor"):
                    result = process_universal(
                        user_input="scan example.com",
                        client=mock_client,
                        conversation_history=[],
                        base_prompt="test",
                        governance=Mock(),
                        target="example.com",
                    )

        assert "[ELENGENIX_AI_UNAVAILABLE]" in result


if __name__ == "__main__":
    pytest.main([__file__, "-v"])