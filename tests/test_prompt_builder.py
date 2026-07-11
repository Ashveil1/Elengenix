"""tests/test_prompt_builder.py — Tests for agents.prompt_builder.PromptBuilder"""

from unittest.mock import MagicMock, patch

import pytest

from agents.prompt_builder import PromptBuilder, _estimate_tokens
from agents.scan_context import ScanContext


# ── Helper ──────────────────────────────────────────────────────

SYSTEM_PROMPT = "You are Elengenix AI, a security research agent."


def _make_ctx(**kwargs) -> ScanContext:
    defaults = {"target": "example.com", "objective": "Find vulns"}
    defaults.update(kwargs)
    return ScanContext(**defaults)


# ── Token Estimate Tests ────────────────────────────────────────


class TestTokenEstimate:
    def test_empty_string(self):
        assert _estimate_tokens("") == 0

    def test_short_text(self):
        assert _estimate_tokens("hello") == 1  # 5 chars / 4 = 1

    def test_longer_text(self):
        assert _estimate_tokens("a" * 100) == 25  # 100 / 4 = 25


# ── Creation Tests ──────────────────────────────────────────────


class TestPromptBuilderCreation:
    def test_create_with_defaults(self):
        pb = PromptBuilder(SYSTEM_PROMPT)
        assert pb.base_prompt == SYSTEM_PROMPT
        assert pb.max_tokens == 8000

    def test_create_with_custom_max_tokens(self):
        pb = PromptBuilder(SYSTEM_PROMPT, max_tokens=4000)
        assert pb.max_tokens == 4000


# ── Chat Prompt Tests ──────────────────────────────────────────


class TestChatPrompt:
    @patch("tools.vector_memory.get_context_for_ai", return_value="")
    def test_chat_prompt_includes_intent(self, mock_memory):
        pb = PromptBuilder(SYSTEM_PROMPT)
        ctx = _make_ctx()
        prompt = pb.build_chat_prompt(ctx, "Hello", "casual")
        assert "Intent category: casual" in prompt

    @patch("tools.vector_memory.get_context_for_ai", return_value="")
    def test_chat_prompt_includes_system_identity(self, mock_memory):
        pb = PromptBuilder(SYSTEM_PROMPT)
        ctx = _make_ctx()
        prompt = pb.build_chat_prompt(ctx, "Hello", "security_chat")
        assert "Elengenix AI v3.0" in prompt

    @patch("tools.vector_memory.get_context_for_ai", return_value="")
    def test_chat_prompt_no_scan_instructions(self, mock_memory):
        pb = PromptBuilder(SYSTEM_PROMPT)
        ctx = _make_ctx()
        prompt = pb.build_chat_prompt(ctx, "Hello", "casual")
        assert "Do NOT attempt to run a scan" in prompt


# ── Tool List Tests ─────────────────────────────────────────────


class TestToolList:
    @patch("agents.prompt_builder.registry", create=True)
    def test_tool_list_includes_available_tools(self, mock_registry):
        mock_registry.list_available_tools.return_value = {
            "fuzzer": {"available": True},
            "recon": {"available": True},
            "missing_tool": {"available": False},
        }
        pb = PromptBuilder(SYSTEM_PROMPT)
        result = pb._build_tool_list()
        assert "fuzzer" in result
        assert "recon" in result
        assert "missing_tool" not in result

    def test_tool_list_handles_registry_error(self):
        pb = PromptBuilder(SYSTEM_PROMPT)
        # Should not raise, just return fallback
        result = pb._build_tool_list()
        assert isinstance(result, str)
        assert "AVAILABLE TOOLS" in result


# ── Section Builder Tests ───────────────────────────────────────


class TestSectionBuilders:
    def test_build_history_empty(self):
        pb = PromptBuilder(SYSTEM_PROMPT)
        ctx = _make_ctx()
        result = pb._build_history(ctx)
        assert result == ""

    def test_build_history_with_messages(self):
        pb = PromptBuilder(SYSTEM_PROMPT)
        ctx = _make_ctx()
        ctx.history = [
            {"role": "user", "content": "scan example.com"},
            {"role": "assistant", "content": "Starting scan..."},
        ]
        result = pb._build_history(ctx)
        assert "CHAT HISTORY" in result
        assert "User: scan example.com" in result
        assert "Assistant: Starting scan..." in result

    def test_build_results_summary_empty(self):
        pb = PromptBuilder(SYSTEM_PROMPT)
        ctx = _make_ctx()
        result = pb._build_results_summary(ctx)
        assert result == ""

    def test_build_mission_state_none(self):
        pb = PromptBuilder(SYSTEM_PROMPT)
        ctx = _make_ctx()
        result = pb._build_mission_state(ctx)
        assert result == ""

    def test_build_coverage_none(self):
        pb = PromptBuilder(SYSTEM_PROMPT)
        ctx = _make_ctx()
        result = pb._build_coverage(ctx)
        assert result == ""

    def test_build_beliefs_none(self):
        pb = PromptBuilder(SYSTEM_PROMPT)
        ctx = _make_ctx()
        result = pb._build_beliefs(ctx)
        assert result == ""

    def test_build_reflection_none(self):
        pb = PromptBuilder(SYSTEM_PROMPT)
        ctx = _make_ctx()
        result = pb._build_reflection(ctx)
        assert result == ""

    def test_build_negative_results_none(self):
        pb = PromptBuilder(SYSTEM_PROMPT)
        ctx = _make_ctx()
        result = pb._build_negative_results(ctx)
        assert result == ""


# ── Budget Assembly Tests ───────────────────────────────────────


class TestBudgetAssembly:
    def test_no_truncation_when_under_budget(self):
        pb = PromptBuilder(SYSTEM_PROMPT, max_tokens=8000)
        sections = [
            ("Short section 1", 500),
            ("Short section 2", 500),
        ]
        result = pb._assemble_with_budget(sections)
        assert "Short section 1" in result
        assert "Short section 2" in result

    def test_truncates_when_over_budget(self):
        pb = PromptBuilder("x", max_tokens=10)
        sections = [
            ("A" * 200, 0),  # ~50 tokens, never truncate
            ("B" * 200, 50),  # ~50 tokens, max 50
            ("C" * 200, 50),  # ~50 tokens, max 50
        ]
        result = pb._assemble_with_budget(sections)
        # Section A (priority 0) should be preserved
        assert "A" * 200 in result or "A" * 100 in result

    def test_never_truncated_sections_preserved(self):
        pb = PromptBuilder("x", max_tokens=10)
        sections = [
            ("CRITICAL_SECTION", 0),  # Never truncate
            ("B" * 500, 10),  # Will be truncated
        ]
        result = pb._assemble_with_budget(sections)
        assert "CRITICAL_SECTION" in result

    def test_empty_sections_skipped(self):
        pb = PromptBuilder(SYSTEM_PROMPT, max_tokens=8000)
        sections = [
            ("", 500),
            ("Real content", 500),
            ("", 500),
        ]
        result = pb._assemble_with_budget(sections)
        assert "Real content" in result
        assert result.count("\n\n") <= 1  # No double blank lines from empty sections


# ── Full Scan Prompt Tests ─────────────────────────────────────


class TestBuildScanPrompt:
    @patch("tools.tool_registry.registry")
    @patch("tools.vector_memory.recall", return_value=[])
    @patch("tools.vector_memory.get_context_for_ai", return_value="")
    def test_scan_prompt_includes_planning_instructions(
        self, mock_memory, mock_recall, mock_registry
    ):
        mock_registry.list_available_tools.return_value = {}

        pb = PromptBuilder(SYSTEM_PROMPT)
        ctx = _make_ctx()
        prompt = pb.build_scan_prompt(ctx, "Find SQLi")

        assert "Plan your next move" in prompt
        assert "COVERAGE GAPS" in prompt
        assert "ACTIVE HYPOTHESES" in prompt

    @patch("tools.tool_registry.registry")
    @patch("tools.vector_memory.recall", return_value=[])
    @patch("tools.vector_memory.get_context_for_ai", return_value="")
    def test_scan_prompt_includes_system_prompt(self, mock_memory, mock_recall, mock_registry):
        mock_registry.list_available_tools.return_value = {}

        pb = PromptBuilder(SYSTEM_PROMPT)
        ctx = _make_ctx()
        prompt = pb.build_scan_prompt(ctx, "Find XSS")

        assert SYSTEM_PROMPT in prompt

    @patch("tools.tool_registry.registry")
    @patch("tools.vector_memory.recall", return_value=[])
    @patch("tools.vector_memory.get_context_for_ai", return_value="")
    def test_scan_prompt_includes_tool_list(self, mock_memory, mock_recall, mock_registry):
        mock_registry.list_available_tools.return_value = {
            "fuzzer": {"available": True},
        }

        pb = PromptBuilder(SYSTEM_PROMPT)
        ctx = _make_ctx()
        prompt = pb.build_scan_prompt(ctx, "Find vulns")

        assert "AVAILABLE TOOLS" in prompt
        assert "fuzzer" in prompt

    @patch("tools.tool_registry.registry")
    @patch("tools.vector_memory.recall", return_value=[])
    @patch("tools.vector_memory.get_context_for_ai", return_value="")
    def test_scan_prompt_includes_chat_history(self, mock_memory, mock_recall, mock_registry):
        mock_registry.list_available_tools.return_value = {}

        pb = PromptBuilder(SYSTEM_PROMPT)
        ctx = _make_ctx()
        ctx.history = [
            {"role": "user", "content": "scan example.com"},
            {"role": "assistant", "content": "OK"},
        ]
        prompt = pb.build_scan_prompt(ctx, "scan example.com")

        assert "CHAT HISTORY" in prompt
        assert "scan example.com" in prompt
