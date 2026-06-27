"""
tests/test_coverage_boost.py — Increase test coverage for core modules

Tests pure functions and utility methods that don't require network or external dependencies.
Focuses on: orchestrator.py, main.py, agent_brain.py
"""

import os
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest


# ── orchestrator.py tests ─────────────────────────────────────────────────────


class TestNormalizeTarget:
    """Test normalize_target function."""

    def test_normalize_plain_domain(self):
        from orchestrator import normalize_target

        assert normalize_target("example.com") == "example.com"

    def test_normalize_domain_with_protocol(self):
        from orchestrator import normalize_target

        assert normalize_target("https://example.com") == "example.com"
        assert normalize_target("http://example.com") == "example.com"

    def test_normalize_domain_with_path(self):
        from orchestrator import normalize_target

        assert normalize_target("https://example.com/path") == "example.com"

    def test_normalize_domain_with_port(self):
        from orchestrator import normalize_target

        assert normalize_target("example.com:8080") == "example.com"

    def test_normalize_domain_with_trailing_dot(self):
        from orchestrator import normalize_target

        assert normalize_target("example.com.") == "example.com"

    def test_normalize_empty_string(self):
        from orchestrator import normalize_target

        assert normalize_target("") == ""

    def test_normalize_none(self):
        from orchestrator import normalize_target

        assert normalize_target(None) == ""

    def test_normalize_strips_whitespace(self):
        from orchestrator import normalize_target

        assert normalize_target("  example.com  ") == "example.com"

    def test_normalize_lowercases(self):
        from orchestrator import normalize_target

        assert normalize_target("EXAMPLE.COM") == "example.com"

    def test_normalize_ipv6_with_port(self):
        from orchestrator import normalize_target

        # IPv6 with brackets should not strip port
        result = normalize_target("[::1]:8080")
        assert "::1" in result


class TestIsValidTarget:
    """Test is_valid_target function."""

    def test_valid_domain(self):
        from orchestrator import is_valid_target

        assert is_valid_target("example.com") is True

    def test_valid_subdomain(self):
        from orchestrator import is_valid_target

        assert is_valid_target("sub.example.com") is True

    def test_invalid_empty(self):
        from orchestrator import is_valid_target

        assert is_valid_target("") is False

    def test_invalid_none(self):
        from orchestrator import is_valid_target

        assert is_valid_target(None) is False

    def test_invalid_no_dot(self):
        from orchestrator import is_valid_target

        assert is_valid_target("localhost") is False

    def test_invalid_too_long(self):
        from orchestrator import is_valid_target

        long_domain = "a" * 254 + ".com"
        assert is_valid_target(long_domain) is False

    def test_invalid_private_ip(self):
        from orchestrator import is_valid_target

        assert is_valid_target("127.0.0.1") is False
        assert is_valid_target("192.168.1.1") is False
        assert is_valid_target("10.0.0.1") is False

    def test_valid_public_ip(self):
        from orchestrator import is_valid_target

        assert is_valid_target("8.8.8.8") is True

    def test_invalid_special_chars(self):
        from orchestrator import is_valid_target

        assert is_valid_target("exam ple.com") is False
        assert is_valid_target("example.com;ls") is False


class TestSanitizePath:
    """Test sanitize_path function."""

    def test_sanitize_normal(self):
        from orchestrator import sanitize_path

        assert sanitize_path("example.com") == "example.com"

    def test_sanitize_special_chars(self):
        from orchestrator import sanitize_path

        result = sanitize_path("example.com/path?query=1")
        assert "/" not in result
        assert "?" not in result

    def test_sanitize_max_length(self):
        from orchestrator import sanitize_path

        long_path = "a" * 200
        result = sanitize_path(long_path)
        assert len(result) <= 100

    def test_sanitize_preserves_dots_and_dashes(self):
        from orchestrator import sanitize_path

        result = sanitize_path("sub-domain.example.com")
        assert "." in result
        assert "-" in result


class TestIsInScope:
    """Test is_in_scope function."""

    def test_in_scope_no_domains(self):
        """When ALLOWED_DOMAINS is empty, all valid targets are in scope."""
        from orchestrator import is_in_scope

        with patch("orchestrator.ALLOWED_DOMAINS", set()):
            assert is_in_scope("example.com") is True

    def test_in_scope_matching_domain(self):
        from orchestrator import is_in_scope

        with patch("orchestrator.ALLOWED_DOMAINS", {"example.com"}):
            assert is_in_scope("example.com") is True

    def test_in_scope_subdomain(self):
        from orchestrator import is_in_scope

        with patch("orchestrator.ALLOWED_DOMAINS", {"example.com"}):
            assert is_in_scope("sub.example.com") is True

    def test_not_in_scope(self):
        from orchestrator import is_in_scope

        with patch("orchestrator.ALLOWED_DOMAINS", {"example.com"}):
            assert is_in_scope("other.com") is False

    def test_in_scope_empty_target(self):
        from orchestrator import is_in_scope

        assert is_in_scope("") is False

    def test_in_scope_none_target(self):
        from orchestrator import is_in_scope

        assert is_in_scope(None) is False

    def test_in_scope_invalid_target(self):
        from orchestrator import is_in_scope

        assert is_in_scope("not valid") is False


# ── main.py tests ─────────────────────────────────────────────────────────────


class TestValidateTarget:
    """Test validate_target function."""

    def test_valid_domain(self):
        from main import validate_target

        assert validate_target("example.com") is True

    def test_valid_subdomain(self):
        from main import validate_target

        assert validate_target("sub.example.com") is True

    def test_valid_ip(self):
        from main import validate_target

        assert validate_target("8.8.8.8") is True

    def test_invalid_empty(self):
        from main import validate_target

        assert validate_target("") is False

    def test_invalid_none(self):
        from main import validate_target

        assert validate_target(None) is False

    def test_invalid_too_long(self):
        from main import validate_target

        assert validate_target("a" * 254) is False

    def test_invalid_shell_metacharacters(self):
        from main import validate_target

        assert validate_target("example.com;ls") is False
        assert validate_target("example.com|cat") is False
        assert validate_target("example.com&whoami") is False
        assert validate_target("example.com`id`") is False
        assert validate_target("example.com$(id)") is False

    def test_invalid_private_ip(self):
        from main import validate_target

        assert validate_target("127.0.0.1") is False
        assert validate_target("192.168.1.1") is False
        assert validate_target("10.0.0.1") is False

    def test_valid_with_protocol(self):
        from main import validate_target

        assert validate_target("https://example.com") is True

    def test_invalid_reserved_ip(self):
        from main import validate_target

        assert validate_target("0.0.0.0") is False


class TestCheckModule:
    """Test _check_module function."""

    def test_existing_module(self):
        from main import _check_module

        assert _check_module("os") is True

    def test_existing_module_path(self):
        from main import _check_module

        assert _check_module("os.path") is True

    def test_nonexistent_module(self):
        from main import _check_module

        assert _check_module("nonexistent_module_xyz") is False


# ── agent_brain.py tests ──────────────────────────────────────────────────────


class TestExtractJson:
    """Test _extract_json method."""

    def setup_method(self):
        """Create a minimal agent instance for testing."""
        from agent_brain import ElengenixAgent

        self.agent = ElengenixAgent.__new__(ElengenixAgent)

    def test_extract_valid_json(self):
        text = '{"action": "run_shell", "command": "ls"}'
        result = self.agent._extract_json(text)
        assert result == {"action": "run_shell", "command": "ls"}

    def test_extract_json_from_text(self):
        text = 'Here is the JSON: {"action": "run_shell", "command": "ls"} and more text'
        result = self.agent._extract_json(text)
        assert result == {"action": "run_shell", "command": "ls"}

    def test_extract_no_json(self):
        text = "No JSON here"
        result = self.agent._extract_json(text)
        assert result is None

    def test_extract_invalid_json(self):
        text = '{"action": "run_shell", "command": "ls"'  # missing closing brace
        result = self.agent._extract_json(text)
        assert result is None

    def test_extract_json_with_nested(self):
        text = '{"action": "run_shell", "data": {"key": "value"}}'
        result = self.agent._extract_json(text)
        assert result["data"]["key"] == "value"


class TestAnalyzeIntent:
    """Test _analyze_intent method."""

    def setup_method(self):
        from agent_brain import ElengenixAgent

        self.agent = ElengenixAgent.__new__(ElengenixAgent)
        self.agent.client = MagicMock()

    def test_scan_intent(self):
        with patch("agent_brain._analyze_intent", return_value="scan"):
            result = self.agent._analyze_intent("scan example.com")
            assert result == "scan"

    def test_casual_intent(self):
        with patch("agent_brain._analyze_intent", return_value="casual"):
            result = self.agent._analyze_intent("hello how are you")
            assert result == "casual"

    def test_research_intent(self):
        with patch("agent_brain._analyze_intent", return_value="research"):
            result = self.agent._analyze_intent("what is SQL injection")
            assert result == "research"


class TestSummarizeResults:
    """Test _summarize_results method."""

    def setup_method(self):
        from agent_brain import ElengenixAgent

        self.agent = ElengenixAgent.__new__(ElengenixAgent)

    def test_empty_results(self):
        from tools.tool_registry import ToolResult

        result = self.agent._summarize_results([])
        assert "No previous results" in result

    def test_with_results(self):
        from tools.tool_registry import ToolResult, ToolCategory

        mock_result = ToolResult(
            success=True,
            tool_name="test_tool",
            category=ToolCategory.RECON,
            findings=[{"type": "xss", "url": "http://example.com"}],
        )
        result = self.agent._summarize_results([mock_result])
        assert "test_tool" in result
        assert "1 findings" in result


# ── ui_components.py tests ────────────────────────────────────────────────────


class TestSeverityColor:
    """Test severity_color function."""

    def test_returns_string(self):
        from ui_components import severity_color

        result = severity_color("critical")
        assert isinstance(result, str)
        assert result.startswith("#")

    def test_case_insensitive(self):
        from ui_components import severity_color

        assert severity_color("CRITICAL") == severity_color("critical")

    def test_unknown_returns_default(self):
        from ui_components import severity_color

        result = severity_color("unknown")
        assert isinstance(result, str)
        assert result.startswith("#")


class TestFormatMenuItem:
    """Test format_menu_item function."""

    def test_format_basic(self):
        from ui_components import format_menu_item

        result = format_menu_item(1, "Test", "Description")
        assert "1" in result
        assert "Test" in result
        assert "Description" in result


# ── tools/tool_registry.py tests ──────────────────────────────────────────────


class TestToolCategory:
    """Test ToolCategory enum."""

    def test_categories_exist(self):
        from tools.tool_registry import ToolCategory

        assert ToolCategory.RECON
        assert ToolCategory.SCANNER
        assert ToolCategory.FUZZING
        assert ToolCategory.UTILITY


class TestToolResult:
    """Test ToolResult dataclass."""

    def test_create_result(self):
        from tools.tool_registry import ToolResult, ToolCategory

        result = ToolResult(
            success=True,
            tool_name="test",
            category=ToolCategory.RECON,
            findings=[{"type": "test"}],
        )
        assert result.success is True
        assert result.tool_name == "test"
        assert len(result.findings) == 1

    def test_create_failed_result(self):
        from tools.tool_registry import ToolResult, ToolCategory

        result = ToolResult(
            success=False,
            tool_name="test",
            category=ToolCategory.RECON,
            error_message="Tool failed",
        )
        assert result.success is False
        assert result.error_message == "Tool failed"


# ── tools/cvss_calculator.py tests ────────────────────────────────────────────


class TestCVSSCalculator:
    """Test CVSS calculator basic functionality."""

    def test_calculator_init(self):
        from tools.cvss_calculator import CVSSCalculator

        calc = CVSSCalculator(use_ai=False)
        assert calc.use_ai is False
        assert calc.client is None


# ── tools/governance.py tests ─────────────────────────────────────────────────


class TestGovernance:
    """Test governance risk classification."""

    def test_safe_commands(self):
        from tools.governance import Governance

        gov = Governance()
        decision = gov.gate(
            "test-mission", "example.com", {"command": "echo hello", "tool": "shell"}
        )
        assert decision.risk_level in ["SAFE", "LOW"]

    def test_destructive_commands(self):
        from tools.governance import Governance

        gov = Governance()
        decision = gov.gate("test-mission", "example.com", {"command": "rm -rf /", "tool": "shell"})
        assert decision.risk_level in ["DESTRUCTIVE", "HIGH", "CRITICAL"]


# ── tools/mission_state.py tests ──────────────────────────────────────────────


class TestMissionState:
    """Test MissionState basic functionality."""

    def test_create_mission(self):
        from tools.mission_state import MissionState

        ms = MissionState(mission_id="test-1", target="example.com", objective="Test")
        assert ms.mission_id == "test-1"
        assert ms.target == "example.com"

    def test_snapshot(self):
        from tools.mission_state import MissionState

        ms = MissionState(mission_id="test-1", target="example.com", objective="Test")
        snap = ms.snapshot()
        assert "mission_id" in snap
        assert snap["mission_id"] == "test-1"


# ── tui/themes.py tests ──────────────────────────────────────────────────────


class TestThemes:
    """Test theme system."""

    def test_default_theme(self):
        from tui.themes import THEMES

        assert "DEFAULT" in THEMES
        assert "CYBERPUNK" in THEMES
        assert "MATRIX" in THEMES

    def test_theme_has_colors(self):
        from tui.themes import THEMES

        default = THEMES["DEFAULT"]
        assert isinstance(default, dict)
        assert "bg_dark" in default or "accent" in default


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
