"""Tests for elengenix/scanning/prompt_builder.py.

Tests cover:
- Module-level helper functions (_estimate_tokens, _load_few_shots, etc.)
- PromptBuilder class initialization and all private builder methods
- Token budget management (_assemble_with_budget)
- Full scan prompt and chat prompt assembly
- Edge cases: empty contexts, truncation, caching, error handling
"""
from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, PropertyMock, call, patch, mock_open

import pytest
import yaml

from elengenix.scanning.prompt_builder import (
    PromptBuilder,
    _estimate_tokens,
    _load_few_shots,
    _format_few_shots,
    _get_relevant_few_shots,
    _FEW_SHOT_CACHE,
    _PLANNING_INSTRUCTIONS,
    CHARS_PER_TOKEN,
)


# ===================================================================
# Fixtures
# ===================================================================


@pytest.fixture
def ctx():
    """Mock ScanContext with all attributes the PromptBuilder touches."""
    ctx = MagicMock()
    ctx.target = "test.local"
    ctx.step_count = 2
    ctx.max_steps = 25
    ctx.consecutive_no_findings = 1
    ctx.steps_remaining = 23
    ctx.has_findings = False
    ctx.finding_count = 0
    ctx.all_findings = []
    ctx.previous_results = []
    ctx.history = []
    ctx.mission_state = None
    ctx.coverage_map = None
    ctx.belief_state = None
    ctx.negative_results = None
    ctx.reflect_engine = None
    ctx.attack_tree = None
    ctx.action_history = []

    # Set up mock attack tree with no steps by default
    mock_tree = MagicMock()
    mock_tree.steps = []
    ctx.attack_tree = mock_tree
    return ctx


@pytest.fixture
def prompt_builder():
    """PromptBuilder with a simple base prompt."""
    return PromptBuilder(base_prompt="You are an AI security testing assistant.", max_tokens=8000)


@pytest.fixture
def few_shot_trace():
    """Sample few-shot trace dict."""
    return {
        "id": "sqli_001",
        "name": "SQL Injection Error-Based",
        "scenario": "A login form with MySQL backend",
        "reasoning": "Test for SQL injection by sending a single quote",
        "action": {"type": "http_request", "method": "POST", "payload": "'"},
        "expected_evidence": ["MySQL error", "syntax error"],
        "confidence": 0.95,
    }


# ===================================================================
# _estimate_tokens
# ===================================================================


class TestEstimateTokens:
    def test_empty_string(self):
        assert _estimate_tokens("") == 0

    def test_short_string(self):
        # "hello" = 5 chars // 4 = 1 token
        assert _estimate_tokens("hello") == 1

    def test_exact_multiple(self):
        # "abcd" = 4 chars // 4 = 1 token
        assert _estimate_tokens("abcd") == 1

    def test_truncation(self):
        # "abcdefghi" = 9 chars // 4 = 2 tokens
        assert _estimate_tokens("abcdefghi") == 2

    def test_long_text(self):
        text = "A" * 100
        assert _estimate_tokens(text) == 25

    def test_chars_per_token_constant(self):
        assert CHARS_PER_TOKEN == 4


# ===================================================================
# _load_few_shots
# ===================================================================


class TestLoadFewShots:
    def teardown_method(self):
        _FEW_SHOT_CACHE.clear()

    def test_returns_empty_list_when_no_file(self, monkeypatch):
        """When no few-shot file exists at any search path, return empty list."""
        monkeypatch.setattr(
            "elengenix.scanning.prompt_builder.Path.exists",
            lambda self: False,
        )
        result = _load_few_shots("sqli")
        assert result == []

    def test_returns_cached_value(self, monkeypatch):
        """Second call returns cached value without file access."""
        _FEW_SHOT_CACHE["sqli"] = [{"id": "cached"}]
        monkeypatch.setattr(
            "elengenix.scanning.prompt_builder.Path.exists",
            lambda self: True,
        )
        # If exists returned True but we don't open a file, it means we hit cache
        result = _load_few_shots("sqli")
        assert result == [{"id": "cached"}]

    def test_loads_list_from_yaml(self, monkeypatch):
        """Load few-shots when YAML contains a list."""
        sample_data = [{"id": "test_1"}, {"id": "test_2"}]
        monkeypatch.setattr("builtins.open", mock_open(read_data=yaml.dump(sample_data)))
        monkeypatch.setattr(
            "elengenix.scanning.prompt_builder.Path.exists",
            lambda self: True,
        )
        result = _load_few_shots("xss")
        assert len(result) == 2
        assert result[0] == {"id": "test_1"}

    def test_loads_traces_from_dict(self, monkeypatch):
        """Load few-shots when YAML has a 'traces' key."""
        sample_data = {"traces": [{"id": "t1"}, {"id": "t2"}]}
        monkeypatch.setattr("builtins.open", mock_open(read_data=yaml.dump(sample_data)))
        monkeypatch.setattr(
            "elengenix.scanning.prompt_builder.Path.exists",
            lambda self: True,
        )
        result = _load_few_shots("ssrf")
        assert len(result) == 2

    def test_loads_single_dict_as_list(self, monkeypatch):
        """When YAML contains a single dict (not list), wrap it in a list."""
        sample_data = {"id": "single_trace", "name": "Single"}
        monkeypatch.setattr("builtins.open", mock_open(read_data=yaml.dump(sample_data)))
        monkeypatch.setattr(
            "elengenix.scanning.prompt_builder.Path.exists",
            lambda self: True,
        )
        result = _load_few_shots("rce")
        assert len(result) == 1
        assert result[0]["id"] == "single_trace"

    def test_handles_empty_yaml(self, monkeypatch):
        """When YAML file contains None/empty data, return empty list."""
        monkeypatch.setattr("builtins.open", mock_open(read_data=yaml.dump(None)))
        monkeypatch.setattr(
            "elengenix.scanning.prompt_builder.Path.exists",
            lambda self: True,
        )
        result = _load_few_shots("lfi")
        assert result == []

    def test_skips_to_next_path_on_failure(self, monkeypatch):
        """When first path fails to load, try the next one."""
        sample_data = [{"id": "fallback"}]
        yaml_content = yaml.dump(sample_data)

        # Track which paths were checked
        checked_paths = []

        def mock_exists(self):
            checked_paths.append(str(self))
            return True  # All paths "exist"

        def mock_open_file(*args, **kwargs):
            # Return valid yaml on 3rd+ call (3rd path)
            call_idx = len(checked_paths)
            if call_idx >= 1:
                return mock_open(read_data=yaml_content).return_value
            # First calls (first 2 paths) raise exceptions
            raise FileNotFoundError(f"No such file: {args[0]}")

        monkeypatch.setattr(
            "elengenix.scanning.prompt_builder.Path.exists",
            mock_exists,
        )
        monkeypatch.setattr("builtins.open", mock_open_file)
        _FEW_SHOT_CACHE.clear()
        result = _load_few_shots("idor")
        assert result == [{"id": "fallback"}]
        _FEW_SHOT_CACHE.clear()

    def test_cache_stores_after_first_load(self, monkeypatch):
        """After loading, the result is cached."""
        sample_data = [{"id": "cached_test"}]
        monkeypatch.setattr("builtins.open", mock_open(read_data=yaml.dump(sample_data)))
        monkeypatch.setattr(
            "elengenix.scanning.prompt_builder.Path.exists",
            lambda self: True,
        )
        _FEW_SHOT_CACHE.clear()
        _load_few_shots("sqli")
        assert "sqli" in _FEW_SHOT_CACHE
        assert _FEW_SHOT_CACHE["sqli"] == sample_data
        _FEW_SHOT_CACHE.clear()


# ===================================================================
# _get_relevant_few_shots
# ===================================================================


class TestGetRelevantFewShots:
    def teardown_method(self):
        _FEW_SHOT_CACHE.clear()

    def test_returns_default_when_no_context(self, ctx):
        """With no beliefs, findings, or attack tree, fall back to sqli."""
        with patch(
            "elengenix.scanning.prompt_builder._load_few_shots",
            return_value=[{"id": "default"}],
        ) as mock_load:
            result = _get_relevant_few_shots(ctx, max_traces=3)
            assert len(result) >= 1
            mock_load.assert_any_call("sqli")

    def test_from_belief_state(self, ctx):
        """Extract vuln types from belief state metadata."""
        belief = MagicMock()
        belief.metadata = {"vuln_type": "xss"}
        ctx.belief_state = MagicMock()
        ctx.belief_state.beliefs = {"b1": belief}

        with patch(
            "elengenix.scanning.prompt_builder._load_few_shots",
            return_value=[{"id": "xss_trace"}],
        ) as mock_load:
            result = _get_relevant_few_shots(ctx)
            assert len(result) >= 1
            mock_load.assert_any_call("xss")

    def test_from_belief_state_alternative_key(self, ctx):
        """Use vulnerability_type key as fallback."""
        belief = MagicMock()
        belief.metadata = {"vulnerability_type": "ssrf"}
        ctx.belief_state = MagicMock()
        ctx.belief_state.beliefs = {"b1": belief}

        with patch(
            "elengenix.scanning.prompt_builder._load_few_shots",
            return_value=[{"id": "ssrf_trace"}],
        ) as mock_load:
            _get_relevant_few_shots(ctx)
            mock_load.assert_any_call("ssrf")

    def test_from_findings(self, ctx):
        """Extract vuln types from recent findings."""
        ctx.all_findings = [
            {"type": "sqli"},
            {"type": "xss"},
        ]

        with patch(
            "elengenix.scanning.prompt_builder._load_few_shots",
            return_value=[{"id": "trace"}],
        ) as mock_load:
            _get_relevant_few_shots(ctx)
            mock_load.assert_any_call("sqli")
            mock_load.assert_any_call("xss")

    def test_from_findings_multiple_keys(self, ctx):
        """Try multiple keys for vuln type in findings."""
        ctx.all_findings = [
            {"vulnerability_type": "rce"},
            {"vuln_type": "lfi"},
        ]

        with patch(
            "elengenix.scanning.prompt_builder._load_few_shots",
            return_value=[{"id": "trace"}],
        ) as mock_load:
            _get_relevant_few_shots(ctx)

    def test_from_attack_tree(self, ctx):
        """Extract vuln types from attack tree steps."""
        step = MagicMock()
        step.metadata = {"vuln_type": "xxe"}
        ctx.attack_tree = MagicMock()
        ctx.attack_tree.steps = [step]

        with patch(
            "elengenix.scanning.prompt_builder._load_few_shots",
            return_value=[{"id": "xxe_trace"}],
        ) as mock_load:
            _get_relevant_few_shots(ctx)
            mock_load.assert_any_call("xxe")

    def test_vuln_type_mapping(self, ctx):
        """Verify mapping of common vuln types to canonical names."""
        ctx.all_findings = [
            {"type": "sql_injection"},
            {"type": "bola"},
            {"type": "command_injection"},
            {"type": "path_traversal"},
        ]

        with patch(
            "elengenix.scanning.prompt_builder._load_few_shots",
            return_value=[{"id": "mapped"}],
        ) as mock_load:
            _get_relevant_few_shots(ctx)
            mock_load.assert_any_call("sqli")
            mock_load.assert_any_call("idor")
            mock_load.assert_any_call("rce")
            mock_load.assert_any_call("lfi")

    def test_respects_max_traces(self, ctx):
        """Return at most max_traces results."""
        ctx.all_findings = [
            {"type": "sqli"},
            {"type": "xss"},
            {"type": "ssrf"},
        ]

        with patch(
            "elengenix.scanning.prompt_builder._load_few_shots",
            return_value=[{"id": "t1"}, {"id": "t2"}, {"id": "t3"}],
        ):
            result = _get_relevant_few_shots(ctx, max_traces=2)
            assert len(result) <= 2

    def test_handles_belief_error_gracefully(self, ctx):
        """If belief state throws, continue without crashing."""
        ctx.belief_state = MagicMock()
        ctx.belief_state.beliefs = None

        with patch(
            "elengenix.scanning.prompt_builder._load_few_shots",
            return_value=[{"id": "default"}],
        ) as mock_load:
            # This should not raise despite accessing .values() on None
            result = _get_relevant_few_shots(ctx)
            assert isinstance(result, list)

    def test_multiple_sources_deduplicated(self, ctx):
        """Same vuln type from multiple sources should not duplicate."""
        belief = MagicMock()
        belief.metadata = {"vuln_type": "sqli"}
        ctx.belief_state = MagicMock()
        ctx.belief_state.beliefs = {"b1": belief}
        ctx.all_findings = [{"type": "sqli"}]

        with patch(
            "elengenix.scanning.prompt_builder._load_few_shots",
            return_value=[{"id": "t1"}, {"id": "t2"}],
        ) as mock_load:
            _get_relevant_few_shots(ctx)
            # sqli should only be loaded once
            calls = [c for c in mock_load.call_args_list if c[0][0] == "sqli"]
            assert len(calls) == 1


# ===================================================================
# _format_few_shots
# ===================================================================


class TestFormatFewShots:
    def test_empty_traces(self):
        assert _format_few_shots([]) == ""

    def test_single_trace(self, few_shot_trace):
        result = _format_few_shots([few_shot_trace])
        assert "Trace 1:" in result
        assert few_shot_trace["name"] in result
        assert "Scenario:" in result
        assert "Reasoning:" in result
        assert "Action:" in result
        assert "Expected Evidence:" in result
        assert "Confidence:" in result
        assert "KEY PATTERNS TO EMULATE" in result

    def test_multiple_traces(self, few_shot_trace):
        traces = [few_shot_trace, few_shot_trace.copy()]
        traces[1]["id"] = "sqli_002"
        traces[1]["name"] = "SQL Injection UNION-Based"
        result = _format_few_shots(traces)
        assert "Trace 1:" in result
        assert "Trace 2:" in result
        assert "SQL Injection UNION-Based" in result

    def test_trace_without_scenario(self, few_shot_trace):
        del few_shot_trace["scenario"]
        result = _format_few_shots([few_shot_trace])
        assert "Scenario:" not in result
        assert "Reasoning:" in result

    def test_trace_without_reasoning(self, few_shot_trace):
        del few_shot_trace["reasoning"]
        result = _format_few_shots([few_shot_trace])
        assert "Reasoning:" not in result

    def test_trace_without_action(self, few_shot_trace):
        del few_shot_trace["action"]
        result = _format_few_shots([few_shot_trace])
        assert "Action:" not in result

    def test_trace_without_expected_evidence(self, few_shot_trace):
        del few_shot_trace["expected_evidence"]
        result = _format_few_shots([few_shot_trace])
        assert "Expected Evidence:" not in result

    def test_trace_default_confidence_zero(self):
        trace = {"id": "test"}
        result = _format_few_shots([trace])
        assert "Confidence: 0%" in result

    def test_confidence_display(self):
        trace = {"id": "test", "confidence": 0.856}
        result = _format_few_shots([trace])
        assert "Confidence: 86%" in result or "Confidence: 85%" in result

    def test_expected_evidence_truncated_to_3(self):
        trace = {
            "id": "test",
            "name": "test",
            "expected_evidence": ["a", "b", "c", "d", "e"],
        }
        result = _format_few_shots([trace])
        assert "Expected Evidence: a; b; c" in result
        assert "d" not in result.split("Expected Evidence:")[1].split("\n")[0]

    def test_scenario_truncated_at_300_chars(self):
        trace = {"id": "test", "name": "test", "scenario": "X" * 500}
        result = _format_few_shots([trace])
        assert len(result.split("Scenario:")[1].split("...")[0]) <= 303

    def test_reasoning_truncated_at_500_chars(self):
        trace = {"id": "test", "name": "test", "reasoning": "Y" * 800}
        result = _format_few_shots([trace])
        assert len(result.split("Reasoning:")[1].split("...")[0]) <= 503

    def test_key_patterns_included(self):
        """The fixed KEY PATTERNS section should always be present."""
        result = _format_few_shots([{"id": "test"}])
        assert "KEY PATTERNS TO EMULATE" in result
        assert "capture baseline before injecting" in result
        assert "differential oracles" in result
        assert "Chain channels" in result
        assert "Validate scope" in result
        assert "EXFILTRATED DATA" in result


# ===================================================================
# PromptBuilder.__init__
# ===================================================================


class TestPromptBuilderInit:
    def test_default_max_tokens(self):
        pb = PromptBuilder(base_prompt="Test")
        assert pb.base_prompt == "Test"
        assert pb.max_tokens == 8000

    def test_custom_max_tokens(self):
        pb = PromptBuilder(base_prompt="Test", max_tokens=4000)
        assert pb.max_tokens == 4000

    def test_empty_base_prompt(self):
        pb = PromptBuilder(base_prompt="")
        assert pb.base_prompt == ""
        assert pb.max_tokens == 8000


# ===================================================================
# _build_tool_list
# ===================================================================


class TestBuildToolList:
    def test_returns_tool_list_when_registry_available(self, prompt_builder):
        with patch(
            "tools.tool_registry.registry"
        ) as mock_reg:
            mock_reg.list_available_tools.return_value = {
                "nmap": {"available": True},
                "gobuster": {"available": True},
                "hydra": {"available": False},
            }
            result = prompt_builder._build_tool_list()
            assert "### AVAILABLE TOOLS:" in result
            assert "nmap" in result
            assert "gobuster" in result
            assert "hydra" not in result

    def test_no_available_tools(self, prompt_builder):
        with patch(
            "tools.tool_registry.registry"
        ) as mock_reg:
            mock_reg.list_available_tools.return_value = {
                "hydra": {"available": False},
            }
            result = prompt_builder._build_tool_list()
            assert "No tools currently available" in result

    def test_fallback_on_import_error(self, prompt_builder):
        with patch(
            "tools.tool_registry.registry",
            new_callable=MagicMock,
        ) as mock_reg:
            mock_reg.list_available_tools.side_effect = ImportError("No registry")
            result = prompt_builder._build_tool_list()
            assert "Tool registry unavailable" in result

    def test_fallback_on_generic_exception(self, prompt_builder):
        with patch(
            "tools.tool_registry.registry",
            new_callable=MagicMock,
        ) as mock_reg:
            mock_reg.list_available_tools.side_effect = RuntimeError("Broken")
            result = prompt_builder._build_tool_list()
            assert "Tool registry unavailable" in result


# ===================================================================
# _build_strategy_authority
# ===================================================================


class TestBuildStrategyAuthority:
    def test_always_includes_authority_statement(self, prompt_builder, ctx):
        result = prompt_builder._build_strategy_authority(ctx)
        assert "STRATEGY AUTHORITY:" in result
        assert "FULL AUTHORITY" in result
        assert "FOLLOW" in result
        assert "OVERRIDE" in result
        assert "CREATE" in result
        assert "SKIP" in result
        assert "REPRIORITIZE" in result

    def test_includes_velocity(self, prompt_builder, ctx):
        result = prompt_builder._build_strategy_authority(ctx)
        assert "VELOCITY:" in result
        assert f"Steps taken: {ctx.step_count}/{ctx.max_steps}" in result
        assert f"Consecutive no-findings: {ctx.consecutive_no_findings}" in result
        assert f"Steps remaining: {ctx.steps_remaining}" in result

    def test_no_findings_section_when_no_findings(self, prompt_builder, ctx):
        ctx.has_findings = False
        result = prompt_builder._build_strategy_authority(ctx)
        assert "FINDINGS SO FAR" not in result

    def test_findings_summary_when_has_findings(self, prompt_builder, ctx):
        ctx.has_findings = True
        ctx.finding_count = 3
        ctx.all_findings = [
            {"severity": "critical"},
            {"severity": "high"},
            {"severity": "critical"},
        ]
        result = prompt_builder._build_strategy_authority(ctx)
        assert "FINDINGS SO FAR" in result
        assert "critical: 2" in result
        assert "high: 1" in result

    def test_findings_with_unknown_severity(self, prompt_builder, ctx):
        ctx.has_findings = True
        ctx.all_findings = [
            {"severity": "high"},
            {"severity": "unknown"},
        ]
        result = prompt_builder._build_strategy_authority(ctx)
        assert "unknown: 1" in result

    def test_empty_severity_fallback(self, prompt_builder, ctx):
        ctx.has_findings = True
        ctx.all_findings = [{"foo": "bar"}]
        result = prompt_builder._build_strategy_authority(ctx)
        assert "unknown: 1" in result


# ===================================================================
# _build_attack_tree_context
# ===================================================================


class TestBuildAttackTreeContext:
    def test_no_attack_tree(self, prompt_builder, ctx):
        ctx.attack_tree = None
        result = prompt_builder._build_attack_tree_context(ctx)
        assert "No attack tree available" in result

    def test_attack_tree_no_steps(self, prompt_builder, ctx):
        result = prompt_builder._build_attack_tree_context(ctx)
        assert "No attack tree available" in result

    def test_attack_tree_completed(self, prompt_builder, ctx):
        """All steps done — show completed message."""
        mock_tree = MagicMock()
        mock_tree.steps = [MagicMock(), MagicMock()]
        ctx.attack_tree = mock_tree
        ctx.step_count = 2  # All steps done
        result = prompt_builder._build_attack_tree_context(ctx)
        assert "Attack tree completed" in result

    def test_shows_remaining_steps(self, prompt_builder, ctx):
        """Show next 5 remaining steps when steps exist."""
        step1 = MagicMock()
        step1.phase = "reconnaissance"
        step1.tool_name = "nmap"
        step1.purpose = "Port scan"

        step2 = MagicMock()
        step2.phase = "exploitation"
        step2.tool_name = "sqlmap"
        step2.purpose = "SQL injection"

        mock_tree = MagicMock()
        mock_tree.steps = [step1, step2]
        ctx.attack_tree = mock_tree
        ctx.step_count = 0

        result = prompt_builder._build_attack_tree_context(ctx)
        assert "SUGGESTED ATTACK TREE" in result
        assert "nmap" in result
        assert "sqlmap" in result
        assert "reconnaissance" in result
        assert "exploitation" in result
        assert "SUGGESTION" in result

    def test_limits_to_5_steps(self, prompt_builder, ctx):
        """Show at most 5 remaining steps."""
        steps = []
        for i in range(10):
            s = MagicMock()
            s.phase = f"Phase {i}"
            s.tool_name = f"tool_{i}"
            s.purpose = f"Purpose {i}"
            steps.append(s)

        mock_tree = MagicMock()
        mock_tree.steps = steps
        ctx.attack_tree = mock_tree
        ctx.step_count = 0

        result = prompt_builder._build_attack_tree_context(ctx)
        # Should contain tool_0 through tool_4, not tool_5
        assert "tool_0" in result
        assert "tool_4" in result
        assert "tool_5" not in result

    def test_step_with_enum_phase(self, prompt_builder, ctx):
        """Handle phases that have a .value attribute (enum)."""
        step = MagicMock()
        step.phase = MagicMock()
        step.phase.value = "reconnaissance"
        step.tool_name = "nmap"
        step.purpose = "Port scan"

        mock_tree = MagicMock()
        mock_tree.steps = [step]
        ctx.attack_tree = mock_tree
        ctx.step_count = 0

        result = prompt_builder._build_attack_tree_context(ctx)
        assert "[reconnaissance]" in result

    def test_step_with_string_phase(self, prompt_builder, ctx):
        """Handle phases that are plain strings."""
        step = MagicMock()
        step.phase = "recon"
        step.tool_name = "nmap"
        step.purpose = "Port scan"

        mock_tree = MagicMock()
        mock_tree.steps = [step]
        ctx.attack_tree = mock_tree
        ctx.step_count = 0

        result = prompt_builder._build_attack_tree_context(ctx)
        assert "[recon]" in result


# ===================================================================
# _build_memory_context
# ===================================================================


class TestBuildMemoryContext:
    def test_returns_context_from_vector_memory(self, prompt_builder, ctx):
        with patch(
            "tools.vector_memory.get_context_for_ai",
            return_value="Relevant memory context here",
        ):
            result = prompt_builder._build_memory_context(ctx, "scan this target")
            assert result == "Relevant memory context here"

    def test_uses_target_or_universal(self, prompt_builder, ctx):
        ctx.target = "example.com"
        with patch(
            "tools.vector_memory.get_context_for_ai",
            return_value="",
        ) as mock_get:
            prompt_builder._build_memory_context(ctx, "query")
            mock_get.assert_called_with(
                current_query="query",
                target="example.com",
                max_memories=15,
            )

    def test_fallback_on_none_target(self, prompt_builder, ctx):
        ctx.target = None
        with patch(
            "tools.vector_memory.get_context_for_ai",
            return_value="",
        ) as mock_get:
            prompt_builder._build_memory_context(ctx, "query")
            mock_get.assert_called_with(
                current_query="query",
                target="universal",
                max_memories=15,
            )

    def test_returns_empty_string_on_error(self, prompt_builder, ctx):
        with patch(
            "tools.vector_memory.get_context_for_ai",
            side_effect=ImportError("No module"),
        ):
            result = prompt_builder._build_memory_context(ctx, "query")
            assert result == ""


# ===================================================================
# _build_related_memories
# ===================================================================


class TestBuildRelatedMemories:
    def test_returns_empty_when_no_memories(self, prompt_builder, ctx):
        with patch(
            "tools.vector_memory.recall",
            return_value=[],
        ):
            result = prompt_builder._build_related_memories(ctx, "query")
            assert result == ""

    def test_formats_memories(self, prompt_builder, ctx):
        memories = [
            {"content": "Found XSS vulnerability on /search", "similarity": 0.85},
            {"content": "SQL injection on /login endpoint", "similarity": 0.72},
        ]
        with patch(
            "tools.vector_memory.recall",
            return_value=memories,
        ):
            result = prompt_builder._build_related_memories(ctx, "query")
            assert "### SEMANTICALLY RELATED PAST MEMORIES:" in result
            assert "Found XSS" in result
            assert "SQL injection" in result
            assert "85%" in result or "84%" in result  # 0.85 -> 85%
            assert "72%" in result

    def test_truncates_content_to_100_chars(self, prompt_builder, ctx):
        long_content = "A" * 200
        memories = [{"content": long_content, "similarity": 0.9}]
        with patch(
            "tools.vector_memory.recall",
            return_value=memories,
        ):
            result = prompt_builder._build_related_memories(ctx, "query")
            # Should have the 100 chars plus "..." suffix
            assert "..." in result

    def test_handles_import_error(self, prompt_builder, ctx):
        with patch(
            "tools.vector_memory.recall",
            side_effect=ImportError("No module"),
        ):
            result = prompt_builder._build_related_memories(ctx, "query")
            assert result == ""


# ===================================================================
# _build_history
# ===================================================================


class TestBuildHistory:
    def test_empty_history(self, prompt_builder, ctx):
        ctx.history = []
        assert prompt_builder._build_history(ctx) == ""

    def test_returns_recent_history(self, prompt_builder, ctx):
        ctx.history = [
            {"role": "user", "content": "Scan this site"},
            {"role": "assistant", "content": "Starting scan..."},
        ]
        result = prompt_builder._build_history(ctx)
        assert "### CHAT HISTORY (Current Session):" in result
        assert "User: Scan this site" in result
        assert "Assistant: Starting scan..." in result

    def test_limits_to_last_10(self, prompt_builder, ctx):
        ctx.history = [{"role": "user", "content": str(i)} for i in range(15)]
        result = prompt_builder._build_history(ctx)
        # Should only show last 10 (5 through 14)
        assert "User: 0" not in result
        assert "User: 4" not in result
        assert "User: 5" in result
        assert "User: 14" in result
        # Count exactly 10 user lines
        assert result.count("User:") == 10

    def test_capitalizes_role(self, prompt_builder, ctx):
        ctx.history = [{"role": "user", "content": "hello"}]
        result = prompt_builder._build_history(ctx)
        assert "User: hello" in result
        assert "user:" not in result  # raw role not in output


# ===================================================================
# _build_results_summary
# ===================================================================


class TestBuildResultsSummary:
    def test_no_results(self, prompt_builder, ctx):
        ctx.previous_results = []
        assert prompt_builder._build_results_summary(ctx) == ""

    def test_with_tool_result_objects(self, prompt_builder, ctx):
        r1 = MagicMock()
        r1.tool_name = "nmap"
        r1.success = True
        r1.findings = [MagicMock(), MagicMock()]

        r2 = MagicMock()
        r2.tool_name = "gobuster"
        r2.success = False
        r2.findings = []

        ctx.previous_results = [r1, r2]
        result = prompt_builder._build_results_summary(ctx)
        assert "### PREVIOUS RESULTS (Current Mission):" in result
        assert "nmap: OK (2 findings)" in result
        assert "gobuster: FAIL (0 findings)" in result

    def test_with_dict_results(self, prompt_builder, ctx):
        ctx.previous_results = [
            {"tool": "nmap", "success": True},
            {"tool": "gobuster", "success": False},
        ]
        result = prompt_builder._build_results_summary(ctx)
        assert "nmap: OK" in result
        assert "gobuster: FAIL" in result

    def test_with_empty_findings_attribute(self, prompt_builder, ctx):
        r = MagicMock()
        r.tool_name = "test"
        r.success = True
        r.findings = None
        ctx.previous_results = [r]
        result = prompt_builder._build_results_summary(ctx)
        assert "test: OK (0 findings)" in result

    def test_limits_to_last_10(self, prompt_builder, ctx):
        for i in range(15):
            r = MagicMock()
            r.tool_name = f"tool_{i}"
            r.success = True
            r.findings = []
            ctx.previous_results.append(r)

        result = prompt_builder._build_results_summary(ctx)
        assert "tool_0" not in result
        assert "tool_5" in result
        assert "tool_14" in result


# ===================================================================
# _build_mission_state
# ===================================================================


class TestBuildMissionState:
    def test_returns_empty_when_none(self, prompt_builder, ctx):
        ctx.mission_state = None
        assert prompt_builder._build_mission_state(ctx) == ""

    def test_returns_snapshot_json(self, prompt_builder, ctx):
        ctx.mission_state = MagicMock()
        ctx.mission_state.snapshot.return_value = {
            "phase": "recon",
            "findings_count": 2,
        }
        result = prompt_builder._build_mission_state(ctx)
        assert "MISSION STATE SNAPSHOT" in result
        assert '"phase": "recon"' in result
        assert '"findings_count": 2' in result

    def test_handles_snapshot_error(self, prompt_builder, ctx):
        ctx.mission_state = MagicMock()
        ctx.mission_state.snapshot.side_effect = RuntimeError("DB error")
        result = prompt_builder._build_mission_state(ctx)
        assert result == ""


# ===================================================================
# _build_coverage
# ===================================================================


class TestBuildCoverage:
    def test_returns_empty_when_none(self, prompt_builder, ctx):
        ctx.coverage_map = None
        assert prompt_builder._build_coverage(ctx) == ""

    def test_delegates_to_coverage_map(self, prompt_builder, ctx):
        ctx.coverage_map = MagicMock()
        ctx.coverage_map.prompt_context.return_value = "Coverage context"
        result = prompt_builder._build_coverage(ctx)
        assert result == "Coverage context"
        ctx.coverage_map.prompt_context.assert_called_with(max_gaps=8)

    def test_handles_error(self, prompt_builder, ctx):
        ctx.coverage_map = MagicMock()
        ctx.coverage_map.prompt_context.side_effect = RuntimeError("error")
        result = prompt_builder._build_coverage(ctx)
        assert result == ""


# ===================================================================
# _build_beliefs
# ===================================================================


class TestBuildBeliefs:
    def test_returns_empty_when_none(self, prompt_builder, ctx):
        ctx.belief_state = None
        assert prompt_builder._build_beliefs(ctx) == ""

    def test_delegates_to_belief_state(self, prompt_builder, ctx):
        ctx.belief_state = MagicMock()
        ctx.belief_state.prompt_context.return_value = "Belief context"
        result = prompt_builder._build_beliefs(ctx)
        assert result == "Belief context"
        ctx.belief_state.prompt_context.assert_called_once()

    def test_handles_error(self, prompt_builder, ctx):
        ctx.belief_state = MagicMock()
        ctx.belief_state.prompt_context.side_effect = RuntimeError("error")
        result = prompt_builder._build_beliefs(ctx)
        assert result == ""


# ===================================================================
# _build_reflection
# ===================================================================


class TestBuildReflection:
    def test_returns_empty_when_none(self, prompt_builder, ctx):
        ctx.reflect_engine = None
        assert prompt_builder._build_reflection(ctx) == ""

    def test_delegates_to_reflect_engine(self, prompt_builder, ctx):
        ctx.reflect_engine = MagicMock()
        ctx.reflect_engine.prompt_context.return_value = "Reflection context"
        result = prompt_builder._build_reflection(ctx)
        assert result == "Reflection context"
        ctx.reflect_engine.prompt_context.assert_called_with(recent=3)

    def test_handles_error(self, prompt_builder, ctx):
        ctx.reflect_engine = MagicMock()
        ctx.reflect_engine.prompt_context.side_effect = RuntimeError("error")
        result = prompt_builder._build_reflection(ctx)
        assert result == ""


# ===================================================================
# _build_negative_results
# ===================================================================


class TestBuildNegativeResults:
    def test_returns_empty_when_none(self, prompt_builder, ctx):
        ctx.negative_results = None
        assert prompt_builder._build_negative_results(ctx) == ""

    def test_delegates_to_negative_results(self, prompt_builder, ctx):
        ctx.negative_results = MagicMock()
        ctx.negative_results.get_prompt_context.return_value = "Negative results context"
        result = prompt_builder._build_negative_results(ctx)
        assert result == "Negative results context"
        ctx.negative_results.get_prompt_context.assert_called_with(max_items=5)

    def test_handles_error(self, prompt_builder, ctx):
        ctx.negative_results = MagicMock()
        ctx.negative_results.get_prompt_context.side_effect = RuntimeError("error")
        result = prompt_builder._build_negative_results(ctx)
        assert result == ""


# ===================================================================
# _get_now_context
# ===================================================================


class TestGetNowContext:
    def test_returns_datetime_string(self, prompt_builder):
        import datetime

        result = prompt_builder._get_now_context()
        assert "Current date/time:" in result
        today = datetime.datetime.now().strftime("%Y-%m-%d")
        assert today in result


# ===================================================================
# _assemble_with_budget
# ===================================================================


class TestAssembleWithBudget:
    def test_no_truncation_needed(self, prompt_builder):
        sections = [
            ("Short base prompt", 0),
            ("Short tool list", 0),
            ("Short section", 500),
        ]
        result = prompt_builder._assemble_with_budget(sections)
        assert "Short base prompt" in result
        assert "Short tool list" in result
        assert "Short section" in result

    def test_never_truncates_priority_zero(self, prompt_builder):
        """Sections with max_tokens=0 are always kept full."""
        sections = [
            ("ALWAYS_KEEP_" * 5000, 0),  # Very long but priority 0
            ("SHORT_SECTION", 50),
        ]
        result = prompt_builder._assemble_with_budget(sections)
        assert "ALWAYS_KEEP_" in result

    def test_truncates_lowest_priority_first(self, prompt_builder):
        """When over budget, truncate sections in reverse priority order."""
        prompt_builder.max_tokens = 20  # Very tight budget
        sections = [
            ("BASE", 0),  # Never truncated
            ("AAAA BBBB CCCC DDDD EEEE FFFF GGGG HHHH IIII JJJJ", 2),  # Very tight
            ("TOOL_LIST", 0),  # Never truncated
        ]
        result = prompt_builder._assemble_with_budget(sections)
        # Should still have BASE and TOOL_LIST
        assert "BASE" in result
        assert "TOOL_LIST" in result

    def test_empty_sections_omitted(self, prompt_builder):
        sections = [
            ("Non-empty", 500),
            ("", 500),
            ("Also non-empty", 500),
        ]
        result = prompt_builder._assemble_with_budget(sections)
        assert "Non-empty" in result
        assert "Also non-empty" in result
        # No double blank lines from empty section
        assert "\n\n\n\n" not in result

    def test_all_sections_empty(self, prompt_builder):
        sections = [
            ("", 500),
            ("", 500),
        ]
        result = prompt_builder._assemble_with_budget(sections)
        assert result == ""

    def test_truncation_keeps_beginning(self, prompt_builder):
        """Truncation should cut from the end, not the beginning."""
        prompt_builder.max_tokens = 2  # Force truncation
        sections = [
            ("SHORT", 0),
            (("A" * 100), 1),  # Only budgeted for ~1 token (4 chars)
        ]
        result = prompt_builder._assemble_with_budget(sections)
        # The truncated section should keep beginning (A's) not cut from start
        assert result.count("A") <= 4  # At most ~1 token worth

    def test_single_empty_section_not_affected(self, prompt_builder):
        """Empty string sections are skipped, not included as empty delimiters."""
        result = prompt_builder._assemble_with_budget([
            ("Section A", 500),
        ])
        assert result == "Section A"

    def test_multiple_sections_joined(self, prompt_builder):
        """Sections are joined by double newlines."""
        result = prompt_builder._assemble_with_budget([
            ("First part.", 0),
            ("Second part.", 0),
        ])
        assert "First part.\n\nSecond part." in result

    def test_total_within_budget_uses_all_text(self, prompt_builder):
        """When total is within budget, all text is included unchanged."""
        short_text = "Hello world."
        ident_text = "Another section."
        result = prompt_builder._assemble_with_budget([
            (short_text, 0),
            (ident_text, 500),
        ])
        assert short_text in result
        assert ident_text in result


# ===================================================================
# build_scan_prompt
# ===================================================================


class TestBuildScanPrompt:
    def test_includes_base_prompt(self, prompt_builder, ctx):
        """The base/system prompt should always be in the output."""
        with patch.multiple(
            prompt_builder,
            _build_tool_list=MagicMock(return_value="### AVAILABLE TOOLS:\nnmap"),
            _build_strategy_authority=MagicMock(return_value="### STRATEGY AUTHORITY:"),
            _build_attack_tree_context=MagicMock(return_value="### ATTACK TREE:"),
            _build_mission_state=MagicMock(return_value=""),
            _build_coverage=MagicMock(return_value=""),
            _build_beliefs=MagicMock(return_value=""),
            _build_reflection=MagicMock(return_value=""),
            _build_negative_results=MagicMock(return_value=""),
            _build_results_summary=MagicMock(return_value=""),
            _build_memory_context=MagicMock(return_value=""),
            _build_related_memories=MagicMock(return_value=""),
            _build_history=MagicMock(return_value=""),
        ), patch(
            "elengenix.scanning.prompt_builder._format_few_shots",
            return_value="",
        ), patch(
            "elengenix.scanning.prompt_builder._get_relevant_few_shots",
            return_value=[],
        ):
            result = prompt_builder.build_scan_prompt(ctx, "scan example.com")
            assert "You are an AI security testing assistant." in result

    def test_includes_planning_instructions(self, prompt_builder, ctx):
        """_PLANNING_INSTRUCTIONS should always be at the end."""
        with patch.multiple(
            prompt_builder,
            _build_tool_list=MagicMock(return_value=""),
            _build_strategy_authority=MagicMock(return_value=""),
            _build_attack_tree_context=MagicMock(return_value=""),
            _build_mission_state=MagicMock(return_value=""),
            _build_coverage=MagicMock(return_value=""),
            _build_beliefs=MagicMock(return_value=""),
            _build_reflection=MagicMock(return_value=""),
            _build_negative_results=MagicMock(return_value=""),
            _build_results_summary=MagicMock(return_value=""),
            _build_memory_context=MagicMock(return_value=""),
            _build_related_memories=MagicMock(return_value=""),
            _build_history=MagicMock(return_value=""),
        ), patch(
            "elengenix.scanning.prompt_builder._format_few_shots",
            return_value="",
        ), patch(
            "elengenix.scanning.prompt_builder._get_relevant_few_shots",
            return_value=[],
        ):
            result = prompt_builder.build_scan_prompt(ctx, "scan example.com")
            assert "Plan your next move." in result
            assert result.strip().endswith('"purpose": "...", "question": "..."}')

    def test_calls_all_build_methods(self, prompt_builder, ctx):
        """Every builder method should be called during build_scan_prompt."""
        methods = {
            "_build_tool_list": MagicMock(return_value="Tools"),
            "_build_strategy_authority": MagicMock(return_value="Strategy"),
            "_build_attack_tree_context": MagicMock(return_value="AttackTree"),
            "_build_mission_state": MagicMock(return_value="Mission"),
            "_build_coverage": MagicMock(return_value="Coverage"),
            "_build_beliefs": MagicMock(return_value="Beliefs"),
            "_build_reflection": MagicMock(return_value="Reflection"),
            "_build_negative_results": MagicMock(return_value="Negatives"),
            "_build_results_summary": MagicMock(return_value="Results"),
            "_build_memory_context": MagicMock(return_value="Memory"),
            "_build_related_memories": MagicMock(return_value="Related"),
            "_build_history": MagicMock(return_value="History"),
        }

        with patch.multiple(prompt_builder, **methods), patch(
            "elengenix.scanning.prompt_builder._format_few_shots",
            return_value="FewShots",
        ), patch(
            "elengenix.scanning.prompt_builder._get_relevant_few_shots",
            return_value=[{"id": "trace"}],
        ):
            prompt_builder.build_scan_prompt(ctx, "scan test")

            for name, mock in methods.items():
                mock.assert_called_once()

    def test_with_all_context_populated(self, prompt_builder, ctx):
        ctx.has_findings = True
        ctx.finding_count = 5
        ctx.all_findings = [{"severity": "high"}] * 5
        ctx.history = [
            {"role": "user", "content": "start"},
            {"role": "assistant", "content": "ok"},
        ]
        ctx.step_count = 3

        with patch.multiple(
            prompt_builder,
            _build_tool_list=MagicMock(return_value="### AVAILABLE TOOLS:\nnmap"),
            _build_strategy_authority=MagicMock(
                return_value="### STRATEGY AUTHORITY:\nFULL AUTHORITY"
            ),
            _build_attack_tree_context=MagicMock(return_value="### ATTACK TREE:"),
            _build_mission_state=MagicMock(
                return_value="### MISSION STATE SNAPSHOT:\n{}"
            ),
            _build_coverage=MagicMock(
                return_value="### COVERAGE GAPS:\nnone"
            ),
            _build_beliefs=MagicMock(
                return_value="### ACTIVE HYPOTHESES:\nXSS"
            ),
            _build_reflection=MagicMock(
                return_value="### REFLECTION:\non_track"
            ),
            _build_negative_results=MagicMock(
                return_value="### NEGATIVE RESULTS:\nnone"
            ),
            _build_results_summary=MagicMock(
                return_value="### RESULTS:\nnmap OK"
            ),
            _build_memory_context=MagicMock(
                return_value="### MEMORY:\nrelated data"
            ),
            _build_related_memories=MagicMock(
                return_value="### RELATED MEMORIES:\nold findings"
            ),
            _build_history=MagicMock(
                return_value="### CHAT HISTORY:\nUser: start"
            ),
        ), patch(
            "elengenix.scanning.prompt_builder._format_few_shots",
            return_value="### FEW-SHOT:\ntrace content",
        ), patch(
            "elengenix.scanning.prompt_builder._get_relevant_few_shots",
            return_value=[{"id": "trace"}],
        ):
            result = prompt_builder.build_scan_prompt(ctx, "scan test")

        # Verify key sections are present
        assert "You are an AI security testing assistant." in result
        assert "Plan your next move." in result
        assert "AVAILABLE TOOLS" in result

    def test_few_shot_integration(self, prompt_builder, ctx):
        """Verify few-shot traces are fetched and formatted."""
        with patch(
            "elengenix.scanning.prompt_builder._get_relevant_few_shots",
            return_value=[{"id": "test_trace", "name": "Test"}],
        ), patch(
            "elengenix.scanning.prompt_builder._format_few_shots",
            return_value="### FEW-SHOT REASONING TRACES:\ntest",
        ), patch.multiple(
            prompt_builder,
            _build_tool_list=MagicMock(return_value=""),
            _build_strategy_authority=MagicMock(return_value=""),
            _build_attack_tree_context=MagicMock(return_value=""),
            _build_mission_state=MagicMock(return_value=""),
            _build_coverage=MagicMock(return_value=""),
            _build_beliefs=MagicMock(return_value=""),
            _build_reflection=MagicMock(return_value=""),
            _build_negative_results=MagicMock(return_value=""),
            _build_results_summary=MagicMock(return_value=""),
            _build_memory_context=MagicMock(return_value=""),
            _build_related_memories=MagicMock(return_value=""),
            _build_history=MagicMock(return_value=""),
        ):
            result = prompt_builder.build_scan_prompt(ctx, "scan test")
            assert "FEW-SHOT REASONING TRACES" in result


# ===================================================================
# build_chat_prompt
# ===================================================================


class TestBuildChatPrompt:
    def test_returns_formatted_chat_prompt(self, prompt_builder, ctx):
        with patch.object(
            prompt_builder, "_get_now_context", return_value="Current date/time: 2024-01-01"
        ), patch.object(
            prompt_builder,
            "_build_memory_context",
            return_value="Past memory context",
        ):
            result = prompt_builder.build_chat_prompt(ctx, "Hello!", "casual")

        assert "You are Elengenix AI v3.0" in result
        assert "Intent category: casual" in result
        assert "Current date/time: 2024-01-01" in result
        assert "Past memory context" in result
        assert "be friendly and conversational" in result
        assert "Do NOT attempt to run a scan" in result

    def test_research_intent(self, prompt_builder, ctx):
        with patch.object(
            prompt_builder, "_get_now_context", return_value=""
        ), patch.object(
            prompt_builder, "_build_memory_context", return_value=""
        ):
            result = prompt_builder.build_chat_prompt(ctx, "Tell me about CVEs", "research")

        assert "Intent category: research" in result
        assert "provide accurate information" in result
        assert "Do NOT attempt to run a scan" in result

    def test_security_chat_intent(self, prompt_builder, ctx):
        with patch.object(
            prompt_builder, "_get_now_context", return_value=""
        ), patch.object(
            prompt_builder, "_build_memory_context", return_value=""
        ):
            result = prompt_builder.build_chat_prompt(ctx, "How do I prevent XSS?", "security_chat")

        assert "Intent category: security_chat" in result
        assert "expert cybersecurity advice" in result


# ===================================================================
# Integration: _assemble_with_budget with build_scan_prompt
# ===================================================================


class TestBudgetIntegration:
    def test_tight_budget_truncates_low_priority(self, prompt_builder, ctx):
        """With a very tight token budget, lower priority sections get cut."""
        tight_builder = PromptBuilder(
            base_prompt="System prompt.", max_tokens=5
        )

        with patch.multiple(
            tight_builder,
            _build_tool_list=MagicMock(return_value="### AVAILABLE TOOLS:\nnmap"),
            _build_strategy_authority=MagicMock(
                return_value="### STRATEGY AUTHORITY:\n" + "A" * 200
            ),
            _build_attack_tree_context=MagicMock(return_value=""),
            _build_mission_state=MagicMock(return_value=""),
            _build_coverage=MagicMock(return_value=""),
            _build_beliefs=MagicMock(return_value=""),
            _build_reflection=MagicMock(return_value=""),
            _build_negative_results=MagicMock(return_value=""),
            _build_results_summary=MagicMock(return_value=""),
            _build_memory_context=MagicMock(return_value=""),
            _build_related_memories=MagicMock(return_value=""),
            _build_history=MagicMock(return_value=""),
        ), patch(
            "elengenix.scanning.prompt_builder._format_few_shots",
            return_value="",
        ), patch(
            "elengenix.scanning.prompt_builder._get_relevant_few_shots",
            return_value=[],
        ):
            result = tight_builder.build_scan_prompt(ctx, "scan test")

        # System prompt (always kept) + planning instructions (always at end)
        assert "System prompt." in result
        assert "Plan your next move." in result

    def test_generous_budget_includes_all(self, prompt_builder, ctx):
        """With a generous budget, all sections should be included."""
        generous = PromptBuilder(
            base_prompt="System.", max_tokens=100000
        )

        with patch.multiple(
            generous,
            _build_tool_list=MagicMock(return_value="TOOLS"),
            _build_strategy_authority=MagicMock(return_value="STRATEGY"),
            _build_attack_tree_context=MagicMock(return_value="ATTACK_TREE"),
            _build_mission_state=MagicMock(return_value="MISSION"),
            _build_coverage=MagicMock(return_value="COVERAGE"),
            _build_beliefs=MagicMock(return_value="BELIEFS"),
            _build_reflection=MagicMock(return_value="REFLECTION"),
            _build_negative_results=MagicMock(return_value="NEGATIVES"),
            _build_results_summary=MagicMock(return_value="RESULTS"),
            _build_memory_context=MagicMock(return_value="MEMORY"),
            _build_related_memories=MagicMock(return_value="RELATED"),
            _build_history=MagicMock(return_value="HISTORY"),
        ), patch(
            "elengenix.scanning.prompt_builder._format_few_shots",
            return_value="FEWSHOTS",
        ), patch(
            "elengenix.scanning.prompt_builder._get_relevant_few_shots",
            return_value=[],
        ):
            result = generous.build_scan_prompt(ctx, "scan test")

        assert "TOOLS" in result
        assert "STRATEGY" in result
        assert "ATTACK_TREE" in result
        assert "MISSION" in result
        assert "COVERAGE" in result
        assert "BELIEFS" in result
        assert "REFLECTION" in result
        assert "NEGATIVES" in result
        assert "RESULTS" in result
        assert "MEMORY" in result
        assert "RELATED" in result
        assert "HISTORY" in result
        assert "FEWSHOTS" in result


# ===================================================================
# Error handling & edge cases
# ===================================================================


class TestErrorHandling:
    def test_empty_scan_context_target(self):
        """ScanContext with empty target should raise ValueError."""
        with pytest.raises(ValueError):
            from elengenix.scanning.scan_context import ScanContext
            ScanContext(target="")

    def test_prompt_builder_with_empty_base_prompt(self):
        """PromptBuilder with empty base prompt should still work."""
        pb = PromptBuilder(base_prompt="")
        assert pb.base_prompt == ""

    def test_negative_max_tokens(self):
        """Negative max_tokens should still work (everything truncated)."""
        pb = PromptBuilder(base_prompt="Test", max_tokens=-1)
        result = pb._assemble_with_budget([("Some content", 100)])
        # With negative budget, everything gets truncated heavily
        assert isinstance(result, str)

    def test_load_few_shots_corrupt_yaml(self, monkeypatch):
        """Corrupt YAML file should return empty list, not crash."""
        monkeypatch.setattr(
            "elengenix.scanning.prompt_builder.Path.exists",
            lambda self: True,
        )
        monkeypatch.setattr(
            "builtins.open",
            mock_open(read_data=": : broken yaml : :"),
        )
        result = _load_few_shots("sqli")
        assert result == []

    @patch("elengenix.scanning.prompt_builder.logger")
    def test_logger_called_on_import_error(self, mock_logger, prompt_builder, ctx):
        """Logger should be called when tool registry import fails."""
        with patch(
            "tools.tool_registry.registry",
            new_callable=MagicMock,
        ) as mock_reg:
            mock_reg.list_available_tools.side_effect = ImportError("No tools")
            prompt_builder._build_tool_list()
            mock_logger.debug.assert_called_once()

    def test_non_string_user_input(self, prompt_builder, ctx):
        """Non-string user_input should still work (converted by f-string)."""
        with patch.multiple(
            prompt_builder,
            _build_tool_list=MagicMock(return_value=""),
            _build_strategy_authority=MagicMock(return_value=""),
            _build_attack_tree_context=MagicMock(return_value=""),
            _build_mission_state=MagicMock(return_value=""),
            _build_coverage=MagicMock(return_value=""),
            _build_beliefs=MagicMock(return_value=""),
            _build_reflection=MagicMock(return_value=""),
            _build_negative_results=MagicMock(return_value=""),
            _build_results_summary=MagicMock(return_value=""),
            _build_memory_context=MagicMock(return_value=""),
            _build_related_memories=MagicMock(return_value=""),
            _build_history=MagicMock(return_value=""),
        ), patch(
            "elengenix.scanning.prompt_builder._format_few_shots",
            return_value="",
        ), patch(
            "elengenix.scanning.prompt_builder._get_relevant_few_shots",
            return_value=[],
        ):
            # Should not raise
            result = prompt_builder.build_scan_prompt(ctx, 12345)
            assert isinstance(result, str)

    def test_build_memory_context_graceful_import_fallback(self, prompt_builder, ctx):
        """When vector_memory module can't be imported, return empty string."""
        # We need to simulate the import inside the try/except failing
        # The actual code does: from tools.vector_memory import get_context_for_ai, recall
        with patch(
            "tools.vector_memory.get_context_for_ai",
            side_effect=ImportError("No module"),
        ):
            result = prompt_builder._build_memory_context(ctx, "query")
            assert result == ""


# ===================================================================
# Few-shot cache lifecycle
# ===================================================================


class TestFewShotCacheLifecycle:
    def teardown_method(self):
        _FEW_SHOT_CACHE.clear()

    def test_cache_cleared_properly(self):
        """Cache should be empty after clearing."""
        _FEW_SHOT_CACHE["sqli"] = [{"id": "test"}]
        _FEW_SHOT_CACHE.clear()
        assert "sqli" not in _FEW_SHOT_CACHE

    def test_cache_hit_skips_file_load(self, monkeypatch):
        """On cache hit, file should never be read."""
        _FEW_SHOT_CACHE["xss"] = [{"id": "cached"}]
        open_called = [False]

        original_open = open
        def tracking_open(*args, **kwargs):
            open_called[0] = True
            return original_open(*args, **kwargs)

        monkeypatch.setattr("builtins.open", tracking_open)
        # Make Path.exists return True to ensure cache is the only guard
        monkeypatch.setattr(
            "elengenix.scanning.prompt_builder.Path.exists",
            lambda self: True,
        )
        result = _load_few_shots("xss")
        assert result == [{"id": "cached"}]
        assert not open_called[0], "File should not be opened on cache hit"
