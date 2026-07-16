"""Tests for elengenix/scanning/vuln_reasoning_phase.py — autonomous vulnerability reasoning phase."""

from __future__ import annotations

import pytest
from unittest.mock import MagicMock, patch, Mock
from typing import Any, Dict, List

from elengenix.scanning.vuln_reasoning_phase import (
    run_reasoning_phase,
    _hypothesis_to_finding,
    _dataclass_to_dict,
    DEFAULT_MIN_CONFIDENCE,
)


class TestHypothesisToFinding:
    """Tests for _hypothesis_to_finding helper function."""

    def test_basic_hypothesis_conversion(self):
        """Convert a basic hypothesis dict to a finding dict."""
        hypothesis = {
            "vuln_class": "sqli",
            "title": "SQL Injection in login form",
            "confidence": 0.8,
            "reasoning": "Found error-based SQLi in username field",
            "evidence": ["SQL error in response", "delayed response on ' OR '1'='1"],
            "suggested_tests": ["Try UNION injection", "Test blind SQLi"],
            "cwe": "CWE-89",
            "severity": "High",
            "target_endpoint": "/login",
            "parameter": "username",
            "payload": "' OR '1'='1",
        }
        target = "https://example.com"
        step = 5

        finding = _hypothesis_to_finding(hypothesis, target, step)

        assert finding["type"] == "sqli"
        assert finding["title"] == "SQL Injection in login form"
        assert finding["severity"] == "high"
        assert finding["confidence"] == 0.8
        assert finding["description"] == "Found error-based SQLi in username field"
        assert finding["evidence"] == ["SQL error in response", "delayed response on ' OR '1'='1"]
        assert finding["suggested_tests"] == ["Try UNION injection", "Test blind SQLi"]
        assert finding["cwe"] == "CWE-89"
        assert finding["target_endpoint"] == "/login"
        assert finding["parameter"] == "username"
        assert finding["payload"] == "' OR '1'='1"
        assert finding["url"] == "/login"
        assert finding["source"] == "ai_reasoning"
        assert finding["provenance"] == "agentic"
        assert finding["trust_class"] == "non_deterministic"
        assert finding["discovered_by"] == "vuln_reasoning_phase"
        assert finding["discovered_at_step"] == 5

    def test_hypothesis_with_missing_optional_fields(self):
        """Hypothesis with minimal fields should use defaults."""
        hypothesis = {
            "vuln_class": "xss",
            "confidence": 0.6,
        }
        target = "https://test.com"
        step = 1

        finding = _hypothesis_to_finding(hypothesis, target, step)

        assert finding["type"] == "xss"
        assert finding["title"] == "AI-generated vulnerability hypothesis"
        assert finding["severity"] == "medium"  # default
        assert finding["confidence"] == 0.6
        assert finding["description"] == ""
        assert finding["evidence"] == []
        assert finding["suggested_tests"] == []
        assert finding["cwe"] == ""
        assert finding["target_endpoint"] == ""
        assert finding["parameter"] == ""
        assert finding["payload"] == ""
        assert finding["url"] == "https://test.com"  # falls back to target

    def test_hypothesis_with_empty_target_endpoint_falls_back_to_target(self):
        """Empty target_endpoint should fall back to target URL."""
        hypothesis = {
            "target_endpoint": "",
        }
        target = "https://fallback.example.com"
        step = 2

        finding = _hypothesis_to_finding(hypothesis, target, step)

        assert finding["url"] == "https://fallback.example.com"

    def test_severity_normalized_to_lowercase(self):
        """Severity should be lowercased."""
        for input_sev, expected in [
            ("Critical", "critical"),
            ("HIGH", "high"),
            ("Medium", "medium"),
            ("LOW", "low"),
            ("Info", "info"),
        ]:
            hypothesis = {"severity": input_sev}
            finding = _hypothesis_to_finding(hypothesis, "http://test.com", 1)
            assert finding["severity"] == expected, f"Failed for {input_sev}"

    def test_confidence_converted_to_float(self):
        """Confidence should be converted to float."""
        hypothesis = {"confidence": "0.75"}  # string input
        finding = _hypothesis_to_finding(hypothesis, "http://test.com", 1)
        assert finding["confidence"] == 0.75
        assert isinstance(finding["confidence"], float)

    def test_provenance_tag_added(self):
        """Finding should be tagged with provenance via tag_provenance."""
        hypothesis = {"vuln_class": "test"}
        finding = _hypothesis_to_finding(hypothesis, "http://test.com", 1)
        # tag_provenance adds these fields
        assert "provenance" in finding
        assert "trust_class" in finding


class TestDataclassToDict:
    """Tests for _dataclass_to_dict helper function."""

    def test_dataclass_with_dict_attr(self):
        """Object with __dict__ should convert to dict."""

        class TestDataclass:
            def __init__(self):
                self.field1 = "value1"
                self.field2 = 42

        obj = TestDataclass()
        result = _dataclass_to_dict(obj)
        assert result == {"field1": "value1", "field2": 42}

    def test_object_with_to_dict_method(self):
        """Object with to_dict() method should use it."""

        class WithToDict:
            __slots__ = []  # No __dict__

            def to_dict(self):
                return {"custom": "dict"}

        obj = WithToDict()
        result = _dataclass_to_dict(obj)
        assert result == {"custom": "dict"}

    def test_to_dict_raises_exception(self):
        """If to_dict() raises, should return empty dict."""

        class BadToDict:
            def to_dict(self):
                raise ValueError("fail")

        obj = BadToDict()
        result = _dataclass_to_dict(obj)
        assert result == {}

    def test_object_without_dict_or_to_dict(self):
        """Plain object without __dict__ or to_dict returns empty dict."""

        class NoDict:
            __slots__ = ["a"]

            def __init__(self):
                self.a = 1

        obj = NoDict()
        result = _dataclass_to_dict(obj)
        assert result == {}


class TestRunReasoningPhase:
    """Tests for run_reasoning_phase main function."""

    def test_empty_evidence_returns_empty_list(self):
        """No evidence and no observation returns empty findings."""
        ctx = None
        result = run_reasoning_phase(ctx, "", "", step=1)
        assert result == []

    def test_only_whitespace_evidence_returns_empty(self):
        """Whitespace-only evidence returns empty."""
        ctx = None
        result = run_reasoning_phase(ctx, "   ", "  ", step=1)
        assert result == []

    def test_no_engine_returns_empty(self):
        """When _get_reasoning_engine returns None, returns empty list."""
        ctx = Mock()
        ctx.target = "http://test.com"
        ctx.all_findings = []

        with patch("elengenix.scanning.vuln_reasoning_phase._get_reasoning_engine", return_value=None):
            result = run_reasoning_phase(ctx, "some output", "observation", step=1)
            assert result == []

    def test_engine_analyze_output_exception_returns_empty(self):
        """Exception from engine.analyze_output returns empty list."""
        ctx = Mock()
        ctx.target = "http://test.com"
        ctx.all_findings = []

        mock_engine = Mock()
        mock_engine.analyze_output.side_effect = Exception("API error")

        with patch("elengenix.scanning.vuln_reasoning_phase._get_reasoning_engine", return_value=mock_engine):
            result = run_reasoning_phase(ctx, "output", "obs", step=1)
            assert result == []

    def test_hypotheses_below_min_confidence_filtered(self):
        """Hypotheses below min_confidence should be filtered out."""
        ctx = Mock()
        ctx.target = "http://test.com"
        ctx.all_findings = []

        mock_engine = Mock()
        mock_result = Mock()
        mock_result.hypotheses = [
            {"vuln_class": "sqli", "confidence": 0.2, "title": "Low confidence"},
            {"vuln_class": "xss", "confidence": 0.9, "title": "High confidence"},
        ]
        mock_engine.analyze_output.return_value = mock_result

        with patch("elengenix.scanning.vuln_reasoning_phase._get_reasoning_engine", return_value=mock_engine):
            result = run_reasoning_phase(ctx, "output", "obs", step=1, min_confidence=0.5)

        assert len(result) == 1
        assert result[0]["title"] == "High confidence"
        assert result[0]["confidence"] == 0.9

    def test_hypothesis_object_converted_via_dataclass_to_dict(self):
        """Hypothesis objects (not dicts) should be converted via _dataclass_to_dict."""
        ctx = Mock()
        ctx.target = "http://test.com"
        ctx.all_findings = []

        # Mock hypothesis as an object with __dict__
        class HypObj:
            def __init__(self):
                self.vuln_class = "sqli"
                self.confidence = 0.8
                self.title = "Test SQLi"
                self.reasoning = "Found it"
                self.evidence = []
                self.suggested_tests = []
                self.cwe = "CWE-89"
                self.severity = "High"
                self.target_endpoint = "/login"
                self.parameter = "user"
                self.payload = "' OR 1=1"

        mock_engine = Mock()
        mock_result = Mock()
        mock_result.hypotheses = [HypObj()]
        mock_engine.analyze_output.return_value = mock_result

        with patch("elengenix.scanning.vuln_reasoning_phase._get_reasoning_engine", return_value=mock_engine):
            result = run_reasoning_phase(ctx, "output", "obs", step=1)

        assert len(result) == 1
        assert result[0]["type"] == "sqli"
        assert result[0]["title"] == "Test SQLi"

    def test_uses_ctx_target_when_target_not_provided(self):
        """Should use ctx.target when target param is empty."""
        ctx = Mock()
        ctx.target = "http://ctx-target.com"
        ctx.all_findings = []

        mock_engine = Mock()
        mock_result = Mock()
        mock_result.hypotheses = [{"vuln_class": "xss", "confidence": 0.7}]
        mock_engine.analyze_output.return_value = mock_result

        with patch("elengenix.scanning.vuln_reasoning_phase._get_reasoning_engine", return_value=mock_engine):
            result = run_reasoning_phase(ctx, "output", "obs", step=1, target="")

        # Should pass ctx.target to engine.analyze_output
        call_args = mock_engine.analyze_output.call_args
        assert call_args[1]["target"] == "http://ctx-target.com"

    def test_passes_previous_findings_from_context(self):
        """Should pass ctx.all_findings as previous_findings."""
        ctx = Mock()
        ctx.target = "http://test.com"
        ctx.all_findings = [{"vuln": "old_xss"}, {"vuln": "old_sqli"}]

        mock_engine = Mock()
        mock_result = Mock()
        mock_result.hypotheses = [{"vuln_class": "new", "confidence": 0.8}]
        mock_engine.analyze_output.return_value = mock_result

        with patch("elengenix.scanning.vuln_reasoning_phase._get_reasoning_engine", return_value=mock_engine):
            run_reasoning_phase(ctx, "output", "obs", step=1)

        call_args = mock_engine.analyze_output.call_args
        assert call_args[1]["previous_findings"] == [{"vuln": "old_xss"}, {"vuln": "old_sqli"}]

    def test_uses_provided_engine_parameter(self):
        """Should use provided engine instead of creating new one."""
        ctx = Mock()
        ctx.target = "http://test.com"
        ctx.all_findings = []

        provided_engine = Mock()
        provided_result = Mock()
        provided_result.hypotheses = [{"vuln_class": "provided", "confidence": 0.9}]
        provided_engine.analyze_output.return_value = provided_result

        with patch("elengenix.scanning.vuln_reasoning_phase._get_reasoning_engine") as mock_get:
            result = run_reasoning_phase(ctx, "output", "obs", step=1, engine=provided_engine)
            mock_get.assert_not_called()

        assert len(result) == 1
        assert result[0]["type"] == "provided"

    def test_uses_provided_client_for_engine_creation(self):
        """Should pass client to _get_reasoning_engine."""
        ctx = Mock()
        ctx.target = "http://test.com"
        ctx.all_findings = []

        mock_client = Mock()
        mock_engine = Mock()
        mock_result = Mock()
        mock_result.hypotheses = [{"vuln_class": "client_test", "confidence": 0.8}]
        mock_engine.analyze_output.return_value = mock_result

        with patch("elengenix.scanning.vuln_reasoning_phase._get_reasoning_engine", return_value=mock_engine) as mock_get:
            run_reasoning_phase(ctx, "output", "obs", step=1, client=mock_client)
            mock_get.assert_called_once_with(client=mock_client)

    def test_evidence_truncated_to_6000_chars(self):
        """Evidence should be truncated to 6000 characters."""
        ctx = Mock()
        ctx.target = "http://test.com"
        ctx.all_findings = []

        long_output = "x" * 10000

        mock_engine = Mock()
        mock_result = Mock()
        mock_result.hypotheses = [{"vuln_class": "test", "confidence": 0.8}]
        mock_engine.analyze_output.return_value = mock_result

        with patch("elengenix.scanning.vuln_reasoning_phase._get_reasoning_engine", return_value=mock_engine):
            run_reasoning_phase(ctx, long_output, "obs", step=1)

        call_args = mock_engine.analyze_output.call_args
        assert len(call_args[1]["tool_output"]) == 6000
        assert call_args[1]["tool_output"].endswith("x" * 6000)

    def test_logs_info_when_findings_produced(self, caplog):
        """Should log info when findings are produced."""
        ctx = Mock()
        ctx.target = "http://test.com"
        ctx.all_findings = []

        mock_engine = Mock()
        mock_result = Mock()
        mock_result.hypotheses = [
            {"vuln_class": "sqli", "confidence": 0.8},
            {"vuln_class": "xss", "confidence": 0.7},
        ]
        mock_engine.analyze_output.return_value = mock_result

        with patch("elengenix.scanning.vuln_reasoning_phase._get_reasoning_engine", return_value=mock_engine):
            with caplog.at_level("INFO"):
                run_reasoning_phase(ctx, "output", "obs", step=3)

        assert "reasoning phase produced 2 AI finding(s) at step 3" in caplog.text

    def test_step_recorded_on_findings(self):
        """Step number should be recorded on each finding."""
        ctx = Mock()
        ctx.target = "http://test.com"
        ctx.all_findings = []

        mock_engine = Mock()
        mock_result = Mock()
        mock_result.hypotheses = [
            {"vuln_class": "sqli", "confidence": 0.8},
            {"vuln_class": "xss", "confidence": 0.7},
        ]
        mock_engine.analyze_output.return_value = mock_result

        with patch("elengenix.scanning.vuln_reasoning_phase._get_reasoning_engine", return_value=mock_engine):
            result = run_reasoning_phase(ctx, "output", "obs", step=7)

        assert result[0]["discovered_at_step"] == 7
        assert result[1]["discovered_at_step"] == 7


class TestDefaultMinConfidence:
    """Test the DEFAULT_MIN_CONFIDENCE constant."""

    def test_default_value(self):
        assert DEFAULT_MIN_CONFIDENCE == 0.35


class TestGetReasoningEngine:
    """Tests for _get_reasoning_engine (internal function)."""

    def test_creates_engine_with_client(self):
        """Should create VulnReasoningEngine with provided client."""
        mock_client = Mock()

        with patch("tools.vuln_reasoning.VulnReasoningEngine") as mock_engine_class:
            mock_instance = Mock()
            mock_engine_class.return_value = mock_instance

            from elengenix.scanning.vuln_reasoning_phase import _get_reasoning_engine
            result = _get_reasoning_engine(client=mock_client)

            mock_engine_class.assert_called_once_with(client=mock_client)
            assert result == mock_instance

    def test_returns_none_on_import_error(self):
        """Should return None if VulnReasoningEngine cannot be imported."""
        with patch("tools.vuln_reasoning.VulnReasoningEngine", side_effect=ImportError("no module")):
            from elengenix.scanning.vuln_reasoning_phase import _get_reasoning_engine
            result = _get_reasoning_engine()
            assert result is None

    def test_returns_none_on_general_exception(self):
        """Should return None on any exception during engine creation."""
        with patch("tools.vuln_reasoning.VulnReasoningEngine", side_effect=Exception("fail")):
            from elengenix.scanning.vuln_reasoning_phase import _get_reasoning_engine
            result = _get_reasoning_engine()
            assert result is None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])