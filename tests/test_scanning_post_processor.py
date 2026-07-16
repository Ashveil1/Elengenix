"""Tests for elengenix/scanning/post_processor.py — PostExecutionProcessor."""
from __future__ import annotations

import json
import sys
import pytest
from unittest.mock import MagicMock, AsyncMock, patch, call

from elengenix.scanning.post_processor import (
    PostExecutionProcessor,
    _safe_operation,
    _get_verification_engine,
)


# ===================================================================
# _safe_operation (module-level helper)
# ===================================================================


class TestSafeOperation:
    def test_success(self):
        result = _safe_operation("test_op", lambda: 42)
        assert result == 42

    def test_exception_swallowed(self):
        def failing():
            raise ValueError("oops")
        result = _safe_operation("fail_op", failing)
        assert result is None

    def test_exception_with_default_not_supported(self):
        """The module-level _safe_operation does NOT accept a default kwarg
        (unlike the helpers.py variant). Just tests exception swallowing."""
        def failing():
            raise RuntimeError("boom")
        result = _safe_operation("fail_op", failing)
        assert result is None

    def test_none_function(self):
        result = _safe_operation("none_op", None)
        assert result is None

    def test_with_positional_args(self):
        result = _safe_operation("add", lambda x, y: x + y, 2, 3)
        assert result == 5

    def test_with_kwargs(self):
        result = _safe_operation("pow", lambda a, b=2: a**b, 3, b=3)
        assert result == 27


# ===================================================================
# _get_verification_engine
# ===================================================================


class TestGetVerificationEngine:
    def setup_method(self):
        # Reset the global singleton before each test
        import elengenix.scanning.post_processor as pp
        pp._verification_engine = None

    def test_returns_none_when_import_fails(self):
        """When tools.verification_engine import fails, returns None."""
        import builtins
        original_import = builtins.__import__

        def mock_import(name, *args, **kwargs):
            if name in ("tools.verification_engine", "tools.universal_ai_client"):
                raise ImportError(f"No module named {name}")
            return original_import(name, *args, **kwargs)

        with patch("builtins.__import__", side_effect=mock_import):
            engine = _get_verification_engine()
            assert engine is None

    @patch("tools.verification_engine.VerificationEngine")
    @patch("tools.universal_ai_client.AIClientManager")
    def test_successful_init(self, MockAIClientManager, MockVerificationEngine):
        mock_engine = MagicMock()
        MockVerificationEngine.return_value = mock_engine
        mock_ai_client = MagicMock()
        MockAIClientManager.return_value = mock_ai_client

        engine = _get_verification_engine()
        assert engine is mock_engine
        MockAIClientManager.assert_called_once()
        MockVerificationEngine.assert_called_once_with(ai_client=mock_ai_client)

    @patch("tools.verification_engine.VerificationEngine")
    @patch("tools.universal_ai_client.AIClientManager")
    def test_caches_singleton(self, MockAIClientManager, MockVerificationEngine):
        mock_engine = MagicMock()
        MockVerificationEngine.return_value = mock_engine
        MockAIClientManager.return_value = MagicMock()

        first = _get_verification_engine()
        second = _get_verification_engine()
        assert first is second is mock_engine
        # Only constructed once
        MockVerificationEngine.assert_called_once()


# ===================================================================
# PostExecutionProcessor — __init__
# ===================================================================


class TestPostExecutionProcessorInit:
    def test_defaults(self):
        p = PostExecutionProcessor()
        assert p.analysis_pipeline is None
        assert p.vuln_reasoning is None
        assert p.planner is None
        assert p.vuln_finder is None
        assert p.callback is None

    def test_with_all_deps(self):
        analysis_pipeline = MagicMock()
        vuln_reasoning = MagicMock()
        planner = MagicMock()
        vuln_finder = MagicMock()
        cb = MagicMock()
        p = PostExecutionProcessor(
            analysis_pipeline=analysis_pipeline,
            vuln_reasoning=vuln_reasoning,
            planner=planner,
            vuln_finder=vuln_finder,
            callback=cb,
        )
        assert p.analysis_pipeline is analysis_pipeline
        assert p.vuln_reasoning is vuln_reasoning
        assert p.planner is planner
        assert p.vuln_finder is vuln_finder
        assert p.callback is cb


# ===================================================================
# Fixtures for processor tests
# ===================================================================


@pytest.fixture
def mock_ctx():
    ctx = MagicMock()
    ctx.target = "http://test.local"
    ctx.mission_key = "scan-001"
    ctx.coverage_map = MagicMock()
    ctx.negative_results = MagicMock()
    ctx.belief_state = MagicMock()
    ctx.verification_pipeline = None  # default: use built-in
    ctx.mission_state = MagicMock()
    ctx.attack_tree = MagicMock()
    ctx.attack_tree.steps = [MagicMock() for _ in range(3)]
    ctx.has_findings = False
    ctx.all_findings = []
    ctx.add_result = MagicMock()
    ctx.add_finding = MagicMock()
    ctx.add_findings = MagicMock()
    ctx.append_history = MagicMock()
    return ctx


@pytest.fixture
def mock_result():
    r = MagicMock()
    r.findings = []
    r.output = ""
    r.error_message = None
    return r


@pytest.fixture
def callback():
    return MagicMock()


@pytest.fixture
def processor(callback):
    return PostExecutionProcessor(callback=callback)


# ===================================================================
# _verify_finding_new
# ===================================================================


class TestVerifyFindingNew:
    def _make_finding(self, **overrides):
        f = {"type": "xss", "severity": "high", "url": "http://test.local/login"}
        f.update(overrides)
        return f

    @pytest.fixture
    def ctx(self):
        c = MagicMock()
        c.coverage_map = MagicMock()
        c.belief_state = MagicMock()
        c.negative_results = MagicMock()
        return c

    # --- No engine available ---

    def test_no_engine_sets_unavailable(self, ctx):
        p = PostExecutionProcessor(callback=MagicMock())
        finding = self._make_finding()
        with patch(
            "elengenix.scanning.post_processor._get_verification_engine",
            return_value=None,
        ):
            result = p._verify_finding_new(ctx, finding, "/login", "xss", "nmap")

        assert result is True
        assert finding["verification"] == {
            "status": "unavailable",
            "reason": "verification_engine_not_initialized",
        }
        ctx.coverage_map.record_finding.assert_called_once_with("/login", "xss")

    def test_no_engine_no_coverage_map(self, ctx):
        ctx.coverage_map = None
        p = PostExecutionProcessor()
        finding = self._make_finding()
        with patch(
            "elengenix.scanning.post_processor._get_verification_engine",
            return_value=None,
        ):
            result = p._verify_finding_new(ctx, finding, "/login", "xss", "nmap")

        assert result is True
        assert finding["verification"]["status"] == "unavailable"
        # Should not crash when coverage_map is None

    # --- Engine returns verified finding ---

    def test_engine_verified(self, ctx):
        p = PostExecutionProcessor(callback=MagicMock())
        finding = self._make_finding()
        engine_result = MagicMock()
        engine_result.verified = True
        engine_result.consensus_verdict = "confirmed"
        engine_result.severity = "high"
        engine_result.confidence = 0.95
        engine_result.consensus_strength = "strong"
        engine_result.requires_human_review = False
        engine_result.model_votes = []

        engine = MagicMock()
        engine.verify_with_consensus.return_value = engine_result

        with patch(
            "elengenix.scanning.post_processor._get_verification_engine",
            return_value=engine,
        ):
            result = p._verify_finding_new(ctx, finding, "/login", "xss", "nmap")

        assert result is True
        assert finding["verification"]["verified"] is True
        assert finding["verification"]["consensus_verdict"] == "confirmed"
        ctx.coverage_map.record_finding.assert_called_once_with("/login", "xss")
        ctx.belief_state.add_belief.assert_called_once()

    def test_engine_verified_severity_adjustment(self, ctx):
        p = PostExecutionProcessor()
        finding = self._make_finding(severity="low")
        engine_result = MagicMock()
        engine_result.verified = True
        engine_result.consensus_verdict = "confirmed"
        engine_result.severity = "critical"
        engine_result.confidence = 0.9
        engine_result.consensus_strength = "strong"
        engine_result.requires_human_review = False
        engine_result.model_votes = []

        engine = MagicMock()
        engine.verify_with_consensus.return_value = engine_result

        with patch(
            "elengenix.scanning.post_processor._get_verification_engine",
            return_value=engine,
        ):
            result = p._verify_finding_new(ctx, finding, "/login", "xss", "nmap")

        assert result is True
        assert finding["severity"] == "critical"
        assert finding["severity_adjusted_by_verification"] is True

    def test_engine_verified_calls_callback(self):
        cb = MagicMock()
        p = PostExecutionProcessor(callback=cb)
        ctx = MagicMock()
        ctx.coverage_map = MagicMock()
        ctx.belief_state = MagicMock()
        finding = {"type": "sqli", "url": "/search", "evidence": "error"}

        engine_result = MagicMock()
        engine_result.verified = True
        engine_result.consensus_verdict = "confirmed"
        engine_result.severity = "critical"
        engine_result.confidence = 0.99
        engine_result.consensus_strength = "strong"
        engine_result.requires_human_review = False
        engine_result.model_votes = []

        engine = MagicMock()
        engine.verify_with_consensus.return_value = engine_result

        with patch(
            "elengenix.scanning.post_processor._get_verification_engine",
            return_value=engine,
        ):
            p._verify_finding_new(ctx, finding, "/search", "sqli", "sqlmap")

        cb.assert_called_once()
        assert "[VERIFIED]" in cb.call_args[0][0]
        assert "sqli" in cb.call_args[0][0]

    # --- Engine returns not verified ---

    def test_engine_not_verified(self, ctx):
        p = PostExecutionProcessor(callback=MagicMock())
        finding = self._make_finding()
        engine_result = MagicMock()
        engine_result.verified = False
        engine_result.consensus_verdict = "false_positive"
        engine_result.severity = "low"
        engine_result.confidence = 0.2
        engine_result.consensus_strength = "weak"
        engine_result.requires_human_review = False
        engine_result.model_votes = []

        engine = MagicMock()
        engine.verify_with_consensus.return_value = engine_result

        with patch(
            "elengenix.scanning.post_processor._get_verification_engine",
            return_value=engine,
        ):
            result = p._verify_finding_new(ctx, finding, "/login", "xss", "nmap")

        assert result is False
        ctx.coverage_map.record_negative.assert_called_once_with(
            "/login", "xss", reason="Verification failed: false_positive"
        )
        ctx.negative_results.record.assert_called_once()

    def test_engine_not_verified_no_negative_results(self, ctx):
        ctx.negative_results = None
        p = PostExecutionProcessor()
        finding = self._make_finding()
        engine_result = MagicMock()
        engine_result.verified = False
        engine_result.consensus_verdict = "false_positive"
        engine_result.severity = "low"
        engine_result.confidence = 0.2
        engine_result.consensus_strength = "weak"
        engine_result.requires_human_review = False
        engine_result.model_votes = []

        engine = MagicMock()
        engine.verify_with_consensus.return_value = engine_result

        with patch(
            "elengenix.scanning.post_processor._get_verification_engine",
            return_value=engine,
        ):
            result = p._verify_finding_new(ctx, finding, "/login", "xss", "nmap")

        assert result is False
        # Should not crash when negative_results is None

    def test_engine_not_verified_calls_callback(self):
        cb = MagicMock()
        p = PostExecutionProcessor(callback=cb)
        ctx = MagicMock()
        ctx.coverage_map = MagicMock()
        ctx.negative_results = MagicMock()
        finding = {"type": "rce", "url": "/exec"}

        engine_result = MagicMock()
        engine_result.verified = False
        engine_result.consensus_verdict = "false_positive"
        engine_result.severity = "info"
        engine_result.confidence = 0.1
        engine_result.consensus_strength = "none"
        engine_result.requires_human_review = False
        engine_result.model_votes = []

        engine = MagicMock()
        engine.verify_with_consensus.return_value = engine_result

        with patch(
            "elengenix.scanning.post_processor._get_verification_engine",
            return_value=engine,
        ):
            p._verify_finding_new(ctx, finding, "/exec", "rce", "dirsearch")

        cb.assert_called_once()
        assert "[DISCARDED]" in cb.call_args[0][0]

    # --- Engine raises exception ---

    def test_engine_exception_accepts_finding(self, ctx):
        p = PostExecutionProcessor()
        finding = self._make_finding()

        engine = MagicMock()
        engine.verify_with_consensus.side_effect = RuntimeError("API timeout")

        with patch(
            "elengenix.scanning.post_processor._get_verification_engine",
            return_value=engine,
        ):
            result = p._verify_finding_new(ctx, finding, "/login", "xss", "nmap")

        assert result is True
        assert finding["verification"]["status"] == "error"
        assert "API timeout" in finding["verification"]["reason"]
        ctx.coverage_map.record_finding.assert_called_once_with("/login", "xss")

    def test_engine_exception_no_coverage_map(self, ctx):
        ctx.coverage_map = None
        p = PostExecutionProcessor()
        finding = self._make_finding()

        engine = MagicMock()
        engine.verify_with_consensus.side_effect = RuntimeError("crash")

        with patch(
            "elengenix.scanning.post_processor._get_verification_engine",
            return_value=engine,
        ):
            result = p._verify_finding_new(ctx, finding, "/login", "xss", "nmap")

        assert result is True
        assert finding["verification"]["status"] == "error"

    # --- Model votes truncation ---

    def test_model_votes_reasoning_truncated(self, ctx):
        p = PostExecutionProcessor()
        finding = self._make_finding()
        long_reasoning = "x" * 500

        vote = MagicMock()
        vote.model_name = "gpt-4"
        vote.verdict = "confirmed"
        vote.confidence = 0.9
        vote.reasoning = long_reasoning
        vote.severity_adjustment = 0

        engine_result = MagicMock()
        engine_result.verified = True
        engine_result.consensus_verdict = "confirmed"
        engine_result.severity = "high"
        engine_result.confidence = 0.9
        engine_result.consensus_strength = "strong"
        engine_result.requires_human_review = False
        engine_result.model_votes = [vote]

        engine = MagicMock()
        engine.verify_with_consensus.return_value = engine_result

        with patch(
            "elengenix.scanning.post_processor._get_verification_engine",
            return_value=engine,
        ):
            p._verify_finding_new(ctx, finding, "/login", "xss", "nmap")

        stored_reasoning = finding["verification"]["model_votes"][0]["reasoning"]
        assert len(stored_reasoning) <= 200


# ===================================================================
# _verify_finding (dispatcher to pipeline or built-in)
# ===================================================================


class TestVerifyFinding:
    def _make_finding(self, **overrides):
        f = {"type": "xss", "severity": "high", "url": "http://test.local/login"}
        f.update(overrides)
        return f

    def test_with_verification_pipeline_actionable(self, mock_ctx, processor):
        mock_ctx.verification_pipeline = MagicMock()
        verdict = MagicMock()
        verdict.is_actionable.return_value = True
        verdict.confidence = 0.95
        verdict.status = "confirmed"
        verdict.to_dict.return_value = {"status": "confirmed"}
        mock_ctx.verification_pipeline.verify_finding.return_value = verdict

        finding = self._make_finding()
        result = processor._verify_finding(mock_ctx, finding, "/login", "xss", "nmap")

        assert result is True
        mock_ctx.verification_pipeline.verify_finding.assert_called_once_with(
            finding, target=mock_ctx.target, callback=processor.callback
        )
        mock_ctx.coverage_map.record_finding.assert_called_once_with("/login", "xss")
        mock_ctx.belief_state.add_belief.assert_called_once()

    def test_with_verification_pipeline_not_actionable(self, mock_ctx, processor):
        mock_ctx.verification_pipeline = MagicMock()
        verdict = MagicMock()
        verdict.is_actionable.return_value = False
        verdict.status = "false_positive"
        verdict.confidence = 0.1
        mock_ctx.verification_pipeline.verify_finding.return_value = verdict

        finding = self._make_finding()
        result = processor._verify_finding(mock_ctx, finding, "/login", "xss", "nmap")

        assert result is False
        mock_ctx.coverage_map.record_negative.assert_called_once()
        mock_ctx.negative_results.record.assert_called_once()

    def test_with_verification_pipeline_exception(self, mock_ctx, processor):
        mock_ctx.verification_pipeline = MagicMock()
        mock_ctx.verification_pipeline.verify_finding.side_effect = ValueError("bad")

        finding = self._make_finding()
        result = processor._verify_finding(mock_ctx, finding, "/login", "xss", "nmap")

        # On exception, accept the finding
        assert result is True
        mock_ctx.coverage_map.record_finding.assert_called_once_with("/login", "xss")

    def test_with_pipeline_calls_callback(self):
        cb = MagicMock()
        p = PostExecutionProcessor(callback=cb)
        ctx = MagicMock()
        ctx.target = "test"
        ctx.coverage_map = MagicMock()
        ctx.belief_state = MagicMock()
        ctx.negative_results = MagicMock()
        ctx.verification_pipeline = MagicMock()
        verdict = MagicMock()
        verdict.is_actionable.return_value = True
        verdict.confidence = 0.9
        verdict.status = "confirmed"
        verdict.to_dict.return_value = {}
        ctx.verification_pipeline.verify_finding.return_value = verdict

        finding = {"type": "xss"}
        result = p._verify_finding(ctx, finding, "/login", "xss", "nmap")

        assert result is True
        cb.assert_called_once()
        assert "[VERIFIED]" in cb.call_args[0][0]

    def test_with_pipeline_discarded_calls_callback(self):
        cb = MagicMock()
        p = PostExecutionProcessor(callback=cb)
        ctx = MagicMock()
        ctx.target = "test"
        ctx.coverage_map = MagicMock()
        ctx.negative_results = MagicMock()
        ctx.verification_pipeline = MagicMock()
        verdict = MagicMock()
        verdict.is_actionable.return_value = False
        verdict.status = "false_positive"
        verdict.confidence = 0.1
        ctx.verification_pipeline.verify_finding.return_value = verdict

        finding = {"type": "xss"}
        result = p._verify_finding(ctx, finding, "/login", "xss", "nmap")

        assert result is False
        cb.assert_called_once()
        assert "[DISCARDED]" in cb.call_args[0][0]

    def test_without_pipeline_falls_back(self, mock_ctx, processor):
        """When ctx.verification_pipeline is None, should use built-in engine."""
        mock_ctx.verification_pipeline = None

        with patch.object(
            processor, "_verify_finding_new", return_value=True
        ) as mock_new:
            finding = self._make_finding()
            result = processor._verify_finding(mock_ctx, finding, "/login", "xss", "nmap")

        assert result is True
        mock_new.assert_called_once_with(mock_ctx, finding, "/login", "xss", "nmap")


# ===================================================================
# _process_coverage_and_verification
# ===================================================================


class TestProcessCoverageAndVerification:
    def test_no_findings_records_negative(self, mock_ctx, mock_result, processor):
        mock_result.findings = []
        mock_result.output = ""
        action_data = {"command": "nmap -p 80 target", "purpose": "port_scan"}

        result = processor._process_coverage_and_verification(
            mock_ctx, mock_result, "nmap", action_data
        )

        assert result == []
        mock_ctx.coverage_map.register_endpoint.assert_called()
        mock_ctx.coverage_map.record_test.assert_called()
        mock_ctx.negative_results.record.assert_called_once()

    def test_no_findings_no_negative_results(self, mock_ctx, mock_result, processor):
        mock_ctx.negative_results = None
        mock_result.findings = []
        action_data = {"command": "scan", "purpose": "recon"}

        # Should not crash
        result = processor._process_coverage_and_verification(
            mock_ctx, mock_result, "tool", action_data
        )
        assert result == []

    def test_no_coverage_map(self, mock_ctx, mock_result, processor):
        mock_ctx.coverage_map = None
        mock_result.findings = []
        action_data = {"command": "scan", "purpose": "recon"}

        result = processor._process_coverage_and_verification(
            mock_ctx, mock_result, "tool", action_data
        )
        assert result == []

    def test_with_findings_all_verified(self, mock_ctx, mock_result, processor):
        finding1 = {"type": "xss", "url": "http://test.local/login"}
        finding2 = {"type": "sqli", "url": "http://test.local/search"}
        mock_result.findings = [finding1, finding2]
        action_data = {"command": "scan", "purpose": "recon"}

        with patch.object(processor, "_verify_finding", return_value=True):
            result = processor._process_coverage_and_verification(
                mock_ctx, mock_result, "tool", action_data
            )

        assert len(result) == 2
        # findings should be replaced with verified ones
        assert len(mock_result.findings) == 2
        mock_ctx.add_findings.assert_called_once_with([finding1, finding2])

    def test_with_findings_some_filtered(self, mock_ctx, mock_result, processor):
        finding1 = {"type": "xss", "url": "http://test.local/login"}
        finding2 = {"type": "sqli", "url": "http://test.local/search"}
        mock_result.findings = [finding1, finding2]
        action_data = {"command": "scan", "purpose": "recon"}

        with patch.object(
            processor, "_verify_finding", side_effect=[True, False]
        ):
            result = processor._process_coverage_and_verification(
                mock_ctx, mock_result, "tool", action_data
            )

        assert len(result) == 1
        assert result[0] is finding1
        assert len(mock_result.findings) == 1
        assert mock_result.findings[0] is finding1

    def test_filter_callback_invoked(self):
        cb = MagicMock()
        p = PostExecutionProcessor(callback=cb)
        ctx = MagicMock()
        ctx.coverage_map = MagicMock()
        ctx.negative_results = MagicMock()
        result = MagicMock()
        result.findings = [{"type": "xss"}, {"type": "sqli"}]
        result.output = ""

        with patch.object(p, "_verify_finding", side_effect=[True, False]):
            p._process_coverage_and_verification(ctx, result, "tool", {"command": "cmd"})

        cb.assert_called_once()
        assert "Filtered" in cb.call_args[0][0]
        assert "1" in cb.call_args[0][0]

    def test_extracts_urls_from_output(self, mock_ctx, mock_result, processor):
        mock_result.findings = []
        mock_result.output = (
            "Found endpoint https://test.local/admin and http://api.example.com/data"
        )
        action_data = {"command": "scan", "purpose": "recon"}

        processor._process_coverage_and_verification(
            mock_ctx, mock_result, "tool", action_data
        )

        # Both URLs should be registered
        calls = mock_ctx.coverage_map.register_endpoint.call_args_list
        urls = [c[0][0] for c in calls]
        assert "https://test.local/admin" in urls
        assert "http://api.example.com/data" in urls

    def test_finding_endpoint_fallback(self, mock_ctx, mock_result, processor):
        """Finding without url/endpoint/host should fall back to action_data command."""
        mock_result.findings = [{"type": "xss"}]  # no url, endpoint, host
        action_data = {"command": "my-scan-tool", "purpose": "recon"}

        with patch.object(processor, "_verify_finding", return_value=True) as mock_vf:
            processor._process_coverage_and_verification(
                mock_ctx, mock_result, "tool", action_data
            )

        # The endpoint should fall back to the command
        call_args = mock_vf.call_args[0]
        # _verify_finding(ctx, finding, f_endpoint, f_class, tool_name)
        assert "my-scan-tool" in call_args[2]

    def test_vuln_class_defaults(self, mock_ctx, mock_result, processor):
        """Finding without type/vuln_class should default to 'unknown'."""
        mock_result.findings = [{"url": "http://test.local/page"}]
        action_data = {"command": "scan", "purpose": "recon"}

        with patch.object(processor, "_verify_finding", return_value=True) as mock_vf:
            processor._process_coverage_and_verification(
                mock_ctx, mock_result, "tool", action_data
            )

        call_args = mock_vf.call_args[0]
        assert call_args[3] == "unknown"

    def test_no_coverage_map_no_url_extraction(self, mock_ctx, mock_result, processor):
        mock_ctx.coverage_map = None
        mock_result.findings = [{"type": "xss", "url": "/login"}]
        mock_result.output = "http://extra.com"
        action_data = {"command": "scan", "purpose": "recon"}

        # Should not crash
        with patch.object(processor, "_verify_finding", return_value=True):
            result = processor._process_coverage_and_verification(
                mock_ctx, mock_result, "tool", action_data
            )
        assert len(result) == 1


# ===================================================================
# _process_escalation_and_chaining
# ===================================================================


class TestProcessEscalationAndChaining:
    def test_no_verified_findings_returns_early(self, mock_ctx, processor):
        # Should not crash
        processor._process_escalation_and_chaining(mock_ctx, [])

    def test_no_vuln_finder_returns_early(self, mock_ctx, processor):
        processor._process_escalation_and_chaining(
            mock_ctx, [{"type": "xss", "severity": "medium"}]
        )
        # No crash

    def test_escalation_low_severity(self, mock_ctx):
        vuln_finder = MagicMock()
        vuln_finder.escalation = MagicMock()
        vuln_finder.escalation.can_escalate.return_value = MagicMock(
            next_steps=["try exploit X"]
        )
        vuln_finder.chaining = None
        p = PostExecutionProcessor(vuln_finder=vuln_finder)

        p._process_escalation_and_chaining(
            mock_ctx,
            [{"type": "xss", "severity": "low", "url": "/login"}],
        )
        vuln_finder.escalation.can_escalate.assert_called_once()
        vuln_finder.add_finding.assert_called_once()

    def test_escalation_high_severity_skipped(self, mock_ctx):
        vuln_finder = MagicMock()
        vuln_finder.escalation = MagicMock()
        p = PostExecutionProcessor(vuln_finder=vuln_finder)

        p._process_escalation_and_chaining(
            mock_ctx,
            [{"type": "xss", "severity": "high", "url": "/login"}],
        )
        vuln_finder.escalation.can_escalate.assert_not_called()

    def test_escalation_exception_swallowed(self, mock_ctx):
        vuln_finder = MagicMock()
        vuln_finder.escalation = MagicMock()
        vuln_finder.escalation.can_escalate.side_effect = RuntimeError("crash")
        p = PostExecutionProcessor(vuln_finder=vuln_finder)

        # Should not raise
        p._process_escalation_and_chaining(
            mock_ctx,
            [{"type": "xss", "severity": "low", "url": "/login"}],
        )

    def test_chaining(self, mock_ctx):
        vuln_finder = MagicMock()
        vuln_finder.escalation = None
        vuln_finder.chaining = MagicMock()
        mock_ctx.has_findings = True
        mock_ctx.all_findings = [
            {"type": "xss", "url": "/a"},
            {"type": "sqli", "url": "/b"},
        ]

        chainable = [(
            {"type": "xss", "url": "/a"},
            {"type": "sqli", "url": "/b"},
        )]
        vuln_finder.chaining.find_chainable_findings.return_value = chainable

        chain = MagicMock()
        chain.chain_type = "sqli_plus_xss"
        chain.combined_severity = "critical"
        chain.impact_description = "SQLi + XSS allows RCE"
        vuln_finder.chaining.analyze_chain.return_value = chain

        p = PostExecutionProcessor(vuln_finder=vuln_finder, callback=MagicMock())

        p._process_escalation_and_chaining(
            mock_ctx, [{"type": "xss", "url": "/a"}]
        )

        mock_ctx.add_finding.assert_called_once()
        vuln_finder.add_finding.assert_called()

    def test_chaining_no_chain_returned(self, mock_ctx):
        vuln_finder = MagicMock()
        vuln_finder.escalation = None
        vuln_finder.chaining = MagicMock()
        mock_ctx.has_findings = True
        mock_ctx.all_findings = [{"type": "xss", "url": "/a"}]

        chainable = [({"type": "xss"}, {"type": "sqli"})]
        vuln_finder.chaining.find_chainable_findings.return_value = chainable
        vuln_finder.chaining.analyze_chain.return_value = None  # no chain formed

        p = PostExecutionProcessor(vuln_finder=vuln_finder)
        p._process_escalation_and_chaining(
            mock_ctx, [{"type": "xss", "url": "/a"}]
        )
        # Should not crash, no add_finding for chained result
        mock_ctx.add_finding.assert_not_called()

    def test_chaining_exception_swallowed(self, mock_ctx):
        vuln_finder = MagicMock()
        vuln_finder.escalation = None
        vuln_finder.chaining = MagicMock()
        vuln_finder.chaining.find_chainable_findings.side_effect = RuntimeError("boom")
        mock_ctx.has_findings = True

        p = PostExecutionProcessor(vuln_finder=vuln_finder)
        # Should not raise
        p._process_escalation_and_chaining(
            mock_ctx, [{"type": "xss", "url": "/a"}]
        )

    def test_chaining_callback(self, mock_ctx):
        cb = MagicMock()
        vuln_finder = MagicMock()
        vuln_finder.escalation = None
        vuln_finder.chaining = MagicMock()
        mock_ctx.has_findings = True
        mock_ctx.all_findings = [{"type": "xss"}, {"type": "sqli"}]

        chainable = [({"type": "xss"}, {"type": "sqli"})]
        vuln_finder.chaining.find_chainable_findings.return_value = chainable
        chain = MagicMock()
        chain.chain_type = "sqli_plus_xss"
        chain.combined_severity = "critical"
        chain.impact_description = "impact"
        vuln_finder.chaining.analyze_chain.return_value = chain

        p = PostExecutionProcessor(vuln_finder=vuln_finder, callback=cb)
        p._process_escalation_and_chaining(
            mock_ctx, [{"type": "xss"}]
        )
        cb.assert_called_once()
        assert "Chained findings" in cb.call_args[0][0]


# ===================================================================
# _process_mission_state
# ===================================================================


class TestProcessMissionState:
    def test_no_mission_state_returns_early(self, mock_ctx, mock_result, processor):
        mock_ctx.mission_state = None
        # Should not crash
        processor._process_mission_state(mock_ctx, mock_result, "nmap", 0)

    def test_mission_state_import_error(self, mock_ctx, mock_result, processor):
        """When GraphNode/GraphEdge import fails, the method catches the ImportError."""
        def mock_import(name, *args, **kwargs):
            if name == "tools.mission_state":
                raise ImportError(f"No module named {name}")
            # Use the real import otherwise
            return __import__(name, *args, **kwargs)

        with patch("builtins.__import__", side_effect=mock_import):
            # Should not raise
            processor._process_mission_state(mock_ctx, mock_result, "nmap", 0)

    def test_with_findings(self, mock_ctx, mock_result, processor):
        mock_result.findings = [
            {"type": "xss", "url": "http://test.local/login", "severity": "high"},
        ]
        mock_ctx.target = "http://test.local"

        processor._process_mission_state(mock_ctx, mock_result, "nmap", 1)

        # Should have called upsert_node, upsert_edge, add_fact
        assert mock_ctx.mission_state.upsert_node.call_count == 1
        assert mock_ctx.mission_state.upsert_edge.call_count == 1
        assert mock_ctx.mission_state.add_fact.call_count == 1

        # Check node props
        node_call = mock_ctx.mission_state.upsert_node.call_args[0][0]
        assert node_call.node_type == "finding"
        assert node_call.props["type"] == "xss"
        assert node_call.props["severity"] == "high"
        assert node_call.props["tool"] == "nmap"

        # Check edge props
        edge_call = mock_ctx.mission_state.upsert_edge.call_args[0][0]
        assert edge_call.src_id == "http://test.local"
        assert edge_call.edge_type == "has_finding"

    def test_with_multiple_findings(self, mock_ctx, mock_result, processor):
        mock_result.findings = [
            {"type": "xss", "url": "/login", "severity": "high"},
            {"type": "sqli", "url": "/search", "severity": "critical"},
        ]
        mock_ctx.target = "target"

        processor._process_mission_state(mock_ctx, mock_result, "sqlmap", 2)

        assert mock_ctx.mission_state.upsert_node.call_count == 2
        assert mock_ctx.mission_state.upsert_edge.call_count == 2
        assert mock_ctx.mission_state.add_fact.call_count == 2

    def test_finding_without_url_uses_fallback(self, mock_ctx, mock_result, processor):
        mock_result.findings = [
            {"type": "xss", "severity": "medium"},  # no url/subdomain/host
        ]

        processor._process_mission_state(mock_ctx, mock_result, "nmap", 0)

        node_call = mock_ctx.mission_state.upsert_node.call_args[0][0]
        # node_id should be the fallback pattern
        assert node_call.node_id.startswith("finding:nmap:0:0")

    def test_mission_state_upsert_exception_swallowed(self, mock_ctx, mock_result, processor):
        mock_result.findings = [{"type": "xss", "url": "/login"}]
        mock_ctx.mission_state.upsert_node.side_effect = RuntimeError("graph error")

        # Should not raise — _safe_operation swallows
        processor._process_mission_state(mock_ctx, mock_result, "nmap", 0)


# ===================================================================
# _process_analysis
# ===================================================================


class TestProcessAnalysis:
    def test_analysis_pipeline_called(self, mock_ctx, mock_result, processor):
        pipeline = MagicMock()
        processor.analysis_pipeline = pipeline

        processor._process_analysis(mock_ctx, mock_result, "nmap", 1)

        pipeline.run_all.assert_called_once_with(
            result=mock_result,
            tool_name="nmap",
            target=mock_ctx.target,
            step=1,
            mission_key=mock_ctx.mission_key,
            mission_state=mock_ctx.mission_state,
            callback=processor.callback,
        )

    def test_analysis_pipeline_exception_swallowed(self, mock_ctx, mock_result, processor):
        pipeline = MagicMock()
        pipeline.run_all.side_effect = RuntimeError("pipeline crash")
        processor.analysis_pipeline = pipeline

        # Should not raise
        processor._process_analysis(mock_ctx, mock_result, "nmap", 1)

    def test_vuln_reasoning_called(self, mock_ctx, mock_result, processor):
        mock_result.findings = [{"type": "xss"}]
        mock_result.error_message = None
        reasoning = MagicMock()
        analysis = MagicMock()
        analysis.hypotheses = []
        reasoning.analyze_output.return_value = analysis
        processor.vuln_reasoning = reasoning

        processor._process_analysis(mock_ctx, mock_result, "nmap", 1)

        reasoning.analyze_output.assert_called_once()
        call_args = reasoning.analyze_output.call_args[1]
        assert call_args["target"] == mock_ctx.target
        assert call_args["tool_name"] == "nmap"
        assert json.loads(call_args["tool_output"]) == {
            "findings": mock_result.findings,
            "error": None,
        }

    def test_vuln_reasoning_with_hypotheses(self, mock_ctx, mock_result):
        cb = MagicMock()
        p = PostExecutionProcessor(vuln_reasoning=MagicMock(), callback=cb)

        mock_result.findings = [{"type": "xss"}]
        analysis = MagicMock()

        hyp1 = MagicMock()
        hyp1.title = "XSS via params"
        hyp1.vuln_class = "xss"
        hyp1.confidence = 0.85
        hyp1.reasoning = "Found unescaped input"

        hyp2 = MagicMock()
        hyp2.title = "SQLi via query"
        hyp2.vuln_class = "sqli"
        hyp2.confidence = 0.72
        hyp2.reasoning = "Error-based detection"

        analysis.hypotheses = [hyp1, hyp2]
        analysis.coverage_gaps = []
        p.vuln_reasoning.analyze_output.return_value = analysis

        p._process_analysis(mock_ctx, mock_result, "nmap", 1)

        # Callback should be called with top hypothesis
        cb.assert_called()
        # History should be appended
        mock_ctx.append_history.assert_called()

    def test_vuln_reasoning_with_coverage_gaps(self, mock_ctx, mock_result):
        p = PostExecutionProcessor(vuln_reasoning=MagicMock())

        mock_result.findings = [{"type": "xss"}]
        analysis = MagicMock()
        hyp = MagicMock()
        hyp.title = "test"
        hyp.vuln_class = "xss"
        hyp.confidence = 0.5
        hyp.reasoning = "test"
        analysis.hypotheses = [hyp]
        analysis.coverage_gaps = ["Missing /api endpoint", "Missing /admin/page"]
        p.vuln_reasoning.analyze_output.return_value = analysis

        p._process_analysis(mock_ctx, mock_result, "nmap", 1)

        # Should have appended coverage gaps as user message
        history_calls = mock_ctx.append_history.call_args_list
        user_calls = [c for c in history_calls if c[0][0] == "user"]
        assert len(user_calls) >= 1
        assert "Coverage gaps" in user_calls[-1][0][1]

    def test_vuln_reasoning_no_hypotheses_skipped(self, mock_ctx, mock_result, processor):
        mock_result.findings = [{"type": "xss"}]
        reasoning = MagicMock()
        analysis = MagicMock()
        analysis.hypotheses = []  # empty
        reasoning.analyze_output.return_value = analysis
        processor.vuln_reasoning = reasoning

        # Should not crash, no callback for hypotheses
        processor._process_analysis(mock_ctx, mock_result, "nmap", 1)

    def test_vuln_reasoning_none_findings(self, mock_ctx, mock_result, processor):
        mock_result.findings = None
        reasoning = MagicMock()
        processor.vuln_reasoning = reasoning

        processor._process_analysis(mock_ctx, mock_result, "nmap", 1)
        # Should skip because result.findings is None
        reasoning.analyze_output.assert_not_called()

    def test_vuln_reasoning_exception_swallowed(self, mock_ctx, mock_result, processor):
        mock_result.findings = [{"type": "xss"}]
        reasoning = MagicMock()
        reasoning.analyze_output.side_effect = RuntimeError("reasoning failed")
        processor.vuln_reasoning = reasoning

        # Should not raise
        processor._process_analysis(mock_ctx, mock_result, "nmap", 1)

    def test_no_pipeline_no_reasoning(self, mock_ctx, mock_result, processor):
        """Without analysis_pipeline or vuln_reasoning, should be a no-op."""
        processor.analysis_pipeline = None
        processor.vuln_reasoning = None
        # Should not crash
        processor._process_analysis(mock_ctx, mock_result, "nmap", 1)


# ===================================================================
# _process_strategy
# ===================================================================


class TestProcessStrategy:
    def test_marks_attack_tree_step(self, mock_ctx, mock_result, processor):
        mock_result.findings = []
        processor._process_strategy(mock_ctx, mock_result, "nmap", 0)

        assert mock_ctx.attack_tree.steps[0].completed is True
        assert mock_ctx.attack_tree.steps[0].result is mock_result
        assert mock_ctx.attack_tree.steps[0].findings is mock_result.findings

    def test_step_out_of_bounds_skipped(self, mock_ctx, mock_result, processor):
        processor._process_strategy(mock_ctx, mock_result, "nmap", 999)
        # Should not crash

    def test_no_attack_tree(self, mock_ctx, mock_result, processor):
        mock_ctx.attack_tree = None
        processor._process_strategy(mock_ctx, mock_result, "nmap", 0)
        # Should not crash

    def test_adaptive_strategy_with_findings(self, mock_ctx, mock_result):
        planner = MagicMock()
        new_steps = [MagicMock(), MagicMock()]
        planner.adapt_strategy.return_value = new_steps
        cb = MagicMock()
        p = PostExecutionProcessor(planner=planner, callback=cb)

        mock_result.findings = [{"type": "xss", "severity": "high"}]
        p._process_strategy(mock_ctx, mock_result, "nmap", 0)

        planner.adapt_strategy.assert_called_once_with(
            mock_ctx.attack_tree, mock_result.findings[0]
        )
        cb.assert_called_once()
        assert "Adapted strategy" in cb.call_args[0][0]

    def test_adaptive_strategy_no_findings(self, mock_ctx, mock_result, processor):
        mock_result.findings = []
        processor.planner = MagicMock()

        processor._process_strategy(mock_ctx, mock_result, "nmap", 0)

        processor.planner.adapt_strategy.assert_not_called()

    def test_adaptive_strategy_no_planner(self, mock_ctx, mock_result, processor):
        processor.planner = None
        mock_result.findings = [{"type": "xss"}]

        processor._process_strategy(mock_ctx, mock_result, "nmap", 0)
        # Should not crash

    def test_adaptive_strategy_exception_swallowed(self, mock_ctx, mock_result):
        planner = MagicMock()
        planner.adapt_strategy.side_effect = RuntimeError("plan crash")
        p = PostExecutionProcessor(planner=planner)

        mock_result.findings = [{"type": "xss"}]
        # Should not raise
        p._process_strategy(mock_ctx, mock_result, "nmap", 0)

    @patch("tools.vector_memory.remember")
    def test_adaptive_strategy_remembers(self, mock_remember, mock_ctx, mock_result):
        planner = MagicMock()
        planner.adapt_strategy.return_value = [MagicMock()]
        p = PostExecutionProcessor(planner=planner, callback=MagicMock())

        mock_result.findings = [{"type": "xss"}]
        p._process_strategy(mock_ctx, mock_result, "nmap", 0)

        mock_remember.assert_called_once()
        assert "Strategy adapted" in mock_remember.call_args[0][0]

    def test_adaptive_strategy_remember_exception_swallowed(
        self, mock_ctx, mock_result
    ):
        """If the internal remember() call fails, it must not propagate."""
        planner = MagicMock()
        planner.adapt_strategy.return_value = [MagicMock()]

        # Patch at the actual import target: tools.vector_memory.remember
        with patch("tools.vector_memory.remember", side_effect=RuntimeError("mem fail")):
            p = PostExecutionProcessor(planner=planner)
            mock_result.findings = [{"type": "xss"}]
            # Should not raise
            p._process_strategy(mock_ctx, mock_result, "nmap", 0)

    def test_adaptive_strategy_no_new_steps(self, mock_ctx, mock_result):
        planner = MagicMock()
        planner.adapt_strategy.return_value = []  # empty
        cb = MagicMock()
        p = PostExecutionProcessor(planner=planner, callback=cb)

        mock_result.findings = [{"type": "xss"}]
        p._process_strategy(mock_ctx, mock_result, "nmap", 0)

        # Callback should NOT be called when no new steps
        cb.assert_not_called()


# ===================================================================
# process (main async entry point)
# ===================================================================


class TestProcess:
    @pytest.mark.asyncio
    async def test_none_result_returns_early(self, mock_ctx, processor):
        await processor.process(mock_ctx, None, "nmap", {}, 0)
        mock_ctx.add_result.assert_not_called()

    @pytest.mark.asyncio
    async def test_orchestrates_all_steps(self):
        """process() should call all sub-processors in order."""
        p = PostExecutionProcessor(callback=MagicMock())
        ctx = MagicMock()
        ctx.coverage_map = MagicMock()
        ctx.negative_results = MagicMock()
        ctx.attack_tree = MagicMock()
        ctx.attack_tree.steps = [MagicMock()]
        result = MagicMock()
        result.findings = []

        with (
            patch.object(p, "_process_coverage_and_verification", return_value=[]) as mock_cov,
            patch.object(p, "_process_escalation_and_chaining") as mock_esc,
            patch.object(p, "_process_mission_state") as mock_ms,
            patch.object(p, "_process_analysis") as mock_an,
            patch.object(p, "_process_strategy") as mock_strat,
        ):
            await p.process(ctx, result, "nmap", {"command": "cmd"}, 1)

        ctx.add_result.assert_called_once_with(result)
        mock_cov.assert_called_once_with(ctx, result, "nmap", {"command": "cmd"})
        mock_esc.assert_called_once_with(ctx, [])
        mock_ms.assert_called_once_with(ctx, result, "nmap", 1)
        mock_an.assert_called_once_with(ctx, result, "nmap", 1)
        mock_strat.assert_called_once_with(ctx, result, "nmap", 1)

    @pytest.mark.asyncio
    async def test_orchestration_order(self, mock_ctx, mock_result, processor):
        """Verify the call order is preserved."""
        call_tracker = []

        with (
            patch.object(
                processor, "_process_coverage_and_verification",
                side_effect=lambda *a, **kw: call_tracker.append("coverage") or [],
            ),
            patch.object(
                processor, "_process_escalation_and_chaining",
                side_effect=lambda *a, **kw: call_tracker.append("escalation"),
            ),
            patch.object(
                processor, "_process_mission_state",
                side_effect=lambda *a, **kw: call_tracker.append("mission_state"),
            ),
            patch.object(
                processor, "_process_analysis",
                side_effect=lambda *a, **kw: call_tracker.append("analysis"),
            ),
            patch.object(
                processor, "_process_strategy",
                side_effect=lambda *a, **kw: call_tracker.append("strategy"),
            ),
        ):
            await processor.process(
                mock_ctx, mock_result, "nmap", {"command": "cmd"}, 1
            )

        assert call_tracker == [
            "coverage",
            "escalation",
            "mission_state",
            "analysis",
            "strategy",
        ]
