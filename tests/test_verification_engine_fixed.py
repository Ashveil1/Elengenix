"""Tests for VerificationEngine (sync API).

Tests use MagicMock to isolate consensus logic from actual AI calls.
"""

from __future__ import annotations

import pytest
from unittest.mock import MagicMock, patch
from tools.verification_engine import VerificationEngine, ModelVote, VerificationResult


class TestVerificationEngineFixed:
    """Tests for VerificationEngine with proper mocking"""

    @pytest.fixture
    def engine(self):
        engine = VerificationEngine()
        engine.models = [
            {"name": "default", "weight": 3.0, "role": "primary", "temperature": 0.1},
            {"name": "default", "weight": 2.0, "role": "conservative", "temperature": 0.05},
        ]
        engine.ai_client = MagicMock()
        engine.ai_client.chat.return_value = MagicMock(content="confirmed - real vulnerability")
        return engine

    @pytest.fixture
    def mock_finding(self):
        return {
            "type": "sqli",
            "severity": "high",
            "url": "http://example.com/login",
            "parameter": "username",
            "payload": "' OR '1'='1",
            "evidence": "SQL error in response",
            "description": "SQL injection in login form"
        }

    # ── _compute_consensus tests (unit-level, no AI calls) ────────────────

    def test_verify_both_confirm(self):
        """All perspectives confirm → finding is verified"""
        engine = VerificationEngine()
        finding = {"type": "XSS", "severity": "HIGH", "url": "http://test.com"}
        votes = [
            _vote("confirmed", confidence=0.9),
            _vote("confirmed", confidence=0.95),
        ]
        result = engine._compute_consensus(finding, votes)
        assert result.verified is True
        assert result.confidence > 0.5
        assert result.severity == "HIGH"

    def test_verify_one_confirm_one_deny(self):
        """Split perspectives → inconclusive → human review"""
        engine = VerificationEngine()
        finding = {"type": "SQLi", "severity": "MEDIUM", "url": "http://test.com"}
        votes = [
            _vote("confirmed", confidence=0.8),
            _vote("false_positive", confidence=0.7),
        ]
        result = engine._compute_consensus(finding, votes)
        assert result.verified is False
        assert result.consensus_verdict == "inconclusive"
        assert result.requires_human_review is True

    def test_verify_both_deny(self):
        """All perspectives deny → false positive"""
        engine = VerificationEngine()
        finding = {"type": "SSRF", "severity": "HIGH", "url": "http://test.com"}
        votes = [
            _vote("false_positive", confidence=0.8),
            _vote("false_positive", confidence=0.9),
        ]
        result = engine._compute_consensus(finding, votes)
        assert result.verified is False
        assert result.consensus_verdict == "false_positive"
        assert result.requires_human_review is False
        assert result.severity == "INFO"
        assert result.confidence > 0.5

    def test_verify_default_severity(self):
        """Missing severity in finding defaults to MEDIUM"""
        engine = VerificationEngine()
        finding = {"type": "IDOR"}
        votes = [
            _vote("confirmed", confidence=0.9),
            _vote("confirmed", confidence=0.95),
        ]
        result = engine._compute_consensus(finding, votes)
        assert result.verified is True
        assert result.severity == "MEDIUM"

    def test_consensus_weighted_majority(self):
        """Weighted votes: heavy confirm outweighs light deny"""
        engine = VerificationEngine()
        finding = {"type": "XSS", "severity": "LOW"}
        votes = [
            _vote("confirmed", confidence=0.9, weight=3.0),
            _vote("false_positive", confidence=0.9, weight=1.0),
        ]
        result = engine._compute_consensus(finding, votes)
        assert result.verified is True
        assert result.consensus_verdict == "confirmed"

    def test_fallback_verification_empty(self):
        """No votes → fallback returns VerificationResult (no crash)"""
        engine = VerificationEngine()
        finding = {"type": "XSS", "url": "http://test.com"}
        result = engine._compute_consensus(finding, [])
        assert isinstance(result, VerificationResult)

    # ── verify_with_consensus integration tests (mocked AI) ───────────────

    def test_verify_integration_both_confirm(self, engine, mock_finding):
        """verify_with_consensus returns confirmed when both perspectives confirm"""
        with patch.object(engine, '_query_perspective') as mock_query:
            mock_query.side_effect = [
                _vote("confirmed", confidence=0.9, weight=3.0),
                _vote("confirmed", confidence=0.85, weight=2.0),
            ]

            result = engine.verify_with_consensus(mock_finding)

            assert result.verified is True
            assert result.consensus_verdict == "confirmed"
            assert result.confidence > 0.8
            assert len(result.model_votes) == 2

    def test_verify_one_confirms_one_denies(self, engine, mock_finding):
        """When perspectives disagree, weighted majority determines outcome"""
        with patch.object(engine, '_query_perspective') as mock_query:
            mock_query.side_effect = [
                _vote("confirmed", confidence=0.9, weight=3.0),
                _vote("false_positive", confidence=0.8, weight=2.0),
            ]

            result = engine.verify_with_consensus(mock_finding)

            # With weights 3.0 (confirmed) vs 2.0 (false_positive), confirmed wins
            assert result.verified is True
            assert result.consensus_verdict == "confirmed"
            assert result.requires_human_review is False

    def test_integration_both_deny(self, engine, mock_finding):
        """When both perspectives deny, finding is false positive"""
        with patch.object(engine, '_query_perspective') as mock_query:
            mock_query.return_value = _vote("false_positive", confidence=0.8, weight=3.0)

            result = engine.verify_with_consensus(mock_finding)

            assert result.verified is False
            assert result.consensus_verdict == "false_positive"
            assert result.confidence > 0.5

    def test_verify_severity_adjustment(self, engine):
        """Severity adjustment via weighted majority"""
        finding = {
            "type": "xss",
            "severity": "HIGH",
            "url": "http://example.com/search",
            "parameter": "q",
            "payload": "<script>alert(1)</script>",
            "evidence": "Script reflected in response",
            "description": "Reflected XSS in search"
        }

        with patch.object(engine, '_query_perspective') as mock_query:
            mock_query.side_effect = [
                _vote("confirmed", confidence=0.9, weight=3.0),
                _vote("severity_adjustment", confidence=0.8, weight=2.0, severity_adj="MEDIUM"),
            ]

            result = engine.verify_with_consensus(finding)

            assert result.verified is True
            assert result.severity == "MEDIUM"
            assert result.confidence > 0.7

    def test_fallback_no_ai_client(self, engine):
        """No AI client → fallback → requires_human_review=True"""
        engine.ai_client = None
        finding = {"type": "xss", "severity": "HIGH", "url": "http://test.com"}

        result = engine.verify_with_consensus(finding)

        assert result.verified is False
        assert result.consensus_verdict == "insufficient_evidence"
        assert result.requires_human_review is True

    def test_all_perspectives_fail(self, engine):
        """All queries fail → fallback → requires_human_review=True"""
        with patch.object(engine, '_query_perspective') as mock_query:
            mock_query.side_effect = Exception("AI call failed")

            result = engine.verify_with_consensus({"type": "xss"})

            assert result.verified is False
            assert result.consensus_verdict == "insufficient_evidence"

    def test_severity_adjustment_weighted(self, engine):
        """Severity adjustment via weighted majority with multiple opinions"""
        finding = {
            "type": "xss",
            "severity": "HIGH",
            "url": "http://example.com/search",
            "parameter": "q",
            "payload": "<script>alert(1)</script>"
        }

        with patch.object(engine, '_query_perspective') as mock_query:
            mock_query.side_effect = [
                _vote("confirmed", confidence=0.9, weight=3.0),
                _vote("severity_adjustment", confidence=0.8, weight=2.0, severity_adj="MEDIUM"),
            ]

            result = engine.verify_with_consensus(finding)

            assert result.verified is True
            assert result.severity == "MEDIUM"
            assert result.confidence > 0.7


# ── Helper ──────────────────────────────────────────────────────────────────


def _vote(verdict, confidence=0.9, weight=1.0, severity_adj=None):
    """Helper to create a ModelVote."""
    return ModelVote(
        model_name="test",
        model_weight=weight,
        verdict=verdict,
        confidence=confidence,
        reasoning="test reasoning",
        severity_adjustment=severity_adj,
    )
