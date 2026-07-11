"""Tests for VerificationEngine - Fixed version with proper mocking"""

from __future__ import annotations

import pytest
from unittest.mock import MagicMock, AsyncMock, patch, AsyncMock
from tools.verification_engine import VerificationEngine, ModelVote, VerificationResult


class TestVerificationEngineFixed:
    """Tests for VerificationEngine with proper mocking"""

    @pytest.fixture
    def engine(self):
        engine = VerificationEngine()
        # Create a mock AI client
        engine.ai_client = MagicMock()
        engine.ai_client.chat = AsyncMock()
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

    @pytest.fixture
    def mock_votes_confirm(self):
        """Model votes that confirm the finding"""
        from tools.verification_engine import ModelVote
        return [
            ModelVote(
                model_name="claude-opus-4-8",
                model_weight=3.0,
                verdict="confirmed",
                confidence=0.9,
                reasoning="Clear SQL error",
                severity_adjustment=None
            ),
            ModelVote(
                model_name="claude-sonnet-5",
                model_weight=2.0,
                verdict="confirmed",
                confidence=0.85,
                reasoning="Clear SQL error",
                severity_adjustment=None
            )
        ]

    @pytest.fixture
    def mock_votes_disagree(self):
        """One confirms, one denies"""
        from tools.verification_engine import ModelVote
        return [
            ModelVote(
                model_name="claude-opus-4-8",
                model_weight=3.0,
                verdict="confirmed",
                confidence=0.9,
                reasoning="Clear SQL error",
                severity_adjustment=None
            ),
            ModelVote(
                model_name="claude-sonnet-5",
                model_weight=2.0,
                verdict="false_positive",
                confidence=0.8,
                reasoning="WAF blocked",
                severity_adjustment=None
            )
        ]

    @pytest.fixture
    def mock_votes_deny(self):
        """Both models deny"""
        from tools.verification_engine import ModelVote
        return [
            ModelVote(
                model_name="claude-opus-4-8",
                model_weight=3.0,
                verdict="false_positive",
                confidence=0.8,
                reasoning="WAF blocked",
                severity_adjustment=None
            ),
            ModelVote(
                model_name="claude-sonnet-5",
                model_weight=2.0,
                verdict="false_positive",
                confidence=0.8,
                reasoning="WAF blocked",
                severity_adjustment=None
            )
        ]

    @pytest.fixture
    def mock_votes_severity_adjust(self):
        """Votes with severity adjustment"""
        from tools.verification_engine import ModelVote
        return [
            ModelVote(
                model_name="claude-opus-4-8",
                model_weight=3.0,
                verdict="confirmed",
                confidence=0.9,
                reasoning="Script reflected",
                severity_adjustment=None
            ),
            ModelVote(
                model_name="claude-sonnet-5",
                model_weight=2.0,
                verdict="severity_adjustment",
                confidence=0.8,
                reasoning="Only self-XSS",
                severity_adjustment="MEDIUM"
            )
        ]

    @pytest.fixture
    def engine(self):
        engine = VerificationEngine()
        # Create a mock AI client
        engine.ai_client = MagicMock()
        engine.ai_client.chat = AsyncMock()
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

    @pytest.fixture
    def mock_votes_confirm(self):
        from tools.verification_engine import ModelVote
        return [
            ModelVote(
                model_name="claude-opus-4-8",
                model_weight=3.0,
                verdict="confirmed",
                confidence=0.9,
                reasoning="Clear SQL error",
                severity_adjustment=None
            ),
            ModelVote(
                model_name="claude-sonnet-5",
                model_weight=2.0,
                verdict="confirmed",
                confidence=0.85,
                reasoning="Clear SQL error",
                severity_adjustment=None
            )
        ]

    @pytest.fixture
    def mock_votes_disagree(self):
        """One confirms, one denies"""
        from tools.verification_engine import ModelVote
        return [
            ModelVote(
                model_name="claude-opus-4-8",
                model_weight=3.0,
                verdict="confirmed",
                confidence=0.9,
                reasoning="Clear SQL error",
                severity_adjustment=None
            ),
            ModelVote(
                model_name="claude-sonnet-5",
                model_weight=2.0,
                verdict="false_positive",
                confidence=0.8,
                reasoning="WAF blocked",
                severity_adjustment=None
            )
        ]

    @pytest.fixture
    def mock_votes_deny(self):
        """Both models deny"""
        from tools.verification_engine import ModelVote
        return [
            ModelVote(
                model_name="claude-opus-4-8",
                model_weight=3.0,
                verdict="false_positive",
                confidence=0.8,
                reasoning="WAF blocked",
                severity_adjustment=None
            ),
            ModelVote(
                model_name="claude-sonnet-5",
                model_weight=2.0,
                verdict="false_positive",
                confidence=0.8,
                reasoning="WAF blocked",
                severity_adjustment=None
            )
        ]

    @pytest.fixture
    def mock_votes_severity_adjust(self):
        """Votes with severity adjustment"""
        from tools.verification_engine import ModelVote
        return [
            ModelVote(
                model_name="claude-opus-4-8",
                model_weight=3.0,
                verdict="confirmed",
                confidence=0.9,
                reasoning="Script reflected",
                severity_adjustment=None
            ),
            ModelVote(
                model_name="claude-sonnet-5",
                model_weight=2.0,
                verdict="severity_adjustment",
                confidence=0.8,
                reasoning="Only self-XSS",
                severity_adjustment="MEDIUM"
            )
        ]

    @pytest.fixture
    def engine(self):
        engine = VerificationEngine()
        # Create a mock AI client
        engine.ai_client = MagicMock()
        engine.ai_client.chat = AsyncMock()
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

    @pytest.fixture
    def mock_votes_confirm(self):
        from tools.verification_engine import ModelVote
        return [
            ModelVote(
                model_name="claude-opus-4-8",
                model_weight=3.0,
                verdict="confirmed",
                confidence=0.9,
                reasoning="Clear SQL error",
                severity_adjustment=None
            ),
            ModelVote(
                model_name="claude-sonnet-5",
                model_weight=2.0,
                verdict="confirmed",
                confidence=0.85,
                reasoning="Clear SQL error",
                severity_adjustment=None
            )
        ]

    @pytest.fixture
    def mock_votes_disagree(self):
        """One confirms, one denies"""
        from tools.verification_engine import ModelVote
        return [
            ModelVote(
                model_name="claude-opus-4-8",
                model_weight=3.0,
                verdict="confirmed",
                confidence=0.9,
                reasoning="Clear SQL error",
                severity_adjustment=None
            ),
            ModelVote(
                model_name="claude-sonnet-5",
                model_weight=2.0,
                verdict="false_positive",
                confidence=0.8,
                reasoning="WAF blocked",
                severity_adjustment=None
            )
        ]

    @pytest.fixture
    def mock_votes_deny(self):
        """Both models deny"""
        from tools.verification_engine import ModelVote
        return [
            ModelVote(
                model_name="claude-opus-4-8",
                model_weight=3.0,
                verdict="false_positive",
                confidence=0.8,
                reasoning="WAF blocked",
                severity_adjustment=None
            ),
            ModelVote(
                model_name="claude-sonnet-5",
                model_weight=2.0,
                verdict="false_positive",
                confidence=0.8,
                reasoning="WAF blocked",
                severity_adjustment=None
            )
        ]

    @pytest.fixture
    def mock_votes_severity_adjust(self):
        """Votes with severity adjustment"""
        from tools.verification_engine import ModelVote
        return [
            ModelVote(
                model_name="claude-opus-4-8",
                model_weight=3.0,
                verdict="confirmed",
                confidence=0.9,
                reasoning="Script reflected",
                severity_adjustment=None
            ),
            ModelVote(
                model_name="claude-sonnet-5",
                model_weight=2.0,
                verdict="severity_adjustment",
                confidence=0.8,
                reasoning="Only self-XSS",
                severity_adjustment="MEDIUM"
            )
        ]

    @pytest.fixture
    def engine(self):
        engine = VerificationEngine()
        # Create a mock AI client
        engine.ai_client = MagicMock()
        engine.ai_client.chat = AsyncMock()
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

    @pytest.mark.asyncio
    async def test_verify_both_confirm(self, engine, mock_finding):
        """Test verification when both models confirm"""
        with patch.object(engine, '_query_model', new_callable=AsyncMock) as mock_query:
            mock_query.side_effect = [
                ModelVote(
                    model_name="claude-opus-4-8",
                    model_weight=3.0,
                    verdict="confirmed",
                    confidence=0.9,
                    reasoning="Clear SQL error",
                    severity_adjustment=None
                ),
                ModelVote(
                    model_name="claude-sonnet-5",
                    model_weight=2.0,
                    verdict="confirmed",
                    confidence=0.85,
                    reasoning="Clear SQL error",
                    severity_adjustment=None
                )
            ]
            result = await engine.verify_with_consensus(mock_finding)

            assert result.verified is True
            assert result.consensus_verdict == "confirmed"
            assert result.confidence > 0.8
            assert len(result.model_votes) == 2

    @pytest.mark.asyncio
    async def test_verify_one_confirms_one_denies(self, engine, mock_finding):
        """Test when models disagree"""
        with patch.object(engine, '_query_model', new_callable=AsyncMock) as mock_query:
            mock_query.side_effect = [
                ModelVote(
                    model_name="claude-opus-4-8",
                    model_weight=3.0,
                    verdict="confirmed",
                    confidence=0.9,
                    reasoning="Clear SQL error",
                    severity_adjustment=None
                ),
                ModelVote(
                    model_name="claude-sonnet-5",
                    model_weight=2.0,
                    verdict="false_positive",
                    confidence=0.8,
                    reasoning="WAF blocked",
                    severity_adjustment=None
                )
            ]

            result = await engine.verify_with_consensus(mock_finding)

            # With weights 3.0 (confirmed) vs 2.0 (false_positive), confirmed wins
            assert result.verified is True
            assert result.consensus_verdict == "confirmed"
            assert result.requires_human_review is False

    @pytest.mark.asyncio
    async def test_verify_both_deny(self, engine, mock_finding):
        """Test when both models deny"""
        with patch.object(engine, '_query_model', new_callable=AsyncMock) as mock_query:
            mock_query.return_value = ModelVote(
                model_name="claude-opus-4-8",
                model_weight=3.0,
                verdict="false_positive",
                confidence=0.8,
                reasoning="WAF blocked",
                severity_adjustment=None
            )

            result = await engine.verify_with_consensus(mock_finding)

            assert result.verified is False
            assert result.consensus_verdict == "false_positive"
            assert result.confidence > 0.5

    @pytest.mark.asyncio
    async def test_verify_severity_adjustment(self, engine):
        """Test severity adjustment by models"""
        finding = {
            "type": "xss",
            "severity": "HIGH",
            "url": "http://example.com/search",
            "parameter": "q",
            "payload": "<script>alert(1)</script>",
            "evidence": "Script reflected in response",
            "description": "Reflected XSS in search"
        }

        with patch.object(engine, '_query_model', new_callable=AsyncMock) as mock_query:
            mock_query.side_effect = [
                ModelVote(
                    model_name="claude-opus-4-8",
                    model_weight=3.0,
                    verdict="confirmed",
                    confidence=0.9,
                    reasoning="Script reflected",
                    severity_adjustment=None
                ),
                ModelVote(
                    model_name="claude-sonnet-5",
                    model_weight=2.0,
                    verdict="severity_adjustment",
                    confidence=0.8,
                    reasoning="Only self-XSS",
                    severity_adjustment="MEDIUM"
                )
            ]

            result = await engine.verify_with_consensus(mock_finding)

            assert result.verified is True
            assert result.severity == "MEDIUM"
            assert result.confidence > 0.7

    @pytest.mark.asyncio
    async def test_fallback_verification(self, engine):
        """Test fallback when no AI client"""
        engine.ai_client = None
        finding = {"type": "xss", "severity": "HIGH", "url": "http://test.com"}

        result = await engine.verify_with_consensus(finding)

        assert result.verified is False
        assert result.consensus_verdict == "insufficient_evidence"
        assert result.requires_human_review is True

    @pytest.mark.asyncio
    async def test_all_models_fail(self, engine):
        """Test when all models fail"""
        with patch.object(engine, '_query_model', new_callable=AsyncMock) as mock_query:
            mock_query.side_effect = Exception("Model failed")

            result = await engine.verify_with_consensus({"type": "xss"})

            assert result.verified is False
            assert result.consensus_verdict == "insufficient_evidence"

    @pytest.mark.asyncio
    async def test_severity_adjustment_consensus(self, engine):
        """Test severity adjustment via weighted majority"""
        finding = {
            "type": "xss",
            "severity": "HIGH",
            "url": "http://example.com/search",
            "parameter": "q",
            "payload": "<script>alert(1)</script>"
        }

        with patch.object(engine, '_query_model', new_callable=AsyncMock) as mock_query:
            mock_query.side_effect = [
                ModelVote(
                    model_name="claude-opus-4-8",
                    model_weight=3.0,
                    verdict="confirmed",
                    confidence=0.9,
                    reasoning="Script reflected",
                    severity_adjustment=None
                ),
                ModelVote(
                    model_name="claude-sonnet-5",
                    model_weight=2.0,
                    verdict="severity_adjustment",
                    confidence=0.8,
                    reasoning="Only self-XSS",
                    severity_adjustment="MEDIUM"
                )
            ]

            result = await engine.verify_with_consensus(mock_finding)

            assert result.verified is True
            assert result.severity == "MEDIUM"
            assert result.confidence > 0.7