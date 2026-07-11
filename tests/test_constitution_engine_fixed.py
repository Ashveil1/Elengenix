"""Tests for Constitution Engine - Fixed version"""

from __future__ import annotations

import pytest
from unittest.mock import MagicMock, AsyncMock, patch, AsyncMock
from elengenix.constitution_engine import ConstitutionalCourt, ConstitutionalAIEngine
from elengenix.constitution import Constitution, ConstitutionalArticle, ConstitutionalPrinciple
from elengenix.types import AIAction, ActionType, RiskLevel


class TestConstitutionEngine:
    """Tests for ConstitutionalAIEngine"""

    @pytest.fixture
    def constitution(self):
        from elengenix.constitution import Constitution
        return Constitution()

    @pytest.fixture
    def engine(self, constitution):
        from elengenix.constitution_engine import ConstitutionalAIEngine
        return ConstitutionalAIEngine(constitution)

    @pytest.fixture
    def sample_action(self):
        from elengenix.types import AIAction, ActionType, RiskLevel
        return AIAction(
            action_id="test-001",
            action_type="scan",
            tool="nmap",
            target="example.com",
            parameters={"param": "value"},
            description="Test scan",
            purpose="Test scanning",
            risk_level=RiskLevel.SAFE,
            prerequisites=[],
            expected_outcome="Find open ports",
            constitutional_guidance=None,
            metadata={},
            timestamp=0.0
        )

    @pytest.fixture
    def malicious_action(self):
        from elengenix.types import AIAction, ActionType, RiskLevel
        return AIAction(
            action_id="test-002",
            action_type=ActionType.EXPLOIT,
            tool="sqlmap",
            target="example.com",
            parameters={"param": "value"},
            description="Drop database",
            purpose="Destroy data",
            risk_level=RiskLevel.DESTRUCTIVE,
            prerequisites=[],
            expected_outcome="Destroy data",
            constitutional_guidance=None,
            metadata={},
            timestamp=0.0
        )

    @pytest.fixture
    def out_of_scope_action(self):
        from elengenix.types import AIAction, ActionType, RiskLevel
        return AIAction(
            action_id="test-003",
            action_type=ActionType.SCAN,
            tool="nmap",
            target="google.com",
            parameters={},
            description="Scan Google",
            purpose="Scan external target",
            risk_level=RiskLevel.HIGH,
            prerequisites=[],
            expected_outcome="Scan external target",
            constitutional_guidance=None,
            metadata={},
            timestamp=0.0
        )

    @pytest.fixture
    def engine(self, constitution):
        from elengenix.constitution_engine import ConstitutionalAIEngine
        return ConstitutionalAIEngine(constitution)

    @pytest.fixture
    def constitution(self):
        from elengenix.constitution import Constitution
        return Constitution()

    @pytest.mark.asyncio
    async def test_engine_initialization(self, engine):
        assert engine.constitution is not None
        assert engine.court is not None
        assert isinstance(engine.precedents, list)

    @pytest.mark.asyncio
    async def test_review_action_allows_safe_action(self, engine):
        from elengenix.types import AIAction, ActionType, RiskLevel
        action = AIAction(
            action_id="test-001",
            action_type="recon",
            tool="nmap",
            target="example.com",
            parameters={},
            description="Port scan",
            purpose="Reconnaissance",
            risk_level=RiskLevel.SAFE,
            prerequisites=[],
            expected_outcome="Find open ports",
            constitutional_guidance=None,
            metadata={},
            timestamp=0.0
        )

        guidance = engine.review_action(action)

        assert guidance.is_constitutional is True
        assert guidance.confidence > 0.5

    @pytest.mark.asyncio
    async def test_review_action_flags_destructive_action(self, engine):
        from elengenix.types import AIAction, ActionType, RiskLevel
        action = AIAction(
            action_id="test-002",
            action_type="exploit",
            tool="sqlmap",
            target="example.com",
            parameters={"param": "value"},
            description="Drop database",
            purpose="Destroy data",
            risk_level=RiskLevel.DESTRUCTIVE,
            prerequisites=[],
            expected_outcome="Destroy data",
            constitutional_guidance=None,
            metadata={},
            timestamp=0.0
        )

        guidance = engine.review_action(action)

        assert guidance.is_constitutional is False
        assert guidance.requires_human_review is True
        assert len(guidance.ruling.violations) > 0

    @pytest.mark.asyncio
    async def test_review_action_flags_out_of_scope(self, engine):
        from elengenix.types import AIAction, ActionType, RiskLevel
        action = AIAction(
            action_id="test-003",
            action_type="scan",
            tool="nmap",
            target="google.com",
            parameters={},
            description="Scan Google",
            purpose="Scan external target",
            risk_level=RiskLevel.HIGH,
            prerequisites=[],
            expected_outcome="Scan external target",
            constitutional_guidance=None,
            metadata={},
            timestamp=0.0
        )

        guidance = engine.review_action(action)

        # Should flag out of scope
        assert guidance.is_constitutional is False

    @pytest.mark.asyncio
    async def test_review_action_safe_scan(self, engine):
        from elengenix.types import AIAction, ActionType, RiskLevel
        action = AIAction(
            action_id="test-004",
            action_type="scan",
            tool="nmap",
            target="example.com",
            parameters={},
            description="Port scan",
            purpose="Reconnaissance",
            risk_level=RiskLevel.SAFE,
            prerequisites=[],
            expected_outcome="Find open ports",
            constitutional_guidance=None,
            metadata={},
            timestamp=0.0
        )

        guidance = engine.review_action(action)

        assert guidance.is_constitutional is True
        assert guidance.requires_human_review is False

    @pytest.mark.asyncio
    async def test_review_action_destructive(self, engine):
        from elengenix.types import AIAction, ActionType, RiskLevel
        action = AIAction(
            action_id="test-005",
            action_type="exploit",
            tool="sqlmap",
            target="example.com",
            parameters={"param": "value"},
            description="Drop database",
            purpose="Destroy data",
            risk_level=RiskLevel.DESTRUCTIVE,
            prerequisites=[],
            expected_outcome="Destroy data",
            constitutional_guidance=None,
            metadata={},
            timestamp=0.0
        )

        guidance = engine.review_action(action)

        assert guidance.is_constitutional is False
        assert guidance.requires_human_review is True

    @pytest.mark.asyncio
    async def test_review_action_out_of_scope(self, engine):
        from elengenix.types import AIAction, ActionType, RiskLevel
        action = AIAction(
            action_id="test-006",
            action_type="scan",
            tool="nmap",
            target="google.com",
            parameters={},
            description="Scan Google",
            purpose="Scan external target",
            risk_level=RiskLevel.HIGH,
            prerequisites=[],
            expected_outcome="Scan external target",
            constitutional_guidance=None,
            metadata={},
            timestamp=0.0
        )

        guidance = engine.review_action(action)

        assert guidance.is_constitutional is False

    @pytest.mark.asyncio
    async def test_verify_action_safe(self, engine):
        from elengenix.types import Finding
        finding = {
            "type": "xss",
            "evidence": "<script>alert(1)</script> found in response",
            "severity": "high",
            "url": "http://example.com/search?q=test",
            "description": "Reflected XSS in search"
        }

        with patch.object(engine, 'verify_with_consensus', new_callable=AsyncMock) as mock_verify:
            mock_result = MagicMock()
            mock_result.verified = True
            mock_result.consensus_verdict = "confirmed"
            mock_result.severity = "high"
            mock_result.confidence = 0.95
            mock_result.consensus_strength = 0.9
            mock_result.requires_human_review = False
            mock_result.model_votes = [
                {"model": "opus", "verdict": "confirmed", "confidence": 0.9},
                {"model": "sonnet", "verdict": "confirmed", "confidence": 0.95}
            ]
            mock_verify.return_value = mock_result

            result = await engine.verify_action(finding)

            assert result.verified is True
            assert result.consensus_verdict == "confirmed"

    @pytest.mark.asyncio
    async def test_verify_false_positive(self, engine):
        finding = {
            "type": "xss",
            "evidence": "test",
            "severity": "low"
        }

        with patch.object(engine, '_query_model', new_callable=AsyncMock) as mock_query:
            mock_query.return_value = {
                "verdict": "false_positive",
                "confidence": 0.9,
                "reasoning": "WAF blocked request"
            }

            result = await engine.verify_action({"type": "xss", "evidence": "test"})

            assert result.verified is False
            assert result.consensus_verdict == "false_positive"

    @pytest.mark.asyncio
    async def test_verify_split_decision(self, engine):
        from elengenix.types import Finding
        finding = {"type": "sqli", "evidence": "test"}

        with patch.object(engine, '_query_model', new_callable=AsyncMock) as mock_query:
            mock_query.side_effect = [
                {"verdict": "confirmed", "confidence": 0.9},
                {"verdict": "false_positive", "confidence": 0.8}
            ]

            result = await engine.verify_action({"type": "sqli"})

            assert result.requires_human_review is True

    def test_constitution_articles(self, constitution):
        assert "ART-1" in constitution.articles
        assert "ART-10" in constitution.articles

        art1 = constitution.get_article("ART-1")
        assert art1.principle.value == "do_no_harm"
        assert art1.enforcement_priority == 1

    def test_precedent_storage(self, engine):
        from elengenix.constitution import ConstitutionalRuling, ConstitutionalViolation
        from elengenix.types import AIAction

        action = type('Action', (), {'description': 'test', 'action_type': type('AT', (), {'value': 'scan'})()})()
        ruling = engine.court.review_action(action)

        engine.constitution.add_precedent(ruling)

        precedents = engine.constitution.get_relevant_precedents("scan target")
        assert len(precedents) >= 1