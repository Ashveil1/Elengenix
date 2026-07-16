"""Tests for elengenix/constitution_engine.py — Constitutional Court & AI Engine."""

from __future__ import annotations

import pytest
from unittest.mock import MagicMock, Mock, patch
from elengenix.constitution_engine import (
    ConstitutionalCourt,
    ConstitutionalAIEngine,
)
from elengenix.constitution import (
    Constitution,
    ConstitutionalArticle,
    ConstitutionalPrinciple,
    ConstitutionalRuling,
)
from elengenix.types import AIAction


class TestConstitutionalCourt:
    """Tests for ConstitutionalCourt."""

    def test_init_sets_attributes(self):
        """Init should set constitution and precedents."""
        constitution = Constitution()
        court = ConstitutionalCourt(constitution)
        assert court.constitution is constitution
        assert court.precedents == []

    def test_review_action_returns_ruling(self):
        """review_action should return a ConstitutionalRuling."""
        constitution = Constitution()
        court = ConstitutionalCourt(constitution)
        action = AIAction(description="scan example.com", tool="nmap", parameters={"target": "example.com"})
        ruling = court.review_action(action)
        assert isinstance(ruling, ConstitutionalRuling)
        assert ruling.constitutional is True
        assert ruling.violations == []

    def test_review_action_detects_destruction_violation(self):
        """Should detect destruction keywords."""
        constitution = Constitution()
        court = ConstitutionalCourt(constitution)
        action = AIAction(description="destroy all data", tool="rm", parameters={"target": "/"})
        ruling = court.review_action(action)
        assert ruling.constitutional is False
        assert len(ruling.violations) >= 1

    def test_review_action_detects_multiple_violations(self):
        """Should detect violations for multiple articles."""
        constitution = Constitution()
        court = ConstitutionalCourt(constitution)
        # "destroy" triggers do_no_harm; check if multiple articles catch it
        action = AIAction(description="destroy all data and obfuscate evidence", tool="rm", parameters={"target": "/"})
        ruling = court.review_action(action)
        assert ruling.constitutional is False
        # At least one violation detected
        assert len(ruling.violations) >= 1

    def test_review_action_no_violation(self):
        """Clean action should have no violations."""
        constitution = Constitution()
        court = ConstitutionalCourt(constitution)
        action = AIAction(description="read file content", tool="cat", parameters={"path": "/etc/passwd"})
        ruling = court.review_action(action)
        assert ruling.constitutional is True

    def test_review_action_adds_precedent(self):
        """Each review should add to precedents."""
        constitution = Constitution()
        court = ConstitutionalCourt(constitution)
        action1 = AIAction(description="safe scan", tool="nmap", parameters={})
        action2 = AIAction(description="safe probe", tool="curl", parameters={})
        court.review_action(action1)
        court.review_action(action2)
        assert len(court.precedents) == 2

    def test_generate_considerations_empty_violations(self):
        """Empty violations should return standard considerations."""
        constitution = Constitution()
        court = ConstitutionalCourt(constitution)
        considerations = court._generate_considerations([])
        assert len(considerations) == 2
        assert "สอดคล้อง" in considerations[0]

    def test_generate_considerations_with_violations(self):
        """With violations, should list them."""
        constitution = Constitution()
        court = ConstitutionalCourt(constitution)
        violations = [
            {"principle": "do_no_harm", "description": "Destruction detected", "remediation_hint": "Use safe mode"},
            {"principle": "transparency", "description": "Hidden action", "remediation_hint": "Be transparent"},
        ]
        considerations = court._generate_considerations(violations)
        assert len(considerations) == 3  # 2 violations + 1 sovereign note
        assert "do_no_harm" in considerations[0]
        assert "Sovereign" in considerations[2]

    def test_find_relevant_precedents(self):
        """Should find precedents with keyword overlap."""
        constitution = Constitution()
        court = ConstitutionalCourt(constitution)

        # Create two precedents
        r1 = ConstitutionalRuling(
            action_id="1", action_description="scan the target network",
            constitutional=True, violations=[], considerations=[],
            relevant_precedents=[], confidence=0.9,
        )
        r2 = ConstitutionalRuling(
            action_id="2", action_description="probe the target server",
            constitutional=True, violations=[], considerations=[],
            relevant_precedents=[], confidence=0.9,
        )
        court.precedents = [r1, r2]

        # Action with overlapping keywords
        action = AIAction(description="scan the target", tool="nmap", parameters={})
        precedents = court._find_relevant_precedents(action)
        assert len(precedents) >= 1  # "scan", "the", "target" overlap with r1

    def test_find_relevant_precedents_limit(self):
        """Should respect limit parameter."""
        constitution = Constitution()
        court = ConstitutionalCourt(constitution)
        for i in range(10):
            court.precedents.append(
                ConstitutionalRuling(
                    action_id=str(i),
                    action_description="scan the target network",
                    constitutional=True, violations=[], considerations=[],
                    relevant_precedents=[], confidence=0.9,
                )
            )
        action = AIAction(description="scan the target", tool="nmap", parameters={})
        precedents = court._find_relevant_precedents(action, limit=3)
        assert len(precedents) <= 3

    def test_calculate_confidence_no_violations(self):
        """No violations → high confidence."""
        constitution = Constitution()
        court = ConstitutionalCourt(constitution)
        conf = court._calculate_confidence([])
        assert conf == 0.95

    def test_calculate_confidence_with_violations(self):
        """Violations should reduce confidence."""
        constitution = Constitution()
        court = ConstitutionalCourt(constitution)
        violations = [
            {"severity": "critical"},
            {"severity": "high"},
            {"severity": "medium"},
        ]
        conf = court._calculate_confidence(violations)
        assert conf < 0.95
        assert conf >= 0.1

    def test_calculate_confidence_many_violations(self):
        """Many violations should hit minimum confidence."""
        constitution = Constitution()
        court = ConstitutionalCourt(constitution)
        violations = [{"severity": "critical"}] * 10
        conf = court._calculate_confidence(violations)
        assert conf == 0.1


class TestConstitutionalAIEngine:
    """Tests for ConstitutionalAIEngine."""

    def test_init_with_default_constitution(self):
        """Should create default constitution when none provided."""
        engine = ConstitutionalAIEngine()
        assert engine.constitution is not None
        assert isinstance(engine.court, ConstitutionalCourt)
        assert engine.precedents == []

    def test_init_with_custom_constitution(self):
        """Should use provided constitution."""
        custom = Constitution()
        engine = ConstitutionalAIEngine(constitution=custom)
        assert engine.constitution is custom

    def test_review_action_returns_guidance(self):
        """review_action should return ConstitutionalGuidance."""
        engine = ConstitutionalAIEngine()
        action = AIAction(description="scan target", tool="nmap", parameters={})
        guidance = engine.review_action(action)
        assert guidance is not None
        assert hasattr(guidance, "ruling")
        assert hasattr(guidance, "relevant_precedents")
        assert hasattr(guidance, "constitutional_interpretation")
        assert hasattr(guidance, "requires_human_review")

    def test_review_action_no_violations(self):
        """Clean action → not requiring human review."""
        engine = ConstitutionalAIEngine()
        action = AIAction(description="read file content", tool="cat", parameters={})
        guidance = engine.review_action(action)
        assert guidance.requires_human_review is False

    def test_review_action_with_violation(self):
        """Violation may require human review."""
        engine = ConstitutionalAIEngine()
        action = AIAction(description="destroy all data", tool="rm", parameters={})
        guidance = engine.review_action(action)
        # High severity violation → requires human review
        assert guidance.requires_human_review is True

    def test_review_action_populates_guidance(self):
        """Guidance should have all fields populated."""
        engine = ConstitutionalAIEngine()
        action = AIAction(description="scan target", tool="nmap", parameters={})
        guidance = engine.review_action(action)
        assert guidance.ruling is not None
        assert isinstance(guidance.relevant_precedents, list)
        assert isinstance(guidance.constitutional_interpretation, str)
        assert isinstance(guidance.recommended_considerations, list)

    def test_interpret_constitution_with_matching_article(self):
        """Should interpret when article matches action."""
        engine = ConstitutionalAIEngine()
        action = AIAction(description="do_no_harm principle test", tool="test", parameters={})
        interpretation = engine._interpret_constitution(action)
        assert len(interpretation) > 0

    def test_interpret_constitution_no_match(self):
        """No matching articles → default message."""
        engine = ConstitutionalAIEngine()
        action = AIAction(description="random action with no principles", tool="test", parameters={})
        interpretation = engine._interpret_constitution(action)
        assert "ไม่พบ" in interpretation

    def test_add_precedent(self):
        """Should add precedent to engine's list."""
        engine = ConstitutionalAIEngine()
        ruling = ConstitutionalRuling(
            action_id="test1",
            action_description="test ruling",
            constitutional=True,
            violations=[],
            considerations=[],
            relevant_precedents=[],
            confidence=0.9,
        )
        engine.add_precedent(ruling)
        assert len(engine.precedents) == 1
        assert engine.precedents[0].action_id == "test1"

    def test_find_relevant_precedents(self):
        """Should find precedents by keyword overlap."""
        engine = ConstitutionalAIEngine()
        engine.precedents = [
            ConstitutionalRuling(
                action_id="1", action_description="scan the target network",
                constitutional=True, violations=[], considerations=[],
                relevant_precedents=[], confidence=0.9,
            ),
        ]
        action = AIAction(description="scan the target server", tool="nmap", parameters={})
        precedents = engine._find_relevant_precedents(action)
        assert len(precedents) == 1
