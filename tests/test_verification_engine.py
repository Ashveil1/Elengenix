"""tests/test_verification_engine.py — Tests for VerificationEngine module."""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from tools.verification_engine import VerificationEngine, VerificationResult, ModelVote


def _vote(verdict, confidence=0.9, weight=1.0, severity_adj=None):
    """Helper to create a ModelVote."""
    return ModelVote(
        model_name="test",
        model_weight=weight,
        verdict=verdict,
        confidence=confidence,
        reasoning="test",
        severity_adjustment=severity_adj,
    )


def test_verify_both_confirm():
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


def test_verify_one_confirm_one_deny():
    engine = VerificationEngine()
    finding = {"type": "SQLi", "severity": "MEDIUM", "url": "http://test.com"}
    votes = [
        _vote("confirmed", confidence=0.8),
        _vote("false_positive", confidence=0.7),
    ]
    result = engine._compute_consensus(finding, votes)
    # Tie with equal weights -> inconclusive
    assert result.verified is False
    assert result.consensus_verdict == "inconclusive"
    assert result.requires_human_review is True


def test_verify_both_deny():
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


def test_verify_default_severity():
    engine = VerificationEngine()
    finding = {"type": "IDOR"}
    votes = [
        _vote("confirmed", confidence=0.9),
        _vote("confirmed", confidence=0.95),
    ]
    result = engine._compute_consensus(finding, votes)
    assert result.verified is True
    assert result.severity == "MEDIUM"  # default


def test_consensus_weighted_majority():
    """Weighted votes: high-weight confirm should outweigh light-weight deny."""
    engine = VerificationEngine()
    finding = {"type": "XSS", "severity": "LOW"}
    votes = [
        _vote("confirmed", confidence=0.9, weight=3.0),
        _vote("false_positive", confidence=0.9, weight=1.0),
    ]
    result = engine._compute_consensus(finding, votes)
    assert result.verified is True
    assert result.consensus_verdict == "confirmed"


def test_fallback_verification_empty():
    """No votes -> fallback verification should run without raising."""
    engine = VerificationEngine()
    finding = {"type": "XSS", "url": "http://test.com"}
    result = engine._compute_consensus(finding, [])
    # Fallback returns a VerificationResult
    assert isinstance(result, VerificationResult)
