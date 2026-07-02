"""tests/test_verification_engine.py — Tests for VerificationEngine module."""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from tools.verification_engine import VerificationEngine


def test_verify_both_confirm():
    engine = VerificationEngine()
    finding = {"type": "XSS", "severity": "HIGH", "url": "http://test.com"}
    result = engine.verify(finding, "confirmed", "confirmed")
    assert result.verified is True
    assert result.confidence == 0.95
    assert result.requires_human_review is False
    assert result.severity == "HIGH"


def test_verify_one_confirm_one_deny():
    engine = VerificationEngine()
    finding = {"type": "SQLi", "severity": "MEDIUM", "url": "http://test.com"}
    result = engine.verify(finding, "confirmed", "false_positive")
    assert result.verified is False
    assert result.confidence == 0.5
    assert result.requires_human_review is True


def test_verify_both_deny():
    engine = VerificationEngine()
    finding = {"type": "SSRF", "severity": "HIGH", "url": "http://test.com"}
    result = engine.verify(finding, "not vulnerable", "fake finding")
    assert result.verified is False
    assert result.confidence == 0.1
    assert result.requires_human_review is False
    assert result.severity == "INFO"


def test_verify_keywords_yes_no():
    engine = VerificationEngine()
    finding = {"type": "XSS", "severity": "LOW"}
    # "yes" is confirmation, "no" is denial
    result = engine.verify(finding, "yes this is real", "no not a vuln")
    assert result.verified is False
    assert result.requires_human_review is True


def test_verify_with_evidence():
    engine = VerificationEngine()
    finding = {"type": "XSS", "severity": "CRITICAL", "url": "http://test.com"}
    result = engine.verify(finding, "valid vulnerability confirmed", "real vulnerability")
    assert result.verified is True
    assert result.severity == "CRITICAL"


def test_verify_default_severity():
    engine = VerificationEngine()
    finding = {"type": "IDOR"}
    result = engine.verify(finding, "confirmed", "confirmed")
    assert result.verified is True
    assert result.severity == "MEDIUM"  # default
