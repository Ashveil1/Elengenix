"""tests/test_escalation_engine.py — Tests for EscalationEngine module."""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from tools.escalation_engine import EscalationEngine


def test_can_escalate_xss():
    engine = EscalationEngine()
    finding = {"type": "XSS", "severity": "LOW"}
    path = engine.can_escalate(finding)
    assert path is not None
    assert path.finding_type == "XSS"
    assert path.expected_severity == "CRITICAL"


def test_can_escalate_sqli():
    engine = EscalationEngine()
    finding = {"type": "SQLi", "severity": "MEDIUM"}
    path = engine.can_escalate(finding)
    assert path is not None
    assert path.expected_severity == "CRITICAL"


def test_can_escalate_idor():
    engine = EscalationEngine()
    finding = {"type": "IDOR", "severity": "LOW"}
    path = engine.can_escalate(finding)
    assert path is not None
    assert path.expected_severity == "HIGH"


def test_can_escalate_ssrf():
    engine = EscalationEngine()
    finding = {"type": "SSRF", "severity": "MEDIUM"}
    path = engine.can_escalate(finding)
    assert path is not None
    assert path.expected_severity == "CRITICAL"


def test_can_escalate_unknown():
    engine = EscalationEngine()
    finding = {"type": "UNKNOWN_TYPE", "severity": "LOW"}
    path = engine.can_escalate(finding)
    assert path is None


def test_get_escalation_steps_xss():
    engine = EscalationEngine()
    finding = {"type": "XSS", "severity": "LOW"}
    steps = engine.get_escalation_steps(finding)
    assert len(steps) > 0
    assert "stored_xss" in steps
    assert "cookie_theft" in steps


def test_get_escalation_steps_unknown():
    engine = EscalationEngine()
    finding = {"type": "UNKNOWN"}
    steps = engine.get_escalation_steps(finding)
    assert steps == []


def test_suggest_next_action_initial():
    engine = EscalationEngine()
    finding = {"type": "XSS"}
    next_step = engine.suggest_next_action(finding, [])
    assert next_step == "stored_xss"


def test_suggest_next_action_partial():
    engine = EscalationEngine()
    finding = {"type": "XSS"}
    next_step = engine.suggest_next_action(finding, ["stored_xss", "cookie_theft"])
    assert next_step == "session_hijack"


def test_suggest_next_action_complete():
    engine = EscalationEngine()
    finding = {"type": "XSS"}
    next_step = engine.suggest_next_action(
        finding, ["stored_xss", "cookie_theft", "session_hijack", "account_takeover"]
    )
    assert next_step is None


def test_suggest_next_action_no_escalation():
    engine = EscalationEngine()
    finding = {"type": "UNKNOWN"}
    next_step = engine.suggest_next_action(finding, [])
    assert next_step is None
