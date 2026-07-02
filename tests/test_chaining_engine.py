"""tests/test_chaining_engine.py — Tests for ChainingEngine module."""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from tools.chaining_engine import ChainingEngine


def test_analyze_chain_idor_info_disclosure():
    engine = ChainingEngine()
    findings = [
        {"type": "IDOR", "severity": "LOW"},
        {"type": "info_disclosure", "severity": "LOW"},
    ]
    chain = engine.analyze_chain(findings)
    assert chain is not None
    assert chain.combined_severity == "CRITICAL"
    assert chain.chain_type == "data_exfiltration"
    assert "IDOR" in chain.impact_description or "IDOR" in str(chain.findings)


def test_analyze_chain_ssrf_cloud_metadata():
    engine = ChainingEngine()
    findings = [
        {"type": "SSRF", "severity": "MEDIUM"},
        {"type": "cloud_metadata_access", "severity": "LOW"},
    ]
    chain = engine.analyze_chain(findings)
    assert chain is not None
    assert chain.combined_severity == "CRITICAL"


def test_analyze_chain_no_match():
    engine = ChainingEngine()
    findings = [
        {"type": "XSS", "severity": "LOW"},
        {"type": "CSRF", "severity": "LOW"},
    ]
    # XSS+CSRF is a valid chain in the engine
    chain = engine.analyze_chain(findings)
    # This should find the XSS+CSRF chain
    assert chain is not None


def test_analyze_chain_no_chain_possible():
    engine = ChainingEngine()
    findings = [
        {"type": "open_redirect", "severity": "LOW"},
        {"type": "clickjacking", "severity": "LOW"},
    ]
    chain = engine.analyze_chain(findings)
    assert chain is None


def test_find_chainable_findings():
    engine = ChainingEngine()
    findings = [
        {"type": "IDOR", "severity": "LOW"},
        {"type": "info_disclosure", "severity": "LOW"},
        {"type": "open_redirect", "severity": "LOW"},
    ]
    chainable = engine.find_chainable_findings(findings)
    assert len(chainable) == 1
    types = {chainable[0][0]["type"], chainable[0][1]["type"]}
    assert "IDOR" in types
    assert "info_disclosure" in types


def test_find_chainable_findings_none():
    engine = ChainingEngine()
    findings = [
        {"type": "open_redirect", "severity": "LOW"},
        {"type": "clickjacking", "severity": "LOW"},
    ]
    chainable = engine.find_chainable_findings(findings)
    assert len(chainable) == 0


def test_suggest_chain():
    engine = ChainingEngine()
    findings = [
        {"type": "IDOR", "severity": "LOW"},
        {"type": "info_disclosure", "severity": "LOW"},
        {"type": "SSRF", "severity": "MEDIUM"},
        {"type": "cloud_metadata_access", "severity": "LOW"},
    ]
    best = engine.suggest_chain(findings)
    assert best is not None
    # Both IDOR+info_disclosure and SSRF+cloud_metadata are CRITICAL
    assert best.combined_severity == "CRITICAL"


def test_suggest_chain_no_match():
    engine = ChainingEngine()
    findings = [
        {"type": "open_redirect", "severity": "LOW"},
    ]
    best = engine.suggest_chain(findings)
    assert best is None
