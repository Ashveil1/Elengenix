"""test_core_modules.py - Tests for critical modules without coverage.

Covers: cvss_calculator, governance, mission_state, vector_memory, cve_database.
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


# ═══════════════════════════════════════════════════════════════════════════
# CVSS Calculator
# ═══════════════════════════════════════════════════════════════════════════

def test_cvss_zero_vector():
    """All-NONE vector should score 0.0."""
    from tools.cvss_calculator import CVSSCalculator, CVSSVector, Severity
    calc = CVSSCalculator(use_ai=False)
    vector = CVSSVector()
    score = calc.calculate(vector)
    assert score.base_score == 0.0
    assert score.severity == Severity.INFO


def test_cvss_critical_rce():
    """Network RCE with no auth should be Critical."""
    from tools.cvss_calculator import CVSSCalculator, CVSSVector, Severity
    calc = CVSSCalculator(use_ai=False)
    vector = CVSSVector(
        attack_vector="N",
        attack_complexity="L",
        privileges_required="N",
        user_interaction="N",
        scope="C",
        confidentiality="H",
        integrity="H",
        availability="H",
    )
    score = calc.calculate(vector)
    assert score.base_score >= 9.0
    assert score.severity == Severity.CRITICAL


def test_cvss_medium_stored_xss():
    """Stored XSS should be around Medium."""
    from tools.cvss_calculator import CVSSCalculator, CVSSVector, Severity
    calc = CVSSCalculator(use_ai=False)
    vector = CVSSVector(
        attack_vector="N",
        attack_complexity="L",
        privileges_required="L",
        user_interaction="R",
        scope="U",
        confidentiality="L",
        integrity="L",
        availability="N",
    )
    score = calc.calculate(vector)
    assert 4.0 <= score.base_score <= 6.0
    assert score.severity in (Severity.MEDIUM, Severity.HIGH)


def test_cvss_vector_string():
    """CVSS vector string should follow standard format."""
    from tools.cvss_calculator import CVSSVector
    vector = CVSSVector()
    vs = vector.to_vector_string()
    assert vs.startswith("CVSS:3.1/AV:")
    assert "AC:" in vs
    assert "PR:" in vs


def test_cvss_from_finding():
    """from_finding should return a valid score."""
    from tools.cvss_calculator import CVSSCalculator, Severity
    calc = CVSSCalculator(use_ai=False)
    score = calc.from_finding("sql_injection", "https://example.com", "UNION SELECT")
    assert 0.0 <= score.base_score <= 10.0
    assert isinstance(score.severity, Severity)


# ═══════════════════════════════════════════════════════════════════════════
# Governance
# ═══════════════════════════════════════════════════════════════════════════

def test_governance_safe_command():
    """Safe commands should be allowed."""
    from tools.governance import Governance
    gov = Governance(require_approval_high_risk=False)
    decision = gov.gate("test", "example.com", {"command": "nuclei -u example.com"})
    assert decision.allowed is True
    assert decision.risk_level == "SAFE"


def test_governance_destructive_rm_rf():
    """rm -rf / should be blocked."""
    from tools.governance import Governance
    gov = Governance()
    decision = gov.gate("test", "example.com", {"command": "rm -rf /"})
    assert decision.allowed is False
    assert decision.risk_level == "DESTRUCTIVE"


def test_governance_destructive_dd():
    """dd if=/dev/zero of=/dev/sda should be blocked."""
    from tools.governance import Governance
    gov = Governance()
    decision = gov.gate("test", "example.com", {"command": "dd if=/dev/zero of=/dev/sda"})
    assert decision.allowed is False
    assert decision.risk_level == "DESTRUCTIVE"


def test_governance_privileged_sudo():
    """sudo commands should need approval."""
    from tools.governance import Governance
    gov = Governance(require_approval_high_risk=True)
    decision = gov.gate("test", "example.com", {"command": "sudo apt install nmap"})
    assert decision.allowed is False
    assert decision.risk_level == "PRIVILEGED"
    assert decision.decision == "needs_approval"


def test_governance_privileged_auto_approve():
    """Auto-approve mode should allow privileged commands."""
    from tools.governance import Governance
    gov = Governance(require_approval_high_risk=True)
    gov.auto_approve_privileged = True
    decision = gov.gate("test", "example.com", {"command": "sudo apt install nmap"})
    assert decision.allowed is True
    assert decision.risk_level == "PRIVILEGED"


def test_governance_classify_risk():
    """classify_risk should return correct risk levels."""
    from tools.governance import Governance
    gov = Governance()
    assert gov.classify_risk({"command": "nuclei -u x"}) == "SAFE"
    assert gov.classify_risk({"command": "rm -rf /"}) == "DESTRUCTIVE"
    assert gov.classify_risk({"command": "sudo ls"}) == "PRIVILEGED"


# ═══════════════════════════════════════════════════════════════════════════
# Mission State
# ═══════════════════════════════════════════════════════════════════════════

def test_mission_state_create():
    """MissionState should create with correct fields."""
    from tools.mission_state import MissionState
    ms = MissionState(mission_id="test:123", target="example.com", objective="scan")
    assert ms.mission_id == "test:123"
    assert ms.target == "example.com"
    assert ms.objective == "scan"


def test_mission_state_snapshot():
    """snapshot should return a dict with expected keys."""
    from tools.mission_state import MissionState
    ms = MissionState(mission_id="test:456", target="example.com", objective="test")
    snap = ms.snapshot()
    assert "target" in snap
    assert "objective" in snap
    assert snap["target"] == "example.com"


def test_mission_state_add_fact():
    """add_fact should store a fact."""
    from tools.mission_state import MissionState
    ms = MissionState(mission_id="test:789", target="example.com", objective="test")
    ms.add_fact(
        fact_id="fact:test:0",
        category="finding",
        statement="Found SQLi at /login",
        confidence=0.9,
    )
    snap = ms.snapshot()
    assert "facts" in snap


# ═══════════════════════════════════════════════════════════════════════════
# CVE Database
# ═══════════════════════════════════════════════════════════════════════════

def test_cve_database_loads():
    """CVE database should load without errors."""
    from tools.cve_database import get_cve_database
    db = get_cve_database(auto_update=False)
    assert db is not None


def test_cve_database_find_similar():
    """find_similar_vulns should return a list."""
    from tools.cve_database import get_cve_database
    db = get_cve_database(auto_update=False)
    results = db.find_similar_vulns("sql_injection", cvss_range=(7.0, 10.0))
    assert isinstance(results, list)


# ═══════════════════════════════════════════════════════════════════════════
# Vector Memory
# ═══════════════════════════════════════════════════════════════════════════

def test_vector_memory_remember_recall():
    """remember and recall should work together."""
    from tools.vector_memory import remember, recall
    remember(
        content="Test memory entry for unit test",
        target="test_target",
        category="test",
    )
    results = recall(query="unit test", target="test_target", n_results=3)
    assert isinstance(results, list)


# ═══════════════════════════════════════════════════════════════════════════
# Tool Registry (expanded)
# ═══════════════════════════════════════════════════════════════════════════

def test_tool_registry_has_multiple_tools():
    """Registry should have discovered tools."""
    from tools.tool_registry import registry
    tools = registry.list_available_tools()
    assert len(tools) >= 5


def test_tool_registry_categories():
    """Each registered tool should have a valid category."""
    from tools.tool_registry import registry, ToolCategory
    tools = registry.list_available_tools()
    for name, info in tools.items():
        assert any(cat.value == info["category"] for cat in ToolCategory), \
            f"{name} has invalid category: {info['category']}"


def test_tool_registry_chain():
    """get_recommended_chain should return ordered tools."""
    from tools.tool_registry import registry
    chain = registry.get_recommended_chain("web")
    assert len(chain) > 0
    # Each tool should be a BaseTool instance
    from tools.tool_registry import BaseTool
    for tool in chain:
        assert isinstance(tool, BaseTool)
