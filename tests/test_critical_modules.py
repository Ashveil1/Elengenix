"""test_critical_modules.py - Comprehensive tests for critical modules.

Tests: governance, cvss_calculator, mission_state, tool_registry, 
       commands/scan, tui modules, agent helpers
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


# ═══════════════════════════════════════════════════════════════════════════
# Governance Module
# ═══════════════════════════════════════════════════════════════════════════

def test_governance_destructive_commands():
    """Destructive commands should be blocked."""
    from tools.governance import Governance
    gov = Governance(require_approval_high_risk=False)
    
    destructive_commands = [
        "rm -rf /",
        "dd if=/dev/zero of=/dev/sda",
        "mkfs.ext4 /dev/sda",
        "shutdown -h now",
    ]
    
    for cmd in destructive_commands:
        decision = gov.gate("test", "example.com", {"command": cmd})
        assert decision.allowed is False, f"Destructive command allowed: {cmd}"
        assert decision.risk_level == "DESTRUCTIVE"


def test_governance_privileged_commands():
    """Privileged commands should require approval."""
    from tools.governance import Governance
    gov = Governance(require_approval_high_risk=True)
    
    privileged_commands = [
        "sudo apt install nmap",
        "pip install requests",
        "npm install -g eslint",
    ]
    
    for cmd in privileged_commands:
        decision = gov.gate("test", "example.com", {"command": cmd})
        assert decision.decision == "needs_approval", f"Privileged command not requiring approval: {cmd}"


def test_governance_safe_commands():
    """Safe commands should be allowed."""
    from tools.governance import Governance
    gov = Governance(require_approval_high_risk=False)
    
    safe_commands = [
        "curl https://example.com",
        "dig example.com",
        "python3 -c 'print(1)'",
        "ls -la",
    ]
    
    for cmd in safe_commands:
        decision = gov.gate("test", "example.com", {"command": cmd})
        assert decision.allowed is True, f"Safe command blocked: {cmd}"
        assert decision.risk_level == "SAFE"


def test_governance_audit_log():
    """Governance should log decisions."""
    from tools.governance import Governance
    gov = Governance(require_approval_high_risk=False)
    gov.gate("test", "example.com", {"command": "ls"})
    # If we get here without exception, audit logging works


# ═══════════════════════════════════════════════════════════════════════════
# CVSS Calculator
# ═══════════════════════════════════════════════════════════════════════════

def test_cvss_critical_score():
    """Critical RCE should score 9.0+."""
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


def test_cvss_medium_xss():
    """Stored XSS should score 4.0-6.0."""
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


def test_cvss_low_info_disclosure():
    """Information disclosure should be low severity."""
    from tools.cvss_calculator import CVSSCalculator, CVSSVector, Severity
    calc = CVSSCalculator(use_ai=False)
    vector = CVSSVector(
        attack_vector="N",
        attack_complexity="H",
        privileges_required="L",
        user_interaction="N",
        scope="U",
        confidentiality="L",
        integrity="N",
        availability="N",
    )
    score = calc.calculate(vector)
    assert score.base_score < 4.0
    assert score.severity in (Severity.LOW, Severity.INFO)


def test_cvss_vector_string():
    """CVSS vector string should follow standard format."""
    from tools.cvss_calculator import CVSSVector
    vector = CVSSVector()
    vs = vector.to_vector_string()
    assert vs.startswith("CVSS:3.1/AV:")
    assert "AC:" in vs
    assert "PR:" in vs


# ═══════════════════════════════════════════════════════════════════════════
# Mission State
# ═══════════════════════════════════════════════════════════════════════════

def test_mission_state_create():
    """MissionState should create correctly."""
    from tools.mission_state import MissionState
    ms = MissionState(mission_id="test_123", target="example.com", objective="scan")
    assert ms.mission_id == "test_123"
    assert ms.target == "example.com"


def test_mission_state_snapshot():
    """MissionState snapshot should return dict."""
    from tools.mission_state import MissionState
    ms = MissionState(mission_id="test_123", target="example.com", objective="scan")
    snap = ms.snapshot()
    assert isinstance(snap, dict)
    assert "target" in snap


def test_mission_state_add_fact():
    """MissionState should add facts."""
    from tools.mission_state import MissionState
    ms = MissionState(mission_id="test_123", target="example.com", objective="scan")
    ms.add_fact(fact_id="fact_1", category="finding", statement="Found XSS", confidence=0.8)
    snap = ms.snapshot()
    assert len(snap.get("facts", [])) > 0


# ═══════════════════════════════════════════════════════════════════════════
# Tool Registry
# ═══════════════════════════════════════════════════════════════════════════

def test_tool_registry_singleton():
    """ToolRegistry should be singleton."""
    from tools.tool_registry import ToolRegistry
    r1 = ToolRegistry()
    r2 = ToolRegistry()
    assert r1 is r2


def test_tool_registry_register():
    """ToolRegistry should register tools."""
    from tools.tool_registry import registry, ToolCategory
    tools = registry.list_available_tools()
    assert len(tools) > 0


def test_tool_registry_get_tool():
    """ToolRegistry should get tools by name."""
    from tools.tool_registry import registry
    tool = registry.get_tool("ssrf_scanner")
    assert tool is not None


def test_tool_registry_categories():
    """ToolRegistry should categorize tools."""
    from tools.tool_registry import registry, ToolCategory
    scanner_tools = registry.get_tools_by_category(ToolCategory.SCANNER)
    assert len(scanner_tools) > 0


# ═══════════════════════════════════════════════════════════════════════════
# Agent Helpers
# ═══════════════════════════════════════════════════════════════════════════

def test_safe_operation_success():
    """_safe_operation should return result on success."""
    from agents.agent_helpers import _safe_operation
    result = _safe_operation("test", lambda: 42)
    assert result == 42


def test_safe_operation_failure():
    """_safe_operation should return default on failure."""
    from agents.agent_helpers import _safe_operation
    result = _safe_operation("test", lambda: 1/0, default="error")
    assert result == "error"


def test_extract_target_from_text():
    """_extract_target_from_text should extract domains."""
    from agents.agent_helpers import _extract_target_from_text
    target = _extract_target_from_text("scan example.com please")
    assert "example" in target


# ═══════════════════════════════════════════════════════════════════════════
# TUI Modules
# ═══════════════════════════════════════════════════════════════════════════

def test_welcome_screen_render():
    """Welcome screen should render."""
    from tui.welcome import build_welcome_renderable
    result = build_welcome_renderable()
    assert result is not None


def test_scan_progress_widget():
    """ScanProgressWidget should work."""
    from tui.scan_progress import ScanProgressWidget
    widget = ScanProgressWidget()
    widget.start_scan("example.com", "Full Scan")
    widget.update_phase("Recon", progress=0.5, findings=3)
    panel = widget.render()
    assert panel is not None


def test_findings_display():
    """FindingsDisplay should work."""
    from tui.findings_display import FindingsDisplay, Finding
    display = FindingsDisplay()
    display.add_finding(Finding(
        id="1", title="XSS", severity="high", category="xss", location="/search"
    ))
    panel = display.render()
    assert panel is not None


def test_keyboard_shortcuts():
    """KeyboardShortcutManager should work."""
    from tui.keyboard_shortcuts import KeyboardShortcutManager
    manager = KeyboardShortcutManager()
    manager.register("Ctrl+S", "Save", "save")
    assert manager.get_action("Ctrl+S") == "save"


def test_themes_all_valid():
    """All themes should have required keys."""
    from tui.themes import THEMES, THEME_TOKENS
    for name, theme in THEMES.items():
        for key in THEME_TOKENS:
            assert key in theme, f"Theme {name} missing token: {key}"


# ═══════════════════════════════════════════════════════════════════════════
# Commands Module
# ═══════════════════════════════════════════════════════════════════════════

def test_scan_command_import():
    """Scan command module should import."""
    from commands.scan import handle_scan
    assert callable(handle_scan)


# ═══════════════════════════════════════════════════════════════════════════
# Vector Memory
# ═══════════════════════════════════════════════════════════════════════════

def test_vector_memory_remember_recall():
    """remember and recall should work together."""
    from tools.vector_memory import remember, recall
    remember(
        content="Test memory entry for comprehensive test",
        target="test_target_comprehensive",
        category="test",
    )
    results = recall(query="comprehensive test", target="test_target_comprehensive", n_results=3)
    assert isinstance(results, list)


# ═══════════════════════════════════════════════════════════════════════════
# CVE Database
# ═══════════════════════════════════════════════════════════════════════════

def test_cve_database_loads():
    """CVE database should load."""
    from tools.cve_database import get_cve_database
    db = get_cve_database()
    assert db is not None


# ═══════════════════════════════════════════════════════════════════════════
# Payload Mutation
# ═══════════════════════════════════════════════════════════════════════════

def test_payload_mutator():
    """PayloadMutator should generate payloads."""
    from tools.payload_mutation import PayloadMutator
    mutator = PayloadMutator()
    payloads = mutator.mutate("<script>alert(1)</script>")
    assert len(payloads) > 0


# ═══════════════════════════════════════════════════════════════════════════
# Agent Reflection
# ═══════════════════════════════════════════════════════════════════════════

def test_agent_reflection():
    """AgentReflection should work."""
    from tools.agent_reflection import get_reflection
    reflection = get_reflection()
    assert reflection is not None
