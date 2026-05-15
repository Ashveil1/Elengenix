"""Integration tests for action types in UniversalExecutor."""

from tools.universal_executor import UniversalExecutor
from tools.governance import Governance


def test_run_tool_unknown_tool():
    """Unknown tool returns error, doesn't crash."""
    ue = UniversalExecutor()
    r = ue.execute_action({"type": "run_tool", "params": {"tool": "nonexistent_tool_xyz"}})
    assert not r.success
    assert "not available" in r.error


def test_run_tool_no_tool():
    """Missing tool name returns error."""
    ue = UniversalExecutor()
    r = ue.execute_action({"type": "run_tool", "params": {}})
    assert not r.success
    assert "No tool specified" in r.error


def test_bounty_intel():
    """bounty_intel returns gracefully when no API key."""
    ue = UniversalExecutor()
    r = ue.execute_action({"type": "bounty_intel", "params": {"program": "test"}})
    assert r.success  # Falls back gracefully


def test_github_search():
    """github_search returns gracefully."""
    ue = UniversalExecutor()
    r = ue.execute_action({"type": "github_search", "params": {"query": "test"}})
    assert r.success  # Returns empty results gracefully


def test_cve_lookup():
    """cve_lookup returns gracefully with no DB."""
    ue = UniversalExecutor()
    r = ue.execute_action({"type": "cve_lookup", "params": {"keyword": "rce"}})
    assert r.success  # Returns empty gracefully


def test_js_analyze_no_url():
    """js_analyze with no URL returns error."""
    ue = UniversalExecutor()
    r = ue.execute_action({"type": "js_analyze", "params": {}})
    assert not r.success


def test_check_takeover_no_subdomain():
    """check_takeover with no subdomain returns error."""
    ue = UniversalExecutor()
    r = ue.execute_action({"type": "check_takeover", "params": {}})
    assert not r.success


def test_unknown_action_type():
    """Unknown action type returns error."""
    ue = UniversalExecutor()
    r = ue.execute_action({"type": "fly_to_moon", "params": {}})
    assert not r.success
    assert "Unknown action type" in r.error


def test_governance_destructive():
    """Governance blocks destructive commands."""
    g = Governance()
    r = g.classify_risk({"command": "rm -rf /"})
    assert r == "DESTRUCTIVE"


def test_governance_privileged():
    """Governance flags install commands as PRIVILEGED."""
    g = Governance()
    r = g.classify_risk({"command": "pip install requests"})
    assert r == "PRIVILEGED"  # No longer PRIVILEGED — AI has full freedom


def test_governance_safe():
    """Governance allows safe commands."""
    g = Governance()
    r = g.classify_risk({"command": "echo hello"})
    assert r == "SAFE"
