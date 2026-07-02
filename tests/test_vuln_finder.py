"""tests/test_vuln_finder.py — Tests for VulnFinder module."""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from tools.vuln_finder import VulnFinder, MissionStatus
from tools.adaptive_planner import AdaptivePlanner


def test_init():
    finder = VulnFinder(target="http://example.com")
    assert finder.target == "http://example.com"
    assert finder.max_steps == 100
    assert finder.budget_limit == 50.0
    assert finder.state.target == "http://example.com"
    assert finder.state.status == MissionStatus.INIT


def test_init_custom_params():
    finder = VulnFinder(target="http://test.com", max_steps=50, budget_limit=10.0)
    assert finder.max_steps == 50
    assert finder.budget_limit == 10.0


def test_recon_sets_status_on_failure():
    # Verify recon sets status even when PythonRecon fails (no network)
    finder = VulnFinder(target="http://127.0.0.1:1")  # port 1 — will fail fast
    assets = finder.recon()
    assert finder.state.status == MissionStatus.RECON
    assert "target" in assets


def test_plan_empty_endpoints():
    finder = VulnFinder(target="http://example.com")
    # Manually set status and assets without network
    finder.state.status = MissionStatus.RECON
    finder.state.assets = {"endpoints": []}
    plan = finder.plan()
    assert isinstance(plan, list)
    assert len(plan) == 0
    assert finder.state.status == MissionStatus.PLANNING


def test_plan_with_endpoints():
    finder = VulnFinder(target="http://example.com")
    finder.state.status = MissionStatus.RECON
    finder.state.assets = {"endpoints": ["/api/users", "/api/admin"]}
    plan = finder.plan()
    assert len(plan) == 2
    # Both should be api_endpoint type with rank 5
    assert plan[0]["rank"] == 5


def test_execute_no_tool():
    finder = VulnFinder(target="http://example.com")
    result = finder.execute({"url": "http://example.com/api"})
    assert result["success"] is False
    assert finder.state.steps == 1


def test_execute_unknown_tool():
    finder = VulnFinder(target="http://example.com")
    result = finder.execute({"url": "http://example.com/api", "tool": "nonexistent_tool"})
    assert result["success"] is False


def test_add_finding():
    finder = VulnFinder(target="http://example.com")
    finding = {"type": "XSS", "severity": "HIGH", "url": "http://example.com/xss"}
    finder.add_finding(finding)
    assert len(finder.state.findings) == 1
    assert finder.state.findings[0]["type"] == "XSS"


def test_add_multiple_findings():
    finder = VulnFinder(target="http://example.com")
    finder.add_finding({"type": "XSS", "severity": "HIGH"})
    finder.add_finding({"type": "SQLi", "severity": "CRITICAL"})
    assert len(finder.state.findings) == 2


def test_escalate():
    finder = VulnFinder(target="http://example.com")
    result = finder.escalate({"type": "XSS", "severity": "LOW"})
    assert result is not None
    assert result["expected_severity"] == "CRITICAL"


def test_escalate_no_match():
    finder = VulnFinder(target="http://example.com")
    result = finder.escalate({"type": "UNKNOWN"})
    assert result is None


def test_chain():
    finder = VulnFinder(target="http://example.com")
    findings = [
        {"type": "IDOR", "severity": "LOW"},
        {"type": "info_disclosure", "severity": "LOW"},
    ]
    result = finder.chain(findings)
    assert result is not None
    assert result["combined_severity"] == "CRITICAL"


def test_verify():
    finder = VulnFinder(target="http://example.com")
    finding = {"type": "XSS", "severity": "HIGH"}
    result = finder.verify(finding, "confirmed", "confirmed")
    assert result.verified is True


def test_get_status():
    finder = VulnFinder(target="http://example.com")
    # Manually set state to avoid network
    finder.state.status = MissionStatus.RECON
    finder.state.assets = {"endpoints": []}
    status = finder.get_status()
    assert status["target"] == "http://example.com"
    assert status["status"] == "recon"
    assert status["findings_count"] == 0
    assert status["steps"] == 0


def test_should_continue():
    finder = VulnFinder(target="http://example.com", max_steps=10)
    assert finder.should_continue() is True
    finder.state.steps = 10
    assert finder.should_continue() is False


def test_should_continue_budget():
    finder = VulnFinder(target="http://example.com", budget_limit=10.0)
    finder.state.cost = 9.5
    assert finder.should_continue() is False


def test_should_continue_cost_at_limit():
    finder = VulnFinder(target="http://example.com", budget_limit=10.0)
    finder.state.cost = 10.0
    assert finder.should_continue() is False


def test_knowledge_graph_populated():
    finder = VulnFinder(target="http://example.com")
    finder.add_finding({"type": "XSS", "severity": "HIGH"})
    assert len(finder.kg.nodes) == 1
