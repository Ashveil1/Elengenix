"""tests/test_vuln_finder_integration.py — Integration test for VulnFinder full flow."""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from tools.vuln_finder import VulnFinder, MissionStatus


def test_full_flow():
    finder = VulnFinder(target="http://test.example.com", max_steps=50)

    # 1. Recon (may fail on network — that's OK, it sets status and returns assets)
    assets = finder.recon()
    assert finder.state.status == MissionStatus.RECON
    assert assets["target"] == "http://test.example.com"

    # 2. Add some endpoints manually and plan
    finder.state.assets["endpoints"] = ["/api/users", "/api/admin", "/login"]
    plan = finder.plan()
    assert finder.state.status == MissionStatus.PLANNING
    assert len(plan) == 3

    # 3. Execute an attack path (no tool — returns failure gracefully)
    result = finder.execute(plan[0])
    assert result["success"] is False  # no tool specified
    steps_after_execute = finder.state.steps

    # 4. Add findings
    finding1 = {"type": "IDOR", "severity": "LOW", "url": "/api/users/1"}
    finding2 = {"type": "info_disclosure", "severity": "LOW", "url": "/api/admin"}
    finder.add_finding(finding1)
    finder.add_finding(finding2)
    assert len(finder.state.findings) == 2

    # 5. Try chaining
    chain_result = finder.chain(finder.state.findings)
    assert chain_result is not None
    assert chain_result["combined_severity"] == "CRITICAL"

    # 6. Try escalation
    esc_result = finder.escalate({"type": "XSS", "severity": "LOW"})
    assert esc_result is not None
    assert esc_result["expected_severity"] == "CRITICAL"

    # 7. Verify finding (mocked)
    from unittest.mock import patch
    from tools.verification_engine import VerificationResult
    with patch.object(finder.verification, 'verify_with_consensus') as mock_v:
        mock_v.return_value = VerificationResult(
            finding=finding1, verified=True, consensus_verdict="confirmed",
            severity="LOW", model_votes=[], requires_human_review=False,
            confidence=0.95, consensus_strength=1.0
        )
        verification = finder.verify(finding1)
        assert verification.verified is True
        assert verification.confidence == 0.95

    # 8. Check status
    status = finder.get_status()
    assert status["target"] == "http://test.example.com"
    assert status["findings_count"] == 2
    assert status["steps"] == steps_after_execute


def test_full_flow_budget_exhausted():
    finder = VulnFinder(target="http://test.example.com", budget_limit=1.0)
    # Manually set budget near limit (avoid network recon)
    finder.state.status = MissionStatus.RECON
    finder.state.assets = {"endpoints": []}
    finder.state.cost = 0.95
    assert finder.should_continue() is False


def test_full_flow_max_steps():
    finder = VulnFinder(target="http://test.example.com", max_steps=3)
    # Manually set up state (avoid network)
    finder.state.status = MissionStatus.EXECUTING
    for i in range(3):
        finder.execute({"url": f"http://test.example.com/page{i}"})
    assert finder.should_continue() is False


def test_full_flow_escalation_and_chain_together():
    finder = VulnFinder(target="http://test.example.com")
    # Add findings that can both chain and escalate
    finder.add_finding({"type": "IDOR", "severity": "LOW"})
    finder.add_finding({"type": "info_disclosure", "severity": "LOW"})
    finder.add_finding({"type": "XSS", "severity": "LOW"})

    # Chain: IDOR + info_disclosure
    chain_result = finder.chain(
        [
            {"type": "IDOR", "severity": "LOW"},
            {"type": "info_disclosure", "severity": "LOW"},
        ]
    )
    assert chain_result is not None

    # Escalate: XSS
    esc_result = finder.escalate({"type": "XSS", "severity": "LOW"})
    assert esc_result is not None

    # Verify all three (mocked)
    from unittest.mock import patch
    from tools.verification_engine import VerificationResult

    with patch.object(finder.verification, 'verify_with_consensus') as mock_v:
        mock_v.side_effect = [
            VerificationResult(
                finding=finder.state.findings[0], verified=True,
                consensus_verdict="confirmed", severity="LOW",
                model_votes=[], requires_human_review=False,
                confidence=0.9, consensus_strength=1.0
            ),
            VerificationResult(
                finding=finder.state.findings[1], verified=False,
                consensus_verdict="no_consensus", severity="LOW",
                model_votes=[], requires_human_review=True,
                confidence=0.4, consensus_strength=0.0
            ),
            VerificationResult(
                finding=finder.state.findings[2], verified=False,
                consensus_verdict="false_positive", severity="LOW",
                model_votes=[], requires_human_review=False,
                confidence=0.1, consensus_strength=0.0
            ),
        ]
        v1 = finder.verify(finder.state.findings[0])
        v2 = finder.verify(finder.state.findings[1])
        v3 = finder.verify(finder.state.findings[2])

        assert v1.verified is True
        assert v2.verified is False  # disagreement
        assert v2.requires_human_review is True
        assert v3.verified is False
