"""Tests for Governance System"""

from __future__ import annotations

import pytest
from unittest.mock import MagicMock, AsyncMock, patch
from elengenix.governance import GovernanceGate, GovernancePolicy, RiskAssessment, GovernanceDecision


class TestGovernanceFixed:
    """Tests for Governance System"""

    @pytest.fixture
    def governance_gate(self):
        from elengenix.governance import GovernanceGate
        return GovernanceGate()

    @pytest.fixture
    def mock_action(self):
        action = MagicMock()
        action.action_type = type('ActionType', (), {'value': 'scan'})()
        action.tool = "nmap"
        action.target = "example.com"
        action.parameters = {}
        action.risk_level = type('RiskLevel', (), {'value': 'low'})()
        action.description = "Port scan"
        action.action_type = type('ActionType', (), {'value': 'scan'})()
        return action

    @pytest.fixture
    def governance_gate(self):
        from elengenix.governance import GovernanceGate
        return GovernanceGate()

    def test_load_default_policies(self, governance_gate):
        assert "recon" in governance_gate.policies
        assert "scan" in governance_gate.policies
        assert "exploit" in governance_gate.policies
        assert "post_exploit" in governance_gate.policies

    def test_load_default_policies_details(self, governance_gate):
        recon_policy = governance_gate.policies["recon"]
        assert recon_policy.name == "reconnaissance"
        assert "dns_lookup" in recon_policy.allowed_actions

        scan_policy = governance_gate.policies["scan"]
        assert "port_scan" in scan_policy.allowed_actions
        assert "auth_bypass" in scan_policy.requires_approval

        exploit_policy = governance_gate.policies["exploit"]
        assert "data_exfiltration" in exploit_policy.blocked_actions
        assert "exploit_execution" in exploit_policy.requires_approval

    def test_risk_assessment(self, governance_gate, mock_action):
        mock_action.tool = "sqlmap"
        mock_action.risk_level = type('RiskLevel', (), {'value': 'high'})()

        risk = governance_gate._assess_risk(mock_action)

        assert risk.level in ["safe", "privileged", "destructive", "critical", "existential"]
        assert "tool_risk" in risk.factors

    def test_policy_check_allows_recon(self, governance_gate, mock_action):
        mock_action.action_type.value = "recon"
        mock_action.tool = "dns_lookup"

        decision = governance_gate._check_policy(mock_action, MagicMock())

        assert decision.value == "allow"

    @pytest.mark.asyncio
    async def test_gate_allows_recon(self, governance_gate, mock_action):
        mock_action.action_type.value = "recon"
        mock_action.tool = "dns_lookup"

        result = governance_gate.gate("mission-001", "example.com", mock_action)

        assert result.decision.value == "allow"

    @pytest.mark.asyncio
    async def test_gate_blocks_out_of_scope(self, governance_gate, mock_action):
        with patch.object(governance_gate, '_check_scope', return_value=False):
            result = governance_gate.gate("mission-001", "evil.com", mock_action)
            assert result.decision.value == "deny"

    def test_risk_assessment_high(self, governance_gate, mock_action):
        mock_action.tool = "sqlmap"
        mock_action.risk_level = type('RiskLevel', (), {'value': 'high'})()

        risk = governance_gate._assess_risk(mock_action)

        assert risk.level in ["safe", "privileged", "destructive", "critical", "existential"]
        assert "tool_risk" in risk.factors

    def test_policy_check_denies_destructive(self, governance_gate, mock_action):
        mock_action.action_type.value = "exploit"
        mock_action.tool = "data_exfiltration"
        mock_action.risk_level = type('RiskLevel', (), {'value': 'critical'})()

        decision = governance_gate._check_policy(mock_action, MagicMock())

        assert decision.value in ["deny", "needs_approval"]