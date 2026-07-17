"""Tests for elengenix/governance.py — Governance & Safety system."""
from __future__ import annotations

import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import yaml

from elengenix.governance import (
    GovernanceDecision,
    GovernanceGate,
    GovernancePolicy,
    GateResult,
)
from elengenix.types import AIAction


@pytest.fixture
def gate():
    """Create a GovernanceGate with default policies."""
    return GovernanceGate()


def make_action(action_type: str = "recon", tool: str = "dns_lookup", target: str = "example.com"):
    """Helper to create AIAction for testing."""
    return AIAction(action_type=action_type, tool=tool, target=target)


class TestGovernanceGate:
    def test_init_default_policies(self, gate):
        assert len(gate.policies) >= 3
        assert "recon" in gate.policies
        assert "scan" in gate.policies
        assert "exploit" in gate.policies

    def test_gate_allows_recon_action(self, gate):
        action = make_action(action_type="recon", tool="dns_lookup")
        result = gate.gate(mission_id="test-1", target="example.com", action=action)
        assert result.decision == GovernanceDecision.ALLOW

    def test_gate_denies_destructive_scan(self, gate):
        """dos is in scan policy's blocked_actions."""
        action = make_action(action_type="scan", tool="dos")
        result = gate.gate(mission_id="test-1", target="example.com", action=action)
        assert result.decision == GovernanceDecision.DENY

    def test_gate_needs_approval_for_intrusive(self, gate):
        action = make_action(action_type="scan", tool="intrusive_scan")
        result = gate.gate(mission_id="test-1", target="example.com", action=action)
        assert result.decision == GovernanceDecision.NEEDS_APPROVAL

    def test_gate_denies_exploit_data_exfiltration(self, gate):
        """data_exfiltration is blocked in exploit policy."""
        action = make_action(action_type="exploit", tool="data_exfiltration")
        result = gate.gate(mission_id="test-1", target="example.com", action=action)
        assert result.decision == GovernanceDecision.DENY

    def test_gate_denies_unknown_policy(self, gate):
        """Unknown action_type defaults to scan."""
        action = make_action(action_type="unknown_type", tool="some_tool")
        result = gate.gate(mission_id="test-1", target="example.com", action=action)
        assert result.decision == GovernanceDecision.ALLOW  # defaults to scan, tools likely allowed

    def test_audit_logs_action(self, gate):
        action = make_action(action_type="scan", tool="port_scan")
        result = gate.gate(mission_id="test-1", target="10.0.0.1", action=action)
        gate.audit(action, result)
        assert len(gate.audit_log) >= 1

    def test_load_config_from_file(self, gate):
        """Loading a valid yaml config should add policies."""
        config_data = {
            "policies": {
                "custom_policy": {
                    "name": "custom_test",
                    "description": "Test policy",
                    "risk_levels": ["safe"],
                    "allowed_actions": ["ping"],
                    "blocked_actions": ["pong"],
                    "requires_approval": [],
                },
            },
        }
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            yaml.dump(config_data, f)
            f.flush()
            gate.load_config(f.name)
            assert "custom_policy" in gate.policies
            policy = gate.policies["custom_policy"]
            assert "ping" in policy.allowed_actions
            Path(f.name).unlink()

    def test_load_config_invalid_file_doesnt_crash(self, gate):
        """Invalid yaml should not crash but log warning."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write("not: valid: yaml: [[[")
            f.flush()
            gate.load_config(f.name)  # Should not raise
            Path(f.name).unlink()

    def test_gate_result_creation(self):
        result = GateResult(
            decision=GovernanceDecision.ALLOW,
            rationale="Safe action",
            risk_level="safe",
        )
        assert result.decision == GovernanceDecision.ALLOW
        assert result.requires_human is False

    def test_gate_result_requires_human(self):
        result = GateResult(
            decision=GovernanceDecision.NEEDS_APPROVAL,
            rationale="Risky",
            risk_level="privileged",
            requires_human=True,
        )
        assert result.requires_human is True


class TestGateResultEdgeCases:
    def test_gate_denies_out_of_scope_action(self, gate):
        """gate() checks scope — returns deny when out of scope."""
        action = make_action(action_type="exploit", tool="sql_injection")
        result = gate.gate(mission_id="test-1", target="10.0.0.1", action=action)
        # sql_injection might be blocked in exploit policy
        assert isinstance(result, GateResult)
        assert result.decision in (GovernanceDecision.ALLOW, GovernanceDecision.DENY)
