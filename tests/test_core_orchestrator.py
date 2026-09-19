"""Tests for elengenix.agent.compat — scan wrappers over VulnAgent.

Covers the relocation of the former ``core/orchestrator.py`` shim: scope
helpers now come from ``elengenix.scope`` and the scan wrappers live in
``elengenix.agent.compat``.
"""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest


class TestScopeHelpers:
    def test_is_in_scope_importable(self):
        from elengenix.scope import is_in_scope

        assert callable(is_in_scope)

    def test_is_valid_target_importable(self):
        from elengenix.scope import is_valid_target

        assert callable(is_valid_target)

    def test_normalize_target_importable(self):
        from elengenix.scope import normalize_target

        assert callable(normalize_target)

    def test_scope_manager_importable(self):
        from elengenix.scope import ScopeManager

        assert ScopeManager is not None


class TestRunStandardScan:
    def test_run_standard_scan_success(self):
        mock_report = MagicMock()
        mock_report.render.return_value = "Report content"
        mock_agent = MagicMock()
        mock_agent.hunt.return_value = mock_report

        with (
            patch("elengenix.agent.VulnAgent", return_value=mock_agent),
            patch("tools.universal_ai_client.create_default_client"),
            patch("elengenix.agent.memory.AgentMemory"),
        ):
            from elengenix.agent.compat import run_standard_scan

            result = run_standard_scan("example.com")
            assert result == "Report content"

    def test_run_standard_scan_failure_returns_none(self):
        with (
            patch("elengenix.agent.VulnAgent", side_effect=Exception("Boom")),
            patch("tools.universal_ai_client.create_default_client"),
            patch("elengenix.agent.memory.AgentMemory"),
        ):
            from elengenix.agent.compat import run_standard_scan

            result = run_standard_scan("example.com")
            assert result is None

    def test_run_standard_scan_with_params(self):
        mock_agent = MagicMock()
        mock_report = MagicMock()
        mock_report.render.return_value = "Report"
        mock_agent.hunt.return_value = mock_report

        with (
            patch("elengenix.agent.VulnAgent", return_value=mock_agent) as MockVA,
            patch("tools.universal_ai_client.create_default_client"),
            patch("elengenix.agent.memory.AgentMemory"),
        ):
            from elengenix.agent.compat import run_standard_scan

            run_standard_scan("test.com", rate_limit=10, timeout=300, use_registry=False)
            MockVA.assert_called_once()
            # Check VulnAgent constructor args
            args, kwargs = MockVA.call_args
            assert "target" in kwargs or "test.com" in str(args)


class TestOrchestrator:
    def test_orchestrator_importable(self):
        from elengenix.agent.compat import Orchestrator

        assert Orchestrator is not None

    def test_orchestrator_delegates_to_vuln_agent(self):
        import asyncio

        from elengenix.agent.compat import Orchestrator

        orch = Orchestrator("example.com")
        mock_report = MagicMock()
        mock_report.findings = [{"type": "xss"}, {"type": "sqli"}]
        mock_agent = MagicMock()
        mock_agent.hunt.return_value = mock_report

        with (
            patch("elengenix.agent.VulnAgent", return_value=mock_agent),
            patch("tools.universal_ai_client.create_default_client"),
            patch("elengenix.agent.memory.AgentMemory"),
        ):
            findings = asyncio.run(orch.run_quick_scan())

        assert findings == [{"type": "xss"}, {"type": "sqli"}]
