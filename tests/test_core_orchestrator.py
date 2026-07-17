"""Tests for core/orchestrator.py — Deprecated compat shim."""
from __future__ import annotations

import warnings
from unittest.mock import MagicMock, patch

import pytest


class TestReExports:
    def test_is_in_scope_reexported(self):
        from core.orchestrator import is_in_scope

        assert callable(is_in_scope)

    def test_is_valid_target_reexported(self):
        from core.orchestrator import is_valid_target

        assert callable(is_valid_target)

    def test_normalize_target_reexported(self):
        from core.orchestrator import normalize_target

        assert callable(normalize_target)

    def test_scope_manager_reexported(self):
        from core.orchestrator import ScopeManager

        assert ScopeManager is not None

    def test_deprecation_warning_on_import(self):
        """Importing core.orchestrator should trigger DeprecationWarning."""
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            import importlib
            import core.orchestrator
            importlib.reload(core.orchestrator)
            deprecation = [x for x in w if issubclass(x.category, DeprecationWarning)]
            assert len(deprecation) >= 1
            assert "deprecated" in str(deprecation[0].message).lower()


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
            from core.orchestrator import run_standard_scan

            result = run_standard_scan("example.com")
            assert result == "Report content"

    def test_run_standard_scan_failure_returns_none(self):
        with (
            patch("elengenix.agent.VulnAgent", side_effect=Exception("Boom")),
            patch("tools.universal_ai_client.create_default_client"),
            patch("elengenix.agent.memory.AgentMemory"),
        ):
            from core.orchestrator import run_standard_scan

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
            from core.orchestrator import run_standard_scan

            run_standard_scan("test.com", rate_limit=10, timeout=300, use_registry=False)
            MockVA.assert_called_once()
            # Check VulnAgent constructor args
            args, kwargs = MockVA.call_args
            assert "target" in kwargs or "test.com" in str(args)


class TestOrchestrator:
    def test_orchestrator_deprecated(self):
        with warnings.catch_warnings(record=True):
            warnings.simplefilter("always")
            from core.orchestrator import Orchestrator
            assert Orchestrator is not None
