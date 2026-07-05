"""tests/test_agent_brain_refactored.py — Tests for agent_brain.py new pipeline"""

from unittest.mock import MagicMock, patch

import pytest

from agents.scan_context import ScanContext


# ── Test ScanContext Integration ────────────────────────────────


class TestScanContextIntegration:
    """Test that ScanContext works with agent_brain.py imports."""

    def test_import_scan_context_from_agents(self):
        """Verify ScanContext is importable from the agents package."""
        from agents import ScanContext as ImportedSC

        assert ImportedSC is ScanContext

    def test_scan_context_from_target(self):
        ctx = ScanContext.from_target("example.com", objective="Find SQLi")
        assert ctx.target == "example.com"
        assert ctx.base_url == "http://example.com"
        assert ctx.objective == "Find SQLi"
        assert ctx.report_dir.exists()

    def test_scan_context_with_state_objects(self):
        ctx = ScanContext.from_target("example.com")
        ctx.mission_state = MagicMock()
        ctx.coverage_map = MagicMock()
        ctx.belief_state = MagicMock()
        ctx.negative_results = MagicMock()

        assert ctx.mission_state is not None
        assert ctx.coverage_map is not None

    def test_scan_context_counter_updates(self):
        ctx = ScanContext.from_target("example.com")
        ctx.update_after_step([{"type": "xss"}])
        assert ctx.step_count == 1
        assert ctx.consecutive_no_findings == 0

        ctx.update_after_step([])
        assert ctx.step_count == 2
        assert ctx.consecutive_no_findings == 1


# ── Test Process Query New Method Exists ────────────────────────


class TestProcessQueryNewExists:
    """Verify the new pipeline method exists and is callable."""

    def test_process_query_has_new_pipeline_param(self):
        """Verify process_query accepts use_new_pipeline parameter."""
        from core.brain import ElengenixAgent

        import inspect

        sig = inspect.signature(ElengenixAgent.process_query)
        assert "use_new_pipeline" in sig.parameters

    def test_process_query_new_method_exists(self):
        """Verify _process_query_new method exists."""
        from core.brain import ElengenixAgent

        assert hasattr(ElengenixAgent, "_process_query_new")

    def test_execute_with_governance_method_exists(self):
        """Verify _execute_with_governance method exists."""
        from core.brain import ElengenixAgent

        assert hasattr(ElengenixAgent, "_execute_with_governance")


# ── Test Backward Compatibility ────────────────────────────────


class TestBackwardCompatibility:
    """Verify old imports still work."""

    def test_imports_preserved(self):
        """Verify existing imports from agent_brain still work."""
        from core.brain import ElengenixAgent

        assert ElengenixAgent is not None

    def test_process_query_default_unchanged(self):
        """Verify default behavior (use_new_pipeline=False) is unchanged."""
        from core.brain import ElengenixAgent

        import inspect

        sig = inspect.signature(ElengenixAgent.process_query)
        default = sig.parameters["use_new_pipeline"].default
        assert default is False


# ── Test Module Wiring ─────────────────────────────────────────


class TestModuleWiring:
    """Test that the new modules are properly wired together."""

    def test_prompt_builder_importable(self):
        from agents.prompt_builder import PromptBuilder

        pb = PromptBuilder("test prompt")
        assert pb.base_prompt == "test prompt"

    def test_decision_engine_importable(self):
        from agents.decision_engine import DecisionEngine

        de = DecisionEngine()
        assert de.ai_client is None

    def test_post_processor_importable(self):
        from agents.post_processor import PostExecutionProcessor

        pp = PostExecutionProcessor()
        assert pp.analysis_pipeline is None

    def test_scan_loop_importable(self):
        from agents.scan_loop import ScanLoop

        de = MagicMock()
        pp = MagicMock()
        loop = ScanLoop(de, pp)
        assert loop.decision_engine is de

    def test_all_modules_in_agents_package(self):
        """Verify all new modules are exported from agents package."""
        from agents import (
            Decision,
            DecisionEngine,
            PostExecutionProcessor,
            PromptBuilder,
            ScanContext,
            ScanLoop,
            ScanResult,
        )

        assert ScanContext is not None
        assert PromptBuilder is not None
        assert DecisionEngine is not None
        assert PostExecutionProcessor is not None
        assert ScanLoop is not None
        assert ScanResult is not None
        assert Decision is not None
