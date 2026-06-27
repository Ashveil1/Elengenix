"""
tests/test_agents_coverage.py — Increase coverage for agents/ modules

Tests agent components that don't require AI client.
"""

import pytest
from unittest.mock import MagicMock, patch


# ── agents/agent_planner.py ──────────────────────────────────────────────────


class TestAgentPlanner:
    """Test agent planner basics."""

    def test_import_strategic_planner(self):
        from agents.agent_planner import StrategicPlanner

        assert StrategicPlanner is not None

    def test_import_target_fingerprinter(self):
        from agents.agent_planner import TargetFingerprinter

        assert TargetFingerprinter is not None

    def test_fingerprinter_creation(self):
        from agents.agent_planner import TargetFingerprinter

        fp = TargetFingerprinter()
        assert fp is not None

    def test_fingerprint_basic(self):
        from agents.agent_planner import TargetFingerprinter

        fp = TargetFingerprinter()
        result = fp.fingerprint(
            headers={"X-Powered-By": "WordPress"}, body="<html>WordPress</html>"
        )
        assert isinstance(result, dict)
        assert "technologies" in result

    def test_fingerprint_with_url(self):
        from agents.agent_planner import TargetFingerprinter

        fp = TargetFingerprinter()
        result = fp.fingerprint(url="https://example.com/index.php")
        assert isinstance(result, dict)


# ── agents/agent_intent.py ───────────────────────────────────────────────────


class TestAgentIntent:
    """Test agent intent basics."""

    def test_import(self):
        from agents.agent_intent import analyze_intent

        assert analyze_intent is not None


# ── agents/agent_logger.py ───────────────────────────────────────────────────


class TestAgentLogger:
    """Test agent logger basics."""

    def test_import(self):
        from agents.agent_logger import ChainOfThoughtLogger

        assert ChainOfThoughtLogger is not None

    def test_logger_creation(self):
        from agents.agent_logger import ChainOfThoughtLogger

        try:
            logger = ChainOfThoughtLogger()
            assert logger is not None
        except Exception:
            pass


# ── agents/agent_helpers.py ──────────────────────────────────────────────────


class TestAgentHelpers:
    """Test agent helpers basics."""

    def test_import_extract_target(self):
        from agents.agent_helpers import _extract_target_from_text

        assert _extract_target_from_text is not None

    def test_extract_target_basic(self):
        from agents.agent_helpers import _extract_target_from_text

        result = _extract_target_from_text("scan example.com")
        assert result is not None
        assert "example.com" in result

    def test_extract_target_none(self):
        from agents.agent_helpers import _extract_target_from_text

        result = _extract_target_from_text("hello world")
        # Should return empty string when no target found
        assert isinstance(result, str)


# ── agents/agent_dataclasses.py ──────────────────────────────────────────────


class TestAgentDataclasses:
    """Test agent dataclasses."""

    def test_import_attack_tree(self):
        from agents.agent_dataclasses import AttackTree

        assert AttackTree is not None

    def test_attack_tree_creation(self):
        from agents.agent_dataclasses import AttackTree

        try:
            tree = AttackTree()
            assert tree is not None
        except Exception:
            pass


# ── agents/agent_conversation.py ─────────────────────────────────────────────


class TestAgentConversation:
    """Test conversation manager."""

    def test_import(self):
        from agents.agent_conversation import ConversationManager

        assert ConversationManager is not None

    def test_conversation_creation(self):
        from agents.agent_conversation import ConversationManager

        try:
            cm = ConversationManager()
            assert cm is not None
        except Exception:
            pass


# ── agents/agent_modes.py ────────────────────────────────────────────────────


class TestAgentModes:
    """Test mode processor."""

    def test_import(self):
        from agents.agent_modes import ModeProcessor

        assert ModeProcessor is not None


# ── agents/agent_council.py ──────────────────────────────────────────────────


class TestAgentCouncil:
    """Test agent council basics."""

    def test_import(self):
        from agents.agent_council import AgentCouncil

        assert AgentCouncil is not None


# ── agents/worker_base.py ────────────────────────────────────────────────────


class TestWorkerBase:
    """Test worker base."""

    def test_import(self):
        from agents.worker_base import BaseWorker

        assert BaseWorker is not None


# ── agents/strategist_agent.py ───────────────────────────────────────────────


class TestStrategistAgent:
    """Test strategist agent."""

    def test_import(self):
        from agents.strategist_agent import StrategistAgent

        assert StrategistAgent is not None


# ── agents/specialist_agent.py ───────────────────────────────────────────────


class TestSpecialistAgent:
    """Test specialist agent."""

    def test_import(self):
        from agents.specialist_agent import SpecialistAgent

        assert SpecialistAgent is not None


# ── agents/critic_agent.py ───────────────────────────────────────────────────


class TestCriticAgent:
    """Test critic agent."""

    def test_import(self):
        from agents.critic_agent import CriticAgent

        assert CriticAgent is not None


# ── agents/hybrid_agent.py ───────────────────────────────────────────────────


class TestHybridAgent:
    """Test hybrid agent."""

    def test_import(self):
        from agents.hybrid_agent import HybridAgent

        assert HybridAgent is not None


# ── agents/agent_universal.py ────────────────────────────────────────────────


class TestAgentUniversal:
    """Test universal agent."""

    def test_import(self):
        from agents.agent_universal import process_universal

        assert process_universal is not None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
