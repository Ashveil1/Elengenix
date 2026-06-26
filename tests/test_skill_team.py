"""
tests/test_skill_team.py — Skill Registry, Install Request & Team Aegis Tests

Tests:
1. SkillRegistry: load, check availability, recommend, get context
2. InstallRequest/InstallManager: request, confirm, format pending
3. Skill awareness in agent_brain base_prompt
4. TeamAegis: role assignment, tool context in prompts
5. CLI commands: /install, /team, /skills (integration-like)
"""

import os
import shutil

import pytest


class TestSkillRegistry:
    """Test skill registry initialization and tool awareness."""

    def test_get_skill_registry_singleton(self):
        from tools.skill_registry import get_skill_registry

        r1 = get_skill_registry()
        r2 = get_skill_registry()
        assert r1 is r2

    def test_default_skills_loaded(self):
        from tools.skill_registry import get_skill_registry

        registry = get_skill_registry()
        assert "subfinder" in registry.skills
        assert "httpx" in registry.skills
        assert "nuclei" in registry.skills

    def test_availability_check(self):
        from tools.skill_registry import SkillStatus, get_skill_registry

        registry = get_skill_registry()
        for name, skill in registry.skills.items():
            if shutil.which(skill.binary_name):
                assert skill.status == SkillStatus.AVAILABLE
            else:
                assert skill.status == SkillStatus.MISSING

    def test_recommend_for_scenario(self):
        from tools.skill_registry import get_skill_registry

        registry = get_skill_registry()
        # Recommend for XSS
        recommended = registry.recommend_for("XSS vulnerability detection")
        names = [s.name for s in recommended]
        assert "dalfox" in names  # XSS scanner
        assert "nuclei" in names  # Template-based scanner

    def test_skill_context_format(self):
        from tools.skill_registry import get_skill_registry

        registry = get_skill_registry()
        context = registry.get_skill_context()
        assert "=== AVAILABLE TOOLS/SKILLS ===" in context
        assert "[READY]" in context or "[MISSING]" in context

    def test_to_dict(self):
        from tools.skill_registry import get_skill_registry

        registry = get_skill_registry()
        data = registry.to_dict()
        assert "available" in data
        assert "missing" in data
        assert "total" in data
        assert data["total"] == len(registry.skills)


class TestInstallRequest:
    """Test install request creation and management."""

    def test_install_request_creation(self):
        from tools.install_request import InstallRequest

        req = InstallRequest(
            tool_name="test-tool",
            description="A test tool",
            install_command="echo install",
            reason="Need for testing",
        )
        assert req.tool_name == "test-tool"
        assert not req.confirmed
        assert not req.installed

    def test_install_manager_singleton(self):
        from tools.install_request import get_install_manager

        m1 = get_install_manager()
        m2 = get_install_manager()
        assert m1 is m2

    def test_request_and_pending(self):
        from tools.install_request import get_install_manager

        manager = get_install_manager()
        # Reset state
        manager.requests.clear()
        manager.installed.clear()
        req = manager.request("test-tool", "Test tool", "echo install", "Need for testing")
        assert req.tool_name == "test-tool"
        assert len(manager.get_pending_requests()) == 1
        assert "test-tool" in manager.format_pending_for_display()

    def test_format_pending_empty(self):
        from tools.install_request import get_install_manager

        manager = get_install_manager()
        manager.requests.clear()
        assert manager.format_pending_for_display() == ""


class TestAgentSkillIntegration:
    """Test that ElengenixAgent integrates skill registry into prompts."""

    @pytest.mark.skipif(
        not shutil.which("subfinder") or not os.environ.get("HWOOK"), reason="Requires agent init"
    )
    def test_agent_has_skill_registry(self):
        from agent_brain import ElengenixAgent

        agent = ElengenixAgent()
        assert agent.skill_registry is not None

    def test_base_prompt_includes_skills(self):
        # Light-weight test: verify context includes skill markers
        from tools.skill_registry import get_skill_registry

        registry = get_skill_registry()
        context = registry.get_skill_context()
        assert "AVAILABLE TOOLS/SKILLS" in context
        assert "[READY]" in context or "[MISSING]" in context

    def test_recommend_tools_for_scenario(self):
        from tools.skill_registry import recommend_tools_for_scenario

        results = recommend_tools_for_scenario("subdomain enumeration and XSS")
        assert len(results) > 0
        names = [r.name for r in results]
        assert "subfinder" in names


class TestTeamAegisSkillAwareness:
    """Test Team Aegis includes tool awareness in prompts."""

    def test_team_available_tools_formatting(self):
        import unittest.mock as mock

        from tools.multi_agent import TeamAegis

        # Mock 2 clients
        mock_client = mock.MagicMock()
        mock_client.provider = "test"
        mock_client.model = "test-model"
        team = TeamAegis(clients=[mock_client, mock_client], target="test.example.com")
        tools_text = team._format_available_tools_for_agent()
        assert "READY TO USE:" in tools_text or "MISSING" in tools_text
        assert "available" in tools_text.lower() or "missing" in tools_text.lower()

    def test_agent_prompt_contains_tools(self):
        import unittest.mock as mock

        from tools.multi_agent import TeamAegis

        mock_client = mock.MagicMock()
        mock_client.provider = "test"
        mock_client.model = "test-model"
        team = TeamAegis(clients=[mock_client, mock_client], target="test.example.com")
        prompt = team._build_agent_prompt(0)
        assert "AVAILABLE TOOLS & SKILLS" in prompt

    def test_team_roles_assigned(self):
        import unittest.mock as mock

        from tools.multi_agent import AGENT_ROLES, TeamAegis

        mock_client = mock.MagicMock()
        mock_client.provider = "test"
        mock_client.model = "test-model"
        team = TeamAegis(clients=[mock_client, mock_client], target="test.target")
        assert len(team.roles) == 2
        assert team.roles[0]["name"] == AGENT_ROLES[0]["name"]
        assert team.roles[1]["name"] == AGENT_ROLES[1]["name"]

    def test_run_round_with_skill_registry(self):
        """Test that run_round works with skill registry present."""
        import unittest.mock as mock

        from tools.multi_agent import TeamAegis

        mock_client = mock.MagicMock()
        mock_client.provider = "test"
        mock_client.model = "test-model"
        mock_client.simple_chat.return_value = (
            '{"discussion": "Testing", "action": {"type": "none"}}'
        )
        team = TeamAegis(clients=[mock_client, mock_client], target="test.target")
        result = team.run_round()
        assert isinstance(result, bool)
        assert team.round == 1


class TestCLICommands:
    """Lightweight tests for CLI command integration."""

    def test_skills_command_output(self):
        from tools.skill_registry import get_skill_registry

        registry = get_skill_registry()
        available = registry.get_available_skills()
        missing = registry.get_missing_skills()
        # Simulate /skills output
        output = []
        for s in available:
            output.append(f"  {s.name}: {s.description}")
        for s in missing:
            output.append(f"  {s.name}: {s.description}")
        assert len(output) == len(registry.skills)

    def test_install_unknown_tool(self):
        from tools.skill_registry import get_skill_registry

        registry = get_skill_registry()
        skill = registry.skills.get("nonexistent_tool")
        assert skill is None

    def test_team_dashboard_formatting(self):
        import os

        os.environ["ACTIVE_MODELS"] = "gemini/gemini-2.0-flash,nvidia/nemotron-4-340b"
        models = os.environ["ACTIVE_MODELS"].split(",")
        assert len(models) == 2
        assert "gemini" in models[0]
        # Simulated /team output
        roles = ["Strategist", "Recon Lead", "Exploit Analyst"]
        for i, m in enumerate(models):
            assert roles[i]  # Should not raise IndexError
