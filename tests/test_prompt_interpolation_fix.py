"""Tests for prompt interpolation fixes in agent_universal.py."""

import sys
from pathlib import Path

# Add project root to path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


def test_build_research_prompt_interpolates():
    """Verify research prompt interpolates variables correctly."""
    from agents.agent_universal import _build_research_prompt
    result = _build_research_prompt("test input", "now context")
    assert "{user_input}" not in result, "user_input placeholder not interpolated"
    assert "{now_context}" not in result, "now_context placeholder not interpolated"
    assert "test input" in result, "user_input value not in prompt"
    assert "now context" in result, "now_context value not in prompt"


def test_build_bug_bounty_prompt_interpolates():
    """Verify bug bounty prompt interpolates variables correctly."""
    from agents.agent_universal import _build_bug_bounty_prompt
    # Mock dependencies
    class MockRegistry:
        def list_available_tools(self):
            return {}
    class MockSkillRegistry:
        def list_available_skills(self):
            return []
        def get_missing_skills(self):
            return []
    result = _build_bug_bounty_prompt(
        "test input", "now context", "target.com", 
        None, None, MockSkillRegistry()
    )
    assert "{user_input}" not in result, "user_input placeholder not interpolated"
    assert "{now_context}" not in result, "now_context placeholder not interpolated"
    assert "{target}" not in result, "target placeholder not interpolated"
    assert "target.com" in result, "target value not in prompt"


def test_build_general_prompt_interpolates():
    """Verify general prompt interpolates variables correctly."""
    from agents.agent_universal import _build_general_prompt
    result = _build_general_prompt("test input", "now context")
    assert "{user_input}" not in result, "user_input placeholder not interpolated"
    assert "{now_context}" not in result, "now_context placeholder not interpolated"
    assert "now context" in result, "now_context value not in prompt"
