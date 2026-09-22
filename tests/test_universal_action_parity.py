"""Bidirectional parity between the advertised action menu and the executor.

The AI's system prompt must never advertise an action the executor cannot
run (phantom capability), and must never hide an action the executor can
run (hidden capability). This file locks that contract for the universal
agent loop:

- ``elengenix.scanning.universal.UNIVERSAL_ACTION_TYPES`` — the menu shown
  to the AI (single source of truth, injected into every prompt variant)
- ``tools.universal_executor.UniversalExecutor.execute_action`` — the real
  dispatch branches
"""

from __future__ import annotations

import re
from pathlib import Path
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
UNIVERSAL_PATH = ROOT / "elengenix" / "scanning" / "universal.py"
EXECUTOR_PATH = ROOT / "tools" / "universal_executor.py"


def _advertised_types() -> set:
    """Action types declared in the canonical menu constant."""
    src = UNIVERSAL_PATH.read_text()
    match = re.search(r"UNIVERSAL_ACTION_TYPES:\s*tuple\s*=\s*\((.*?)\)", src, re.S)
    assert match, "UNIVERSAL_ACTION_TYPES constant not found in universal.py"
    return set(re.findall(r'"([a-z_]+)"', match.group(1)))


def _implemented_types() -> set:
    """Action types actually dispatched (executor branches + loop-level)."""
    src = EXECUTOR_PATH.read_text()
    types = set(re.findall(r'action_type == "([a-z_]+)"', src))
    # "finish" is a control action handled by the universal loop itself
    # (asserted separately by test_finish_handled_by_loop).
    types.add("finish")
    return types


class TestMenuExecutorParity:
    """The core anti-drift contract: advertised == implemented."""

    def test_no_phantom_actions(self):
        """Every advertised action must have a real executor branch."""
        phantom = _advertised_types() - _implemented_types()
        assert not phantom, f"phantom actions (advertised, not implemented): {phantom}"

    def test_no_hidden_capabilities(self):
        """Every executor branch must be advertised to the AI."""
        hidden = _implemented_types() - _advertised_types()
        assert not hidden, f"hidden actions (implemented, not advertised): {hidden}"

    def test_menu_is_completeness_minimum(self):
        """The menu must cover at least the essential action set."""
        essential = {"shell", "run_tool", "ask_user", "finish"}
        assert essential <= _advertised_types()


class TestMenuIntegrity:
    """The menu constant itself must be complete and well-formed."""

    def test_menu_block_lists_every_type(self):
        from elengenix.scanning.universal import (
            _UNIVERSAL_ACTION_MENU,
            UNIVERSAL_ACTION_TYPES,
        )

        for action in UNIVERSAL_ACTION_TYPES:
            assert f"`{action}`" in _UNIVERSAL_ACTION_MENU, (
                f"`{action}` missing from the formatted action menu"
            )

    def test_single_ask_user_branch(self):
        """The executor must have exactly one ask_user branch (the bridge)."""
        src = EXECUTOR_PATH.read_text()
        assert src.count('action_type == "ask_user"') == 1

    def test_ask_user_routes_through_bridge(self):
        """The live ask_user branch must use the real interaction bridge."""
        src = EXECUTOR_PATH.read_text()
        assert "from elengenix.chat.user_interaction import ask_user" in src

    def test_finish_handled_by_loop(self):
        """`finish` is a loop-level action (universal.py), not an executor branch."""
        src = UNIVERSAL_PATH.read_text()
        assert 'if action_type == "finish":' in src


class TestPromptsAdvertiseFullMenu:
    """Every prompt variant shown to the AI must carry the complete menu."""

    def _assert_full_menu(self, prompt: str):
        from elengenix.scanning.universal import UNIVERSAL_ACTION_TYPES

        for action in UNIVERSAL_ACTION_TYPES:
            assert action in prompt, f"action `{action}` missing from prompt"

    def test_research_prompt(self):
        from elengenix.scanning.universal import _build_research_prompt

        prompt = _build_research_prompt("latest CVE news", "Now: 2026")
        self._assert_full_menu(prompt)
        # Mission guidance stays research-focused without starving the menu.
        assert "MUST call search_web" in prompt

    def test_general_prompt(self):
        from elengenix.scanning.universal import _build_general_prompt

        prompt = _build_general_prompt("help me", "Now: 2026")
        self._assert_full_menu(prompt)
        assert "Universal AI Agent" in prompt

    def test_bug_bounty_prompt(self):
        from elengenix.scanning.universal import (
            _build_bug_bounty_prompt,
            UNIVERSAL_ACTION_TYPES,
        )

        skill_registry = Mock()
        skill_registry.list_available_skills.return_value = []
        skill_registry.get_missing_skills.return_value = []

        with patch("elengenix.scanning.universal.registry") as mock_reg:
            mock_reg.list_available_tools.return_value = {}
            prompt = _build_bug_bounty_prompt(
                "scan", "Now: 2026", "example.com", Mock(), Mock(), skill_registry
            )

        for action in UNIVERSAL_ACTION_TYPES:
            assert action in prompt, f"action `{action}` missing from prompt"
        # Autonomy contract: strategist framing, no phase script.
        assert "no fixed phases" in prompt
        assert "FULL autonomy" in prompt
