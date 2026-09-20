"""Regression tests for CLI command/shortcut routing.

Locks in three routing fixes:

- Every :data:`CommandSimplifier.SHORTCUTS` entry must resolve to a command
  that ``main.py`` actually dispatches on. The former bug routed ``swarm``
  to a *phantom* command which then fell through the bare-target branch and
  became an attempt to scan a domain literally named ``swarm``.
- One canonical entry point per destination. The TUI used to be reachable
  via five names (``tui``/``cli``/``universal``/``cli-textual``/``clitest``)
  and the line-mode AI chat via four (``hack``/``ai``/``learn``/
  ``cli-legacy``). Only ``tui`` and ``hack`` remain — the duplicates are
  removed, not aliased.
- The specific mappings stay stable: ``swarm``/``batch`` -> ``autonomous``
  (Team Aegis multi-agent mode).
"""

from __future__ import annotations

import ast
from pathlib import Path
from types import SimpleNamespace

from tools.auto_detector import CommandSimplifier

MAIN_PY = Path(__file__).resolve().parent.parent / "main.py"

#: Names that used to be duplicate entry points and must stay removed.
REMOVED_DUPLICATES = {
    "ai",
    "cli",
    "universal",
    "cli-textual",
    "clitest",
    "cli-legacy",
}


def _handled_commands() -> set[str]:
    """Extract every command main.py dispatches on via ``args.command ==/in``."""
    tree = ast.parse(MAIN_PY.read_text(encoding="utf-8"))
    handled: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Compare):
            continue
        left = node.left
        if not (isinstance(left, ast.Attribute) and left.attr == "command"):
            continue
        for op, comp in zip(node.ops, node.comparators):
            if isinstance(op, ast.Eq) and isinstance(comp, ast.Constant):
                handled.add(comp.value)
            elif isinstance(op, ast.In) and isinstance(comp, (ast.Tuple, ast.List)):
                handled |= {e.value for e in comp.elts if isinstance(e, ast.Constant)}
    return handled


def _declared_commands() -> set[str]:
    """Extract every command listed in main.py's ``command_choices``."""
    tree = ast.parse(MAIN_PY.read_text(encoding="utf-8"))
    declared: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for t in node.targets:
                if (
                    isinstance(t, ast.Name)
                    and t.id == "command_choices"
                    and isinstance(node.value, ast.List)
                ):
                    declared |= {
                        e.value for e in node.value.elts if isinstance(e, ast.Constant)
                    }
    return declared


class TestShortcutTargetsHaveHandlers:
    def test_every_shortcut_target_has_a_handler(self):
        handled = _handled_commands()
        assert handled, "failed to extract handled commands from main.py"
        for shortcut, resolved in CommandSimplifier.SHORTCUTS.items():
            target = resolved.split()[0]
            assert target in handled, (
                f"shortcut '{shortcut}' resolves to command '{target}', which has "
                f"no handler in main.py (phantom-command routing bug)"
            )

    def test_hack_is_canonical_chat_command_not_shortcut(self):
        """The chat used to be reachable via hack->ai expansion; now hack is
        the command itself and the ``ai`` alias is gone."""
        assert "hack" not in CommandSimplifier.SHORTCUTS
        assert "learn" not in CommandSimplifier.SHORTCUTS
        assert "hack" in _handled_commands()

    def test_swarm_and_batch_route_to_autonomous(self):
        assert CommandSimplifier.SHORTCUTS["swarm"] == "autonomous"
        assert CommandSimplifier.SHORTCUTS["batch"] == "autonomous"


class TestDeclaredCommandsAreRoutable:
    def test_every_declared_command_has_a_handler_or_shortcut(self):
        """A declared command with no handler and no shortcut is a phantom:
        it passes validation, then silently does nothing (the former `pdf` bug)."""
        special = {"auto", "help", "welcome"}
        routable = _handled_commands() | set(CommandSimplifier.SHORTCUTS) | special
        phantom = _declared_commands() - routable
        assert not phantom, (
            f"declared commands with no handler and no shortcut: {sorted(phantom)}"
        )


class TestNoDuplicateEntryPoints:
    def test_removed_duplicate_commands_are_gone(self):
        """tui and hack are the single entry points; the old aliases must not
        creep back into the declared command list."""
        declared = _declared_commands()
        survivors = declared & REMOVED_DUPLICATES
        assert not survivors, (
            f"duplicate entry points came back in command_choices: {sorted(survivors)}"
        )


class TestApplyToArgs:
    def test_swarm_resolves_to_handled_command(self):
        args = SimpleNamespace(command="swarm")
        CommandSimplifier.apply_to_args(args)
        assert args.command == "autonomous"
        assert args.command in _handled_commands()

    def test_hack_passes_through_as_handled_command(self):
        args = SimpleNamespace(command="hack")
        CommandSimplifier.apply_to_args(args)
        assert args.command == "hack"
        assert args.command in _handled_commands()

    def test_scan_shortcut_with_flags(self):
        args = SimpleNamespace(command="bb", phase=None, interactive=None)
        CommandSimplifier.apply_to_args(args)
        assert args.command == "scan"
        assert args.phase == "bola"
