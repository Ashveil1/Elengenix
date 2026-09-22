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
import re
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


class TestHelpSurfaceTruthfulness:
    def test_help_box_only_advertises_routable_names(self):
        """Every command/shortcut name printed in the help box must actually
        route: the former `hack -> ai` line advertised a removed command and
        `elengenix ai` answered 'Unknown command'."""
        help_text = CommandSimplifier.get_help_text()
        tokens = set(re.findall(r"\[cyan\]([a-z][a-z0-9-]*)\[/cyan\]", help_text))
        tokens.discard("elengenix")
        routable = (
            _handled_commands() | set(CommandSimplifier.SHORTCUTS) | {"auto", "help", "welcome"}
        )
        ghosts = tokens - routable
        assert not ghosts, f"help box advertises non-routable names: {sorted(ghosts)}"


class TestWelcomeWizardPersistsRuntimeConfig:
    """The wizard used to write .config/elengenix/setup.json — a file nothing
    ever read. It must now persist into the runtime config.yaml using the
    exact schema tools.ai_config loads (ai.active_provider + providers).
    """

    def _make_config(self):
        from tools.welcome_wizard import SetupConfig

        return SetupConfig(
            ai_provider="Gemini (Google)",
            ai_model="gemini-3.1-pro",
            default_mode="ai",
            rate_limit=5,
            theme="minimal",
            auto_update=True,
            telemetry=False,
            first_run_complete=True,
        )

    def test_saved_config_is_readable_by_ai_config(self, tmp_path, monkeypatch):
        from tools import ai_config
        from tools.welcome_wizard import WelcomeWizard

        cfg_file = tmp_path / "config.yaml"
        monkeypatch.setenv("ELENGENIX_CONFIG", str(cfg_file))
        try:
            WelcomeWizard()._save_config(self._make_config())
            assert cfg_file.exists(), "wizard did not write the runtime config"

            ai_config.reset_config_cache()
            ai_config.load_config(config_path=cfg_file)
            assert ai_config.get_active_provider() == "gemini"
            assert ai_config.get_provider_config("gemini").get("model") == "gemini-3.1-pro"
        finally:
            ai_config.reset_config_cache()

    def test_get_saved_config_roundtrip(self, tmp_path, monkeypatch):
        from tools.welcome_wizard import WelcomeWizard

        monkeypatch.setenv("ELENGENIX_CONFIG", str(tmp_path / "config.yaml"))
        WelcomeWizard()._save_config(self._make_config())

        saved = WelcomeWizard.get_saved_config()
        assert saved is not None
        assert saved.default_mode == "ai"
        assert saved.ai_provider == "gemini"  # display name canonicalized
        assert saved.ai_model == "gemini-3.1-pro"

    def test_save_preserves_unrelated_sections(self, tmp_path, monkeypatch):
        import yaml

        from tools.welcome_wizard import WelcomeWizard

        cfg_file = tmp_path / "config.yaml"
        monkeypatch.setenv("ELENGENIX_CONFIG", str(cfg_file))
        cfg_file.write_text(yaml.safe_dump({"other": {"keep": True}}))

        WelcomeWizard()._save_config(self._make_config())
        data = yaml.safe_load(cfg_file.read_text())
        assert data["other"] == {"keep": True}
        assert data["ai"]["active_provider"] == "gemini"
