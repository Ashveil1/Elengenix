"""tests/test_executor_freedom.py

Unit tests for the upgraded agent execution layer.

Tests cover:
  - write_script: file creation + execution
  - install_tool: command building for each package manager
  - _prompt_approval: UI output without interactive input
  - Action alias resolution (script, install, write_and_run, etc.)
  - Governance integration: SAFE runs freely, PRIVILEGED triggers approval
  - Destructive commands remain blocked
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import patch

import pytest

# ── Ensure project root is importable ─────────────────────────────────────────
sys.path.insert(0, str(Path(__file__).parent.parent))

from agents.agent_executor import (
    _prompt_approval,
    execute_install_tool,
    execute_shell_command,
    execute_tool,
    execute_write_script,
)
from tools.governance import Governance
from tools.universal_executor import UniversalExecutor

# ── Fixtures ──────────────────────────────────────────────────────────────────


@pytest.fixture()
def gov() -> Governance:
    """Governance with approval required for privileged actions."""
    return Governance(require_approval_high_risk=True)


@pytest.fixture()
def gov_no_approval() -> Governance:
    """Governance that auto-approves privileged actions (CI mode)."""
    return Governance(require_approval_high_risk=False)


# ── write_script ──────────────────────────────────────────────────────────────


class TestWriteScript:
    """Tests for execute_write_script()."""

    def test_python_script_runs_and_returns_output(self, gov: Governance, tmp_path: Path):
        """A Python script written by the AI should execute and return stdout."""
        # Use a unique test-only filename — never a generic name like hello.py
        # which would overwrite real user-created files in data/scripts/.
        test_filename = "_test_write_ok_.py"
        action = {
            "filename": test_filename,
            "code": 'print("WRITE_SCRIPT_OK")',
            "purpose": "Unit test",
        }
        result = execute_write_script(action, gov)
        # Cleanup: remove the generated test file
        scripts_dir = Path(__file__).parent.parent / "data" / "scripts"
        (scripts_dir / test_filename).unlink(missing_ok=True)
        assert "WRITE_SCRIPT_OK" in result

    def test_missing_code_returns_error(self, gov: Governance):
        """An action without 'code' should return a clear error."""
        result = execute_write_script({"filename": "empty.py", "code": ""}, gov)
        assert "[FAIL]" in result
        assert "code" in result.lower()

    def test_auto_detect_python_runner(self, gov: Governance):
        """Runner should be inferred as python3 for .py extension."""
        action = {
            "filename": "test_runner.py",
            "code": 'print("RUNNER_OK")',
        }
        result = execute_write_script(action, gov)
        assert "RUNNER_OK" in result

    def test_auto_detect_bash_runner(self, gov: Governance):
        """Runner should be inferred as bash for .sh extension."""
        action = {
            "filename": "test_runner.sh",
            "code": "echo BASH_RUNNER_OK",
        }
        result = execute_write_script(action, gov)
        assert "BASH_RUNNER_OK" in result

    def test_script_saved_to_data_scripts(self, gov: Governance):
        """Script file must be written to data/scripts/ directory."""
        action = {
            "filename": "persistence_check.py",
            "code": 'print("PERSISTED")',
            "purpose": "Verify persistence",
        }
        execute_write_script(action, gov)
        scripts_dir = Path(__file__).parent.parent / "data" / "scripts"
        assert (scripts_dir / "persistence_check.py").exists()

    def test_execute_tool_dispatches_write_script(self, gov: Governance):
        """execute_tool() must route action='write_script' to the handler."""
        action = {
            "action": "write_script",
            "filename": "dispatch_test.py",
            "code": 'print("DISPATCH_OK")',
        }
        result = execute_tool(action, gov)
        assert "DISPATCH_OK" in result

    def test_alias_script_resolves(self, gov: Governance):
        """Alias 'script' must map to 'write_script'."""
        result = execute_tool(
            {
                "action": "script",
                "filename": "alias_script.py",
                "code": 'print("ALIAS_OK")',
            },
            gov,
        )
        assert "ALIAS_OK" in result

    def test_alias_write_and_run_resolves(self, gov: Governance):
        """Alias 'write_and_run' must map to 'write_script'."""
        result = execute_tool(
            {
                "action": "write_and_run",
                "filename": "alias_war.py",
                "code": 'print("WAR_OK")',
            },
            gov,
        )
        assert "WAR_OK" in result


# ── install_tool ──────────────────────────────────────────────────────────────


class TestInstallTool:
    """Tests for execute_install_tool()."""

    def _mock_shell(self, monkeypatch, expected_cmd_substring: str) -> list[str]:
        """Capture the command passed to execute_safely without running it."""
        captured: list[str] = []

        def fake_exec(cmd, timeout=300, cwd=None):
            captured.append(cmd)
            return {
                "success": True,
                "stdout": f"Installed: {cmd}",
                "stderr": "",
                "exit_code": 0,
                "error": "",
            }

        monkeypatch.setattr("agents.agent_executor.execute_safely", fake_exec)
        return captured

    def test_pip_manager_builds_correct_command(self, gov_no_approval, monkeypatch):
        """pip manager should produce 'pip install <name>'."""
        captured = self._mock_shell(monkeypatch, "pip")
        execute_install_tool(
            {"name": "requests", "manager": "pip", "purpose": "HTTP library"},
            gov_no_approval,
        )
        assert any("pip install requests" in c for c in captured)

    def test_apt_manager_uses_sudo(self, gov_no_approval, monkeypatch):
        """apt manager must use 'sudo apt-get install -y'."""
        captured = self._mock_shell(monkeypatch, "apt")
        execute_install_tool(
            {"name": "nmap", "manager": "apt", "purpose": "Port scanner"},
            gov_no_approval,
        )
        assert any("sudo apt-get install -y nmap" in c for c in captured)

    def test_cargo_manager_builds_correct_command(self, gov_no_approval, monkeypatch):
        """cargo manager should produce 'cargo install <name>'."""
        captured = self._mock_shell(monkeypatch, "cargo")
        execute_install_tool(
            {"name": "feroxbuster", "manager": "cargo", "purpose": "Directory fuzzer"},
            gov_no_approval,
        )
        assert any("cargo install feroxbuster" in c for c in captured)

    def test_npm_manager_uses_global_flag(self, gov_no_approval, monkeypatch):
        """npm manager must use 'npm install -g'."""
        captured = self._mock_shell(monkeypatch, "npm")
        execute_install_tool(
            {"name": "retire", "manager": "npm", "purpose": "JS vulnerability scanner"},
            gov_no_approval,
        )
        assert any("npm install -g retire" in c for c in captured)

    def test_custom_install_cmd_passed_directly(self, gov_no_approval, monkeypatch):
        """If install_cmd is provided it should be used verbatim."""
        captured = self._mock_shell(monkeypatch, "go install")
        custom_cmd = "go install github.com/projectdiscovery/katana/cmd/katana@latest"
        execute_install_tool(
            {"install_cmd": custom_cmd, "purpose": "Web crawler"},
            gov_no_approval,
        )
        assert any(custom_cmd in c for c in captured)

    def test_missing_name_and_cmd_returns_error(self, gov_no_approval):
        """Missing both 'name' and 'install_cmd' should return an error."""
        result = execute_install_tool({"manager": "pip"}, gov_no_approval)
        assert "[FAIL]" in result

    def test_execute_tool_dispatches_install_tool(self, gov_no_approval, monkeypatch):
        """execute_tool() must route action='install_tool' correctly."""
        captured = self._mock_shell(monkeypatch, "pip")
        execute_tool(
            {"action": "install_tool", "name": "httpx", "manager": "pip"},
            gov_no_approval,
        )
        assert any("pip install httpx" in c for c in captured)

    def test_alias_install_resolves(self, gov_no_approval, monkeypatch):
        """Alias 'install' must map to 'install_tool'."""
        captured = self._mock_shell(monkeypatch, "pip")
        execute_tool(
            {"action": "install", "name": "beautifulsoup4", "manager": "pip"},
            gov_no_approval,
        )
        assert any("pip install beautifulsoup4" in c for c in captured)

    def test_alias_install_package_resolves(self, gov_no_approval, monkeypatch):
        """Alias 'install_package' must map to 'install_tool'."""
        captured = self._mock_shell(monkeypatch, "cargo")
        execute_tool(
            {"action": "install_package", "name": "rustscan", "manager": "cargo"},
            gov_no_approval,
        )
        assert any("cargo install rustscan" in c for c in captured)


# ── Governance integration ────────────────────────────────────────────────────


class TestGovernanceIntegration:
    """Verify that Governance gates work correctly with the executor."""

    def test_safe_command_runs_without_approval(self, gov: Governance):
        """Safe commands should never require user approval."""
        result = execute_shell_command("echo SAFE_RUN", gov)
        assert "SAFE_RUN" in result

    def test_destructive_command_is_blocked(self, gov: Governance):
        """Destructive commands (rm -rf /) must be blocked regardless of approval."""
        result = execute_shell_command("rm -rf /", gov)
        assert "[WARN]" in result or "blocked" in result.lower()

    def test_privileged_command_shows_approval_prompt(self, gov: Governance):
        """Privileged commands must surface an approval prompt (not auto-run)."""
        with patch("agents.agent_executor._prompt_approval", return_value=(False, False)) as mock_p:
            result = execute_shell_command(
                "pip install something",
                gov,
                purpose="Install test tool",
                thought="I need this for scanning",
            )
        mock_p.assert_called_once()
        assert "[SKIP]" in result

    def test_privileged_command_runs_when_approved(self, gov: Governance, monkeypatch):
        """When the user approves (y), the privileged command must execute."""
        monkeypatch.setattr("agents.agent_executor._prompt_approval", lambda **_: (True, False))
        monkeypatch.setattr(
            "agents.agent_executor.execute_safely",
            lambda cmd, **_: {
                "success": True,
                "stdout": "APPROVED_RUN",
                "stderr": "",
                "exit_code": 0,
                "error": "",
            },
        )
        result = execute_shell_command("pip install mytool", gov, purpose="Test")
        assert "APPROVED_RUN" in result

    def test_allow_auto_enables_session_flag(self, gov: Governance, monkeypatch):
        """Choosing Allow Auto (a) must set governance.auto_approve_privileged = True."""
        monkeypatch.setattr("agents.agent_executor._prompt_approval", lambda **_: (True, True))
        monkeypatch.setattr(
            "agents.agent_executor.execute_safely",
            lambda cmd, **_: {
                "success": True,
                "stdout": "AUTO_RUN",
                "stderr": "",
                "exit_code": 0,
                "error": "",
            },
        )
        assert gov.auto_approve_privileged is False
        result = execute_shell_command("pip install x", gov, purpose="Test")
        assert "AUTO_RUN" in result
        assert gov.auto_approve_privileged is True

    def test_auto_approve_skips_prompt_for_subsequent_commands(self, gov: Governance, monkeypatch):
        """Once auto_approve_privileged is True, future PRIVILEGED commands skip the prompt."""
        gov.auto_approve_privileged = True
        prompt_called = []
        monkeypatch.setattr(
            "agents.agent_executor._prompt_approval",
            lambda **_: prompt_called.append(True) or (True, False),
        )
        monkeypatch.setattr(
            "agents.agent_executor.execute_safely",
            lambda cmd, **_: {
                "success": True,
                "stdout": "BYPASSED",
                "stderr": "",
                "exit_code": 0,
                "error": "",
            },
        )
        result = execute_shell_command("pip install anothertool", gov)
        # Prompt should NOT have been called because governance already allows
        assert len(prompt_called) == 0
        assert "BYPASSED" in result

    def test_auto_approve_does_not_bypass_destructive_commands(self, gov: Governance, monkeypatch):
        """Session auto-approve must never allow DESTRUCTIVE commands."""
        gov.auto_approve_privileged = True
        called = []
        monkeypatch.setattr(
            "agents.agent_executor.execute_safely",
            lambda cmd, **_: called.append(cmd)
            or {"success": True, "stdout": "BAD", "stderr": "", "exit_code": 0, "error": ""},
        )
        result = execute_shell_command("rm -rf /", gov)
        assert not called
        assert "blocked" in result.lower()


class TestUniversalExecutorGovernance:
    """Verify UniversalExecutor uses the same governance policy."""

    def test_privileged_command_requires_approval(self, monkeypatch):
        ue = UniversalExecutor()
        monkeypatch.setattr(
            "agents.agent_executor._prompt_approval",
            lambda **_: (False, False),
        )
        result = ue.execute_shell("pip install something")
        assert result.success is False
        assert "rejected" in result.error.lower()

    def test_privileged_command_runs_when_approved(self, monkeypatch):
        ue = UniversalExecutor()
        monkeypatch.setattr(
            "agents.agent_executor._prompt_approval",
            lambda **_: (True, False),
        )

        class FakeCompleted:
            returncode = 0
            stdout = "UNIVERSAL_APPROVED"
            stderr = ""

        monkeypatch.setattr(
            "tools.universal_executor.subprocess.run",
            lambda *_, **__: FakeCompleted(),
        )
        result = ue.execute_shell("pip install approved")
        assert result.success is True
        assert "UNIVERSAL_APPROVED" in result.output

    def test_destructive_command_is_blocked_before_subprocess(self, monkeypatch):
        ue = UniversalExecutor()
        called = []
        monkeypatch.setattr(
            "tools.universal_executor.subprocess.run",
            lambda *_, **__: called.append(True),
        )
        result = ue.execute_shell("rm -rf --no-preserve-root /")
        assert result.success is False
        assert not called
        assert "destructive" in result.error.lower()


# ── _prompt_approval ──────────────────────────────────────────────────────────


class TestPromptApproval:
    """Unit tests for the approval UI helper.

    confirm() is imported lazily inside _prompt_approval with
    ``from ui_components import confirm``, so it must be patched at
    ``ui_components.confirm``, not at the executor module level.

    _prompt_approval now returns tuple[bool, bool]: (approved, enable_auto).
    """

    def test_returns_deny_when_user_types_n(self):
        """Typing 'n' must return (False, False)."""
        with patch("ui_components.console"), patch("builtins.input", return_value="n"):
            approved, enable_auto = _prompt_approval(
                cmd="pip install evil",
                risk_level="PRIVILEGED",
                purpose="Test",
                thought="Thinking...",
            )
        assert approved is False
        assert enable_auto is False

    def test_returns_allow_when_user_types_y(self):
        """Typing 'y' must return (True, False) — allow this command only."""
        with patch("ui_components.console"), patch("builtins.input", return_value="y"):
            approved, enable_auto = _prompt_approval(
                cmd="sudo apt install nmap",
                risk_level="PRIVILEGED",
                purpose="Port scan",
            )
        assert approved is True
        assert enable_auto is False

    def test_returns_allow_auto_when_user_types_a(self):
        """Typing 'a' must return (True, True) — allow + enable session auto-approve."""
        with patch("ui_components.console"), patch("builtins.input", return_value="a"):
            approved, enable_auto = _prompt_approval(
                cmd="cargo install feroxbuster",
                risk_level="PRIVILEGED",
                purpose="Directory fuzzer",
            )
        assert approved is True
        assert enable_auto is True

    def test_returns_deny_on_eof(self):
        """If input() raises EOFError (non-interactive), must safely return (False, False)."""
        with patch("ui_components.console"), patch("builtins.input", side_effect=EOFError):
            approved, enable_auto = _prompt_approval(
                cmd="pip install x",
                risk_level="PRIVILEGED",
            )
        assert approved is False
        assert enable_auto is False

    def test_unknown_input_defaults_to_deny(self):
        """Any input that is not y/Y/a/A must default to deny."""
        for bad_input in ["yes", "allow", "", "q", "1", "no"]:
            with patch("ui_components.console"), patch("builtins.input", return_value=bad_input):
                approved, _ = _prompt_approval(cmd="pip install x", risk_level="PRIVILEGED")
            assert approved is False, f"Expected deny for input={bad_input!r}"


# ── Action alias table completeness ──────────────────────────────────────────


class TestActionAliases:
    """Verify alias table completeness for all new actions."""

    @pytest.mark.parametrize("alias", ["write_and_run", "write_and_exec", "script"])
    def test_write_script_aliases(self, alias: str, gov: Governance):
        """All write_script aliases should successfully execute a Python script."""
        result = execute_tool(
            {
                "action": alias,
                "filename": f"alias_{alias}.py",
                "code": f'print("{alias.upper()}_ALIAS_OK")',
            },
            gov,
        )
        assert f"{alias.upper()}_ALIAS_OK" in result

    @pytest.mark.parametrize("alias", ["install", "install_package", "install_binary"])
    def test_install_tool_aliases(self, alias: str, gov_no_approval: Governance, monkeypatch):
        """All install_tool aliases should route to the install handler."""
        captured: list[str] = []
        monkeypatch.setattr(
            "agents.agent_executor.execute_safely",
            lambda cmd, **_: captured.append(cmd)
            or {"success": True, "stdout": "OK", "stderr": "", "exit_code": 0, "error": ""},
        )
        execute_tool({"action": alias, "name": "testpkg", "manager": "pip"}, gov_no_approval)
        assert any("pip install testpkg" in c for c in captured)
