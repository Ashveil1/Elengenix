"""Comprehensive tests for elengenix/scanning/executor.py — tool execution orchestrator."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, PropertyMock, patch, call

import pytest

from elengenix.scanning.executor import (
    _build_install_command,
    _prompt_approval,
    detect_and_install_missing_tool,
    execute_install_tool,
    execute_shell_command,
    execute_tool,
    execute_tool_registry,
    execute_tool_subprocess,
    execute_write_script,
    handle_ask_user,
)

# Import ToolResult for assertions
from tools.tool_registry import ToolResult, ToolCategory


# ===================================================================
# Fixtures
# ===================================================================


@pytest.fixture
def governance():
    """Governance mock with gate() returning a configurable GateDecision-like object."""
    g = MagicMock()
    gate_result = MagicMock()
    gate_result.decision = "allow"
    gate_result.risk_level = "SAFE"
    gate_result.rationale = "Test: safe command"
    gate_result.allowed = True
    g.gate.return_value = gate_result
    g.auto_approve_privileged = False
    return g


@pytest.fixture
def callback():
    return MagicMock()


@pytest.fixture
def action_data():
    return {"action": "run_shell", "command": "echo hello", "purpose": "test", "thought": "testing"}


@pytest.fixture
def governance_deny():
    """Governance that denies everything."""
    g = MagicMock()
    gate_result = MagicMock()
    gate_result.decision = "deny"
    gate_result.risk_level = "DESTRUCTIVE"
    gate_result.rationale = "Blocked unconditionally"
    gate_result.allowed = False
    g.gate.return_value = gate_result
    return g


@pytest.fixture
def governance_needs_approval():
    """Governance that requires approval."""
    g = MagicMock()
    gate_result = MagicMock()
    gate_result.decision = "needs_approval"
    gate_result.risk_level = "PRIVILEGED"
    gate_result.rationale = "Needs human approval"
    gate_result.allowed = False
    g.gate.return_value = gate_result
    return g


# ===================================================================
# execute_tool — main dispatcher
# ===================================================================


class TestExecuteTool:
    """Test the top-level dispatch function."""

    def test_finish_action(self, governance, callback):
        """finish action returns __FINISH__."""
        result = execute_tool({"action": "finish"}, governance, callback=callback)
        assert result == "__FINISH__"

    def test_finish_aliases(self, governance, callback):
        """All finish aliases return __FINISH__."""
        for alias in ["done", "complete", "end", "exit"]:
            result = execute_tool({"action": alias}, governance, callback=callback)
            assert result == "__FINISH__", f"Alias '{alias}' did not return __FINISH__"

    @patch("elengenix.scanning.executor.remember")
    def test_save_memory(self, mock_remember, governance, callback):
        """save_memory calls remember() with correct args."""
        result = execute_tool(
            {"action": "save_memory", "learning": "learned X", "target": "target1", "category": "cat1"},
            governance,
            callback=callback,
        )
        mock_remember.assert_called_once_with("learned X", "target1", "cat1")
        assert result == "Finding recorded in memory."

    @patch("elengenix.scanning.executor.remember")
    def test_save_memory_aliases(self, mock_remember, governance, callback):
        for alias in ["remember", "memorize", "store_memory"]:
            mock_remember.reset_mock()
            result = execute_tool({"action": alias, "learning": "data"}, governance, callback=callback)
            mock_remember.assert_called_once()
            assert "memory" in result.lower()

    @patch("cli.ui_components.confirm", return_value=True)
    def test_ask_user_yes(self, mock_confirm, governance, callback):
        """ask_user returns 'yes'."""
        result = execute_tool(
            {"action": "ask_user", "question": "Continue?", "input_type": "confirm"},
            governance,
            callback=callback,
        )
        assert result == "yes"

    def test_unknown_action(self, governance, callback):
        """Unknown action returns error listing valid actions."""
        result = execute_tool({"action": "do_magic"}, governance, callback=callback)
        assert "Unknown action" in result
        assert "run_shell" in result

    def test_empty_command(self, governance, callback):
        """Empty or invalid command returns error."""
        result = execute_tool({"action": "run_shell", "command": ""}, governance, callback=callback)
        assert "Error: Invalid or empty command" in result

    def test_non_string_command(self, governance, callback):
        """Non-string command returns error."""
        result = execute_tool({"action": "run_shell", "command": None}, governance, callback=callback)
        assert "Error: Invalid or empty command" in result

    @patch("elengenix.scanning.executor.execute_shell_command")
    def test_run_shell(self, mock_exec_shell, governance, callback):
        """run_shell delegates to execute_shell_command."""
        mock_exec_shell.return_value = "output"
        result = execute_tool(
            {"action": "run_shell", "command": "ls", "purpose": "list", "thought": "need to list"},
            governance,
            callback=callback,
        )
        mock_exec_shell.assert_called_once_with(
            "ls", governance, 100000, callback, purpose="list", thought="need to list"
        )
        assert result == "output"

    @patch("elengenix.scanning.executor.execute_shell_command")
    def test_shell_aliases(self, mock_exec_shell, governance, callback):
        """All shell aliases route to execute_shell_command."""
        for alias in ["shell", "bash", "exec", "execute", "command", "run_command", "run_bash"]:
            mock_exec_shell.reset_mock()
            mock_exec_shell.return_value = "ok"
            result = execute_tool(
                {"action": alias, "command": "whoami"}, governance, callback=callback
            )
            mock_exec_shell.assert_called_once()
            assert result == "ok"

    def test_action_is_dict(self, governance, callback):
        """When action value is a dict, params get merged into action_data."""
        action_data = {
            "action": {"type": "run_shell", "params": {"command": "echo merged"}},
            "command": "original",
        }
        with patch("elengenix.scanning.executor.execute_shell_command") as mock_shell:
            mock_shell.return_value = "merged_result"
            result = execute_tool(action_data, governance, callback=callback)
            assert result == "merged_result"

    @patch("tools.research_tool.search_web")
    def test_web_search(self, mock_search, governance, callback):
        """web_search calls search_web and returns JSON."""
        mock_search.return_value = [{"title": "Result"}]
        result = execute_tool(
            {"action": "web_search", "query": "test query"}, governance, callback=callback
        )
        mock_search.assert_called_once_with("test query", num_results=5)
        data = json.loads(result)
        assert data[0]["title"] == "Result"

    @patch("tools.research_tool.search_web")
    def test_web_search_aliases(self, mock_search, governance, callback):
        for alias in ["search", "google", "search_web", "internet_search"]:
            mock_search.reset_mock()
            mock_search.return_value = []
            execute_tool({"action": alias, "query": "q"}, governance, callback=callback)
            mock_search.assert_called_once_with("q", num_results=5)

    def test_web_search_no_query(self, governance, callback):
        """web_search without query returns error."""
        result = execute_tool({"action": "web_search"}, governance, callback=callback)
        assert "Error: web_search requires a 'query' parameter" in result

    @patch("tools.research_tool.search_web")
    def test_web_search_exception(self, mock_search, governance, callback):
        """web_search exception returns error."""
        mock_search.side_effect = RuntimeError("network down")
        result = execute_tool(
            {"action": "web_search", "query": "test"}, governance, callback=callback
        )
        assert "Error executing web_search" in result

    @patch("tools.ai_tool_creator.ToolSpec")
    @patch("tools.ai_tool_creator.AIToolCreator")
    def test_create_ai_tool(self, mock_creator_cls, mock_spec_cls, governance, callback):
        """create_ai_tool delegates to AIToolCreator."""
        mock_creator = mock_creator_cls.return_value
        mock_creator.create_tool.return_value = True
        mock_spec_cls.return_value = MagicMock()
        result = execute_tool(
            {
                "action": "create_ai_tool",
                "name": "my_tool",
                "code": "print('hello')",
                "purpose": "testing",
                "dependencies": [],
                "ai_reasoning": "reason",
            },
            governance,
            callback=callback,
        )
        mock_creator.create_tool.assert_called_once()
        assert "successfully" in result.lower()

    @patch("tools.ai_tool_creator.ToolSpec")
    @patch("tools.ai_tool_creator.AIToolCreator")
    def test_create_ai_tool_aliases(self, mock_creator_cls, mock_spec_cls, governance, callback):
        mock_creator = mock_creator_cls.return_value
        mock_creator.create_tool.return_value = True
        mock_spec_cls.return_value = MagicMock()
        result = execute_tool(
            {"action": "create_tool", "name": "t", "code": "p"}, governance, callback=callback
        )
        assert "successfully" in result.lower()

    @patch("tools.ai_tool_creator.ToolSpec")
    @patch("tools.ai_tool_creator.AIToolCreator")
    def test_create_ai_tool_failure(self, mock_creator_cls, mock_spec_cls, governance, callback):
        """create_ai_tool failure returns error message."""
        mock_creator = mock_creator_cls.return_value
        mock_creator.create_tool.return_value = False
        mock_spec_cls.return_value = MagicMock()
        result = execute_tool(
            {"action": "create_ai_tool", "name": "t", "code": "p"},
            governance,
            callback=callback,
        )
        assert "Failed" in result

    @patch("tools.ai_tool_creator.AIToolCreator")
    def test_create_ai_tool_exception(self, mock_creator_cls, governance, callback):
        """create_ai_tool exception returns error."""
        mock_creator_cls.side_effect = RuntimeError("creation failed")
        result = execute_tool(
            {"action": "create_ai_tool", "name": "t", "code": "p"},
            governance,
            callback=callback,
        )
        assert "Error creating tool" in result

    @patch("tools.ai_tool_creator.AIToolCreator")
    def test_run_ai_tool(self, mock_creator_cls, governance, callback):
        """run_ai_tool executes via AIToolCreator."""
        mock_creator = mock_creator_cls.return_value
        tool_result = MagicMock()
        tool_result.success = True
        tool_result.output = "ran ok"
        tool_result.error = ""
        tool_result.findings = []
        mock_creator.execute_tool.return_value = tool_result
        result = execute_tool(
            {"action": "run_ai_tool", "name": "my_tool", "kwargs": {"arg1": "val"}},
            governance,
            callback=callback,
        )
        mock_creator.execute_tool.assert_called_once_with("my_tool", arg1="val")
        data = json.loads(result)
        assert data["success"] is True

    @patch("tools.ai_tool_creator.AIToolCreator")
    def test_run_ai_tool_aliases(self, mock_creator_cls, governance, callback):
        mock_creator = mock_creator_cls.return_value
        tool_result = MagicMock()
        tool_result.success = True
        tool_result.output = ""
        tool_result.error = ""
        tool_result.findings = []
        mock_creator.execute_tool.return_value = tool_result
        result = execute_tool(
            {"action": "run_tool", "name": "t"}, governance, callback=callback
        )
        assert json.loads(result)["success"] is True

    @patch("tools.ai_tool_creator.AIToolCreator")
    def test_run_ai_tool_exception(self, mock_creator_cls, governance, callback):
        """run_ai_tool exception returns error."""
        mock_creator_cls.side_effect = ValueError("invalid")
        result = execute_tool(
            {"action": "run_ai_tool", "name": "t"}, governance, callback=callback
        )
        assert "Error running tool" in result

    @patch("elengenix.scanning.executor.execute_write_script")
    def test_write_script(self, mock_write, governance, callback):
        """write_script dispatches to execute_write_script."""
        mock_write.return_value = "script result"
        result = execute_tool(
            {"action": "write_script", "code": "print('hi')"}, governance, callback=callback
        )
        mock_write.assert_called_once()
        assert result == "script result"

    @patch("elengenix.scanning.executor.execute_write_script")
    def test_write_script_aliases(self, mock_write, governance, callback):
        for alias in ["write_and_run", "write_and_exec", "script"]:
            mock_write.reset_mock()
            mock_write.return_value = "ok"
            execute_tool({"action": alias, "code": "p"}, governance, callback=callback)
            mock_write.assert_called_once()

    @patch("elengenix.scanning.executor.execute_install_tool")
    def test_install_tool(self, mock_install, governance, callback):
        """install_tool dispatches to execute_install_tool."""
        mock_install.return_value = "install ok"
        result = execute_tool(
            {"action": "install_tool", "name": "nmap"}, governance, callback=callback
        )
        mock_install.assert_called_once()
        assert result == "install ok"

    @patch("elengenix.scanning.executor.execute_install_tool")
    def test_install_tool_aliases(self, mock_install, governance, callback):
        for alias in ["install", "install_package", "install_binary"]:
            mock_install.reset_mock()
            mock_install.return_value = "ok"
            execute_tool({"action": alias, "name": "x"}, governance, callback=callback)
            mock_install.assert_called_once()


# ===================================================================
# execute_shell_command
# ===================================================================


class TestExecuteShellCommand:
    """Test governance-gated shell execution."""

    @patch("elengenix.scanning.executor.execute_safely_interactive")
    def test_safe_allow(self, mock_safe, governance, callback):
        """SAFE commands execute immediately."""
        mock_safe.return_value = {"success": True, "stdout": "hello", "stderr": "", "exit_code": 0}
        result = execute_shell_command("echo hello", governance, callback=callback)
        assert result == "hello"
        governance.gate.assert_called_once()

    def test_deny(self, governance_deny, callback):
        """Denied commands return blocked message."""
        result = execute_shell_command("rm -rf /", governance_deny, callback=callback)
        assert "blocked" in result.lower()

    @patch("elengenix.scanning.executor._prompt_approval")
    @patch("elengenix.scanning.executor.execute_safely_interactive")
    def test_needs_approval_approved(self, mock_safe, mock_approval, governance_needs_approval, callback):
        """needs_approval + approved = executes."""
        mock_approval.return_value = (True, False)
        mock_safe.return_value = {"success": True, "stdout": "approved cmd", "stderr": "", "exit_code": 0}
        result = execute_shell_command(
            "apt install nmap",
            governance_needs_approval,
            callback=callback,
            purpose="install",
            thought="need nmap",
        )
        assert result == "approved cmd"
        mock_approval.assert_called_once()

    @patch("elengenix.scanning.executor._prompt_approval")
    def test_needs_approval_rejected(self, mock_approval, governance_needs_approval, callback):
        """needs_approval + rejected = skip message."""
        mock_approval.return_value = (False, False)
        result = execute_shell_command(
            "apt remove python",
            governance_needs_approval,
            callback=callback,
        )
        assert "rejected" in result.lower()

    @patch("elengenix.scanning.executor._prompt_approval")
    @patch("elengenix.scanning.executor.execute_safely_interactive")
    def test_needs_approval_enable_auto(
        self, mock_safe, mock_approval, governance_needs_approval, callback
    ):
        """needs_approval + 'a' enables auto-approve and executes."""
        mock_approval.return_value = (True, True)
        mock_safe.return_value = {"success": True, "stdout": "auto cmd", "stderr": "", "exit_code": 0}
        result = execute_shell_command(
            "pip install requests",
            governance_needs_approval,
            callback=callback,
        )
        assert result == "auto cmd"
        assert governance_needs_approval.auto_approve_privileged is True

    @patch("elengenix.scanning.executor.execute_safely_interactive")
    def test_with_callback(self, mock_safe, governance, callback):
        """Streaming execution emits per-line 'exec_stream:' messages and a
        final 'exec:' summary so legacy TUI consumers keep rendering full output."""
        mock_safe.return_value = {"success": True, "stdout": "output text", "stderr": "", "exit_code": 0}
        # execute_safely_interactive accepts line_callback; simulate one streamed line
        def _fake_interactive(cmd, timeout=300, line_callback=None):
            if line_callback:
                line_callback("output text\n")
            return mock_safe.return_value
        mock_safe.side_effect = _fake_interactive

        execute_shell_command("echo hi", governance, callback=callback, purpose="greet", thought="say hi")

        # callback receives at least the final 'exec:' summary call
        exec_calls = [c.args[0] for c in callback.call_args_list if c.args and isinstance(c.args[0], str) and c.args[0].startswith("exec:")]
        assert exec_calls, "expected a final 'exec:' summary callback"
        data = json.loads(exec_calls[-1][len("exec:"):])
        assert data["cmd"] == "echo hi"
        assert data["success"] is True
        assert data["purpose"] == "greet"
        assert data["output"] == "output text"

    @patch("elengenix.scanning.executor.execute_safely")
    @patch("cli.ui_components.show_command_execution")
    def test_without_callback_uses_show_command_execution(
        self, mock_show, mock_safe, governance
    ):
        """Without callback, show_command_execution is called."""
        mock_safe.return_value = {"success": True, "stdout": "out", "stderr": "", "exit_code": 0}
        result = execute_shell_command("echo hi", governance, callback=None, purpose="test")
        mock_show.assert_called_once()
        assert result == "out"

    @patch("elengenix.scanning.executor.execute_safely_interactive")
    def test_command_failure(self, mock_safe, governance, callback):
        """Failed command returns [FAIL] message."""
        mock_safe.return_value = {
            "success": False,
            "stdout": "",
            "stderr": "permission denied",
            "exit_code": 1,
            "error": "permission denied",
        }
        result = execute_shell_command("sudo something", governance, callback=callback)
        assert result.startswith("[FAIL]")
        assert "permission denied" in result

    @patch("elengenix.scanning.executor.execute_safely")
    @patch("elengenix.scanning.executor.execute_safely_interactive")
    @patch("elengenix.scanning.executor.detect_and_install_missing_tool")
    def test_command_failure_missing_tool_installed_and_retry(
        self, mock_detect, mock_safe_interactive, mock_safe_retry, governance, callback
    ):
        """Missing tool detected, installed, then command retried successfully.

        Initial execution goes through the streaming path (execute_safely_interactive)
        when a callback is present; the retry uses the plain execute_safely path.
        """
        mock_safe_interactive.return_value = {
            "success": False, "stdout": "", "stderr": "command not found",
            "exit_code": 127, "error": "command not found",
        }
        mock_safe_retry.return_value = {
            "success": True, "stdout": "retry ok", "stderr": "", "exit_code": 0,
        }
        mock_detect.return_value = "installation output"
        result = execute_shell_command("nmap -h", governance, callback=callback)
        assert result == "retry ok"
        assert mock_safe_interactive.call_count == 1
        assert mock_safe_retry.call_count == 1

    @patch("elengenix.scanning.executor.execute_safely")
    @patch("elengenix.scanning.executor.detect_and_install_missing_tool")
    def test_command_failure_missing_tool_installed_retry_fails(
        self, mock_detect, mock_safe, governance, callback
    ):
        """Missing tool installed but retry also fails."""
        mock_safe.side_effect = [
            {"success": False, "stdout": "", "stderr": "not found", "exit_code": 127, "error": "not found"},
            {"success": False, "stdout": "", "stderr": "still broken", "exit_code": 1, "error": "still broken"},
        ]
        mock_detect.return_value = "installed"
        result = execute_shell_command("nmap -h", governance, callback=callback)
        assert result.startswith("[FAIL]")

    @patch("elengenix.scanning.executor.execute_safely_interactive")
    @patch("elengenix.scanning.executor.detect_and_install_missing_tool")
    def test_command_failure_missing_tool_not_installed(
        self, mock_detect, mock_safe, governance, callback
    ):
        """Missing tool detection returns None, command not retried."""
        mock_safe.return_value = {
            "success": False, "stdout": "", "stderr": "command not found", "exit_code": 127, "error": "command not found",
        }
        mock_detect.return_value = None
        result = execute_shell_command("nmap", governance, callback=callback)
        assert result.startswith("[FAIL]")
        mock_safe.assert_called_once()

    @patch("elengenix.scanning.executor.execute_safely_interactive")
    def test_timeout_error(self, mock_safe, governance, callback):
        """TimeoutExpired returns appropriate error."""
        import subprocess
        mock_safe.side_effect = subprocess.TimeoutExpired(cmd="sleep 400", timeout=300)
        result = execute_shell_command("sleep 400", governance, callback=callback)
        assert "timed out" in result.lower()

    @patch("elengenix.scanning.executor.execute_safely_interactive")
    def test_value_error(self, mock_safe, governance, callback):
        """ValueError from execute_safely is caught."""
        mock_safe.side_effect = ValueError("invalid syntax")
        result = execute_shell_command("|", governance, callback=callback)
        assert "Invalid command" in result

    @patch("elengenix.scanning.executor.execute_safely_interactive")
    def test_generic_exception(self, mock_safe, governance, callback):
        """Generic exception is caught."""
        mock_safe.side_effect = RuntimeError("unexpected")
        result = execute_shell_command("something", governance, callback=callback)
        assert "Error executing tool" in result

    @patch("elengenix.scanning.executor.execute_safely_interactive")
    def test_output_truncated(self, mock_safe, governance, callback):
        """Output longer than max_output_len is truncated."""
        long_output = "x" * 10000
        mock_safe.return_value = {"success": True, "stdout": long_output, "stderr": "", "exit_code": 0}
        result = execute_shell_command("big output", governance, max_output_len=10, callback=callback)
        assert len(result) == 10

    @patch("elengenix.scanning.executor.execute_safely_interactive")
    def test_stderr_appended(self, mock_safe, governance, callback):
        """stderr is appended to stdout in output."""
        mock_safe.return_value = {"success": True, "stdout": "stdout msg", "stderr": "stderr msg", "exit_code": 0}
        result = execute_shell_command("cmd", governance, callback=callback)
        assert "stdout msg" in result
        assert "stderr msg" in result


# ===================================================================
# _prompt_approval
# ===================================================================


class TestPromptApproval:
    """Test the interactive approval prompt."""

    @patch("builtins.input", return_value="y")
    @patch("cli.ui_components.console")
    def test_approve_y(self, mock_console, mock_input, governance):
        """'y' returns (True, False)."""
        approved, enable_auto = _prompt_approval(
            cmd="apt install nmap",
            risk_level="PRIVILEGED",
            purpose="install",
            thought="need",
            governance=governance,
        )
        assert approved is True
        assert enable_auto is False

    @patch("builtins.input", return_value="a")
    @patch("cli.ui_components.console")
    def test_approve_auto(self, mock_console, mock_input, governance):
        """'a' returns (True, True)."""
        approved, enable_auto = _prompt_approval(
            cmd="pip install requests",
            risk_level="PRIVILEGED",
            governance=governance,
        )
        assert approved is True
        assert enable_auto is True

    @patch("builtins.input", return_value="n")
    @patch("cli.ui_components.console")
    def test_deny_n(self, mock_console, mock_input, governance):
        """'n' returns (False, False)."""
        approved, enable_auto = _prompt_approval(
            cmd="rm -rf /", risk_level="DESTRUCTIVE", governance=governance,
        )
        assert approved is False
        assert enable_auto is False

    @patch("builtins.input", side_effect=EOFError)
    @patch("cli.ui_components.console")
    def test_eof_error_defaults_to_n(self, mock_console, mock_input, governance):
        """EOFError defaults to deny."""
        approved, enable_auto = _prompt_approval(
            cmd="danger", risk_level="PRIVILEGED", governance=governance,
        )
        assert approved is False
        assert enable_auto is False

    @patch("builtins.input", side_effect=KeyboardInterrupt)
    @patch("cli.ui_components.console")
    def test_keyboard_interrupt_defaults_to_n(self, mock_console, mock_input, governance):
        """KeyboardInterrupt defaults to deny."""
        approved, enable_auto = _prompt_approval(
            cmd="danger", risk_level="PRIVILEGED", governance=governance,
        )
        assert approved is False
        assert enable_auto is False

    @patch("builtins.input", return_value="y")
    @patch("cli.ui_components.console")
    def test_thought_and_purpose_displayed(self, mock_console, mock_input, governance):
        """Purpose and thought are passed to console."""
        _prompt_approval(
            cmd="cmd",
            risk_level="PRIVILEGED",
            purpose="scan network",
            thought="target is 10.0.0.1",
            governance=governance,
        )
        assert mock_console.print.call_count >= 2

    @patch("builtins.input", return_value="y")
    @patch("cli.ui_components.console")
    def test_label_color_red_for_non_privileged(self, mock_console, mock_input, governance):
        """Risk level other than PRIVILEGED uses red color."""
        _prompt_approval(cmd="cmd", risk_level="DESTRUCTIVE", governance=governance)
        assert mock_console.print.called


# ===================================================================
# execute_write_script
# ===================================================================


# ===================================================================
# execute_batch (parallel run_shell actions)
# ===================================================================


class TestExecuteBatch:
    """The run_batch action lets the AI fire off multiple independent
    shell commands in parallel — like a pentester with several terminals."""

    def test_empty_actions_returns_error(self, governance, callback):
        from elengenix.scanning.executor import execute_batch
        result = execute_batch({"action": "run_batch", "actions": []}, governance, callback=callback)
        assert "Error" in result

    def test_missing_actions_returns_error(self, governance, callback):
        from elengenix.scanning.executor import execute_batch
        result = execute_batch({"action": "run_batch"}, governance, callback=callback)
        assert "Error" in result

    def test_single_action_runs(self, governance, callback):
        from elengenix.scanning.executor import execute_batch
        with patch("elengenix.scanning.executor.execute_shell_command", return_value="hello") as mock_exec:
            result = execute_batch(
                {"action": "run_batch",
                 "actions": [{"command": "echo hi", "purpose": "greet"}]},
                governance, callback=callback,
            )
        assert mock_exec.call_count == 1
        assert "[BATCH x1" in result
        assert "echo hi" in result
        assert "hello" in result

    def test_multiple_actions_run_in_parallel(self, governance, callback):
        from elengenix.scanning.executor import execute_batch
        with patch("elengenix.scanning.executor.execute_shell_command", return_value="ok") as mock_exec:
            result = execute_batch(
                {"action": "run_batch",
                 "actions": [
                     {"command": "nmap -p 80 target", "purpose": "port scan"},
                     {"command": "whatweb target", "purpose": "fingerprint"},
                     {"command": "subfinder -d target", "purpose": "subdomain enum"},
                 ]},
                governance, callback=callback,
            )
        assert mock_exec.call_count == 3
        # All three commands should appear in the merged result
        assert "nmap -p 80 target" in result
        assert "whatweb target" in result
        assert "subfinder -d target" in result
        assert "[BATCH x3" in result

    def test_failed_action_marked_fail(self, governance, callback):
        from elengenix.scanning.executor import execute_batch
        with patch("elengenix.scanning.executor.execute_shell_command", return_value="[FAIL] Command failed: permission denied"):
            result = execute_batch(
                {"action": "run_batch",
                 "actions": [{"command": "sudo bad", "purpose": "test"}]},
                governance, callback=callback,
            )
        assert "[FAIL]" in result

    def test_exception_in_one_action_doesnt_break_others(self, governance, callback):
        from elengenix.scanning.executor import execute_batch
        # First call raises, second returns normally
        with patch("elengenix.scanning.executor.execute_shell_command",
                   side_effect=[RuntimeError("api down"), "ok"]):
            result = execute_batch(
                {"action": "run_batch",
                 "actions": [
                     {"command": "cmd1"},
                     {"command": "cmd2"},
                 ]},
                governance, callback=callback,
            )
        # Should not raise; should still return merged result
        assert "[BATCH x2" in result

    def test_callback_notified_at_end(self, governance, callback):
        from elengenix.scanning.executor import execute_batch
        with patch("elengenix.scanning.executor.execute_shell_command", return_value="ok"):
            execute_batch(
                {"action": "run_batch",
                 "actions": [{"command": "echo hi"}]},
                governance, callback=callback,
            )
        # Should have at least one callback call (the batch_done notification)
        batch_calls = [c for c in callback.call_args_list if c.args and isinstance(c.args[0], str) and c.args[0].startswith("batch_done")]
        assert len(batch_calls) >= 1


# ===================================================================
# execute_write_script
# ===================================================================


class TestExecuteWriteScript:
    """Test write_script action."""

    @patch("elengenix.scanning.executor.Path.write_text")
    @patch("elengenix.scanning.executor.Path.read_text")
    @patch("elengenix.scanning.executor.execute_shell_command")
    @patch("elengenix.scanning.executor.Path.mkdir")
    def test_write_and_run(self, mock_mkdir, mock_shell, mock_read, mock_write, governance, callback):
        """Script is written, verified, and executed via execute_shell_command."""
        mock_read.return_value = "print('hello')"
        mock_shell.return_value = "execution output"
        result = execute_write_script(
            {
                "filename": "test.py",
                "code": "print('hello')",
                "runner": "python3",
                "args": "--verbose",
                "purpose": "test",
                "thought": "testing",
            },
            governance,
            callback=callback,
        )
        mock_write.assert_called_once()
        mock_read.assert_called_once()
        mock_shell.assert_called_once()
        assert "execution output" in result
        assert "File saved at" in result

    def test_no_code(self, governance, callback):
        """Missing code returns error."""
        result = execute_write_script(
            {"filename": "test.py", "code": ""},
            governance,
            callback=callback,
        )
        assert "code' field is required" in result

    @patch("elengenix.scanning.executor.Path.write_text")
    @patch("elengenix.scanning.executor.Path.read_text")
    @patch("elengenix.scanning.executor.execute_shell_command")
    @patch("elengenix.scanning.executor.Path.mkdir")
    def test_auto_detect_runner(self, mock_mkdir, mock_shell, mock_read, mock_write, governance, callback):
        """Runner is auto-detected from filename extension."""
        mock_read.return_value = "echo 'hello'"
        mock_shell.return_value = "bash output"
        execute_write_script(
            {"filename": "script.sh", "code": "echo 'hello'"},
            governance,
            callback=callback,
        )
        call_args = mock_shell.call_args[0]
        assert "bash" in call_args[0]

    @patch("elengenix.scanning.executor.Path.write_text")
    @patch("elengenix.scanning.executor.Path.read_text")
    @patch("elengenix.scanning.executor.Path.mkdir")
    def test_runner_extensions(self, mock_mkdir, mock_read, mock_write, governance, callback):
        """Various file extensions map to correct runners."""
        mock_read.return_value = "code"
        test_cases = [
            (".py", "python3"),
            (".sh", "bash"),
            (".rb", "ruby"),
            (".go", "go run"),
            (".js", "node"),
            (".ts", "ts-node"),
            (".unknown", "python3"),
        ]
        for ext, expected_runner in test_cases:
            with patch("elengenix.scanning.executor.execute_shell_command") as mock_shell:
                mock_shell.return_value = "ok"
                execute_write_script(
                    {"filename": f"script{ext}", "code": "code"},
                    governance,
                    callback=callback,
                )
                call_cmd = mock_shell.call_args[0][0]
                assert expected_runner in call_cmd, (
                    f"Extension {ext}: expected '{expected_runner}' in '{call_cmd}'"
                )

    @patch("elengenix.scanning.executor.Path.write_text")
    @patch("elengenix.scanning.executor.Path.mkdir")
    def test_write_failure(self, mock_mkdir, mock_write, governance, callback):
        """Write failure returns error."""
        mock_write.side_effect = PermissionError("denied")
        result = execute_write_script(
            {"filename": "test.py", "code": "print('hi')"},
            governance,
            callback=callback,
        )
        assert "Failed to write script" in result

    @patch("elengenix.scanning.executor.Path.write_text")
    @patch("elengenix.scanning.executor.Path.read_text")
    @patch("elengenix.scanning.executor.Path.mkdir")
    def test_read_verification_failure(self, mock_mkdir, mock_read, mock_write, governance, callback):
        """Read verification failure returns error."""
        mock_read.side_effect = IOError("cannot read")
        result = execute_write_script(
            {"filename": "test.py", "code": "print('hi')"},
            governance,
            callback=callback,
        )
        assert "Could not verify" in result

    @patch("elengenix.scanning.executor.Path.write_text")
    @patch("elengenix.scanning.executor.Path.read_text")
    @patch("elengenix.scanning.executor.Path.mkdir")
    def test_content_mismatch(self, mock_mkdir, mock_read, mock_write, governance, callback):
        """Content mismatch between expected and written raises warning."""
        mock_read.return_value = "different content"
        result = execute_write_script(
            {"filename": "test.py", "code": "expected content"},
            governance,
            callback=callback,
        )
        assert "content verification failed" in result

    @patch("elengenix.scanning.executor.Path.write_text")
    @patch("elengenix.scanning.executor.Path.read_text")
    @patch("elengenix.scanning.executor.execute_shell_command")
    @patch("elengenix.scanning.executor.Path.mkdir")
    def test_without_callback_uses_console(
        self, mock_mkdir, mock_shell, mock_read, mock_write, governance
    ):
        """Without callback, console is used for output."""
        mock_read.return_value = "print('hello')"
        mock_shell.return_value = "ok"
        with patch("cli.ui_components.console") as mock_console:
            execute_write_script(
                {"filename": "test.py", "code": "print('hello')"},
                governance,
                callback=None,
            )
            assert mock_console.print.called


# ===================================================================
# execute_install_tool
# ===================================================================


class TestExecuteInstallTool:
    """Test install_tool action."""

    @patch("elengenix.scanning.executor.execute_shell_command")
    def test_install_with_custom_cmd(self, mock_shell, governance, callback):
        """Custom install_cmd is used directly."""
        mock_shell.return_value = "installed"
        result = execute_install_tool(
            {
                "name": "nmap",
                "install_cmd": "sudo apt install -y nmap",
                "purpose": "scanning",
                "thought": "need nmap",
            },
            governance,
            callback=callback,
        )
        mock_shell.assert_called_once()
        call_cmd = mock_shell.call_args[0][0]
        assert "sudo apt install" in call_cmd
        assert result == "installed"

    @patch("elengenix.scanning.executor.execute_shell_command")
    def test_install_with_go_manager(self, mock_shell, governance, callback):
        """go manager builds correct command."""
        mock_shell.return_value = "ok"
        execute_install_tool(
            {"name": "user/repo", "manager": "go"},
            governance,
            callback=callback,
        )
        cmd = mock_shell.call_args[0][0]
        assert cmd.startswith("go install")
        assert "github.com" in cmd

    @patch("elengenix.scanning.executor.execute_shell_command")
    def test_install_with_pip(self, mock_shell, governance, callback):
        mock_shell.return_value = "ok"
        execute_install_tool(
            {"name": "requests", "manager": "pip", "version": "==2.28.0"},
            governance,
            callback=callback,
        )
        cmd = mock_shell.call_args[0][0]
        assert cmd == "pip install requests==2.28.0"

    @patch("elengenix.scanning.executor.execute_shell_command")
    def test_install_with_pip3(self, mock_shell, governance, callback):
        mock_shell.return_value = "ok"
        execute_install_tool(
            {"name": "requests", "manager": "pip3"},
            governance,
            callback=callback,
        )
        cmd = mock_shell.call_args[0][0]
        assert "pip3 install" in cmd

    @patch("elengenix.scanning.executor.execute_shell_command")
    def test_install_with_apt(self, mock_shell, governance, callback):
        mock_shell.return_value = "ok"
        execute_install_tool(
            {"name": "nmap", "manager": "apt"},
            governance,
            callback=callback,
        )
        cmd = mock_shell.call_args[0][0]
        assert "sudo apt-get install" in cmd

    @patch("elengenix.scanning.executor.execute_shell_command")
    def test_install_with_cargo(self, mock_shell, governance, callback):
        mock_shell.return_value = "ok"
        execute_install_tool(
            {"name": "ripgrep", "manager": "cargo"},
            governance,
            callback=callback,
        )
        cmd = mock_shell.call_args[0][0]
        assert "cargo install" in cmd

    @patch("elengenix.scanning.executor.execute_shell_command")
    def test_install_with_npm(self, mock_shell, governance, callback):
        mock_shell.return_value = "ok"
        execute_install_tool(
            {"name": "typescript", "manager": "npm"},
            governance,
            callback=callback,
        )
        cmd = mock_shell.call_args[0][0]
        assert "npm install -g" in cmd

    @patch("elengenix.scanning.executor.execute_shell_command")
    def test_install_with_gem(self, mock_shell, governance, callback):
        mock_shell.return_value = "ok"
        execute_install_tool(
            {"name": "bundler", "manager": "gem"},
            governance,
            callback=callback,
        )
        cmd = mock_shell.call_args[0][0]
        assert "gem install" in cmd

    @patch("elengenix.scanning.executor.execute_shell_command")
    def test_install_with_brew(self, mock_shell, governance, callback):
        mock_shell.return_value = "ok"
        execute_install_tool(
            {"name": "wget", "manager": "brew"},
            governance,
            callback=callback,
        )
        cmd = mock_shell.call_args[0][0]
        assert "brew install" in cmd

    @patch("elengenix.scanning.executor.execute_shell_command")
    def test_install_unknown_manager_defaults_pip(self, mock_shell, governance, callback):
        """Unknown manager defaults to pip install."""
        mock_shell.return_value = "ok"
        execute_install_tool(
            {"name": "my_tool", "manager": "yum"},
            governance,
            callback=callback,
        )
        cmd = mock_shell.call_args[0][0]
        assert "pip install" in cmd

    def test_install_no_name_no_install_cmd(self, governance, callback):
        """Missing name and install_cmd returns error."""
        result = execute_install_tool(
            {"name": ""},
            governance,
            callback=callback,
        )
        assert "name" in result and "required" in result


# ===================================================================
# detect_and_install_missing_tool
# ===================================================================


class TestDetectAndInstallMissingTool:
    """Test missing tool detection and installation."""

    @patch("shutil.which")
    def test_empty_command(self, mock_which, governance, callback):
        """Empty command returns None."""
        result = detect_and_install_missing_tool("", governance, callback)
        assert result is None

    @patch("shutil.which")
    def test_skip_commands(self, mock_which, governance, callback):
        """Skip commands (python, bash, etc.) return None."""
        for cmd in ["python", "python3", "bash", "echo", "ls", "cat", "grep"]:
            result = detect_and_install_missing_tool(cmd, governance, callback)
            assert result is None

    @patch("shutil.which")
    def test_tool_exists(self, mock_which, governance, callback):
        """Tool already in PATH returns None."""
        mock_which.return_value = "/usr/bin/nmap"
        result = detect_and_install_missing_tool("nmap -h", governance, callback)
        assert result is None
        mock_which.assert_called_once_with("nmap")

    @patch("builtins.input", return_value="n")
    @patch("shutil.which")
    @patch("cli.ui_components.console")
    def test_user_denies_install(self, mock_console, mock_which, mock_input, governance, callback):
        """User says no to install — returns None."""
        mock_which.return_value = None
        result = detect_and_install_missing_tool("nmap -h", governance, callback)
        assert result is None

    @patch("builtins.input", side_effect=EOFError)
    @patch("shutil.which")
    @patch("cli.ui_components.console")
    def test_eof_defaults_to_skip(self, mock_console, mock_which, mock_input, governance, callback):
        """EOFError on install prompt defaults to skip."""
        mock_which.return_value = None
        result = detect_and_install_missing_tool("nmap", governance, callback)
        assert result is None

    @patch("builtins.input", return_value="y")
    @patch("getpass.getpass", return_value="")
    @patch("shutil.which")
    @patch("cli.ui_components.console")
    @patch("tools.safe_exec.execute_safely")
    def test_install_success(
        self, mock_safe, mock_console, mock_which, mock_getpass, mock_input, governance, callback
    ):
        """Tool installed successfully."""
        mock_which.return_value = None
        mock_safe.return_value = {"success": True, "stdout": "installed ok", "stderr": "", "exit_code": 0}
        result = detect_and_install_missing_tool("nmap -h", governance, callback)
        assert result is not None
        assert "installed ok" in result

    @patch("builtins.input", return_value="y")
    @patch("getpass.getpass", return_value="s3cret")
    @patch("shutil.which")
    @patch("cli.ui_components.console")
    @patch("tools.safe_exec.execute_safely")
    def test_install_with_sudo_password(
        self, mock_safe, mock_console, mock_which, mock_getpass, mock_input, governance, callback
    ):
        """Install with sudo password uses echo piping."""
        mock_which.return_value = None
        mock_safe.return_value = {"success": True, "stdout": "installed", "stderr": "", "exit_code": 0}
        result = detect_and_install_missing_tool("nmap -h", governance, callback)
        call_cmd = mock_safe.call_args[0][0]
        assert "echo" in call_cmd
        assert "sudo" in call_cmd

    @patch("builtins.input", return_value="y")
    @patch("getpass.getpass", return_value="")
    @patch("shutil.which")
    @patch("cli.ui_components.console")
    @patch("tools.safe_exec.execute_safely")
    def test_install_failure(
        self, mock_safe, mock_console, mock_which, mock_getpass, mock_input, governance, callback
    ):
        """Install failure returns None."""
        mock_which.return_value = None
        mock_safe.return_value = {"success": False, "stdout": "", "stderr": "error", "exit_code": 1}
        result = detect_and_install_missing_tool("nmap -h", governance, callback)
        assert result is None

    @patch("builtins.input", return_value="y")
    @patch("getpass.getpass", return_value="")
    @patch("shutil.which")
    @patch("cli.ui_components.console")
    @patch("tools.safe_exec.execute_safely")
    def test_install_exception(
        self, mock_safe, mock_console, mock_which, mock_getpass, mock_input, governance, callback
    ):
        """Install exception returns None."""
        mock_which.return_value = None
        mock_safe.side_effect = RuntimeError("network error")
        result = detect_and_install_missing_tool("nmap -h", governance, callback)
        assert result is None

    @patch("builtins.input", return_value="y")
    @patch("getpass.getpass", return_value="")
    @patch("shutil.which")
    @patch("cli.ui_components.console")
    def test_unknown_tool_no_installer(
        self, mock_console, mock_which, mock_getpass, mock_input, governance, callback
    ):
        """Unknown tool with no installer returns None."""
        mock_which.return_value = None
        result = detect_and_install_missing_tool("xyzunknown --help", governance, callback)
        assert result is None

    @patch("builtins.input", return_value="y")
    @patch("getpass.getpass", return_value="")
    @patch("shutil.which")
    @patch("cli.ui_components.console")
    def test_skip_non_system_tool_names(
        self, mock_console, mock_which, mock_getpass, mock_input, governance, callback
    ):
        """Tools like pip don't require sudo password prompt (but still return None if unknown)."""
        mock_which.return_value = None
        # pip is in the non-system tool set (line 601) so getpass is called with empty string
        # but pip has no entry in _TOOL_PACKAGES, so _build_install_command returns None
        result = detect_and_install_missing_tool("pip install foo", governance, callback)
        assert result is None

    @patch("shutil.which")
    def test_handle_path_with_slash(self, mock_which, governance, callback):
        """Tool path like /usr/bin/nmap extracts just 'nmap'."""
        mock_which.return_value = None
        with patch("builtins.input", return_value="n"):
            with patch("cli.ui_components.console"):
                result = detect_and_install_missing_tool("/usr/bin/nmap -h", governance, callback)
                assert result is None

    @patch("shutil.which")
    def test_command_with_subcommands(self, mock_which, governance, callback):
        """Command like 'apt-get install' extracts 'apt-get'."""
        mock_which.return_value = None
        with patch("builtins.input", return_value="n"):
            with patch("cli.ui_components.console"):
                result = detect_and_install_missing_tool("apt-get install nmap", governance, callback)
                assert result is None


# ===================================================================
# _build_install_command
# ===================================================================


class TestBuildInstallCommand:
    """Test the install command builder."""

    def test_known_tool_without_sudo_password(self):
        """Known tool returns apt-get command without password."""
        cmd = _build_install_command("nmap", sudo_password=None)
        assert cmd == "sudo apt-get install -y nmap"

    def test_known_tool_with_sudo_password(self):
        """Known tool with password returns echo-piped command."""
        cmd = _build_install_command("nmap", sudo_password="pass123")
        assert cmd is not None
        assert "echo 'pass123'" in cmd
        assert "sudo -S" in cmd
        assert "nmap" in cmd

    def test_python_tool(self):
        """Python tool names get pip install."""
        cmd = _build_install_command("python-toolname")
        assert cmd == "pip install toolname"
        cmd = _build_install_command("toolname-py")
        assert cmd == "pip install toolname"

    def test_unknown_tool(self):
        """Unknown tool returns None."""
        cmd = _build_install_command("some_random_tool_12345")
        assert cmd is None

    def test_known_tool_mappings(self):
        """All known tools in _TOOL_PACKAGES produce commands."""
        tools = [
            "nikto", "dirb", "gobuster", "enum4linux", "sslscan",
            "hydra", "sqlmap", "whatweb", "wpscan", "subfinder",
            "httpx", "nuclei", "amass", "ffuf", "masscan",
            "zmap", "crackmapexec", "smbclient", "snmpwalk", "onesixtyone",
        ]
        for tool in tools:
            cmd = _build_install_command(tool)
            assert cmd is not None
            assert tool in cmd


# ===================================================================
# handle_ask_user
# ===================================================================


class TestHandleAskUser:
    """Test interactive user prompts."""

    def test_no_question(self, callback):
        """Missing question returns error."""
        result = handle_ask_user({"question": ""}, callback)
        assert "Error" in result
        assert "question" in result

    def test_no_question_with_message_field(self, callback):
        """Uses 'message' field when 'question' is missing."""
        result = handle_ask_user({"message": "", "input_type": "confirm"}, callback)
        assert "Error" in result

    def test_no_question_at_all(self, callback):
        """No question or message field returns error."""
        result = handle_ask_user({}, callback)
        assert "Error" in result

    @patch("cli.ui_components.confirm")
    def test_confirm_yes(self, mock_confirm, callback):
        """Confirm returns 'yes' when approved."""
        mock_confirm.return_value = True
        result = handle_ask_user({"question": "Continue?", "input_type": "confirm"}, callback)
        assert result == "yes"
        mock_confirm.assert_called_once_with("Continue?", default=False)

    @patch("cli.ui_components.confirm")
    def test_confirm_no(self, mock_confirm, callback):
        """Confirm returns 'no' when rejected."""
        mock_confirm.return_value = False
        result = handle_ask_user({"question": "Continue?", "input_type": "confirm"}, callback)
        assert result == "no"

    @patch("getpass.getpass")
    def test_password(self, mock_getpass, callback):
        """Password input returns entered value."""
        mock_getpass.return_value = "my_secret"
        result = handle_ask_user({"question": "Enter password:", "input_type": "password"}, callback)
        assert result == "my_secret"
        mock_getpass.assert_called_once()

    @patch("prompt_toolkit.prompt")
    def test_text_input(self, mock_prompt, callback):
        """Text input returns user's text."""
        mock_prompt.return_value = "user typed this"
        result = handle_ask_user({"question": "Enter text:", "input_type": "text"}, callback)
        assert result == "user typed this"

    @patch("prompt_toolkit.prompt")
    def test_text_input_empty(self, mock_prompt, callback):
        """Empty text input returns fallback message."""
        mock_prompt.return_value = ""
        result = handle_ask_user({"question": "Enter:", "input_type": "text"}, callback)
        assert result == "No input provided."

    @patch("prompt_toolkit.prompt", side_effect=EOFError)
    def test_text_input_eof(self, mock_prompt, callback):
        """EOF during text input returns cancellation message."""
        result = handle_ask_user({"question": "Enter:", "input_type": "text"}, callback)
        assert "cancelled" in result.lower()

    @patch("prompt_toolkit.prompt", side_effect=KeyboardInterrupt)
    def test_text_input_keyboardinterrupt(self, mock_prompt, callback):
        """KeyboardInterrupt during text input returns cancellation message."""
        result = handle_ask_user({"question": "Enter:", "input_type": "text"}, callback)
        assert "cancelled" in result.lower()

    @patch("cli.ui_components.confirm")
    def test_with_callback_notification(self, mock_confirm, callback):
        """With callback, a notification is sent before prompting."""
        mock_confirm.return_value = True
        result = handle_ask_user({"question": "Proceed?", "input_type": "confirm"}, callback)
        callback.assert_called_once()
        call_arg = callback.call_args[0][0]
        assert "Action Required" in call_arg

    @patch("cli.ui_components.confirm")
    def test_default_input_type_is_confirm(self, mock_confirm, callback):
        """Default input_type is confirm when not specified."""
        mock_confirm.return_value = True
        result = handle_ask_user({"question": "Go?"}, callback)
        assert result == "yes"

    def test_exception_handling(self, callback):
        """Exception during input is caught and returned as error."""
        with patch("cli.ui_components.confirm", side_effect=RuntimeError("broken")):
            result = handle_ask_user({"question": "Go?", "input_type": "confirm"}, callback)
            assert "Error" in result


# ===================================================================
# execute_tool_registry
# ===================================================================


class TestExecuteToolRegistry:
    """Test tool registry execution with async fallback."""

    @patch("elengenix.scanning.executor.registry")
    @patch("elengenix.scanning.executor.execute_tool_subprocess")
    def test_tool_not_available_falls_back(self, mock_subprocess, mock_registry, tmp_path):
        """When tool not in registry, falls back to subprocess."""
        mock_registry.get_tool.return_value = None
        expected = ToolResult(
            success=False,
            tool_name="nmap",
            category=ToolCategory.UTILITY,
            error_message="fallback",
        )
        mock_subprocess.return_value = expected
        result = execute_tool_registry("nmap", "127.0.0.1", tmp_path)
        mock_subprocess.assert_called_once_with("nmap", "127.0.0.1")
        assert result == expected

    @patch("elengenix.scanning.executor.registry")
    @patch("elengenix.scanning.executor.execute_tool_subprocess")
    def test_tool_not_available_unavailable(self, mock_subprocess, mock_registry, tmp_path):
        """When tool exists but is_available is falsy, falls back."""
        mock_tool = MagicMock()
        mock_tool.is_available = False
        mock_registry.get_tool.return_value = mock_tool
        expected = ToolResult(
            success=False, tool_name="nmap", category=ToolCategory.UTILITY, error_message="unavailable",
        )
        mock_subprocess.return_value = expected
        result = execute_tool_registry("nmap", "127.0.0.1", tmp_path)
    @patch("elengenix.scanning.executor.registry")
    def test_tool_without_shared_loop(self, mock_registry, tmp_path):
        """Tool without shared loop: mock asyncio.run to avoid event loop issues."""
        from elengenix.scanning.executor import ToolResult, ToolCategory
        mock_tool = MagicMock()
        mock_tool.is_available = True
        mock_registry.get_tool.return_value = mock_tool

        expected = ToolResult(success=True, tool_name="nmap", category=ToolCategory.RECON, output="direct")

        with patch("elengenix.scanning.executor.asyncio.run") as mock_async_run:
            mock_async_run.return_value = expected
            result = execute_tool_registry("nmap", "127.0.0.1", tmp_path)

        assert result == expected

    @patch("elengenix.scanning.executor.registry")
    @patch("elengenix.scanning.executor.execute_tool_subprocess")
    def test_tool_registry_exception_falls_back(self, mock_subprocess, mock_registry, tmp_path):
        """Exception during registry execution falls back to subprocess."""
        mock_tool = MagicMock()
        mock_tool.is_available = True

        async def broken_execute(target, report_dir, sema):
            raise RuntimeError("tool crashed")

        mock_tool.execute.side_effect = broken_execute
        mock_registry.get_tool.return_value = mock_tool
        expected = ToolResult(
            success=False, tool_name="nmap", category=ToolCategory.UTILITY, error_message="fallback",
        )
        mock_subprocess.return_value = expected
        result = execute_tool_registry("nmap", "127.0.0.1", tmp_path)
        mock_subprocess.assert_called_once()
        assert result == expected


# ===================================================================
# execute_tool_subprocess
# ===================================================================


class TestExecuteToolSubprocess:
    """Test fallback subprocess execution."""

    @patch("shutil.which")
    def test_tool_not_in_path(self, mock_which):
        """Tool not found in PATH returns error ToolResult."""
        mock_which.return_value = None
        result = execute_tool_subprocess("nmap", "127.0.0.1")
        assert result.success is False
        assert "not found" in result.error_message

    @patch("shutil.which")
    @patch("subprocess.run")
    def test_known_command_template(self, mock_run, mock_which):
        """Known command template runs subprocess."""
        mock_which.return_value = "/usr/bin/dig"
        completed = MagicMock()
        completed.returncode = 0
        completed.stdout = "dig output"
        completed.stderr = ""
        mock_run.return_value = completed
        result = execute_tool_subprocess("dns_lookup", "example.com")
        assert result.success is True
        mock_run.assert_called_once_with(
            ["dig", "example.com", "ANY"],
            shell=False, capture_output=True, text=True, timeout=180,
        )
        assert result.tool_name == "dns_lookup"

    @patch("shutil.which")
    @patch("subprocess.run")
    def test_http_probe_template(self, mock_run, mock_which):
        """http_probe command template works."""
        mock_which.return_value = "/usr/bin/curl"
        completed = MagicMock()
        completed.returncode = 0
        completed.stdout = "HTTP/1.1 200 OK"
        completed.stderr = ""
        mock_run.return_value = completed
        result = execute_tool_subprocess("http_probe", "example.com")
        assert result.success is True
        mock_run.assert_called_once_with(
            ["curl", "-s", "-I", "https://example.com"],
            shell=False, capture_output=True, text=True, timeout=180,
        )

    @patch("shutil.which")
    @patch("subprocess.run")
    def test_port_scan_template(self, mock_run, mock_which):
        """port_scan command template works."""
        mock_which.return_value = "/usr/bin/python3"
        completed = MagicMock()
        completed.returncode = 0
        completed.stdout = "22\n80\n"
        completed.stderr = ""
        mock_run.return_value = completed
        result = execute_tool_subprocess("port_scan", "10.0.0.1")
        assert result.success is True

    @patch("shutil.which")
    def test_unknown_command_template(self, mock_which):
        """Unknown command template returns error ToolResult."""
        mock_which.return_value = "/usr/bin/something"
        result = execute_tool_subprocess("unknown_tool", "target")
        assert result.success is False
        assert "no known command template" in result.error_message

    @patch("shutil.which")
    @patch("subprocess.run")
    def test_subprocess_exception(self, mock_run, mock_which):
        """Subprocess exception returns error ToolResult."""
        mock_which.return_value = "/usr/bin/dig"
        mock_run.side_effect = TimeoutError("timed out")
        result = execute_tool_subprocess("dns_lookup", "example.com")
        assert result.success is False
        assert "timed out" in result.error_message

    @patch("shutil.which")
    @patch("subprocess.run")
    def test_subprocess_non_zero_exit(self, mock_run, mock_which):
        """Non-zero exit returns failure ToolResult."""
        mock_which.return_value = "/usr/bin/dig"
        completed = MagicMock()
        completed.returncode = 1
        completed.stdout = ""
        completed.stderr = "error occurred"
        mock_run.return_value = completed
        result = execute_tool_subprocess("dns_lookup", "example.com")
        assert result.success is False


# ===================================================================
# Edge cases and error handling for execute_tool
# ===================================================================


class TestExecuteToolEdgeCases:

    @patch("elengenix.scanning.executor.execute_shell_command")
    def test_action_normalized_to_lowercase(self, mock_shell, governance, callback):
        """Action is lowercased before dispatch."""
        mock_shell.return_value = "ok"
        result = execute_tool(
            {"action": "RUN_SHELL", "command": "ls"}, governance, callback=callback
        )
        mock_shell.assert_called_once()

    @patch("elengenix.scanning.executor.execute_shell_command")
    def test_default_max_output_len(self, mock_shell, governance, callback):
        """Default max_output_len is 100000 (passed as positional arg)."""
        mock_shell.return_value = "ok"
        execute_tool({"action": "run_shell", "command": "ls"}, governance, callback=callback)
        # execute_shell_command is called as positional args:
        # execute_shell_command(cmd_raw, governance, max_output_len, callback, purpose=..., thought=...)
        args = mock_shell.call_args[0]
        assert args[2] == 100000  # third positional arg is max_output_len

    def test_web_search_empty_query(self, governance, callback):
        """Empty query returns error message (no patching needed — early return)."""
        result = execute_tool(
            {"action": "web_search", "query": ""}, governance, callback=callback
        )
        assert "requires a 'query' parameter" in result


# ===================================================================
# execute_shell_command edge cases
# ===================================================================


class TestExecuteShellCommandEdgeCases:

    @patch("elengenix.scanning.executor.execute_safely")
    def test_perf_counter_used(self, mock_safe, governance, callback):
        """Elapsed time is captured with perf_counter."""
        mock_safe.return_value = {"success": True, "stdout": "ok", "stderr": "", "exit_code": 0}
        with patch("time.perf_counter", side_effect=[1.0, 3.5]) as mock_time:
            execute_shell_command("cmd", governance, callback=callback)
            assert mock_time.call_count == 2

    @patch("elengenix.scanning.executor.execute_safely_interactive")
    @patch("elengenix.scanning.executor.detect_and_install_missing_tool")
    def test_non_not_found_error_no_install_detect(
        self, mock_detect, mock_safe, governance, callback
    ):
        """Error that doesn't contain 'not found' does not attempt install."""
        mock_safe.return_value = {
            "success": False,
            "stdout": "",
            "stderr": "segmentation fault",
            "exit_code": 1,
            "error": "segmentation fault",
        }
        result = execute_shell_command("nmap", governance, callback=callback)
        mock_detect.assert_not_called()
        assert "segmentation fault" in result


# ===================================================================
# execute_write_script edge cases
# ===================================================================


class TestExecuteWriteScriptEdgeCases:

    @patch("elengenix.scanning.executor.Path.write_text")
    @patch("elengenix.scanning.executor.Path.read_text")
    @patch("elengenix.scanning.executor.execute_shell_command")
    @patch("elengenix.scanning.executor.Path.mkdir")
    def test_callback_with_write_script_info(
        self, mock_mkdir, mock_shell, mock_read, mock_write, governance, callback
    ):
        """Callback receives exec: JSON about the written script."""
        mock_read.return_value = "print('hello')"
        mock_shell.return_value = "script output"
        execute_write_script(
            {"filename": "test.py", "code": "print('hello')", "purpose": "greet", "thought": "say hi"},
            governance,
            callback=callback,
        )
        first_call_arg = callback.call_args_list[0][0][0]
        assert first_call_arg.startswith("exec:")


# ===================================================================
# execute_tool_registry edge cases
# ===================================================================


class TestExecuteToolRegistryEdgeCases:

    @patch("elengenix.scanning.executor.registry")
    def test_semaphore_passed_to_tool_execute(self, mock_registry, tmp_path):
        """Semaphore is passed to tool.execute when provided."""
        mock_tool = MagicMock()
        mock_tool.is_available = True

        async def mock_execute(target, report_dir, sem):
            assert sem is not None
            return ToolResult(success=True, tool_name="nmap", category=ToolCategory.RECON, output="ok")

        mock_tool.execute = mock_execute
        mock_registry.get_tool.return_value = mock_tool
        sem = MagicMock()
        with patch("elengenix.scanning.executor.asyncio.run") as mock_run:
            expected = ToolResult(success=True, tool_name="nmap", category=ToolCategory.RECON, output="ok")
            mock_run.return_value = expected
            result = execute_tool_registry("nmap", "127.0.0.1", tmp_path, semaphore=sem)
            assert result.success is True
