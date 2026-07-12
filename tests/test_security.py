"""test_security.py — Tests for security-sensitive operations.

Tests target validation, governance enforcement, and shell-execution
security boundaries.
"""

from main import is_authorized_scan_target
from pipeline.scope import is_valid_target, normalize_target
from tools.governance import Governance


def _default_gov() -> Governance:
    """Minimal governance instance for unit tests."""
    return Governance(require_approval_high_risk=True)


def _execute_tool(action_data, governance=None, max_output_len=2000):
    """Minimal _execute_tool equivalent using executor module."""
    from elengenix.scanning.executor import execute_tool as _exec
    return _exec(action_data, governance or _default_gov(), max_output_len)


def test_execute_tool_destructive_requires_approval():
    """DESTRUCTIVE commands now show popup for user approval (not auto-blocked)."""
    from unittest.mock import patch

    with patch("elengenix.scanning.executor._prompt_approval", return_value=(False, False)):
        result = _execute_tool({"action": "run_shell", "command": "rm -rf /"})
    assert "rejected" in result.lower() or "blocked" in result.lower() or "deny" in result.lower()


def test_execute_tool_destructive_dd_requires_approval():
    """DESTRUCTIVE dd commands now show popup for user approval."""
    from unittest.mock import patch

    with patch("elengenix.scanning.executor._prompt_approval", return_value=(False, False)):
        result = _execute_tool(
            {"action": "run_shell", "command": "dd if=/dev/zero of=/dev/sda"}
        )
    assert "rejected" in result.lower() or "blocked" in result.lower() or "deny" in result.lower()


def test_execute_tool_allows_metacharacters():
    """Pipes, redirects, and chaining are now ALLOWED."""
    result = _execute_tool({"action": "run_shell", "command": "echo hello; echo world"})
    assert "hello\nworld" in result or "hello" in result


def test_execute_tool_allows_safe_command():
    """echo is SAFE -> should run freely."""
    result = _execute_tool({"action": "run_shell", "command": "echo hello"})
    assert "hello" in result


def test_execute_tool_allows_variable_expansion():
    """${} is now ALLOWED -- shell=True expands variables natively."""
    result = _execute_tool({"action": "run_shell", "command": "echo ${USER}"})
    assert "command failed" not in result.lower()


def test_execute_tool_allows_path_in_binary():
    """./scripts are now ALLOWED -- AI can run custom scripts."""
    result = _execute_tool({"action": "run_shell", "command": "./nonexistent_script.sh"})
    # Will fail to execute (file not found) but NOT blocked by governance
    assert "blocked" not in result.lower()


def test_execute_tool_allows_any_binary():
    """Any binary is now allowed -- no whitelist."""
    result = _execute_tool({"action": "run_shell", "command": "nonexistent_tool_xyz"})
    # Should fail with "not found" or similar, NOT "not in allowlist"
    assert "not in" not in result.lower()


def test_target_validation_and_normalization():
    assert normalize_target("https://target-site.net/api/v1") == "target-site.net"
    assert is_valid_target("example.com") is True
    assert is_valid_target("example.com; rm -rf /") is False
    assert is_valid_target("target.com | nmap") is False


def test_authorized_scan_target_allows_when_scope_unset(monkeypatch):
    """Without configured scope, targets are denied (fail-closed)."""
    monkeypatch.setattr("pipeline.scope._default_scope._domains", set())
    assert is_authorized_scan_target("example.com") is False


def test_authorized_scan_target_enforces_scope(monkeypatch):
    """Configured scope must gate scan-capable entrypoints."""
    monkeypatch.setattr("pipeline.scope._default_scope._domains", {"example.com"})
    assert is_authorized_scan_target("example.com") is True
    assert is_authorized_scan_target("https://api.example.com/v1/search") is True
    assert is_authorized_scan_target("other.com") is False


def test_authorized_scan_target_rejects_invalid_before_scope(monkeypatch):
    """Invalid shell-like targets remain blocked before scope checks matter."""
    monkeypatch.setattr("pipeline.scope._default_scope._domains", {"example.com"})
    assert is_authorized_scan_target("example.com; rm -rf /") is False
