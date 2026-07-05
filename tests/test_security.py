from core.brain import ElengenixAgent
from main import is_authorized_scan_target
from core.orchestrator import is_valid_target, normalize_target
from tools.governance import Governance


def _lightweight_agent() -> ElengenixAgent:
    """Create a lightweight agent instance for unit tests."""
    agent = ElengenixAgent.__new__(ElengenixAgent)
    agent.max_output_len = 2000
    agent.governance = Governance(require_approval_high_risk=True)
    return agent


def test_execute_tool_destructive_requires_approval():
    """DESTRUCTIVE commands now show popup for user approval (not auto-blocked)."""
    agent = _lightweight_agent()
    # Mock the popup to return "deny"
    from unittest.mock import patch
    with patch('agents.agent_executor._prompt_approval', return_value=(False, False)):
        result = agent._execute_tool({"action": "run_shell", "command": "rm -rf /"})
    assert "rejected" in result.lower() or "blocked" in result.lower() or "deny" in result.lower()


def test_execute_tool_destructive_dd_requires_approval():
    """DESTRUCTIVE dd commands now show popup for user approval."""
    agent = _lightweight_agent()
    from unittest.mock import patch
    with patch('agents.agent_executor._prompt_approval', return_value=(False, False)):
        result = agent._execute_tool({"action": "run_shell", "command": "dd if=/dev/zero of=/dev/sda"})
    assert "rejected" in result.lower() or "blocked" in result.lower() or "deny" in result.lower()


def test_execute_tool_allows_metacharacters():
    """Pipes, redirects, and chaining are now ALLOWED."""
    agent = _lightweight_agent()
    result = agent._execute_tool({"action": "run_shell", "command": "echo hello; echo world"})
    assert "hello\nworld" in result or "hello" in result


def test_execute_tool_allows_safe_command():
    """echo is SAFE → should run freely."""
    agent = _lightweight_agent()
    result = agent._execute_tool({"action": "run_shell", "command": "echo hello"})
    assert "hello" in result


def test_execute_tool_allows_variable_expansion():
    """${} is now ALLOWED — shell=True expands variables natively."""
    agent = _lightweight_agent()
    result = agent._execute_tool({"action": "run_shell", "command": "echo ${USER}"})
    assert "command failed" not in result.lower()


def test_execute_tool_allows_path_in_binary():
    """./scripts are now ALLOWED — AI can run custom scripts."""
    agent = _lightweight_agent()
    result = agent._execute_tool({"action": "run_shell", "command": "./nonexistent_script.sh"})
    # Will fail to execute (file not found) but NOT blocked by governance
    assert "blocked" not in result.lower()


def test_execute_tool_allows_any_binary():
    """Any binary is now allowed — no whitelist."""
    agent = _lightweight_agent()
    result = agent._execute_tool({"action": "run_shell", "command": "nonexistent_tool_xyz"})
    # Should fail with "not found" or similar, NOT "not in allowlist"
    assert "not in" not in result.lower()


def test_target_validation_and_normalization():
    assert normalize_target("https://target-site.net/api/v1") == "target-site.net"
    assert is_valid_target("example.com") is True
    assert is_valid_target("example.com; rm -rf /") is False
    assert is_valid_target("target.com | nmap") is False


def test_authorized_scan_target_allows_when_scope_unset(monkeypatch):
    """Without configured scope, valid public targets remain allowed."""
    monkeypatch.setattr("core.orchestrator.ALLOWED_DOMAINS", set())
    assert is_authorized_scan_target("example.com") is True


def test_authorized_scan_target_enforces_scope(monkeypatch):
    """Configured scope must gate scan-capable entrypoints."""
    monkeypatch.setattr("core.orchestrator.ALLOWED_DOMAINS", {"example.com"})
    assert is_authorized_scan_target("example.com") is True
    assert is_authorized_scan_target("https://api.example.com/v1/search") is True
    assert is_authorized_scan_target("other.com") is False


def test_authorized_scan_target_rejects_invalid_before_scope(monkeypatch):
    """Invalid shell-like targets remain blocked before scope checks matter."""
    monkeypatch.setattr("core.orchestrator.ALLOWED_DOMAINS", {"example.com"})
    assert is_authorized_scan_target("example.com; rm -rf /") is False
