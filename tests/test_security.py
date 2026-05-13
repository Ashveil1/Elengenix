from agent_brain import ElengenixAgent
from orchestrator import is_valid_target, normalize_target
from tools.governance import Governance


def _lightweight_agent() -> ElengenixAgent:
    """Create a lightweight agent instance for unit tests."""
    agent = ElengenixAgent.__new__(ElengenixAgent)
    agent.max_output_len = 2000
    agent.governance = Governance(require_approval_high_risk=True)
    return agent


def test_execute_tool_blocks_destructive_rm_rf():
    """DESTRUCTIVE commands like rm -rf / must be unconditionally blocked."""
    agent = _lightweight_agent()
    result = agent._execute_tool({"action": "run_shell", "command": "rm -rf /"})
    assert "blocked" in result.lower() or "denied" in result.lower()


def test_execute_tool_blocks_destructive_dd():
    agent = _lightweight_agent()
    result = agent._execute_tool({"action": "run_shell", "command": "dd if=/dev/zero of=/dev/sda"})
    assert "blocked" in result.lower() or "denied" in result.lower()


def test_execute_tool_blocks_metacharacters():
    """safe_exec FORBIDDEN_CHARS (| & ; ` > < etc.) still blocked."""
    agent = _lightweight_agent()
    result = agent._execute_tool({"action": "run_shell", "command": "echo hello; whoami"})
    assert "prohibited" in result.lower() or "blocked" in result.lower()


def test_execute_tool_allows_safe_command():
    """echo is SAFE → should run freely."""
    agent = _lightweight_agent()
    result = agent._execute_tool({"action": "run_shell", "command": "echo hello"})
    assert "hello" in result


def test_execute_tool_allows_variable_expansion():
    """${} is now ALLOWED — shell=False prevents expansion."""
    agent = _lightweight_agent()
    result = agent._execute_tool({"action": "run_shell", "command": "echo ${HOME}"})
    # Should run the command (echo ${HOME} literally, no shell expansion)
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
