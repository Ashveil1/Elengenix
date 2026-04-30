from agent_brain import ElengenixAgent
from orchestrator import is_valid_target, normalize_target


def _lightweight_agent() -> ElengenixAgent:
    """Create a lightweight agent instance for unit tests."""
    agent = ElengenixAgent.__new__(ElengenixAgent)
    agent.max_output_len = 2000
    agent.ALLOWED_TOOLS = ElengenixAgent.ALLOWED_TOOLS
    return agent


def test_execute_tool_blocks_unauthorized_binary():
    agent = _lightweight_agent()
    result = agent._execute_tool({"action": "run_shell", "command": "bash -c whoami"})
    assert "not in the security allowlist" in result


def test_execute_tool_blocks_shell_metacharacters():
    agent = _lightweight_agent()
    result = agent._execute_tool({"action": "run_shell", "command": "nmap -sV example.com; whoami"})
    assert "prohibited characters" in result


def test_execute_tool_allows_safe_allowlisted_command():
    agent = _lightweight_agent()
    result = agent._execute_tool({"action": "run_shell", "command": "echo hello"})
    assert "hello" in result


def test_target_validation_and_normalization():
    assert normalize_target("https://target-site.net/api/v1") == "target-site.net"
    assert is_valid_target("example.com") is True
    assert is_valid_target("example.com; rm -rf /") is False
    assert is_valid_target("target.com | nmap") is False
