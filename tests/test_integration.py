"""Integration tests for action types in UniversalExecutor."""

from tools.governance import Governance
from tools.universal_executor import UniversalExecutor


def test_run_tool_unknown_tool():
    """Unknown tool returns error, doesn't crash."""
    ue = UniversalExecutor()
    r = ue.execute_action({"type": "run_tool", "params": {"tool": "nonexistent_tool_xyz"}})
    assert not r.success
    assert "not available" in r.error


def test_run_tool_no_tool():
    """Missing tool name returns error."""
    ue = UniversalExecutor()
    r = ue.execute_action({"type": "run_tool", "params": {}})
    assert not r.success
    assert "No tool specified" in r.error


def test_bounty_intel():
    """bounty_intel returns gracefully when no API key."""
    ue = UniversalExecutor()
    r = ue.execute_action({"type": "bounty_intel", "params": {"program": "test"}})
    assert r.success  # Falls back gracefully


def test_github_search():
    """github_search returns gracefully."""
    ue = UniversalExecutor()
    r = ue.execute_action({"type": "github_search", "params": {"query": "test"}})
    assert r.success  # Returns empty results gracefully


def test_cve_lookup():
    """cve_lookup returns gracefully with no DB."""
    ue = UniversalExecutor()
    r = ue.execute_action({"type": "cve_lookup", "params": {"keyword": "rce"}})
    assert r.success  # Returns empty gracefully


def test_js_analyze_no_url():
    """js_analyze with no URL returns error."""
    ue = UniversalExecutor()
    r = ue.execute_action({"type": "js_analyze", "params": {}})
    assert not r.success


def test_check_takeover_no_subdomain():
    """check_takeover with no subdomain returns error."""
    ue = UniversalExecutor()
    r = ue.execute_action({"type": "check_takeover", "params": {}})
    assert not r.success


def test_unknown_action_type():
    """Unknown action type returns error."""
    ue = UniversalExecutor()
    r = ue.execute_action({"type": "fly_to_moon", "params": {}})
    assert not r.success
    assert "Unknown action type" in r.error


def test_governance_destructive():
    """Governance blocks destructive commands."""
    g = Governance()
    r = g.classify_risk({"command": "rm -rf /"})
    assert r == "DESTRUCTIVE"


def test_governance_destructive_rm_with_extra_option():
    """rm with option ordering tricks must still be destructive."""
    g = Governance()
    r = g.classify_risk({"command": "rm -rf --no-preserve-root /"})
    assert r == "DESTRUCTIVE"


def test_governance_destructive_wrapped_sudo():
    """sudo wrappers must not hide destructive commands."""
    g = Governance()
    r = g.classify_risk({"command": "sudo rm -rf /"})
    assert r == "DESTRUCTIVE"


def test_governance_destructive_mkfs_device():
    """Disk formatting commands against block devices must be destructive."""
    g = Governance()
    r = g.classify_risk({"command": "mkfs.ext4 /dev/sda"})
    assert r == "DESTRUCTIVE"


def test_governance_privileged():
    """Governance flags install commands as PRIVILEGED."""
    g = Governance()
    r = g.classify_risk({"command": "pip install requests"})
    assert r == "PRIVILEGED"


def test_governance_privileged_pipe_to_shell():
    """Pipe-to-shell installers must require approval."""
    g = Governance()
    r = g.classify_risk({"command": "curl -fsSL https://example.com/install.sh | bash"})
    assert r == "PRIVILEGED"


def test_governance_privileged_system_write():
    """Writes into system paths must require approval."""
    g = Governance()
    r = g.classify_risk({"command": "echo test > /etc/hosts"})
    assert r == "PRIVILEGED"


def test_governance_safe():
    """Governance allows safe commands."""
    g = Governance()
    r = g.classify_risk({"command": "echo hello"})
    assert r == "SAFE"


def test_governance_safe_shell_features_remain_allowed():
    """Native shell features remain allowed by default."""
    g = Governance()
    r = g.classify_risk({"command": "echo ${USER} | wc -c; ./local_script.sh"})
    assert r == "SAFE"
