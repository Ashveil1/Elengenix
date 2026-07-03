"""test_main_coverage.py - Comprehensive tests for main.py to boost coverage.

Covers: _check_module, validate_target, ensure_dependencies, ensure_path_priorities,
is_authorized_scan_target, require_authorized_scan_target, show_banner, _cmd_list_tools,
_cmd_examples, _cmd_prefetch, _cmd_scan_report, _cmd_marketplace, _cmd_update,
_cmd_plugins, and main() command dispatch branches.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

# Common patch dict used by all main() tests to prevent stdin blocking
# and the print_error scoping bug in main()'s except handler.
_MAIN_SAFE = {
    "ui_components.confirm": MagicMock(return_value=False),
}


@pytest.fixture(autouse=True)
def _reset_main_depth():
    """Reset main._depth before every test to prevent accumulation."""
    import main as _main_mod
    _main_mod.main._depth = 0
    yield
    _main_mod.main._depth = 0


# ═══════════════════════════════════════════════════════════════════════════
# _check_module
# ═══════════════════════════════════════════════════════════════════════════


def test_check_module_existing():
    from main import _check_module
    assert _check_module("json") is True


def test_check_module_missing():
    from main import _check_module
    assert _check_module("nonexistent_fake_module_xyz") is False


def test_check_module_dotted_path():
    from main import _check_module
    assert _check_module("os.path") is True


def test_check_module_value_error():
    from main import _check_module
    with patch("importlib.util.find_spec", side_effect=ValueError("bad")):
        assert _check_module("something") is False


# ═══════════════════════════════════════════════════════════════════════════
# validate_target
# ═══════════════════════════════════════════════════════════════════════════


def test_validate_target_valid_domain():
    from main import validate_target
    assert validate_target("example.com") is True


def test_validate_target_valid_subdomain():
    from main import validate_target
    assert validate_target("sub.example.com") is True


def test_validate_target_valid_ip():
    from main import validate_target
    assert validate_target("8.8.8.8") is True


def test_validate_target_empty():
    from main import validate_target
    assert validate_target("") is False


def test_validate_target_too_long():
    from main import validate_target
    assert validate_target("a" * 254) is False


def test_validate_target_shell_metachar_pipe():
    from main import validate_target
    assert validate_target("example.com|cat") is False


def test_validate_target_shell_metachar_amp():
    from main import validate_target
    assert validate_target("example.com&whoami") is False


def test_validate_target_shell_metachar_semicolon():
    from main import validate_target
    assert validate_target("example.com;rm") is False


def test_validate_target_shell_metachar_backtick():
    from main import validate_target
    assert validate_target("`whoami`.com") is False


def test_validate_target_shell_metachar_dollar_paren():
    from main import validate_target
    assert validate_target("$(whoami).com") is False


def test_validate_target_shell_metachar_dollar_brace():
    from main import validate_target
    assert validate_target("${whoami}.com") is False


def test_validate_target_shell_metachar_gt():
    from main import validate_target
    assert validate_target("example.com>file") is False


def test_validate_target_shell_metachar_lt():
    from main import validate_target
    assert validate_target("example.com<file") is False


def test_validate_target_shell_metachar_backslash():
    from main import validate_target
    assert validate_target("example.com\\etc") is False


def test_validate_target_shell_metachar_single_quote():
    from main import validate_target
    assert validate_target("example.com'") is False


def test_validate_target_shell_metachar_double_quote():
    from main import validate_target
    assert validate_target('example.com"') is False


def test_validate_target_shell_metachar_excl():
    from main import validate_target
    assert validate_target("example.com!") is False


def test_validate_target_shell_metachar_newline():
    from main import validate_target
    assert validate_target("example.com\n") is False


def test_validate_target_shell_metachar_cr():
    from main import validate_target
    assert validate_target("example.com\r") is False


def test_validate_target_private_ip():
    from main import validate_target
    assert validate_target("192.168.1.1") is False


def test_validate_target_loopback_ip():
    from main import validate_target
    assert validate_target("127.0.0.1") is False


def test_validate_target_reserved_ip():
    from main import validate_target
    assert validate_target("240.0.0.1") is False


def test_validate_target_link_local_ip():
    from main import validate_target
    assert validate_target("169.254.1.1") is False


def test_validate_target_strips_http():
    from main import validate_target
    assert validate_target("http://example.com") is True


def test_validate_target_strips_https():
    from main import validate_target
    assert validate_target("https://example.com") is True


def test_validate_target_strips_path():
    from main import validate_target
    assert validate_target("example.com/path/to/resource") is True


def test_validate_target_invalid_domain():
    from main import validate_target
    assert validate_target("-invalid.com") is False


def test_validate_target_ip_with_port():
    from main import validate_target
    assert validate_target("8.8.8.8:8080") is False


def test_validate_target_domain_with_hyphen():
    from main import validate_target
    assert validate_target("my-site.example.com") is True


def test_validate_target_tld_only():
    from main import validate_target
    assert validate_target("com") is False


# ═══════════════════════════════════════════════════════════════════════════
# ensure_dependencies
# ═══════════════════════════════════════════════════════════════════════════


def test_ensure_dependencies_all_present():
    from main import ensure_dependencies
    with patch("main._check_module", return_value=True):
        assert ensure_dependencies() is True


def test_ensure_dependencies_core_missing():
    from main import ensure_dependencies
    def fake_check(mod):
        return mod != "yaml"
    with patch("main._check_module", side_effect=fake_check):
        assert ensure_dependencies() is False


def test_ensure_dependencies_optional_missing():
    from main import ensure_dependencies
    def fake_check(mod):
        return mod != "openai"
    with patch("main._check_module", side_effect=fake_check):
        assert ensure_dependencies() is True


# ═══════════════════════════════════════════════════════════════════════════
# ensure_path_priorities
# ═══════════════════════════════════════════════════════════════════════════


def test_ensure_path_priorities_no_new_dirs():
    from main import ensure_path_priorities
    with patch("pathlib.Path.home", return_value=Path("/fake")), \
         patch("pathlib.Path.is_dir", return_value=False):
        old_path = os.environ.get("PATH", "")
        ensure_path_priorities()
        assert os.environ.get("PATH", "") == old_path


# ═══════════════════════════════════════════════════════════════════════════
# is_authorized_scan_target
# ═══════════════════════════════════════════════════════════════════════════


def test_is_authorized_scan_target_invalid():
    from main import is_authorized_scan_target
    assert is_authorized_scan_target("") is False


def test_is_authorized_scan_target_in_scope():
    from main import is_authorized_scan_target
    with patch("main.validate_target", return_value=True), \
         patch("orchestrator.is_in_scope", return_value=True):
        assert is_authorized_scan_target("example.com") is True


def test_is_authorized_scan_target_out_of_scope():
    from main import is_authorized_scan_target
    with patch("main.validate_target", return_value=True), \
         patch("orchestrator.is_in_scope", return_value=False):
        assert is_authorized_scan_target("evil.com") is False


# ═══════════════════════════════════════════════════════════════════════════
# require_authorized_scan_target
# ═══════════════════════════════════════════════════════════════════════════


def test_require_authorized_invalid():
    from main import require_authorized_scan_target
    with patch("main.validate_target", return_value=False), \
         patch("main.print_error") as mock_err:
        assert require_authorized_scan_target("bad") is False
        mock_err.assert_called_once()


def test_require_authorized_out_of_scope():
    from main import require_authorized_scan_target
    with patch("main.validate_target", return_value=True), \
         patch("orchestrator.is_in_scope", return_value=False), \
         patch("orchestrator.normalize_target", return_value="evil.com"), \
         patch("main.print_error") as mock_err:
        assert require_authorized_scan_target("evil.com") is False
        mock_err.assert_called()


def test_require_authorized_valid():
    from main import require_authorized_scan_target
    with patch("main.validate_target", return_value=True), \
         patch("orchestrator.is_in_scope", return_value=True), \
         patch("orchestrator.normalize_target", return_value="example.com"):
        assert require_authorized_scan_target("example.com") is True


# ═══════════════════════════════════════════════════════════════════════════
# show_banner
# ═══════════════════════════════════════════════════════════════════════════


def test_show_banner():
    from main import show_banner
    with patch("ui_components.show_main_banner") as mock_b:
        show_banner()
        mock_b.assert_called_once()


# ═══════════════════════════════════════════════════════════════════════════
# _cmd_examples
# ═══════════════════════════════════════════════════════════════════════════


def test_cmd_examples():
    from main import _cmd_examples
    _cmd_examples()


# ═══════════════════════════════════════════════════════════════════════════
# _cmd_list_tools
# ═══════════════════════════════════════════════════════════════════════════


def test_cmd_list_tools():
    from main import _cmd_list_tools
    _cmd_list_tools()


def test_cmd_list_tools_with_mocked_registry():
    from main import _cmd_list_tools
    mock_reg = MagicMock()
    mock_reg.list_available_tools.return_value = {
        "test_tool": {"category": "recon", "description": "Test", "available": True}
    }
    with patch.dict("sys.modules", {"tools.tool_registry": SimpleNamespace(registry=mock_reg)}):
        _cmd_list_tools()


# ═══════════════════════════════════════════════════════════════════════════
# _cmd_scan_report
# ═══════════════════════════════════════════════════════════════════════════


def test_cmd_scan_report_no_file():
    from main import _cmd_scan_report
    args = SimpleNamespace(target=None, format="html", output=None)
    _cmd_scan_report(args)


def test_cmd_scan_report_file_not_found():
    from main import _cmd_scan_report
    args = SimpleNamespace(target="/nonexistent.json", format="html", output=None)
    _cmd_scan_report(args)


def test_cmd_scan_report_empty_findings():
    from main import _cmd_scan_report
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump([], f)
        f.flush()
        tmp = f.name
    try:
        args = SimpleNamespace(target=tmp, format="html", output=None)
        _cmd_scan_report(args)
    finally:
        os.unlink(tmp)


def test_cmd_scan_report_valid_findings():
    from main import _cmd_scan_report
    findings = [{"id": "1", "title": "XSS", "severity": "High", "cvss": 7.5,
                 "url": "http://example.com", "type": "XSS", "details": "Found XSS",
                 "impact": "High", "remediation": "Fix it"}]
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump({"target": "example.com", "findings": findings}, f)
        f.flush()
        tmp = f.name
    try:
        args = SimpleNamespace(target=tmp, format="html", output=None)
        _cmd_scan_report(args)
    finally:
        os.unlink(tmp)


def test_cmd_scan_report_dict_findings():
    from main import _cmd_scan_report
    findings = [{"id": "1", "title": "SQLi", "severity": "Critical",
                 "cvss_score": 9.8, "endpoint": "http://example.com/api",
                 "vuln_class": "SQLi", "description": "SQL injection"}]
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump({"target": "example.com", "findings": findings}, f)
        f.flush()
        tmp = f.name
    try:
        args = SimpleNamespace(target=tmp, format="md", output=None)
        _cmd_scan_report(args)
    finally:
        os.unlink(tmp)


def test_cmd_scan_report_all_formats():
    from main import _cmd_scan_report
    findings = [{"id": "1", "title": "Test", "severity": "Low", "cvss": 2.0}]
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(findings, f)
        f.flush()
        tmp = f.name
    try:
        out_dir = tempfile.mkdtemp()
        args = SimpleNamespace(target=tmp, format="all", output=f"{out_dir}/report")
        _cmd_scan_report(args)
    finally:
        os.unlink(tmp)


def test_cmd_scan_report_unknown_format():
    from main import _cmd_scan_report
    findings = [{"id": "1", "title": "Test", "severity": "Low", "cvss": 2.0}]
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(findings, f)
        f.flush()
        tmp = f.name
    try:
        args = SimpleNamespace(target=tmp, format="xml", output=None)
        _cmd_scan_report(args)
    finally:
        os.unlink(tmp)


def test_cmd_scan_report_invalid_json():
    from main import _cmd_scan_report
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        f.write("not valid json {{{")
        f.flush()
        tmp = f.name
    try:
        args = SimpleNamespace(target=tmp, format="html", output=None)
        _cmd_scan_report(args)
    finally:
        os.unlink(tmp)


# ═══════════════════════════════════════════════════════════════════════════
# _cmd_update
# ═══════════════════════════════════════════════════════════════════════════


def test_cmd_update_check_no_update():
    from main import _cmd_update
    mock_u = MagicMock()
    mock_u.current_version = "1.0.0"
    mock_u.check_for_updates.return_value = None
    mock_u.stats.return_value = {"repo": "url"}
    with patch("tools.updater.Updater", return_value=mock_u):
        _cmd_update(SimpleNamespace(check=True, apply=False, force=False, yes=False))


def test_cmd_update_check_with_update():
    from main import _cmd_update
    rel = MagicMock()
    rel.version = "2.0.0"
    rel.tag = "v2.0.0"
    rel.published_at = "2025-01-15"
    rel.url = "https://github.com/test"
    mock_u = MagicMock()
    mock_u.current_version = "1.0.0"
    mock_u.check_for_updates.return_value = rel
    mock_u.stats.return_value = {"repo": "url"}
    with patch("tools.updater.Updater", return_value=mock_u):
        _cmd_update(SimpleNamespace(check=True, apply=False, force=False, yes=False))


def test_cmd_update_apply_no_release():
    from main import _cmd_update
    mock_u = MagicMock()
    mock_u.current_version = "1.0.0"
    mock_u.check_for_updates.return_value = None
    mock_u.stats.return_value = {}
    with patch("tools.updater.Updater", return_value=mock_u):
        _cmd_update(SimpleNamespace(check=False, apply=True, force=False, yes=False))


def test_cmd_update_apply_yes():
    from main import _cmd_update
    rel = MagicMock()
    rel.version = "2.0.0"
    mock_u = MagicMock()
    mock_u.current_version = "1.0.0"
    mock_u.check_for_updates.return_value = rel
    mock_u.apply_update.return_value = (True, "OK")
    mock_u.stats.return_value = {}
    with patch("tools.updater.Updater", return_value=mock_u):
        _cmd_update(SimpleNamespace(check=False, apply=True, force=False, yes=True))
        mock_u.apply_update.assert_called_once_with(rel)


def test_cmd_update_default_status():
    from main import _cmd_update
    mock_u = MagicMock()
    mock_u.current_version = "1.0.0"
    mock_u.check_for_updates.return_value = None
    mock_u.stats.return_value = {}
    with patch("tools.updater.Updater", return_value=mock_u):
        _cmd_update(SimpleNamespace(check=False, apply=False, force=False, yes=False))


def test_cmd_update_apply_user_declines():
    from main import _cmd_update
    rel = MagicMock()
    rel.version = "2.0.0"
    mock_u = MagicMock()
    mock_u.current_version = "1.0.0"
    mock_u.check_for_updates.return_value = rel
    mock_u.stats.return_value = {}
    with patch("tools.updater.Updater", return_value=mock_u), \
         patch("builtins.input", return_value="n"):
        _cmd_update(SimpleNamespace(check=False, apply=True, force=False, yes=False))
        mock_u.apply_update.assert_not_called()


# ═══════════════════════════════════════════════════════════════════════════
# _cmd_marketplace
# ═══════════════════════════════════════════════════════════════════════════


def test_cmd_marketplace_list_empty():
    from main import _cmd_marketplace
    mock_m = MagicMock()
    mock_m.list_installed.return_value = []
    mock_m.install_dir = "/tmp"
    with patch("tools.marketplace.Marketplace", return_value=mock_m):
        _cmd_marketplace(SimpleNamespace(subcommand="list", query=None, verified=False, upgrade=False))


def test_cmd_marketplace_list_with_plugins():
    from main import _cmd_marketplace
    mock_m = MagicMock()
    mock_m.list_installed.return_value = [{"name": "p", "version": "1", "author": "a", "description": "d"}]
    with patch("tools.marketplace.Marketplace", return_value=mock_m):
        _cmd_marketplace(SimpleNamespace(subcommand="list", query=None, verified=False, upgrade=False))


def test_cmd_marketplace_search():
    from main import _cmd_marketplace
    entry = MagicMock()
    entry.name = "plug"
    entry.version = "1.0"
    entry.downloads = 100
    entry.stars = 5
    entry.description = "Desc"
    entry.verified = True
    entry.tags = ["sec"]
    mock_m = MagicMock()
    mock_m.search.return_value = [entry]
    with patch("tools.marketplace.Marketplace", return_value=mock_m):
        _cmd_marketplace(SimpleNamespace(subcommand="search", query="sec", verified=False, upgrade=False))


def test_cmd_marketplace_search_empty():
    from main import _cmd_marketplace
    mock_m = MagicMock()
    mock_m.search.return_value = []
    with patch("tools.marketplace.Marketplace", return_value=mock_m):
        _cmd_marketplace(SimpleNamespace(subcommand="search", query="none", verified=False, upgrade=False))


def test_cmd_marketplace_install():
    from main import _cmd_marketplace
    mock_m = MagicMock()
    mock_m.install.return_value = (True, "Installed")
    with patch("tools.marketplace.Marketplace", return_value=mock_m):
        args = SimpleNamespace(subcommand="install", name="my-plugin", query=None, verified=False, upgrade=False, target=None)
        _cmd_marketplace(args)
        mock_m.install.assert_called_once_with("my-plugin", upgrade=False)


def test_cmd_marketplace_install_no_name():
    from main import _cmd_marketplace
    mock_m = MagicMock()
    with patch("tools.marketplace.Marketplace", return_value=mock_m):
        _cmd_marketplace(SimpleNamespace(subcommand="install", name=None, query=None, verified=False, upgrade=False, target=None))


def test_cmd_marketplace_uninstall():
    from main import _cmd_marketplace
    mock_m = MagicMock()
    mock_m.uninstall.return_value = (True, "Gone")
    with patch("tools.marketplace.Marketplace", return_value=mock_m):
        args = SimpleNamespace(subcommand="uninstall", name="my-plugin", query=None, verified=False, upgrade=False, target=None)
        _cmd_marketplace(args)
        mock_m.uninstall.assert_called_once_with("my-plugin")


def test_cmd_marketplace_uninstall_no_name():
    from main import _cmd_marketplace
    mock_m = MagicMock()
    with patch("tools.marketplace.Marketplace", return_value=mock_m):
        _cmd_marketplace(SimpleNamespace(subcommand="uninstall", name=None, query=None, verified=False, upgrade=False, target=None))


def test_cmd_marketplace_unknown_sub():
    from main import _cmd_marketplace
    mock_m = MagicMock()
    with patch("tools.marketplace.Marketplace", return_value=mock_m):
        _cmd_marketplace(SimpleNamespace(subcommand="unknown", query=None, verified=False, upgrade=False))


# ═══════════════════════════════════════════════════════════════════════════
# _cmd_plugins
# ═══════════════════════════════════════════════════════════════════════════


def _mock_plugin(name="test", state="active"):
    p = MagicMock()
    p.name = name
    p.manifest.version = "1.0"
    p.manifest.author = "tester"
    p.manifest.description = "Test"
    p.manifest.sdk_version = "1.0"
    p.manifest.capabilities = []
    p.manifest.tags = []
    p.state.value = state
    p.registered_tools = ["tool1"]
    p.registered_commands = ["cmd1"]
    p.registered_ai_providers = []
    p.registered_hooks = []
    p.error = None
    p.path = "/tmp/plugin"
    return p


def test_cmd_plugins_list_empty():
    from main import _cmd_plugins
    host = MagicMock()
    host.list_plugins.return_value = []
    with patch("tools.ecosystem.discover_and_load", return_value=host):
        _cmd_plugins(SimpleNamespace(subcommand="list", name=None, target=None))


def test_cmd_plugins_list_with_plugins():
    from main import _cmd_plugins
    host = MagicMock()
    host.list_plugins.return_value = [_mock_plugin()]
    with patch("tools.ecosystem.discover_and_load", return_value=host):
        _cmd_plugins(SimpleNamespace(subcommand="list", name=None, target=None))


def test_cmd_plugins_info():
    from main import _cmd_plugins
    host = MagicMock()
    host.get_plugin.return_value = _mock_plugin()
    with patch("tools.ecosystem.discover_and_load", return_value=host):
        _cmd_plugins(SimpleNamespace(subcommand="info", name="test", target=None))


def test_cmd_plugins_info_not_found():
    from main import _cmd_plugins
    host = MagicMock()
    host.get_plugin.return_value = None
    with patch("tools.ecosystem.discover_and_load", return_value=host):
        _cmd_plugins(SimpleNamespace(subcommand="info", name="none", target=None))


def test_cmd_plugins_info_no_name():
    from main import _cmd_plugins
    host = MagicMock()
    with patch("tools.ecosystem.discover_and_load", return_value=host):
        _cmd_plugins(SimpleNamespace(subcommand="info", name=None, target=None))


def test_cmd_plugins_reload():
    from main import _cmd_plugins
    host = MagicMock()
    result = MagicMock()
    result.name = "test"
    host.reload.return_value = result
    with patch("tools.ecosystem.discover_and_load", return_value=host):
        _cmd_plugins(SimpleNamespace(subcommand="reload", name="test", target=None))


def test_cmd_plugins_reload_not_found():
    from main import _cmd_plugins
    host = MagicMock()
    host.reload.return_value = None
    with patch("tools.ecosystem.discover_and_load", return_value=host):
        _cmd_plugins(SimpleNamespace(subcommand="reload", name="none", target=None))


def test_cmd_plugins_reload_no_name():
    from main import _cmd_plugins
    host = MagicMock()
    with patch("tools.ecosystem.discover_and_load", return_value=host):
        _cmd_plugins(SimpleNamespace(subcommand="reload", name=None, target=None))


def test_cmd_plugins_unknown_sub():
    from main import _cmd_plugins
    host = MagicMock()
    with patch("tools.ecosystem.discover_and_load", return_value=host):
        _cmd_plugins(SimpleNamespace(subcommand="unknown", name=None, target=None))


# ═══════════════════════════════════════════════════════════════════════════
# _cmd_prefetch
# ═══════════════════════════════════════════════════════════════════════════


def test_cmd_prefetch_runs():
    from main import _cmd_prefetch
    _cmd_prefetch()


# ═══════════════════════════════════════════════════════════════════════════
# main() command dispatch
# ═══════════════════════════════════════════════════════════════════════════


def _run_main(argv, extra_patches=None):
    """Run main() with common safe patches. Always patches confirm."""
    ep = extra_patches or {}
    with patch("main.ensure_path_priorities"), \
         patch("main.show_banner"), \
         patch("main.ensure_dependencies", return_value=True), \
         patch("tools.welcome_wizard.WelcomeWizard"), \
         patch("tools.history_manager.get_history_manager", return_value=MagicMock(get_contextual_suggestions=MagicMock(return_value=[]))), \
         patch("ui_components.confirm", return_value=False), \
         patch("tools.auto_detector.CommandSimplifier.simplify", side_effect=lambda cmd: cmd), \
         patch("tools.auto_detector.AutoDetector.detect", return_value={"action": "ai", "module": "ai", "explanation": "test", "confidence": 0.5}), \
         patch("sys.argv", ["main.py"] + argv):
        # Apply any extra patches
        active = []
        for path, val in ep.items():
            if isinstance(val, MagicMock) and not hasattr(val, '_mock_name'):
                # It's a MagicMock return value or side_effect - wrap it
                p = patch(path, val)
            else:
                p = patch(path, val)
            p.start()
            active.append(p)
        try:
            from main import main
            main()
        finally:
            for p in active:
                p.stop()


def test_main_help():
    _run_main(["help"])


def test_main_unknown_no_suggestion():
    mock_suggester = MagicMock()
    mock_suggester.suggest_correction.return_value = None
    mock_simplifier = MagicMock()
    mock_simplifier.get_help_text.return_value = "Help"
    _run_main(["foobar"], {
        "tools.command_suggest.CommandSuggester": MagicMock(return_value=mock_suggester),
        "tools.auto_detector.CommandSimplifier": mock_simplifier,
    })


def test_main_unknown_with_correction_declined():
    mock_suggester = MagicMock()
    mock_suggester.suggest_correction.return_value = "scan"
    mock_simplifier = MagicMock()
    mock_simplifier.get_help_text.return_value = "Help"
    mock_hist = MagicMock()
    mock_hist.get_contextual_suggestions.return_value = []
    mock_hist.get_recent_commands.return_value = []
    _run_main(["scn"], {
        "tools.command_suggest.CommandSuggester": MagicMock(return_value=mock_suggester),
        "tools.auto_detector.CommandSimplifier": mock_simplifier,
        "tools.history_manager.get_history_manager": MagicMock(return_value=mock_hist),
        "ui_components.confirm": MagicMock(return_value=False),
    })


def test_main_list_tools():
    _run_main(["list-tools"], {"main._cmd_list_tools": MagicMock()})


def test_main_examples():
    _run_main(["examples"], {"main._cmd_examples": MagicMock()})


def test_main_prefetch():
    _run_main(["prefetch"], {"main._cmd_prefetch": MagicMock()})


def test_main_scan_report():
    _run_main(["scan-report", "f.json"], {"main._cmd_scan_report": MagicMock()})


def test_main_scan():
    _run_main(["scan", "example.com"], {"commands.scan.handle_scan": MagicMock()})


def test_main_doctor():
    _run_main(["doctor"], {"tools.doctor.check_health": MagicMock()})


def test_main_configure():
    _run_main(["configure"], {"tools.config_wizard.run_config_wizard": MagicMock()})


def test_main_update():
    _run_main(["update"], {"main._cmd_update": MagicMock()})


def test_main_arsenal():
    _run_main(["arsenal"], {"tools_menu.show_tools_menu": MagicMock()})


def test_main_cve_update_success():
    mock_db = MagicMock()
    mock_db.update_database.return_value = {"status": "success", "added": 5, "updated": 10, "total": 1000}
    _run_main(["cve-update"], {"tools.cve_database.get_cve_database": MagicMock(return_value=mock_db)})


def test_main_cve_update_failure():
    mock_db = MagicMock()
    mock_db.update_database.return_value = {"status": "error", "error": "Net err"}
    _run_main(["cve-update"], {"tools.cve_database.get_cve_database": MagicMock(return_value=mock_db)})


def test_main_cve_update_exception():
    _run_main(["cve-update"], {"tools.cve_database.get_cve_database": MagicMock(side_effect=Exception("err"))})


def test_main_research_no_target():
    _run_main(["research"])


def test_main_research_cve():
    mock_res = MagicMock()
    mock_cve = MagicMock()
    mock_cve.cve_id = "CVE-2024-1234"
    mock_cve.cvss_score = 9.8
    mock_cve.severity = "Critical"
    mock_cve.description = "Test vuln"
    mock_cve.exploitation_requirements = ["net"]
    mock_cve.available_pocs = [{"source": "GH", "url": "https://x"}]
    mock_cve.confidence = 0.85
    mock_res.research_cve.return_value = mock_cve
    _run_main(["research", "CVE-2024-1234"], {
        "tools.vuln_researcher.VulnerabilityResearcher": MagicMock(return_value=mock_res)
    })


def test_main_research_cve_no_result():
    mock_res = MagicMock()
    mock_res.research_cve.return_value = None
    _run_main(["research", "CVE-2024-99999"], {
        "tools.vuln_researcher.VulnerabilityResearcher": MagicMock(return_value=mock_res)
    })


def test_main_research_vuln_type():
    mock_res = MagicMock()
    mock_res.get_exploitation_guide.return_value = {
        "description": "SQLi guide", "impact": "High", "cvss_base": "8.6",
        "common_vectors": ["Union"], "detection_methods": ["SQLMap"],
    }
    mock_poc = MagicMock()
    mock_poc.language = "python"
    mock_poc.target_framework = "django"
    mock_poc.code = "code"
    mock_res.generate_custom_poc.return_value = mock_poc
    _run_main(["research", "sqli"], {
        "tools.vuln_researcher.VulnerabilityResearcher": MagicMock(return_value=mock_res)
    })


def test_main_poc_no_target():
    _run_main(["poc"])


def test_main_poc_with_target():
    mock_res = MagicMock()
    mock_poc = MagicMock()
    mock_poc.code = "exploit"
    mock_res.generate_custom_poc.return_value = mock_poc
    _run_main(["poc", "rce", "--framework", "spring-boot"], {
        "tools.vuln_researcher.VulnerabilityResearcher": MagicMock(return_value=mock_res)
    })


def test_main_poc_no_result():
    mock_res = MagicMock()
    mock_res.generate_custom_poc.return_value = None
    _run_main(["poc", "unknown"], {
        "tools.vuln_researcher.VulnerabilityResearcher": MagicMock(return_value=mock_res)
    })


def test_main_autonomous_no_target():
    _run_main(["autonomous"])


def test_main_autonomous_with_target():
    mock_agent = MagicMock()
    mock_res = MagicMock()
    mock_res.summary = "Done"
    mock_res.report_path = "/tmp/r.html"
    mock_res.success = True
    mock_agent.run_autonomous_scan.return_value = mock_res
    _run_main(["autonomous", "example.com"], {
        "main.require_authorized_scan_target": MagicMock(return_value=True),
        "tools.autonomous_agent.AutonomousAgent": MagicMock(return_value=mock_agent),
        "os.environ": {"ACTIVE_MODELS": "m1"},
    })


def test_main_autonomous_team_aegis():
    mock_agent = MagicMock()
    mock_res = MagicMock()
    mock_res.summary = "Team done"
    mock_res.report_path = None
    mock_res.success = True
    mock_agent.run_team_scan.return_value = mock_res
    _run_main(["autonomous", "example.com", "--mode", "auto"], {
        "main.require_authorized_scan_target": MagicMock(return_value=True),
        "tools.autonomous_agent.AutonomousAgent": MagicMock(return_value=mock_agent),
        "os.environ": {"ACTIVE_MODELS": "m1,m2"},
    })


def test_main_autonomous_not_authorized():
    _run_main(["autonomous", "evil.com"], {
        "main.require_authorized_scan_target": MagicMock(return_value=False),
    })


def test_main_autonomous_failed():
    mock_agent = MagicMock()
    mock_res = MagicMock()
    mock_res.summary = "Failed"
    mock_res.report_path = None
    mock_res.success = False
    mock_agent.run_autonomous_scan.return_value = mock_res
    _run_main(["autonomous", "example.com"], {
        "main.require_authorized_scan_target": MagicMock(return_value=True),
        "tools.autonomous_agent.AutonomousAgent": MagicMock(return_value=mock_agent),
        "os.environ": {"ACTIVE_MODELS": ""},
    })


def test_main_hunt_not_authorized():
    _run_main(["hunt", "example.com"], {
        "main.require_authorized_scan_target": MagicMock(return_value=False),
    })


def test_main_report_no_target():
    _run_main(["report"])


def test_main_report_file_not_found():
    _run_main(["report", "/nonexistent.json"])


def test_main_report_no_findings():
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump({"findings": []}, f)
        f.flush()
        tmp = f.name
    try:
        _run_main(["report", tmp])
    finally:
        os.unlink(tmp)


def test_main_pause_no_target():
    _run_main(["pause"])


def test_main_pause_with_target():
    mock_scanner = MagicMock()
    _run_main(["pause", "mission-123"], {
        "tools.smart_scanner.SmartScanner.load": MagicMock(return_value=mock_scanner),
    })
    mock_scanner.pause.assert_called_once()


def test_main_pause_not_found():
    _run_main(["pause", "none"], {
        "tools.smart_scanner.SmartScanner.load": MagicMock(return_value=None),
    })


def test_main_resume_no_target():
    _run_main(["resume"])


def test_main_resume_with_target():
    mock_scanner = MagicMock()
    mock_scanner.resume.return_value = {"status": "running", "findings": []}
    _run_main(["resume", "mission-123"], {
        "tools.smart_scanner.SmartScanner.load": MagicMock(return_value=mock_scanner),
    })


def test_main_resume_not_found():
    _run_main(["resume", "none"], {
        "tools.smart_scanner.SmartScanner.load": MagicMock(return_value=None),
    })


def test_main_history_list():
    mock_hist = MagicMock()
    mock_hist.format_history_list.return_value = "History"
    _run_main(["history", "list"], {
        "tools.history_manager.get_history_manager": MagicMock(return_value=mock_hist),
    })


def test_main_history_stats():
    mock_hist = MagicMock()
    mock_hist.get_stats.return_value = {
        "total_commands": 100, "unique_commands": 10, "favorites": [],
        "success_rate": 0.95, "most_used": ("q", 50), "favorite_commands": 5,
    }
    _run_main(["history", "stats"], {
        "tools.history_manager.get_history_manager": MagicMock(return_value=mock_hist),
    })


def test_main_history_suggest():
    mock_hist = MagicMock()
    mock_hist.get_contextual_suggestions.return_value = ["quick example.com"]
    _run_main(["history", "suggest"], {
        "tools.history_manager.get_history_manager": MagicMock(return_value=mock_hist),
    })


def test_main_history_search():
    mock_hist = MagicMock()
    entry = MagicMock()
    entry.command = "scan"
    entry.args = "ex.com"
    mock_hist.search.return_value = [entry]
    _run_main(["history", "search"], {
        "tools.history_manager.get_history_manager": MagicMock(return_value=mock_hist),
        "builtins.input": MagicMock(return_value="scan"),
    })


def test_main_history_search_empty():
    mock_hist = MagicMock()
    mock_hist.search.return_value = []
    _run_main(["history", "search"], {
        "tools.history_manager.get_history_manager": MagicMock(return_value=mock_hist),
        "builtins.input": MagicMock(return_value="q"),
    })


def test_main_history_clear():
    _run_main(["history", "clear"], {
        "tools.history_manager.get_history_manager": MagicMock(return_value=MagicMock(clear_history=MagicMock())),
        "ui_components.confirm": MagicMock(return_value=True),
    })


def test_main_history_clear_cancel():
    _run_main(["history", "clear"], {
        "tools.history_manager.get_history_manager": MagicMock(return_value=MagicMock()),
        "ui_components.confirm": MagicMock(return_value=False),
    })


def test_main_history_default():
    mock_hist = MagicMock()
    mock_hist.format_history_list.return_value = "Hist"
    _run_main(["history", "unknown"], {
        "tools.history_manager.get_history_manager": MagicMock(return_value=mock_hist),
    })


def test_main_profile_no_target():
    mock_mgr = MagicMock()
    mock_mgr.format_profile_list.return_value = "Profiles"
    _run_main(["profile"], {
        "tools.profile_manager.ProfileManager": MagicMock(return_value=mock_mgr),
    })


def test_main_profile_list():
    mock_mgr = MagicMock()
    mock_mgr.format_profile_list.return_value = "Profiles"
    _run_main(["profile", "list"], {
        "tools.profile_manager.ProfileManager": MagicMock(return_value=mock_mgr),
    })


def test_main_profile_create_empty_name():
    _run_main(["profile", "create"], {
        "tools.profile_manager.ProfileManager": MagicMock(return_value=MagicMock()),
        "builtins.input": MagicMock(side_effect=[""]),
    })


def test_main_profile_create_success():
    mock_mgr = MagicMock()
    mock_mgr.clone_profile.return_value = True
    _run_main(["profile", "create"], {
        "tools.profile_manager.ProfileManager": MagicMock(return_value=mock_mgr),
        "builtins.input": MagicMock(side_effect=["my_profile", "quick", "Desc", ""]),
    })


def test_main_profile_create_failed():
    mock_mgr = MagicMock()
    mock_mgr.clone_profile.return_value = False
    _run_main(["profile", "create"], {
        "tools.profile_manager.ProfileManager": MagicMock(return_value=mock_mgr),
        "builtins.input": MagicMock(side_effect=["my_profile", "quick", "Desc", ""]),
    })


def test_main_profile_delete():
    mock_mgr = MagicMock()
    mock_mgr.delete_profile.return_value = True
    _run_main(["profile", "delete"], {
        "tools.profile_manager.ProfileManager": MagicMock(return_value=mock_mgr),
        "builtins.input": MagicMock(side_effect=["test"]),
    })


def test_main_profile_delete_failed():
    mock_mgr = MagicMock()
    mock_mgr.delete_profile.return_value = False
    _run_main(["profile", "delete"], {
        "tools.profile_manager.ProfileManager": MagicMock(return_value=mock_mgr),
        "builtins.input": MagicMock(side_effect=["test"]),
    })


def test_main_profile_unknown():
    mock_mgr = MagicMock()
    _run_main(["profile", "unknown"], {
        "tools.profile_manager.ProfileManager": MagicMock(return_value=mock_mgr),
    })


def test_main_quick_no_target():
    mock_mgr = MagicMock()
    mock_prof = MagicMock()
    mock_prof.description = "Quick"
    mock_prof.base_command = "scan"
    mock_mgr.get_profile.return_value = mock_prof
    _run_main(["quick"], {
        "tools.profile_manager.ProfileManager": MagicMock(return_value=mock_mgr),
    })


def test_main_quick_with_target():
    mock_mgr = MagicMock()
    mock_mgr.expand_profile.return_value = ("scan", ["example.com"])
    _run_main(["quick", "example.com"], {
        "tools.profile_manager.ProfileManager": MagicMock(return_value=mock_mgr),
        "commands.scan.handle_scan": MagicMock(),
    })


def test_main_quick_profile_not_found():
    mock_mgr = MagicMock()
    mock_mgr.expand_profile.return_value = None
    _run_main(["quick", "example.com"], {
        "tools.profile_manager.ProfileManager": MagicMock(return_value=mock_mgr),
    })


def test_main_bounty_no_target():
    mock_intel = MagicMock()
    mock_intel.discover_programs_public.return_value = []
    _run_main(["bounty"], {
        "tools.bounty_intelligence.BountyIntelligence": MagicMock(return_value=mock_intel),
    })


def test_bounty_top():
    mock_intel = MagicMock()
    top = MagicMock()
    top.name = "Top"
    top.bounty_range = "$500"
    top.url = "https://h1.com/top"
    top.response_time_hours = 48
    top.score_total = 85.5
    mock_intel.get_top_recommendation.return_value = top
    _run_main(["bounty", "top"], {
        "tools.bounty_intelligence.BountyIntelligence": MagicMock(return_value=mock_intel),
    })


def test_bounty_top_none():
    mock_intel = MagicMock()
    mock_intel.get_top_recommendation.return_value = None
    _run_main(["bounty", "top"], {
        "tools.bounty_intelligence.BountyIntelligence": MagicMock(return_value=mock_intel),
    })


def test_bounty_api():
    mock_intel = MagicMock()
    prog = MagicMock()
    prog.name = "P"
    prog.bounty_range = "$500"
    prog.url = "https://h1.com/p"
    prog.response_time_hours = 24
    prog.score_total = 90
    mock_intel.discover_programs_api.return_value = [prog]
    mock_intel.rank_programs.return_value = [prog]
    mock_intel.format_programs_list.return_value = "List"
    _run_main(["bounty", "api"], {
        "tools.bounty_intelligence.BountyIntelligence": MagicMock(return_value=mock_intel),
        "os.environ": {"HACKERONE_API_KEY": "key"},
    })


def test_bounty_api_no_key():
    mock_intel = MagicMock()
    _run_main(["bounty", "api"], {
        "tools.bounty_intelligence.BountyIntelligence": MagicMock(return_value=mock_intel),
        "os.environ": {},
    })


def test_bounty_public():
    mock_intel = MagicMock()
    prog = MagicMock()
    prog.name = "P"
    prog.bounty_range = "$500"
    prog.url = "https://h1.com/p"
    prog.score_total = 75
    mock_intel.discover_programs_public.return_value = [prog]
    mock_intel.rank_programs.return_value = [prog]
    mock_intel.format_programs_list.return_value = "List"
    _run_main(["bounty", "public"], {
        "tools.bounty_intelligence.BountyIntelligence": MagicMock(return_value=mock_intel),
    })


def test_bounty_auto_no_key():
    mock_intel = MagicMock()
    mock_intel.discover_programs_public.return_value = []
    _run_main(["bounty"], {
        "tools.bounty_intelligence.BountyIntelligence": MagicMock(return_value=mock_intel),
        "os.environ": {},
    })


def test_bounty_auto_with_key():
    mock_intel = MagicMock()
    prog = MagicMock()
    prog.name = "P"
    prog.bounty_range = "$500"
    prog.url = "https://h1.com/p"
    prog.score_total = 75
    mock_intel.discover_programs_api.return_value = [prog]
    mock_intel.rank_programs.return_value = [prog]
    mock_intel.format_programs_list.return_value = "List"
    _run_main(["bounty"], {
        "tools.bounty_intelligence.BountyIntelligence": MagicMock(return_value=mock_intel),
        "os.environ": {"HACKERONE_API_KEY": "key"},
    })


def test_bounty_programs_no_programs():
    mock_intel = MagicMock()
    mock_intel.discover_programs_public.return_value = []
    _run_main(["bounty"], {
        "tools.bounty_intelligence.BountyIntelligence": MagicMock(return_value=mock_intel),
    })


def test_main_mission_no_target():
    _run_main(["mission"])


def test_main_mission_not_authorized():
    _run_main(["mission", "evil.com"], {
        "main.require_authorized_scan_target": MagicMock(return_value=False),
    })


def test_main_mission_exception():
    _run_main(["mission", "example.com"], {
        "main.require_authorized_scan_target": MagicMock(return_value=True),
        "tools.smart_scanner.SmartScanner": MagicMock(side_effect=Exception("err")),
    })


def test_main_api():
    mock_server = MagicMock()
    _run_main(["api"], {"tools.api_server.run_server": mock_server})
    mock_server.assert_called_once_with(host="0.0.0.0", port=8443)


def test_main_api_import_error():
    _run_main(["api"], {"tools.api_server.run_server": MagicMock(side_effect=ImportError("no fastapi"))})


def test_main_api_exception():
    _run_main(["api"], {"tools.api_server.run_server": MagicMock(side_effect=Exception("err"))})


def test_main_dashboard():
    _run_main(["dashboard", "example.com"], {"tools.tui_dashboard.run_dashboard": MagicMock()})


def test_main_dashboard_fallback():
    _run_main(["dashboard"], {
        "tools.tui_dashboard.run_dashboard": MagicMock(side_effect=Exception("err")),
        "tools.tui_dashboard.run_minimal": MagicMock(),
    })


def test_main_dashboard_fallback_also_fails():
    _run_main(["dashboard"], {
        "tools.tui_dashboard.run_dashboard": MagicMock(side_effect=Exception("err")),
        "tools.tui_dashboard.run_minimal": MagicMock(side_effect=Exception("err2")),
    })


def test_main_memory():
    mock_vm = MagicMock()
    mock_vm.get_memory_stats.return_value = {"status": "ok", "total_memories": 10, "unique_targets": 5}
    mock_vm.get_all_targets.return_value = ["ex.com"]
    mock_q = MagicMock()
    mock_q.select.return_value.ask.return_value = "Back"
    _run_main(["memory"], {
        "tools.vector_memory.get_vector_memory": MagicMock(return_value=mock_vm),
        "questionary": mock_q,
    })


def test_main_memory_search():
    mock_vm = MagicMock()
    mock_vm.get_memory_stats.return_value = {"status": "ok", "total_memories": 10, "unique_targets": 5}
    mock_q = MagicMock()
    mock_q.select.return_value.ask.return_value = "Search memories"
    _run_main(["memory"], {
        "tools.vector_memory.get_vector_memory": MagicMock(return_value=mock_vm),
        "tools.vector_memory.recall": MagicMock(return_value=[{"content": "mem", "similarity": 0.9}]),
        "questionary": mock_q,
        "builtins.input": MagicMock(side_effect=["query", "target"]),
    })


def test_main_memory_search_empty():
    mock_vm = MagicMock()
    mock_vm.get_memory_stats.return_value = {"status": "ok", "total_memories": 10, "unique_targets": 5}
    mock_q = MagicMock()
    mock_q.select.return_value.ask.return_value = "Search memories"
    _run_main(["memory"], {
        "tools.vector_memory.get_vector_memory": MagicMock(return_value=mock_vm),
        "tools.vector_memory.recall": MagicMock(return_value=[]),
        "questionary": mock_q,
        "builtins.input": MagicMock(side_effect=["query", ""]),
    })


def test_main_memory_list_targets():
    mock_vm = MagicMock()
    mock_vm.get_memory_stats.return_value = {"status": "ok", "total_memories": 10, "unique_targets": 5}
    mock_vm.get_all_targets.return_value = ["ex.com", "test.com"]
    mock_q = MagicMock()
    mock_q.select.return_value.ask.return_value = "List all targets"
    _run_main(["memory"], {
        "tools.vector_memory.get_vector_memory": MagicMock(return_value=mock_vm),
        "questionary": mock_q,
    })


def test_main_memory_list_targets_empty():
    mock_vm = MagicMock()
    mock_vm.get_memory_stats.return_value = {"status": "ok", "total_memories": 0, "unique_targets": 0}
    mock_vm.get_all_targets.return_value = []
    mock_q = MagicMock()
    mock_q.select.return_value.ask.return_value = "List all targets"
    _run_main(["memory"], {
        "tools.vector_memory.get_vector_memory": MagicMock(return_value=mock_vm),
        "questionary": mock_q,
    })


def test_main_memory_clear():
    mock_vm = MagicMock()
    mock_vm.get_memory_stats.return_value = {"status": "ok", "total_memories": 10, "unique_targets": 5}
    mock_q = MagicMock()
    mock_q.select.return_value.ask.return_value = "Clear target memory"
    _run_main(["memory"], {
        "tools.vector_memory.get_vector_memory": MagicMock(return_value=mock_vm),
        "questionary": mock_q,
        "builtins.input": MagicMock(side_effect=["target.com"]),
        "ui_components.confirm": MagicMock(return_value=True),
    })


def test_main_memory_clear_cancel():
    mock_vm = MagicMock()
    mock_vm.get_memory_stats.return_value = {"status": "ok", "total_memories": 10, "unique_targets": 5}
    mock_q = MagicMock()
    mock_q.select.return_value.ask.return_value = "Clear target memory"
    _run_main(["memory"], {
        "tools.vector_memory.get_vector_memory": MagicMock(return_value=mock_vm),
        "questionary": mock_q,
        "builtins.input": MagicMock(side_effect=["target.com"]),
        "ui_components.confirm": MagicMock(return_value=False),
    })


def test_main_compliance_no_target():
    mock_eng = MagicMock()
    std = MagicMock()
    std.name = "PCI"
    std.version = "4.0"
    std.controls = ["1.1"]
    mock_eng.get_standard.return_value = std
    mock_eng.list_standards.return_value = [{"name": "PCI"}]
    mock_eng.assess.return_value = {"compliance_pct": 75, "passed": 3, "failed": 1, "not_tested": 0}
    mock_eng.generate_report.return_value = "/tmp/r.html"
    _run_main(["compliance"], {
        "tools.compliance_engine.ComplianceEngine": MagicMock(return_value=mock_eng),
    })


def test_main_compliance_unknown():
    mock_eng = MagicMock()
    mock_eng.get_standard.return_value = None
    mock_eng.list_standards.return_value = [{"name": "PCI"}]
    _run_main(["compliance", "unknown"], {
        "tools.compliance_engine.ComplianceEngine": MagicMock(return_value=mock_eng),
    })


def test_main_compliance_exception():
    _run_main(["compliance"], {
        "tools.compliance_engine.ComplianceEngine": MagicMock(side_effect=Exception("err")),
    })


def test_main_soc_no_target():
    mock_analyzer = MagicMock()
    mock_analyzer.analyze.return_value = {"alerts": []}
    _run_main(["soc"], {"tools.soc_analyzer.SOCAnalyzer": MagicMock(return_value=mock_analyzer)})


def test_main_soc_exception():
    _run_main(["soc"], {"tools.soc_analyzer.SOCAnalyzer": MagicMock(side_effect=Exception("err"))})


def test_main_cloud_no_target():
    _run_main(["cloud"])


def test_main_cloud_exception():
    _run_main(["cloud", "/tmp/tf"], {"tools.cloud_scanner.CloudScanner": MagicMock(side_effect=Exception("err"))})


def test_main_mobile_no_target():
    _run_main(["mobile"])


def test_main_mobile_exception():
    _run_main(["mobile", "http://api.com"], {"tools.mobile_api_tester.MobileAPITester": MagicMock(side_effect=Exception("err"))})


def test_main_recon():
    mock_eng = MagicMock()
    result = MagicMock()
    result.stats = {"domains": 5, "ips": 3, "endpoints": 10}
    result.findings = []
    mock_eng.run_full_recon.return_value = result
    _run_main(["recon", "example.com"], {
        "main.require_authorized_scan_target": MagicMock(return_value=True),
        "tools.smart_recon.SmartReconEngine": MagicMock(return_value=mock_eng),
        "tools.smart_recon.format_recon_for_display": MagicMock(return_value="Recon output"),
    })


def test_main_recon_exception():
    _run_main(["recon", "example.com"], {
        "main.require_authorized_scan_target": MagicMock(return_value=True),
        "tools.smart_recon.SmartReconEngine": MagicMock(side_effect=Exception("err")),
    })


def test_main_evasion_list():
    mock_eng = MagicMock()
    mock_eng.list_techniques.return_value = []
    mock_q = MagicMock()
    mock_q.select.return_value.ask.return_value = "List techniques"
    _run_main(["evasion"], {
        "tools.edr_evasion.EDREvasionEngine": MagicMock(return_value=mock_eng),
        "questionary": mock_q,
    })


def test_main_evasion_back():
    mock_eng = MagicMock()
    mock_q = MagicMock()
    mock_q.select.return_value.ask.return_value = "Back"
    _run_main(["evasion"], {
        "tools.edr_evasion.EDREvasionEngine": MagicMock(return_value=mock_eng),
        "questionary": mock_q,
    })


def test_main_evasion_generate():
    mock_eng = MagicMock()
    mock_eng.generate_payload.return_value = {"generated_code": "payload"}
    mock_q = MagicMock()
    mock_q.select.return_value.ask.return_value = "Generate payload"
    _run_main(["evasion"], {
        "tools.edr_evasion.EDREvasionEngine": MagicMock(return_value=mock_eng),
        "tools.edr_evasion.format_edr_report": MagicMock(return_value="Report"),
        "questionary": mock_q,
        "builtins.input": MagicMock(side_effect=["tech"]),
    })


def test_main_evasion_generate_no_name():
    mock_eng = MagicMock()
    mock_q = MagicMock()
    mock_q.select.return_value.ask.return_value = "Generate payload"
    _run_main(["evasion"], {
        "tools.edr_evasion.EDREvasionEngine": MagicMock(return_value=mock_eng),
        "questionary": mock_q,
        "builtins.input": MagicMock(side_effect=[""]),
    })


def test_main_evasion_generate_error():
    mock_eng = MagicMock()
    mock_eng.generate_payload.return_value = {"error": "not found"}
    mock_q = MagicMock()
    mock_q.select.return_value.ask.return_value = "Generate payload"
    _run_main(["evasion"], {
        "tools.edr_evasion.EDREvasionEngine": MagicMock(return_value=mock_eng),
        "questionary": mock_q,
        "builtins.input": MagicMock(side_effect=["tech"]),
    })


def test_main_evasion_plan():
    mock_eng = MagicMock()
    mock_eng.generate_red_team_plan.return_value = {"plan": "p"}
    mock_q = MagicMock()
    mock_q.select.return_value.ask.return_value = "Plan attack"
    _run_main(["evasion"], {
        "tools.edr_evasion.EDREvasionEngine": MagicMock(return_value=mock_eng),
        "tools.edr_evasion.format_edr_report": MagicMock(return_value="Report"),
        "questionary": mock_q,
        "builtins.input": MagicMock(side_effect=["crowdstrike", "persistence,evasion"]),
    })


def test_main_evasion_fallback_input():
    mock_eng = MagicMock()
    mock_eng.list_techniques.return_value = []
    _run_main(["evasion"], {
        "tools.edr_evasion.EDREvasionEngine": MagicMock(return_value=mock_eng),
        "questionary": None,
        "builtins.input": MagicMock(side_effect=["list", "all"]),
    })


def test_main_unknown_registry_fallback():
    mock_reg = MagicMock()
    mock_reg.get.return_value = None
    _run_main(["unknowncmd"], {
        "commands.registry.CommandRegistry": MagicMock(return_value=mock_reg),
    })


def test_main_unknown_registry_found():
    mock_reg = MagicMock()
    mock_reg.get.return_value = MagicMock()
    mock_loop = MagicMock()
    _run_main(["regcmd"], {
        "commands.registry.CommandRegistry": MagicMock(return_value=mock_reg),
        "asyncio.new_event_loop": MagicMock(return_value=mock_loop),
        "asyncio.set_event_loop": MagicMock(),
    })


def test_main_smart_scan_flag():
    _run_main(["list-tools", "--smart-scan"], {"main._cmd_list_tools": MagicMock()})


def test_main_quiet_flag():
    _run_main(["list-tools", "--quiet"], {"main._cmd_list_tools": MagicMock()})


def test_main_keyboard_interrupt():
    with patch("main.ensure_path_priorities"), \
         patch("main.show_banner"), \
         patch("main.ensure_dependencies", return_value=True), \
         patch("tools.welcome_wizard.WelcomeWizard"), \
         patch("tools.history_manager.get_history_manager", return_value=MagicMock(get_contextual_suggestions=MagicMock(return_value=[]))), \
         patch("commands.scan.handle_scan", side_effect=KeyboardInterrupt), \
         patch("ui_components.confirm", return_value=False), \
         patch("sys.argv", ["main.py", "scan", "example.com"]):
        from main import main
        with pytest.raises(SystemExit):
            main()


def test_main_generic_exception():
    _run_main(["scan", "example.com"], {
        "commands.scan.handle_scan": MagicMock(side_effect=RuntimeError("broke")),
    })


def test_main_name_error():
    _run_main(["scan", "example.com"], {
        "commands.scan.handle_scan": MagicMock(side_effect=NameError("undef")),
    })


def test_bounty_confirm_scan():
    mock_intel = MagicMock()
    prog = MagicMock()
    prog.name = "P"
    prog.bounty_range = "$500"
    prog.url = "https://h1.com/p"
    prog.score_total = 75
    mock_intel.discover_programs_public.return_value = [prog]
    mock_intel.rank_programs.return_value = [prog]
    mock_intel.format_programs_list.return_value = "List"
    # confirm=True triggers re-dispatch to quick command
    _run_main(["bounty", "public"], {
        "tools.bounty_intelligence.BountyIntelligence": MagicMock(return_value=mock_intel),
        "ui_components.confirm": MagicMock(return_value=True),
        "tools.profile_manager.ProfileManager": MagicMock(return_value=MagicMock(expand_profile=("scan", ["p.com"]))),
        "commands.scan.handle_scan": MagicMock(),
    })


def test_main_bounty_programs():
    _run_main(["programs"], {
        "tools.bounty_intelligence.BountyIntelligence": MagicMock(return_value=MagicMock(
            discover_programs_public=MagicMock(return_value=[]),
        )),
    })


def test_main_intel():
    _run_main(["intel"], {
        "tools.bounty_intelligence.BountyIntelligence": MagicMock(return_value=MagicMock(
            discover_programs_public=MagicMock(return_value=[]),
        )),
    })
