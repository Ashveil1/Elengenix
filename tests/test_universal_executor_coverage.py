"""tests/test_universal_executor_coverage.py — Coverage tests for tools/universal_executor.py

Focuses on uncovered lines in execute_action and other methods.
"""

import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from tools.universal_executor import (
    ExecutionResult,
    FileEditor,
    UniversalExecutor,
    get_universal_executor,
)


# ═══════════════════════════════════════════════════════════════════════════════
# FileEditor edge cases
# ═══════════════════════════════════════════════════════════════════════════════


class TestFileEditorEdgeCases:
    def test_validate_path_outside_base(self):
        editor = FileEditor(base_dir="/tmp")
        result = editor._validate_path("/etc/passwd")
        assert result is None

    def test_validate_path_invalid(self):
        editor = FileEditor(base_dir="/tmp")
        result = editor._validate_path("/tmp/nonexistent/../../../etc/passwd")
        assert result is None

    def test_read_sensitive_file(self):
        editor = FileEditor(base_dir="/tmp")
        result = editor.read_file("/tmp/.env")
        assert not result.success
        assert "sensitive" in result.error.lower()

    def test_read_file_with_offset(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            f = Path(tmpdir) / "test.txt"
            f.write_text("line1\nline2\nline3\n")
            editor = FileEditor(base_dir=tmpdir)
            result = editor.read_file(str(f), offset=2, limit=1)
            assert result.success
            assert "line2" in result.output

    def test_edit_file_not_found(self):
        editor = FileEditor(base_dir="/tmp")
        result = editor.edit_file("/tmp/nonexistent_xyz.txt", "old", "new")
        assert not result.success

    def test_edit_file_string_not_found(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            f = Path(tmpdir) / "test.txt"
            f.write_text("hello world")
            editor = FileEditor(base_dir=tmpdir)
            result = editor.edit_file(str(f), "nonexistent_string", "new")
            assert not result.success

    def test_edit_file_multiple_occurrences(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            f = Path(tmpdir) / "test.txt"
            f.write_text("aaa bbb aaa")
            editor = FileEditor(base_dir=tmpdir)
            result = editor.edit_file(str(f), "aaa", "xxx")
            assert not result.success

    def test_search_in_file_no_match(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            f = Path(tmpdir) / "test.txt"
            f.write_text("hello world")
            editor = FileEditor(base_dir=tmpdir)
            result = editor.search_in_file(str(f), "nonexistent_pattern")
            assert result.success
            assert "no matches" in result.output.lower() or "0 matches" in result.output.lower()

    def test_list_not_a_dir(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            f = Path(tmpdir) / "test.txt"
            f.write_text("hello")
            editor = FileEditor(base_dir=tmpdir)
            result = editor.list_directory(str(f))
            assert not result.success


# ═══════════════════════════════════════════════════════════════════════════════
# UniversalExecutor.execute_action edge cases
# ═══════════════════════════════════════════════════════════════════════════════


class TestExecuteActionCoverage:
    def test_run_tool_single(self):
        ue = UniversalExecutor()
        mock_tool = MagicMock()
        mock_tool.is_available = True

        async def mock_execute(*args, **kwargs):
            return MagicMock(success=True, output="done", findings=[], error_message="")

        mock_tool.execute = mock_execute
        with patch("tools.tool_registry.registry") as mock_reg:
            mock_reg.get_tool.return_value = mock_tool
            result = ue.execute_action(
                {"type": "run_tool", "params": {"tool": "test_tool", "target": "example.com"}}
            )
            assert result.success

    def test_run_tool_not_available(self):
        ue = UniversalExecutor()
        with patch("tools.tool_registry.registry") as mock_reg:
            mock_reg.get_tool.return_value = None
            result = ue.execute_action(
                {"type": "run_tool", "params": {"tool": "nonexistent_xyz", "target": "example.com"}}
            )
            assert not result.success
            assert "not available" in result.error.lower()

    def test_run_tool_no_tool_specified(self):
        ue = UniversalExecutor()
        result = ue.execute_action({"type": "run_tool", "params": {"target": "example.com"}})
        assert not result.success
        assert "no tool" in result.error.lower()

    def test_run_tool_parallel(self):
        ue = UniversalExecutor()
        mock_tool = MagicMock()
        mock_tool.is_available = True

        async def mock_execute(*args, **kwargs):
            return MagicMock(
                success=True, output="done", findings=[{"type": "xss"}], error_message=""
            )

        mock_tool.execute = mock_execute
        with patch("tools.tool_registry.registry") as mock_reg:
            mock_reg.get_tool.return_value = mock_tool
            result = ue.execute_action(
                {
                    "type": "run_tool",
                    "params": {"target": "example.com", "tools": ["tool1", "tool2"]},
                }
            )
            assert result.success

    def test_github_search_no_query(self):
        ue = UniversalExecutor()
        result = ue.execute_action({"type": "github_search", "params": {}})
        assert not result.success
        assert "no query" in result.error.lower()

    def test_github_search(self):
        ue = UniversalExecutor()
        with patch(
            "tools.github_intel.search_code",
            return_value=[
                {"repo": "test/repo", "file": "test.py", "content": "secret_key = 'xxx'"}
            ],
        ):
            result = ue.execute_action({"type": "github_search", "params": {"query": "secret_key"}})
            assert result.success

    def test_github_search_exception(self):
        ue = UniversalExecutor()
        with patch("tools.github_intel.search_code", side_effect=Exception("network error")):
            result = ue.execute_action({"type": "github_search", "params": {"query": "test"}})
            assert not result.success

    def test_cve_lookup_by_id(self):
        ue = UniversalExecutor()
        mock_db = MagicMock()
        mock_entry = MagicMock()
        mock_entry.cve_id = "CVE-2024-1234"
        mock_entry.description = "Test vulnerability"
        mock_db.get_cve.return_value = mock_entry
        with patch("tools.cve_database.get_cve_database", return_value=mock_db):
            result = ue.execute_action(
                {"type": "cve_lookup", "params": {"cve_id": "CVE-2024-1234"}}
            )
            assert result.success
            assert "CVE-2024-1234" in result.output

    def test_cve_lookup_not_found(self):
        ue = UniversalExecutor()
        mock_db = MagicMock()
        mock_db.get_cve.return_value = None
        with patch("tools.cve_database.get_cve_database", return_value=mock_db):
            result = ue.execute_action(
                {"type": "cve_lookup", "params": {"cve_id": "CVE-9999-9999"}}
            )
            assert result.success
            assert "not found" in result.output.lower()

    def test_cve_lookup_by_keyword(self):
        ue = UniversalExecutor()
        mock_db = MagicMock()
        mock_entry = MagicMock()
        mock_entry.cve_id = "CVE-2024-1234"
        mock_entry.description = "Test vuln"
        mock_db.search_cves.return_value = [mock_entry]
        with patch("tools.cve_database.get_cve_database", return_value=mock_db):
            result = ue.execute_action({"type": "cve_lookup", "params": {"keyword": "injection"}})
            assert result.success

    def test_cve_lookup_no_params(self):
        ue = UniversalExecutor()
        mock_db = MagicMock()
        with patch("tools.cve_database.get_cve_database", return_value=mock_db):
            result = ue.execute_action({"type": "cve_lookup", "params": {}})
            assert result.success
            assert "specify" in result.output.lower()

    def test_cve_lookup_exception(self):
        ue = UniversalExecutor()
        with patch("tools.cve_database.get_cve_database", side_effect=Exception("db error")):
            result = ue.execute_action(
                {"type": "cve_lookup", "params": {"cve_id": "CVE-2024-1234"}}
            )
            assert not result.success

    def test_js_analyze_no_url(self):
        ue = UniversalExecutor()
        result = ue.execute_action({"type": "js_analyze", "params": {}})
        assert not result.success
        assert "no url" in result.error.lower()

    def test_js_analyze(self):
        ue = UniversalExecutor()
        with patch(
            "tools.js_analyzer.analyze_js",
            return_value={
                "secrets": [{"type": "api_key", "value": "sk_test_123"}],
                "endpoints": ["/api/v1/users"],
            },
        ):
            result = ue.execute_action(
                {"type": "js_analyze", "params": {"url": "https://example.com/app.js"}}
            )
            assert result.success
            assert "1 secrets" in result.output

    def test_js_analyze_exception(self):
        ue = UniversalExecutor()
        with patch("tools.js_analyzer.analyze_js", side_effect=Exception("parse error")):
            result = ue.execute_action(
                {"type": "js_analyze", "params": {"url": "https://example.com/app.js"}}
            )
            assert not result.success

    def test_check_takeover_no_subdomain(self):
        ue = UniversalExecutor()
        result = ue.execute_action({"type": "check_takeover", "params": {}})
        assert not result.success
        assert "no subdomain" in result.error.lower()

    def test_check_takeover(self):
        ue = UniversalExecutor()
        with patch(
            "tools.subdomain_takeover.check_single_subdomain",
            return_value={"vulnerable": True, "service": "github-pages"},
        ):
            result = ue.execute_action(
                {"type": "check_takeover", "params": {"subdomain": "test.example.com"}}
            )
            assert result.success
            assert "TAKEOVER YES" in result.output

    def test_check_takeover_no_risk(self):
        ue = UniversalExecutor()
        with patch("tools.subdomain_takeover.check_single_subdomain", return_value=None):
            result = ue.execute_action(
                {"type": "check_takeover", "params": {"subdomain": "test.example.com"}}
            )
            assert result.success
            assert "No takeover risk" in result.output

    def test_check_takeover_exception(self):
        ue = UniversalExecutor()
        with patch(
            "tools.subdomain_takeover.check_single_subdomain", side_effect=Exception("dns error")
        ):
            result = ue.execute_action(
                {"type": "check_takeover", "params": {"subdomain": "test.example.com"}}
            )
            assert not result.success

    def test_ask_user_no_question(self):
        ue = UniversalExecutor()
        result = ue.execute_action({"type": "ask_user", "params": {}})
        assert not result.success
        assert "no question" in result.error.lower()

    def test_ask_user_non_interactive(self):
        ue = UniversalExecutor()
        result = ue.execute_action({"type": "ask_user", "params": {"question": "Continue?"}})
        # In pytest, stdin is not a tty, so this should return non-interactive error
        assert not result.success
        assert "non-interactive" in result.error.lower()

    def test_submit_findings_no_findings(self):
        ue = UniversalExecutor()
        result = ue.execute_action(
            {"type": "submit_findings", "params": {"findings": [], "target": "example.com"}}
        )
        assert not result.success
        assert "no findings" in result.error.lower()

    def test_submit_findings(self):
        ue = UniversalExecutor()
        with patch("tools.vector_memory.remember"):
            result = ue.execute_action(
                {
                    "type": "submit_findings",
                    "params": {
                        "findings": [
                            {
                                "type": "xss",
                                "endpoint": "/api",
                                "severity": "high",
                                "description": "Reflected XSS",
                            }
                        ],
                        "target": "example.com",
                    },
                }
            )
            assert result.success
            assert "1 findings" in result.output

    def test_web_search_no_query(self):
        ue = UniversalExecutor()
        result = ue.execute_action({"type": "web_search", "params": {}})
        assert not result.success
        assert "no query" in result.error.lower()

    def test_web_search(self):
        ue = UniversalExecutor()
        with patch(
            "tools.research_tool.search_web",
            return_value=[
                {"url": "https://example.com", "title": "Test", "content": "Content here"}
            ],
        ):
            result = ue.execute_action({"type": "web_search", "params": {"query": "test query"}})
            assert result.success

    def test_unknown_action_type(self):
        ue = UniversalExecutor()
        result = ue.execute_action({"type": "unknown_action_xyz", "params": {}})
        assert not result.success
        assert "unknown" in result.error.lower()

    def test_bounty_intel_no_program(self):
        ue = UniversalExecutor()
        result = ue.execute_action({"type": "bounty_intel", "params": {"program": ""}})
        # Should still work (fetches all programs)
        assert result.action_type == "bounty_intel"


# ═══════════════════════════════════════════════════════════════════════════════
# get_universal_executor singleton
# ═══════════════════════════════════════════════════════════════════════════════


class TestGetUniversalExecutor:
    def test_singleton(self):
        import tools.universal_executor as mod

        mod._universal_executor = None
        e1 = get_universal_executor()
        e2 = get_universal_executor()
        assert e1 is e2


# ═══════════════════════════════════════════════════════════════════════════════
# PackageManager edge cases
# ═══════════════════════════════════════════════════════════════════════════════


class TestPackageManagerCoverage:
    def test_pip_install(self):
        ue = UniversalExecutor()
        result = ue.package_manager.execute("pip", "install", "nonexistent_package_xyz")
        # Should return result (may fail but shouldn't crash)
        assert isinstance(result, ExecutionResult)

    def test_unknown_manager(self):
        ue = UniversalExecutor()
        result = ue.package_manager.execute("unknown_manager_xyz", "install", "package")
        assert not result.success

    def test_unknown_action(self):
        ue = UniversalExecutor()
        result = ue.package_manager.execute("pip", "unknown_action_xyz", "package")
        assert not result.success


# ═══════════════════════════════════════════════════════════════════════════════
# get_capabilities
# ═══════════════════════════════════════════════════════════════════════════════


class TestGetCapabilities:
    def test_returns_string(self):
        ue = UniversalExecutor()
        caps = ue.get_capabilities()
        assert isinstance(caps, str)
        assert "File Operations" in caps
        assert "Shell" in caps
