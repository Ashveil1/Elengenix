"""
Tests for elengenix/agent/vuln_agent.py — file, shell, python, and analysis tools.
"""
import json
import sys
import os
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).parent.parent))

from elengenix.agent.vuln_agent import (
    _tool_read_file,
    _tool_write_file,
    _tool_edit_file,
    _tool_search_files,
    _tool_run_command,
    _tool_run_python,
    _tool_analyze_security,
    _tool_delegate,
    _tool_create_tool,
    _tool_edit_own_tool,
    _dynamic_tools,
    AVAILABLE_TOOLS,
)


# ---------------------------------------------------------------------------
# File tools
# ---------------------------------------------------------------------------


class TestReadFile:
    def test_read_existing_file(self):
        r = _tool_read_file(__file__, limit=5)
        assert r["success"], r
        assert r["total_lines"] > 0
        assert "total_lines" in r

    def test_read_nonexistent_file(self):
        r = _tool_read_file("/tmp/nonexistent_xyzzy.txt")
        assert not r["success"]
        assert "not found" in r["error"].lower()

    def test_read_with_offset(self):
        r = _tool_read_file(__file__, offset=3, limit=2)
        assert r["success"]
        assert "3|" in r["output"] or "4|" in r["output"]


class TestWriteFile:
    def test_write_new_file(self):
        tmp = tempfile.mktemp(suffix=".txt")
        try:
            r = _tool_write_file(tmp, "hello world")
            assert r["success"], r
            assert Path(tmp).read_text() == "hello world"
        finally:
            os.unlink(tmp)

    def test_create_parent_dir(self):
        tmp = tempfile.mktemp(suffix="/nested/test.txt")
        try:
            r = _tool_write_file(tmp, "nested")
            assert r["success"], r
            assert Path(tmp).read_text() == "nested"
        finally:
            os.unlink(tmp)
            os.rmdir(Path(tmp).parent)


class TestEditFile:
    def test_edit_existing(self):
        tmp = tempfile.mktemp(suffix=".txt")
        Path(tmp).write_text("hello world")
        try:
            r = _tool_edit_file(tmp, "hello", "HELLO")
            assert r["success"], r
            assert Path(tmp).read_text() == "HELLO world"
        finally:
            os.unlink(tmp)

    def test_edit_not_found(self):
        tmp = tempfile.mktemp(suffix=".txt")
        Path(tmp).write_text("hello")
        try:
            r = _tool_edit_file(tmp, "zzzz", "aaaa")
            assert not r["success"]
            assert "not found" in r["error"]
        finally:
            os.unlink(tmp)


class TestSearchFiles:
    def test_search_finds_matches(self):
        r = _tool_search_files("_tool_read_file", path="elengenix/agent", file_glob="*.py", limit=5)
        assert r["success"], r
        assert r["total_matches"] > 0

    def test_search_no_match(self):
        r = _tool_search_files("ZZZZ_XYZZY_NONEXISTENT_99999", path="/tmp")
        assert r["success"]
        assert r.get("total_matches", 0) == 0 or "No matches" in r["output"]


# ---------------------------------------------------------------------------
# Shell + Python tools
# ---------------------------------------------------------------------------


class TestRunCommand:
    def test_simple_echo(self):
        r = _tool_run_command("echo hello", timeout=5)
        assert r["success"], r
        assert r["output"].strip() == "hello"

    def test_failing_command(self):
        r = _tool_run_command("false", timeout=5)
        assert not r["success"]

    def test_stderr_captured(self):
        r = _tool_run_command('echo out && echo err >&2', timeout=5)
        assert r["success"]
        assert "out" in r["output"]
        assert "err" in r["output"]


class TestRunPython:
    def test_basic_print(self):
        r = _tool_run_python("print(2**16)", timeout=10)
        assert r["success"], r
        assert r["output"].strip() == "65536"

    def test_multi_line(self):
        r = _tool_run_python(
            'import json\n'
            'data = {"a": 1, "b": [2, 3]}\n'
            'print(json.dumps(data))',
            timeout=10,
        )
        assert r["success"], r
        assert '"a": 1' in r["output"]

    def test_error_handling(self):
        r = _tool_run_python("1/0", timeout=10)
        assert not r["success"]
        assert "ZeroDivisionError" in r["output"] or "ZeroDivisionError" in r["error"]

    def test_import_available(self):
        r = _tool_run_python("import json; print(json.__name__)", timeout=10)
        assert r["success"]
        assert r["output"].strip() == "json"

    def test_timeout_short_code(self):
        r = _tool_run_python("print('ok')", timeout=10)
        assert r["success"]
        assert r["output"].strip() == "ok"


class TestAnalyzeSecurity:
    def test_returns_analysis_or_unavailable(self):
        """If UniversalAIClient is unavailable, returns clear error.
        If available, returns real analysis."""
        r = _tool_analyze_security(
            source="password = 'admin123'",
            context="find hardcoded credentials",
        )
        if not r["success"]:
            # Either UniversalAIClient missing or model unavailable
            err = r.get("error", "")
            assert any(x in err for x in ("UniversalAIClient", "API", "auth", "rate", "timeout")), err
        else:
            assert len(r["output"]) > 20

    def test_truncates_large_source(self):
        """Should not crash on large input."""
        large = "x = 1\n" * 1000
        r = _tool_analyze_security(source=large, context="")
        assert "success" in r
        # If failed, should be a meaningful error
        if not r["success"]:
            err = r.get("error", "")
            assert "500" not in err or "Internal" in err  # not server crash


# ---------------------------------------------------------------------------
# Tool registry completeness
# ---------------------------------------------------------------------------


class TestToolRegistry:
    def test_all_17_tools_registered(self):
        names = [t["name"] for t in AVAILABLE_TOOLS]
        assert len(names) == 17

    def test_file_tools_present(self):
        names = [t["name"] for t in AVAILABLE_TOOLS]
        for tool in ("read_file", "write_file", "edit_file", "search_files"):
            assert tool in names, f"{tool} missing from AVAILABLE_TOOLS"

    def test_shell_tools_present(self):
        names = [t["name"] for t in AVAILABLE_TOOLS]
        for tool in ("run_command", "run_python"):
            assert tool in names, f"{tool} missing"

    def test_analyze_present(self):
        names = [t["name"] for t in AVAILABLE_TOOLS]
        assert "analyze_security" in names

    def test_all_have_handler(self):
        for t in AVAILABLE_TOOLS:
            assert "handler_name" in t, f"{t['name']} missing handler_name"

    def test_handler_functions_exist(self):
        import elengenix.agent.vuln_agent as va

        for t in AVAILABLE_TOOLS:
            handler = getattr(va, t["handler_name"], None)
            assert handler is not None, f"handler function {t['handler_name']} not found"
            assert callable(handler), f"{t['handler_name']} is not callable"

    def test_child_agent_code_is_valid(self):
        from elengenix.agent.vuln_agent import CHILD_AGENT_CODE
        import py_compile, tempfile
        tmp = Path(tempfile.mktemp(suffix=".py"))
        tmp.write_text(CHILD_AGENT_CODE)
        py_compile.compile(str(tmp), doraise=True)
        tmp.unlink()

    def test_delegate_has_max_steps_param(self):
        from elengenix.agent.vuln_agent import _tool_delegate
        import inspect
        sig = inspect.signature(_tool_delegate)
        assert "max_steps" in sig.parameters
        assert "targets" in sig.parameters
        assert "timeout" in sig.parameters
        assert sig.parameters["max_steps"].default == 5


# ---------------------------------------------------------------------------
# Delegate (parallel scan)
# ---------------------------------------------------------------------------


class TestDelegate:
    def test_runs_threaded(self):
        """Should handle multiple targets with thread pool."""
        r = _tool_delegate(
            task="test",
            targets=["127.0.0.1", "127.0.0.2"],
            timeout=15,
        )
        assert r["success"] or not r["success"]  # can succeed or fail gracefully
        assert "output" in r
        assert "aggregated" in r
        assert len(r["aggregated"]) == 2

    def test_single_target(self):
        r = _tool_delegate(task="test", targets=["127.0.0.1"], timeout=10)
        assert len(r.get("aggregated", {})) == 1

    def test_registered_in_tools(self):
        names = [t["name"] for t in AVAILABLE_TOOLS]
        assert "delegate" in names


class TestEditOwnTool:
    """Tests for edit_own_tool dynamic tool editing."""

    def setup_method(self):
        if "test_edit_target" in _dynamic_tools:
            del _dynamic_tools["test_edit_target"]
        AVAILABLE_TOOLS[:] = [t for t in AVAILABLE_TOOLS if t["name"] != "test_edit_target"]
        for f in Path("~/.elengenix/tools/test_edit_target.py").expanduser().parent.glob("test_edit_target*"):
            f.unlink(missing_ok=True)

    def test_edit_nonexistent_tool(self):
        r = _tool_edit_own_tool("test_nonexistent", "def handler(args): return {'success': True}")
        assert not r["success"]
        assert "not found" in r["error"]

    def test_edit_syntax_error_on_existing(self):
        create = _tool_create_tool(
            name="test_edit_target",
            description="test tool",
            parameters={"type": "object", "properties": {}, "required": []},
            handler_code='def handler(args): return {"success": True, "output": "original"}',
        )
        assert create["success"]

        r = _tool_edit_own_tool("test_edit_target", "def handler(args): return {")
        assert not r["success"]
        assert "Syntax error" in r["error"]

        # Cleanup
        _dynamic_tools.pop("test_edit_target", None)
        AVAILABLE_TOOLS[:] = [t for t in AVAILABLE_TOOLS if t["name"] != "test_edit_target"]
        for f in Path("~/.elengenix/tools/test_edit_target.py").expanduser().parent.glob("test_edit_target*"):
            f.unlink(missing_ok=True)

    def test_edit_and_verify(self):
        create = _tool_create_tool(
            name="test_edit_target",
            description="test tool",
            parameters={"type": "object", "properties": {}, "required": []},
            handler_code='def handler(args): return {"success": True, "output": "original"}',
        )
        assert create["success"]

        r = _tool_edit_own_tool(
            "test_edit_target",
            'def handler(args): return {"success": True, "output": "edited!"}',
        )
        assert r["success"], f"edit failed: {r}"
        assert "test_edit_target" in r["output"]
        assert r["edits_remaining"] >= 0

        handler = _dynamic_tools["test_edit_target"]
        result = handler({})
        assert result["output"] == "edited!", f"expected 'edited!', got {result}"

        # Cleanup
        del _dynamic_tools["test_edit_target"]
        AVAILABLE_TOOLS[:] = [t for t in AVAILABLE_TOOLS if t["name"] != "test_edit_target"]
        for f in Path("~/.elengenix/tools/test_edit_target.py").expanduser().parent.glob("test_edit_target*"):
            f.unlink(missing_ok=True)

    def test_edit_limit_respected(self):
        import elengenix.agent.vuln_agent as va

        saved = va._edit_count
        try:
            va._edit_count = va._MAX_EDITS
            r = _tool_edit_own_tool("test_edit_target", "def handler(args): return {'success': True}")
            assert not r["success"]
            assert "Edit limit" in r["error"]
        finally:
            va._edit_count = saved
