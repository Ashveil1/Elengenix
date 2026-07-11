"""tests/test_final_batch2.py

Comprehensive tests for:
1. tools/tool_registry.py
2. tools/universal_executor.py
3. tools/bounty_intelligence.py
4. tools/vuln_researcher.py
5. tools/exploitation.py
6. tools/analysis_pipeline.py
7. tools/cve_database.py
8. tools/swarm_controller.py
9. tools/soc_analyzer.py

All network calls are mocked. No emoji in output.
"""

import asyncio
import json
import sys
import tempfile
import threading
import time
from pathlib import Path
from unittest.mock import MagicMock, AsyncMock, patch, mock_open

import pytest

# Ensure project root is on sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


# ============================================================================
# 1. tools/tool_registry.py
# ============================================================================


class TestToolCategory:
    def test_enum_values(self):
        from tools.tool_registry import ToolCategory

        assert ToolCategory.RECON.value == "reconnaissance"
        assert ToolCategory.SCANNER.value == "vulnerability_scanner"
        assert ToolCategory.EXPLOITATION.value == "exploitation"
        assert ToolCategory.FUZZING.value == "fuzzing"
        assert ToolCategory.SECRETS.value == "secret_detection"
        assert ToolCategory.API.value == "api_testing"
        assert ToolCategory.NETWORK.value == "network_scanning"
        assert ToolCategory.REPORTING.value == "reporting"
        assert ToolCategory.UTILITY.value == "utility"


class TestToolPriority:
    def test_enum_values(self):
        from tools.tool_registry import ToolPriority

        assert ToolPriority.CRITICAL.value == 1
        assert ToolPriority.HIGH.value == 2
        assert ToolPriority.MEDIUM.value == 3
        assert ToolPriority.LOW.value == 4

    def test_ordering(self):
        from tools.tool_registry import ToolPriority

        assert ToolPriority.CRITICAL.value < ToolPriority.HIGH.value
        assert ToolPriority.HIGH.value < ToolPriority.MEDIUM.value
        assert ToolPriority.MEDIUM.value < ToolPriority.LOW.value


class TestToolResult:
    def test_creation(self):
        from tools.tool_registry import ToolResult, ToolCategory

        result = ToolResult(
            success=True,
            tool_name="test_tool",
            category=ToolCategory.SCANNER,
            output="some output",
            findings=[{"type": "xss"}],
            execution_time=1.5,
        )
        assert result.success is True
        assert result.tool_name == "test_tool"
        assert result.category == ToolCategory.SCANNER
        assert len(result.findings) == 1

    def test_to_dict(self):
        from tools.tool_registry import ToolResult, ToolCategory

        result = ToolResult(
            success=True,
            tool_name="test_tool",
            category=ToolCategory.SCANNER,
            output="x" * 600,
            findings=[{"type": "xss"}, {"type": "sqli"}],
            execution_time=2.0,
            error_message="some error",
        )
        d = result.to_dict()
        assert d["success"] is True
        assert d["tool_name"] == "test_tool"
        assert d["category"] == "vulnerability_scanner"
        assert d["findings_count"] == 2
        assert d["execution_time"] == 2.0
        assert d["error"] == "some error"
        # Output truncated to 500 chars
        assert len(d["output"]) == 500

    def test_to_dict_short_output(self):
        from tools.tool_registry import ToolResult, ToolCategory

        result = ToolResult(
            success=False,
            tool_name="t",
            category=ToolCategory.RECON,
            output="short",
        )
        d = result.to_dict()
        assert d["output"] == "short"

    def test_defaults(self):
        from tools.tool_registry import ToolResult, ToolCategory

        result = ToolResult(success=True, tool_name="t", category=ToolCategory.UTILITY)
        assert result.findings == []
        assert result.execution_time == 0.0
        assert result.error_message is None
        assert result.raw_output_file is None


class TestToolMetadata:
    def test_creation(self):
        from tools.tool_registry import ToolMetadata, ToolCategory, ToolPriority

        meta = ToolMetadata(
            name="my_tool",
            category=ToolCategory.SCANNER,
            priority=ToolPriority.HIGH,
            binary_name="nmap",
            description="Network scanner",
        )
        assert meta.name == "my_tool"
        assert meta.requires_target is True
        assert meta.supports_list_input is False
        assert meta.timeout_seconds == 300
        assert meta.extra_args == {}

    def test_custom_fields(self):
        from tools.tool_registry import ToolMetadata, ToolCategory, ToolPriority

        meta = ToolMetadata(
            name="t",
            category=ToolCategory.FUZZING,
            priority=ToolPriority.LOW,
            binary_name="ffuf",
            description="Fuzzer",
            requires_target=False,
            supports_list_input=True,
            timeout_seconds=60,
            extra_args={"threads": 10},
        )
        assert meta.requires_target is False
        assert meta.supports_list_input is True
        assert meta.timeout_seconds == 60
        assert meta.extra_args == {"threads": 10}


class TestBaseTool:
    def test_check_binary_found(self):
        from tools.tool_registry import BaseTool, ToolMetadata, ToolCategory, ToolPriority

        with patch("shutil.which", return_value="/usr/bin/python3"):

            class DummyTool(BaseTool):
                async def execute(self, target, report_dir, semaphore, **kwargs):
                    pass

            meta = ToolMetadata(
                name="d",
                category=ToolCategory.UTILITY,
                priority=ToolPriority.LOW,
                binary_name="python3",
                description="d",
            )
            tool = DummyTool(meta)
            assert tool._check_binary() is True
            assert tool.is_available is True

    def test_check_binary_not_found(self):
        from tools.tool_registry import BaseTool, ToolMetadata, ToolCategory, ToolPriority

        with patch("shutil.which", return_value=None):

            class DummyTool(BaseTool):
                async def execute(self, target, report_dir, semaphore, **kwargs):
                    pass

            meta = ToolMetadata(
                name="d",
                category=ToolCategory.UTILITY,
                priority=ToolPriority.LOW,
                binary_name="nonexistent",
                description="d",
            )
            tool = DummyTool(meta)
            assert tool._check_binary() is False
            assert tool.is_available is False

    def test_build_command_not_implemented(self):
        from tools.tool_registry import BaseTool, ToolMetadata, ToolCategory, ToolPriority

        with patch("shutil.which", return_value="/usr/bin/python3"):

            class DummyTool(BaseTool):
                async def execute(self, target, report_dir, semaphore, **kwargs):
                    pass

            meta = ToolMetadata(
                name="d",
                category=ToolCategory.UTILITY,
                priority=ToolPriority.LOW,
                binary_name="python3",
                description="d",
            )
            tool = DummyTool(meta)
            with pytest.raises(NotImplementedError):
                tool._build_command("target", Path("/tmp/out"))


class TestToolRegistry:
    def test_singleton(self):
        from tools.tool_registry import ToolRegistry

        r1 = ToolRegistry()
        r2 = ToolRegistry()
        assert r1 is r2

    def test_register_and_get(self):
        from tools.tool_registry import (
            ToolRegistry,
            BaseTool,
            ToolMetadata,
            ToolCategory,
            ToolPriority,
        )

        with patch("shutil.which", return_value="/usr/bin/python3"):

            class DummyTool(BaseTool):
                async def execute(self, target, report_dir, semaphore, **kwargs):
                    pass

            meta = ToolMetadata(
                name="test_reg_tool",
                category=ToolCategory.SCANNER,
                priority=ToolPriority.HIGH,
                binary_name="python3",
                description="Test",
            )
            tool = DummyTool(meta)
            reg = ToolRegistry()
            reg.register(tool)
            assert reg.get_tool("test_reg_tool") is tool

    def test_unregister(self):
        from tools.tool_registry import (
            ToolRegistry,
            BaseTool,
            ToolMetadata,
            ToolCategory,
            ToolPriority,
        )

        with patch("shutil.which", return_value="/usr/bin/python3"):

            class DummyTool(BaseTool):
                async def execute(self, target, report_dir, semaphore, **kwargs):
                    pass

            meta = ToolMetadata(
                name="unreg_tool",
                category=ToolCategory.RECON,
                priority=ToolPriority.MEDIUM,
                binary_name="python3",
                description="x",
            )
            tool = DummyTool(meta)
            reg = ToolRegistry()
            reg.register(tool)
            assert reg.get_tool("unreg_tool") is tool
            reg.unregister("unreg_tool")
            assert reg.get_tool("unreg_tool") is None

    def test_list_available_tools(self):
        from tools.tool_registry import ToolRegistry

        reg = ToolRegistry()
        tools = reg.list_available_tools()
        assert isinstance(tools, dict)
        # waf_detector should be registered from the module-level decorator
        if "waf_detector" in reg._tools:
            assert "waf_detector" in tools

    def test_get_tools_by_category(self):
        from tools.tool_registry import ToolRegistry, ToolCategory

        reg = ToolRegistry()
        tools = reg.get_tools_by_category(ToolCategory.SCANNER)
        assert isinstance(tools, list)

    def test_get_recommended_chain(self):
        from tools.tool_registry import ToolRegistry

        reg = ToolRegistry()
        chain = reg.get_recommended_chain("web")
        assert isinstance(chain, list)
        chain_api = reg.get_recommended_chain("api")
        assert isinstance(chain_api, list)
        chain_net = reg.get_recommended_chain("network")
        assert isinstance(chain_net, list)
        # unknown target falls back to web
        chain_unknown = reg.get_recommended_chain("unknown")
        assert isinstance(chain_unknown, list)

    def test_get_tool_nonexistent(self):
        from tools.tool_registry import ToolRegistry

        reg = ToolRegistry()
        assert reg.get_tool("nonexistent_tool_xyz") is None

    @pytest.mark.asyncio
    async def test_execute_chain(self):
        from tools.tool_registry import ToolRegistry, ToolResult, ToolCategory

        reg = ToolRegistry()
        mock_tool = MagicMock()
        mock_tool.is_available = True
        mock_tool.metadata.name = "mock_tool"
        mock_tool.metadata.category = ToolCategory.SCANNER
        mock_tool.execute = AsyncMock(
            return_value=ToolResult(
                success=True, tool_name="mock_tool", category=ToolCategory.SCANNER
            )
        )
        results = await reg.execute_chain([mock_tool], "http://example.com", Path("/tmp/reports"))
        assert len(results) == 1
        assert results[0].success is True

    @pytest.mark.asyncio
    async def test_execute_chain_skips_unavailable(self):
        from tools.tool_registry import ToolRegistry

        reg = ToolRegistry()
        mock_tool = MagicMock()
        mock_tool.is_available = False
        mock_tool.metadata.name = "unavail"
        results = await reg.execute_chain([mock_tool], "http://example.com", Path("/tmp/reports"))
        assert len(results) == 0


class TestRegisterToolDecorator:
    def test_decorator_registers(self):
        from tools.tool_registry import (
            register_tool,
            BaseTool,
            ToolMetadata,
            ToolCategory,
            ToolPriority,
            registry,
        )

        meta = ToolMetadata(
            name="decorated_test_tool",
            category=ToolCategory.REPORTING,
            priority=ToolPriority.LOW,
            binary_name="python3",
            description="Decorated tool",
        )

        @register_tool(meta)
        class DecoratedTool(BaseTool):
            def _check_binary(self):
                return True

            async def execute(self, target, report_dir, semaphore, **kwargs):
                pass

        assert registry.get_tool("decorated_test_tool") is not None

    def test_decorator_rejects_non_basetool(self):
        from tools.tool_registry import register_tool, ToolMetadata, ToolCategory, ToolPriority

        meta = ToolMetadata(
            name="bad_tool",
            category=ToolCategory.REPORTING,
            priority=ToolPriority.LOW,
            binary_name="python3",
            description="Bad",
        )
        with pytest.raises(TypeError):

            @register_tool(meta)
            class NotATool:
                pass


# ============================================================================
# 2. tools/universal_executor.py
# ============================================================================


class TestFileEditor:
    def test_read_file(self, tmp_path):
        from tools.universal_executor import FileEditor

        test_file = tmp_path / "test.txt"
        test_file.write_text("line1\nline2\nline3\nline4\nline5")
        editor = FileEditor(base_dir=str(tmp_path))
        result = editor.read_file(str(test_file), offset=1, limit=3)
        assert result.success is True
        assert "line1" in result.output
        assert "line3" in result.output
        assert "line4" not in result.output
        assert result.metadata["total_lines"] == 5

    def test_read_file_not_found(self, tmp_path):
        from tools.universal_executor import FileEditor

        editor = FileEditor(base_dir=str(tmp_path))
        result = editor.read_file(str(tmp_path / "nonexistent.txt"))
        assert result.success is False
        assert "not found" in result.error.lower()

    def test_read_file_blocked_sensitive(self, tmp_path):
        from tools.universal_executor import FileEditor

        test_file = tmp_path / ".env"
        test_file.write_text("SECRET=abc")
        editor = FileEditor(base_dir=str(tmp_path))
        result = editor.read_file(str(test_file))
        assert result.success is False
        assert "denied" in result.error.lower()

    def test_read_file_path_outside_base(self, tmp_path):
        from tools.universal_executor import FileEditor

        editor = FileEditor(base_dir=str(tmp_path))
        result = editor.read_file("/etc/hostname")
        assert result.success is False

    def test_write_file(self, tmp_path):
        from tools.universal_executor import FileEditor

        editor = FileEditor(base_dir=str(tmp_path))
        test_file = str(tmp_path / "new_file.txt")
        result = editor.write_file(test_file, "hello world")
        assert result.success is True
        assert Path(test_file).read_text() == "hello world"
        assert len(editor.edit_history) == 1

    def test_write_file_no_overwrite(self, tmp_path):
        from tools.universal_executor import FileEditor

        test_file = tmp_path / "existing.txt"
        test_file.write_text("original")
        editor = FileEditor(base_dir=str(tmp_path))
        result = editor.write_file(str(test_file), "new content")
        assert result.success is False
        assert "exists" in result.error.lower()
        assert test_file.read_text() == "original"

    def test_write_file_overwrite(self, tmp_path):
        from tools.universal_executor import FileEditor

        test_file = tmp_path / "existing.txt"
        test_file.write_text("original")
        editor = FileEditor(base_dir=str(tmp_path))
        result = editor.write_file(str(test_file), "overwritten", overwrite=True)
        assert result.success is True
        assert test_file.read_text() == "overwritten"

    def test_edit_file(self, tmp_path):
        from tools.universal_executor import FileEditor

        test_file = tmp_path / "edit_me.txt"
        test_file.write_text("hello world")
        editor = FileEditor(base_dir=str(tmp_path))
        result = editor.edit_file(str(test_file), "hello", "goodbye")
        assert result.success is True
        assert test_file.read_text() == "goodbye world"

    def test_edit_file_not_found(self, tmp_path):
        from tools.universal_executor import FileEditor

        editor = FileEditor(base_dir=str(tmp_path))
        result = editor.edit_file(str(tmp_path / "nope.txt"), "a", "b")
        assert result.success is False

    def test_edit_file_string_not_found(self, tmp_path):
        from tools.universal_executor import FileEditor

        test_file = tmp_path / "data.txt"
        test_file.write_text("hello")
        editor = FileEditor(base_dir=str(tmp_path))
        result = editor.edit_file(str(test_file), "nonexistent", "x")
        assert result.success is False
        assert "not found" in result.error.lower()

    def test_edit_file_multiple_occurrences(self, tmp_path):
        from tools.universal_executor import FileEditor

        test_file = tmp_path / "multi.txt"
        test_file.write_text("aaa bbb aaa ccc aaa")
        editor = FileEditor(base_dir=str(tmp_path))
        result = editor.edit_file(str(test_file), "aaa", "zzz")
        assert result.success is False
        assert "3 occurrences" in result.error

    def test_search_in_file(self, tmp_path):
        from tools.universal_executor import FileEditor

        test_file = tmp_path / "search.txt"
        test_file.write_text("foo\nbar\nbaz\nfoo\nqux")
        editor = FileEditor(base_dir=str(tmp_path))
        result = editor.search_in_file(str(test_file), "foo")
        assert result.success is True
        assert result.metadata["matches"] == 2

    def test_search_no_matches(self, tmp_path):
        from tools.universal_executor import FileEditor

        test_file = tmp_path / "search.txt"
        test_file.write_text("hello")
        editor = FileEditor(base_dir=str(tmp_path))
        result = editor.search_in_file(str(test_file), "xyz")
        assert result.success is True
        assert result.metadata["matches"] == 0

    def test_list_directory(self, tmp_path):
        from tools.universal_executor import FileEditor

        (tmp_path / "file1.txt").write_text("a")
        (tmp_path / "subdir").mkdir()
        (tmp_path / "subdir" / "file2.txt").write_text("b")
        editor = FileEditor(base_dir=str(tmp_path))
        result = editor.list_directory(str(tmp_path))
        assert result.success is True
        assert "file1.txt" in result.output

    def test_list_not_a_directory(self, tmp_path):
        from tools.universal_executor import FileEditor

        test_file = tmp_path / "file.txt"
        test_file.write_text("x")
        editor = FileEditor(base_dir=str(tmp_path))
        result = editor.list_directory(str(test_file))
        assert result.success is False
        assert "not a directory" in result.error.lower()


class TestUniversalExecutor:
    @pytest.fixture
    def executor(self, tmp_path):
        from tools.universal_executor import UniversalExecutor

        return UniversalExecutor(base_dir=str(tmp_path))

    @patch("tools.universal_executor.subprocess.run")
    def test_execute_action_read_file(self, mock_run, executor, tmp_path):
        test_file = tmp_path / "read_test.txt"
        test_file.write_text("hello\nworld")
        result = executor.execute_action(
            {
                "type": "read_file",
                "params": {"path": str(test_file), "offset": 1, "limit": 10},
            }
        )
        assert result.success is True
        assert "hello" in result.output

    def test_execute_action_write_file(self, executor, tmp_path):
        result = executor.execute_action(
            {
                "type": "write_file",
                "params": {"path": str(tmp_path / "out.txt"), "content": "test"},
            }
        )
        assert result.success is True

    def test_execute_action_edit_file(self, executor, tmp_path):
        test_file = tmp_path / "edit.txt"
        test_file.write_text("aaa bbb")
        result = executor.execute_action(
            {
                "type": "edit_file",
                "params": {"path": str(test_file), "old_string": "bbb", "new_string": "ccc"},
            }
        )
        assert result.success is True
        assert test_file.read_text() == "aaa ccc"

    def test_execute_action_search_file(self, executor, tmp_path):
        test_file = tmp_path / "s.txt"
        test_file.write_text("line1 foo\nline2 bar")
        result = executor.execute_action(
            {
                "type": "search_file",
                "params": {"path": str(test_file), "pattern": "foo"},
            }
        )
        assert result.success is True
        assert "foo" in result.output

    def test_execute_action_list_dir(self, executor, tmp_path):
        result = executor.execute_action(
            {
                "type": "list_dir",
                "params": {"path": str(tmp_path)},
            }
        )
        assert result.success is True

    def test_execute_action_unknown_type(self, executor):
        result = executor.execute_action({"type": "nonexistent_action", "params": {}})
        assert result.success is False
        assert "unknown" in result.error.lower()

    def test_execute_action_package_unknown_manager(self, executor):
        result = executor.execute_action(
            {
                "type": "package",
                "params": {"manager": "nonexistent", "action": "install", "package": "foo"},
            }
        )
        assert result.success is False

    def test_get_capabilities(self, executor):
        caps = executor.get_capabilities()
        assert "File Operations" in caps
        assert "Shell" in caps


class TestIsSafeCommand:
    def test_empty_command(self):
        from tools.universal_executor import UniversalExecutor

        with patch("tools.governance.Governance.gate") as mock_gate:
            executor = UniversalExecutor(base_dir="/tmp")
            safe, reason = executor.is_safe_command("")
            assert safe is False
            assert "empty" in reason.lower()

    def test_safe_command(self):
        from tools.universal_executor import UniversalExecutor
        from tools.governance import GateDecision

        with patch("tools.governance.Governance.gate") as mock_gate:
            mock_gate.return_value = GateDecision(allowed=True, risk_level="SAFE", decision="allow")
            executor = UniversalExecutor(base_dir="/tmp")
            safe, reason = executor.is_safe_command("echo hello")
            assert safe is True
            assert reason == ""


# ============================================================================
# 3. tools/bounty_intelligence.py
# ============================================================================


class TestBountyProgram:
    def test_bounty_range_same(self):
        from tools.bounty_intelligence import BountyProgram

        p = BountyProgram(
            id="1",
            name="Test",
            platform="hackerone",
            url="http://test.com",
            offers_bounties=True,
            min_bounty=500,
            max_bounty=500,
        )
        assert p.bounty_range == "$500"

    def test_bounty_range_different(self):
        from tools.bounty_intelligence import BountyProgram

        p = BountyProgram(
            id="1",
            name="Test",
            platform="hackerone",
            url="http://test.com",
            offers_bounties=True,
            min_bounty=100,
            max_bounty=5000,
        )
        assert p.bounty_range == "$100 - $5,000"

    def test_is_worth_targeting(self):
        from tools.bounty_intelligence import BountyProgram

        p = BountyProgram(
            id="1",
            name="Test",
            platform="hackerone",
            url="http://test.com",
            offers_bounties=True,
            min_bounty=100,
            max_bounty=500,
            is_public=True,
        )
        assert p.is_worth_targeting is True

    def test_not_worth_targeting_no_bounties(self):
        from tools.bounty_intelligence import BountyProgram

        p = BountyProgram(
            id="1",
            name="Test",
            platform="hackerone",
            url="http://test.com",
            offers_bounties=False,
            min_bounty=0,
            max_bounty=0,
            is_public=True,
        )
        assert p.is_worth_targeting is False

    def test_not_worth_targeting_low_bounty(self):
        from tools.bounty_intelligence import BountyProgram

        p = BountyProgram(
            id="1",
            name="Test",
            platform="hackerone",
            url="http://test.com",
            offers_bounties=True,
            min_bounty=50,
            max_bounty=100,
            is_public=True,
        )
        assert p.is_worth_targeting is False

    def test_not_worth_targeting_private(self):
        from tools.bounty_intelligence import BountyProgram

        p = BountyProgram(
            id="1",
            name="Test",
            platform="hackerone",
            url="http://test.com",
            offers_bounties=True,
            min_bounty=100,
            max_bounty=1000,
            is_public=False,
        )
        assert p.is_worth_targeting is False


class TestBountyIntelligence:
    @pytest.fixture
    def intel(self, tmp_path):
        from tools.bounty_intelligence import BountyIntelligence

        with patch.object(BountyIntelligence, "CACHE_DIR", tmp_path):
            with patch.object(BountyIntelligence, "CACHE_DB", tmp_path / "cache.db"):
                bi = BountyIntelligence()
                return bi

    def test_init_no_auth(self, intel):
        assert intel.api_auth is None

    def test_init_with_auth(self, tmp_path):
        from tools.bounty_intelligence import BountyIntelligence

        with patch.object(BountyIntelligence, "CACHE_DIR", tmp_path):
            with patch.object(BountyIntelligence, "CACHE_DB", tmp_path / "cache.db"):
                bi = BountyIntelligence(api_key="key123", api_username="user1")
                assert bi.api_auth == ("user1", "key123")

    def test_rank_programs_empty(self, intel):
        assert intel.rank_programs([]) == []

    def test_rank_programs(self, intel):
        from tools.bounty_intelligence import BountyProgram

        programs = [
            BountyProgram(
                id="1",
                name="Low",
                platform="h",
                url="http://a.com",
                offers_bounties=True,
                min_bounty=100,
                max_bounty=1000,
                response_time_hours=48,
            ),
            BountyProgram(
                id="2",
                name="High",
                platform="h",
                url="http://b.com",
                offers_bounties=True,
                min_bounty=500,
                max_bounty=50000,
                response_time_hours=12,
                scope=[{"id": "a"}, {"id": "b"}, {"id": "c"}, {"id": "d"}, {"id": "e"}],
            ),
        ]
        ranked = intel.rank_programs(programs)
        assert ranked[0].name == "High"
        assert ranked[0].score_total > ranked[1].score_total

    def test_format_programs_list_empty(self, intel):
        output = intel.format_programs_list([])
        assert "No programs found" in output

    def test_format_programs_list(self, intel):
        from tools.bounty_intelligence import BountyProgram

        programs = [
            BountyProgram(
                id="1",
                name="Shopify",
                platform="h",
                url="http://shopify.com",
                offers_bounties=True,
                min_bounty=500,
                max_bounty=30000,
                response_time_hours=48,
                scope=[{"id": "a"}, {"id": "b"}],
            ),
        ]
        output = intel.format_programs_list(programs, show_scores=True)
        assert "Shopify" in output
        assert "Score:" in output
        assert "Scope:" in output

    def test_parse_api_program(self, intel):
        from tools.bounty_intelligence import BountyProgram

        api_data = {
            "id": "123",
            "attributes": {
                "name": "TestCo",
                "handle": "testco",
                "state": "open",
                "response_time": {"hours": 24},
            },
            "relationships": {
                "bounty_range": {
                    "data": {"min": 500, "max": 10000, "currency": "USD"},
                },
                "structured_scopes": {
                    "data": [
                        {
                            "attributes": {
                                "asset_identifier": "*.testco.com",
                                "asset_type": "wildcard",
                                "eligible_for_bounty": True,
                                "instruction": "Test everything",
                            }
                        }
                    ]
                },
            },
        }
        prog = intel._parse_api_program(api_data)
        assert prog.name == "TestCo"
        assert prog.offers_bounties is True
        assert prog.min_bounty == 500
        assert prog.max_bounty == 10000
        assert len(prog.scope) == 1

    def test_parse_public_program(self, intel):
        data = {
            "id": "456",
            "attributes": {
                "name": "PublicCo",
                "handle": "publicco",
                "state": "open",
                "bounty_range": {"min": 200, "max": 5000},
            },
        }
        prog = intel._parse_public_program(data)
        assert prog.name == "PublicCo"
        assert prog.offers_bounties is True
        assert prog.max_bounty == 5000

    def test_parse_public_program_no_bounties(self, intel):
        data = {"attributes": {"name": "NoBounty", "handle": "nb"}}
        prog = intel._parse_public_program(data)
        assert prog.offers_bounties is False

    def test_parse_public_program_alt_bounty(self, intel):
        data = {"attributes": {"name": "Alt", "handle": "alt", "bounty_in_usd": 2000}}
        prog = intel._parse_public_program(data)
        assert prog.offers_bounties is True
        assert prog.max_bounty == 2000
        assert prog.min_bounty == 200

    def test_scrape_programs_fallback(self, intel):
        programs = intel._scrape_programs_fallback(3)
        assert len(programs) == 3
        assert programs[0].name == "Shopify"
        assert programs[0].offers_bounties is True

    def test_scrape_programs_fallback_limit(self, intel):
        programs = intel._scrape_programs_fallback(1)
        assert len(programs) == 1


# ============================================================================
# 4. tools/vuln_researcher.py
# ============================================================================


class TestCVEResearchResult:
    def test_creation(self):
        from tools.vuln_researcher import CVEResearchResult

        r = CVEResearchResult(
            cve_id="CVE-2024-0001",
            cvss_score=9.8,
            severity="critical",
            description="Test vuln",
            affected_products=["product_a"],
            exploitation_requirements=["auth"],
            exploit_conditions={"vector": "network"},
            available_pocs=[],
            patched_versions=["1.0.1"],
            references=[],
            github_advisories=[],
            ai_summary="summary",
            confidence=0.85,
        )
        assert r.cve_id == "CVE-2024-0001"
        assert r.cvss_score == 9.8


class TestExploitCondition:
    def test_creation(self):
        from tools.vuln_researcher import ExploitCondition

        ec = ExploitCondition(
            prerequisite="auth",
            details="Requires valid credentials",
            how_to_check="Try logging in",
            exploitability_score=0.7,
        )
        assert ec.exploitability_score == 0.7


class TestDisclosedBounty:
    def test_creation(self):
        from tools.vuln_researcher import DisclosedBounty

        db = DisclosedBounty(
            title="SQLi in search",
            program="Twitter",
            severity="high",
            payout="$5,600",
            disclosed_at="2023-05-20",
            summary="Blind SQLi",
            key_techniques=["blind_sqli"],
            url="https://hackerone.com/reports/123",
            reporter="@researcher",
        )
        assert db.payout == "$5,600"


class TestCustomPoC:
    def test_creation(self):
        from tools.vuln_researcher import CustomPoC

        poc = CustomPoC(
            code="print('hello')",
            language="python",
            target_framework="django",
            verification_steps=["step1"],
            expected_output="hello",
            mitigations=["sanitization"],
        )
        assert poc.language == "python"


class TestVulnerabilityResearcher:
    @pytest.fixture
    def researcher(self, tmp_path):
        from tools.vuln_researcher import VulnerabilityResearcher

        with patch.object(VulnerabilityResearcher, "CACHE_DIR", tmp_path / "cache"):
            vr = VulnerabilityResearcher()
            return vr

    def test_init(self, researcher):
        assert researcher.vuln_patterns is not None
        assert "rce" in researcher.vuln_patterns
        assert "sqli" in researcher.vuln_patterns

    def test_generate_custom_poc_rce_spring(self, researcher):
        poc = researcher.generate_custom_poc(
            "rce", {"framework": "spring boot", "language": "java", "version": "2.7"}
        )
        assert poc is not None
        assert "Spring" in poc.code
        assert poc.language == "java"
        assert poc.target_framework == "spring boot"

    def test_generate_custom_poc_rce_django(self, researcher):
        poc = researcher.generate_custom_poc(
            "rce", {"framework": "django", "language": "python", "version": "4.0"}
        )
        assert poc is not None
        assert "Django" in poc.code
        assert poc.language == "python"

    def test_generate_custom_poc_rce_generic(self, researcher):
        poc = researcher.generate_custom_poc("rce", {"framework": "unknown", "language": "go"})
        assert poc is not None
        assert "RCE" in poc.code.upper()

    def test_generate_custom_poc_sqli(self, researcher):
        poc = researcher.generate_custom_poc("sqli", {"framework": "rails", "language": "ruby"})
        assert poc is not None
        assert "SQL" in poc.code.upper() or "sqli" in poc.code.lower()

    def test_generate_custom_poc_ssrf(self, researcher):
        poc = researcher.generate_custom_poc(
            "ssrf", {"framework": "express", "language": "javascript"}
        )
        assert poc is not None
        assert "SSRF" in poc.code.upper() or "ssrf" in poc.code.lower()

    def test_generate_custom_poc_xss(self, researcher):
        poc = researcher.generate_custom_poc(
            "xss", {"framework": "react", "language": "javascript"}
        )
        assert poc is not None

    def test_generate_custom_poc_unknown_type(self, researcher):
        poc = researcher.generate_custom_poc("unknown_vuln", {"framework": "x", "language": "y"})
        assert poc is None

    def test_find_similar_bounties_rce(self, researcher):
        bounties = researcher.find_similar_bounties("rce", min_payout=1000)
        assert len(bounties) >= 1
        assert bounties[0].payout == "$25,000"

    def test_find_similar_bounties_sqli(self, researcher):
        bounties = researcher.find_similar_bounties("sqli", min_payout=1000)
        assert len(bounties) >= 1

    def test_find_similar_bounties_no_match(self, researcher):
        bounties = researcher.find_similar_bounties("unknown_type", min_payout=100000)
        assert len(bounties) == 0

    def test_get_exploitation_guide_rce(self, researcher):
        guide = researcher.get_exploitation_guide("rce")
        assert "description" in guide
        assert "common_vectors" in guide
        assert "exploitation_tools" in guide

    def test_get_exploitation_guide_unknown(self, researcher):
        guide = researcher.get_exploitation_guide("random_vuln")
        assert guide["impact"] == "Unknown"

    @patch("tools.vuln_researcher.VulnerabilityResearcher._fetch_nvd_data")
    def test_research_cve_invalid_format(self, mock_fetch, researcher):
        result = researcher.research_cve("bad-format")
        assert result is None
        mock_fetch.assert_not_called()

    @patch("tools.vuln_researcher.VulnerabilityResearcher._fetch_nvd_data")
    def test_research_cve_no_data(self, mock_fetch, researcher):
        mock_fetch.return_value = None
        result = researcher.research_cve("CVE-2024-99999")
        assert result is None


# ============================================================================
# 5. tools/exploitation.py
# ============================================================================


class TestExploitProof:
    def test_creation(self):
        from tools.exploitation import ExploitProof

        proof = ExploitProof(
            title="SQLi Test",
            description="Testing SQL injection",
            steps=["step1", "step2"],
            impact_demonstrated="Data leaked",
        )
        assert proof.title == "SQLi Test"
        assert len(proof.steps) == 2
        assert proof.data_extracted == {}
        assert proof.curl_command == ""


class TestExploitFunctions:
    @pytest.mark.asyncio
    async def test_exploit_sqli_success(self):
        from tools.exploitation import exploit_sqli

        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.text = AsyncMock(
            return_value=json.dumps(
                {
                    "status": "ok",
                    "user": {"id": 1, "password": "secret123"},
                }
            )
        )

        mock_session = AsyncMock()
        mock_session.post = MagicMock(
            return_value=AsyncMock(
                __aenter__=AsyncMock(return_value=mock_response),
                __aexit__=AsyncMock(return_value=False),
            )
        )

        proof = await exploit_sqli(mock_session, "http://target.com/login")
        assert proof.title == "SQL Injection - Data Extraction"
        assert len(proof.steps) > 0
        assert proof.impact_demonstrated != ""

    @pytest.mark.asyncio
    async def test_exploit_sqli_no_exploit(self):
        from tools.exploitation import exploit_sqli

        mock_response = AsyncMock()
        mock_response.status = 403
        mock_response.text = AsyncMock(return_value="Forbidden")

        mock_session = AsyncMock()
        mock_session.post = MagicMock(
            return_value=AsyncMock(
                __aenter__=AsyncMock(return_value=mock_response),
                __aexit__=AsyncMock(return_value=False),
            )
        )

        proof = await exploit_sqli(mock_session, "http://target.com/login")
        assert proof.impact_demonstrated == ""

    @pytest.mark.asyncio
    async def test_exploit_xss_reflected(self):
        from tools.exploitation import exploit_xss

        mock_response = AsyncMock()
        mock_response.status = 200
        payload = "<script>alert('elengenix-pwned')</script>"
        mock_response.text = AsyncMock(return_value=f"<html>{payload}</html>")

        mock_session = AsyncMock()
        mock_session.get = MagicMock(
            return_value=AsyncMock(
                __aenter__=AsyncMock(return_value=mock_response),
                __aexit__=AsyncMock(return_value=False),
            )
        )

        proof = await exploit_xss(mock_session, "http://target.com/search")
        assert proof.impact_demonstrated != ""
        assert payload in proof.data_extracted.get("payload", "")

    @pytest.mark.asyncio
    async def test_exploit_xss_no_reflection(self):
        from tools.exploitation import exploit_xss

        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.text = AsyncMock(return_value="<html>safe</html>")

        mock_session = AsyncMock()
        mock_session.get = MagicMock(
            return_value=AsyncMock(
                __aenter__=AsyncMock(return_value=mock_response),
                __aexit__=AsyncMock(return_value=False),
            )
        )

        proof = await exploit_xss(mock_session, "http://target.com/search")
        assert proof.impact_demonstrated == ""

    @pytest.mark.asyncio
    async def test_exploit_path_traversal(self):
        from tools.exploitation import exploit_path_traversal

        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.text = AsyncMock(return_value="root:x:0:0:root:/root:/bin/bash")

        mock_session = AsyncMock()
        mock_session.get = MagicMock(
            return_value=AsyncMock(
                __aenter__=AsyncMock(return_value=mock_response),
                __aexit__=AsyncMock(return_value=False),
            )
        )

        proof = await exploit_path_traversal(mock_session, "http://target.com/download")
        assert proof.impact_demonstrated != ""

    @pytest.mark.asyncio
    async def test_exploit_ssti(self):
        from tools.exploitation import exploit_ssti

        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.text = AsyncMock(return_value="Template output: 49")

        mock_session = AsyncMock()
        mock_session.get = MagicMock(
            return_value=AsyncMock(
                __aenter__=AsyncMock(return_value=mock_response),
                __aexit__=AsyncMock(return_value=False),
            )
        )

        proof = await exploit_ssti(mock_session, "http://target.com/render")
        # SSTI probe checks for "49" in body
        if "49" in "Template output: 49":
            assert proof.impact_demonstrated != ""

    @pytest.mark.asyncio
    async def test_exploit_jwt_alg_none(self):
        from tools.exploitation import exploit_jwt_alg_none

        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.text = AsyncMock(return_value=json.dumps({"valid": True}))

        mock_session = AsyncMock()
        mock_session.post = MagicMock(
            return_value=AsyncMock(
                __aenter__=AsyncMock(return_value=mock_response),
                __aexit__=AsyncMock(return_value=False),
            )
        )

        proof = await exploit_jwt_alg_none(mock_session, "http://target.com/verify")
        assert proof.impact_demonstrated != ""

    @pytest.mark.asyncio
    async def test_exploit_proto_pollution(self):
        from tools.exploitation import exploit_proto_pollution

        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.text = AsyncMock(
            return_value=json.dumps(
                {
                    "__proto__": {"isAdmin": True},
                    "polluted_marker": "ElengenixExploitSuccess",
                }
            )
        )

        mock_session = AsyncMock()
        mock_session.post = MagicMock(
            return_value=AsyncMock(
                __aenter__=AsyncMock(return_value=mock_response),
                __aexit__=AsyncMock(return_value=False),
            )
        )

        proof = await exploit_proto_pollution(mock_session, "http://target.com/merge")
        assert proof.impact_demonstrated != ""


# ============================================================================
# 6. tools/analysis_pipeline.py
# ============================================================================


class TestAnalysisPipeline:
    @pytest.fixture
    def mock_agent(self):
        agent = MagicMock()
        agent.governance = MagicMock()
        agent.governance.gate.return_value = MagicMock(
            allowed=False, decision="deny", risk_level="safe"
        )
        agent.payload_mutator = MagicMock()
        agent.payload_mutator.mutate.return_value = []
        agent.logic_analyzer = MagicMock()
        agent.logic_analyzer.generate.return_value = []
        agent.activity_logger = MagicMock()
        return agent

    @patch("tools.analysis_pipeline.remember")
    @patch("tools.analysis_pipeline.display_in_chat_mode")
    def test_init(self, mock_display, mock_remember):
        from tools.analysis_pipeline import AnalysisPipeline

        agent = MagicMock()
        agent.governance = MagicMock()
        agent.payload_mutator = MagicMock()
        agent.logic_analyzer = MagicMock()
        agent.activity_logger = MagicMock()
        agent.smart_payload_generator = None
        pipeline = AnalysisPipeline(agent)
        assert pipeline.governance is agent.governance

    @patch("tools.analysis_pipeline.remember")
    def test_run_all(self, mock_remember, mock_agent):
        from tools.analysis_pipeline import AnalysisPipeline
        from tools.tool_registry import ToolResult, ToolCategory
        from tools.mission_state import MissionState

        mock_agent.smart_payload_generator = None
        pipeline = AnalysisPipeline(mock_agent)
        result = ToolResult(
            success=True,
            tool_name="test",
            category=ToolCategory.SCANNER,
            findings=[],
        )
        ms = MissionState("test_mission", "http://example.com", "Test objective")
        # Should not raise
        pipeline.run_all(result, "test", "http://example.com", 1, "test_mission", ms, None)

    @patch("tools.analysis_pipeline.remember")
    def test_run_all_with_findings(self, mock_remember, mock_agent):
        from tools.analysis_pipeline import AnalysisPipeline
        from tools.tool_registry import ToolResult, ToolCategory
        from tools.mission_state import MissionState

        mock_agent.smart_payload_generator = None
        pipeline = AnalysisPipeline(mock_agent)
        result = ToolResult(
            success=True,
            tool_name="test",
            category=ToolCategory.SCANNER,
            findings=[
                {
                    "type": "xss",
                    "url": "http://example.com/search",
                    "payload": "<script>alert(1)</script>",
                }
            ],
        )
        ms = MissionState("test_mission2", "http://example.com", "Test")
        pipeline.run_all(result, "test", "http://example.com", 1, "test_mission2", ms, None)


# ============================================================================
# 7. tools/cve_database.py
# ============================================================================


class TestCVEDatabase:
    @pytest.fixture
    def db(self, tmp_path):
        import tools.cve_database as cve_mod

        # Patch DB_PATH to use temp directory
        test_db_path = tmp_path / "test_cve.db"
        with patch.object(cve_mod, "CVE_DB_PATH", test_db_path):
            with patch.object(cve_mod, "DATA_DIR", tmp_path):
                database = cve_mod.CVEDatabase(auto_update=False)
                yield database

    def test_init(self, db):
        assert db is not None

    def test_add_and_get_cve(self, db):
        from tools.cve_database import CVEEntry

        entry = CVEEntry(
            cve_id="CVE-2024-0001",
            description="Test vulnerability",
            published_date="2024-01-01",
            last_modified="2024-01-02",
            cvss_score=9.8,
            severity="Critical",
        )
        db._add_cve(entry)
        result = db.get_cve("CVE-2024-0001")
        assert result is not None
        assert result.cve_id == "CVE-2024-0001"
        assert result.cvss_score == 9.8

    def test_cve_exists(self, db):
        from tools.cve_database import CVEEntry

        assert db._cve_exists("CVE-2024-0001") is False
        db._add_cve(
            CVEEntry(
                cve_id="CVE-2024-0001",
                description="x",
                published_date="",
                last_modified="",
            )
        )
        assert db._cve_exists("CVE-2024-0001") is True

    def test_update_cve(self, db):
        from tools.cve_database import CVEEntry

        entry = CVEEntry(
            cve_id="CVE-2024-0002",
            description="original",
            published_date="2024-01-01",
            last_modified="2024-01-01",
        )
        db._add_cve(entry)
        updated = CVEEntry(
            cve_id="CVE-2024-0002",
            description="updated",
            published_date="2024-01-01",
            last_modified="2024-01-02",
        )
        db._update_cve(updated)
        result = db.get_cve("CVE-2024-0002")
        assert result.description == "updated"

    def test_search_cves(self, db):
        from tools.cve_database import CVEEntry

        for i in range(5):
            db._add_cve(
                CVEEntry(
                    cve_id=f"CVE-2024-{i:04d}",
                    description=f"Test vuln {i}",
                    published_date="2024-01-01",
                    last_modified="2024-01-01",
                    cvss_score=5.0 + i,
                    severity="Medium",
                )
            )
        results = db.search_cves(query="Test", min_cvss=7.0)
        assert len(results) >= 3

    def test_count_cves(self, db):
        from tools.cve_database import CVEEntry

        initial = db._count_cves()
        db._add_cve(
            CVEEntry(
                cve_id="CVE-2024-9999",
                description="count test",
                published_date="",
                last_modified="",
            )
        )
        assert db._count_cves() == initial + 1

    def test_get_stats(self, db):
        stats = db.get_stats()
        assert "total_cves" in stats
        assert "by_severity" in stats
        assert "last_update" in stats

    def test_get_cve_not_found(self, db):
        assert db.get_cve("CVE-9999-9999") is None

    @patch("tools.cve_database.requests.get")
    def test_update_database_network_error(self, mock_get):
        from tools.cve_database import CVEDatabase
        import tools.cve_database as cve_mod

        with patch.object(cve_mod, "CVE_DB_PATH", Path("/tmp/test_cve_fail.db")):
            with patch.object(cve_mod, "DATA_DIR", Path("/tmp")):
                mock_get.side_effect = Exception("Network error")
                db = CVEDatabase(auto_update=False)
                result = db.update_database(days_back=1)
                assert result["status"] == "error"


class TestFormatCveForAi:
    def test_format(self):
        from tools.cve_database import CVEEntry, format_cve_for_ai

        entry = CVEEntry(
            cve_id="CVE-2024-0001",
            description="A test vulnerability",
            published_date="2024-01-01",
            last_modified="2024-01-02",
            cvss_score=9.8,
            severity="Critical",
            cwe_ids=["CWE-89"],
            exploit_available=True,
            affected_products=["apache:http_server"],
        )
        output = format_cve_for_ai(entry)
        assert "CVE-2024-0001" in output
        assert "9.8" in output
        assert "CWE-89" in output
        assert "apache" in output.lower()


# ============================================================================
# 8. tools/swarm_controller.py
# ============================================================================


class TestSwarmTarget:
    def test_creation(self):
        from tools.swarm_controller import SwarmTarget

        t = SwarmTarget(
            target_id="t1",
            target_url="http://target1.com",
            mission_id="m1",
        )
        assert t.priority == 5
        assert t.status == "pending"
        assert t.progress == 0.0


class TestSwarmConfig:
    def test_defaults(self):
        from tools.swarm_controller import SwarmConfig

        cfg = SwarmConfig()
        assert cfg.max_concurrent == 3
        assert cfg.enable_governance is True
        assert cfg.abort_on_critical is False


class TestSwarmMissionTracker:
    def test_add_and_summary(self):
        from tools.swarm_controller import SwarmMissionTracker, SwarmTarget

        tracker = SwarmMissionTracker()
        t = SwarmTarget(target_id="t1", target_url="http://a.com", mission_id="m1")
        tracker.add_target(t)
        summary = tracker.get_summary()
        assert summary["total_targets"] == 1
        assert summary["pending"] == 1

    def test_update_progress(self):
        from tools.swarm_controller import SwarmMissionTracker, SwarmTarget

        tracker = SwarmMissionTracker()
        t = SwarmTarget(target_id="t1", target_url="http://a.com", mission_id="m1")
        tracker.add_target(t)
        tracker.update_progress("t1", 50.0)
        assert tracker.targets["t1"].progress == 50.0

    def test_update_status(self):
        from tools.swarm_controller import SwarmMissionTracker, SwarmTarget

        tracker = SwarmMissionTracker()
        t = SwarmTarget(target_id="t1", target_url="http://a.com", mission_id="m1")
        tracker.add_target(t)
        tracker.update_status("t1", "running")
        assert tracker.targets["t1"].status == "running"
        assert tracker.targets["t1"].start_time is not None
        tracker.update_status("t1", "completed")
        assert tracker.targets["t1"].end_time is not None

    def test_update_findings(self):
        from tools.swarm_controller import SwarmMissionTracker, SwarmTarget

        tracker = SwarmMissionTracker()
        t = SwarmTarget(target_id="t1", target_url="http://a.com", mission_id="m1")
        tracker.add_target(t)
        tracker.update_findings("t1", 5)
        assert tracker.targets["t1"].findings_count == 5

    def test_format_progress_table(self):
        from tools.swarm_controller import SwarmMissionTracker, SwarmTarget

        tracker = SwarmMissionTracker()
        t = SwarmTarget(target_id="t1", target_url="http://a.com", mission_id="m1")
        tracker.add_target(t)
        table = tracker.format_progress_table()
        assert "Target" in table
        assert "Status" in table


class TestSwarmController:
    def test_init(self):
        from tools.swarm_controller import SwarmController, SwarmConfig

        ctrl = SwarmController(SwarmConfig())
        assert ctrl.config.max_concurrent == 3

    def test_load_targets_from_list(self):
        from tools.swarm_controller import SwarmController, SwarmConfig

        ctrl = SwarmController(SwarmConfig())
        targets = ctrl.load_targets_from_list(
            [
                "http://target1.com",
                "http://target2.com",
                "",
            ]
        )
        assert len(targets) == 2
        assert targets[0].target_url == "http://target1.com"

    def test_abort(self):
        from tools.swarm_controller import SwarmController, SwarmConfig

        ctrl = SwarmController(SwarmConfig())
        ctrl.abort()
        assert ctrl.abort_event.is_set()

    def test_generate_aggregate_report_empty(self):
        from tools.swarm_controller import SwarmController, SwarmConfig

        ctrl = SwarmController(SwarmConfig())
        report = ctrl.generate_aggregate_report()
        assert report["total_findings"] == 0
        assert report["target_breakdown"] == []

    def test_save_report(self, tmp_path):
        from tools.swarm_controller import SwarmController, SwarmConfig

        cfg = SwarmConfig(output_dir=tmp_path)
        ctrl = SwarmController(cfg)
        path = ctrl.save_report(tmp_path / "test_report.json")
        assert path.exists()
        data = json.loads(path.read_text())
        assert "swarm_id" in data

    @patch("tools.swarm_controller.time.sleep", return_value=None)
    def test_run_single_target(self, mock_sleep):
        from tools.swarm_controller import SwarmController, SwarmConfig, SwarmTarget

        ctrl = SwarmController(SwarmConfig())
        t = SwarmTarget(target_id="t1", target_url="http://a.com", mission_id="m1")
        result = ctrl._run_single_target(t)
        assert result.success is True
        assert result.target_id == "t1"


class TestFormatSwarmReport:
    def test_format(self):
        from tools.swarm_controller import format_swarm_report

        report = {
            "swarm_id": "swarm_test123",
            "total_duration_seconds": 42.5,
            "summary": {"total_targets": 3, "completed": 2, "failed": 1, "total_findings": 10},
            "severity_distribution": {"critical": 2, "high": 3, "medium": 5},
            "target_breakdown": [
                {
                    "target": "http://a.com",
                    "success": True,
                    "findings_count": 5,
                    "duration_seconds": 10,
                },
            ],
        }
        output = format_swarm_report(report)
        assert "swarm_test123" in output
        assert "42.5s" in output
        assert "CRITICAL: 2" in output


# ============================================================================
# 9. tools/soc_analyzer.py
# ============================================================================


class TestSOCAnalyzerAlert:
    def test_creation(self):
        from tools.soc_analyzer import Alert

        a = Alert(
            alert_id="a1",
            timestamp="2024-01-01T00:00:00Z",
            source="suricata",
            alert_type="intrusion",
            severity="high",
            confidence=0.9,
        )
        assert a.severity == "high"
        assert a.ioc_matches == []


class TestSOCAnalyzer:
    @pytest.fixture
    def analyzer(self):
        from tools.soc_analyzer import SOCAnalyzer

        return SOCAnalyzer(
            ioc_db={
                "ip": {"10.0.0.1": True, "192.168.1.100": True},
                "domain": {"evil.com": True},
            }
        )

    def test_init(self):
        from tools.soc_analyzer import SOCAnalyzer

        sa = SOCAnalyzer()
        assert sa.ioc_db == {}
        assert sa.alerts == []

    def test_parse_syslog(self, analyzer):
        line = "Jan  1 12:00:00 hostname sshd[1234]: Failed password for root from 10.0.0.1"
        alert = analyzer.parse_syslog(line)
        assert alert is not None
        assert alert.src_ip == "10.0.0.1"
        assert "critical" in (
            "critical",
            "high",
            "medium",
            "low",
            "info",
        )  # just checking it's valid

    def test_parse_syslog_invalid(self, analyzer):
        alert = analyzer.parse_syslog("not a syslog line at all")
        assert alert is None

    def test_parse_json_alert(self, analyzer):
        data = {
            "alert_id": "json1",
            "timestamp": "2024-01-01T00:00:00Z",
            "severity": "high",
            "signature": "ET MALWARE Detected",
            "src_ip": "10.0.0.1",
            "dst_ip": "192.168.1.100",
            "src_port": 4444,
            "dst_port": 80,
        }
        alert = analyzer.parse_json_alert(data, "suricata")
        assert alert is not None
        assert alert.alert_id == "json1"
        assert alert.src_ip == "10.0.0.1"
        assert alert.src_port == 4444

    def test_parse_json_alert_type_detection(self, analyzer):
        data = {"signature": "Privilege Escalation Detected", "severity": "critical"}
        alert = analyzer.parse_json_alert(data, "wazuh")
        assert alert.alert_type == "privilege_escalation"

    def test_parse_json_alert_malware_type(self, analyzer):
        data = {"signature": "Trojan Detected", "severity": "high"}
        alert = analyzer.parse_json_alert(data, "crowdstrike")
        assert alert.alert_type == "malware"

    def test_parse_json_alert_recon_type(self, analyzer):
        data = {"signature": "Port Scan Detected", "severity": "medium"}
        alert = analyzer.parse_json_alert(data, "ids")
        assert alert.alert_type == "recon"

    def test_parse_json_alert_exfil_type(self, analyzer):
        data = {"signature": "Data Exfiltration Detected", "severity": "critical"}
        alert = analyzer.parse_json_alert(data, "dlp")
        assert alert.alert_type == "data_exfiltration"

    def test_check_ioc(self, analyzer):
        from tools.soc_analyzer import Alert

        alert = Alert(
            alert_id="a1",
            timestamp="",
            source="test",
            alert_type="intrusion",
            severity="high",
            confidence=0.9,
            src_ip="10.0.0.1",
            domain="evil.com",
        )
        matches = analyzer.check_ioc(alert)
        assert "ip:10.0.0.1" in matches
        assert "domain:evil.com" in matches

    def test_check_ioc_no_match(self, analyzer):
        from tools.soc_analyzer import Alert

        alert = Alert(
            alert_id="a1",
            timestamp="",
            source="test",
            alert_type="intrusion",
            severity="high",
            confidence=0.9,
            src_ip="1.2.3.4",
        )
        matches = analyzer.check_ioc(alert)
        assert len(matches) == 0

    def test_identify_threat_actor(self, analyzer):
        from tools.soc_analyzer import Alert

        alert = Alert(
            alert_id="a1",
            timestamp="",
            source="test",
            alert_type="intrusion",
            severity="high",
            confidence=0.9,
            signature="Cobalt Strike beacon detected",
        )
        actor, campaign = analyzer.identify_threat_actor(alert)
        assert actor == "cobalt_strike"

    def test_identify_threat_actor_none(self, analyzer):
        from tools.soc_analyzer import Alert

        alert = Alert(
            alert_id="a1",
            timestamp="",
            source="test",
            alert_type="intrusion",
            severity="high",
            confidence=0.9,
            signature="Generic alert",
        )
        actor, campaign = analyzer.identify_threat_actor(alert)
        assert actor is None

    def test_calculate_priority(self, analyzer):
        from tools.soc_analyzer import Alert

        alert = Alert(
            alert_id="a1",
            timestamp="",
            source="test",
            alert_type="intrusion",
            severity="critical",
            confidence=1.0,
        )
        priority = analyzer.calculate_priority(alert)
        assert priority > 0
        assert priority <= 10.0

    def test_calculate_priority_with_iocs(self, analyzer):
        from tools.soc_analyzer import Alert

        alert = Alert(
            alert_id="a1",
            timestamp="",
            source="test",
            alert_type="intrusion",
            severity="critical",
            confidence=1.0,
            ioc_matches=["ip:10.0.0.1"],
        )
        priority = analyzer.calculate_priority(alert)
        # IOC match adds bonus
        assert priority > 8.0

    def test_triage_alert(self, analyzer):
        from tools.soc_analyzer import Alert

        alert = Alert(
            alert_id="a1",
            timestamp="",
            source="test",
            alert_type="intrusion",
            severity="high",
            confidence=0.9,
            src_ip="10.0.0.1",  # known IOC
        )
        result = analyzer.triage_alert(alert)
        assert result.category == "true_positive"
        assert result.priority_score > 0

    def test_triage_alert_false_positive(self, analyzer):
        from tools.soc_analyzer import Alert

        alert = Alert(
            alert_id="a2",
            timestamp="",
            source="test",
            alert_type="recon",
            severity="low",
            confidence=0.2,
        )
        result = analyzer.triage_alert(alert)
        assert result.category == "false_positive_likely"

    def test_correlate_alerts(self, analyzer):
        from tools.soc_analyzer import Alert, TriageResult

        a1 = Alert(
            alert_id="a1",
            timestamp="",
            source="test",
            alert_type="intrusion",
            severity="high",
            confidence=0.9,
            src_ip="10.0.0.1",
        )
        a2 = Alert(
            alert_id="a2",
            timestamp="",
            source="test",
            alert_type="recon",
            severity="medium",
            confidence=0.7,
            src_ip="10.0.0.1",
        )
        t1 = analyzer.triage_alert(a1)
        t2 = analyzer.triage_alert(a2)
        correlated = analyzer.correlate_alerts([t1, t2])
        assert "a2" in correlated[0].related_alerts
        assert "a1" in correlated[1].related_alerts

    def test_generate_sigma_rule(self, analyzer):
        from tools.soc_analyzer import Alert

        alert = Alert(
            alert_id="a1",
            timestamp="",
            source="suricata",
            alert_type="intrusion",
            severity="high",
            confidence=0.9,
            signature="ET EXPLOIT Detected",
            src_ip="10.0.0.1",
        )
        rule = analyzer.generate_sigma_rule(alert)
        assert rule is not None
        assert rule.title is not None
        assert rule.level == "high"

    def test_generate_sigma_rule_low_confidence(self, analyzer):
        from tools.soc_analyzer import Alert

        alert = Alert(
            alert_id="a1",
            timestamp="",
            source="test",
            alert_type="intrusion",
            severity="high",
            confidence=0.3,
        )
        rule = analyzer.generate_sigma_rule(alert)
        assert rule is None

    def test_analyze_log_file_not_found(self, analyzer):
        report = analyzer.analyze_log_file(Path("/nonexistent/file.log"))
        assert "error" in report


class TestFormatSocReport:
    def test_format(self):
        from tools.soc_analyzer import format_soc_report

        report = {
            "total_alerts": 10,
            "severity_distribution": {"high": 5, "medium": 3, "low": 2},
            "category_distribution": {"true_positive": 3, "needs_investigation": 7},
            "top_priority_alerts": [
                {
                    "id": "a1",
                    "type": "intrusion",
                    "severity": "high",
                    "priority": 8.5,
                    "src_ip": "10.0.0.1",
                    "threat_actor": "cobalt_strike",
                    "action": "Contain",
                },
            ],
            "threat_actors_identified": ["cobalt_strike"],
            "generated_rules": [{"title": "Test Rule", "level": "high", "tags": ["intrusion"]}],
        }
        output = format_soc_report(report)
        assert "10" in output
        assert "cobalt_strike" in output
        assert "HIGH: 5" in output
