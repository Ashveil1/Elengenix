"""tests/test_tool_registry_coverage.py — Coverage tests for tools/tool_registry.py

Focuses on uncovered lines in execute_chain, tool wrappers, and edge cases.
"""

import asyncio
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from tools.tool_registry import (
    BaseTool,
    ToolCategory,
    ToolMetadata,
    ToolPriority,
    ToolRegistry,
    ToolResult,
    registry,
)


def _run_async(coro):
    """Run async coroutine in event loop."""
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


# ═══════════════════════════════════════════════════════════════════════════════
# ToolResult edge cases
# ═══════════════════════════════════════════════════════════════════════════════


class TestToolResultEdgeCases:
    def test_to_dict_long_output_truncated(self):
        result = ToolResult(
            success=True,
            tool_name="test",
            category=ToolCategory.SCANNER,
            output="x" * 1000,
        )
        d = result.to_dict()
        assert len(d["output"]) == 500

    def test_to_dict_short_output_not_truncated(self):
        result = ToolResult(
            success=True,
            tool_name="test",
            category=ToolCategory.SCANNER,
            output="short",
        )
        d = result.to_dict()
        assert d["output"] == "short"

    def test_to_dict_with_findings(self):
        result = ToolResult(
            success=True,
            tool_name="test",
            category=ToolCategory.SCANNER,
            findings=[{"type": "xss"}, {"type": "sqli"}],
        )
        d = result.to_dict()
        assert d["findings_count"] == 2

    def test_to_dict_with_error(self):
        result = ToolResult(
            success=False,
            tool_name="test",
            category=ToolCategory.SCANNER,
            error_message="Connection refused",
        )
        d = result.to_dict()
        assert d["error"] == "Connection refused"


# ═══════════════════════════════════════════════════════════════════════════════
# ToolRegistry edge cases
# ═══════════════════════════════════════════════════════════════════════════════


class TestToolRegistryEdgeCases:
    def test_singleton_behavior(self):
        r1 = ToolRegistry()
        r2 = ToolRegistry()
        assert r1 is r2

    def test_unregister_nonexistent(self):
        reg = ToolRegistry()
        reg._initialized = True
        reg.unregister("nonexistent_tool_xyz")

    def test_get_tools_by_category_returns_list(self):
        reg = ToolRegistry()
        reg._initialized = True
        result = reg.get_tools_by_category(ToolCategory.EXPLOITATION)
        assert isinstance(result, list)

    def test_list_available_tools_includes_metadata(self):
        reg = ToolRegistry()
        reg._initialized = True
        tools = reg.list_available_tools()
        for name, info in tools.items():
            assert "available" in info
            assert "category" in info
            assert "priority" in info
            assert "description" in info

    def test_get_recommended_chain_web(self):
        reg = ToolRegistry()
        reg._initialized = True
        chain = reg.get_recommended_chain("web")
        assert isinstance(chain, list)

    def test_get_recommended_chain_api(self):
        reg = ToolRegistry()
        reg._initialized = True
        chain = reg.get_recommended_chain("api")
        assert isinstance(chain, list)

    def test_get_recommended_chain_network(self):
        reg = ToolRegistry()
        reg._initialized = True
        chain = reg.get_recommended_chain("network")
        assert isinstance(chain, list)

    def test_get_recommended_chain_unknown(self):
        reg = ToolRegistry()
        reg._initialized = True
        chain = reg.get_recommended_chain("unknown_type")
        assert isinstance(chain, list)


# ═══════════════════════════════════════════════════════════════════════════════
# execute_chain coverage
# ═══════════════════════════════════════════════════════════════════════════════


class TestExecuteChainCoverage:
    def test_execute_chain_with_available_tool(self):
        reg = ToolRegistry()
        reg._initialized = True
        mock_tool = MagicMock()
        mock_tool.is_available = True
        mock_tool.metadata = ToolMetadata(
            name="avail_test",
            category=ToolCategory.SCANNER,
            priority=ToolPriority.HIGH,
            binary_name="python3",
            description="Available test tool",
        )
        mock_tool.execute = AsyncMock(
            return_value=ToolResult(
                success=True,
                tool_name="avail_test",
                category=ToolCategory.SCANNER,
                output="done",
                findings=[{"type": "test"}],
            )
        )
        reg.register(mock_tool)

        async def run():
            return await reg.execute_chain([mock_tool], "target", Path("/tmp"))

        results = _run_async(run())
        assert len(results) == 1
        assert results[0].success
        reg.unregister("avail_test")

    def test_execute_chain_with_progress_callback(self):
        reg = ToolRegistry()
        reg._initialized = True
        mock_tool = MagicMock()
        mock_tool.is_available = True
        mock_tool.metadata = ToolMetadata(
            name="cb_test",
            category=ToolCategory.SCANNER,
            priority=ToolPriority.HIGH,
            binary_name="python3",
            description="Callback test",
        )
        mock_tool.execute = AsyncMock(
            return_value=ToolResult(
                success=True,
                tool_name="cb_test",
                category=ToolCategory.SCANNER,
            )
        )
        reg.register(mock_tool)

        callback_results = []

        def progress_cb(result):
            callback_results.append(result)

        async def run():
            return await reg.execute_chain(
                [mock_tool], "target", Path("/tmp"), progress_callback=progress_cb
            )

        results = _run_async(run())
        assert len(callback_results) == 1
        reg.unregister("cb_test")

    def test_execute_chain_tool_exception(self):
        reg = ToolRegistry()
        reg._initialized = True
        mock_tool = MagicMock()
        mock_tool.is_available = True
        mock_tool.metadata = ToolMetadata(
            name="err_test",
            category=ToolCategory.SCANNER,
            priority=ToolPriority.HIGH,
            binary_name="python3",
            description="Error test",
        )
        mock_tool.execute = AsyncMock(side_effect=RuntimeError("boom"))
        reg.register(mock_tool)

        async def run():
            return await reg.execute_chain([mock_tool], "target", Path("/tmp"))

        results = _run_async(run())
        assert len(results) == 1
        assert not results[0].success
        assert "boom" in results[0].error_message
        reg.unregister("err_test")

    def test_execute_chain_multiple_tools_mixed(self):
        reg = ToolRegistry()
        reg._initialized = True

        tool1 = MagicMock()
        tool1.is_available = True
        tool1.metadata = ToolMetadata(
            name="mixed_ok",
            category=ToolCategory.RECON,
            priority=ToolPriority.HIGH,
            binary_name="python3",
            description="OK tool",
        )
        tool1.execute = AsyncMock(
            return_value=ToolResult(
                success=True,
                tool_name="mixed_ok",
                category=ToolCategory.RECON,
            )
        )

        tool2 = MagicMock()
        tool2.is_available = False
        tool2.metadata = ToolMetadata(
            name="mixed_unavail",
            category=ToolCategory.SCANNER,
            priority=ToolPriority.HIGH,
            binary_name="nonexistent_xyz",
            description="Unavailable",
        )

        reg.register(tool1)
        reg.register(tool2)

        async def run():
            return await reg.execute_chain([tool1, tool2], "target", Path("/tmp"))

        results = _run_async(run())
        assert len(results) == 1
        assert results[0].success
        reg.unregister("mixed_ok")
        reg.unregister("mixed_unavail")


# ═══════════════════════════════════════════════════════════════════════════════
# BaseTool edge cases
# ═══════════════════════════════════════════════════════════════════════════════


class TestBaseToolEdgeCases:
    def test_build_command_raises_not_implemented(self):
        meta = ToolMetadata(
            name="test",
            category=ToolCategory.SCANNER,
            priority=ToolPriority.HIGH,
            binary_name="python3",
            description="Test",
        )

        class StubTool(BaseTool):
            async def execute(self, target, report_dir, semaphore, **kwargs):
                return ToolResult(True, "test", ToolCategory.SCANNER)

        tool = StubTool(meta)
        with pytest.raises(NotImplementedError):
            tool._build_command("target", Path("/tmp"))

    def test_is_available_checks_binary(self):
        meta = ToolMetadata(
            name="test",
            category=ToolCategory.SCANNER,
            priority=ToolPriority.HIGH,
            binary_name="python3",
            description="Test",
        )

        class StubTool(BaseTool):
            async def execute(self, target, report_dir, semaphore, **kwargs):
                return ToolResult(True, "test", ToolCategory.SCANNER)

        tool = StubTool(meta)
        assert tool.is_available is True

    def test_is_available_false_for_missing_binary(self):
        meta = ToolMetadata(
            name="test",
            category=ToolCategory.SCANNER,
            priority=ToolPriority.HIGH,
            binary_name="nonexistent_binary_xyz_123",
            description="Test",
        )

        class StubTool(BaseTool):
            async def execute(self, target, report_dir, semaphore, **kwargs):
                return ToolResult(True, "test", ToolCategory.SCANNER)

        tool = StubTool(meta)
        assert tool.is_available is False


# ═══════════════════════════════════════════════════════════════════════════════
# register_tool decorator edge cases
# ═══════════════════════════════════════════════════════════════════════════════


class TestRegisterToolDecorator:
    def test_decorator_rejects_non_basetool(self):
        from tools.tool_registry import register_tool

        meta = ToolMetadata(
            name="bad_tool",
            category=ToolCategory.SCANNER,
            priority=ToolPriority.HIGH,
            binary_name="python3",
            description="Not a BaseTool",
        )

        with pytest.raises(TypeError):

            @register_tool(meta)
            class NotATool:
                pass


# ═══════════════════════════════════════════════════════════════════════════════
# Dynamic tool loading
# ═══════════════════════════════════════════════════════════════════════════════


class TestDynamicToolLoading:
    def test_load_dynamic_tools_nonexistent_dir(self):
        reg = ToolRegistry()
        reg._initialized = True
        reg.load_dynamic_tools("/nonexistent/path/xyz")

    def test_load_dynamic_tools_empty_dir(self):
        reg = ToolRegistry()
        reg._initialized = True
        with tempfile.TemporaryDirectory() as tmpdir:
            reg.load_dynamic_tools(tmpdir)

    def test_load_dynamic_tools_with_bad_python(self):
        reg = ToolRegistry()
        reg._initialized = True
        with tempfile.TemporaryDirectory() as tmpdir:
            bad_file = Path(tmpdir) / "bad.py"
            bad_file.write_text("this is not valid python {{{")
            reg.load_dynamic_tools(tmpdir)


# ═══════════════════════════════════════════════════════════════════════════════
# _run_subprocess edge cases
# ═══════════════════════════════════════════════════════════════════════════════


class TestRunSubprocess:
    def test_run_subprocess_with_semaphore(self):
        meta = ToolMetadata(
            name="test",
            category=ToolCategory.SCANNER,
            priority=ToolPriority.HIGH,
            binary_name="python3",
            description="Test",
        )

        class StubTool(BaseTool):
            async def execute(self, target, report_dir, semaphore, **kwargs):
                return ToolResult(True, "test", ToolCategory.SCANNER)

        tool = StubTool(meta)
        sem = asyncio.Semaphore(1)

        async def run():
            return await tool._run_subprocess(["echo", "hello"], timeout=5, semaphore=sem)

        stdout, stderr, rc = _run_async(run())
        assert "hello" in stdout
        assert rc == 0

    def test_run_subprocess_timeout(self):
        meta = ToolMetadata(
            name="test",
            category=ToolCategory.SCANNER,
            priority=ToolPriority.HIGH,
            binary_name="python3",
            description="Test",
            timeout_seconds=1,
        )

        class StubTool(BaseTool):
            async def execute(self, target, report_dir, semaphore, **kwargs):
                return ToolResult(True, "test", ToolCategory.SCANNER)

        tool = StubTool(meta)

        async def run():
            return await tool._run_subprocess(["sleep", "30"], timeout=1)

        stdout, stderr, rc = _run_async(run())
        assert rc == 1
        assert "Timeout" in stderr

    def test_run_subprocess_file_not_found(self):
        meta = ToolMetadata(
            name="test",
            category=ToolCategory.SCANNER,
            priority=ToolPriority.HIGH,
            binary_name="python3",
            description="Test",
        )

        class StubTool(BaseTool):
            async def execute(self, target, report_dir, semaphore, **kwargs):
                return ToolResult(True, "test", ToolCategory.SCANNER)

        tool = StubTool(meta)

        async def run():
            return await tool._run_subprocess(["nonexistent_binary_xyz_123"], timeout=5)

        stdout, stderr, rc = _run_async(run())
        assert rc == 1
        assert "not found" in stderr.lower()
