"""
tools/tool_registry.py — Elengenix Plugin System
- Dynamic tool registration and discovery
- Standardized interface for all security tools
- Async execution with semaphore-based rate limiting
- Auto-discovery from tools/ directory
"""

import asyncio
import logging
import shutil
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Type, Union

from rich.progress import Progress, SpinnerColumn, TextColumn

from ui_components import console

logger = logging.getLogger("elengenix.tools")


class ToolCategory(Enum):
    """Classification of security tools by purpose."""

    RECON = "reconnaissance"
    SCANNER = "vulnerability_scanner"
    EXPLOITATION = "exploitation"
    FUZZING = "fuzzing"
    SECRETS = "secret_detection"
    API = "api_testing"
    NETWORK = "network_scanning"
    REPORTING = "reporting"
    UTILITY = "utility"


class ToolPriority(Enum):
    """Execution priority for tool ordering."""

    CRITICAL = 1
    HIGH = 2
    MEDIUM = 3
    LOW = 4


@dataclass
class ToolResult:
    """Standardized result format for all tools."""

    success: bool
    tool_name: str
    category: ToolCategory
    output: str = ""
    findings: List[Dict[str, Any]] = field(default_factory=list)
    execution_time: float = 0.0
    error_message: Optional[str] = None
    raw_output_file: Optional[Path] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "success": self.success,
            "tool_name": self.tool_name,
            "category": self.category.value,
            "output": self.output[:500] if len(self.output) > 500 else self.output,
            "findings_count": len(self.findings),
            "execution_time": self.execution_time,
            "error": self.error_message,
        }


@dataclass
class ToolMetadata:
    """Metadata for tool registration."""

    name: str
    category: ToolCategory
    priority: ToolPriority
    binary_name: str
    description: str
    requires_target: bool = True
    supports_list_input: bool = False
    timeout_seconds: int = 300
    extra_args: Dict[str, Any] = field(default_factory=dict)


class BaseTool(ABC):
    """Abstract base class for all Elengenix tools."""

    def __init__(self, metadata: ToolMetadata):
        self.metadata = metadata
        self._check_binary()

    def _check_binary(self) -> bool:
        """Verify the tool binary is installed."""
        return shutil.which(self.metadata.binary_name) is not None

    @property
    def is_available(self) -> bool:
        return self._check_binary()

    @abstractmethod
    async def execute(
        self,
        target: Union[str, List[str]],
        report_dir: Path,
        semaphore: asyncio.Semaphore,
        **kwargs,
    ) -> ToolResult:
        """Execute the tool and return standardized result."""

    def _build_command(
        self,
        target: Union[str, List[str]],
        output_file: Path,
        extra_flags: Optional[List[str]] = None,
    ) -> List[str]:
        """Build command arguments. Override in subclasses."""
        raise NotImplementedError("Subclasses must implement _build_command")

    async def _run_subprocess(
        self,
        cmd: List[str],
        timeout: Optional[int] = None,
        semaphore: Optional[asyncio.Semaphore] = None,
    ) -> tuple:
        """Execute subprocess with optional semaphore.

        Returns:
            Tuple of (stdout, stderr, return_code).
        """

        async def _exec():
            proc = None
            try:
                proc = await asyncio.create_subprocess_exec(
                    *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
                )
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(), timeout=timeout or self.metadata.timeout_seconds
                )
                return stdout.decode(), stderr.decode(), proc.returncode
            except asyncio.TimeoutError:
                if proc is not None:
                    proc.kill()
                return "", "Timeout exceeded", 1
            except FileNotFoundError:
                return "", f"Binary not found: {cmd[0]}", 1
            except OSError as e:
                return "", f"OS error: {e}", 1

        if semaphore:
            async with semaphore:
                return await _exec()
        return await _exec()


class ToolRegistry:
    """Central registry for all security tools."""

    _instance = None
    _tools: Dict[str, BaseTool] = {}
    _categories: Dict[ToolCategory, List[str]] = {}

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if not getattr(self, "_initialized", False):
            self._initialized = True
            self.load_dynamic_tools()

    def register(self, tool: BaseTool) -> None:
        """Register a tool instance."""
        name = tool.metadata.name
        self._tools[name] = tool

        category = tool.metadata.category
        if category not in self._categories:
            self._categories[category] = []
        if name not in self._categories[category]:
            self._categories[category].append(name)

        logger.info(f"Registered tool: {name} ({category.value})")

    def unregister(self, name: str) -> None:
        """Remove a tool from registry."""
        if name in self._tools:
            tool = self._tools.pop(name)
            self._categories[tool.metadata.category].remove(name)

    def load_dynamic_tools(self, ai_tools_dir: Union[str, Path] = "tools/ai_generated") -> None:
        """Dynamically load and register AI-generated tools from the specified directory."""
        import importlib.util
        import sys

        path = Path(ai_tools_dir).resolve()
        if not path.exists() or not path.is_dir():
            return

        for py_file in path.glob("*.py"):
            try:
                module_name = f"ai_generated.{py_file.stem}"
                spec = importlib.util.spec_from_file_location(module_name, py_file)
                if spec and spec.loader:
                    module = importlib.util.module_from_spec(spec)
                    sys.modules[module_name] = module
                    spec.loader.exec_module(module)
                    logger.info(f"Dynamically loaded AI tool module: {py_file.name}")
            except Exception as e:
                logger.error(f"Failed to load dynamic tool {py_file.name}: {e}")

    def get_tool(self, name: str) -> Optional[BaseTool]:
        """Get tool by name."""
        return self._tools.get(name)

    def get_tools_by_category(self, category: ToolCategory) -> List[BaseTool]:
        """Get all tools in a category."""
        names = self._categories.get(category, [])
        return [self._tools[n] for n in names if n in self._tools]

    def list_available_tools(self) -> Dict[str, Dict[str, Any]]:
        """List all registered tools with availability status."""
        return {
            name: {
                "available": tool.is_available,
                "category": tool.metadata.category.value,
                "priority": tool.metadata.priority.name,
                "description": tool.metadata.description,
            }
            for name, tool in self._tools.items()
        }

    def get_recommended_chain(self, target_type: str = "web") -> List[BaseTool]:
        """Get recommended tool execution chain based on target type."""
        chains = {
            "web": [
                ToolCategory.RECON,
                ToolCategory.NETWORK,
                ToolCategory.API,
                ToolCategory.SECRETS,
                ToolCategory.SCANNER,
                ToolCategory.EXPLOITATION,
            ],
            "api": [
                ToolCategory.RECON,
                ToolCategory.API,
                ToolCategory.SECRETS,
                ToolCategory.FUZZING,
            ],
            "network": [
                ToolCategory.NETWORK,
                ToolCategory.RECON,
                ToolCategory.SCANNER,
            ],
        }

        result = []
        for category in chains.get(target_type, chains["web"]):
            tools = self.get_tools_by_category(category)
            # Sort by priority
            tools.sort(key=lambda t: t.metadata.priority.value)
            result.extend(tools)

        return result

    async def execute_chain(
        self,
        tools: List[BaseTool],
        target: str,
        report_dir: Path,
        rate_limit: int = 5,
        progress_callback: Optional[Callable] = None,
    ) -> List[ToolResult]:
        """Execute a chain of tools sequentially with rate limiting."""
        semaphore = asyncio.Semaphore(rate_limit)
        results = []

        with Progress(
            SpinnerColumn(),
            TextColumn("[bold cyan]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task("Executing tool chain...", total=len(tools))

            for tool in tools:
                if not tool.is_available:
                    logger.warning(f"Tool {tool.metadata.name} not available, skipping")
                    progress.advance(task)
                    continue

                progress.update(task, description=f"Running {tool.metadata.name}...")

                try:
                    result = await tool.execute(target, report_dir, semaphore)
                    results.append(result)

                    if progress_callback:
                        progress_callback(result)

                except Exception as e:
                    logger.error(f"Tool {tool.metadata.name} failed: {e}")
                    results.append(
                        ToolResult(
                            success=False,
                            tool_name=tool.metadata.name,
                            category=tool.metadata.category,
                            error_message=str(e),
                        )
                    )

                progress.advance(task)

        return results


# Global registry instance
registry = ToolRegistry()


def register_tool(metadata: ToolMetadata):
    """Decorator to register a tool class."""

    def decorator(cls: Type[BaseTool]):
        if not issubclass(cls, BaseTool):
            raise TypeError(f"{cls.__name__} must inherit from BaseTool")

        tool_instance = cls(metadata)
        registry.register(tool_instance)
        return cls

    return decorator


# ═══════════════════════════════════════════════════════════════════════════════
# NATIVE PYTHON TOOL WRAPPERS
# ═══════════════════════════════════════════════════════════════════════════════


# ═══════════════════════════════════════════════════════════════════════════════
# NATIVE PYTHON TOOL WRAPPERS
# ═══════════════════════════════════════════════════════════════════════════════


@register_tool(
    ToolMetadata(
        name="waf_detector",
        category=ToolCategory.SCANNER,
        priority=ToolPriority.HIGH,
        binary_name="python3",
        description="Smart WAF detection via probe-based analysis",
        timeout_seconds=120,
    )
)
class WAFDetectorTool(BaseTool):
    """Wrapper for the SmartWAFDetector native Python module."""

    def _check_binary(self) -> bool:
        return True

    async def execute(
        self,
        target: Union[str, List[str]],
        report_dir: Path,
        semaphore: asyncio.Semaphore,
        **kwargs,
    ) -> ToolResult:
        import time

        start_time = time.time()
        base_url = target if isinstance(target, str) else target[0]

        try:
            from tools.waf_detector import SmartWAFDetector

            detector = SmartWAFDetector()
            result = detector.probe(base_url)

            findings = []
            if result.waf_detected:
                findings.append(
                    {
                        "type": "waf_detected",
                        "waf_name": result.waf_name,
                        "confidence": result.confidence,
                        "blocked_payloads": result.blocked_payloads,
                        "suggested_evasions": result.suggested_evasions,
                        "url": base_url,
                    }
                )

            return ToolResult(
                success=True,
                tool_name=self.metadata.name,
                category=self.metadata.category,
                output=f"WAF detected: {result.waf_detected}, name: {result.waf_name}",
                findings=findings,
                execution_time=time.time() - start_time,
            )
        except Exception as e:
            return ToolResult(
                success=False,
                tool_name=self.metadata.name,
                category=self.metadata.category,
                error_message=str(e),
                execution_time=time.time() - start_time,
            )


@register_tool(
    ToolMetadata(
        name="active_fuzzer",
        category=ToolCategory.FUZZING,
        priority=ToolPriority.HIGH,
        binary_name="python3",
        description="Active fuzzing with response delta scoring",
        timeout_seconds=300,
    )
)
class ActiveFuzzerTool(BaseTool):
    """Wrapper for the ActiveFuzzer native Python module."""

    def _check_binary(self) -> bool:
        return True

    async def execute(
        self,
        target: Union[str, List[str]],
        report_dir: Path,
        semaphore: asyncio.Semaphore,
        **kwargs,
    ) -> ToolResult:
        import time

        start_time = time.time()
        base_url = target if isinstance(target, str) else target[0]

        try:
            from tools.active_fuzzer import ActiveFuzzer

            fuzzer = ActiveFuzzer()
            results = fuzzer.fuzz(target=base_url, max_params=kwargs.get("max_params", 5))

            findings = []
            for r in results:
                if r.get("vulnerable"):
                    findings.append(
                        {
                            "type": r.get("vuln_type", "unknown"),
                            "url": r.get("url", base_url),
                            "param": r.get("param", ""),
                            "payload": r.get("payload", ""),
                            "delta_score": r.get("delta_score", 0),
                        }
                    )

            return ToolResult(
                success=True,
                tool_name=self.metadata.name,
                category=self.metadata.category,
                output=f"Fuzzed {len(results)} parameters",
                findings=findings,
                execution_time=time.time() - start_time,
            )
        except Exception as e:
            return ToolResult(
                success=False,
                tool_name=self.metadata.name,
                category=self.metadata.category,
                error_message=str(e),
                execution_time=time.time() - start_time,
            )


@register_tool(
    ToolMetadata(
        name="python_recon",
        category=ToolCategory.RECON,
        priority=ToolPriority.MEDIUM,
        binary_name="python3",
        description="Pure Python HTTP probe, directory discovery, and port scan",
        timeout_seconds=180,
    )
)
class PythonReconTool(BaseTool):
    """Wrapper for the PythonRecon native Python module."""

    def _check_binary(self) -> bool:
        return True

    async def execute(
        self,
        target: Union[str, List[str]],
        report_dir: Path,
        semaphore: asyncio.Semaphore,
        **kwargs,
    ) -> ToolResult:
        import time

        start_time = time.time()
        base_url = target if isinstance(target, str) else target[0]

        try:
            from tools.python_recon import PythonRecon

            recon = PythonRecon()
            results = recon.run(base_url)

            findings = []
            for r in results:
                findings.append(
                    {
                        "type": r.get("type", "recon"),
                        "url": r.get("url", base_url),
                        "title": r.get("title", ""),
                        "details": r.get("details", ""),
                    }
                )

            return ToolResult(
                success=True,
                tool_name=self.metadata.name,
                category=self.metadata.category,
                output=f"Recon completed: {len(findings)} findings",
                findings=findings,
                execution_time=time.time() - start_time,
            )
        except Exception as e:
            return ToolResult(
                success=False,
                tool_name=self.metadata.name,
                category=self.metadata.category,
                error_message=str(e),
                execution_time=time.time() - start_time,
            )


# ═══════════════════════════════════════════════════════════════════════════════
# ADVANCED SCANNING MODULES
# ═══════════════════════════════════════════════════════════════════════════════


@register_tool(
    ToolMetadata(
        name="ssrf_scanner",
        category=ToolCategory.SCANNER,
        priority=ToolPriority.HIGH,
        binary_name="python3",
        description="Server-Side Request Forgery (SSRF) vulnerability scanner",
        timeout_seconds=300,
    )
)
class SSRFScannerTool(BaseTool):
    """Wrapper for the SSRFScanner module."""

    def _check_binary(self) -> bool:
        return True

    async def execute(
        self,
        target: Union[str, List[str]],
        report_dir: Path,
        semaphore: asyncio.Semaphore,
        **kwargs,
    ) -> ToolResult:
        import time

        start_time = time.time()
        base_url = target if isinstance(target, str) else target[0]

        try:
            from tools.ssrf_scanner import SSRFScanner

            scanner = SSRFScanner()
            result = scanner.scan(base_url)

            findings = []
            for r in result.results:
                if r.vulnerable:
                    findings.append(
                        {
                            "type": "ssrf",
                            "url": r.url,
                            "param": r.param,
                            "payload": r.payload,
                            "evidence": r.evidence,
                            "severity": r.severity,
                        }
                    )

            return ToolResult(
                success=True,
                tool_name=self.metadata.name,
                category=self.metadata.category,
                output=f"SSRF scan completed: {len(findings)} findings",
                findings=findings,
                execution_time=time.time() - start_time,
            )
        except Exception as e:
            return ToolResult(
                success=False,
                tool_name=self.metadata.name,
                category=self.metadata.category,
                error_message=str(e),
                execution_time=time.time() - start_time,
            )


@register_tool(
    ToolMetadata(
        name="ssti_scanner",
        category=ToolCategory.SCANNER,
        priority=ToolPriority.HIGH,
        binary_name="python3",
        description="Server-Side Template Injection (SSTI) vulnerability scanner",
        timeout_seconds=300,
    )
)
class SSTIScannerTool(BaseTool):
    """Wrapper for the SSTIScanner module."""

    def _check_binary(self) -> bool:
        return True

    async def execute(
        self,
        target: Union[str, List[str]],
        report_dir: Path,
        semaphore: asyncio.Semaphore,
        **kwargs,
    ) -> ToolResult:
        import time

        start_time = time.time()
        base_url = target if isinstance(target, str) else target[0]

        try:
            from tools.ssti_scanner import SSTIScanner

            scanner = SSTIScanner()
            result = scanner.scan(base_url)

            findings = []
            for r in result.results:
                if r.vulnerable:
                    findings.append(
                        {
                            "type": "ssti",
                            "url": r.url,
                            "param": r.param,
                            "engine": r.engine,
                            "payload": r.payload,
                            "evidence": r.evidence,
                            "severity": r.severity,
                        }
                    )

            return ToolResult(
                success=True,
                tool_name=self.metadata.name,
                category=self.metadata.category,
                output=f"SSTI scan completed: {len(findings)} findings",
                findings=findings,
                execution_time=time.time() - start_time,
            )
        except Exception as e:
            return ToolResult(
                success=False,
                tool_name=self.metadata.name,
                category=self.metadata.category,
                error_message=str(e),
                execution_time=time.time() - start_time,
            )


@register_tool(
    ToolMetadata(
        name="xxe_scanner",
        category=ToolCategory.SCANNER,
        priority=ToolPriority.HIGH,
        binary_name="python3",
        description="XML External Entity (XXE) vulnerability scanner",
        timeout_seconds=300,
    )
)
class XXEScannerTool(BaseTool):
    """Wrapper for the XXEScanner module."""

    def _check_binary(self) -> bool:
        return True

    async def execute(
        self,
        target: Union[str, List[str]],
        report_dir: Path,
        semaphore: asyncio.Semaphore,
        **kwargs,
    ) -> ToolResult:
        import time

        start_time = time.time()
        base_url = target if isinstance(target, str) else target[0]

        try:
            from tools.xxe_scanner import XXEScanner

            scanner = XXEScanner()
            result = scanner.scan(base_url)

            findings = []
            for r in result.results:
                if r.vulnerable:
                    findings.append(
                        {
                            "type": "xxe",
                            "url": r.url,
                            "payload_type": r.payload_type,
                            "payload": r.payload,
                            "evidence": r.evidence,
                            "severity": r.severity,
                        }
                    )

            return ToolResult(
                success=True,
                tool_name=self.metadata.name,
                category=self.metadata.category,
                output=f"XXE scan completed: {len(findings)} findings",
                findings=findings,
                execution_time=time.time() - start_time,
            )
        except Exception as e:
            return ToolResult(
                success=False,
                tool_name=self.metadata.name,
                category=self.metadata.category,
                error_message=str(e),
                execution_time=time.time() - start_time,
            )


@register_tool(
    ToolMetadata(
        name="deserialization_scanner",
        category=ToolCategory.SCANNER,
        priority=ToolPriority.HIGH,
        binary_name="python3",
        description="Insecure deserialization vulnerability scanner",
        timeout_seconds=300,
    )
)
class DeserializationScannerTool(BaseTool):
    """Wrapper for the DeserializationScanner module."""

    def _check_binary(self) -> bool:
        return True

    async def execute(
        self,
        target: Union[str, List[str]],
        report_dir: Path,
        semaphore: asyncio.Semaphore,
        **kwargs,
    ) -> ToolResult:
        import time

        start_time = time.time()
        base_url = target if isinstance(target, str) else target[0]

        try:
            from tools.deserialization_scanner import DeserializationScanner

            scanner = DeserializationScanner()
            result = scanner.scan(base_url)

            findings = []
            for r in result.results:
                if r.vulnerable:
                    findings.append(
                        {
                            "type": "deserialization",
                            "url": r.url,
                            "param": r.param,
                            "format": r.format_type,
                            "payload": r.payload,
                            "evidence": r.evidence,
                            "severity": r.severity,
                        }
                    )

            return ToolResult(
                success=True,
                tool_name=self.metadata.name,
                category=self.metadata.category,
                output=f"Deserialization scan completed: {len(findings)} findings",
                findings=findings,
                execution_time=time.time() - start_time,
            )
        except Exception as e:
            return ToolResult(
                success=False,
                tool_name=self.metadata.name,
                category=self.metadata.category,
                error_message=str(e),
                execution_time=time.time() - start_time,
            )


@register_tool(
    ToolMetadata(
        name="graphql_scanner",
        category=ToolCategory.API,
        priority=ToolPriority.HIGH,
        binary_name="python3",
        description="GraphQL API vulnerability scanner",
        timeout_seconds=300,
    )
)
class GraphQLScannerTool(BaseTool):
    """Wrapper for the GraphQLScanner module."""

    def _check_binary(self) -> bool:
        return True

    async def execute(
        self,
        target: Union[str, List[str]],
        report_dir: Path,
        semaphore: asyncio.Semaphore,
        **kwargs,
    ) -> ToolResult:
        import time

        start_time = time.time()
        base_url = target if isinstance(target, str) else target[0]

        try:
            from tools.graphql_scanner import GraphQLScanner

            scanner = GraphQLScanner()
            result = scanner.scan(base_url)

            findings = []
            for r in result.results:
                if r.vulnerable:
                    findings.append(
                        {
                            "type": "graphql",
                            "url": r.url,
                            "test_type": r.test_type,
                            "evidence": r.evidence,
                            "schema_info": r.schema_info,
                            "severity": r.severity,
                        }
                    )

            return ToolResult(
                success=True,
                tool_name=self.metadata.name,
                category=self.metadata.category,
                output=f"GraphQL scan completed: {len(findings)} findings",
                findings=findings,
                execution_time=time.time() - start_time,
            )
        except Exception as e:
            return ToolResult(
                success=False,
                tool_name=self.metadata.name,
                category=self.metadata.category,
                error_message=str(e),
                execution_time=time.time() - start_time,
            )


@register_tool(
    ToolMetadata(
        name="race_condition_tester",
        category=ToolCategory.SCANNER,
        priority=ToolPriority.HIGH,
        binary_name="python3",
        description="Race condition vulnerability tester",
        timeout_seconds=300,
    )
)
class RaceConditionTesterTool(BaseTool):
    """Wrapper for the RaceConditionTester module."""

    def _check_binary(self) -> bool:
        return True

    async def execute(
        self,
        target: Union[str, List[str]],
        report_dir: Path,
        semaphore: asyncio.Semaphore,
        **kwargs,
    ) -> ToolResult:
        import time

        start_time = time.time()
        base_url = target if isinstance(target, str) else target[0]

        try:
            from tools.race_condition_tester import RaceConditionTester

            tester = RaceConditionTester()
            result = tester.test_endpoint(base_url)

            findings = []
            for r in result.results:
                if r.vulnerable:
                    findings.append(
                        {
                            "type": "race_condition",
                            "test_type": r.test_type,
                            "endpoint": r.endpoint,
                            "evidence": r.evidence,
                            "severity": r.severity,
                        }
                    )

            return ToolResult(
                success=True,
                tool_name=self.metadata.name,
                category=self.metadata.category,
                output=f"Race condition test completed: {len(findings)} findings",
                findings=findings,
                execution_time=time.time() - start_time,
            )
        except Exception as e:
            return ToolResult(
                success=False,
                tool_name=self.metadata.name,
                category=self.metadata.category,
                error_message=str(e),
                execution_time=time.time() - start_time,
            )


@register_tool(
    ToolMetadata(
        name="api_schema_diff",
        category=ToolCategory.API,
        priority=ToolPriority.MEDIUM,
        binary_name="python3",
        description="API schema comparison and drift detection",
        timeout_seconds=120,
    )
)
class APISchemaDiffTool(BaseTool):
    """Wrapper for the APISchemaDiffer module."""

    def _check_binary(self) -> bool:
        return True

    async def execute(
        self,
        target: Union[str, List[str]],
        report_dir: Path,
        semaphore: asyncio.Semaphore,
        **kwargs,
    ) -> ToolResult:
        import time

        start_time = time.time()
        base_url = target if isinstance(target, str) else target[0]

        try:
            from tools.api_schema_diff import APISchemaDiffer

            differ = APISchemaDiffer()

            # Try to fetch schema from common endpoints
            schema_url = f"{base_url.rstrip('/')}/openapi.json"
            result = differ.compare_urls(
                url1=schema_url,
                url2=schema_url,  # Self-comparison for demo
            )

            findings = []
            for ep in result.added_endpoints:
                findings.append(
                    {
                        "type": "schema_added",
                        "path": ep.path,
                        "method": ep.method,
                        "details": ep.details,
                        "severity": "Informational",
                    }
                )
            for ep in result.removed_endpoints:
                findings.append(
                    {
                        "type": "schema_removed",
                        "path": ep.path,
                        "method": ep.method,
                        "details": ep.details,
                        "severity": "Medium",
                    }
                )

            return ToolResult(
                success=True,
                tool_name=self.metadata.name,
                category=self.metadata.category,
                output=f"Schema diff completed: {result.total_changes} changes",
                findings=findings,
                execution_time=time.time() - start_time,
            )
        except Exception as e:
            return ToolResult(
                success=False,
                tool_name=self.metadata.name,
                category=self.metadata.category,
                error_message=str(e),
                execution_time=time.time() - start_time,
            )


@register_tool(
    ToolMetadata(
        name="supply_chain_analyzer",
        category=ToolCategory.SCANNER,
        priority=ToolPriority.MEDIUM,
        binary_name="python3",
        description="Software supply chain vulnerability analyzer",
        timeout_seconds=120,
    )
)
class SupplyChainAnalyzerTool(BaseTool):
    """Wrapper for the SupplyChainAnalyzer module."""

    def _check_binary(self) -> bool:
        return True

    async def execute(
        self,
        target: Union[str, List[str]],
        report_dir: Path,
        semaphore: asyncio.Semaphore,
        **kwargs,
    ) -> ToolResult:
        import time

        start_time = time.time()
        base_path = target if isinstance(target, str) else target[0]

        try:
            from tools.supply_chain_analyzer import SupplyChainAnalyzer

            analyzer = SupplyChainAnalyzer()
            result = analyzer.analyze_directory(base_path)

            findings = []
            for pkg in result.suspicious_packages:
                findings.append(
                    {
                        "type": "suspicious_package",
                        "package": pkg,
                        "severity": "High",
                    }
                )
            for src, dest in result.typosquatting_detected:
                findings.append(
                    {
                        "type": "typosquatting",
                        "package": src,
                        "similar_to": dest,
                        "severity": "High",
                    }
                )
            for pkg in result.unpinned_versions[:10]:  # Limit to first 10
                findings.append(
                    {
                        "type": "unpinned_version",
                        "package": pkg,
                        "severity": "Low",
                    }
                )

            return ToolResult(
                success=True,
                tool_name=self.metadata.name,
                category=self.metadata.category,
                output=f"Supply chain analysis completed: {result.total_dependencies} dependencies",
                findings=findings,
                execution_time=time.time() - start_time,
            )
        except Exception as e:
            return ToolResult(
                success=False,
                tool_name=self.metadata.name,
                category=self.metadata.category,
                error_message=str(e),
                execution_time=time.time() - start_time,
            )


@register_tool(
    ToolMetadata(
        name="logic_flaw_engine",
        category=ToolCategory.SCANNER,
        priority=ToolPriority.HIGH,
        binary_name="python3",
        description="Business logic vulnerability analyzer",
        timeout_seconds=300,
    )
)
class LogicFlawEngineTool(BaseTool):
    """Wrapper for the LogicFlawEngine module."""

    def _check_binary(self) -> bool:
        return True

    async def execute(
        self,
        target: Union[str, List[str]],
        report_dir: Path,
        semaphore: asyncio.Semaphore,
        **kwargs,
    ) -> ToolResult:
        import time

        start_time = time.time()
        base_url = target if isinstance(target, str) else target[0]

        try:
            from tools.logic_flaw_engine import LogicFlawEngine

            engine = LogicFlawEngine()
            result = engine.analyze_endpoint(base_url)

            findings = []
            for flaw in result.flaws:
                findings.append(
                    {
                        "type": "logic_flaw",
                        "flaw_type": flaw.flaw_type,
                        "endpoint": flaw.endpoint,
                        "description": flaw.description,
                        "evidence": flaw.evidence,
                        "severity": flaw.severity,
                        "remediation": flaw.remediation,
                    }
                )

            return ToolResult(
                success=True,
                tool_name=self.metadata.name,
                category=self.metadata.category,
                output=f"Logic flaw analysis completed: {len(result.flaws)} flaws found",
                findings=findings,
                execution_time=time.time() - start_time,
            )
        except Exception as e:
            return ToolResult(
                success=False,
                tool_name=self.metadata.name,
                category=self.metadata.category,
                error_message=str(e),
                execution_time=time.time() - start_time,
            )


@register_tool(
    ToolMetadata(
        name="cors_checker",
        category=ToolCategory.SCANNER,
        priority=ToolPriority.MEDIUM,
        binary_name="python3",
        description="CORS misconfiguration tester",
        timeout_seconds=120,
    )
)
class CORSCheckerTool(BaseTool):
    """Wrapper for the CORSChecker module."""

    def _check_binary(self) -> bool:
        return True

    async def execute(
        self,
        target: Union[str, List[str]],
        report_dir: Path,
        semaphore: asyncio.Semaphore,
        **kwargs,
    ) -> ToolResult:
        import time

        start_time = time.time()
        base_url = target if isinstance(target, str) else target[0]

        try:
            from tools.cors_checker import CORSChecker

            checker = CORSChecker()
            result = checker.check(base_url)

            findings = []
            for r in result.results:
                if r.vulnerable:
                    findings.append(
                        {
                            "type": "cors_misconfiguration",
                            "test_type": r.test_type,
                            "origin": r.origin,
                            "evidence": r.evidence,
                            "severity": r.severity,
                        }
                    )

            return ToolResult(
                success=True,
                tool_name=self.metadata.name,
                category=self.metadata.category,
                output=f"CORS check completed: {len(findings)} findings",
                findings=findings,
                execution_time=time.time() - start_time,
            )
        except Exception as e:
            return ToolResult(
                success=False,
                tool_name=self.metadata.name,
                category=self.metadata.category,
                error_message=str(e),
                execution_time=time.time() - start_time,
            )


@register_tool(
    ToolMetadata(
        name="jwt_tester",
        category=ToolCategory.SCANNER,
        priority=ToolPriority.HIGH,
        binary_name="python3",
        description="JWT security vulnerability tester",
        timeout_seconds=300,
    )
)
class JWTTesterTool(BaseTool):
    """Wrapper for the JWTTester module."""

    def _check_binary(self) -> bool:
        return True

    async def execute(
        self,
        target: Union[str, List[str]],
        report_dir: Path,
        semaphore: asyncio.Semaphore,
        **kwargs,
    ) -> ToolResult:
        import time

        start_time = time.time()
        base_url = target if isinstance(target, str) else target[0]

        try:
            from tools.jwt_tester import JWTScanResult, JWTTester

            tester = JWTTester()

            # Try to get token from kwargs
            token = kwargs.get("token", "")
            if token:
                result = tester.analyze_token(token)
            else:
                result = JWTScanResult(target=base_url)

            findings = []
            for r in result.results:
                if r.vulnerable:
                    findings.append(
                        {
                            "type": "jwt_vulnerability",
                            "test_type": r.test_type,
                            "evidence": r.evidence,
                            "severity": r.severity,
                        }
                    )

            return ToolResult(
                success=True,
                tool_name=self.metadata.name,
                category=self.metadata.category,
                output=f"JWT analysis completed: {len(findings)} findings",
                findings=findings,
                execution_time=time.time() - start_time,
            )
        except Exception as e:
            return ToolResult(
                success=False,
                tool_name=self.metadata.name,
                category=self.metadata.category,
                error_message=str(e),
                execution_time=time.time() - start_time,
            )


# ═══════════════════════════════════════════════════════════════════════════════
# AUTO-DISCOVERY
# ═══════════════════════════════════════════════════════════════════════════════


def auto_discover_tools() -> List[str]:
    """Auto-discover and import all tool modules in tools/ directory.

    Scans every *.py file (except tool_registry.py and __pycache__) and
    attempts to import it.  Modules that use the ``@register_tool``
    decorator will self-register on import.
    """
    tools_dir = Path(__file__).parent
    discovered = []
    skip = {"tool_registry", "__init__", "__pycache__"}

    for file in sorted(tools_dir.glob("*.py")):
        stem = file.stem
        if stem in skip or file.is_dir():
            continue

        module_name = f"tools.{stem}"
        try:
            __import__(module_name)
            discovered.append(module_name)
        except Exception as e:
            logger.debug(f"Skipped {stem}: {e}")

    return discovered


# Run auto-discovery on module load
discoveries = auto_discover_tools()


if __name__ == "__main__":
    # Test the registry
    print("[+] Tool Registry Test")
    print(f"    Registered tools: {list(registry.list_available_tools().keys())}")
    print(f"    Auto-discovered: {discoveries}")
