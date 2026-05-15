"""scan_engine_upgrade.py — Upgraded Scan Engine with Parallel Execution, State Persistence, and Finding Correlation.

Integrates with `file_relationship_mapper` to run intelligent scans based on
code relationships, cache state across runs, and correlate findings.
"""
from __future__ import annotations

import asyncio
import json
import threading
import time as time_module
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Set, Optional, Tuple, Any
from collections import defaultdict
import hashlib
import pickle
import logging

from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from file_relationship_mapper import (
    FileRelationshipGraph,
    get_scan_recommendations,
)
from tools.tool_registry import registry, ToolResult

console = Console()
logger = logging.getLogger("scan_engine_upgrade")

# ── Shared Persistent Event Loop ──────────────────────────
_SHARED_LOOP: Optional[asyncio.AbstractEventLoop] = None
_SHARED_LOOP_LOCK: threading.Lock = threading.Lock()
_SHARED_LOOP_THREAD: Optional[threading.Thread] = None


def _get_shared_loop() -> asyncio.AbstractEventLoop:
    """Get or create the module-level persistent event loop."""
    global _SHARED_LOOP, _SHARED_LOOP_THREAD
    with _SHARED_LOOP_LOCK:
        if _SHARED_LOOP is None:
            _SHARED_LOOP = asyncio.new_event_loop()

            def _run_forever(loop: asyncio.AbstractEventLoop) -> None:
                asyncio.set_event_loop(loop)
                loop.run_forever()

            _SHARED_LOOP_THREAD = threading.Thread(
                target=_run_forever,
                args=(_SHARED_LOOP,),
                daemon=True,
                name="scan-engine-event-loop",
            )
            _SHARED_LOOP_THREAD.start()
        return _SHARED_LOOP

# ── Constants ────────────────────────────────────────────────
STATE_DIR = Path("data/scan_state")
STATE_DIR.mkdir(parents=True, exist_ok=True)


@dataclass
class ScanState:
    """Persistent scan state across runs.
    
    Attributes:
        target: The scanned target
        scan_id: Unique identifier for this scan session
        start_time: When the scan started
        end_time: When it finished (None if in progress)
        completed_tools: Set of tool names that already ran
        pending_tools: Set of tool names queued to run
        failed_tools: Set of tool names that failed
        results: Mapping of tool_name -> ToolResult
        findings: Flat list of all findings from all tools
        metadata: Additional scan metadata (config, args, etc.)
    """
    target: str
    scan_id: str = ""
    start_time: float = 0.0
    end_time: Optional[float] = None
    completed_tools: Set[str] = field(default_factory=set)
    pending_tools: Set[str] = field(default_factory=set)
    failed_tools: Set[str] = field(default_factory=set)
    results: Dict[str, ToolResult] = field(default_factory=dict)
    findings: List[Dict[str, Any]] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        if not self.scan_id:
            self.scan_id = hashlib.md5(
                f"{self.target}:{time_module.time()}".encode()
            ).hexdigest()[:12]
        if not self.start_time:
            self.start_time = time_module.time()
    
    def mark_complete(self, tool_name: str, result: ToolResult) -> None:
        self.completed_tools.add(tool_name)
        self.pending_tools.discard(tool_name)
        self.results[tool_name] = result
        if result.findings:
            self.findings.extend(result.findings)
        if not result.success:
            self.failed_tools.add(tool_name)
    
    def is_complete(self) -> bool:
        return len(self.pending_tools) == 0
    
    @property
    def duration(self) -> float:
        end = self.end_time or time_module.time()
        return end - self.start_time
    
    def to_dict(self) -> dict:
        """Serialize state to a plain dict (for JSON)."""
        d = asdict(self)
        # Convert ToolResult to dict for JSON-ability
        d["results"] = {
            name: {
                "success": r.success,
                "tool_name": r.tool_name,
                "findings": r.findings,
                "error_message": r.error_message,
                "raw_output": r.raw_output if isinstance(r.raw_output, (str, bytes)) else str(r.raw_output),
            }
            for name, r in self.results.items()
        }
        return d
    
    def save(self) -> None:
        """Save state to disk."""
        state_file = STATE_DIR / f"{self.scan_id}.json"
        with open(state_file, "w") as f:
            json.dump(self.to_dict(), f, indent=2, default=str)
        logger.debug(f"[ScanState] Saved to {state_file}")
    
    @classmethod
    def load(cls, scan_id: str) -> Optional["ScanState"]:
        """Load state from disk."""
        state_file = STATE_DIR / f"{scan_id}.json"
        if not state_file.exists():
            return None
        with open(state_file, "r") as f:
            data = json.load(f)
        # Reconstruct basic state (results lost, but re-runnable)
        return cls(
            target=data["target"],
            scan_id=data["scan_id"],
            start_time=data.get("start_time", 0),
            end_time=data.get("end_time"),
            completed_tools=set(data.get("completed_tools", [])),
            pending_tools=set(data.get("pending_tools", [])),
            failed_tools=set(data.get("failed_tools", [])),
            findings=data.get("findings", []),
            metadata=data.get("metadata", {}),
        )


class ParallelRunner:
    """Manages parallel execution of scan tools with dependency awareness.
    
    Uses the FileRelationshipGraph to determine which tools can run in
    parallel and which must wait for others to complete.
    """
    
    def __init__(self, max_concurrency: int = 5):
        self.max_concurrency = max_concurrency
        self.semaphore = asyncio.Semaphore(max_concurrency)
        
    async def run_tool(self, tool_name: str, target: str, report_dir: Path) -> ToolResult:
        """Run a single tool with semaphore control."""
        async with self.semaphore:
            tool = registry.get_tool(tool_name)
            if not tool or not tool.is_available:
                return ToolResult(
                    success=False,
                    tool_name=tool_name,
                    error_message="Tool not available"
                )
            return await tool.execute(target, report_dir)
    
    async def run_in_parallel(
        self,
        tools: List[str],
        target: str,
        report_dir: Path,
        state: ScanState
    ) -> List[ToolResult]:
        """Run multiple tools in parallel with dependency awareness.
        
        Args:
            tools: List of tool names to run
            target: Scan target
            report_dir: Where to save reports
            state: ScanState for tracking
        """
        results = []
        tasks = {}
        
        for tool_name in tools:
            if tool_name in state.completed_tools:
                logger.debug(f"[ParallelRunner] Skipping already-completed {tool_name}")
                continue
            
            state.pending_tools.add(tool_name)
            
            async def task_for_tool(tn=tool_name):
                result = await self.run_tool(tn, target, report_dir)
                state.mark_complete(tn, result)
                state.save()
                return result
            
            tasks[tool_name] = asyncio.create_task(task_for_tool())
        
        if tasks:
            done, pending = await asyncio.wait(
                tasks.values(),
                return_when=asyncio.ALL_COMPLETED
            )
            
            for task in done:
                try:
                    result = task.result()
                    results.append(result)
                except Exception as e:
                    logger.error(f"[ParallelRunner] Tool execution failed: {e}")
                    # Create a failure result
                    results.append(ToolResult(
                        success=False,
                        tool_name="unknown",
                        error_message=str(e)
                    ))
        
        return results


class FindingCorrelator:
    """Correlates findings from multiple tools to identify related issues.
    
    Example: If subfinder finds a subdomain and nuclei finds a vulnerability
    on that subdomain, these findings are correlated.
    """
    
    def __init__(self, findings: List[Dict[str, Any]]):
        self.findings = findings
        self.clusters: List[List[Dict[str, Any]]] = []
        self._build_clusters()
    
    def _normalize_url(self, url: str) -> str:
        """Normalize a URL for comparison."""
        from urllib.parse import urlparse
        try:
            parsed = urlparse(url)
            return f"{parsed.netloc}{parsed.path}".lower().rstrip("/")
        except Exception:
            return url.lower()
    
    def _findings_similar(self, a: Dict[str, Any], b: Dict[str, Any]) -> bool:
        """Check if two findings are likely related."""
        # Same URL/domain
        url_a = self._normalize_url(a.get("url", ""))
        url_b = self._normalize_url(b.get("url", ""))
        if url_a and url_b and url_a == url_b:
            return True
        
        # Same target
        if a.get("target") and b.get("target") and a["target"] == b["target"]:
            return True
        
        # Similar path/pattern
        path_a = a.get("path", "")
        path_b = b.get("path", "")
        if path_a and path_b and path_a == path_b:
            return True
        
        return False
    
    def _build_clusters(self) -> None:
        """Group related findings into clusters."""
        unclustered = self.findings.copy()
        
        while unclustered:
            # Start a new cluster with the first finding
            current = unclustered.pop(0)
            cluster = [current]
            
            # Find all related findings
            to_remove = []
            for i, finding in enumerate(unclustered):
                if self._findings_similar(current, finding):
                    cluster.append(finding)
                    to_remove.append(i)
            
            # Remove clustered findings from unclustered list
            for i in sorted(to_remove, reverse=True):
                unclustered.pop(i)
            
            self.clusters.append(cluster)
    
    def get_clustered_report(self) -> List[Dict[str, Any]]:
        """Get a report of correlated findings.
        
        Returns list of clusters, each with:
        - id: Cluster ID
        - primary_target: Main target/URL
        - findings: List of findings in cluster
        - tool_count: Number of unique tools
        - severity_score: Combined severity
        """
        report = []
        for idx, cluster in enumerate(self.clusters):
            if not cluster:
                continue
            
            primary = cluster[0]
            tools = set(f.get("tool", "unknown") for f in cluster)
            
            # Calculate combined severity
            severity_scores = {
                "Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Informational": 0
            }
            severities = [f.get("severity", "Info").capitalize() for f in cluster]
            max_score = max(
                (severity_scores.get(s, 0) for s in severities),
                default=0
            )
            severity_label = {
                4: "Critical", 3: "High", 2: "Medium", 1: "Low", 0: "Informational"
            }.get(max_score, "Info")
            
            report.append({
                "id": idx + 1,
                "primary_target": primary.get("url", primary.get("target", "unknown")),
                "findings": cluster,
                "tool_count": len(tools),
                "severity": severity_label,
                "severity_score": max_score,
            })
        
        # Sort by severity score descending
        report.sort(key=lambda x: x["severity_score"], reverse=True)
        return report
    
    def print_correlation_table(self) -> None:
        """Print a rich table of correlated findings."""
        clusters = self.get_clustered_report()
        
        if not clusters:
            console.print("[dim]No correlated findings to display[/dim]")
            return
        
        console.print("\n[bold #cc4444]Correlated Findings[/bold #cc4444]\n")
        
        for cluster in clusters[:10]:  # Show top 10
            color_map = {
                "Critical": "#cc4444",
                "High": "#ff6b6b",
                "Medium": "#888888",
                "Low": "#666666",
                "Informational": "#444444",
            }
            color = color_map.get(cluster["severity"], "#888888")
            
            console.print(
                f"[{color}]Cluster #{cluster['id']}[/] | "
                f"[{color}]{cluster['severity']}[/] | "
                f"[{color}]{cluster['tool_count']} tools[/] | "
                f"[{color}]{cluster['primary_target']}[/]"
            )
            
            for f in cluster["findings"][:5]:  # Show up to 5 per cluster
                tool = f.get("tool", "?")
                type_ = f.get("type", "?")
                console.print(f"  [dim]• {tool}: {type_}[/]")
            
            if len(cluster["findings"]) > 5:
                console.print(f"  [dim]... and {len(cluster['findings']) - 5} more[/]\n")


class SmartOrchestrator:
    """Intelligent orchestrator that combines FileRelationshipGraph with
    parallel scanning and finding correlation.
    """
    
    def __init__(self, max_concurrency: int = 5):
        self.max_concurrency = max_concurrency
        self.parallel_runner = ParallelRunner(max_concurrency)
        self.file_graph: Optional[FileRelationshipGraph] = None
        self.state: Optional[ScanState] = None
    
    def build_file_graph(self, project_root: Path = None) -> FileRelationshipGraph:
        """Build the file relationship graph."""
        self.file_graph = FileRelationshipGraph(project_root).build()
        return self.file_graph
    
    async def run_smart_scan(
        self,
        target: str,
        report_dir: Path,
        tools: List[str] = None,
        rate_limit: int = 5,
        correlate: bool = True,
        use_smart_chain: bool = True
    ) -> Tuple[ScanState, Optional[FindingCorrelator]]:
        """Run an intelligent scan with full orchestration.
        
        Args:
            target: Target domain/IP
            report_dir: Where to save reports
            tools: Specific tools to run (or None for auto-selection)
            rate_limit: Max concurrent tools
            correlate: Whether to correlate findings
            use_smart_chain: Whether to use file relationship for tool selection
        
        Returns:
            (ScanState, FindingCorrelator or None)
        """
        # Determine which tools to run
        if use_smart_chain and self.file_graph:
            # Use file relationships to recommend tools
            changed_files = self._get_changed_files()
            recommended = get_scan_recommendations(self.file_graph, changed_files)
            if recommended:
                tools = recommended
                logger.info(f"[SmartOrchestrator] Using smart tool chain: {tools}")
        
        if not tools:
            # Fall back to registry recommendations
            tools = [t.metadata.name for t in registry.get_recommended_chain("web")]
        
        # Initialize scan state
        self.state = ScanState(target=target)
        self.state.pending_tools = set(tools)
        self.state.save()
        
        console.print(
            f"[red][RUN] Smart scan: {target} with {len(tools)} tools "
            f"(concurrency={rate_limit})[/red]"
        )
        
        # Run tools in parallel
        results = await self.parallel_runner.run_in_parallel(
            tools, target, report_dir, self.state
        )
        
        # Mark scan complete
        self.state.end_time = time_module.time()
        self.state.save()
        
        # Calculate CVSS scores
        # (Reuse logic from orchestrator.py)
        from tools.cvss_calculator import CVSSCalculator
        calculator = CVSSCalculator(use_ai=False)
        
        for result in results:
            for finding in result.findings:
                calculator.calculate_from_tool_result(
                    result.tool_name, finding, target
                )
        
        # Correlate findings if requested
        correlator = None
        if correlate and self.state.findings:
            correlator = FindingCorrelator(self.state.findings)
            clustered = correlator.get_clustered_report()
            
            console.print(
                f"\n[bold green][OK] Scan complete in {self.state.duration:.1f}s[/bold green]"
            )
            console.print(
                f"[dim]{len(results)} tools, "
                f"{len(self.state.findings)} findings, "
                f"{len(clustered)} clusters[/dim]"
            )
            
            # Print correlation table
            correlator.print_correlation_table()
        
        return self.state, correlator
    
    def _get_changed_files(self) -> List[str]:
        """Detect recently changed files via git diff or mtime comparison.

        Priority:
        1. ``git diff --name-only HEAD`` (cleanest, works in any repo)
        2. ``git status --porcelain`` (covers untracked files)
        3. mtime-based fallback (last 24 h) when not in a git repo
        """
        import subprocess
        import time as time_mod

        try:
            # Strategy 1: git diff against HEAD
            result = subprocess.run(
                ["git", "diff", "--name-only", "HEAD"],
                capture_output=True, text=True,
                timeout=10,
            )
            if result.returncode == 0:
                tracked = [f.strip() for f in result.stdout.split("\n") if f.strip()]
            else:
                tracked = []

            # Strategy 2: untracked / modified files
            result2 = subprocess.run(
                ["git", "status", "--porcelain"],
                capture_output=True, text=True,
                timeout=10,
            )
            if result2.returncode == 0:
                untracked = []
                for line in result2.stdout.split("\n"):
                    line = line.strip()
                    if not line:
                        continue
                    # porcelain format: XY filename
                    status = line[:2].strip()
                    filename = line[2:].strip()
                    if status in ("M", "A", "?", "MM", "AM"):
                        untracked.append(filename)
            else:
                untracked = []

            changed = list(set(tracked + untracked))
            if changed:
                logger.info(f"[SmartOrchestrator] {len(changed)} changed files detected via git")
                return changed

        except Exception as e:
            logger.debug(f"git diff failed, falling back to mtime: {e}")

        # Strategy 3: mtime fallback — files modified in the last 24 h
        try:
            now = time_mod.time()
            day_ago = now - 86400
            from pathlib import Path as _Path
            repo_root = _Path(__file__).parent.parent
            changed = [
                str(f.relative_to(repo_root))
                for f in repo_root.rglob("*")
                if f.is_file()
                and f.suffix in {".py", ".md", ".yaml", ".yml", ".json", ".txt", ".toml"}
                and f.stat().st_mtime > day_ago
                and ".git" not in str(f)
            ]
            if changed:
                logger.info(f"[SmartOrchestrator] {len(changed)} recently modified files (mtime)")
            return changed
        except Exception as e:
            logger.debug(f"mtime fallback failed: {e}")

        return []


def run_smart_scan_sync(
    target: str,
    report_dir: Path,
    tools: List[str] = None,
    rate_limit: int = 5,
    correlate: bool = True
) -> Tuple[ScanState, Optional[FindingCorrelator]]:
    """Synchronous wrapper for SmartOrchestrator.run_smart_scan().

    Uses the module-level shared persistent event loop.
    """
    orchestrator = SmartOrchestrator(max_concurrency=rate_limit)

    async def _run():
        return await orchestrator.run_smart_scan(
            target, report_dir, tools, rate_limit, correlate,
        )

    loop = _get_shared_loop()
    future = asyncio.run_coroutine_threadsafe(_run(), loop)
    return future.result(timeout=600)


if __name__ == "__main__":
    import sys
    print("This module is not meant to be run directly.")
    print("Import SmartOrchestrator or run_smart_scan_sync() instead.")
    print("Example:")
    print("    from scan_engine_upgrade import SmartOrchestrator")
    print("    async def main():")
    print("        orchestrator = SmartOrchestrator()")
    print("        _, correlator = await orchestrator.run_smart_scan('example.com', Path('reports'))")
