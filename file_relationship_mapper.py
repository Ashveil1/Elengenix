"""
file_relationship_mapper.py — Dependency & Coupling Analysis Engine
- AST-based import extraction
- Graph generation for file relationships
- Circular dependency detection
- Interface with scan engine for intelligent tool selection
"""
from __future__ import annotations

import os
from pathlib import Path
from dataclasses import dataclass, field
from typing import Dict, List, Set, Tuple, Optional, Iterator
from collections import defaultdict, deque

try:
    import networkx as nx
    NETWORKX_AVAILABLE = True
except ImportError:
    NETWORKX_AVAILABLE = False
    nx = None

from rich.console import Console
from rich.table import Table
from rich.tree import Tree

console = Console()


@dataclass
class FileNode:
    """Represents a Python module in the dependency graph."""
    path: Path
    imports: Set[str] = field(default_factory=set)
    imported_by: Set[str] = field(default_factory=set)
    category: str = "module"  # module, config, tool, core, entrypoint
    complexity: int = 0
    lines_of_code: int = 0
    
    @property
    def name(self) -> str:
        return self.path.stem
    
    @property
    def is_entrypoint(self) -> bool:
        return self.category == "entrypoint"
    
    @property
    def is_tool(self) -> bool:
        return self.category == "tool"


class FileRelationshipGraph:
    """Graph of file relationships in the project.
    
    Provides:
    - Import/dependency tracking
    - Centrality scoring (which files are most critical)
    - Circular dependency detection
    - Tool recommendation based on relationships
    """
    
    def __init__(self, project_root: Path = None):
        self.project_root = project_root or Path.cwd()
        self.nodes: Dict[str, FileNode] = {}
        self._edges: List[Tuple[str, str]] = []
        self._graph = nx.DiGraph() if NETWORKX_AVAILABLE else None
        self._affected_by_scan_cache: Dict[str, List[str]] = {}
        
    def _discover_files(self, include_tests: bool = False) -> List[Path]:
        """Discover all Python files in the project."""
        files = []
        extensions = ["*.py"]
        for ext in extensions:
            for file_path in self.project_root.rglob(ext):
                if "venv" in str(file_path) or "__pycache__" in str(file_path):
                    continue
                if not include_tests and str(file_path).startswith(str(self.project_root / "tests")):
                    continue
                files.append(file_path)
        return sorted(files)
    
    def _categorize(self, path: Path) -> str:
        """Categorize a file based on its path."""
        rel = str(path.relative_to(self.project_root))
        if rel.startswith("tools/"):
            return "tool"
        elif rel.startswith("tests/"):
            return "test"
        elif rel == "main.py" or rel == "cli.py":
            return "entrypoint"
        elif rel.startswith("config") or rel.startswith("data/"):
            return "config"
        else:
            return "core"
    
    def _extract_imports(self, file_path: Path) -> Set[str]:
        """Extract top-level imports from a Python file using simple parser."""
        imports = set()
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("import ") or line.startswith("from "):
                        # Simple parsing: "from x import y" or "import x"
                        parts = line.split()
                        if len(parts) >= 2:
                            if parts[0] == "from":
                                imports.add(parts[1])
                            elif parts[0] == "import":
                                imports.add(parts[1])
        except (OSError, UnicodeDecodeError):
            pass
        return imports
    
    def build(self, include_tests: bool = False) -> "FileRelationshipGraph":
        """Build the graph from project files."""
        files = self._discover_files(include_tests=include_tests)
        
        for file_path in files:
            if file_path.name == "__init__.py":
                continue
            node = FileNode(
                path=file_path,
                category=self._categorize(file_path),
                lines_of_code=len(open(file_path, "rb").read().split(b"\n"))
            )
            self.nodes[node.name] = node
        
        # Build edges based on imports
        for name, node in self.nodes.items():
            imports = self._extract_imports(node.path)
            for imp in imports:
                # Match import to a module in our project
                if imp in self.nodes:
                    self._edges.append((name, imp))
                    node.imports.add(imp)
                    self.nodes[imp].imported_by.add(name)
        
        # Build networkx graph if available
        if NETWORKX_AVAILABLE and self._graph is not None:
            for name in self.nodes:
                self._graph.add_node(name)
            for src, dst in self._edges:
                self._graph.add_edge(src, dst)
        
        # Cache "affected by scan" relationships (which tools depend on which core files)
        self._build_scan_cache()
        
        return self
    
    def _build_scan_cache(self) -> None:
        """Cache which tools are affected when a core file changes."""
        for name, node in self.nodes.items():
            if node.category == "tool":
                # Find all core files this tool depends on
                core_deps = set()
                visited = set()
                queue = deque([name])
                visited.add(name)
                
                while queue:
                    current = queue.popleft()
                    if current in self.nodes:
                        for imp in self.nodes[current].imports:
                            if imp not in visited:
                                if self.nodes.get(imp, FileNode(Path(""))).category == "core":
                                    core_deps.add(imp)
                                visited.add(imp)
                                queue.append(imp)
                
                for dep in core_deps:
                    if dep not in self._affected_by_scan_cache:
                        self._affected_by_scan_cache[dep] = []
                    self._affected_by_scan_cache[dep].append(name)
    
    def get_tools_affected_by_core_file(self, core_file: str) -> List[str]:
        """Get list of tools that depend on a given core file.
        
        Used for: when a core file changes, know which tools to re-scan.
        """
        return self._affected_by_scan_cache.get(core_file, [])
    
    def detect_cycles(self) -> List[List[str]]:
        """Detect circular dependencies in the project.
        
        Returns:
            List of cycles, each cycle is a list of file names.
        """
        cycles = []
        if NETWORKX_AVAILABLE and self._graph is not None:
            import networkx as nx_lib
            for cycle in nx_lib.simple_cycles(self._graph):
                cycles.append(cycle)
        else:
            # Manual DFS-based cycle detection
            visited = set()
            current_path = []
            in_current_path = set()
            
            def dfs(node):
                if node in in_current_path:
                    # Found cycle
                    cycle_start = current_path.index(node)
                    cycles.append(current_path[cycle_start:] + [node])
                    return
                if node in visited:
                    return
                
                visited.add(node)
                current_path.append(node)
                in_current_path.add(node)
                
                for neighbor in self.nodes.get(node, FileNode(Path(""))).imports:
                    if neighbor in self.nodes:
                        dfs(neighbor)
                
                current_path.pop()
                in_current_path.discard(node)
            
            for name in self.nodes:
                if name not in visited:
                    dfs(name)
        
        return cycles
    
    def get_centrality_scores(self) -> Dict[str, float]:
        """Get centrality scores for each file.
        
        Higher scores mean the file is more central/important.
        """
        if NETWORKX_AVAILABLE and self._graph is not None:
            return nx.degree_centrality(self._graph) if NETWORKX_AVAILABLE else {}
        else:
            # Manual centrality calculation
            scores = {}
            for node in self.nodes.values():
                in_degree = len(node.imported_by)
                out_degree = len(node.imports)
                # Weighted by being imported (more = more important)
                scores[node.name] = in_degree * 2 + out_degree * 1
            return scores
    
    def get_complexity_report(self) -> List[Tuple[str, int, int]]:
        """Get complexity report for all files.
        
        Returns list of (name, line_count, dependent_count)
        where dependent_count is how many other files import this one.
        """
        report = []
        for name, node in self.nodes.items():
            dependents = len(node.imported_by)
            report.append((name, node.lines_of_code, dependents))
        return sorted(report, key=lambda x: x[2], reverse=True)
    
    def print_table(self, show_cycles: bool = True) -> None:
        """Print a rich table of the relationship graph."""
        # Sort by centrality/importance
        scores = self.get_centrality_scores()
        sorted_nodes = sorted(self.nodes.values(), key=lambda n: scores.get(n.name, 0), reverse=True)
        
        console.print("\n[bold #cc4444]Elengenix File Relationship Map[/bold #cc4444]")
        console.print(f"[dim]{len(self.nodes)} files, {len(self._edges)} dependencies[/dim]\n")
        
        table = Table(show_header=True, header_style="bold #cc4444")
        table.add_column("File", style="#e0e0e0", no_wrap=True)
        table.add_column("Type", style="#888888", width=12)
        table.add_column("Imports", style="#666666", justify="right", width=8)
        table.add_column("Imported By", style="#cc4444", justify="right", width=11)
        table.add_column("LOC", style="#888888", justify="right", width=6)
        table.add_column("Centrality", style="#e0e0e0", justify="right", width=10)
        
        for idx, node in enumerate(sorted_nodes[:30]):  # Top 30
            centrality = scores.get(node.name, 0)
            color = "#cc4444" if node.category == "core" else "#888888"
            if node.category in ("entrypoint",):
                color = "#ff6b6b"
            
            table.add_row(
                f"[{color}]{node.name}[/]",
                f"[dim]{node.category}[/]",
                str(len(node.imports)),
                str(len(node.imported_by)),
                str(node.lines_of_code),
                f"{centrality:.2f}"
            )
        
        console.print(table)
        
        # Show cycles
        if show_cycles:
            cycles = self.detect_cycles()
            if cycles:
                console.print("\n[bold #cc4444]Circular Dependencies Detected:[/bold #cc4444]")
                for cycle in cycles[:5]:  # Show first 5
                    console.print(f"  [red]→[/] {' → '.join(cycle)}")
            else:
                console.print("\n[dim][OK] No circular dependencies detected[/dim]")
    
    def to_dict(self) -> dict:
        """Export graph as a dictionary for serialization."""
        return {
            "project_root": str(self.project_root),
            "files": [
                {
                    "name": node.name,
                    "path": str(node.path),
                    "category": node.category,
                    "imports": list(node.imports),
                    "imported_by": list(node.imported_by),
                    "lines_of_code": node.lines_of_code,
                }
                for node in self.nodes.values()
            ],
            "edges": self._edges,
        }
    
    def save(self, output_path: Path = None) -> None:
        """Save the graph as JSON."""
        import json
        output_path = output_path or self.project_root / "data" / "file_relationships.json"
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w") as f:
            json.dump(self.to_dict(), f, indent=2)
        console.print(f"[dim][OK] Relationship map saved to {output_path}[/dim]")


def get_scan_recommendations(graph: FileRelationshipGraph, changed_files: List[str]) -> List[str]:
    """Get tool recommendations based on which files changed.
    
    When a core file changes, re-scan all tools that depend on it.
    """
    affected_tools = set()
    for file in changed_files:
        file_name = Path(file).stem
        for tool in graph.get_tools_affected_by_core_file(file_name):
            affected_tools.add(tool)
    return sorted(affected_tools)


if __name__ == "__main__":
    import time as t
    
    start = t.time()
    graph = FileRelationshipGraph(Path("/home/aponith/Elengenix")).build()
    
    graph.print_table()
    graph.save()
    
    print(f"\nAnalysis completed in {t.time() - start:.2f}s")
