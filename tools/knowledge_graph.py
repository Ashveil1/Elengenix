"""tools/knowledge_graph.py — Knowledge Graph for tracking relationships.

Tracks relationships between assets, findings, tools, and attack paths.
Enables AI to see connections between findings for better chaining decisions.

Public API:
    KnowledgeGraph - Main graph class
    NodeType - Enum for node types
    EdgeType - Enum for edge types
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("elengenix.knowledge_graph")


class NodeType(Enum):
    """Types of nodes in the knowledge graph."""

    ASSET = "asset"
    FINDING = "finding"
    TOOL = "tool"
    VULN_CLASS = "vuln_class"
    ATTACK_PATH = "attack_path"


class EdgeType(Enum):
    """Types of edges in the knowledge graph."""

    HAS = "has"
    FOUND_BY = "found_by"
    BELONGS_TO = "belongs_to"
    CHAINS_TO = "chains_to"
    CONSISTS_OF = "consists_of"
    WORKS_ON = "works_on"
    RELATED_TO = "related_to"


@dataclass
class Node:
    """A node in the knowledge graph."""

    id: str
    node_type: NodeType
    data: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Edge:
    """An edge in the knowledge graph."""

    source: str
    edge_type: EdgeType
    target: str


class KnowledgeGraph:
    """Knowledge Graph for tracking relationships between assets, findings, and tools.

    This graph helps AI understand:
    - Which findings are related to which assets
    - Which tools work for which vulnerability classes
    - How findings can be chained together
    - What attack paths exist

    Example:
        kg = KnowledgeGraph()
        kg.add_asset("example.com", {"type": "domain"})
        kg.add_finding("xss-1", {"type": "XSS", "severity": "MEDIUM"})
        kg.add_edge("example.com", "has", "xss-1")
        related = kg.find_related_findings("xss-1")
    """

    def __init__(self) -> None:
        """Initialize empty knowledge graph."""
        self.nodes: Dict[str, Node] = {}
        self.edges: List[Edge] = []
        self._adjacency: Dict[str, List[Tuple[EdgeType, str]]] = {}

    def add_asset(self, asset_id: str, data: Optional[Dict[str, Any]] = None) -> None:
        """Add an asset node to the graph.

        Args:
            asset_id: Unique identifier for the asset.
            data: Optional metadata dictionary.
        """
        self.nodes[asset_id] = Node(asset_id, NodeType.ASSET, data or {})
        logger.debug(f"Added asset: {asset_id}")

    def add_finding(self, finding_id: str, data: Optional[Dict[str, Any]] = None) -> None:
        """Add a finding node to the graph.

        Args:
            finding_id: Unique identifier for the finding.
            data: Optional metadata dictionary (severity, type, etc.).
        """
        self.nodes[finding_id] = Node(finding_id, NodeType.FINDING, data or {})
        logger.debug(f"Added finding: {finding_id}")

    def add_tool(self, tool_id: str, data: Optional[Dict[str, Any]] = None) -> None:
        """Add a tool node to the graph.

        Args:
            tool_id: Unique identifier for the tool.
            data: Optional metadata dictionary.
        """
        self.nodes[tool_id] = Node(tool_id, NodeType.TOOL, data or {})
        logger.debug(f"Added tool: {tool_id}")

    def add_vuln_class(self, vuln_class_id: str, data: Optional[Dict[str, Any]] = None) -> None:
        """Add a vulnerability class node to the graph.

        Args:
            vuln_class_id: Unique identifier for the vuln class (e.g., "XSS", "SQLi").
            data: Optional metadata dictionary.
        """
        self.nodes[vuln_class_id] = Node(vuln_class_id, NodeType.VULN_CLASS, data or {})

    def add_edge(self, source: str, edge_type: str, target: str) -> None:
        """Add an edge between two nodes.

        Args:
            source: Source node ID.
            edge_type: Type of edge (has, found_by, chains_to, etc.).
            target: Target node ID.
        """
        et = EdgeType(edge_type)
        self.edges.append(Edge(source, et, target))

        if source not in self._adjacency:
            self._adjacency[source] = []
        self._adjacency[source].append((et, target))

        if target not in self._adjacency:
            self._adjacency[target] = []
        self._adjacency[target].append((et, source))

        logger.debug(f"Added edge: {source} --{edge_type}--> {target}")

    def get_asset(self, asset_id: str) -> Optional[Dict[str, Any]]:
        """Get asset data by ID.

        Args:
            asset_id: The asset identifier.

        Returns:
            Asset data dictionary or None if not found.
        """
        node = self.nodes.get(asset_id)
        return node.data if node and node.node_type == NodeType.ASSET else None

    def get_finding(self, finding_id: str) -> Optional[Dict[str, Any]]:
        """Get finding data by ID.

        Args:
            finding_id: The finding identifier.

        Returns:
            Finding data dictionary or None if not found.
        """
        node = self.nodes.get(finding_id)
        return node.data if node and node.node_type == NodeType.FINDING else None

    def find_related_findings(self, finding_id: str) -> List[str]:
        """Find findings related to a given finding via chains_to edges.

        Args:
            finding_id: The finding to find relations for.

        Returns:
            List of related finding IDs.
        """
        related = []
        for edge in self.edges:
            if edge.source == finding_id and edge.edge_type == EdgeType.CHAINS_TO:
                related.append(edge.target)
            elif edge.target == finding_id and edge.edge_type == EdgeType.CHAINS_TO:
                related.append(edge.source)
        return related

    def get_tools_for_vuln_class(self, vuln_class: str) -> List[str]:
        """Get tools that work on a specific vulnerability class.

        Args:
            vuln_class: The vulnerability class (e.g., "XSS", "SQLi").

        Returns:
            List of tool IDs that work on this vuln class.
        """
        tools = []
        for edge in self.edges:
            if edge.edge_type == EdgeType.WORKS_ON and edge.target == vuln_class:
                tools.append(edge.source)
        return tools

    def get_attack_paths(self, asset_id: str) -> List[List[str]]:
        """Get attack paths for a specific asset.

        Args:
            asset_id: The asset to get attack paths for.

        Returns:
            List of attack paths (each path is a list of finding IDs).
        """
        paths = []
        for edge in self.edges:
            if edge.source == asset_id and edge.edge_type == EdgeType.HAS:
                finding_id = edge.target
                chain = self.find_related_findings(finding_id)
                if chain:
                    paths.append([finding_id] + chain)
                else:
                    paths.append([finding_id])
        return paths

    def get_chains(self) -> List[List[str]]:
        """Get all chains in the graph.

        Returns:
            List of chains (each chain is a list of finding IDs).
        """
        chains = []
        for edge in self.edges:
            if edge.edge_type == EdgeType.CHAINS_TO:
                chains.append([edge.source, edge.target])
        return chains

    def can_chain(self, finding1_id: str, finding2_id: str) -> bool:
        """Check if two findings can be chained.

        Args:
            finding1_id: First finding ID.
            finding2_id: Second finding ID.

        Returns:
            True if a chain edge exists between them.
        """
        for edge in self.edges:
            if edge.edge_type == EdgeType.CHAINS_TO:
                if (edge.source == finding1_id and edge.target == finding2_id) or (
                    edge.source == finding2_id and edge.target == finding1_id
                ):
                    return True
        return False

    def to_dict(self) -> Dict[str, Any]:
        """Serialize graph to dictionary.

        Returns:
            Dictionary representation of the graph.
        """
        return {
            "nodes": {
                k: {"type": v.node_type.value, "data": v.data} for k, v in self.nodes.items()
            },
            "edges": [
                {"source": e.source, "type": e.edge_type.value, "target": e.target}
                for e in self.edges
            ],
        }

    def save(self, path: str) -> None:
        """Save graph to JSON file.

        Args:
            path: File path to save to.
        """
        with open(path, "w") as f:
            json.dump(self.to_dict(), f, indent=2)
        logger.info(f"Saved knowledge graph to {path}")

    def load(self, path: str) -> None:
        """Load graph from JSON file.

        Args:
            path: File path to load from.
        """
        with open(path) as f:
            data = json.load(f)

        for node_id, node_data in data.get("nodes", {}).items():
            node_type = NodeType(node_data["type"])
            if node_type == NodeType.ASSET:
                self.add_asset(node_id, node_data.get("data", {}))
            elif node_type == NodeType.FINDING:
                self.add_finding(node_id, node_data.get("data", {}))
            elif node_type == NodeType.TOOL:
                self.add_tool(node_id, node_data.get("data", {}))
            elif node_type == NodeType.VULN_CLASS:
                self.add_vuln_class(node_id, node_data.get("data", {}))

        for edge_data in data.get("edges", []):
            self.add_edge(edge_data["source"], edge_data["type"], edge_data["target"])

        logger.info(f"Loaded knowledge graph from {path}")
