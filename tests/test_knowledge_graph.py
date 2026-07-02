"""tests/test_knowledge_graph.py — Tests for KnowledgeGraph module."""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from tools.knowledge_graph import KnowledgeGraph, NodeType, EdgeType


def test_add_asset():
    kg = KnowledgeGraph()
    kg.add_asset("example.com", {"type": "domain"})
    assert "example.com" in kg.nodes
    assert kg.nodes["example.com"].node_type == NodeType.ASSET
    assert kg.nodes["example.com"].data["type"] == "domain"


def test_add_finding():
    kg = KnowledgeGraph()
    kg.add_finding("xss-1", {"type": "XSS", "severity": "MEDIUM"})
    assert "xss-1" in kg.nodes
    assert kg.nodes["xss-1"].node_type == NodeType.FINDING
    assert kg.nodes["xss-1"].data["severity"] == "MEDIUM"


def test_add_edge():
    kg = KnowledgeGraph()
    kg.add_asset("example.com")
    kg.add_finding("xss-1")
    kg.add_edge("example.com", "has", "xss-1")
    assert len(kg.edges) == 1
    assert kg.edges[0].source == "example.com"
    assert kg.edges[0].target == "xss-1"
    assert kg.edges[0].edge_type == EdgeType.HAS


def test_find_related_findings():
    kg = KnowledgeGraph()
    kg.add_finding("idor-1")
    kg.add_finding("info-disc-1")
    kg.add_edge("idor-1", "chains_to", "info-disc-1")
    related = kg.find_related_findings("idor-1")
    assert "info-disc-1" in related
    related_reverse = kg.find_related_findings("info-disc-1")
    assert "idor-1" in related_reverse


def test_find_related_findings_none():
    kg = KnowledgeGraph()
    kg.add_finding("solo-1")
    related = kg.find_related_findings("solo-1")
    assert related == []


def test_get_tools_for_vuln_class():
    kg = KnowledgeGraph()
    kg.add_tool("xss-scanner")
    kg.add_vuln_class("XSS")
    kg.add_edge("xss-scanner", "works_on", "XSS")
    tools = kg.get_tools_for_vuln_class("XSS")
    assert "xss-scanner" in tools


def test_get_tools_for_vuln_class_empty():
    kg = KnowledgeGraph()
    tools = kg.get_tools_for_vuln_class("SQLi")
    assert tools == []


def test_can_chain():
    kg = KnowledgeGraph()
    kg.add_finding("f1")
    kg.add_finding("f2")
    kg.add_edge("f1", "chains_to", "f2")
    assert kg.can_chain("f1", "f2") is True
    assert kg.can_chain("f2", "f1") is True


def test_can_chain_false():
    kg = KnowledgeGraph()
    kg.add_finding("f1")
    kg.add_finding("f2")
    kg.add_edge("f1", "has", "f2")
    assert kg.can_chain("f1", "f2") is False


def test_to_dict():
    kg = KnowledgeGraph()
    kg.add_asset("example.com", {"type": "domain"})
    kg.add_finding("xss-1", {"severity": "HIGH"})
    kg.add_edge("example.com", "has", "xss-1")
    d = kg.to_dict()
    assert "nodes" in d
    assert "edges" in d
    assert "example.com" in d["nodes"]
    assert d["nodes"]["example.com"]["type"] == "asset"
    assert d["edges"][0]["source"] == "example.com"
    assert d["edges"][0]["type"] == "has"
