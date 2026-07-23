"""Tests for tools/knowledge_graph.py — Cross-Session Knowledge Graph."""

from __future__ import annotations

import pathlib
import tempfile

import pytest

from tools.knowledge_graph import (
    EDGE_KINDS,
    GraphEdge,
    GraphNode,
    KnowledgeGraph,
    NODE_KINDS,
    _stable_id,
)


@pytest.fixture
def kg():
    """Fresh KnowledgeGraph in a temp DB (isolated per test)."""
    with tempfile.TemporaryDirectory() as tmp:
        graph = KnowledgeGraph(db_path=pathlib.Path(tmp) / "test_kg.db")
        yield graph
        graph.close()


# ===================================================================
# _stable_id
# ===================================================================


class TestStableId:
    def test_same_inputs_produce_same_id(self):
        a = _stable_id("target", "example.com")
        b = _stable_id("target", "example.com")
        assert a == b

    def test_case_insensitive(self):
        assert _stable_id("target", "Example.COM") == _stable_id("target", "example.com")

    def test_whitespace_stripped(self):
        assert _stable_id("target", "  example.com  ") == _stable_id("target", "example.com")

    def test_different_inputs_produce_different_ids(self):
        assert _stable_id("target", "a.com") != _stable_id("target", "b.com")

    def test_id_length_capped(self):
        assert len(_stable_id("target", "x" * 1000)) == 16


# ===================================================================
# Constants
# ===================================================================


class TestConstants:
    def test_node_kinds_complete(self):
        assert "target" in NODE_KINDS
        assert "tech" in NODE_KINDS
        assert "vuln_class" in NODE_KINDS
        assert "chain" in NODE_KINDS
        assert "strategy" in NODE_KINDS
        assert len(NODE_KINDS) == 8

    def test_edge_kinds_complete(self):
        assert "has_tech" in EDGE_KINDS
        assert "succeeded_with" in EDGE_KINDS
        assert "failed_with" in EDGE_KINDS
        assert "chained_with" in EDGE_KINDS
        assert len(EDGE_KINDS) == 9


# ===================================================================
# upsert_node / upsert_edge
# ===================================================================


class TestUpsert:
    def test_upsert_node_returns_stable_id(self, kg):
        nid = kg.upsert_node("target", "example.com")
        assert isinstance(nid, str)
        assert len(nid) == 16

    def test_upsert_same_node_increments_hit_count(self, kg):
        nid1 = kg.upsert_node("target", "example.com")
        nid2 = kg.upsert_node("target", "example.com")
        assert nid1 == nid2
        stats = kg.stats()
        assert stats["nodes"]["target"] == 1
        # hit_count not exposed via stats, but no duplicate created

    def test_upsert_node_rejects_unknown_kind(self, kg):
        with pytest.raises(ValueError):
            kg.upsert_node("unknown_kind", "x")

    def test_upsert_edge_links_two_nodes(self, kg):
        a = kg.upsert_node("target", "a.com")
        b = kg.upsert_node("tech", "php")
        kg.upsert_edge(a, b, "has_tech")
        assert kg.stats()["edges"]["has_tech"] == 1

    def test_upsert_edge_rejects_unknown_kind(self, kg):
        a = kg.upsert_node("target", "a.com")
        b = kg.upsert_node("tech", "php")
        with pytest.raises(ValueError):
            kg.upsert_edge(a, b, "unknown_edge")


# ===================================================================
# record_finding
# ===================================================================


class TestRecordFinding:
    def test_creates_all_expected_nodes(self, kg):
        kg.record_finding(
            target="example.com", endpoint="/admin",
            tech_stack=["php", "nginx"],
            vuln_class="lfi", tool="ffuf", payload="../etc/passwd",
            severity="high", success=True, mission_id="m1",
        )
        stats = kg.stats()
        assert stats["nodes"]["target"] == 1
        assert stats["nodes"]["tech"] == 2
        assert stats["nodes"]["endpoint"] == 1
        assert stats["nodes"]["vuln_class"] == 1
        assert stats["nodes"]["finding"] == 1
        assert stats["nodes"]["exploit"] == 1
        assert stats["nodes"]["strategy"] == 1

    def test_creates_expected_edges(self, kg):
        kg.record_finding(
            target="example.com", endpoint="/admin",
            tech_stack=["php", "nginx"],
            vuln_class="lfi", tool="ffuf", payload="../etc/passwd",
            severity="high", success=True, mission_id="m1",
        )
        e = kg.stats()["edges"]
        assert e["has_tech"] == 2
        assert e["has_endpoint"] == 1
        assert e["has_vuln"] == 2  # endpoint->vuln + target->vuln
        assert e["found_at"] == 1
        assert e["exploited_by"] == 1
        assert e["succeeded_with"] == 1
        assert e["failed_with"] == 0

    def test_failure_creates_failed_with_edge(self, kg):
        kg.record_finding(
            target="example.com", endpoint="/api",
            tech_stack=["php"],
            vuln_class="ssrf", tool="ffuf", payload="http://evil",
            severity="medium", success=False, mission_id="m1",
        )
        assert kg.stats()["edges"]["failed_with"] == 1
        assert kg.stats()["edges"]["succeeded_with"] == 0

    def test_dedup_on_same_finding(self, kg):
        """Re-recording the same finding should NOT create duplicates."""
        for _ in range(3):
            kg.record_finding(
                target="example.com", endpoint="/admin",
                tech_stack=["php"],
                vuln_class="lfi", tool="ffuf", payload="../etc/passwd",
                severity="high", success=True, mission_id="m1",
            )
        stats = kg.stats()
        # Same target/tech/endpoint/vuln/exploit/finding — no duplicates
        assert stats["nodes"]["target"] == 1
        assert stats["nodes"]["tech"] == 1
        assert stats["nodes"]["endpoint"] == 1
        assert stats["nodes"]["vuln_class"] == 1
        assert stats["nodes"]["finding"] == 1

    def test_returns_finding_id(self, kg):
        fid = kg.record_finding(
            target="x.com", endpoint="/", tech_stack=[],
            vuln_class="xss", tool="dalfox", payload="<script>",
            severity="medium", success=True,
        )
        assert isinstance(fid, str)
        assert len(fid) == 16


# ===================================================================
# record_chain
# ===================================================================


class TestRecordChain:
    def test_creates_chain_node_and_links_findings(self, kg):
        steps = [
            {"vuln": "lfi", "endpoint": "/admin", "tool": "ffuf"},
            {"vuln": "rce", "endpoint": "/logs", "tool": "manual"},
        ]
        cid = kg.record_chain(steps, "critical", "example.com", "m1")
        assert isinstance(cid, str)
        assert kg.stats()["nodes"]["chain"] == 1
        assert kg.stats()["edges"]["chained_with"] == 3  # target->chain + chain->2 findings

    def test_chain_stores_steps_and_severity(self, kg):
        steps = [{"vuln": "sqli", "endpoint": "/api"}]
        kg.record_chain(steps, "high", "x.com", "m1")
        chains = kg.recall_chains(target="x.com")
        assert len(chains) == 1
        assert chains[0]["combined_severity"] == "high"
        assert len(chains[0]["steps"]) == 1


# ===================================================================
# recall_strategies / recall_failures / recall_chains
# ===================================================================


class TestRecall:
    @pytest.fixture
    def populated_kg(self, kg):
        """Pre-populated with mixed success/failure findings."""
        kg.record_finding(
            target="example.com", endpoint="/admin",
            tech_stack=["php", "nginx"],
            vuln_class="lfi", tool="ffuf", payload="../etc/passwd",
            severity="high", success=True, mission_id="m1",
        )
        kg.record_finding(
            target="example.com", endpoint="/login",
            tech_stack=["php", "nginx"],
            vuln_class="sqli", tool="sqlmap", payload="' OR 1=1--",
            severity="critical", success=True, mission_id="m1",
        )
        kg.record_finding(
            target="example.com", endpoint="/api",
            tech_stack=["php"],
            vuln_class="ssrf", tool="ffuf", payload="http://evil",
            severity="medium", success=False, mission_id="m1",
        )
        return kg

    def test_recall_strategies_returns_successful_tools(self, populated_kg):
        results = populated_kg.recall_strategies(tech_stack=["php", "nginx"])
        tools = [r.get("tool") for r in results]
        assert "ffuf" in tools
        assert "sqlmap" in tools

    def test_recall_strategies_empty_when_no_match(self, populated_kg):
        results = populated_kg.recall_strategies(tech_stack=["nonexistent_tech"])
        assert results == []

    def test_recall_strategies_empty_when_no_args(self, populated_kg):
        assert populated_kg.recall_strategies() == []

    def test_recall_failures_returns_failed_tools(self, populated_kg):
        results = populated_kg.recall_failures(tech_stack=["php"])
        assert len(results) == 1
        assert results[0]["tool"] == "ffuf"

    def test_recall_failures_empty_when_no_failures(self, populated_kg):
        results = populated_kg.recall_failures(tech_stack=["nonexistent"])
        assert results == []

    def test_recall_chains_returns_recorded_chains(self, populated_kg):
        populated_kg.record_chain(
            steps=[{"vuln": "lfi", "endpoint": "/admin"},
                   {"vuln": "rce", "endpoint": "/logs"}],
            combined_severity="critical", target="example.com", mission_id="m1",
        )
        chains = populated_kg.recall_chains(target="example.com")
        assert len(chains) == 1
        assert chains[0]["combined_severity"] == "critical"
        assert len(chains[0]["steps"]) == 2

    def test_recall_chains_empty_when_no_chains(self, populated_kg):
        chains = populated_kg.recall_chains(target="example.com")
        assert chains == []


# ===================================================================
# stats / reset
# ===================================================================


class TestStatsAndReset:
    def test_stats_returns_expected_structure(self, kg):
        stats = kg.stats()
        assert "nodes" in stats
        assert "edges" in stats
        assert "missions" in stats
        assert "total_nodes" in stats
        assert "total_edges" in stats
        assert stats["total_nodes"] == 0  # empty graph

    def test_stats_counts_correctly(self, kg):
        kg.record_finding(
            target="x.com", endpoint="/", tech_stack=["php"],
            vuln_class="xss", tool="dalfox", payload="<script>",
            severity="low", success=True,
        )
        stats = kg.stats()
        assert stats["total_nodes"] > 0
        assert stats["total_edges"] > 0
        assert stats["missions"] == 0  # no mission_id passed

    def test_reset_clears_everything(self, kg):
        kg.record_finding(
            target="x.com", endpoint="/", tech_stack=["php"],
            vuln_class="xss", tool="dalfox", payload="<script>",
            severity="low", success=True, mission_id="m1",
        )
        assert kg.stats()["total_nodes"] > 0
        kg.reset()
        assert kg.stats()["total_nodes"] == 0
        assert kg.stats()["total_edges"] == 0
        assert kg.stats()["missions"] == 0
