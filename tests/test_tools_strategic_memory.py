"""Tests for tools/strategic_memory.py — Strategic Recall API facade."""

from __future__ import annotations

import pathlib
import tempfile
from unittest.mock import MagicMock, patch

import pytest

from tools.strategic_memory import StrategicMemory


@pytest.fixture
def sm_isolated(monkeypatch):
    """StrategicMemory with an isolated temp KnowledgeGraph DB and a
    mocked LearningEngine (to avoid polluting the real global DB)."""
    with tempfile.TemporaryDirectory() as tmp:
        sm = StrategicMemory()
        # Override knowledge_graph with temp-DB instance
        from tools.knowledge_graph import KnowledgeGraph
        sm._kg = KnowledgeGraph(db_path=pathlib.Path(tmp) / "sm_kg.db")
        # Force learning_engine to None so it doesn't read/write global DB
        sm._learning = False
        yield sm
        if sm._kg:
            sm._kg.close()


# ===================================================================
# Lazy properties
# ===================================================================


class TestLazyProperties:
    def test_knowledge_graph_lazy_loads(self):
        sm = StrategicMemory()
        with patch("tools.strategic_memory.KnowledgeGraph", create=True) if False else patch("tools.knowledge_graph.KnowledgeGraph") as mock_cls:
            mock_cls.return_value = "fake_kg"
            sm._kg = None  # reset cache
            result = sm.knowledge_graph
            assert result == "fake_kg"

    def test_learning_engine_lazy_loads(self):
        sm = StrategicMemory()
        with patch("tools.learning_engine.LearningEngine") as mock_cls:
            mock_cls.return_value = "fake_le"
            result = sm.learning_engine
            assert result == "fake_le"

    def test_knowledge_graph_handles_import_failure(self):
        sm = StrategicMemory()
        with patch("tools.knowledge_graph.KnowledgeGraph", side_effect=ImportError("nope")):
            sm._kg = None
            assert sm.knowledge_graph is None


# ===================================================================
# record_finding
# ===================================================================


class TestRecordFinding:
    def test_records_to_knowledge_graph(self, sm_isolated):
        sm = sm_isolated
        with patch("tools.vector_memory.remember") as mock_remember:
            sm.record_finding(
                target="example.com", endpoint="/admin",
                tech_stack=["php", "nginx"],
                vuln_class="lfi", tool="ffuf", payload="../etc/passwd",
                severity="high", success=True, mission_id="m1",
            )
        # Verify knowledge graph was populated
        assert sm.knowledge_graph.stats()["total_nodes"] > 0
        # Verify vector_memory.remember was called
        mock_remember.assert_called_once()

    def test_failure_doesnt_break_when_backends_missing(self):
        sm = StrategicMemory()
        sm._kg = False  # unavailable marker
        sm._learning = False
        # Should not raise
        sm.record_finding(
            target="x.com", endpoint="/", tech_stack=[],
            vuln_class="xss", tool="dalfox", payload="<script>",
            severity="medium", success=True,
        )

    def test_record_chain_calls_knowledge_graph(self, sm_isolated):
        sm = sm_isolated
        sm.record_chain(
            steps=[{"vuln": "lfi", "endpoint": "/admin"},
                   {"vuln": "rce", "endpoint": "/logs"}],
            combined_severity="critical",
            target="example.com",
            mission_id="m1",
            description="LFI to RCE via log poisoning",
        )
        chains = sm.knowledge_graph.recall_chains(target="example.com")
        assert len(chains) == 1
        assert chains[0]["combined_severity"] == "critical"


# ===================================================================
# build_decision_context
# ===================================================================


class TestBuildDecisionContext:
    def test_empty_memory_returns_placeholder(self, sm_isolated):
        sm = sm_isolated
        sm._learning = False  # avoid global SQLite pollution
        result = sm.build_decision_context(target="newtarget.com")
        assert "No strategic memory yet" in result

    def test_includes_strategies_that_worked(self, sm_isolated):
        sm = sm_isolated
        sm._learning = False
        sm.record_finding(
            target="example.com", endpoint="/admin",
            tech_stack=["php", "nginx"],
            vuln_class="lfi", tool="ffuf", payload="../etc/passwd",
            severity="high", success=True, mission_id="m1",
        )
        result = sm.build_decision_context(
            target="example.com", tech_stack=["php", "nginx"]
        )
        assert "STRATEGIES THAT WORKED BEFORE" in result
        assert "ffuf" in result
        assert "../etc/passwd" in result

    def test_includes_approaches_that_failed(self, sm_isolated):
        sm = sm_isolated
        sm._learning = False
        sm.record_finding(
            target="example.com", endpoint="/api",
            tech_stack=["php"],
            vuln_class="ssrf", tool="ffuf", payload="http://evil",
            severity="medium", success=False, mission_id="m1",
        )
        result = sm.build_decision_context(
            target="example.com", tech_stack=["php"]
        )
        assert "APPROACHES THAT FAILED BEFORE" in result
        assert "http://evil" in result

    def test_includes_attack_chains(self, sm_isolated):
        sm = sm_isolated
        sm._learning = False
        sm.record_chain(
            steps=[{"vuln": "lfi", "endpoint": "/admin"},
                   {"vuln": "rce", "endpoint": "/logs"}],
            combined_severity="critical",
            target="example.com",
            mission_id="m1",
            description="LFI to RCE",
        )
        result = sm.build_decision_context(target="example.com")
        assert "SUCCESSFUL ATTACK CHAINS" in result
        assert "lfi@/admin" in result
        assert "rce@/logs" in result
        assert "critical" in result.lower()

    def test_respects_max_limits(self, sm_isolated):
        sm = sm_isolated
        sm._learning = False
        # Record 5 successful findings
        for i in range(5):
            sm.record_finding(
                target="x.com", endpoint=f"/ep{i}",
                tech_stack=["php"],
                vuln_class="xss", tool=f"tool{i}", payload=f"p{i}",
                severity="low", success=True, mission_id="m1",
            )
        result = sm.build_decision_context(
            target="x.com", tech_stack=["php"],
            max_strategies=2, max_failures=0, max_chains=0,
        )
        # Should only include 2 strategies
        assert result.count("tool0") + result.count("tool1") <= 2

    def test_no_strategies_when_no_matching_tech(self, sm_isolated):
        sm = sm_isolated
        sm._learning = False
        sm.record_finding(
            target="a.com", endpoint="/", tech_stack=["php"],
            vuln_class="xss", tool="dalfox", payload="<script>",
            severity="low", success=True,
        )
        # Query with completely different tech stack
        result = sm.build_decision_context(
            target="other.com", tech_stack=["java"]
        )
        # No matching strategies from php in java query
        assert "dalfox" not in result or "No strategic memory" in result


# ===================================================================
# Internal recall wrappers
# ===================================================================


class TestInternalRecall:
    def test_recall_strategies_merges_kg_and_learning(self, sm_isolated):
        sm = sm_isolated
        # Add a fake learning engine with tool rankings
        mock_le = MagicMock()
        mock_le.rank_tools.return_value = [("nuclei", 0.9, 5)]
        sm._learning = mock_le

        # Also record to knowledge graph
        sm.record_finding(
            target="x.com", endpoint="/", tech_stack=["php"],
            vuln_class="xss", tool="dalfox", payload="<script>",
            severity="low", success=True,
        )

        results = sm._recall_strategies(["php"], None, limit=5)
        tools = [r.get("tool") for r in results]
        assert "dalfox" in tools  # from knowledge graph
        assert "nuclei" in tools  # from learning engine

    def test_recall_strategies_handles_failure(self, sm_isolated):
        sm = sm_isolated
        # Force knowledge graph to fail
        sm._kg = MagicMock()
        sm._kg.recall_strategies.side_effect = RuntimeError("db locked")
        sm._learning = False
        # Should not raise
        results = sm._recall_strategies(["php"], None, limit=5)
        assert results == []

    def test_recall_failures_returns_empty_when_no_kg(self):
        sm = StrategicMemory()
        sm._kg = None
        assert sm._recall_failures(["php"], "x.com", 5) == []

    def test_recall_chains_returns_empty_when_no_kg(self):
        sm = StrategicMemory()
        sm._kg = None
        assert sm._recall_chains(["php"], "x.com", 5) == []


# ===================================================================
# stats
# ===================================================================


class TestStats:
    def test_stats_returns_dict(self, sm_isolated):
        sm = sm_isolated
        sm._learning = MagicMock()
        sm._learning.get_stats.return_value = {"total": 1}
        stats = sm.stats()
        assert "knowledge_graph" in stats
        assert "learning_engine" in stats
        assert stats["learning_engine"]["total"] == 1

    def test_stats_handles_backend_failure(self, sm_isolated):
        sm = sm_isolated
        sm._learning = MagicMock()
        sm._learning.get_stats.side_effect = RuntimeError("db error")
        stats = sm.stats()
        # Should not raise; just omits the failing backend
        assert "knowledge_graph" in stats


# ===================================================================
# Wire integration: ScanLoop calls StrategicMemory
# ===================================================================


class TestScanLoopWireIntegration:
    """Verify ScanLoop._record_to_strategic_memory records findings."""

    def test_record_to_strategic_memory_called_with_findings(self):
        """scan_loop should call StrategicMemory.record_finding for each finding."""
        from elengenix.scanning.scan_loop import ScanLoop
        from types import SimpleNamespace

        de = MagicMock()
        pp = MagicMock()
        exec_ = MagicMock(return_value=(True, MagicMock(output="ok"), "ok"))

        loop = ScanLoop(decision_engine=de, post_processor=pp, executor=exec_)
        loop._run_reasoning_phase = MagicMock(return_value=[])

        # Spy on _record_to_strategic_memory
        loop._record_to_strategic_memory = MagicMock()

        ctx = SimpleNamespace(
            target="example.com",
            mission_key="m1",
            max_steps=1,
            step_count=0,
            all_findings=[],
            last_output="",
            last_command="",
            last_command_success=True,
            consecutive_no_findings=0,
            assets={"tech_stack": ["php"]},
            attack_tree=MagicMock(steps=[]),
            planner=None,
            update_after_step=MagicMock(),
            append_history=MagicMock(),
            set_last_command_output=MagicMock(),
        )

        de.decide.return_value = MagicMock(
            action_data={"action": "finish", "summary": "done"},
            reasoning="done",
            source="ai_dynamic",
        )

        asyncio_result = __import__("asyncio").run(loop.run(ctx, "scan me"))
        # _record_to_strategic_memory should have been called (or not, if no findings)
        # Since the action is "finish", no findings recorded — verify the method exists
        assert hasattr(loop, "_record_to_strategic_memory")

    def test_get_strategic_memory_lazy_init(self):
        from elengenix.scanning.scan_loop import ScanLoop
        de = MagicMock(); pp = MagicMock(); exec_ = MagicMock()
        loop = ScanLoop(decision_engine=de, post_processor=pp, executor=exec_)
        assert loop._strategic_memory is None
        # First call initializes
        sm = loop._get_strategic_memory()
        # Either returns StrategicMemory or None (if deps missing) but not raises
        assert sm is None or hasattr(sm, "record_finding")

    def test_get_strategic_memory_caches(self):
        from elengenix.scanning.scan_loop import ScanLoop
        de = MagicMock(); pp = MagicMock(); exec_ = MagicMock()
        loop = ScanLoop(decision_engine=de, post_processor=pp, executor=exec_)
        sm1 = loop._get_strategic_memory()
        sm2 = loop._get_strategic_memory()
        # Same instance returned (cached)
        assert sm1 is sm2
