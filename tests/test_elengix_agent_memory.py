"""Tests for elengenix/agent/memory.py — AgentMemory.

Patches _vm / _le in the module directly (via unittest.mock.patch.object)
so tests work even if the real tools.vector_memory was already imported.
"""
from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import ANY, MagicMock, patch, call

import pytest

import elengenix.agent.memory as _mem_mod

AgentMemory = _mem_mod.AgentMemory


# ===================================================================
# Fixtures
# ===================================================================


@pytest.fixture(autouse=True)
def mock_get_data_path():
    with patch("elengenix.agent.memory.get_data_path") as m:
        m.return_value = Path("/tmp/.elengenix_test/learning.db")
        yield m


@pytest.fixture(autouse=True)
def inject_exploit_record():
    _mem_mod.ExploitRecord = MagicMock()
    yield
    if hasattr(_mem_mod, "ExploitRecord"):
        del _mem_mod.ExploitRecord


@pytest.fixture(autouse=True)
def mock_vm_module():
    """Patch memory module's _vm reference so AgentMemory uses our mock VectorMemory."""
    fake_vm = MagicMock()
    fake_vm.VectorMemory = MagicMock()
    fake_vm.MemoryEntry = MagicMock()
    fake_vm._VECTOR_AVAILABLE = True
    with patch.object(_mem_mod, "_vm", fake_vm):
        yield fake_vm


@pytest.fixture(autouse=True)
def mock_le_module():
    """Patch memory module's _le reference so AgentMemory uses our mock LearningEngine."""
    fake_le = MagicMock()
    fake_le.LearningEngine = MagicMock()
    with patch.object(_mem_mod, "_le", fake_le):
        yield fake_le


@pytest.fixture
def mock_vector():
    vm = MagicMock()
    vm._initialized = True
    vm.add_memory.return_value = "mem_abc123"
    vm.search.return_value = []
    vm.get_target_memories.return_value = []
    return vm


@pytest.fixture
def mock_learning():
    le = MagicMock()
    le.rank_tools.return_value = [("nmap", 0.85, 10)]
    le.remember = MagicMock()
    return le


@pytest.fixture
def memory(mock_vector, mock_learning, mock_vm_module, mock_le_module):
    mock_vm_module.VectorMemory.return_value = mock_vector
    mock_le_module.LearningEngine.return_value = mock_learning
    mem = AgentMemory()
    yield mem


# ===================================================================
# Constructor
# ===================================================================


class TestConstructor:
    def test_default_init(self, mock_vector, mock_learning, mock_vm_module, mock_le_module):
        mock_vm_module.VectorMemory.return_value = mock_vector
        mock_le_module.LearningEngine.return_value = mock_learning
        mem = AgentMemory()
        assert mem._vector is mock_vector
        assert mem._learning is mock_learning
        mock_vm_module.VectorMemory.assert_called_once_with(persist_directory=None)
        mock_le_module.LearningEngine.assert_called_once_with(
            db_path=Path("/tmp/.elengenix_test/learning.db")
        )

    def test_custom_paths(self, mock_vector, mock_learning, mock_vm_module, mock_le_module):
        vdir = Path("/custom/vector")
        ldb = Path("/custom/learning.db")
        mock_vm_module.VectorMemory.return_value = mock_vector
        mock_le_module.LearningEngine.return_value = mock_learning
        AgentMemory(vector_dir=vdir, learning_db=ldb)
        mock_vm_module.VectorMemory.assert_called_once_with(persist_directory=str(vdir))
        mock_le_module.LearningEngine.assert_called_once_with(db_path=ldb)

    def test_vector_failure_graceful(self, mock_learning, mock_vm_module, mock_le_module):
        mock_vm_module.VectorMemory.side_effect = Exception("ChromaDB crash")
        mock_le_module.LearningEngine.return_value = mock_learning
        mem = AgentMemory()
        assert mem._vector is None
        assert mem._learning is mock_learning

    def test_learning_failure_graceful(self, mock_vector, mock_vm_module, mock_le_module):
        mock_vm_module.VectorMemory.return_value = mock_vector
        mock_le_module.LearningEngine.side_effect = Exception("LE crash")
        mem = AgentMemory()
        assert mem._vector is mock_vector
        assert mem._learning is None

    def test_no_vector_no_learning(self, mock_vm_module, mock_le_module):
        mock_vm_module.VectorMemory.side_effect = ImportError("no vm")
        mock_le_module.LearningEngine.side_effect = ImportError("no le")
        mem = AgentMemory()
        assert mem._vector is None


# ===================================================================
# PreHunt
# ===================================================================


class TestPreHunt:
    def test_returns_dict(self, memory, mock_vector):
        mock_vector.search.return_value = []
        result = memory.pre_hunt("example.com")
        assert isinstance(result, dict)
        assert "memories" in result
        assert "learned_skills" in result
        assert "context" in result

    def test_semantic_search_called(self, memory, mock_vector):
        mock_vector.search.return_value = []
        memory.pre_hunt("example.com")
        mock_vector.search.assert_called_once_with(
            query="example.com", n_results=15, min_similarity=0.15
        )

    def test_target_memories_appended(self, memory, mock_vector):
        sem_mem = [{"id": "1", "content": "port 80", "target": "other.com"}]
        tgt_mem = [{"id": "2", "content": "port 443", "target": "example.com"}]
        mock_vector.search.return_value = sem_mem
        mock_vector.get_target_memories.return_value = tgt_mem
        result = memory.pre_hunt("example.com")
        assert len(result["memories"]) == 2

    def test_deduplicates_memories(self, memory, mock_vector):
        both = [{"id": "1", "content": "dup", "target": "x"}]
        mock_vector.search.return_value = both
        mock_vector.get_target_memories.return_value = both
        result = memory.pre_hunt("x")
        assert len(result["memories"]) == 1

    def test_learning_skills_included(self, memory, mock_learning, mock_vector):
        mock_learning.rank_tools.return_value = [("dirb", 0.88, 12)]
        result = memory.pre_hunt("x")
        assert len(result["learned_skills"]) == 1
        assert result["learned_skills"][0]["tool"] == "dirb"

    def test_context_string_built(self, memory, mock_vector):
        mock_vector.search.return_value = [{"id": "1", "content": "open port", "target": "t"}]
        result = memory.pre_hunt("t")
        assert "Found" in result["context"]

    def test_exception_propagates(self, memory, mock_vector):
        with pytest.raises(RuntimeError):
            mock_vector.search.side_effect = RuntimeError("fail")
            memory.pre_hunt("x")


# ===================================================================
# PostStep
# ===================================================================


class TestPostStep:
    def test_stores_reasoning(self, memory, mock_vector):
        memory.post_step("ex.com", 1, "nmap", {"port": 80}, {"success": True}, reasoning="Scanning port 80")
        mock_vector.add_memory.assert_any_call(
            content="Reasoning: Scanning port 80",
            target="ex.com",
            category="reasoning",
            metadata=ANY,
        )

    def test_stores_tool_result(self, memory, mock_vector):
        memory.post_step("ex.com", 2, "curl", {}, {"success": True, "output": "200 OK"})
        mock_vector.add_memory.assert_any_call(
            content=ANY,
            target="ex.com",
            category="tool_result",
            metadata=ANY,
        )

    def test_empty_reasoning_skipped(self, memory, mock_vector):
        memory.post_step("ex.com", 3, "test", {}, {"success": True, "output": "ok"})
        reasoning_calls = [c for c in mock_vector.add_memory.call_args_list
                          if c.kwargs.get("category") == "reasoning"]
        assert len(reasoning_calls) == 0

    def test_no_output_skipped(self, memory, mock_vector):
        memory.post_step("ex.com", 4, "quiet", {}, {}, reasoning="silent")
        result_calls = [c for c in mock_vector.add_memory.call_args_list
                       if c.kwargs.get("category") == "tool_result"]
        assert len(result_calls) == 0

    def test_learning_triggered_on_success(self, memory, mock_learning):
        memory.post_step("ex.com", 5, "nmap", {},
                         {"success": True, "output": "open ports: 22, 80, 443"},
                         reasoning="scan done")
        mock_learning.remember.assert_called_once()

    def test_learning_not_triggered_on_short_output(self, memory, mock_learning):
        memory.post_step("ex.com", 6, "ping", {},
                         {"success": True, "output": "ok"},
                         reasoning="quick")
        mock_learning.remember.assert_not_called()

    def test_no_vector_noop(self, mock_vector, mock_learning, mock_vm_module, mock_le_module):
        mock_vm_module.VectorMemory.return_value = mock_vector
        mock_le_module.LearningEngine.return_value = mock_learning
        mem = AgentMemory()
        mem._vector = None
        mem.post_step("ex.com", 1, "test", {}, {"output": "ok"}, reasoning="test")
        mock_vector.add_memory.assert_not_called()

    def test_exception_handled(self, memory, mock_vector):
        mock_vector.add_memory.side_effect = RuntimeError("crash")
        memory.post_step("ex.com", 8, "bad", {}, {"output": "x"}, reasoning="boom")

    def test_long_reasoning_truncated(self, memory, mock_vector):
        long_r = "x" * 1000
        memory.post_step("ex.com", 10, "nmap", {}, {"output": "ok"}, reasoning=long_r)
        for c in mock_vector.add_memory.call_args_list:
            if c.kwargs.get("category") == "reasoning":
                content = c.kwargs["content"]
                assert len(content) <= 311
                break
        else:
            pytest.fail("no reasoning call found")


# ===================================================================
# RememberFinding
# ===================================================================


class TestRememberFinding:
    @pytest.fixture
    def finding(self):
        f = MagicMock()
        f.target = "ex.com"
        f.title = "Open SSH Port"
        f.severity = "high"
        f.confidence = 0.8
        f.description = "SSH is exposed"
        f.tech_stack = None
        f.source_tool = "nmap"
        return f

    def test_stores_finding(self, memory, mock_vector, finding):
        memory.remember_finding("ex.com", finding)
        mock_vector.add_memory.assert_called_once_with(
            content=ANY,
            target="ex.com",
            category="finding",
            metadata=ANY,
        )

    def test_content_includes_severity_title(self, memory, mock_vector, finding):
        memory.remember_finding("ex.com", finding)
        content = mock_vector.add_memory.call_args.kwargs["content"]
        assert "[HIGH]" in content
        assert "Open SSH Port" in content

    def test_learning_gated_by_confidence(self, memory, mock_learning, finding):
        finding.confidence = 0.3
        memory.remember_finding("ex.com", finding)
        mock_learning.remember.assert_not_called()

    def test_learning_called_at_high_confidence(self, memory, mock_learning, finding):
        finding.confidence = 0.7
        memory.remember_finding("ex.com", finding)
        mock_learning.remember.assert_called_once()

    def test_exception_graceful(self, memory, mock_vector, finding):
        mock_vector.add_memory.side_effect = RuntimeError("full")
        memory.remember_finding("ex.com", finding)

    def test_no_vector_does_not_crash(self, mock_vector, mock_vm_module, mock_le_module, mock_learning, finding):
        mock_vm_module.VectorMemory.return_value = mock_vector
        mock_le_module.LearningEngine.return_value = mock_learning
        mem = AgentMemory()
        mem._vector = None
        mem.remember_finding("ex.com", finding)

    def test_metadata_includes_tool(self, memory, mock_vector, finding):
        memory.remember_finding("ex.com", finding)
        meta = mock_vector.add_memory.call_args.kwargs.get("metadata", {})
        assert meta.get("tool") == "nmap"

    def test_metadata_includes_severity(self, memory, mock_vector, finding):
        memory.remember_finding("ex.com", finding)
        meta = mock_vector.add_memory.call_args.kwargs.get("metadata", {})
        assert meta.get("severity") == "high"


# ===================================================================
# PostHunt
# ===================================================================


class TestPostHunt:
    @pytest.fixture
    def report(self):
        r = MagicMock()
        r.target = "ex.com"
        r.total_steps = 5
        r.findings = []
        r.hypotheses_confirmed = 2
        r.hypotheses_tested = 3
        r.scan_duration = 30.0
        r.summary = "Found 3 issues"
        return r

    def test_stores_report_summary(self, memory, mock_vector, report):
        memory.post_hunt(report)
        mock_vector.add_memory.assert_any_call(
            content=ANY,
            target="ex.com",
            category="report_summary",
            metadata=ANY,
        )

    def test_summary_contains_finding_count(self, memory, mock_vector, report):
        memory.post_hunt(report)
        content = None
        for c in mock_vector.add_memory.call_args_list:
            if c.kwargs.get("category") == "report_summary":
                content = c.kwargs["content"]
                break
        assert content is not None
        assert "5 steps" in content

    def test_individual_findings_stored(self, memory, mock_vector, report):
        f1 = MagicMock()
        f1.target = "ex.com"
        f1.title = "XSS"
        f1.severity = "medium"
        f1.confidence = 0.6
        f1.description = ""
        f1.source_tool = "scanner"
        f1.tech_stack = []
        report.findings = [f1]
        memory.post_hunt(report)
        finding_calls = [c for c in mock_vector.add_memory.call_args_list
                        if c.kwargs.get("category") == "finding"]
        assert len(finding_calls) >= 1

    def test_auto_skill_created(self, memory, mock_vector, report):
        f1 = MagicMock()
        f1.target = "ex.com"
        f1.title = "SQLi"
        f1.severity = "critical"
        f1.confidence = 0.9
        f1.description = ""
        f1.source_tool = "sqlmap"
        f1.tech_stack = []
        report.findings = [f1]
        memory.post_hunt(report)
        skill_calls = [c for c in mock_vector.add_memory.call_args_list
                      if c.kwargs.get("category") == "skill"]
        assert len(skill_calls) >= 1

    def test_no_findings_no_auto_skill(self, memory, mock_vector, report):
        report.findings = []
        memory.post_hunt(report)
        skill_calls = [c for c in mock_vector.add_memory.call_args_list
                      if c.kwargs.get("category") == "skill"]
        assert len(skill_calls) == 0

    def test_no_vector_does_not_crash(self, mock_vector, mock_vm_module, mock_le_module, mock_learning, report):
        mock_vm_module.VectorMemory.return_value = mock_vector
        mock_le_module.LearningEngine.return_value = mock_learning
        mem = AgentMemory()
        mem._vector = None
        mem.post_hunt(report)


# ===================================================================
# CreateSkill
# ===================================================================


class TestCreateSkill:
    def test_stores_skill(self, memory, mock_vector):
        memory.create_skill("check_ssh", "Check SSH version", "ssh_check -t target")
        mock_vector.add_memory.assert_called_once_with(
            content=ANY,
            target="global",
            category="skill",
            metadata=ANY,
        )

    def test_returns_memory_id(self, memory, mock_vector):
        result = memory.create_skill("p", "desc", "tech")
        assert result == "mem_abc123"

    def test_metadata_has_skill_name(self, memory, mock_vector):
        memory.create_skill("port_scan", "Scan ports", "nmap -p- target")
        meta = mock_vector.add_memory.call_args.kwargs["metadata"]
        assert meta["skill_name"] == "port_scan"

    def test_metadata_has_technique(self, memory, mock_vector):
        memory.create_skill("p", "d", "nmap -p- target")
        meta = mock_vector.add_memory.call_args.kwargs["metadata"]
        assert "nmap" in meta["technique"]

    def test_no_vector_returns_none(self, mock_vector, mock_vm_module, mock_learning, mock_le_module):
        mock_vm_module.VectorMemory.return_value = mock_vector
        mock_le_module.LearningEngine.return_value = mock_learning
        mem = AgentMemory()
        mem._vector = None
        assert mem.create_skill("x", "y", "z") is None

    def test_custom_target(self, memory, mock_vector):
        memory.create_skill("p", "d", "tech", target="my_target")
        assert mock_vector.add_memory.call_args.kwargs["target"] == "my_target"

    def test_tags_in_metadata(self, memory, mock_vector):
        memory.create_skill("p", "d", "tech", tags=["web", "recon"])
        meta = mock_vector.add_memory.call_args.kwargs["metadata"]
        assert "web" in meta["tags"]


# ===================================================================
# RecallSkills
# ===================================================================


class TestRecallSkills:
    def test_returns_string(self, memory, mock_vector):
        mock_vector.search.return_value = []
        result = memory.recall_skills("ssh")
        assert isinstance(result, str)

    def test_formats_found_skills(self, memory, mock_vector):
        mock_vector.search.return_value = [
            {"content": "Check SSH", "metadata": {"type": "ai_created", "skill_name": "ssh_check"}, "similarity": 0.8},
        ]
        result = memory.recall_skills("ssh")
        assert "Check SSH" in result
        assert "AI-CREATED SKILL" in result

    def test_empty_when_no_vector(self, mock_vector, mock_vm_module, mock_learning, mock_le_module):
        mock_vm_module.VectorMemory.return_value = mock_vector
        mock_le_module.LearningEngine.return_value = mock_learning
        mem = AgentMemory()
        mem._vector = None
        assert mem.recall_skills("ssh") == ""

    def test_empty_when_no_results(self, memory, mock_vector):
        mock_vector.search.return_value = []
        assert memory.recall_skills("ssh") == ""

    def test_limits_to_five_skills(self, memory, mock_vector):
        mock_vector.search.return_value = [
            {"content": f"Skill {i}", "metadata": {}, "similarity": 0.1 * i}
            for i in range(10)
        ]
        result = memory.recall_skills("generic")
        assert result.count("1. ") == 1
        assert result.count("5. ") == 1
        assert result.count("6. ") == 0

    def test_uses_query_fallback(self, memory, mock_vector):
        mock_vector.search.return_value = []
        result = memory.recall_skills()
        assert isinstance(result, str)

    def test_exception_returns_empty(self, memory, mock_vector):
        mock_vector.search.side_effect = RuntimeError("fail")
        assert memory.recall_skills("x") == ""


# ===================================================================
# GetContext
# ===================================================================


class TestGetContext:
    def test_returns_string(self, memory, mock_vector):
        mock_vector.search.return_value = []
        result = memory.get_context("ex.com")
        assert isinstance(result, str)

    def test_with_memories(self, memory, mock_vector):
        mock_vector.search.return_value = [
            {"content": "port 80 open", "target": "A", "metadata": {"category": "recon"}, "similarity": 0.5},
        ]
        result = memory.get_context("A")
        assert "port 80" in result

    def test_with_skills(self, memory, mock_vector, mock_learning):
        mock_vector.search.return_value = []
        mock_learning.rank_tools.return_value = [("nmap", 0.85, 10)]
        result = memory.get_context("A")
        assert isinstance(result, str)

    def test_no_past_memories(self, memory, mock_vector):
        mock_vector.search.return_value = []
        result = memory.get_context("new.target")
        assert "No past memories" in result

    def test_formats_skill_header(self, memory, mock_vector):
        mock_vector.search.return_value = [
            {"content": "secret", "target": "x", "metadata": {}, "similarity": 0.9},
        ]
        result = memory.get_context("x")
        assert "PAST SESSION MEMORIES" in result


# ===================================================================
# AddMemory (internal helper)
# ===================================================================


class TestAddMemory:
    def test_delegates_to_vector(self, memory, mock_vector):
        memory._add_memory("test content", "target.com", "test")
        mock_vector.add_memory.assert_called_once_with(
            content="test content",
            target="target.com",
            category="test",
            metadata=None,
        )

    def test_no_vector_returns_none(self, mock_vector, mock_vm_module, mock_learning, mock_le_module):
        mock_vm_module.VectorMemory.return_value = mock_vector
        mock_le_module.LearningEngine.return_value = mock_learning
        mem = AgentMemory()
        mem._vector = None
        result = mem._add_memory("x", "t", "c")
        assert result is None

    def test_metadata_passed(self, memory, mock_vector):
        extra = {"port": 443}
        memory._add_memory("scan result", "host", "recon", metadata=extra)
        mock_vector.add_memory.assert_called_once_with(
            content="scan result",
            target="host",
            category="recon",
            metadata=extra,
        )

    def test_exception_returns_none(self, memory, mock_vector):
        mock_vector.add_memory.side_effect = RuntimeError("db locked")
        result = memory._add_memory("x", "t", "c")
        assert result is None

    def test_returns_memory_id(self, memory, mock_vector):
        result = memory._add_memory("x", "t", "c")
        assert result == "mem_abc123"
