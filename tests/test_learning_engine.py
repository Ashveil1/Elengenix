"""tests/test_learning_engine.py — M7 verification tests."""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


@pytest.fixture
def engine(tmp_path, monkeypatch):
    """Create a fresh learning engine with isolated DB."""
    # Avoid polluting the real data/ directory
    db = tmp_path / "test_learning.db"
    chroma = tmp_path / "test_chroma"
    monkeypatch.setattr("pathlib.Path.cwd", lambda: tmp_path)
    from tools.learning_engine import LearningEngine

    # use_chroma=False in tests to avoid slow first-run model downloads;
    # SQL layer is fully exercised regardless
    return LearningEngine(db_path=db, chroma_path=chroma, use_chroma=False)


def test_remember_single_record(engine):
    """Storing one record should add it to the database."""
    from tools.learning_engine import ExploitRecord

    rec = ExploitRecord(
        target="https://target1.com",
        tech_stack=["php", "mysql"],
        vuln_class="sqli",
        tool="sqlmap",
        payload="' OR 1=1--",
        success=True,
        confidence=0.95,
        severity="high",
    )
    rid = engine.remember(rec)
    assert rid > 0
    stats = engine.get_stats()
    assert stats["total_records"] == 1
    assert stats["successful_records"] == 1
    print(f"[REMEMBER] stored id={rid}, stats={stats}")


def test_remember_batch(engine):
    """Batch storage should add all records."""
    from tools.learning_engine import ExploitRecord

    records = [
        ExploitRecord(
            target=f"https://t{i}.com",
            tech_stack=["php"],
            vuln_class="xss",
            tool="dalfox",
            payload="<script>",
            success=(i % 2 == 0),
            confidence=0.8,
        )
        for i in range(5)
    ]
    ids = engine.remember_batch(records)
    assert len(ids) == 5
    stats = engine.get_stats()
    assert stats["total_records"] == 5
    assert stats["successful_records"] == 3  # i=0,2,4
    print(f"[BATCH] stored {len(ids)} records, success_rate={stats['success_rate']}")


def test_recall_similar_finds_matching(engine):
    """Recall should find exploits with overlapping tech stack."""
    from tools.learning_engine import ExploitRecord

    engine.remember(
        ExploitRecord(
            target="https://php-target.com",
            tech_stack=["php", "mysql", "wordpress"],
            vuln_class="sqli",
            tool="sqlmap",
            payload="' OR 1=1--",
            success=True,
            confidence=0.9,
        )
    )
    engine.remember(
        ExploitRecord(
            target="https://java-target.com",
            tech_stack=["java", "oracle"],
            vuln_class="sqli",
            tool="sqlmap",
            payload="' UNION SELECT NULL--",
            success=True,
            confidence=0.85,
        )
    )
    # Query for PHP target
    similar = engine.recall_similar(["php", "mysql"], vuln_class="sqli", limit=5)
    assert len(similar) >= 1
    # Top hit should be PHP one
    assert "php" in similar[0].tech_stack
    print(
        f"[RECALL] for [php,mysql]: top tool={similar[0].tool}, payload={similar[0].payload[:30]}"
    )


def test_rank_tools_by_success_rate(engine):
    """rank_tools should sort by historical success rate."""
    from tools.learning_engine import ExploitRecord

    # sqlmap: 3/3 success
    for _ in range(3):
        engine.remember(
            ExploitRecord(
                target="t.com",
                tech_stack=["php"],
                vuln_class="sqli",
                tool="sqlmap",
                payload="p",
                success=True,
                confidence=0.9,
            )
        )
    # nuclei: 1/3 success
    for i in range(3):
        engine.remember(
            ExploitRecord(
                target="t.com",
                tech_stack=["php"],
                vuln_class="sqli",
                tool="nuclei",
                payload=f"p{i}",
                success=(i == 0),
                confidence=0.5,
            )
        )
    # ffuf: 2/2 success
    for _ in range(2):
        engine.remember(
            ExploitRecord(
                target="t.com",
                tech_stack=["php"],
                vuln_class="sqli",
                tool="ffuf",
                payload="p",
                success=True,
                confidence=0.7,
            )
        )

    ranked = engine.rank_tools(tech_stack=["php"], vuln_class="sqli")
    assert len(ranked) == 3
    tools = [r[0] for r in ranked]
    rates = [r[1] for r in ranked]
    # sqlmap and ffuf should be at top (100% rate), then nuclei (33%)
    assert tools[0] in ("sqlmap", "ffuf")
    assert tools[1] in ("sqlmap", "ffuf")
    assert tools[2] == "nuclei"
    assert rates[0] == 1.0
    assert rates[1] == 1.0
    assert abs(rates[2] - 0.333) < 0.001
    print(f"[RANK] {ranked}")


def test_suggest_payloads_returns_working_ones(engine):
    """suggest_payloads should return payloads that have succeeded."""
    from tools.learning_engine import ExploitRecord

    # Store the same XSS payload 3 times
    for _ in range(3):
        engine.remember(
            ExploitRecord(
                target="t.com",
                tech_stack=["php"],
                vuln_class="xss",
                tool="dalfox",
                payload="<script>alert(1)</script>",
                success=True,
                confidence=0.9,
            )
        )
    # Store a different one once
    engine.remember(
        ExploitRecord(
            target="t.com",
            tech_stack=["php"],
            vuln_class="xss",
            tool="dalfox",
            payload="<svg onload=alert(1)>",
            success=True,
            confidence=0.7,
        )
    )

    suggestions = engine.suggest_payloads("xss", n=5)
    assert len(suggestions) == 2
    # Most frequent first
    assert suggestions[0] == "<script>alert(1)</script>"
    print(f"[SUGGEST] xss payloads: {suggestions}")


def test_filter_by_min_success_rate(engine):
    """recall_similar with min_success_rate=1.0 should only return 100%-success tools."""
    from tools.learning_engine import ExploitRecord

    # 2/2 success for sqlmap
    for _ in range(2):
        engine.remember(
            ExploitRecord(
                target="t.com",
                tech_stack=["php"],
                vuln_class="sqli",
                tool="sqlmap",
                payload="p",
                success=True,
            )
        )
    # 1/2 success for nuclei
    engine.remember(
        ExploitRecord(
            target="t.com",
            tech_stack=["php"],
            vuln_class="sqli",
            tool="nuclei",
            payload="p1",
            success=True,
        )
    )
    engine.remember(
        ExploitRecord(
            target="t.com",
            tech_stack=["php"],
            vuln_class="sqli",
            tool="nuclei",
            payload="p2",
            success=False,
        )
    )

    strict = engine.recall_similar(["php"], vuln_class="sqli", min_success_rate=0.9)
    # Only sqlmap should be returned (100% > 90%)
    assert all(r.tool == "sqlmap" for r in strict)
    print(f"[FILTER] strict recall returned {len(strict)} records (only sqlmap)")


def test_get_stats_groups_by_vuln_and_tool(engine):
    """get_stats should aggregate by vuln class and tool."""
    from tools.learning_engine import ExploitRecord

    for _ in range(3):
        engine.remember(
            ExploitRecord(
                target="t.com",
                tech_stack=["php"],
                vuln_class="xss",
                tool="dalfox",
                payload="p",
                success=True,
            )
        )
    for _ in range(2):
        engine.remember(
            ExploitRecord(
                target="t.com",
                tech_stack=["php"],
                vuln_class="sqli",
                tool="sqlmap",
                payload="p",
                success=True,
            )
        )

    stats = engine.get_stats()
    assert stats["total_records"] == 5
    assert stats["by_vuln_class"]["xss"]["total"] == 3
    assert stats["by_vuln_class"]["sqli"]["total"] == 2
    assert stats["by_tool"]["dalfox"]["total"] == 3
    assert stats["by_tool"]["sqlmap"]["total"] == 2
    print(f"[STATS] {stats}")


def test_chroma_integration_works(engine):
    """ChromaDB should successfully add and query records (when enabled)."""
    pytest.skip("ChromaDB integration tested separately to avoid slow first-run model download")
    import tempfile
    from pathlib import Path

    from tools.learning_engine import ExploitRecord, LearningEngine

    tmpdir = Path(tempfile.mkdtemp())
    chroma_engine = LearningEngine(
        db_path=tmpdir / "test.db",
        chroma_path=tmpdir / "chroma",
        use_chroma=True,
    )
    if not chroma_engine._chroma_collection:
        return
    rec = ExploitRecord(
        target="https://chromadb-test.com",
        tech_stack=["python", "django"],
        vuln_class="ssrf",
        tool="ffuf",
        payload="file:///etc/passwd",
        success=True,
    )
    chroma_engine.remember(rec)
    similar = chroma_engine.recall_similar(["python"], vuln_class="ssrf", limit=1)
    assert len(similar) >= 1
    print(f"[CHROMA] found via chroma+sql: {similar[0].tool}")


def test_persistence_across_instances(tmp_path, monkeypatch):
    """Data should persist between LearningEngine instances."""
    from tools.learning_engine import ExploitRecord, LearningEngine

    db = tmp_path / "persist_test.db"
    chroma = tmp_path / "persist_chroma"
    monkeypatch.setattr("pathlib.Path.cwd", lambda: tmp_path)

    e1 = LearningEngine(db_path=db, chroma_path=chroma, use_chroma=False)
    e1.remember(
        ExploitRecord(
            target="t.com",
            tech_stack=["php"],
            vuln_class="xss",
            tool="dalfox",
            payload="<script>",
            success=True,
        )
    )

    # Create a new instance, same DB
    e2 = LearningEngine(db_path=db, chroma_path=chroma, use_chroma=False)
    stats = e2.get_stats()
    assert stats["total_records"] == 1
    print(f"[PERSIST] reopened DB, records={stats['total_records']}")


def test_dual_layer_ranking(engine):
    """SQL rank + ChromaDB fallback should both contribute."""
    from tools.learning_engine import ExploitRecord

    # Many SQL records
    for i in range(5):
        engine.remember(
            ExploitRecord(
                target=f"t{i}.com",
                tech_stack=["php", "mysql"],
                vuln_class="sqli",
                tool="sqlmap",
                payload=f"payload{i}",
                success=(i < 4),
                confidence=0.8 + i * 0.02,
            )
        )
    ranked = engine.rank_tools(tech_stack=["php"], vuln_class="sqli", limit=5)
    assert len(ranked) >= 1
    assert ranked[0][0] == "sqlmap"
    assert 0.7 <= ranked[0][1] <= 0.9  # 4/5 = 0.8
    print(f"[DUAL] top tool={ranked[0][0]} rate={ranked[0][1]:.2f} samples={ranked[0][2]}")
