"""
Tests for elengenix/agent/agent_skills.py — SkillStore CRUD + persistence.
"""

import json
import os
import sys
import tempfile
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from elengenix.agent.agent_skills import SkillStore


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_store(tmp_dir: str) -> tuple[SkillStore, Path]:
    """Create a SkillStore pointed at a temp directory.

    Returns (store, data_dir) so the caller can inspect the backing file.
    """
    data_dir = Path(tmp_dir) / ".elengenix" / "data"
    with patch("elengenix.agent.agent_skills.ELENGENIX_HOME", Path(tmp_dir) / ".elengenix"):
        store = SkillStore()
        # Force _loaded=False so _load picks up our patched path
        store._loaded = False
        store._SKILLS_DIR = data_dir
        store._SKILLS_FILE = data_dir / "skills.json"
    return store, data_dir


# ---------------------------------------------------------------------------
# Constructor & lazy loading
# ---------------------------------------------------------------------------


class TestSkillStoreInit:
    def test_default_state(self):
        store = SkillStore()
        assert store._skills == {}
        assert store._loaded is False

    def test_lazy_load_creates_dir(self):
        with tempfile.TemporaryDirectory() as tmp:
            store, data_dir = _make_store(tmp)
            # Access triggers _load → mkdir
            _ = store.count()
            assert data_dir.exists()

    def test_lazy_load_creates_nothing_on_init(self):
        """Constructor should not create directories."""
        store = SkillStore()
        assert store._loaded is False
        assert store._skills == {}
        # No side effects until first access


# ---------------------------------------------------------------------------
# CRUD — save
# ---------------------------------------------------------------------------


class TestSkillStoreSave:
    def test_creates_entry(self):
        with tempfile.TemporaryDirectory() as tmp:
            store, data_dir = _make_store(tmp)
            result = store.save("sqlmap", "Run sqlmap scans", "sqlmap -u <target> --batch")

            assert result["name"] == "sqlmap"
            assert result["description"] == "Run sqlmap scans"
            assert result["content"] == "sqlmap -u <target> --batch"
            assert "created" in result
            assert "updated" in result
            assert result["created"] == result["updated"]  # first save

    def test_sets_created_and_updated(self):
        with tempfile.TemporaryDirectory() as tmp:
            store, _ = _make_store(tmp)
            before = time.time() - 0.1
            result = store.save("nmap", "Quick scan", "nmap -sV target")
            after = time.time() + 0.1
            assert before <= result["created"] <= after
            assert before <= result["updated"] <= after

    def test_update_preserves_created(self):
        with tempfile.TemporaryDirectory() as tmp:
            store, _ = _make_store(tmp)
            orig = store.save("skill_a", "desc1", "content1")
            time.sleep(0.01)
            updated = store.save("skill_a", "desc2", "content2")

            assert updated["name"] == "skill_a"
            assert updated["description"] == "desc2"
            assert updated["content"] == "content2"
            assert updated["created"] == orig["created"]  # preserved
            assert updated["updated"] > orig["updated"]

    def test_save_writes_to_disk(self):
        with tempfile.TemporaryDirectory() as tmp:
            store, data_dir = _make_store(tmp)
            store.save("test_skill", "test desc", "test content")

            assert data_dir.joinpath("skills.json").exists()
            raw = json.loads(data_dir.joinpath("skills.json").read_text(encoding="utf-8"))
            assert "skills" in raw
            assert "test_skill" in raw["skills"]

    def test_save_multiple_skills(self):
        with tempfile.TemporaryDirectory() as tmp:
            store, _ = _make_store(tmp)
            store.save("a", "desc a", "content a")
            store.save("b", "desc b", "content b")
            assert store.count() == 2


# ---------------------------------------------------------------------------
# CRUD — get
# ---------------------------------------------------------------------------


class TestSkillStoreGet:
    def test_returns_skill(self):
        with tempfile.TemporaryDirectory() as tmp:
            store, _ = _make_store(tmp)
            store.save("my_skill", "my desc", "my content")
            result = store.get("my_skill")
            assert result is not None
            assert result["name"] == "my_skill"
            assert result["description"] == "my desc"
            assert result["content"] == "my content"

    def test_returns_none_for_missing(self):
        with tempfile.TemporaryDirectory() as tmp:
            store, _ = _make_store(tmp)
            assert store.get("nonexistent") is None

    def test_returns_copy_not_reference(self):
        """get() should return a dict copy, not the internal reference."""
        with tempfile.TemporaryDirectory() as tmp:
            store, _ = _make_store(tmp)
            store.save("x", "desc", "content")
            result = store.get("x")
            result["name"] = "hacked"
            # Internal should be unchanged
            internal = store._skills["x"]
            assert internal["name"] == "x"


# ---------------------------------------------------------------------------
# CRUD — list_all
# ---------------------------------------------------------------------------


class TestSkillStoreListAll:
    def test_empty_when_no_skills(self):
        with tempfile.TemporaryDirectory() as tmp:
            store, _ = _make_store(tmp)
            assert store.list_all() == []

    def test_returns_sorted_skills(self):
        with tempfile.TemporaryDirectory() as tmp:
            store, _ = _make_store(tmp)
            store.save("z_skill", "desc", "content")
            store.save("a_skill", "desc", "content")
            store.save("m_skill", "desc", "content")

            skills = store.list_all()
            names = [s["name"] for s in skills]
            assert names == ["a_skill", "m_skill", "z_skill"]

    def test_each_entry_has_all_fields(self):
        with tempfile.TemporaryDirectory() as tmp:
            store, _ = _make_store(tmp)
            store.save("s1", "d1", "c1")
            store.save("s2", "d2", "c2")

            for entry in store.list_all():
                assert "name" in entry
                assert "description" in entry
                assert "content" in entry
                assert "created" in entry
                assert "updated" in entry


# ---------------------------------------------------------------------------
# CRUD — delete
# ---------------------------------------------------------------------------


class TestSkillStoreDelete:
    def test_removes_skill(self):
        with tempfile.TemporaryDirectory() as tmp:
            store, _ = _make_store(tmp)
            store.save("to_remove", "desc", "content")
            assert store.count() == 1

            result = store.delete("to_remove")
            assert result is True
            assert store.count() == 0
            assert store.get("to_remove") is None

    def test_returns_false_for_missing(self):
        with tempfile.TemporaryDirectory() as tmp:
            store, _ = _make_store(tmp)
            assert store.delete("nonexistent") is False

    def test_delete_writes_to_disk(self):
        with tempfile.TemporaryDirectory() as tmp:
            store, data_dir = _make_store(tmp)
            store.save("temp_skill", "desc", "content")
            store.save("keep_skill", "desc", "content")
            store.delete("temp_skill")

            raw = json.loads(data_dir.joinpath("skills.json").read_text(encoding="utf-8"))
            assert "keep_skill" in raw["skills"]
            assert "temp_skill" not in raw["skills"]


# ---------------------------------------------------------------------------
# CRUD — count
# ---------------------------------------------------------------------------


class TestSkillStoreCount:
    def test_starts_at_zero(self):
        with tempfile.TemporaryDirectory() as tmp:
            store, _ = _make_store(tmp)
            assert store.count() == 0

    def test_increments_with_saves(self):
        with tempfile.TemporaryDirectory() as tmp:
            store, _ = _make_store(tmp)
            assert store.count() == 0
            store.save("a", "d", "c")
            assert store.count() == 1
            store.save("b", "d", "c")
            assert store.count() == 2

    def test_decrements_with_delete(self):
        with tempfile.TemporaryDirectory() as tmp:
            store, _ = _make_store(tmp)
            store.save("a", "d", "c")
            store.save("b", "d", "c")
            assert store.count() == 2
            store.delete("a")
            assert store.count() == 1


# ---------------------------------------------------------------------------
# Persistence across instances
# ---------------------------------------------------------------------------


class TestSkillStorePersistence:
    def test_saves_survive_instance_recreation(self):
        with tempfile.TemporaryDirectory() as tmp:
            data_dir = Path(tmp) / ".elengenix" / "data"

            # First instance
            with patch("elengenix.agent.agent_skills.ELENGENIX_HOME", Path(tmp) / ".elengenix"):
                s1 = SkillStore()
                s1._loaded = False
                s1._SKILLS_DIR = data_dir
                s1._SKILLS_FILE = data_dir / "skills.json"
                s1.save("persisted", "desc", "content")

            # Second instance — _SKILLS_DIR/_SKILLS_FILE are class-level attributes
            # computed at import time, so we must override them on the instance
            s2 = SkillStore()
            s2._loaded = False
            s2._SKILLS_DIR = data_dir
            s2._SKILLS_FILE = data_dir / "skills.json"
            assert s2.count() == 1
            assert s2.get("persisted") is not None


# ---------------------------------------------------------------------------
# Error handling
# ---------------------------------------------------------------------------


class TestSkillStoreErrors:
    def test_corrupt_json_file(self, caplog):
        """Should handle corrupted skills.json gracefully."""
        with tempfile.TemporaryDirectory() as tmp:
            data_dir = Path(tmp) / ".elengenix" / "data"
            data_dir.mkdir(parents=True, exist_ok=True)
            skills_file = data_dir / "skills.json"
            skills_file.write_text("this is not json", encoding="utf-8")

            with patch("elengenix.agent.agent_skills.ELENGENIX_HOME", Path(tmp) / ".elengenix"):
                store = SkillStore()
                store._loaded = False
                store._SKILLS_DIR = data_dir
                store._SKILLS_FILE = skills_file
                # Should not raise
                assert store.count() == 0
                assert store._skills == {}

    def test_save_os_error(self):
        """Should not crash when write_text fails."""
        with tempfile.TemporaryDirectory() as tmp:
            store, data_dir = _make_store(tmp)
            # _save returns False on OSError; save() still returns the entry
            with patch.object(Path, "write_text", side_effect=OSError("mock error")):
                result = store.save("oops", "desc", "content")
                assert result is not None
                assert result["name"] == "oops"
