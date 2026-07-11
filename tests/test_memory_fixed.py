"""Tests for Memory System"""

from __future__ import annotations

import pytest
from unittest.mock import MagicMock, AsyncMock, patch, AsyncMock
import tempfile
import os

from elengenix.memory import (
    MemoryEntry, MemoryBackend, VectorMemoryBackend,
    SQLiteMemoryBackend, CognitiveMemoryManager
)
from elengenix.types import Finding, MissionContext


class TestMemoryFixed:
    """Tests for Memory System"""

    @pytest.fixture
    def temp_db(self):
        """Create temporary database"""
        with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as f:
            db_path = f.name
        yield db_path
        os.unlink(db_path)

    @pytest.fixture
    def sqlite_backend(self, temp_db):
        from elengenix.memory import SQLiteMemoryBackend
        return SQLiteMemoryBackend(temp_db)

    @pytest.mark.asyncio
    async def test_sqlite_store_retrieve(self, sqlite_backend):
        from elengenix.memory import MemoryEntry

        entry = MemoryEntry(
            content="Test memory content",
            category="episodic",
            importance=0.8,
            tags=["test", "security"],
            metadata={"target": "example.com"}
        )

        entry_id = await sqlite_backend.store(entry)
        assert entry_id is not None

        results = await sqlite_backend.retrieve("memory content", limit=5)
        assert len(results) > 0
        assert results[0].content == "Test memory content"

    @pytest.mark.asyncio
    async def test_sqlite_delete(self, sqlite_backend):
        from elengenix.memory import MemoryEntry

        entry = MemoryEntry(content="To delete", category="test")
        entry_id = await sqlite_backend.store(entry)

        deleted = await sqlite_backend.delete(entry_id)
        assert deleted is True

        results = await sqlite_backend.retrieve("To delete", limit=10)
        assert len(results) == 0

    @pytest.mark.asyncio
    async def test_memory_manager_remember_recall(self):
        manager = CognitiveMemoryManager()

        entry_id = await manager.remember(
            content="Test learning",
            target="example.com",
            category="episodic",
            importance=0.8,
            tags=["test", "learning"]
        )

        assert entry_id is not None

        results = await manager.recall("learning", target="example.com", limit=5)
        assert len(results) > 0
        assert "learning" in results[0].content.lower()

    @pytest.mark.asyncio
    async def test_get_context_for_ai(self):
        manager = CognitiveMemoryManager()

        await manager.remember(
            content="Found SQLi in login form",
            target="example.com",
            category="semantic",
            importance=0.9,
            tags=["sqli", "vulnerability"]
        )

        context = await manager.get_context_for_ai(target="example.com", query="SQLi")
        assert "SQLi" in context
        assert "login" in context.lower()