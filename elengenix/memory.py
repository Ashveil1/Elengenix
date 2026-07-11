"""elengenix/memory.py - Cognitive Memory System"""

from __future__ import annotations

import asyncio
import json
import logging
import sqlite3
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
from uuid import uuid4

import chromadb
from chromadb.config import Settings

from .types import Finding, MissionContext

logger = logging.getLogger("elengenix.memory")


@dataclass
class MemoryEntry:
    """Memory Entry"""
    id: str = field(default_factory=lambda: str(uuid4()))
    content: str = ""
    category: str = "general"  # working, episodic, semantic, constitutional
    importance: float = 0.5
    tags: List[str] = field(default_factory=list)
    metadata: Dict = field(default_factory=dict)
    embedding: Optional[List[float]] = None
    created_at: float = field(default_factory=lambda: datetime.now().timestamp())
    accessed_at: float = field(default_factory=lambda: datetime.now().timestamp())
    access_count: int = 0


class MemoryBackend(ABC):
    """Abstract Memory Backend"""

    @abstractmethod
    async def store(self, entry: "MemoryEntry") -> str:
        pass

    @abstractmethod
    async def retrieve(self, query: str, limit: int = 10, category: Optional[str] = None) -> List["MemoryEntry"]:
        pass

    @abstractmethod
    async def delete(self, entry_id: str) -> bool:
        pass

    @abstractmethod
    async def close(self):
        pass


class VectorMemoryBackend(MemoryBackend):
    """ChromaDB Vector Memory Backend"""

    def __init__(self, persist_dir: str = "./data/memory"):
        self.persist_dir = Path(persist_dir)
        self.persist_dir.mkdir(parents=True, exist_ok=True)

        self.client = chromadb.PersistentClient(
            path=str(self.persist_dir),
            settings=Settings(anonymized_telemetry=False)
        )

        # Collections for different memory types
        self.working = self.client.get_or_create_collection("working_memory")
        self.episodic = self.client.get_or_create_collection("episodic_memory")
        self.semantic = self.client.get_or_create_collection("semantic_memory")
        self.constitutional = self.client.get_or_create_collection("constitutional_memory")

    async def store(self, entry: "MemoryEntry") -> str:
        collection = self._get_collection(entry.category)

        if entry.embedding is None:
            # Generate embedding - placeholder
            entry.embedding = [0.0] * 384  # MiniLM embedding size

        collection.add(
            ids=[entry.id],
            documents=[entry.content],
            embeddings=[entry.embedding],
            metadatas=[{
                "category": entry.category,
                "importance": entry.importance,
                "tags": json.dumps(entry.tags),
                "metadata": json.dumps(entry.metadata),
                "created_at": entry.created_at,
                "accessed_at": entry.accessed_at,
                "access_count": entry.access_count
            }]
        )
        return entry.id

    def _get_collection(self, category: str):
        mapping = {
            "working": self.working,
            "episodic": self.episodic,
            "semantic": self.semantic,
            "constitutional": self.constitutional,
        }
        return mapping.get(category, self.working)

    async def retrieve(self, query: str, limit: int = 10, category: Optional[str] = None) -> List["MemoryEntry"]:
        # Simplified - in production use actual embedding search
        if category:
            collection = self._get_collection(category)
        else:
            collection = self.working

        # Placeholder - use actual vector search in production
        results = collection.query(query_texts=[query], n_results=limit)
        return self._parse_results(results)

    def _parse_results(self, results) -> List["MemoryEntry"]:
        entries = []
        for i, doc_id in enumerate(results.get("ids", [[]])[0]):
            metadata = results.get("metadatas", [[]])[0][i]
            entries.append(MemoryEntry(
                id=doc_id,
                content=results.get("documents", [[]])[0][i],
                category=metadata.get("category", "general"),
                importance=metadata.get("importance", 0.5),
                tags=json.loads(metadata.get("tags", "[]")),
                metadata=json.loads(metadata.get("metadata", "{}")),
                created_at=metadata.get("created_at", 0),
                accessed_at=metadata.get("accessed_at", 0),
                access_count=metadata.get("access_count", 0)
            ))
        return entries

    async def delete(self, entry_id: str) -> bool:
        for collection in [self.working, self.episodic, self.semantic, self.constitutional]:
            try:
                collection.delete(ids=[entry_id])
                return True
            except:
                pass
        return False

    async def close(self):
        pass


class SQLiteMemoryBackend(MemoryBackend):
    """SQLite FTS5 Memory Backend"""

    def __init__(self, db_path: str = "./data/memory.db"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS memory (
                    id TEXT PRIMARY KEY,
                    content TEXT NOT NULL,
                    category TEXT NOT NULL,
                    importance REAL,
                    tags TEXT,
                    metadata TEXT,
                    created_at REAL,
                    accessed_at REAL,
                    access_count INTEGER DEFAULT 0
                )
            """)
            conn.execute("""
                CREATE VIRTUAL TABLE IF NOT EXISTS memory_fts
                USING fts5(content, tags, metadata, content='memory', content_rowid='rowid')
            """)
            conn.commit()

    async def store(self, entry: "MemoryEntry") -> str:
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """INSERT OR REPLACE INTO memory
                (id, content, category, importance, tags, metadata, created_at, accessed_at, access_count)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (entry.id, entry.content, entry.category, entry.importance,
                 json.dumps(entry.tags), json.dumps(entry.metadata),
                 entry.created_at, entry.accessed_at, entry.access_count)
            )
            conn.commit()
        return entry.id

    async def retrieve(self, query: str, limit: int = 10, category: Optional[str] = None) -> List["MemoryEntry"]:
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            if category:
                cursor = conn.execute(
                    "SELECT * FROM memory WHERE category=? AND content MATCH ? ORDER BY importance DESC, access_count DESC LIMIT ?",
                    (category, query, limit)
                )
            else:
                cursor = conn.execute(
                    "SELECT * FROM memory WHERE content MATCH ? ORDER BY importance DESC, access_count DESC LIMIT ?",
                    (query, limit)
                )
            rows = cursor.fetchall()
            return [self._row_to_entry(row) for row in rows]

    def _row_to_entry(self, row) -> "MemoryEntry":
        return MemoryEntry(
            id=row["id"],
            content=row["content"],
            category=row["category"],
            importance=row["importance"],
            tags=json.loads(row["tags"]) if row["tags"] else [],
            metadata=json.loads(row["metadata"]) if row["metadata"] else {},
            created_at=row["created_at"],
            accessed_at=row["accessed_at"],
            access_count=row["access_count"]
        )

    async def delete(self, entry_id: str) -> bool:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("DELETE FROM memory WHERE id=?", (entry_id,))
            conn.commit()
            return cursor.rowcount > 0

    async def close(self):
        pass


@dataclass
class MemoryEntry:
    """Memory Entry"""
    id: str = field(default_factory=lambda: str(uuid4()))
    content: str = ""
    category: str = "general"  # working, episodic, semantic, constitutional
    importance: float = 0.5
    tags: List[str] = field(default_factory=list)
    metadata: Dict = field(default_factory=dict)
    embedding: Optional[List[float]] = None
    created_at: float = field(default_factory=lambda: datetime.now().timestamp())
    accessed_at: float = field(default_factory=lambda: datetime.now().timestamp())
    access_count: int = 0


class CognitiveMemoryManager:
    """Cognitive Memory Manager - Unified Memory Interface"""

    def __init__(self, backends: Optional[List["MemoryBackend"]] = None, config: Optional[Dict] = None):
        self.config = config or {}
        self.backends = backends or [
            SQLiteMemoryBackend(self.config.get("sqlite_path", "./data/memory.db")),
            VectorMemoryBackend(self.config.get("vector_path", "./data/memory"))
        ]
        self._cache: Dict[str, MemoryEntry] = {}
        self._lock = asyncio.Lock()

    async def remember(
        self,
        content: str,
        target: str = "global",
        category: str = "general",
        importance: float = 0.5,
        tags: List[str] = None,
        **metadata
    ) -> str:
        """Store memory"""
        entry = MemoryEntry(
            content=content,
            category=category,
            importance=importance,
            tags=tags or [],
            metadata={"target": target, **metadata}
        )

        # Store in all backends
        for backend in self.backends:
            await backend.store(entry)

        return entry.id

    async def recall(
        self,
        query: str,
        target: str = "global",
        category: Optional[str] = None,
        limit: int = 10
    ) -> List[MemoryEntry]:
        """Recall memories"""
        all_results = []
        for backend in self.backends:
            try:
                results = await backend.retrieve(query, limit=limit, category=category)
                all_results.extend(results)
            except Exception as e:
                logger.debug(f"Memory backend error: {e}")

        # Deduplicate and sort by importance
        seen = set()
        unique = []
        for entry in all_results:
            if entry.id not in seen:
                seen.add(entry.id)
                unique.append(entry)

        return sorted(unique, key=lambda x: x.importance, reverse=True)[:limit]

    async def get_context_for_ai(self, target: str = "global", query: str = "") -> str:
        """Get formatted context for AI"""
        memories = await self.recall(query=query or "recent activity", limit=20)
        if not memories:
            return "No relevant memories."

        lines = ["RELEVANT MEMORIES:"]
        for mem in memories[:15]:
            tags = f" [{', '.join(mem.tags)}]" if mem.tags else ""
            lines.append(f"- {mem.content[:200]}...{tags} (importance: {mem.importance:.1f})")

        return "\n".join(lines)

    async def close(self):
        for backend in self.backends:
            await backend.close()