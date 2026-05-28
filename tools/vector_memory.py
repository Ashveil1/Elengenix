"""
tools/vector_memory.py — Semantic Vector Memory System (v99999 (god nine is the best))
- ChromaDB-based vector storage for persistent AI memory
- SQLite FTS5 fallback (built-in, zero deps) when ChromaDB unavailable
- Semantic search: finds similar, not exact matches
- Remembers every conversation, finding, decision permanently
- Cross-session memory: remembers even after restart
"""

import logging
import hashlib
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, asdict

logger = logging.getLogger("elengenix.vector_memory")

# Try to import ChromaDB, fallback to SQLite FTS5 if not available
try:
    import chromadb
    from chromadb.config import Settings
    CHROMADB_AVAILABLE = True
except ImportError:
    CHROMADB_AVAILABLE = False
    logger.info("ChromaDB not installed — using SQLite FTS5 fallback (zero deps).")


@dataclass
class MemoryEntry:
    """Single memory entry with metadata."""
    id: str
    content: str  # Text to embed (searchable)
    target: str   # target domain/IP
    category: str # finding, conversation, decision, tool_result
    timestamp: str
    metadata: Dict[str, Any]  # Additional metadata
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class VectorMemory:
    """
    Semantic vector memory using ChromaDB.
    Remembers everything, searches by semantic similarity.
    """
    
    def __init__(self, persist_directory: str = None):
        self.persist_dir = Path(persist_directory) if persist_directory else \
                          Path(__file__).parent.parent / "data" / "vector_memory"
        self.persist_dir.mkdir(parents=True, exist_ok=True)
        
        self.client = None
        self.collection = None
        self._initialized = False
        
        if CHROMADB_AVAILABLE:
            try:
                self._init_chromadb()
            except Exception as e:
                logger.error(f"Failed to init ChromaDB: {e}")
                self._initialized = False
    
    def _init_chromadb(self):
        """Initialize ChromaDB client and collection."""
        self.client = chromadb.Client(
            Settings(
                persist_directory=str(self.persist_dir),
                anonymized_telemetry=False,
                is_persistent=True,
            )
        )
        
        # Get or create collection for Elengenix memories
        self.collection = self.client.get_or_create_collection(
            name="elengenix_memories",
            metadata={"description": "Persistent AI memory for Elengenix"}
        )
        
        self._initialized = True
        logger.info(f"VectorMemory initialized at {self.persist_dir}")
    
    def _generate_id(self, content: str, target: str, timestamp: str) -> str:
        """Generate unique ID from content hash."""
        hash_input = f"{content}{target}{timestamp}"
        return hashlib.md5(hash_input.encode()).hexdigest()[:16]
    
    def add_memory(
        self,
        content: str,
        target: str,
        category: str = "general",
        metadata: Dict[str, Any] = None
    ) -> str:
        """
        Add a new memory to the vector database.
        
        Args:
            content: Text content to remember (will be embedded)
            target: Associated target domain/IP
            category: Type (finding, conversation, decision, tool_result)
            metadata: Additional metadata
            
        Returns:
            memory_id: ID of the saved memory
        """
        if not self._initialized:
            logger.warning("VectorMemory not initialized, storing in SQLite fallback")
            return self._fallback_add(content, target, category, metadata)
        
        timestamp = datetime.now(timezone.utc).isoformat()
        memory_id = self._generate_id(content, target, timestamp)
        
        # Build document for embedding
        doc = content
        
        # Build metadata
        meta = {
            "target": target.lower().strip(),
            "category": category.lower(),
            "timestamp": timestamp,
            **(metadata or {})
        }
        
        try:
            self.collection.add(
                ids=[memory_id],
                documents=[doc],
                metadatas=[meta],
            )
            logger.debug(f"Added memory: {memory_id[:8]}... for {target}")
            return memory_id
        except Exception as e:
            logger.error(f"Failed to add memory: {e}")
            return self._fallback_add(content, target, category, metadata)
    
    def search(
        self,
        query: str,
        target: str = None,
        category: str = None,
        n_results: int = 10,
        min_similarity: float = 0.4
    ) -> List[Dict[str, Any]]:
        """
        Search for memories similar to the query (semantic search).
        
        Args:
            query: Search query text
            target: Filter for specific target (optional)
            category: Filter for specific category (optional)
            n_results: Number of results desired
            min_similarity: Minimum similarity threshold (0-1)
            
        Returns:
            List of matching memories with similarity scores
        """
        if not self._initialized:
            logger.warning("VectorMemory not initialized, using fallback search")
            return self._fallback_search(query, target, category, n_results)
        
        # Build where clause for filtering
        where_clause = {}
        if target:
            where_clause["target"] = target.lower().strip()
        if category:
            where_clause["category"] = category.lower()
        
        try:
            results = self.collection.query(
                query_texts=[query],
                n_results=n_results,
                where=where_clause if where_clause else None,
            )
            
            # Format results
            memories = []
            if results["ids"] and results["ids"][0]:
                for i, mem_id in enumerate(results["ids"][0]):
                    distance = results["distances"][0][i] if results["distances"] else 1.0
                    similarity = 1.0 - (distance / 2)  # Convert distance to similarity
                    
                    if similarity >= min_similarity:
                        memories.append({
                            "id": mem_id,
                            "content": results["documents"][0][i] if results["documents"] else "",
                            "metadata": results["metadatas"][0][i] if results["metadatas"] else {},
                            "similarity": similarity,
                        })
            
            return memories
            
        except Exception as e:
            logger.error(f"Search failed: {e}")
            return self._fallback_search(query, target, category, n_results)
    
    def get_target_memories(
        self,
        target: str,
        category: str = None,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """
        Get all memories for a specific target.
        
        Args:
            target: Target domain/IP
            category: Filter for specific category (optional)
            limit: Maximum number of results
        """
        if not self._initialized:
            return self._fallback_get_target(target, category, limit)
        
        where_clause = {"target": target.lower().strip()}
        if category:
            where_clause["category"] = category.lower()
        
        try:
            results = self.collection.get(
                where=where_clause,
                limit=limit,
            )
            
            memories = []
            if results["ids"]:
                for i, mem_id in enumerate(results["ids"]):
                    memories.append({
                        "id": mem_id,
                        "content": results["documents"][i] if results["documents"] else "",
                        "metadata": results["metadatas"][i] if results["metadatas"] else {},
                    })
            
            # Sort by timestamp (newest first)
            memories.sort(
                key=lambda x: x["metadata"].get("timestamp", ""),
                reverse=True
            )
            
            return memories
            
        except Exception as e:
            logger.error(f"Get target memories failed: {e}")
            return self._fallback_get_target(target, category, limit)
    
    def get_all_targets(self) -> List[str]:
        """Get list of all targets stored in memory."""
        if not self._initialized:
            return []
        
        try:
            results = self.collection.get(limit=10000)
            targets = set()
            
            if results["metadatas"]:
                for meta in results["metadatas"]:
                    if meta and "target" in meta:
                        targets.add(meta["target"])
            
            return sorted(list(targets))
        except Exception as e:
            logger.error(f"Get all targets failed: {e}")
            return []
    
    def delete_target_memories(self, target: str) -> int:
        """Delete all memories for a specific target."""
        if not self._initialized:
            return self._fallback_delete_target(target)

        try:
            self.collection.delete(
                where={"target": target.lower().strip()}
            )
            logger.info(f"Deleted all memories for {target}")
            return 1
        except Exception as e:
            logger.error(f"Delete failed: {e}")
            return 0
    
    def get_memory_stats(self) -> Dict[str, Any]:
        """Get memory database statistics."""
        if not self._initialized:
            return self._fallback_stats()
        
        try:
            count = self.collection.count()
            targets = self.get_all_targets()
            
            return {
                "status": "active",
                "total_memories": count,
                "unique_targets": len(targets),
                "targets": targets[:20],  # Show only first 20
                "persist_directory": str(self.persist_dir),
            }
        except Exception as e:
            logger.error(f"Stats failed: {e}")
            return {"status": "error", "error": str(e)}
    
    # ═════════════════════════════════════════════════════════════════
    # FALLBACK: SQLite FTS5 mode (when ChromaDB is unavailable)
    # ═════════════════════════════════════════════════════════════════
    #
    # SQLite FTS5 (Full-Text Search v5) is built into Python's sqlite3
    # module — no extra dependencies.  It provides BM25-ranked keyword
    # search, which is vastly better than a single "summary blob".
    # ═════════════════════════════════════════════════════════════════

    _FTS_DB_PATH: Optional[Path] = None

    def _fts_db(self) -> Path:
        if self._FTS_DB_PATH is None:
            self.__class__._FTS_DB_PATH = self.persist_dir / "fts_memory.db"
        return self._FTS_DB_PATH

    def _init_fts(self) -> None:
        """Create the FTS5 table if it does not exist."""
        self.persist_dir.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(str(self._fts_db())) as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("""
                CREATE VIRTUAL TABLE IF NOT EXISTS memories_fts USING fts5(
                    content,
                    target     UNINDEXED,
                    category   UNINDEXED,
                    timestamp  UNINDEXED,
                    metadata   UNINDEXED,
                    tokenize='unicode61'
                )
            """)

    def _fallback_add(
        self,
        content: str,
        target: str,
        category: str = "general",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Optional[str]:
        """Store a memory in the FTS5 index with deduplication."""
        try:
            self._init_fts()
            timestamp = datetime.now(timezone.utc).isoformat()
            memory_id = self._generate_id(content, target, timestamp)
            rowid = int(memory_id, 16) % (2**63)

            with sqlite3.connect(str(self._fts_db())) as conn:
                # Check for duplicate by rowid (derived from content hash)
                existing = conn.execute(
                    "SELECT 1 FROM memories_fts WHERE rowid = ?", (rowid,)
                ).fetchone()
                if existing:
                    logger.debug(f"[FTS] Duplicate memory skipped: {memory_id[:8]}...")
                    return memory_id

                conn.execute(
                    "INSERT INTO memories_fts (rowid, content, target, category, timestamp, metadata) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (rowid, content, target.lower().strip(),
                     category.lower(), timestamp, json.dumps(metadata or {}, ensure_ascii=False)),
                )
            logger.debug(f"[FTS] Added memory: {memory_id[:8]}... for {target}")
            return memory_id
        except Exception as e:
            logger.error(f"[FTS] Add failed: {e}")
            return None

    def _fallback_search(
        self,
        query: str,
        target: Optional[str] = None,
        category: Optional[str] = None,
        n_results: int = 10,
    ) -> List[Dict[str, Any]]:
        """Full-text search via FTS5 with BM25 ranking."""
        fts_db = self._fts_db()
        if not fts_db.exists():
            return []
        try:
            self._init_fts()
            # Build FTS5 query: prefix each word with + for AND matching
            words = query.split()
            safe_query = " ".join(f'"+{w}"' for w in words if w) or query

            sql = (
                "SELECT rowid, content, target, category, timestamp, metadata, "
                "       rank "
                "FROM memories_fts "
                "WHERE memories_fts MATCH ? "
            )
            params: List[Any] = [safe_query]

            if target:
                sql += "AND target = ? "
                params.append(target.lower().strip())
            if category:
                sql += "AND category = ? "
                params.append(category.lower())

            sql += "ORDER BY rank LIMIT ?"
            params.append(n_results)

            with sqlite3.connect(str(fts_db)) as conn:
                rows = conn.execute(sql, params).fetchall()

            results = []
            for rowid, content, tgt, cat, ts, meta_json, rank in rows:
                meta = json.loads(meta_json) if meta_json else {}
                meta.update({"target": tgt, "category": cat, "timestamp": ts})
                # Convert FTS5 rank (0 = perfect match) to similarity (0-1)
                similarity = max(0.0, min(1.0, 1.0 - rank / 10.0))
                results.append({
                    "id": str(rowid),
                    "content": content,
                    "metadata": meta,
                    "similarity": similarity,
                })

            return results
        except Exception as e:
            logger.error(f"[FTS] Search failed: {e}")
            return []

    def _fallback_get_target(
        self,
        target: str,
        category: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """Get all memories for a target from FTS5."""
        fts_db = self._fts_db()
        if not fts_db.exists():
            return []
        try:
            self._init_fts()
            sql = "SELECT rowid, content, target, category, timestamp, metadata FROM memories_fts WHERE target = ?"
            params: List[Any] = [target.lower().strip()]
            if category:
                sql += " AND category = ?"
                params.append(category.lower())
            sql += " ORDER BY rowid DESC LIMIT ?"
            params.append(limit)

            with sqlite3.connect(str(fts_db)) as conn:
                rows = conn.execute(sql, params).fetchall()

            results = []
            for rowid, content, tgt, cat, ts, meta_json in rows:
                meta = json.loads(meta_json) if meta_json else {}
                meta.update({"target": tgt, "category": cat, "timestamp": ts})
                results.append({
                    "id": str(rowid),
                    "content": content,
                    "metadata": meta,
                })
            return results
        except Exception as e:
            logger.error(f"[FTS] Get target failed: {e}")
            return []

    def _fallback_delete_target(self, target: str) -> int:
        """Delete all memories for a target from FTS5."""
        fts_db = self._fts_db()
        if not fts_db.exists():
            return 0
        try:
            self._init_fts()
            with sqlite3.connect(str(fts_db)) as conn:
                cursor = conn.execute(
                    "DELETE FROM memories_fts WHERE target = ?",
                    (target.lower().strip(),),
                )
                return cursor.rowcount
        except Exception as e:
            logger.error(f"[FTS] Delete failed: {e}")
            return 0

    def _fallback_stats(self) -> Dict[str, Any]:
        """Get statistics from FTS5 store."""
        fts_db = self._fts_db()
        if not fts_db.exists():
            return {"status": "fallback_uninitialized", "count": 0}
        try:
            self._init_fts()
            with sqlite3.connect(str(fts_db)) as conn:
                count = conn.execute("SELECT COUNT(*) FROM memories_fts").fetchone()[0]
                targets = [
                    r[0] for r in conn.execute(
                        "SELECT DISTINCT target FROM memories_fts ORDER BY target"
                    ).fetchall()
                ]
            return {
                "status": "fallback_fts5",
                "total_memories": count,
                "unique_targets": len(targets),
                "targets": targets[:20],
                "persist_directory": str(self.persist_dir),
            }
        except Exception as e:
            return {"status": "error", "error": str(e)}


# Global instance
_vector_memory = None

def get_vector_memory() -> VectorMemory:
    """Get singleton VectorMemory instance."""
    global _vector_memory
    if _vector_memory is None:
        _vector_memory = VectorMemory()
    return _vector_memory


# ═════════════════════════════════════════════════════════════════
# CONVENIENCE FUNCTIONS (easy to use)
# ═════════════════════════════════════════════════════════════════

def remember(
    content: str,
    target: str,
    category: str = "general",
    **metadata
) -> str:
    """
    Save new memory.
    
    Example:
        remember(
            "Found admin panel at /admin",
            "example.com",
            "finding",
            severity="high",
            tool="ffuf"
        )
    """
    vm = get_vector_memory()
    return vm.add_memory(content, target, category, metadata)


def recall(
    query: str,
    target: str = None,
    category: str = None,
    n_results: int = 5
) -> List[Dict[str, Any]]:
    """
    Find memories similar to query.
    
    Example:
        recall("admin panel vulnerabilities", "example.com")
        -> finds memories related to admin panel
    """
    vm = get_vector_memory()
    return vm.search(query, target, category, n_results)


def get_context_for_ai(
    current_query: str,
    target: str,
    max_memories: int = 10,
    conversation_history: Optional[List[Dict]] = None
) -> str:
    """
    Build context for AI from relevant memories.
    
    Args:
        current_query: Current question/command
        target: Current target being worked on
        max_memories: Maximum number of memories
        conversation_history: Recent conversation turns (optional)
        
    Returns:
        Formatted context string for prompt injection
    """
    vm = get_vector_memory()
    
    # Search for relevant memories
    memories = vm.search(
        query=current_query,
        target=target,
        n_results=max_memories,
        min_similarity=0.35
    )
    
    # Also get recent memories for this target
    recent = vm.get_target_memories(target, limit=15)
    
    # Combine and deduplicate
    seen_ids = set()
    all_memories = []
    
    for mem in memories + recent:
        mem_id = mem.get("id") or mem.get("memory_id") or str(hash(str(mem)))
        if mem_id and mem_id not in seen_ids:
            seen_ids.add(mem_id)
            all_memories.append(mem)
    
    # Format as context
    lines = ["### PREVIOUS KNOWLEDGE (from memory):"]
    
    if not all_memories:
        lines.append("No prior knowledge about this target.")
    else:
        for i, mem in enumerate(all_memories[:max_memories], 1):
            content = mem["content"][:200]  # Limit content length
            category = mem["metadata"].get("category", "general")
            timestamp = mem["metadata"].get("timestamp", "unknown")
            
            # Format timestamp
            if timestamp != "unknown":
                try:
                    dt = datetime.fromisoformat(timestamp)
                    time_str = dt.strftime("%Y-%m-%d")
                except Exception:
                    time_str = timestamp[:10]
            else:
                time_str = "unknown"
            
            lines.append(f"{i}. [{category.upper()}] ({time_str}): {content}")
        
        lines.append(f"\n(Total {len(all_memories)} related memories in database)")
    
    # ADD: Append recent conversation turns for context
    if conversation_history:
        lines.append("\n### RECENT CONVERSATION (last 8 turns):")
        recent_turns = conversation_history[-8:]  # Last 8 turns
        for turn in recent_turns:
            role = turn.get("role", "unknown")
            content = turn.get("content", "")[:300]
            if role == "user":
                lines.append(f"[User]: {content}")
            elif role == "assistant":
                lines.append(f"[Agent]: {content}")
    
    return "\n".join(lines)


def contextual_memory_search(
    current_query: str,
    target: str,
    conversation_history: Optional[List[Dict]] = None,
    max_memories: int = 12
) -> List[Dict[str, Any]]:
    """
    Search memories using both current query and conversation context.
    
    Args:
        current_query: Current question
        target: Target domain/IP
        conversation_history: Recent conversation turns
        max_memories: Maximum number of results
        
    Returns:
        List of memories deduplicated and sorted by relevance
    """
    vm = get_vector_memory()
    
    # Primary search: current query
    primary_results = vm.search(
        query=current_query,
        target=target,
        n_results=max_memories,
        min_similarity=0.35
    )
    
    # Secondary search: use last assistant response for context
    secondary_results = []
    if conversation_history:
        # Get last assistant response
        for turn in reversed(conversation_history):
            if turn.get("role") == "assistant":
                assistant_content = turn.get("content", "")
                if len(assistant_content) > 20:
                    # Search for memories related to this response
                    secondary_results = vm.search(
                        query=assistant_content,
                        target=target,
                        n_results=max_memories // 2,
                        min_similarity=0.35
                    )
                break
    
    # Merge and deduplicate
    seen_ids = set()
    all_results = []
    
    for mem in primary_results + secondary_results:
        mem_id = mem.get("id", str(hash(str(mem))))
        if mem_id not in seen_ids:
            seen_ids.add(mem_id)
            all_results.append(mem)
    
    # Sort by similarity (descending)
    all_results.sort(
        key=lambda x: x.get("similarity", 0),
        reverse=True
    )
    
    return all_results[:max_memories]


def persist_conversation_turns(
    conversation_history: List[Dict],
    target: str,
    batch_size: int = 4
) -> int:
    """
    Persist recent conversation turns to vector memory.
    
    Args:
        conversation_history: List of conversation turns
        target: Target domain/IP
        batch_size: Save every N turns
        
    Returns:
        Number of turns saved
    """
    if len(conversation_history) < 2:
        return 0
    
    vm = get_vector_memory()
    count = 0
    
    # Only persist the last batch_size * 2 turns
    turns_to_persist = conversation_history[-(batch_size * 2):]
    
    for i in range(0, len(turns_to_persist) - 1, 2):
        user_turn = turns_to_persist[i]
        assistant_turn = turns_to_persist[i + 1]
        
        if user_turn.get("role") == "user" and assistant_turn.get("role") == "assistant":
            # Create a combined memory entry
            content = f"Q: {user_turn['content']}\nA: {assistant_turn['content'][:500]}"
            
            vm.add_memory(
                content=content,
                target=target or "universal",
                category="conversation",
                metadata={
                    "user_query": user_turn["content"][:200],
                    "agent_response": assistant_turn["content"][:500],
                }
            )
            count += 1
    
    return count


def show_memory_stats():
    """Display memory statistics (for CLI)."""
    vm = get_vector_memory()
    stats = vm.get_memory_stats()
    
    print("\n Vector Memory Statistics:")
    print(f"  Status: {stats['status']}")
    print(f"  Total Memories: {stats.get('total_memories', 0)}")
    print(f"  Unique Targets: {stats.get('unique_targets', 0)}")
    
    if stats.get('targets'):
        print(f"  Targets: {', '.join(stats['targets'][:10])}")


# Quick test
if __name__ == "__main__":
    print("Testing Vector Memory...")
    
    # Test add
    mem_id = remember(
        "Discovered SQL injection in login form at /auth/login",
        "test-example.com",
        "finding",
        severity="critical",
        tool="dalfox"
    )
    print(f"Added memory: {mem_id}")
    
    # Test search
    results = recall("login form vulnerabilities", "test-example.com")
    print(f"\nFound {len(results)} relevant memories")
    
    for r in results:
        print(f"  - {r['content'][:50]}... (sim: {r.get('similarity', 0):.2f})")
    
    # Test context
    context = get_context_for_ai("scan for vulnerabilities", "test-example.com")
    print(f"\nContext preview:\n{context[:300]}...")
    
    # Stats
    show_memory_stats()
