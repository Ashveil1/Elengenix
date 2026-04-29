"""
tools/vector_memory.py — Semantic Vector Memory System (v1.0.0)
- ChromaDB-based vector storage for persistent AI memory
- Semantic search: 
    pass  # TODO: Implement
- conversation, finding, decision 
- Cross-session memory: 
    pass  # TODO: Implement
"""

import logging
import hashlib
import json
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional, Union
from dataclasses import dataclass, asdict

logger = logging.getLogger("elengenix.vector_memory")

# Try to import ChromaDB, fallback to SQLite if not available
try:
    pass  # TODO: Implement
 import chromadb
 from chromadb.config import Settings
 CHROMADB_AVAILABLE = True
except ImportError:
    pass  # TODO: Implement
 CHROMADB_AVAILABLE = False
 logger.warning("ChromaDB not available. Falling back to SQLite.")

@dataclass
class MemoryEntry:
    pass  # TODO: Implement
 """Single memory entry with metadata."""
 id: str
 content: str # embed ( searchable )
 target: str # target domain/IP
 category: str # finding, conversation, decision, tool_result
 timestamp: str
 metadata: Dict[str, Any] # 
 
 def to_dict(self) -> Dict[str, Any]:
     pass  # TODO: Implement
 return asdict(self)

class VectorMemory:
    pass  # TODO: Implement
 """
 Semantic vector memory using ChromaDB.
 (semantic similarity)
 """
 
 def __init__(self, persist_directory: str = None):
     pass  # TODO: Implement
 self.persist_dir = Path(persist_directory) if persist_directory else \
 Path(__file__).parent.parent / "data" / "vector_memory"
 self.persist_dir.mkdir(parents=True, exist_ok=True)
 
 self.client = None
 self.collection = None
 self._initialized = False
 
 if CHROMADB_AVAILABLE:
     pass  # TODO: Implement
 try:
     pass  # TODO: Implement
 self._init_chromadb()
 except Exception as e:
     pass  # TODO: Implement
 logger.error(f"Failed to init ChromaDB: {e}")
 self._initialized = False
 
 def _init_chromadb(self):
     pass  # TODO: Implement
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
     pass  # TODO: Implement
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
     pass  # TODO: Implement
 """
 memory vector database
 
 Args:
     pass  # TODO: Implement
 content: Requires (Cheap embed)
 target: target domain/IP 
 category: (finding, conversation, decision, tool_result)
 metadata: 
 
 Returns:
     pass  # TODO: Implement
 memory_id: ID memory Saved
 """
 if not self._initialized:
     pass  # TODO: Implement
 logger.warning("VectorMemory not initialized, storing in SQLite fallback")
 return self._fallback_add(content, target, category, metadata)
 
 timestamp = datetime.utcnow().isoformat()
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
     pass  # TODO: Implement
 self.collection.add(
 ids=[memory_id],
 documents=[doc],
 metadatas=[meta],
 )
 logger.debug(f"Added memory: {memory_id[:8]}... for {target}")
 return memory_id
 except Exception as e:
     pass  # TODO: Implement
 logger.error(f"Failed to add memory: {e}")
 return self._fallback_add(content, target, category, metadata)
 
 def search(
 self,
 query: str,
 target: str = None,
 category: str = None,
 n_results: int = 10,
 min_similarity: float = 0.7
 ) -> List[Dict[str, Any]]:
     pass  # TODO: Implement
 """
 memory query (semantic search)
 
 Args:
     pass  # TODO: Implement
 query: Requires
 target: filter target (optional)
 category: filter category (optional)
 n_results: Requires
 min_similarity: (0-1)
 
 Returns:
     pass  # TODO: Implement
 List of matching memories with similarity scores
 """
 if not self._initialized:
     pass  # TODO: Implement
 logger.warning("VectorMemory not initialized, using fallback search")
 return self._fallback_search(query, target, category, n_results)
 
 # Build where clause for filtering
 where_clause = {}
 if target:
     pass  # TODO: Implement
 where_clause["target"] = target.lower().strip()
 if category:
     pass  # TODO: Implement
 where_clause["category"] = category.lower()
 
 try:
     pass  # TODO: Implement
 results = self.collection.query(
 query_texts=[query],
 n_results=n_results,
 where=where_clause if where_clause else None,
 )
 
 # Format results
 memories = []
 if results["ids"] and results["ids"][0]:
     pass  # TODO: Implement
 for i, mem_id in enumerate(results["ids"][0]):
     pass  # TODO: Implement
 distance = results["distances"][0][i] if results["distances"] else 1.0
 similarity = 1.0 - (distance / 2) # Convert distance to similarity
 
 if similarity >= min_similarity:
     pass  # TODO: Implement
 memories.append({
 "id": mem_id,
 "content": results["documents"][0][i] if results["documents"] else "",
 "metadata": results["metadatas"][0][i] if results["metadatas"] else {},
 "similarity": similarity,
 })
 
 return memories
 
 except Exception as e:
     pass  # TODO: Implement
 logger.error(f"Search failed: {e}")
 return self._fallback_search(query, target, category, n_results)
 
 def get_target_memories(
 self,
 target: str,
 category: str = None,
 limit: int = 100
 ) -> List[Dict[str, Any]]:
     pass  # TODO: Implement
 """
 memory target 
 
 Args:
     pass  # TODO: Implement
 target: domain/IP Requires
 category: filter category (optional)
 limit: 
     pass  # TODO: Implement
 """
 if not self._initialized:
     pass  # TODO: Implement
 return self._fallback_get_target(target, category, limit)
 
 where_clause = {"target": target.lower().strip()}
 if category:
     pass  # TODO: Implement
 where_clause["category"] = category.lower()
 
 try:
     pass  # TODO: Implement
 results = self.collection.get(
 where=where_clause,
 limit=limit,
 )
 
 memories = []
 if results["ids"]:
     pass  # TODO: Implement
 for i, mem_id in enumerate(results["ids"]):
     pass  # TODO: Implement
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
     pass  # TODO: Implement
 logger.error(f"Get target memories failed: {e}")
 return self._fallback_get_target(target, category, limit)
 
 def get_all_targets(self) -> List[str]:
     pass  # TODO: Implement
 """ target memory"""
 if not self._initialized:
     pass  # TODO: Implement
 return []
 
 try:
     pass  # TODO: Implement
 results = self.collection.get(limit=10000)
 targets = set()
 
 if results["metadatas"]:
     pass  # TODO: Implement
 for meta in results["metadatas"]:
     pass  # TODO: Implement
 if meta and "target" in meta:
     pass  # TODO: Implement
 targets.add(meta["target"])
 
 return sorted(list(targets))
 except Exception as e:
     pass  # TODO: Implement
 logger.error(f"Get all targets failed: {e}")
 return []
 
 def delete_target_memories(self, target: str) -> int:
     pass  # TODO: Implement
 """ memory target """
 if not self._initialized:
     pass  # TODO: Implement
 return 0
 
 try:
     pass  # TODO: Implement
 self.collection.delete(
 where={"target": target.lower().strip()}
 )
 logger.info(f"Deleted all memories for {target}")
 return 1
 except Exception as e:
     pass  # TODO: Implement
 logger.error(f"Delete failed: {e}")
 return 0
 
 def get_memory_stats(self) -> Dict[str, Any]:
     pass  # TODO: Implement
 """ memory database"""
 if not self._initialized:
     pass  # TODO: Implement
 return {"status": "fallback", "count": 0}
 
 try:
     pass  # TODO: Implement
 count = self.collection.count()
 targets = self.get_all_targets()
 
 return {
 "status": "active",
 "total_memories": count,
 "unique_targets": len(targets),
 "targets": targets[:20], # 20 
 "persist_directory": str(self.persist_dir),
 }
 except Exception as e:
     pass  # TODO: Implement
 logger.error(f"Stats failed: {e}")
 return {"status": "error", "error": str(e)}
 
 # 
 # FALLBACK: SQLite mode ( ChromaDB Ready)
 # 
 
 def _fallback_add(self, content, target, category, metadata):
     pass  # TODO: Implement
 """Fallback to SQLite memory_manager"""
 try:
     pass  # TODO: Implement
 from tools.memory_manager import save_learning
 save_learning(target, content, category)
 return "fallback"
 except Exception as e:
     pass  # TODO: Implement
 logger.error(f"Fallback add failed: {e}")
 return None
 
 def _fallback_search(self, query, target, category, limit):
     pass  # TODO: Implement
 """Fallback search using exact match"""
 try:
     pass  # TODO: Implement
 from tools.memory_manager import get_summarized_learnings
 summary = get_summarized_learnings(target or "global", max_chars=2000)
 return [{"content": summary, "metadata": {}, "similarity": 1.0}]
 except Exception as e:
     pass  # TODO: Implement
 logger.error(f"Fallback search failed: {e}")
 return []
 
 def _fallback_get_target(self, target, category, limit):
     pass  # TODO: Implement
 """Fallback get target"""
 try:
     pass  # TODO: Implement
 from tools.memory_manager import get_summarized_learnings
 summary = get_summarized_learnings(target, max_chars=5000)
 return [{"content": summary, "metadata": {"target": target}}]
 except Exception as e:
     pass  # TODO: Implement
 return []

# Global instance
_vector_memory = None

def get_vector_memory() -> VectorMemory:
    pass  # TODO: Implement
 """Get singleton VectorMemory instance."""
 global _vector_memory
 if _vector_memory is None:
     pass  # TODO: Implement
 _vector_memory = VectorMemory()
 return _vector_memory

# 
# CONVENIENCE FUNCTIONS ()
# 

def remember(
 content: str,
 target: str,
 category: str = "general",
 **metadata
) -> str:
    pass  # TODO: Implement
 """
 Saved
 
 Example:
     pass  # TODO: Implement
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
    pass  # TODO: Implement
 """
 query
 
 Example:
     pass  # TODO: Implement
 recall("admin panel vulnerabilities", "example.com")
 → memories admin panel
 """
 vm = get_vector_memory()
 return vm.search(query, target, category, n_results)

def get_context_for_ai(
 current_query: str,
 target: str,
 max_memories: int = 10
) -> str:
    pass  # TODO: Implement
 """
 context AI memories 
 
 Args:
     pass  # TODO: Implement
 current_query: /
 target: target Running
 max_memories: memory 
 
 Returns:
     pass  # TODO: Implement
 Formatted context string prompt
 """
 vm = get_vector_memory()
 
 # Search for relevant memories
 memories = vm.search(
 query=current_query,
 target=target,
 n_results=max_memories,
 min_similarity=0.6
 )
 
 # Also get recent memories for this target
 recent = vm.get_target_memories(target, limit=5)
 
 # Combine and deduplicate
 seen_ids = set()
 all_memories = []
 
 for mem in memories + recent:
     pass  # TODO: Implement
 if mem["id"] not in seen_ids:
     pass  # TODO: Implement
 seen_ids.add(mem["id"])
 all_memories.append(mem)
 
 # Format as context
 if not all_memories:
     pass  # TODO: Implement
 return "No prior knowledge about this target."
 
 lines = ["### PREVIOUS KNOWLEDGE (from memory):"]
 
 for i, mem in enumerate(all_memories[:max_memories], 1):
     pass  # TODO: Implement
 content = mem["content"][:200] # 
 category = mem["metadata"].get("category", "general")
 timestamp = mem["metadata"].get("timestamp", "unknown")
 
 # Format timestamp
 if timestamp != "unknown":
     pass  # TODO: Implement
 try:
     pass  # TODO: Implement
 dt = datetime.fromisoformat(timestamp)
 time_str = dt.strftime("%Y-%m-%d")
 except:
     pass  # TODO: Implement
 time_str = timestamp[:10]
 else:
     pass  # TODO: Implement
 time_str = "unknown"
 
 lines.append(f"{i}. [{category.upper()}] ({time_str}): {content}")
 
 lines.append(f"\n(Total {len(all_memories)} related memories in database)")
 
 return "\n".join(lines)

def show_memory_stats():
    pass  # TODO: Implement
 """ memory ( CLI)"""
 vm = get_vector_memory()
 stats = vm.get_memory_stats()
 
 print("\n Vector Memory Statistics:")
 print(f" Status: {stats['status']}")
 print(f" Total Memories: {stats.get('total_memories', 0)}")
 print(f" Unique Targets: {stats.get('unique_targets', 0)}")
 
 if stats.get('targets'):
     pass  # TODO: Implement
 print(f" Targets: {', '.join(stats['targets'][:10])}")

# Quick test
if __name__ == "__main__":
    pass  # TODO: Implement
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
     pass  # TODO: Implement
 print(f" - {r['content'][:50]}... (sim: {r.get('similarity', 0):.2f})")
 
 # Test context
 context = get_context_for_ai("scan for vulnerabilities", "test-example.com")
 print(f"\nContext preview:\n{context[:300]}...")
 
 # Stats
 show_memory_stats()
