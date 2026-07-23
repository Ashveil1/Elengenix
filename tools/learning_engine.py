"""tools/learning_engine.py — M7: Cross-Session Learning Engine.

Stores successful exploit patterns from past scans and uses them to
suggest high-probability tools/payloads/techniques for new targets.

Architecture:
- ExploitRecord: tech stack + vuln_class + tool + payload + success
- LearningEngine: stores ExploitRecord in ChromaDB (with in-memory
  fallback if ChromaDB unavailable)
- recall_similar(target, tech_stack): find exploits that worked on
  similar targets
- rank_tools(tech_stack, vuln_class): rank tools by historical
  success rate on this combo
- suggest_payloads(vuln_class): payloads that worked for this class

Storage is dual: ChromaDB for semantic similarity search + SQLite for
deterministic lookups (no AI, no embeddings, just SQL).

Public API:
    ExploitRecord  - one past exploit
    LearningEngine:
        remember(record: ExploitRecord)
        recall_similar(tech_stack: List[str], limit=5) -> List[ExploitRecord]
        rank_tools(tech_stack, vuln_class) -> List[(tool, success_rate)]
        suggest_payloads(vuln_class, n=10) -> List[str]
        get_stats() -> Dict
        consolidate(target=None) -> int
        decay(max_age_days=90) -> int
        record_adaptation(trigger, change, result)
        suggest_adaptation(state) -> Optional[str]
"""

from __future__ import annotations

import json
import logging
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path
from elengenix.paths import get_data_path, get_data_dir
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("elengenix.learning_engine")


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class ExploitRecord:
    """One past exploit attempt + result."""

    target: str
    tech_stack: List[str]  # ["php", "mysql", "wordpress"]
    vuln_class: str  # "sqli", "xss", "rce", etc.
    tool: str  # "sqlmap", "nuclei", "dalfox"
    payload: str  # the payload that worked
    success: bool  # did it actually find the vuln?
    confidence: float = 0.5  # 0.0-1.0, AI/heuristic confidence
    severity: str = "unknown"  # "low", "medium", "high", "critical"
    timestamp: float = 0.0
    notes: str = ""


# ---------------------------------------------------------------------------
# Learning engine
# ---------------------------------------------------------------------------


class LearningEngine:
    """Cross-session learning: remember what worked, recall for new targets."""

    def __init__(
        self,
        db_path: Optional[Path] = None,
        chroma_path: Optional[Path] = None,
        use_chroma: bool = True,
    ):
        self.db_path = db_path or get_data_path("learning.db")
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._init_schema()

        # ChromaDB (optional, for semantic similarity)
        self._chroma = None
        self._chroma_collection = None
        if use_chroma:
            try:
                # Disable telemetry to avoid background threads
                import os

                import chromadb

                os.environ.setdefault("ANONYMIZED_TELEMETRY", "False")
                # Use bypass embedding to avoid downloading 79MB ONNX model
                # We rely on SQL ranking for the heavy lifting; ChromaDB
                # is only used for keyword fallback on the SQL store.
                chroma_path = chroma_path or get_data_dir("chroma_learning")
                chroma_path.mkdir(parents=True, exist_ok=True)
                settings = chromadb.Settings(anonymized_telemetry=False)
                client = chromadb.PersistentClient(path=str(chroma_path), settings=settings)
                self._chroma_collection = client.get_or_create_collection(
                    name="exploits",
                    metadata={"description": "Past exploit records (text-only, no model)"},
                )
                logger.debug("ChromaDB initialized without embedding (SQL-first)")
            except Exception as e:
                logger.debug(f"ChromaDB unavailable ({e}), using SQLite-only mode")

    def _init_schema(self) -> None:
        cur = self._conn.cursor()
        cur.executescript(
            """
            CREATE TABLE IF NOT EXISTS exploits (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT NOT NULL,
                tech_stack_json TEXT,
                vuln_class TEXT,
                tool TEXT,
                payload TEXT,
                success INTEGER,
                confidence REAL,
                severity TEXT,
                timestamp REAL,
                notes TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_exploits_vuln
                ON exploits(vuln_class, success);
            CREATE INDEX IF NOT EXISTS idx_exploits_tool
                ON exploits(tool, vuln_class);

            CREATE TABLE IF NOT EXISTS adaptations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                trigger_finding TEXT NOT NULL,
                strategy_change TEXT NOT NULL,
                result TEXT,
                success INTEGER DEFAULT 1,
                timestamp REAL
            );
            CREATE INDEX IF NOT EXISTS idx_adaptations_trigger
                ON adaptations(trigger_finding);
        """
        )
        self._conn.commit()

    # -- Remembering --

    def remember(self, record: ExploitRecord) -> int:
        """Store a past exploit. Returns the row ID."""
        record.timestamp = record.timestamp or time.time()
        cur = self._conn.cursor()
        cur.execute(
            "INSERT INTO exploits (target, tech_stack_json, vuln_class, tool, payload, "
            "success, confidence, severity, timestamp, notes) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                record.target,
                json.dumps(record.tech_stack),
                record.vuln_class,
                record.tool,
                record.payload[:500],
                int(record.success),
                record.confidence,
                record.severity,
                record.timestamp,
                record.notes,
            ),
        )
        self._conn.commit()
        row_id: int = cur.lastrowid or 0

        # Also store in ChromaDB for semantic search
        if self._chroma_collection is not None:
            try:
                doc_text = f"{record.vuln_class} {record.tool} {' '.join(record.tech_stack)}"
                metadata = {
                    "target": record.target,
                    "vuln_class": record.vuln_class,
                    "tool": record.tool,
                    "success": int(record.success),
                    "confidence": record.confidence,
                    "severity": record.severity,
                }
                self._chroma_collection.add(
                    documents=[doc_text],
                    metadatas=[metadata],  # type: ignore[list-item]
                    ids=[f"exploit_{row_id}"],
                )
            except Exception as e:
                logger.debug(f"ChromaDB add failed: {e}")

        return row_id

    def remember_batch(self, records: List[ExploitRecord]) -> List[int]:
        """Store many records at once. Returns list of IDs."""
        return [self.remember(r) for r in records]

    # -- Recall --

    def recall_similar(
        self,
        tech_stack: List[str],
        vuln_class: Optional[str] = None,
        limit: int = 5,
        min_success_rate: float = 0.5,
    ) -> List[ExploitRecord]:
        """Recall past exploits that worked on similar tech stacks.

        Strategy: SQL query first (deterministic), then ChromaDB
        (semantic, only if available) for the "fuzzy" matching.
        """
        # SQL-based recall
        cur = self._conn.cursor()
        placeholders = ",".join("?" * len(tech_stack))
        vuln_clause = "AND vuln_class = ?" if vuln_class else ""
        query = f"""
            SELECT *, (
                SELECT COUNT(*) FROM exploits e2
                WHERE e2.tool = exploits.tool
                  AND e2.vuln_class = exploits.vuln_class
                  AND e2.success = 1
            ) * 1.0 / MAX(
                (SELECT COUNT(*) FROM exploits e3
                 WHERE e3.tool = exploits.tool
                   AND e3.vuln_class = exploits.vuln_class), 1
            ) as success_rate
            FROM exploits
            WHERE (
                tech_stack_json LIKE ?
                {vuln_clause}
            )
              AND success = 1
            ORDER BY confidence DESC, timestamp DESC
            LIMIT ?
        """
        # Search for each tech
        seen_ids = set()
        results: List[ExploitRecord] = []
        for tech in tech_stack:
            pattern = f'%"{tech}"%'
            params: List[Any] = [pattern]
            if vuln_class:
                params.append(vuln_class)
            params.append(limit)
            rows = cur.execute(query, params).fetchall()
            for r in rows:
                if r["id"] in seen_ids:
                    continue
                seen_ids.add(r["id"])
                if r["success_rate"] >= min_success_rate:
                    results.append(self._row_to_record(r))
                if len(results) >= limit:
                    return results

        # ChromaDB fuzzy recall (if SQL didn't fill the quota)
        if self._chroma_collection is not None and len(results) < limit:
            try:
                query_text = f"{vuln_class or 'security'} {' '.join(tech_stack)}"
                where: Dict[str, Any] = {"success": 1}
                if vuln_class:
                    where["vuln_class"] = vuln_class
                chroma_results = self._chroma_collection.query(
                    query_texts=[query_text],
                    n_results=limit - len(results),
                    where=where,
                )
                if chroma_results and chroma_results.get("ids"):
                    for cid in chroma_results["ids"][0]:
                        exploit_id = int(cid.replace("exploit_", ""))
                        cur2 = self._conn.cursor()
                        row = cur2.execute(
                            "SELECT * FROM exploits WHERE id=?", (exploit_id,)
                        ).fetchone()
                        if row and row["id"] not in seen_ids:
                            seen_ids.add(row["id"])
                            results.append(self._row_to_record(row))
            except Exception as e:
                logger.debug(f"ChromaDB query failed: {e}")

        return results

    def _row_to_record(self, row: sqlite3.Row) -> ExploitRecord:
        return ExploitRecord(
            target=row["target"],
            tech_stack=json.loads(row["tech_stack_json"] or "[]"),
            vuln_class=row["vuln_class"],
            tool=row["tool"],
            payload=row["payload"],
            success=bool(row["success"]),
            confidence=row["confidence"],
            severity=row["severity"],
            timestamp=row["timestamp"],
            notes=row["notes"] or "",
        )

    def rank_tools(
        self,
        tech_stack: Optional[List[str]] = None,
        vuln_class: Optional[str] = None,
        limit: int = 10,
    ) -> List[Tuple[str, float, int]]:
        """Rank tools by historical success rate.

        Returns: [(tool, success_rate, sample_size), ...]
        Sorted by success_rate DESC, then sample_size DESC.
        """
        cur = self._conn.cursor()
        conditions = []
        params: List[Any] = []
        if vuln_class:
            conditions.append("vuln_class = ?")
            params.append(vuln_class)
        if tech_stack:
            for tech in tech_stack:
                conditions.append("tech_stack_json LIKE ?")
                params.append(f'%"{tech}"%')
        where = " AND ".join(conditions) if conditions else "1=1"

        rows = cur.execute(
            f"""
            SELECT tool,
                   SUM(success) * 1.0 / COUNT(*) as success_rate,
                   COUNT(*) as sample_size
            FROM exploits
            WHERE {where}
            GROUP BY tool
            HAVING sample_size >= 1
            ORDER BY success_rate DESC, sample_size DESC
            LIMIT ?
        """,
            params + [limit],
        ).fetchall()

        return [(r["tool"], r["success_rate"], r["sample_size"]) for r in rows]

    def suggest_payloads(self, vuln_class: str, n: int = 10) -> List[str]:
        """Suggest payloads that worked for this vuln class in the past.

        Returns most-frequent successful payloads, sorted by frequency.
        """
        cur = self._conn.cursor()
        rows = cur.execute(
            """
            SELECT payload, COUNT(*) as freq, AVG(confidence) as avg_conf
            FROM exploits
            WHERE vuln_class = ? AND success = 1 AND payload IS NOT NULL
            GROUP BY payload
            ORDER BY freq DESC, avg_conf DESC
            LIMIT ?
        """,
            (vuln_class, n),
        ).fetchall()
        return [r["payload"] for r in rows]

    def get_stats(self) -> Dict[str, Any]:
        """Aggregate stats for the learning database."""
        cur = self._conn.cursor()
        total = cur.execute("SELECT COUNT(*) FROM exploits").fetchone()[0]
        successful = cur.execute("SELECT COUNT(*) FROM exploits WHERE success=1").fetchone()[0]
        by_vuln = cur.execute(
            """
            SELECT vuln_class, COUNT(*) as cnt, SUM(success) as succ
            FROM exploits
            GROUP BY vuln_class
            ORDER BY cnt DESC
        """
        ).fetchall()
        by_tool = cur.execute(
            """
            SELECT tool, COUNT(*) as cnt, SUM(success) as succ
            FROM exploits
            GROUP BY tool
            ORDER BY cnt DESC
        """
        ).fetchall()
        return {
            "total_records": total,
            "successful_records": successful,
            "success_rate": round(successful / max(total, 1), 3),
            "by_vuln_class": {
                r["vuln_class"]: {"total": r["cnt"], "success": r["succ"]} for r in by_vuln
            },
            "by_tool": {r["tool"]: {"total": r["cnt"], "success": r["succ"]} for r in by_tool},
            "chroma_enabled": self._chroma_collection is not None,
        }

    # -- Memory Management (Phase 3) --

    def consolidate(self, target: Optional[str] = None) -> int:
        """Merge similar exploit records, keep highest confidence.

        Groups by (vuln_class, tool, payload_prefix) and keeps only the
        record with the highest confidence in each group.

        Args:
            target: Optional target to consolidate for. If None, consolidates all.

        Returns:
            Number of duplicate records deleted.
        """
        cur = self._conn.cursor()
        target_clause = "AND target = ?" if target else ""
        params = [target] if target else []

        # Find duplicates: same vuln_class + tool + similar payload
        rows = cur.execute(
            f"""
            SELECT vuln_class, tool, SUBSTR(payload, 1, 50) as payload_prefix,
                   MAX(confidence) as max_conf,
                   GROUP_CONCAT(id) as ids,
                   COUNT(*) as cnt
            FROM exploits
            WHERE success = 1 {target_clause}
            GROUP BY vuln_class, tool, payload_prefix
            HAVING cnt > 1
        """,
            params,
        ).fetchall()

        deleted = 0
        for row in rows:
            ids = [int(i) for i in row["ids"].split(",")]
            # Keep the first one (highest confidence due to MAX), delete the rest
            keep_id = ids[0]
            delete_ids = ids[1:]
            if delete_ids:
                placeholders = ",".join("?" * len(delete_ids))
                cur.execute(f"DELETE FROM exploits WHERE id IN ({placeholders})", delete_ids)
                deleted += len(delete_ids)

        self._conn.commit()
        if deleted > 0:
            logger.debug(f"Consolidated {deleted} duplicate exploit records")
        return deleted

    def decay(self, max_age_days: int = 90) -> int:
        """Reduce confidence of old records and delete very old low-confidence ones.

        Records older than max_age_days get confidence reduced by 10%.
        Records older than max_age_days with confidence < 0.1 are deleted.

        Args:
            max_age_days: Age threshold in days.

        Returns:
            Number of records deleted.
        """
        cur = self._conn.cursor()
        cutoff = time.time() - (max_age_days * 86400)

        # Reduce confidence for old records
        cur.execute(
            """
            UPDATE exploits
            SET confidence = confidence * 0.9
            WHERE timestamp < ? AND confidence > 0.1
        """,
            (cutoff,),
        )

        # Delete very old records with very low confidence
        cur.execute(
            """
            DELETE FROM exploits
            WHERE timestamp < ? AND confidence < 0.1
        """,
            (cutoff,),
        )

        deleted = cur.rowcount
        self._conn.commit()
        if deleted > 0:
            logger.debug(f"Decayed and deleted {deleted} old exploit records")
        return deleted

    # -- Adaptation Tracking (Phase 4) --

    def record_adaptation(
        self,
        trigger_finding: str,
        strategy_change: str,
        result: str,
        success: bool = True,
    ) -> int:
        """Store successful strategy adaptations for reuse.

        When the AI changes strategy and succeeds, store the chain
        (trigger -> adaptation -> result) for future reference.

        Args:
            trigger_finding: What finding triggered the adaptation.
            strategy_change: What strategy was changed.
            result: Outcome of the adaptation.
            success: Whether the adaptation was successful.

        Returns:
            Row ID of the stored adaptation.
        """
        cur = self._conn.cursor()
        cur.execute(
            """
            INSERT INTO adaptations (trigger_finding, strategy_change, result, success, timestamp)
            VALUES (?, ?, ?, ?, ?)
        """,
            (trigger_finding, strategy_change, result, int(success), time.time()),
        )
        self._conn.commit()
        return cur.lastrowid or 0

    def suggest_adaptation(self, current_state: str) -> Optional[str]:
        """Suggest strategy adaptation based on past successes.

        Looks for past adaptations where the trigger matches the current state.

        Args:
            current_state: Description of the current situation.

        Returns:
            Suggested adaptation or None if no match found.
        """
        cur = self._conn.cursor()
        rows = cur.execute(
            """
            SELECT strategy_change, COUNT(*) as cnt
            FROM adaptations
            WHERE trigger_finding LIKE ? AND success = 1
            GROUP BY strategy_change
            ORDER BY cnt DESC
            LIMIT 1
        """,
            (f"%{current_state}%",),
        ).fetchone()

        return rows["strategy_change"] if rows else None

    def get_adaptation_stats(self) -> Dict[str, Any]:
        """Get statistics about strategy adaptations."""
        cur = self._conn.cursor()
        total = cur.execute("SELECT COUNT(*) FROM adaptations").fetchone()[0]
        successful = cur.execute(
            "SELECT COUNT(*) FROM adaptations WHERE success=1"
        ).fetchone()[0]
        by_trigger = cur.execute(
            """
            SELECT trigger_finding, COUNT(*) as cnt
            FROM adaptations
            GROUP BY trigger_finding
            ORDER BY cnt DESC
            LIMIT 10
        """
        ).fetchall()
        return {
            "total_adaptations": total,
            "successful_adaptations": successful,
            "success_rate": round(successful / max(total, 1), 3),
            "top_triggers": {r["trigger_finding"]: r["cnt"] for r in by_trigger},
        }

    def reset(self) -> None:
        """Drop all data (for tests)."""
        cur = self._conn.cursor()
        cur.execute("DELETE FROM exploits")
        cur.execute("DELETE FROM adaptations")
        self._conn.commit()
        if self._chroma_collection is not None:
            try:
                self._chroma_collection.delete(where={})
            except Exception:
                pass
