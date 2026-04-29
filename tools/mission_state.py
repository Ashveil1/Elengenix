"""tools/mission_state.py

Unified mission state for Elengenix autonomous expert system.

Stores:
- Target graph (assets/endpoints/services)
- Facts/hypotheses with confidence
- Action ledger (tool executions, decisions)

SQLite-backed for Termux compatibility.
"""

from __future__ import annotations

import json
import logging
import sqlite3
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Generator, List, Optional, Tuple

logger = logging.getLogger("elengenix.mission_state")

_DB_PATH = Path(__file__).parent.parent / "data" / "mission_state.db"

def _db_path() -> Path:
 _DB_PATH.parent.mkdir(parents=True, exist_ok=True)
 return _DB_PATH

@contextmanager
def _get_conn() -> Generator[sqlite3.Connection, None, None]:
    conn = sqlite3.connect(str(_db_path()), timeout=10)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

def init_db() -> None:
    with _get_conn() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS missions (
            mission_id TEXT PRIMARY KEY,
            target TEXT NOT NULL,
            objective TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            status TEXT DEFAULT 'running',
            current_phase TEXT DEFAULT 'discovery',
            phase_index INTEGER DEFAULT 0,
            tokens_used INTEGER DEFAULT 0,
            findings_count INTEGER DEFAULT 0,
            paused_at TEXT,
            resumed_at TEXT
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS graph_nodes (
            mission_id TEXT NOT NULL,
            node_id TEXT NOT NULL,
            node_type TEXT NOT NULL,
            props_json TEXT NOT NULL,
            created_at TEXT NOT NULL,
            PRIMARY KEY (mission_id, node_id),
            FOREIGN KEY (mission_id) REFERENCES missions(mission_id) ON DELETE CASCADE
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS graph_edges (
            mission_id TEXT NOT NULL,
            edge_id TEXT NOT NULL,
            src_id TEXT NOT NULL,
            dst_id TEXT NOT NULL,
            edge_type TEXT NOT NULL,
            props_json TEXT NOT NULL,
            created_at TEXT NOT NULL,
            PRIMARY KEY (mission_id, edge_id),
            FOREIGN KEY (mission_id) REFERENCES missions(mission_id) ON DELETE CASCADE
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS facts (
            mission_id TEXT NOT NULL,
            fact_id TEXT NOT NULL,
            category TEXT NOT NULL,
            statement TEXT NOT NULL,
            confidence REAL NOT NULL,
            evidence_json TEXT NOT NULL,
            created_at TEXT NOT NULL,
            PRIMARY KEY (mission_id, fact_id),
            FOREIGN KEY (mission_id) REFERENCES missions(mission_id) ON DELETE CASCADE
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS hypotheses (
            mission_id TEXT NOT NULL,
            hyp_id TEXT NOT NULL,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            confidence REAL NOT NULL,
            status TEXT NOT NULL,
            tags_json TEXT NOT NULL,
            evidence_json TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            PRIMARY KEY (mission_id, hyp_id),
            FOREIGN KEY (mission_id) REFERENCES missions(mission_id) ON DELETE CASCADE
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS ledger (
            mission_id TEXT NOT NULL,
            entry_id TEXT NOT NULL,
            ts TEXT NOT NULL,
            kind TEXT NOT NULL,
            tool TEXT,
            action_json TEXT NOT NULL,
            result_json TEXT NOT NULL,
            PRIMARY KEY (mission_id, entry_id),
            FOREIGN KEY (mission_id) REFERENCES missions(mission_id) ON DELETE CASCADE
            )
            """
        )

def _now() -> str:
    return datetime.utcnow().isoformat()

def _j(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=False)

def _uj(s: str) -> Any:
    return json.loads(s) if s else None

@dataclass
class GraphNode:
 node_id: str
 node_type: str
 props: Dict[str, Any] = field(default_factory=dict)

@dataclass
class GraphEdge:
 edge_id: str
 src_id: str
 dst_id: str
 edge_type: str
 props: Dict[str, Any] = field(default_factory=dict)

class MissionState:
    def __init__(self, mission_id: str, target: str, objective: str):
        self.mission_id = mission_id
        self.target = target
        self.objective = objective
        init_db()
        self._ensure_mission_row()

    def _ensure_mission_row(self) -> None:
        now = _now()
        with _get_conn() as conn:
            conn.execute(
                """
                INSERT OR IGNORE INTO missions (mission_id, target, objective, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (self.mission_id, self.target, self.objective, now, now),
            )

    def pause_mission(self) -> None:
        """Pause the mission."""
        now = _now()
        with _get_conn() as conn:
            conn.execute(
                """
                UPDATE missions 
                SET status = 'paused', paused_at = ?, updated_at = ?
                WHERE mission_id = ?
                """,
                (now, now, self.mission_id),
            )

    def resume_mission(self) -> None:
        """Resume a paused mission."""
        now = _now()
        with _get_conn() as conn:
            conn.execute(
                """
                UPDATE missions 
                SET status = 'running', resumed_at = ?, updated_at = ?
                WHERE mission_id = ?
                """,
                (now, now, self.mission_id),
            )

    def update_phase(self, phase: str, phase_index: int = None) -> None:
        """Update current phase."""
        with _get_conn() as conn:
            if phase_index is not None:
                conn.execute(
                    """
                    UPDATE missions 
                    SET current_phase = ?, phase_index = ?, updated_at = ?
                    WHERE mission_id = ?
                    """,
                    (phase, phase_index, _now(), self.mission_id),
                )
            else:
                conn.execute(
                    """
                    UPDATE missions 
                    SET current_phase = ?, updated_at = ?
                    WHERE mission_id = ?
                    """,
                    (phase, _now(), self.mission_id),
                )

    def add_tokens(self, tokens: int) -> None:
        """Add to token count."""
        with _get_conn() as conn:
            conn.execute(
                """
                UPDATE missions 
                SET tokens_used = tokens_used + ?, updated_at = ?
                WHERE mission_id = ?
                """,
                (tokens, _now(), self.mission_id),
            )

    def add_finding(self) -> None:
        """Increment findings count."""
        with _get_conn() as conn:
            conn.execute(
                """
                UPDATE missions 
                SET findings_count = findings_count + 1, updated_at = ?
                WHERE mission_id = ?
                """,
                (_now(), self.mission_id),
            )

    def get_status(self) -> Dict[str, Any]:
        """Get mission status."""
        with _get_conn() as conn:
            row = conn.execute(
                """
                SELECT status, current_phase, phase_index, tokens_used, findings_count, paused_at, resumed_at
                FROM missions WHERE mission_id = ?
                """,
                (self.mission_id,),
            ).fetchone()
        
            if row:
                return {
                    "status": row[0],
                    "current_phase": row[1],
                    "phase_index": row[2],
                    "tokens_used": row[3],
                    "findings_count": row[4],
                    "paused_at": row[5],
                    "resumed_at": row[6],
                }
            return {}

    def touch(self) -> None:
        with _get_conn() as conn:
            conn.execute(
                "UPDATE missions SET updated_at = ? WHERE mission_id = ?",
                (_now(), self.mission_id),
            )

    def upsert_node(self, node: GraphNode) -> None:
        with _get_conn() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO graph_nodes (mission_id, node_id, node_type, props_json, created_at)
                VALUES (?, ?, ?, ?, COALESCE((SELECT created_at FROM graph_nodes WHERE mission_id=? AND node_id=?), ?))
                """,
                (
                    self.mission_id,
                    node.node_id,
                    node.node_type,
                    _j(node.props),
                    self.mission_id,
                    node.node_id,
                    _now(),
                ),
            )
            self.touch()

    def upsert_edge(self, edge: GraphEdge) -> None:
        with _get_conn() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO graph_edges (mission_id, edge_id, src_id, dst_id, edge_type, props_json, created_at)
                VALUES (?, ?, ?, ?, ?, ?, COALESCE((SELECT created_at FROM graph_edges WHERE mission_id=? AND edge_id=?), ?))
                """,
                (
                    self.mission_id,
                    edge.edge_id,
                    edge.src_id,
                    edge.dst_id,
                    edge.edge_type,
                    _j(edge.props),
                    self.mission_id,
                    edge.edge_id,
                    _now(),
                ),
            )
            self.touch()

    def add_fact(
        self,
        fact_id: str,
        category: str,
        statement: str,
        confidence: float,
        evidence: Optional[Dict[str, Any]] = None,
    ) -> None:
        with _get_conn() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO facts (mission_id, fact_id, category, statement, confidence, evidence_json, created_at)
                VALUES (?, ?, ?, ?, ?, ?, COALESCE((SELECT created_at FROM facts WHERE mission_id=? AND fact_id=?), ?))
                """,
                (
                    self.mission_id,
                    fact_id,
                    category,
                    statement,
                    float(confidence),
                    _j(evidence or {}),
                    self.mission_id,
                    fact_id,
                    _now(),
                ),
            )
            self.touch()

    def upsert_hypothesis(
        self,
        hyp_id: str,
        title: str,
        description: str,
        confidence: float,
        status: str = "open",
        tags: Optional[List[str]] = None,
        evidence: Optional[Dict[str, Any]] = None,
    ) -> None:
        now = _now()
        with _get_conn() as conn:
            existing = conn.execute(
                "SELECT created_at FROM hypotheses WHERE mission_id=? AND hyp_id=?",
                (self.mission_id, hyp_id),
            ).fetchone()
            created_at = existing[0] if existing else now
            conn.execute(
                """
                INSERT OR REPLACE INTO hypotheses (
                mission_id, hyp_id, title, description, confidence, status,
                tags_json, evidence_json, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    self.mission_id,
                    hyp_id,
                    title,
                    description,
                    float(confidence),
                    status,
                    _j(tags or []),
                    _j(evidence or {}),
                    created_at,
                    now,
                ),
            )
            self.touch()

    def add_ledger_entry(
        self,
        entry_id: str,
        kind: str,
        action: Dict[str, Any],
        result: Optional[Dict[str, Any]] = None,
        tool: Optional[str] = None,
        ts: Optional[str] = None,
    ) -> None:
        with _get_conn() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO ledger (mission_id, entry_id, ts, kind, tool, action_json, result_json)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    self.mission_id,
                    entry_id,
                    ts or _now(),
                    kind,
                    tool,
                    _j(action),
                    _j(result or {}),
                ),
            )
            self.touch()

    def snapshot(self, max_items: int = 50) -> Dict[str, Any]:
        with _get_conn() as conn:
            nodes = conn.execute(
                "SELECT node_id, node_type, props_json FROM graph_nodes WHERE mission_id=? LIMIT ?",
                (self.mission_id, max_items),
            ).fetchall()
            edges = conn.execute(
                "SELECT edge_id, src_id, dst_id, edge_type, props_json FROM graph_edges WHERE mission_id=? LIMIT ?",
                (self.mission_id, max_items),
            ).fetchall()
            facts = conn.execute(
                "SELECT fact_id, category, statement, confidence, evidence_json FROM facts WHERE mission_id=? LIMIT ?",
                (self.mission_id, max_items),
            ).fetchall()
            hyps = conn.execute(
                "SELECT hyp_id, title, description, confidence, status, tags_json, evidence_json FROM hypotheses WHERE mission_id=? LIMIT ?",
                (self.mission_id, max_items),
            ).fetchall()

            return {
                "mission_id": self.mission_id,
                "target": self.target,
                "objective": self.objective,
                "nodes": [
                    {"id": n[0], "type": n[1], "props": _uj(n[2])}
                    for n in nodes
                ],
                "edges": [
                    {"id": e[0], "src": e[1], "dst": e[2], "type": e[3], "props": _uj(e[4])}
                    for e in edges
                ],
                "facts": [
                    {
                        "id": f[0],
                        "category": f[1],
                        "statement": f[2],
                        "confidence": f[3],
                        "evidence": _uj(f[4]),
                    }
                    for f in facts
                ],
                "hypotheses": [
                    {
                        "id": h[0],
                        "title": h[1],
                        "description": h[2],
                        "confidence": h[3],
                        "status": h[4],
                        "tags": _uj(h[5]),
                        "evidence": _uj(h[6]),
                    }
                    for h in hyps
                ],
            }

def open_mission(mission_id: str) -> Optional[MissionState]:
    init_db()
    with _get_conn() as conn:
        row = conn.execute(
            "SELECT target, objective FROM missions WHERE mission_id=?",
            (mission_id,),
        ).fetchone()
        if not row:
            return None
        return MissionState(mission_id=mission_id, target=row[0], objective=row[1])
