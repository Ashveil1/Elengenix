"""tools/knowledge_graph.py — Cross-Session Knowledge Graph

Persistent knowledge graph that survives across scan sessions. Unlike
per-mission MissionState (which is scoped to a single mission), this
graph stores long-term relationships between targets, technologies,
endpoints, vulnerabilities, exploits, and successful attack chains.

Why this exists
---------------
A senior pentester's real advantage is *pattern memory*: "last time I
saw PHP + nginx + a /admin endpoint, a misconfig in nginx alias gave
me LFI which chained into RCE via log poisoning". Elengenix's previous
memory layers stored flat records (LearningEngine) or per-mission
graphs (MissionState) — neither could answer "what chains worked on
similar targets before?".

This graph closes that gap:

- Nodes:    Target, Tech, Endpoint, VulnClass, Exploit, Finding, Chain, Strategy
- Edges:    has_tech, has_endpoint, has_vuln, exploited_by,
            chained_with, succeeded_with, failed_with, suggested_for

The graph is stored in SQLite (zero deps, atomic, ACID). Each node
has a stable hash-based ID so re-discovering the same target/tech
merges instead of duplicating.

Public API
----------
    kg = KnowledgeGraph()

    # Record a finding + the exploit that produced it
    kg.record_finding(target="example.com", endpoint="/admin",
                     tech_stack=["php", "nginx"],
                     vuln_class="lfi", tool="ffuf",
                     payload="../etc/passwd", severity="high",
                     success=True, mission_id="m-2026-001")

    # Record an attack chain (multi-step escalation that worked)
    kg.record_chain(steps=[{"vuln": "lfi", "endpoint": "/admin"},
                           {"vuln": "rce", "endpoint": "/logs"}],
                    combined_severity="critical",
                    target="example.com", mission_id="m-2026-001")

    # Recall what worked on similar targets
    kg.recall_strategies(tech_stack=["php", "nginx"], limit=5)

    # Recall what FAILED on similar targets (avoid repeating)
    kg.recall_failures(tech_stack=["php"], limit=5)

    # Recall successful attack chains for a tech stack
    kg.recall_chains(tech_stack=["php", "nginx"], limit=3)

    # Stats for observability
    kg.stats()
"""

from __future__ import annotations

import hashlib
import json
import logging
import sqlite3
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from elengenix.paths import get_data_path

logger = logging.getLogger("elengenix.knowledge_graph")


# Node kinds — limited vocabulary keeps the graph queryable & predictable.
NODE_KINDS = (
    "target",        # a host / domain / IP
    "tech",          # a technology: php, nginx, wordpress, ...
    "endpoint",      # a URL path: /admin, /api/v1/users, ...
    "vuln_class",    # sqli, xss, ssrf, rce, lfi, ...
    "exploit",       # a concrete exploit attempt: tool + payload
    "finding",       # a discovered vulnerability
    "chain",         # a multi-step attack chain
    "strategy",      # a high-level strategy that worked
)

# Edge kinds — directed relationships between nodes.
EDGE_KINDS = (
    "has_tech",          # target -> tech
    "has_endpoint",      # target -> endpoint
    "has_vuln",          # endpoint -> vuln_class  (or target -> vuln_class)
    "exploited_by",      # finding -> exploit
    "found_at",          # finding -> endpoint
    "chained_with",      # chain -> finding (ordered by step)
    "succeeded_with",    # strategy -> exploit / chain (success=True)
    "failed_with",       # strategy -> exploit (success=False)
    "suggested_for",     # strategy -> tech / vuln_class
)


@dataclass
class GraphNode:
    """A node in the knowledge graph."""
    node_id: str
    kind: str
    label: str
    data: Dict[str, Any] = field(default_factory=dict)


@dataclass
class GraphEdge:
    """A directed edge between two nodes."""
    src_id: str
    dst_id: str
    kind: str
    weight: float = 1.0
    data: Dict[str, Any] = field(default_factory=dict)


def _stable_id(*parts: str) -> str:
    """Deterministic ID from parts — same parts -> same ID (dedup on upsert)."""
    raw = "|".join(str(p).lower().strip() for p in parts if p is not None)
    return hashlib.sha1(raw.encode("utf-8")).hexdigest()[:16]


class KnowledgeGraph:
    """Persistent cross-session knowledge graph.

    Stored in SQLite. Atomic, zero-deps, ACID. Each node has a stable
    hash-based ID so re-discovering the same target/tech merges
    instead of duplicating.
    """

    def __init__(self, db_path: Optional[Path] = None):
        self.db_path = Path(db_path) if db_path else get_data_path("knowledge_graph.db")
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._init_schema()

    def _init_schema(self) -> None:
        cur = self._conn.cursor()
        cur.executescript(
            """
            CREATE TABLE IF NOT EXISTS nodes (
                node_id TEXT PRIMARY KEY,
                kind TEXT NOT NULL,
                label TEXT NOT NULL,
                data_json TEXT,
                first_seen REAL,
                last_seen REAL,
                hit_count INTEGER DEFAULT 1
            );
            CREATE INDEX IF NOT EXISTS idx_nodes_kind ON nodes(kind);
            CREATE INDEX IF NOT EXISTS idx_nodes_label ON nodes(label);

            CREATE TABLE IF NOT EXISTS edges (
                src_id TEXT NOT NULL,
                dst_id TEXT NOT NULL,
                kind TEXT NOT NULL,
                weight REAL DEFAULT 1.0,
                data_json TEXT,
                first_seen REAL,
                last_seen REAL,
                hit_count INTEGER DEFAULT 1,
                PRIMARY KEY (src_id, dst_id, kind)
            );
            CREATE INDEX IF NOT EXISTS idx_edges_src ON edges(src_id);
            CREATE INDEX IF NOT EXISTS idx_edges_dst ON edges(dst_id);
            CREATE INDEX IF NOT EXISTS idx_edges_kind ON edges(kind);

            CREATE TABLE IF NOT EXISTS missions (
                mission_id TEXT PRIMARY KEY,
                target TEXT,
                started REAL,
                ended REAL,
                findings_count INTEGER DEFAULT 0,
                summary TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_missions_target ON missions(target);
            """
        )
        self._conn.commit()

    # ------------------------------------------------------------------
    # Upsert primitives
    # ------------------------------------------------------------------

    def upsert_node(self, kind: str, label: str, data: Optional[Dict] = None) -> str:
        """Insert or update a node. Returns its stable ID.

        Re-upserting the same (kind, label) increments hit_count and
        refreshes last_seen — it does NOT create a duplicate.
        """
        if kind not in NODE_KINDS:
            raise ValueError(f"unknown node kind: {kind!r}")
        node_id = _stable_id(kind, label)
        now = time.time()
        cur = self._conn.cursor()
        cur.execute(
            "INSERT INTO nodes (node_id, kind, label, data_json, first_seen, last_seen, hit_count) "
            "VALUES (?, ?, ?, ?, ?, ?, 1) "
            "ON CONFLICT(node_id) DO UPDATE SET "
            "  last_seen=excluded.last_seen, "
            "  hit_count=hit_count+1, "
            "  data_json=excluded.data_json",
            (node_id, kind, label, json.dumps(data or {}, default=str), now, now),
        )
        self._conn.commit()
        return node_id

    def upsert_edge(
        self,
        src_id: str,
        dst_id: str,
        kind: str,
        weight: float = 1.0,
        data: Optional[Dict] = None,
    ) -> None:
        """Insert or update an edge. Increments hit_count on conflict."""
        if kind not in EDGE_KINDS:
            raise ValueError(f"unknown edge kind: {kind!r}")
        now = time.time()
        cur = self._conn.cursor()
        cur.execute(
            "INSERT INTO edges (src_id, dst_id, kind, weight, data_json, first_seen, last_seen, hit_count) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, 1) "
            "ON CONFLICT(src_id, dst_id, kind) DO UPDATE SET "
            "  last_seen=excluded.last_seen, "
            "  hit_count=hit_count+1, "
            "  weight=excluded.weight, "
            "  data_json=excluded.data_json",
            (src_id, dst_id, kind, float(weight),
             json.dumps(data or {}, default=str), now, now),
        )
        self._conn.commit()

    # ------------------------------------------------------------------
    # High-level recording API (what scan_loop / post_processor call)
    # ------------------------------------------------------------------

    def record_finding(
        self,
        target: str,
        endpoint: str,
        tech_stack: Optional[List[str]],
        vuln_class: str,
        tool: str,
        payload: str,
        severity: str,
        success: bool,
        confidence: float = 0.5,
        mission_id: Optional[str] = None,
    ) -> str:
        """Record a finding + the exploit that produced it.

        Creates/updates:
          target node, tech nodes, endpoint node, vuln_class node,
          finding node, exploit node,
          has_tech / has_endpoint / has_vuln / found_at / exploited_by edges.

        Returns the finding node ID.
        """
        target = (target or "").strip().lower()
        endpoint = (endpoint or "/").strip()
        vuln_class = (vuln_class or "unknown").strip().lower()
        tool = (tool or "unknown").strip().lower()

        target_id = self.upsert_node("target", target, {"first_target": target})
        end_id = self.upsert_node("endpoint", endpoint, {"target": target})
        self.upsert_edge(target_id, end_id, "has_endpoint")

        vuln_id = self.upsert_node("vuln_class", vuln_class)
        self.upsert_edge(end_id, vuln_id, "has_vuln")
        # Also tag the target itself with the vuln class for fast recall.
        self.upsert_edge(target_id, vuln_id, "has_vuln")

        for tech in (tech_stack or []):
            tech_id = self.upsert_node("tech", tech.strip().lower())
            self.upsert_edge(target_id, tech_id, "has_tech")

        # The exploit (concrete: tool + payload)
        exploit_label = f"{tool}:{payload[:60]}" if payload else tool
        exploit_id = self.upsert_node(
            "exploit", exploit_label,
            {"tool": tool, "payload": payload[:500], "success": success,
             "confidence": confidence, "mission_id": mission_id},
        )

        # The finding (a verified vuln at an endpoint)
        finding_label = f"{vuln_class}@{endpoint}"
        finding_id = self.upsert_node(
            "finding", finding_label,
            {"target": target, "endpoint": endpoint, "vuln_class": vuln_class,
             "severity": severity, "success": success,
             "confidence": confidence, "mission_id": mission_id,
             "timestamp": time.time()},
        )
        self.upsert_edge(finding_id, end_id, "found_at")
        self.upsert_edge(finding_id, exploit_id, "exploited_by")

        # Success/failure edges to a per-tech strategy node
        if tech_stack:
            strat_label = "strategy:" + ",".join(sorted(t.lower() for t in tech_stack))
            strat_id = self.upsert_node("strategy", strat_label, {"tech_stack": tech_stack})
            self.upsert_edge(strat_id, exploit_id,
                             "succeeded_with" if success else "failed_with",
                             weight=float(confidence))
            self.upsert_edge(strat_id, vuln_id, "suggested_for")

        if mission_id:
            self._touch_mission(mission_id, target)
        return finding_id

    def record_chain(
        self,
        steps: List[Dict[str, Any]],
        combined_severity: str,
        target: str,
        mission_id: Optional[str] = None,
        description: str = "",
    ) -> str:
        """Record a successful multi-step attack chain.

        ``steps`` is an ordered list, each like:
            {"vuln": "lfi", "endpoint": "/admin", "tool": "ffuf"}
        """
        target = (target or "").strip().lower()
        chain_label = "->".join(
            f"{s.get('vuln', '?')}@{s.get('endpoint', '/')}" for s in steps
        )
        chain_id = self.upsert_node(
            "chain", chain_label,
            {"steps": steps, "combined_severity": combined_severity,
             "target": target, "description": description,
             "mission_id": mission_id, "timestamp": time.time()},
        )

        target_id = self.upsert_node("target", target)
        self.upsert_edge(target_id, chain_id, "chained_with", data={"order": "owns"})

        for i, step in enumerate(steps):
            f_label = f"{step.get('vuln', 'unknown')}@{step.get('endpoint', '/')}"
            f_id = self.upsert_node("finding", f_label, {"step_index": i, **step})
            self.upsert_edge(chain_id, f_id, "chained_with",
                             weight=float(i + 1), data={"step": i})
        if mission_id:
            self._touch_mission(mission_id, target)
        return chain_id

    def _touch_mission(self, mission_id: str, target: str) -> None:
        now = time.time()
        cur = self._conn.cursor()
        cur.execute(
            "INSERT INTO missions (mission_id, target, started, ended, findings_count, summary) "
            "VALUES (?, ?, ?, ?, 0, '') "
            "ON CONFLICT(mission_id) DO UPDATE SET ended=excluded.ended, "
            "findings_count=missions.findings_count+1",
            (mission_id, target, now, now),
        )
        self._conn.commit()

    # ------------------------------------------------------------------
    # Recall API (what decision_engine / prompt_builder call)
    # ------------------------------------------------------------------

    def recall_strategies(
        self,
        tech_stack: Optional[List[str]] = None,
        vuln_class: Optional[str] = None,
        limit: int = 5,
    ) -> List[Dict[str, Any]]:
        """Recall strategies that succeeded on similar tech / vuln_class."""
        if not tech_stack and not vuln_class:
            return []
        rows = self._conn.execute(
            "SELECT src_id, dst_id, weight, hit_count, data_json "
            "FROM edges WHERE kind='succeeded_with' "
            "ORDER BY weight DESC, hit_count DESC LIMIT ?",
            (limit,),
        ).fetchall()
        results = []
        for r in rows:
            exploit_data = self._node_data(r["dst_id"])
            strat_data = self._node_data(r["src_id"])
            strat_tech = strat_data.get("data", {}).get("tech_stack", [])
            # Filter by tech overlap if tech_stack given
            if tech_stack:
                overlap = set(t.lower() for t in strat_tech) & set(t.lower() for t in tech_stack)
                if not overlap:
                    continue
            results.append({
                "exploit": exploit_data.get("label", ""),
                "tool": exploit_data.get("data", {}).get("tool"),
                "payload": exploit_data.get("data", {}).get("payload"),
                "weight": r["weight"],
                "hits": r["hit_count"],
                "tech_stack": strat_tech,
            })
        return results

    def recall_failures(
        self,
        tech_stack: Optional[List[str]] = None,
        target: Optional[str] = None,
        limit: int = 5,
    ) -> List[Dict[str, Any]]:
        """Recall exploits that FAILED on similar tech/target — avoid repeating."""
        rows = self._conn.execute(
            "SELECT dst_id, weight, hit_count, data_json "
            "FROM edges WHERE kind='failed_with' "
            "ORDER BY hit_count DESC, weight DESC LIMIT ?",
            (limit,),
        ).fetchall()
        results = []
        for r in rows:
            d = self._node_data(r["dst_id"])
            # If tech_stack filter is given, only include failures whose
            # parent strategy shared at least one tech with the filter.
            if tech_stack:
                strat_rows = self._conn.execute(
                    "SELECT src_id FROM edges WHERE dst_id=? AND kind='failed_with'",
                    (r["dst_id"],),
                ).fetchall()
                strat_techs: List[str] = []
                for sr in strat_rows:
                    sd = self._node_data(sr["src_id"])
                    strat_techs.extend(sd.get("data", {}).get("tech_stack", []))
                overlap = set(t.lower() for t in strat_techs) & set(t.lower() for t in tech_stack)
                if not overlap:
                    continue
            results.append({
                "exploit": d.get("label", ""),
                "tool": d.get("data", {}).get("tool"),
                "payload": d.get("data", {}).get("payload"),
                "fail_count": r["hit_count"],
            })
        return results

    def recall_chains(
        self,
        tech_stack: Optional[List[str]] = None,
        target: Optional[str] = None,
        limit: int = 3,
    ) -> List[Dict[str, Any]]:
        """Recall successful multi-step attack chains for similar targets."""
        if target:
            rows = self._conn.execute(
                "SELECT label, data_json, hit_count, last_seen "
                "FROM nodes WHERE kind='chain' AND data_json LIKE ? "
                "ORDER BY hit_count DESC, last_seen DESC LIMIT ?",
                ('%"target": "%' + target.lower() + '%"%', limit),
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT label, data_json, hit_count, last_seen "
                "FROM nodes WHERE kind='chain' "
                "ORDER BY hit_count DESC, last_seen DESC LIMIT ?",
                (limit,),
            ).fetchall()
        results = []
        for r in rows:
            try:
                data = json.loads(r["data_json"]) if r["data_json"] else {}
            except Exception:
                data = {}
            results.append({
                "chain": r["label"],
                "steps": data.get("steps", []),
                "combined_severity": data.get("combined_severity", "unknown"),
                "description": data.get("description", ""),
                "hits": r["hit_count"],
            })
        return results

    # ------------------------------------------------------------------
    # Observability
    # ------------------------------------------------------------------

    def stats(self) -> Dict[str, Any]:
        """Return graph statistics for observability."""
        counts: Dict[str, int] = {}
        for kind in NODE_KINDS:
            row = self._conn.execute(
                "SELECT COUNT(*) AS c FROM nodes WHERE kind=?", (kind,)
            ).fetchone()
            counts[kind] = row["c"] if row else 0
        edge_counts: Dict[str, int] = {}
        for kind in EDGE_KINDS:
            row = self._conn.execute(
                "SELECT COUNT(*) AS c FROM edges WHERE kind=?", (kind,)
            ).fetchone()
            edge_counts[kind] = row["c"] if row else 0
        missions = self._conn.execute(
            "SELECT COUNT(*) AS c FROM missions"
        ).fetchone()
        return {
            "nodes": counts,
            "edges": edge_counts,
            "missions": missions["c"] if missions else 0,
            "total_nodes": sum(counts.values()),
            "total_edges": sum(edge_counts.values()),
        }

    def reset(self) -> None:
        """Drop all data (used by tests)."""
        cur = self._conn.cursor()
        cur.executescript(
            "DELETE FROM edges; DELETE FROM nodes; DELETE FROM missions;"
        )
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _node_data(self, node_id: str) -> Dict[str, Any]:
        """Return {'label': ..., 'data': {...}} for a node, or empty dict."""
        row = self._conn.execute(
            "SELECT label, data_json FROM nodes WHERE node_id=?", (node_id,)
        ).fetchone()
        if not row:
            return {}
        try:
            data = json.loads(row["data_json"]) if row["data_json"] else {}
        except Exception:
            data = {}
        return {"label": row["label"], "data": data}

