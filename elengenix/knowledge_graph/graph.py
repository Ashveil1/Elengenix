"""elengenix/knowledge_graph/graph.py — Local knowledge graph (NetworkX + SQLite)
mirroring PentAGI's Graphiti integration.

This module provides a self-contained, dependency-light replacement for
PentAGI's Graphiti/Neo4j knowledge graph. It implements the same conceptual
model — Nodes, Edges, Episodes, Communities — and the same seven search
strategies exposed by PentAGI's ``graphiti_search`` tool:

    1. ``temporal_window_search``        — time-bounded fuzzy retrieval
    2. ``entity_relationships_search``   — BFS from a center node
    3. ``diverse_results_search``        — MMR-reranked diverse retrieval
    4. ``episode_context_search``        — episodic memory of agent/tool runs
    5. ``successful_tools_search``       — proven successful tool executions
    6. ``recent_context_search``         — recency-bounded context window
    7. ``entity_by_label_search``        — type-filtered entity inventory

Persistence uses SQLite (via ``aiosqlite``) at
``~/.elengenix/data/knowledge_graph.db``; the in-memory representation is a
``networkx.MultiDiGraph`` (lazy-imported). Every entity is scoped by
``group_id = f"flow-{flow_id}"`` for per-engagement isolation, exactly as in
PentAGI.

The two ingestion templates (``agent_response.tmpl`` and
``tool_execution.tmpl`` from ``pentagi/backend/pkg/templates/graphiti/``) are
ported verbatim as :meth:`KnowledgeGraph.ingest_agent_response` and
:meth:`KnowledgeGraph.ingest_tool_execution`.

All public methods are ``async`` and fully type-hinted.
"""

from __future__ import annotations

import difflib
import json
import logging
import math
import re
import uuid
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Iterable

import aiosqlite

logger = logging.getLogger("elengenix.knowledge_graph.graph")

# ──────────────────────────────────────────────────────────────────────────────
# Defaults & allowed values (ported from PentAGI graphiti_search.go lines 27-55)
# ──────────────────────────────────────────────────────────────────────────────

DEFAULT_TEMPORAL_MAX_RESULTS = 15
DEFAULT_RECENT_MAX_RESULTS = 10
DEFAULT_SUCCESSFUL_MAX_RESULTS = 15
DEFAULT_EPISODE_MAX_RESULTS = 10
DEFAULT_RELATIONSHIP_MAX_RESULTS = 20
DEFAULT_DIVERSE_MAX_RESULTS = 10
DEFAULT_LABEL_MAX_RESULTS = 25

DEFAULT_MAX_DEPTH = 2
DEFAULT_MIN_MENTIONS = 2
DEFAULT_DIVERSITY_LEVEL = "medium"
DEFAULT_RECENCY_WINDOW = "24h"

MAX_ALLOWED_DEPTH = 3

ALLOWED_RECENCY_WINDOWS = {"1h", "6h", "24h", "7d"}
ALLOWED_DIVERSITY_LEVELS = {"low", "medium", "high"}

# MMR λ per diversity level. λ=1 → pure relevance; λ=0 → pure diversity.
DIVERSITY_LAMBDA: dict[str, float] = {
    "low": 0.7,
    "medium": 0.5,
    "high": 0.3,
}

RECENCY_WINDOW_DELTA: dict[str, timedelta] = {
    "1h": timedelta(hours=1),
    "6h": timedelta(hours=6),
    "24h": timedelta(hours=24),
    "7d": timedelta(days=7),
}

DEFAULT_DB_PATH = Path("~/.elengenix/data/knowledge_graph.db").expanduser()


# ──────────────────────────────────────────────────────────────────────────────
# Enums
# ──────────────────────────────────────────────────────────────────────────────


class NodeLabel(str, Enum):
    """Node type tags. Mirrors PentAGI's entity label vocabulary plus
    ``EPISODE`` and ``COMMUNITY`` for wrapper nodes."""

    IP_ADDRESS = "IP_ADDRESS"
    SERVICE = "SERVICE"
    VULNERABILITY = "VULNERABILITY"
    ENDPOINT = "ENDPOINT"
    CREDENTIAL = "CREDENTIAL"
    TOOL = "TOOL"
    ENTITY = "ENTITY"
    EPISODE = "EPISODE"
    COMMUNITY = "COMMUNITY"


class EdgeType(str, Enum):
    """Edge relationship types. Mirrors PentAGI's edge vocabulary."""

    HAS_PORT = "HAS_PORT"
    EXPLOITS = "EXPLOITS"
    MENTIONS = "MENTIONS"
    WORKS_ON = "WORKS_ON"
    DISCOVERED_BY = "DISCOVERED_BY"
    RELATED_TO = "RELATED_TO"


# ──────────────────────────────────────────────────────────────────────────────
# Dataclasses
# ──────────────────────────────────────────────────────────────────────────────


@dataclass
class Node:
    """A knowledge-graph entity (IP, service, vulnerability, etc.)."""

    uuid: str
    name: str
    labels: list[NodeLabel]
    summary: str
    attributes: dict[str, Any]
    created_at: datetime
    group_id: str

    def to_row(self) -> dict[str, Any]:
        return {
            "uuid": self.uuid,
            "name": self.name,
            "labels": json.dumps([lbl.value for lbl in self.labels]),
            "summary": self.summary,
            "attributes": json.dumps(self.attributes, default=str, sort_keys=True),
            "created_at": _iso(self.created_at),
            "group_id": self.group_id,
        }

    @classmethod
    def from_row(cls, row: aiosqlite.Row | dict[str, Any]) -> "Node":
        labels_raw = row["labels"]
        labels = [NodeLabel(l) for l in json.loads(labels_raw)] if labels_raw else []
        attrs_raw = row["attributes"]
        attrs = json.loads(attrs_raw) if attrs_raw else {}
        return cls(
            uuid=row["uuid"],
            name=row["name"],
            labels=labels,
            summary=row["summary"],
            attributes=attrs,
            created_at=_parse_dt(row["created_at"]),
            group_id=row["group_id"],
        )


@dataclass
class Edge:
    """A directed, fact-bearing relationship between two Nodes."""

    uuid: str
    name: str
    fact: str
    source_node_uuid: str
    target_node_uuid: str
    edge_type: EdgeType
    created_at: datetime
    valid_at: datetime | None
    invalid_at: datetime | None
    group_id: str

    def to_row(self) -> dict[str, Any]:
        return {
            "uuid": self.uuid,
            "name": self.name,
            "fact": self.fact,
            "source_node_uuid": self.source_node_uuid,
            "target_node_uuid": self.target_node_uuid,
            "edge_type": self.edge_type.value,
            "created_at": _iso(self.created_at),
            "valid_at": _iso(self.valid_at) if self.valid_at else None,
            "invalid_at": _iso(self.invalid_at) if self.invalid_at else None,
            "group_id": self.group_id,
        }

    @classmethod
    def from_row(cls, row: aiosqlite.Row | dict[str, Any]) -> "Edge":
        return cls(
            uuid=row["uuid"],
            name=row["name"],
            fact=row["fact"],
            source_node_uuid=row["source_node_uuid"],
            target_node_uuid=row["target_node_uuid"],
            edge_type=EdgeType(row["edge_type"]),
            created_at=_parse_dt(row["created_at"]),
            valid_at=_parse_dt(row["valid_at"]) if row["valid_at"] else None,
            invalid_at=_parse_dt(row["invalid_at"]) if row["invalid_at"] else None,
            group_id=row["group_id"],
        )


@dataclass
class Episode:
    """An episodic memory entry — an agent response or tool execution.

    Ported from PentAGI's ``graphiti.EpisodeResult``. ``source`` is either
    ``"message"`` (agent response) or ``"tool_execution"``.
    """

    uuid: str
    source: str
    source_description: str
    content: str
    created_at: datetime
    group_id: str

    def to_row(self) -> dict[str, Any]:
        return {
            "uuid": self.uuid,
            "source": self.source,
            "source_description": self.source_description,
            "content": self.content,
            "created_at": _iso(self.created_at),
            "group_id": self.group_id,
        }

    @classmethod
    def from_row(cls, row: aiosqlite.Row | dict[str, Any]) -> "Episode":
        return cls(
            uuid=row["uuid"],
            source=row["source"],
            source_description=row["source_description"],
            content=row["content"],
            created_at=_parse_dt(row["created_at"]),
            group_id=row["group_id"],
        )


@dataclass
class Community:
    """A cluster of related nodes within one ``group_id``."""

    uuid: str
    name: str
    summary: str
    member_node_uuids: list[str]
    group_id: str

    def to_row(self) -> dict[str, Any]:
        return {
            "uuid": self.uuid,
            "name": self.name,
            "summary": self.summary,
            "member_node_uuids": json.dumps(self.member_node_uuids),
            "group_id": self.group_id,
        }

    @classmethod
    def from_row(cls, row: aiosqlite.Row | dict[str, Any]) -> "Community":
        members_raw = row["member_node_uuids"]
        members = json.loads(members_raw) if members_raw else []
        return cls(
            uuid=row["uuid"],
            name=row["name"],
            summary=row["summary"],
            member_node_uuids=members,
            group_id=row["group_id"],
        )


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime | None) -> str:
    if dt is None:
        return ""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat()


def _parse_dt(s: str | None) -> datetime:
    if not s:
        return _now()
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        return _now()
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


_TOKEN_RE = re.compile(r"\w+", re.UNICODE)


def _tokenize(text: str) -> list[str]:
    return [t.lower() for t in _TOKEN_RE.findall(text or "") if len(t) > 1]


def _truncate(s: str, max_len: int = 200) -> str:
    if len(s) <= max_len:
        return s
    return s[:max_len] + "..."


def _fuzzy_ratio(query: str, candidate: str) -> float:
    """Quick normalised fuzzy similarity in [0, 1] using SequenceMatcher."""
    if not query or not candidate:
        return 0.0
    return difflib.SequenceMatcher(None, query.lower(), candidate.lower()).ratio()


def _fuzzy_score(query: str, texts: Iterable[str]) -> float:
    """Best fuzzy score of the query against any of ``texts`` plus a token-
    overlap bonus."""
    q = (query or "").lower()
    if not q:
        return 0.0
    q_tokens = set(_tokenize(q))
    best = 0.0
    for t in texts:
        if not t:
            continue
        ratio = _fuzzy_ratio(q, str(t))
        toks = set(_tokenize(str(t)))
        overlap = len(q_tokens & toks) / max(1, len(q_tokens))
        score = max(ratio, overlap * 0.85)
        if score > best:
            best = score
    return best


# ─── TF-IDF + cosine + MMR (pure-Python, no sklearn) ─────────────────────────


def _tfidf_vectors(docs: list[str]) -> list[dict[str, float]]:
    """Return sparse TF-IDF vectors for each doc. Uses smoothed IDF:
    ``idf = ln((1 + N) / (1 + df)) + 1``."""
    n = len(docs)
    if n == 0:
        return []
    tokenized = [_tokenize(d) for d in docs]
    df: dict[str, int] = {}
    for toks in tokenized:
        for t in set(toks):
            df[t] = df.get(t, 0) + 1
    idf = {t: math.log((1 + n) / (1 + d)) + 1.0 for t, d in df.items()}
    vectors: list[dict[str, float]] = []
    for toks in tokenized:
        tf = Counter(toks)
        total = sum(tf.values()) or 1
        vec = {t: (c / total) * idf[t] for t, c in tf.items()}
        vectors.append(vec)
    return vectors


def _cosine(a: dict[str, float], b: dict[str, float]) -> float:
    if not a or not b:
        return 0.0
    if len(a) > len(b):
        a, b = b, a
    dot = 0.0
    for t, v in a.items():
        w = b.get(t)
        if w is not None:
            dot += v * w
    na = math.sqrt(sum(v * v for v in a.values()))
    nb = math.sqrt(sum(v * v for v in b.values()))
    if na == 0.0 or nb == 0.0:
        return 0.0
    return dot / (na * nb)


def _mmr_rerank(
    items: list[Any],
    texts: list[str],
    relevances: list[float],
    query: str,
    diversity_level: str,
    max_results: int,
) -> list[tuple[Any, float, float]]:
    """Maximal Marginal Relevance reranking.

    Returns a list of ``(item, relevance, mmr_score)`` tuples of length up to
    ``max_results``. ``relevance`` is the post-rerank relevance used in the
    MMR objective (max of supplied relevance and TF-IDF cosine to the query).
    """
    if not items:
        return []
    lam = DIVERSITY_LAMBDA.get(diversity_level, 0.5)
    docs = [query] + list(texts)
    vecs = _tfidf_vectors(docs)
    qvec = vecs[0]
    cvecs = vecs[1:]
    tf_rel = [_cosine(qvec, cv) for cv in cvecs]
    combined = [
        max(r, tf_rel[i], relevances[i] if i < len(relevances) else 0.0)
        for i, r in enumerate(tf_rel)
    ]
    selected: list[int] = []
    remaining = list(range(len(items)))
    result: list[tuple[Any, float, float]] = []
    while remaining and len(result) < max_results:
        best_idx = -1
        best_score = -float("inf")
        for i in remaining:
            if selected:
                max_sim = max(_cosine(cvecs[i], cvecs[j]) for j in selected)
            else:
                max_sim = 0.0
            score = lam * combined[i] - (1.0 - lam) * max_sim
            if score > best_score:
                best_score = score
                best_idx = i
        if best_idx < 0:
            break
        selected.append(best_idx)
        remaining.remove(best_idx)
        result.append((items[best_idx], combined[best_idx], best_score))
    return result


# ──────────────────────────────────────────────────────────────────────────────
# KnowledgeGraph
# ──────────────────────────────────────────────────────────────────────────────


class KnowledgeGraph:
    """Local knowledge graph (NetworkX + SQLite) mirroring PentAGI's Graphiti.

    All public operations are ``async`` and scoped by ``group_id`` for
    per-engagement isolation. Construction is cheap — the heavy work (DB
    connect, schema create, row load) happens lazily on first use via
    :meth:`_ensure_initialized`.
    """

    def __init__(self, db_path: Path | str | None = None) -> None:
        # Lazy import networkx so the module loads even if networkx is absent
        # at import time (e.g. in lightweight CLI contexts that never touch
        # the KG).
        import networkx as nx  # noqa: F401  (lazy import per spec)

        self._nx = nx
        self._graph: "nx.MultiDiGraph" = nx.MultiDiGraph()
        self._episodes: dict[str, dict[str, Episode]] = {}
        self._communities: dict[str, dict[str, Community]] = {}
        self._db_path: Path = (
            Path(db_path).expanduser() if db_path else DEFAULT_DB_PATH
        )
        self._db: aiosqlite.Connection | None = None
        self._initialized: bool = False
        logger.debug("KnowledgeGraph constructed (db_path=%s)", self._db_path)

    # ─── lifecycle ───────────────────────────────────────────────────────────

    async def _ensure_initialized(self) -> None:
        if self._initialized:
            return
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._db = await aiosqlite.connect(str(self._db_path))
        self._db.row_factory = aiosqlite.Row
        await self._create_tables()
        await self._load_all()
        self._initialized = True
        logger.info(
            "KnowledgeGraph initialized: %d nodes, %d edges, %d episodes, %d "
            "communities",
            self._graph.number_of_nodes(),
            self._graph.number_of_edges(),
            sum(len(d) for d in self._episodes.values()),
            sum(len(d) for d in self._communities.values()),
        )

    async def _create_tables(self) -> None:
        assert self._db is not None
        await self._db.executescript(
            """
            CREATE TABLE IF NOT EXISTS nodes (
                uuid        TEXT PRIMARY KEY,
                name        TEXT NOT NULL,
                labels      TEXT NOT NULL,
                summary     TEXT NOT NULL,
                attributes  TEXT NOT NULL,
                created_at  TEXT NOT NULL,
                group_id    TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_nodes_group ON nodes(group_id);
            CREATE INDEX IF NOT EXISTS idx_nodes_name  ON nodes(name);

            CREATE TABLE IF NOT EXISTS edges (
                uuid              TEXT PRIMARY KEY,
                name              TEXT NOT NULL,
                fact              TEXT NOT NULL,
                source_node_uuid  TEXT NOT NULL,
                target_node_uuid  TEXT NOT NULL,
                edge_type         TEXT NOT NULL,
                created_at        TEXT NOT NULL,
                valid_at          TEXT,
                invalid_at        TEXT,
                group_id          TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_edges_group   ON edges(group_id);
            CREATE INDEX IF NOT EXISTS idx_edges_source  ON edges(source_node_uuid);
            CREATE INDEX IF NOT EXISTS idx_edges_target  ON edges(target_node_uuid);
            CREATE INDEX IF NOT EXISTS idx_edges_type    ON edges(edge_type);

            CREATE TABLE IF NOT EXISTS episodes (
                uuid                TEXT PRIMARY KEY,
                source              TEXT NOT NULL,
                source_description  TEXT NOT NULL,
                content             TEXT NOT NULL,
                created_at          TEXT NOT NULL,
                group_id            TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_episodes_group   ON episodes(group_id);
            CREATE INDEX IF NOT EXISTS idx_episodes_created ON episodes(created_at);
            CREATE INDEX IF NOT EXISTS idx_episodes_source  ON episodes(source);

            CREATE TABLE IF NOT EXISTS communities (
                uuid               TEXT PRIMARY KEY,
                name               TEXT NOT NULL,
                summary            TEXT NOT NULL,
                member_node_uuids  TEXT NOT NULL,
                group_id           TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_communities_group ON communities(group_id);
            """
        )
        await self._db.commit()

    async def _load_all(self) -> None:
        assert self._db is not None
        # Nodes + edges
        async with self._db.execute("SELECT * FROM nodes") as cur:
            rows = await cur.fetchall()
        for row in rows:
            node = Node.from_row(row)
            self._graph.add_node(
                node.uuid,
                data=node,
                group_id=node.group_id,
                labels=node.labels,
                name=node.name,
                summary=node.summary,
            )
        async with self._db.execute("SELECT * FROM edges") as cur:
            rows = await cur.fetchall()
        for row in rows:
            edge = Edge.from_row(row)
            self._graph.add_edge(
                edge.source_node_uuid,
                edge.target_node_uuid,
                key=edge.uuid,
                data=edge,
                group_id=edge.group_id,
                edge_type=edge.edge_type,
                name=edge.name,
            )
        # Episodes
        async with self._db.execute(
            "SELECT * FROM episodes ORDER BY created_at"
        ) as cur:
            rows = await cur.fetchall()
        for row in rows:
            ep = Episode.from_row(row)
            self._episodes.setdefault(ep.group_id, {})[ep.uuid] = ep
        # Communities
        async with self._db.execute("SELECT * FROM communities") as cur:
            rows = await cur.fetchall()
        for row in rows:
            comm = Community.from_row(row)
            self._communities.setdefault(comm.group_id, {})[comm.uuid] = comm

    async def close(self) -> None:
        if self._db is not None:
            await self._db.close()
            self._db = None
        self._initialized = False

    # ─── primitive writes ────────────────────────────────────────────────────

    async def add_node(
        self,
        name: str,
        labels: list[NodeLabel],
        summary: str,
        attributes: dict[str, Any] | None = None,
        group_id: str = "default",
    ) -> Node:
        """Create a Node, persist to SQLite, and add to the in-memory graph."""
        await self._ensure_initialized()
        node = Node(
            uuid=str(uuid.uuid4()),
            name=name,
            labels=list(labels),
            summary=summary,
            attributes=dict(attributes or {}),
            created_at=_now(),
            group_id=group_id,
        )
        self._graph.add_node(
            node.uuid,
            data=node,
            group_id=node.group_id,
            labels=node.labels,
            name=node.name,
            summary=node.summary,
        )
        assert self._db is not None
        await self._db.execute(
            "INSERT OR REPLACE INTO nodes "
            "(uuid, name, labels, summary, attributes, created_at, group_id) "
            "VALUES (:uuid, :name, :labels, :summary, :attributes, "
            ":created_at, :group_id)",
            node.to_row(),
        )
        await self._db.commit()
        logger.debug("added node %s (%s) group=%s", node.uuid, node.name, group_id)
        return node

    async def add_edge(
        self,
        source_uuid: str,
        target_uuid: str,
        edge_type: EdgeType,
        fact: str,
        group_id: str = "default",
        valid_at: datetime | None = None,
        name: str | None = None,
    ) -> Edge:
        """Create a directed Edge between two existing Nodes."""
        await self._ensure_initialized()
        if source_uuid not in self._graph:
            raise ValueError(f"source node {source_uuid} does not exist")
        if target_uuid not in self._graph:
            raise ValueError(f"target node {target_uuid} does not exist")
        edge = Edge(
            uuid=str(uuid.uuid4()),
            name=name or edge_type.value,
            fact=fact,
            source_node_uuid=source_uuid,
            target_node_uuid=target_uuid,
            edge_type=edge_type,
            created_at=_now(),
            valid_at=valid_at,
            invalid_at=None,
            group_id=group_id,
        )
        self._graph.add_edge(
            edge.source_node_uuid,
            edge.target_node_uuid,
            key=edge.uuid,
            data=edge,
            group_id=edge.group_id,
            edge_type=edge.edge_type,
            name=edge.name,
        )
        assert self._db is not None
        await self._db.execute(
            "INSERT OR REPLACE INTO edges "
            "(uuid, name, fact, source_node_uuid, target_node_uuid, edge_type, "
            "created_at, valid_at, invalid_at, group_id) "
            "VALUES (:uuid, :name, :fact, :source_node_uuid, :target_node_uuid, "
            ":edge_type, :created_at, :valid_at, :invalid_at, :group_id)",
            edge.to_row(),
        )
        await self._db.commit()
        logger.debug(
            "added edge %s %s->%s type=%s group=%s",
            edge.uuid,
            source_uuid,
            target_uuid,
            edge_type.value,
            group_id,
        )
        return edge

    async def add_episode(
        self,
        source: str,
        source_description: str,
        content: str,
        group_id: str = "default",
    ) -> Episode:
        """Record an episodic memory entry (agent response or tool execution)."""
        await self._ensure_initialized()
        if source not in ("message", "tool_execution"):
            raise ValueError(
                f"source must be 'message' or 'tool_execution', got {source!r}"
            )
        ep = Episode(
            uuid=str(uuid.uuid4()),
            source=source,
            source_description=source_description,
            content=content,
            created_at=_now(),
            group_id=group_id,
        )
        self._episodes.setdefault(group_id, {})[ep.uuid] = ep
        assert self._db is not None
        await self._db.execute(
            "INSERT OR REPLACE INTO episodes "
            "(uuid, source, source_description, content, created_at, group_id) "
            "VALUES (:uuid, :source, :source_description, :content, "
            ":created_at, :group_id)",
            ep.to_row(),
        )
        await self._db.commit()
        logger.debug(
            "added episode %s source=%s group=%s", ep.uuid, source, group_id
        )
        return ep

    async def add_community(
        self,
        name: str,
        summary: str,
        member_node_uuids: list[str],
        group_id: str = "default",
    ) -> Community:
        """Create a Community (cluster of related nodes)."""
        await self._ensure_initialized()
        comm = Community(
            uuid=str(uuid.uuid4()),
            name=name,
            summary=summary,
            member_node_uuids=list(member_node_uuids),
            group_id=group_id,
        )
        self._communities.setdefault(group_id, {})[comm.uuid] = comm
        assert self._db is not None
        await self._db.execute(
            "INSERT OR REPLACE INTO communities "
            "(uuid, name, summary, member_node_uuids, group_id) "
            "VALUES (:uuid, :name, :summary, :member_node_uuids, :group_id)",
            comm.to_row(),
        )
        await self._db.commit()
        logger.debug(
            "added community %s members=%d group=%s",
            comm.uuid,
            len(member_node_uuids),
            group_id,
        )
        return comm

    # ─── primitive reads ─────────────────────────────────────────────────────

    async def get_node(self, uuid_: str) -> Node | None:
        """Return the Node with ``uuid_`` or ``None``. Group-agnostic (caller
        must verify ``group_id`` if needed)."""
        await self._ensure_initialized()
        data = self._graph.nodes.get(uuid_)
        if data is None:
            return None
        node = data.get("data")
        return node if isinstance(node, Node) else None

    async def get_nodes_by_label(
        self,
        label: NodeLabel,
        group_id: str,
    ) -> list[Node]:
        """Return all Nodes in ``group_id`` that carry ``label``."""
        await self._ensure_initialized()
        out: list[Node] = []
        for n, data in self._graph.nodes(data=True):
            if data.get("group_id") != group_id:
                continue
            if label in (data.get("labels") or []):
                node = data.get("data")
                if isinstance(node, Node):
                    out.append(node)
        return out

    async def get_edges(
        self,
        node_uuid: str,
        direction: str = "both",
    ) -> list[Edge]:
        """Return Edges incident to ``node_uuid``.

        ``direction`` is ``"in"``, ``"out"``, or ``"both"``.
        """
        await self._ensure_initialized()
        if direction not in ("in", "out", "both"):
            raise ValueError(
                f"direction must be 'in', 'out', or 'both', got {direction!r}"
            )
        out: list[Edge] = []
        if direction in ("out", "both"):
            for _u, _v, key, data in self._graph.out_edges(
                node_uuid, keys=True, data=True
            ):
                edge = data.get("data")
                if isinstance(edge, Edge):
                    out.append(edge)
        if direction in ("in", "both"):
            for _u, _v, key, data in self._graph.in_edges(
                node_uuid, keys=True, data=True
            ):
                edge = data.get("data")
                if isinstance(edge, Edge):
                    out.append(edge)
        return out

    async def get_episodes(
        self,
        group_id: str,
        max_results: int = 10,
    ) -> list[Episode]:
        """Return the most recent ``max_results`` Episodes in ``group_id``."""
        await self._ensure_initialized()
        eps = list(self._episodes.get(group_id, {}).values())
        eps.sort(key=lambda e: e.created_at, reverse=True)
        return eps[:max_results]

    async def get_communities(self, group_id: str) -> list[Community]:
        """Return all Communities in ``group_id``."""
        await self._ensure_initialized()
        return list(self._communities.get(group_id, {}).values())

    # ─── fuzzy search primitives ─────────────────────────────────────────────

    async def search_nodes(
        self,
        query: str,
        group_id: str,
        max_results: int = 10,
    ) -> list[tuple[Node, float]]:
        """Fuzzy text match over node name + summary + attributes."""
        await self._ensure_initialized()
        scored: list[tuple[Node, float]] = []
        for _n, data in self._graph.nodes(data=True):
            if data.get("group_id") != group_id:
                continue
            node = data.get("data")
            if not isinstance(node, Node):
                continue
            attr_text = " ".join(f"{k}:{v}" for k, v in node.attributes.items())
            score = _fuzzy_score(
                query, [node.name, node.summary, attr_text]
            )
            if score > 0.0:
                scored.append((node, score))
        scored.sort(key=lambda x: x[1], reverse=True)
        return scored[:max_results]

    async def search_edges(
        self,
        query: str,
        group_id: str,
        max_results: int = 10,
    ) -> list[tuple[Edge, float]]:
        """Fuzzy text match over edge name + fact."""
        await self._ensure_initialized()
        scored: list[tuple[Edge, float]] = []
        for _u, _v, _k, data in self._graph.edges(data=True, keys=True):
            if data.get("group_id") != group_id:
                continue
            edge = data.get("data")
            if not isinstance(edge, Edge):
                continue
            score = _fuzzy_score(query, [edge.name, edge.fact])
            if score > 0.0:
                scored.append((edge, score))
        scored.sort(key=lambda x: x[1], reverse=True)
        return scored[:max_results]

    # ─────────────────────────────────────────────────────────────────────────
    # The 7 PentAGI search types
    # ─────────────────────────────────────────────────────────────────────────

    async def temporal_window_search(
        self,
        query: str,
        group_id: str,
        time_start: datetime,
        time_end: datetime,
        max_results: int = DEFAULT_TEMPORAL_MAX_RESULTS,
    ) -> dict[str, Any]:
        """Time-bounded fuzzy retrieval over nodes, edges, and episodes.

        Mirrors PentAGI ``TemporalWindowSearch``. Items are filtered by
        ``created_at`` falling within ``[time_start, time_end]`` and then
        fuzzy-ranked against ``query``.
        """
        await self._ensure_initialized()
        if time_end < time_start:
            raise ValueError("time_end must be after time_start")
        if max_results <= 0:
            max_results = DEFAULT_TEMPORAL_MAX_RESULTS

        node_hits: list[tuple[Node, float]] = []
        for _n, data in self._graph.nodes(data=True):
            if data.get("group_id") != group_id:
                continue
            node = data.get("data")
            if not isinstance(node, Node):
                continue
            if not (time_start <= node.created_at <= time_end):
                continue
            attr_text = " ".join(f"{k}:{v}" for k, v in node.attributes.items())
            score = _fuzzy_score(query, [node.name, node.summary, attr_text])
            if score > 0.0:
                node_hits.append((node, score))
        node_hits.sort(key=lambda x: x[1], reverse=True)
        node_hits = node_hits[:max_results]

        edge_hits: list[tuple[Edge, float]] = []
        for _u, _v, _k, data in self._graph.edges(data=True, keys=True):
            if data.get("group_id") != group_id:
                continue
            edge = data.get("data")
            if not isinstance(edge, Edge):
                continue
            if not (time_start <= edge.created_at <= time_end):
                continue
            score = _fuzzy_score(query, [edge.name, edge.fact])
            if score > 0.0:
                edge_hits.append((edge, score))
        edge_hits.sort(key=lambda x: x[1], reverse=True)
        edge_hits = edge_hits[:max_results]

        ep_hits: list[tuple[Episode, float]] = []
        for ep in self._episodes.get(group_id, {}).values():
            if not (time_start <= ep.created_at <= time_end):
                continue
            score = _fuzzy_score(
                query, [ep.source, ep.source_description, ep.content]
            )
            if score > 0.0:
                ep_hits.append((ep, score))
        ep_hits.sort(key=lambda x: x[1], reverse=True)
        ep_hits = ep_hits[:max_results]

        return {
            "query": query,
            "time_window": {"start": time_start, "end": time_end},
            "nodes": [n for n, _ in node_hits],
            "node_scores": [s for _, s in node_hits],
            "edges": [e for e, _ in edge_hits],
            "edge_scores": [s for _, s in edge_hits],
            "episodes": [e for e, _ in ep_hits],
            "episode_scores": [s for _, s in ep_hits],
        }

    async def entity_relationships_search(
        self,
        query: str,
        group_id: str,
        center_node_uuid: str,
        max_depth: int = DEFAULT_MAX_DEPTH,
        node_labels: list[NodeLabel] | None = None,
        edge_types: list[EdgeType] | None = None,
        max_results: int = DEFAULT_RELATIONSHIP_MAX_RESULTS,
    ) -> dict[str, Any]:
        """BFS from a center node up to ``max_depth`` hops, filtered by
        optional ``node_labels`` / ``edge_types``. Mirrors PentAGI
        ``EntityRelationshipsSearch``."""
        await self._ensure_initialized()
        if not center_node_uuid:
            raise ValueError("center_node_uuid is required")
        if max_depth <= 0:
            max_depth = DEFAULT_MAX_DEPTH
        if max_depth > MAX_ALLOWED_DEPTH:
            max_depth = MAX_ALLOWED_DEPTH
        if max_results <= 0:
            max_results = DEFAULT_RELATIONSHIP_MAX_RESULTS

        center = await self.get_node(center_node_uuid)
        if center is None or center.group_id != group_id:
            return {
                "query": query,
                "center_node": None,
                "nodes": [],
                "node_distances": [],
                "edges": [],
                "edge_distances": [],
            }

        label_set = set(node_labels) if node_labels else None
        type_set = set(edge_types) if edge_types else None

        # BFS over the in-memory MultiDiGraph, treating edges as undirected
        # for traversal (we still record direction in the returned edges).
        visited: dict[str, int] = {center.uuid: 0}
        collected_edges: list[tuple[Edge, int]] = []
        queue: list[tuple[str, int]] = [(center.uuid, 0)]
        while queue:
            current, depth = queue.pop(0)
            if depth >= max_depth:
                continue
            neighbors: list[tuple[str, Edge]] = []
            for _u, _v, _k, data in self._graph.out_edges(
                current, keys=True, data=True
            ):
                edge = data.get("data")
                if isinstance(edge, Edge) and edge.group_id == group_id:
                    neighbors.append((_v, edge))
            for _u, _v, _k, data in self._graph.in_edges(
                current, keys=True, data=True
            ):
                edge = data.get("data")
                if isinstance(edge, Edge) and edge.group_id == group_id:
                    neighbors.append((_u, edge))
            for other_uuid, edge in neighbors:
                if type_set is not None and edge.edge_type not in type_set:
                    continue
                edge_depth = depth + 1
                collected_edges.append((edge, edge_depth))
                if other_uuid not in visited:
                    visited[other_uuid] = edge_depth
                    queue.append((other_uuid, edge_depth))

        # Build candidate node list with distances, apply label filter + fuzzy
        candidate_nodes: list[tuple[Node, int, float]] = []
        for n_uuid, dist in visited.items():
            if n_uuid == center.uuid:
                continue
            data = self._graph.nodes.get(n_uuid)
            if data is None or data.get("group_id") != group_id:
                continue
            node = data.get("data")
            if not isinstance(node, Node):
                continue
            if label_set is not None and not (
                set(node.labels) & label_set
            ):
                continue
            attr_text = " ".join(f"{k}:{v}" for k, v in node.attributes.items())
            score = _fuzzy_score(query, [node.name, node.summary, attr_text])
            candidate_nodes.append((node, dist, score))
        candidate_nodes.sort(key=lambda x: (-x[2], x[1]))
        candidate_nodes = candidate_nodes[:max_results]

        # Deduplicate edges by uuid, keep closest distance, then fuzzy-rank
        seen_edge_uuids: set[str] = set()
        unique_edges: list[tuple[Edge, int]] = []
        for edge, dist in collected_edges:
            if edge.uuid in seen_edge_uuids:
                continue
            seen_edge_uuids.add(edge.uuid)
            unique_edges.append((edge, dist))
        unique_edges.sort(key=lambda x: x[1])
        unique_edges = unique_edges[:max_results]

        # If node_labels filter is provided, restrict edges to those whose
        # endpoints survive the filter
        survivor_uuids = {n.uuid for n, _, _ in candidate_nodes}
        survivor_uuids.add(center.uuid)
        if label_set is not None:
            unique_edges = [
                (e, d)
                for e, d in unique_edges
                if e.source_node_uuid in survivor_uuids
                and e.target_node_uuid in survivor_uuids
            ]

        return {
            "query": query,
            "center_node": center,
            "nodes": [n for n, _, _ in candidate_nodes],
            "node_distances": [d for _, d, _ in candidate_nodes],
            "edges": [e for e, _ in unique_edges],
            "edge_distances": [d for _, d in unique_edges],
        }

    async def diverse_results_search(
        self,
        query: str,
        group_id: str,
        diversity_level: str = DEFAULT_DIVERSITY_LEVEL,
        max_results: int = DEFAULT_DIVERSE_MAX_RESULTS,
    ) -> dict[str, Any]:
        """Diverse, non-redundant retrieval via MMR reranking.

        Mirrors PentAGI ``DiverseResultsSearch``. Candidates are gathered via
        fuzzy match over nodes, edges, and episodes, then reranked with
        Maximal Marginal Relevance. Communities are derived from
        connected-component clustering of the matching nodes.
        """
        await self._ensure_initialized()
        if diversity_level not in ALLOWED_DIVERSITY_LEVELS:
            raise ValueError(
                f"invalid diversity_level: {diversity_level} "
                f"(allowed: {sorted(ALLOWED_DIVERSITY_LEVELS)})"
            )
        if max_results <= 0:
            max_results = DEFAULT_DIVERSE_MAX_RESULTS

        node_hits = await self.search_nodes(query, group_id, max_results * 3)
        edge_hits = await self.search_edges(query, group_id, max_results * 3)
        ep_hits = await self._search_episodes(query, group_id, max_results * 3)

        node_items = [n for n, _ in node_hits]
        node_texts = [
            f"{n.name} {n.summary} "
            + " ".join(f"{k}:{v}" for k, v in n.attributes.items())
            for n in node_items
        ]
        node_rels = [s for _, s in node_hits]
        reranked_nodes = _mmr_rerank(
            node_items,
            node_texts,
            node_rels,
            query,
            diversity_level,
            max_results,
        )

        edge_items = [e for e, _ in edge_hits]
        edge_texts = [f"{e.name} {e.fact}" for e in edge_items]
        edge_rels = [s for _, s in edge_hits]
        reranked_edges = _mmr_rerank(
            edge_items,
            edge_texts,
            edge_rels,
            query,
            diversity_level,
            max_results,
        )

        ep_items = [e for e, _ in ep_hits]
        ep_texts = [f"{e.source} {e.source_description} {e.content}" for e in ep_items]
        ep_rels = [s for _, s in ep_hits]
        reranked_eps = _mmr_rerank(
            ep_items,
            ep_texts,
            ep_rels,
            query,
            diversity_level,
            max_results,
        )

        # Communities: connected components among the matched nodes, restricted
        # to this group_id
        communities = await self._build_communities_for(
            [n for n, _, _ in reranked_nodes], group_id
        )
        comm_items = communities
        comm_texts = [f"{c.name} {c.summary}" for c in comm_items]
        comm_rels = [_fuzzy_score(query, [c.name, c.summary]) for c in comm_items]
        reranked_comms = _mmr_rerank(
            comm_items,
            comm_texts,
            comm_rels,
            query,
            diversity_level,
            max_results,
        )

        return {
            "query": query,
            "communities": [c for c, _, _ in reranked_comms],
            "community_mmr_scores": [s for _, _, s in reranked_comms],
            "nodes": [n for n, _, _ in reranked_nodes],
            "node_mmr_scores": [s for _, _, s in reranked_nodes],
            "edges": [e for e, _, _ in reranked_edges],
            "edge_mmr_scores": [s for _, _, s in reranked_edges],
            "episodes": [e for e, _, _ in reranked_eps],
            "episode_scores": [r for _, r, _ in reranked_eps],
        }

    async def episode_context_search(
        self,
        query: str,
        group_id: str,
        max_results: int = DEFAULT_EPISODE_MAX_RESULTS,
    ) -> dict[str, Any]:
        """Search through agent responses and tool execution records.

        Mirrors PentAGI ``EpisodeContextSearch``. Returns matching episodes
        plus any nodes whose ``name`` is mentioned in the episode content.
        """
        await self._ensure_initialized()
        if max_results <= 0:
            max_results = DEFAULT_EPISODE_MAX_RESULTS

        ep_hits = await self._search_episodes(query, group_id, max_results)
        episodes = [e for e, _ in ep_hits]
        ep_scores = [s for _, s in ep_hits]

        # Mentioned nodes: entities whose name appears in any matched episode
        mentioned: dict[str, float] = {}
        for ep in episodes:
            text = ep.content.lower()
            for _n, data in self._graph.nodes(data=True):
                if data.get("group_id") != group_id:
                    continue
                node = data.get("data")
                if not isinstance(node, Node):
                    continue
                if not node.name or len(node.name) < 3:
                    continue
                if node.name.lower() in text:
                    score = _fuzzy_score(
                        query, [node.name, node.summary]
                    )
                    cur = mentioned.get(node.uuid, 0.0)
                    if score > cur:
                        mentioned[node.uuid] = score

        mentioned_nodes: list[tuple[Node, float]] = []
        for n_uuid, score in mentioned.items():
            data = self._graph.nodes.get(n_uuid)
            if data is None:
                continue
            node = data.get("data")
            if isinstance(node, Node):
                mentioned_nodes.append((node, score))
        mentioned_nodes.sort(key=lambda x: x[1], reverse=True)
        mentioned_nodes = mentioned_nodes[:max_results]

        return {
            "query": query,
            "episodes": episodes,
            "reranker_scores": ep_scores,
            "mentioned_nodes": [n for n, _ in mentioned_nodes],
            "mentioned_node_scores": [s for _, s in mentioned_nodes],
        }

    async def successful_tools_search(
        self,
        query: str,
        group_id: str,
        min_mentions: int = DEFAULT_MIN_MENTIONS,
        max_results: int = DEFAULT_SUCCESSFUL_MAX_RESULTS,
    ) -> dict[str, Any]:
        """Find successful tool executions and attack patterns.

        Mirrors PentAGI ``SuccessfulToolsSearch``. Filters episodes with
        ``source == "tool_execution"`` whose content indicates success
        (status ``success``), then surfaces TOOL nodes mentioned at least
        ``min_mentions`` times along with their DISCOVERED_BY edges.
        """
        await self._ensure_initialized()
        if min_mentions <= 0:
            min_mentions = DEFAULT_MIN_MENTIONS
        if max_results <= 0:
            max_results = DEFAULT_SUCCESSFUL_MAX_RESULTS

        successful: list[Episode] = []
        tool_mention_count: Counter = Counter()
        for ep in self._episodes.get(group_id, {}).values():
            if ep.source != "tool_execution":
                continue
            content_lc = ep.content.lower()
            # Heuristic: status line indicates success
            if "status: success" not in content_lc and "status:success" not in content_lc:
                continue
            # Match against query
            score = _fuzzy_score(
                query, [ep.source_description, ep.content]
            )
            if score <= 0.0 and query.strip():
                continue
            successful.append(ep)
            # Find TOOL nodes whose name appears in content
            for _n, data in self._graph.nodes(data=True):
                if data.get("group_id") != group_id:
                    continue
                node = data.get("data")
                if not isinstance(node, Node):
                    continue
                if NodeLabel.TOOL not in node.labels:
                    continue
                if not node.name or len(node.name) < 2:
                    continue
                if node.name.lower() in content_lc:
                    tool_mention_count[node.uuid] += 1

        successful.sort(
            key=lambda e: _fuzzy_score(query, [e.source_description, e.content]),
            reverse=True,
        )
        successful = successful[:max_results]

        # Edges to TOOL nodes meeting min_mentions threshold
        proven_tools = {
            uuid_ for uuid_, c in tool_mention_count.items() if c >= min_mentions
        }
        success_edges: list[tuple[Edge, int]] = []
        for _u, _v, _k, data in self._graph.edges(data=True, keys=True):
            if data.get("group_id") != group_id:
                continue
            edge = data.get("data")
            if not isinstance(edge, Edge):
                continue
            if edge.edge_type != EdgeType.DISCOVERED_BY:
                continue
            if (
                edge.source_node_uuid in proven_tools
                or edge.target_node_uuid in proven_tools
            ):
                mentions = tool_mention_count.get(edge.source_node_uuid, 0) or \
                    tool_mention_count.get(edge.target_node_uuid, 0)
                success_edges.append((edge, mentions))
        success_edges.sort(key=lambda x: x[1], reverse=True)
        success_edges = success_edges[:max_results]

        return {
            "query": query,
            "episodes": successful,
            "episode_scores": [
                _fuzzy_score(query, [e.source_description, e.content])
                for e in successful
            ],
            "edges": [e for e, _ in success_edges],
            "edge_mention_counts": [float(c) for _, c in success_edges],
        }

    async def recent_context_search(
        self,
        query: str,
        group_id: str,
        recency_window: str = DEFAULT_RECENCY_WINDOW,
        max_results: int = DEFAULT_RECENT_MAX_RESULTS,
    ) -> dict[str, Any]:
        """Recency-bounded context retrieval.

        Mirrors PentAGI ``RecentContextSearch``. Allowed windows: ``1h``,
        ``6h``, ``24h``, ``7d``.
        """
        await self._ensure_initialized()
        if recency_window not in ALLOWED_RECENCY_WINDOWS:
            raise ValueError(
                f"invalid recency_window: {recency_window} "
                f"(allowed: {sorted(ALLOWED_RECENCY_WINDOWS)})"
            )
        if max_results <= 0:
            max_results = DEFAULT_RECENT_MAX_RESULTS

        now = _now()
        start = now - RECENCY_WINDOW_DELTA[recency_window]
        return await self.temporal_window_search(
            query=query,
            group_id=group_id,
            time_start=start,
            time_end=now,
            max_results=max_results,
        )

    async def entity_by_label_search(
        self,
        query: str,
        group_id: str,
        node_labels: list[NodeLabel],
        edge_types: list[EdgeType] | None = None,
        max_results: int = DEFAULT_LABEL_MAX_RESULTS,
    ) -> dict[str, Any]:
        """Type-filtered entity inventory search.

        Mirrors PentAGI ``EntityByLabelSearch``. Returns Nodes carrying any of
        ``node_labels`` plus their associated edges (optionally filtered by
        ``edge_types``).
        """
        await self._ensure_initialized()
        if not node_labels:
            raise ValueError("node_labels is required for entity_by_label search")
        if max_results <= 0:
            max_results = DEFAULT_LABEL_MAX_RESULTS
        label_set = set(node_labels)
        type_set = set(edge_types) if edge_types else None

        node_hits: list[tuple[Node, float]] = []
        for _n, data in self._graph.nodes(data=True):
            if data.get("group_id") != group_id:
                continue
            node = data.get("data")
            if not isinstance(node, Node):
                continue
            if not (set(node.labels) & label_set):
                continue
            attr_text = " ".join(f"{k}:{v}" for k, v in node.attributes.items())
            score = _fuzzy_score(query, [node.name, node.summary, attr_text])
            # When query is empty, return all matching nodes in insertion order
            node_hits.append((node, score if query.strip() else 1.0))
        node_hits.sort(key=lambda x: x[1], reverse=True)
        node_hits = node_hits[:max_results]
        node_uuid_set = {n.uuid for n, _ in node_hits}

        edge_hits: list[tuple[Edge, float]] = []
        for _u, _v, _k, data in self._graph.edges(data=True, keys=True):
            if data.get("group_id") != group_id:
                continue
            edge = data.get("data")
            if not isinstance(edge, Edge):
                continue
            if (
                edge.source_node_uuid not in node_uuid_set
                and edge.target_node_uuid not in node_uuid_set
            ):
                continue
            if type_set is not None and edge.edge_type not in type_set:
                continue
            score = _fuzzy_score(query, [edge.name, edge.fact])
            edge_hits.append((edge, score if query.strip() else 1.0))
        edge_hits.sort(key=lambda x: x[1], reverse=True)
        edge_hits = edge_hits[:max_results]

        return {
            "query": query,
            "nodes": [n for n, _ in node_hits],
            "node_scores": [s for _, s in node_hits],
            "edges": [e for e, _ in edge_hits],
            "edge_scores": [s for _, s in edge_hits],
        }

    # ─── private search helpers ──────────────────────────────────────────────

    async def _search_episodes(
        self,
        query: str,
        group_id: str,
        max_results: int,
    ) -> list[tuple[Episode, float]]:
        scored: list[tuple[Episode, float]] = []
        for ep in self._episodes.get(group_id, {}).values():
            score = _fuzzy_score(
                query, [ep.source, ep.source_description, ep.content]
            )
            if score > 0.0:
                scored.append((ep, score))
        scored.sort(key=lambda x: x[1], reverse=True)
        return scored[:max_results]

    async def _build_communities_for(
        self,
        nodes: list[Node],
        group_id: str,
    ) -> list[Community]:
        """Group ``nodes`` into Communities by connected component on the
        in-memory graph (restricted to ``group_id``)."""
        if not nodes:
            return []
        node_uuid_set = {n.uuid for n in nodes}
        # Build a subgraph restricted to the matched nodes and this group
        sub = self._nx.MultiDiGraph()
        for n in nodes:
            sub.add_node(n.uuid)
        for u, v, _k, data in self._graph.edges(data=True, keys=True):
            if data.get("group_id") != group_id:
                continue
            if u in node_uuid_set and v in node_uuid_set:
                sub.add_edge(u, v)
        # Weakly-connected components → communities
        components = list(self._nx.weakly_connected_components(sub))
        out: list[Community] = []
        for i, comp in enumerate(components):
            members = list(comp)
            member_nodes = [
                self._graph.nodes[m].get("data")
                for m in members
                if m in self._graph.nodes
            ]
            member_nodes = [n for n in member_nodes if isinstance(n, Node)]
            if not member_nodes:
                continue
            labels_seen = sorted(
                {l.value for n in member_nodes for l in n.labels}
            )
            name = f"Cluster-{i + 1} ({', '.join(labels_seen[:3])})"
            summary = (
                f"{len(member_nodes)} entities sharing relationships: "
                + "; ".join(n.name for n in member_nodes[:5])
            )
            out.append(
                Community(
                    uuid=str(uuid.uuid4()),
                    name=name,
                    summary=summary,
                    member_node_uuids=members,
                    group_id=group_id,
                )
            )
        return out

    # ─────────────────────────────────────────────────────────────────────────
    # Ingestion (port of PentAGI's agent_response.tmpl + tool_execution.tmpl)
    # ─────────────────────────────────────────────────────────────────────────

    async def ingest_agent_response(
        self,
        agent_type: str,
        response: str,
        task_id: int | None,
        subtask_id: int | None,
        group_id: str,
    ) -> Episode:
        """Ingest an agent response as an episodic memory entry.

        Ported from PentAGI ``storeAgentResponseToGraphiti`` +
        ``templates/graphiti/agent_response.tmpl``. The rendered template
        becomes the episode ``content``; ``source = "message"``.
        """
        content = self._render_agent_response(
            agent_type=agent_type,
            response=response,
            task_id=task_id,
            subtask_id=subtask_id,
        )
        parts = [f"Elengenix {agent_type} agent execution"]
        if task_id is not None:
            parts.append(f"task {task_id}")
        if subtask_id is not None:
            parts.append(f"subtask {subtask_id}")
        source_description = ", ".join(parts)
        return await self.add_episode(
            source="message",
            source_description=source_description,
            content=content,
            group_id=group_id,
        )

    async def ingest_tool_execution(
        self,
        tool_name: str,
        description: str,
        is_barrier: bool,
        arguments: str | dict[str, Any],
        invoked_by: str,
        status: str,
        result: str,
        task_id: int | None,
        subtask_id: int | None,
        group_id: str,
    ) -> Episode:
        """Ingest a tool execution as an episodic memory entry.

        Ported from PentAGI ``storeToolExecutionToGraphiti`` +
        ``templates/graphiti/tool_execution.tmpl``. The rendered template
        becomes the episode ``content``; ``source = "tool_execution"``.
        """
        content = self._render_tool_execution(
            tool_name=tool_name,
            description=description,
            is_barrier=is_barrier,
            arguments=arguments,
            invoked_by=invoked_by,
            status=status,
            result=result,
            task_id=task_id,
            subtask_id=subtask_id,
        )
        parts = ["Elengenix tool execution"]
        if task_id is not None:
            parts.append(f"task {task_id}")
        if subtask_id is not None:
            parts.append(f"subtask {subtask_id}")
        source_description = ", ".join(parts)
        return await self.add_episode(
            source="tool_execution",
            source_description=source_description,
            content=content,
            group_id=group_id,
        )

    @staticmethod
    def _render_agent_response(
        agent_type: str,
        response: str,
        task_id: int | None,
        subtask_id: int | None,
    ) -> str:
        """Render the agent_response template (verbatim port from
        ``pentagi/backend/pkg/templates/graphiti/agent_response.tmpl``)."""
        return (
            f"Agent: {agent_type}\n"
            f"Response: {response}\n"
            f"Context: Task {task_id}, Subtask {subtask_id}\n"
        )

    @staticmethod
    def _render_tool_execution(
        tool_name: str,
        description: str,
        is_barrier: bool,
        arguments: str | dict[str, Any],
        invoked_by: str,
        status: str,
        result: str,
        task_id: int | None,
        subtask_id: int | None,
    ) -> str:
        """Render the tool_execution template (verbatim port from
        ``pentagi/backend/pkg/templates/graphiti/tool_execution.tmpl``)."""
        args_str = (
            arguments
            if isinstance(arguments, str)
            else json.dumps(arguments, default=str, sort_keys=True)
        )
        return (
            f"Tool: {tool_name}\n"
            f"Description: {description}\n"
            f"Barrier Function: {is_barrier}\n"
            f"Arguments: {args_str}\n"
            f"Invoked by: {invoked_by} Agent\n"
            f"Status: {status}\n"
            f"Result: {result}\n"
            f"Context: Task {task_id}, Subtask {subtask_id}\n"
        )

    # ─────────────────────────────────────────────────────────────────────────
    # Markdown formatters (one per search type — port of PentAGI
    # FormatGraphiti*Results functions)
    # ─────────────────────────────────────────────────────────────────────────

    def format_temporal_window_results(self, results: dict[str, Any]) -> str:
        """Port of PentAGI ``FormatGraphitiTemporalResults``."""
        q = results.get("query", "")
        tw = results.get("time_window") or {}
        start = tw.get("start")
        end = tw.get("end")
        out: list[str] = [
            "# Temporal Search Results",
            "",
            f"**Query:** {q}",
            "",
            f"**Time Window:** {_iso(start) if start else 'N/A'}"
            f" to {_iso(end) if end else 'N/A'}",
            "",
        ]
        edges: list[Edge] = results.get("edges", []) or []
        edge_scores: list[float] = results.get("edge_scores", []) or []
        if edges:
            out.append("## Facts & Relationships")
            out.append("")
            for i, edge in enumerate(edges):
                score_str = (
                    f" (score: {edge_scores[i]:.3f})"
                    if i < len(edge_scores)
                    else ""
                )
                out.append(f"{i + 1}. **{edge.name}**{score_str}")
                out.append(f"   - Fact: {edge.fact}")
                out.append(f"   - Created: {_iso(edge.created_at)}")
                if edge.valid_at is not None:
                    out.append(f"   - Valid At: {_iso(edge.valid_at)}")
                out.append("")

        nodes: list[Node] = results.get("nodes", []) or []
        node_scores: list[float] = results.get("node_scores", []) or []
        if nodes:
            out.append("## Entities")
            out.append("")
            for i, node in enumerate(nodes):
                score_str = (
                    f" (score: {node_scores[i]:.3f})"
                    if i < len(node_scores)
                    else ""
                )
                out.append(f"{i + 1}. **{node.name}**{score_str}")
                out.append(f"   - UUID: {node.uuid}")
                out.append(
                    f"   - Labels: {[l.value for l in node.labels]}"
                )
                out.append(f"   - Summary: {node.summary}")
                if node.attributes:
                    out.append(f"   - Attributes: {node.attributes}")
                out.append("")

        episodes: list[Episode] = results.get("episodes", []) or []
        ep_scores: list[float] = results.get("episode_scores", []) or []
        if episodes:
            out.append("## Agent Responses & Tool Executions")
            out.append("")
            for i, ep in enumerate(episodes):
                score_str = (
                    f" (score: {ep_scores[i]:.3f})"
                    if i < len(ep_scores)
                    else ""
                )
                out.append(f"{i + 1}. **{ep.source}**{score_str}")
                out.append(f"   - Description: {ep.source_description}")
                out.append(f"   - Created: {_iso(ep.created_at)}")
                out.append("   - Content:")
                out.append("```")
                out.append(ep.content)
                out.append("```")
                out.append("")

        if not edges and not nodes and not episodes:
            out.append("No results found in the specified time window.")
            out.append("")
        return "\n".join(out)

    def format_entity_relationships_results(self, results: dict[str, Any]) -> str:
        """Port of PentAGI ``FormatGraphitiEntityRelationshipResults``."""
        q = results.get("query", "")
        out: list[str] = [
            "# Entity Relationship Search Results",
            "",
            f"**Query:** {q}",
            "",
        ]
        center: Node | None = results.get("center_node")
        if center is not None:
            out.append(f"## Center Node: {center.name}")
            out.append(f"- UUID: {center.uuid}")
            out.append(f"- Summary: {center.summary}")
            out.append("")

        edges: list[Edge] = results.get("edges", []) or []
        edge_dists: list[int] = results.get("edge_distances", []) or []
        if edges:
            out.append("## Related Facts & Relationships")
            out.append("")
            for i, edge in enumerate(edges):
                dist_str = (
                    f" (distance: {edge_dists[i]})"
                    if i < len(edge_dists)
                    else ""
                )
                out.append(f"{i + 1}. **{edge.name}**{dist_str}")
                out.append(f"   - Fact: {edge.fact}")
                out.append(f"   - Source: {edge.source_node_uuid}")
                out.append(f"   - Target: {edge.target_node_uuid}")
                out.append("")

        nodes: list[Node] = results.get("nodes", []) or []
        node_dists: list[int] = results.get("node_distances", []) or []
        if nodes:
            out.append("## Related Entities")
            out.append("")
            for i, node in enumerate(nodes):
                dist_str = (
                    f" (distance: {node_dists[i]})"
                    if i < len(node_dists)
                    else ""
                )
                out.append(f"{i + 1}. **{node.name}**{dist_str}")
                out.append(f"   - UUID: {node.uuid}")
                out.append(
                    f"   - Labels: {[l.value for l in node.labels]}"
                )
                out.append(f"   - Summary: {node.summary}")
                out.append("")

        if not edges and not nodes:
            out.append("No relationships found matching criteria.")
            out.append("")
        return "\n".join(out)

    def format_diverse_results(self, results: dict[str, Any]) -> str:
        """Port of PentAGI ``FormatGraphitiDiverseResults``."""
        q = results.get("query", "")
        out: list[str] = [
            "# Diverse Search Results",
            "",
            f"**Query:** {q}",
            "",
        ]
        comms: list[Community] = results.get("communities", []) or []
        comm_scores: list[float] = (
            results.get("community_mmr_scores", []) or []
        )
        if comms:
            out.append("## Communities (Context Clusters)")
            out.append("")
            for i, comm in enumerate(comms):
                score_str = (
                    f" (MMR score: {comm_scores[i]:.3f})"
                    if i < len(comm_scores)
                    else ""
                )
                out.append(f"{i + 1}. **{comm.name}**{score_str}")
                out.append(f"   - Summary: {comm.summary}")
                out.append("")

        edges: list[Edge] = results.get("edges", []) or []
        edge_scores: list[float] = results.get("edge_mmr_scores", []) or []
        if edges:
            out.append("## Diverse Facts")
            out.append("")
            for i, edge in enumerate(edges):
                score_str = (
                    f" (MMR score: {edge_scores[i]:.3f})"
                    if i < len(edge_scores)
                    else ""
                )
                out.append(f"{i + 1}. **{edge.name}**{score_str}")
                out.append(f"   - Fact: {edge.fact}")
                out.append("")

        episodes: list[Episode] = results.get("episodes", []) or []
        ep_scores: list[float] = results.get("episode_scores", []) or []
        if episodes:
            out.append("## Diverse Agent Activity")
            out.append("")
            for i, ep in enumerate(episodes):
                score_str = (
                    f" (score: {ep_scores[i]:.3f})"
                    if i < len(ep_scores)
                    else ""
                )
                out.append(f"{i + 1}. **{ep.source}**{score_str}")
                out.append(f"   - Description: {ep.source_description}")
                out.append(f"   - Content: {_truncate(ep.content, 200)}")
                out.append("")
        return "\n".join(out)

    def format_episode_context_results(self, results: dict[str, Any]) -> str:
        """Port of PentAGI ``FormatGraphitiEpisodeContextResults``."""
        q = results.get("query", "")
        out: list[str] = [
            "# Episode Context Results",
            "",
            f"**Query:** {q}",
            "",
        ]
        episodes: list[Episode] = results.get("episodes", []) or []
        ep_scores: list[float] = results.get("reranker_scores", []) or []
        if episodes:
            out.append("## Relevant Agent Activity")
            out.append("")
            for i, ep in enumerate(episodes):
                score_str = (
                    f" (relevance: {ep_scores[i]:.3f})"
                    if i < len(ep_scores)
                    else ""
                )
                out.append(f"{i + 1}. **{ep.source}**{score_str}")
                out.append(f"   - Time: {_iso(ep.created_at)}")
                out.append(f"   - Description: {ep.source_description}")
                out.append("   - Content:")
                out.append("```")
                out.append(ep.content)
                out.append("```")
                out.append("")

        mentioned: list[Node] = results.get("mentioned_nodes", []) or []
        mentioned_scores: list[float] = (
            results.get("mentioned_node_scores", []) or []
        )
        if mentioned:
            out.append("## Mentioned Entities")
            out.append("")
            for i, node in enumerate(mentioned):
                score_str = (
                    f" (relevance: {mentioned_scores[i]:.3f})"
                    if i < len(mentioned_scores)
                    else ""
                )
                out.append(
                    f"- **{node.name}**{score_str}: {node.summary}"
                )

        if not episodes:
            out.append("No episode context found.")
            out.append("")
        return "\n".join(out)

    def format_successful_tools_results(self, results: dict[str, Any]) -> str:
        """Port of PentAGI ``FormatGraphitiSuccessfulToolsResults``."""
        q = results.get("query", "")
        out: list[str] = [
            "# Successful Tools & Techniques",
            "",
            f"**Query:** {q}",
            "",
        ]
        episodes: list[Episode] = results.get("episodes", []) or []
        ep_scores: list[float] = results.get("episode_scores", []) or []
        if episodes:
            out.append("## Successful Executions")
            out.append("")
            for i, ep in enumerate(episodes):
                score_str = (
                    f" (score: {ep_scores[i]:.3f})"
                    if i < len(ep_scores)
                    else ""
                )
                out.append(f"{i + 1}. **{ep.source}**{score_str}")
                out.append(f"   - Description: {ep.source_description}")
                out.append("   - Command/Output:")
                out.append("```")
                out.append(ep.content)
                out.append("```")
                out.append("")

        edges: list[Edge] = results.get("edges", []) or []
        counts: list[float] = results.get("edge_mention_counts", []) or []
        if edges:
            out.append("## Related Facts (Success Indicators)")
            out.append("")
            for i, edge in enumerate(edges):
                count_str = (
                    f" (mentions: {int(counts[i])})"
                    if i < len(counts)
                    else ""
                )
                out.append(f"- **{edge.name}**{count_str}: {edge.fact}")

        if not episodes:
            out.append(
                "No successful tool executions found matching criteria."
            )
            out.append("")
        return "\n".join(out)

    def format_recent_context_results(self, results: dict[str, Any]) -> str:
        """Port of PentAGI ``FormatGraphitiRecentContextResults``."""
        q = results.get("query", "")
        tw = results.get("time_window") or {}
        start = tw.get("start")
        end = tw.get("end")
        out: list[str] = [
            "# Recent Context",
            "",
            f"**Query:** {q}",
            "",
            f"**Time Window:** {_iso(start) if start else 'N/A'}"
            f" to {_iso(end) if end else 'N/A'}",
            "",
        ]
        nodes: list[Node] = results.get("nodes", []) or []
        node_scores: list[float] = results.get("node_scores", []) or []
        if nodes:
            out.append("## Recently Discovered Entities")
            out.append("")
            for i, node in enumerate(nodes):
                score_str = (
                    f" (score: {node_scores[i]:.3f})"
                    if i < len(node_scores)
                    else ""
                )
                out.append(f"{i + 1}. **{node.name}**{score_str}")
                out.append(
                    f"   - Labels: {[l.value for l in node.labels]}"
                )
                out.append(f"   - Summary: {node.summary}")
                out.append("")

        edges: list[Edge] = results.get("edges", []) or []
        edge_scores: list[float] = results.get("edge_scores", []) or []
        if edges:
            out.append("## Recent Facts")
            out.append("")
            for i, edge in enumerate(edges):
                score_str = (
                    f" (score: {edge_scores[i]:.3f})"
                    if i < len(edge_scores)
                    else ""
                )
                out.append(
                    f"- **{edge.name}**{score_str}: {edge.fact}"
                )

        episodes: list[Episode] = results.get("episodes", []) or []
        ep_scores: list[float] = results.get("episode_scores", []) or []
        if episodes:
            out.append("## Recent Activity")
            out.append("")
            for i, ep in enumerate(episodes):
                score_str = (
                    f" (score: {ep_scores[i]:.3f})"
                    if i < len(ep_scores)
                    else ""
                )
                out.append(
                    f"- **{ep.source}**{score_str}: {ep.source_description}"
                )

        if not nodes and not edges and not episodes:
            out.append(
                "No recent context found in the specified window."
            )
            out.append("")
        return "\n".join(out)

    def format_entity_by_label_results(self, results: dict[str, Any]) -> str:
        """Port of PentAGI ``FormatGraphitiEntityByLabelResults``."""
        q = results.get("query", "")
        out: list[str] = [
            "# Entity Inventory Search",
            "",
            f"**Query:** {q}",
            "",
        ]
        nodes: list[Node] = results.get("nodes", []) or []
        node_scores: list[float] = results.get("node_scores", []) or []
        if nodes:
            out.append("## Matching Entities")
            out.append("")
            for i, node in enumerate(nodes):
                score_str = (
                    f" (score: {node_scores[i]:.3f})"
                    if i < len(node_scores)
                    else ""
                )
                out.append(f"{i + 1}. **{node.name}**{score_str}")
                out.append(f"   - UUID: {node.uuid}")
                out.append(
                    f"   - Labels: {[l.value for l in node.labels]}"
                )
                out.append(f"   - Summary: {node.summary}")
                if node.attributes:
                    out.append(f"   - Attributes: {node.attributes}")
                out.append("")

        edges: list[Edge] = results.get("edges", []) or []
        edge_scores: list[float] = results.get("edge_scores", []) or []
        if edges:
            out.append("## Associated Facts")
            out.append("")
            for i, edge in enumerate(edges):
                score_str = (
                    f" (score: {edge_scores[i]:.3f})"
                    if i < len(edge_scores)
                    else ""
                )
                out.append(
                    f"- **{edge.name}**{score_str}: {edge.fact}"
                )

        if not nodes:
            out.append(
                "No entities found matching the specified labels/query."
            )
            out.append("")
        return "\n".join(out)


__all__ = [
    "ALLOWED_DIVERSITY_LEVELS",
    "ALLOWED_RECENCY_WINDOWS",
    "Community",
    "DEFAULT_DIVERSITY_LEVEL",
    "DEFAULT_EPISODE_MAX_RESULTS",
    "DEFAULT_LABEL_MAX_RESULTS",
    "DEFAULT_MAX_DEPTH",
    "DEFAULT_MIN_MENTIONS",
    "DEFAULT_RECENCY_WINDOW",
    "DEFAULT_RECENT_MAX_RESULTS",
    "DEFAULT_RELATIONSHIP_MAX_RESULTS",
    "DEFAULT_SUCCESSFUL_MAX_RESULTS",
    "DEFAULT_TEMPORAL_MAX_RESULTS",
    "DIVERSITY_LAMBDA",
    "Edge",
    "EdgeType",
    "Episode",
    "KnowledgeGraph",
    "Node",
    "NodeLabel",
    "RECENCY_WINDOW_DELTA",
]
