"""elengenix/knowledge_graph/community.py — community detection & merging.

Detects communities (clusters of tightly-connected nodes) in the
KnowledgeGraph using NetworkX's Louvain algorithm (preferred) with a
greedy-modularity fallback for graphs where Louvain is unavailable or
returns a single degenerate partition. Communities are persisted back
into the KG via ``kg.add_community`` (Task 5-a's API) and can be
LLM-summarised for human-readable overviews.

The detector is **lazy** about its heavy dependency: ``networkx`` is
imported inside each method so the module can be AST-validated and
imported in environments where ``networkx`` is not installed. It
gracefully handles the case where the KG exposes its in-memory NetworkX
graph directly (``kg._graph`` — used by Task 5-a) and falls back to the
public ``get_nodes_by_label`` / ``get_edges`` API when ``_graph`` is
not accessible.

Public API:
    CommunityDetector  — main class.
    Community          — re-exported from Task 5-a's ``graph.py``.
"""

from __future__ import annotations

import logging
import uuid
from typing import Any, Iterable, Protocol, TYPE_CHECKING

from .extractor import Edge, EdgeType, Node, NodeLabel, _label_str, _now_dt
from .graph import Community, KnowledgeGraph  # noqa: F401  (re-exported)

if TYPE_CHECKING:  # pragma: no cover - typing only
    from elengenix.agents.base import LLMClient

logger = logging.getLogger("elengenix.knowledge_graph.community")


# ---------------------------------------------------------------------------
# Protocol — structural type for the subset of KG methods we need.
# ---------------------------------------------------------------------------


class _KGWithCommunities(Protocol):
    """Structural protocol for a KG that supports community detection.

    Matches Task 5-a's :class:`KnowledgeGraph` public surface. Concrete
    implementations may expose more, but at minimum must provide these
    async methods.
    """

    async def add_community(
        self,
        name: str,
        summary: str,
        member_node_uuids: list[str],
        group_id: str = "default",
    ) -> Community:
        """Persist a community."""
        ...

    async def get_communities(self, group_id: str) -> list[Community]:
        """List communities stored for ``group_id``."""
        ...

    async def get_node(self, uuid_: str) -> Node | None:
        """Fetch a node by UUID."""
        ...

    async def get_nodes_by_label(
        self, label: NodeLabel, group_id: str
    ) -> list[Node]:
        """List nodes for ``group_id`` carrying ``label``."""
        ...

    async def get_edges(
        self, node_uuid: str, direction: str = "both"
    ) -> list[Edge]:
        """List edges incident to ``node_uuid``."""
        ...


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

#: Jaccard-similarity threshold for merging two communities.
DEFAULT_MERGE_THRESHOLD: float = 0.5

#: Default LLM summary prompt template.
COMMUNITY_SUMMARY_PROMPT = """\
You are a security analyst. Given a cluster of related entities from a
penetration-test knowledge graph, write a concise (2-4 sentence) summary
of what this cluster represents.

Entities (label: name):
{entities}

Notable relationships:
{relationships}

Summary:"""


# ---------------------------------------------------------------------------
# CommunityDetector
# ---------------------------------------------------------------------------


class CommunityDetector:
    """Detect, summarise, and merge communities in a KnowledgeGraph.

    Usage:
        detector = CommunityDetector(kg=my_kg)
        communities = await detector.detect_communities("flow-42")
        for c in communities:
            c.summary = await detector.get_community_summary(c, llm_client)
        await detector.merge_communities("flow-42")

    Args:
        kg: KnowledgeGraph instance (Protocol-compatible). Pass ``None``
            to disable the detector.
        algorithm: Detection algorithm — ``"louvain"`` (default) or
            ``"greedy"``. Louvain falls back to greedy on failure.
        merge_threshold: Jaccard-similarity threshold for
            :meth:`merge_communities`. Two communities are merged when
            their node-set similarity exceeds this value.
        llm_client: Optional LLM client for community summaries.
    """

    def __init__(
        self,
        kg: "_KGWithCommunities | None",
        algorithm: str = "louvain",
        merge_threshold: float = DEFAULT_MERGE_THRESHOLD,
        llm_client: "LLMClient | None" = None,
    ) -> None:
        self.kg = kg
        self.algorithm = algorithm.lower()
        if self.algorithm not in {"louvain", "greedy"}:
            self.algorithm = "louvain"
        self.merge_threshold = float(merge_threshold)
        self.llm_client = llm_client

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def detect_communities(
        self,
        group_id: str,
        min_community_size: int = 3,
    ) -> list[Community]:
        """Detect communities in the sub-graph for ``group_id``.

        Args:
            group_id: KG group ID (typically ``"flow-{id}"``).
            min_community_size: Discard communities with fewer than this
                many nodes (default 3). Set to 1 to keep all communities.

        Returns:
            List of :class:`Community` objects, sorted by size (largest
            first). Empty list when the KG is disabled or has no nodes.
        """
        if self.kg is None:
            return []
        try:
            nodes, edges = await self._fetch_subgraph(group_id)
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning(
                "fetch_subgraph_failed group=%s error=%s", group_id, exc
            )
            return []
        if not nodes:
            return []
        communities = self._build_communities(
            nodes=nodes, edges=edges, group_id=group_id,
            min_community_size=min_community_size,
        )
        # Persist if the KG supports it.
        save = getattr(self.kg, "add_community", None)
        if save is not None and callable(save):
            for c in communities:
                try:
                    # Task 5-a's add_community generates its own UUID —
                    # we re-store with the same member set so the caller
                    # can re-fetch via get_communities later. The
                    # returned Community may have a different UUID than
                    # the one we constructed locally; we substitute.
                    stored = await save(
                        name=c.name,
                        summary=c.summary,
                        member_node_uuids=list(c.member_node_uuids),
                        group_id=c.group_id,
                    )
                    # Mutate in place so callers see the persisted UUID.
                    c.uuid = stored.uuid
                except Exception as exc:  # pragma: no cover - defensive
                    logger.warning(
                        "save_community_failed uuid=%s error=%s",
                        c.uuid, exc,
                    )
        logger.info(
            "detect_communities_done group=%s communities=%d nodes=%d edges=%d",
            group_id, len(communities), len(nodes), len(edges),
        )
        return communities

    async def get_community_summary(
        self,
        community: Community,
        llm_client: "LLMClient | None" = None,
    ) -> str:
        """Generate an LLM summary of ``community``.

        Falls back to a deterministic template-based summary when no LLM
        client is available (so the method is always usable).

        Args:
            community: The community to summarise.
            llm_client: Optional LLM client override. When ``None`` uses
                the detector's configured ``self.llm_client``.

        Returns:
            Summary string. Empty string when the community has no nodes.
        """
        client = llm_client or self.llm_client
        nodes = await self._resolve_nodes(community)
        edges = await self._resolve_edges(community, nodes)
        if not nodes:
            return ""
        if client is None:
            return self._template_summary(community, nodes, edges)
        try:
            return await self._llm_summary(community, nodes, edges, client)
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning(
                "llm_community_summary_failed uuid=%s error=%s -- "
                "falling back to template",
                getattr(community, "uuid", "?"), exc,
            )
            return self._template_summary(community, nodes, edges)

    async def merge_communities(
        self,
        group_id: str,
        threshold: float | None = None,
    ) -> None:
        """Merge similar communities stored in the KG for ``group_id``.

        Two communities are merged when their Jaccard similarity
        (node-set overlap) exceeds ``threshold`` (default
        :attr:`self.merge_threshold`). The smaller community is folded
        into the larger one (its nodes are added to the larger
        community's node set, and the smaller community is removed).

        Args:
            group_id: KG group ID.
            threshold: Optional Jaccard threshold override.

        Note:
            Task 5-a's KG does not expose a ``delete_community`` method,
            so merged-away communities remain in the store. Callers
            should treat the merged survivors as authoritative for the
            group_id.
        """
        if self.kg is None:
            return
        list_c = getattr(self.kg, "get_communities", None)
        save_c = getattr(self.kg, "add_community", None)
        if list_c is None or save_c is None:
            logger.debug(
                "merge_communities_skipped group=%s reason=kg_missing_methods",
                group_id,
            )
            return
        try:
            communities = await list_c(group_id)
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning(
                "list_communities_failed group=%s error=%s", group_id, exc
            )
            return
        if len(communities) < 2:
            return
        thr = self.merge_threshold if threshold is None else float(threshold)
        merged = self._merge_by_overlap(communities, thr)
        # Persist the merged communities.
        for c in merged:
            try:
                await save_c(
                    name=c.name,
                    summary=c.summary,
                    member_node_uuids=list(c.member_node_uuids),
                    group_id=c.group_id,
                )
            except Exception as exc:  # pragma: no cover - defensive
                logger.warning(
                    "save_community_failed uuid=%s error=%s",
                    getattr(c, "uuid", "?"), exc,
                )
        logger.info(
            "merge_communities_done group=%s before=%d after=%d threshold=%.2f",
            group_id, len(communities), len(merged), thr,
        )

    # ------------------------------------------------------------------
    # Subgraph fetching
    # ------------------------------------------------------------------

    async def _fetch_subgraph(
        self, group_id: str
    ) -> tuple[list[Node], list[Edge]]:
        """Fetch the full (nodes, edges) for ``group_id``.

        First tries to read directly from the KG's in-memory NetworkX
        graph (``kg._graph``) for efficiency; falls back to the public
        ``get_nodes_by_label`` + ``get_edges`` API when ``_graph`` is
        not accessible.
        """
        kg_graph = getattr(self.kg, "_graph", None)
        if kg_graph is not None:
            return self._snapshot_from_nx(kg_graph, group_id)
        # Public-API fallback.
        nodes: list[Node] = []
        for label in NodeLabel:
            try:
                got = await self.kg.get_nodes_by_label(label, group_id)  # type: ignore[union-attr]
                nodes.extend(got)
            except Exception as exc:  # pragma: no cover - defensive
                logger.debug(
                    "get_nodes_by_label_failed label=%s error=%s",
                    label.value, exc,
                )
        edges: list[Edge] = []
        seen_edges: set[str] = set()
        for n in nodes:
            try:
                got = await self.kg.get_edges(n.uuid, direction="both")  # type: ignore[union-attr]
            except Exception as exc:  # pragma: no cover - defensive
                logger.debug("get_edges_failed uuid=%s error=%s", n.uuid, exc)
                continue
            for e in got:
                if e.uuid in seen_edges:
                    continue
                seen_edges.add(e.uuid)
                edges.append(e)
        return nodes, edges

    @staticmethod
    def _snapshot_from_nx(
        kg_graph: Any, group_id: str
    ) -> tuple[list[Node], list[Edge]]:
        """Read (nodes, edges) for ``group_id`` directly from the KG's
        in-memory NetworkX MultiDiGraph."""
        nodes: list[Node] = []
        edges: list[Edge] = []
        for _n, data in kg_graph.nodes(data=True):
            if data.get("group_id") != group_id:
                continue
            node = data.get("data")
            if isinstance(node, Node):
                nodes.append(node)
        for _u, _v, _k, data in kg_graph.edges(data=True, keys=True):
            if data.get("group_id") != group_id:
                continue
            edge = data.get("data")
            if isinstance(edge, Edge):
                edges.append(edge)
        return nodes, edges

    # ------------------------------------------------------------------
    # Community construction
    # ------------------------------------------------------------------

    def _build_communities(
        self,
        *,
        nodes: list[Node],
        edges: list[Edge],
        group_id: str,
        min_community_size: int,
    ) -> list[Community]:
        """Run NetworkX-based community detection and wrap as Community."""
        nx = self._lazy_import_networkx()
        if nx is None:
            return []
        g = nx.Graph()
        for n in nodes:
            g.add_node(n.uuid, label=_label_str(n), name=n.name)
        for e in edges:
            # Skip self-loops (would skew modularity).
            if e.source_node_uuid == e.target_node_uuid:
                continue
            g.add_edge(
                e.source_node_uuid,
                e.target_node_uuid,
                edge_type=e.edge_type.value,
                uuid=e.uuid,
            )

        raw_communities: list[set[str]] = []
        if self.algorithm == "louvain":
            raw_communities = self._louvain(nx, g)
        if not raw_communities:
            raw_communities = self._greedy(nx, g)

        out: list[Community] = []
        for idx, node_set in enumerate(raw_communities):
            if len(node_set) < min_community_size:
                continue
            edge_uuids = [
                e.uuid for e in edges
                if e.source_node_uuid in node_set
                and e.target_node_uuid in node_set
            ]
            cuuid = self._deterministic_uuid(
                f"community:{group_id}:{idx}:{':'.join(sorted(node_set))}"
            )
            # Derive a deterministic name from the most common node label.
            label_counts: dict[str, int] = {}
            name_hints: list[str] = []
            for n in nodes:
                if n.uuid not in node_set:
                    continue
                lbl = _label_str(n)
                label_counts[lbl] = label_counts.get(lbl, 0) + 1
                if len(name_hints) < 3:
                    name_hints.append(n.name)
            top_label = (
                max(label_counts.items(), key=lambda kv: kv[1])[0]
                if label_counts else "mixed"
            )
            name = f"{top_label}-cluster-{idx + 1}"
            if name_hints:
                name += f" ({', '.join(name_hints)})"
            summary = (
                f"Cluster of {len(node_set)} entities ({label_counts}). "
                f"Sample: {', '.join(name_hints)}."
            )
            out.append(
                Community(
                    uuid=cuuid,
                    name=name,
                    summary=summary,
                    member_node_uuids=sorted(node_set),
                    group_id=group_id,
                )
            )
        # Sort by size (descending) for stable output.
        out.sort(key=lambda c: len(c.member_node_uuids), reverse=True)
        return out

    @staticmethod
    def _louvain(nx: Any, g: Any) -> list[set[str]]:
        """Run Louvain community detection. Returns list of node sets."""
        try:
            from networkx.algorithms.community import louvain_communities
        except ImportError:  # pragma: no cover - very old networkx
            return []
        try:
            raw = louvain_communities(g, seed=42)
        except Exception as exc:  # pragma: no cover - defensive
            logger.debug("louvain_failed error=%s -- will try greedy", exc)
            return []
        return [set(s) for s in raw]

    @staticmethod
    def _greedy(nx: Any, g: Any) -> list[set[str]]:
        """Run greedy modularity community detection. Fallback."""
        try:
            from networkx.algorithms.community import (
                greedy_modularity_communities,
            )
        except ImportError:  # pragma: no cover
            return []
        try:
            raw = greedy_modularity_communities(g)
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning("greedy_modularity_failed error=%s", exc)
            # Last-ditch: each connected component is its own community.
            try:
                raw = list(nx.connected_components(g))
            except Exception:
                return []
        return [set(s) for s in raw]

    # ------------------------------------------------------------------
    # Summaries
    # ------------------------------------------------------------------

    async def _resolve_nodes(
        self, community: Community
    ) -> list[Node]:
        """Best-effort resolution of community.member_node_uuids -> Node."""
        if self.kg is None:
            return []
        get_node = getattr(self.kg, "get_node", None)
        nodes: list[Node] = []
        if get_node is not None:
            for u in community.member_node_uuids:
                try:
                    n = await get_node(u)
                except Exception:  # pragma: no cover - defensive
                    n = None
                if n is not None:
                    nodes.append(n)
        if not nodes:
            # Fallback: pull the entire group's subgraph and filter.
            try:
                all_nodes, _ = await self._fetch_subgraph(community.group_id)
                wanted = set(community.member_node_uuids)
                nodes = [n for n in all_nodes if n.uuid in wanted]
            except Exception:  # pragma: no cover - defensive
                pass
        return nodes

    async def _resolve_edges(
        self,
        community: Community,
        nodes: list[Node],
    ) -> list[Edge]:
        """Best-effort resolution of edges inside the community."""
        if self.kg is None or not nodes:
            return []
        try:
            _, all_edges = await self._fetch_subgraph(community.group_id)
        except Exception:  # pragma: no cover - defensive
            return []
        wanted = {n.uuid for n in nodes}
        return [
            e for e in all_edges
            if e.source_node_uuid in wanted
            and e.target_node_uuid in wanted
        ]

    def _template_summary(
        self,
        community: Community,
        nodes: list[Node],
        edges: list[Edge],
    ) -> str:
        """Deterministic fallback summary when no LLM is configured."""
        if not nodes:
            return ""
        label_counts: dict[str, int] = {}
        for n in nodes:
            lbl = _label_str(n)
            label_counts[lbl] = label_counts.get(lbl, 0) + 1
        label_str = ", ".join(
            f"{count} {label}"
            for label, count in sorted(
                label_counts.items(), key=lambda kv: (-kv[1], kv[0])
            )
        )
        sample = ", ".join(n.name for n in nodes[:5])
        edge_sample = "; ".join(e.fact for e in edges[:3] if e.fact)
        parts = [
            f"Cluster of {len(nodes)} entities ({label_str}).",
            f"Sample: {sample}{' …' if len(nodes) > 5 else ''}.",
        ]
        if edge_sample:
            parts.append(f"Notable relationships: {edge_sample}.")
        return " ".join(parts)

    async def _llm_summary(
        self,
        community: Community,
        nodes: list[Node],
        edges: list[Edge],
        llm_client: "LLMClient",
    ) -> str:
        """LLM-generated summary of the community."""
        from elengenix.agents.base import Message  # type: ignore

        entities_block = "\n".join(
            f"  - {_label_str(n)}: {n.name}" for n in nodes[:50]
        )
        rels_block = "\n".join(
            f"  - {e.fact or e.edge_type.value}" for e in edges[:20] if e.fact
        ) or "  (none)"
        prompt = COMMUNITY_SUMMARY_PROMPT.format(
            entities=entities_block or "  (none)",
            relationships=rels_block,
        )
        chain = [
            Message(role="system", content="You are a security analyst."),
            Message(role="user", content=prompt),
        ]
        resp = await llm_client.call(chain=chain, tools=None)
        content = getattr(resp, "content", "") or ""
        return content.strip()

    # ------------------------------------------------------------------
    # Merging
    # ------------------------------------------------------------------

    def _merge_by_overlap(
        self,
        communities: list[Community],
        threshold: float,
    ) -> list[Community]:
        """Greedily merge communities whose Jaccard overlap >= threshold."""
        if not communities:
            return []
        # Sort by size (largest first) so smaller communities fold into
        # the largest similar one.
        ordered = sorted(
            communities,
            key=lambda c: len(c.member_node_uuids),
            reverse=True,
        )
        survivors: list[Community] = []
        for c in ordered:
            merged_into: Community | None = None
            for s in survivors:
                if self._jaccard(
                    c.member_node_uuids, s.member_node_uuids
                ) >= threshold:
                    merged_into = s
                    break
            if merged_into is None:
                survivors.append(c)
            else:
                # Fold c into merged_into.
                existing = set(merged_into.member_node_uuids)
                new_nodes = set(c.member_node_uuids) - existing
                merged_into.member_node_uuids = sorted(existing | new_nodes)
                # Append to summary if both have LLM/template summaries.
                if c.summary and c.summary not in (merged_into.summary or ""):
                    if merged_into.summary:
                        merged_into.summary = (
                            merged_into.summary + " || " + c.summary
                        )
                    else:
                        merged_into.summary = c.summary
        return survivors

    @staticmethod
    def _jaccard(a: Iterable[str], b: Iterable[str]) -> float:
        """Jaccard similarity between two iterables of strings."""
        sa = set(a)
        sb = set(b)
        if not sa and not sb:
            return 1.0
        if not sa or not sb:
            return 0.0
        return len(sa & sb) / len(sa | sb)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _lazy_import_networkx() -> Any:
        """Lazy-import networkx. Returns None on ImportError."""
        try:
            import networkx  # type: ignore
            return networkx
        except ImportError:  # pragma: no cover - networkx is optional
            logger.warning(
                "networkx_not_installed community_detection_unavailable"
            )
            return None

    @staticmethod
    def _deterministic_uuid(seed: str) -> str:
        """Return a deterministic UUID5 (DNS namespace) for ``seed``."""
        return str(uuid.uuid5(uuid.NAMESPACE_DNS, seed))


__all__ = [
    "CommunityDetector",
    "Community",
    "DEFAULT_MERGE_THRESHOLD",
    "COMMUNITY_SUMMARY_PROMPT",
]
