"""elengenix/knowledge_graph/integration.py — wire KG + extractor into VulnAgent.

Provides :class:`KnowledgeGraphIntegration` — a thin async facade that
sits alongside :class:`elengenix.agent.vuln_agent.VulnAgent` and
ingests entities / relationships / findings into a KnowledgeGraph as
the agent runs. The integration exposes four hooks:

* ``on_agent_response``       — extract entities from an LLM response.
* ``on_tool_execution``       — extract entities from a tool's output.
* ``on_finding_discovered``   — ingest a vulnerability as a node + edges.
* ``get_relevant_context``    — search the graph for prior knowledge
  relevant to a query and return formatted Markdown for prompt injection.

All hooks are **no-ops** when the KnowledgeGraph is disabled (``None``).
This lets callers wire the integration unconditionally and toggle the
feature via configuration without touching the agent loop.

The integration never raises — every hook catches and logs its own
exceptions so a KG failure can never break the agent's reasoning loop.

It uses Task 5-a's :class:`KnowledgeGraph` API directly:
``add_node(name, labels, summary, attributes, group_id)``,
``add_edge(source_uuid, target_uuid, edge_type, fact, group_id, ...)``,
``add_episode(source, source_description, content, group_id)`` and the
``diverse_results_search`` retrieval method.
"""

from __future__ import annotations

import logging
import uuid
from typing import Any, Iterable, Protocol, TYPE_CHECKING

from .extractor import (
    Edge,
    EdgeType,
    EntityExtractor,
    Node,
    NodeLabel,
    _label_str,
    _now_dt,
)
from .graph import Community, Episode  # noqa: F401  (re-exported below)

if TYPE_CHECKING:  # pragma: no cover - typing only
    from elengenix.agents.base import LLMClient

logger = logging.getLogger("elengenix.knowledge_graph.integration")


# ---------------------------------------------------------------------------
# KnowledgeGraphProtocol — structural type matching Task 5-a's KG class.
# ---------------------------------------------------------------------------


class KnowledgeGraphProtocol(Protocol):
    """Structural protocol for a KG compatible with Task 5-a's surface.

    Concrete implementations may expose more, but at minimum must provide
    these async methods. ``enabled`` is optional — its absence is treated
    as "enabled".
    """

    enabled: bool

    async def add_node(
        self,
        name: str,
        labels: list[NodeLabel],
        summary: str,
        attributes: dict[str, Any] | None = None,
        group_id: str = "default",
    ) -> Node:
        """Persist a node (returns the stored Node incl. UUID)."""
        ...

    async def add_edge(
        self,
        source_uuid: str,
        target_uuid: str,
        edge_type: EdgeType,
        fact: str,
        group_id: str = "default",
        valid_at: Any | None = None,
        name: str | None = None,
    ) -> Edge:
        """Persist a directed edge between two existing nodes."""
        ...

    async def add_episode(
        self,
        source: str,
        source_description: str,
        content: str,
        group_id: str = "default",
    ) -> Episode:
        """Persist an episode. ``source`` must be 'message' or 'tool_execution'."""
        ...

    async def add_community(
        self,
        name: str,
        summary: str,
        member_node_uuids: list[str],
        group_id: str = "default",
    ) -> Community:
        """Persist a community."""
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

    async def get_communities(self, group_id: str) -> list[Community]:
        """List communities stored for ``group_id``."""
        ...

    async def search_nodes(
        self, query: str, group_id: str, max_results: int = 10
    ) -> list[tuple[Node, float]]:
        """Fuzzy search nodes."""
        ...

    async def diverse_results_search(
        self,
        query: str,
        group_id: str,
        diversity_level: str = "medium",
        max_results: int = 10,
    ) -> dict[str, Any]:
        """MMR-reranked diverse retrieval (returns dict with 'nodes',
        'edges', 'episodes', 'communities' keys)."""
        ...


# ---------------------------------------------------------------------------
# Finding protocol — matches vuln_agent.Finding (duck-typed).
# ---------------------------------------------------------------------------


class _FindingLike(Protocol):
    """Structural protocol for a VulnAgent Finding dataclass."""

    title: str
    description: str
    severity: str
    target: str
    evidence: str
    remediation: str
    source_tool: str
    confidence: float


# ---------------------------------------------------------------------------
# KnowledgeGraphIntegration
# ---------------------------------------------------------------------------


class KnowledgeGraphIntegration:
    """Wire :class:`EntityExtractor` + KnowledgeGraph into the VulnAgent loop.

    Usage:

        integration = KnowledgeGraphIntegration(kg=my_kg, extractor=my_ext)
        await integration.on_agent_response(
            agent_type="pentester",
            response="Found OpenSSH 8.2 on 10.0.0.1:22",
            task_id="task-1", subtask_id="sub-1", flow_id="flow-42",
        )

    The integration is **best-effort idempotent** — before creating a
    new node it looks up existing nodes in the same group with the same
    name + primary label, and reuses their UUID if found. This keeps
    re-extraction (e.g. across agent turns) from spamming the KG with
    duplicate nodes.

    Args:
        kg: KnowledgeGraph instance (Protocol-compatible). Pass ``None``
            to disable integration.
        extractor: :class:`EntityExtractor` instance. If ``None`` one is
            constructed with no LLM client (heuristic-only).
        llm_client: Optional LLM client for the extractor and for
            relationship inference. Ignored when ``extractor`` is
            explicitly provided.
        enabled_override: Force-enable/disable the integration
            (overrides ``kg is None``). Useful for feature-flagging.
    """

    def __init__(
        self,
        kg: KnowledgeGraphProtocol | None,
        extractor: EntityExtractor | None = None,
        llm_client: "LLMClient | None" = None,
        enabled_override: bool | None = None,
    ) -> None:
        self.kg = kg
        if extractor is None:
            extractor = EntityExtractor(llm_client=llm_client, kg=kg)
        self.extractor = extractor
        self._enabled_override = enabled_override
        # Cache of (group_id, label, name) -> existing KG node UUID, used
        # to avoid creating duplicate nodes across hook invocations.
        self._node_uuid_cache: dict[tuple[str, str, str], str] = {}

    # ------------------------------------------------------------------
    # Enabled-state helpers
    # ------------------------------------------------------------------

    @property
    def enabled(self) -> bool:
        """True iff the integration will actually ingest / search."""
        if self._enabled_override is not None:
            return self._enabled_override
        if self.kg is None:
            return False
        return bool(getattr(self.kg, "enabled", True))

    def _group_id(self, flow_id: str | None) -> str:
        """Compute the KG group_id from a flow_id (PentAGI convention)."""
        if not flow_id:
            return "flow-default"
        if flow_id.startswith("flow-"):
            return flow_id
        return f"flow-{flow_id}"

    # ------------------------------------------------------------------
    # Hooks
    # ------------------------------------------------------------------

    async def on_agent_response(
        self,
        agent_type: str,
        response: str,
        task_id: str | None = None,
        subtask_id: str | None = None,
        flow_id: str | None = None,
    ) -> None:
        """Extract entities from an agent's textual response and ingest.

        Records the response as an Episode (``source="message"``),
        extracts entities from the response text, infers relationships,
        and ingests both into the KG. All failures are caught and
        logged — never raises.

        Args:
            agent_type: Agent type string (e.g. ``"pentester"``).
            response: The agent's textual response.
            task_id: Optional task ID for provenance.
            subtask_id: Optional subtask ID for provenance.
            flow_id: Flow ID — used to compute the KG ``group_id``.
        """
        if not self.enabled or not response:
            return
        group_id = self._group_id(flow_id)
        try:
            episode_uuid = await self._record_episode(
                group_id=group_id,
                source="message",
                content=response,
                source_description=self._describe(
                    agent_type=agent_type,
                    task_id=task_id,
                    subtask_id=subtask_id,
                ),
            )
            nodes = await self.extractor.extract_from_text(
                response, group_id=group_id, source_episode_uuid=episode_uuid
            )
            if not nodes:
                return
            uuid_map = await self._ingest_nodes(nodes)
            edges = await self.extractor.extract_relationships(
                nodes, context=response, group_id=group_id
            )
            await self._ingest_edges(edges, uuid_map)
            logger.info(
                "on_agent_response_ingested agent=%s nodes=%d edges=%d group=%s",
                agent_type, len(nodes), len(edges), group_id,
            )
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning(
                "on_agent_response_failed agent=%s error=%s", agent_type, exc
            )

    async def on_tool_execution(
        self,
        tool_name: str,
        args: dict[str, Any] | str | None,
        result: Any,
        status: str,
        agent_type: str,
        task_id: str | None = None,
        subtask_id: str | None = None,
        flow_id: str | None = None,
    ) -> None:
        """Extract entities from a tool's output and ingest.

        Records the tool call as an Episode (``source="tool_execution"``),
        runs the tool-output extractor (which applies tool-specific
        parsing in addition to generic regex extraction), infers
        relationships, and ingests.

        Args:
            tool_name: Tool identifier (e.g. ``"port_scan"``).
            args: Tool arguments (dict or JSON string).
            result: Tool output (string or JSON-serialisable object).
            status: ``"success"`` / ``"error"`` / ``"timeout"`` / etc.
            agent_type: Agent that invoked the tool.
            task_id / subtask_id / flow_id: Provenance.
        """
        if not self.enabled:
            return
        group_id = self._group_id(flow_id)
        output = self._stringify_tool_output(result)
        if not output:
            return
        try:
            args_str = self._stringify_args(args)
            episode_uuid = await self._record_episode(
                group_id=group_id,
                source="tool_execution",
                content=output,
                source_description=self._describe(
                    agent_type=agent_type,
                    task_id=task_id,
                    subtask_id=subtask_id,
                    tool_name=tool_name,
                    status=status,
                ),
            )
            nodes = await self.extractor.extract_from_tool_output(
                tool_name, output, group_id=group_id
            )
            if not nodes:
                return
            # Stamp the source episode on every node so provenance survives.
            for n in nodes:
                if "source_episode_uuid" not in (n.attributes or {}):
                    n.attributes["source_episode_uuid"] = episode_uuid
            uuid_map = await self._ingest_nodes(nodes)
            edges = await self.extractor.extract_relationships(
                nodes, context=output, group_id=group_id
            )
            await self._ingest_edges(edges, uuid_map)
            logger.info(
                "on_tool_execution_ingested tool=%s status=%s nodes=%d "
                "edges=%d group=%s",
                tool_name, status, len(nodes), len(edges), group_id,
            )
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning(
                "on_tool_execution_failed tool=%s error=%s", tool_name, exc
            )

    async def on_finding_discovered(
        self,
        finding: "_FindingLike | dict[str, Any]",
        flow_id: str | None = None,
    ) -> None:
        """Ingest a vulnerability finding as a VULNERABILITY node + edges.

        Creates a ``VULNERABILITY`` node for the finding, links it to the
        target IP/domain (when extractable from ``finding.target``),
        and adds a ``DISCOVERED_BY`` edge from the source tool to the
        finding.

        Args:
            finding: Either a VulnAgent ``Finding`` dataclass instance
                or a dict with the same keys (``title``, ``description``,
                ``severity``, ``target``, ``evidence``, ``remediation``,
                ``source_tool``, ``confidence``).
            flow_id: Flow ID — used to compute the KG ``group_id``.
        """
        if not self.enabled:
            return
        group_id = self._group_id(flow_id)
        try:
            fdata = self._finding_to_dict(finding)
            if not fdata.get("title"):
                return
            # Build the vulnerability node.
            vuln_node = Node(
                uuid=self._deterministic_uuid(
                    f"node:{group_id}:VULNERABILITY:{fdata['title'].lower()}"
                ),
                name=fdata["title"],
                labels=[NodeLabel.VULNERABILITY],
                summary=fdata.get("description", "")[:500],
                attributes={
                    "severity": fdata.get("severity", "info"),
                    "confidence": float(fdata.get("confidence", 0.5)),
                    "evidence": fdata.get("evidence", ""),
                    "remediation": fdata.get("remediation", ""),
                    "source_tool": fdata.get("source_tool", ""),
                    "kind": "finding",
                },
                created_at=_now_dt(),
                group_id=group_id,
            )
            uuid_map = await self._ingest_nodes([vuln_node])

            # Build / link target node (host / IP / domain / endpoint).
            target_str = fdata.get("target") or ""
            target_nodes: list[Node] = []
            if target_str:
                target_entities = self.extractor._extract_all_patterns(
                    target_str, source_episode_uuid=None
                )
                target_nodes = self.extractor._entities_to_nodes(
                    target_entities, group_id=group_id
                )
                target_map = await self._ingest_nodes(target_nodes)
                uuid_map.update(target_map)

            # Build / link source-tool node.
            source_tool = fdata.get("source_tool") or ""
            tool_node: Node | None = None
            if source_tool:
                tool_node = Node(
                    uuid=self._deterministic_uuid(
                        f"node:{group_id}:TOOL:{source_tool.lower()}"
                    ),
                    name=source_tool,
                    labels=[NodeLabel.TOOL],
                    summary=f"Tool: {source_tool}",
                    attributes={"tool_kind": "vulnagent_tool"},
                    created_at=_now_dt(),
                    group_id=group_id,
                )
                tool_map = await self._ingest_nodes([tool_node])
                uuid_map.update(tool_map)

            # Edges.
            edges: list[Edge] = []
            for tn in target_nodes:
                edges.append(self._make_edge(
                    source=tn,
                    target=vuln_node,
                    edge_type=EdgeType.RELATED_TO,
                    group_id=group_id,
                    fact=f"{tn.name} affected by {vuln_node.name}",
                ))
            if tool_node is not None:
                edges.append(self._make_edge(
                    source=tool_node,
                    target=vuln_node,
                    edge_type=EdgeType.DISCOVERED_BY,
                    group_id=group_id,
                    fact=f"{vuln_node.name} discovered by {tool_node.name}",
                ))
            await self._ingest_edges(edges, uuid_map)
            logger.info(
                "on_finding_discovered_ingested title=%r severity=%s "
                "targets=%d edges=%d group=%s",
                fdata["title"], fdata.get("severity"),
                len(target_nodes), len(edges), group_id,
            )
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning("on_finding_discovered_failed error=%s", exc)

    async def get_relevant_context(
        self,
        query: str,
        flow_id: str | None = None,
        max_results: int = 10,
    ) -> str:
        """Search the KG for prior knowledge relevant to ``query``.

        Returns formatted Markdown suitable for direct injection into an
        agent prompt. Returns an empty string when the KG is disabled or
        when no matches are found.

        Uses :meth:`KnowledgeGraph.diverse_results_search` (MMR-reranked
        diverse retrieval) so the returned context spans multiple
        relevant entities / relationships rather than clustering around
        a single near-duplicate hit.

        Args:
            query: Search query (typically the agent's current task or
                the target it's investigating).
            flow_id: Flow ID — used to scope the search.
            max_results: Max nodes / edges / episodes to return per type.

        Returns:
            Markdown string. Format::

                ## Relevant Knowledge (N entities, M relationships)

                ### <label>: <name>
                <summary>

                **Attributes:**
                - `key`: value

                **Relationships:**
                - -> `EDGE_TYPE` **other** (fact)
        """
        if not self.enabled or not query:
            return ""
        group_id = self._group_id(flow_id)
        try:
            # diverse_results_search returns a dict with nodes/edges/
            # episodes/communities keys + MMR scores.
            results = await self.kg.diverse_results_search(  # type: ignore[union-attr]
                query=query,
                group_id=group_id,
                diversity_level="medium",
                max_results=max_results,
            )
            nodes: list[Node] = list(results.get("nodes") or [])
            edges: list[Edge] = list(results.get("edges") or [])
            if not nodes and not edges:
                return ""
            return self._format_context(nodes, edges)
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning(
                "get_relevant_context_failed query=%r error=%s", query, exc
            )
            return ""

    # ------------------------------------------------------------------
    # Ingestion helpers
    # ------------------------------------------------------------------

    async def _record_episode(
        self,
        *,
        group_id: str,
        source: str,
        content: str,
        source_description: str = "",
    ) -> str | None:
        """Persist an episode; return its UUID (or None on failure)."""
        if self.kg is None:
            return None
        add_ep = getattr(self.kg, "add_episode", None)
        if add_ep is None:
            return None
        try:
            ep = await add_ep(
                source=source,
                source_description=source_description,
                content=content,
                group_id=group_id,
            )
            return getattr(ep, "uuid", None)
        except Exception as exc:  # pragma: no cover - defensive
            logger.debug("record_episode_failed error=%s", exc)
            return None

    async def _ingest_nodes(
        self, nodes: Iterable[Node]
    ) -> dict[str, str]:
        """Upsert each node into the KG; return original_uuid -> kg_uuid map.

        For each input node, looks up an existing KG node with the same
        name + primary label in the same group. If found, reuses its
        UUID. Otherwise calls ``add_node`` to create a new one.
        """
        if self.kg is None:
            return {}
        uuid_map: dict[str, str] = {}
        for n in nodes:
            try:
                kg_uuid = await self._resolve_or_create_node(n)
                uuid_map[n.uuid] = kg_uuid
            except Exception as exc:  # pragma: no cover - defensive
                logger.warning(
                    "ingest_node_failed name=%s label=%s error=%s",
                    n.name, _label_str(n), exc,
                )
        return uuid_map

    async def _resolve_or_create_node(self, node: Node) -> str:
        """Find an existing KG node by name+label, or create a new one.

        Returns the actual KG UUID. Caches lookups per (group, label,
        name) to avoid repeated searches across hook calls.
        """
        if self.kg is None:
            return node.uuid
        primary_label = node.labels[0] if node.labels else NodeLabel.ENTITY
        cache_key = (node.group_id, primary_label.value, node.name.lower())
        cached = self._node_uuid_cache.get(cache_key)
        if cached is not None:
            return cached
        # Look up existing nodes with this label in this group.
        existing_uuid: str | None = None
        try:
            get_by_label = getattr(self.kg, "get_nodes_by_label", None)
            if get_by_label is not None:
                candidates = await get_by_label(primary_label, node.group_id)
                for c in candidates:
                    if c.name.lower() == node.name.lower():
                        existing_uuid = c.uuid
                        break
        except Exception as exc:  # pragma: no cover - defensive
            logger.debug("lookup_node_failed name=%s error=%s", node.name, exc)
        if existing_uuid is not None:
            self._node_uuid_cache[cache_key] = existing_uuid
            return existing_uuid
        # Create a new node.
        new_node = await self.kg.add_node(
            name=node.name,
            labels=list(node.labels),
            summary=node.summary,
            attributes=dict(node.attributes),
            group_id=node.group_id,
        )
        self._node_uuid_cache[cache_key] = new_node.uuid
        return new_node.uuid

    async def _ingest_edges(
        self,
        edges: Iterable[Edge],
        uuid_map: dict[str, str],
    ) -> None:
        """Upsert each edge into the KG, translating UUIDs via ``uuid_map``.

        ``add_edge`` raises ``ValueError`` if the source or target node
        doesn't exist; we skip edges whose endpoints couldn't be
        resolved (logged at debug level).
        """
        if self.kg is None:
            return
        for e in edges:
            src_uuid = uuid_map.get(e.source_node_uuid, e.source_node_uuid)
            tgt_uuid = uuid_map.get(e.target_node_uuid, e.target_node_uuid)
            try:
                await self.kg.add_edge(
                    source_uuid=src_uuid,
                    target_uuid=tgt_uuid,
                    edge_type=e.edge_type,
                    fact=e.fact,
                    group_id=e.group_id,
                    name=e.name,
                )
            except Exception as exc:  # pragma: no cover - defensive
                logger.debug(
                    "ingest_edge_failed src=%s tgt=%s type=%s error=%s",
                    src_uuid[:8], tgt_uuid[:8], e.edge_type.value, exc,
                )

    # ------------------------------------------------------------------
    # Formatting helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _format_context(nodes: list[Node], edges: list[Edge]) -> str:
        """Render ``nodes`` + ``edges`` as a Markdown block for prompts."""
        if not nodes and not edges:
            return ""
        lines: list[str] = []
        lines.append(
            f"## Relevant Knowledge ({len(nodes)} entities, "
            f"{len(edges)} relationships)"
        )
        lines.append("")
        node_by_uuid = {n.uuid: n for n in nodes}
        for n in nodes:
            label_str = _label_str(n)
            lines.append(f"### {label_str}: {n.name}")
            if n.summary and n.summary != n.name:
                lines.append(n.summary)
            attrs = n.attributes or {}
            interesting = {
                k: v for k, v in attrs.items()
                if k in {
                    "severity", "port", "protocol", "service_name",
                    "service_version", "cvss", "is_private", "algorithm",
                    "banner", "confidence", "evidence", "remediation",
                    "source_tool", "method", "status", "title",
                    "cve_id", "kind", "url",
                }
                and v not in (None, "", [])
            }
            if interesting:
                lines.append("")
                lines.append("**Attributes:**")
                for k, v in interesting.items():
                    val_str = str(v)
                    if len(val_str) > 120:
                        val_str = val_str[:117] + "..."
                    lines.append(f"- `{k}`: {val_str}")
            rels = [
                e for e in edges
                if e.source_node_uuid == n.uuid or e.target_node_uuid == n.uuid
            ]
            if rels:
                lines.append("")
                lines.append("**Relationships:**")
                for e in rels[:8]:  # cap to avoid prompt bloat
                    other_uuid = (
                        e.target_node_uuid
                        if e.source_node_uuid == n.uuid
                        else e.source_node_uuid
                    )
                    other = node_by_uuid.get(other_uuid)
                    other_name = other.name if other else other_uuid[:8]
                    direction = "->" if e.source_node_uuid == n.uuid else "<-"
                    lines.append(
                        f"- {direction} `{e.edge_type.value}` "
                        f"**{other_name}**"
                        + (f" ({e.fact})" if e.fact else "")
                    )
            lines.append("")
        # Mention edges whose endpoints aren't in the node set (rare).
        dangling = [
            e for e in edges
            if e.source_node_uuid not in node_by_uuid
            and e.target_node_uuid not in node_by_uuid
        ]
        if dangling:
            lines.append("**Other relationships:**")
            for e in dangling[:5]:
                lines.append(
                    f"- `{e.edge_type.value}`: {e.fact}"
                )
        return "\n".join(lines).strip()

    # ------------------------------------------------------------------
    # Finding / output normalisation
    # ------------------------------------------------------------------

    @staticmethod
    def _finding_to_dict(
        finding: "_FindingLike | dict[str, Any]",
    ) -> dict[str, Any]:
        """Coerce a Finding dataclass or dict into a plain dict."""
        if isinstance(finding, dict):
            return dict(finding)
        out: dict[str, Any] = {}
        for k in (
            "title", "description", "severity", "target", "evidence",
            "remediation", "source_tool", "confidence",
        ):
            v = getattr(finding, k, None)
            if v is not None:
                out[k] = v
        return out

    @staticmethod
    def _stringify_tool_output(result: Any) -> str:
        """Coerce a tool result (str / dict / list / etc.) to a string."""
        if result is None:
            return ""
        if isinstance(result, str):
            return result
        if isinstance(result, (dict, list)):
            try:
                import json
                return json.dumps(result, default=str)
            except (TypeError, ValueError):
                return str(result)
        return str(result)

    @staticmethod
    def _stringify_args(args: Any) -> str:
        if args is None:
            return ""
        if isinstance(args, str):
            return args
        try:
            import json
            return json.dumps(args, default=str)
        except (TypeError, ValueError):
            return str(args)

    @staticmethod
    def _describe(
        *,
        agent_type: str | None = None,
        task_id: str | None = None,
        subtask_id: str | None = None,
        tool_name: str | None = None,
        status: str | None = None,
    ) -> str:
        """Build a human-readable source_description for an episode."""
        parts: list[str] = []
        if agent_type:
            parts.append(f"agent={agent_type}")
        if tool_name:
            parts.append(f"tool={tool_name}")
        if status:
            parts.append(f"status={status}")
        if task_id:
            parts.append(f"task={task_id}")
        if subtask_id:
            parts.append(f"subtask={subtask_id}")
        return " ".join(parts) if parts else "elengenix"

    @staticmethod
    def _deterministic_uuid(seed: str) -> str:
        """Return a deterministic UUID5 (DNS namespace) for ``seed``."""
        return str(uuid.uuid5(uuid.NAMESPACE_DNS, seed))

    @staticmethod
    def _make_edge(
        *,
        source: Node,
        target: Node,
        edge_type: EdgeType,
        group_id: str,
        fact: str,
    ) -> Edge:
        edge_uuid = str(
            uuid.uuid5(
                uuid.NAMESPACE_DNS,
                f"edge:{group_id}:{source.uuid}:{edge_type.value}:{target.uuid}",
            )
        )
        return Edge(
            uuid=edge_uuid,
            name=edge_type.value,
            fact=fact,
            source_node_uuid=source.uuid,
            target_node_uuid=target.uuid,
            edge_type=edge_type,
            created_at=_now_dt(),
            valid_at=None,
            invalid_at=None,
            group_id=group_id,
        )


__all__ = [
    "KnowledgeGraphIntegration",
    "KnowledgeGraphProtocol",
]
