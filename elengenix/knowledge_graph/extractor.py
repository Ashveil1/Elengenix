"""elengenix/knowledge_graph/extractor.py — entity & relationship extraction.

Extracts entities (IP addresses, domains, URLs, ports, CVEs, hashes,
credentials, file paths, service banners, emails) from arbitrary text and
from VulnAgent tool outputs, classifies them into :class:`NodeLabel`
buckets (the seven labels exposed by Task 5-a's ``graph.py``:
``IP_ADDRESS``, ``SERVICE``, ``VULNERABILITY``, ``ENDPOINT``,
``CREDENTIAL``, ``TOOL``, ``ENTITY``), and infers relationships between
the extracted nodes via a combination of deterministic heuristics and an
optional LLM pass.

The extractor is intentionally lazy about heavy dependencies — the only
top-level imports are stdlib (``re``, ``logging``, ``uuid``, ``asyncio``,
``dataclasses``, ``enum``, ``json``, ``typing``). The LLM client (when
configured) is supplied by callers via the
:class:`elengenix.agents.base.LLMClient` Protocol so the module never
imports langchain / litellm / pydantic-ai directly.

Public API:
    EntityExtractor            — main extractor class.
    ExtractedEntity            — intermediate (label, value, attrs) triple.
    RELATIONSHIP_EXTRACTION_PROMPT — Jinja-ready system prompt template.

Design notes
------------
* Regex patterns are pre-compiled once at module load (immutable) and
  re-used across all instances. Patterns that share a character class
  (e.g. IPs inside URLs) are de-duplicated by value before node creation
  via ``_dedup_entities``.
* The LLM relationship pass is **optional**: if ``llm_client`` is
  ``None`` the extractor falls back to purely heuristic relationship
  inference (co-occurrence + label-based rules). This keeps the
  extractor useful in offline / unit-test scenarios.
* The extractor never mutates the KnowledgeGraph itself — it returns
  ``list[Node]`` / ``list[Edge]`` and lets the caller (typically
  :class:`KnowledgeGraphIntegration`) decide whether to ingest them.
  This separation keeps the extractor pure and trivially testable.
* Node UUIDs are derived deterministically from ``(group_id, label,
  value)`` so re-extracting the same entity from a different source
  yields the same UUID (enables idempotent ingestion + edge dedup).
  Edges similarly derive their UUID from
  ``(group_id, source_uuid, edge_type, target_uuid)``.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Iterable, Protocol, TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover - typing only
    from elengenix.agents.base import LLMClient

logger = logging.getLogger("elengenix.knowledge_graph.extractor")

# ---------------------------------------------------------------------------
# Core graph primitives — imported from Task 5-a's ``graph.py``.
# ---------------------------------------------------------------------------

from .graph import (  # noqa: E402
    Edge,
    EdgeType,
    Node,
    NodeLabel,
)


# ---------------------------------------------------------------------------
# Regex patterns — pre-compiled at module load.
# ---------------------------------------------------------------------------

_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_IPV6_RE = re.compile(r"\b(?:[A-F0-9]{1,4}:){7}[A-F0-9]{1,4}\b", re.IGNORECASE)
_DOMAIN_RE = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b"
)
_URL_RE = re.compile(r"https?://[^\s<>\"{}|\\^`\[\]]+")
_PORT_KEYWORD_RE = re.compile(r"\bport[:\s]+(\d{1,5})\b", re.IGNORECASE)
_PORT_COLON_RE = re.compile(r":(\d{1,5})\b")
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
_EMAIL_RE = re.compile(
    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"
)
_CRED_RE = re.compile(
    r"(?:password|passwd|pwd|secret|token|api[_-]?key)[\s:=]+[\"']?([^\"'\s]+)[\"']?",
    re.IGNORECASE,
)
_FILE_PATH_RE = re.compile(r"(?:/[\w\-./]+)+")
_BANNER_RE = re.compile(
    r"(?:Apache|nginx|OpenSSH|MySQL|PostgreSQL|Redis|MongoDB)[/\s][\d.]+",
    re.IGNORECASE,
)
_MD5_RE = re.compile(r"\b[a-fA-F0-9]{32}\b")
_SHA1_RE = re.compile(r"\b[a-fA-F0-9]{40}\b")
_SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")

# Private-IP ranges — recorded as an attribute on the IP_ADDRESS node.
_PRIVATE_IPV4_RE = re.compile(
    r"^(?:10\.|127\.|192\.168\.|169\.254\.|172\.(?:1[6-9]|2\d|3[01])\.)"
)


# ---------------------------------------------------------------------------
# ExtractedEntity — intermediate value used before node-UUID assignment.
# ---------------------------------------------------------------------------


@dataclass
class ExtractedEntity:
    """Intermediate extracted entity (label + value + optional attrs).

    Carries everything needed to mint a :class:`Node` later without the
    extractor having to know about UUID generation or KnowledgeGraph
    storage semantics.
    """

    label: NodeLabel
    value: str
    attributes: dict[str, Any] = field(default_factory=dict)
    source_episode_uuid: str | None = None

    def key(self) -> tuple[NodeLabel, str]:
        """Return the de-dup key (label, lowercased value)."""
        return (self.label, self.value.lower().strip())


# ---------------------------------------------------------------------------
# LLM relationship-extraction prompt.
# ---------------------------------------------------------------------------

RELATIONSHIP_EXTRACTION_PROMPT = """\
You are a security knowledge-graph builder. Given a list of entities
(nodes) and the surrounding context they were extracted from, identify
the relationships between them.

Each entity is described as:
  [N<i>] <label> = <value>

Valid relationship types (use EXACTLY these names):
  - HAS_PORT        : a host/IP exposes a port.
  - EXPLOITS        : a tool / CVE exploits a service or vulnerability.
  - MENTIONS        : one entity references another.
  - WORKS_ON        : a tool works on a target / vulnerability class.
  - DISCOVERED_BY   : a finding was discovered by a tool / agent.
  - RELATED_TO      : generic relationship (use sparingly).

Respond with a JSON array of objects with keys:
  {"source": "N<i>", "target": "N<j>", "type": "<RELATIONSHIP_TYPE>",
   "fact": "<short natural-language description>"}

Only emit relationships you are confident about. If there are none,
respond with an empty array `[]`. Do not include any prose outside the
JSON array.

Entities:
{entities}

Context:
{context}
"""


# ---------------------------------------------------------------------------
# Optional LLM client protocol (structural — matches agents.base.LLMClient).
# ---------------------------------------------------------------------------


class _SupportsLLMCall(Protocol):
    """Structural protocol for any object exposing ``async call(chain, ...)``.

    Matches :class:`elengenix.agents.base.LLMClient` so callers can pass
    either the real client or any test double without a hard dependency.
    """

    async def call(
        self,
        chain: list[Any],
        tools: list[dict[str, Any]] | None = None,
        agent_type: Any | None = None,
    ) -> Any:
        """Return an object with a ``content`` string attribute."""
        ...


# ---------------------------------------------------------------------------
# EntityExtractor
# ---------------------------------------------------------------------------


class EntityExtractor:
    """Extract entities & relationships from text / tool outputs.

    Usage:
        extractor = EntityExtractor(llm_client=my_llm)
        nodes = await extractor.extract_from_text(
            "Scan found 10.0.0.1:22 (OpenSSH 8.2p1)",
            group_id="flow-42",
        )
        edges = await extractor.extract_relationships(
            nodes, context="port-scan output", group_id="flow-42",
        )

    Args:
        llm_client: Optional LLM client (matches ``agents.base.LLMClient``
            Protocol). When ``None`` the extractor uses purely heuristic
            relationship inference.
        kg: Optional KnowledgeGraph reference. Currently unused but kept
            on the constructor for forward compatibility (future versions
            may consult existing nodes for de-duplication / merging).
        max_text_chars: Hard cap on the text length passed to the LLM
            during relationship extraction (default 8_000 chars). Texts
            longer than this are truncated to keep prompt size bounded.
    """

    # Map of pattern-name -> (compiled_regex, NodeLabel, value_group_index_or_fn)
    # ``value_group`` is either an int (group index) or a callable(match) -> str.
    _PATTERNS: list[
        tuple[str, re.Pattern[str], NodeLabel, "int | Callable[[re.Match[str]], str]"]
    ] = [
        # CVEs first so they win over generic text patterns.
        ("cve", _CVE_RE, NodeLabel.VULNERABILITY, 0),
        ("url", _URL_RE, NodeLabel.ENDPOINT, 0),
        ("email", _EMAIL_RE, NodeLabel.ENTITY, 0),
        ("ipv6", _IPV6_RE, NodeLabel.IP_ADDRESS, 0),
        ("ipv4", _IPV4_RE, NodeLabel.IP_ADDRESS, 0),
        ("domain", _DOMAIN_RE, NodeLabel.ENTITY, 0),
        ("md5", _MD5_RE, NodeLabel.ENTITY, 0),
        ("sha1", _SHA1_RE, NodeLabel.ENTITY, 0),
        ("sha256", _SHA256_RE, NodeLabel.ENTITY, 0),
        ("banner", _BANNER_RE, NodeLabel.SERVICE, 0),
        ("credential", _CRED_RE, NodeLabel.CREDENTIAL, 1),
        ("port_keyword", _PORT_KEYWORD_RE, NodeLabel.ENTITY, 1),
        ("file_path", _FILE_PATH_RE, NodeLabel.ENTITY, 0),
    ]

    def __init__(
        self,
        llm_client: "_SupportsLLMCall | None" = None,
        kg: Any | None = None,
        max_text_chars: int = 8_000,
    ) -> None:
        self.llm_client = llm_client
        self.kg = kg
        self.max_text_chars = max_text_chars

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def extract_from_text(
        self,
        text: str,
        group_id: str,
        source_episode_uuid: str | None = None,
    ) -> list[Node]:
        """Extract entities from free-form ``text``.

        Runs every regex pattern in :attr:`_PATTERNS` against ``text``,
        classifies each match into a :class:`NodeLabel`, and mints a
        :class:`Node` per unique (label, value) pair. De-duplication is
        case-insensitive on the value.

        Args:
            text: Input text (agent response, tool output, etc.).
            group_id: Knowledge-graph group ID (typically ``"flow-{id}"``).
            source_episode_uuid: Optional UUID of the originating episode
                so nodes can be traced back to the text that produced
                them (stored in ``node.attributes["source_episode_uuid"]``).

        Returns:
            List of :class:`Node` objects (de-duplicated). Order is
            deterministic: by label name then by value.
        """
        if not text:
            return []
        entities = self._extract_all_patterns(text, source_episode_uuid)
        return self._entities_to_nodes(entities, group_id)

    async def extract_from_tool_output(
        self,
        tool_name: str,
        output: str,
        group_id: str,
    ) -> list[Node]:
        """Extract entities from a VulnAgent tool's output.

        Runs the generic text-extraction pass plus a tool-specific
        extraction pass (e.g. ``port_scan`` -> structured port entities,
        ``search_cve`` -> CVE/vulnerability nodes, ``web_recon`` ->
        endpoint nodes). Tool-specific extractors are best-effort —
        unknown tool names fall back to plain text extraction.

        Args:
            tool_name: Tool identifier (e.g. ``"port_scan"``,
                ``"web_recon"``, ``"vuln_scan"``, ``"search_cve"``).
            output: Raw tool output (string).
            group_id: Knowledge-graph group ID.

        Returns:
            List of de-duplicated :class:`Node` objects. The first node
            is always the tool itself (label=TOOL).
        """
        if not output:
            return []
        # Treat the tool itself as a node so relationships can reference it.
        tool_node = self._make_node(
            ExtractedEntity(
                label=NodeLabel.TOOL,
                value=tool_name,
                attributes={"tool_kind": "vulnagent_tool"},
            ),
            group_id=group_id,
        )
        nodes: list[Node] = [tool_node]

        # Generic regex pass over the textual output.
        nodes.extend(
            await self.extract_from_text(output, group_id=group_id)
        )

        # Tool-specific structured extraction.
        tool_specific = self._extract_tool_specific(tool_name, output)
        nodes.extend(self._entities_to_nodes(tool_specific, group_id))
        return self._dedup_nodes(nodes)

    async def extract_relationships(
        self,
        nodes: list[Node],
        context: str,
        group_id: str,
    ) -> list[Edge]:
        """Identify relationships between ``nodes``.

        If an LLM client is configured, sends a structured prompt asking
        the LLM to identify relationships; otherwise falls back to
        deterministic heuristics based on node labels and co-occurrence.

        Args:
            nodes: Nodes to relate (typically the output of
                :meth:`extract_from_text` or
                :meth:`extract_from_tool_output`).
            context: Surrounding text the nodes were extracted from.
                Passed to the LLM as grounding context.
            group_id: Knowledge-graph group ID.

        Returns:
            List of :class:`Edge` objects. Each edge has stable UUIDs
            derived from (source, target, edge_type) so re-running
            extraction on the same input is idempotent.
        """
        if not nodes:
            return []
        if self.llm_client is not None:
            try:
                edges = await self._llm_relationships(nodes, context, group_id)
                if edges:
                    return edges
            except Exception as exc:  # pragma: no cover - defensive
                logger.warning(
                    "llm_relationship_extraction_failed error=%s -- "
                    "falling back to heuristics",
                    exc,
                )
        return self._heuristic_relationships(nodes, group_id)

    # ------------------------------------------------------------------
    # Pattern matching
    # ------------------------------------------------------------------

    def _extract_all_patterns(
        self,
        text: str,
        source_episode_uuid: str | None,
    ) -> list[ExtractedEntity]:
        """Run every regex pattern and return a list of ExtractedEntity."""
        out: list[ExtractedEntity] = []
        for name, pat, label, value_src in self._PATTERNS:
            for m in pat.finditer(text):
                value = m.group(value_src) if isinstance(value_src, int) \
                    else value_src(m)
                value = value.strip()
                if not value:
                    continue
                attrs = self._initial_attributes(name, label, value)
                out.append(
                    ExtractedEntity(
                        label=label,
                        value=value,
                        attributes=attrs,
                        source_episode_uuid=source_episode_uuid,
                    )
                )
        # Bare ``:NNNN`` ports — but only after masking URLs so we don't
        # pick up ``:443`` from ``https://host:443/``.
        masked = _URL_RE.sub(" ", text)
        for m in _PORT_COLON_RE.finditer(masked):
            port_val = m.group(1)
            if not port_val.isdigit():
                continue
            pnum = int(port_val)
            if pnum == 0 or pnum > 65535:
                continue
            out.append(
                ExtractedEntity(
                    label=NodeLabel.ENTITY,
                    value=port_val,
                    attributes={
                        "pattern": "port_colon", "kind": "port",
                        "port": pnum,
                    },
                    source_episode_uuid=source_episode_uuid,
                )
            )
        return self._dedup_entities(out)

    @staticmethod
    def _initial_attributes(name: str, label: NodeLabel, value: str) -> dict[str, Any]:
        """Build the initial attributes dict for a freshly-extracted entity."""
        attrs: dict[str, Any] = {"pattern": name}
        if label is NodeLabel.IP_ADDRESS:
            attrs["is_private"] = bool(_PRIVATE_IPV4_RE.match(value))
        elif label is NodeLabel.ENTITY:
            # Disambiguate the kind of entity so callers can still tell a
            # domain from a port / email / hash / file_path.
            kind_map = {
                "domain": "domain",
                "email": "email",
                "md5": "hash",
                "sha1": "hash",
                "sha256": "hash",
                "port_keyword": "port",
                "port_colon": "port",
                "file_path": "file_path",
            }
            kind = kind_map.get(name)
            if kind is not None:
                attrs["kind"] = kind
            if name in {"md5", "sha1", "sha256"}:
                attrs["algorithm"] = EntityExtractor._hash_algorithm(value)
                attrs["value"] = value
            if name in {"port_keyword", "port_colon"} and value.isdigit():
                attrs["port"] = int(value)
        elif label is NodeLabel.SERVICE:
            attrs["banner"] = value
            parsed = EntityExtractor._parse_banner(value)
            if parsed:
                attrs["service_name"] = parsed[0]
                attrs["service_version"] = parsed[1]
        elif label is NodeLabel.VULNERABILITY:
            attrs["cve_id"] = value
        elif label is NodeLabel.ENDPOINT:
            attrs["kind"] = "url"
            attrs["url"] = value
        elif label is NodeLabel.CREDENTIAL:
            attrs["secret"] = value  # NB: stored verbatim — caller's call.
            attrs["kind"] = name
        return attrs

    def _extract_tool_specific(
        self,
        tool_name: str,
        output: str,
    ) -> list[ExtractedEntity]:
        """Tool-specific structured extraction.

        Looks for JSON-shaped tool outputs (VulnAgent tools return dicts
        that get JSON-serialised) and pulls out structured fields.
        Best-effort: any parsing failure simply yields no entities.
        """
        out: list[ExtractedEntity] = []
        payload: Any = None
        try:
            payload = json.loads(output)
        except (json.JSONDecodeError, TypeError):
            payload = None

        tn = tool_name.lower()

        if tn in {"port_scan", "vuln_scan", "analyze_target"} and isinstance(
            payload, dict
        ):
            out.extend(self._extract_from_port_scan(payload))
        if tn in {"search_cve", "vuln_scan"} and isinstance(payload, dict):
            out.extend(self._extract_from_cve_search(payload))
        if tn in {"web_recon", "web_extract"} and isinstance(payload, dict):
            out.extend(self._extract_from_web_recon(payload))
        return self._dedup_entities(out)

    def _extract_from_port_scan(
        self, payload: dict[str, Any]
    ) -> list[ExtractedEntity]:
        out: list[ExtractedEntity] = []
        ports = payload.get("ports") or payload.get("open_ports") or []
        if isinstance(ports, list):
            for p in ports:
                pnum: int | None = None
                proto = "tcp"
                svc: str | None = None
                if isinstance(p, int):
                    pnum = p
                elif isinstance(p, str) and p.isdigit():
                    pnum = int(p)
                elif isinstance(p, dict):
                    pnum = p.get("port") or p.get("number")
                    proto = p.get("protocol", "tcp")
                    svc = p.get("service") or p.get("name")
                if pnum is None:
                    continue
                out.append(
                    ExtractedEntity(
                        label=NodeLabel.ENTITY,
                        value=str(int(pnum)),
                        attributes={
                            "kind": "port", "port": int(pnum),
                            "protocol": proto,
                        },
                    )
                )
                if svc:
                    out.append(
                        ExtractedEntity(
                            label=NodeLabel.SERVICE,
                            value=f"{svc}/{int(pnum)}",
                            attributes={
                                "service_name": svc, "port": int(pnum),
                            },
                        )
                    )
        return out

    def _extract_from_cve_search(
        self, payload: dict[str, Any]
    ) -> list[ExtractedEntity]:
        out: list[ExtractedEntity] = []
        cves = payload.get("cves") or payload.get("vulnerabilities") or []
        if isinstance(cves, list):
            for c in cves:
                if isinstance(c, str):
                    out.append(
                        ExtractedEntity(
                            label=NodeLabel.VULNERABILITY,
                            value=c,
                            attributes={"cve_id": c},
                        )
                    )
                elif isinstance(c, dict):
                    cid = c.get("id") or c.get("cve")
                    if not cid:
                        continue
                    attrs: dict[str, Any] = {"cve_id": str(cid)}
                    if "cvss" in c:
                        attrs["cvss"] = c["cvss"]
                    if "severity" in c:
                        attrs["severity"] = c["severity"]
                    if "description" in c:
                        attrs["description"] = str(c["description"])[:500]
                    out.append(
                        ExtractedEntity(
                            label=NodeLabel.VULNERABILITY,
                            value=str(cid),
                            attributes=attrs,
                        )
                    )
        return out

    def _extract_from_web_recon(
        self, payload: dict[str, Any]
    ) -> list[ExtractedEntity]:
        out: list[ExtractedEntity] = []
        for key in ("endpoints", "links", "urls"):
            items = payload.get(key) or []
            if isinstance(items, list):
                for item in items:
                    if isinstance(item, str):
                        out.append(
                            ExtractedEntity(
                                label=NodeLabel.ENDPOINT,
                                value=item,
                                attributes={"kind": "url", "url": item},
                            )
                        )
                    elif isinstance(item, dict):
                        path = item.get("path") or item.get("url")
                        if path:
                            attrs: dict[str, Any] = {
                                "kind": "endpoint", "url": str(path),
                            }
                            for k in ("method", "status", "title"):
                                if k in item:
                                    attrs[k] = item[k]
                            out.append(
                                ExtractedEntity(
                                    label=NodeLabel.ENDPOINT,
                                    value=str(path),
                                    attributes=attrs,
                                )
                            )
        return out

    # ------------------------------------------------------------------
    # Relationship inference
    # ------------------------------------------------------------------

    async def _llm_relationships(
        self,
        nodes: list[Node],
        context: str,
        group_id: str,
    ) -> list[Edge]:
        """Ask the LLM to identify relationships between ``nodes``."""
        from elengenix.agents.base import Message  # type: ignore

        ctx = context[: self.max_text_chars]
        entities_block = "\n".join(
            f"  [N{i}] {_label_str(n)} = {n.name}"
            for i, n in enumerate(nodes)
        )
        prompt = RELATIONSHIP_EXTRACTION_PROMPT.format(
            entities=entities_block or "  (none)",
            context=ctx or "(no context provided)",
        )
        chain = [
            Message(role="system", content="You are a security knowledge-graph builder."),
            Message(role="user", content=prompt),
        ]
        resp = await self.llm_client.call(chain=chain, tools=None)  # type: ignore[attr-defined]
        content = getattr(resp, "content", "") or ""
        parsed = self._parse_llm_relationship_json(content)
        edges: list[Edge] = []
        for rel in parsed:
            try:
                src_idx = int(str(rel.get("source"))[1:])
                tgt_idx = int(str(rel.get("target"))[1:])
            except (ValueError, AttributeError, IndexError):
                continue
            if not (0 <= src_idx < len(nodes) and 0 <= tgt_idx < len(nodes)):
                continue
            rtype = str(rel.get("type", "")).upper().strip()
            try:
                etype = EdgeType(rtype)
            except ValueError:
                etype = EdgeType.RELATED_TO
            fact = str(rel.get("fact", "")).strip()
            edges.append(self._make_edge(
                source=nodes[src_idx],
                target=nodes[tgt_idx],
                edge_type=etype,
                group_id=group_id,
                fact=fact or (
                    f"{nodes[src_idx].name} {etype.value} "
                    f"{nodes[tgt_idx].name}"
                ),
            ))
        return edges

    def _parse_llm_relationship_json(self, content: str) -> list[dict[str, Any]]:
        """Parse the LLM's JSON-array response.

        Tolerates fenced ```json blocks and trailing prose by extracting
        the first ``[`` ... last ``]`` slice.
        """
        if not content:
            return []
        start = content.find("[")
        end = content.rfind("]")
        if start == -1 or end == -1 or end < start:
            return []
        try:
            data = json.loads(content[start : end + 1])
        except json.JSONDecodeError:
            return []
        if not isinstance(data, list):
            return []
        return [d for d in data if isinstance(d, dict)]

    def _heuristic_relationships(
        self,
        nodes: list[Node],
        group_id: str,
    ) -> list[Edge]:
        """Deterministic relationship inference.

        Rules:
          * IP_ADDRESS -> HAS_PORT -> ENTITY (kind=port)
          * IP_ADDRESS -> MENTIONS -> SERVICE
          * IP_ADDRESS -> RELATED_TO -> ENDPOINT
          * TOOL -> WORKS_ON -> IP_ADDRESS / ENDPOINT
          * TOOL -> DISCOVERED_BY -> VULNERABILITY
          * VULNERABILITY -> EXPLOITS -> SERVICE
          * ENTITY (kind=domain) -> RELATED_TO -> IP_ADDRESS (resolves-to)
        """
        if not nodes:
            return []
        edges: list[Edge] = []
        ips = [n for n in nodes if NodeLabel.IP_ADDRESS in n.labels]
        ports = [
            n for n in nodes
            if NodeLabel.ENTITY in n.labels
            and n.attributes.get("kind") == "port"
        ]
        domains = [
            n for n in nodes
            if NodeLabel.ENTITY in n.labels
            and n.attributes.get("kind") == "domain"
        ]
        services = [n for n in nodes if NodeLabel.SERVICE in n.labels]
        cves = [n for n in nodes if NodeLabel.VULNERABILITY in n.labels]
        tools = [n for n in nodes if NodeLabel.TOOL in n.labels]
        endpoints = [n for n in nodes if NodeLabel.ENDPOINT in n.labels]

        seen: set[tuple[str, str, str]] = set()

        def add(src: Node, tgt: Node, etype: EdgeType, fact: str) -> None:
            key = (src.uuid, tgt.uuid, etype.value)
            if key in seen:
                return
            seen.add(key)
            edges.append(
                self._make_edge(src, tgt, etype, group_id, fact)
            )

        for ip in ips:
            for port in ports:
                add(ip, port, EdgeType.HAS_PORT,
                    f"{ip.name} exposes port {port.name}")
            for svc in services:
                add(ip, svc, EdgeType.MENTIONS,
                    f"{ip.name} runs {svc.name}")
            for ep in endpoints:
                add(ip, ep, EdgeType.RELATED_TO,
                    f"{ip.name} exposes endpoint {ep.name}")
        for tool in tools:
            for ip in ips:
                add(tool, ip, EdgeType.WORKS_ON,
                    f"{tool.name} targeted {ip.name}")
            for cve in cves:
                add(tool, cve, EdgeType.DISCOVERED_BY,
                    f"{cve.name} surfaced by {tool.name}")
            for ep in endpoints:
                add(tool, ep, EdgeType.WORKS_ON,
                    f"{tool.name} probed {ep.name}")
        for cve in cves:
            for svc in services:
                add(cve, svc, EdgeType.EXPLOITS,
                    f"{cve.name} may exploit {svc.name}")
        # Cross-link domains -> IPs (RESOLVES_TO maps to RELATED_TO since
        # Task 5-a's EdgeType doesn't have RESOLVES_TO).
        for d in domains:
            for ip in ips:
                add(d, ip, EdgeType.RELATED_TO,
                    f"{d.name} resolves to {ip.name}")
        return edges

    # ------------------------------------------------------------------
    # Node / Edge / Entity helpers
    # ------------------------------------------------------------------

    def _entities_to_nodes(
        self,
        entities: list[ExtractedEntity],
        group_id: str,
    ) -> list[Node]:
        out: list[Node] = []
        for ent in self._dedup_entities(entities):
            out.append(self._make_node(ent, group_id=group_id))
        out.sort(key=lambda n: (_label_str(n), n.name.lower()))
        return out

    def _make_node(
        self,
        ent: ExtractedEntity,
        group_id: str,
    ) -> Node:
        """Mint a Node from an ExtractedEntity.

        UUID is derived deterministically from (group_id, label, value)
        so re-extracting the same entity from a different source yields
        the same UUID (enables idempotent ingestion + edge dedup).
        """
        node_uuid = self._deterministic_uuid(
            f"node:{group_id}:{ent.label.value}:{ent.value.lower()}"
        )
        attrs = dict(ent.attributes)
        if ent.source_episode_uuid:
            attrs["source_episode_uuid"] = ent.source_episode_uuid
        summary = attrs.pop("description", "") or ent.value
        return Node(
            uuid=node_uuid,
            name=ent.value,
            labels=[ent.label],
            summary=summary[:500],
            attributes=attrs,
            created_at=_now_dt(),
            group_id=group_id,
        )

    def _make_edge(
        self,
        source: Node,
        target: Node,
        edge_type: EdgeType,
        group_id: str,
        fact: str,
    ) -> Edge:
        edge_uuid = self._deterministic_uuid(
            f"edge:{group_id}:{source.uuid}:{edge_type.value}:{target.uuid}"
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

    @staticmethod
    def _deterministic_uuid(seed: str) -> str:
        """Return a deterministic UUID5 (DNS namespace) for ``seed``."""
        return str(uuid.uuid5(uuid.NAMESPACE_DNS, seed))

    @staticmethod
    def _dedup_entities(entities: Iterable[ExtractedEntity]) -> list[ExtractedEntity]:
        """De-duplicate by (label, lowercased value), merging attributes."""
        out: dict[tuple[NodeLabel, str], ExtractedEntity] = {}
        for ent in entities:
            key = ent.key()
            if key not in out:
                out[key] = ent
                continue
            merged = out[key]
            merged_attrs = dict(merged.attributes)
            merged_attrs.update(ent.attributes)
            merged.attributes = merged_attrs
            if ent.source_episode_uuid and not merged.source_episode_uuid:
                merged.source_episode_uuid = ent.source_episode_uuid
        return list(out.values())

    @staticmethod
    def _dedup_nodes(nodes: Iterable[Node]) -> list[Node]:
        """De-duplicate by UUID, merging labels + attributes."""
        out: dict[str, Node] = {}
        for n in nodes:
            if n.uuid in out:
                existing = out[n.uuid]
                merged_labels = list(existing.labels)
                for lbl in n.labels:
                    if lbl not in merged_labels:
                        merged_labels.append(lbl)
                merged_attrs = dict(existing.attributes)
                merged_attrs.update(n.attributes)
                out[n.uuid] = Node(
                    uuid=existing.uuid,
                    name=existing.name,
                    labels=merged_labels,
                    summary=existing.summary or n.summary,
                    attributes=merged_attrs,
                    created_at=existing.created_at,
                    group_id=existing.group_id,
                )
            else:
                out[n.uuid] = n
        return list(out.values())

    @staticmethod
    def _hash_algorithm(value: str) -> str:
        n = len(value)
        if n == 32:
            return "md5"
        if n == 40:
            return "sha1"
        if n == 64:
            return "sha256"
        return "unknown"

    @staticmethod
    def _parse_banner(banner: str) -> tuple[str, str] | None:
        """Parse a service banner like ``Apache/2.4.41`` -> (name, version)."""
        if not banner:
            return None
        m = re.match(
            r"^([A-Za-z]+)[/\s]+([\d][\d.]*)",
            banner,
        )
        if not m:
            return None
        return (m.group(1).lower(), m.group(2))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _now_dt() -> datetime:
    """Return current UTC time as a timezone-aware datetime."""
    return datetime.now(tz=timezone.utc)


def _label_str(node: Node) -> str:
    """Return a human-friendly label string for a node."""
    if not node.labels:
        return "ENTITY"
    return node.labels[0].value


__all__ = [
    "EntityExtractor",
    "ExtractedEntity",
    "Node",
    "Edge",
    "NodeLabel",
    "EdgeType",
    "RELATIONSHIP_EXTRACTION_PROMPT",
]
