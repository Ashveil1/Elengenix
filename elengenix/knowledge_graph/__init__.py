"""elengenix.knowledge_graph — Knowledge Graph entity extraction & integration.

This subpackage ports PentAGI's Graphiti-backed knowledge-graph layer to
Elengenix. It is composed of four modules:

* ``graph``        — core primitives (:class:`Node`, :class:`Edge`,
  :class:`NodeLabel`, :class:`EdgeType`, :class:`Episode`,
  :class:`Community`, :class:`KnowledgeGraph`) backed by NetworkX +
  SQLite. Provided by Task 5-a.
* ``extractor``    — :class:`EntityExtractor` regex + LLM extraction of
  entities (IPs, domains, URLs, ports, CVEs, hashes, credentials,
  file paths, service banners, emails) and relationships
  (``HAS_PORT``, ``EXPLOITS``, ``MENTIONS``, ``WORKS_ON``,
  ``DISCOVERED_BY``, ``RELATED_TO``).
* ``integration``  — :class:`KnowledgeGraphIntegration` wires the
  extractor + KnowledgeGraph into VulnAgent's reasoning loop via
  ``on_agent_response`` / ``on_tool_execution`` /
  ``on_finding_discovered`` / ``get_relevant_context`` hooks. All hooks
  are no-ops when the KG is disabled.
* ``community``    — :class:`CommunityDetector` runs NetworkX's Louvain
  (with greedy-modularity fallback) over the per-flow subgraph and
  summarises / merges the resulting communities.

Design constraints
------------------
* All public APIs are ``async``.
* Heavy dependencies (``networkx``, the LLM client SDK) are lazy-imported
  inside methods so the package can be AST-validated without them.
* Each module degrades gracefully when ``graph.py`` (Task 5-a) is absent
  via try/except fallback stubs — the package is importable in isolation.
"""

from __future__ import annotations

from .graph import (
    Community,
    Edge,
    EdgeType,
    Episode,
    KnowledgeGraph,
    Node,
    NodeLabel,
)
from .extractor import (
    RELATIONSHIP_EXTRACTION_PROMPT,
    EntityExtractor,
    ExtractedEntity,
)
from .integration import (
    KnowledgeGraphIntegration,
    KnowledgeGraphProtocol,
)
from .community import (
    COMMUNITY_SUMMARY_PROMPT,
    DEFAULT_MERGE_THRESHOLD,
    CommunityDetector,
)

__all__ = [
    # graph (Task 5-a)
    "Node",
    "Edge",
    "NodeLabel",
    "EdgeType",
    "Episode",
    "Community",
    "KnowledgeGraph",
    # extractor
    "EntityExtractor",
    "ExtractedEntity",
    "RELATIONSHIP_EXTRACTION_PROMPT",
    # integration
    "KnowledgeGraphIntegration",
    "KnowledgeGraphProtocol",
    # community
    "CommunityDetector",
    "DEFAULT_MERGE_THRESHOLD",
    "COMMUNITY_SUMMARY_PROMPT",
]
