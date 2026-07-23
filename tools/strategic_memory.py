"""tools/strategic_memory.py — Strategic Recall API

Single facade that the DecisionEngine / PromptBuilder call to get
*strategic* memory context: what worked, what failed, what chains
succeeded, on similar targets before.

Why a facade?
-------------
Elengenix had three memory layers that didn't talk to each other:
- LearningEngine (flat exploit records, SQLite + ChromaDB)
- VectorMemory (semantic recall, ChromaDB)
- MissionState (per-mission graph, dies with the mission)

DecisionEngine had to know which layer to ask. In practice it never
asked any of them at decision time. This facade:

1. Aggregates recall across all three layers in one call.
2. Returns a single formatted string ready for prompt injection.
3. Adds the new KnowledgeGraph (cross-session reasoning graph) which
   captures *chains* and *strategies* — not just flat records.

Public API
----------
    sm = StrategicMemory()

    # Before each decision turn:
    ctx_str = sm.build_decision_context(
        target="example.com",
        tech_stack=["php", "nginx"],
        vuln_class="lfi",
    )
    # -> formatted string for prompt injection

    # After each finding:
    sm.record_finding(target=..., endpoint=..., tech_stack=...,
                     vuln_class=..., tool=..., payload=...,
                     severity=..., success=..., mission_id=...)
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger("elengenix.strategic_memory")


class StrategicMemory:
    """Facade aggregating all memory layers into strategic recall.

    Lazily loads each backend so missing optional deps (ChromaDB) don't
    break the agent — the facade just returns less context.
    """

    def __init__(self):
        self._kg = None
        self._learning = None
        self._vector = None

    @property
    def knowledge_graph(self):
        if self._kg is None:
            try:
                from tools.knowledge_graph import KnowledgeGraph
                self._kg = KnowledgeGraph()
            except Exception as e:
                logger.debug(f"KnowledgeGraph unavailable: {e}")
        return self._kg

    @property
    def learning_engine(self):
        if self._learning is None:
            try:
                from tools.learning_engine import LearningEngine
                self._learning = LearningEngine()
            except Exception as e:
                logger.debug(f"LearningEngine unavailable: {e}")
        return self._learning

    @property
    def vector_memory(self):
        if self._vector is None:
            try:
                from tools.vector_memory import get_vector_memory
                self._vector = get_vector_memory()
            except Exception as e:
                logger.debug(f"VectorMemory unavailable: {e}")
        return self._vector

    # ------------------------------------------------------------------
    # Recording
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
    ) -> None:
        """Record a finding across all memory layers.

        Best-effort: failures in one layer don't block the others.
        """
        # 1. Knowledge graph (cross-session reasoning graph)
        if self.knowledge_graph:
            try:
                self.knowledge_graph.record_finding(
                    target=target, endpoint=endpoint, tech_stack=tech_stack,
                    vuln_class=vuln_class, tool=tool, payload=payload,
                    severity=severity, success=success,
                    confidence=confidence, mission_id=mission_id,
                )
            except Exception as e:
                logger.debug(f"kg.record_finding failed: {e}")

        # 2. Learning engine (flat exploit records)
        if self.learning_engine:
            try:
                from tools.learning_engine import ExploitRecord
                record = ExploitRecord(
                    target=target,
                    tech_stack=list(tech_stack or []),
                    vuln_class=vuln_class,
                    tool=tool,
                    payload=(payload or "")[:500],
                    success=success,
                    confidence=confidence,
                    severity=severity,
                    notes=f"{vuln_class}@{endpoint}",
                )
                self.learning_engine.remember(record)
            except Exception as e:
                logger.debug(f"learning.remember failed: {e}")

        # 3. Vector memory (semantic recall)
        try:
            from tools.vector_memory import remember
            content = f"{vuln_class} at {endpoint} on {target}: {severity} (tool={tool}, success={success})"
            remember(content, target=target or "global",
                     category="finding",
                     vuln_class=vuln_class, tool=tool, severity=severity)
        except Exception as e:
            logger.debug(f"vector_memory.remember failed: {e}")

    def record_chain(
        self,
        steps: List[Dict[str, Any]],
        combined_severity: str,
        target: str,
        mission_id: Optional[str] = None,
        description: str = "",
    ) -> None:
        """Record a successful multi-step attack chain."""
        if self.knowledge_graph:
            try:
                self.knowledge_graph.record_chain(
                    steps=steps,
                    combined_severity=combined_severity,
                    target=target,
                    mission_id=mission_id,
                    description=description,
                )
            except Exception as e:
                logger.debug(f"kg.record_chain failed: {e}")

    # ------------------------------------------------------------------
    # Recall
    # ------------------------------------------------------------------

    def build_decision_context(
        self,
        target: Optional[str] = None,
        tech_stack: Optional[List[str]] = None,
        vuln_class: Optional[str] = None,
        max_strategies: int = 5,
        max_failures: int = 5,
        max_chains: int = 3,
    ) -> str:
        """Build a single formatted context string for the AI decision prompt.

        Pulls from all memory layers and assembles a concise summary
        the AI can read in <2k tokens.

        Args:
            target: The target being scanned.
            tech_stack: Detected tech stack.
            vuln_class: Optional specific vuln class being investigated.
            max_strategies: Cap on recalled successful strategies.
            max_failures: Cap on recalled failures to avoid.
            max_chains: Cap on recalled attack chains.

        Returns:
            Formatted string ready to inject into the AI prompt. May be
            empty if no relevant memory exists yet.
        """
        parts: List[str] = []

        # 1. Successful strategies (what worked before)
        strategies = self._recall_strategies(tech_stack, vuln_class, max_strategies)
        if strategies:
            parts.append("**STRATEGIES THAT WORKED BEFORE (consider these first):**")
            for s in strategies:
                tool = s.get("tool", "?")
                payload = (s.get("payload") or "")[:60]
                weight = s.get("weight", 0)
                hits = s.get("hits", 0)
                parts.append(f"  - {tool} `{payload}` (weight={weight:.2f}, hits={hits})")
            parts.append("")

        # 2. Failures (what to AVOID)
        failures = self._recall_failures(tech_stack, target, max_failures)
        if failures:
            parts.append("**APPROACHES THAT FAILED BEFORE (do not repeat):**")
            for f in failures:
                tool = f.get("tool", "?")
                payload = (f.get("payload") or "")[:60]
                fc = f.get("fail_count", 1)
                parts.append(f"  - {tool} `{payload}` (failed {fc}x)")
            parts.append("")

        # 3. Attack chains (multi-step escalations that worked)
        chains = self._recall_chains(tech_stack, target, max_chains)
        if chains:
            parts.append("**SUCCESSFUL ATTACK CHAINS (reuse if applicable):**")
            for c in chains:
                sev = c.get("combined_severity", "?")
                steps = c.get("steps", [])
                step_str = " -> ".join(
                    f"{s.get('vuln', '?')}@{s.get('endpoint', '/')}" for s in steps
                )
                parts.append(f"  - [{sev}] {step_str}")
            parts.append("")

        # 4. Vector recall (semantic — what do we know about this target?)
        if target:
            semantic = self._recall_semantic(target, vuln_class)
            if semantic:
                parts.append("**SEMANTIC RECALL (prior knowledge about this target):**")
                for entry in semantic[:5]:
                    content = (entry.get("content") or "")[:200]
                    parts.append(f"  - {content}")
                parts.append("")

        if not parts:
            return "(No strategic memory yet — first encounter with this target profile.)"

        return "\n".join(parts)

    # ------------------------------------------------------------------
    # Internal recall wrappers (best-effort, tolerate missing backends)
    # ------------------------------------------------------------------

    def _recall_strategies(
        self,
        tech_stack: Optional[List[str]],
        vuln_class: Optional[str],
        limit: int,
    ) -> List[Dict[str, Any]]:
        results: List[Dict[str, Any]] = []
        # Knowledge graph
        if self.knowledge_graph:
            try:
                results.extend(self.knowledge_graph.recall_strategies(
                    tech_stack=tech_stack, vuln_class=vuln_class, limit=limit
                ))
            except Exception as e:
                logger.debug(f"kg.recall_strategies failed: {e}")
        # Learning engine (tool rankings)
        if self.learning_engine and len(results) < limit:
            try:
                rankings = self.learning_engine.rank_tools(
                    tech_stack=tech_stack, vuln_class=vuln_class, limit=limit
                )
                for tool, rate, samples in rankings:
                    if len(results) >= limit:
                        break
                    results.append({
                        "tool": tool,
                        "payload": "",
                        "weight": float(rate),
                        "hits": int(samples),
                        "tech_stack": tech_stack or [],
                    })
            except Exception as e:
                logger.debug(f"learning.rank_tools failed: {e}")
        return results[:limit]

    def _recall_failures(
        self,
        tech_stack: Optional[List[str]],
        target: Optional[str],
        limit: int,
    ) -> List[Dict[str, Any]]:
        if self.knowledge_graph:
            try:
                return self.knowledge_graph.recall_failures(
                    tech_stack=tech_stack, target=target, limit=limit
                )
            except Exception as e:
                logger.debug(f"kg.recall_failures failed: {e}")
        return []

    def _recall_chains(
        self,
        tech_stack: Optional[List[str]],
        target: Optional[str],
        limit: int,
    ) -> List[Dict[str, Any]]:
        if self.knowledge_graph:
            try:
                return self.knowledge_graph.recall_chains(
                    tech_stack=tech_stack, target=target, limit=limit
                )
            except Exception as e:
                logger.debug(f"kg.recall_chains failed: {e}")
        return []

    def _recall_semantic(
        self,
        target: str,
        vuln_class: Optional[str],
    ) -> List[Dict[str, Any]]:
        if not self.vector_memory:
            return []
        try:
            from tools.vector_memory import recall
            query = f"{vuln_class} {target}" if vuln_class else target
            results = recall(query, target=target, n_results=5)
            # Normalize to list of dicts
            if isinstance(results, list):
                return results
            return []
        except Exception as e:
            logger.debug(f"vector recall failed: {e}")
            return []

    # ------------------------------------------------------------------
    # Observability
    # ------------------------------------------------------------------

    def stats(self) -> Dict[str, Any]:
        """Aggregate stats from all backends."""
        stats: Dict[str, Any] = {}
        if self.knowledge_graph:
            try:
                stats["knowledge_graph"] = self.knowledge_graph.stats()
            except Exception:
                pass
        if self.learning_engine:
            try:
                stats["learning_engine"] = self.learning_engine.get_stats()
            except Exception:
                pass
        return stats
