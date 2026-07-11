"""agents/vuln_reasoning_phase.py

The autonomous vulnerability-reasoning phase.

Why this exists
--------------
The original scan loop was "tool-chaining with an AI on top": deterministic
scanners and the 14-analyzer pipeline produced the findings, and the AI only
chose *which* tool to run next. The AI never *reasoned a vulnerability into
existence* from raw evidence — it could not, because nothing asked it to.

This phase closes that gap. After each action the loop hands the raw tool
output + observation to the LLM reasoning engine, which is free to:
  - form vulnerability hypotheses the static analyzers cannot see,
  - turn a hypothesis into a finding on its own authority,
  - propose the next test to confirm/refute it.

No hardcoded step list, no forced sequence. The AI decides what it thinks is
a vulnerability. This is what makes Elengenix an *agent* rather than a wrapper.

Integration
-----------
ScanLoop calls ``run_reasoning_phase(ctx, raw_output, observation, step)`` in
the post-execute phase. Hypotheses returned by the engine become findings
tagged ``source="ai_reasoning"`` (see tools/finding_provenance.py) so they
are never silently merged with deterministic tool output.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any, Dict, List, Optional

if TYPE_CHECKING:
    from agents.scan_context import ScanContext

logger = logging.getLogger("elengenix.reasoning_phase")

# Minimum confidence before a hypothesis is promoted to a real finding.
DEFAULT_MIN_CONFIDENCE = 0.35


def _get_reasoning_engine(client=None):
    """Lazily build the VulnReasoning engine.

    Pass a live LLM client so the engine performs REAL LLM reasoning rather
    than falling back to regex heuristics. Without a client the engine is
    useless in production (it silently degrades to keyword matching).
    """
    try:
        from tools.vuln_reasoning import VulnReasoningEngine

        return VulnReasoningEngine(client=client)
    except Exception as e:  # pragma: no cover - engine optional
        logger.debug(f"Could not init reasoning engine: {e}")
        return None


def _hypothesis_to_finding(h: Dict[str, Any], target: str, step: int) -> Dict[str, Any]:
    """Convert one LLM-generated hypothesis into a tagged finding dict."""
    from tools.finding_provenance import tag_provenance

    sev = str(h.get("severity", "Medium")).lower()
    finding = {
        "type": h.get("vuln_class", "ai_hypothesis"),
        "title": h.get("title", "AI-generated vulnerability hypothesis"),
        "severity": sev,
        "confidence": float(h.get("confidence", 0.5)),
        "description": h.get("reasoning", ""),
        "evidence": h.get("evidence", []),
        "suggested_tests": h.get("suggested_tests", []),
        "cwe": h.get("cwe", ""),
        "target_endpoint": h.get("target_endpoint", ""),
        "parameter": h.get("parameter", ""),
        "payload": h.get("payload", ""),
        "url": h.get("target_endpoint", "") or target,
        "source": "ai_reasoning",
        "provenance": "agentic",
        "trust_class": "non_deterministic",
        "discovered_by": "vuln_reasoning_phase",
        "discovered_at_step": step,
    }
    return tag_provenance(finding, source_hint="ai_reasoning")


def run_reasoning_phase(
    ctx: Any,
    raw_output: str,
    observation: str,
    step: int,
    engine=None,
    target: str = "",
    min_confidence: float = DEFAULT_MIN_CONFIDENCE,
    previous_findings: Optional[List[Dict[str, Any]]] = None,
    client: Any = None,
) -> List[Dict[str, Any]]:
    """Run the autonomous reasoning phase for one step.

    Args:
        ctx: scan context (used only for tech-stack / target hints).
        raw_output: raw stdout / tool output collected this step.
        observation: the loop's observation string for this step.
        step: current step index (recorded on findings).
        engine: optional pre-built VulnReasoning instance.
        target: target URL/host for context.
        min_confidence: drop hypotheses below this confidence.
        previous_findings: prior findings to give the AI correlation context.

    Returns:
        List of new finding dicts produced by the AI (may be empty).
    """
    evidence = (raw_output or "")[:6000]
    if not evidence.strip() and not (observation or "").strip():
        return []

    engine = engine or _get_reasoning_engine(client=client)
    if engine is None:
        return []
    try:
        result = engine.analyze_output(
            target=target or (ctx.target if ctx else ""),
            tool_name="agent_reasoning",
            tool_output=evidence,
            previous_findings=previous_findings or (ctx.all_findings if ctx else []),
        )
    except Exception as e:
        logger.debug(f"reasoning phase analyse failed: {e}")
        return []

    hypotheses = getattr(result, "hypotheses", None) or []
    new_findings: List[Dict[str, Any]] = []
    for h in hypotheses:
        hdict = h if isinstance(h, dict) else _dataclass_to_dict(h)
        conf = float(hdict.get("confidence", 0.0))
        if conf < min_confidence:
            continue
        new_findings.append(_hypothesis_to_finding(hdict, target or (ctx.target if ctx else ""), step))

    if new_findings:
        logger.info(
            f"reasoning phase produced {len(new_findings)} AI finding(s) at step {step}"
        )
    return new_findings


def _dataclass_to_dict(obj: Any) -> Dict[str, Any]:
    """Best-effort conversion of a dataclass/object to a dict."""
    if hasattr(obj, "__dict__"):
        return dict(obj.__dict__)
    if hasattr(obj, "to_dict"):
        try:
            return obj.to_dict()
        except Exception:
            return {}
    return {}
