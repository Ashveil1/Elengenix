"""tools/finding_provenance.py

Finding Provenance — deterministic vs agentic classification.

Why this exists:
    A deterministic scanner module (active fuzzer, passive pattern matcher,
    signature check) produces the *same* finding for the *same* input every
    run. An LLM-driven agent that plans its own attack path and writes its
    own probes is the opposite: powerful on a good day, non-deterministic by
    construction, and very hard to regression-test.

    Per the Vigolium/diviner critique (Moltbook, 2026-05-29): a finding from
    the deterministic pipeline and a finding from the agent should NEVER sit
    in the same queue without a tag saying which produced it. This module
    makes that tag first-class so the rest of Elengenix (dedup, reporting,
    governance) can treat the two trust classes differently.

Usage:
    from tools.finding_provenance import tag_provenance, Provenance

    finding = tag_provenance(finding, source_hint="ai_reasoning")
    # finding["provenance"] == "agentic"
    # finding["trust_class"]  == "non_deterministic"

The classification is derived from the existing "source"/"tool" field when
present, so legacy findings are auto-classified without code changes上游.
"""

from __future__ import annotations

import logging
from enum import Enum
from typing import Any, Dict, List

logger = logging.getLogger("elengenix.provenance")

# Sources that are driven by an LLM/agent reasoning loop (non-deterministic).
AGENTIC_SOURCES = {
    "ai_reasoning",
    "ai_dynamic",
    "reflection",
    "attack_tree",
    "strategist",
    "specialist",
    "critic",
    "agent",
    "olium",          # Vigolium's agentic runtime — parity reference
    "vuln_reasoning",
    "zero_day_heuristics",
    "autonomous_agent",
}

# Sources that are pure deterministic tooling (reproducible by construction).
DETERMINISTIC_SOURCES = {
    "recon",
    "http_probe",
    "waf_detect",
    "auth_tester",
    "active_fuzzer",
    "passive_matcher",
    "signature",
    "tool_finding",
    "native_scanner",
    "smart_scanner",
    "cve_database",
    "nvd_cve",
}


class Provenance(str, Enum):
    """Trust class of how a finding was produced."""

    DETERMINISTIC = "deterministic"      # reproducible, auditable
    AGENTIC = "agentic"                  # LLM-driven, non-deterministic
    MIXED = "mixed"                      # merged from both classes
    UNKNOWN = "unknown"                  # could not be inferred


# Human-readable trust posture per provenance.
TRUST_CLASS = {
    Provenance.DETERMINISTIC: "reproducible",
    Provenance.AGENTIC: "non_deterministic",
    Provenance.MIXED: "mixed_confidence",
    Provenance.UNKNOWN: "unverified",
}


def _norm(value: Any) -> str:
    return str(value or "").lower().strip()


def infer_provenance(finding: Dict[str, Any]) -> Provenance:
    """Infer provenance from a finding's existing source/tool fields.

    Resolution order:
        1. Explicit ``provenance`` already set on the finding.
        2. ``source`` field (may be a ``+``-joined merge of multiple).
        3. ``tool`` field.
        4. ``discovered_by`` field.
    """
    explicit = finding.get("provenance")
    if isinstance(explicit, Provenance):
        return explicit
    if explicit in {p.value for p in Provenance}:
        return Provenance(explicit)

    candidates: List[str] = []
    for field_name in ("source", "tool", "discovered_by"):
        raw = finding.get(field_name, "")
        if isinstance(raw, str) and raw:
            # source may be "ai_reasoning+auth_tester" after a dedup merge
            candidates.extend(part for part in raw.split("+") if part)

    has_agentic = any(c in AGENTIC_SOURCES for c in candidates)
    has_det = any(c in DETERMINISTIC_SOURCES for c in candidates)

    if has_agentic and has_det:
        return Provenance.MIXED
    if has_agentic:
        return Provenance.AGENTIC
    if has_det:
        return Provenance.DETERMINISTIC
    return Provenance.UNKNOWN


def tag_provenance(finding: Dict[str, Any], source_hint: str | None = None) -> Dict[str, Any]:
    """Annotate a finding dict with provenance + trust_class in place.

    Args:
        finding: The finding dict to annotate.
        source_hint: Optional explicit source to record before inferring
            (e.g. "ai_reasoning" when the agent loop emits a finding).

    Returns:
        The same dict, annotated.
    """
    if source_hint:
        existing = finding.get("source", "")
        parts = [p for p in existing.split("+") if p] if existing else []
        if source_hint not in parts:
            parts.append(source_hint)
        finding["source"] = "+".join(parts)

    prov = infer_provenance(finding)
    finding["provenance"] = prov.value
    finding["trust_class"] = TRUST_CLASS[prov]
    return finding


def is_reproducible(finding: Dict[str, Any]) -> bool:
    """True only for findings safe to put in a regression-test queue."""
    prov = infer_provenance(finding)
    if prov is Provenance.DETERMINISTIC:
        return True
    if prov is Provenance.AGENTIC:
        # An agentic finding with high reproducibility score may still be
        # promoted, but it is never auto-trusted the way deterministic is.
        return float(finding.get("reproducibility", 0.0)) >= 0.8
    return False
