"""tools/finding_dedup.py

Finding Deduplication Engine.

Purpose:
- Deduplicate findings across different tools and scan phases
- Hash-based matching on (type + url + key evidence)
- Merge similar findings into single entries with combined sources
- Prevent inflated finding counts from duplicate detections
"""

from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger("elengenix.dedup")


def _finding_hash(finding: Dict[str, Any]) -> str:
    """Generate a stable hash for a finding based on type + url + key evidence."""
    ftype = finding.get("type", "").lower().strip()
    url = finding.get("url", finding.get("target", "")).lower().strip().rstrip("/")

    # Include key evidence fields that differentiate findings
    evidence_parts = []
    for key in ["param", "payload", "endpoint", "path", "template", "cwe"]:
        val = finding.get(key, "")
        if val:
            evidence_parts.append(f"{key}={str(val).lower().strip()}")

    evidence_str = "|".join(sorted(evidence_parts))
    raw = f"{ftype}::{url}::{evidence_str}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


@dataclass
class DedupResult:
    """Result of deduplication."""
    unique_findings: List[Dict[str, Any]]
    duplicates_removed: int
    merge_count: int


def deduplicate_findings(
    findings: List[Dict[str, Any]],
    merge_sources: bool = True,
) -> DedupResult:
    """
    Remove duplicate findings and optionally merge source info.

    Args:
        findings: Raw list of finding dicts
        merge_sources: If True, merge 'source' and 'tool' from duplicates

    Returns:
        DedupResult with unique findings and stats
    """
    seen: Dict[str, Dict[str, Any]] = {}
    duplicates = 0
    merges = 0

    for finding in findings:
        fhash = _finding_hash(finding)

        if fhash in seen:
            duplicates += 1
            if merge_sources:
                existing = seen[fhash]
                # Merge source info
                sources = set()
                for src in [existing.get("source", ""), finding.get("source", "")]:
                    if src:
                        sources.add(src)
                if sources:
                    existing["source"] = "+".join(sorted(sources))

                # Keep higher severity
                sev_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
                old_sev = sev_order.get(existing.get("severity", "info").lower(), 0)
                new_sev = sev_order.get(finding.get("severity", "info").lower(), 0)
                if new_sev > old_sev:
                    existing["severity"] = finding["severity"]

                # Keep higher confidence
                old_conf = existing.get("confidence", 0)
                new_conf = finding.get("confidence", 0)
                if isinstance(new_conf, (int, float)) and isinstance(old_conf, (int, float)):
                    if new_conf > old_conf:
                        existing["confidence"] = new_conf

                # Merge tool info
                tools = set()
                for tool in [existing.get("tool", ""), finding.get("tool", "")]:
                    if tool:
                        tools.add(tool)
                if tools:
                    existing["tool"] = "+".join(sorted(tools))

                merges += 1
        else:
            seen[fhash] = dict(finding)  # shallow copy

    return DedupResult(
        unique_findings=list(seen.values()),
        duplicates_removed=duplicates,
        merge_count=merges,
    )


def deduplicate_in_place(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Convenience: deduplicate and return unique list."""
    result = deduplicate_findings(findings)
    if result.duplicates_removed > 0:
        logger.info(f"Dedup: removed {result.duplicates_removed} duplicates, merged {result.merge_count}")
    return result.unique_findings
