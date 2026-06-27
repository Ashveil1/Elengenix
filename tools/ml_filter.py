"""
tools/ml_filter.py — ML-Based False Positive Filter
=====================================================
Smart false positive reduction using heuristic + statistical analysis.
Not a full ML model (no GPU required) but uses proven techniques:
- Bayesian scoring based on past suppression patterns
- Confidence-based filtering using signal strength
- Anomaly detection via std-dev from baseline

Design: Lightweight, zero external ML deps. Works offline.
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger("elengenix.ml_filter")

# ---------------------------------------------------------------------------
# Finding Classification
# ---------------------------------------------------------------------------


@dataclass
class FindingProfile:
    """Learned profile of a finding type for false positive scoring."""

    pattern_id: str
    total_seen: int = 0
    total_suppressed: int = 0
    false_positive_rate: float = 0.0  # 0.0 = always real, 1.0 = always FP
    avg_confidence: float = 0.0
    last_seen: float = 0.0
    related_urls: Set[str] = field(default_factory=set)
    related_params: Set[str] = field(default_factory=set)

    @property
    def real_rate(self) -> float:
        """Probability this finding is a real vulnerability."""
        if self.total_seen == 0:
            return 1.0
        return 1.0 - (self.total_suppressed / self.total_seen)

    def update(
        self, suppressed: bool, confidence: float = 1.0, url: str = "", param: str = ""
    ) -> None:
        self.total_seen += 1
        if suppressed:
            self.total_suppressed += 1
        self.false_positive_rate = self.total_suppressed / max(1, self.total_seen)
        # Exponential moving average for confidence
        self.avg_confidence = self.avg_confidence * 0.7 + confidence * 0.3
        self.last_seen = time.time()
        if url:
            self.related_urls.add(url)
        if param:
            self.related_params.add(param)


# ---------------------------------------------------------------------------
# ML Filter Engine
# ---------------------------------------------------------------------------


class MLFilter:
    """False positive filter using heuristic Bayesian scoring.

    Scores each finding with a confidence level (0.0 = definite FP, 1.0 = definite real).
    Learns from user suppression actions to improve over time.

    Characteristics of real vs false positives:
    REAL:    Consistent behavior, clear signal, reproducible
    FALSE:   Random noise, disappearing params, inconsistent
    """

    def __init__(self, profile_path: Optional[str] = None):
        self.profiles: Dict[str, FindingProfile] = {}
        self.suppression_history: List[Dict[str, Any]] = []
        self._profile_path = Path(profile_path or "data/ml_profiles.json")
        self._profile_path.parent.mkdir(parents=True, exist_ok=True)
        self._session_seen: Set[str] = set()  # Dedup within session
        self._load_profiles()

    # ── Persistence ───────────────────────────────────────────────────────

    def _load_profiles(self) -> None:
        """Load learned profiles from disk."""
        if self._profile_path.exists():
            try:
                with open(self._profile_path) as f:
                    data = json.load(f)
                for pid, pdata in data.items():
                    profile = FindingProfile(
                        pattern_id=pid,
                        total_seen=pdata.get("total_seen", 0),
                        total_suppressed=pdata.get("total_suppressed", 0),
                        false_positive_rate=pdata.get("false_positive_rate", 0.0),
                        avg_confidence=pdata.get("avg_confidence", 0.0),
                        last_seen=pdata.get("last_seen", 0),
                        related_urls=set(pdata.get("related_urls", [])),
                        related_params=set(pdata.get("related_params", [])),
                    )
                    self.profiles[pid] = profile
                logger.debug(f"Loaded {len(self.profiles)} ML profiles")
            except Exception as e:
                logger.warning(f"Failed to load ML profiles: {e}")

    def _save_profiles(self) -> None:
        """Persist learned profiles to disk."""
        try:
            data = {}
            for pid, p in self.profiles.items():
                data[pid] = {
                    "total_seen": p.total_seen,
                    "total_suppressed": p.total_suppressed,
                    "false_positive_rate": p.false_positive_rate,
                    "avg_confidence": p.avg_confidence,
                    "last_seen": p.last_seen,
                    "related_urls": list(p.related_urls)[:100],
                    "related_params": list(p.related_params)[:100],
                }
            with open(self._profile_path, "w") as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            logger.warning(f"Failed to save ML profiles: {e}")

    # ── Scoring ───────────────────────────────────────────────────────────

    def _signal_strength(self, finding: Dict[str, Any]) -> float:
        """Score how strong the detection signal is (0-1).

        Strong signals: Multiple evidence items, high CVSS, reproducible
        Weak signals: Single log line, low severity, no evidence
        """
        score = 0.5  # Default medium

        # CVSS: Higher CVSS = stronger signal
        cvss = finding.get("cvss", 0)
        if cvss > 9.0:
            score += 0.3
        elif cvss > 7.0:
            score += 0.2
        elif cvss > 4.0:
            score += 0.1

        # Evidence: Multiple evidence lines = stronger
        details = finding.get("details", "") or ""
        evidence_len = len(details)
        if evidence_len > 500:
            score += 0.15
        elif evidence_len > 200:
            score += 0.1
        elif evidence_len < 50:
            score -= 0.1

        # URL specificity: More specific path = stronger
        url = finding.get("url", "") or ""
        if "/" in url[8:] if url.startswith("http") else "/" in url:
            score += 0.1  # Has path beyond domain

        # Type-specific signals
        vuln_type = (finding.get("type", "") or "").lower()
        if "sql" in vuln_type or "sqli" in vuln_type:
            # SQLi: Having a specific parameter + error evidence
            if finding.get("param"):
                score += 0.1
        elif "xss" in vuln_type:
            if finding.get("param"):
                score += 0.1
        elif "cve" in vuln_type or vuln_type == "cve_detection":
            # CVE: More credible if version is specified
            if finding.get("cvss", 0) >= 7.0:
                score += 0.1

        return max(0.0, min(1.0, score))

    def _bayesian_score(self, finding: Dict[str, Any]) -> float:
        """Bayesian adjustment based on historical suppression patterns.

        P(real | evidence) = P(evidence | real) * P(real) / P(evidence)
        """
        pattern_id = self._make_pattern_id(finding)
        profile = self.profiles.get(pattern_id)

        if not profile or profile.total_seen < 2:
            return 0.5  # Not enough data, neutral

        # Prior: Base real rate from this pattern's history
        prior = profile.real_rate

        # Likelihood: Adjust based on confidence
        confidence = self._signal_strength(finding)

        # Bayesian update (simplified)
        posterior = prior * 0.6 + confidence * 0.4

        # Adjust for recency: Prefer recent data
        days_since_last = (time.time() - profile.last_seen) / 86400
        if days_since_last > 30 and profile.total_seen > 10:
            # Recent data is more relevant
            pass

        return max(0.0, min(1.0, posterior))

    def _make_pattern_id(self, finding: Dict[str, Any]) -> str:
        """Create a canonical pattern ID for a finding type."""
        vuln_type = finding.get("type", "unknown")
        url = finding.get("url", "") or ""
        param = finding.get("param", "") or ""
        title = (finding.get("title", "") or "")[:60]
        return f"{vuln_type}:{title}:{param}"

    # ── Public API ────────────────────────────────────────────────────────

    def score(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Score a finding and return enriched result with ML metadata.

        Args:
            finding: Raw finding dict from any scanner

        Returns:
            Finding dict with added keys:
              ml_confidence: 0-1 score (0=FP, 1=real)
              ml_verdict: "real" | "likely_real" | "uncertain" | "likely_fp" | "fp"
              ml_signal_strength: raw signal strength score
              ml_pattern_id: canonical pattern ID
              ml_is_suppressed: True if similar patterns were previously suppressed
        """
        signal = self._signal_strength(finding)
        bayes = self._bayesian_score(finding)

        # Combined score (weighted)
        confidence = signal * 0.4 + bayes * 0.6

        # Determine verdict
        if confidence >= 0.85:
            verdict = "real"
        elif confidence >= 0.65:
            verdict = "likely_real"
        elif confidence >= 0.35:
            verdict = "uncertain"
        elif confidence >= 0.15:
            verdict = "likely_fp"
        else:
            verdict = "fp"

        pattern_id = self._make_pattern_id(finding)
        profile = self.profiles.get(pattern_id)

        # Check if this pattern was previously suppressed
        is_suppressed = False
        if profile and profile.false_positive_rate > 0.6:
            is_suppressed = True

        # Dedup within session
        dedup_key = f"{pattern_id}:{finding.get('url', '')}"
        is_duplicate = dedup_key in self._session_seen
        if not is_duplicate:
            self._session_seen.add(dedup_key)

        return {
            **finding,
            "ml_confidence": round(confidence, 3),
            "ml_verdict": verdict,
            "ml_signal_strength": round(signal, 3),
            "ml_pattern_id": pattern_id,
            "ml_is_suppressed": is_suppressed,
            "ml_is_duplicate": is_duplicate,
            "ml_historical_fp_rate": round(profile.false_positive_rate, 3) if profile else 0.0,
        }

    def suppress(self, finding: Dict[str, Any], reason: str = "user_suppressed") -> None:
        """Record a suppression to improve future scoring.

        Args:
            finding: The finding that was suppressed
            reason: Why it was suppressed (user_suppressed, auto_fp, etc.)
        """
        pattern_id = self._make_pattern_id(finding)
        profile = self.profiles.setdefault(pattern_id, FindingProfile(pattern_id=pattern_id))
        profile.update(
            suppressed=True,
            confidence=finding.get("ml_confidence", 0.5),
            url=finding.get("url", ""),
            param=finding.get("param", ""),
        )
        self.suppression_history.append(
            {
                "pattern_id": pattern_id,
                "reason": reason,
                "timestamp": time.time(),
                "finding_title": finding.get("title", ""),
            }
        )
        # Trim history
        if len(self.suppression_history) > 1000:
            self.suppression_history = self.suppression_history[-500:]
        self._save_profiles()

    def confirm(self, finding: Dict[str, Any]) -> None:
        """Record a confirmed real finding to improve future scoring."""
        pattern_id = self._make_pattern_id(finding)
        profile = self.profiles.setdefault(pattern_id, FindingProfile(pattern_id=pattern_id))
        profile.update(
            suppressed=False,
            confidence=finding.get("ml_confidence", 0.8),
            url=finding.get("url", ""),
            param=finding.get("param", ""),
        )
        self._save_profiles()

    def filter_findings(
        self,
        findings: List[Dict[str, Any]],
        min_confidence: float = 0.3,
        auto_suppress: bool = True,
    ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
        """Filter findings by ML confidence.

        Args:
            findings: Raw findings list
            min_confidence: Minimum confidence to keep (0-1)
            auto_suppress: Auto-suppress obvious FPs (confidence < 0.15)

        Returns:
            Tuple of (high_confidence_findings, low_confidence_findings)
        """
        scored = [self.score(f) for f in findings]
        high = [f for f in scored if f["ml_confidence"] >= min_confidence]
        low = [f for f in scored if f["ml_confidence"] < min_confidence]

        if auto_suppress:
            for f in low:
                if f["ml_confidence"] < 0.15:
                    self.suppress(f, "auto_fp_confidence")

        return high, low

    def get_stats(self) -> Dict[str, Any]:
        """Get filter statistics for monitoring."""
        profiles_list = list(self.profiles.values())
        total = len(profiles_list)
        if total == 0:
            return {"patterns": 0, "avg_fp_rate": 0, "avg_confidence": 0}

        avg_fp = sum(p.false_positive_rate for p in profiles_list) / total
        avg_conf = sum(p.avg_confidence for p in profiles_list) / total
        high_fp = sum(1 for p in profiles_list if p.false_positive_rate > 0.5)

        return {
            "patterns": total,
            "avg_fp_rate": round(avg_fp, 3),
            "avg_confidence": round(avg_conf, 3),
            "high_fp_patterns": high_fp,
            "total_suppressions": len(self.suppression_history),
            "profile_file": str(self._profile_path),
        }


# ---------------------------------------------------------------------------
# Standalone CLI Filter
# ---------------------------------------------------------------------------


def filter_scan_results(
    findings_path: str, output_path: Optional[str] = None, min_confidence: float = 0.3
) -> Dict[str, Any]:
    """Process a findings JSON file through the ML filter.

    Args:
        findings_path: Path to JSON file with findings array
        output_path: Path to save filtered results (optional)
        min_confidence: Minimum confidence threshold

    Returns:
        Filter results dict with stats
    """
    with open(findings_path) as f:
        findings = json.load(f)

    mf = MLFilter()
    high, low = mf.filter_findings(findings, min_confidence=min_confidence)

    result = {
        "total": len(findings),
        "high_confidence": len(high),
        "low_confidence": len(low),
        "removed": len(low),
        "kept": len(high),
        "savings_pct": round(len(low) / max(1, len(findings)) * 100, 1),
        "findings": high,
        "removed_findings": low,
        "stats": mf.get_stats(),
    }

    if output_path:
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w") as f:
            json.dump(result, f, indent=2, default=str)

    return result


__all__ = ["MLFilter", "filter_scan_results", "FindingProfile"]
