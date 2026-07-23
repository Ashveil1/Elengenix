"""benchmark/grading.py — Benchmark grading & metrics.

Compares Elengenix's reported findings against the known ground-truth
vulnerabilities in tests/vulnerable_target/app.py and computes:
  - Precision  = TP / (TP + FP)
  - Recall     = TP / (total known vulns)
  - F1         = harmonic mean of precision & recall
  - False positives / negatives
  - Time to first finding
  - Steps taken

A "true positive" is a reported finding whose (vuln_class, endpoint)
matches a known ground-truth vuln. Matching is fuzzy on vuln_class
synonyms (e.g. "sqli" == "sql_injection" == "SQL Injection") so the
grader is robust to how the agent phrases its findings.

Public API
----------
    from benchmark.grading import BenchmarkGrader, GROUND_TRUTH

    grader = BenchmarkGrader(GROUND_TRUTH)
    result = grader.grade(reported_findings)
    print(result.summary())
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger("elengenix.benchmark.grading")


# ---------------------------------------------------------------------------#
# Ground truth — the 10 known vulnerabilities in tests/vulnerable_target/app.py
# ---------------------------------------------------------------------------#

# Each entry: (vuln_class, endpoint, description)
# vuln_class uses the canonical short name; synonyms are resolved below.
GROUND_TRUTH: List[Dict[str, str]] = [
    {"vuln_class": "sqli", "endpoint": "/login", "description": "SQL Injection in login form"},
    {"vuln_class": "xss", "endpoint": "/search", "description": "Reflected XSS in search"},
    {"vuln_class": "xss", "endpoint": "/comments", "description": "Stored XSS in comments"},
    {"vuln_class": "idor", "endpoint": "/api/user/", "description": "IDOR/BOLA on user profile"},
    {"vuln_class": "mass_assignment", "endpoint": "/register", "description": "Mass assignment role=admin"},
    {"vuln_class": "ssti", "endpoint": "/render", "description": "Server-Side Template Injection"},
    {"vuln_class": "jwt_none", "endpoint": "/api/jwt/verify", "description": "JWT alg=none bypass"},
    {"vuln_class": "prototype_pollution", "endpoint": "/api/merge", "description": "Prototype pollution via JSON merge"},
    {"vuln_class": "race_condition", "endpoint": "/api/coupon/redeem", "description": "Race condition in coupon redemption"},
    {"vuln_class": "path_traversal", "endpoint": "/download", "description": "Path traversal in file download"},
]


# ---------------------------------------------------------------------------#
# Vuln-class synonym resolution
# ---------------------------------------------------------------------------#

# Map all the ways the agent might phrase a vuln class to a canonical key.
# This makes grading robust to wording differences.
_VULN_CLASS_SYNONYMS: Dict[str, str] = {}
_CANONICAL_KEYS = [
    ("sqli", ["sqli", "sql_injection", "sql injection", "sql", "injection_sql"]),
    ("xss", ["xss", "cross_site_scripting", "cross-site scripting", "cross site scripting", "stored xss", "reflected xss"]),
    ("idor", ["idor", "bola", "broken_access_control", "broken object level auth", "insecure direct object reference"]),
    ("mass_assignment", ["mass_assignment", "mass assignment", "mass-assignment", "auto-binding", "autobinding"]),
    ("ssti", ["ssti", "server_side_template_injection", "server-side template injection", "template injection"]),
    ("jwt_none", ["jwt_none", "jwt none", "jwt alg=none", "jwt bypass", "none algorithm", "jwt alg none"]),
    ("prototype_pollution", ["prototype_pollution", "prototype pollution", "proto pollution"]),
    ("race_condition", ["race_condition", "race condition", "race", "toctou", "concurrency"]),
    ("path_traversal", ["path_traversal", "path traversal", "lfi", "local file inclusion", "directory traversal", "traversal"]),
    ("rce", ["rce", "remote_code_execution", "remote code execution", "command injection", "cmd injection"]),
    ("ssrf", ["ssrf", "server_side_request_forgery", "server-side request forgery"]),
    ("open_redirect", ["open_redirect", "open redirect", "redirect"]),
    ("xxe", ["xxe", "xml_external_entity", "xml external entity"]),
]


def _build_synonym_map() -> None:
    for canonical, synonyms in _CANONICAL_KEYS:
        for syn in synonyms:
            _VULN_CLASS_SYNONYMS[syn.lower().strip()] = canonical


_build_synonym_map()


def canonicalize_vuln_class(raw: str) -> str:
    """Normalize a vuln-class string to its canonical short name."""
    if not raw:
        return "unknown"
    key = raw.lower().strip()
    return _VULN_CLASS_SYNONYMS.get(key, key.replace(" ", "_"))


def endpoint_matches(reported: str, truth: str) -> bool:
    """Fuzzy endpoint match — prefix/substring match in either direction."""
    if not reported or not truth:
        return False
    r = reported.lower().strip()
    t = truth.lower().strip()
    # Exact match
    if r == t:
        return True
    # Prefix match (e.g. "/api/user/1" matches truth "/api/user/")
    if r.startswith(t) or t.startswith(r):
        return True
    # Substring match (e.g. "http://host:5555/login" contains "/login")
    return t in r or r in t


# ---------------------------------------------------------------------------#
# Dataclasses
# ---------------------------------------------------------------------------#


@dataclass
class GradedFinding:
    """A single reported finding, graded against ground truth."""
    reported_class: str
    canonical_class: str
    reported_endpoint: str
    matched_truth: Optional[Dict[str, str]] = None
    is_true_positive: bool = False
    severity: str = "unknown"


@dataclass
class BenchmarkResult:
    """Full grading result for one benchmark run."""
    true_positives: List[GradedFinding] = field(default_factory=list)
    false_positives: List[GradedFinding] = field(default_factory=list)
    false_negatives: List[Dict[str, str]] = field(default_factory=list)
    total_reported: int = 0
    total_ground_truth: int = 0
    scan_duration_sec: float = 0.0
    time_to_first_finding_sec: float = 0.0
    steps_taken: int = 0

    def precision(self) -> float:
        tp = len(self.true_positives)
        fp = len(self.false_positives)
        denom = tp + fp
        return tp / denom if denom > 0 else 0.0

    def recall(self) -> float:
        tp = len(self.true_positives)
        return tp / self.total_ground_truth if self.total_ground_truth > 0 else 0.0

    def f1(self) -> float:
        p, r = self.precision(), self.recall()
        return 2 * p * r / (p + r) if (p + r) > 0 else 0.0

    def summary(self) -> str:
        lines = [
            "═══ BENCHMARK RESULT ═══",
            f"Precision:  {self.precision():.1%} ({len(self.true_positives)} TP / {self.total_reported} reported)",
            f"Recall:     {self.recall():.1%} ({len(self.true_positives)} TP / {self.total_ground_truth} known)",
            f"F1 Score:   {self.f1():.1%}",
            f"False Positives: {len(self.false_positives)}",
            f"False Negatives: {len(self.false_negatives)} (missed vulns)",
            f"Scan duration:   {self.scan_duration_sec:.1f}s",
            f"Time to 1st finding: {self.time_to_first_finding_sec:.1f}s",
            f"Steps taken: {self.steps_taken}",
        ]
        if self.false_negatives:
            lines.append("\nMISSED VULNERABILITIES:")
            for fn in self.false_negatives:
                lines.append(f"  - {fn['vuln_class']} at {fn['endpoint']}: {fn['description']}")
        if self.false_positives:
            lines.append("\nFALSE POSITIVES:")
            for fp in self.false_positives:
                lines.append(f"  - {fp.canonical_class} at {fp.reported_endpoint}")
        return "\n".join(lines)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "precision": self.precision(),
            "recall": self.recall(),
            "f1": self.f1(),
            "true_positives": len(self.true_positives),
            "false_positives": len(self.false_positives),
            "false_negatives": len(self.false_negatives),
            "total_reported": self.total_reported,
            "total_ground_truth": self.total_ground_truth,
            "scan_duration_sec": self.scan_duration_sec,
            "time_to_first_finding_sec": self.time_to_first_finding_sec,
            "steps_taken": self.steps_taken,
            "missed": self.false_negatives,
        }


# ---------------------------------------------------------------------------#
# Grader
# ---------------------------------------------------------------------------#


class BenchmarkGrader:
    """Grade reported findings against a ground-truth vuln set.

    Args:
        ground_truth: List of {vuln_class, endpoint, description} dicts.
    """

    def __init__(self, ground_truth: List[Dict[str, str]]):
        self.ground_truth = ground_truth
        # Pre-canonicalize ground truth for fast lookup
        self._gt_canonical: List[Tuple[str, str, Dict[str, str]]] = [
            (canonicalize_vuln_class(g["vuln_class"]), g["endpoint"], g)
            for g in ground_truth
        ]

    def grade(
        self,
        reported_findings: List[Dict[str, Any]],
        scan_duration_sec: float = 0.0,
        time_to_first_finding_sec: float = 0.0,
        steps_taken: int = 0,
    ) -> BenchmarkResult:
        """Grade a list of reported findings against ground truth.

        Args:
            reported_findings: Findings reported by the agent/scanner.
                Each should have 'type'/'vuln_class' and 'url'/'endpoint'.
            scan_duration_sec: Total scan wall-clock time.
            time_to_first_finding_sec: Time until the first TP was found.
            steps_taken: Number of agent steps executed.

        Returns:
            BenchmarkResult with full metrics.
        """
        result = BenchmarkResult(
            total_reported=len(reported_findings),
            total_ground_truth=len(self.ground_truth),
            scan_duration_sec=scan_duration_sec,
            time_to_first_finding_sec=time_to_first_finding_sec,
            steps_taken=steps_taken,
        )

        matched_truth_indices: Set[int] = set()

        for finding in reported_findings:
            raw_class = (
                finding.get("type")
                or finding.get("vuln_class")
                or finding.get("vulnerability_class")
                or "unknown"
            )
            canonical = canonicalize_vuln_class(str(raw_class))
            reported_endpoint = (
                finding.get("url")
                or finding.get("endpoint")
                or finding.get("target_endpoint")
                or ""
            )
            severity = finding.get("severity", "unknown")

            graded = GradedFinding(
                reported_class=str(raw_class),
                canonical_class=canonical,
                reported_endpoint=str(reported_endpoint),
                severity=str(severity),
            )

            # Try to match against ground truth
            matched = False
            for i, (gt_class, gt_endpoint, gt_dict) in enumerate(self._gt_canonical):
                if i in matched_truth_indices:
                    continue
                if canonical == gt_class and endpoint_matches(str(reported_endpoint), gt_endpoint):
                    graded.matched_truth = gt_dict
                    graded.is_true_positive = True
                    matched_truth_indices.add(i)
                    matched = True
                    break

            if matched:
                result.true_positives.append(graded)
            else:
                result.false_positives.append(graded)

        # False negatives = ground truth items that were never matched
        for i, (gt_class, gt_endpoint, gt_dict) in enumerate(self._gt_canonical):
            if i not in matched_truth_indices:
                result.false_negatives.append(gt_dict)

        return result
