"""Tests for benchmark/grading.py — benchmark grading & metrics.

Tests the grader against synthetic finding sets with known precision/recall.
The grader is pure logic (no network, no subprocess), so these tests are
fast and deterministic.
"""

from __future__ import annotations

import pytest

from benchmark.grading import (
    GROUND_TRUTH,
    BenchmarkGrader,
    BenchmarkResult,
    GradedFinding,
    canonicalize_vuln_class,
    endpoint_matches,
)


# ===================================================================
# canonicalize_vuln_class
# ===================================================================


class TestCanonicalizeVulnClass:
    def test_canonical_short_name_passes_through(self):
        assert canonicalize_vuln_class("sqli") == "sqli"
        assert canonicalize_vuln_class("xss") == "xss"

    def test_synonyms_resolved(self):
        assert canonicalize_vuln_class("SQL Injection") == "sqli"
        assert canonicalize_vuln_class("sql_injection") == "sqli"
        assert canonicalize_vuln_class("Cross-site Scripting") == "xss"
        assert canonicalize_vuln_class("stored xss") == "xss"
        assert canonicalize_vuln_class("IDOR") == "idor"
        assert canonicalize_vuln_class("BOLA") == "idor"

    def test_case_insensitive(self):
        assert canonicalize_vuln_class("SQLi") == "sqli"
        assert canonicalize_vuln_class("  XSS  ") == "xss"

    def test_unknown_class_preserved_with_underscores(self):
        assert canonicalize_vuln_class("Some Unknown Vuln") == "some_unknown_vuln"

    def test_empty_returns_unknown(self):
        assert canonicalize_vuln_class("") == "unknown"
        assert canonicalize_vuln_class(None) == "unknown"


# ===================================================================
# endpoint_matches
# ===================================================================


class TestEndpointMatches:
    def test_exact_match(self):
        assert endpoint_matches("/login", "/login") is True

    def test_prefix_match(self):
        assert endpoint_matches("/api/user/1", "/api/user/") is True
        assert endpoint_matches("/api/user/", "/api/user/1") is True

    def test_substring_match(self):
        assert endpoint_matches("http://host:5555/login", "/login") is True
        assert endpoint_matches("/login", "http://host:5555/login") is True

    def test_no_match(self):
        assert endpoint_matches("/admin", "/login") is False

    def test_empty_returns_false(self):
        assert endpoint_matches("", "/login") is False
        assert endpoint_matches("/login", "") is False


# ===================================================================
# BenchmarkGrader — perfect detection
# ===================================================================


class TestGraderPerfectDetection:
    @pytest.fixture
    def grader(self):
        return BenchmarkGrader(GROUND_TRUTH)

    def test_all_vulns_found_perfect_score(self, grader):
        """If the agent reports all 10 ground-truth vulns correctly,
        precision=100%, recall=100%, F1=100%."""
        findings = [
            {"type": "sqli", "url": "/login"},
            {"type": "xss", "url": "/search"},
            {"type": "xss", "url": "/comments"},
            {"type": "idor", "url": "/api/user/1"},
            {"type": "mass_assignment", "url": "/register"},
            {"type": "ssti", "url": "/render"},
            {"type": "jwt_none", "url": "/api/jwt/verify"},
            {"type": "prototype_pollution", "url": "/api/merge"},
            {"type": "race_condition", "url": "/api/coupon/redeem"},
            {"type": "path_traversal", "url": "/download"},
        ]
        result = grader.grade(findings)
        assert result.precision() == 1.0
        assert result.recall() == 1.0
        assert result.f1() == 1.0
        assert len(result.true_positives) == 10
        assert len(result.false_positives) == 0
        assert len(result.false_negatives) == 0


# ===================================================================
# BenchmarkGrader — partial detection
# ===================================================================


class TestGraderPartialDetection:
    @pytest.fixture
    def grader(self):
        return BenchmarkGrader(GROUND_TRUTH)

    def test_half_found(self, grader):
        """Find 5 of 10 → recall=50%."""
        findings = [
            {"type": "sqli", "url": "/login"},
            {"type": "xss", "url": "/search"},
            {"type": "idor", "url": "/api/user/1"},
            {"type": "ssti", "url": "/render"},
            {"type": "path_traversal", "url": "/download"},
        ]
        result = grader.grade(findings)
        assert result.recall() == 0.5
        assert len(result.true_positives) == 5
        assert len(result.false_negatives) == 5

    def test_false_positives_lower_precision(self, grader):
        """5 TP + 5 FP → precision=50%, recall=50%."""
        findings = [
            {"type": "sqli", "url": "/login"},
            {"type": "xss", "url": "/search"},
            {"type": "idor", "url": "/api/user/1"},
            {"type": "ssti", "url": "/render"},
            {"type": "path_traversal", "url": "/download"},
            # False positives:
            {"type": "rce", "url": "/nonexistent"},
            {"type": "ssrf", "url": "/fake"},
            {"type": "xxe", "url": "/imaginary"},
            {"type": "rce", "url": "/nope"},
            {"type": "open_redirect", "url": "/ghost"},
        ]
        result = grader.grade(findings)
        assert result.precision() == 0.5
        assert result.recall() == 0.5
        assert len(result.false_positives) == 5

    def test_synonym_matching_works(self, grader):
        """Agent uses different wording — still counts as TP."""
        findings = [
            {"type": "SQL Injection", "url": "/login"},
            {"type": "Cross-site Scripting", "url": "/search"},
        ]
        result = grader.grade(findings)
        assert len(result.true_positives) == 2
        assert result.recall() == 0.2  # 2/10

    def test_endpoint_with_full_url_matches(self, grader):
        """Agent reports full URL with host:port — still matches."""
        findings = [
            {"type": "sqli", "url": "http://127.0.0.1:5555/login"},
        ]
        result = grader.grade(findings)
        assert len(result.true_positives) == 1


# ===================================================================
# BenchmarkGrader — edge cases
# ===================================================================


class TestGraderEdgeCases:
    @pytest.fixture
    def grader(self):
        return BenchmarkGrader(GROUND_TRUTH)

    def test_empty_findings_zero_recall(self, grader):
        result = grader.grade([])
        assert result.recall() == 0.0
        assert result.precision() == 0.0
        assert len(result.false_negatives) == 10

    def test_duplicate_findings_dont_double_count(self, grader):
        """Reporting the same vuln twice = 1 TP + 1 FP (not 2 TP)."""
        findings = [
            {"type": "sqli", "url": "/login"},
            {"type": "sqli", "url": "/login"},
        ]
        result = grader.grade(findings)
        assert len(result.true_positives) == 1
        assert len(result.false_positives) == 1

    def test_unknown_vuln_class_is_false_positive(self, grader):
        findings = [{"type": "some_unknown_vuln", "url": "/whatever"}]
        result = grader.grade(findings)
        assert len(result.false_positives) == 1
        assert len(result.true_positives) == 0


# ===================================================================
# BenchmarkResult — metrics & summary
# ===================================================================


class TestBenchmarkResult:
    def test_precision_recall_f1_zero_on_empty(self):
        r = BenchmarkResult()
        assert r.precision() == 0.0
        assert r.recall() == 0.0
        assert r.f1() == 0.0

    def test_f1_harmonic_mean(self):
        r = BenchmarkResult(total_ground_truth=10)
        r.true_positives = [GradedFinding("a", "a", "/x")] * 5
        r.false_positives = [GradedFinding("b", "b", "/y")] * 5
        # precision = 5/10 = 0.5, recall = 5/10 = 0.5
        # F1 = 2*0.5*0.5/(0.5+0.5) = 0.5
        assert r.precision() == 0.5
        assert r.recall() == 0.5
        assert r.f1() == 0.5

    def test_summary_includes_metrics(self):
        r = BenchmarkResult(total_ground_truth=10, scan_duration_sec=42.5, steps_taken=15)
        r.true_positives = [GradedFinding("sqli", "sqli", "/login")]
        r.false_negatives = [{"vuln_class": "xss", "endpoint": "/search", "description": "XSS"}]
        summary = r.summary()
        assert "Precision" in summary
        assert "Recall" in summary
        assert "F1" in summary
        assert "MISSED VULNERABILITIES" in summary
        assert "xss" in summary.lower()

    def test_to_dict_returns_all_fields(self):
        r = BenchmarkResult(
            total_ground_truth=10, scan_duration_sec=10.0,
            time_to_first_finding_sec=2.0, steps_taken=5,
        )
        d = r.to_dict()
        assert "precision" in d
        assert "recall" in d
        assert "f1" in d
        assert "missed" in d
        assert d["steps_taken"] == 5
        assert d["scan_duration_sec"] == 10.0

    def test_to_dict_backward_compat_keys_present(self):
        """Legacy consumers rely on these exact keys — they must not move."""
        d = BenchmarkResult().to_dict()
        legacy_keys = {
            "precision", "recall", "f1", "true_positives", "false_positives",
            "false_negatives", "total_reported", "total_ground_truth",
            "scan_duration_sec", "time_to_first_finding_sec", "steps_taken",
            "error", "missed",
        }
        assert legacy_keys.issubset(d.keys())

    def test_to_dict_includes_additive_impact_keys(self):
        d = BenchmarkResult().to_dict()
        assert "impact_proven" in d
        assert "impact_rate" in d
        # New keys default safely for runs graded without a flag.
        assert d["impact_proven"] == []
        assert d["impact_rate"] == 0.0


# ===================================================================
# Impact (FLAG) metrics — additive, flag-eligible classes only
# ===================================================================


class TestImpactMetrics:
    """Per-run FLAG planted by the runner proves exploitation when it appears
    verbatim in a finding's evidence. Only sqli / ssti / path_traversal count
    toward the impact_rate denominator (3 classes)."""

    FLAG = "ELENGENIX-FLAG-testvalue123"
    ELIGIBLE = 3  # sqli + ssti + path_traversal

    @pytest.fixture
    def grader(self):
        return BenchmarkGrader(GROUND_TRUTH)

    def _findings_with_flag(self, *specs):
        """specs: (vuln_class, url, include_flag)."""
        return [
            {
                "type": vc,
                "url": url,
                "evidence": (
                    f"extracted {self.FLAG} successfully" if inc else "detected, no proof"
                ),
            }
            for vc, url, inc in specs
        ]

    def test_no_flag_no_impact(self, grader):
        findings = [{"type": "sqli", "url": "/login", "evidence": self.FLAG}]
        r = grader.grade(findings)  # flag not supplied
        assert r.impact_proven == []
        assert r.impact_rate == 0.0

    def test_flag_in_sqli_evidence_proves_impact(self, grader):
        r = grader.grade(
            self._findings_with_flag(("sqli", "/login", True)), flag=self.FLAG
        )
        assert r.impact_proven == ["sqli"]
        assert r.impact_rate == pytest.approx(1 / self.ELIGIBLE)

    def test_flag_absent_from_evidence_no_impact(self, grader):
        r = grader.grade(
            self._findings_with_flag(
                ("sqli", "/login", False), ("ssti", "/render", False)
            ),
            flag=self.FLAG,
        )
        assert r.impact_proven == []
        assert r.impact_rate == 0.0

    def test_all_three_eligible_classes_give_full_impact(self, grader):
        r = grader.grade(
            self._findings_with_flag(
                ("sqli", "/login", True),
                ("ssti", "/render", True),
                ("path_traversal", "/download", True),
            ),
            flag=self.FLAG,
        )
        assert set(r.impact_proven) == {"sqli", "ssti", "path_traversal"}
        assert r.impact_rate == pytest.approx(1.0)

    def test_non_eligible_class_with_flag_not_counted(self, grader):
        """xss carrying the flag string is NOT impact-eligible — must not
        inflate impact_proven / impact_rate."""
        r = grader.grade(
            self._findings_with_flag(("xss", "/search", True)), flag=self.FLAG
        )
        assert r.impact_proven == []
        assert r.impact_rate == 0.0

    def test_flag_in_evidence_but_wrong_class_no_impact(self, grader):
        # lfi→path_traversal is eligible, jwt is not.
        r = grader.grade(
            self._findings_with_flag(("jwt_none", "/api/jwt/verify", True)),
            flag=self.FLAG,
        )
        assert r.impact_proven == []

    def test_impact_does_not_change_precision_recall_f1(self, grader):
        findings = self._findings_with_flag(("sqli", "/login", True))
        plain = grader.grade(findings)
        flagged = grader.grade(findings, flag=self.FLAG)
        assert plain.precision() == flagged.precision()
        assert plain.recall() == flagged.recall()
        assert plain.f1() == flagged.f1()
        assert flagged.impact_proven == ["sqli"]

    def test_impact_proven_serialized(self, grader):
        r = grader.grade(
            self._findings_with_flag(("ssti", "/render", True)), flag=self.FLAG
        )
        d = r.to_dict()
        assert d["impact_proven"] == ["ssti"]
        assert d["impact_rate"] == pytest.approx(1 / self.ELIGIBLE)

    def test_error_run_still_serializes_impact_fields(self, grader):
        r = grader.grade([], error="no AI key", flag=self.FLAG)
        d = r.to_dict()
        assert d["impact_proven"] == []
        assert d["impact_rate"] == 0.0
        assert "Impact proven" not in r.summary()  # error path has its own summary

    def test_flag_eligible_mapping_declared_in_one_place(self):
        from benchmark import grading

        assert grading.FLAG_ELIGIBLE_CLASSES == {"sqli", "ssti", "path_traversal"}
        assert grading.flag_eligible_ground_truth_count(grading.GROUND_TRUTH) == 3


# ===================================================================
# Ground truth integrity
# ===================================================================


class TestGroundTruth:
    def test_has_10_vulns(self):
        assert len(GROUND_TRUTH) == 10

    def test_each_entry_has_required_fields(self):
        for entry in GROUND_TRUTH:
            assert "vuln_class" in entry
            assert "endpoint" in entry
            assert "description" in entry

    def test_covers_expected_vuln_classes(self):
        classes = {e["vuln_class"] for e in GROUND_TRUTH}
        assert "sqli" in classes
        assert "xss" in classes
        assert "idor" in classes
        assert "ssti" in classes
        assert "path_traversal" in classes
