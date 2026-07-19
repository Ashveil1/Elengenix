"""Tests for tools/vuln_knowledge.py — vulnerability knowledge base."""

from __future__ import annotations

import pytest

from tools.vuln_knowledge import VulnerabilityKnowledge


@pytest.fixture
def kb():
    return VulnerabilityKnowledge()


class TestOwaspTop10:
    def test_returns_10_items(self, kb):
        result = kb.get_owasp_top_10()
        assert len(result) == 10

    def test_returns_copy_not_reference(self, kb):
        a = kb.get_owasp_top_10()
        b = kb.get_owasp_top_10()
        assert a == b
        a.append("X")
        assert b[-1] != "X"

    def test_includes_ssrf(self, kb):
        result = kb.get_owasp_top_10()
        assert any("SSRF" in item for item in result)


class TestCommonCwes:
    def test_returns_all_when_no_category(self, kb):
        result = kb.get_common_cwes()
        assert isinstance(result, list)
        assert len(result) > 0

    def test_filter_by_category(self, kb):
        injection = kb.get_common_cwes(category="injection")
        assert "CWE-89: SQL Injection" in injection
        assert "CWE-79: Cross-site Scripting (XSS)" in injection

    def test_unknown_category_returns_empty(self, kb):
        result = kb.get_common_cwes(category="nonexistent")
        assert result == []

    def test_returns_copy(self, kb):
        a = kb.get_common_cwes(category="injection")
        a.append("X")
        b = kb.get_common_cwes(category="injection")
        assert "X" not in b


class TestTechVulns:
    def test_php_returns_vulns(self, kb):
        result = kb.get_tech_vulns("php")
        assert isinstance(result, list)
        assert len(result) > 0
        assert any("PHP" in v for v in result)

    def test_case_insensitive(self, kb):
        assert kb.get_tech_vulns("PHP") == kb.get_tech_vulns("php")

    def test_unknown_tech_returns_empty(self, kb):
        assert kb.get_tech_vulns("nonexistent_tech") == []

    def test_returns_copy(self, kb):
        a = kb.get_tech_vulns("php")
        a.append("INJECTED")
        b = kb.get_tech_vulns("php")
        assert "INJECTED" not in b

    def test_has_multiple_tech_entries(self, kb):
        # Sanity check: knowledge base has broad tech coverage
        assert len(kb.TECH_VULNS) >= 10


class TestVulnClasses:
    def test_returns_list(self, kb):
        result = kb.get_vuln_classes()
        assert isinstance(result, list)
        assert len(result) > 0

    def test_includes_core_classes(self, kb):
        result = kb.get_vuln_classes()
        for cls in ("sqli", "xss", "ssrf", "rce"):
            assert cls in result

    def test_returns_copy(self, kb):
        a = kb.get_vuln_classes()
        a.append("injected")
        b = kb.get_vuln_classes()
        assert "injected" not in b


class TestGetRelevantVulns:
    def test_returns_dict_with_expected_keys(self, kb):
        result = kb.get_relevant_vulns(["php", "mysql"])
        assert "owasp" in result
        assert "tech_specific" in result
        assert "relevant_cwes" in result

    def test_tech_specific_aggregates_across_stack(self, kb):
        result = kb.get_relevant_vulns(["php", "mysql"])
        # Should include vulns from both php and mysql
        assert any("PHP" in v for v in result["tech_specific"])
        assert any("SQL" in v or "MySQL" in v for v in result["tech_specific"])

    def test_injection_cwes_added_for_php(self, kb):
        result = kb.get_relevant_vulns(["php"])
        assert len(result["relevant_cwes"]) > 0
        assert "CWE-89: SQL Injection" in result["relevant_cwes"]

    def test_empty_stack_returns_owasp_only(self, kb):
        result = kb.get_relevant_vulns([])
        assert len(result["owasp"]) == 10
        assert result["tech_specific"] == []
