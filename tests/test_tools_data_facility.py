"""Tests for tools/data_facility.py — LLM empowerment data facility."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from tools.data_facility import DataFacility


@pytest.fixture
def facility():
    return DataFacility()


class TestLazyProperties:
    def test_learning_engine_lazy_load(self, facility):
        with patch("tools.learning_engine.LearningEngine") as mock_cls:
            mock_cls.return_value = "fake_engine"
            # First access loads
            result = facility.learning_engine
            assert result == "fake_engine"
            mock_cls.assert_called_once()
            # Second access uses cache
            facility.learning_engine
            assert mock_cls.call_count == 1

    def test_vuln_knowledge_lazy_load(self, facility):
        with patch("tools.vuln_knowledge.VulnerabilityKnowledge") as mock_cls:
            mock_cls.return_value = "fake_kb"
            result = facility.vuln_knowledge
            assert result == "fake_kb"
            mock_cls.assert_called_once()

    def test_tool_recommender_lazy_load(self, facility):
        with patch("tools.tool_recommender.ToolRecommender") as mock_cls:
            mock_cls.return_value = "fake_rec"
            result = facility.tool_recommender
            assert result == "fake_rec"
            mock_cls.assert_called_once()

    def test_learning_engine_handles_import_failure(self, facility):
        with patch("tools.learning_engine.LearningEngine", side_effect=ImportError("nope")):
            assert facility.learning_engine is None


class TestGetFullContext:
    def test_returns_dict_with_expected_structure(self, facility):
        result = facility.get_full_context(target="https://example.com")
        assert isinstance(result, dict)
        assert result["target"] == "https://example.com"
        assert "data_sections" in result
        sections = result["data_sections"]
        assert "past_knowledge" in sections
        assert "tool_recommendations" in sections
        assert "vuln_knowledge" in sections
        assert "payload_suggestions" in sections
        assert "target_summary" in sections

    def test_passes_tech_stack_through(self, facility):
        result = facility.get_full_context(target="example.com", tech_stack=["php", "mysql"])
        assert result["target"] == "example.com"


class TestGetPromptContext:
    def test_returns_formatted_string(self, facility):
        result = facility.get_prompt_context(target="example.com")
        assert isinstance(result, str)
        assert "AVAILABLE DATA" in result

    def test_includes_no_data_placeholder_when_empty(self, facility):
        # All deps None → no data → placeholder message
        with patch.object(DataFacility, "learning_engine", new_callable=lambda: property(lambda self: None)), \
             patch.object(DataFacility, "tool_recommender", new_callable=lambda: property(lambda self: None)), \
             patch.object(DataFacility, "vuln_knowledge", new_callable=lambda: property(lambda self: None)):
            result = facility.get_prompt_context(target="example.com")
            assert "No additional data available" in result


class TestPastKnowledge:
    def test_handles_missing_learning_engine(self, facility):
        with patch.object(DataFacility, "learning_engine", new_callable=lambda: property(lambda self: None)):
            result = facility._get_past_knowledge("example.com")
            assert result["similar_targets"] == []
            assert result["successful_tools"] == []
            assert result["successful_payloads"] == []

    def test_handles_learning_engine_exception(self, facility):
        mock_engine = MagicMock()
        mock_engine.recall_similar.side_effect = RuntimeError("db error")
        with patch.object(DataFacility, "learning_engine", new_callable=lambda: property(lambda self: mock_engine)):
            result = facility._get_past_knowledge("example.com", tech_stack=["php"])
            # Should not raise; returns empty structure
            assert result["similar_targets"] == []

    def test_aggregates_similar_targets(self, facility):
        mock_engine = MagicMock()
        rec1 = MagicMock(target="a.com", vuln_class="sqli", tool="sqlmap", success=True)
        rec2 = MagicMock(target="b.com", vuln_class="xss", tool="dalfox", success=False)
        mock_engine.recall_similar.return_value = [rec1, rec2]
        mock_engine.rank_tools.return_value = [("sqlmap", 0.85, 10)]
        mock_engine.suggest_payloads.return_value = ["' OR 1=1--"]
        with patch.object(DataFacility, "learning_engine", new_callable=lambda: property(lambda self: mock_engine)):
            result = facility._get_past_knowledge("example.com", tech_stack=["php"])
            assert len(result["similar_targets"]) == 2
            assert result["similar_targets"][0]["target"] == "a.com"
            assert len(result["successful_tools"]) == 1
            assert result["successful_tools"][0]["tool"] == "sqlmap"


class TestVulnKnowledgeSection:
    def test_handles_missing_vuln_knowledge(self, facility):
        with patch.object(DataFacility, "vuln_knowledge", new_callable=lambda: property(lambda self: None)):
            result = facility._get_vuln_knowledge(tech_stack=["php"])
            assert result["owasp_top_10"] == []
            assert result["tech_specific_vulns"] == []

    def test_aggregates_tech_specific_vulns(self, facility):
        mock_kb = MagicMock()
        mock_kb.get_tech_vulns.side_effect = lambda tech: {"php": ["PHP LFI"], "mysql": ["SQLi"]}.get(tech, [])
        mock_kb.get_owasp_top_10.return_value = ["A01:2021"]
        mock_kb.get_common_cwes.return_value = ["CWE-89"]
        with patch.object(DataFacility, "vuln_knowledge", new_callable=lambda: property(lambda self: mock_kb)):
            result = facility._get_vuln_knowledge(tech_stack=["php", "mysql"])
            assert "PHP LFI" in result["tech_specific_vulns"]
            assert "SQLi" in result["tech_specific_vulns"]
            assert result["owasp_top_10"] == ["A01:2021"]


class TestToolRecommendations:
    def test_handles_missing_tool_recommender(self, facility):
        with patch.object(DataFacility, "tool_recommender", new_callable=lambda: property(lambda self: None)):
            result = facility._get_tool_recommendations(tech_stack=["php"])
            assert result["recommended_tools"] == []

    def test_returns_recommendations(self, facility):
        mock_rec = MagicMock()
        mock_rec.recommend.return_value = [{"name": "nuclei", "score": 0.9}]
        with patch.object(DataFacility, "tool_recommender", new_callable=lambda: property(lambda self: mock_rec)):
            result = facility._get_tool_recommendations(tech_stack=["php"])
            assert len(result["recommended_tools"]) == 1
            assert result["recommended_tools"][0]["name"] == "nuclei"


class TestPayloadSuggestions:
    def test_handles_missing_learning_engine(self, facility):
        with patch.object(DataFacility, "learning_engine", new_callable=lambda: property(lambda self: None)):
            result = facility._get_payload_suggestions()
            assert result == {}

    def test_returns_payloads_per_vuln_class(self, facility):
        mock_engine = MagicMock()
        mock_engine.suggest_payloads.return_value = ["' OR 1=1--"]
        with patch.object(DataFacility, "learning_engine", new_callable=lambda: property(lambda self: mock_engine)):
            result = facility._get_payload_suggestions()
            # 6 vuln classes queried (sqli, xss, ssrf, rce, lfi, ssti)
            assert mock_engine.suggest_payloads.call_count == 6
            assert "sqli" in result


class TestTargetSummary:
    def test_returns_default_structure(self, facility):
        result = facility._get_target_summary("example.com")
        assert result["target"] == "example.com"
        assert result["known_endpoints"] == []
        assert result["known_vulns"] == []
        assert result["scan_history"] == []


class TestFormatForPrompt:
    def test_empty_context_yields_placeholder(self, facility):
        empty_context = {
            "target": "x",
            "data_sections": {
                "past_knowledge": {},
                "tool_recommendations": {},
                "vuln_knowledge": {},
                "payload_suggestions": {},
                "target_summary": {},
            },
        }
        result = facility._format_for_prompt(empty_context)
        assert "No additional data available" in result

    def test_includes_tools_section(self, facility):
        ctx = {
            "target": "x",
            "data_sections": {
                "tool_recommendations": {
                    "recommended_tools": [{"name": "nuclei"}],
                },
            },
        }
        result = facility._format_for_prompt(ctx)
        assert "nuclei" in result
        assert "Recommended Tools" in result

    def test_includes_owasp_section(self, facility):
        ctx = {
            "target": "x",
            "data_sections": {
                "vuln_knowledge": {
                    "owasp_top_10": ["A01:2021 - Broken Access Control"],
                },
            },
        }
        result = facility._format_for_prompt(ctx)
        assert "A01:2021" in result
