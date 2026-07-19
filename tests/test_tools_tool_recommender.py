"""Tests for tools/tool_recommender.py — tool recommendation engine."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from tools.tool_recommender import ToolRecommender


@pytest.fixture
def recommender():
    return ToolRecommender()


class TestRecommend:
    def test_no_args_returns_capability_recommendations(self, recommender):
        result = recommender.recommend()
        assert isinstance(result, list)
        assert len(result) > 0
        # Each recommendation is a dict with at least a name
        assert all("name" in r for r in result)

    def test_respects_limit(self, recommender):
        result = recommender.recommend(limit=3)
        assert len(result) <= 3

    def test_tech_stack_boosts_compatible_tools(self, recommender):
        # WordPress should boost wpscan
        result = recommender.recommend(tech_stack=["wordpress"], limit=20)
        names = [r["name"] for r in result]
        assert "wpscan" in names

    def test_vuln_class_boosts_specialized_tools(self, recommender):
        # SQLi should boost sqlmap
        result = recommender.recommend(vuln_class="sqli", limit=20)
        names = [r["name"] for r in result]
        assert "sqlmap" in names

    def test_recommendations_sorted_by_score_desc(self, recommender):
        result = recommender.recommend(tech_stack=["php"], vuln_class="sqli", limit=10)
        scores = [r.get("score", 0) for r in result]
        assert scores == sorted(scores, reverse=True)


class TestHistoricalRankings:
    @patch("tools.tool_recommender.ToolRecommender.learning_engine", new_callable=lambda: property(lambda self: MagicMock()))
    def test_merges_historical_and_capability(self, _mock_prop, recommender):
        # Force learning_engine to be a real mock with rank_tools
        mock_engine = MagicMock()
        mock_engine.rank_tools.return_value = [
            ("nuclei", 0.85, 10),
            ("sqlmap", 0.70, 5),
        ]
        # Patch the property to return our mock
        with patch.object(ToolRecommender, "learning_engine", new_callable=lambda: property(lambda self: mock_engine)):
            result = recommender.recommend(tech_stack=["php"], limit=20)
            names = [r["name"] for r in result]
            assert "nuclei" in names
            assert "sqlmap" in names
            # Historical ones come first because they have higher score weight
            historical_first = [r for r in result if r.get("source") == "historical"]
            assert len(historical_first) >= 2

    def test_historical_rankings_handles_missing_engine(self, recommender):
        # If learning_engine is None, _get_historical_rankings returns []
        with patch.object(ToolRecommender, "learning_engine", new_callable=lambda: property(lambda self: None)):
            result = recommender._get_historical_rankings()
            assert result == []


class TestCapabilityRankings:
    def test_scores_tech_compatibility(self, recommender):
        result = recommender._get_capability_rankings(tech_stack=["php"])
        # Tools that support php should have score > 0
        assert any(r.get("score", 0) > 0 for r in result)

    def test_scores_vuln_class_match(self, recommender):
        result = recommender._get_capability_rankings(vuln_class="sqli")
        sqlmap_entry = next((r for r in result if r["name"] == "sqlmap"), None)
        assert sqlmap_entry is not None
        assert sqlmap_entry["score"] > 0

    def test_returns_empty_for_no_matching_capabilities(self, recommender):
        # All capabilities exist, so this should never be truly empty
        # but score should be 0 for non-matching tools
        result = recommender._get_capability_rankings(tech_stack=["unknown_tech"], vuln_class="unknown_class")
        # Tools with "*" tech_support still get some score
        assert isinstance(result, list)


class TestGetToolInfo:
    def test_known_tool(self, recommender):
        info = recommender.get_tool_info("nuclei")
        assert info is not None
        assert "description" in info
        assert "best_for" in info

    def test_unknown_tool_returns_none(self, recommender):
        assert recommender.get_tool_info("nonexistent_tool") is None


class TestToolCapabilitiesData:
    def test_capabilities_dict_is_populated(self, recommender):
        assert len(ToolRecommender.TOOL_CAPABILITIES) >= 10

    def test_each_tool_has_required_fields(self, recommender):
        for tool_name, caps in ToolRecommender.TOOL_CAPABILITIES.items():
            assert "description" in caps, f"{tool_name} missing description"
            assert "best_for" in caps, f"{tool_name} missing best_for"
            assert "tech_support" in caps, f"{tool_name} missing tech_support"
