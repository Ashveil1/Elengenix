"""tests/test_coverage_analyzer.py — M6 verification tests."""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


@pytest.fixture
def analyzer(tmp_path):
    from tools.coverage_analyzer import CoverageAnalyzer

    db = tmp_path / "test_coverage.db"
    return CoverageAnalyzer(db_path=db)


def test_record_endpoint(analyzer):
    """Recording a new endpoint should add to the catalog."""
    ep = analyzer.record_endpoint(
        "https://target.com/api/users", "GET", params=["id", "name"], source="crawl"
    )
    assert ep.url == "https://target.com/api/users"
    assert ep.params == ["id", "name"]
    assert ep.source == "crawl"
    assert ep.endpoint_key().endswith("/api/users")
    print(f"[RECORD] {ep.endpoint_key()}")


def test_duplicate_endpoint_returns_existing(analyzer):
    """Recording the same endpoint twice should not duplicate."""
    ep1 = analyzer.record_endpoint("https://target.com/login", "POST", params=["u", "p"])
    ep2 = analyzer.record_endpoint("https://target.com/login", "POST", params=["u", "p", "csrf"])
    report = analyzer.get_coverage_report()
    assert report.total_endpoints == 1
    assert len(ep2.params) == 3
    print(f"[DEDUPE] 1 endpoint with merged params: {ep2.params}")


def test_record_test_marks_coverage(analyzer):
    """Recording a test should mark that param slot as tested."""
    analyzer.record_endpoint("https://target.com/search", "GET", params=["q"])
    analyzer.record_test(
        url="https://target.com/search",
        method="GET",
        tool="dalfox",
        injection_point="param:q",
        payload="<script>",
        status=200,
        response_size=1234,
        is_interesting=True,
        notes="XSS reflected",
    )
    cov = analyzer.get_endpoint_coverage("https://target.com/search")
    assert cov["coverage_pct"] == 100.0
    assert cov["total_tests"] == 1
    assert cov["interesting_tests"] == 1
    print(f"[COVERAGE] {cov}")


def test_get_untested_endpoints(analyzer):
    """Endpoints with no tests should appear as untested."""
    analyzer.record_endpoint("https://target.com/a", "GET", params=["x"])
    analyzer.record_endpoint("https://target.com/b", "GET", params=["y"])
    analyzer.record_test("https://target.com/a", "GET", "nuclei", "param:x", "1", 200, 100, False)
    untested = analyzer.get_untested_endpoints()
    assert len(untested) == 1
    assert untested[0].url == "https://target.com/b"
    print(f"[UNTESTED] {len(untested)} endpoints: {[e.url for e in untested]}")


def test_get_undertested_params(analyzer):
    """Params tested < 2 times should appear as undertested."""
    analyzer.record_endpoint("https://target.com/api", "GET", params=["id"])
    analyzer.record_test(
        "https://target.com/api", "GET", "nuclei", "param:id", "1", 200, 100, False
    )
    undertested = analyzer.get_undertested_params(min_tests=2)
    assert len(undertested) == 1
    assert undertested[0] == ("https://target.com/api", "param:id")
    print(f"[UNDERTESTED] {undertested}")


def test_coverage_report(analyzer):
    """Report should aggregate all stats."""
    analyzer.record_endpoint("https://target.com/a", "GET", params=["x", "y"], source="recon")
    analyzer.record_endpoint("https://target.com/b", "POST", params=["p"], source="crawl")
    analyzer.record_test("https://target.com/a", "GET", "tool1", "param:x", "1", 200, 100, True)
    analyzer.record_test("https://target.com/a", "GET", "tool1", "param:x", "2", 200, 100, False)
    analyzer.record_test("https://target.com/a", "GET", "tool2", "param:y", "3", 200, 100, False)

    report = analyzer.get_coverage_report()
    assert report.total_endpoints == 2
    assert report.total_param_slots == 3
    assert report.tested_param_slots == 2  # x (2x) + y (1x) = 2 unique params
    assert report.coverage_pct == round(2 / 3 * 100, 1)
    assert report.total_tests == 3
    assert report.interesting_findings == 1
    assert report.unique_tools_used == 2
    assert report.endpoints_by_source == {"recon": 1, "crawl": 1}
    print(f"[REPORT] {report.to_dict()}")


def test_suggest_next_targets_untested_first(analyzer):
    """Suggestions should prioritize untested over undertested."""
    analyzer.record_endpoint("https://target.com/a", "GET", params=["id", "name"])
    analyzer.record_endpoint("https://target.com/b", "GET", params=["file"])
    analyzer.record_test("https://target.com/a", "GET", "tool", "param:id", "1", 200, 100, False)

    suggestions = analyzer.suggest_next_targets(limit=10)
    # /b is untested, /a name is untested, /a id is tested, /a name is high-value
    urls = [s["url"] for s in suggestions]
    assert "https://target.com/b" in urls  # untested
    assert "https://target.com/a" in urls  # has untested name
    # First suggestion should be highest priority (untested or high-value)
    assert suggestions[0]["priority"] in (0, 1)
    print(
        f"[SUGGEST] {len(suggestions)} suggestions: {[(s['type'], s['url'], s['param']) for s in suggestions[:3]]}"
    )


def test_high_value_param_priority(analyzer):
    """High-value params (id, file, path) should get priority 0."""
    analyzer.record_endpoint("https://target.com/api", "GET", params=["id", "q", "name"])
    suggestions = analyzer.suggest_next_targets(limit=10)
    # 'id' is high-value and untested
    high_value = [s for s in suggestions if s["param"] == "id"]
    assert len(high_value) == 1
    assert high_value[0]["priority"] == 0
    print(f"[HIGH-VALUE] {high_value[0]}")


def test_attack_surface_growth(analyzer):
    """Endpoints discovered in this session should be counted."""
    initial_report = analyzer.get_coverage_report()
    assert initial_report.attack_surface_growth == 0
    analyzer.record_endpoint("https://target.com/new", "GET", params=["x"])
    new_report = analyzer.get_coverage_report()
    assert new_report.attack_surface_growth == 1
    assert new_report.total_endpoints == 1
    print(f"[GROWTH] {initial_report.attack_surface_growth} -> {new_report.attack_surface_growth}")


def test_discover_from_url(analyzer):
    """discover_from_url should parse query string and add endpoint."""
    records = analyzer.discover_from_url("https://target.com/api?user_id=1&name=foo&page=2")
    assert len(records) == 1
    assert records[0].params == ["user_id", "name", "page"]
    assert records[0].source == "unknown"
    print(f"[DISCOVER] params parsed: {records[0].params}")


def test_endpoint_key_normalizes_path(analyzer):
    """Same path with different query strings should dedupe."""
    analyzer.record_endpoint("https://target.com/api?id=1", "GET", params=["id"])
    analyzer.record_endpoint("https://target.com/api?id=2", "GET", params=["id"])
    report = analyzer.get_coverage_report()
    assert report.total_endpoints == 1
    print(f"[DEDUPE-PATH] {report.total_endpoints} endpoint(s)")


def test_interesting_count(analyzer):
    """Interesting findings count should be accurate."""
    analyzer.record_endpoint("https://target.com/api", "GET", params=["id"])
    for i in range(5):
        analyzer.record_test(
            "https://target.com/api",
            "GET",
            "tool",
            "param:id",
            str(i),
            200,
            100,
            is_interesting=(i % 2 == 0),
        )
    report = analyzer.get_coverage_report()
    assert report.interesting_findings == 3  # i=0,2,4
    assert report.total_tests == 5
    print(f"[INTERESTING] {report.interesting_findings}/{report.total_tests}")
