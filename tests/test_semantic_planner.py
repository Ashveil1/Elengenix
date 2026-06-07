"""tests/test_semantic_planner.py

Tests for the new semantic planner: TargetFingerprinter, AttackVectorDatabase,
and StrategicPlanner's new methods.
"""
from __future__ import annotations

import sys
from pathlib import Path

# Make the project root importable
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from agents.agent_planner import (
    AttackVectorDatabase,
    StrategicPlanner,
    TargetFingerprinter,
    VULN_BY_STACK,
)
from agents.agent_dataclasses import AttackPhase, AttackStep, AttackTree


# ---------------------------------------------------------------------------
# TargetFingerprinter tests
# ---------------------------------------------------------------------------


def test_fingerprinter_empty_returns_defaults():
    fp = TargetFingerprinter()
    r = fp.fingerprint()
    assert r["server"] is None
    assert r["language"] is None
    assert r["cms"] is None
    assert r["technologies"] == []


def test_fingerprinter_detects_nginx():
    fp = TargetFingerprinter()
    r = fp.fingerprint(headers={"Server": "nginx/1.21.4"})
    assert r["server"] == "nginx"


def test_fingerprinter_detects_apache():
    fp = TargetFingerprinter()
    r = fp.fingerprint(headers={"Server": "Apache/2.4.41"})
    assert r["server"] == "apache"


def test_fingerprinter_detects_php():
    fp = TargetFingerprinter()
    r = fp.fingerprint(headers={"X-Powered-By": "PHP/8.1"})
    assert r["language"] == "php"


def test_fingerprinter_detects_aspnet():
    fp = TargetFingerprinter()
    r = fp.fingerprint(headers={"X-Powered-By": "ASP.NET"})
    assert r["language"] == "aspnet"


def test_fingerprinter_detects_express_via_header():
    fp = TargetFingerprinter()
    r = fp.fingerprint(headers={"X-Powered-By": "Express"})
    # Express is a Node.js framework, so it shows up as framework=express
    assert r["framework"] == "express"


def test_fingerprinter_detects_wordpress_via_body():
    fp = TargetFingerprinter()
    r = fp.fingerprint(body="<html>wp-content/themes/foo.css")
    assert r["cms"] == "wordpress"


def test_fingerprinter_detects_drupal_via_body():
    fp = TargetFingerprinter()
    r = fp.fingerprint(body="var Drupal = {settings: ...}")
    assert r["cms"] == "drupal"


def test_fingerprinter_detects_rails_via_cookie():
    fp = TargetFingerprinter()
    r = fp.fingerprint(cookies={"_rails_session": "abc123"})
    assert r["framework"] == "rails"


def test_fingerprinter_detects_django_via_cookie():
    fp = TargetFingerprinter()
    r = fp.fingerprint(cookies={"csrftoken": "xyz"})
    assert r["framework"] == "django"


def test_fingerprinter_detects_express_via_cookie():
    fp = TargetFingerprinter()
    r = fp.fingerprint(cookies={"connect.sid": "abc"})
    assert r["framework"] == "express"


def test_fingerprinter_detects_java_via_jsessionid():
    fp = TargetFingerprinter()
    r = fp.fingerprint(cookies={"JSESSIONID": "abc"})
    assert r["language"] == "java"


def test_fingerprinter_detects_php_via_phpsessid():
    fp = TargetFingerprinter()
    r = fp.fingerprint(cookies={"PHPSESSID": "abc"})
    assert r["language"] == "php"


def test_fingerprinter_url_php_hint():
    fp = TargetFingerprinter()
    r = fp.fingerprint(url="https://example.com/index.php?id=1")
    assert r["language"] == "php"


def test_fingerprinter_url_aspx_hint():
    fp = TargetFingerprinter()
    r = fp.fingerprint(url="https://example.com/page.aspx?id=1")
    assert r["language"] == "aspnet"


def test_fingerprinter_url_jsp_hint():
    fp = TargetFingerprinter()
    r = fp.fingerprint(url="https://example.com/page.jsp?id=1")
    assert r["language"] == "java"


def test_fingerprinter_cdn_via_header():
    fp = TargetFingerprinter()
    r = fp.fingerprint(headers={"cf-ray": "abc123"})
    assert r["cdn"] is not None
    assert "cdn" in r["technologies"]


def test_fingerprinter_waf_via_server():
    fp = TargetFingerprinter()
    r = fp.fingerprint(headers={"Server": "cloudflare"})
    # cloudflare sets the server, but we also classify as WAF
    assert r["server"] == "cloudflare"
    assert r["waf"] is not None


def test_fingerprinter_combined_stack():
    fp = TargetFingerprinter()
    r = fp.fingerprint(
        headers={"Server": "nginx/1.21", "X-Powered-By": "PHP/8.1"},
        body="<html>...wp-content/themes/x.css",
    )
    assert r["server"] == "nginx"
    assert r["language"] == "php"
    assert r["cms"] == "wordpress"
    assert "nginx" in r["technologies"]
    assert "php" in r["technologies"]
    assert "wordpress" in r["technologies"]


def test_fingerprinter_db_inferred_from_server():
    fp = TargetFingerprinter()
    r = fp.fingerprint(headers={"X-Powered-By": "PHP/8.1"})
    assert r["db"] == "mysql"


def test_fingerprinter_case_insensitive_headers():
    fp = TargetFingerprinter()
    r = fp.fingerprint(headers={"server": "nginx"})
    assert r["server"] == "nginx"


# ---------------------------------------------------------------------------
# AttackVectorDatabase tests
# ---------------------------------------------------------------------------


def test_vector_db_has_well_known_stacks():
    db = AttackVectorDatabase()
    for tech in ("php", "aspnet", "java", "python", "node", "ruby", "go",
                 "wordpress", "drupal", "joomla", "magento", "laravel",
                 "rails", "django", "flask", "express", "tomcat", "jenkins",
                 "graphql", "openapi", "phpmyadmin", "kibana", "grafana"):
        assert tech in db.db, f"missing vuln entry for {tech}"


def test_vector_db_hypotheses_for_php():
    db = AttackVectorDatabase()
    hyps = db.hypotheses_for(["php"])
    assert len(hyps) >= 3
    vuln_classes = {h[0] for h in hyps}
    assert "sqli" in vuln_classes
    assert "lfi" in vuln_classes


def test_vector_db_hypotheses_for_wordpress():
    db = AttackVectorDatabase()
    hyps = db.hypotheses_for(["wordpress"])
    vuln_classes = {h[0] for h in hyps}
    assert "sqli" in vuln_classes or "rce" in vuln_classes


def test_vector_db_dedups_hypotheses():
    db = AttackVectorDatabase()
    # php + mysql -> sqli mentioned for php; should appear once
    hyps = db.hypotheses_for(["php", "mysql"])
    sqli_descriptions = [h[1] for h in hyps if h[0] == "sqli"]
    assert len(sqli_descriptions) == len(set(sqli_descriptions))


def test_vector_db_returns_recommended_tools():
    db = AttackVectorDatabase()
    hyps = db.hypotheses_for(["php"])
    for h in hyps:
        assert len(h[2]) >= 1, f"hypothesis {h[0]} has no tools"


def test_vector_db_technologies_for_vuln():
    db = AttackVectorDatabase()
    techs = db.technologies_for_vuln("sqli")
    assert "php" in techs
    assert "mysql" in techs


def test_vector_db_add_custom():
    db = AttackVectorDatabase()
    db.add("mytech", [("custom", "custom vuln", ("nuclei",))])
    hyps = db.hypotheses_for(["mytech"])
    assert any(h[0] == "custom" for h in hyps)


def test_vector_db_unknown_tech_returns_empty():
    db = AttackVectorDatabase()
    hyps = db.hypotheses_for(["nonexistent-tech-xyz"])
    assert hyps == []


def test_vector_db_combined_php_wordpress_includes_union():
    db = AttackVectorDatabase()
    hyps = db.hypotheses_for(["php", "wordpress"])
    vuln_classes = {h[0] for h in hyps}
    # Union of both
    assert "sqli" in vuln_classes
    assert "rce" in vuln_classes or "lfi" in vuln_classes


# ---------------------------------------------------------------------------
# StrategicPlanner semantic methods
# ---------------------------------------------------------------------------


class _StubClient:
    """Minimal stand-in for AIClientManager to avoid LLM calls in tests."""
    def chat(self, messages, **kwargs):
        class _Resp:
            content = "{}"
        return _Resp()

    # Some AIClientManager implementations also have these; provide them for safety.
    def stream(self, messages, **kwargs):  # pragma: no cover
        return iter([])

    def get_provider(self):  # pragma: no cover
        return None

    def list_providers(self):  # pragma: no cover
        return []


def _make_planner() -> StrategicPlanner:
    return StrategicPlanner(client=_StubClient())


def test_strategic_planner_preserved_construction():
    p = _make_planner()
    assert p.fingerprinter is not None
    assert p.vector_db is not None
    assert p.cvss_calc is not None


def test_strategic_planner_semantic_steps_for_php():
    p = _make_planner()
    fp = p.fingerprinter.fingerprint(headers={"X-Powered-By": "PHP/8.1"})
    steps = p.semantic_steps_for(fp, "http://target.example.com")
    assert len(steps) >= 1
    # The first step should be a high-severity vuln
    purposes = " ".join(s.purpose for s in steps)
    assert "sqli" in purposes or "lfi" in purposes or "ssrf" in purposes


def test_strategic_planner_semantic_attack_tree_construction():
    p = _make_planner()
    fp = p.fingerprinter.fingerprint(headers={"Server": "nginx"})
    tree = p.semantic_attack_tree("http://target.example.com", fp)
    assert isinstance(tree, AttackTree)
    assert tree.target == "http://target.example.com"
    assert tree.reasoning  # non-empty


def test_strategic_planner_semantic_attack_tree_assigns_phases():
    p = _make_planner()
    fp = p.fingerprinter.fingerprint(
        headers={"X-Powered-By": "PHP/8.1"},
        body="Drupal.settings",
    )
    tree = p.semantic_attack_tree("http://target.example.com", fp)
    phases = {s.phase for s in tree.steps}
    assert AttackPhase.EXPLOITATION in phases


def test_strategic_planner_semantic_steps_unique_tools():
    p = _make_planner()
    fp = p.fingerprinter.fingerprint(headers={"X-Powered-By": "PHP/8.1"})
    steps = p.semantic_steps_for(fp, "http://target.example.com")
    tools = [s.tool_name for s in steps]
    # Each tool appears at most once
    assert len(tools) == len(set(tools)), "duplicate tools in semantic plan"


def test_strategic_planner_generate_attack_tree_uses_fingerprint():
    p = _make_planner()
    fp = p.fingerprinter.fingerprint(headers={"X-Powered-By": "PHP/8.1"})
    tree = p.generate_attack_tree("http://target.example.com", fingerprint=fp)
    # Even with a stub LLM, the semantic steps should be present
    assert any(s.purpose.startswith("[") for s in tree.steps)


def test_strategic_planner_fingerprint_target_method():
    p = _make_planner()
    fp = p.fingerprint_target(headers={"Server": "Apache"}, body="wp-content")
    assert fp["server"] == "apache"
    assert fp["cms"] == "wordpress"


def test_strategic_planner_fallback_to_default_tree():
    p = _make_planner()
    # Empty fingerprint + stub LLM returning {} -> no semantic steps, no AI steps
    # The planner should fall back to default
    tree = p.generate_attack_tree("http://nope.invalid", fingerprint={})
    # We have a default tree as fallback
    assert len(tree.steps) >= 1


def test_strategic_planner_legacy_default_tree_method():
    """The _default_attack_tree method should still return a full default tree."""
    p = _make_planner()
    tree = p._default_attack_tree("http://example.com", "test")
    assert len(tree.steps) >= 6
    assert any(s.tool_name == "subfinder" for s in tree.steps)
    assert any(s.tool_name == "nuclei" for s in tree.steps)


def test_strategic_planner_select_next_tool_preserved():
    p = _make_planner()
    tree = p._default_attack_tree("http://example.com", "test")
    # Mark subfinder as completed to get to httpx
    for s in tree.steps:
        if s.tool_name == "subfinder":
            s.completed = True
    nxt = p.select_next_tool(tree, [])
    assert nxt is not None


def test_strategic_planner_adapt_strategy_preserved():
    p = _make_planner()
    tree = p._default_attack_tree("http://example.com", "test")
    before = len(tree.steps)
    p.adapt_strategy(tree, {"type": "api_endpoint", "url": "http://example.com/api"})
    assert len(tree.steps) > before
    assert any(s.tool_name == "arjun" for s in tree.steps)


def test_vuln_by_stack_db_size_is_substantial():
    """The static vuln DB should cover many tech stacks and vuln classes."""
    assert len(VULN_BY_STACK) >= 25, f"expected 25+ techs, got {len(VULN_BY_STACK)}"
    total_hyps = sum(len(v) for v in VULN_BY_STACK.values())
    assert total_hyps >= 60, f"expected 60+ hypotheses, got {total_hyps}"


def test_fingerprinter_combined_real_world_example():
    """Realistic testphp.vulnweb.com-like fingerprint."""
    fp = TargetFingerprinter()
    r = fp.fingerprint(
        headers={
            "Server": "nginx/1.19.0",
            "X-Powered-By": "PHP/5.6.40",
        },
        body="<html><head><title>Welcome to the Vuln Web App</title></head>"
             "<body>...index.php?page=login...</body></html>",
        cookies={"PHPSESSID": "abc123"},
        url="http://testphp.vulnweb.com/login.php",
    )
    assert r["server"] == "nginx"
    assert r["language"] == "php"
    assert r["db"] == "mysql"
    assert "php" in r["technologies"]
    assert "nginx" in r["technologies"]


if __name__ == "__main__":
    # Allow running as a script
    import pytest
    sys.exit(pytest.main([__file__, "-v"]))
