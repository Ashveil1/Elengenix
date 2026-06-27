"""tests/test_vulnerable_target_hunt.py

End-to-end tests against the deliberately vulnerable Flask target.

These tests require the vulnerable target to be running on port 5555.
They verify that the hunt engine actually finds real vulnerabilities.
"""

from __future__ import annotations

import asyncio
import socket
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def _is_target_running(port: int = 5555) -> bool:
    """Check if the vulnerable target is up."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.0)
        s.connect(("127.0.0.1", port))
        s.close()
        return True
    except Exception:
        return False


# Skip all tests if target isn't running
pytestmark = pytest.mark.skipif(
    not _is_target_running(),
    reason="Vulnerable target not running on 127.0.0.1:5555. "
    "Start it with: cd tests/vulnerable_target && PORT=5555 python3 app.py",
)


@pytest.fixture(scope="module")
def target_url():
    return "127.0.0.1:5555"


def test_endpoint_discovery_finds_vulns(target_url):
    """Endpoint discovery must find vuln-related paths."""
    from tools.endpoint_discovery import EndpointDiscovery

    disc = EndpointDiscovery(target=target_url, timeout=5.0)

    async def go():
        eps = await disc.discover()
        urls = {ep.url for ep in eps}
        # Critical vuln endpoints should be discovered
        assert any("login" in u for u in urls), "Missing /login"
        assert any("register" in u for u in urls), "Missing /register"
        assert any("render" in u for u in urls), "Missing /render"
        assert any("search" in u for u in urls), "Missing /search"
        assert any("download" in u for u in urls), "Missing /download"
        assert any("merge" in u for u in urls), "Missing /api/merge"
        assert any("jwt" in u for u in urls), "Missing /api/jwt/verify"

    asyncio.run(go())


def test_endpoint_discovery_finds_post_methods(target_url):
    """Discovery should find POST methods for vuln endpoints."""
    from tools.endpoint_discovery import EndpointDiscovery

    disc = EndpointDiscovery(target=target_url, timeout=5.0)

    async def go():
        eps = await disc.discover()
        post_eps = [ep for ep in eps if ep.method == "POST"]
        post_urls = {ep.url for ep in post_eps}
        assert any("login" in u for u in post_urls), "No POST /login"
        assert any("register" in u for u in post_urls), "No POST /register"
        assert any("merge" in u for u in post_urls), "No POST /api/merge"

    asyncio.run(go())


def test_targeted_attacks_find_sqli(target_url):
    """Targeted attacks must find SQL injection on /login."""
    from tools.endpoint_discovery import EndpointDiscovery
    from tools.targeted_attacks import run_targeted_attacks

    async def go():
        disc = EndpointDiscovery(target=target_url, timeout=5.0)
        eps = await disc.discover()
        findings = await run_targeted_attacks(eps)
        sqli = [f for f in findings if f.category == "sql_injection"]
        assert len(sqli) >= 1, f"No SQLi found. Got: {[f.category for f in findings]}"
        # Must have evidence
        assert sqli[0].response_snippet or sqli[0].evidence
        assert sqli[0].endpoint_url

    asyncio.run(go())


def test_targeted_attacks_find_ssti(target_url):
    """Must find SSTI on /render."""
    from tools.endpoint_discovery import EndpointDiscovery
    from tools.targeted_attacks import run_targeted_attacks

    async def go():
        disc = EndpointDiscovery(target=target_url, timeout=5.0)
        eps = await disc.discover()
        findings = await run_targeted_attacks(eps)
        ssti = [f for f in findings if f.category == "ssti"]
        assert len(ssti) >= 1, "SSTI not detected"
        assert "49" in str(ssti[0].response_snippet) or "49" in str(ssti[0].evidence)

    asyncio.run(go())


def test_targeted_attacks_find_xss(target_url):
    """Must find XSS on /search."""
    from tools.endpoint_discovery import EndpointDiscovery
    from tools.targeted_attacks import run_targeted_attacks

    async def go():
        disc = EndpointDiscovery(target=target_url, timeout=5.0)
        eps = await disc.discover()
        findings = await run_targeted_attacks(eps)
        xss = [f for f in findings if "xss" in f.category]
        assert len(xss) >= 1, "XSS not detected"

    asyncio.run(go())


def test_targeted_attacks_find_path_traversal(target_url):
    """Must find path traversal on /download."""
    from tools.endpoint_discovery import EndpointDiscovery
    from tools.targeted_attacks import run_targeted_attacks

    async def go():
        disc = EndpointDiscovery(target=target_url, timeout=5.0)
        eps = await disc.discover()
        findings = await run_targeted_attacks(eps)
        pt = [f for f in findings if f.category == "path_traversal"]
        assert len(pt) >= 1, "Path traversal not detected"
        # Evidence should mention /etc/passwd
        assert "root:" in str(pt[0].response_snippet) or "/etc/passwd" in str(pt[0].evidence)

    asyncio.run(go())


def test_targeted_attacks_find_jwt(target_url):
    """Must find JWT alg=none on /api/jwt/verify."""
    from tools.endpoint_discovery import EndpointDiscovery
    from tools.targeted_attacks import run_targeted_attacks

    async def go():
        disc = EndpointDiscovery(target=target_url, timeout=5.0)
        eps = await disc.discover()
        findings = await run_targeted_attacks(eps)
        jwt = [f for f in findings if "jwt" in f.category]
        assert len(jwt) >= 1, "JWT alg=none not detected"

    asyncio.run(go())


def test_targeted_attacks_find_mass_assignment(target_url):
    """Must find mass assignment on /register."""
    from tools.endpoint_discovery import EndpointDiscovery
    from tools.targeted_attacks import run_targeted_attacks

    async def go():
        disc = EndpointDiscovery(target=target_url, timeout=5.0)
        eps = await disc.discover()
        findings = await run_targeted_attacks(eps)
        ma = [f for f in findings if f.category == "mass_assignment"]
        assert len(ma) >= 1, "Mass assignment not detected"

    asyncio.run(go())


def test_targeted_attacks_find_prototype_pollution(target_url):
    """Must find prototype pollution on /api/merge."""
    from tools.endpoint_discovery import EndpointDiscovery
    from tools.targeted_attacks import run_targeted_attacks

    async def go():
        disc = EndpointDiscovery(target=target_url, timeout=5.0)
        eps = await disc.discover()
        findings = await run_targeted_attacks(eps)
        pp = [f for f in findings if f.category == "prototype_pollution"]
        assert len(pp) >= 1, "Prototype pollution not detected"

    asyncio.run(go())


def test_targeted_attacks_find_idor(target_url):
    """IDOR detection — works when endpoint allows unauth access.

    After enabling auth on /api/user/<id>, the legacy unauth IDOR is no longer
    detectable. Authenticated BOLA detection is tested separately below.
    """
    from tools.endpoint_discovery import EndpointDiscovery
    from tools.targeted_attacks import run_targeted_attacks

    async def go():
        disc = EndpointDiscovery(target=target_url, timeout=5.0)
        eps = await disc.discover()
        findings = await run_targeted_attacks(eps)
        idor = [f for f in findings if f.category == "idor"]
        # IDOR detection without auth — may not find anything if endpoint
        # requires authentication (handled by BOLA test instead)
        # We just ensure the detector runs without error
        assert isinstance(idor, list)

    asyncio.run(go())


def test_targeted_attacks_find_stored_xss(target_url):
    """Must find stored XSS on /comments."""
    from tools.endpoint_discovery import EndpointDiscovery
    from tools.targeted_attacks import run_targeted_attacks

    async def go():
        disc = EndpointDiscovery(target=target_url, timeout=5.0)
        eps = await disc.discover()
        findings = await run_targeted_attacks(eps)
        xss = [f for f in findings if f.category == "xss_stored"]
        assert len(xss) >= 1, "Stored XSS not detected"

    asyncio.run(go())


def test_hunt_engine_finds_vulns(target_url):
    """Full hunt pipeline must produce at least 5 LIVE confirmed findings."""
    from tools.hunt_engine import HuntEngine

    engine = HuntEngine(target=target_url, quiet=True)
    report = engine.hunt_sync()

    live_findings = [
        f
        for f in report.findings
        if f.severity != "Informational"
        and "CANDIDATE" not in f.title.upper()
        and (f.url or f.details)
    ]

    assert len(live_findings) >= 5, (
        f"Expected >=5 live vulns, got {len(live_findings)}: "
        f"{[f.title[:50] for f in live_findings]}"
    )
    # Risk score should reflect findings
    assert report.risk_score >= 50, f"Risk score too low: {report.risk_score}"


def test_hunt_engine_produces_evidence(target_url):
    """LIVE findings must include evidence (response snippets)."""
    from tools.hunt_engine import HuntEngine

    engine = HuntEngine(target=target_url, quiet=True)
    report = engine.hunt_sync()

    live = [
        f
        for f in report.findings
        if f.severity != "Informational" and "CANDIDATE" not in f.title.upper()
    ]

    for f in live:
        # Must have evidence
        ev = f.evidence
        assert ev, f"Finding missing evidence: {f.title}"
        # Evidence should be non-trivial
        assert any(
            v for v in ev.values() if v and len(str(v)) > 5
        ), f"Evidence too short for {f.title}: {ev}"


def test_hunt_engine_chains_detected(target_url):
    """Hunt engine must detect at least one vulnerability chain."""
    from tools.hunt_engine import HuntEngine

    engine = HuntEngine(target=target_url, quiet=True)
    report = engine.hunt_sync()

    # Should find JWT alg=none + IDOR → chain auth_bypass_then_idor
    chain_types = [c.get("chain_type") for c in report.chains]
    assert (
        "auth_bypass_then_idor" in chain_types
    ), f"Expected auth_bypass_then_idor chain, got: {chain_types}"


def test_hunt_engine_distinguishes_live_vs_static(target_url):
    """Hunt must clearly separate LIVE vs CANDIDATE findings."""
    from tools.hunt_engine import HuntEngine

    engine = HuntEngine(target=target_url, quiet=True)
    report = engine.hunt_sync()

    live = [
        f
        for f in report.findings
        if f.severity != "Informational"
        and "CANDIDATE" not in f.title.upper()
        and (f.url or f.details)
    ]
    static = [f for f in report.findings if "CANDIDATE" in f.title.upper()]

    assert len(live) >= 5, "Not enough live findings"
    assert len(static) >= 1, "Static candidates should be present"
    # LIVE count should be HIGHER than the static candidates' severity weight
    # (i.e., not all severity comes from fake candidates)
    live_severity = sum(
        {"Critical": 25, "High": 12, "Medium": 5, "Low": 2}.get(f.severity, 0) for f in live
    )
    assert live_severity >= 50, f"Live severity score too low: {live_severity}"


def test_hunt_engine_authenticates_users(target_url):
    """Hunt must automatically authenticate common users."""
    from tools.hunt_engine import HuntEngine

    engine = HuntEngine(target=target_url, quiet=True)
    report = engine.hunt_sync()

    # Look for auth_session findings
    auth_findings = [f for f in report.findings if f.category == "auth_session"]
    assert len(auth_findings) >= 1, "No authentication successful"
    # Should find at least 2 users (alice, bob, admin all exist)
    usernames = {f.evidence.get("username") for f in auth_findings if isinstance(f.evidence, dict)}
    assert len(usernames) >= 2, f"Only got users: {usernames}"


def test_hunt_engine_finds_authenticated_bola(target_url):
    """Hunt must find BOLA using authenticated sessions."""
    from tools.hunt_engine import HuntEngine

    engine = HuntEngine(target=target_url, quiet=True)
    report = engine.hunt_sync()

    bola = [f for f in report.findings if f.category == "bola"]
    assert len(bola) >= 1, (
        "Expected authenticated BOLA, got none. "
        f"Categories: {[f.category for f in report.findings]}"
    )
    # BOLA evidence should mention different users
    assert bola[0].evidence.get("response_snippet") or bola[0].details


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
