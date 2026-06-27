"""
tools/python_recon.py — Pure-Python Recon Fallback

Runs reconnaissance WITHOUT any third-party security tools.
Used when:
- User has no scanners installed
- AI provider is unavailable
- Offline mode

Capabilities:
- Subdomain brute-force (small wordlist, cert-transparency fallback)
- HTTP header / tech fingerprint
- Directory / endpoint brute-force (small wordlist)
- Port scan (top common ports via async TCP connect)
- Parameter discovery (common param names)

All output is structured (list of dicts) for downstream consumption.
"""

from __future__ import annotations

import asyncio
import logging
import socket
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logger = logging.getLogger("elengenix.python_recon")


@dataclass
class SubdomainHit:
    subdomain: str
    source: str  # "bruteforce" | "ct" | "dns"
    ips: List[str] = field(default_factory=list)


@dataclass
class EndpointHit:
    url: str
    status: int
    length: int
    content_type: str = ""
    title: str = ""


@dataclass
class PortHit:
    host: str
    port: int
    state: str  # "open" | "closed" | "filtered"
    service: str = ""  # "http" | "https" | "ssh" | ...


@dataclass
class ParamHit:
    url: str
    method: str
    param: str
    baseline_len: int
    test_len: int
    is_interesting: bool
    delta_pct: float


# Small but effective wordlists (kept lean for speed)
SUBDOMAIN_WORDLIST = [
    "www",
    "mail",
    "api",
    "dev",
    "test",
    "staging",
    "admin",
    "portal",
    "blog",
    "shop",
    "store",
    "cdn",
    "static",
    "media",
    "img",
    "images",
    "docs",
    "wiki",
    "support",
    "help",
    "status",
    "monitor",
    "grafana",
    "kibana",
    "jenkins",
    "jira",
    "gitlab",
    "github",
    "git",
    "svn",
    "vpn",
    "remote",
    "ssh",
    "ftp",
    "sftp",
    "smtp",
    "imap",
    "pop",
    "db",
    "mysql",
    "postgres",
    "redis",
    "mongo",
    "elastic",
    "es",
    "auth",
    "login",
    "sso",
    "oauth",
    "account",
    "accounts",
    "user",
    "users",
    "app",
    "web",
    "web1",
    "web2",
    "host",
    "server",
    "node1",
    "node2",
    "internal",
    "intranet",
    "corp",
    "corporate",
    "office",
    "hr",
    "finance",
    "beta",
    "alpha",
    "release",
    "preview",
    "demo",
    "sandbox",
    "lab",
    "cloud",
    "aws",
    "azure",
    "gcp",
    "k8s",
    "kubernetes",
    "docker",
    "m",
    "mobile",
    "mapi",
    "wap",
    "touch",
]

# Common directory names (top 200 most common)
DIR_WORDLIST = [
    "admin",
    "administrator",
    "login",
    "wp-admin",
    "wp-login.php",
    "dashboard",
    "panel",
    "controlpanel",
    "cpanel",
    "phpmyadmin",
    "api",
    "api/v1",
    "api/v2",
    "v1",
    "v2",
    "rest",
    "graphql",
    "robots.txt",
    "sitemap.xml",
    "sitemap_index.xml",
    "crossdomain.xml",
    "humans.txt",
    "security.txt",
    ".well-known/security.txt",
    ".git",
    ".git/HEAD",
    ".git/config",
    ".svn",
    ".env",
    ".htaccess",
    "backup",
    "backups",
    "bak",
    "old",
    "temp",
    "tmp",
    "test",
    "tests",
    "uploads",
    "upload",
    "files",
    "media",
    "images",
    "img",
    "static",
    "assets",
    "css",
    "js",
    "javascript",
    "fonts",
    "docs",
    "doc",
    "download",
    "downloads",
    "data",
    "database",
    "db",
    "sql",
    "dump",
    "config",
    "conf",
    "configuration",
    "settings",
    "setup",
    "install",
    "readme",
    "README.md",
    "CHANGELOG.md",
    "LICENSE",
    "license.txt",
    "user",
    "users",
    "account",
    "accounts",
    "profile",
    "profiles",
    "register",
    "signup",
    "signin",
    "forgot",
    "reset",
    "password",
    "search",
    "find",
    "lookup",
    "query",
    "info",
    "info.php",
    "phpinfo.php",
    "test.php",
    "debug",
    "log",
    "logs",
    "log.txt",
    "error.log",
    "debug.log",
    "shell",
    "cmd",
    "exec",
    "run",
    "system",
    "command",
    "internal",
    "private",
    "secret",
    "hidden",
]

# Common parameter names (top 100 for fuzzing)
PARAM_WORDLIST = [
    "id",
    "user_id",
    "uid",
    "userId",
    "user",
    "username",
    "name",
    "email",
    "mail",
    "phone",
    "mobile",
    "tel",
    "q",
    "query",
    "search",
    "s",
    "term",
    "keyword",
    "k",
    "page",
    "p",
    "pg",
    "offset",
    "limit",
    "count",
    "size",
    "per_page",
    "sort",
    "order",
    "orderby",
    "sort_by",
    "direction",
    "dir",
    "filter",
    "f",
    "filter_by",
    "where",
    "category",
    "cat",
    "tag",
    "type",
    "format",
    "lang",
    "locale",
    "language",
    "l",
    "file",
    "filename",
    "path",
    "url",
    "uri",
    "src",
    "source",
    "dest",
    "redirect",
    "redirect_uri",
    "return",
    "return_url",
    "next",
    "prev",
    "callback",
    "cb",
    "jsonp",
    "ref",
    "referer",
    "referrer",
    "debug",
    "test",
    "verbose",
    "admin",
    "root",
    "sudo",
    "action",
    "do",
    "method",
    "op",
    "operation",
    "cmd",
    "command",
    "input",
    "data",
    "value",
    "val",
    "v",
    "key",
    "k",
    "secret",
    "token",
    "access_token",
    "api_key",
    "apikey",
    "auth",
    "authorization",
    "session",
    "sessionid",
    "sid",
    "csrf",
    "csrf_token",
    "nonce",
    "id[]",
    "ids[]",
    "user_ids[]",
    "items[]",  # array params
    "x",
    "y",
    "z",
    "a",
    "b",
    "c",
    "w",
    "h",
    "width",
    "height",
]

# Top common ports
PORT_WORDLIST = [
    (21, "ftp"),
    (22, "ssh"),
    (23, "telnet"),
    (25, "smtp"),
    (53, "dns"),
    (80, "http"),
    (110, "pop3"),
    (135, "msrpc"),
    (139, "netbios"),
    (143, "imap"),
    (443, "https"),
    (445, "smb"),
    (993, "imaps"),
    (995, "pop3s"),
    (1433, "mssql"),
    (1521, "oracle"),
    (2082, "cpanel"),
    (2083, "cpanel-ssl"),
    (2086, "whm"),
    (2087, "whm-ssl"),
    (3306, "mysql"),
    (3389, "rdp"),
    (5432, "postgres"),
    (5900, "vnc"),
    (5984, "couchdb"),
    (6379, "redis"),
    (8000, "http-alt"),
    (8008, "http-alt"),
    (8080, "http-alt"),
    (8081, "http-alt"),
    (8443, "https-alt"),
    (8888, "http-alt"),
    (9000, "http-alt"),
    (9090, "prometheus"),
    (9200, "elasticsearch"),
    (9300, "elasticsearch"),
    (11211, "memcached"),
    (27017, "mongodb"),
    (27018, "mongodb"),
    (50000, "sap"),
]


class PythonRecon:
    """Pure-Python reconnaissance. No third-party tools required."""

    def __init__(self, timeout: float = 5.0, max_concurrent: int = 20):
        self.timeout = timeout
        self.max_concurrent = max_concurrent
        self._session = self._build_session()

    def _build_session(self) -> requests.Session:
        s = requests.Session()
        # No retries on connect errors — we want to fail fast and move on
        # when a target is slow/unreachable. Retries only on 5xx (server hiccups).
        retry = Retry(total=0, connect=0, read=0, status_forcelist=[500, 502, 503, 504])
        adapter = HTTPAdapter(max_retries=retry, pool_connections=50, pool_maxsize=50)
        s.mount("http://", adapter)
        s.mount("https://", adapter)
        s.headers.update(
            {
                "User-Agent": "Mozilla/5.0 (Elengenix Python Recon) AppleWebKit/537.36",
            }
        )
        return s

    def _normalize_url(self, target: str) -> str:
        """Accept bare domain or full URL. Return http://domain."""
        t = target.strip()
        if not t.startswith(("http://", "https://")):
            t = "http://" + t
        return t.rstrip("/")

    def _extract_title(self, html: str) -> str:
        import re

        m = re.search(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
        return m.group(1).strip()[:100] if m else ""

    # ── Subdomain enum ───────────────────────────────────────────────

    def enum_subdomains(
        self, domain: str, wordlist: Optional[List[str]] = None
    ) -> List[SubdomainHit]:
        """Brute-force subdomains via DNS resolution."""
        wordlist = wordlist or SUBDOMAIN_WORDLIST
        domain = domain.lower().strip()
        results: List[SubdomainHit] = []

        def _resolve(word: str) -> Optional[SubdomainHit]:
            sub = f"{word}.{domain}"
            try:
                ips = socket.getaddrinfo(sub, None, type=socket.SOCK_STREAM)
                ip_list = sorted({str(entry[4][0]) for entry in ips})
                return SubdomainHit(subdomain=sub, source="bruteforce", ips=ip_list)
            except (socket.gaierror, OSError):
                return None

        # Sequential (DNS is rate-limited anyway)
        for w in wordlist:
            hit = _resolve(w)
            if hit:
                results.append(hit)
        return results

    # ── HTTP probe + tech fingerprint ───────────────────────────────

    def probe_http(self, target: str) -> Dict[str, Any]:
        """Fetch the base URL, extract headers, title, server tech."""
        url = self._normalize_url(target)
        result: Dict[str, Any] = {
            "url": url,
            "status": 0,
            "headers": {},
            "title": "",
            "tech": [],
            "final_url": url,
            "length": 0,
        }
        try:
            r = self._session.get(url, timeout=self.timeout, allow_redirects=True, verify=False)
            result["status"] = r.status_code
            result["headers"] = dict(r.headers)
            result["final_url"] = r.url
            result["length"] = len(r.content)
            result["title"] = self._extract_title(r.text)
            # Quick tech fingerprint
            server = r.headers.get("Server", "") + r.headers.get("server", "")
            xpb = r.headers.get("X-Powered-By", "") + r.headers.get("x-powered-by", "")
            if server:
                result["tech"].append(f"server:{server}")
            if xpb:
                result["tech"].append(f"powered-by:{xpb}")
            # Common CMS / framework signals
            body_l = r.text.lower()
            if "wp-content" in body_l or "wp-includes" in body_l:
                result["tech"].append("cms:wordpress")
            if "drupal" in body_l:
                result["tech"].append("cms:drupal")
            if "joomla" in body_l:
                result["tech"].append("cms:joomla")
            if "laravel" in body_l or "csrf-token" in body_l:
                result["tech"].append("framework:laravel")
            if "csrfmiddlewaretoken" in body_l:
                result["tech"].append("framework:django")
            if "__next" in body_l or "_next" in body_l:
                result["tech"].append("framework:nextjs")
            if "phpsessid" in (r.headers.get("Set-Cookie", "").lower()):
                result["tech"].append("lang:php")
        except requests.RequestException as e:
            result["error"] = str(e)
        return result

    # ── Directory brute-force ───────────────────────────────────────

    def brute_dirs(self, target: str, wordlist: Optional[List[str]] = None) -> List[EndpointHit]:
        """Brute-force common directories. Returns only non-404 hits."""
        url = self._normalize_url(target)
        wordlist = wordlist or DIR_WORDLIST
        results: List[EndpointHit] = []
        for path in wordlist:
            test_url = f"{url}/{path}"
            try:
                r = self._session.get(
                    test_url, timeout=self.timeout, allow_redirects=False, verify=False
                )
                if r.status_code != 404:
                    results.append(
                        EndpointHit(
                            url=test_url,
                            status=r.status_code,
                            length=len(r.content),
                            content_type=r.headers.get("Content-Type", ""),
                            title=self._extract_title(r.text),
                        )
                    )
            except requests.RequestException:
                continue
        return results

    # ── Port scan (async) ──────────────────────────────────────────

    async def _probe_port(self, host: str, port: int, service: str) -> Optional[PortHit]:
        try:
            conn = asyncio.open_connection(host, port)
            reader, writer = await asyncio.wait_for(conn, timeout=1.0)
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return PortHit(host=host, port=port, state="open", service=service)
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            return None

    async def scan_ports(self, host: str, ports: Optional[List] = None) -> List[PortHit]:
        """Async TCP connect scan."""
        ports = ports or PORT_WORDLIST
        # Resolve hostname if needed
        try:
            ip = socket.gethostbyname(host)
        except socket.gaierror:
            return []
        sem = asyncio.Semaphore(self.max_concurrent)

        async def _bounded(port_info):
            port, service = port_info
            async with sem:
                return await self._probe_port(ip, port, service)

        tasks = [_bounded(p) for p in ports]
        out = await asyncio.gather(*tasks, return_exceptions=False)
        return [h for h in out if h is not None]

    # ── Parameter discovery ────────────────────────────────────────

    def discover_params(
        self, target: str, path: str = "/", wordlist: Optional[List[str]] = None
    ) -> List[ParamHit]:
        """Send common param names; flag responses that differ in size from baseline."""
        base = self._normalize_url(target)
        url = base + path
        wordlist = wordlist or PARAM_WORDLIST

        # Baseline (no params)
        try:
            baseline = self._session.get(url, timeout=self.timeout, verify=False)
            base_len = len(baseline.content)
        except requests.RequestException:
            return []

        results: List[ParamHit] = []
        for p in wordlist:
            for method in ("GET", "POST"):
                try:
                    if method == "GET":
                        r = self._session.get(
                            url, params={p: "test123"}, timeout=self.timeout, verify=False
                        )
                    else:
                        r = self._session.post(
                            url, data={p: "test123"}, timeout=self.timeout, verify=False
                        )
                    test_len = len(r.content)
                    delta_pct = (abs(test_len - base_len) / max(base_len, 1)) * 100
                    is_interesting = (
                        r.status_code not in (200, 204, 301, 302, 304)
                        or delta_pct > 30
                        or r.status_code >= 500
                    )
                    results.append(
                        ParamHit(
                            url=url,
                            method=method,
                            param=p,
                            baseline_len=base_len,
                            test_len=test_len,
                            is_interesting=is_interesting,
                            delta_pct=round(delta_pct, 1),
                        )
                    )
                except requests.RequestException:
                    continue
        return results

    # ── One-shot full recon ────────────────────────────────────────

    def full_recon(self, target: str, quick: bool = False) -> Dict[str, Any]:
        """Run all recon passes. Returns a structured dict.

        Args:
            target: domain or URL
            quick: If True, use smaller wordlists and skip slow passes.
                   Default False (full recon). Set True for production scans
                   where speed matters more than completeness.
        """
        target = target.strip()
        domain = urlparse(self._normalize_url(target)).netloc.split(":")[0]
        result: Dict[str, Any] = {"target": target, "domain": domain, "quick": quick}

        # 1. HTTP probe (always fast)
        result["http_probe"] = self.probe_http(target)

        # 2. Directory brute (small wordlist if quick)
        dirs = DIR_WORDLIST[:20] if quick else DIR_WORDLIST
        result["directories"] = [asdict(d) for d in self.brute_dirs(target, dirs)]

        # 3. Subdomain enum (small wordlist if quick)
        if quick:
            result["subdomains"] = []  # Skip in quick mode (too slow on real domains)
        else:
            subs = SUBDOMAIN_WORDLIST[:20] if quick else SUBDOMAIN_WORDLIST
            result["subdomains"] = [asdict(s) for s in self.enum_subdomains(domain, subs)]

        # 4. Param discovery (small wordlist if quick)
        params = PARAM_WORDLIST[:20] if quick else PARAM_WORDLIST
        result["parameters"] = [asdict(p) for p in self.discover_params(target, "/", params)]

        # 5. Port scan (async, top ports only if quick)
        loop = None
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            ports = PORT_WORDLIST[:15] if quick else PORT_WORDLIST
            port_hits = loop.run_until_complete(self.scan_ports(domain, ports))
            result["ports"] = [asdict(p) for p in port_hits]
        except Exception as e:
            result["ports_error"] = str(e)
        finally:
            if loop is not None:
                try:
                    loop.close()
                except Exception:
                    pass
        return result
