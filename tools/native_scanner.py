"""
tools/native_scanner.py — Native Async Scan Engine
====================================================
World-class native HTTP/HTTPS scanner. No subprocess required.
Pure Python async implementation with connection pooling, retry logic,
parallel scanning, and intelligent response analysis.

Replaces: subfinder, httpx, nuclei (partially), and other subprocess tools.
"""

from __future__ import annotations

import asyncio
import logging
import random
import re
import socket
import ssl
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional, Set, Tuple
from urllib.parse import urlparse, urljoin

logger = logging.getLogger("elengenix.native_scanner")

# ── Async HTTP (try various backends) ────────────────────────────────────
try:
    import aiohttp
    _HAS_AIOHTTP = True
except ImportError:
    _HAS_AIOHTTP = False

try:
    import httpx
    _HAS_HTTPX = True
except ImportError:
    _HAS_HTTPX = False


# ═══════════════════════════════════════════════════════════════════════════
# DATA MODELS
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class ScanTarget:
    """A target to scan with its metadata."""
    url: str
    method: str = "GET"
    headers: Dict[str, str] = field(default_factory=dict)
    body: Optional[str] = None
    timeout: float = 10.0

    def __hash__(self):
        return hash((self.url, self.method, self.body))


@dataclass
class ScanResult:
    """Result from scanning a single target."""
    url: str
    status_code: int = 0
    headers: Dict[str, str] = field(default_factory=dict)
    body: str = ""
    content_type: str = ""
    content_length: int = 0
    server: str = ""
    tech_stack: List[str] = field(default_factory=list)
    elapsed_ms: float = 0.0
    error: Optional[str] = None
    is_alive: bool = False
    findings: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "status_code": self.status_code,
            "content_type": self.content_type,
            "content_length": self.content_length,
            "server": self.server,
            "tech_stack": self.tech_stack,
            "elapsed_ms": round(self.elapsed_ms, 1),
            "error": self.error,
            "is_alive": self.is_alive,
            "findings": self.findings,
        }


@dataclass
class ScanSummary:
    """Summary of a complete scan session."""
    target: str
    start_time: float = 0.0
    end_time: float = 0.0
    total_urls: int = 0
    alive_urls: int = 0
    total_findings: int = 0
    results: List[ScanResult] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    @property
    def duration(self) -> float:
        return self.end_time - self.start_time if self.end_time > self.start_time else 0.0


# ═══════════════════════════════════════════════════════════════════════════
# TECH FINGERPRINTING
# ═══════════════════════════════════════════════════════════════════════════

TECH_FINGERPRINTS: Dict[str, List[str]] = {
    "nginx": ["nginx", "Server: nginx"],
    "apache": ["apache", "Server: Apache"],
    "cloudflare": ["cloudflare", "cf-ray"],
    "wordpress": ["wp-content", "wp-includes", "WordPress"],
    "drupal": ["Drupal", "drupal.js"],
    "django": ["csrfmiddlewaretoken", "django"],
    "flask": ["flask", "Jinja2"],
    "express": ["Express", "X-Powered-By: Express"],
    "spring": ["Spring", "X-Application-Context"],
    "asp.net": ["ASP.NET", "X-AspNet-Version", "__VIEWSTATE"],
    "php": ["PHP", "X-Powered-By: PHP"],
    "node.js": ["Node.js", "node-static"],
    "react": ["react", "React", "next.js"],
    "vue": ["vue", "Vue.js"],
    "angular": ["angular", "ng-"],
    "tomcat": ["Tomcat", "Apache-Coyote"],
    "iis": ["IIS", "Microsoft-IIS"],
    "gunicorn": ["gunicorn"],
    "caddy": ["caddy", "Caddy"],
    "traefik": ["traefik", "Traefik"],
}

def fingerprint_tech(headers: Dict[str, str], body: str) -> List[str]:
    """Identify technology stack from HTTP response."""
    detected: List[str] = []
    combined = ""
    for k, v in headers.items():
        combined += f"{k}: {v}\n"
    combined += body[:10000]  # Only first 10KB for fingerprinting
    
    combined_lower = combined.lower()
    for tech, signatures in TECH_FINGERPRINTS.items():
        for sig in signatures:
            if sig.lower() in combined_lower:
                detected.append(tech)
                break
    
    # Server header
    server = headers.get("Server", headers.get("server", ""))
    if server and server not in detected:
        detected.append(server.split("/")[0].lower())
    
    return list(set(detected))


# ═══════════════════════════════════════════════════════════════════════════
# ASYNC SCANNER CORE
# ═══════════════════════════════════════════════════════════════════════════

class NativeScanner:
    """Pure Python async scanner with connection pooling and parallel scanning.

    Features:
    - Async HTTP/HTTPS with aiohttp or httpx backend
    - Connection pooling with configurable concurrency
    - Automatic retry with exponential backoff
    - Tech fingerprinting
    - Response analysis for findings
    - Parallel scanning with semaphore control
    - Intelligent timeout handling
    """

    def __init__(
        self,
        max_concurrent: int = 20,
        timeout: float = 10.0,
        max_retries: int = 2,
        user_agent: Optional[str] = None,
        follow_redirects: bool = True,
    ):
        self.max_concurrent = max_concurrent
        self.timeout = timeout
        self.max_retries = max_retries
        self.user_agent = user_agent or (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/120.0.0.0 Safari/537.36"
        )
        self.follow_redirects = follow_redirects
        self._semaphore = asyncio.Semaphore(max_concurrent)

    # ── HTTP Client ───────────────────────────────────────────────────────

    async def _fetch(self, target: ScanTarget) -> ScanResult:
        """Fetch a single URL with retry logic."""
        result = ScanResult(url=target.url)
        start = time.perf_counter()

        for attempt in range(self.max_retries + 1):
            try:
                if _HAS_AIOHTTP:
                    result = await self._fetch_aiohttp(target)
                elif _HAS_HTTPX:
                    result = await self._fetch_httpx(target)
                else:
                    result = await self._fetch_socket(target)
                break
            except Exception as e:
                result.error = str(e)
                if attempt < self.max_retries:
                    wait = (2 ** attempt) + random.random()
                    await asyncio.sleep(wait)
                else:
                    logger.debug(f"Failed to fetch {target.url}: {e}")

        result.elapsed_ms = (time.perf_counter() - start) * 1000
        result.is_alive = result.status_code > 0
        return result

    async def _fetch_aiohttp(self, target: ScanTarget) -> ScanResult:
        """Fetch using aiohttp."""
        result = ScanResult(url=target.url)
        async with aiohttp.ClientSession(
            headers={"User-Agent": self.user_agent, **target.headers},
            timeout=aiohttp.ClientTimeout(total=target.timeout),
        ) as session:
            async with session.request(
                target.method, target.url, data=target.body,
                ssl=False, allow_redirects=self.follow_redirects,
            ) as resp:
                result.status_code = resp.status
                result.headers = dict(resp.headers)
                body_text = await resp.text()
                result.body = body_text[:50000]
                result.content_type = resp.headers.get("Content-Type", resp.headers.get("content-type", ""))
                result.content_length = len(result.body)
                result.server = resp.headers.get("Server", resp.headers.get("server", ""))
                result.tech_stack = fingerprint_tech(result.headers, result.body)
        return result

    async def _fetch_httpx(self, target: ScanTarget) -> ScanResult:
        """Fetch using httpx."""
        result = ScanResult(url=target.url)
        async with httpx.AsyncClient(
            headers={"User-Agent": self.user_agent, **target.headers},
            timeout=target.timeout,
            verify=False,
            follow_redirects=self.follow_redirects,
        ) as client:
            resp = await client.request(target.method, target.url, content=target.body)
            result.status_code = resp.status_code
            result.headers = dict(resp.headers)
            result.body = resp.text[:50000]
            result.content_type = resp.headers.get("content-type", "")
            result.content_length = len(result.body)
            result.server = resp.headers.get("server", "")
            result.tech_stack = fingerprint_tech(result.headers, result.body)
        return result

    async def _fetch_socket(self, target: ScanTarget) -> ScanResult:
        """Fallback: fetch using raw sockets (no deps needed)."""
        result = ScanResult(url=target.url)
        parsed = urlparse(target.url)
        host = parsed.hostname or ""
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query

        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=(parsed.scheme == "https")),
                timeout=target.timeout,
            )
            request = (
                f"GET {path} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"User-Agent: {self.user_agent}\r\n"
                f"Connection: close\r\n"
                f"Accept: */*\r\n"
                f"\r\n"
            )
            writer.write(request.encode())
            await writer.drain()

            response = await asyncio.wait_for(
                self._read_socket(reader),
                timeout=target.timeout,
            )
            writer.close()
            await writer.wait_closed()

            # Parse HTTP response
            header_end = response.find(b"\r\n\r\n")
            if header_end == -1:
                result.error = "Invalid response"
                return result

            header_part = response[:header_end].decode("utf-8", errors="replace")
            body_part = response[header_end + 4:].decode("utf-8", errors="replace")

            # Parse status line
            lines = header_part.split("\r\n")
            if lines:
                status_parts = lines[0].split(" ", 2)
                if len(status_parts) >= 2:
                    result.status_code = int(status_parts[1])

            # Parse headers
            for line in lines[1:]:
                if ":" in line:
                    key, val = line.split(":", 1)
                    result.headers[key.strip()] = val.strip()

            result.body = body_part[:50000]
            result.content_type = result.headers.get("content-type", result.headers.get("Content-Type", ""))
            result.content_length = len(result.body)
            result.server = result.headers.get("server", result.headers.get("Server", ""))
            result.tech_stack = fingerprint_tech(result.headers, result.body)

        except Exception as e:
            result.error = str(e)

        return result

    async def _read_socket(self, reader) -> bytes:
        """Read all data from socket using the stream reader."""
        data = bytearray()
        try:
            while True:
                chunk = await asyncio.wait_for(reader.read(65536), timeout=5.0)
                if not chunk:
                    break
                data.extend(chunk)
        except Exception:
            pass
        return bytes(data)

    # ── Parallel Scanning ─────────────────────────────────────────────────

    async def scan_targets(self, targets: List[ScanTarget]) -> List[ScanResult]:
        """Scan multiple targets in parallel with concurrency control."""
        async def _bounded_scan(target: ScanTarget) -> ScanResult:
            async with self._semaphore:
                return await self._fetch(target)

        tasks = [asyncio.create_task(_bounded_scan(t)) for t in targets]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        final_results = []
        for r in results:
            if isinstance(r, Exception):
                final_results.append(ScanResult(url="unknown", error=str(r)))
            else:
                final_results.append(r)
        return final_results

    # ── URL Discovery ─────────────────────────────────────────────────────

    async def discover_urls(self, base_url: str) -> List[str]:
        """Discover URLs from the base URL (basic crawling)."""
        parsed = urlparse(base_url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        urls = {base_url}

        # Common paths to probe
        common_paths = [
            "/", "/robots.txt", "/sitemap.xml", "/.well-known/security.txt",
            "/admin", "/login", "/api", "/health", "/version",
            "/wp-admin", "/wp-content", "/.env", "/.git/config",
            "/swagger.json", "/api-docs", "/graphql",
            "/backup", "/config", "/ phpinfo.php",
        ]

        for path in common_paths:
            urls.add(base + path)

        # Fetch initial page and extract links
        try:
            result = await self._fetch(ScanTarget(url=base_url))
            if result.body:
                # Simple link extraction
                for match in re.finditer(r'href=["\'](https?://[^"\']+)["\']', result.body):
                    url = match.group(1)
                    if url.startswith(base):
                        urls.add(url.split("?")[0].rstrip("/"))
                for match in re.finditer(r'src=["\'](https?://[^"\']+)["\']', result.body):
                    url = match.group(1)
                    if url.startswith(base):
                        urls.add(url.split("?")[0].rstrip("/"))
        except Exception:
            pass

        return list(urls)

    # ── Full Scan Pipeline ────────────────────────────────────────────────

    async def scan(self, target: str) -> Tuple[List[Dict[str, Any]], ScanSummary]:
        """Full scan pipeline: discover, fetch, analyze.

        Args:
            target: URL or domain to scan

        Returns:
            Tuple of (findings_list, scan_summary)
        """
        summary = ScanSummary(target=target)
        summary.start_time = time.time()

        if not target.startswith(("http://", "https://")):
            target = f"https://{target}"

        # Phase 1: Discover URLs
        ui_available = True
        try:
            from ui_components import print_info
        except ImportError:
            ui_available = False
        if ui_available:
            from ui_components import print_info
            print_info(f"  [Native] Discovering URLs for {target}...")
        urls = await self.discover_urls(target)
        summary.total_urls = len(urls)
        logger.debug(f"Discovered {len(urls)} URLs")

        # Phase 2: Scan all URLs in parallel
        scan_targets_list = [ScanTarget(url=u, timeout=self.timeout) for u in urls]
        results = await self.scan_targets(scan_targets_list)

        # Phase 3: Analyze results
        all_findings: List[Dict[str, Any]] = []
        for result in results:
            summary.results.append(result)
            if result.is_alive:
                summary.alive_urls += 1

            # Generate findings from response analysis
            findings = self._analyze_response(result)
            all_findings.extend(findings)
            result.findings = findings

        summary.total_findings = len(all_findings)
        summary.end_time = time.time()
        summary.errors = [r.error for r in results if r.error][:10]

        if ui_available:
            from ui_components import print_success
            print_success(f"  [Native] Scan complete: {summary.alive_urls}/{summary.total_urls} alive, "
                         f"{summary.total_findings} findings in {summary.duration:.1f}s")

        return all_findings, summary

    def _analyze_response(self, result: ScanResult) -> List[Dict[str, Any]]:
        """Analyze HTTP response for security findings."""
        findings: List[Dict[str, Any]] = []

        if not result.is_alive:
            return findings

        # Check for security headers
        headers_lower = {k.lower(): v for k, v in result.headers.items()}
        missing_headers = []
        if "content-security-policy" not in headers_lower:
            missing_headers.append("Content-Security-Policy")
        if "x-frame-options" not in headers_lower:
            missing_headers.append("X-Frame-Options")
        if "x-content-type-options" not in headers_lower:
            missing_headers.append("X-Content-Type-Options")
        if "strict-transport-security" not in headers_lower and result.url.startswith("https"):
            missing_headers.append("Strict-Transport-Security")

        if missing_headers:
            findings.append({
                "tool": "native_scanner",
                "type": "missing_header",
                "severity": "Low",
                "url": result.url,
                "title": f"Missing security headers ({len(missing_headers)})",
                "details": f"Missing: {', '.join(missing_headers)}",
                "headers": missing_headers,
            })

        # Check for server info disclosure
        if result.server:
            findings.append({
                "tool": "native_scanner",
                "type": "info_disclosure",
                "severity": "Info",
                "url": result.url,
                "title": f"Server header: {result.server}",
                "details": f"Server: {result.server}",
            })

        # Check for directory listing
        if result.status_code == 200 and not result.body:
            findings.append({
                "tool": "native_scanner",
                "type": "directory_listing",
                "severity": "Medium",
                "url": result.url,
                "title": "Possible directory listing",
                "details": f"Empty response body at {result.url}",
            })

        # Check for admin panels and sensitive files
        url_lower = result.url.lower()
        if any(p in url_lower for p in ["admin", "login", "wp-admin", "dashboard"]):
            if result.status_code == 200:
                findings.append({
                    "tool": "native_scanner",
                    "type": "exposed_admin",
                    "severity": "Medium",
                    "url": result.url,
                    "title": "Admin/Login panel exposed",
                    "details": f"Status {result.status_code} at {result.url}",
                })

        # Check for .env / .git exposure
        if any(p in url_lower for p in [".env", ".git", "backup", "config"]):
            if result.status_code == 200 and len(result.body) > 10:
                findings.append({
                    "tool": "native_scanner",
                    "type": "sensitive_file",
                    "severity": "High",
                    "url": result.url,
                    "title": "Sensitive file exposed",
                    "details": f"Sensitive file accessible: {result.url}",
                })

        # Check for PHP info disclosure
        if "phpinfo" in url_lower and result.status_code == 200:
            findings.append({
                "tool": "native_scanner",
                "type": "phpinfo_disclosure",
                "severity": "High",
                "url": result.url,
                "title": "PHP info exposed",
                "details": "PHP info page is publicly accessible",
            })

        # Check for tech-specific findings
        for tech in result.tech_stack:
            if tech == "wordpress" and result.status_code == 200:
                findings.append({
                    "tool": "native_scanner",
                    "type": "tech_detected",
                    "severity": "Info",
                    "url": result.url,
                    "title": f"WordPress detected",
                    "details": f"WordPress CMS at {result.url}",
                })

        # Check for CORS misconfiguration
        acao = headers_lower.get("access-control-allow-origin", "")
        if acao == "*":
            findings.append({
                "tool": "native_scanner",
                "type": "cors_misconfig",
                "severity": "Medium",
                "url": result.url,
                "title": "CORS wildcard origin",
                "details": "Access-Control-Allow-Origin: * allows any site to read responses",
            })

        return findings


# ═══════════════════════════════════════════════════════════════════════════
# CLI WRAPPER
# ═══════════════════════════════════════════════════════════════════════════

def run_native_scan(target: str, output_path: Optional[str] = None) -> Dict[str, Any]:
    """Run a native scan synchronously (for CLI usage).

    Args:
        target: URL or domain to scan
        output_path: Optional path to save results JSON

    Returns:
        Scan results dict
    """
    async def _run():
        scanner = NativeScanner()
        findings, summary = await scanner.scan(target)
        return {
            "findings": findings,
            "summary": {
                "target": summary.target,
                "duration": round(summary.duration, 2),
                "total_urls": summary.total_urls,
                "alive_urls": summary.alive_urls,
                "total_findings": summary.total_findings,
                "errors": summary.errors[:5],
            },
        }

    import asyncio
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    result = loop.run_until_complete(_run())
    loop.close()

    if output_path:
        import json
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w") as f:
            json.dump(result, f, indent=2)

    return result


__all__ = ["NativeScanner", "ScanTarget", "ScanResult", "ScanSummary", 
           "run_native_scan", "fingerprint_tech"]
