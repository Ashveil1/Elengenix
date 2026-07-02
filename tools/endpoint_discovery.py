"""tools/endpoint_discovery.py

Smart endpoint discovery for the hunt engine.

Reads the target's root response (often self-documents endpoints in JSON),
probes common API paths, and builds a list of candidate endpoints with their
methods/parameters.

This is the missing piece that turns "probe root URL" into "scan the actual
attack surface".
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urljoin

try:
    import aiohttp
except ImportError:
    aiohttp = None  # type: ignore[assignment]

logger = logging.getLogger("elengenix.discovery")


@dataclass
class Endpoint:
    """A discovered HTTP endpoint with metadata."""

    url: str
    method: str = "GET"
    params: Dict[str, Any] = field(default_factory=dict)  # query/body params
    content_type: str = ""
    requires_auth: bool = False
    source: str = ""  # how we found it (root | common_path | introspection)


# Common paths to probe — if a path returns 200, it's likely an endpoint
COMMON_PATHS = [
    # API roots
    "/api",
    "/api/v1",
    "/api/v2",
    "/v1",
    "/v2",
    # Auth
    "/login",
    "/logout",
    "/register",
    "/signup",
    "/auth",
    "/auth/login",
    "/oauth",
    "/oauth/token",
    "/token",
    "/api/token",
    "/api/auth",
    # User / profile
    "/user",
    "/users",
    "/api/user",
    "/api/users",
    "/me",
    "/profile",
    "/api/user/1",
    "/api/me",
    # Search / data
    "/search",
    "/api/search",
    "/query",
    "/api/query",
    "/find",
    # CRUD
    "/items",
    "/products",
    "/posts",
    "/comments",
    "/messages",
    "/api/items",
    "/api/posts",
    "/api/comments",
    # Admin
    "/admin",
    "/admin/login",
    "/dashboard",
    "/manage",
    # File ops
    "/upload",
    "/download",
    "/file",
    "/files",
    "/static",
    "/assets",
    "/api/upload",
    "/api/download",
    # GraphQL / introspection
    "/graphql",
    "/api/graphql",
    "/graphiql",
    "/gql",
    "/query",
    # Common vuln paths
    "/render",
    "/template",
    "/preview",
    "/exec",
    "/eval",
    "/merge",
    "/api/merge",
    "/api/jwt/verify",
    "/api/jwt/issue",
    "/api/coupon/redeem",
    # Docs
    "/docs",
    "/swagger",
    "/openapi.json",
    "/redoc",
    "/.well-known/openid-configuration",
    "/jwks.json",
    # Debug
    "/debug",
    "/debug/vars",
    "/trace",
    "/actuator",
    "/health",
    "/status",
    "/version",
    "/info",
]


# Pattern detection from response bodies — what kind of endpoint is this?
PATTERN_HINTS = {
    r"vulnerabilit|exploit|inject|xss|sqli|trav": "self_doc",
    r"\{[\s\S]*\"login\"|\"register\"": "auth",
    r"\{[\s\S]*\"id\":\s*\d+": "user_resource",
    r"\{[\s\S]*\"token\":\s*\"[A-Za-z0-9_-]+\"": "auth_token",
    r"\{[\s\S]*\"query\"|\"mutation\"": "graphql",
}


class EndpointDiscovery:
    """Discover endpoints on a target by combining:
    - Root response analysis (self-documenting APIs)
    - Common path probing
    - Pattern detection
    - Response body keyword extraction
    """

    def __init__(self, target: str, timeout: float = 5.0) -> None:
        self.target = self._normalize(target)
        self.timeout = timeout
        self.session: Optional[aiohttp.ClientSession] = None

    @staticmethod
    def _normalize(target: str) -> str:
        t = target.strip()
        if not t.startswith(("http://", "https://")):
            t = "http://" + t
        return t.rstrip("/")

    async def discover(self) -> List[Endpoint]:
        """Main entry: discover all endpoints."""
        endpoints: List[Endpoint] = []
        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=self.timeout)
        ) as session:
            self.session = session

            # Step 1: read root
            root_eps = await self._discover_from_root()
            endpoints.extend(root_eps)

            # Step 2: probe common paths
            common_eps = await self._discover_from_common_paths()
            endpoints.extend(common_eps)

            # Step 3: dedupe
            seen: Set[str] = set()
            unique = []
            for ep in endpoints:
                key = f"{ep.method}:{ep.url}"
                if key not in seen:
                    seen.add(key)
                    unique.append(ep)

        logger.info("Discovered %d unique endpoints", len(unique))
        return unique

    async def _discover_from_root(self) -> List[Endpoint]:
        """Read root and extract endpoint hints from response."""
        eps: List[Endpoint] = []
        try:
            async with self.session.get(self.target) as r:
                if r.status != 200:
                    return eps
                ct = r.headers.get("content-type", "")
                body = await r.text()
                eps.append(Endpoint(url=self.target, method="GET", content_type=ct, source="root"))

                if "json" in ct:
                    try:
                        data = json.loads(body)
                    except Exception:
                        return eps
                    # If JSON has a list of vuln descriptions with paths, parse them
                    if isinstance(data, dict):
                        for key in ("vulnerabilities", "endpoints", "routes"):
                            if key in data and isinstance(data[key], list):
                                for item in data[key]:
                                    if isinstance(item, str):
                                        # Try to extract method + path
                                        ep = self._parse_endpoint_hint(item)
                                        if ep:
                                            eps.append(
                                                Endpoint(
                                                    url=urljoin(
                                                        self.target + "/", ep["path"].lstrip("/")
                                                    ),
                                                    method=ep.get("method", "GET"),
                                                    params=ep.get("params", {}),
                                                    content_type="application/json",
                                                    source="root_hint",
                                                )
                                            )
                                    elif isinstance(item, dict):
                                        # Object form: {"path": "/x", "method": "POST"}
                                        path = item.get("path") or item.get("url")
                                        if path:
                                            full = urljoin(self.target + "/", str(path).lstrip("/"))
                                            eps.append(
                                                Endpoint(
                                                    url=full,
                                                    method=item.get("method", "GET").upper(),
                                                    content_type="application/json",
                                                    source="root_hint",
                                                )
                                            )
        except Exception as e:
            logger.debug("root discovery failed: %s", e)
        return eps

    @staticmethod
    def _parse_endpoint_hint(text: str) -> Optional[Dict[str, Any]]:
        """Parse strings like 'POST /login' or 'GET /search?q='."""
        m = re.match(r"(GET|POST|PUT|DELETE|PATCH)\s+(\S+)", text, re.I)
        if not m:
            return None
        method = m.group(1).upper()
        path_full = m.group(2)
        # Split path from params
        path, _, query = path_full.partition("?")
        params = {}
        if query:
            for pair in query.split("&"):
                if "=" in pair:
                    k, v = pair.split("=", 1)
                    params[k.strip()] = v.strip()
        return {"method": method, "path": path, "params": params}

    async def _discover_from_common_paths(self) -> List[Endpoint]:
        """Probe common paths in parallel — both GET and POST."""
        eps: List[Endpoint] = []
        sem = asyncio.Semaphore(10)

        # Endpoints likely to accept POST
        POST_LIKELY = {
            "/login",
            "/logout",
            "/register",
            "/signup",
            "/auth/login",
            "/auth",
            "/oauth/token",
            "/token",
            "/api/token",
            "/api/auth",
            "/register",
            "/signup",
            "/users",
            "/api/users",
            "/comments",
            "/posts",
            "/messages",
            "/api/comments",
            "/api/posts",
            "/api/merge",
            "/api/coupon/redeem",
            "/upload",
            "/api/upload",
        }

        async def probe(path: str) -> List[Endpoint]:
            url = self.target + path
            found: List[Endpoint] = []
            # Probe GET
            try:
                async with sem, self.session.get(url, allow_redirects=False) as r:
                    if r.status in (200, 201, 204, 301, 302, 401, 403, 405):
                        ct = r.headers.get("content-type", "")
                        body = await r.text()
                        params = self._extract_params_from_path(path)
                        # Try POST if path looks POST-likely OR GET returned 405
                        methods_to_try = ["GET"]
                        if path in POST_LIKELY or r.status == 405:
                            methods_to_try.append("POST")
                        for method in methods_to_try:
                            found.append(
                                Endpoint(
                                    url=url,
                                    method=method,
                                    content_type=ct,
                                    params=params,
                                    requires_auth=(r.status in (401, 403)),
                                    source="common_path",
                                )
                            )
            except Exception:
                return found
            return found

        tasks = [probe(p) for p in COMMON_PATHS]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, list):
                eps.extend(r)
        return eps

    @staticmethod
    def _extract_params_from_path(path: str) -> Dict[str, str]:
        """Extract template params like <int:id> or <id>."""
        params = {}
        for m in re.finditer(r"<[^>]+>", path):
            tag = m.group(0)[1:-1]  # strip < >
            name = re.sub(r"^[^:]+:", "", tag)  # strip type prefix
            params[name] = "1"  # default test value
        return params
