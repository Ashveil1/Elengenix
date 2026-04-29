"""
tools/api_finder.py — API Documentation & Endpoint Discovery (v2.0.0)
- Common API/swagger/openapi endpoint probing
- Concurrent requests with threading
- Returns structured results with status codes
"""

from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict
from urllib.parse import urljoin

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logger = logging.getLogger("elengenix.api_finder")

API_ENDPOINTS: List[str] = [
 "/swagger.json", "/swagger/v1/swagger.json", "/openapi.json",
 "/openapi/v1.json", "/openapi/v2.json",
 "/api/v1/docs", "/api/v2/docs", "/api/v3/docs",
 "/v1/api-docs", "/v2/api-docs", "/api-docs",
 "/docs", "/swagger-ui.html", "/redoc",
 "/.well-known/api-configuration",
 "/api/v1/health", "/api/v2/health", "/health",
 "/graphql", "/api/graphql",
 "/api/v1/swagger.json", "/api/v2/swagger.json",
 "/_ah/api/discovery/v1/apis",
]

_TIMEOUT = 6
_MAX_WORKERS = 10

def _make_session() -> requests.Session:
 session = requests.Session()
 retry = Retry(total=2, backoff_factor=0.5, status_forcelist=[500, 502, 503])
 session.mount("https://", HTTPAdapter(max_retries=retry))
 session.mount("http://", HTTPAdapter(max_retries=retry))
 session.headers.update({"User-Agent": "Elengenix-Security-Scanner/2.0"})
 return session

def _probe(session: requests.Session, base_url: str, endpoint: str) -> Dict | None:
 url = urljoin(base_url.rstrip("/") + "/", endpoint.lstrip("/"))
 try:
 r = session.get(url, timeout=_TIMEOUT, allow_redirects=False, verify=False)
 if r.status_code in (200, 201, 204):
 content_type = r.headers.get("Content-Type", "")
 return {
 "url": url,
 "status": r.status_code,
 "content_type": content_type,
 "size": len(r.content),
 "is_json": "json" in content_type or url.endswith(".json"),
 }
 except Exception:
 return None

def find_api_docs(url: str) -> List[Dict]:
 """
 Probe the target for API documentation endpoints.
 Returns a list of dicts with url, status, content_type, size.
 """
 if not url.startswith(("http://", "https://")):
 url = f"https://{url}"

 session = _make_session()
 found: List[Dict] = []

 with ThreadPoolExecutor(max_workers=_MAX_WORKERS) as pool:
 futures = {
 pool.submit(_probe, session, url, ep): ep
 for ep in API_ENDPOINTS
 }
 for future in as_completed(futures):
 result = future.result()
 if result:
 found.append(result)
 logger.info(f"API endpoint found: {result['url']}")

 session.close()
 return sorted(found, key=lambda x: x["url"])

if __name__ == "__main__":
 import sys, json
 if len(sys.argv) > 1:
 results = find_api_docs(sys.argv[1])
 print(json.dumps(results, indent=2))
