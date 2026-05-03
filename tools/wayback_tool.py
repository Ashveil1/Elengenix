"""tools/wayback_tool.py — Historical URL & Archive Intelligence

Fetches historical URLs from:
  - Wayback Machine (web.archive.org)
  - AlienVault OTX (otx.alienvault.com)

Purpose: Find forgotten endpoints, old API versions, leaked parameters,
         and legacy pages that may still be accessible and vulnerable.
"""

import logging
import re
import requests
from typing import Dict, List, Set
from urllib.parse import urlparse

logger = logging.getLogger("elengenix.wayback")

_TIMEOUT = 15


def fetch_wayback_urls(domain: str, limit: int = 500) -> List[str]:
    """
    Fetch historical URLs from the Wayback Machine CDX API.
    Returns a deduplicated list of unique URL paths.
    """
    urls: Set[str] = set()
    try:
        # CDX API — returns all archived URLs for the domain
        params = {
            "url": f"*.{domain}/*",
            "output": "text",
            "fl": "original",
            "collapse": "urlkey",
            "limit": str(limit),
        }
        resp = requests.get(
            "https://web.archive.org/cdx/search/cdx",
            params=params,
            timeout=_TIMEOUT,
        )
        if resp.status_code == 200:
            for line in resp.text.strip().splitlines():
                line = line.strip()
                if line and line.startswith("http"):
                    urls.add(line)
            logger.info(f"Wayback returned {len(urls)} unique URLs for {domain}")
        else:
            logger.warning(f"Wayback CDX returned status {resp.status_code}")
    except Exception as e:
        logger.error(f"Wayback fetch error: {e}")

    return list(urls)


def fetch_otx_urls(domain: str) -> List[str]:
    """
    Fetch passive DNS / URL data from AlienVault OTX (no API key needed).
    """
    urls: Set[str] = set()
    try:
        resp = requests.get(
            f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/url_list",
            params={"limit": 200},
            timeout=_TIMEOUT,
        )
        if resp.status_code == 200:
            data = resp.json()
            for entry in data.get("url_list", []):
                url = entry.get("url", "")
                if url:
                    urls.add(url)
            logger.info(f"OTX returned {len(urls)} URLs for {domain}")
    except Exception as e:
        logger.error(f"OTX fetch error: {e}")

    return list(urls)


def _classify_url(url: str) -> str:
    """Classify a URL by its security interest level."""
    path = urlparse(url).path.lower()
    query = urlparse(url).query.lower()

    # High-value patterns
    high_patterns = [
        r"/api/", r"/v\d+/", r"/admin", r"/login", r"/auth",
        r"/upload", r"/export", r"/download", r"/backup",
        r"/config", r"/debug", r"/test", r"/staging",
        r"/internal", r"/private", r"/secret", r"/token",
        r"\.env", r"\.json", r"\.xml", r"\.sql", r"\.bak",
        r"/graphql", r"/swagger", r"/openapi", r"/docs",
        r"/wp-admin", r"/wp-json", r"/xmlrpc", r"/phpmyadmin",
        r"/actuator", r"/metrics", r"/health", r"/status",
        r"/\.git", r"/\.svn", r"/\.htaccess",
    ]

    # Parameter patterns that suggest injection points
    param_patterns = [
        r"id=", r"user=", r"file=", r"path=", r"url=",
        r"redirect=", r"next=", r"return=", r"callback=",
        r"query=", r"search=", r"page=", r"cmd=", r"exec=",
        r"token=", r"key=", r"secret=",
    ]

    full_url = path + "?" + query

    for pat in high_patterns:
        if re.search(pat, full_url):
            return "high"
    for pat in param_patterns:
        if re.search(pat, query):
            return "medium"

    return "low"


def gather_historical_intel(domain: str) -> Dict:
    """
    Main entry point: gather all historical URL intelligence for a domain.

    Returns:
        Dict with categorized URLs and summary stats.
    """
    print(f"  [wayback] Fetching archived URLs for {domain}...")

    # Gather from multiple sources
    wayback_urls = fetch_wayback_urls(domain)
    otx_urls = fetch_otx_urls(domain)

    # Merge and deduplicate
    all_urls = list(set(wayback_urls + otx_urls))

    # Classify by interest level
    high_interest = []
    medium_interest = []
    low_interest = []

    for url in all_urls:
        level = _classify_url(url)
        if level == "high":
            high_interest.append(url)
        elif level == "medium":
            medium_interest.append(url)
        else:
            low_interest.append(url)

    # Extract unique paths (for fuzzing later)
    unique_paths: Set[str] = set()
    for url in all_urls:
        parsed = urlparse(url)
        path = parsed.path
        if path and path != "/":
            unique_paths.add(path)

    # Extract unique parameters
    unique_params: Set[str] = set()
    for url in all_urls:
        query = urlparse(url).query
        if query:
            for param in query.split("&"):
                key = param.split("=")[0]
                if key:
                    unique_params.add(key)

    result = {
        "domain": domain,
        "total_urls": len(all_urls),
        "high_interest": high_interest[:50],   # Cap for AI context
        "medium_interest": medium_interest[:30],
        "low_count": len(low_interest),
        "unique_paths": list(unique_paths)[:100],
        "unique_params": list(unique_params)[:50],
        "sources": {
            "wayback": len(wayback_urls),
            "otx": len(otx_urls),
        }
    }

    print(f"  [wayback] Found {len(all_urls)} total URLs "
          f"({len(high_interest)} high, {len(medium_interest)} medium)")
    print(f"  [wayback] {len(unique_paths)} unique paths, "
          f"{len(unique_params)} unique parameters")

    return result
