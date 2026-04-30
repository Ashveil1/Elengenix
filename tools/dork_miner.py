"""
tools/dork_miner.py — Google Dorking Engine (v2.0.0)
- Structured dork templates per category
- Deduplication of results
- Returns structured list with dork + URLs
"""

from __future__ import annotations

import logging
from typing import Dict, List

from tools.research_tool import search_web

logger = logging.getLogger("elengenix.dork_miner")

_DORK_TEMPLATES: Dict[str, List[str]] = {
    "exposed_files": [
        "site:{target} ext:sql | ext:db | ext:sqlite | ext:bak",
        "site:{target} ext:log | ext:txt | ext:env | ext:conf",
        "site:{target} ext:zip | ext:7z | ext:tar | ext:gz",
    ],
    "admin_panels": [
        "site:{target} inurl:admin | inurl:administrator | inurl:manager",
        "site:{target} intitle:\"admin panel\" | intitle:\"dashboard\"",
        "site:{target} inurl:wp-admin | inurl:wp-login",
    ],
    "directory_listings": [
        "site:{target} intitle:index.of",
        "site:{target} intitle:\"directory listing\"",
    ],
    "api_endpoints": [
        "site:{target} inurl:api | inurl:v1 | inurl:v2 | inurl:graphql",
        "site:{target} inurl:swagger | inurl:openapi",
    ],
    "cloud_leaks": [
        '"{target}" site:pastebin.com | site:gist.github.com | site:trello.com',
        '"{target}" api_key | secret | password | token site:github.com',
    ],
}


def run_smart_dorking(
    target: str,
    categories: List[str] | None = None,
    results_per_dork: int = 3,
) -> List[Dict]:
    """
    Run Google dorks for the target.

    Args:
        target:            Domain to dork (e.g. example.com)
        categories:        Subset of _DORK_TEMPLATES keys, or None for all
        results_per_dork:  Max URLs per dork query

    Returns:
        List of {dork, category, urls}
    """
    cats = categories or list(_DORK_TEMPLATES.keys())
    results: List[Dict] = []
    seen_urls: set = set()

    for cat in cats:
        if cat not in _DORK_TEMPLATES:
            logger.warning(f"Unknown dork category: {cat}")
            continue
        for template in _DORK_TEMPLATES[cat]:
            dork = template.replace("{target}", target)
            urls = [u for u in search_web(dork, num_results=results_per_dork)
                    if u not in seen_urls]
            seen_urls.update(urls)
            if urls:
                results.append({"dork": dork, "category": cat, "urls": urls})
                logger.info(f"[{cat}] {len(urls)} results for: {dork}")

    return results
