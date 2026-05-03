"""tools/github_intel.py — GitHub Intelligence & Leak Hunter

Searches GitHub for:
  - Leaked credentials, API keys, tokens related to the target
  - Internal IPs, hostnames, and configuration files
  - Source code repositories belonging to the target organization

Requires: GITHUB_TOKEN environment variable (Personal Access Token)
Works without token but with heavily rate-limited results.
"""

import os
import logging
import re
import requests
from typing import Dict, List, Optional
from urllib.parse import quote

logger = logging.getLogger("elengenix.github_intel")

_TIMEOUT = 15
_API_BASE = "https://api.github.com"


def _get_headers() -> Dict[str, str]:
    token = os.getenv("GITHUB_TOKEN")
    headers = {
        "Accept": "application/vnd.github.v3+json",
        "User-Agent": "Elengenix-Security-Scanner/3.0",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def search_code(query: str, per_page: int = 10) -> List[Dict]:
    """
    Search GitHub code for a query string.
    Returns list of matching files with metadata.
    """
    results = []
    try:
        resp = requests.get(
            f"{_API_BASE}/search/code",
            headers=_get_headers(),
            params={"q": query, "per_page": per_page},
            timeout=_TIMEOUT,
        )

        if resp.status_code == 403:
            logger.warning("GitHub API rate limited. Set GITHUB_TOKEN for higher limits.")
            return []
        
        resp.raise_for_status()
        data = resp.json()

        for item in data.get("items", []):
            results.append({
                "name": item.get("name", ""),
                "path": item.get("path", ""),
                "repo": item.get("repository", {}).get("full_name", ""),
                "url": item.get("html_url", ""),
                "score": item.get("score", 0),
            })

        logger.info(f"GitHub code search '{query}': {len(results)} results")
    except Exception as e:
        logger.error(f"GitHub code search error: {e}")

    return results


def _build_dork_queries(domain: str) -> List[Dict[str, str]]:
    """Build a list of GitHub dork queries targeting a domain."""
    # Extract base domain name for organization search
    parts = domain.replace("www.", "").split(".")
    org_name = parts[0] if parts else domain

    return [
        # Credential leaks
        {"query": f'"{domain}" password OR secret OR token OR api_key', "category": "credentials"},
        {"query": f'"{domain}" AWS_ACCESS_KEY OR AWS_SECRET OR AKIA', "category": "aws_keys"},
        {"query": f'"{domain}" PRIVATE KEY', "category": "private_keys"},

        # Configuration files
        {"query": f'"{domain}" filename:.env', "category": "env_files"},
        {"query": f'"{domain}" filename:config.json OR filename:config.yaml', "category": "config_files"},
        {"query": f'"{domain}" filename:docker-compose.yml', "category": "docker"},

        # Internal infrastructure
        {"query": f'"{domain}" internal OR staging OR dev OR localhost', "category": "internal_infra"},
        {"query": f'"{domain}" 10.0. OR 172.16. OR 192.168.', "category": "internal_ips"},

        # API and endpoint leaks
        {"query": f'"{domain}" /api/ OR /v1/ OR /v2/ OR graphql', "category": "api_endpoints"},

        # Organization repositories
        {"query": f'org:{org_name} filename:.env OR filename:.htpasswd', "category": "org_secrets"},
    ]


def hunt_leaks(domain: str) -> Dict:
    """
    Main entry point: run all GitHub dork queries against a target domain.

    Returns:
        Dict with categorized leak findings and summary.
    """
    if not os.getenv("GITHUB_TOKEN"):
        logger.warning("GITHUB_TOKEN not set. GitHub intel will be very limited.")

    print(f"  [github] Hunting for leaks related to {domain}...")

    dorks = _build_dork_queries(domain)
    all_findings: List[Dict] = []
    categories_found: Dict[str, int] = {}

    for dork in dorks:
        query = dork["query"]
        category = dork["category"]

        results = search_code(query, per_page=5)

        for r in results:
            finding = {
                "category": category,
                "file": r["name"],
                "path": r["path"],
                "repo": r["repo"],
                "url": r["url"],
                "dork_query": query,
            }
            all_findings.append(finding)

        if results:
            categories_found[category] = categories_found.get(category, 0) + len(results)

    # Severity assessment
    critical_categories = {"credentials", "aws_keys", "private_keys"}
    high_categories = {"env_files", "internal_ips", "org_secrets"}

    critical_count = sum(
        categories_found.get(c, 0) for c in critical_categories
    )
    high_count = sum(
        categories_found.get(c, 0) for c in high_categories
    )

    severity = "info"
    if critical_count > 0:
        severity = "critical"
    elif high_count > 0:
        severity = "high"
    elif all_findings:
        severity = "medium"

    result = {
        "domain": domain,
        "total_findings": len(all_findings),
        "severity": severity,
        "categories": categories_found,
        "findings": all_findings[:30],  # Cap for AI context
        "critical_count": critical_count,
        "high_count": high_count,
    }

    print(f"  [github] Found {len(all_findings)} potential leaks "
          f"(critical: {critical_count}, high: {high_count})")

    return result
