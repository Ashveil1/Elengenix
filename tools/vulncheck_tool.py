"""tools/vulncheck_tool.py

VulnCheck Intelligence Tool - Real-time vulnerability and exploit intelligence.
"""

import os
import logging
import requests
from typing import Dict, List, Optional

logger = logging.getLogger("elengenix.vulncheck")

BASE_URL = "https://api.vulncheck.com"

def _get_headers() -> Dict[str, str]:
    token = os.getenv("VULNCHECK_API_KEY")
    return {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json"
    }

def lookup_cve(cve_id: str) -> Optional[Dict]:
    """Look up a specific CVE in VulnCheck NVD2 index."""
    if not os.getenv("VULNCHECK_API_KEY"):
        return None
        
    try:
        url = f"{BASE_URL}/v3/index/vulncheck-nvd2"
        params = {"cve": cve_id}
        resp = requests.get(url, headers=_get_headers(), params=params, timeout=15)
        resp.raise_for_status()
        data = resp.json()
        
        if data.get("data"):
            return data["data"][0]
        return None
    except Exception as e:
        logger.error(f"VulnCheck lookup error ({cve_id}): {e}")
        return None

def search_exploits(query: str) -> List[Dict]:
    """Search for known exploits related to a query."""
    if not os.getenv("VULNCHECK_API_KEY"):
        return []
        
    try:
        # Using the Exploit Intelligence index
        url = f"{BASE_URL}/v3/index/vulncheck-known-exploited-vulnerabilities"
        params = {"query": query}
        resp = requests.get(url, headers=_get_headers(), params=params, timeout=15)
        resp.raise_for_status()
        data = resp.json()
        
        return data.get("data", [])
    except Exception as e:
        logger.error(f"VulnCheck exploit search error ({query}): {e}")
        return []

def get_target_intel(target: str) -> Dict:
    """Get summarized intelligence for a target (domain/product)."""
    # This is a high-level helper for the AI
    intel = {
        "cves": [],
        "exploits": [],
        "threat_notes": ""
    }
    
    if not os.getenv("VULNCHECK_API_KEY"):
        return intel
        
    # 1. Search for exploits related to target name
    exploits = search_exploits(target)
    intel["exploits"] = exploits[:5] # Top 5
    
    # 2. If it's a domain, search for related mentions in indices (simplified)
    # For now, we return exploit data which is most valuable
    
    return intel
