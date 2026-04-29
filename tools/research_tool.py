"""
tools/research_tool.py — OSINT Web Research Tool (v2.0.0)
- Random UA rotation with realistic browser headers
- trafilatura for clean text extraction
- Respects robots.txt intent (no aggressive crawling)
- Returns structured result dicts
"""

from __future__ import annotations

import logging
import random
import time
from typing import Dict, List, Optional

import requests
import trafilatura
from googlesearch import search

logger = logging.getLogger("elengenix.research")

_USER_AGENTS: List[str] = [
 "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
 "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
 "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/537.36 "
 "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
 "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
]

_TIMEOUT = 15
_MAX_TEXT = 4000 # chars returned to LLM

def _headers() -> Dict[str, str]:
 return {
 "User-Agent": random.choice(_USER_AGENTS),
 "Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8",
 "Accept-Language": "en-US,en;q=0.5",
 "DNT": "1",
 "Connection": "keep-alive",
 }

def search_web(query: str, num_results: int = 5) -> List[str]:
 """Return a list of URLs from Google search."""
 try:
 return list(search(query, num_results=num_results, stop=num_results))
 except Exception as e:
 logger.error(f"Web search error: {e}")
 return []

def extract_and_summarize(url: str, max_chars: int = _MAX_TEXT) -> Dict:
 """
 Fetch and extract readable text from a URL.
 Returns: {url, title, text, chars, error}
 """
 try:
 r = requests.get(url, headers=_headers(), timeout=_TIMEOUT, verify=False)
 r.raise_for_status()

 text = trafilatura.extract(
 r.text,
 include_tables=False,
 include_links=False,
 no_fallback=False,
 )
 if not text:
 text = "No readable content extracted."

 return {
 "url": url,
 "text": text[:max_chars],
 "chars": len(text),
 "error": "",
 }
 except Exception as e:
 logger.error(f"Extract error ({url}): {e}")
 return {"url": url, "text": "", "chars": 0, "error": str(e)}

def research_target(
 target: str,
 num_results: int = 5,
 summarize: bool = True,
) -> List[Dict]:
 """
 Search for OSINT about a target and optionally extract page text.
 """
 queries = [
 f'site:{target} inurl:admin OR inurl:config OR inurl:api',
 f'"{target}" vulnerability OR CVE OR exploit',
 f'"{target}" tech stack framework',
 ]

 results: List[Dict] = []
 seen: set = set()

 for q in queries:
 for url in search_web(q, num_results=num_results):
 if url in seen:
 continue
 seen.add(url)
 if summarize:
 data = extract_and_summarize(url)
 results.append(data)
 else:
 results.append({"url": url, "text": "", "chars": 0, "error": ""})
 time.sleep(0.3) # polite delay

 return results
