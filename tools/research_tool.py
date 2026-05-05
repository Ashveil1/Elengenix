"""
tools/research_tool.py — OSINT Web Research Tool (v2.0.0)
- Random UA rotation with realistic browser headers
- trafilatura for clean text extraction
- Respects robots.txt intent (no aggressive crawling)
- Returns structured result dicts
"""

import os
import logging
import random
import time
from typing import Dict, List, Optional

import requests

try:
    import trafilatura
    _HAS_TRAFILATURA = True
except ImportError:
    _HAS_TRAFILATURA = False

try:
    from googlesearch import search
    _HAS_GOOGLESEARCH = True
except ImportError:
    _HAS_GOOGLESEARCH = False

logger = logging.getLogger("elengenix.research")

_USER_AGENTS: List[str] = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
]

_TIMEOUT  = 15
_MAX_TEXT = 4000  # chars returned to LLM


def _headers() -> Dict[str, str]:
    return {
        "User-Agent":      random.choice(_USER_AGENTS),
        "Accept":          "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "DNT":             "1",
        "Connection":      "keep-alive",
    }


def search_web(query: str, num_results: int = 5) -> List[Dict]:
    """
    Search the web using Tavily (if API key exists) or Google.
    Returns: List[Dict] with {url, title, content}
    """
    tavily_key = os.getenv("TAVILY_API_KEY")
    
    if tavily_key:
        try:
            logger.info(f"Searching Tavily for: {query}")
            resp = requests.post(
                "https://api.tavily.com/search",
                json={
                    "api_key": tavily_key,
                    "query": query,
                    "search_depth": "smart",
                    "max_results": num_results
                },
                timeout=_TIMEOUT
            )
            resp.raise_for_status()
            data = resp.json()
            results = []
            for r in data.get("results", []):
                results.append({
                    "url": r.get("url"),
                    "title": r.get("title"),
                    "content": r.get("content") or r.get("snippet", "")
                })
            return results
        except Exception as e:
            logger.error(f"Tavily search error: {e}")
            # Fallback to Google
            
    # Google Fallback
    if not _HAS_GOOGLESEARCH:
        logger.warning("googlesearch-python not installed; web search unavailable")
        return []
    try:
        logger.info(f"Searching Google for: {query}")
        urls: List[str] = []
        # googlesearch package has multiple API variants across versions.
        # Try a few compatible signatures.
        try:
            urls = list(search(query, num_results=num_results))
        except TypeError:
            try:
                urls = list(search(query, num_results=num_results, stop=num_results))
            except TypeError:
                try:
                    urls = list(search(query, num=num_results, stop=num_results))
                except TypeError:
                    urls = list(search(query))[:num_results]
        return [{"url": u, "title": "Web Result", "content": ""} for u in urls]
    except Exception as e:
        logger.error(f"Google search error: {e}")
        return []


def extract_and_summarize(url: str, max_chars: int = _MAX_TEXT) -> Dict:
    """
    Fetch and extract readable text from a URL.
    Returns: {url, title, text, chars, error}
    """
    try:
        r = requests.get(url, headers=_headers(), timeout=_TIMEOUT, verify=False)
        r.raise_for_status()

        if not _HAS_TRAFILATURA:
            return {"url": url, "text": "trafilatura not installed; cannot extract content", "chars": 0, "error": "missing trafilatura"}
        text = trafilatura.extract(
            r.text,
            include_tables=False,
            include_links=False,
            no_fallback=False,
        )
        if not text:
            text = "No readable content extracted."

        return {
            "url":   url,
            "text":  text[:max_chars],
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
        search_results = search_web(q, num_results=num_results)
        for res in search_results:
            url = res["url"]
            if url in seen:
                continue
            seen.add(url)
            
            if summarize:
                # If Tavily already gave us content, we might skip extraction or merge it
                if res.get("content") and len(res["content"]) > 500:
                     results.append({"url": url, "text": res["content"][:_MAX_TEXT], "chars": len(res["content"]), "error": ""})
                else:
                    data = extract_and_summarize(url)
                    results.append(data)
            else:
                results.append({"url": url, "text": "", "chars": 0, "error": ""})
            
            time.sleep(0.3)  # polite delay

    return results
