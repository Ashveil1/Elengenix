import requests
import random
import trafilatura
from googlesearch import search
import logging

logger = logging.getLogger(__name__)

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1"
]

def get_random_headers():
    return {
        "User-Agent": random.choice(USER_AGENTS),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "DNT": "1",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1"
    }

def search_web(query, num_results=3):
    try:
        # googlesearch-python handles its own rotation usually, but top-level num is good
        return [url for url in search(query, stop=num_results)]
    except Exception as e:
        logger.error(f"Search error: {e}")
        return []

def extract_and_summarize(url, max_chars=3000):
    try:
        # 🕵️ Proxy support could be added here in the future
        response = requests.get(url, headers=get_random_headers(), timeout=15)
        response.raise_for_status()
        
        text = trafilatura.extract(response.text, include_tables=False, include_links=False)
        if not text: return "No readable content found."
        
        return text[:max_chars]
    except Exception as e:
        logger.error(f"Extraction error for {url}: {e}")
        return f"Error: {str(e)}"
