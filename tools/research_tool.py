import trafilatura
from googlesearch import search
import logging

logger = logging.getLogger(__name__)

def search_web(query, num_results=3):
    """
    Search Google and return only the most relevant links to save tokens.
    """
    try:
        # Limit to top 3 results to keep context small
        return [url for url in search(query, stop=num_results)]
    except Exception as e:
        logger.error(f"Search error: {e}")
        return []

def extract_and_summarize(url, max_chars=2000):
    """
    Extracts text and cuts it down strictly to prevent token overflow.
    """
    try:
        downloaded = trafilatura.fetch_url(url)
        # extract() with no_tables and no_links to get pure text content
        text = trafilatura.extract(downloaded, include_tables=False, include_links=False)
        
        if not text:
            return "No readable content found."
        
        # 🎯 SMART CUT: Only keep the first 2000 chars which usually contain the meat of the info
        return text[:max_chars]
    except Exception as e:
        return f"Error extracting: {str(e)}"

def deep_intelligence_gathering(tech_stack):
    """
    Called by AI to get a quick summary of vulnerabilities for a tech stack.
    """
    query = f"{tech_stack} latest critical vulnerabilities exploit proof of concept"
    links = search_web(query, num_results=2)
    
    intel = []
    for link in links:
        content = extract_and_summarize(link)
        intel.append(f"Source: {link}\nContent: {content}\n---")
    
    return "\n".join(intel)
