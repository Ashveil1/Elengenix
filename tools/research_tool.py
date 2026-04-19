from googlesearch import search
import trafilatura
from rich.console import Console

console = Console()

def search_web(query, num_results=3):
    """
    Searches Google and returns a list of relevant links.
    """
    console.print(f"[*] Searching web for: {query}")
    results = []
    try:
        for url in search(query, num_results=num_results):
            results.append(url)
        return results
    except Exception as e:
        return [f"Error searching: {str(e)}"]

def extract_web_content(url):
    """
    Extracts text content from a URL for AI analysis.
    """
    console.print(f"[*] Extracting content from: {url}")
    try:
        downloaded = trafilatura.fetch_url(url)
        content = trafilatura.extract(downloaded)
        return content[:3000] # Limit content for AI context
    except Exception as e:
        return f"Error extracting content: {str(e)}"

def research_topic(query):
    """
    Performs search and summarizes the top result.
    """
    links = search_web(query)
    if not links or "Error" in links[0]:
        return "No links found or search error."
    
    content = extract_web_content(links[0])
    return {
        "source": links[0],
        "summary": content
    }
