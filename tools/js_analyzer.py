import re
import requests
from rich.console import Console

console = Console()

def analyze_js(url):
    """
    Extracts sensitive information and endpoints from JavaScript files.
    """
    console.print(f"[*] Analyzing JS: {url}")
    try:
        response = requests.get(url, timeout=10)
        content = response.text

        # Regex patterns for secrets and endpoints
        patterns = {
            "API Keys/Secrets": r'["\'](AIza[0-9A-Za-z-_]{35}|[0-9a-f]{32}|[A-Z0-9]{20})["\']',
            "Endpoints": r'["\'](/[a-zA-Z0-9/._-]{2,})["\']',
            "Cloud Storage": r'([a-z0-9.-]+\.s3\.amazonaws\.com|[a-z0-9.-]+\.blob\.core\.windows\.net)'
        }

        results = {}
        for name, pattern in patterns.items():
            found = list(set(re.findall(pattern, content)))
            if found:
                results[name] = found

        return results
    except Exception as e:
        return {"error": str(e)}

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        print(analyze_js(sys.argv[1]))
