import requests
from rich.console import Console

console = Console()

API_ENDPOINTS = [
    "/swagger.json", "/swagger/v1/swagger.json", "/openapi.json", 
    "/api/v1/docs", "/api/v2/docs", "/v1/api-docs", "/v2/api-docs",
    "/api-docs", "/docs", "/swagger-ui.html", "/redoc",
    "/.well-known/api-configuration", "/api/v1/health", "/api/v2/health"
]

def find_api_docs(url):
    """
    Scans for common API documentation and configuration files.
    """
    if not url.startswith("http"): url = f"http://{url}"
    found_docs = []
    
    for endpoint in API_ENDPOINTS:
        target_url = f"{url.rstrip('/')}{endpoint}"
        try:
            response = requests.get(target_url, timeout=5, allow_redirects=False)
            if response.status_code == 200:
                found_docs.append(target_url)
        except:
            continue
            
    return found_docs

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        print(find_api_docs(sys.argv[1]))
