from tools.research_tool import search_web
import yaml

def run_smart_dorking(target):
    """
    Performs Google Dorking for target and returns interesting files.
    """
    dorks = [
        f"site:{target} intitle:index.of",
        f"site:{target} ext:sql | ext:db | ext:7z",
        f"site:{target} inurl:admin | inurl:config",
        f"site:{target} ext:log | ext:txt | ext:env"
    ]

    results = []
    for dork in dorks:
        found_links = search_web(dork, num_results=2)
        if found_links and "Error" not in found_links[0]:
            results.extend(found_links)
    
    return results
