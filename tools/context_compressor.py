import re

def compress_output(raw_output: str, tool_name: str) -> str:
    """
    Filters and summarizes security tool output to save LLM tokens.
    """
    if not raw_output:
        return "No output received."

    tool_name = tool_name.lower()
    
    if "nmap" in tool_name:
        # Extract only open ports and services
        lines = raw_output.split('\n')
        important = [l for l in lines if "/tcp" in l or "/udp" in l or "Service Info" in l]
        return "\n".join(important) if important else raw_output[:1000]

    elif "nuclei" in tool_name:
        # Extract finding names, severity, and URLs
        lines = raw_output.split('\n')
        important = [l for l in lines if "[" in l and "]" in l]
        return "\n".join(important) if important else raw_output[:1000]

    elif "subfinder" in tool_name or "wayback" in tool_name:
        # Just count the number of items if there are too many
        items = raw_output.strip().split('\n')
        if len(items) > 50:
            return f"Found {len(items)} items. First 10: {', '.join(items[:10])}"
        return raw_output

    elif "katana" in tool_name:
        # Filter for interesting extensions or status codes if available
        items = raw_output.strip().split('\n')
        if len(items) > 30:
            return f"Crawled {len(items)} URLs. Use specific tools to analyze further."
        return raw_output

    # Default: Truncate to safe limit
    if len(raw_output) > 2000:
        return raw_output[-2000:] + "\n... [Truncated for Token Optimization]"
    
    return raw_output
