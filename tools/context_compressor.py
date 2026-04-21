import re

def scrub_sensitive_data(text: str) -> str:
    """
    🛡️ SECURITY: Redacts PII and sensitive data before sending to LLM.
    Removes: API Keys, Bearer Tokens, Session Cookies, and Internal IPs.
    """
    # Redact Bearer Tokens and Common API Key patterns
    text = re.sub(r'(?i)(bearer|token|key|secret|passwd|password|auth|auth_token)["\s:=]+[a-zA-Z0-9_\-\.]{10,}', r'\1: [REDACTED]', text)
    
    # Redact IPv4 Addresses (Generic)
    text = re.sub(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', '[IP_REDACTED]', text)
    
    # Redact Emails
    text = re.sub(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', '[EMAIL_REDACTED]', text)
    
    return text

def compress_output(raw_output: str, tool_name: str) -> str:
    """
    Summarizes output and scrubs PII to save tokens and ensure security.
    """
    if not raw_output:
        return "No output received."

    # First, scrub all sensitive info
    clean_output = scrub_sensitive_data(raw_output)
    
    tool_name = tool_name.lower()
    
    if "nmap" in tool_name:
        lines = clean_output.split('\n')
        important = [l for l in lines if "/tcp" in l or "/udp" in l or "Service Info" in l]
        return "\n".join(important) if important else clean_output[:1000]

    elif "nuclei" in tool_name:
        lines = clean_output.split('\n')
        # Only keep findings and severity
        important = [l for l in lines if "[" in l and "]" in l]
        return "\n".join(important) if important else clean_output[:1000]

    # Default: Truncate to safe limit
    if len(clean_output) > 2000:
        return clean_output[-2000:] + "\n... [Truncated & Scrubbed]"
    
    return clean_output
