"""
tools/context_compressor.py — Output Scrubbing & Compression (v2.0.0)
- Redacts PII, secrets, tokens, internal IPs before LLM submission
- Tool-aware compression (nuclei, nmap, httpx, katana)
- Keeps output within token budget
"""

from __future__ import annotations

import re

# ── Redaction Patterns ─────────────────────────────────────────────────────────
_REDACT_PATTERNS = [
    # Bearer / API tokens
    (re.compile(r'(?i)(bearer|token|key|secret|passwd?|auth(?:_token)?)\s*[:=]\s*[a-zA-Z0-9_\-\.]{10,}'),
     r'\1: [REDACTED]'),
    # AWS keys
    (re.compile(r'AKIA[0-9A-Z]{16}'), '[AWS_KEY_REDACTED]'),
    # Generic hex secrets (32+ chars)
    (re.compile(r'\b[a-fA-F0-9]{32,}\b'), '[HASH_REDACTED]'),
    # Private IPv4
    (re.compile(r'\b(10|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}\b'),
     '[PRIVATE_IP]'),
    # Emails
    (re.compile(r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b'),
     '[EMAIL_REDACTED]'),
]


def scrub_sensitive_data(text: str) -> str:
    """Remove PII and secrets from tool output before sending to LLM."""
    for pattern, replacement in _REDACT_PATTERNS:
        text = pattern.sub(replacement, text)
    return text


def compress_output(raw_output: str, tool_name: str, max_chars: int = 3000) -> str:
    """
    Summarise and scrub tool output to fit within the LLM token budget.
    Tool-specific logic extracts the most security-relevant lines.
    """
    if not raw_output or not raw_output.strip():
        return f"[{tool_name}] No output."

    clean = scrub_sensitive_data(raw_output)
    tool  = tool_name.lower()

    if "nmap" in tool:
        lines = clean.splitlines()
        important = [
            l for l in lines
            if any(k in l for k in ("/tcp", "/udp", "open", "Service Info", "OS:", "script output"))
        ]
        result = "\n".join(important) if important else clean
    elif "nuclei" in tool:
        lines = clean.splitlines()
        important = [l for l in lines if "[" in l and "]" in l and l.strip()]
        result = "\n".join(important) if important else clean
    elif "httpx" in tool:
        lines = clean.splitlines()
        important = [l for l in lines if l.strip() and not l.startswith("#")]
        result = "\n".join(important[:200])
    elif "katana" in tool or "wayback" in tool or "gau" in tool:
        lines = sorted(set(clean.splitlines()))
        result = "\n".join(lines[:300])
    else:
        result = clean

    if len(result) > max_chars:
        half = max_chars // 2
        result = result[:half] + "\n... [TRUNCATED] ...\n" + result[-half:]

    return result
