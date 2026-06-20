"""tools/llm_reasoning.py

LLM-powered reasoning layer for the hunt engine.

Uses configured AI providers to:
    1. Prioritize endpoints by likely vulnerability surface
    2. Suggest attack vectors beyond simple routing
    3. Explain findings in human-readable language
    4. Generate exploitation hypotheses

This is the difference between "probe everything blindly" and "think about
what we're seeing and adapt".
"""
from __future__ import annotations

import json
import logging
import os
from typing import Any, Dict, List, Optional

logger = logging.getLogger("elengenix.llm_reasoning")


def _get_ai_client():
    """Get the configured AI client. Lazy import to avoid hard dep."""
    try:
        from tools.universal_ai_client import create_default_client
        return create_default_client()
    except Exception as e:
        logger.warning("AI client not available: %s", e)
        return None


def _safe_ask(prompt: str, max_tokens: int = 300, timeout: float = 15.0) -> Optional[str]:
    """Ask the AI a question with timeout. Returns None on any failure."""
    client = _get_ai_client()
    if client is None:
        return None
    try:
        import asyncio
        async def ask():
            from tools.universal_ai_client import AIMessage
            resp = await client.chat([
                AIMessage(role="user", content=prompt)
            ], max_tokens=max_tokens, temperature=0.2)
            return resp.content if hasattr(resp, "content") else str(resp)
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                # Inside another loop — run in thread
                import concurrent.futures
                with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
                    return ex.submit(asyncio.run, ask()).result(timeout=timeout)
            return asyncio.run(ask())
        except RuntimeError:
            return asyncio.run(ask())
    except Exception as e:
        logger.debug("AI ask failed: %s", e)
        return None


# ═══════════════════════════════════════════════════════════════════════════
# ENDPOINT PRIORITIZATION
# ═══════════════════════════════════════════════════════════════════════════

PRIORITIZATION_PROMPT = """You are a senior penetration tester. Given these endpoints discovered on a target, rank them by likely vulnerability surface (highest first). Respond with ONLY a JSON array of path strings, no other text.

Endpoints:
{endpoints}

Most-likely vulnerable endpoints usually include:
- Authentication (login, auth, token, jwt)
- User input handling (search, comments, posts, upload, profile)
- Data access (user/<id>, profile, settings, download, file)
- Privileged operations (admin, manage, redeem, coupon, register)

JSON array only:"""


async def prioritize_endpoints(endpoints: List[str]) -> List[str]:
    """Use AI to rank endpoints by vulnerability likelihood.

    Falls back to original order if AI is unavailable.
    """
    if not endpoints:
        return endpoints

    prompt = PRIORITIZATION_PROMPT.format(
        endpoints="\n".join(f"- {e}" for e in endpoints[:30])
    )
    response = _safe_ask(prompt, max_tokens=400)
    if not response:
        return endpoints

    # Parse JSON array from response
    try:
        # Find JSON array in response
        start = response.find("[")
        end = response.rfind("]") + 1
        if start >= 0 and end > start:
            ranked = json.loads(response[start:end])
            if isinstance(ranked, list):
                # Keep only endpoints that exist in original list
                valid = [e for e in ranked if any(e in orig for orig in endpoints)]
                if valid:
                    return valid
    except Exception as e:
        logger.debug("Failed to parse AI prioritization: %s", e)

    return endpoints


# ═══════════════════════════════════════════════════════════════════════════
# FINDING EXPLANATION
# ═══════════════════════════════════════════════════════════════════════════

EXPLANATION_PROMPT = """You are a security researcher writing a bug bounty report. Explain this finding concisely (2-3 sentences) for a technical audience. Include: what the vulnerability is, why it's exploitable, and the impact.

Finding: {title}
Evidence: {evidence}
Severity: {severity}

Brief technical explanation:"""


def explain_finding(title: str, evidence: str, severity: str) -> Optional[str]:
    """Get AI explanation of a finding. Returns None on failure."""
    prompt = EXPLANATION_PROMPT.format(
        title=title[:200],
        evidence=evidence[:500],
        severity=severity,
    )
    return _safe_ask(prompt, max_tokens=200)


# ═══════════════════════════════════════════════════════════════════════════
# ATTACK VECTOR SUGGESTION
# ═══════════════════════════════════════════════════════════════════════════

SUGGEST_VECTOR_PROMPT = """You are a penetration tester. Given this endpoint, suggest 3 specific attack vectors to test (concise, technical). Format as a JSON array of strings.

Endpoint: {endpoint}
Method: {method}
Known parameters: {params}

JSON array only:"""


async def suggest_attack_vectors(endpoint: str, method: str, params: List[str]) -> List[str]:
    """Get AI-suggested attack vectors for an endpoint."""
    prompt = SUGGEST_VECTOR_PROMPT.format(
        endpoint=endpoint,
        method=method,
        params=", ".join(params) if params else "(unknown)",
    )
    response = _safe_ask(prompt, max_tokens=200)
    if not response:
        return []
    try:
        start = response.find("[")
        end = response.rfind("]") + 1
        if start >= 0 and end > start:
            vectors = json.loads(response[start:end])
            if isinstance(vectors, list):
                return [str(v) for v in vectors[:5]]
    except Exception:
        pass
    return []


# ═══════════════════════════════════════════════════════════════════════════
# REPORT NARRATIVE
# ═══════════════════════════════════════════════════════════════════════════

NARRATIVE_PROMPT = """You are writing an executive summary for a penetration test report. Given these findings, write a 2-paragraph narrative: (1) overall risk posture, (2) top priorities for remediation.

Target: {target}
Total findings: {total}
Critical: {critical}, High: {high}, Medium: {medium}, Low: {low}

Top findings:
{findings}

Executive summary (2 paragraphs, technical but readable):"""


def generate_executive_summary(
    target: str,
    findings: List[Dict[str, Any]],
) -> Optional[str]:
    """Generate AI-written executive summary of the hunt."""
    if not findings:
        return None

    by_sev = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    top = []
    for f in findings[:5]:
        sev = f.get("severity", "Low")
        by_sev[sev] = by_sev.get(sev, 0) + 1
        top.append(f"- [{sev}] {f.get('title', '?')}")

    prompt = NARRATIVE_PROMPT.format(
        target=target,
        total=len(findings),
        critical=by_sev["Critical"],
        high=by_sev["High"],
        medium=by_sev["Medium"],
        low=by_sev["Low"],
        findings="\n".join(top),
    )
    return _safe_ask(prompt, max_tokens=500, timeout=30.0)


# ═══════════════════════════════════════════════════════════════════════════
# QUICK SMOKE TEST
# ═══════════════════════════════════════════════════════════════════════════

def is_ai_available() -> bool:
    """Check if AI is configured and reachable."""
    return _get_ai_client() is not None
