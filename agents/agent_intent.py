"""agents/agent_intent.py — AI-driven intent classification extracted from agent_brain.py."""

from __future__ import annotations

import logging
from typing import Any

from tools.universal_ai_client import AIMessage

logger = logging.getLogger("elengenix.agent")

_INTENT_PROMPT = """You are an intelligent intent classifier. Analyze the user's message and determine their TRUE intent.

### INTENT CATEGORIES:
1. **casual** - Social chat, greetings, asking who you are, what you can do
   - Examples: "hi", "hello", "who are you", "what can you do", "help"
   - The user wants conversation, not information retrieval

2. **research** - Time-sensitive info that REQUIRES live web search
   - Examples: "today's scores", "latest news", "stock prices now", "tomorrow's weather"
   - MUST be: current events, sports scores, weather forecasts, stock prices, breaking news
   - Information that CHANGES constantly and needs fresh data
   - NOT for: definitions, explanations, how things work (those are security_chat)

3. **scan** - Requesting active security testing on a SPECIFIC target
   - Examples: "scan example.com", "attack 192.168.1.1", "pentest google.com"
   - MUST have a target domain/IP - not just talking about scanning in general
   - The user wants you to run security tools against a target

4. **security_chat** - Security questions, advice, code review without active scanning
   - Examples: "how does SQL injection work", "review this code", "explain XSS"
   - Security discussion without asking to attack a target
   - The user wants knowledge, not tool execution

### CLASSIFICATION RULES:
- **Ask yourself**: "Does this need TODAY's data from the internet?"
- **research** = Live sports scores, current news, weather now, stock prices TODAY (time-sensitive)
- **security_chat** = "what is CVE", "explain SQL injection", "how does XSS work" (knowledge questions)
- **casual** = "hello", "who are you", "what can you do" (social chat)
- **scan** = "scan example.com", "pentest 192.168.1.1" (has specific target)
- "today" + sports/news/weather = research (needs live data)
- "explain/what is/how does" = security_chat (knowledge, not live data)

### OUTPUT:
Reply with ONLY ONE word: casual, research, scan, or security_chat"""


def analyze_intent(client: Any, query: str) -> str:
    """Use AI to classify user intent."""
    try:
        res = client.chat([
            AIMessage(role="system", content=_INTENT_PROMPT),
            AIMessage(role="user", content=query),
        ]).content
        if res is None:
            return "security_chat"
        intent = str(res).strip().lower()

        for valid in ["casual", "research", "scan", "security_chat"]:
            if valid in intent:
                return valid

        return "security_chat"
    except Exception as e:
        logger.warning(f"Intent classification failed: {e}")
        return "security_chat"
