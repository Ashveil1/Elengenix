"""agent_brain.py -- Core AI Agent Logic

Provides the ElengenixAgent class expected by agent.py.
Handles intelligent routing between casual chat (low token) and
serious vulnerability hunting (high token/tools) to optimize usage.
"""

import logging
from typing import Callable, Optional

from tools.universal_ai_client import AIClientManager, AIMessage
from tools.autonomous_agent import AutonomousAgent

logger = logging.getLogger("elengenix.agent_brain")

class ElengenixAgent:
    """Smart AI Agent that distinguishes chat from scanning."""
    
    def __init__(self, **kwargs):
        # Initializes the universal AI client manager capable of fallback.
        self.ai_manager = AIClientManager(preferred_order=["gemini", "openai", "groq", "ollama"])
        
    def process_universal(self, query: str, callback: Optional[Callable] = None, target: str = "", mode: str = "auto") -> str:
        """Alias for process_query in auto mode."""
        return self.process_query(query, callback, target)
        
    def process_query(self, query: str, callback: Optional[Callable] = None, target: str = "") -> str:
        """Process user query, auto-detecting casual chat vs serious scanning."""
        if callback:
            callback("Analyzing intent to optimize token usage...")
            
        is_casual = self._is_casual_chat(query)
        
        if is_casual:
            if callback:
                callback("Intent: Casual Chat. Using lightweight prompt (Token Saver Mode).")
            
            # Use small prompt to save tokens
            sys_prompt = (
                "You are Elengenix AI. Be helpful, concise, and professional. "
                "You do not have tools active for this response to save tokens. "
                "If the user asks for a scan or vulnerability assessment, tell them you are ready "
                "and they should use scan keywords like 'scan' or 'find vulnerabilities'."
            )
            messages = [
                AIMessage(role="system", content=sys_prompt),
                AIMessage(role="user", content=query)
            ]
            response = self.ai_manager.chat(messages, temperature=0.7)
            return response.content
        else:
            if callback:
                callback("Intent: Security Operation. Activating deep analysis...")
            
            # Check if it's a request to run an autonomous scan
            action_keywords = ["scan", "mission", "autonomous", "hunt", "find bugs", "pentest"]
            if any(kw in query.lower() for kw in action_keywords) and (target or len(query.split()) > 1):
                if callback:
                    callback("Starting autonomous security engine...")
                agent = AutonomousAgent(governance_mode="ask")
                
                # Try to extract a target if missing
                eff_target = target
                if not eff_target:
                    # Simple target extraction from query
                    words = query.split()
                    for w in words:
                        if "." in w and "/" not in w:
                            eff_target = w
                        elif "http" in w:
                            eff_target = w
                
                if eff_target:
                    result = agent.run_autonomous_scan(eff_target)
                    return f"**Autonomous Scan Complete**\n\n{result.summary}\n\nReport saved: {result.report_path}"
                
            # If not an explicit autonomous scan, use deep technical prompt
            sys_prompt = (
                "You are Elengenix AI v2.0.0 — A Universal AI Agent specialized for Bug Bounty. "
                "Provide detailed, technical guidance on vulnerability discovery and exploitation. "
                "Use the 4-phase methodology: Recon, Enum, Scanning, Exploitation. "
                "Provide comprehensive and professional answers."
            )
            messages = [
                AIMessage(role="system", content=sys_prompt),
                AIMessage(role="user", content=f"Target Context: {target}\nUser Query: {query}")
            ]
            response = self.ai_manager.chat(messages, temperature=0.3)
            return response.content
            
    def _is_casual_chat(self, query: str) -> bool:
        """Heuristic to save tokens on simple queries."""
        query_lower = query.lower()
        casual_keywords = [
            "hello", "hi", "how are you", "what is", "explain", "help", 
            "who are you", "what can you do", "thanks", "thank you", "ok", "yes", "no"
        ]
        action_keywords = [
            "scan", "hack", "find", "exploit", "vulnerability", "recon", 
            "nmap", "nuclei", "attack", "cve", "payload", "idor", "xss", "sqli"
        ]
        
        # If it explicitly asks for action, not casual
        if any(kw in query_lower for kw in action_keywords):
            return False
            
        # If it matches casual keywords exactly
        if query_lower in casual_keywords:
            return True
            
        # If it starts with a casual keyword
        if any(query_lower.startswith(kw + " ") for kw in casual_keywords):
            return True
            
        # If it's very short, likely casual
        if len(query.split()) < 6 and not any(char in query for char in ["/", "{", "}", "```", "curl", "http", "."]):
            return True
            
        return False
