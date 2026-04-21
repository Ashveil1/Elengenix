"""
agent_brain.py — Elengenix Intelligent Hunting Engine (v1.5.0)
- Improved State Management (Reset per query)
- Robust JSON Extraction (Regex-based)
- High-security Subprocess Execution (Shell=False + Strict Allowlist)
"""

import os
import json
import re
import subprocess
import shlex
from pathlib import Path
from collections import Counter
from typing import Optional, Callable, Dict, Any, List

from llm_client import LLMClient
from tools.memory_manager import save_learning, get_summarized_learnings
from bot_utils import send_telegram_notification

class ElengenixAgent:
    """
    Relentless Security Research Agent.
    Orchestrates tools and reasons through discoveries autonomously.
    """
    
    # 🔒 GLOBAL SECURITY ALLOWLIST (Fixed Binaries Only)
    ALLOWED_TOOLS = {
        "subfinder", "httpx", "nuclei", "katana", 
        "waybackurls", "curl", "nmap", "ffuf", "gau",
        "grep", "cat", "ls", "echo", "whois", "dig"
    }

    def __init__(
        self,
        max_steps: int = 20,
        loop_threshold: int = 3,
        history_limit: int = 5,
        max_output_len: int = 2000
    ):
        self.client = LLMClient()
        self.max_steps = max_steps
        self.loop_threshold = loop_threshold
        self.history_limit = history_limit
        self.max_output_len = max_output_len
        
        # 📍 Absolute Path Resolution for Prompts
        self.base_dir = Path(__file__).parent.absolute()
        prompt_path = self.base_dir / "prompts" / "system_prompt.txt"
        
        if not prompt_path.exists():
            # Fallback or initialization
            self.base_prompt = "You are a specialized security AI agent."
        else:
            self.base_prompt = prompt_path.read_text(encoding="utf-8")

    def _extract_json(self, text: str) -> Optional[Dict[str, Any]]:
        """🛠️ Extract JSON from LLM response, supporting Markdown and raw blocks."""
        json_match = re.search(r'```(?:json)?\s*([\s\S]*?)\s*```|({[\s\S]*})', text)
        if not json_match:
            return None
        
        json_str = json_match.group(1) or json_match.group(2)
        try:
            return json.loads(json_str)
        except json.JSONDecodeError:
            return None

    def _execute_tool(self, action_data: Dict[str, Any], callback: Optional[Callable] = None) -> str:
        """
        🔒 ENTERPRISE SECURITY: 
        Execute commands using list-based arguments without shell=True.
        """
        action = action_data.get("action", "").lower()
        cmd_raw = action_data.get("command", "")

        # 1. Action Validation
        if action == "finish": return "__FINISH__"
        if action == "save_memory":
            save_learning(action_data.get("target", "global"), action_data.get("learning", ""), action_data.get("category", "general"))
            return "Finding recorded in SQLite memory."
        
        if action != "run_shell":
            return f"Error: Unknown action '{action}'."

        # 2. Binary Validation (Whitelist)
        try:
            parts = shlex.split(cmd_raw)
            if not parts: return "Error: Empty command."
            
            binary = os.path.basename(parts[0])
            if binary not in self.ALLOWED_TOOLS:
                return f"Error: Tool '{binary}' is not in the security allowlist."
            
            # 3. Injection Prevention (Metacharacter block)
            forbidden = ["|", "&", ";", "`", "$(", ">", "<", "\\"]
            if any(char in cmd_raw for char in forbidden):
                return "Error: Command contains prohibited characters (redirection/piping)."

            if callback: callback(f"Executing: {cmd_raw}")

            # 4. Safe Execution
            result = subprocess.run(
                parts,
                shell=False,
                capture_output=True,
                text=True,
                timeout=180
            )
            return (result.stdout + result.stderr)[:self.max_output_len]

        except subprocess.TimeoutExpired:
            return "Error: Command timed out after 180 seconds."
        except Exception as e:
            return f"Error executing tool: {str(e)}"

    def process_query(self, user_input: str, callback: Optional[Callable] = None, target: str = "") -> str:
        """Process a single mission with isolated state management."""
        send_telegram_notification(f"🎯 Mission Started: \"{user_input}\"")
        
        # 🔄 Reset mission-specific history (State Isolation)
        action_history = []
        history = [{"role": "user", "content": user_input}]
        
        for step in range(self.max_steps):
            # Dynamic Context Construction
            memory = get_summarized_learnings(target or user_input)
            recent_history = history[-self.history_limit:]
            
            history_text = "\n".join([f"{m['role'].capitalize()}: {m['content']}" for m in recent_history])
            full_prompt = f"{self.base_prompt}\n### PREVIOUS FINDINGS (MEMORY):\n{memory}\n\n### CHAT HISTORY:\n{history_text}"
            
            # LLM Reasoning Round
            response_text = self.client.chat(full_prompt, "Plan your next move. Use JSON for tools or direct text for final reports.")
            
            # Action Extraction
            action_data = self._extract_json(response_text)
            if action_data:
                # 🛡️ Loop & Deadlock Protection
                action_sig = f"{action_data.get('action')}:{action_data.get('command') or action_data.get('target')}"
                action_history.append(action_sig)
                
                if Counter(action_history)[action_sig] > self.loop_threshold:
                    msg = f"⚠️ DEADLOCK DETECTED: Agent is repeating '{action_sig}'. Terminating to save resources."
                    send_telegram_notification(msg)
                    return msg

                # Execution
                obs = self._execute_tool(action_data, callback)
                
                if obs == "__FINISH__":
                    send_telegram_notification(f"🏁 Mission Accomplished: {user_input}")
                    return action_data.get("summary", "Mission successfully completed.")
                
                # Feedback Loop
                history.append({"role": "assistant", "content": response_text})
                history.append({"role": "user", "content": f"OBSERVATION: {obs}"})
                continue
            
            # If no JSON found, assume final text answer
            return response_text
            
        return "Task halted: Maximum operation steps (20) reached without a conclusion."
