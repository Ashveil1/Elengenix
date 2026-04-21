"""
agent_brain.py — Elengenix Upgraded Agent (v1.3)
- Relentless Hunting Logic
- Autonomous loop up to 20 rounds
- Deep Search and Tool Chaining
"""

import os
import json
import subprocess
import shlex
import sys
from llm_client import LLMClient
from knowledge_loader import load_knowledge_base
from orchestrator import run_standard_scan
from tools.memory_manager import save_learning, get_learnings
from tools.reporter import generate_bug_report
from bot_utils import send_telegram_notification, send_document

class ElengenixAgent:
    MAX_STEPS = 20

    ALLOWED_COMMANDS = [
        "subfinder", "httpx", "nuclei", "katana",
        "waybackurls", "curl", "nmap", "ffuf", "gau",
        "python3", "python", "grep", "cat", "ls", "echo"
    ]

    def __init__(self):
        self.client = LLMClient()
        self.base_dir = os.path.dirname(os.path.abspath(__file__))
        prompt_path = os.path.join(self.base_dir, "prompts", "system_prompt.txt")
        with open(prompt_path, "r") as f:
            self.base_prompt = f.read()
        self.knowledge = load_knowledge_base()

    def _build_prompt(self, target: str = "") -> str:
        memory_context = ""
        if target:
            learnings = get_learnings(target)
            if learnings and "No prior memory" not in learnings:
                memory_context = f"\n### MEMORY OF PREVIOUS ATTEMPTS ON {target}:\n{learnings}\n"

        tools_desc = f"""
### AVAILABLE TOOLS
You must respond with a JSON object. Always think about the technical impact before choosing an action.

{{"action": "run_shell", "command": "subfinder -d example.com -silent"}}
{{"action": "run_standard_scan", "target": "example.com"}}
{{"action": "search_web", "query": "CVE-2024 target-technology exploit"}}
{{"action": "read_web_page", "url": "https://example.com/api/v1"}}
{{"action": "save_memory", "target": "example.com", "category": "vuln|recon|bypass", "learning": "..."}}
{{"action": "finish", "summary": "Detailed technical report of the hunt..."}}

### PERSISTENCE RULES:
1. If 'run_standard_scan' finds nothing, use 'search_web' to find custom endpoints or specific technology vulnerabilities.
2. Chain your actions: search for secrets -> find endpoint -> try access bypass.
3. You have 20 steps. Do not waste them on simple greetings. Focus on the target.
"""
        return f"{self.base_prompt}\n{self.knowledge}\n{memory_context}\n{tools_desc}"

    def _execute_tool(self, action_data: dict, callback=None) -> str:
        action = action_data.get("action", "")
        try:
            if action == "run_shell":
                cmd = action_data.get("command", "")
                args = shlex.split(cmd)
                if args[0] not in self.ALLOWED_COMMANDS: return "Command not allowed."
                if callback: callback(f"Executing: {cmd}")
                result = subprocess.run(args, capture_output=True, text=True, timeout=120)
                return (result.stdout + result.stderr)[:4000]

            elif action == "run_standard_scan":
                target = action_data.get("target")
                if callback: callback(f"Initiating full Elengenix pipeline on {target}")
                run_standard_scan(target)
                return "Full scan finished. Check local reports for deep details."

            elif action == "search_web":
                from tools.research_tool import search_web
                query = action_data.get("query", "")
                if callback: callback(f"Searching web for intelligence: {query}")
                return str(search_web(query))

            elif action == "read_web_page":
                from tools.research_tool import extract_web_content
                return extract_web_content(action_data.get("url", ""))[:4000]

            elif action == "save_memory":
                save_learning(action_data["target"], action_data["learning"], action_data.get("category", "general"))
                return "Learning recorded in SQLite database."

            elif action == "finish": return "__FINISH__"
            return "Invalid action."

        except Exception as e: return f"Error: {str(e)}"

    def process_query(self, user_input: str, callback=None, target: str = "") -> str:
        send_telegram_notification(f"Analysis Started: \"{user_input}\"")
        history = [{"role": "user", "content": user_input}]
        
        for step in range(self.MAX_STEPS):
            history_text = "\n".join([f"{'User' if m['role'] == 'user' else 'Agent'}: {m['content']}" for m in history[-10:]])
            response_text = self.client.chat(self._build_prompt(target or user_input), history_text)
            
            if callback: callback(f"Step {step+1}: Analyzing...")

            if "{" in response_text and "}" in response_text:
                try:
                    json_start = response_text.find("{")
                    action_data = json.loads(response_text[json_start:response_text.rfind("}")+1])
                    
                    obs = self._execute_tool(action_data, callback)
                    if obs == "__FINISH__":
                        send_telegram_notification("Hunt Completed Successfully.")
                        return action_data.get("summary", "Task finished.")
                    
                    history.append({"role": "assistant", "content": response_text})
                    history.append({"role": "user", "content": f"Observation: {obs}"})
                    continue
                except: pass
            
            return response_text
        return "Reached maximum steps without conclusion."
