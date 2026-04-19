"""
agent_brain.py — Elengenix Upgraded Agent (v1.2)
- Autonomous loop up to 20 rounds
- Enterprise-grade safety allowlist
- SQLite-powered memory
- Full toolset integration
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

    DANGEROUS_PATTERNS = [
        "rm -rf", "mkfs", "dd if=", "shutdown", "reboot",
        "> /dev/", "format c:", ":(){:|:&};:", "wget|sh",
        "curl|bash", "chmod 777 /", "chown root"
    ]

    def __init__(self):
        self.client = LLMClient()
        # Fix path for prompts
        self.base_dir = os.path.dirname(os.path.abspath(__file__))
        prompt_path = os.path.join(self.base_dir, "prompts", "system_prompt.txt")
        with open(prompt_path, "r") as f:
            self.base_prompt = f.read()
        self.knowledge = load_knowledge_base()

    def _is_safe_command(self, cmd: str) -> bool:
        cmd_lower = cmd.lower().strip()
        for pattern in self.DANGEROUS_PATTERNS:
            if pattern in cmd_lower: return False
        try:
            parts = shlex.split(cmd)
            if not parts: return False
            binary = os.path.basename(parts[0])
            return binary in self.ALLOWED_COMMANDS
        except: return False

    def _build_prompt(self, target: str = "") -> str:
        memory_context = ""
        if target:
            learnings = get_learnings(target)
            if learnings and "No prior memory" not in learnings:
                memory_context = f"\n### 🧠 YOUR MEMORY OF {target}:\n{learnings}\n"

        tools_desc = f"""
### 🛠️ YOUR TOOLSET
Respond ONLY with a single JSON object to use a tool. Think out loud BEFORE the JSON.

{{"action": "run_shell", "command": "subfinder -d example.com -silent"}}
{{"action": "run_standard_scan", "target": "example.com"}}
{{"action": "search_web", "query": "CVE-2024 example.com bypass"}}
{{"action": "read_web_page", "url": "https://example.com/api"}}
{{"action": "read_file", "path": "reports/example_com/nuclei.txt"}}
{{"action": "save_memory", "target": "example.com", "category": "endpoint|secret|bypass|vuln|recon", "learning": "Found /api/v2 leaking user data"}}
{{"action": "generate_report", "target": "example.com", "findings": ["XSS on /search", "API key in JS"]}}
{{"action": "finish", "summary": "Completed. Found 2 issues: ..."}}

### RULES:
1. Think step by step BEFORE every action
2. save_memory after EVERY important finding
3. Use finish when done — max {self.MAX_STEPS} steps
4. Only use allowed shell commands.
"""
        return f"{self.base_prompt}\n{self.knowledge}\n{memory_context}\n{tools_desc}"

    def _execute_tool(self, action_data: dict, callback=None) -> str:
        action = action_data.get("action", "")
        try:
            if action == "save_memory":
                save_learning(action_data["target"], action_data["learning"], action_data.get("category", "general"))
                return f"✅ Memory saved."

            elif action == "run_shell":
                cmd = action_data.get("command", "")
                if not self._is_safe_command(cmd): return "🚫 BLOCKED: Dangerous command."
                if callback: callback(f"💻 Executing: `{cmd}`")
                result = subprocess.run(shlex.split(cmd), capture_output=True, text=True, timeout=90)
                return (result.stdout + result.stderr)[:4000] or "(no output)"

            elif action == "run_standard_scan":
                target = action_data.get("target")
                if callback: callback(f"🚀 AI Action: Running standard scan on {target}")
                results = run_standard_scan(target)
                return f"✅ Scan complete."

            elif action == "search_web":
                from tools.research_tool import search_web
                return str(search_web(action_data.get("query", "")))

            elif action == "read_web_page":
                from tools.research_tool import extract_web_content
                return extract_web_content(action_data.get("url", ""))[:3000]

            elif action == "read_file":
                path = action_data.get("path", "")
                if ".." in path: return "🚫 BLOCKED: Path traversal."
                with open(path, "r") as f: return f.read()[:4000]

            elif action == "generate_report":
                from tools.reporter import generate_bug_report
                report_path = f"reports/{action_data['target']}_summary.md"
                generate_bug_report(action_data["target"], [], report_path)
                return f"✅ Report saved: {report_path}"

            elif action == "__FINISH__": return "__FINISH__"
            return f"❓ Unknown action: {action}"

        except Exception as e: return f"❌ Error: {str(e)}"

    def process_query(self, user_input: str, callback=None, target: str = "") -> str:
        send_telegram_notification(f"🧠 *Elengenix AI v1.2 started*\nTarget: `{target or 'N/A'}`")
        history = [{"role": "user", "content": user_input}]
        final_answer = "⚠️ Agent stopped."

        for step in range(self.MAX_STEPS):
            step_label = f"Step {step + 1}/{self.MAX_STEPS}"
            history_text = "\n".join([f"{'User' if m['role'] == 'user' else 'Agent'}: {m['content']}" for m in history[-10:]])
            
            response_text = self.client.chat(self._build_prompt(target), history_text)
            if callback: callback(f"[{step_label}] {response_text[:300]}")

            if '"action": "finish"' in response_text:
                send_telegram_notification(f"✅ *Mission Completed*")
                return response_text

            if "{" in response_text and "}" in response_text:
                try:
                    json_start = response_text.find("{")
                    action_data = json.loads(response_text[json_start:response_text.rfind("}")+1])
                    thought = response_text[:json_start].strip()
                    if thought: send_telegram_notification(f"💭 {step_label}: {thought[:300]}")
                    
                    obs = self._execute_tool(action_data, callback)
                    history.append({"role": "assistant", "content": response_text})
                    history.append({"role": "user", "content": f"Observation: {obs}"})
                    continue
                except: pass
            
            return response_text
        return final_answer
