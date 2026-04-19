import os
import json
import subprocess
from llm_client import LLMClient
from knowledge_loader import load_knowledge_base
from orchestrator import run_standard_scan
from tools.research_tool import search_web, extract_web_content
from tools.memory_manager import save_learning, get_learnings
from bot_utils import send_telegram_notification, send_document

class ElengenixAgent:
    def __init__(self):
        self.client = LLMClient()
        with open("prompts/system_prompt.txt", "r") as f:
            self.base_prompt = f.read()
        self.knowledge = load_knowledge_base()
        self.dangerous_keywords = ["rm ", "delete", "shutdown", "kill", "format", "> /dev/"]

    def get_full_prompt(self, target=""):
        # Fetch Memory for this target
        memory_context = ""
        if target:
            memory_context = f"\n### YOUR MEMORY OF {target}:\n{get_learnings(target)}\n"

        tools_desc = """
### 🛠️ YOUR POWERFUL TOOLSET:
... (standard tools) ...

1. **save_memory(target, learning)**: Use this to record a technical discovery or successful bypass.
   {"action": "save_memory", "target": "example.com", "learning": "Found hidden /dev/v1 endpoint via JS analysis."}
"""
        return f"{self.base_prompt}\n{self.knowledge}\n{memory_context}\n{tools_desc}"

    def execute_tool(self, action_data, callback=None):
        action = action_data.get("action")
        try:
            if action == "save_memory":
                target = action_data.get("target")
                learning = action_data.get("learning")
                save_learning(target, learning)
                return f"✅ Learning saved to memory for {target}."
            
            # ... (Rest of existing tools: run_shell, search_web, etc.) ...
            elif action == "run_shell":
                cmd = action_data.get("command")
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                return f"STDOUT: {result.stdout}"
            elif action == "run_standard_scan":
                target = action_data.get("target")
                results = run_standard_scan(target)
                return f"Scan complete at {results}"
            elif action == "search_web":
                return f"Links: {search_web(action_data.get('query'))}"
            elif action == "read_web_page":
                return extract_web_content(action_data.get("url"))
            elif action == "read_file":
                with open(action_data.get("path"), "r") as f: return f.read()
        
        except Exception as e:
            return f"❌ Tool Error: {str(e)}"

    def process_query(self, user_input, callback=None, target=""):
        history = f"User: {user_input}"
        send_telegram_notification(f"🧠 *Elengenix AI analysis started for* \"{user_input}\"")
        
        for i in range(3):
            # Prompt now includes Memory!
            full_prompt = f"{self.get_full_prompt(target)}\n\nHistory: {history}\n\nWhat is your next step?"
            response_text = self.client.chat(full_prompt, "")

            if "{" in response_text and "}" in response_text:
                try:
                    json_str = response_text[response_text.find("{"):response_text.rfind("}")+1]
                    action_data = json.loads(json_str)
                    
                    thought = response_text[:response_text.find("{")].strip()
                    if thought: send_telegram_notification(f"💭 *AI Thought:* {thought}")

                    observation = self.execute_tool(action_data, callback)
                    history += f"\nAI: {response_text}\nObservation: {observation}"
                    continue 
                except: pass
            
            send_telegram_notification(f"🏁 *Analysis Finished:*\\n\\n{response_text}")
            return response_text
