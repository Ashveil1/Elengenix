import os
import json
import subprocess
import shlex
import logging
from pathlib import Path
from llm_client import LLMClient
from knowledge_loader import load_knowledge_base
from orchestrator import run_standard_scan
from tools.memory_manager import save_learning, get_learnings
from bot_utils import send_telegram_notification

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# 🛡️ RESTRICTED ALLOWLIST: Removed python/python3 to prevent sandbox escape
ALLOWED_COMMANDS = [
    "subfinder", "httpx", "nuclei", "katana",
    "waybackurls", "curl", "nmap", "ffuf", "gau",
    "grep", "cat", "ls", "echo"
]

class ElengenixAgent:
    MAX_STEPS = 20

    def __init__(self):
        self.client = LLMClient()
        self.base_dir = Path(__file__).parent.absolute()
        prompt_path = self.base_dir / "prompts" / "system_prompt.txt"
        
        try:
            with open(prompt_path, "r") as f:
                self.base_prompt = f.read()
        except FileNotFoundError:
            logger.error(f"System prompt not found at {prompt_path}")
            self.base_prompt = "You are a security assistant."
            
        self.knowledge = load_knowledge_base()

    def _is_safe_command(self, cmd: str) -> bool:
        try:
            parts = shlex.split(cmd)
            if not parts: return False
            binary = os.path.basename(parts[0])
            
            # Strict check against allowlist
            if binary not in ALLOWED_COMMANDS:
                logger.warning(f"Blocked unauthorized command: {binary}")
                return False
                
            # Block shell redirection and piping in arguments
            forbidden_chars = [">", ">>", "|", "&", ";", "`", "$"]
            if any(char in cmd for char in forbidden_chars):
                logger.warning(f"Blocked command with dangerous characters: {cmd}")
                return False
                
            return True
        except ValueError as e:
            logger.error(f"Command parsing error: {e}")
            return False

    def _execute_tool(self, action_data: dict, callback=None) -> str:
        action = action_data.get("action", "")
        try:
            if action == "run_shell":
                cmd_raw = action_data.get("command", "")
                if not self._is_safe_command(cmd_raw):
                    return f"Error: Command '{cmd_raw}' is not allowed or contains forbidden characters."
                
                if callback: callback(f"Executing: {cmd_raw}")
                # shell=False is strictly enforced here
                result = subprocess.run(shlex.split(cmd_raw), capture_output=True, text=True, timeout=180)
                return (result.stdout + result.stderr)[:4000]

            elif action == "run_standard_scan":
                target = action_data.get("target")
                if callback: callback(f"Starting standard pipeline on {target}")
                run_standard_scan(target)
                return "Full scan finished."

            elif action == "save_memory":
                save_learning(action_data["target"], action_data["learning"], action_data.get("category", "general"))
                return "Technical discovery saved to memory."

            elif action == "finish": return "__FINISH__"
            return "Unknown action."

        except subprocess.TimeoutExpired:
            return "Error: Execution timed out (180s)."
        except Exception as e:
            logger.error(f"Tool execution error: {e}")
            return f"Error: {str(e)}"

    def process_query(self, user_input: str, callback=None, target: str = "") -> str:
        send_telegram_notification(f"Task Started: \"{user_input}\"")
        history = [{"role": "user", "content": user_input}]
        
        for step in range(self.MAX_STEPS):
            history_text = "\n".join([f"{m['role']}: {m['content']}" for m in history[-10:]])
            system_prompt = f"{self.base_prompt}\n{self.knowledge}\n{self.get_tool_desc(target)}"
            
            response_text = self.client.chat(system_prompt, history_text)
            
            if "{" in response_text and "}" in response_text:
                try:
                    json_start = response_text.find("{")
                    action_data = json.loads(response_text[json_start:response_text.rfind("}")+1])
                    
                    obs = self._execute_tool(action_data, callback)
                    if obs == "__FINISH__":
                        return action_data.get("summary", "Mission completed.")
                    
                    history.append({"role": "assistant", "content": response_text})
                    history.append({"role": "user", "content": f"Observation: {obs}"})
                    continue
                except json.JSONDecodeError:
                    pass
            
            return response_text
        return "Max steps reached."

    def get_tool_desc(self, target):
        memory = get_learnings(target) if target else ""
        return f"\n### MEMORY:\n{memory}\n\n### TOOLS:\n- run_shell(command)\n- run_standard_scan(target)\n- save_memory(target, learning, category)\n- finish(summary)"
