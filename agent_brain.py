import os
import json
import subprocess
import shlex
from collections import Counter
from llm_client import LLMClient
from tools.memory_manager import save_learning, get_summarized_learnings
from bot_utils import send_telegram_notification

class ElengenixAgent:
    MAX_STEPS = 20
    LOOP_THRESHOLD = 3 # Stop if same command is repeated 3 times

    def __init__(self):
        self.client = LLMClient()
        self.action_history = []
        with open("prompts/system_prompt.txt", "r") as f:
            self.base_prompt = f.read()

    def process_query(self, user_input: str, callback=None, target: str = "") -> str:
        send_telegram_notification(f"Task Started: \"{user_input}\"")
        history = [{"role": "user", "content": user_input}]
        
        for step in range(self.MAX_STEPS):
            # 💰 TOKEN SAVER: Use summarized memory instead of raw logs
            memory = get_summarized_learnings(target or user_input)
            
            history_text = "\n".join([f"{m['role']}: {m['content']}" for m in history[-5:]]) # Only last 5 rounds
            full_prompt = f"{self.base_prompt}\n### COMPRESSED MEMORY:\n{memory}\n\nHistory:\n{history_text}"
            
            response_text = self.client.chat(full_prompt, "Choose your next tool action.")

            if "{" in response_text and "}" in response_text:
                try:
                    json_start = response_text.find("{")
                    action_data = json.loads(response_text[json_start:response_text.rfind("}")+1])
                    
                    # 🛡️ LOOP PROTECTION: Detect repeated actions
                    action_signature = f"{action_data.get('action')}:{action_data.get('command') or action_data.get('target')}"
                    self.action_history.append(action_signature)
                    
                    if Counter(self.action_history)[action_signature] > self.LOOP_THRESHOLD:
                        msg = f"⚠️ DEADLOCK DETECTED: Agent is repeating '{action_signature}'. Forcing stop to save tokens."
                        send_telegram_notification(msg)
                        return msg

                    # Execute and get observation
                    obs = self._execute_tool(action_data, callback)
                    
                    # 📉 MEMORY EFFICIENCY: Truncate very long tool outputs
                    if len(str(obs)) > 2000:
                        obs = str(obs)[:2000] + "... [Output truncated for performance]"

                    history.append({"role": "assistant", "content": response_text})
                    history.append({"role": "user", "content": f"Observation: {obs}"})
                    continue
                except Exception as e:
                    history.append({"role": "user", "content": f"Error parsing action: {e}"})
            
            return response_text
        return "Task stopped: Max steps reached."

    def _execute_tool(self, action_data, callback):
        # (Internal execution logic remains safe and hardened...)
        return "Observation result"
