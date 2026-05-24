import json
import os
import requests
from typing import List, Dict, Any, Optional
from .config import GEMINI_API_KEY, OPENAI_API_KEY, NVIDIA_API_KEY, CUSTOM_API_KEY, CUSTOM_API_BASE

class LLMClient:
    """A clean, minimal, multi-provider LLM client using direct HTTP calls."""
    
    def __init__(self, provider: str = "gemini", model: Optional[str] = None, api_key: Optional[str] = None, base_url: Optional[str] = None):
        self.provider = provider.lower() if provider else "gemini"
        self.timeout = 180
        
        # Configure defaults for endpoints, API keys, and models
        if self.provider == "gemini":
            self.base_url = "https://generativelanguage.googleapis.com/v1beta/openai/v1/chat/completions"
            self.api_key = GEMINI_API_KEY
            self.model = "gemini-1.5-flash"
        elif self.provider == "openai":
            self.base_url = "https://api.openai.com/v1/chat/completions"
            self.api_key = OPENAI_API_KEY
            self.model = "gpt-4o-mini"
        elif self.provider == "nvidia":
            self.base_url = "https://integrate.api.nvidia.com/v1/chat/completions"
            self.api_key = NVIDIA_API_KEY
            self.model = "nvidia/nemotron-3-super-120b-a12b"
        elif self.provider == "custom":
            self.base_url = CUSTOM_API_BASE or ""
            self.api_key = CUSTOM_API_KEY
            self.model = "custom-model"
        elif self.provider == "anthropic":
            self.base_url = "https://api.anthropic.com/v1/messages"
            self.api_key = os.getenv("ANTHROPIC_API_KEY")
            self.model = "claude-3-5-sonnet-latest"
        else:
            # Fallback to local Ollama
            self.base_url = "http://localhost:11434/v1/chat/completions"
            self.api_key = ""
            self.model = "llama3.2"

        # Override with environment variable if present (allows persistent config)
        env_model = os.getenv(f"{self.provider.upper()}_MODEL")
        if env_model:
            self.model = env_model

        # Apply overrides if provided by the user during setup wizard
        if model:
            self.model = model
        if api_key:
            self.api_key = api_key
        if base_url:
            self.base_url = base_url

    def chat(self, messages: List[Dict[str, str]], temperature: float = 0.5, fast: bool = False) -> str:
        """
        Send chat message to the active provider and return the response text.
        fast=True disables extended reasoning modes (e.g. Nemotron thinking) for speed.
        """
        if not self.api_key and self.provider != "ollama":
            return f"Error: API Key not configured for provider '{self.provider}'."

        if self.provider == "anthropic":
            return self._call_anthropic(messages, temperature)
            
        # Standard OpenAI-compatible format
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}"
        } if self.api_key else {"Content-Type": "application/json"}
        
        payload = {
            "model": self.model,
            "messages": messages,
            "temperature": temperature
        }

        # Nemotron reasoning — disable in fast mode (used for Strategist planning)
        if self.provider == "nvidia" and "nemotron" in self.model.lower():
            payload["chat_template_kwargs"] = {"enable_thinking": not fast}
            
        try:
            response = requests.post(self.base_url, json=payload, headers=headers, timeout=self.timeout)
            response.raise_for_status()
            data = response.json()
            return data["choices"][0]["message"]["content"]
        except Exception as e:
            return f"Error contacting provider '{self.provider}': {str(e)}"

    def _call_anthropic(self, messages: List[Dict[str, str]], temperature: float) -> str:
        """Handle Anthropic specific API structure."""
        system_prompt = ""
        formatted_messages = []
        
        for msg in messages:
            if msg["role"] == "system":
                system_prompt = msg["content"]
            else:
                formatted_messages.append({"role": msg["role"], "content": msg["content"]})
                
        headers = {
            "Content-Type": "application/json",
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01"
        }
        
        payload = {
            "model": self.model,
            "max_tokens": 4096,
            "messages": formatted_messages,
            "temperature": temperature
        }
        if system_prompt:
            payload["system"] = system_prompt
            
        try:
            response = requests.post(self.base_url, json=payload, headers=headers, timeout=self.timeout)
            response.raise_for_status()
            data = response.json()
            return data["content"][0]["text"]
        except Exception as e:
            return f"Error contacting Anthropic: {str(e)}"
