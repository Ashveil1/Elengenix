"""tools/config_wizard.py

Configuration Wizard - Interactive setup for Elengenix.

Purpose:
- Configure AI providers and API keys
- Set default preferences
- Initialize project settings
- Check configuration status
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

from ui_components import console, print_info, print_success, print_warning, print_error


@dataclass
class AIProviderConfig:
    """AI Provider configuration."""
    name: str
    env_key: str
    base_url: str
    signup_url: str
    is_free: bool
    notes: str
    api_type: str = "openai"  # "openai", "native", "azure"


class ConfigWizard:
    """Interactive configuration wizard."""
    
    AI_PROVIDERS = [
        AIProviderConfig(
            name="Gemini (Google)",
            env_key="GEMINI_API_KEY",
            base_url="https://generativelanguage.googleapis.com/v1beta/openai",
            signup_url="https://aistudio.google.com/app/apikey",
            is_free=True,
            notes="Free, fast, good Thai support (recommended)",
            api_type="native"
        ),
        AIProviderConfig(
            name="OpenAI (GPT-4)",
            env_key="OPENAI_API_KEY",
            base_url="https://api.openai.com/v1",
            signup_url="https://platform.openai.com/api-keys",
            is_free=False,
            notes="Most accurate but paid, requires credit card",
            api_type="openai"
        ),
        AIProviderConfig(
            name="Anthropic (Claude)",
            env_key="ANTHROPIC_API_KEY",
            base_url="https://api.anthropic.com/v1",
            signup_url="https://console.anthropic.com/settings/keys",
            is_free=False,
            notes="Excellent reasoning, Claude 3.5 Sonnet",
            api_type="native"
        ),
        AIProviderConfig(
            name="Groq",
            env_key="GROQ_API_KEY",
            base_url="https://api.groq.com/openai/v1",
            signup_url="https://console.groq.com/keys",
            is_free=True,
            notes="Very fast, Llama 3.1 free",
            api_type="openai"
        ),
        AIProviderConfig(
            name="Cohere",
            env_key="COHERE_API_KEY",
            base_url="https://api.cohere.ai/v1",
            signup_url="https://dashboard.cohere.com/api-keys",
            is_free=True,
            notes="Free tier available, good for text generation",
            api_type="native"
        ),
        AIProviderConfig(
            name="Hugging Face",
            env_key="HUGGINGFACE_API_KEY",
            base_url="https://api-inference.huggingface.co",
            signup_url="https://huggingface.co/settings/tokens",
            is_free=True,
            notes="Free inference for many models",
            api_type="native"
        ),
        AIProviderConfig(
            name="Together AI",
            env_key="TOGETHER_API_KEY",
            base_url="https://api.together.xyz/v1",
            signup_url="https://api.together.xyz/settings/api-keys",
            is_free=True,
            notes="Free tier, fast inference",
            api_type="openai"
        ),
        AIProviderConfig(
            name="Replicate",
            env_key="REPLICATE_API_TOKEN",
            base_url="https://api.replicate.com/v1",
            signup_url="https://replicate.com/account/api-tokens",
            is_free=True,
            notes="Pay-as-you-go, many open-source models",
            api_type="native"
        ),
        AIProviderConfig(
            name="Mistral",
            env_key="MISTRAL_API_KEY",
            base_url="https://api.mistral.ai/v1",
            signup_url="https://console.mistral.ai/api-keys",
            is_free=True,
            notes="Free tier, Mistral 7B/8x7B",
            api_type="openai"
        ),
        AIProviderConfig(
            name="DeepSeek",
            env_key="DEEPSEEK_API_KEY",
            base_url="https://api.deepseek.com/v1",
            signup_url="https://platform.deepseek.com/api_keys",
            is_free=True,
            notes="Very affordable, strong performance",
            api_type="openai"
        ),
        AIProviderConfig(
            name="Perplexity",
            env_key="PERPLEXITY_API_KEY",
            base_url="https://api.perplexity.ai",
            signup_url="https://www.perplexity.ai/settings/api",
            is_free=True,
            notes="Free tier, good for research",
            api_type="openai"
        ),
        AIProviderConfig(
            name="OpenRouter",
            env_key="OPENROUTER_API_KEY",
            base_url="https://openrouter.ai/api/v1",
            signup_url="https://openrouter.ai/keys",
            is_free=True,
            notes="Access to many models via one API",
            api_type="openai"
        ),
        AIProviderConfig(
            name="Azure OpenAI",
            env_key="AZURE_OPENAI_API_KEY",
            base_url="https://YOUR_RESOURCE.openai.azure.com",
            signup_url="https://portal.azure.com",
            is_free=False,
            notes="Enterprise OpenAI, requires Azure account",
            api_type="azure"
        ),
        AIProviderConfig(
            name="Ollama (Local)",
            env_key="",
            base_url="http://localhost:11434/v1",
            signup_url="https://ollama.com/download",
            is_free=True,
            notes="No API key needed, runs locally",
        ),
    ]
    
    def __init__(self, config_dir: Path = Path(".")):
        self.config_dir = config_dir
        self.env_file = config_dir / ".env"
    
    def run(self) -> None:
        """Run the configuration wizard."""
        console.print("""
╔════════════════════════════════════════════════════════════════╗
║            ELENGENIX CONFIGURATION WIZARD                    ║
╚════════════════════════════════════════════════════════════════╝
""")
        
        # Main menu
        while True:
            console.print("\n[bold]Select configuration:[/bold]")
            console.print("  [1] Configure AI Provider (API Keys)")
            console.print("  [2] Configure Telegram Bot")
            console.print("  [3] Configure HackerOne")
            console.print("  [4] Configure Default Target")
            console.print("  [5] Configure Rate Limits")
            console.print("  [6] View configuration status")
            console.print("  [7] Check system (Health Check)")
            console.print("  [0] Exit")
            
            choice = console.input("\nSelect [0-7]: ").strip()
            
            if choice == "1":
                self._setup_ai_provider()
            elif choice == "2":
                self._setup_telegram()
            elif choice == "3":
                self._setup_hackerone()
            elif choice == "4":
                self._setup_default_target()
            elif choice == "5":
                self._setup_rate_limits()
            elif choice == "6":
                self._show_status()
            elif choice == "7":
                self._health_check()
            elif choice == "0":
                console.print("\n[dim]Saving configuration...[/dim]")
                break
            else:
                print_warning("Please select 0-7")
    
    def _setup_ai_provider(self) -> None:
        """Setup AI provider and API key."""
        console.print("\n[bold cyan]AI Provider Setup[/bold cyan]\n")
        
        # Show available providers
        console.print("Select AI Provider:\n")
        for i, provider in enumerate(self.AI_PROVIDERS, 1):
            free_badge = "[green]Free[/green]" if provider.is_free else "[yellow]Paid[/yellow]"
            console.print(f"  [{i}] {provider.name}")
            console.print(f"      {free_badge} - {provider.notes}")
            console.print()
        
        choice = console.input(f"Select provider [1-{len(self.AI_PROVIDERS)}] or [S]kip: ").strip()
        
        if choice.lower() == 's':
            print_info("Skipped AI provider configuration")
            return
        
        try:
            idx = int(choice) - 1
            if 0 <= idx < len(self.AI_PROVIDERS):
                provider = self.AI_PROVIDERS[idx]
                self._configure_provider(provider)
            else:
                print_warning(f"Please select 1-{len(self.AI_PROVIDERS)}")
        except ValueError:
            print_warning("Please enter a number")
    
    def _configure_provider(self, provider: AIProviderConfig) -> None:
        """Configure specific provider."""
        console.print(f"\n[bold]{provider.name}[/bold]")
        console.print(f"[dim]Sign up: {provider.signup_url}[/dim]\n")
        
        if provider.name == "Ollama (Local)":
            # Ollama special setup
            print_info("Ollama requires no API key")
            console.print("\nInstall Ollama:")
            console.print("  [cyan]curl -fsSL https://ollama.com/install.sh | sh[/cyan]")
            console.print("  [cyan]ollama pull llama3.1:8b[/cyan]")
            
            # Check if running
            import requests
            try:
                resp = requests.get("http://localhost:11434/api/tags", timeout=2)
                if resp.status_code == 200:
                    print_success("[green]OK[/green] Ollama is running!")
                else:
                    print_warning("Ollama not responding")
            except:
                print_warning("Ollama not running, run 'ollama serve' first")
            
            # Save to .env
            self._save_env_var("OLLAMA_URL", "http://localhost:11434")
            return
        
        # Get API key
        current_key = os.getenv(provider.env_key, "")
        masked = f"{current_key[:8]}..." if len(current_key) > 10 else "(none)"
        
        console.print(f"Current API Key: [dim]{masked}[/dim]")
        new_key = console.input(f"Enter {provider.env_key} or [S]kip: ").strip()
        
        if new_key.lower() == 's':
            print_info("Skipped API key configuration")
            return
        
        if new_key:
            self._save_env_var(provider.env_key, new_key)
            print_success(f"Saved {provider.env_key}")
            
            # Test connection
            console.print("[dim]Testing connection...[/dim]")
            if self._test_provider(provider, new_key):
                print_success("Connection successful!")
            else:
                print_warning("Connection failed, please check API key")
        else:
            print_info("Skipped API key configuration")
    
    def _test_provider(self, provider: AIProviderConfig, api_key: str) -> bool:
        """Test provider connection."""
        import requests
        
        try:
            headers = {
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            }
            
            # Simple test request
            payload = {
                "model": provider.base_url.split("/")[-1] if "gemini" in provider.base_url else "gpt-4o-mini",
                "messages": [{"role": "user", "content": "Hello"}],
                "max_tokens": 10,
            }
            
            resp = requests.post(
                f"{provider.base_url}/chat/completions",
                headers=headers,
                json=payload,
                timeout=10,
            )
            
            return resp.status_code == 200
        except Exception as e:
            console.print(f"[dim]Error: {e}[/dim]")
            return False
    
    def _setup_telegram(self) -> None:
        """Setup Telegram bot configuration."""
        console.print("\n[bold cyan]Telegram Bot Setup[/bold cyan]\n")
        console.print("[dim]Get your bot token from @BotFather on Telegram[/dim]\n")
        
        # Bot Token
        current_token = os.getenv("TELEGRAM_BOT_TOKEN", "")
        masked_token = f"{current_token[:8]}..." if len(current_token) > 10 else "(none)"
        console.print(f"Current Bot Token: [dim]{masked_token}[/dim]")
        
        new_token = console.input("Enter TELEGRAM_BOT_TOKEN or [S]kip: ").strip()
        
        if new_token.lower() == 's':
            print_info("Skipped Telegram bot token")
        elif new_token:
            self._save_env_var("TELEGRAM_BOT_TOKEN", new_token)
            print_success("Saved TELEGRAM_BOT_TOKEN")
        else:
            print_info("Skipped Telegram bot token")
        
        # Chat ID
        current_chat = os.getenv("TELEGRAM_CHAT_ID", "")
        console.print(f"\nCurrent Chat ID: [dim]{current_chat or '(none)'}[/dim]")
        console.print("[dim]Get your chat ID from @userinfobot on Telegram[/dim]")
        
        new_chat = console.input("Enter TELEGRAM_CHAT_ID or [S]kip: ").strip()
        
        if new_chat.lower() == 's':
            print_info("Skipped Telegram chat ID")
        elif new_chat:
            self._save_env_var("TELEGRAM_CHAT_ID", new_chat)
            print_success("Saved TELEGRAM_CHAT_ID")
        else:
            print_info("Skipped Telegram chat ID")
    
    def _setup_hackerone(self) -> None:
        """Setup HackerOne configuration."""
        console.print("\n[bold cyan]HackerOne Setup[/bold cyan]\n")
        console.print("[dim]Get your API credentials from https://hackerone.com/settings/me[/dim]\n")
        
        # API Key
        current_key = os.getenv("HACKERONE_API_KEY", "")
        masked_key = f"{current_key[:8]}..." if len(current_key) > 10 else "(none)"
        console.print(f"Current API Key: [dim]{masked_key}[/dim]")
        
        new_key = console.input("Enter HACKERONE_API_KEY or [S]kip: ").strip()
        
        if new_key.lower() == 's':
            print_info("Skipped HackerOne API key")
        elif new_key:
            self._save_env_var("HACKERONE_API_KEY", new_key)
            print_success("Saved HACKERONE_API_KEY")
        else:
            print_info("Skipped HackerOne API key")
        
        # API User
        current_user = os.getenv("HACKERONE_API_USER", "")
        console.print(f"\nCurrent API User: [dim]{current_user or '(none)'}[/dim]")
        
        new_user = console.input("Enter HACKERONE_API_USER or [S]kip: ").strip()
        
        if new_user.lower() == 's':
            print_info("Skipped HackerOne API user")
        elif new_user:
            self._save_env_var("HACKERONE_API_USER", new_user)
            print_success("Saved HACKERONE_API_USER")
        else:
            print_info("Skipped HackerOne API user")

    def _setup_default_target(self) -> None:
        """Setup default target."""
        console.print("\n[bold cyan]Default Target Setup[/bold cyan]\n")
        
        current = os.getenv("ELENGENIX_DEFAULT_TARGET", "")
        if current:
            console.print(f"Current default target: [cyan]{current}[/cyan]")
        
        target = console.input("Enter default target or [S]kip: ").strip()
        
        if target.lower() == 's':
            print_info("Skipped default target configuration")
        elif target:
            self._save_env_var("ELENGENIX_DEFAULT_TARGET", target)
            print_success("Saved default target")
        else:
            print_info("Skipped default target configuration")
    
    def _setup_rate_limits(self) -> None:
        """Setup rate limits."""
        console.print("\n[bold cyan]Rate Limit Setup[/bold cyan]\n")
        
        current = os.getenv("ELENGENIX_RATE_LIMIT", "5")
        console.print(f"Current rate limit: [cyan]{current} req/s[/cyan]")
        console.print("[dim]Recommended: 5 for production, 10 for testing[/dim]\n")
        
        limit = console.input("Enter rate limit (req/s, Enter to keep current): ").strip()
        
        if limit:
            try:
                int(limit)
                self._save_env_var("ELENGENIX_RATE_LIMIT", limit)
                print_success(f"Saved rate limit: {limit} req/s")
            except ValueError:
                print_warning("Please enter a number")
    
    def _show_status(self) -> None:
        """Show configuration status."""
        console.print("\n[bold cyan]Configuration Status[/bold cyan]\n")
        
        # AI Providers
        console.print("[bold]AI Providers:[/bold]")
        for provider in self.AI_PROVIDERS:
            key = os.getenv(provider.env_key, "")
            status = "[green]Ready[/green]" if key else "[red]No API key[/red]"
            console.print(f"  {provider.name}: {status}")
        
        # Ollama check
        try:
            import requests
            resp = requests.get("http://localhost:11434/api/tags", timeout=2)
            ollama_status = "[green]Running[/green]" if resp.status_code == 200 else "[yellow]Not responding[/yellow]"
        except:
            ollama_status = "[yellow]Not found[/yellow]"
        console.print(f"  Ollama (Local): {ollama_status}")
        
        # Active provider
        try:
            from tools.universal_ai_client import AIClientManager
            manager = AIClientManager()
            active = manager.get_active_provider()
            console.print(f"\n[bold]Active Provider:[/bold] [cyan]{active}[/cyan]")
        except:
            console.print(f"\n[bold]Active Provider:[/bold] [yellow]Not configured[/yellow]")
        
        # Integrations
        console.print("\n[bold]Integrations:[/bold]")
        telegram_token = os.getenv("TELEGRAM_BOT_TOKEN", "")
        telegram_chat = os.getenv("TELEGRAM_CHAT_ID", "")
        telegram_status = "[green]Ready[/green]" if telegram_token and telegram_chat else "[red]Not configured[/red]"
        console.print(f"  Telegram Bot: {telegram_status}")
        
        hackerone_key = os.getenv("HACKERONE_API_KEY", "")
        hackerone_user = os.getenv("HACKERONE_API_USER", "")
        hackerone_status = "[green]Ready[/green]" if hackerone_key and hackerone_user else "[red]Not configured[/red]"
        console.print(f"  HackerOne: {hackerone_status}")
        
        # Other settings
        console.print("\n[bold]Other Settings:[/bold]")
        default_target = os.getenv("ELENGENIX_DEFAULT_TARGET", "(none)")
        rate_limit = os.getenv("ELENGENIX_RATE_LIMIT", "5")
        console.print(f"  Default Target: {default_target}")
        console.print(f"  Rate Limit: {rate_limit} req/s")
        
        # .env file status
        if self.env_file.exists():
            console.print(f"\n[green].env file exists:[/green] {self.env_file.absolute()}")
        else:
            console.print(f"\n[yellow].env file not found[/yellow]")
    
    def _health_check(self) -> None:
        """Run health check."""
        from tools.doctor import check_health
        check_health()
    
    def _save_env_var(self, key: str, value: str) -> None:
        """Save environment variable to .env file."""
        # Also set in current session
        os.environ[key] = value
        
        # Read existing
        lines = []
        if self.env_file.exists():
            lines = self.env_file.read_text().splitlines()
        
        # Remove existing line with same key
        lines = [l for l in lines if not l.startswith(f"{key}=")]
        
        # Add new line
        lines.append(f"{key}={value}")
        
        # Write back
        self.env_file.write_text("\n".join(lines) + "\n")
    
    def _remove_env_var(self, key: str) -> None:
        """Remove environment variable from .env file."""
        # Remove from current session
        if key in os.environ:
            del os.environ[key]
        
        # Read existing
        if not self.env_file.exists():
            return
        
        lines = self.env_file.read_text().splitlines()
        lines = [l for l in lines if not l.startswith(f"{key}=")]
        self.env_file.write_text("\n".join(lines) + "\n")


def run_config_wizard() -> None:
    """Entry point for configuration wizard."""
    wizard = ConfigWizard()
    wizard.run()
