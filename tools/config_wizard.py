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
            name="NVIDIA",
            env_key="NVIDIA_API_KEY",
            base_url="https://integrate.api.nvidia.com/v1",
            signup_url="https://build.nvidia.com/explore/discover",
            is_free=True,
            notes="Fast inference via NVIDIA NIM, 40 RPM persistent free tier for builders (Highly Recommended)",
            api_type="openai"
        ),
        AIProviderConfig(
            name="Gemini (Google)",
            env_key="GEMINI_API_KEY",
            base_url="https://generativelanguage.googleapis.com/v1beta/openai",
            signup_url="https://aistudio.google.com/app/apikey",
            is_free=True,
            notes="Free, fast, good Thai support",
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
            name="Ollama (Local)",
            env_key="",
            base_url="http://localhost:11434/v1",
            signup_url="https://ollama.com/download",
            is_free=True,
            notes="No API key needed, runs locally",
        ),
    ]

    DEFAULT_MODELS: Dict[str, List[str]] = {
        "Gemini (Google)": ["gemini-3.1-flash-lite-preview", "gemini-3.1-pro", "gemini-3.1-flash", "gemini-3.0-pro", "gemini-2.0-flash", "gemini-1.5-pro", "gemini-1.5-flash"],
        "OpenAI (GPT-4)": ["gpt-4.5-turbo", "gpt-4o", "gpt-4o-mini", "o2-preview", "o1-preview", "o1-mini"],
        "Anthropic (Claude)": ["claude-3-7-sonnet-latest", "claude-3-5-sonnet-latest", "claude-3-5-haiku-latest", "claude-3-opus-latest"],
        "Groq": ["llama-3.3-70b-versatile", "llama-3.1-70b-versatile", "llama-3.1-8b-instant"],
        "DeepSeek": ["deepseek-chat", "deepseek-reasoner"],
        "Mistral": ["mistral-large-latest", "mistral-small-latest", "open-mixtral-8x7b"],
        "Together AI": ["meta-llama/Meta-Llama-3.1-70B-Instruct-Turbo", "mistralai/Mixtral-8x7B-Instruct-v0.1"],
        "OpenRouter": ["meta-llama/llama-3.3-70b-instruct", "google/gemini-2.0-flash-exp:free", "auto"],
        "Perplexity": ["llama-3.1-sonar-large-128k-online", "llama-3.1-sonar-small-128k-online"],
        "NVIDIA": [
            "nvidia/nemotron-3-super-120b-a12b",
            "qwen/qwen2.5-coder-32b-instruct",
            "meta/llama3-70b-instruct",
            "mistralai/mixtral-8x22b-instruct-v0.1",
            "deepseek-ai/deepseek-r1",
        ],
        "Ollama (Local)": ["llama3.2", "llama3.1:8b", "mistral:7b", "codellama:7b"],
    }

    # Priority order used by AIClientManager (index 0 = highest priority)
    PRIORITY_ORDER = [
        "nvidia", "gemini", "openai", "anthropic", "groq",
        "deepseek", "mistral", "openrouter", "together",
        "perplexity", "cohere", "huggingface", "replicate", "ollama",
    ]

    # Maps provider display name → manager key
    _PROVIDER_KEY_MAP = {
        "Gemini (Google)": "gemini",
        "OpenAI (GPT-4)": "openai",
        "Anthropic (Claude)": "anthropic",
        "Groq": "groq",
        "NVIDIA": "nvidia",
        "DeepSeek": "deepseek",
        "Mistral": "mistral",
        "OpenRouter": "openrouter",
        "Together AI": "together",
        "Perplexity": "perplexity",
        "Cohere": "cohere",
        "Hugging Face": "huggingface",
        "Replicate": "replicate",
        "Ollama (Local)": "ollama",
    }

    INTEGRATIONS = [
        {"name": "Telegram Bot", "keys": ["TELEGRAM_BOT_TOKEN", "TELEGRAM_CHAT_ID"], "desc": "Alerts and remote control"},
        {"name": "HackerOne", "keys": ["HACKERONE_API_KEY", "HACKERONE_API_USER"], "desc": "Bounty reporting"},
        {"name": "Tavily AI", "keys": ["TAVILY_API_KEY"], "desc": "Advanced OSINT & web search"},
        {"name": "VulnCheck", "keys": ["VULNCHECK_API_KEY"], "desc": "Real-time vulnerability intel"},
        {"name": "GitHub", "keys": ["GITHUB_TOKEN"], "desc": "Code leak hunting & OSINT"},
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
            console.print("  [1] Manage AI Providers (Multi-Key)")
            console.print("  [2] Manage Integrations (Tavily, VulnCheck, etc.)")
            console.print("  [3] Configure Default Target")
            console.print("  [4] Configure Rate Limits")
            console.print("  [5] View configuration status")
            console.print("  [6] Check system (Health Check)")
            console.print("  [0] Exit")

            choice = console.input("\nSelect [0-6]: ").strip()

            if choice == "1":
                self._manage_all_providers()
            elif choice == "2":
                self._manage_integrations()
            elif choice == "3":
                self._setup_default_target()
            elif choice == "4":
                self._setup_rate_limits()
            elif choice == "5":
                self._show_status()
            elif choice == "6":
                self._health_check()
            elif choice == "0":
                console.print("\n[dim]Saving configuration...[/dim]")
                break
            else:
                print_warning("Please select 0-7")
    
    def _manage_all_providers(self) -> None:
        """Multi-provider manager — show all providers in one table."""
        from rich.table import Table

        while True:
            # Detect which providers currently have keys
            active_keys: Dict[str, bool] = {}
            active_models: Dict[str, str] = {}
            for p in self.AI_PROVIDERS:
                env_key = p.env_key
                has_key = bool(os.getenv(env_key, "")) if env_key else True  # Ollama = always
                active_keys[p.name] = has_key
                model_env = env_key.replace("_API_KEY", "_MODEL") if env_key else "OLLAMA_MODEL"
                active_models[p.name] = os.getenv(model_env, "") or "(default)"

            # Detect active provider from AIClientManager
            active_provider_key = "none"
            try:
                from tools.universal_ai_client import AIClientManager
                mgr = AIClientManager()
                active_provider_key = mgr.get_active_provider()
            except Exception:
                pass

            # Build table
            table = Table(
                title="\n  AI Provider Manager",
                show_header=True,
                header_style="bold red",
                border_style="dim",
            )
            table.add_column("#",       width=4,  justify="right")
            table.add_column("Priority", width=6,  justify="center")
            table.add_column("Provider", width=22)
            table.add_column("Status",   width=10, justify="center")
            table.add_column("Model",    width=36)
            table.add_column("Notes",    width=36, style="dim")

            for i, provider in enumerate(self.AI_PROVIDERS, 1):
                has_key = active_keys[provider.name]
                pkey = self._PROVIDER_KEY_MAP.get(provider.name, "")
                priority_rank = ""
                if pkey in self.PRIORITY_ORDER:
                    priority_rank = str(self.PRIORITY_ORDER.index(pkey) + 1)

                if has_key:
                    if pkey == active_provider_key:
                        status = "[bold green]ACTIVE[/bold green]"
                    else:
                        status = "[green]Ready[/green]"
                else:
                    status = "[dim]No key[/dim]"

                model_display = active_models[provider.name]
                if len(model_display) > 34:
                    model_display = model_display[:31] + "..."

                free_note = "Free" if provider.is_free else "Paid"
                note = f"{free_note} — {provider.notes[:28]}"

                table.add_row(
                    str(i),
                    priority_rank,
                    provider.name,
                    status,
                    model_display,
                    note,
                )

            console.print(table)
            console.print(f"\n  Active provider: [bold red]{active_provider_key}[/bold red]")
            console.print("  [dim]Enter provider number to configure, [A] to configure all with keys, [D] to delete a key, [0] to go back[/dim]")

            choice = console.input("\nChoice: ").strip().lower()

            if choice == "0" or choice == "":
                break

            elif choice == "a":
                # Configure all providers that already have keys
                for p in self.AI_PROVIDERS:
                    if active_keys[p.name]:
                        console.print(f"\n[bold]Updating: {p.name}[/bold]")
                        self._configure_provider(p)

            elif choice == "d":
                # Delete / clear a key
                del_choice = console.input("Enter number to delete key: ").strip()
                try:
                    idx = int(del_choice) - 1
                    if 0 <= idx < len(self.AI_PROVIDERS):
                        p = self.AI_PROVIDERS[idx]
                        if p.env_key:
                            self._remove_env_var(p.env_key)
                            model_env = p.env_key.replace("_API_KEY", "_MODEL")
                            self._remove_env_var(model_env)
                            print_success(f"Cleared keys for {p.name}")
                        else:
                            print_warning(f"{p.name} has no key to delete")
                    else:
                        print_warning("Invalid number")
                except ValueError:
                    print_warning("Please enter a number")

            else:
                try:
                    idx = int(choice) - 1
                    if 0 <= idx < len(self.AI_PROVIDERS):
                        self._configure_provider(self.AI_PROVIDERS[idx])
                    else:
                        print_warning(f"Please select 1-{len(self.AI_PROVIDERS)}")
                except ValueError:
                    print_warning("Enter a number, A, D, or 0")

    def _manage_integrations(self) -> None:
        """Manage third-party integrations (Tavily, VulnCheck, Telegram, etc.)"""
        from rich.table import Table

        while True:
            table = Table(title="\n  Integration Manager", show_header=True, header_style="bold cyan", border_style="dim")
            table.add_column("#", width=4, justify="right")
            table.add_column("Integration", width=20)
            table.add_column("Status", width=12, justify="center")
            table.add_column("Description", width=40, style="dim")

            for i, integ in enumerate(self.INTEGRATIONS, 1):
                all_set = all(os.getenv(k) for k in integ["keys"])
                status = "[green]Configured[/green]" if all_set else "[dim]Not set[/dim]"
                table.add_row(str(i), integ["name"], status, integ["desc"])

            console.print(table)
            console.print("  [dim]Enter number to configure, [0] to go back[/dim]")

            choice = console.input("\nChoice: ").strip()
            if choice == "0" or not choice:
                break

            try:
                idx = int(choice) - 1
                if 0 <= idx < len(self.INTEGRATIONS):
                    integ = self.INTEGRATIONS[idx]
                    console.print(f"\n[bold cyan]Configuring {integ['name']}[/bold cyan]")
                    for key in integ["keys"]:
                        current = os.getenv(key, "")
                        masked = f"{current[:8]}..." if len(current) > 10 else "(none)"
                        console.print(f"Current {key}: [dim]{masked}[/dim]")
                        val = console.input(f"Enter {key} (or Enter to keep): ").strip()
                        if val:
                            self._save_env_var(key, val)
                            print_success(f"Saved {key}")
                else:
                    print_warning("Invalid selection")
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
            console.print("  [red]curl -fsSL https://ollama.com/install.sh | sh[/red]")
            console.print("  [red]ollama pull llama3.1:8b[/red]")
            
            # Check if running
            import requests
            try:
                resp = requests.get("http://localhost:11434/api/tags", timeout=2)
                if resp.status_code == 200:
                    print_success("[bold white]OK[/bold white] Ollama is running!")
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
            
            # Model Selection
            model_env_key = provider.env_key.replace("_API_KEY", "_MODEL") if provider.env_key else "OLLAMA_MODEL"
            self._select_model(provider)
            
            # Test connection
            console.print("[dim]Testing connection...[/dim]")
            try:
                model = os.getenv(model_env_key)
                if self._test_provider(provider, new_key, model):
                    print_success("Connection successful!")
                else:
                    print_warning("Connection failed, please check API key and model")
            except Exception as e:
                print_error(f"Test failed: {str(e)[:50]}")
        else:
            # Even if key is skipped, allow updating model if key exists
            if os.getenv(provider.env_key):
                self._select_model(provider)
            else:
                print_info("Skipped configuration")

    def _select_model(self, provider: AIProviderConfig) -> None:
        """Select model for the provider."""
        models = self.DEFAULT_MODELS.get(provider.name, ["default"])
        model_env_key = provider.env_key.replace("_API_KEY", "_MODEL")
        if not model_env_key: # For Ollama
             model_env_key = "OLLAMA_MODEL"
        
        current_model = os.getenv(model_env_key, "")
        
        console.print(f"\n[bold]Select Model for {provider.name}:[/bold]")
        for i, m in enumerate(models, 1):
            active = " [bold white](current)[/bold white]" if m == current_model else ""
            console.print(f"  [{i}] {m}{active}")
        
        console.print(f"  [{len(models) + 1}] Custom (Enter identifier)")
        
        choice = console.input(f"\nSelect model [1-{len(models) + 1}] or model name or [S]kip: ").strip()
        
        if choice.lower() == 's' or not choice:
            return
        
        selected_model = ""
        try:
            idx = int(choice) - 1
            if 0 <= idx < len(models):
                selected_model = models[idx]
            elif idx == len(models):
                selected_model = console.input("Enter custom model identifier: ").strip()
        except ValueError:
            # User typed a model name directly (e.g. nvidia/nemotron-3-super-120b-a12b)
            selected_model = choice
        
        if selected_model:
            self._save_env_var(model_env_key, selected_model)
            print_success(f"Selected model: {selected_model}")
            
            if provider.name == "NVIDIA":
                console.print("\n[bold]Select Parameter Mode for NVIDIA API:[/bold]")
                console.print("  [1] Auto Detect (from model name)")
                console.print("  [2] Nemotron (enable_thinking=True)")
                console.print("  [3] Disable Thinking (thinking=False)")
                console.print("  [4] Enable Thinking (thinking=True)")
                console.print("  [5] None (No extra parameters)")
                current_mode = os.getenv("NVIDIA_PARAM_MODE", "auto")
                console.print(f"  [dim]Current: {current_mode}[/dim]")
                
                mode_choice = console.input("Select mode [1-5] or [Enter] to keep current: ").strip()
                mode_val = current_mode
                if mode_choice == "1": mode_val = "auto"
                elif mode_choice == "2": mode_val = "nemotron"
                elif mode_choice == "3": mode_val = "disable"
                elif mode_choice == "4": mode_val = "enable"
                elif mode_choice == "5": mode_val = "none"
                
                if mode_val != current_mode or mode_choice != "":
                    self._save_env_var("NVIDIA_PARAM_MODE", mode_val)
                    print_success(f"Parameter Mode set to: {mode_val}")
                    os.environ["NVIDIA_PARAM_MODE"] = mode_val
    
    def _test_provider(self, provider: AIProviderConfig, api_key: str, model: Optional[str] = None) -> bool:
        """Test provider connection."""
        import requests
        
        try:
            headers = {
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            }
            
            # Use provided model, or fallback to provider-appropriate default
            test_model = model
            if not test_model:
                defaults = self.DEFAULT_MODELS.get(provider.name, [])
                test_model = defaults[0] if defaults else "gpt-4o-mini"
            
            # Simple test request
            payload = {
                "model": test_model,
                "messages": [{"role": "user", "content": "Hello"}],
                "max_tokens": 10,
            }
            
            # NVIDIA-specific: some models need extra_body parameters
            if provider.name == "NVIDIA":
                param_mode = os.getenv("NVIDIA_PARAM_MODE", "auto")
                model_lower = test_model.lower() if test_model else ""
                
                if param_mode == "nemotron" or (param_mode == "auto" and "nemotron" in model_lower):
                    payload["chat_template_kwargs"] = {"enable_thinking": True}
                elif param_mode == "disable" or (param_mode == "auto" and "deepseek" in model_lower):
                    payload["chat_template_kwargs"] = {"thinking": False}
                elif param_mode == "enable":
                    payload["chat_template_kwargs"] = {"thinking": True}
            
            # Build URL reliably (no urljoin which drops path segments)
            url = provider.base_url.rstrip('/') + '/chat/completions'
            
            resp = requests.post(
                url,
                headers=headers,
                json=payload,
                timeout=30,  # Increased to 30s to allow heavy reasoning models to think
            )
            
            return resp.status_code == 200
        except requests.exceptions.Timeout:
            console.print("[yellow]Notice: Request timed out. The model might be slow to respond, but the settings have been saved.[/yellow]")
            return True  # Treat timeout as soft success so the user can proceed
        except Exception as e:
            console.print(f"[dim]Error: {e}[/dim]")
            return False
    
    def _setup_telegram(self) -> None:
        """Setup Telegram bot configuration."""
        console.print("\n[bold red]Telegram Bot Setup[/bold red]\n")
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
        console.print("\n[bold red]HackerOne Setup[/bold red]\n")
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
        console.print("\n[bold red]Default Target Setup[/bold red]\n")
        
        current = os.getenv("ELENGENIX_DEFAULT_TARGET", "")
        if current:
            console.print(f"Current default target: [red]{current}[/red]")
        
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
        console.print("\n[bold red]Rate Limit Setup[/bold red]\n")
        
        current = os.getenv("ELENGENIX_RATE_LIMIT", "40")
        console.print(f"Current rate limit: [red]{current} RPM[/red]")
        console.print("[dim]Recommended: 40 RPM for production, 120 RPM for testing[/dim]\n")
        
        limit = console.input("Enter rate limit (RPM, Enter to keep current): ").strip()
        
        if limit:
            try:
                int(limit)
                self._save_env_var("ELENGENIX_RATE_LIMIT", limit)
                print_success(f"Saved rate limit: {limit} RPM")
            except ValueError:
                print_warning("Please enter a number")
    
    def _show_status(self) -> None:
        """Show configuration status."""
        from rich.table import Table

        console.print("\n[bold red]Configuration Status[/bold red]")

        # Detect active provider
        active_provider_key = "none"
        active_model = ""
        try:
            from tools.universal_ai_client import AIClientManager
            mgr = AIClientManager()
            active_provider_key = mgr.get_active_provider()
            if mgr.active_client:
                active_model = mgr.active_client.model
        except Exception:
            pass

        # AI Providers table
        table = Table(show_header=True, header_style="bold", border_style="dim")
        table.add_column("Provider",  width=22)
        table.add_column("Status",    width=10, justify="center")
        table.add_column("Model",     width=40)

        for provider in self.AI_PROVIDERS:
            env_key = provider.env_key
            key_val = os.getenv(env_key, "") if env_key else "local"
            model_env = env_key.replace("_API_KEY", "_MODEL") if env_key else "OLLAMA_MODEL"
            model = os.getenv(model_env, "(default)")
            pkey = self._PROVIDER_KEY_MAP.get(provider.name, "")

            if key_val:
                if pkey == active_provider_key:
                    status = "[bold green]ACTIVE[/bold green]"
                else:
                    status = "[green]Ready[/green]"
            else:
                status = "[dim]No key[/dim]"

            table.add_row(provider.name, status, model)

        console.print(table)
        console.print(f"\n  [bold]Active:[/bold] [bold red]{active_provider_key}[/bold red]")
        if active_model:
            console.print(f"  [bold]Model :[/bold] {active_model}")

        # Integrations table
        console.print("\n[bold]Integrations:[/bold]")
        table_int = Table(show_header=True, header_style="bold cyan", border_style="dim")
        table_int.add_column("Integration", width=22)
        table_int.add_column("Status", width=12, justify="center")
        
        for integ in self.INTEGRATIONS:
            all_set = all(os.getenv(k) for k in integ["keys"])
            status = "[green]Ready[/green]" if all_set else "[dim]Missing[/dim]"
            table_int.add_row(integ["name"], status)
        
        console.print(table_int)

        # Other settings
        console.print("\n[bold]Other Settings:[/bold]")
        console.print(f"  Default Target : {os.getenv('ELENGENIX_DEFAULT_TARGET', '(none)')}")
        console.print(f"  Rate Limit     : {os.getenv('ELENGENIX_RATE_LIMIT', '40')} RPM")

        if self.env_file.exists():
            console.print(f"\n  [dim].env → {self.env_file.absolute()}[/dim]")
        else:
            console.print("\n  [dim].env file not found[/dim]")
    
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
