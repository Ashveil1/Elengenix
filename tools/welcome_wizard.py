"""tools/welcome_wizard.py

First-Run Welcome Wizard - Beautiful Apple-like Onboarding.

Purpose:
- Guide new users through initial setup in 30 seconds
- Auto-detect best configuration for user's environment
- One-command setup: configure AI, preferences, defaults
- Beautiful, minimal, friction-free experience

Philosophy:
- Wozniak simplicity: Works perfectly with minimal steps
- Apple beauty: Clean visuals, delightful micro-interactions
- Zero friction: Smart defaults, auto-detect, skip unnecessary steps

Usage:
    # Auto-triggered on first run
    from tools.welcome_wizard import WelcomeWizard
    wizard = WelcomeWizard()
    wizard.run_if_first_time()
    
    # Or force run
    wizard.run_setup()

Setup Steps:
    1. Detect environment & AI providers
    2. Configure best available AI (free first)
    3. Set sensible defaults
    4. Quick demo/test
    5. Show next steps
"""

from __future__ import annotations

import json
import logging
import os
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("elengenix.welcome")


@dataclass
class SetupConfig:
    """User's setup configuration."""
    ai_provider: str
    ai_model: str
    default_mode: str  # autonomous, ai, manual
    rate_limit: int
    theme: str  # minimal, detailed
    auto_update: bool
    telemetry: bool
    first_run_complete: bool = False
    setup_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())


class WelcomeWizard:
    """
    Beautiful first-run welcome wizard.
    
    Apple-inspired design:
    - Clean, minimal visual style
    - Smart defaults (user just presses Enter)
    - Progress indicators with delightful animations
    - Context-aware suggestions
    """
    
    CONFIG_FILE = Path(".config/elengenix/setup.json")
    BANNER_WIDTH = 60
    
    # AI Providers in order of preference (free → paid)
    AI_PREFERENCES = [
        ("Gemini (Google)", "GEMINI_API_KEY", "Free, fast", "gemini-2.0-flash"),
        ("Groq", "GROQ_API_KEY", "Very fast, free tier", "llama-3.1-70b"),
        ("OpenRouter", "OPENROUTER_API_KEY", "Multiple models", "auto"),
        ("OpenAI", "OPENAI_API_KEY", "Most accurate", "gpt-4o"),
        ("Anthropic", "ANTHROPIC_API_KEY", "Best reasoning", "claude-3-opus"),
    ]
    
    def __init__(self):
        self.config: Optional[SetupConfig] = None
        self.detected_providers: List[Tuple[str, str, str]] = []
        
    def _ensure_config_dir(self) -> None:
        """Ensure configuration directory exists."""
        self.CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
    
    def _load_config(self) -> Optional[SetupConfig]:
        """Load existing configuration."""
        if not self.CONFIG_FILE.exists():
            return None
        
        try:
            data = json.loads(self.CONFIG_FILE.read_text())
            return SetupConfig(**data)
        except Exception as e:
            logger.debug(f"Failed to load config: {e}")
            return None
    
    def _save_config(self, config: SetupConfig) -> None:
        """Save configuration."""
        self._ensure_config_dir()
        self.CONFIG_FILE.write_text(
            json.dumps(config.__dict__, indent=2),
            encoding="utf-8"
        )
    
    def _detect_ai_providers(self) -> List[Tuple[str, str, str]]:
        """
        Auto-detect available AI providers from environment.
        
        Returns:
            List of (provider_name, env_key, status)
        """
        detected = []
        
        for name, env_key, desc, _ in self.AI_PREFERENCES:
            if os.getenv(env_key):
                detected.append((name, env_key, "configured"))
            else:
                detected.append((name, env_key, "available"))
        
        # Check Ollama (local)
        try:
            import requests
            resp = requests.get("http://localhost:11434/api/tags", timeout=2)
            if resp.status_code == 200:
                detected.append(("Ollama (Local)", "OLLAMA_URL", "running"))
        except:
            detected.append(("Ollama (Local)", "OLLAMA_URL", "installable"))
        
        return detected
    
    def _print_header(self, title: str, step: int = 0, total: int = 0) -> None:
        """Print beautiful section header."""
        width = self.BANNER_WIDTH
        
        if step and total:
            progress = f"Step {step}/{total}"
            padding = width - len(title) - len(progress) - 4
            header = f"  {title}{ ' ' * padding }{progress}"
        else:
            padding = width - len(title) - 2
            header = f"  {title}{ ' ' * padding }"
        
        print(f"\n┌{'─' * width}┐")
        print(f"│{header}│")
        print(f"└{'─' * width}┘")
    
    def _print_success(self, message: str) -> None:
        """Print success indicator."""
        print(f"   {message}")
    
    def _print_info(self, message: str) -> None:
        """Print info message."""
        print(f"  • {message}")
    
    def _print_suggestion(self, message: str) -> None:
        """Print suggestion/tip."""
        print(f"  → {message}")
    
    def _ask_input(self, prompt: str, default: str = "", options: List[str] = None) -> str:
        """Ask user input with smart defaults."""
        if options:
            print(f"\n  {prompt}")
            for i, opt in enumerate(options, 1):
                marker = "→" if i == 1 else " "
                print(f"    {marker} [{i}] {opt}")
            
            try:
                choice = input(f"\n  Select [1-{len(options)}] or Enter for default: ").strip()
                if not choice:
                    return options[0]
                idx = int(choice) - 1
                if 0 <= idx < len(options):
                    return options[idx]
                return options[0]
            except:
                return options[0]
        else:
            default_str = f" [{default}]" if default else ""
            response = input(f"\n  {prompt}{default_str}: ").strip()
            return response if response else default
    
    def _show_spinner(self, message: str, duration: float = 1.0) -> None:
        """Show animated spinner."""
        import sys
        import time
        
        spinner = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏']
        end_time = time.time() + duration
        
        i = 0
        while time.time() < end_time:
            sys.stdout.write(f"\r  {spinner[i % len(spinner)]} {message}")
            sys.stdout.flush()
            time.sleep(0.1)
            i += 1
        
        sys.stdout.write(f"\r   {message}{' ' * 20}\n")
        sys.stdout.flush()
    
    def run_setup(self) -> SetupConfig:
        """
        Run complete welcome wizard.
        
        Returns:
            SetupConfig with user preferences
        """
        print("\n" + "=" * 64)
        print("  Welcome to Elengenix")
        print("  Autonomous Bug Bounty AI")
        print("=" * 64)
        
        print("\n  Let's get you set up in 30 seconds...")
        print("  (Press Enter to accept smart defaults)")
        
        # Step 1: Detect environment
        self._print_header("Detecting Your Environment", 1, 4)
        self._show_spinner("Checking system...", 0.8)
        
        self.detected_providers = self._detect_ai_providers()
        configured = [p for p in self.detected_providers if p[2] == "configured"]
        
        if configured:
            self._print_success(f"Found {len(configured)} configured AI provider(s)")
            for name, _, _ in configured:
                self._print_info(name)
        else:
            self._print_info("No AI providers configured yet")
        
        # Step 2: Configure AI
        self._print_header("AI Provider Setup", 2, 4)
        
        ai_provider = self._configure_ai_provider()
        
        # Step 3: Default Mode
        self._print_header("Choose Your Default Mode", 3, 4)
        
        print("\n  How do you prefer to work?")
        print()
        print("  [1] Autonomous — AI does everything (recommended)")
        print("      Just provide a target, AI finds bugs automatically")
        print()
        print("  [2] AI Assistant — Chat with AI for guidance")
        print("      Ask questions, get suggestions, work together")
        print()
        print("  [3] Manual — Traditional CLI commands")
        print("      Full control, run commands yourself")
        
        mode_choice = self._ask_input("Select mode", "1", ["1", "2", "3"])
        modes = {"1": "autonomous", "2": "ai", "3": "manual"}
        default_mode = modes.get(mode_choice, "autonomous")
        
        self._print_success(f"Default mode: {default_mode}")
        
        # Show mode-specific tip
        if default_mode == "autonomous":
            self._print_suggestion("Try: elengenix autonomous https://target.com")
        elif default_mode == "ai":
            self._print_suggestion("Try: elengenix ai")
        
        # Step 4: Preferences
        self._print_header("Quick Preferences", 4, 4)
        
        # Smart defaults
        rate_limit = 5
        theme = "minimal"
        auto_update = True
        
        # Only ask if user seems advanced (has providers configured)
        if configured:
            print("\n  Using smart defaults:")
            self._print_info(f"Rate limit: {rate_limit} req/s (safe for most targets)")
            self._print_info(f"Theme: {theme} (clean output)")
            self._print_info("Auto-update: enabled")
        
        # Save configuration
        self._print_header("Saving Configuration")
        
        config = SetupConfig(
            ai_provider=ai_provider,
            ai_model=self._get_model_for_provider(ai_provider),
            default_mode=default_mode,
            rate_limit=rate_limit,
            theme=theme,
            auto_update=auto_update,
            telemetry=False,  # Privacy first
            first_run_complete=True,
        )
        
        self._save_config(config)
        self._show_spinner("Saving settings...", 0.5)
        
        # Final: Show quick demo + next steps
        self._show_completion(config)
        
        return config
    
    def _configure_ai_provider(self) -> str:
        """Configure AI provider with smart defaults."""
        configured = [(n, d) for n, _, d in self.detected_providers if d == "configured"]
        available = [(n, d) for n, _, d in self.detected_providers if d != "configured"]
        
        if configured:
            # Auto-pick first configured, but show all
            print(f"\n   Using: {configured[0][0]}")
            
            if len(configured) > 1:
                print("\n  Other configured providers:")
                for name, _ in configured[1:]:
                    print(f"    • {name}")
            
            return configured[0][0]
        
        # No providers configured - recommend free options
        print("\n  No AI providers configured yet.")
        print("\n  Recommended (Free):")
        
        for i, (name, env_key, desc, _) in enumerate(self.AI_PREFERENCES[:3], 1):
            signup_url = self._get_signup_url(name)
            print(f"  [{i}] {name}")
            print(f"      {desc}")
            print(f"      Sign up: {signup_url}")
            print()
        
        print("  [4] Ollama (Local, Free)")
        print("      Runs AI on your machine, no API key needed")
        print("      Install: curl -fsSL https://ollama.com/install.sh | sh")
        print()
        
        choice = self._ask_input("Select provider to configure", "1", ["1", "2", "3", "4"])
        
        if choice == "4":
            print("\n  To set up Ollama:")
            print("  1. curl -fsSL https://ollama.com/install.sh | sh")
            print("  2. ollama pull llama3.1:8b")
            print("  3. ollama serve")
            print("\n  Then run Elengenix again!")
            return "Ollama (Local)"
        
        # Show API key setup for selected provider
        selected = self.AI_PREFERENCES[int(choice) - 1]
        provider_name, env_key, desc, model = selected
        
        print(f"\n  To configure {provider_name}:")
        print(f"  1. Get API key: {self._get_signup_url(provider_name)}")
        print(f"  2. Set environment variable:")
        print(f"     export {env_key}=your_key_here")
        print(f"\n  Or add to .env file in this directory")
        
        # Ask for key now (optional)
        key = input(f"\n  Paste {provider_name} API key (or Enter to skip): ").strip()
        if key:
            os.environ[env_key] = key
            # Save to .env
            self._save_to_env(env_key, key)
            print(f"   {provider_name} configured!")
        
        return provider_name
    
    def _get_signup_url(self, provider: str) -> str:
        """Get signup URL for provider."""
        urls = {
            "Gemini (Google)": "https://aistudio.google.com/app/apikey",
            "Groq": "https://console.groq.com/keys",
            "OpenRouter": "https://openrouter.ai/keys",
            "OpenAI": "https://platform.openai.com/api-keys",
            "Anthropic": "https://console.anthropic.com/settings/keys",
        }
        return urls.get(provider, "provider website")
    
    def _get_model_for_provider(self, provider: str) -> str:
        """Get default model for provider."""
        for name, _, _, model in self.AI_PREFERENCES:
            if name == provider:
                return model
        return "auto"
    
    def _save_to_env(self, key: str, value: str) -> None:
        """Save key to .env file."""
        env_file = Path(".env")
        
        lines = []
        if env_file.exists():
            lines = env_file.read_text().splitlines()
        
        # Remove existing key
        lines = [l for l in lines if not l.startswith(f"{key}=")]
        
        # Add new key
        lines.append(f"{key}={value}")
        
        env_file.write_text("\n".join(lines) + "\n", encoding="utf-8")
    
    def _show_completion(self, config: SetupConfig) -> None:
        """Show completion screen with next steps."""
        print("\n" + "=" * 64)
        print("   Setup Complete!")
        print("=" * 64)
        
        print("\n  Your configuration:")
        print(f"    AI Provider:  {config.ai_provider}")
        print(f"    Default Mode: {config.default_mode}")
        print(f"    Rate Limit:   {config.rate_limit} req/s")
        
        print("\n" + "─" * 64)
        print("  Quick Start:")
        print("─" * 64)
        
        if config.default_mode == "autonomous":
            print("\n  Try your first autonomous scan:")
            print("    $ elengenix autonomous https://example.com")
            print("\n  Or with auto-approval (faster):")
            print("    $ elengenix autonomous https://example.com --mode auto")
        
        elif config.default_mode == "ai":
            print("\n  Start chatting with AI:")
            print("    $ elengenix ai")
            print("\n  Then try asking:")
            print('    > "How do I find IDOR vulnerabilities?"')
            print('    > "Research CVE-2024-21626 for me"')
        
        else:
            print("\n  Available commands:")
            print("    $ elengenix scan <target>       # Quick scan")
            print("    $ elengenix research CVE-XXXX   # Research CVE")
            print("    $ elengenix poc rce             # Generate PoC")
        
        print("\n  Get help anytime:")
        print("    $ elengenix help")
        print("    $ elengenix doctor              # Check system")
        
        print("\n" + "=" * 64)
        print("  Happy hunting! ")
        print("=" * 64 + "\n")
    
    def run_if_first_time(self) -> Optional[SetupConfig]:
        """
        Run wizard only if first time (no config exists).
        
        Returns:
            SetupConfig if run, None if already configured
        """
        existing = self._load_config()
        
        if existing and existing.first_run_complete:
            logger.debug("Setup already complete, skipping wizard")
            return None
        
        return self.run_setup()
    
    def reset_and_rerun(self) -> SetupConfig:
        """Reset configuration and run wizard again."""
        if self.CONFIG_FILE.exists():
            self.CONFIG_FILE.unlink()
        
        print("\n  Configuration reset.")
        return self.run_setup()
    
    def get_config(self) -> Optional[SetupConfig]:
        """Get current configuration."""
        return self._load_config()


def run_cli():
    """CLI entry point for welcome wizard."""
    import sys
    
    wizard = WelcomeWizard()
    
    if len(sys.argv) > 1 and sys.argv[1] == "--reset":
        wizard.reset_and_rerun()
    else:
        wizard.run_setup()


if __name__ == "__main__":
    run_cli()
