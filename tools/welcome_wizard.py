"""tools/welcome_wizard.py

First-Run Welcome Wizard - Beautiful Apple-like Onboarding.

Purpose:
- Guide new users through initial setup in 30 seconds
- Auto-detect best configuration for user's environment
- One-command setup: configure AI, preferences, defaults
- Beautiful, minimal, friction-free experience

Persistence (important): choices are saved to the *runtime* config.yaml
(elengenix.paths.find_config order: $ELENGENIX_CONFIG -> ~/.elengenix/
-> ./config.yaml) using the schema tools.ai_config reads:

    ai:
      active_provider: <canonical id>
      providers:
        <canonical id>:
          model: <default model>

plus a `wizard:` section for preferences (default_mode, theme, ...).
`default_mode` is honored by main.py on bare runs, so what the user picks
here actually changes behavior. The old .config/elengenix/setup.json was
a write-only dead end (nothing ever read it) and is no longer written.

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
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from elengenix.paths import ELENGENIX_HOME
from elengenix.providers import catalog

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
    setup_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class WelcomeWizard:
    """
    Beautiful first-run welcome wizard.

    Apple-inspired design:
    - Clean, minimal visual style
    - Smart defaults (user just presses Enter)
    - Progress indicators with delightful animations
    - Context-aware suggestions
    """

    # Old write-only locations kept here only so `reset` can sweep them.
    LEGACY_SETUP_FILES = (
        Path(".config/elengenix/setup.json"),
        Path(".config/elengenix"),
        ELENGENIX_HOME / "setup.json",
    )
    BANNER_WIDTH = 60

    # Wizard display names -> canonical provider ids (derived from the
    # catalog; plain ids fall through _canonical_provider unchanged).
    _PROVIDER_ALIASES = {
        spec.display.lower(): spec.id for spec in catalog.iter_specs()
    }

    # Derived from the provider catalog (single source of truth:
    # elengenix/providers/catalog.py) — free tiers first, then by priority.
    # Tuple shape (display, env_key, tagline, recommended_model) kept for
    # the existing menu code.
    AI_PREFERENCES = [
        (
            spec.display,
            spec.env_key or "",
            spec.tagline,
            spec.recommended_model or spec.default_model,
        )
        for spec in sorted(catalog.iter_specs(), key=lambda s: (not s.is_free, s.priority))
    ]

    def __init__(self):
        self.config: Optional[SetupConfig] = None
        self.detected_providers: List[Tuple[str, str, str]] = []
        # Real runtime config — the same file tools.ai_config loads at startup.
        # Priority matches elengenix.paths.find_config(): env var > ~/.elengenix/.
        # Resolved per-instance so $ELENGENIX_CONFIG still works after import.
        self.CONFIG_FILE = Path(
            os.environ.get("ELENGENIX_CONFIG", "") or str(ELENGENIX_HOME / "config.yaml")
        ).expanduser()
        self.CONFIG_DIR = self.CONFIG_FILE.parent

    def _ensure_config_dir(self) -> None:
        """Ensure configuration directory exists."""
        self.CONFIG_DIR.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def _canonical_provider(name: str) -> str:
        """Map a wizard display name to the canonical provider id."""
        key = (name or "").strip().lower()
        return WelcomeWizard._PROVIDER_ALIASES.get(key, key)

    def _read_yaml(self) -> Dict[str, Any]:
        """Best-effort read of the runtime config ({} when absent/broken)."""
        if not self.CONFIG_FILE.exists():
            return {}
        try:
            import yaml

            data = yaml.safe_load(self.CONFIG_FILE.read_text(encoding="utf-8"))
            return data if isinstance(data, dict) else {}
        except Exception as e:
            logger.warning(f"Could not parse {self.CONFIG_FILE}: {e}")
            return {}

    def _maybe_migrate_legacy_setup(self) -> None:
        """One-time import of the old write-only setup.json.

        Users who ran the old wizard had their choices land in
        .config/elengenix/setup.json — a file nothing ever read, so they were
        silently dropped back into the wizard on every run. If that legacy
        file exists (and config.yaml carries no wizard section yet), lift its
        preferences into the runtime config.yaml and remove the stale file.
        """
        legacy = Path(".config/elengenix/setup.json")
        try:
            if not legacy.exists():
                return
            data = json.loads(legacy.read_text(encoding="utf-8"))
        except Exception as e:
            logger.debug(f"Ignoring unreadable legacy setup.json: {e}")
            return
        if not isinstance(data, dict) or not data.get("first_run_complete"):
            return

        config = SetupConfig(
            ai_provider=str(data.get("ai_provider") or ""),
            ai_model=str(data.get("ai_model") or ""),
            default_mode=str(data.get("default_mode") or "manual"),
            rate_limit=int(data.get("rate_limit") or 5),
            theme=str(data.get("theme") or "minimal"),
            auto_update=bool(data.get("auto_update", True)),
            telemetry=bool(data.get("telemetry", False)),
            first_run_complete=True,
            setup_at=str(data.get("setup_at") or datetime.now(timezone.utc).isoformat()),
        )
        self._save_config(config)
        try:
            legacy.unlink()
            parent = legacy.parent
            if parent.exists() and not any(parent.iterdir()):
                parent.rmdir()
                if parent.parent == Path(".config").resolve() and not any(
                    parent.parent.iterdir()
                ):
                    parent.parent.rmdir()
        except OSError as e:
            logger.debug(f"Legacy setup cleanup skipped: {e}")
        logger.info("Migrated legacy setup.json into %s", self.CONFIG_FILE)

    def _load_config(self) -> Optional[SetupConfig]:
        """Load wizard preferences from config.yaml.

        Mode/theme live in the `wizard:` section; the chosen provider/model
        live in the `ai:` section (runtime schema) and are joined back here.
        """
        # Import a legacy setup.json (if any) before the first read so the
        # migrated `ai`/`wizard` sections are visible below.
        self._maybe_migrate_legacy_setup()
        data = self._read_yaml()
        wiz = data.get("wizard", {})
        wiz = wiz if isinstance(wiz, dict) else {}
        ai = data.get("ai", {})
        ai = ai if isinstance(ai, dict) else {}
        provider = str(ai.get("active_provider") or "")
        model = ""
        providers = ai.get("providers")
        if isinstance(providers, dict):
            pc = providers.get(provider)
            if isinstance(pc, dict):
                model = str(pc.get("model") or "")
        if not wiz and not provider:
            # Nothing saved by this wizard AND nothing configured at all
            # (e.g. empty/new config) → genuinely a first run.
            return None
        # A config with a valid ai.active_provider (written by `configure`,
        # by hand, or by an older wizard) counts as configured: never nag
        # the user with the wizard again just because the `wizard:` section
        # is absent. Missing preferences fall back to the same defaults the
        # wizard itself uses.
        try:
            return SetupConfig(
                ai_provider=provider,
                ai_model=model,
                rate_limit=int(wiz.get("rate_limit") or 5),
                default_mode=str(wiz.get("default_mode") or ""),
                theme=str(wiz.get("theme") or "minimal"),
                auto_update=bool(wiz.get("auto_update", True)),
                telemetry=bool(wiz.get("telemetry", False)),
                first_run_complete=bool(wiz.get("first_run_complete", True)),
            )
        except Exception as e:
            logger.debug(f"Failed to load config: {e}")
            return None

    def _save_config(self, config: SetupConfig) -> None:
        """Persist setup into the runtime config.yaml (schema of tools.ai_config).

        Only the `ai` and `wizard` keys are managed here; everything else
        already present in the file is preserved untouched.
        """
        provider = self._canonical_provider(config.ai_provider)
        wizard_section: Dict[str, Any] = {
            "default_mode": config.default_mode,
            "rate_limit": config.rate_limit,
            "theme": config.theme,
            "auto_update": config.auto_update,
            "telemetry": config.telemetry,
            "setup_at": config.setup_at,
            "first_run_complete": config.first_run_complete,
        }
        ai_section: Dict[str, Any] = {
            "active_provider": provider,
            "providers": {provider: {"model": config.ai_model}},
        }

        merged = self._read_yaml()
        existing_ai = merged.get("ai")
        if isinstance(existing_ai, dict):
            providers = ai_section.get("providers", {})
            old_providers = existing_ai.get("providers")
            if isinstance(old_providers, dict):
                providers = {**old_providers, **providers}
            ai_section = {**existing_ai, **ai_section, "providers": providers}
        existing_wiz = merged.get("wizard")
        if isinstance(existing_wiz, dict):
            wizard_section = {**existing_wiz, **wizard_section}
        merged.update({"ai": ai_section, "wizard": wizard_section})

        self._ensure_config_dir()
        try:
            import yaml

            self.CONFIG_FILE.write_text(
                yaml.safe_dump(merged, sort_keys=False), encoding="utf-8"
            )
        except ImportError:
            logger.warning("PyYAML not installed — setup not persisted. Run: pip install pyyaml")

    def _detect_ai_providers(self) -> List[Tuple[str, str, str]]:
        """
        Auto-detect available AI providers from environment.

        Returns:
            List of (provider_name, env_key, status)
        """
        detected = []

        for name, env_key, desc, _ in self.AI_PREFERENCES:
            # One row per provider: "configured" when its key is set, else it
            # is only a recommendation (no duplicate rows).
            detected.append(
                (name, env_key, "configured" if os.getenv(env_key) else "available")
            )

        # Check Ollama (local)
        try:
            import requests

            resp = requests.get("http://localhost:11434/api/tags", timeout=2)
            if resp.status_code == 200:
                detected.append(("Ollama (Local)", "OLLAMA_URL", "running"))
        except Exception:
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
            except Exception:
                return options[0]
        else:
            default_str = f" [{default}]" if default else ""
            response = input(f"\n  {prompt}{default_str}: ").strip()
            return response if response else default

    def _show_spinner(self, message: str, duration: float = 1.0) -> None:
        """Show animated spinner (Rich status; no raw \\r writes that fight Rich Live)."""
        import os as _os

        if _os.environ.get("ELENGENIX_NO_ANIMATION", "") == "1":
            print(f"  [INFO] {message}")
            time.sleep(min(0.1, duration))
            return
        try:
            from cli.ui_components import show_spinner as _rich_spinner

            with _rich_spinner(f"  {message}"):
                time.sleep(duration)
        except Exception:
            import sys as _sys

            from tui.motion import SPINNER_DOTS as _frames

            end_time = time.time() + duration
            i = 0
            while time.time() < end_time:
                _sys.stdout.write(f"\r  {_frames[i % len(_frames)]} {message}")
                _sys.stdout.flush()
                time.sleep(0.1)
                i += 1
            _sys.stdout.write(f"\r   {message}{' ' * 20}\n")
            _sys.stdout.flush()

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
            self._print_suggestion(
                "Saved as your default: bare `elengenix` now opens Autonomous mode"
            )
        elif default_mode == "ai":
            self._print_suggestion("Saved as your default: bare `elengenix` now opens AI chat")

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
        print("  2. Set environment variable:")
        print(f"     export {env_key}=your_key_here")
        print("\n  Or add to .env file in this directory")

        # Ask for key now (optional) — EOF (piped/closed stdin) means skip
        try:
            key = input(f"\n  Paste {provider_name} API key (or Enter to skip): ").strip()
        except EOFError:
            key = ""
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
            "NVIDIA": "https://build.nvidia.com/explore/discover",
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
        """Save key to the .env file the runtime actually loads.

        elengenix.paths.find_env() looks in ~/.elengenix/ first, then CWD —
        writing only to CWD hid the key from pip-installed runs.
        """
        env_file = ELENGENIX_HOME / ".env"
        if Path(".env").exists():
            env_file = Path(".env").resolve()

        lines = []
        if env_file.exists():
            lines = env_file.read_text().splitlines()

        # Remove existing key
        lines = [line for line in lines if not line.startswith(f"{key}=")]

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
        print(f"    Saved to:     {self.CONFIG_FILE}")

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
            print("    $ elengenix hack")
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

        # UX: setup is a Q&A wizard — over a pipe (scripts, CI, `echo … |`)
        # it would silently eat the caller's input as answers and then
        # overwrite the config with defaults. Skip politely instead.
        import sys

        if not (sys.stdin.isatty() and sys.stdout.isatty()):
            print(
                "\n[elengenix] First-run setup skipped (non-interactive session).\n"
                "            Run `elengenix configure` in a terminal to set up later."
            )
            return None

        return self.run_setup()

    def reset_and_rerun(self) -> SetupConfig:
        """Reset configuration and run wizard again."""
        removed = []
        for path in (self.CONFIG_FILE, *self.LEGACY_SETUP_FILES):
            try:
                if path.is_dir() or not path.exists():
                    continue
                path.unlink()
                removed.append(str(path))
            except OSError as e:
                logger.debug(f"Could not remove {path}: {e}")
        if removed:
            print(f"\n  Removed: {', '.join(removed)}")

        print("\n  Configuration reset.")
        return self.run_setup()

    def get_config(self) -> Optional[SetupConfig]:
        """Get current configuration."""
        return self._load_config()

    @classmethod
    def get_saved_config(cls) -> Optional[SetupConfig]:
        """Read saved preferences without printing anything.

        Used by main.py to honor the wizard's default_mode on bare runs.
        """
        try:
            return cls()._load_config()
        except Exception:
            return None


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
