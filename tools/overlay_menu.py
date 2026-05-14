"""
tools/overlay_menu.py -- Settings Overlay (Ctrl+E)
====================================================
State-driven overlay rendered inside the main Live layout.
Usage:
    overlay = SettingsOverlay(agent, console, target)
    overlay.handle_char(ch)  # Process keyboard input
    panel = overlay.render()  # Build Rich panel for display
"""

import os
import re
import json
import time
import logging
from pathlib import Path
from typing import Optional, List, Dict, Tuple

from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.align import Align
from rich.box import ROUNDED

logger = logging.getLogger("elengenix.overlay")

MENU_ITEMS = [
    {"id": "sessions", "label": "Sessions", "icon": "[S]"},
    {"id": "agent_setup", "label": "Agent Setup", "icon": "[1]"},
    {"id": "api_keys", "label": "API Keys", "icon": "[2]"},
    {"id": "rate_limits", "label": "Rate Limits", "icon": "[3]"},
    {"id": "skills", "label": "Skills & Tools", "icon": "[4]"},
    {"id": "mode_settings", "label": "Mode Settings", "icon": "[5]"},
]


class SettingsOverlay:
    """State-driven settings overlay. Call handle_char() for input, render() for output."""

    def __init__(self, agent, console: Console, target: str = ""):
        self.agent = agent
        self.console = console
        self.target = target
        self.reset()

    def reset(self) -> None:
        """Reset overlay state."""
        self._current_layer = "main"
        self._selected_idx = 0
        self._search = ""
        self._agent_config: List[Dict[str, str]] = self._load_agent_config()
        self._rate_limits = [40, 40, 40]
        self._api_keys_dirty: Dict[str, str] = {}
        self._model_cache: Dict[str, Tuple[float, List[str]]] = {}
        self._agent_idx = 0
        self._current_provider = ""
        self._editing_provider = ""
        self._items: List[Dict] = []
        self._update_items()

    def handle_char(self, ch: str) -> Optional[str]:
        """Process a single key character. Returns 'exit', 'saved', 'error', or None."""
        # Arrow keys - must have full escape sequence
        if ch == "\x1b[A" or ch == "\x1b[OA":
            self._selected_idx = max(0, self._selected_idx - 1)
            return None
        if ch == "\x1b[B" or ch == "\x1b[OB":
            self._selected_idx = min(len(self._items) - 1, self._selected_idx + 1)
            return None
        if ch == "\x1b[C" or ch == "\x1b[OC":
            return None
        if ch == "\x1b[D" or ch == "\x1b[OD":
            return None
        # Vim-style navigation: j=down, k=up
        if ch == "j":
            self._selected_idx = min(len(self._items) - 1, self._selected_idx + 1)
            return None
        if ch == "k":
            self._selected_idx = max(0, self._selected_idx - 1)
            return None
        # Enter
        if ch in ("\r", "\n"):
            return self._handle_enter()
        # Esc - if it's a bare ESC (length 1), exit
        if ch == "\x1b" and len(ch) == 1:
            if self._current_layer == "main":
                return "exit"
            return self._go_back()
        # B for back
        if ch.lower() == "b":
            if self._current_layer == "main":
                return "exit"
            self._go_back()
            return None
        # Q to quit overlay
        if ch.lower() == "q":
            return "exit"

        return None

    def render(self) -> Panel:
        """Build a Rich Panel representing the current overlay state."""
        # Approximate panel width
        try:
            width = min(int(self.console.width * 0.7), 78)
        except AttributeError:
            width = 70
        if width < 30:
            width = 30

        # Build title
        title = self._get_title()
        lines = Text()
        lines.append(f"\n{title}\n", style="bold #ff4444")
        lines.append("=" * 40 + "\n\n", style="#ff4444")

        # Build items
        for i, item in enumerate(self._items):
            label = item.get("label", "???")
            if not label:
                lines.append("\n")
                continue
            is_selected = (i == self._selected_idx)
            if is_selected:
                prefix = " >"
                style = "bold #ff4444 on #1a1a1a"
            else:
                prefix = "  "
                style = "white on #0a0a0a"
            lines.append(f"{prefix} {label}\n", style=style)

        # Footer
        lines.append("\n")
        if self._current_layer == "main":
            lines.append("[j/k or Arrow: Navigate]  [Enter: Select]  [q/B: Exit]\n", style="dim")
        else:
            lines.append("[j/k or Arrow: Navigate]  [Enter: Select]  [q/B: Back]\n", style="dim")

        # Wrap in panel
        panel = Panel(
            Align.center(lines, vertical="middle"),
            box=ROUNDED,
            width=width,
            style="on #0a0a0a",
            border_style="#ff4444",
            padding=(1, 2),
        )

        return panel

    def _handle_enter(self) -> Optional[str]:
        """Handle Enter on selected item."""
        if not self._items:
            return None

        idx = min(self._selected_idx, len(self._items) - 1)
        item = self._items[idx]
        item_id = item.get("id", "")
        action = item.get("action", "")

        if item_id == "exit" or action == "exit":
            if self._current_layer == "main":
                return "exit"
            return self._go_back()

        if item_id == "save_and_apply" or action == "save":
            return self._save_and_apply()

        if action == "save_key":
            return self._save_api_key()

        if action == "back":
            self._go_back()
            return None

        if action == "increase_rpm":
            rpm = item.get("rpm", -1)
            if 0 <= rpm < len(self._rate_limits):
                self._rate_limits[rpm] = min(self._rate_limits[rpm] + 5, 200)
            return None

        if action == "decrease_rpm":
            rpm = item.get("rpm", -1)
            if 0 <= rpm < len(self._rate_limits):
                self._rate_limits[rpm] = max(self._rate_limits[rpm] - 5, 1)
            return None

        return self._navigate_to(item_id)

    def _go_back(self) -> Optional[str]:
        """Go back to parent layer."""
        if self._current_layer == "main":
            return "exit"
        back_map = {
            "sessions": "main",
            "agent_setup": "main",
            "api_keys": "main",
            "rate_limits": "main",
            "skills": "main",
            "mode_settings": "main",
            "provider_select": "agent_setup",
            "model_select": "provider_select",
            "api_key_edit": "api_keys",
        }
        self._current_layer = back_map.get(self._current_layer, "main")
        self._selected_idx = 0
        self._update_items()
        return None

    def _navigate_to(self, item_id: str) -> Optional[str]:
        """Navigate to a sub-layer."""
        if self._current_layer == "main":
            if item_id == "sessions":
                self._current_layer = "sessions"
                self._selected_idx = 0
                self._update_items()
                return None
            if item_id in ("agent_setup", "api_keys", "rate_limits", "skills", "mode_settings"):
                self._current_layer = item_id
                self._selected_idx = 0
                self._update_items()
                return None

        if self._current_layer == "agent_setup":
            if item_id.startswith("agent_"):
                try:
                    self._agent_idx = int(item_id.split("_")[1]) - 1
                except (IndexError, ValueError):
                    self._agent_idx = 0
                self._current_layer = "provider_select"
                self._selected_idx = 0
                self._update_items()
                return None

        if self._current_layer == "provider_select":
            self._current_provider = item_id
            self._current_layer = "model_select"
            self._selected_idx = 0
            self._fetch_models(item_id)
            self._search = ""
            self._update_items()
            return None

        if self._current_layer == "model_select":
            if not item_id.startswith("["):
                self._agent_config[self._agent_idx] = {
                    "provider": self._current_provider,
                    "model": item_id,
                }
                self._current_layer = "agent_setup"
                self._selected_idx = min(self._agent_idx, len(self._agent_config) - 1)
                self._update_items()
            return None

        if self._current_layer == "api_keys":
            if item_id.startswith("key_"):
                self._editing_provider = item_id.replace("key_", "")
                self._current_layer = "api_key_edit"
                self._selected_idx = 0
                self._update_items()
            return None

        if self._current_layer == "sessions":
            if item_id.startswith("sess_"):
                session_id = item_id.replace("sess_", "")
                return f"load_session:{session_id}"
            return None

        if self._current_layer == "mode_settings":
            if item_id.startswith("mode_"):
                mode = item_id.replace("mode_", "")
                self._current_layer = "main"
                self._selected_idx = 0
                self._update_items()
            return None

        return None

    # ── Item builders ─────────────────────────────────────────────

    def _update_items(self) -> None:
        builders = {
            "main": self._build_main_items,
            "sessions": self._build_sessions_items,
            "agent_setup": self._build_agent_items,
            "provider_select": self._build_provider_items,
            "model_select": self._build_model_items,
            "api_keys": self._build_api_key_items,
            "api_key_edit": self._build_api_key_edit_items,
            "rate_limits": self._build_rate_limit_items,
            "skills": self._build_skills_items,
            "mode_settings": self._build_mode_items,
        }
        self._items = builders.get(self._current_layer, lambda: [])()

    def _build_main_items(self):
        items = []
        for m in MENU_ITEMS:
            items.append({"id": m["id"], "label": f"{m['icon']} {m['label']}", "action": ""})
        items.append({"id": "", "label": "", "action": ""})
        items.append({"id": "save_and_apply", "label": "[SAVE] Save & Apply", "action": "save"})
        items.append({"id": "exit", "label": "[BACK] Exit", "action": "exit"})
        return items

    def _build_sessions_items(self):
        items = [{"id": "", "label": "--- Select a session to load ---", "action": ""}]
        try:
            from tools.session_manager import SessionManager
            mgr = SessionManager()
            sessions = mgr.list_sessions()
            if not sessions:
                items.append({"id": "", "label": "  (no saved sessions)", "action": ""})
            else:
                for s in sessions[-15:]:
                    label = f"  {s.name}  [{s.target or '-'}]  {s.turns}turns"
                    items.append({"id": f"sess_{s.name}", "label": label, "action": ""})
        except Exception as e:
            items.append({"id": "", "label": f"  Error: {e}", "action": ""})
        items.append({"id": "", "label": "", "action": ""})
        items.append({"id": "back", "label": "[B] Back", "action": "back"})
        return items

    def _build_agent_items(self):
        roles = ["Strategist", "Recon Lead", "Exploit"]
        items = []
        for i, role in enumerate(roles, 1):
            cfg = self._agent_config[i - 1] if i - 1 < len(self._agent_config) else {}
            if cfg.get("provider") and cfg.get("model"):
                label = f"Agent {i} ({role}): {cfg['provider']}/{cfg['model'][:20]}"
            else:
                label = f"Agent {i} ({role}): Not set"
            items.append({"id": f"agent_{i}", "label": label, "action": ""})
        items.append({"id": "", "label": "", "action": ""})
        items.append({"id": "back_to_main", "label": "[BACK] Back to Settings", "action": "back"})
        return items

    def _build_provider_items(self):
        items = []
        providers = ["nvidia", "gemini", "openai", "anthropic", "deepseek", "groq", "mistral"]
        for prov in providers:
            has_key = bool(os.environ.get(f"{prov.upper()}_API_KEY"))
            status = "[OK]" if has_key else "[WARN] (no key)"
            items.append({"id": prov, "label": f"{prov.upper()} {status}", "action": ""})
        items.append({"id": "", "label": "", "action": ""})
        items.append({"id": "back_to_agents", "label": "[BACK] Back to Agent Setup", "action": "back"})
        return items

    def _build_model_items(self):
        items = []
        provider = self._current_provider
        models = self._get_cached_models(provider)
        search = self._search.lower()
        if search:
            models = [m for m in models if search in m.lower()]
        for m in models[:50]:
            items.append({"id": m, "label": m, "action": ""})
        if not items:
            items.append({"id": "", "label": "(No models found)", "action": ""})
        items.append({"id": "", "label": "", "action": ""})
        items.append({"id": "back_to_provider", "label": "[BACK] Back to Provider", "action": "back"})
        return items

    def _build_api_key_items(self):
        items = []
        providers = ["nvidia", "gemini", "openai", "anthropic", "deepseek"]
        for prov in providers:
            key_val = os.environ.get(f"{prov.upper()}_API_KEY", "")
            masked = "****" + key_val[-4:] if len(key_val) > 4 else "(not set)"
            items.append({"id": f"key_{prov}", "label": f"{prov.upper()}: {masked}", "action": ""})
        items.append({"id": "", "label": "", "action": ""})
        items.append({"id": "back_to_main", "label": "[BACK] Back to Settings", "action": "back"})
        return items

    def _build_api_key_edit_items(self):
        prov = self._editing_provider
        label = f"Enter API Key for {prov.upper()}:"
        return [
            {"id": "", "label": label, "action": ""},
            {"id": "key_value", "label": self._api_keys_dirty.get(prov, "") or "(type here)", "action": ""},
            {"id": "", "label": "", "action": ""},
            {"id": "confirm_save", "label": "[OK] Confirm & Save", "action": "save_key"},
            {"id": "cancel_edit", "label": "[BACK] Cancel", "action": "back"},
        ]

    def _build_rate_limit_items(self):
        items = []
        for i in range(3):
            items.append({
                "id": f"agent_{i+1}_rpm", "label": f"Agent {i+1}: {self._rate_limits[i]} RPM",
                "action": "", "rpm": i,
            })
            items.append({"id": f"decrease_{i}", "label": "  [-] Decrease", "action": "decrease_rpm", "rpm": i})
            items.append({"id": f"increase_{i}", "label": "  [+] Increase", "action": "increase_rpm", "rpm": i})
            items.append({"id": "", "label": "", "action": ""})
        items.append({"id": "", "label": "", "action": ""})
        items.append({"id": "back_to_main", "label": "[BACK] Back to Settings", "action": "back"})
        return items

    def _build_skills_items(self):
        try:
            from tools.skill_registry import get_skill_registry
            registry = get_skill_registry()
            missing = registry.get_missing_skills()
            names = [s.name for s in missing[:3]]
            label = f"Missing tools: {len(missing)} " + ", ".join(names) + ("..." if len(missing) > 3 else "")
        except Exception:
            label = "Skills registry not available"
        return [
            {"id": "", "label": label, "action": ""},
            {"id": "", "label": "", "action": ""},
            {"id": "back_to_main", "label": "[BACK] Back to Settings", "action": "back"},
        ]

    def _build_mode_items(self):
        return [
            {"id": "mode_scan", "label": "Mode: Scan", "action": ""},
            {"id": "mode_research", "label": "Mode: Research", "action": ""},
            {"id": "mode_auto", "label": "Mode: Auto-detect", "action": ""},
            {"id": "", "label": "", "action": ""},
            {"id": "back_to_main", "label": "[BACK] Back to Settings", "action": "back"},
        ]

    # ── Model cache ─────────────────────────────────────────────

    def _fetch_models(self, provider: str) -> None:
        now = time.time()
        if provider in self._model_cache:
            ts, models = self._model_cache[provider]
            if now - ts < 86400:
                return
            stale = models
        else:
            stale = []

        try:
            from tools.universal_ai_client import UniversalAIClient
            client = UniversalAIClient(provider=provider)
            if client.is_available():
                models = client.fetch_available_models()
                self._model_cache[provider] = (now, models)
            else:
                self._model_cache[provider] = (now, stale or ["(No API key)"])
        except Exception:
            self._model_cache[provider] = (now, stale or ["(Fetch failed)"])

    def _get_cached_models(self, provider: str):
        if provider in self._model_cache:
            return self._model_cache[provider][1]
        return ["(Not fetched)"]

    # ── Save & Reload ────────────────────────────────────────────

    def _save_and_apply(self) -> str:
        try:
            active_models = []
            for cfg in self._agent_config:
                if cfg.get("provider") and cfg.get("model"):
                    active_models.append(f"{cfg['provider']}/{cfg['model']}")
            if active_models:
                os.environ["ACTIVE_MODELS"] = ",".join(active_models)

            if self._api_keys_dirty:
                self._save_api_keys_to_env()

            self._save_config()

            saved_history = getattr(self.agent, "conversation_history", []).copy()
            from tools.universal_ai_client import AIClientManager
            new_manager = AIClientManager()
            self.agent.client = new_manager
            self.agent.conversation_history = saved_history

            return "saved"
        except Exception as e:
            logger.error(f"Save failed: {e}")
            return "error"

    def _save_api_key(self) -> Optional[str]:
        self._current_layer = "api_keys"
        self._selected_idx = 0
        self._update_items()
        return None

    def _save_api_keys_to_env(self) -> None:
        env_path = Path(".env")
        existing = {}
        if env_path.exists():
            for line in env_path.read_text().splitlines():
                if "=" in line and not line.startswith("#"):
                    k, v = line.split("=", 1)
                    existing[k] = v
        existing.update(self._api_keys_dirty)
        lines = [f"{k}={v}" for k, v in existing.items()]
        env_path.write_text("\n".join(lines))

    def _save_config(self) -> None:
        import yaml
        config_file = Path("config.yaml")
        if not config_file.exists():
            config = {}
        else:
            config = yaml.safe_load(config_file.read_text()) or {}
        config.setdefault("ai", {}).setdefault("active_models", [])
        active = [f"{cfg['provider']}/{cfg['model']}" for cfg in self._agent_config if cfg.get("provider")]
        config["ai"]["active_models"] = active
        config_file.write_text(yaml.dump(config, allow_unicode=True))

    def _load_agent_config(self):
        active = os.environ.get("ACTIVE_MODELS", "")
        config = []
        if active:
            for model_str in active.split(","):
                model_str = model_str.strip()
                if "/" in model_str:
                    p, m = model_str.split("/", 1)
                    config.append({"provider": p, "model": m})
                elif model_str:
                    config.append({"provider": "", "model": model_str})
        while len(config) < 3:
            config.append({"provider": "", "model": ""})
        return config[:3]

    def _get_title(self) -> str:
        titles = {
            "main": "[CONFIG] ELENGENIX SETTINGS",
            "agent_setup": "[AGENT] AGENT SETUP",
            "provider_select": "[PROVIDER] SELECT PROVIDER",
            "model_select": "[MODEL] SELECT MODEL",
            "api_keys": "[KEYS] API KEYS",
            "api_key_edit": "[EDIT] EDIT API KEY",
            "rate_limits": "[RATE] RATE LIMITS",
            "skills": "[SKILLS] SKILLS & TOOLS",
            "mode_settings": "[MODE] MODE SETTINGS",
        }
        return titles.get(self._current_layer, "[CONFIG] SETTINGS")
