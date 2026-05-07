"""
tools/overlay_menu.py — Settings Overlay (Ctrl+E)
================================================
Overlay menu for Elengenix CLI v3.0+
Features: mouse click + scroll, arrow keys, layered navigation
Saves to .env + config.yaml, reloads agent without losing history

Usage:
    from tools.overlay_menu import SettingsOverlay
    overlay = SettingsOverlay(agent, console, target)
    result = overlay.run()  # 'saved' | 'cancelled' | 'error'
"""

import os
import re
import sys
import json
import time
import select
import logging
import termios
import tty
from pathlib import Path
from typing import Optional, List, Dict, Tuple

from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.align import Align
from rich.box import ROUNDED

logger = logging.getLogger("elengenix.overlay")

# Mouse tracking ANSI escape sequences
_MOUSE_ENABLE = "\x1b[?1000h\x1b[?1002h\x1b[?1006h"
_MOUSE_DISABLE = "\x1b[?1006l\x1b[?1002l\x1b[?1000l"

MENU_ITEMS = [
    {"id": "agent_setup",   "label": "Agent Setup",     "icon": "[1]"},
    {"id": "api_keys",      "label": "API Keys",        "icon": "[2]"},
    {"id": "rate_limits",   "label": "Rate Limits",     "icon": "[3]"},
    {"id": "skills",        "label": "Skills & Tools",  "icon": "[4]"},
    {"id": "mode_settings", "label": "Mode Settings",   "icon": "[5]"},
]


class SettingsOverlay:
    """Overlay settings menu for Elengenix CLI."""

    def __init__(self, agent, console: Console, target: str = ""):
        self.agent = agent
        self.console = console
        self.target = target
        
        # Navigation state
        self._current_layer = "main"
        self._selected_idx = 0
        self._scroll_offset = 0
        
        # Menu items for current layer
        self._items: List[Dict] = []
        
        # Search/filter for model selector
        self._search = ""
        
        # Agent config (3 slots)
        self._agent_config: List[Dict[str, str]] = self._load_agent_config()
        self._rate_limits = [40, 40, 40]
        self._api_keys_dirty: Dict[str, str] = {}
        
        # Model cache: provider -> (timestamp, [models])
        self._model_cache: Dict[str, Tuple[float, List[str]]] = {}
        
        # Running flag
        self._running = False
        
        # Context for layer transitions
        self._agent_idx = 0
        self._current_provider = ""
        self._editing_provider = ""

    # ── Public API ────────────────────────────────────────────────────
    
    def run(self) -> str:
        """Run the overlay. Returns 'saved', 'cancelled', or 'error'."""
        self._running = True
        self._enable_mouse()
        try:
            return self._loop()
        except KeyboardInterrupt:
            return 'cancelled'
        except Exception as e:
            logger.error(f"Overlay error: {e}")
            return 'error'
        finally:
            self._disable_mouse()

    # ── Event Loop ────────────────────────────────────────────────────
    
    def _loop(self) -> str:
        """Main event loop."""
        # Save old terminal state
        old = None
        try:
            if sys.stdin.isatty():
                old = termios.tcgetattr(sys.stdin.fileno())
                tty.setcbreak(sys.stdin.fileno())
        except (termios.error, OSError):
            pass
        
        try:
            while self._running:
                self._update_items()
                self._render()
                ch = self._read_char(timeout=0.05)
                if ch is None:
                    continue
                    
                action = self._handle_input(ch)
                if action == "exit":
                    return 'cancelled'
                elif action == "back" and self._current_layer == "main":
                    return 'cancelled'
                elif action == "saved":
                    return 'saved'
                print(f"[DEBUG] action={action}")  # TODO: remove
                    
        finally:
            if old and sys.stdin.isatty():
                try:
                    termios.tcsetattr(sys.stdin.fileno(), termios.TCSADRAIN, old)
                except Exception:
                    pass
                    
        return 'cancelled'

    # ── Input ──────────────────────────────────────────────────────────
    
    def _read_char(self, timeout: float = 0.05) -> Optional[str]:
        """Read a single character or escape sequence."""
        try:
            if select.select([sys.stdin], [], [], timeout)[0]:
                ch = sys.stdin.read(1)
                if ch == "\x1b":
                    # Escape sequence
                    more = ""
                    if select.select([sys.stdin], [], [], 0.01)[0]:
                        more = sys.stdin.read(1)
                        if more == "[":
                            more += sys.stdin.read(1)
                            if more[-1] == "M":
                                # SGR mouse event
                                buf = more
                                while True:
                                    if select.select([sys.stdin], [], [], 0.01)[0]:
                                        c = sys.stdin.read(1)
                                        buf += c
                                        if c in ("M", "m"):
                                            break
                                    else:
                                        break
                                return ch + buf
                            # Complete escape for arrow keys
                            if select.select([sys.stdin], [], [], 0.01)[0]:
                                more += sys.stdin.read(1)
                    return ch + more
                return ch
            return None
        except (ValueError, OSError):
            return None

    def _handle_input(self, ch: str) -> Optional[str]:
        """Route input to handler. Returns action or None."""
        # Mouse click (SGR format)
        if ch.startswith("\x1b[<"):
            return self._handle_mouse(ch)
            
        # Arrow keys
        if ch == "\x1b[A" or ch == "\x1b[OA":
            self._selected_idx = max(0, self._selected_idx - 1)
            return None
        if ch == "\x1b[B" or ch == "\x1b[OB":
            self._selected_idx = min(len(self._items) - 1, self._selected_idx + 1)
            return None
            
        # Enter
        if ch in ("\r", "\n"):
            return self._handle_enter()
            
        # Esc
        if ch == "\x1b":
            if self._current_layer == "main":
                return "exit"
            return "back"
            
        # B for back
        if ch.lower() == "b":
            if self._current_layer == "main":
                return "exit"
            return "back"
            
        return None

    def _handle_mouse(self, ch: str) -> Optional[str]:
        """Handle mouse events."""
        m = re.match(r"\x1b\<(\d+);(\d+);(\d+)([Mm])", ch)
        if not m:
            return None
        btn, col, row = m.group(1), int(m.group(2)), int(m.group(3))
        
        if btn == "0":  # Left click
            # Map row to item index
            # Get viewport start (centered)
            try:
                import shutil
                term_h = shutil.get_terminal_size().lines
            except:
                term_h = 24
            
            # Rough conversion from row to item index
            # Menu starts around term_h/2 - len(self._items)//2
            start_row = max(2, (term_h - len(self._items)) // 2 + 2)
            item_idx = row - start_row
            
            if 0 <= item_idx < len(self._items):
                self._selected_idx = item_idx
                return self._handle_enter()
                
        if btn == "64":  # Scroll up
            self._selected_idx = max(0, self._selected_idx - 1)
            return None
        if btn == "65":  # Scroll down
            self._selected_idx = min(len(self._items) - 1, self._selected_idx + 1)
            return None
            
        return None

    def _handle_enter(self) -> Optional[str]:
        """Handle Enter on selected item."""
        if not self._items:
            return None
        
        idx = min(self._selected_idx, len(self._items) - 1)
        item = self._items[idx]
        item_id = item.get("id", "")
        action = item.get("action", "")
        
        # Exit
        if item_id == "exit" or action == "exit":
            if self._current_layer == "main":
                return "exit"
            return "back"
            
        # Save
        if item_id == "save_and_apply" or action == "save":
            return self._save_and_apply()
            
        # Save API key
        if action == "save_key":
            return self._save_api_key()
            
        # Back action
        if action == "back":
            return self._go_back()
            
        # RPM adjust
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
            
        # Layer navigation
        return self._navigate_to(item_id)

    def _go_back(self) -> Optional[str]:
        """Go back to parent layer."""
        if self._current_layer == "main":
            return "exit"
        if self._current_layer in ("agent_setup", "api_keys", "rate_limits", "skills", "mode_settings"):
            self._current_layer = "main"
        elif self._current_layer == "provider_select":
            self._current_layer = "agent_setup"
        elif self._current_layer == "model_select":
            self._current_layer = "provider_select"
        elif self._current_layer == "api_key_edit":
            self._current_layer = "api_keys"
        self._selected_idx = 0
        return None

    def _navigate_to(self, item_id: str) -> Optional[str]:
        """Navigate to a sub-layer based on item ID."""
        # Main menu items
        if self._current_layer == "main":
            if item_id in ("agent_setup", "api_keys", "rate_limits", "skills", "mode_settings"):
                self._current_layer = item_id
                self._selected_idx = 0
                return None
                
        # Agent setup items → provider select
        if self._current_layer == "agent_setup":
            if item_id.startswith("agent_"):
                try:
                    self._agent_idx = int(item_id.split("_")[1]) - 1
                except:
                    self._agent_idx = 0
                self._current_layer = "provider_select"
                self._selected_idx = 0
                return None
                
        # Provider select → model select
        if self._current_layer == "provider_select":
            self._current_provider = item_id
            self._current_layer = "model_select"
            self._fetch_models(item_id)
            self._selected_idx = 0
            self._search = ""
            return None
            
        # Model select → save to agent config
        if self._current_layer == "model_select":
            if not item_id.startswith("["):
                self._agent_config[self._agent_idx] = {
                    "provider": self._current_provider,
                    "model": item_id,
                }
                self._current_layer = "agent_setup"
                self._selected_idx = min(self._agent_idx, len(self._agent_config) - 1)
            return None
            
        # API keys → key editor
        if self._current_layer == "api_keys":
            if item_id.startswith("key_"):
                self._editing_provider = item_id.replace("key_", "")
                self._current_layer = "api_key_edit"
                self._selected_idx = 0
            return None
            
        # Mode settings → set mode
        if self._current_layer == "mode_settings":
            if item_id.startswith("mode_"):
                # Store in agent config
                mode = item_id.replace("mode_", "")
                self._current_layer = "main"
                self._selected_idx = 0
            return None
            
        return None

    # ── Rendering ─────────────────────────────────────────────────────
    
    def _render(self) -> None:
        """Render current layer."""
        self.console.clear()
        
        # Terminal size
        try:
            import shutil
            term_w, term_h = shutil.get_terminal_size()
        except:
            term_w, term_h = 80, 24
        
        # Build content
        lines = Text()
        
        # Sub-menu title
        title = self._get_title()
        lines.append(f"\n{title}\n", style="bold #FF6B6B")
        lines.append("═" * 40 + "\n\n", style="#FF6B6B")
        
        # Menu items
        for i, item in enumerate(self._items):
            label = item.get("label", "???")
            if not label:
                lines.append("\n")
                continue
                
            is_selected = (i == self._selected_idx)
            
            if is_selected:
                prefix = " ▶"
                style = "bold #FF6B6B on #1a1a1a"
            else:
                prefix = "  "
                style = "white on #0a0a0a"
                
            lines.append(f"{prefix} {label}\n", style=style)
            
        # Footer
        lines.append("\n")
        if self._current_layer == "main":
            lines.append("[ESC/B: Exit]  [↑↓: Navigate]  [Enter: Select]  [Mouse: Click]\n", style="dim")
        else:
            lines.append("[ESC/B: Back]  [↑↓: Navigate]  [Enter: Select]\n", style="dim")
            
        # Wrap in panel
        try:
            width = min(int(term_w * 0.7), 78)
        except:
            width = 70
            
        panel = Panel(
            Align.center(lines, vertical="middle"),
            box=ROUNDED,
            width=width,
            style="on #0a0a0a",
            border_style="#FF6B6B",
            padding=(1, 2),
        )
        
        self.console.print(panel)

    def _get_title(self) -> str:
        """Return title for current layer."""
        titles = {
            "main": "⚙  ELENGENIX SETTINGS",
            "agent_setup": "🤖 AGENT SETUP",
            "provider_select": "📡 SELECT PROVIDER",
            "model_select": "🔬 SELECT MODEL",
            "api_keys": "🔑 API KEYS",
            "api_key_edit": "✏️ EDIT API KEY",
            "rate_limits": "⚡ RATE LIMITS",
            "skills": "🛠 SKILLS & TOOLS",
            "mode_settings": "🔣 MODE SETTINGS",
        }
        return titles.get(self._current_layer, "⚙ SETTINGS")

    def _update_items(self) -> None:
        """Build items for current layer."""
        layer = self._current_layer
        
        if layer == "main":
            self._items = self._build_main_items()
        elif layer == "agent_setup":
            self._items = self._build_agent_items()
        elif layer == "provider_select":
            self._items = self._build_provider_items()
        elif layer == "model_select":
            self._items = self._build_model_items()
        elif layer == "api_keys":
            self._items = self._build_api_key_items()
        elif layer == "api_key_edit":
            self._items = self._build_api_key_edit_items()
        elif layer == "rate_limits":
            self._items = self._build_rate_limit_items()
        elif layer == "skills":
            self._items = self._build_skills_items()
        elif layer == "mode_settings":
            self._items = self._build_mode_items()
        else:
            self._items = []

    # ── Item Builders ─────────────────────────────────────────────────
    
    def _build_main_items(self) -> List[Dict]:
        items = []
        for m in MENU_ITEMS:
            items.append({"id": m["id"], "label": f"{m['icon']} {m['label']}", "action": ""})
        items.append({"id": "", "label": "", "action": ""})
        items.append({"id": "save_and_apply", "label": "💾  Save & Apply", "action": "save"})
        items.append({"id": "exit", "label": "←  Exit", "action": "exit"})
        return items

    def _build_agent_items(self) -> List[Dict]:
        roles = ["Strategist", "Recon Lead", "Exploit"]
        items = []
        for i, role in enumerate(roles, 1):
            cfg = self._agent_config[i-1] if i-1 < len(self._agent_config) else {}
            if cfg.get("provider") and cfg.get("model"):
                label = f"Agent {i} ({role}): {cfg['provider']}/{cfg['model'][:20]}"
            else:
                label = f"Agent {i} ({role}): Not set"
            items.append({"id": f"agent_{i}", "label": label, "action": ""})
        items.append({"id": "", "label": "", "action": ""})
        items.append({"id": "back_to_main", "label": "← Back to Settings", "action": "back"})
        return items

    def _build_provider_items(self) -> List[Dict]:
        items = []
        providers = ["nvidia", "gemini", "openai", "anthropic", "deepseek", "groq", "mistral"]
        for prov in providers:
            has_key = bool(os.environ.get(f"{prov.upper()}_API_KEY"))
            status = "✓" if has_key else "⚠ (no key)"
            items.append({"id": prov, "label": f"{prov.upper()}  {status}", "action": ""})
        items.append({"id": "", "label": "", "action": ""})
        items.append({"id": "back_to_agents", "label": "← Back to Agent Setup", "action": "back"})
        return items

    def _build_model_items(self) -> List[Dict]:
        items = []
        provider = self._current_provider
        models = self._get_cached_models(provider)
        search = self._search.lower()
        
        if search:
            models = [m for m in models if search in m.lower()]
            
        for m in models[:50]:  # max 50 models
            items.append({"id": m, "label": m, "action": ""})
            
        if not items:
            items.append({"id": "", "label": "(No models found)", "action": ""})
            
        items.append({"id": "", "label": "", "action": ""})
        items.append({"id": "back_to_provider", "label": "← Back to Provider", "action": "back"})
        return items

    def _build_api_key_items(self) -> List[Dict]:
        items = []
        providers = ["nvidia", "gemini", "openai", "anthropic", "deepseek"]
        for prov in providers:
            key_val = os.environ.get(f"{prov.upper()}_API_KEY", "")
            masked = "****" + key_val[-4:] if len(key_val) > 4 else "(not set)"
            items.append({"id": f"key_{prov}", "label": f"{prov.upper()}: {masked}", "action": ""})
        items.append({"id": "", "label": "", "action": ""})
        items.append({"id": "back_to_main", "label": "← Back to Settings", "action": "back"})
        return items

    def _build_api_key_edit_items(self) -> List[Dict]:
        prov = self._editing_provider
        label = f"Enter API Key for {prov.upper()}:"
        return [
            {"id": "", "label": label, "action": ""},
            {"id": "key_value", "label": self._api_keys_dirty.get(prov, "") or "(type here)", "action": ""},
            {"id": "", "label": "", "action": ""},
            {"id": "confirm_save", "label": "✓ Confirm & Save", "action": "save_key"},
            {"id": "cancel_edit", "label": "← Cancel", "action": "back"},
        ]

    def _build_rate_limit_items(self) -> List[Dict]:
        items = []
        for i in range(3):
            items.append({
                "id": f"agent_{i+1}_rpm", "label": f"Agent {i+1}: {self._rate_limits[i]} RPM", 
                "action": "", "rpm": i
            })
            items.append({"id": f"decrease_{i}", "label": "  [-] Decrease", "action": "decrease_rpm", "rpm": i})
            items.append({"id": f"increase_{i}", "label": "  [+] Increase", "action": "increase_rpm", "rpm": i})
            items.append({"id": "", "label": "", "action": ""})
        items.append({"id": "", "label": "", "action": ""})
        items.append({"id": "back_to_main", "label": "← Back to Settings", "action": "back"})
        return items

    def _build_skills_items(self) -> List[Dict]:
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
            {"id": "back_to_main", "label": "← Back to Settings", "action": "back"},
        ]

    def _build_mode_items(self) -> List[Dict]:
        return [
            {"id": "mode_scan", "label": "Mode: Scan", "action": ""},
            {"id": "mode_research", "label": "Mode: Research", "action": ""},
            {"id": "mode_auto", "label": "Mode: Auto-detect", "action": ""},
            {"id": "", "label": "", "action": ""},
            {"id": "back_to_main", "label": "← Back to Settings", "action": "back"},
        ]

    # ── Model Fetching ────────────────────────────────────────────────
    
    def _fetch_models(self, provider: str) -> None:
        """Fetch models from provider with cache."""
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

    def _get_cached_models(self, provider: str) -> List[str]:
        if provider in self._model_cache:
            return self._model_cache[provider][1]
        return ["(Not fetched)"]

    # ── Save & Reload ─────────────────────────────────────────────────
    
    def _save_and_apply(self) -> str:
        """Save configuration and reload agent."""
        try:
            # 1. Update env vars
            active_models = []
            for cfg in self._agent_config:
                if cfg.get("provider") and cfg.get("model"):
                    active_models.append(f"{cfg['provider']}/{cfg['model']}")
            if active_models:
                os.environ["ACTIVE_MODELS"] = ",".join(active_models)
                
            # 2. Save API keys to .env
            if self._api_keys_dirty:
                self._save_api_keys_to_env()
                
            # 3. Save to config.yaml
            self._save_config()
            
            # 4. Reload agent (preserve conversation history)
            saved_history = getattr(self.agent, "conversation_history", []).copy()
            from tools.universal_ai_client import AIClientManager
            new_manager = AIClientManager()
            self.agent.client = new_manager
            self.agent.conversation_history = saved_history
            
            # 5. Done
            self._running = False
            return "saved"
        except Exception as e:
            logger.error(f"Save failed: {e}")
            return "error"

    def _save_api_key(self) -> Optional[str]:
        """Save current API key edits."""
        # Keys saved when _save_and_apply called
        self._current_layer = "api_keys"
        self._selected_idx = 0
        return None

    def _save_api_keys_to_env(self) -> None:
        """Write API keys to .env file."""
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
        """Write to config.yaml."""
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

    def _load_agent_config(self) -> List[Dict[str, str]]:
        """Load agent configuration from environment."""
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

    # ── Mouse tracking ────────────────────────────────────────────────
    
    def _enable_mouse(self) -> None:
        sys.stdout.write(_MOUSE_ENABLE)
        sys.stdout.flush()

    def _disable_mouse(self) -> None:
        sys.stdout.write(_MOUSE_DISABLE)
        sys.stdout.flush()
