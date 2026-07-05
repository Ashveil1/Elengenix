"""
tools/overlay_menu.py -- Settings Overlay (Ctrl+E)
====================================================
State-driven overlay rendered inside the main Live layout.
Usage:
    overlay = SettingsOverlay(agent, console, target)
    overlay.handle_char(ch)  # Process keyboard input
    panel = overlay.render()  # Build Rich panel for display
"""

import logging
import os
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from rich.align import Align
from rich.box import ROUNDED
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

logger = logging.getLogger("elengenix.overlay")

MENU_ITEMS = [
    {"id": "sessions", "label": "Sessions", "icon": "[S]"},
    {"id": "agent_setup", "label": "Agent Setup", "icon": "[1]"},
    {"id": "api_keys", "label": "API Keys", "icon": "[2]"},
    {"id": "rate_limits", "label": "Rate Limits", "icon": "[3]"},
    {"id": "mcp_servers", "label": "MCP Servers", "icon": "[4]"},
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
        self._scroll_offset = 0
        self._max_visible = 14
        self._search = ""
        self._agent_config: List[Dict[str, str]] = self._load_agent_config()
        self._rate_limits = [40, 40, 40]
        self._api_keys_dirty: Dict[str, str] = {}
        self._model_cache: Dict[str, Tuple[float, List[str]]] = {}
        self._agent_idx = 0
        self._current_provider = ""
        self._custom_url = ""
        self._custom_step = ""
        self._editing_provider = ""
        self._items: List[Dict] = []
        self._update_items()

    def render(self) -> Panel:
        """Render the settings overlay as a Rich Panel."""
        title = self._get_title()
        lines = []
        
        for i, item in enumerate(self._items):
            label = item.get("label", "")
            if not label:
                lines.append("")
                continue
            
            # Highlight selected item
            if i == self._selected_idx:
                lines.append(f"[bold white]> {label}[/bold white]")
            else:
                lines.append(f"  {label}")
        
        content = "\n".join(lines) if lines else "[dim]No items[/dim]"
        
        from rich.text import Text
        text = Text.from_markup(content)
        
        return Panel(
            text,
            title=f"[bold]{title}[/bold]",
            border_style="white",
            padding=(1, 2),
        )

    def handle_char(self, ch: str) -> Optional[str]:
        """Process a single key character. Returns 'exit', 'saved', 'error', or None."""
        # Arrow keys - must have full escape sequence
        if ch == "\x1b[A" or ch == "\x1b[OA":
            self._selected_idx = max(0, self._selected_idx - 1)
            self._adjust_scroll()
            return None
        if ch == "\x1b[B" or ch == "\x1b[OB":
            self._selected_idx = min(len(self._items) - 1, self._selected_idx + 1)
            self._adjust_scroll()
            return None
        if ch == "\x1b[C" or ch == "\x1b[OC":
            return None
        if ch == "\x1b[D" or ch == "\x1b[OD":
            return None

        # Custom URL input: capture ALL printable characters FIRST
        if self._current_layer == "custom_url":
            if ch.isprintable() and len(ch) == 1:
                self._custom_url += ch
                self._update_items()
                return None
            if ch == "\x7f" and self._custom_url:
                self._custom_url = self._custom_url[:-1]
                self._update_items()
                return None
            if ch in ("\r", "\n") and self._custom_url:
                self._agent_config[self._agent_idx] = {
                    "provider": "custom",
                    "model": self._custom_url,
                }
                self._current_layer = "agent_setup"
                self._selected_idx = min(self._agent_idx, len(self._agent_config) - 1)
                self._update_items()
                return "saved"
            # Esc to cancel custom URL
            if ch == "\x1b" and len(ch) == 1:
                return self._go_back()
            return None

        # Vim-style navigation: j=down, k=up
        if ch == "j":
            self._selected_idx = min(len(self._items) - 1, self._selected_idx + 1)
            self._adjust_scroll()
            return None
        if ch == "k":
            self._selected_idx = max(0, self._selected_idx - 1)
            self._adjust_scroll()
            return None
        # Enter
        if ch in ("\r", "\n"):
            return self._handle_enter()
        # Space - toggle MCP server
        if ch == " ":
            return self._handle_space()
        # Esc - if it's a bare ESC (length 1), exit
        if ch == "\x1b" and len(ch) == 1:
            if self._current_layer == "main":
                return "exit"
            return self._go_back()

    def _handle_space(self) -> Optional[str]:
        """Handle Space key - toggle MCP server."""
        if self._current_layer != "mcp_servers":
            return None
        
        if not self._items:
            return None
        
        idx = min(self._selected_idx, len(self._items) - 1)
        item = self._items[idx]
        action = item.get("action", "")
        
        if action == "mcp_toggle":
            server_name = item.get("server_name", "")
            if server_name:
                self._toggle_mcp_server(server_name)
                self._update_items()
                return "toggled"
        
        return None

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

        # MCP actions
        if action == "mcp_toggle":
            server_name = item.get("server_name", "")
            if server_name:
                self._toggle_mcp_server(server_name)
            return None

        if action == "mcp_add":
            self._current_layer = "mcp_add"
            self._selected_idx = 0
            self._update_items()
            return None

        if action == "mcp_defaults":
            self._add_mcp_defaults()
            return None

        return self._navigate_to(item_id)

    def _go_back(self) -> Optional[str]:
        """Go back to parent layer."""
        if self._current_layer == "main":
            return "exit"
        back_map = {
            "sessions": "main",
            "custom_url": "main",
            "agent_setup": "main",
            "api_keys": "main",
            "rate_limits": "main",
            "mcp_servers": "main",
            "mcp_add": "mcp_servers",
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
            if item_id in ("agent_setup", "api_keys", "rate_limits", "mcp_servers", "mode_settings"):
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
            if item_id == "custom":
                return "show_custom_url"
            self._current_layer = "model_select"
            self._fetch_models(item_id)
            self._selected_idx = 0
            self._search = ""
            self._update_items()
            return None

        if self._current_layer == "model_select":
            if not item_id.startswith("["):
                if item_id.startswith("manual:"):
                    # Keep user on model_select so they can type more
                    return None
                # For custom provider, save URL as env var + model name
                if self._current_provider == "custom":
                    url = getattr(self, "_custom_url", "")
                    if url:
                        os.environ["CUSTOM_API_BASE"] = url
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
                item_id.replace("mode_", "")
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
            "custom_url": self._build_custom_url_items,
            "agent_setup": self._build_agent_items,
            "provider_select": self._build_provider_items,
            "model_select": self._build_model_items,
            "api_keys": self._build_api_key_items,
            "api_key_edit": self._build_api_key_edit_items,
            "rate_limits": self._build_rate_limit_items,
            "mcp_servers": self._build_mcp_items,
            "mcp_add": self._build_mcp_add_items,
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

    def _build_custom_url_items(self):
        url = getattr(self, "_custom_url", "")
        items = [
            {"id": "", "label": "--- ENTER CUSTOM API URL ---", "action": ""},
            {"id": "", "label": f"  URL: {url or '(start typing...)'}", "action": ""},
        ]
        if url:
            items.append({"id": "", "label": "", "action": ""})
            items.append({"id": "", "label": "  Press ENTER to confirm", "action": ""})
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

    ALL_PROVIDERS = [
        "openai",
        "gemini",
        "anthropic",
        "groq",
        "nvidia",
        "deepseek",
        "mistral",
        "openrouter",
        "together",
        "perplexity",
        "cohere",
        "huggingface",
        "replicate",
        "ollama",
    ]

    def _build_provider_items(self):
        items = []
        for prov in self.ALL_PROVIDERS:
            has_key = bool(os.environ.get(f"{prov.upper()}_API_KEY"))
            status = "[OK]" if has_key else ""
            items.append({"id": prov, "label": f"{prov.upper()} {status}", "action": ""})
        items.append({"id": "", "label": "", "action": ""})
        items.append({"id": "custom", "label": "CUSTOM (OpenAI-compatible URL)", "action": ""})
        items.append({"id": "", "label": "", "action": ""})
        items.append(
            {"id": "back_to_agents", "label": "[BACK] Back to Agent Setup", "action": "back"}
        )
        return items

    def _build_model_items(self):
        items = []
        provider = self._current_provider
        if provider == "custom":
            url = getattr(self, "_custom_url", "")
            items.append({"id": "", "label": f"  API: {url}", "action": ""})
            items.append({"id": "", "label": "", "action": ""})
        models = self._get_cached_models(provider)
        search = self._search.lower()
        if search:
            models = [m for m in models if search in m.lower()]
        for m in models[:50]:
            items.append({"id": m, "label": m, "action": ""})
        if not items:
            items.append(
                {
                    "id": "",
                    "label": "(No models — enter manually below or type to search)",
                    "action": "",
                }
            )
        items.append({"id": "", "label": "", "action": ""})
        items.append(
            {
                "id": f"manual:{provider}",
                "label": f"TYPE MODEL NAME MANUALLY: {provider}/<model>",
                "action": "",
            }
        )
        items.append({"id": "", "label": "", "action": ""})
        items.append(
            {"id": "back_to_provider", "label": "[BACK] Back to Provider", "action": "back"}
        )
        return items

    def _build_api_key_items(self):
        items = []
        for prov in self.ALL_PROVIDERS:
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
            {
                "id": "key_value",
                "label": self._api_keys_dirty.get(prov, "") or "(type here)",
                "action": "",
            },
            {"id": "", "label": "", "action": ""},
            {"id": "confirm_save", "label": "[OK] Confirm & Save", "action": "save_key"},
            {"id": "cancel_edit", "label": "[BACK] Cancel", "action": "back"},
        ]

    def _build_rate_limit_items(self):
        items = []
        for i in range(3):
            items.append(
                {
                    "id": f"agent_{i+1}_rpm",
                    "label": f"Agent {i+1}: {self._rate_limits[i]} RPM",
                    "action": "",
                    "rpm": i,
                }
            )
            items.append(
                {
                    "id": f"decrease_{i}",
                    "label": "  [-] Decrease",
                    "action": "decrease_rpm",
                    "rpm": i,
                }
            )
            items.append(
                {
                    "id": f"increase_{i}",
                    "label": "  [+] Increase",
                    "action": "increase_rpm",
                    "rpm": i,
                }
            )
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
            label = (
                f"Missing tools: {len(missing)} "
                + ", ".join(names)
                + ("..." if len(missing) > 3 else "")
            )
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

    def _build_mcp_items(self):
        """Build MCP servers list with status indicators."""
        items = [{"id": "", "label": "--- MCP SERVERS ---", "action": ""}]
        
        try:
            from mcp.config import get_config_manager
            from mcp.manager import get_mcp_manager
            
            manager = get_config_manager()
            config = manager.config
            mcp_manager = get_mcp_manager()
            
            if config.servers:
                for name, server in config.servers.items():
                    # Check if server is actually running
                    is_running = mcp_manager.is_running and server.enabled
                    
                    if is_running:
                        indicator = "[bold red]\u25cf[/bold red]"  # Red = connected
                    else:
                        indicator = "[grey50]\u25cb[/grey50]"  # Gray = not connected
                    
                    status_text = "connected" if is_running else "disabled"
                    items.append({
                        "id": f"mcp_toggle_{name}",
                        "label": f"  {indicator} {name} [dim]({status_text})[/dim]",
                        "action": "mcp_toggle",
                        "server_name": name,
                    })
            else:
                items.append({"id": "", "label": "  (no servers configured)", "action": ""})
        except Exception as e:
            items.append({"id": "", "label": f"  Error: {e}", "action": ""})
        
        items.append({"id": "", "label": "", "action": ""})
        items.append({"id": "mcp_add", "label": "[+] Add Server", "action": "mcp_add"})
        items.append({"id": "mcp_defaults", "label": "[*] Add Defaults", "action": "mcp_defaults"})
        items.append({"id": "", "label": "", "action": ""})
        items.append({"id": "back_to_main", "label": "[BACK] Back to Settings", "action": "back"})
        return items

    def _build_mcp_add_items(self):
        """Build MCP add server form."""
        return [
            {"id": "", "label": "--- ADD MCP SERVER ---", "action": ""},
            {"id": "", "label": "  Server name:", "action": ""},
            {"id": "", "label": "  Command (e.g., npx):", "action": ""},
            {"id": "", "label": "  Arguments (space-separated):", "action": ""},
            {"id": "", "label": "", "action": ""},
            {"id": "back_to_mcp", "label": "[BACK] Back to MCP", "action": "back"},
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

    def handle_custom_url(self, url: str) -> None:
        """Save the custom URL, signal to ask for API key next."""
        if not url:
            return
        self._custom_url = url
        self._custom_step = "apikey"
        self._current_provider = "custom"

    def handle_custom_apikey(self, apikey: str) -> None:
        """Save API key, fetch models, go to model selection."""
        if apikey:
            os.environ["CUSTOM_API_KEY"] = apikey
        url = getattr(self, "_custom_url", "")

        # Derive models endpoint
        models_url = url.rstrip("/")
        if models_url.endswith("/chat/completions"):
            models_url = models_url.replace("/chat/completions", "/models")
        elif models_url.endswith("/v1"):
            models_url += "/models"
        else:
            models_url += "/models"

        models = []
        try:
            import requests

            headers = {}
            if apikey:
                headers["Authorization"] = f"Bearer {apikey}"
            resp = requests.get(models_url, headers=headers, timeout=5)
            if resp.status_code == 200:
                data = resp.json()
                raw = data.get("data", data if isinstance(data, list) else [])
                for item in raw:
                    if isinstance(item, dict):
                        mid = item.get("id", "")
                        if mid:
                            models.append(mid)
                    elif isinstance(item, str):
                        models.append(item)
        except Exception:
            pass

        now = time.time()
        if models:
            self._model_cache["custom"] = (now, models)
        else:
            self._model_cache["custom"] = (now, ["(No models fetched — type manually below)"])

        self._custom_step = ""
        self._current_layer = "model_select"
        self._selected_idx = 0
        self._search = ""
        self._update_items()

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

            # Clear global agent cache so next get_agent() creates fresh instance with new config
            try:
                import agent

                agent._agent_instance = None
            except Exception:
                pass

            # If we have an agent, preserve history but re-init client
            if self.agent:
                saved_history = getattr(self.agent, "conversation_history", []).copy()
                from tools.universal_ai_client import AIClientManager

                new_manager = AIClientManager()
                self.agent.client = new_manager
                # Also re-init team_aegis clients
                if hasattr(self.agent, "_init_team_aegis_clients"):
                    self.agent._team_aegis_clients = self.agent._init_team_aegis_clients()
                # Re-create planner with new client
                if hasattr(self.agent, "planner") and self.agent.planner:
                    from core.brain import StrategicPlanner

                    self.agent.planner = StrategicPlanner(new_manager)
                self.agent.conversation_history = saved_history

            return f"saved:{','.join(active_models)}"
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
        active = [
            f"{cfg['provider']}/{cfg['model']}" for cfg in self._agent_config if cfg.get("provider")
        ]
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

    def _toggle_mcp_server(self, server_name: str) -> None:
        """Toggle MCP server enabled/disabled and start/stop."""
        try:
            from mcp.config import get_config_manager
            from mcp.manager import get_mcp_manager
            
            manager = get_config_manager()
            config = manager.config
            mcp_manager = get_mcp_manager()
            
            if server_name in config.servers:
                server = config.servers[server_name]
                server.enabled = not server.enabled
                manager.save()
                
                # Start/stop MCP manager based on any server being enabled
                has_enabled = any(s.enabled for s in config.servers.values())
                if has_enabled and not mcp_manager.is_running:
                    mcp_manager.start()
                elif not has_enabled and mcp_manager.is_running:
                    mcp_manager.stop()
        except Exception as e:
            logger.debug(f"Failed to toggle MCP server: {e}")

    def _add_mcp_defaults(self) -> None:
        """Add default MCP servers."""
        try:
            from mcp.config import get_config_manager
            
            manager = get_config_manager()
            config = manager.config
            
            defaults = {
                "sequential-thinking": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-sequential-thinking"]},
                "reasoning-server": {"command": "npx", "args": ["-y", "mcp-reasoning-server"]},
                "chain-of-recursive-thoughts": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-chain-of-recursive-thoughts"]},
                "mcp-thinking": {"command": "npx", "args": ["-y", "mcp-thinking"]},
                "mcp-structured-thinking": {"command": "npx", "args": ["-y", "mcp-structured-thinking"]},
                "memory": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-memory"]},
            }
            
            for name, server_data in defaults.items():
                if name not in config.servers:
                    manager.add_server(name, server_data["command"], server_data["args"])
            
            self._update_items()
        except Exception as e:
            logger.debug(f"Failed to add MCP defaults: {e}")

    def _get_title(self) -> str:
        titles = {
            "main": "[CONFIG] ELENGENIX SETTINGS",
            "sessions": "[SESSIONS] LOAD SESSION",
            "agent_setup": "[AGENT] AGENT SETUP",
            "provider_select": "[PROVIDER] SELECT PROVIDER",
            "model_select": "[MODEL] SELECT MODEL",
            "api_keys": "[KEYS] API KEYS",
            "api_key_edit": "[EDIT] EDIT API KEY",
            "rate_limits": "[RATE] RATE LIMITS",
            "mcp_servers": "[MCP] MCP SERVERS",
            "mcp_add": "[MCP] ADD SERVER",
            "mode_settings": "[MODE] MODE SETTINGS",
            "custom_url": "[CUSTOM] ENTER API URL",
        }
        return titles.get(self._current_layer, "[CONFIG] SETTINGS")
