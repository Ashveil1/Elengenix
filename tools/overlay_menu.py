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
from rich.console import Console, Group
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


def _catalog():
    """Lazy provider-catalog import (module body imports heavyweight deps)."""
    from elengenix.providers import catalog

    return catalog


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

    # ── Render styling ────────────────────────────────────────────
    # House identity: white / black / red.

    _ACCENT = "#ffffff"
    _SELECT_BG = "#333333"
    _PARENT_LAYERS = {
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

    _LAYER_HINTS = {
        "main": "\u2191\u2193 navigate \u00b7 Enter open \u00b7 S save \u00b7 Esc close",
        "model_select": "\u2191\u2193 navigate \u00b7 type to filter \u00b7 Enter select \u00b7 Esc back",
        "api_key_edit": "type key \u00b7 Enter confirm \u00b7 Esc cancel",
        "custom_url": "type URL \u00b7 Enter confirm \u00b7 Esc cancel",
        "mcp_servers": "\u2191\u2193 navigate \u00b7 Space toggle \u00b7 Enter open \u00b7 Esc back",
        "rate_limits": "Enter on +/\u2212 to adjust \u00b7 Esc back",
    }
    _DEFAULT_HINT = "\u2191\u2193/j/k navigate \u00b7 Enter select \u00b7 q/Esc back"

    def _title_for(self, layer: str) -> str:
        titles = {
            "main": "SETTINGS",
            "sessions": "LOAD SESSION",
            "agent_setup": "AGENT SETUP",
            "provider_select": "SELECT PROVIDER",
            "model_select": "SELECT MODEL",
            "api_keys": "API KEYS",
            "api_key_edit": "EDIT API KEY",
            "rate_limits": "RATE LIMITS",
            "mcp_servers": "MCP SERVERS",
            "mcp_add": "ADD SERVER",
            "mode_settings": "MODE SETTINGS",
            "custom_url": "ENTER API URL",
        }
        return titles.get(layer, "SETTINGS")

    def _breadcrumb(self) -> List[str]:
        """Layer trail from SETTINGS down to the current layer."""
        chain = [self._current_layer]
        while chain[-1] != "main":
            chain.append(self._PARENT_LAYERS.get(chain[-1], "main"))
        return [self._title_for(layer) for layer in reversed(chain)]

    @staticmethod
    def _row_kind(label: str) -> str:
        """Classify a row for styling: section/action/info/item."""
        s = label.strip()
        if s.startswith("---"):
            return "section"
        if s.startswith(("[SAVE]", "[OK] Confirm", "TYPE MODEL")):
            return "primary"
        if s.startswith(("[BACK]", "[B] Back")):
            return "back"
        if s.startswith(("[+]", "[*]")):
            return "accent"
        if s.startswith("(") or s.startswith("Error") or "start typing" in s:
            return "info"
        return "item"

    def _style_row(self, label: str, selected: bool) -> Text:
        """Style one menu row."""
        kind = self._row_kind(label)
        if kind == "section":
            core = label.strip().strip("-").strip() or " "
            return Text(f"  \u2500\u2500 {core} \u2500\u2500", style="#666666")
        base = Text.from_markup(label)
        if selected:
            base.stylize(f"bold white on {self._SELECT_BG}")
            marker = Text("\u25b6 ", style=f"bold {self._ACCENT} on {self._SELECT_BG}")
            return Text.assemble(marker, base)
        if kind == "primary":
            base.stylize(f"bold {self._ACCENT}")
        elif kind == "accent":
            base.stylize("bold #cccccc")
        elif kind == "back":
            base.stylize("#888888")
        elif kind == "info":
            base.stylize("dim #666666")
        else:
            base.stylize("#e8e8e8")
        return Text.assemble(Text("  "), base)

    def render(self) -> Panel:
        """Render the settings overlay as a Rich Panel.

        Shows a breadcrumb trail, a scroll window with ▲/▼ indicators,
        a red selection bar, and per-layer key hints.
        """
        title = self._get_title()
        crumbs = self._breadcrumb()
        total = len(self._items)
        start = max(0, min(self._scroll_offset, max(0, total - 1)))
        window = self._items[start : start + self._max_visible]

        body: List[Text] = []
        if len(crumbs) > 1:
            trail = Text()
            for i, crumb in enumerate(crumbs):
                if i:
                    trail.append(" \u203a ", style="#666666")
                trail.append(
                    crumb,
                    style=f"bold {self._ACCENT}" if i == len(crumbs) - 1 else "#888888",
                )
            body.append(trail)
            body.append(Text(""))

        if start > 0:
            body.append(Text(f"  \u25b2 {start} more above", style="dim #555555"))

        shown = 0
        for idx, item in enumerate(window):
            label = item.get("label", "")
            if not label:
                continue
            body.append(self._style_row(label, selected=(start + idx) == self._selected_idx))
            shown += 1
        if not shown:
            body.append(Text("  (no items)", style="dim #666666"))

        remaining = total - (start + len(window))
        if remaining > 0:
            body.append(Text(f"  \u25bc {remaining} more below", style="dim #555555"))

        body.append(Text(""))
        hint = self._LAYER_HINTS.get(self._current_layer, self._DEFAULT_HINT)
        body.append(Text(f"  {hint}", style="#777777"))

        pos = min(self._selected_idx + 1, max(total, 1))
        return Panel(
            Align.left(Group(*body)),
            title=f"[bold {self._ACCENT}]\u25cf[/bold {self._ACCENT}] [bold white]{title}[/bold white]",
            subtitle=f"[dim]{pos}/{total}[/dim]",
            border_style=self._ACCENT,
            box=ROUNDED,
            padding=(1, 2),
        )

    def _adjust_scroll(self) -> None:
        """Adjust scroll offset to keep selected item visible."""
        if self._selected_idx < self._scroll_offset:
            self._scroll_offset = self._selected_idx
        elif self._selected_idx >= self._scroll_offset + self._max_visible:
            self._scroll_offset = self._selected_idx - self._max_visible + 1

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

        # API-key edit layer: free typing (the value row shows progress).
        if self._current_layer == "api_key_edit":
            prov = self._editing_provider
            if ch.isprintable() and len(ch) == 1 and ch not in ("\r", "\n"):
                self._api_keys_dirty[prov] = self._api_keys_dirty.get(prov, "") + ch
                self._update_items()
                return None
            if ch == "\x7f":
                cur = self._api_keys_dirty.get(prov, "")
                if cur:
                    self._api_keys_dirty[prov] = cur[:-1]
                    self._update_items()
                return None
            if ch in ("\r", "\n"):
                return self._confirm_api_key()
            if ch == "\x1b" and len(ch) == 1:
                self._api_keys_dirty.pop(prov, None)
                return self._go_back()
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

        # Vim-style navigation: j=down, k=up, q=quit, b=back
        if ch == "j":
            self._selected_idx = min(len(self._items) - 1, self._selected_idx + 1)
            self._adjust_scroll()
            return None
        if ch == "k":
            self._selected_idx = max(0, self._selected_idx - 1)
            self._adjust_scroll()
            return None
        if ch == "q":
            if self._current_layer == "main":
                return "exit"
            return self._go_back()
        if ch == "b":
            if self._current_layer == "main":
                return "exit"
            return self._go_back()
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

    @staticmethod
    def _env_keys_for_provider(pid: str) -> List[str]:
        """Every env var that counts as configuration for a provider id."""
        from tools.ai_config import OLLAMA_URL_VARS

        if pid == "custom":
            return ["CUSTOM_API_BASE", "CUSTOM_API_KEY", "CUSTOM_MODEL"]
        if pid == "ollama":
            return list(OLLAMA_URL_VARS) + ["OLLAMA_MODEL"]
        try:
            env_key = SettingsOverlay._provider_env_key(pid)
        except Exception:
            env_key = None
        if not env_key:
            return []
        keys = [env_key]
        if env_key.endswith("_API_KEY"):
            keys.append(env_key.replace("_API_KEY", "_MODEL"))
        elif env_key.endswith("_API_TOKEN"):
            keys.append(env_key.replace("_API_TOKEN", "_MODEL"))
        return keys

    def _persist_key(self, pid: str, value: str) -> None:
        """Write one provider key to the resolved .env + live env + cache."""
        from elengenix.paths import default_env_file
        from tools.ai_config import CUSTOM_API_KEY_KEY, refresh_runtime_config

        if pid == "custom":
            env_key = CUSTOM_API_KEY_KEY
        else:
            try:
                env_key = self._provider_env_key(pid) or ""
            except Exception:
                env_key = ""
        if not env_key:
            return
        os.environ[env_key] = value
        try:
            env_path = default_env_file()
            lines = env_path.read_text().splitlines() if env_path.exists() else []
            lines = [ln for ln in lines if not ln.startswith(f"{env_key}=")]
            lines.append(f"{env_key}={value}")
            env_path.write_text("\n".join(lines) + "\n")
            try:
                env_path.chmod(0o600)
            except OSError:
                pass
        except Exception as e:
            logger.debug(f"Key persist skipped: {e}")
        try:
            refresh_runtime_config()
        except Exception:
            pass

    def _clear_provider_keys(self, pid: str) -> None:
        """Delete every env var for a provider id (env + file + references)."""
        from elengenix.paths import default_env_file
        from tools.ai_config import refresh_runtime_config

        for var in self._env_keys_for_provider(pid):
            if var in os.environ:
                del os.environ[var]
        try:
            env_path = default_env_file()
            if env_path.exists():
                doomed = set(self._env_keys_for_provider(pid))
                lines = [
                    ln
                    for ln in env_path.read_text().splitlines()
                    if not any(ln.startswith(f"{var}=") for var in doomed)
                ]
                env_path.write_text("\n".join(lines) + "\n")
        except Exception as e:
            logger.debug(f"Key clear skipped: {e}")
        # Scrub team/active references so nothing keeps naming the provider.
        team = [m.strip() for m in os.getenv("ACTIVE_MODELS", "").split(",") if m.strip()]
        kept = [m for m in team if m.split("/", 1)[0].lower() != pid.lower()]
        if len(kept) != len(team):
            if kept:
                os.environ["ACTIVE_MODELS"] = ",".join(kept)
            elif "ACTIVE_MODELS" in os.environ:
                del os.environ["ACTIVE_MODELS"]
        if os.getenv("ACTIVE_AI_PROVIDER", "").strip().lower() == pid.lower():
            del os.environ["ACTIVE_AI_PROVIDER"]
        try:
            refresh_runtime_config()
        except Exception:
            pass

    def _confirm_api_key(self) -> Optional[str]:
        """Persist the typed key immediately (Confirm & Save)."""
        prov = self._editing_provider
        value = self._api_keys_dirty.pop(prov, "").strip()
        if value:
            self._persist_key(prov, value)
        self._current_layer = "api_keys"
        self._selected_idx = 0
        self._update_items()
        return None

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
            return self._confirm_api_key()

        if action == "clear_key":
            self._api_keys_dirty.pop(self._editing_provider, None)
            self._clear_provider_keys(self._editing_provider)
            self._current_layer = "api_keys"
            self._selected_idx = 0
            self._update_items()
            return None

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
            if item_id in (
                "agent_setup",
                "api_keys",
                "rate_limits",
                "mcp_servers",
                "mode_settings",
            ):
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

    # Derived from the provider catalog (single source of truth:
    # elengenix/providers/catalog.py) — key-checking loop below uses
    # f"{id.upper()}_API_KEY", which matches every spec.env_key.
    ALL_PROVIDERS = _catalog().PROVIDER_IDS

    @staticmethod
    def _provider_env_key(pid: str):
        """Env var for a provider id from the catalog (None if key-free).

        The old code guessed ``{ID}_API_KEY``, which broke for replicate
        (``REPLICATE_API_TOKEN``).
        """
        return _catalog().env_key_for(pid)

    def _build_provider_items(self):
        from tools.ai_config import provider_status

        items = []
        for prov in self.ALL_PROVIDERS:
            try:
                has_key = bool(provider_status(prov).get("key_set"))
            except Exception:
                has_key = False
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

    @staticmethod
    def _mask_key(key_val: str) -> str:
        if len(key_val) > 4:
            return "****" + key_val[-4:]
        return key_val or "(not set)"

    def _build_api_key_items(self):
        from tools.ai_config import CUSTOM_API_BASE_KEY, provider_status

        items = []
        for prov in self.ALL_PROVIDERS:
            env_name = self._provider_env_key(prov)
            key_val = os.environ.get(env_name, "") if env_name else ""
            if not key_val:
                try:
                    key_val = "key-free" if provider_status(prov).get("key_set") else ""
                except Exception:
                    key_val = ""
            masked = self._mask_key(key_val)
            items.append({"id": f"key_{prov}", "label": f"{prov.upper()}: {masked}", "action": ""})
        # Custom endpoint key (+ its base URL so status is unambiguous).
        custom_key = os.environ.get("CUSTOM_API_KEY", "")
        custom_base = os.environ.get(CUSTOM_API_BASE_KEY, "")
        custom_label = f"CUSTOM: {self._mask_key(custom_key)}"
        if custom_base:
            custom_label += f" @ {custom_base[:40]}"
        items.append({"id": "key_custom", "label": custom_label, "action": ""})
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
            {"id": "clear_key", "label": "[DEL] Clear Saved Key", "action": "clear_key"},
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
                    items.append(
                        {
                            "id": f"mcp_toggle_{name}",
                            "label": f"  {indicator} {name} [dim]({status_text})[/dim]",
                            "action": "mcp_toggle",
                            "server_name": name,
                        }
                    )
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
                self.agent.conversation_history = saved_history

            return f"saved:{','.join(active_models)}"
        except Exception as e:
            logger.error(f"Save failed: {e}")
            return "error"

    def _save_api_key(self) -> Optional[str]:
        # Legacy entry point — Confirm & Save persists immediately now.
        return self._confirm_api_key()

    def _save_api_keys_to_env(self) -> None:
        from elengenix.paths import default_env_file

        try:
            env_path = default_env_file()
        except Exception:
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

        from elengenix.paths import default_config_file

        try:
            config_file = default_config_file()
        except Exception:
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
                "sequential-thinking": {
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-sequential-thinking"],
                },
                "reasoning-server": {"command": "npx", "args": ["-y", "mcp-reasoning-server"]},
                "chain-of-recursive-thoughts": {
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-chain-of-recursive-thoughts"],
                },
                "mcp-thinking": {"command": "npx", "args": ["-y", "mcp-thinking"]},
                "mcp-structured-thinking": {
                    "command": "npx",
                    "args": ["-y", "mcp-structured-thinking"],
                },
                "memory": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-memory"]},
            }

            for name, server_data in defaults.items():
                if name not in config.servers:
                    manager.add_server(name, server_data["command"], server_data["args"])

            self._update_items()
        except Exception as e:
            logger.debug(f"Failed to add MCP defaults: {e}")

    def _get_title(self) -> str:
        title = self._title_for(self._current_layer)
        return f"ELENGENIX {title}" if self._current_layer == "main" else title
