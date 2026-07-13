"""
cli.py — Elengenix AI Partner Mode
- Universal Agent Mode: Flexible like Claude Code / Gemini CLI
- Bug Bounty Specialist Mode: Deep security expertise
- Secure Interactive CLI with Input Sanitization
- Usage Logging & Rate Limiting
- Non-blocking input with timeout support
- Robust Error Handling and Thread-safe Callbacks
- AI Usage Disclaimer & Consent Tracking
"""

import hashlib
import logging
import os
import select
import sys
import threading
import time
import warnings

warnings.filterwarnings("ignore", category=FutureWarning)
warnings.filterwarnings("ignore", message=".*google.generativeai.*")
from collections import deque
from pathlib import Path
from elengenix.paths import get_data_dir
from typing import (

from rich.align import Align
from rich.box import ASCII
from rich.console import Console
from rich.markdown import Markdown

from core.agent import get_agent
from tools.overlay_menu import SettingsOverlay
from cli.ui_components import console, render_sidebar

# Logging Setup
LOG_FILE = get_data_dir("elengenix_cli.log")
LOG_FILE.parent.mkdir(exist_ok=True)

# Use a stream handler for module-level logging to avoid unclosed file warnings.
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.StreamHandler(),
    ],
)
logger = logging.getLogger("elengenix.cli")

# Dedicated file logger (created once, flushed properly).
_file_handler = logging.FileHandler(LOG_FILE, encoding="utf-8")
_file_handler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
logger.addHandler(_file_handler)

# ── AI Disclaimer & Consent Management ─────────────────────────
CONSENT_FILE = get_data_dir(".ai_consent_accepted")

AI_DISCLAIMER_TEXT = """
[WARNING] AI SYSTEM DISCLAIMER

AI models generate responses and outputs based on complex algorithms
and machine learning techniques. Those responses or outputs may be:
  - Inaccurate or misleading
  - Harmful or inappropriate
  - Biased or incomplete
  - Outdated or incorrect

By using this AI system, you acknowledge and assume the full risk of
any harm caused by any response or output of the model.

DO NOT upload any information that is:
  - Confidential or proprietary
  - Personal data (PII, PHI) unless expressly permitted
  - Classified or sensitive government information
  - Insider information subject to trading regulations

All usage is logged for security and audit purposes.
Your behavior and inputs may be analyzed to prevent misuse.
Source: Elengenix Security Framework
"""


def _compute_disclaimer_hash() -> str:
    """Compute SHA256 of current disclaimer text for version tracking."""
    return hashlib.sha256(AI_DISCLAIMER_TEXT.encode("utf-8")).hexdigest()[:16]


def _has_user_consented() -> bool:
    """Check if user has accepted the current disclaimer version."""
    if not CONSENT_FILE.exists():
        return False
    try:
        stored = CONSENT_FILE.read_text(encoding="utf-8").strip()
        current_hash = _compute_disclaimer_hash()
        return stored == current_hash
    except Exception:
        return False


def _record_consent() -> None:
    """Record that user has accepted the current disclaimer."""
    try:
        CONSENT_FILE.write_text(_compute_disclaimer_hash(), encoding="utf-8")
    except Exception as e:
        logger.warning(f"Failed to write consent file: {e}")


def _remove_consent_record() -> None:
    """Remove consent record (used for testing or policy updates)."""
    if CONSENT_FILE.exists():
        try:
            CONSENT_FILE.unlink()
        except Exception:
            pass


def show_ai_disclaimer() -> bool:
    """
    Display AI disclaimer and request user consent.

    Returns:
        True if user accepts, False if user declines.
    """
    console.print("\n[bold red]═══════════════════════════════════════════════════[/]")
    console.print(AI_DISCLAIMER_TEXT)
    console.print("[bold red]═══════════════════════════════════════════════════[/]\n")

    # Show confirmation prompt 2 times before forcing accept/decline
    attempts = 0
    while attempts < 3:
        response = input("Do you accept these terms? (yes/no): ").strip().lower()
        if response in ("yes", "y", "accept", "agree"):
            _record_consent()
            console.print("[dim]Consent recorded. Proceeding...[/]\n")
            return True
        elif response in ("no", "n", "decline", "reject"):
            console.print("[bold red]You must accept the terms to use the AI features.[/]")
            return False
        else:
            console.print("[yellow]Please enter 'yes' or 'no'.[/]")
            attempts += 1

    # After 3 failed attempts, block usage
    console.print("[bold red]Too many invalid attempts. Access denied.[/]")
    return False


# Rate Limiting Configuration (Thread-safe)
RATE_LIMIT = 5
RATE_WINDOW = 60
user_requests = deque()
_rate_limit_lock = threading.Lock()


def check_rate_limit() -> bool:
    """Rate limit checker with thread-safe locking."""
    with _rate_limit_lock:
        rate_limit_val = int(os.getenv("ELENGENIX_RATE_LIMIT", "40"))
        rate_window = 60

        now = time.time()
        while user_requests and user_requests[0] < now - rate_window:
            user_requests.popleft()
        if len(user_requests) >= rate_limit_val:
            return False
        user_requests.append(now)
        return True


def sanitize_input(text: str, max_length: int = 2000) -> str:
    """Sanitize and truncate user input for safety.

    Uses character-class allowlisting to prevent prompt-injection and
    code-execution payloads from reaching the AI agent.
    """
    text = text.strip()
    if not text:
        return ""

    if len(text) > max_length:
        logger.warning(f"Input truncated from {len(text)} to {max_length}")
        text = text[:max_length]

    # ── Blocklist (defense-in-depth, catches obvious injection) ──────
    dangerous_exact = [
        "__import__",
        "eval(",
        "exec(",
        "os.system",
        "os.popen",
        "subprocess",
        "__builtins__",
        "open(__",
        "breakpoint(",
        "compile(",
        "getattr(",
        "setattr(",
        "delattr(",
    ]
    text_lower = text.lower()
    for pattern in dangerous_exact:
        if pattern in text_lower:
            logger.warning(f"Dangerous pattern blocked: {pattern}")
            console.print(
                f"[bold red] Security Alert: Pattern '{pattern}' is restricted.[/bold red]"
            )
            return ""

    # ── Normalise whitespace in function-call-like patterns ──────────
    #     "eval (" -> "eval("  so the blocklist above can catch it.
    import re as _re

    text = _re.sub(r"\b(exec|eval)\s*\(", r"\1(", text, flags=_re.IGNORECASE)

    # ── Character-class allowlisting ─────────────────────────────────
    #     The vast majority of legitimate inputs (URLs, filenames,
    #     search queries, Thai text) fit within these ranges.
    allowed = _re.compile(
        r"^[\w \.\,\/\:\;\?\&\=\+\~\@\#\%\!\*\-\(\)\[\]\{\}'\""
        r"\u0E00-\u0E7F"  # Thai
        r"\u4E00-\u9FFF"  # CJK (Chinese, Japanese)
        r"\u3040-\u309F"  # Hiragana
        r"\u30A0-\u30FF"  # Katakana
        r"\u0400-\u04FF"  # Cyrillic
        r"\u0600-\u06FF"  # Arabic
        r"]*$",
        _re.UNICODE,
    )
    if not allowed.match(text):
        logger.warning(f"Input contains disallowed characters: {text[:100]!r}")
        console.print("[bold red] Security Alert: Input contains disallowed characters.[/bold red]")
        return ""

    return text


def get_secure_input(prompt: str, timeout: int = 300) -> Optional[str]:
    """Retrieves user input with a timeout (Unix-friendly)."""
    console.print(prompt, end="")
    if sys.platform != "win32":
        ready, _, _ = select.select([sys.stdin], [], [], timeout)
        if ready:
            return sys.stdin.readline().rstrip("\n")
        return None
    else:
        try:
            return input()
        except EOFError:
            return None


def create_callback(console_obj: Console, use_live_display: bool = False) -> Callable[[str], None]:
    """Factory for agent thought updates - minimal output."""

    def callback(msg: str):
        # Only show important actions and results, skip thinking
        msg_lower = msg.lower()

        # Skip thinking/thought messages
        if any(
            skip in msg_lower
            for skip in ["step", "thinking", "reasoning", "i will", "i need to", "plan"]
        ):
            return

        if use_live_display:
            from cli.live_display import display_in_chat_mode

            if "→" in msg or ":" in msg[:30]:
                display_in_chat_mode(msg, "action")
            elif "success" in msg_lower or "complete" in msg_lower or "done" in msg_lower:
                display_in_chat_mode(msg, "result")
        else:
            # Show only actions and errors, skip verbose thoughts
            if "→" in msg or ":" in msg[:30]:
                console_obj.print(f"[cyan]→ {msg[:100]}[/cyan]")
            elif "error" in msg_lower or "fail" in msg_lower:
                console_obj.print(f"[red] {msg[:100]}[/red]")

    return callback


def select_agent_mode() -> str:
    """Auto-detect mode to save tokens and merge capabilities."""
    return "auto"


from prompt_toolkit.formatted_text import HTML


def get_bottom_toolbar(
    target_state: str, mode_state: str, model_name: str = "default", thinking_on: bool = False
):
    """Generate dynamic bottom toolbar with status indicators."""
    t_disp = target_state if target_state else "no target"

    # Status indicators
    research_status = "ON" if mode_state == "research" else "off"
    mode_display = "scan" if mode_state == "scan" else "normal"  # Show scan or normal
    think_status = "ON" if thinking_on else "off"

    # Team/Model display
    active_models = os.environ.get("ACTIVE_MODELS", "").split(",")
    active_models = [m.strip() for m in active_models if m.strip()]
    active_provider = os.environ.get("ACTIVE_AI_PROVIDER", "")

    if len(active_models) >= 2:
        model_display = f"team({len(active_models)})"
    elif active_provider:
        model_display = active_provider
    elif model_name != "default":
        model_display = model_name
    else:
        model_display = "model"

    # Use prompt_toolkit HTML format
    return HTML(
        " <b>workspace</b> (~/Elengenix)    "
        f"<b>target</b> ({t_disp})    "
        f"<b>ctrl+r</b>:research[<b>{research_status}</b>]    "
        f"<b>ctrl+m</b>:<b>{mode_display}</b>    "
        f"<b>ctrl+t</b>:think[<b>{think_status}</b>]    "
        f"<b>ctrl+p</b>:<b>{model_display}</b>    "
        "<b>status</b> (Ready)"
    )


def show_mode_selector(console: Console) -> Optional[str]:
    """Interactive mode selector menu."""
    modes = [
        ("auto", "Auto-detect (AI chooses mode)", "AI automatically classifies your intent"),
        ("research", "Research Mode", "Web search for current information, news, sports"),
        ("security_chat", "Security Chat", "Ask security questions, get expert advice"),
        ("scan", "Scan Mode", "Active security testing with tools (requires target)"),
        ("casual", "Casual Chat", "General conversation, greetings, chit-chat"),
    ]

    print("\n========== Mode Selector ==========")
    for i, (key, name, desc) in enumerate(modes, 1):
        print(f"  {i}. {name:<20} - {desc}")
    print("  0. Cancel (or just press Enter)")
    print("====================================")

    try:
        choice = input("Select (0-5): ").strip()
        if not choice:  # Empty = cancel
            print("Cancelled.")
            return None
        if choice.isdigit():
            idx = int(choice)
            if idx == 0:
                print("Cancelled.")
                return None
            if 1 <= idx <= len(modes):
                selected = modes[idx - 1][0]
                print(f"Selected: {selected}")
                return selected
        print("Invalid choice.")
    except (EOFError, KeyboardInterrupt):
        print("Cancelled.")
    return None


def show_model_selector(console: Console, manager: Any) -> Optional[List[Any]]:
    """Advanced interactive model selector with ultra-stable overlay feel."""
    import questionary

    def print_centered_box(title: str, subtitle: str, width: int = 60):
        """Stable centered box using string manipulation (no complex ANSI)."""
        os.system("clear" if os.name == "posix" else "cls")

        terminal_width = 80
        padding = (terminal_width - width) // 2
        pad_str = " " * padding

        # Draw Box with pure text (avoids terminal proxy color glitches)
        print("\n" * 2)
        print(f"{pad_str}╭─{'─' * (width-4)}─╮")
        print(f"{pad_str}│ {title.center(width-4)} │")
        print(f"{pad_str}╰─{'─' * (width-4)}─╯")
        print(f"{pad_str}  {subtitle.center(width-4)}  ")
        print("\n")

    try:
        # Load current team from environment
        active_models_str = os.environ.get("ACTIVE_MODELS", "")
        current_team = []
        for m in active_models_str.split(","):
            m = m.strip()
            if m:
                if "/" in m:
                    prov, mod = m.split("/", 1)
                    current_team.append({"provider": prov, "model": mod})
                else:
                    # Legacy fallback
                    prov = os.environ.get("ACTIVE_AI_PROVIDER", "auto")
                    current_team.append({"provider": prov, "model": m})

        # Pad to 3
        while len(current_team) < 3:
            current_team.append(None)

        roles = ["Strategist", "Recon Lead", "Exploit Analyst"]

        while True:
            os.system("clear" if os.name == "posix" else "cls")
            print_centered_box("TEAM AEGIS BUILDER", "Build your multi-agent security team")

            print("  Current Team Roster:")
            for i in range(3):
                agent = current_team[i]
                if agent:
                    print(
                        f"  [{i+1}] {roles[i]:<15}: {agent['provider'].upper()} / {agent['model']}"
                    )
                else:
                    print(f"  [{i+1}] {roles[i]:<15}: (Empty)")
            print("")

            # Build menu options
            options = []
            for i in range(3):
                options.append(f"Assign Agent {i+1} ({roles[i]})")

            options.append(questionary.Separator())
            options.append("Remove an Agent")
            options.append("Done / Save Team")
            options.append("Cancel")

            choice = questionary.select(
                "    Options:",
                choices=options,
                style=questionary.Style(
                    [
                        ("qmark", "fg:#ff0000 bold"),
                        ("pointer", "fg:#ff0000 bold"),
                        ("highlighted", "fg:#ffffff bg:#880000 bold"),
                        ("selected", "fg:#ff0000"),
                    ]
                ),
            ).ask()

            if choice == "Cancel" or not choice:
                return None

            if choice == "Done / Save Team":
                # Filter out empty slots
                final_team = [agent for agent in current_team if agent]
                if not final_team:
                    print("  Cannot save an empty team.")
                    time.sleep(1)
                    continue
                return final_team

            if choice == "Remove an Agent":
                remove_choices = []
                for i in range(3):
                    if current_team[i]:
                        remove_choices.append(f"Agent {i+1} ({current_team[i]['model']})")

                if not remove_choices:
                    print("  No agents to remove.")
                    time.sleep(1)
                    continue

                remove_choices.append("Back")
                to_remove = questionary.select(
                    "Select agent to remove:", choices=remove_choices
                ).ask()

                if to_remove and to_remove != "Back":
                    idx = int(to_remove.split(" ")[1]) - 1
                    current_team[idx] = None
                continue

            if choice.startswith("Assign Agent"):
                agent_idx = int(choice.split(" ")[2]) - 1

                # Step 1: Select Provider
                providers_status = manager.get_all_providers_status()
                provider_choices = []
                for p in providers_status:
                    status_label = (
                        " [ACTIVE]"
                        if p["active"]
                        else " [READY]"
                        if p["available"]
                        else " [KEY MISSING]"
                    )
                    provider_choices.append(
                        {
                            "name": f"{p['provider'].upper():<12} {status_label}",
                            "value": p["provider"],
                        }
                    )

                provider_choices.append(questionary.Separator())
                provider_choices.append(
                    {"name": "CUSTOM (OpenAI-compatible URL)", "value": "custom"}
                )
                provider_choices.append({"name": "Back", "value": None})

                selected_provider = questionary.select(
                    "    Choose Provider:", choices=provider_choices
                ).ask()
                if not selected_provider:
                    continue

                # Step 2: Handle custom provider
                if selected_provider == "custom":
                    custom_url = questionary.text("    Enter API base URL:").ask()
                    if not custom_url:
                        continue
                    custom_key = questionary.text("    Enter API key (or leave empty):").ask()
                    # Save to env AND .env file for persistence
                    os.environ["CUSTOM_API_BASE"] = custom_url
                    if custom_key:
                        os.environ["CUSTOM_API_KEY"] = custom_key
                    # Save to .env file for persistence
                    try:
                        env_path = Path(__file__).parent / ".env"
                        if not env_path.exists():
                            env_path.write_text("")
                        lines = env_path.read_text().splitlines()
                        # Remove old entries
                        lines = [
                            line
                            for line in lines
                            if not line.startswith("CUSTOM_API_BASE=")
                            and not line.startswith("CUSTOM_API_KEY=")
                        ]
                        lines.append(f"CUSTOM_API_BASE={custom_url}")
                        if custom_key:
                            lines.append(f"CUSTOM_API_KEY={custom_key}")
                        # Remove trailing empty lines
                        while lines and not lines[-1].strip():
                            lines.pop()
                        lines.append("")
                        env_path.write_text("\n".join(lines))
                    except Exception:
                        pass

                    # Fetch models from {url}/models
                    models_url = custom_url.rstrip("/")
                    if models_url.endswith("/chat/completions"):
                        models_url = models_url.replace("/chat/completions", "/models")
                    elif models_url.endswith("/v1"):
                        models_url += "/models"
                    else:
                        models_url += "/models"

                    print(f"\n  Fetching models from {models_url}...")
                    available_models = []
                    try:
                        import requests

                        headers = {}
                        if custom_key:
                            headers["Authorization"] = f"Bearer {custom_key}"
                        resp = requests.get(models_url, headers=headers, timeout=5)
                        if resp.status_code == 200:
                            data = resp.json()
                            raw = data.get("data", data if isinstance(data, list) else [])
                            for item in raw:
                                if isinstance(item, dict):
                                    mid = item.get("id", "")
                                    if mid:
                                        available_models.append(mid)
                                elif isinstance(item, str):
                                    available_models.append(item)
                    except Exception as e:
                        print(f"  Could not fetch models: {e}")

                    if not available_models:
                        available_models = ["(type manually below)"]

                    selected_model = questionary.select(
                        f"    Choose Model for Agent {agent_idx+1}:",
                        choices=available_models + ["TYPE MANUALLY"],
                    ).ask()

                    if selected_model == "TYPE MANUALLY":
                        selected_model = questionary.text("    Enter model name:").ask()
                    if not selected_model:
                        continue

                    current_team[agent_idx] = {"provider": "custom", "model": selected_model}
                    continue

                # Step 2: Select Model for regular provider
                client = manager.clients.get(selected_provider)
                if not client:
                    from tools.universal_ai_client import UniversalAIClient

                    client = UniversalAIClient(provider=selected_provider)
                    if not client.is_available():
                        print(f"\n  Error: {selected_provider} API key missing!")
                        time.sleep(2)
                        continue

                print(f"\n  Fetching models for {selected_provider}...")
                available_models = client.fetch_available_models()
                if not available_models:
                    available_models = [client.model]

                selected_model = questionary.select(
                    f"    Choose Model for Agent {agent_idx+1}:", choices=available_models
                ).ask()

                if not selected_model:
                    continue

                # Step 3: Set RPM
                env_key = f"RPM_{selected_provider.upper()}_{selected_model.upper()}"
                current_rpm = os.environ.get(env_key, "40")
                rpm_input = questionary.text(
                    f"    Set RPM for {selected_model} (Current: {current_rpm}):",
                    default=current_rpm,
                ).ask()

                try:
                    rpm_val = int(rpm_input) if rpm_input else int(current_rpm)
                except ValueError:
                    rpm_val = 40

                # Update team
                current_team[agent_idx] = {
                    "provider": selected_provider,
                    "model": selected_model,
                    "rpm": str(rpm_val),
                }

    except (EOFError, KeyboardInterrupt):
        return None
    except Exception as e:
        print(f"  Team Builder Error: {e}")
        time.sleep(2)
        return None


def show_help_panel(console: Console):
    """Show keyboard shortcuts help panel."""
    print("\n┌─ Keyboard Shortcuts ────────────────────────────────────┐")
    print("│  Ctrl+R  - Toggle Research mode [ON/off] (forces web search)")
    print("│  Ctrl+B  - Toggle Scan mode [on/OFF] (security testing)")
    print("│  Ctrl+T  - Toggle Thinking mode [on/OFF] (show AI reasoning)")
    print("│  Ctrl+P  - Open model selector (Gemini models)")
    print("│  Ctrl+G  - Show this help panel")
    print("│  Escape  - Cancel current operation")
    print("│  ?       - Show slash commands")
    print("│  /quit   - Exit Elengenix")
    print("│  /help   - Show available commands")
    print("└─────────────────────────────────────────────────────────┘")


def main(mode: str = "auto", target: Optional[str] = None):
    in_tmux = os.environ.get("TMUX") is not None

    console.clear()
    mode = "auto"

    if in_tmux:
        console.print("[bold cyan]Elengenix Core[/bold cyan] [dim](tmux mode)[/dim]\n")
    else:
        # Spacing for clean start (Banner already shown by main.py)
        console.print("  [dim]Signed in with secure profile[/dim]")
        console.print("  [dim]Plan: Elengenix Professional Edition[/dim]")
        print(
            "         ctrl+r:research[ON/off]  ctrl+b:mode[on/OFF]  ctrl+t:think[on/OFF]  ctrl+p:model"
        )
        print("────────────────────────────────────────────────────────────────────────────────")
        print(" Shift+Tab to accept edits")

    try:
        agent = get_agent()
    except Exception as e:
        logger.error(f"Agent Init Failed: {e}")
        console.print(f"[bold red] Failed to initialize Agent: {e}[/bold red]")
        return

    # ── AI Disclaimer Consent Check (First Run or Policy Update) ──────────
    if not _has_user_consented():
        console.print("[bold yellow]⚠ AI SYSTEM DISCLAIMER (First Time Setup)[/bold yellow]\n")
        accepted = show_ai_disclaimer()
        if not accepted:
            console.print(
                "[bold red]Access denied. You must accept the terms to continue.[/bold red]"
            )
            console.print("[dim]To re-accept terms later, run: elengenix cli --accept-terms[/dim]")
            return

    # Silence verbose tool/discovery logs during startup for a cleaner UI
    logging.getLogger("elengenix.agent").setLevel(logging.WARNING)
    logging.getLogger("elengenix.brain").setLevel(logging.WARNING)

    # ── Session Management ─────────────────────────────────────────────────
    from tools.session_manager import get_session_manager

    session_mgr = get_session_manager()
    session_mgr.start_session(target=target or "", mode=mode, model="default")
    callback = create_callback(console, use_live_display=in_tmux)

    # ── Persistent Sidebar + Live Layout ────────────────────────────────────
    from rich.box import MINIMAL
    from rich.layout import Layout
    from rich.live import Live
    from rich.panel import Panel
    from rich.text import Text

    SIDEBAR_W = 45

    from rich.console import Group

    class ChatLog:
        """Thread-safe chat message buffer with styled message panels and scrolling."""

        def __init__(self, max_messages=50):
            self._messages: list[dict] = []
            self._max = max_messages
            self._lock = threading.Lock()
            self._thinking = False
            self._spinner_frames = [
                "█ ",
                "▓ ",
                "▒ ",
                "░ ",
                "▒ ",
                "▓ ",
            ]
            self._spinner_idx = 0
            self._thinking_start = 0
            self._streaming_text = ""
            self._streaming_active = False
            self._streaming_done = False
            # Scroll state
            self._scroll_offset = 0
            self._viewport_lines = 20  # Approximate lines visible in content area
            self._is_scrolled = False
            # Paste state
            self._paste_buffer = ""  # Store full paste text for sending

        def add(self, text: str, role: str = "system"):
            with self._lock:
                self._messages.append({"role": role, "text": text})
                if len(self._messages) > self._max:
                    self._messages = self._messages[-self._max :]
                # Auto-reset scroll when new message arrives (unless user is actively scrolling)
                if not self._is_scrolled:
                    self._scroll_offset = 0

        def start_streaming(self):
            with self._lock:
                self._streaming_text = ""
                self._streaming_active = True
                self._streaming_done = False
                self._thinking = False

        def append_stream(self, chunk: str):
            with self._lock:
                if chunk:
                    self._streaming_text += chunk

        def end_streaming(self):
            with self._lock:
                self._streaming_active = False
                self._streaming_done = True
                if self._streaming_text:
                    self._messages.append({"role": "agent", "text": self._streaming_text})
                    self._streaming_text = ""
                    # Reset scroll to show latest when streaming ends
                    if not self._is_scrolled:
                        self._scroll_offset = 0

        def set_thinking(self, state: bool):
            with self._lock:
                self._thinking = state

        def tick_spinner(self):
            with self._lock:
                self._spinner_idx = (self._spinner_idx + 1) % len(self._spinner_frames)

        # ─── Scroll Methods ─────────────────────────────────────
        def scroll_up(self):
            """Scroll up to see older messages."""
            with self._lock:
                max_scroll = max(0, len(self._messages) - self._viewport_lines + 5)
                if self._scroll_offset < max_scroll:
                    self._scroll_offset += 1
                    self._is_scrolled = True

        def scroll_down(self):
            """Scroll down to see newer messages."""
            with self._lock:
                if self._scroll_offset > 0:
                    self._scroll_offset -= 1
                    if self._scroll_offset == 0:
                        self._is_scrolled = False

        def scroll_reset(self):
            """Reset scroll to show latest messages."""
            with self._lock:
                self._scroll_offset = 0
                self._is_scrolled = False

        def get_scroll_info(self):
            """Return (is_scrolled, offset, total)."""
            with self._lock:
                total = len(self._messages)
                return self._is_scrolled, self._scroll_offset, total

        def render(self) -> Group:
            with self._lock:
                panels = []

                # Calculate visible message range based on scroll
                total_msgs = len(self._messages)

                # If scrolled, show older messages first
                if self._scroll_offset > 0:
                    start_idx = max(0, total_msgs - self._viewport_lines - self._scroll_offset)
                    visible_msgs = self._messages[start_idx:total_msgs]
                else:
                    # Show latest messages (most recent at bottom)
                    visible_msgs = (
                        self._messages[-self._viewport_lines :]
                        if total_msgs > self._viewport_lines
                        else self._messages
                    )

                for msg in visible_msgs:
                    role = msg["role"]
                    text = msg["text"]
                    if role == "user":
                        t = (
                            Text.from_markup(text)
                            if text.startswith("[")
                            else Text(text, style="white")
                        )
                        panels.append(
                            Panel(
                                t,
                                box=ASCII,
                                border_style="#ffffff",
                                title="You",
                                title_align="left",
                                padding=(0, 1),
                                style="on #0a0a0a",
                            )
                        )
                    elif role == "agent":
                        panels.append(
                            Panel(
                                Markdown(text),
                                box=ASCII,
                                border_style="#555555",
                                title="Agent",
                                title_align="left",
                                padding=(0, 1),
                                style="on #0a0a0a",
                            )
                        )
                    elif role == "system":
                        panels.append(Text.from_markup(text))
                    elif role == "error":
                        panels.append(
                            Panel(
                                Text.from_markup(text),
                                box=ASCII,
                                border_style="#ffffff",
                                padding=(0, 1),
                                style="on #0a0a0a",
                            )
                        )

                # Streaming response with spinner animation
                if self._streaming_active:
                    display_text = self._streaming_text
                    if not display_text:
                        spin = self._spinner_frames[self._spinner_idx % len(self._spinner_frames)]
                        dots = "." * ((self._spinner_idx // 2) % 4)
                        display_text = f"{spin} [THINKING{dots}]"
                    panels.append(
                        Panel(
                            Markdown(display_text),
                            box=ASCII,
                            border_style="#555555",
                            title="Agent",
                            title_align="left",
                            padding=(0, 1),
                            style="on #0a0a0a",
                        )
                    )
                elif self._streaming_done and self._streaming_text:
                    panels.append(
                        Panel(
                            Markdown(self._streaming_text),
                            box=ASCII,
                            border_style="#555555",
                            title="Agent",
                            title_align="left",
                            padding=(0, 1),
                            style="on #0a0a0a",
                        )
                    )

                if self._thinking:
                    spin = self._spinner_frames[self._spinner_idx % len(self._spinner_frames)]
                    dots = "." * ((self._spinner_idx // 2) % 4)
                    thinking_text = Text()
                    thinking_text.append(" AGENT ", style="bold white on #0a0a0a")
                    thinking_text.append(spin, style="bold #ffffff on #0a0a0a")
                    thinking_text.append(f"  THINKING{dots}", style="bold #ffffff on #0a0a0a")
                    panels.append(
                        Panel(
                            thinking_text,
                            box=ASCII,
                            border_style="#ffffff",
                            padding=(0, 1),
                            style="on #0a0a0a",
                        )
                    )

                # Add scroll indicator if scrolled
                if self._scroll_offset > 0 or total_msgs > self._viewport_lines:
                    total = total_msgs
                    # Calculate scrollbar position
                    visible_lines = min(self._viewport_lines, total)
                    if total > visible_lines:
                        scroll_pos = int((self._scroll_offset / max(1, total - visible_lines)) * 10)
                        scrollbar = "█" * scroll_pos + "░" * (10 - scroll_pos)
                    else:
                        scrollbar = "██████████"
                    indicator = f"[#ffffff]|{scrollbar}|[/] [dim]j/k scroll[/dim]"
                    panels.append(
                        Panel(
                            Text(indicator, style="white"),
                            box=MINIMAL,
                            padding=(0, 1),
                            style="on #111111",
                        )
                    )

                return Group(*panels)

        def clear(self):
            with self._lock:
                self._messages.clear()

    chat = ChatLog()

    def _token_count() -> int:
        if not hasattr(agent, "conversation_history") or not agent.conversation_history:
            return 0
        from tools.token_counter import count_tokens

        return sum(count_tokens(str(m.get("content", ""))) for m in agent.conversation_history)

    def _get_active_model() -> str:
        active = os.environ.get("ACTIVE_MODELS", "").split(",")
        active = [m.strip() for m in active if m.strip()]
        if len(active) >= 2:
            return f"Team ({len(active)} agents)"
        if active:
            return active[0].split("/")[-1] if "/" in active[0] else active[0]
        if hasattr(agent, "client") and hasattr(agent.client, "active_client"):
            return getattr(agent.client.active_client, "model", "default")
        return model_state[0]

    def _sidebar() -> Panel:
        s = session_mgr.live
        # Get scroll info
        is_scrolled, offset, total = chat.get_scroll_info()
        # Calculate scroll percentage
        if total > 10:
            scroll_pct = min(100, int((offset / max(1, total - 10)) * 100))
            scroll_bar = "█" * int(scroll_pct / 10) + "░" * (10 - int(scroll_pct / 10))
            scroll_info = f"  [{scroll_bar}] {scroll_pct}% (j/k scroll)"
        else:
            scroll_info = ""
        return render_sidebar(
            session_name=s.name,
            mode=s.mode,
            model=_get_active_model(),
            token_count=_token_count(),
            token_limit=s.token_limit,
            target=s.target,
            turn_count=s.turn_count,
            status=s.status,
            width=SIDEBAR_W,
            scroll_info=scroll_info,
        )

    def _header() -> Panel:
        return Panel(
            "[bold #ffffff] Elengenix AI Agent Framework [/bold #ffffff]"
            "  [dim #757575]| Ctrl+R: Research  Ctrl+B: Scan  Ctrl+T: Think  Ctrl+P: Models  Ctrl+E: Settings  Ctrl+G: Help  /quit: Exit[/dim #757575]",
            box=MINIMAL,
            padding=(0, 1),
        )

    def _info_input(buf: str, cursor: int) -> Panel:
        mode_label = {
            "scan": "SCAN",
            "research": "RESEARCH",
            "security_chat": "SEC-CHAT",
        }.get(mode_state[0], mode_state[0].upper())

        is_active = mode_state[0] in ("scan", "research")
        mode_color = "#ffffff" if is_active else "#666666"

        # Top section with prompt + cursor blink
        top = Text()

        # Paste indicator at start
        if buf.startswith("[Pasted ~"):
            top.append(buf, style="bold #44FF44 on #0a0a0a")
            # Add newline and info below
            top.append("\n")
            top.append("  ", style="on #0a0a0a")
            top.append("\n")
            top.append("  ", style="on #0a0a0a")
            top.append("\n")
        else:
            # Check if paste indicator mode
            if buf.startswith("[Pasted ~") and buf.endswith("L]"):
                top.append(buf, style="bold #44FF44 on #0a0a0a")
                # Show cursor at end
                top.append("▌", style="bold blink #44FF44 on #0a0a0a")
            else:
                top.append(" Σlengenix ❭ ", style="bold #ffffff on #0a0a0a")
                if not buf:
                    top.append("▌", style="bold blink #ffffff on #0a0a0a")
                else:
                    cur = min(cursor, len(buf))
                    before = buf[:cur]
                    after = buf[cur:]
                    cursor_char = after[0] if after else "▌"
                    remaining = after[1:] if after else ""
                    top.append(before, style="white on #0a0a0a")
                    top.append(cursor_char, style="bold blink white on #ffffff")
                    if remaining:
                        top.append(remaining, style="white on #0a0a0a")

        top.append("\n")
        top.append("  ", style="on #0a0a0a")
        top.append("\n")
        top.append("  ", style="on #0a0a0a")
        top.append("\n")

        # Info bar at bottom
        bottom = Text()
        bottom.append(" MODE ", style="bold #cccccc on #111111")
        bottom.append(f" {mode_label} ", style=f"bold {mode_color} on #111111")
        if thinking_state[0]:
            bottom.append(" THINK ", style="bold #ffffff on #111111")
        # Normal input (paste shows full text in input area now)
        else:
            bottom.append("      ", style="dim #777777 on #111111")
        bottom.append(" TARGET ", style="bold #cccccc on #111111")
        bottom.append(f" {target or '—'} ", style=f"bold {mode_color} on #111111")

        combined = Text()
        combined.append_text(top)
        combined.append_text(bottom)

        return Panel(
            combined, box=ASCII, border_style="#111111", padding=(0, 1), style="on #0a0a0a"
        )

    # ── Raw terminal input (replaces prompt_toolkit for Live compatibility) ─
    import termios
    import tty

    class RawTerm:
        _old: Any

        def __enter__(self):
            if sys.stdin.isatty():
                self._old = termios.tcgetattr(sys.stdin.fileno())
                tty.setcbreak(sys.stdin.fileno())
            return self

        def __exit__(self, *a):
            if sys.stdin.isatty():
                termios.tcsetattr(sys.stdin.fileno(), termios.TCSADRAIN, self._old)

        def read_char(self, timeout=0.05):
            try:
                if not sys.stdin.isatty():
                    return None
                r, _, _ = select.select([sys.stdin], [], [], timeout)
                if not r:
                    return None
                return sys.stdin.read(1)
            except (ValueError, OSError):
                return None

    # ── Command processor ───────────────────────────────────────────────────
    mode_state = [mode]
    model_state = ["default"]
    thinking_state = [False]

    def process_cmd(cmd: str):
        nonlocal target
        cmd = cmd.strip()
        if not cmd:
            return

        chat.add(cmd, role="user")

        if cmd.lower() in ("/exit", "/quit", "exit", "quit"):
            chat.add("[dim]Agent powering down. Goodbye![/dim]")
            raise EOFError("exit")

        if cmd.lower() == "/clear":
            chat.clear()
            chat.add("[dim]Screen cleared. History preserved.[/dim]")
            return

        if cmd.lower() == "/reset":
            chat.clear()
            chat.add("[dim]Screen cleared. History reset.[/dim]")
            if hasattr(agent, "clear_conversation_history"):
                agent.clear_conversation_history()
            try:
                from tools.memory_persistence import clear_session

                clear_session("default")
                chat.add("[dim]Persistent memory cleared.[/dim]")
            except Exception:
                pass
            session_mgr.live.turn_count = 0
            session_mgr.live.token_count = 0
            return

        if cmd.lower() == "/help":
            chat.add("")
            chat.add("[bold #ffffff]Commands:[/bold #ffffff]")
            chat.add("  /clear       Clear screen (keep history)")
            chat.add("  /reset       Clear screen + reset history")
            chat.add("  /quit        Exit")
            chat.add("  /mode        Switch agent mode")
            chat.add("  /target X    Set target domain")
            chat.add("  /thinking X  Toggle AI thinking (enable/disable/auto)")
            chat.add("  /stats       Reflection & memory stats")
            chat.add("  /save [name] Save session")
            chat.add("  /load [name] Load session")
            chat.add("  /compress    Compress history (save tokens)")
            chat.add("  /skills      List available & missing tools")
            chat.add("  /install [X] Install a missing tool")
            chat.add("  /team [X,X]  View or configure multi-agent team")
            chat.add("")
            chat.add("[bold #ffffff]Shortcuts:[/bold #ffffff]")
            chat.add("  Ctrl+R  Research  |  Ctrl+B  Scan  |  Ctrl+T  Think")
            chat.add("  Ctrl+P  Models    |  Ctrl+E  Settings  |  Ctrl+G  Help  |  Ctrl+C  Exit")
            chat.add("  ↑/↓     History   |  Tab     Slash-complete")
            return

        if cmd.lower().startswith("/target"):
            parts = cmd.split(" ", 1)
            if len(parts) > 1:
                target = parts[1].strip()
                session_mgr.live.target = target
                chat.add(f"[dim]Target: {target}[/dim]")
            else:
                target = None
                session_mgr.live.target = ""
                chat.add("[dim]Target cleared.[/dim]")
            return

        if cmd.lower().startswith("/thinking"):
            parts = cmd.split(" ", 1)
            valid = ["auto", "nemotron", "enable", "disable", "none"]
            if len(parts) > 1 and parts[1].strip() in valid:
                os.environ["NVIDIA_PARAM_MODE"] = parts[1].strip()
                thinking_state[0] = parts[1].strip() in ("enable", "nemotron")
                chat.add(f"[dim]Thinking: {parts[1].strip()}[/dim]")
            else:
                cur = os.getenv("NVIDIA_PARAM_MODE", "auto")
                chat.add(f"[dim]Thinking: {cur}. Modes: {', '.join(valid)}[/dim]")
            return

        if cmd.lower() == "/mode":
            modes = [
                ("auto", "Auto-detect"),
                ("research", "Research"),
                ("security_chat", "Security Chat"),
                ("scan", "Scan"),
                ("casual", "Casual"),
            ]
            chat.add("[bold #ffffff]Modes (type /mode <name>):[/bold #ffffff]")
            for k, v in modes:
                chat.add(f"  {v} {'← current' if k == mode_state[0] else ''}")
            return

        if cmd.lower().startswith("/mode "):
            val = cmd.split(" ", 1)[1].strip()
            valid_modes = ["auto", "research", "security_chat", "scan", "casual"]
            if val in valid_modes:
                mode_state[0] = val
                session_mgr.live.mode = val
                chat.add(f"[dim]Mode: {val}[/dim]")
            else:
                chat.add(f"[dim]Invalid mode. Valid: {', '.join(valid_modes)}[/dim]")
            return

        if cmd.lower().startswith("/save"):
            parts = cmd.split(" ", 1)
            sname = parts[1].strip() if len(parts) > 1 else ""
            ok = session_mgr.save_session(sname, agent)
            chat.add(f"[dim]Session {'saved' if ok else 'failed'}: '{session_mgr.live.name}'[/dim]")
            return

        if cmd.lower().startswith("/load"):
            parts = cmd.split(" ", 1)
            sname = parts[1].strip() if len(parts) > 1 else ""
            if not sname:
                chat.add(session_mgr.format_session_list())
                return
            info = session_mgr.resume_session(sname, agent)
            if info:
                chat.add(f"[dim]Loaded '{sname}' ({info['turns']} turns)[/dim]")
                if info.get("target"):
                    target = info["target"]
                    session_mgr.live.target = target
                mode_state[0] = info.get("mode", "auto")
                session_mgr.live.mode = mode_state[0]
            else:
                chat.add(f"[dim]Not found: '{sname}'[/dim]")
            return

        if cmd.lower().startswith("/stats"):
            from tools.agent_reflection import get_reflection
            from tools.vector_memory import get_vector_memory

            refl = get_reflection()
            st = refl.get_reflection_stats()
            chat.add(
                f"[bold #ffffff]Reflection:[/bold #ffffff] Total={st.get('total', 0)} Neg={st.get('negative', 0)} Pos={st.get('positive', 0)}"
            )
            try:
                vm = get_vector_memory()
                vs = vm.get_memory_stats()
                chat.add(
                    f"[bold #ffffff]Memory:[/bold #ffffff] Entries={vs.get('total_memories', 0)} Targets={vs.get('unique_targets', 0)}"
                )
            except Exception as e:
                chat.add(f"[dim]Vector memory unavailable: {e}[/dim]")
            return

        if cmd.lower().startswith("/compress"):
            if hasattr(agent, "_summarize_old_conversation") and agent.conversation_history:
                before = len(agent.conversation_history)
                try:
                    agent._summarize_old_conversation()
                    after = len(agent.conversation_history)
                    chat.add(f"[dim]Compressed via LLM: {before} → {after} messages[/dim]")
                except Exception as e:
                    chat.add(f"[dim]LLM compress failed: {e}, trying legacy...[/dim]")
                    from tools.context_compressor import get_compressor

                    comp = get_compressor(aggressive="aggressive" in cmd.lower())
                    ch = comp.compress_and_return_history(agent.conversation_history)
                    orig = len(agent.conversation_history)
                    agent.conversation_history = ch
                    chat.add(f"[dim]Compressed: {orig} → {len(ch)} turns (legacy)[/dim]")
            elif hasattr(agent, "conversation_history") and agent.conversation_history:
                from tools.context_compressor import get_compressor

                comp = get_compressor(aggressive="aggressive" in cmd.lower())
                ch = comp.compress_and_return_history(agent.conversation_history)
                orig = len(agent.conversation_history)
                agent.conversation_history = ch
                chat.add(f"[dim]Compressed: {orig} → {len(ch)} turns[/dim]")
            else:
                chat.add("[dim]No history.[/dim]")
            return

        if cmd.lower() == "/accept-terms":
            _remove_consent_record()
            chat.add("[dim]Consent cleared. Re-showing disclaimer...[/dim]")
            return

        if cmd.lower() == "/skills":
            try:
                from tools.skill_registry import get_skill_registry

                registry = get_skill_registry()
                available = registry.get_available_skills()
                missing = registry.get_missing_skills()
                chat.add("[bold #ffffff]Skills:[/bold #ffffff]")
                if available:
                    chat.add(f"[dim]READY ({len(available)}):[/dim]")
                    for s in available:
                        chat.add(f"  [green]{s.name}[/green]: {s.description}")
                if missing:
                    chat.add(f"[dim]MISSING ({len(missing)}):[/dim]")
                    for s in missing:
                        chat.add(
                            f"  [red]{s.name}[/red]: {s.description}  [dim](install: {s.install_command})[/dim]"
                        )
                if not available and not missing:
                    chat.add("[dim]No skills registered.[/dim]")
            except ImportError:
                chat.add("[dim]Skill registry not available.[/dim]")
            return

        if cmd.lower().startswith("/install"):
            parts = cmd.split(" ", 2)
            # /install → list missing tools
            if len(parts) < 2 or not parts[1].strip():
                try:
                    from tools.skill_registry import get_skill_registry

                    registry = get_skill_registry()
                    missing = registry.get_missing_skills()
                    if missing:
                        chat.add("[bold #ffffff]Installable tools:[/bold #ffffff]")
                        for s in missing:
                            chat.add(f"  /install {s.name}: {s.description}")
                    else:
                        chat.add("[dim]All known tools are already installed.[/dim]")
                except ImportError:
                    chat.add("[dim]Skill registry not available.[/dim]")
                return

            sub = parts[1].strip().lower()
            # /install confirm <tool>
            if sub == "confirm" and len(parts) == 3:
                tool_name = parts[2].strip()
                try:
                    from tools.install_request import get_install_manager
                    from tools.skill_registry import get_skill_registry

                    mgr = get_install_manager()
                    registry = get_skill_registry()
                    pending = mgr.get_pending_requests()
                    req = None
                    for r in pending:
                        if r.tool_name == tool_name:
                            req = r
                            break
                    if not req:
                        chat.add(f"[dim]No pending install request for: {tool_name}[/dim]")
                        return
                    chat.add(f"[dim]Installing {tool_name}...[/dim]")
                    success = mgr.confirm_install(req)
                    if success:
                        chat.add(f"[OK] Installed: {tool_name}")
                    else:
                        chat.add(
                            f"[FAIL] Could not install {tool_name}. Manual: {req.install_command}[/dim]"
                        )
                except Exception as e:
                    chat.add(f"[dim]Error: {e}[/dim]")
                return
            # /install <tool>
            tool_name = parts[1].strip()
            try:
                from tools.skill_registry import get_skill_registry

                registry = get_skill_registry()
                skill = registry.skills.get(tool_name)
                if not skill:
                    chat.add(
                        f"[dim]Unknown tool: {tool_name}. Use /skills to list available tools.[/dim]"
                    )
                    return
                if skill.status.value == "available":
                    chat.add(f"[dim]{tool_name} is already installed.[/dim]")
                    return
                if hasattr(agent, "request_tool_install"):
                    result = agent.request_tool_install(tool_name, ask_first=True)
                    chat.add(f"[INFO] {result}")
                else:
                    success = registry.request_install(tool_name)
                    if success:
                        chat.add(f"[green][OK] Installed: {tool_name}[/green]")
                    else:
                        chat.add(
                            f"[red][FAIL] Could not install {tool_name}. Manual: {skill.install_command}[/red]"
                        )
            except ImportError:
                chat.add("[dim]Skill registry not available.[/dim]")
            return

        # Global short-answer: y/yes or n/no for pending installs (anytime)
        lower_trim = cmd.strip().lower()
        if lower_trim in ("y", "yes", "n", "no", "nvm", "cancel"):
            from tools.install_request import get_install_manager

            mgr = get_install_manager()
            pending = mgr.get_pending_requests()
            if pending:
                req = pending[0]
                if lower_trim in ("n", "no", "nvm", "cancel"):
                    chat.add(f"[dim]Cancelled install for: {req.tool_name}[/dim]")
                    return
                if lower_trim in ("y", "yes"):
                    chat.add(f"[dim]Installing {req.tool_name}...[/dim]")
                    success = mgr.confirm_install(req)
                    if success:
                        chat.add(f"[OK] Installed: {req.tool_name}")
                    else:
                        chat.add(
                            f"[FAIL] Could not install {req.tool_name}. Manual: {req.install_command}[/dim]"
                        )
                    return
        if cmd.lower() == "/team":
            active = [
                m.strip() for m in os.environ.get("ACTIVE_MODELS", "").split(",") if m.strip()
            ]
            if not active:
                chat.add(
                    "[dim]No team configured. Use /team <model1,model2,model3> to set up a team.[/dim]"
                )
                # Show current model
                if hasattr(agent, "client") and hasattr(agent.client, "active_client"):
                    chat.add(f"[dim]Current model: {agent.client.active_client.model}[/dim]")
                return

            # Remove trailing comma from env var
            active = [m for m in active if m and m != ","]
            if len(active) < 2:
                chat.add(
                    f"[dim]Team needs 2-3 models. Currently using: {active}. Use /team model1,model2,model3[/dim]"
                )
                return

            chat.add("[bold #ffffff]TEAM AEGIS DASHBOARD:[/bold #ffffff]")
            roles = ["Strategist", "Recon Lead", "Exploit Analyst"]
            for i, m in enumerate(active):
                role = roles[i] if i < len(roles) else f"Agent {i+1}"
                prov = "?"
                if "/" in m:
                    parts2 = m.split("/", 1)
                    prov, mod = parts2[0], parts2[1]
                else:
                    mod = m
                    prov = os.environ.get("ACTIVE_AI_PROVIDER", "?")
                chat.add(f"  [{role}] {prov}/{mod}  [dim](status: ready)[/dim]")

            chat.add(f"[dim]   Target: {target or 'not set'}[/dim]")
            chat.add(f"[dim]   Mode: {mode_state[0]}[/dim]")
            chat.add("[dim]   Use /quit to exit, any message to start team scan[/dim]")
            return

        # /team with arguments (comma-separated models)
        if cmd.lower().startswith("/team "):
            parts = cmd.split(" ", 1)
            models_str = parts[1].strip() if len(parts) > 1 else ""
            if not models_str:
                return
            from tools.universal_ai_client import AIClientManager

            manager = AIClientManager()
            # Auto-detect providers from model names
            resolved = []
            for m in models_str.split(","):
                m = m.strip()
                if not m:
                    continue
                if "/" in m:
                    resolved.append(m)
                else:
                    prov = (
                        manager._detect_provider(m)
                        if hasattr(manager, "_detect_provider")
                        else "gemini"
                    )
                    resolved.append(f"{prov}/{m}")
            os.environ["ACTIVE_MODELS"] = ",".join(resolved)
            chat.add(f"[dim]Team configured: {', '.join(resolved)}[/dim]")
            if target and mode_state[0] == "scan":
                chat.add("[dim]Ready for team scan. Start by asking about the target.[/dim]")
            else:
                chat.add("[dim]Set target and switch to scan mode for team operations.[/dim]")
            return

        # ── Send query to agent ─────────────────────────────────────────────
        user_query = sanitize_input(cmd)
        if not user_query:
            return
        if not check_rate_limit():
            chat.add("Rate limit reached. Wait a moment.", role="error")
            return

        session_mgr.set_status("thinking")
        chat.set_thinking(True)

        # For simple chat, use direct streaming via UniversalAIClient
        is_simple_chat = not target and mode_state[0] in ("auto", "security_chat", "casual")

        if is_simple_chat:
            chat.set_thinking(False)
            chat.start_streaming()

            def _stream_run():
                try:
                    from tools.universal_ai_client import UniversalAIClient

                    # Reuse the agent's already-configured active client
                    active_client = None
                    if hasattr(agent, "client"):
                        mgr = agent.client
                        if hasattr(mgr, "active_client") and mgr.active_client is not None:
                            active_client = mgr.active_client
                        elif isinstance(mgr, UniversalAIClient):
                            active_client = mgr

                    if active_client is None:
                        # Fallback: create new client using same env vars
                        active = [
                            m.strip()
                            for m in os.environ.get("ACTIVE_MODELS", "").split(",")
                            if m.strip()
                        ]
                        model = active[0] if active else "nvidia/nemotron-3-super-120b-a12b"
                        provider = model.split("/")[0] if "/" in model else "nvidia"
                        active_client = UniversalAIClient(model=model, provider=provider)

                    url = active_client.base_url.rstrip("/") + "/chat/completions"

                    # Build system prompt from context
                    system_prompt = "You are Elengenix AI Agent Framework, a security research assistant. Be concise and helpful."

                    payload = {
                        "model": active_client.model,
                        "messages": [
                            {"role": "system", "content": system_prompt},
                            {"role": "user", "content": user_query},
                        ],
                        "temperature": 0.7,
                        "max_tokens": 4096,
                        "stream": True,
                    }

                    # NVIDIA-specific parameters
                    if active_client.provider == "nvidia":
                        param_mode = os.environ.get("NVIDIA_PARAM_MODE", "auto")
                        model_lower = active_client.model.lower()
                        if param_mode == "nemotron" or (
                            param_mode == "auto" and "nemotron" in model_lower
                        ):
                            payload["chat_template_kwargs"] = {"enable_thinking": True}
                            payload["reasoning_budget"] = min(4096, 16384)

                    full_response = []
                    for chunk in active_client._stream_response(url, payload):
                        if chunk:
                            chat.append_stream(chunk)
                            full_response.append(chunk)

                    chat.end_streaming()
                    session_mgr.update_turn()
                    session_mgr.set_status("ready")
                except Exception as ex:
                    chat.end_streaming()
                    chat.add(f"Error: {ex}", role="error")
                    session_mgr.set_status("error")

            t = threading.Thread(target=_stream_run, daemon=True)
            t.start()
            return

        # For scan/research, use the full agent (non-streaming)
        # Auto-detect if team mode should be used
        is_scan_mode = mode_state[0] in ("scan", "bug_bounty")
        active_models = [
            m.strip() for m in os.environ.get("ACTIVE_MODELS", "").split(",") if m.strip()
        ]
        # If user configured multiple models (via /team or env), use team
        use_team = is_scan_mode and target and len(active_models) >= 2

        if use_team:
            chat.add(f"[dim]Auto team mode: {len(active_models)} agents[/dim]")

        try:

            def _run():
                try:
                    active = [
                        m.strip()
                        for m in os.environ.get("ACTIVE_MODELS", "").split(",")
                        if m.strip()
                    ]
                    if len(active) >= 2 and target and mode_state[0] in ("scan", "bug_bounty"):
                        resp = agent.process_team_scan(
                            user_query, model_names=active, target=target, callback=callback
                        )
                    else:
                        resp = agent.process_universal(
                            user_query, callback=callback, target=target, mode=mode_state[0]
                        )

                    # Add response to chat (thread-safe)
                    if resp:
                        chat.set_thinking(False)
                        chat.add(resp, role="agent")
                        session_mgr.update_turn()
                        session_mgr.set_status("ready")
                    else:
                        chat.set_thinking(False)
                        chat.add("No response.", role="error")
                        session_mgr.set_status("error")
                except Exception as ex:
                    import traceback

                    traceback.print_exc()
                    chat.set_thinking(False)
                    chat.add(f"Error: {ex}", role="error")
                    session_mgr.set_status("error")

            t = threading.Thread(target=_run, daemon=True)
            t.start()
            # Don't block - let the thread run in background
            return
        except Exception as e:
            chat.add(f"Error: {e}", role="error")
            session_mgr.set_status("error")
            chat.set_thinking(False)

    # ── Key handler ─────────────────────────────────────────────────────────
    SLASH_CMDS = [
        "/exit",
        "/quit",
        "/clear",
        "/reset",
        "/help",
        "/mode",
        "/target",
        "/thinking",
        "/save",
        "/load",
        "/stats",
        "/compress",
        "/accept-terms",
        "/install",
        "/team",
        "/skills",
    ]
    ARROW = {"[A": "UP", "[B": "DOWN", "[C": "RIGHT", "[D": "LEFT"}
    PAGE = {"[5~": "PAGEUP", "[6~": "PAGEDOWN"}  # Page Up / Page Down

    def handle_key(ch, buf, cur_pos, history, hidx):
        """Returns (new_buf, new_cur_pos, new_hidx, consumed). consumed=True means exit."""
        if ch is None:
            return buf, cur_pos, hidx, False
        # Escape seq
        if ch == "\x1b":
            s1 = raw.read_char(0.05) or ""
            if s1 == "[":
                s2 = raw.read_char(0.05) or ""
                act = ARROW.get(s2)
                page_act = PAGE.get(s2)
                if act == "UP" and history:
                    hidx = max(0, hidx - 1)
                    buf = history[hidx]
                    cur_pos = len(buf)
                elif act == "DOWN" and history:
                    hidx = min(len(history) - 1, hidx + 1)
                    buf = history[hidx]
                    cur_pos = len(buf)
                elif act == "LEFT":
                    cur_pos = max(0, cur_pos - 1)
                elif act == "RIGHT":
                    cur_pos = min(len(buf), cur_pos + 1)
                elif page_act == "PAGEUP":
                    chat.scroll_up()
                    return buf, cur_pos, hidx, False
                elif page_act == "PAGEDOWN":
                    chat.scroll_down()
                    return buf, cur_pos, hidx, False
            return buf, cur_pos, hidx, False

        if ch == "\x03" or ch == "\x04":
            chat.add("[dim]Session ended. Goodbye![/dim]")
            return buf, cur_pos, hidx, True  # exit

        if ch == "\x07":  # Ctrl+G help
            chat.add("")
            chat.add("[bold #ffffff]Shortcuts:[/bold #ffffff]")
            chat.add("  Ctrl+R  Research  |  Ctrl+B  Scan  |  Ctrl+T  Think")
            chat.add("  Ctrl+P  Models    |  Ctrl+E  Settings  |  Ctrl+G  Help  |  Ctrl+C  Exit")
            chat.add("  ↑/↓     History   |  Tab     Complete")
            chat.add("  PgUp   Scroll Up  |  PgDn   Scroll Down")
            return buf, cur_pos, hidx, False

        if ch == "\x12":  # Ctrl+R research
            if mode_state[0] == "research":
                mode_state[0] = "auto"
                session_mgr.live.mode = "auto"
                chat.add("[dim]Research: OFF[/dim]")
            else:
                mode_state[0] = "research"
                session_mgr.live.mode = "research"
                chat.add("[dim]Research: ON[/dim]")
            return buf, cur_pos, hidx, False

        if ch == "\x02":  # Ctrl+B scan
            if mode_state[0] == "scan":
                mode_state[0] = "auto"
                session_mgr.live.mode = "auto"
                chat.add("[dim]Mode: NORMAL[/dim]")
            else:
                mode_state[0] = "scan"
                session_mgr.live.mode = "scan"
                chat.add("[dim]Mode: SCAN[/dim]")
            return buf, cur_pos, hidx, False

        if ch == "\x14":  # Ctrl+T think
            cur = os.environ.get("NVIDIA_PARAM_MODE", "auto")
            if cur in ("enable", "nemotron"):
                os.environ["NVIDIA_PARAM_MODE"] = "disable"
                thinking_state[0] = False
                chat.add("[dim]Thinking: OFF[/dim]")
            else:
                os.environ["NVIDIA_PARAM_MODE"] = "enable"
                thinking_state[0] = True
                chat.add("[dim]Thinking: ON[/dim]")
            return buf, cur_pos, hidx, False

        if ch == "\x10":  # Ctrl+P model info
            am = os.environ.get("ACTIVE_MODELS", "")
            chat.add(f"[dim]Active models: {am or model_state[0]}[/dim]")
            return buf, cur_pos, hidx, False

        # Scroll keys: j/k (vim-style) or Ctrl+U/D
        if ch == "j" and not buf:
            chat.scroll_down()
            return buf, cur_pos, hidx, False
        if ch == "k" and not buf:
            chat.scroll_up()
            return buf, cur_pos, hidx, False
        if ch == "\x15":  # Ctrl+U = scroll up
            for _ in range(3):
                chat.scroll_up()
            return buf, cur_pos, hidx, False
        if ch == "\x04":  # Ctrl+D = scroll down
            for _ in range(3):
                chat.scroll_down()
            return buf, cur_pos, hidx, False

        # Paste buffer state (module-level for handle_key)
        if not hasattr(handle_key, "_paste_raw_buffer"):
            handle_key._paste_raw_buffer = ""
        if not hasattr(handle_key, "_is_pasting"):
            handle_key._is_pasting = False
        if not hasattr(handle_key, "_last_key_time"):
            handle_key._last_key_time = time.time()

        # Track timing for paste detection
        current_time = time.time()
        time_since_last = current_time - handle_key._last_key_time
        handle_key._last_key_time = current_time

        # Detect paste via rapid input (characters arriving < 5ms apart AND multiple lines)
        if time_since_last < 0.05 and not handle_key._is_pasting:
            # Start monitoring for rapid-fire paste
            if buf.count("\n") >= 2:
                handle_key._is_pasting = True

        # Enter key - send on \r or \n
        if ch == "\r" or ch == "\n":
            # If paste indicator mode (shown in buffer), send full pasted text
            if buf.startswith("[Pasted ~"):
                full_text = getattr(handle_key, "_paste_content", "")
                if full_text and full_text.strip():
                    history.append(full_text)
                    hidx = len(history)
                    process_cmd(full_text)
                handle_key._paste_content = ""
                handle_key._is_pasting = False
                handle_key._paste_raw_buffer = ""
                return "", 0, hidx, False

            # If actively pasting (detected rapid input), add newline instead of sending
            if handle_key._is_pasting:
                handle_key._is_pasting = False  # Reset for next detection
                buf = buf[:cur_pos] + "\n" + buf[cur_pos:]
                cur_pos += 1
                return buf, cur_pos, hidx, False

            # If buffer has 5+ newlines (likely paste), display indicator
            if buf.count("\n") >= 5:
                handle_key._paste_content = buf
                line_count = buf.count("\n") + 1
                buf = f"[Pasted ~{line_count}L]"
                cur_pos = len(buf)
                return buf, cur_pos, hidx, False

            # If buffer has newlines but < 5, require double Enter to send
            if buf.count("\n") >= 1:
                line_parts = buf.split("\n")
                last_line = line_parts[-1] if line_parts else ""
                if not last_line.strip():
                    # Second Enter on empty line = send
                    if buf.strip():
                        history.append(buf)
                        hidx = len(history)
                        process_cmd(buf)
                        return "", 0, hidx, False
                else:
                    # First Enter on non-empty line = add newline
                    buf = buf[:cur_pos] + "\n" + buf[cur_pos:]
                    cur_pos += 1
                    return buf, cur_pos, hidx, False

            # Normal single-line: send
            if buf.strip():
                history.append(buf)
                hidx = len(history)
                process_cmd(buf)
                return "", 0, hidx, False

            return "", 0, hidx, False

        if ch in ("\x07", "\x08"):
            if cur_pos > 0:
                buf = buf[: cur_pos - 1] + buf[cur_pos:]
                cur_pos -= 1
            return buf, cur_pos, hidx, False

        if ch == "\t":
            if buf.startswith("/"):
                word = buf.split(" ")[0]
                matches = [c for c in SLASH_CMDS if c.startswith(word)]
                if len(matches) == 1:
                    buf = matches[0] + " "
                    cur_pos = len(buf)
                elif len(matches) > 1:
                    chat.add("")
                    for m in matches:
                        chat.add(f"[bold #ffffff]{m}[/bold #ffffff]")
                    chat.add("[dim]Press Tab to select[/dim]")
            return buf, cur_pos, hidx, False

        if len(ch) == 1 and ord(ch) >= 32:
            buf = buf[:cur_pos] + ch + buf[cur_pos:]
            cur_pos += 1
            # Detect paste: 5+ newlines in buffer with indicator replacement
            if not buf.startswith("[Pasted ~"):
                line_count = buf.count("\n") + 1
                if line_count >= 6:  # 6+ lines = paste
                    handle_key._paste_content = buf
                    buf = f"[Pasted ~{line_count}L]"
                    cur_pos = len(buf)

        return buf, cur_pos, hidx, False

    # ── Run Live loop ───────────────────────────────────────────────────────
    raw = RawTerm()
    # Welcome banner with ASCII logo
    chat.add(
        "    [bold #ffffff] ███████╗██╗     ███████╗███╗   ██╗ ██████╗ ███████╗███╗   ██╗[/bold #ffffff]",
        role="system",
    )
    chat.add(
        "    [bold #FF4757] ██╔════╝██║     ██╔════╝████╗  ██║██╔════╝ ██╔════╝████╗  ██║[/bold #FF4757]",
        role="system",
    )
    chat.add(
        "    [bold #DC143C] █████╗  ██║     █████╗  ██╔██╗ ██║██║  ███╗█████╗  ██╔██╗ ██║[/bold #DC143C]",
        role="system",
    )
    chat.add(
        "    [bold #B22222] ██╔══╝  ██║     ██╔══╝  ██║╚██╗██║██║   ██║██╔══╝  ██║╚██╗██║[/bold #B22222]",
        role="system",
    )
    chat.add(
        "    [bold #8B0000] ███████╗███████╗███████╗██║ ╚████║╚██████╔╝███████╗██║ ╚████║[/bold #8B0000]",
        role="system",
    )
    chat.add(
        "    [dim #ffffff] ╚══════╝╚══════╝╚══════╝╚═╝  ╚═══╝ ╚═════╝ ╚══════╝╚═╝  ╚═══╝[/dim #ffffff]",
        role="system",
    )
    chat.add("           [dim #ffffff]Universal AI & Bug Bounty Agent[/dim #ffffff]", role="system")
    chat.add("           [dim]Type /help for commands[/dim]", role="system")

    with raw:
        layout = Layout()
        layout.split_row(
            Layout(name="main"),
            Layout(name="sidebar", size=SIDEBAR_W),
        )
        layout["main"].split_column(
            Layout(name="header", size=2),
            Layout(name="content"),
            Layout(name="input", size=4),  # Start small, expand dynamically
        )

        ibuf, icur, hist, hidx = "", 0, [], 0
        show_overlay = [False]
        overlay_obj: list[Any] = [None]

        with Live(layout, screen=True, refresh_per_second=10) as live:
            try:
                while True:
                    try:
                        chat.tick_spinner()
                    except Exception:
                        import traceback

                        traceback.print_exc()
                        break

                    # Dynamic input height: 1 line = 1, +2 for padding
                    lines = ibuf.count("\n") + 1 if ibuf else 1
                    input_height = max(4, min(15, lines + 2))  # min 4, max 15

                    # Recreate layout with new input size
                    layout["main"].split_column(
                        Layout(name="header", size=2),
                        Layout(name="content"),
                        Layout(name="input", size=input_height),
                    )

                    layout["sidebar"].update(_sidebar())
                    layout["header"].update(_header())
                    if show_overlay[0]:
                        try:
                            layout["content"].update(
                                Align.center(overlay_obj[0].render(), vertical="middle")
                            )
                            layout["input"].update(
                                Panel(
                                    "[dim]Settings Overlay - Esc to cancel, Enter to select[/dim]"
                                )
                            )
                        except Exception as e:
                            print(f"[RENDER ERROR] {e}", file=sys.stderr)
                            show_overlay[0] = False
                            overlay_obj[0] = None
                    else:
                        try:
                            layout["content"].update(chat.render())
                            input_panel = _info_input(ibuf, icur)
                            layout["input"].update(input_panel)
                        except Exception as e:
                            traceback.print_exc()
                            print(f"RENDER ERROR: {e}", file=sys.stderr)

                    # Read input
                    ch = raw.read_char(0.05)
                    exit_flag = False
                    if ch:
                        if ch == "\x05":
                            if show_overlay[0]:
                                show_overlay[0] = False
                                overlay_obj[0] = None
                            else:
                                overlay_obj[0] = SettingsOverlay(agent, console, target=target)
                                show_overlay[0] = True
                        elif show_overlay[0]:
                            try:
                                result = overlay_obj[0].handle_char(ch)
                            except Exception:
                                result = None
                            if result == "exit":
                                show_overlay[0] = False
                                overlay_obj[0] = None
                            elif result == "saved":
                                chat.add("[OK] Settings saved. Agent reloaded.", role="system")
                                show_overlay[0] = False
                                overlay_obj[0] = None
                            elif result == "error":
                                chat.add(
                                    "[WARN] Failed to save settings. Check logs.", role="error"
                                )
                                show_overlay[0] = False
                                overlay_obj[0] = None
                        elif not show_overlay[0]:
                            ibuf, icur, hidx, exit_flag = handle_key(ch, ibuf, icur, hist, hidx)
                    if exit_flag:
                        break
            except (EOFError, KeyboardInterrupt):
                chat.add("[dim]Session ended.[/dim]")
                layout["content"].update(chat.render())
                live.refresh()
                time.sleep(0.3)


if __name__ == "__main__":
    main()
