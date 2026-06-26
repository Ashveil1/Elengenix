"""
main.py — Red Team Agent CLI entry point and core execution loop.
"""

import itertools
import json
import re
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from redteam_agent.config import save_to_env
from redteam_agent.executor import ShellExecutor
from redteam_agent.llm import LLMClient
from redteam_agent.prompts import SPECIALIST_PROMPT, STRATEGIST_PROMPT
from redteam_agent.state import MissionState

# ── Spinner ──────────────────────────────────────────────────────────────────


class Spinner:
    """Simple terminal spinner shown while waiting for AI response."""

    def __init__(self, label: str = "Thinking"):
        self.label = label
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._spin, daemon=True)

    def _spin(self):
        for ch in itertools.cycle([".", "..", "...", "   "]):
            if self._stop.is_set():
                break
            print(f"\r{self.label}{ch}   ", end="", flush=True)
            time.sleep(0.4)
        print("\r" + " " * (len(self.label) + 6) + "\r", end="", flush=True)

    def __enter__(self):
        self._thread.start()
        return self

    def __exit__(self, *_):
        self._stop.set()
        self._thread.join()


# ── Helpers ───────────────────────────────────────────────────────────────────


def extract_json(text: str):
    """Extract JSON from LLM response (handles markdown fences)."""
    match = re.search(r"```(?:json)?\s*([\s\S]*?)\s*```", text)
    candidate = match.group(1).strip() if match else text.strip()
    try:
        return json.loads(candidate)
    except json.JSONDecodeError:
        pass
    for s, e in [("{", "}"), ("[", "]")]:
        si = candidate.find(s)
        ei = candidate.rfind(e)
        if si != -1 and ei > si:
            try:
                return json.loads(candidate[si : ei + 1])
            except json.JSONDecodeError:
                continue
    raise ValueError(f"No valid JSON in response:\n{text[:300]}")


# Keywords that indicate a real security mission (not casual chat)
_MISSION_KEYWORDS = re.compile(
    r"\b(scan|recon|pentest|exploit|enumerate|fuzz|attack|test|check|audit|"
    r"hack|target|domain|ip|port|vuln|cve|xss|sqli|ssrf|rce|lfi|idor|bola|"
    r"subdomain|endpoint|api|payload|inject|bypass|credential|shell|reverse)\b",
    re.IGNORECASE,
)


def is_mission(text: str) -> bool:
    """Return True if the input looks like a security mission, not casual chat."""
    return bool(_MISSION_KEYWORDS.search(text))


# ── Strategist ────────────────────────────────────────────────────────────────


def run_strategist(llm: LLMClient, state: MissionState):
    """Update task list. Uses fast=True to skip extended reasoning for speed."""
    user_msg = f"Current Mission State:\n{state.get_summary_prompt()}\n\nOutput the updated JSON task list now."
    try:
        with Spinner("Strategist planning"):
            raw = llm.chat(
                [
                    {"role": "system", "content": STRATEGIST_PROMPT},
                    {"role": "user", "content": user_msg},
                ],
                temperature=0.2,
                fast=True,  # ← skip Nemotron reasoning for planning
            )
        tasks = extract_json(raw)
        if isinstance(tasks, list):
            state.clear_tasks()
            for t in tasks:
                state.add_task(t.get("description", ""), t.get("status", "pending"))
    except Exception as e:
        state.add_history("Strategist", "task-refresh", f"Error: {e}")


# ── Specialist ────────────────────────────────────────────────────────────────


def run_specialist_cycle(llm: LLMClient, executor: ShellExecutor, state: MissionState) -> bool:
    """
    Single Specialist reasoning cycle.
    Returns True  → keep looping
            False → pause (agent messaged user or declared mission complete)
    """
    prompt = SPECIALIST_PROMPT.format(state_summary=state.get_summary_prompt())
    try:
        with Spinner("AI"):
            raw = llm.chat([{"role": "user", "content": prompt}], temperature=0.4)
        data = extract_json(raw)
    except Exception as e:
        print(f"\n[System] Parse error: {e}")
        state.add_history("Specialist", "parse-response", f"Error: {e}")
        return False

    action = data.get("action", "")
    thought = data.get("thought", "")
    if thought:
        print(f"\n\033[90m[Thought] {thought}\033[0m")  # Grey text for thoughts

    if action == "run_command":
        cmd = data.get("command", "").strip()
        if not cmd:
            return True
        print(f"\033[96mAI [cmd]: {cmd}\033[0m")  # Cyan for commands
        result = executor.execute(cmd)

        status_color = (
            "\033[92m[OK]\033[0m" if result["success"] else "\033[91m[FAIL]\033[0m"
        )  # Green OK, Red FAIL
        summary = f"{status_color} {result['error'] or result['stdout_summary']}"
        if result.get("stderr_summary") and not result["success"]:
            summary += f"\n\033[93m[STDERR] {result['stderr_summary']}\033[0m"  # Yellow for errors

        print(f"   -> {summary[:500]}")  # Increased summary length for better context
        state.add_history("Specialist", f"run_command: {cmd}", summary)
        return True

    elif action == "update_intel":
        intel = data.get("intel", {})
        for k, v in intel.items():
            state.add_intel(k, v)
            print(f"\033[95mAI [intel]: {k} = {v}\033[0m")  # Magenta for intel
        state.add_history("Specialist", "update_intel", f"Keys: {list(intel.keys())}")
        return True

    elif action == "message":
        print(f"\n\033[92mAI: {data.get('message', '')}\033[0m")
        return False

    elif action == "complete_mission":
        msg = data.get("message", "")
        print(f"\n\033[92m\033[1mAI [Mission Complete]: {msg}\033[0m")  # Bold green for complete
        state.add_history("Specialist", "complete_mission", msg)
        return False

    else:
        print(f"\n\033[91m[System] Unknown action '{action}'\033[0m")
        return True


# ── Casual chat ───────────────────────────────────────────────────────────────


def run_chat(llm: LLMClient, text: str):
    """Quick conversational reply for non-mission input."""
    sys_prompt = (
        "You are a Red Team AI assistant. "
        "Answer concisely. If the user greets you, greet back briefly. "
        "If the user asks what you can do, explain you help plan and execute security assessments. "
        "No markdown, no bullet points, plain text only."
    )
    try:
        with Spinner("AI"):
            reply = llm.chat(
                [
                    {"role": "system", "content": sys_prompt},
                    {"role": "user", "content": text},
                ],
                temperature=0.7,
                fast=True,
            )
        print(f"\nAI: {reply.strip()}\n")
    except Exception as e:
        print(f"\nAI: (error — {e})\n")


# ── Provider selector ─────────────────────────────────────────────────────────

import requests  # Ensure requests is available in main.py

PROVIDERS = {
    "1": ("nvidia", "NVIDIA Nemotron"),
    "2": ("gemini", "Google Gemini"),
    "3": ("openai", "OpenAI GPT"),
    "4": ("anthropic", "Anthropic Claude"),
    "5": ("custom", "Custom / OpenAI-compatible"),
    "6": ("ollama", "Ollama (local)"),
}


def get_default_base_url(provider_id: str) -> str:
    if provider_id == "gemini":
        return "https://generativelanguage.googleapis.com/v1beta/openai/v1/chat/completions"
    elif provider_id == "openai":
        return "https://api.openai.com/v1/chat/completions"
    elif provider_id == "nvidia":
        return "https://integrate.api.nvidia.com/v1/chat/completions"
    elif provider_id == "anthropic":
        return "https://api.anthropic.com/v1/messages"
    elif provider_id == "ollama":
        return "http://localhost:11434/v1/chat/completions"
    return ""


def fetch_models(provider_id: str, base_url: str, api_key: str) -> list[str]:
    """Attempt to fetch a list of available models from the provider."""
    print("  [Fetching available models...]")
    headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}
    models = []

    try:
        if provider_id == "ollama":
            url = base_url.replace("/v1/chat/completions", "/api/tags")
            resp = requests.get(url, timeout=5)
            if resp.status_code == 200:
                models = [m["name"] for m in resp.json().get("models", [])]
        elif provider_id == "anthropic":
            # Anthropic doesn't have a standard /models endpoint yet
            models = [
                "claude-3-7-sonnet-latest",
                "claude-3-5-sonnet-latest",
                "claude-3-haiku-20240307",
                "claude-3-opus-20240229",
            ]
        else:
            # Standard OpenAI-compatible /models endpoint
            url = base_url.replace("/chat/completions", "/models")
            resp = requests.get(url, headers=headers, timeout=5)
            if resp.status_code == 200:
                models = [m["id"] for m in resp.json().get("data", [])]
    except Exception:
        pass

    return models


def setup_slot(slot: int, current_provider: str):
    """Interactive wizard to configure a specific AI slot and save to .env."""
    print(f"\n\033[96m=== Setup AI {slot} ===\033[0m")

    print("\n\033[1m[Step 1] Select Provider\033[0m")
    for k, (pid, label) in PROVIDERS.items():
        active = " (active)" if pid == current_provider else ""
        print(f"  {k}. {label}{active}")

    choice = input(f"\nProvider Choice [Enter to keep '{current_provider}']: ").strip()
    provider_id = current_provider
    if choice in PROVIDERS:
        provider_id = PROVIDERS[choice][0]

    if not provider_id:
        return

    save_to_env(f"AI{slot}_PROVIDER", provider_id)

    # 2. Base URL
    base_url = ""
    if provider_id in ["custom", "ollama"]:
        print(f"\n\033[1m[Step 2] Base URL ({provider_id})\033[0m")
        base_url = input("Base URL (leave blank to keep current/default): ").strip()
        if base_url and provider_id == "custom":
            save_to_env(f"AI{slot}_CUSTOM_API_BASE", base_url)

    # 3. API Key
    api_key = ""
    if provider_id != "ollama":
        print("\n\033[1m[Step 3] API Key\033[0m")
        api_key = input("API Key (leave blank to keep current): ").strip()
        if api_key:
            env_key_name = (
                f"{provider_id.upper()}_API_KEY"
                if provider_id != "custom"
                else f"AI{slot}_CUSTOM_API_KEY"
            )
            save_to_env(env_key_name, api_key)

    # Resolve URL for fetching models
    import os

    actual_base_url = base_url or (
        os.getenv(f"AI{slot}_CUSTOM_API_BASE")
        if provider_id == "custom"
        else get_default_base_url(provider_id)
    )

    # Attempt to resolve api key if blank so we can fetch models
    resolved_key = api_key
    if not resolved_key:
        if provider_id == "gemini":
            resolved_key = os.getenv("GEMINI_API_KEY")
        elif provider_id == "openai":
            resolved_key = os.getenv("OPENAI_API_KEY")
        elif provider_id == "nvidia":
            resolved_key = os.getenv("NVIDIA_API_KEY")
        elif provider_id == "anthropic":
            resolved_key = os.getenv("ANTHROPIC_API_KEY")
        elif provider_id == "custom":
            resolved_key = os.getenv(f"AI{slot}_CUSTOM_API_KEY")

    # 4. Model
    model = ""
    print("\n\033[1m[Step 4] Select Model\033[0m")
    available_models = fetch_models(provider_id, actual_base_url, resolved_key)

    if available_models:
        print("Available Models:")
        for i, m in enumerate(available_models, 1):
            print(f"  {i}. {m}")

        m_choice = input(
            f"\nSelect Model number (or type custom name) [Enter to keep current/default]: "
        ).strip()
        if m_choice.isdigit():
            idx = int(m_choice) - 1
            if 0 <= idx < len(available_models):
                model = available_models[idx]
            else:
                model = m_choice
        else:
            model = m_choice
    else:
        model = input("Model name (leave blank to keep current/default): ").strip()

    if model:
        save_to_env(f"{provider_id.upper()}_MODEL", model)

    print(f"\n\033[92m[System] AI {slot} configuration saved successfully!\033[0m\n")


def config_dashboard():
    """Main dashboard loop to configure 3 AI slots."""
    import os

    while True:
        # Reload env logic manually or just use current environ
        ai1_p = os.getenv("AI1_PROVIDER", "")
        ai1_m = os.getenv(f"{ai1_p.upper()}_MODEL", "") if ai1_p else ""

        ai2_p = os.getenv("AI2_PROVIDER", "")
        ai2_m = os.getenv(f"{ai2_p.upper()}_MODEL", "") if ai2_p else ""

        ai3_p = os.getenv("AI3_PROVIDER", "")
        ai3_m = os.getenv(f"{ai3_p.upper()}_MODEL", "") if ai3_p else ""

        print("\n\033[96m=== AI Team Configuration ===\033[0m")
        print(f"  1. [AI 1 - Strategist] : {ai1_p or 'none'} ({ai1_m})")
        print(f"  2. [AI 2 - Specialist] : {ai2_p or 'none'} ({ai2_m})")
        print(f"  3. [AI 3 - Chat/Misc]  : {ai3_p or 'none'} ({ai3_m})")
        print("  0. Exit and Save")

        choice = input("\nSelect AI to configure (1-3) or 0 to finish: ").strip()

        if choice == "1":
            setup_slot(1, ai1_p)
        elif choice == "2":
            setup_slot(2, ai2_p)
        elif choice == "3":
            setup_slot(3, ai3_p)
        elif choice == "0":
            print("Configuration finished.\n")
            break
        else:
            print("Invalid choice.")


# ── Main ──────────────────────────────────────────────────────────────────────

MAX_LOOPS = 30


def main(run_config: bool = False):
    print("=" * 60)
    print("          RED TEAM AI FRAMEWORK  v1.0")
    print("=" * 60)

    if run_config:
        config_dashboard()

    # Load AI team from environment
    import os

    from redteam_agent.config import AI1_PROVIDER, AI2_PROVIDER, AI3_PROVIDER

    def _make_llm(n: int, provider: str) -> LLMClient:
        """Build an LLMClient for a specific slot using slot-specific env variables."""
        # Resolve base_url: prefer slot-specific custom URL
        base_url = os.getenv(f"AI{n}_CUSTOM_API_BASE") if provider == "custom" else None
        # Resolve api_key: prefer slot-specific key, then fall back to global
        api_key = os.getenv(f"AI{n}_CUSTOM_API_KEY") or os.getenv(f"{provider.upper()}_API_KEY")
        model = os.getenv(f"{provider.upper()}_MODEL")
        return LLMClient(provider=provider, model=model or None, base_url=base_url, api_key=api_key)

    # Instantiate LLMs (with fallback to AI 1 if others are missing)
    llm1 = _make_llm(1, AI1_PROVIDER) if AI1_PROVIDER else LLMClient()
    llm2 = _make_llm(2, AI2_PROVIDER) if AI2_PROVIDER else llm1
    llm3 = _make_llm(3, AI3_PROVIDER) if AI3_PROVIDER else llm1

    executor = ShellExecutor(log_dir="logs")
    state = MissionState(state_file="logs/mission_state.json")

    print("\n\033[1m[Active AI Team]\033[0m")
    print(f"  Strategist : \033[96m{llm1.provider}\033[0m ({llm1.model})")
    print(f"  Specialist : \033[96m{llm2.provider}\033[0m ({llm2.model})")
    print(f"  Chat/Misc  : \033[96m{llm3.provider}\033[0m ({llm3.model})")
    print("\nType your objective or chat. Commands: 'exit' | 'reset'\n")

    while True:
        try:
            user_input = input("You: ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\nGoodbye.")
            break

        if not user_input:
            continue
        if user_input.lower() == "exit":
            print("Goodbye.")
            break
        if user_input.lower() == "reset":
            state.reset()
            state.save()
            print("Mission state cleared.\n")
            continue

        # ── Route: casual chat vs mission ────────────────────────────────────
        if not is_mission(user_input):
            run_chat(llm3, user_input)
            continue

        # ── Mission mode ─────────────────────────────────────────────────────
        state.update_objective(user_input)
        run_strategist(llm1, state)

        if state.data["tasks"]:
            print("\nTasks:")
            for i, t in enumerate(state.data["tasks"]):
                print(f"  {i+1}. [{t['status'].upper():<10}] {t['description']}")

        print("\n[Specialist] Starting...\n")
        loops = 0
        try:
            while loops < MAX_LOOPS:
                loops += 1
                if loops > 1 and loops % 5 == 1:
                    run_strategist(llm1, state)
                keep_going = run_specialist_cycle(llm2, executor, state)
                if not keep_going:
                    break

            if loops >= MAX_LOOPS:
                print(f"\n\033[93m[System] Reached {MAX_LOOPS}-step limit. Back to prompt.\033[0m")
        except KeyboardInterrupt:
            print(
                "\n\033[93m[System] Mission interrupted by user (Ctrl+C). Returning to prompt.\033[0m"
            )
        print()


if __name__ == "__main__":
    main()
