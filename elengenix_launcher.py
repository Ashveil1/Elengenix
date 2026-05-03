#!/usr/bin/env python3
"""
elengenix_launcher.py -- Elengenix CLI Launcher (v3.0.0)

Lightweight entry point for the Elengenix Bug Bounty Automation Platform.
Routes user commands to the appropriate subsystem modules without
requiring heavy imports at startup.

Usage:
    python elengenix_launcher.py <command> [options]
    python elengenix_launcher.py help

Environment:
    Automatically activates the project's virtual environment if present.

Author: Elengenix Project Contributors
"""

import sys
import os
import subprocess
import logging
from pathlib import Path
from typing import List

logger = logging.getLogger("elengenix.launcher")


# ---------------------------------------------------------------------------
# Terminal Color Codes (ANSI)
# Used only in this module to avoid importing Rich at startup for speed.
# ---------------------------------------------------------------------------

class Colors:
    """ANSI escape codes for terminal output styling (Ancient Greek Theme)."""
    HEADER    = "\033[38;5;178m"  # Gold3
    BLUE      = "\033[38;5;67m"   # Steel Blue
    CYAN      = "\033[38;5;178m"  # Gold3 (Replaces Cyan for primary text)
    GREEN     = "\033[38;5;113m"  # Dark Olive Green2
    YELLOW    = "\033[38;5;208m"  # Dark Orange
    RED       = "\033[38;5;131m"  # Indian Red
    BOLD      = "\033[1m"
    DIM       = "\033[2m"
    UNDERLINE = "\033[4m"
    END       = "\033[0m"


# ---------------------------------------------------------------------------
# Environment Bootstrap
# ---------------------------------------------------------------------------

def bootstrap() -> Path:
    """Detect project root and activate virtual environment if present.

    Returns:
        Path to the project root directory.
    """
    project_root = Path(__file__).parent.absolute()
    venv_bin = project_root / "venv" / "bin"

    if venv_bin.exists():
        current_path = os.environ.get("PATH", "")
        if str(venv_bin) not in current_path:
            os.environ["PATH"] = f"{venv_bin}:{current_path}"

    # Load .env file (API keys, model preferences, rate limits)
    env_file = project_root / ".env"
    if env_file.exists():
        try:
            from dotenv import load_dotenv
            load_dotenv(env_file, override=False)
        except ImportError:
            # Fallback: manual .env parsing if python-dotenv is missing
            for line in env_file.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    key, _, value = line.partition("=")
                    key, value = key.strip(), value.strip()
                    if key and key not in os.environ:
                        os.environ[key] = value

    return project_root


# ---------------------------------------------------------------------------
# UI Output Utilities
# ---------------------------------------------------------------------------

class ElengenixUI:
    """Lightweight terminal UI with color-coded output and text-only markers."""

    MARKERS = {
        "info":    "[*]",
        "success": "[OK]",
        "error":   "[FAIL]",
        "warning": "[WARN]",
        "header":  "",
        "bold":    "",
    }

    @classmethod
    def print(cls, message: str, style: str = "info"):
        color_map = {
            "info":    Colors.CYAN,
            "success": Colors.GREEN,
            "error":   Colors.RED,
            "warning": Colors.YELLOW,
            "header":  Colors.HEADER,
            "bold":    Colors.BOLD,
        }
        color = color_map.get(style, Colors.END)
        marker = cls.MARKERS.get(style, "")
        if marker:
            print(f"{color}{marker}{Colors.END} {message}")
        else:
            print(f"{color}{message}{Colors.END}")

    @classmethod
    def banner(cls):
        """Display the professional application banner."""
        width = 62
        line = Colors.BLUE + ("─" * width) + Colors.END
        print()
        print(line)
        print(f"{Colors.BOLD}{Colors.CYAN}  ELENGENIX{Colors.END}  {Colors.DIM}v3.0.0  |  Universal AI + Bug Bounty Agent{Colors.END}")
        print(line)
        print()


# ---------------------------------------------------------------------------
# Application Router
# ---------------------------------------------------------------------------

class ElengenixApp:
    """Main application command router.

    Maps CLI arguments to handler methods. Each handler either:
    - Handles logic directly (lightweight commands), OR
    - Delegates to main.py via subprocess (full-featured commands).

    All commands go through this router — no "Unknown command" surprises.
    """

    # All supported commands grouped by category (for help display)
    COMMAND_GROUPS = {
        "AI & Agent": [
            ("ai [query]",           "Interactive AI chat assistant"),
            ("cli",                  "Gemini-style CLI session (prompt_toolkit)"),
            ("universal",            "Autonomous agent mode — open-ended tasks"),
            ("autonomous <target>",  "Fully autonomous AI-driven scan"),
        ],
        "Reconnaissance": [
            ("recon <domain>",       "Subdomain + asset discovery & correlation"),
            ("scan <target>",        "Full pipeline: Recon -> Vuln -> Report"),
            ("mission <target>",     "Start autonomous scanning mission"),
            ("bounty [program]",     "Bug bounty program intel & predictor"),
            ("programs",             "List known bug bounty programs"),
        ],
        "Exploitation & Testing": [
            ("bola <url>",           "BOLA / IDOR differential tests"),
            ("waf <url>",            "WAF detection & XSS bypass engine"),
            ("evasion",              "EDR/AV evasion framework"),
            ("research <CVE|type>",  "CVE research + PoC generator"),
            ("poc <vuln-type>",      "Generate custom exploit PoC"),
        ],
        "Analysis & Intelligence": [
            ("sast <file|dir>",      "Static code analysis (Python, JS, Go, Java)"),
            ("cloud <file|dir>",     "Terraform / IaC / cloud security review"),
            ("mobile <target>",      "Mobile API traffic analysis & fuzzing"),
            ("soc [logfile]",        "Security log & SIEM threat analysis"),
        ],
        "Reports & Memory": [
            ("report [findings]",    "Generate HTML/PDF security report"),
            ("memory",               "View & search AI semantic memory"),
            ("history",              "Browse past scan sessions"),
            ("dashboard",            "Launch live web dashboard (browser UI)"),
            ("cve-update",           "Refresh local CVE database"),
        ],
        "Mission Control": [
            ("status <mission_id>",  "Check mission status"),
            ("pause <mission_id>",   "Pause a running mission"),
            ("resume <mission_id>",  "Resume a paused mission"),
        ],
        "System": [
            ("doctor",               "System health check — tools & API keys"),
            ("configure",            "Set up AI providers, Telegram, HackerOne"),
            ("gateway",              "Start Telegram bot gateway"),
            ("arsenal",              "Manual tool selector menu"),
            ("menu",                 "Interactive categorized menu"),
            ("update",               "Update framework via git pull"),
            ("help",                 "Show this help message"),
        ],
    }

    # Commands that delegate to main.py (full Rich/heavy-import pipeline)
    DELEGATE_TO_MAIN = {
        "ai", "cli", "universal", "autonomous",
        "recon", "scan", "bola", "waf", "evasion",
        "research", "poc", "sast", "cloud", "mobile", "soc",
        "report", "memory", "history", "dashboard", "cve-update",
        "configure", "gateway", "arsenal", "menu", "update",
        "profile", "intel", "web", "api", "bb", "check", "test",
        "red", "pdf", "hack", "quick", "deep", "stealth",
    }

    def __init__(self):
        self.root = bootstrap()
        self.main_py = self.root / "main.py"

    def run(self, args: List[str]):
        """Route the command to the appropriate handler."""
        if not args or args[0] in ["help", "-h", "--help"]:
            self.show_help()
            return

        command = args[0]
        remaining = args[1:]

        # Commands with native handlers in this launcher
        native_handlers = {
            "mission":   self.cmd_mission,
            "bounty":    self.cmd_bounty,
            "programs":  self.cmd_programs,
            "status":    self.cmd_status,
            "pause":     self.cmd_pause,
            "resume":    self.cmd_resume,
            "doctor":    self.cmd_doctor,
            "telegram":  self.cmd_telegram,
        }

        if command in native_handlers:
            native_handlers[command](remaining)
        elif command in self.DELEGATE_TO_MAIN:
            self._delegate(args)  # pass ALL args including command
        else:
            self.cmd_unknown(command)

    def _delegate(self, args: List[str]):
        """Pass command to main.py (full-featured pipeline)."""
        if not self.main_py.exists():
            ElengenixUI.print(f"main.py not found at {self.main_py}", "error")
            return
        try:
            result = subprocess.run(
                [sys.executable, str(self.main_py)] + args,
                cwd=str(self.root),
            )
            sys.exit(result.returncode)
        except KeyboardInterrupt:
            # Handle Ctrl+C during subprocess execution
            print(f"\n{Colors.DIM}[info] Interrupt received. Closing session...{Colors.END}")
            sys.exit(0)

    # -- Help Display -------------------------------------------------------

    def show_help(self):
        """Display the categorized help menu."""
        ElengenixUI.banner()

        print(f"{Colors.BOLD}Usage:{Colors.END} elengenix <command> [target] [options]")
        print()
        print(f"  {Colors.DIM}Smart mode — just type a target:{Colors.END}")
        print(f"    {Colors.GREEN}elengenix example.com{Colors.END}         →  auto-detect and route")
        print(f"    {Colors.GREEN}elengenix https://api.x.com/{Colors.END}  →  BOLA / WAF workflow")
        print(f"    {Colors.GREEN}elengenix myapp.py{Colors.END}            →  SAST static scan")
        print()

        for category, commands in self.COMMAND_GROUPS.items():
            print(f"  {Colors.BOLD}{category}{Colors.END}")
            for cmd, desc in commands:
                print(f"    {Colors.CYAN}{cmd:<28}{Colors.END} {desc}")
            print()

        print(f"{Colors.BOLD}Examples:{Colors.END}")
        print(f"  {Colors.GREEN}elengenix bounty{Colors.END}")
        print(f"  {Colors.GREEN}elengenix mission example.com{Colors.END}")
        print(f"  {Colors.GREEN}elengenix doctor{Colors.END}")
        print(f"  {Colors.GREEN}elengenix configure{Colors.END}")
        print(f"  {Colors.GREEN}elengenix menu{Colors.END}")
        print()

    # -- Native Command Handlers --------------------------------------------

    def cmd_mission(self, args):
        """Start an autonomous scanning mission against a target."""
        if not args:
            ElengenixUI.print("Usage: elengenix mission <target>", "warning")
            return
        target = args[0]
        ElengenixUI.print(f"Starting mission: {target}", "info")
        try:
            from tools.smart_scanner import SmartScanner
            scanner = SmartScanner(target=target)
            results = scanner.run()
            findings = len(results.get("findings", []))
            ElengenixUI.print(f"Complete. Findings: {findings}", "success")
        except Exception as e:
            ElengenixUI.print(f"Mission failed: {e}", "error")

    def cmd_bounty(self, args):
        """Discover bug bounty programs from public and API sources."""
        ElengenixUI.print("Discovering programs...", "info")
        try:
            from tools.bounty_intelligence import BountyIntelligence
            api_key = os.environ.get("HACKERONE_API_KEY")
            api_user = os.environ.get("HACKERONE_API_USER")
            intel = BountyIntelligence(api_key=api_key, api_username=api_user)
            programs = intel.discover_programs_api(500, 10) if api_key else intel.discover_programs_public(10)
            if programs:
                ranked = intel.rank_programs(programs)
                top = ranked[0]
                ElengenixUI.print(f"Top program: {top.name}", "success")
                print(f"    Reward: {top.bounty_range}")
                print(f"    URL:    {top.url}")
                print(f"    Run:    elengenix mission {top.url}")
            else:
                ElengenixUI.print("No programs found", "warning")
        except Exception as e:
            ElengenixUI.print(f"Discovery failed: {e}", "error")

    def cmd_programs(self, args):
        """List available bug bounty programs (alias for bounty)."""
        self.cmd_bounty(args)

    def cmd_status(self, args):
        """Check the status of a running or completed mission."""
        if not args:
            ElengenixUI.print("Usage: elengenix status <mission_id>", "warning")
            return
        mission_id = args[0]
        ElengenixUI.print(f"Checking: {mission_id}...", "info")
        try:
            from tools.smart_scanner import SmartScanner
            scanner = SmartScanner.load(mission_id)
            if scanner:
                status = scanner.get_status()
                print(f"    Status:   {status.get('status', 'unknown')}")
                print(f"    Phase:    {status.get('current_phase', 'unknown')}")
                print(f"    Findings: {status.get('findings_count', 0)}")
            else:
                ElengenixUI.print(f"Not found: {mission_id}", "warning")
        except Exception as e:
            ElengenixUI.print(f"Status check failed: {e}", "error")

    def cmd_pause(self, args):
        """Pause a running mission."""
        if not args:
            ElengenixUI.print("Usage: elengenix pause <mission_id>", "warning")
            return
        mission_id = args[0]
        ElengenixUI.print(f"Pausing: {mission_id}...", "info")
        try:
            from tools.smart_scanner import SmartScanner
            scanner = SmartScanner.load(mission_id)
            if scanner:
                scanner.pause()
                ElengenixUI.print(f"Paused: {mission_id}", "success")
            else:
                ElengenixUI.print(f"Not found: {mission_id}", "warning")
        except Exception as e:
            ElengenixUI.print(f"Pause failed: {e}", "error")

    def cmd_resume(self, args):
        """Resume a paused mission."""
        if not args:
            ElengenixUI.print("Usage: elengenix resume <mission_id>", "warning")
            return
        mission_id = args[0]
        ElengenixUI.print(f"Resuming: {mission_id}...", "info")
        try:
            from tools.smart_scanner import SmartScanner
            scanner = SmartScanner.load(mission_id)
            if scanner:
                results = scanner.resume()
                ElengenixUI.print(f"Resumed. Status: {results['status']}", "success")
            else:
                ElengenixUI.print(f"Not found: {mission_id}", "warning")
        except Exception as e:
            ElengenixUI.print(f"Resume failed: {e}", "error")

    def cmd_doctor(self, args):
        """Run the system health check (delegates to main.py)."""
        ElengenixUI.print("Running health check...", "info")
        self._delegate(["doctor"])

    def cmd_telegram(self, args):
        """Start the Telegram bot gateway."""
        ElengenixUI.print("Starting Telegram bot...", "info")
        bot_py = self.root / "bot.py"
        subprocess.run([sys.executable, str(bot_py)], cwd=str(self.root))

    def cmd_unknown(self, command: str):
        """Handle unrecognized commands with smart suggestion."""
        ElengenixUI.print(
            f"Unknown command: '{command}'  —  run 'elengenix help' for all commands.",
            "warning"
        )
        # Show closest match hint
        all_cmds = list(self.DELEGATE_TO_MAIN) + list({
            "mission", "bounty", "programs", "status", "pause", "resume",
            "doctor", "telegram",
        })
        close = [c for c in all_cmds if command in c or c.startswith(command[:3])]
        if close:
            print(f"  Did you mean: {', '.join(close[:3])}?")


# ---------------------------------------------------------------------------
# Entry Point
# ---------------------------------------------------------------------------

def main():
    """Application entry point. Parses sys.argv and routes to handlers."""
    try:
        app = ElengenixApp()
        app.run(sys.argv[1:])
    except KeyboardInterrupt:
        print(f"\n{Colors.DIM}[info] Elengenix session terminated.{Colors.END}")
        sys.exit(0)


if __name__ == "__main__":
    main()
