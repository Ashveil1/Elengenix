#!/usr/bin/env python3
"""
elengenix_launcher.py -- Elengenix CLI Launcher (v2.0.0)

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

    return project_root


# ---------------------------------------------------------------------------
# UI Output Utilities
# ---------------------------------------------------------------------------

class ElengenixUI:
    """Lightweight terminal UI with color-coded output and text-only markers.

    All output methods use plain ANSI codes for fast rendering
    without Rich library dependency.
    """

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
        """Print a message with a colored status marker.

        Args:
            message: Text content to display.
            style: One of 'info', 'success', 'error', 'warning', 'header', 'bold'.
        """
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
        width = 56
        line = Colors.BLUE + ("=" * width) + Colors.END

        print()
        print(line)
        print(f"{Colors.BOLD}{Colors.CYAN}  ELENGENIX{Colors.END}  {Colors.DIM}v2.0.0{Colors.END}")
        print(f"  {Colors.CYAN}Autonomous Bug Bounty Hunter{Colors.END}")
        print(line)
        print()


# ---------------------------------------------------------------------------
# Application Router
# ---------------------------------------------------------------------------

class ElengenixApp:
    """Main application command router.

    Maps CLI arguments to handler methods. Each handler is responsible
    for importing its own dependencies to keep startup time minimal.
    """

    # Commands grouped by category for help display
    COMMAND_GROUPS = {
        "Scanning": [
            ("mission <target>",   "Start autonomous scanning mission"),
            ("scan <target>",      "Quick security scan"),
            ("bounty",             "Discover bug bounty programs"),
            ("programs",           "List bug bounty programs"),
        ],
        "Mission Control": [
            ("status <mission>",   "Check mission status"),
            ("pause <mission>",    "Pause running mission"),
            ("resume <mission>",   "Resume paused mission"),
        ],
        "AI and Tools": [
            ("ai <query>",         "Ask AI assistant"),
            ("doctor",             "System health check"),
            ("telegram",           "Start Telegram bot"),
        ],
    }

    def __init__(self):
        self.root = bootstrap()

    def run(self, args: List[str]):
        """Route the command to the appropriate handler.

        Args:
            args: Command-line arguments (sys.argv[1:]).
        """
        if not args or args[0] in ["help", "-h", "--help"]:
            self.show_help()
            return

        command = args[0]
        remaining = args[1:]

        handlers = {
            "mission":  self.cmd_mission,
            "bounty":   self.cmd_bounty,
            "scan":     self.cmd_scan,
            "programs": self.cmd_programs,
            "status":   self.cmd_status,
            "pause":    self.cmd_pause,
            "resume":   self.cmd_resume,
            "ai":       self.cmd_ai,
            "doctor":   self.cmd_doctor,
            "telegram": self.cmd_telegram,
        }

        handler = handlers.get(command, self.cmd_unknown)
        handler(remaining)

    # -- Help Display -------------------------------------------------------

    def show_help(self):
        """Display the categorized help menu."""
        ElengenixUI.banner()

        print(f"{Colors.BOLD}Usage:{Colors.END} elengenix <command> [options]")
        print()

        for category, commands in self.COMMAND_GROUPS.items():
            print(f"  {Colors.BOLD}{category}{Colors.END}")
            for cmd, desc in commands:
                print(f"    {Colors.CYAN}{cmd:<25}{Colors.END} {desc}")
            print()

        print(f"{Colors.BOLD}Examples:{Colors.END}")
        print(f"  {Colors.GREEN}elengenix bounty{Colors.END}")
        print(f"  {Colors.GREEN}elengenix mission example.com{Colors.END}")
        print(f"  {Colors.GREEN}elengenix doctor{Colors.END}")
        print()

    # -- Command Handlers ---------------------------------------------------

    def cmd_mission(self, args):
        """Start an autonomous scanning mission against a target.

        Args:
            args: Should contain at least one element (the target domain).
        """
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

            if api_key:
                programs = intel.discover_programs_api(500, 10)
            else:
                programs = intel.discover_programs_public(10)

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

    def cmd_scan(self, args):
        """Run a quick security scan on the specified target.

        Delegates to main.py for the full scan pipeline.
        """
        if not args:
            ElengenixUI.print("Usage: elengenix scan <target>", "warning")
            return

        target = args[0]
        ElengenixUI.print(f"Scanning {target}...", "info")
        subprocess.run([sys.executable, "main.py", "scan", target])

    def cmd_programs(self, args):
        """List available bug bounty programs (alias for bounty)."""
        self.cmd_bounty(args)

    def cmd_status(self, args):
        """Check the status of a running or completed mission.

        Args:
            args: Should contain the mission ID.
        """
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
        """Pause a running mission.

        Args:
            args: Should contain the mission ID.
        """
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
        """Resume a paused mission.

        Args:
            args: Should contain the mission ID.
        """
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

    def cmd_ai(self, args):
        """Send a query to the AI assistant.

        Delegates to main.py for the full AI chat pipeline.
        """
        if not args:
            ElengenixUI.print("Usage: elengenix ai <query>", "warning")
            return

        query = " ".join(args)
        ElengenixUI.print(f"Query: {query}", "info")
        subprocess.run([sys.executable, "main.py", "ai", query])

    def cmd_doctor(self, args):
        """Run the system health check.

        Delegates to main.py doctor command.
        """
        ElengenixUI.print("Running health check...", "info")
        subprocess.run([sys.executable, "main.py", "doctor"])

    def cmd_telegram(self, args):
        """Start the Telegram bot gateway."""
        ElengenixUI.print("Starting Telegram bot...", "info")
        subprocess.run([sys.executable, "bot.py"])

    def cmd_unknown(self, args):
        """Handle unrecognized commands with a helpful message."""
        ElengenixUI.print(
            "Unknown command. Run 'elengenix help' for available commands.",
            "warning"
        )


# ---------------------------------------------------------------------------
# Entry Point
# ---------------------------------------------------------------------------

def main():
    """Application entry point. Parses sys.argv and routes to handlers."""
    app = ElengenixApp()
    app.run(sys.argv[1:])


if __name__ == "__main__":
    main()
