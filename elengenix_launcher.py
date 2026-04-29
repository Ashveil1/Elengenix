#!/usr/bin/env python3
"""
Elengenix Apple-Inspired Launcher v3.0
"Just works" - Clean, minimal, delightful.

Principles:
- Simplicity: One command does everything
- Elegance: Beautiful output, minimal text
- Power: Advanced features when you need them
- Integration: All phases work seamlessly
"""

import sys
import os
import subprocess
from pathlib import Path
from typing import List, Optional

# ── Minimal Bootstrap ──────────────────────────────────────────
def bootstrap():
    """Ensure we can run, no matter what."""
    project_root = Path(__file__).parent.absolute()
    venv_path = project_root / "venv"
    
    # Activate venv if exists
    if venv_path.exists():
        venv_bin = venv_path / "bin"
        if str(venv_bin) not in os.environ.get("PATH", ""):
            os.environ["PATH"] = f"{venv_bin}:{os.environ.get('PATH', '')}"
    
    return project_root

# ── Apple-Inspired UI ─────────────────────────────────────────
class ElengenixUI:
    """Clean, minimal UI - Apple style."""
    
    ICONS = {
        "target": "🎯",
        "scan": "🔍",
        "ai": "🤖",
        "mission": "🚀",
        "bounty": "💰",
        "telegram": "📱",
        "success": "✨",
        "error": "⚠️",
        "info": "ℹ️",
        "settings": "⚙️",
        "warning": "🔶",
    }
    
    @classmethod
    def print(cls, message: str, icon: str = "info"):
        """Print with icon."""
        icon_char = cls.ICONS.get(icon, "•")
        print(f"{icon_char}  {message}")
    
    @classmethod
    def banner(cls):
        """Clean Apple-style banner."""
        print()
        print("  ╔═══════════════════════════════════════════╗")
        print("  ║     Elengenix  v3.0  —  Bug Hunter        ║")
        print("  ║     Autonomous • Intelligent • Secure     ║")
        print("  ╚═══════════════════════════════════════════╝")
        print()

# ── Unified Command Router ───────────────────────────────────
class ElengenixApp:
    """Single entry point for all Elengenix operations."""
    
    def __init__(self):
        self.root = bootstrap()
        self.ui = ElengenixUI()
    
    def run(self, args: List[str]):
        """Route commands to appropriate handlers."""
        if not args or args[0] in ["help", "-h", "--help"]:
            self.show_help()
            return
        
        command = args[0]
        remaining = args[1:]
        
        handlers = {
            "mission": self.cmd_mission,
            "bounty": self.cmd_bounty,
            "scan": self.cmd_scan,
            "programs": self.cmd_programs,
            "status": self.cmd_status,
            "pause": self.cmd_pause,
            "resume": self.cmd_resume,
            "ai": self.cmd_ai,
            "doctor": self.cmd_doctor,
            "telegram": self.cmd_telegram,
        }
        
        handler = handlers.get(command, self.cmd_unknown)
        handler(remaining)
    
    def show_help(self):
        """Show beautiful help - Apple style."""
        self.ui.banner()
        
        print("  Usage: elengenix <command> [options]")
        print()
        
        commands = [
            ("mission <target>", "Start autonomous scanning mission", "🚀"),
            ("bounty", "Discover top bug bounty programs", "💰"),
            ("scan <target>", "Quick security scan", "🔍"),
            ("programs", "List available bug bounty programs", "📋"),
            ("status <mission>", "Check mission status", "📊"),
            ("pause <mission>", "Pause running mission", "⏸️"),
            ("resume <mission>", "Resume paused mission", "▶️"),
            ("ai <query>", "Ask AI assistant", "🤖"),
            ("doctor", "System health check", "🏥"),
            ("telegram", "Start Telegram bot", "📱"),
        ]
        
        print("  Commands:")
        for cmd, desc, icon in commands:
            print(f"    {icon}  elengenix {cmd:<20} {desc}")
        
        print()
        print("  Examples:")
        print("    elengenix bounty              # Find programs")
        print("    elengenix mission example.com # Start mission")
        print("    elengenix status mission-abc  # Check status")
        print()
    
    def cmd_mission(self, args):
        """Start autonomous mission - Phase 2."""
        if not args:
            self.ui.print("Usage: elengenix mission <target>", "warning")
            return
        
        target = args[0]
        self.ui.print(f"Starting autonomous mission: {target}", "mission")
        
        try:
            from tools.smart_scanner import SmartScanner
            scanner = SmartScanner(target=target)
            results = scanner.run()
            
            self.ui.print(f"Mission complete! Findings: {len(results.get('findings', []))}", "success")
            
        except Exception as e:
            self.ui.print(f"Mission failed: {e}", "error")
    
    def cmd_bounty(self, args):
        """Discover bounty programs - Phase 1."""
        self.ui.print("Discovering bug bounty programs...", "bounty")
        
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
                self.ui.print(f"Top: {top.name} ({top.bounty_range})", "success")
                print(f"    URL: {top.url}")
                print(f"    Start: elengenix mission {top.url}")
            else:
                self.ui.print("No programs found", "warning")
                
        except Exception as e:
            self.ui.print(f"Discovery failed: {e}", "error")
    
    def cmd_scan(self, args):
        """Quick scan."""
        if not args:
            self.ui.print("Usage: elengenix scan <target>", "warning")
            return
        
        target = args[0]
        self.ui.print(f"Scanning {target}...", "scan")
        # Delegate to main.py scan logic
        subprocess.run([sys.executable, "main.py", "scan", target])
    
    def cmd_programs(self, args):
        """List programs."""
        self.cmd_bounty(args)
    
    def cmd_status(self, args):
        """Check mission status."""
        if not args:
            self.ui.print("Usage: elengenix status <mission_id>", "warning")
            return
        
        mission_id = args[0]
        self.ui.print(f"Checking status: {mission_id}...", "info")
        
        try:
            from tools.smart_scanner import SmartScanner
            scanner = SmartScanner.load(mission_id)
            
            if scanner:
                status = scanner.get_status()
                print(f"    Status: {status.get('status', 'unknown')}")
                print(f"    Phase: {status.get('current_phase', 'unknown')}")
                print(f"    Findings: {status.get('findings_count', 0)}")
            else:
                self.ui.print(f"Mission not found: {mission_id}", "warning")
        except Exception as e:
            self.ui.print(f"Status check failed: {e}", "error")
    
    def cmd_pause(self, args):
        """Pause mission."""
        if not args:
            self.ui.print("Usage: elengenix pause <mission_id>", "warning")
            return
        
        mission_id = args[0]
        self.ui.print(f"Pausing mission: {mission_id}...", "info")
        
        try:
            from tools.smart_scanner import SmartScanner
            scanner = SmartScanner.load(mission_id)
            if scanner:
                scanner.pause()
                self.ui.print(f"Mission {mission_id} paused", "success")
            else:
                self.ui.print(f"Mission not found: {mission_id}", "warning")
        except Exception as e:
            self.ui.print(f"Pause failed: {e}", "error")
    
    def cmd_resume(self, args):
        """Resume mission."""
        if not args:
            self.ui.print("Usage: elengenix resume <mission_id>", "warning")
            return
        
        mission_id = args[0]
        self.ui.print(f"Resuming mission: {mission_id}...", "info")
        
        try:
            from tools.smart_scanner import SmartScanner
            scanner = SmartScanner.load(mission_id)
            if scanner:
                results = scanner.resume()
                self.ui.print(f"Mission resumed! Status: {results['status']}", "success")
            else:
                self.ui.print(f"Mission not found: {mission_id}", "warning")
        except Exception as e:
            self.ui.print(f"Resume failed: {e}", "error")
    
    def cmd_ai(self, args):
        """AI assistant."""
        if not args:
            self.ui.print("Usage: elengenix ai <query>", "warning")
            return
        
        query = " ".join(args)
        self.ui.print(f"AI: {query}", "ai")
        subprocess.run([sys.executable, "main.py", "ai", query])
    
    def cmd_doctor(self, args):
        """System health check."""
        self.ui.print("Running system health check...", "info")
        subprocess.run([sys.executable, "main.py", "doctor"])
    
    def cmd_telegram(self, args):
        """Start Telegram bot."""
        self.ui.print("Starting Telegram bot...", "telegram")
        subprocess.run([sys.executable, "bot.py"])
    
    def cmd_unknown(self, args):
        """Unknown command."""
        self.ui.print(f"Unknown command. Type 'elengenix help' for usage.", "warning")

# ── Entry Point ───────────────────────────────────────────────
def main():
    """Elengenix - Just works."""
    app = ElengenixApp()
    app.run(sys.argv[1:])

if __name__ == "__main__":
    main()
