#!/usr/bin/env python3
"""
Elengenix Launcher v3.0
Professional Bug Bounty Automation Platform
"""

import sys
import os
import subprocess
from pathlib import Path
from typing import List

# Color codes for terminal output
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'

def bootstrap():
    """Setup environment."""
    project_root = Path(__file__).parent.absolute()
    venv_path = project_root / "venv"
    
    if venv_path.exists():
        venv_bin = venv_path / "bin"
        if str(venv_bin) not in os.environ.get("PATH", ""):
            os.environ["PATH"] = f"{venv_bin}:{os.environ.get('PATH', '')}"
    
    return project_root

class ElengenixUI:
    """Clean UI with colors, no emojis."""
    
    SYMBOLS = {
        "bullet": ">",
        "arrow": "->",
        "check": "[OK]",
        "error": "[ERR]",
        "warn": "[!]",
        "info": "[*]",
    }
    
    @classmethod
    def print(cls, message: str, style: str = "info"):
        """Print with style."""
        symbols = {
            "info": (Colors.CYAN, cls.SYMBOLS["info"]),
            "success": (Colors.GREEN, cls.SYMBOLS["check"]),
            "error": (Colors.RED, cls.SYMBOLS["error"]),
            "warning": (Colors.YELLOW, cls.SYMBOLS["warn"]),
            "header": (Colors.HEADER, ""),
            "bold": (Colors.BOLD, ""),
        }
        
        color, symbol = symbols.get(style, (Colors.END, ""))
        if symbol:
            print(f"{color}{symbol}{Colors.END} {message}")
        else:
            print(f"{color}{message}{Colors.END}")
    
    @classmethod
    def banner(cls):
        """Professional banner."""
        print()
        print(f"{Colors.BLUE}{'='*50}{Colors.END}")
        print(f"{Colors.BOLD}{Colors.CYAN}  ELENGENIX v3.0{Colors.END}")
        print(f"{Colors.CYAN}  Autonomous Bug Bounty Hunter{Colors.END}")
        print(f"{Colors.BLUE}{'='*50}{Colors.END}")
        print()

class ElengenixApp:
    """Main application router."""
    
    def __init__(self):
        self.root = bootstrap()
    
    def run(self, args: List[str]):
        """Route commands."""
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
        """Show help menu."""
        ElengenixUI.banner()
        
        print(f"{Colors.BOLD}Usage:{Colors.END} elengenix <command> [options]")
        print()
        
        commands = [
            ("mission <target>", "Start autonomous scanning mission"),
            ("bounty", "Discover bug bounty programs"),
            ("scan <target>", "Quick security scan"),
            ("programs", "List bug bounty programs"),
            ("status <mission>", "Check mission status"),
            ("pause <mission>", "Pause running mission"),
            ("resume <mission>", "Resume paused mission"),
            ("ai <query>", "Ask AI assistant"),
            ("doctor", "System health check"),
            ("telegram", "Start Telegram bot"),
        ]
        
        print(f"{Colors.BOLD}Commands:{Colors.END}")
        for cmd, desc in commands:
            print(f"  {Colors.CYAN}{cmd:<25}{Colors.END} {desc}")
        
        print()
        print(f"{Colors.BOLD}Examples:{Colors.END}")
        print(f"  {Colors.GREEN}elengenix bounty{Colors.END}")
        print(f"  {Colors.GREEN}elengenix mission example.com{Colors.END}")
        print(f"  {Colors.GREEN}elengenix status mission-abc{Colors.END}")
        print()
    
    def cmd_mission(self, args):
        """Start mission."""
        if not args:
            ElengenixUI.print("Usage: elengenix mission <target>", "warning")
            return
        
        target = args[0]
        ElengenixUI.print(f"Starting mission: {target}", "info")
        
        try:
            from tools.smart_scanner import SmartScanner
            scanner = SmartScanner(target=target)
            results = scanner.run()
            
            findings = len(results.get('findings', []))
            ElengenixUI.print(f"Complete. Findings: {findings}", "success")
            
        except Exception as e:
            ElengenixUI.print(f"Failed: {e}", "error")
    
    def cmd_bounty(self, args):
        """Discover programs."""
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
                ElengenixUI.print(f"Top: {top.name}", "success")
                print(f"    Reward: {top.bounty_range}")
                print(f"    URL: {top.url}")
                print(f"    Run: elengenix mission {top.url}")
            else:
                ElengenixUI.print("No programs found", "warning")
                
        except Exception as e:
            ElengenixUI.print(f"Discovery failed: {e}", "error")
    
    def cmd_scan(self, args):
        """Quick scan."""
        if not args:
            ElengenixUI.print("Usage: elengenix scan <target>", "warning")
            return
        
        target = args[0]
        ElengenixUI.print(f"Scanning {target}...", "info")
        subprocess.run([sys.executable, "main.py", "scan", target])
    
    def cmd_programs(self, args):
        """List programs."""
        self.cmd_bounty(args)
    
    def cmd_status(self, args):
        """Check status."""
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
                print(f"    Status: {status.get('status', 'unknown')}")
                print(f"    Phase: {status.get('current_phase', 'unknown')}")
                print(f"    Findings: {status.get('findings_count', 0)}")
            else:
                ElengenixUI.print(f"Not found: {mission_id}", "warning")
        except Exception as e:
            ElengenixUI.print(f"Check failed: {e}", "error")
    
    def cmd_pause(self, args):
        """Pause mission."""
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
        """Resume mission."""
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
        """AI query."""
        if not args:
            ElengenixUI.print("Usage: elengenix ai <query>", "warning")
            return
        
        query = " ".join(args)
        ElengenixUI.print(f"Query: {query}", "info")
        subprocess.run([sys.executable, "main.py", "ai", query])
    
    def cmd_doctor(self, args):
        """Health check."""
        ElengenixUI.print("Running health check...", "info")
        subprocess.run([sys.executable, "main.py", "doctor"])
    
    def cmd_telegram(self, args):
        """Start Telegram."""
        ElengenixUI.print("Starting Telegram bot...", "info")
        subprocess.run([sys.executable, "bot.py"])
    
    def cmd_unknown(self, args):
        """Unknown command."""
        ElengenixUI.print("Unknown command. Type 'elengenix help' for usage.", "warning")

def main():
    """Entry point."""
    app = ElengenixApp()
    app.run(sys.argv[1:])

if __name__ == "__main__":
    main()
