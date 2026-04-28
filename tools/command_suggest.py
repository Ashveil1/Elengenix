"""tools/command_suggest.py

Smart Command Suggestions - Helpful UX When Users Need It.

Purpose:
- Auto-correct typos in commands ("scann" → "scan")
- Suggest commands based on context and history
- Provide intelligent completions
- Guide users with helpful examples
- Learn from usage patterns

Philosophy:
- Wozniak: Works perfectly without thinking
- Apple: Beautiful, helpful, never annoying
- Friction-free: Just works, anticipates needs

Features:
1. Fuzzy matching for typos
2. Context-aware suggestions
3. Command history learning
4. Smart completions
5. Progressive disclosure (simple → advanced)

Usage:
    from tools.command_suggest import CommandSuggester
    
    suggester = CommandSuggester()
    
    # Check if command has typo
    correction = suggester.suggest_correction("scann")
    # Returns: "scan"
    
    # Get suggestions for partial input
    suggestions = suggester.suggest_completions("re")
    # Returns: ["research", "recon", "red"]
    
    # Get contextual help
    help_text = suggester.get_contextual_help("research")
"""

from __future__ import annotations

import json
import logging
import re
from difflib import SequenceMatcher, get_close_matches
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("elengenix.command_suggest")


class CommandSuggester:
    """
    Smart command suggestion engine.
    
    Provides intelligent help when users:
    - Type commands incorrectly
    - Need guidance on what to do next
    - Want to discover features
    """
    
    # All available commands with metadata
    COMMANDS = {
        "ai": {
            "description": "Chat with AI security assistant",
            "examples": ["elengenix ai", "Ask about vulnerabilities, get guidance"],
            "category": "core",
            "requires_target": False,
            "aliases": ["chat", "assistant"],
        },
        "autonomous": {
            "description": "AI runs complete security scan automatically",
            "examples": ["elengenix autonomous https://target.com", "elengenix autonomous target.com --mode auto"],
            "category": "core",
            "requires_target": True,
            "aliases": ["auto", "full"],
        },
        "scan": {
            "description": "Quick security scan on target",
            "examples": ["elengenix scan target.com", "elengenix scan https://api.target.com --rate-limit 10"],
            "category": "scanning",
            "requires_target": True,
            "aliases": ["quick", "s"],
        },
        "research": {
            "description": "Research CVEs and vulnerability types",
            "examples": ["elengenix research CVE-2024-21626", "elengenix research rce", "elengenix research sqli"],
            "category": "research",
            "requires_target": False,
            "aliases": ["cve", "lookup"],
        },
        "poc": {
            "description": "Generate proof-of-concept exploit code",
            "examples": ["elengenix poc rce --framework spring-boot", "elengenix poc sqli > poc.py"],
            "category": "research",
            "requires_target": False,
            "aliases": ["exploit", "generate"],
        },
        "bola": {
            "description": "Test for BOLA/IDOR access control vulnerabilities",
            "examples": ["elengenix bola https://api.target.com", "Interactive: paste two account headers"],
            "category": "testing",
            "requires_target": True,
            "aliases": ["idor", "access"],
        },
        "waf": {
            "description": "WAF detection and bypass testing",
            "examples": ["elengenix waf https://target.com/login", "Tests payload mutations against WAF"],
            "category": "testing",
            "requires_target": True,
            "aliases": ["bypass", "firewall"],
        },
        "recon": {
            "description": "Smart reconnaissance on target",
            "examples": ["elengenix recon target.com", "Discovers assets, endpoints, technologies"],
            "category": "scanning",
            "requires_target": True,
            "aliases": ["discover", "enum"],
        },
        "evasion": {
            "description": "EDR/AV evasion techniques (red team)",
            "examples": ["elengenix evasion", "List/generate anti-detection payloads"],
            "category": "advanced",
            "requires_target": False,
            "aliases": ["red", "stealth"],
        },
        "report": {
            "description": "Generate security reports",
            "examples": ["elengenix report findings.json", "Creates PDF/HTML reports"],
            "category": "reporting",
            "requires_target": False,
            "aliases": ["pdf", "generate"],
        },
        "configure": {
            "description": "Configure AI providers and settings",
            "examples": ["elengenix configure", "Interactive setup wizard"],
            "category": "system",
            "requires_target": False,
            "aliases": ["config", "setup"],
        },
        "doctor": {
            "description": "Check system health and dependencies",
            "examples": ["elengenix doctor", "elengenix doctor --fix"],
            "category": "system",
            "requires_target": False,
            "aliases": ["check", "health"],
        },
        "welcome": {
            "description": "Run first-time setup wizard",
            "examples": ["elengenix welcome", "Reset and rerun setup"],
            "category": "system",
            "requires_target": False,
            "aliases": ["setup", "init"],
        },
        "help": {
            "description": "Show help and available commands",
            "examples": ["elengenix help", "Get command reference"],
            "category": "system",
            "requires_target": False,
            "aliases": ["h", "?"],
        },
        "update": {
            "description": "Update Elengenix to latest version",
            "examples": ["elengenix update", "git pull && ./setup.sh"],
            "category": "system",
            "requires_target": False,
            "aliases": ["upgrade"],
        },
        "memory": {
            "description": "AI memory system management",
            "examples": ["elengenix memory", "View conversation history and stats"],
            "category": "system",
            "requires_target": False,
            "aliases": ["history"],
        },
    }
    
    # Common typos and their corrections
    TYPO_CORRECTIONS = {
        # Scan typos
        "scann": "scan",
        "scn": "scan",
        "sacn": "scan",
        "csan": "scan",
        
        # Research typos
        "reserch": "research",
        "researh": "research",
        "rech": "research",
        "lookup": "research",
        "cve": "research",
        
        # Autonomous typos
        "autonomus": "autonomous",
        "autonomos": "autonomous",
        "auto": "autonomous",
        "automatic": "autonomous",
        "full": "autonomous",
        
        # BOLA/IDOR typos
        "bolla": "bola",
        "idoor": "bola",
        "idor": "bola",
        "access": "bola",
        
        # Recon typos
        "reconn": "recon",
        "reconnaissance": "recon",
        "discover": "recon",
        "enum": "recon",
        
        # WAF typos
        "waff": "waf",
        "firewall": "waf",
        "bypass": "waf",
        
        # POC typos
        "poc": "poc",
        "exploit": "poc",
        "explot": "poc",
        "generate": "poc",
        
        # Common command typos
        "helo": "help",
        "hellp": "help",
        "hlep": "help",
        "configg": "configure",
        "confg": "configure",
        "cofigure": "configure",
    }
    
    def __init__(self):
        """Initialize command suggester."""
        self.history_file = Path(".config/elengenix/command_history.json")
        self.usage_stats: Dict[str, int] = {}
        self._load_history()
    
    def _load_history(self) -> None:
        """Load command usage history."""
        if self.history_file.exists():
            try:
                data = json.loads(self.history_file.read_text())
                self.usage_stats = data.get("command_counts", {})
            except Exception as e:
                logger.debug(f"Failed to load history: {e}")
    
    def _save_history(self) -> None:
        """Save command usage history."""
        self.history_file.parent.mkdir(parents=True, exist_ok=True)
        try:
            self.history_file.write_text(
                json.dumps({"command_counts": self.usage_stats}, indent=2),
                encoding="utf-8"
            )
        except Exception as e:
            logger.debug(f"Failed to save history: {e}")
    
    def record_usage(self, command: str) -> None:
        """Record that a command was used."""
        self.usage_stats[command] = self.usage_stats.get(command, 0) + 1
        # Save periodically (every 10 uses)
        if sum(self.usage_stats.values()) % 10 == 0:
            self._save_history()
    
    def suggest_correction(self, input_cmd: str) -> Optional[str]:
        """
        Suggest correction for a potentially mistyped command.
        
        Args:
            input_cmd: The command the user typed
            
        Returns:
            Corrected command or None if no suggestion
        """
        input_lower = input_cmd.lower().strip()
        
        # Check direct typo corrections first
        if input_lower in self.TYPO_CORRECTIONS:
            return self.TYPO_CORRECTIONS[input_lower]
        
        # Check if it's a valid command (no correction needed)
        if input_lower in self.COMMANDS:
            return None
        
        # Check aliases
        for cmd, meta in self.COMMANDS.items():
            if input_lower in [a.lower() for a in meta.get("aliases", [])]:
                return cmd
        
        # Fuzzy matching for close matches
        all_names = list(self.COMMANDS.keys())
        for cmd, meta in self.COMMANDS.items():
            all_names.extend(meta.get("aliases", []))
        
        matches = get_close_matches(input_lower, all_names, n=1, cutoff=0.6)
        if matches:
            # Map alias back to main command
            for cmd, meta in self.COMMANDS.items():
                if matches[0].lower() in [a.lower() for a in meta.get("aliases", [])]:
                    return cmd
            return matches[0]
        
        return None
    
    def suggest_completions(self, partial: str) -> List[str]:
        """
        Suggest command completions for partial input.
        
        Args:
            partial: Partial command typed by user
            
        Returns:
            List of matching commands
        """
        partial_lower = partial.lower().strip()
        
        matches = []
        
        # Check command names
        for cmd in self.COMMANDS.keys():
            if cmd.startswith(partial_lower):
                matches.append(cmd)
        
        # Check aliases
        for cmd, meta in self.COMMANDS.items():
            for alias in meta.get("aliases", []):
                if alias.lower().startswith(partial_lower):
                    if cmd not in matches:
                        matches.append(cmd)
        
        # Sort by usage frequency (most used first)
        matches.sort(key=lambda x: self.usage_stats.get(x, 0), reverse=True)
        
        return matches
    
    def get_contextual_help(self, command: str = None, after_error: bool = False) -> str:
        """
        Get helpful suggestions based on context.
        
        Args:
            command: Current command context
            after_error: Whether showing help after an error
            
        Returns:
            Helpful text for user
        """
        lines = []
        
        if after_error:
            lines.append("\n  [Did you mean one of these?]")
            
            if command:
                suggestion = self.suggest_correction(command)
                if suggestion:
                    lines.append(f"    → elengenix {suggestion}")
            
            lines.append("\n  [Popular commands:]")
            popular = self._get_popular_commands(3)
            for cmd in popular:
                meta = self.COMMANDS.get(cmd, {})
                desc = meta.get("description", "")
                lines.append(f"    • {cmd:12} - {desc[:40]}")
        
        else:
            # General guidance
            lines.append("\n  [Quick Start]")
            lines.append("    elengenix autonomous https://target.com")
            lines.append("    elengenix ai")
            lines.append("    elengenix research CVE-2024-21626")
            
            lines.append("\n  [Get Help]")
            lines.append("    elengenix help")
            lines.append("    elengenix welcome")
        
        return "\n".join(lines)
    
    def _get_popular_commands(self, n: int = 5) -> List[str]:
        """Get most frequently used commands."""
        sorted_cmds = sorted(
            self.usage_stats.items(),
            key=lambda x: x[1],
            reverse=True
        )
        return [cmd for cmd, _ in sorted_cmds[:n]]
    
    def get_command_info(self, command: str) -> Optional[Dict[str, Any]]:
        """Get full information about a command."""
        return self.COMMANDS.get(command.lower())
    
    def format_suggestion(self, input_cmd: str, suggestion: str) -> str:
        """Format a suggestion message beautifully."""
        # Highlight differences
        sm = SequenceMatcher(None, input_cmd, suggestion)
        
        return f"""
┌────────────────────────────────────────────────────────────┐
│  Did you mean:                                             │
│                                                            │
│    $ elengenix {suggestion:<45} │
│                                                            │
│  Run it? [Y/n]:                                            │
└────────────────────────────────────────────────────────────┘
"""
    
    def get_similar_commands(self, command: str, n: int = 3) -> List[str]:
        """Get commands similar to the given one."""
        meta = self.COMMANDS.get(command)
        if not meta:
            return []
        
        category = meta.get("category")
        similar = []
        
        for cmd, cmd_meta in self.COMMANDS.items():
            if cmd != command and cmd_meta.get("category") == category:
                similar.append(cmd)
        
        return similar[:n]
    
    def suggest_next_command(self, last_command: str, had_findings: bool = False) -> Optional[str]:
        """
        Suggest what to do next based on previous command.
        
        Args:
            last_command: Command that was just run
            had_findings: Whether the command found anything
            
        Returns:
            Suggested next command
        """
        # Suggest report generation after finding things
        if had_findings and last_command in ["scan", "autonomous", "bola", "waf"]:
            return "report"
        
        # Suggest research after recon
        if last_command == "recon":
            return "research"
        
        # Suggest poc after research
        if last_command == "research":
            return "poc"
        
        # Suggest autonomous for comprehensive testing
        if last_command in ["scan", "recon"] and not had_findings:
            return "autonomous"
        
        return None


def handle_command_error(input_cmd: str, args: List[str] = None) -> str:
    """
    Handle unknown command with helpful suggestions.
    
    This is the main entry point for CLI integration.
    
    Args:
        input_cmd: The command user tried to run
        args: Additional arguments
        
    Returns:
        Helpful error message with suggestions
    """
    suggester = CommandSuggester()
    
    lines = []
    lines.append(f"\n  Unknown command: '{input_cmd}'")
    
    # Try to suggest correction
    correction = suggester.suggest_correction(input_cmd)
    if correction:
        lines.append(f"\n  Did you mean: 'elengenix {correction}'?")
        lines.append(f"    Run: elengenix {correction} {' '.join(args or [])}")
    
    # Show contextual help
    help_text = suggester.get_contextual_help(input_cmd, after_error=True)
    lines.append(help_text)
    
    return "\n".join(lines)


def print_command_categories() -> None:
    """Print all commands organized by category."""
    suggester = CommandSuggester()
    
    categories = {}
    for cmd, meta in suggester.COMMANDS.items():
        cat = meta.get("category", "other")
        if cat not in categories:
            categories[cat] = []
        categories[cat].append((cmd, meta))
    
    print("\n  Available Commands:")
    print("  " + "─" * 50)
    
    for cat in ["core", "scanning", "testing", "research", "reporting", "advanced", "system"]:
        if cat in categories:
            print(f"\n  [{cat.upper()}]")
            for cmd, meta in sorted(categories[cat]):
                desc = meta.get("description", "")
                print(f"    {cmd:15} {desc[:35]}")
    
    print("\n  " + "─" * 50)
    print("  Run 'elengenix help <command>' for detailed usage")
    print()


def run_cli():
    """CLI for testing command suggestions."""
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python command_suggest.py <command>")
        print("Examples:")
        print("  python command_suggest.py scann")
        print("  python command_suggest.py re")
        print_command_categories()
        sys.exit(1)
    
    input_cmd = sys.argv[1]
    args = sys.argv[2:]
    
    suggester = CommandSuggester()
    
    # Check for correction
    correction = suggester.suggest_correction(input_cmd)
    if correction:
        print(f"\n  Typo detected: '{input_cmd}' → '{correction}'")
        print(f"  Suggested: elengenix {correction} {' '.join(args)}")
    
    # Check for completions
    completions = suggester.suggest_completions(input_cmd)
    if completions and not correction:
        print(f"\n  Commands starting with '{input_cmd}':")
        for cmd in completions[:5]:
            meta = suggester.get_command_info(cmd)
            print(f"    • {cmd:12} - {meta.get('description', '')[:40]}")
    
    # Show contextual help
    if not correction and not completions:
        print(handle_command_error(input_cmd, args))
    
    # Show command info if exact match
    if input_cmd in suggester.COMMANDS:
        info = suggester.get_command_info(input_cmd)
        print(f"\n  [{input_cmd.upper()}]")
        print(f"  {info.get('description', '')}")
        print(f"\n  Examples:")
        for ex in info.get("examples", []):
            print(f"    $ {ex}")


if __name__ == "__main__":
    run_cli()
