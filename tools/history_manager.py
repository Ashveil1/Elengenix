"""tools/history_manager.py

Command History Manager - Smart Context and Recommendations.

Purpose:
- Track command history with metadata
- Provide intelligent auto-complete
- Suggest commands based on context
- Quick re-run with improvements
- Learn from user patterns

Philosophy:
- Apple: Anticipates what you need next
- Wozniak: Just works, no configuration
- Friction-free: History appears when you need it

Features:
1. Persistent command history with timestamps
2. Context-aware suggestions (time, location, project)
3. Quick re-run with up-arrow or !!
4. Favorite/bookmark commands
5. Usage pattern learning
6. Smart search through history

Usage:
    from tools.history_manager import HistoryManager
    
    # Record command
    history = HistoryManager()
    history.record_command("scan target.com", {"findings": 5})
    
    # Get suggestions for current context
    suggestions = history.get_contextual_suggestions("scan")
    
    # Quick re-run last command
    last = history.get_last_command()
    
    # Search history
    results = history.search("target.com")
    
    # Get favorites
    favorites = history.get_favorites()
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("elengenix.history")


@dataclass
class CommandEntry:
    """A single command history entry."""
    command: str
    args: str
    timestamp: str
    duration_seconds: float
    success: bool
    findings_count: int = 0
    target: str = ""
    tags: List[str] = field(default_factory=list)
    notes: str = ""
    is_favorite: bool = False
    run_count: int = 1
    
    @property
    def full_command(self) -> str:
        """Get full command string."""
        if self.args:
            return f"elengenix {self.command} {self.args}"
        return f"elengenix {self.command}"
    
    @property
    def age_days(self) -> int:
        """Get age in days."""
        try:
            dt = datetime.fromisoformat(self.timestamp)
            return (datetime.utcnow() - dt).days
        except Exception:
            return 999


@dataclass
class UsagePattern:
    """Detected usage pattern."""
    pattern_type: str  # time_based, target_based, command_sequence
    description: str
    confidence: float
    suggested_action: str


class HistoryManager:
    """
    Intelligent command history management.
    
    Features:
    - Persistent history storage
    - Context-aware suggestions
    - Pattern detection
    - Quick re-run
    - Favorites
    """
    
    HISTORY_FILE = Path(".config/elengenix/history.json")
    MAX_HISTORY = 1000  # Keep last 1000 commands
    
    def __init__(self):
        self.entries: List[CommandEntry] = []
        self._ensure_dir()
        self._load_history()
        self.patterns: List[UsagePattern] = []
    
    def _ensure_dir(self) -> None:
        """Ensure history directory exists."""
        self.HISTORY_FILE.parent.mkdir(parents=True, exist_ok=True)
    
    def _load_history(self) -> None:
        """Load history from disk."""
        if not self.HISTORY_FILE.exists():
            return
        
        try:
            data = json.loads(self.HISTORY_FILE.read_text())
            self.entries = [CommandEntry(**e) for e in data.get("entries", [])]
            logger.debug(f"Loaded {len(self.entries)} history entries")
        except Exception as e:
            logger.warning(f"Failed to load history: {e}")
    
    def _save_history(self) -> None:
        """Save history to disk."""
        try:
            data = {
                "entries": [asdict(e) for e in self.entries[-self.MAX_HISTORY:]],
                "saved_at": datetime.utcnow().isoformat(),
            }
            self.HISTORY_FILE.write_text(json.dumps(data, indent=2), encoding="utf-8")
        except Exception as e:
            logger.warning(f"Failed to save history: {e}")
    
    def record_command(self, command: str, args: str = "",
                      duration: float = 0,
                      success: bool = True,
                      findings: int = 0,
                      target: str = "",
                      tags: List[str] = None) -> None:
        """
        Record a command execution.
        
        Args:
            command: Command name (scan, research, etc.)
            args: Arguments passed to command
            duration: Execution time in seconds
            success: Whether command succeeded
            findings: Number of findings (for security scans)
            target: Target scanned
            tags: Additional tags
        """
        # Check if similar command already exists
        for entry in self.entries:
            if entry.command == command and entry.args == args:
                # Update existing entry
                entry.run_count += 1
                entry.timestamp = datetime.utcnow().isoformat()
                entry.duration_seconds = duration
                entry.success = success
                entry.findings_count = findings
                self._save_history()
                return
        
        # Create new entry
        entry = CommandEntry(
            command=command,
            args=args,
            timestamp=datetime.utcnow().isoformat(),
            duration_seconds=duration,
            success=success,
            findings_count=findings,
            target=target,
            tags=tags or [],
        )
        
        self.entries.append(entry)
        
        # Auto-detect patterns
        self._detect_patterns()
        
        # Save periodically
        if len(self.entries) % 5 == 0:
            self._save_history()
    
    def get_last_command(self, n: int = 1) -> Optional[CommandEntry]:
        """Get nth last command."""
        if len(self.entries) >= n:
            return self.entries[-n]
        return None
    
    def get_recent_commands(self, hours: int = 24, limit: int = 10) -> List[CommandEntry]:
        """Get commands from last N hours."""
        cutoff = datetime.utcnow() - timedelta(hours=hours)
        
        recent = []
        for entry in reversed(self.entries):
            try:
                entry_time = datetime.fromisoformat(entry.timestamp)
                if entry_time >= cutoff:
                    recent.append(entry)
                    if len(recent) >= limit:
                        break
            except Exception:
                continue
        
        return recent
    
    def search(self, query: str, limit: int = 10) -> List[CommandEntry]:
        """
        Search command history.
        
        Args:
            query: Search string
            limit: Max results
            
        Returns:
            Matching entries
        """
        query_lower = query.lower()
        results = []
        
        for entry in reversed(self.entries):
            # Check command, args, target, tags
            if (query_lower in entry.command.lower() or
                query_lower in entry.args.lower() or
                query_lower in entry.target.lower() or
                any(query_lower in t.lower() for t in entry.tags)):
                results.append(entry)
                
                if len(results) >= limit:
                    break
        
        return results
    
    def get_favorites(self) -> List[CommandEntry]:
        """Get favorite/bookmarked commands."""
        return [e for e in self.entries if e.is_favorite]
    
    def add_favorite(self, command: str, args: str) -> bool:
        """Mark a command as favorite."""
        for entry in self.entries:
            if entry.command == command and entry.args == args:
                entry.is_favorite = True
                self._save_history()
                return True
        return False
    
    def remove_favorite(self, command: str, args: str) -> bool:
        """Remove from favorites."""
        for entry in self.entries:
            if entry.command == command and entry.args == args:
                entry.is_favorite = False
                self._save_history()
                return True
        return False
    
    def get_popular_commands(self, limit: int = 5) -> List[Tuple[str, int]]:
        """Get most frequently used commands."""
        counts: Dict[str, int] = {}
        
        for entry in self.entries:
            cmd = entry.command
            counts[cmd] = counts.get(cmd, 0) + entry.run_count
        
        sorted_cmds = sorted(counts.items(), key=lambda x: x[1], reverse=True)
        return sorted_cmds[:limit]
    
    def get_contextual_suggestions(self, current_input: str = "") -> List[str]:
        """
        Get context-aware command suggestions.
        
        Based on:
        - Time of day (morning = deep scans, evening = quick checks)
        - Recent targets (suggest same target, different command)
        - Recent commands (suggest next logical step)
        - Usage patterns
        
        Args:
            current_input: What user has typed so far
            
        Returns:
            List of suggested commands
        """
        suggestions = []
        
        # Get recent context
        recent = self.get_recent_commands(hours=1, limit=3)
        
        if recent:
            last = recent[0]
            
            # Suggest next logical step
            if last.command == "recon":
                suggestions.append(f"scan {last.target} -- Deep scan after recon")
            elif last.command == "scan" and last.findings_count > 0:
                suggestions.append(f"report -- Generate report from findings")
            elif last.command == "research":
                suggestions.append(f"poc {last.args.split()[0] if last.args else 'rce'} -- Create PoC")
            
            # Suggest same target, different approach
            if last.target and last.command != "autonomous":
                suggestions.append(f"autonomous {last.target} -- Full AI scan")
        
        # Time-based suggestions
        hour = datetime.utcnow().hour
        if 9 <= hour <= 17:  # Work hours
            if "quick" not in [s.split()[0] for s in suggestions]:
                suggestions.insert(0, "quick <target> -- Fast check")
        else:  # Evening/night
            if "deep" not in [s.split()[0] for s in suggestions]:
                suggestions.insert(0, "deep <target> -- Thorough scan")
        
        # Filter by current input
        if current_input:
            input_lower = current_input.lower()
            suggestions = [s for s in suggestions if input_lower in s.lower()]
        
        return suggestions[:3]  # Max 3 suggestions
    
    def suggest_replacements(self, target: str) -> List[str]:
        """
        Suggest command replacements for a target.
        
        Based on what worked before for similar targets.
        
        Args:
            target: Target domain/URL
            
        Returns:
            List of suggested commands that worked before
        """
        suggestions = []
        
        # Find similar targets
        target_domain = self._extract_domain(target)
        
        similar_targets = []
        for entry in self.entries:
            entry_domain = self._extract_domain(entry.target)
            if entry_domain and entry_domain != target_domain:
                # Check similarity (same TLD, or both contain 'api', etc.)
                similarity = self._target_similarity(target_domain, entry_domain)
                if similarity > 0.5:
                    similar_targets.append((entry, similarity))
        
        # Sort by similarity and success
        similar_targets.sort(key=lambda x: (x[1], x[0].success, x[0].findings_count), reverse=True)
        
        # Extract successful command patterns
        seen = set()
        for entry, _ in similar_targets[:5]:
            key = (entry.command, entry.args)
            if key not in seen and entry.success:
                seen.add(key)
                cmd_str = f"{entry.command} {target}"
                if cmd_str not in suggestions:
                    suggestions.append(cmd_str)
        
        return suggestions[:3]
    
    def _extract_domain(self, target: str) -> str:
        """Extract domain from target URL."""
        if not target:
            return ""
        
        # Remove protocol
        domain = target.replace("https://", "").replace("http://", "")
        # Remove path
        domain = domain.split("/")[0]
        return domain.lower()
    
    def _target_similarity(self, t1: str, t2: str) -> float:
        """Calculate similarity between two targets."""
        if not t1 or not t2:
            return 0.0
        
        # Exact match
        if t1 == t2:
            return 1.0
        
        # Same TLD
        if t1.split(".")[-1] == t2.split(".")[-1]:
            return 0.3
        
        # Both contain 'api'
        if "api" in t1 and "api" in t2:
            return 0.4
        
        # Both contain 'admin'
        if "admin" in t1 and "admin" in t2:
            return 0.4
        
        return 0.0
    
    def _detect_patterns(self) -> None:
        """Detect usage patterns from history."""
        self.patterns = []
        
        if len(self.entries) < 5:
            return
        
        # Pattern 1: Time-based (scans usually at certain times)
        hour_counts: Dict[int, int] = {}
        for entry in self.entries:
            try:
                dt = datetime.fromisoformat(entry.timestamp)
                hour_counts[dt.hour] = hour_counts.get(dt.hour, 0) + 1
            except Exception:
                continue
        
        if hour_counts:
            peak_hour = max(hour_counts, key=hour_counts.get)
            if hour_counts[peak_hour] > len(self.entries) * 0.3:
                self.patterns.append(UsagePattern(
                    pattern_type="time_based",
                    description=f"Peak activity at {peak_hour}:00",
                    confidence=hour_counts[peak_hour] / len(self.entries),
                    suggested_action="schedule_scans",
                ))
        
        # Pattern 2: Command sequences (recon → scan → report)
        sequences = []
        for i in range(len(self.entries) - 2):
            seq = (self.entries[i].command, 
                   self.entries[i+1].command, 
                   self.entries[i+2].command)
            sequences.append(seq)
        
        # Look for common 3-command sequences
        from collections import Counter
        seq_counts = Counter(sequences)
        for seq, count in seq_counts.most_common(2):
            if count >= 2:
                self.patterns.append(UsagePattern(
                    pattern_type="command_sequence",
                    description=f"Often use: {' → '.join(seq)}",
                    confidence=min(count / 5, 1.0),
                    suggested_action="workflow_optimization",
                ))
    
    def get_stats(self) -> Dict[str, Any]:
        """Get history statistics."""
        if not self.entries:
            return {
                "total_commands": 0,
                "unique_commands": 0,
                "favorite_commands": 0,
                "most_used": None,
                "patterns": [],
            }
        
        unique_cmds = len(set(e.command for e in self.entries))
        favorites = len(self.get_favorites())
        popular = self.get_popular_commands(1)
        
        return {
            "total_commands": sum(e.run_count for e in self.entries),
            "unique_commands": unique_cmds,
            "favorite_commands": favorites,
            "most_used": popular[0] if popular else None,
            "patterns": self.patterns,
            "success_rate": sum(1 for e in self.entries if e.success) / len(self.entries),
        }
    
    def format_history_list(self, entries: List[CommandEntry] = None, 
                         show_favorites_only: bool = False) -> str:
        """Format history entries for display."""
        if entries is None:
            entries = self.entries
        
        if show_favorites_only:
            entries = [e for e in entries if e.is_favorite]
        
        if not entries:
            return "\n  [No command history yet]\n"
        
        lines = []
        lines.append("\n  Command History:")
        lines.append("  " + "─" * 60)
        
        # Show last 10 entries
        for i, entry in enumerate(entries[-10:], 1):
            # Format timestamp
            try:
                dt = datetime.fromisoformat(entry.timestamp)
                time_str = dt.strftime("%H:%M")
            except Exception:
                time_str = "??:??"
            
            # Status indicator
            status = "" if entry.is_favorite else " "
            if not entry.success:
                status = ""
            
            # Truncate args
            args = entry.args[:30] + "..." if len(entry.args) > 30 else entry.args
            
            lines.append(f"  {status} [{time_str}] {entry.command:12} {args}")
            
            if entry.findings_count > 0:
                lines.append(f"            └─ Found {entry.findings_count} issues")
        
        lines.append("  " + "─" * 60)
        
        # Show stats
        stats = self.get_stats()
        lines.append(f"\n  Total: {stats['total_commands']} runs | "
                    f"Favorites: {stats['favorite_commands']} | "
                    f"Success rate: {stats['success_rate']:.0%}")
        
        return "\n".join(lines)
    
    def clear_history(self) -> None:
        """Clear all history."""
        self.entries = []
        self._save_history()
        logger.info("History cleared")


def get_history_manager() -> HistoryManager:
    """Get singleton history manager instance."""
    if not hasattr(get_history_manager, "_instance"):
        get_history_manager._instance = HistoryManager()
    return get_history_manager._instance


def run_cli():
    """CLI for history management."""
    import sys
    
    history = get_history_manager()
    
    if len(sys.argv) < 2:
        print(history.format_history_list())
        sys.exit(0)
    
    command = sys.argv[1]
    
    if command == "list" or command == "ls":
        favorites_only = "--favorites" in sys.argv
        print(history.format_history_list(show_favorites_only=favorites_only))
    
    elif command == "search":
        if len(sys.argv) < 3:
            print("Usage: history search <query>")
            sys.exit(1)
        
        query = sys.argv[2]
        results = history.search(query)
        
        if results:
            print(f"\n  Found {len(results)} matches:")
            for entry in results:
                print(f"    • {entry.full_command}")
        else:
            print("\n  No matches found")
    
    elif command == "stats":
        stats = history.get_stats()
        print("\n  Command History Statistics:")
        print("  " + "─" * 40)
        print(f"    Total runs:     {stats['total_commands']}")
        print(f"    Unique commands: {stats['unique_commands']}")
        print(f"    Favorites:      {stats['favorite_commands']}")
        print(f"    Success rate:   {stats['success_rate']:.1%}")
        
        if stats['most_used']:
            cmd, count = stats['most_used']
            print(f"\n    Most used: {cmd} ({count} times)")
        
        if stats['patterns']:
            print("\n    Detected patterns:")
            for pattern in stats['patterns']:
                print(f"      • {pattern.description}")
    
    elif command == "suggest":
        suggestions = history.get_contextual_suggestions()
        
        if suggestions:
            print("\n  Suggested commands based on context:")
            for i, sugg in enumerate(suggestions, 1):
                print(f"    {i}. elengenix {sugg}")
        else:
            print("\n  No specific suggestions. Try:")
            print("    elengenix quick <target>")
            print("    elengenix ai")
    
    elif command == "clear":
        if input("Clear all history? (yes/no): ").strip().lower() == "yes":
            history.clear_history()
            print("History cleared.")
        else:
            print("Cancelled.")
    
    elif command == "favorite" or command == "fav":
        if len(sys.argv) < 3:
            # List favorites
            print(history.format_history_list(show_favorites_only=True))
        else:
            # Add favorite
            cmd_str = sys.argv[2]
            parts = cmd_str.split(maxsplit=1)
            if len(parts) >= 2:
                cmd, args = parts[0], parts[1]
            else:
                cmd, args = parts[0], ""
            
            if history.add_favorite(cmd, args):
                print(f"Added to favorites: {cmd} {args}")
            else:
                print(f"Command not found in history: {cmd} {args}")
    
    else:
        print(f"Unknown command: {command}")
        print("Usage: history [list|search|stats|suggest|clear|favorite]")


if __name__ == "__main__":
    run_cli()
