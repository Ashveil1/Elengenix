"""tools/profile_manager.py

Command Profile Manager - One-Command Shortcuts.

Purpose:
- Create and manage command profiles (shortcuts)
- One-command execution for common workflows
- Built-in profiles for common use cases
- Custom user-defined profiles
- Profile sharing and import/export

Philosophy:
- Apple: Simple, elegant, just works
- Wozniak: Powerful under the hood, simple on surface
- Zero friction: Common tasks in one word

Built-in Profiles:
- quick: Fast reconnaissance only
- deep: Full autonomous scan with all tools
- bounty: Focus on bounty-critical vulnerabilities
- stealth: Slow, careful scan with evasion
- api: API-focused testing
- web: Web application testing

Usage:
    # Use built-in profile
    elengenix quick target.com
    elengenix deep target.com
    elengenix bounty target.com
    
    # Create custom profile
    elengenix profile create myprofile --based-on quick --add "--rate-limit 10"
    
    # List profiles
    elengenix profile list
    
    # Export/Share
    elengenix profile export myprofile > myprofile.json
"""

from __future__ import annotations

import json
import logging
import shutil
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("elengenix.profile_manager")


@dataclass
class CommandProfile:
    """A command profile definition."""
    name: str
    description: str
    base_command: str
    args: List[str]
    options: Dict[str, Any]
    env_vars: Dict[str, str]
    created_by: str  # built-in or user
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    usage_count: int = 0
    tags: List[str] = field(default_factory=list)


class ProfileManager:
    """
    Manage command profiles for one-command execution.
    
    Provides:
    - Built-in profiles for common workflows
    - Custom profile creation
    - Profile persistence
    - Command expansion
    """
    
    PROFILES_DIR = Path(".config/elengenix/profiles")
    
    # Built-in profiles (carefully curated)
    BUILTIN_PROFILES = {
        "quick": CommandProfile(
            name="quick",
            description="Fast reconnaissance - 2 minute overview",
            base_command="recon",
            args=[],
            options={"rate_limit": 10, "depth": "shallow"},
            env_vars={},
            created_by="built-in",
            tags=["fast", "overview", "beginner"],
        ),
        "deep": CommandProfile(
            name="deep",
            description="Full autonomous scan - comprehensive testing",
            base_command="autonomous",
            args=[],
            options={"mode": "auto", "rate_limit": 2},
            env_vars={},
            created_by="built-in",
            tags=["thorough", "complete", "all-tools"],
        ),
        "bounty": CommandProfile(
            name="bounty",
            description="Bounty-focused scan - high-value vulnerabilities only",
            base_command="autonomous",
            args=[],
            options={"mode": "auto", "focus": "bounty-critical"},
            env_vars={},
            created_by="built-in",
            tags=["bounty", "high-value", "payout"],
        ),
        "stealth": CommandProfile(
            name="stealth",
            description="Slow, careful scan with evasion techniques",
            base_command="autonomous",
            args=[],
            options={"mode": "auto", "rate_limit": 0.5, "stealth": True},
            env_vars={},
            created_by="built-in",
            tags=["stealth", "evasion", "careful"],
        ),
        "api": CommandProfile(
            name="api",
            description="API-focused security testing",
            base_command="bola",
            args=[],
            options={"rate_limit": 5},
            env_vars={},
            created_by="built-in",
            tags=["api", "idor", "bola"],
        ),
        "web": CommandProfile(
            name="web",
            description="Web application testing (WAF, XSS, etc.)",
            base_command="waf",
            args=[],
            options={"rate_limit": 3},
            env_vars={},
            created_by="built-in",
            tags=["web", "waf", "xss"],
        ),
        "research": CommandProfile(
            name="research",
            description="Deep research mode - CVEs, PoCs, intelligence",
            base_command="research",
            args=[],
            options={},
            env_vars={},
            created_by="built-in",
            tags=["research", "cve", "poc"],
        ),
    }
    
    def __init__(self):
        """Initialize profile manager."""
        self.profiles: Dict[str, CommandProfile] = {}
        self._ensure_profiles_dir()
        self._load_builtin_profiles()
        self._load_user_profiles()
    
    def _ensure_profiles_dir(self) -> None:
        """Ensure profiles directory exists."""
        self.PROFILES_DIR.mkdir(parents=True, exist_ok=True)
    
    def _load_builtin_profiles(self) -> None:
        """Load built-in profiles."""
        self.profiles.update(self.BUILTIN_PROFILES)
        logger.debug(f"Loaded {len(self.BUILTIN_PROFILES)} built-in profiles")
    
    def _load_user_profiles(self) -> None:
        """Load user-created profiles."""
        for profile_file in self.PROFILES_DIR.glob("*.json"):
            try:
                data = json.loads(profile_file.read_text())
                profile = CommandProfile(**data)
                self.profiles[profile.name] = profile
            except Exception as e:
                logger.warning(f"Failed to load profile {profile_file}: {e}")
        
        user_count = len(self.profiles) - len(self.BUILTIN_PROFILES)
        logger.debug(f"Loaded {user_count} user profiles")
    
    def get_profile(self, name: str) -> Optional[CommandProfile]:
        """Get a profile by name."""
        return self.profiles.get(name)
    
    def list_profiles(self, category: str = None) -> List[CommandProfile]:
        """List all available profiles."""
        profiles = list(self.profiles.values())
        
        if category:
            profiles = [p for p in profiles if category in p.tags]
        
        # Sort: built-in first, then by name
        profiles.sort(key=lambda p: (p.created_by != "built-in", p.name))
        
        return profiles
    
    def create_profile(self, name: str, base_command: str,
                      description: str = None,
                      args: List[str] = None,
                      options: Dict[str, Any] = None,
                      tags: List[str] = None) -> bool:
        """
        Create a new custom profile.
        
        Args:
            name: Profile name (unique)
            base_command: Base elengenix command
            description: Human-readable description
            args: Positional arguments
            options: Command options (--flag, --key value)
            tags: Category tags
            
        Returns:
            True if created successfully
        """
        if name in self.profiles and name in self.BUILTIN_PROFILES:
            logger.error(f"Cannot override built-in profile: {name}")
            return False
        
        if name in self.profiles:
            logger.warning(f"Overwriting existing profile: {name}")
        
        profile = CommandProfile(
            name=name,
            description=description or f"Custom profile based on {base_command}",
            base_command=base_command,
            args=args or [],
            options=options or {},
            env_vars={},
            created_by="user",
            tags=tags or ["custom"],
        )
        
        # Save to disk
        profile_file = self.PROFILES_DIR / f"{name}.json"
        try:
            profile_file.write_text(
                json.dumps(profile.__dict__, indent=2, default=str),
                encoding="utf-8"
            )
            self.profiles[name] = profile
            logger.info(f"Created profile: {name}")
            return True
        except Exception as e:
            logger.error(f"Failed to create profile: {e}")
            return False
    
    def delete_profile(self, name: str) -> bool:
        """Delete a user-created profile."""
        if name in self.BUILTIN_PROFILES:
            logger.error(f"Cannot delete built-in profile: {name}")
            return False
        
        if name not in self.profiles:
            logger.error(f"Profile not found: {name}")
            return False
        
        profile_file = self.PROFILES_DIR / f"{name}.json"
        try:
            profile_file.unlink(missing_ok=True)
            del self.profiles[name]
            logger.info(f"Deleted profile: {name}")
            return True
        except Exception as e:
            logger.error(f"Failed to delete profile: {e}")
            return False
    
    def expand_profile(self, name: str, target: str = None) -> Optional[Tuple[str, List[str]]]:
        """
        Expand a profile to full command and arguments.
        
        Args:
            name: Profile name
            target: Target to scan (optional)
            
        Returns:
            (command, args) tuple or None if profile not found
        """
        profile = self.get_profile(name)
        if not profile:
            return None
        
        # Increment usage count
        profile.usage_count += 1
        
        # Build command arguments
        args = []
        
        # Add target if provided
        if target:
            args.append(target)
        elif profile.args:
            # Use profile's default args
            args.extend(profile.args)
        
        # Add options
        for key, value in profile.options.items():
            if isinstance(value, bool):
                if value:
                    args.append(f"--{key}")
            else:
                args.append(f"--{key}")
                args.append(str(value))
        
        return (profile.base_command, args)
    
    def clone_profile(self, source_name: str, new_name: str,
                     modifications: Dict[str, Any] = None) -> bool:
        """
        Clone an existing profile with modifications.
        
        Args:
            source_name: Profile to clone
            new_name: Name for new profile
            modifications: Changes to apply
            
        Returns:
            True if cloned successfully
        """
        source = self.get_profile(source_name)
        if not source:
            logger.error(f"Source profile not found: {source_name}")
            return False
        
        # Create new profile with modifications
        description = modifications.get("description", f"Cloned from {source_name}")
        args = modifications.get("args", source.args.copy())
        options = modifications.get("options", source.options.copy())
        tags = modifications.get("tags", source.tags.copy())
        
        # Apply specific modifications
        if "add_options" in modifications:
            options.update(modifications["add_options"])
        
        if "remove_options" in modifications:
            for opt in modifications["remove_options"]:
                options.pop(opt, None)
        
        return self.create_profile(
            name=new_name,
            base_command=source.base_command,
            description=description,
            args=args,
            options=options,
            tags=tags,
        )
    
    def export_profile(self, name: str) -> Optional[str]:
        """Export profile to JSON string."""
        profile = self.get_profile(name)
        if not profile:
            return None
        
        return json.dumps(profile.__dict__, indent=2, default=str)
    
    def import_profile(self, json_data: str, overwrite: bool = False) -> bool:
        """Import profile from JSON string."""
        try:
            data = json.loads(json_data)
            name = data.get("name")
            
            if not name:
                logger.error("Invalid profile data: no name")
                return False
            
            if name in self.profiles and not overwrite:
                logger.error(f"Profile already exists: {name}")
                return False
            
            profile = CommandProfile(**data)
            profile.created_by = "imported"
            
            # Save
            profile_file = self.PROFILES_DIR / f"{name}.json"
            profile_file.write_text(
                json.dumps(profile.__dict__, indent=2, default=str),
                encoding="utf-8"
            )
            self.profiles[name] = profile
            
            logger.info(f"Imported profile: {name}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to import profile: {e}")
            return False
    
    def get_recommended_profile(self, target_type: str = None) -> Optional[str]:
        """Get recommended profile based on context."""
        if target_type:
            if "api" in target_type.lower():
                return "api"
            elif "web" in target_type.lower():
                return "web"
        
        # Default to deep scan
        return "deep"
    
    def format_profile_list(self, profiles: List[CommandProfile] = None) -> str:
        """Format profile list for display."""
        if profiles is None:
            profiles = self.list_profiles()
        
        lines = []
        lines.append("\n  Available Profiles:")
        lines.append("  " + "─" * 55)
        
        # Group by type
        built_in = [p for p in profiles if p.created_by == "built-in"]
        custom = [p for p in profiles if p.created_by != "built-in"]
        
        if built_in:
            lines.append("\n  [Built-in]")
            for p in built_in:
                tags = ", ".join(p.tags[:2])
                lines.append(f"    {p.name:12} {p.description[:40]}")
                lines.append(f"               Command: elengenix {p.name} <target>")
                if tags:
                    lines.append(f"               Tags: {tags}")
                lines.append("")
        
        if custom:
            lines.append("\n  [Custom]")
            for p in custom:
                lines.append(f"    {p.name:12} {p.description[:40]}")
                if p.usage_count > 0:
                    lines.append(f"               Used {p.usage_count} times")
                lines.append("")
        
        lines.append("  " + "─" * 55)
        lines.append("\n  Usage: elengenix <profile> <target>")
        lines.append("  Example: elengenix quick target.com")
        lines.append("\n  Create custom: elengenix profile create <name> --based-on <profile>")
        
        return "\n".join(lines)


def run_cli():
    """CLI for profile management."""
    import sys
    
    manager = ProfileManager()
    
    if len(sys.argv) < 2:
        print(manager.format_profile_list())
        sys.exit(1)
    
    command = sys.argv[1]
    
    if command == "list":
        print(manager.format_profile_list())
    
    elif command == "create":
        if len(sys.argv) < 3:
            print("Usage: profile create <name> [--based-on <profile>] [--option value]")
            sys.exit(1)
        
        name = sys.argv[2]
        
        # Parse options
        based_on = "quick"
        options = {}
        
        i = 3
        while i < len(sys.argv):
            if sys.argv[i] == "--based-on" and i + 1 < len(sys.argv):
                based_on = sys.argv[i + 1]
                i += 2
            elif sys.argv[i].startswith("--"):
                key = sys.argv[i][2:]
                if i + 1 < len(sys.argv) and not sys.argv[i + 1].startswith("--"):
                    options[key] = sys.argv[i + 1]
                    i += 2
                else:
                    options[key] = True
                    i += 1
            else:
                i += 1
        
        # Get base profile
        base = manager.get_profile(based_on)
        if not base:
            print(f"Base profile not found: {based_on}")
            sys.exit(1)
        
        # Create with modifications
        success = manager.clone_profile(
            based_on, name,
            modifications={
                "description": f"Custom profile based on {based_on}",
                "add_options": options,
                "tags": ["custom", based_on],
            }
        )
        
        if success:
            print(f" Created profile: {name}")
            print(f"  Based on: {based_on}")
            print(f"  Options: {options}")
        else:
            print(f" Failed to create profile")
            sys.exit(1)
    
    elif command == "delete":
        if len(sys.argv) < 3:
            print("Usage: profile delete <name>")
            sys.exit(1)
        
        name = sys.argv[2]
        if manager.delete_profile(name):
            print(f" Deleted profile: {name}")
        else:
            print(f" Failed to delete profile: {name}")
            sys.exit(1)
    
    elif command == "export":
        if len(sys.argv) < 3:
            print("Usage: profile export <name>")
            sys.exit(1)
        
        name = sys.argv[2]
        json_data = manager.export_profile(name)
        if json_data:
            print(json_data)
        else:
            print(f"Profile not found: {name}")
            sys.exit(1)
    
    elif command == "import":
        if len(sys.argv) < 3:
            print("Usage: profile import <json_file>")
            sys.exit(1)
        
        file_path = sys.argv[2]
        try:
            json_data = Path(file_path).read_text()
            if manager.import_profile(json_data):
                print(f" Imported profile from {file_path}")
            else:
                print(" Failed to import profile")
                sys.exit(1)
        except Exception as e:
            print(f" Error: {e}")
            sys.exit(1)
    
    else:
        # Try to use as profile name
        profile = manager.get_profile(command)
        if profile:
            target = sys.argv[2] if len(sys.argv) > 2 else None
            expanded = manager.expand_profile(command, target)
            if expanded:
                cmd, args = expanded
                print(f"Profile: {command}")
                print(f"Expands to: elengenix {cmd} {' '.join(args)}")
            else:
                print(f"Failed to expand profile: {command}")
        else:
            print(f"Unknown command: {command}")
            print(manager.format_profile_list())
            sys.exit(1)


if __name__ == "__main__":
    run_cli()
