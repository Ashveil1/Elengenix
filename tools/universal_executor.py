"""
tools/universal_executor.py — Universal AI Agent Executor (v1.0.0)
- Flexible like Claude Code, Gemini CLI, OpenClaw
- File operations: read, edit, write, search
- Package management: pip, npm, apt, gem, etc.
- Shell execution with intelligent allowlist
- Multi-turn conversation support
- Bug Bounty specialized reasoning
"""

from __future__ import annotations

import logging
import os
import re
import shlex
import subprocess
import json
from pathlib import Path
from typing import Dict, List, Optional, Union, Any
from dataclasses import dataclass
from datetime import datetime

logger = logging.getLogger("elengenix.universal")


@dataclass
class ExecutionResult:
    """Standard result format for all operations."""
    success: bool
    output: str
    error: str
    action_type: str
    metadata: Dict[str, Any]


class FileEditor:
    """Intelligent file editor like Claude Code."""
    
    def __init__(self, base_dir: str = None):
        self.base_dir = Path(base_dir).resolve() if base_dir else Path.cwd().resolve()
        self.edit_history: List[Dict] = []
    
    def _validate_path(self, file_path: str) -> Optional[Path]:
        """Validate and resolve path within base directory."""
        try:
            path = Path(file_path).resolve()
            # Security: Must be within project directory
            if not str(path).startswith(str(self.base_dir)):
                logger.warning(f"Path outside base dir blocked: {file_path}")
                return None
            return path
        except Exception as e:
            logger.error(f"Invalid path: {e}")
            return None
    
    def read_file(self, file_path: str, offset: int = 1, limit: int = 100) -> ExecutionResult:
        """Read file with line numbers."""
        path = self._validate_path(file_path)
        if not path:
            return ExecutionResult(False, "", "Invalid or unsafe path", "read", {})
        
        if not path.exists():
            return ExecutionResult(False, "", f"File not found: {file_path}", "read", {})
        
        try:
            content = path.read_text(encoding='utf-8', errors='replace')
            lines = content.split('\n')
            
            # Get requested range
            start_idx = max(0, offset - 1)
            end_idx = min(len(lines), offset - 1 + limit)
            selected_lines = lines[start_idx:end_idx]
            
            # Format with line numbers
            numbered = []
            for i, line in enumerate(selected_lines, start_idx + 1):
                numbered.append(f"{i:4d} | {line}")
            
            output = '\n'.join(numbered)
            total_lines = len(lines)
            
            return ExecutionResult(
                True, 
                output, 
                "", 
                "read", 
                {
                    "file": str(path),
                    "total_lines": total_lines,
                    "showing": f"{offset}-{min(end_idx, total_lines)}",
                    "truncated": limit < total_lines
                }
            )
        except Exception as e:
            return ExecutionResult(False, "", str(e), "read", {})
    
    def write_file(self, file_path: str, content: str, overwrite: bool = False) -> ExecutionResult:
        """Write content to file."""
        path = self._validate_path(file_path)
        if not path:
            return ExecutionResult(False, "", "Invalid or unsafe path", "write", {})
        
        if path.exists() and not overwrite:
            return ExecutionResult(
                False, 
                "", 
                f"File exists. Use overwrite=True to replace.", 
                "write", 
                {"file": str(path)}
            )
        
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding='utf-8')
            
            # Log edit
            self.edit_history.append({
                "action": "write",
                "file": str(path),
                "timestamp": datetime.utcnow().isoformat(),
                "chars": len(content)
            })
            
            return ExecutionResult(
                True,
                f"Written {len(content)} chars to {path}",
                "",
                "write",
                {"file": str(path), "chars": len(content)}
            )
        except Exception as e:
            return ExecutionResult(False, "", str(e), "write", {})
    
    def edit_file(self, file_path: str, old_string: str, new_string: str) -> ExecutionResult:
        """Strategic file edit - replace old with new (like Claude Code)."""
        path = self._validate_path(file_path)
        if not path:
            return ExecutionResult(False, "", "Invalid or unsafe path", "edit", {})
        
        if not path.exists():
            return ExecutionResult(False, "", f"File not found: {file_path}", "edit", {})
        
        try:
            content = path.read_text(encoding='utf-8', errors='replace')
            
            # Count occurrences
            count = content.count(old_string)
            if count == 0:
                return ExecutionResult(
                    False,
                    "",
                    f"String not found in file. Use search first to verify.",
                    "edit",
                    {"file": str(path), "attempted": old_string[:50]}
                )
            
            if count > 1:
                return ExecutionResult(
                    False,
                    "",
                    f"Found {count} occurrences. Be more specific with unique context.",
                    "edit",
                    {"file": str(path), "count": count}
                )
            
            # Perform edit
            new_content = content.replace(old_string, new_string, 1)
            path.write_text(new_content, encoding='utf-8')
            
            # Log edit
            self.edit_history.append({
                "action": "edit",
                "file": str(path),
                "timestamp": datetime.utcnow().isoformat(),
                "old_len": len(old_string),
                "new_len": len(new_string)
            })
            
            return ExecutionResult(
                True,
                f"Edited {path}: {len(old_string)} chars → {len(new_string)} chars",
                "",
                "edit",
                {
                    "file": str(path),
                    "replaced_chars": len(old_string),
                    "new_chars": len(new_string),
                    "total_chars": len(new_content)
                }
            )
        except Exception as e:
            return ExecutionResult(False, "", str(e), "edit", {})
    
    def search_in_file(self, file_path: str, pattern: str) -> ExecutionResult:
        """Search pattern in file with context."""
        path = self._validate_path(file_path)
        if not path:
            return ExecutionResult(False, "", "Invalid or unsafe path", "search", {})
        
        if not path.exists():
            return ExecutionResult(False, "", f"File not found: {file_path}", "search", {})
        
        try:
            content = path.read_text(encoding='utf-8', errors='replace')
            lines = content.split('\n')
            
            matches = []
            for i, line in enumerate(lines, 1):
                if re.search(pattern, line, re.IGNORECASE):
                    # Get context (2 lines before and after)
                    start = max(0, i - 3)
                    end = min(len(lines), i + 2)
                    context = lines[start:end]
                    
                    matches.append({
                        "line": i,
                        "match": line.strip(),
                        "context": '\n'.join([f"{j+1:4d} | {l}" for j, l in enumerate(context, start)])
                    })
            
            if not matches:
                return ExecutionResult(
                    True,
                    f"No matches for '{pattern}'",
                    "",
                    "search",
                    {"file": str(path), "pattern": pattern, "matches": 0}
                )
            
            output = f"Found {len(matches)} matches for '{pattern}':\n\n"
            for m in matches:
                output += f"Line {m['line']}:\n{m['context']}\n{'─' * 40}\n"
            
            return ExecutionResult(
                True,
                output,
                "",
                "search",
                {"file": str(path), "pattern": pattern, "matches": len(matches)}
            )
        except Exception as e:
            return ExecutionResult(False, "", str(e), "search", {})
    
    def list_directory(self, dir_path: str = ".", max_depth: int = 2) -> ExecutionResult:
        """List directory structure."""
        path = self._validate_path(dir_path)
        if not path:
            return ExecutionResult(False, "", "Invalid or unsafe path", "list", {})
        
        if not path.is_dir():
            return ExecutionResult(False, "", f"Not a directory: {dir_path}", "list", {})
        
        try:
            files = []
            for item in sorted(path.iterdir()):
                rel_path = item.relative_to(self.base_dir)
                if item.is_dir():
                    files.append(f" {rel_path}/")
                    if max_depth > 1:
                        for sub in sorted(item.iterdir()):
                            if sub.is_file():
                                files.append(f"    {sub.relative_to(self.base_dir)}")
                else:
                    size = item.stat().st_size
                    files.append(f" {rel_path} ({size:,} bytes)")
            
            output = f"Contents of {path.relative_to(self.base_dir)}:\n" + '\n'.join(files)
            return ExecutionResult(True, output, "", "list", {"dir": str(path), "items": len(files)})
        except Exception as e:
            return ExecutionResult(False, "", str(e), "list", {})


class PackageManager:
    """Universal package manager for multiple ecosystems."""
    
    MANAGERS = {
        "pip": {
            "install": "pip install {package} --quiet",
            "uninstall": "pip uninstall {package} -y",
            "search": "pip search {package}",
            "list": "pip list",
            "update": "pip install --upgrade {package}",
        },
        "npm": {
            "install": "npm install {package} --silent",
            "uninstall": "npm uninstall {package}",
            "search": "npm search {package}",
            "list": "npm list",
            "update": "npm update {package}",
        },
        "apt": {
            "install": "apt-get install -y {package}",
            "uninstall": "apt-get remove -y {package}",
            "search": "apt-cache search {package}",
            "list": "dpkg -l",
            "update": "apt-get upgrade -y {package}",
        },
        "go": {
            "install": "go install {package}@latest",
            "uninstall": "rm $(which {binary})",
            "list": "go list -m all",
        },
        "gem": {
            "install": "gem install {package} --no-document",
            "uninstall": "gem uninstall {package}",
            "list": "gem list",
        },
    }
    
    def execute(self, manager: str, action: str, package: str = None) -> ExecutionResult:
        """Execute package manager command."""
        if manager not in self.MANAGERS:
            return ExecutionResult(
                False,
                "",
                f"Unknown package manager: {manager}. Supported: {list(self.MANAGERS.keys())}",
                "package",
                {}
            )
        
        if action not in self.MANAGERS[manager]:
            return ExecutionResult(
                False,
                "",
                f"Action '{action}' not supported for {manager}",
                "package",
                {}
            )
        
        cmd_template = self.MANAGERS[manager][action]
        cmd = cmd_template.format(package=package or "", binary=package or "" if " " not in str(package) else package.split()[-1])
        
        try:
            result = subprocess.run(
                shlex.split(cmd),
                capture_output=True,
                text=True,
                timeout=300,
                shell=False
            )
            
            output = result.stdout if result.stdout else result.stderr
            success = result.returncode == 0
            
            return ExecutionResult(
                success,
                output[:5000],  # Limit output size
                "" if success else f"Exit code: {result.returncode}",
                "package",
                {"manager": manager, "action": action, "package": package, "exit_code": result.returncode}
            )
        except subprocess.TimeoutExpired:
            return ExecutionResult(False, "", "Command timed out after 300s", "package", {})
        except Exception as e:
            return ExecutionResult(False, "", str(e), "package", {})


class UniversalExecutor:
    """
    Universal AI Agent Executor.
    Combines file editing, package management, and flexible shell execution.
    """
    
    # Flexible allowlist - allows more than just security tools
    ALLOWED_COMMANDS = frozenset({
        # Package managers
        "pip", "npm", "apt", "apt-get", "yum", "dnf", "brew", "pacman",
        "gem", "bundle", "composer", "cargo", "go", "conda", "poetry",
        # Common tools
        "curl", "wget", "git", "ssh", "scp", "rsync",
        "grep", "find", "awk", "sed", "cut", "sort", "uniq",
        "cat", "head", "tail", "less", "more", "vim", "nano",
        "ls", "cd", "pwd", "mkdir", "rm", "cp", "mv", "touch",
        "chmod", "chown", "ps", "top", "htop", "kill", "pkill",
        "tar", "gzip", "gunzip", "zip", "unzip",
        "ping", "traceroute", "netstat", "ss", "lsof",
        "python", "python3", "node", "ruby", "php", "perl",
        "echo", "printenv", "export", "source",
        # Security tools
        "nmap", "masscan", "subfinder", "nuclei", "httpx", "katana",
        "waybackurls", "ffuf", "gau", "amass", "hakrawler", "gospider",
        "assetfinder", "dalfox", "arjun", "naabu", "trufflehog",
    })
    
    DANGEROUS_PATTERNS = [
        r"rm\s+-rf\s+/",
        r"dd\s+if=.*of=/dev/[sh]d",
        r"mkfs\.\w+\s+/dev",
        r">\s*/dev/[sh]d",
        r":\(\)\{\s*:\|:&\};:",  # Fork bomb
        r"curl.*\|.*sh",  # Pipe to shell
        r"wget.*\|.*sh",
    ]
    
    def __init__(self, base_dir: str = None):
        self.file_editor = FileEditor(base_dir)
        self.package_manager = PackageManager()
        self.execution_history: List[Dict] = []
    
    def is_safe_command(self, command: str) -> tuple[bool, str]:
        """Check if command is safe to execute."""
        if not command or not command.strip():
            return False, "Empty command"
        
        # Check dangerous patterns
        for pattern in self.DANGEROUS_PATTERNS:
            if re.search(pattern, command, re.IGNORECASE):
                return False, f"Blocked dangerous pattern: {pattern}"
        
        # Check binary is allowed
        try:
            args = shlex.split(command.strip())
            if not args:
                return False, "Empty command"
            
            binary = os.path.basename(args[0])
            
            # Allow if in allowlist
            if binary in self.ALLOWED_COMMANDS:
                return True, ""
            
            # Special case: scripts in project directory
            if command.startswith("./") or command.startswith("python"):
                return True, ""
            
            return False, f"Command '{binary}' not in allowlist. Allowed: {', '.join(sorted(self.ALLOWED_COMMANDS))[:100]}..."
            
        except ValueError as e:
            return False, f"Parse error: {e}"
    
    def execute_shell(self, command: str, timeout: int = 300, cwd: str = None) -> ExecutionResult:
        """Execute shell command with safety checks."""
        safe, reason = self.is_safe_command(command)
        if not safe:
            return ExecutionResult(False, "", reason, "shell", {"command": command})
        
        try:
            result = subprocess.run(
                shlex.split(command),
                capture_output=True,
                text=True,
                timeout=timeout,
                shell=False,
                cwd=cwd
            )
            
            output = result.stdout
            if result.stderr and result.returncode != 0:
                output += f"\n[STDERR]: {result.stderr}"
            
            # Log execution
            self.execution_history.append({
                "command": command,
                "timestamp": datetime.utcnow().isoformat(),
                "success": result.returncode == 0,
                "exit_code": result.returncode
            })
            
            return ExecutionResult(
                result.returncode == 0,
                output[:10000],  # Limit output
                result.stderr if result.returncode != 0 else "",
                "shell",
                {
                    "command": command,
                    "exit_code": result.returncode,
                    "duration": timeout
                }
            )
        except subprocess.TimeoutExpired:
            return ExecutionResult(False, "", f"Timeout after {timeout}s", "shell", {"command": command})
        except Exception as e:
            return ExecutionResult(False, "", str(e), "shell", {"command": command})
    
    def execute_action(self, action: Dict[str, Any]) -> ExecutionResult:
        """
        Execute a structured action from AI.
        
        Action format:
        {
            "type": "read_file|write_file|edit_file|search_file|list_dir|shell|package|search_web",
            "params": {...}
        }
        """
        action_type = action.get("type", "")
        params = action.get("params", {})
        
        if action_type == "read_file":
            return self.file_editor.read_file(
                params.get("path"),
                params.get("offset", 1),
                params.get("limit", 100)
            )
        
        elif action_type == "write_file":
            return self.file_editor.write_file(
                params.get("path"),
                params.get("content"),
                params.get("overwrite", False)
            )
        
        elif action_type == "edit_file":
            return self.file_editor.edit_file(
                params.get("path"),
                params.get("old_string"),
                params.get("new_string")
            )
        
        elif action_type == "search_file":
            return self.file_editor.search_in_file(
                params.get("path"),
                params.get("pattern")
            )
        
        elif action_type == "list_dir":
            return self.file_editor.list_directory(
                params.get("path", "."),
                params.get("max_depth", 2)
            )
        
        elif action_type == "shell":
            return self.execute_shell(
                params.get("command"),
                params.get("timeout", 300),
                params.get("cwd")
            )
        
        elif action_type == "package":
            return self.package_manager.execute(
                params.get("manager", "pip"),
                params.get("action", "install"),
                params.get("package")
            )
        
        elif action_type == "search_web":
            from tools.research_tool import search_web
            query = params.get("query", "")
            num = params.get("num_results", 5)
            results = search_web(query, num)
            return ExecutionResult(
                True,
                json.dumps(results, indent=2),
                "",
                "search_web",
                {"query": query, "results": len(results)}
            )
        
        else:
            return ExecutionResult(
                False,
                "",
                f"Unknown action type: {action_type}",
                "unknown",
                {}
            )
    
    def get_capabilities(self) -> str:
        """Return capabilities description for AI prompt."""
        return """
## Universal Agent Capabilities

You can perform these actions:

### File Operations
- `read_file`: Read file with line numbers
- `write_file`: Create new file
- `edit_file`: Strategic edit (replace specific text)
- `search_file`: Search pattern with context
- `list_dir`: List directory contents

### Package Management
- `package`: Install/uninstall packages (pip, npm, apt, go, gem)

### Shell Execution
- `shell`: Run shell commands (security filtered)

### Web Research
- `search_web`: Search internet for information

### Response Format
Always respond with JSON:
```json
{
  "type": "action_type",
  "params": {...},
  "reasoning": "why you're doing this"
}
```

For multi-step tasks, chain multiple actions.
"""


# Global instance
_universal_executor = None

def get_universal_executor(base_dir: str = None) -> UniversalExecutor:
    """Get singleton UniversalExecutor instance."""
    global _universal_executor
    if _universal_executor is None:
        _universal_executor = UniversalExecutor(base_dir)
    return _universal_executor


if __name__ == "__main__":
    # Test
    print("Testing Universal Executor...")
    executor = UniversalExecutor()
    
    # Test file operations
    test_file = "/tmp/test_universal.txt"
    r1 = executor.file_editor.write_file(test_file, "Hello World\nLine 2\nLine 3")
    print(f"Write: {r1.success}")
    
    r2 = executor.file_editor.read_file(test_file)
    print(f"Read:\n{r2.output}")
    
    r3 = executor.file_editor.edit_file(test_file, "Line 2", "Line 2 MODIFIED")
    print(f"Edit: {r3.success}")
    
    r4 = executor.file_editor.read_file(test_file)
    print(f"After edit:\n{r4.output}")
    
    # Test shell
    r5 = executor.execute_shell("echo 'Universal Executor Working!'")
    print(f"Shell: {r5.output}")
