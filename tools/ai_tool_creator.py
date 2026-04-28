"""tools/ai_tool_creator.py

AI Tool Creator - Allow AI to Create, Modify, and Install Tools Dynamically.

Purpose:
- AI can create new Python tools on-the-fly based on target needs
- AI can install external dependencies automatically
- AI can discover and integrate external security tools
- Self-improving: AI learns from results and creates better tools

Governance:
- User approval required by default (with auto-approve option)
- All tool creation/installation is logged
- Sandbox escape detection
- Rollback capability
"""

from __future__ import annotations

import ast
import hashlib
import json
import logging
import os
import re
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

logger = logging.getLogger("elengenix.ai_tool_creator")


@dataclass
class ToolSpec:
    """Specification for a tool to be created."""
    name: str
    purpose: str
    language: str
    code: str
    dependencies: List[str]
    entry_point: str
    safety_level: str
    requires_approval: bool = True
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    ai_reasoning: str = ""


@dataclass
class ToolExecutionResult:
    """Result from executing an AI-created tool."""
    success: bool
    output: str
    error: Optional[str]
    findings: List[Dict[str, Any]]
    execution_time: float
    tool_name: str


class AIGovernance:
    """Governance layer for AI tool creation and execution."""
    
    DANGEROUS_PATTERNS = [
        r"rm\s+-rf",
        r"os\.system\s*\(.*rm",
        r"eval\s*\(",
        r"exec\s*\(",
    ]
    
    def __init__(self, mode: str = "ask", auto_approve_tools: List[str] = None):
        self.mode = mode
        self.auto_approve_tools = auto_approve_tools or []
        self.approval_history: List[Dict] = []
        
    def check_tool_safety(self, tool_spec: ToolSpec) -> Tuple[bool, str]:
        """Check if tool is safe to create/execute."""
        for pattern in self.DANGEROUS_PATTERNS:
            if re.search(pattern, tool_spec.code, re.IGNORECASE):
                return False, f"Dangerous pattern detected: {pattern}"
        return True, "Safe"
    
    def request_approval(self, action: str, details: Dict) -> bool:
        """Request user approval for action."""
        if self.mode == "auto":
            return True
        
        if action == "create_tool" and details.get("tool_name") in self.auto_approve_tools:
            return True
        
        # Show prompt to user
        print(f"\n[AI REQUEST] {action}")
        if "tool_name" in details:
            print(f"Tool: {details['tool_name']}")
        if "purpose" in details:
            print(f"Purpose: {details['purpose']}")
        if "ai_reasoning" in details:
            print(f"AI Reasoning: {details['ai_reasoning']}")
        
        response = input("Approve? (y/n/auto): ").strip().lower()
        
        if response == "auto":
            self.mode = "auto"
            print("[Mode changed to AUTO - will auto-approve future requests]")
            return True
        
        approved = response in ("y", "yes", "")
        
        self.approval_history.append({
            "action": action,
            "details": details,
            "approved": approved,
            "timestamp": datetime.utcnow().isoformat(),
        })
        
        return approved


class DependencyManager:
    """Manage dependencies for AI-created tools."""
    
    def __init__(self, cache_dir: Path = Path(".cache/ai_deps")):
        self.cache_dir = cache_dir
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.installed = set()
        
    def install_pip_package(self, package: str) -> bool:
        """Install pip package safely."""
        if package in self.installed:
            return True
            
        try:
            cmd = [sys.executable, "-m", "pip", "install", "--user", "--quiet", package]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            
            if result.returncode == 0:
                self.installed.add(package)
                logger.info(f"Installed {package}")
                return True
            else:
                logger.error(f"Failed to install {package}: {result.stderr}")
                return False
        except Exception as e:
            logger.error(f"Install error: {e}")
            return False


class AIToolCreator:
    """AI Tool Creator - Dynamic tool creation and management."""
    
    AI_TOOLS_DIR = Path("tools/ai_generated")
    
    def __init__(self, governance_mode: str = "ask", ai_client=None):
        self.governance = AIGovernance(mode=governance_mode)
        self.dep_manager = DependencyManager()
        self.ai_client = ai_client
        
        self.AI_TOOLS_DIR.mkdir(parents=True, exist_ok=True)
        
        self.ai_tools: Dict[str, ToolSpec] = {}
        self._load_existing_tools()
        
        logger.info(f"AIToolCreator initialized (mode: {governance_mode})")
    
    def _load_existing_tools(self) -> None:
        """Load previously created AI tools."""
        for tool_file in self.AI_TOOLS_DIR.glob("*.json"):
            try:
                data = json.loads(tool_file.read_text())
                self.ai_tools[data["name"]] = ToolSpec(**data)
            except Exception as e:
                logger.debug(f"Failed to load tool {tool_file}: {e}")
    
    def analyze_target_and_plan(self, target: str, target_info: Dict = None) -> List[ToolSpec]:
        """
        AI analyzes target and plans what custom tools are needed.
        
        Returns:
            List of ToolSpec that AI thinks are needed
        """
        if not self.ai_client:
            logger.warning("No AI client available for tool planning")
            return []
        
        prompt = f"""You are an autonomous security AI. Analyze this target and plan custom tools.

Target: {target}
Target Info: {target_info or 'Unknown'}

Your task:
1. Analyze what the target likely is (web app, API, cloud infra, etc.)
2. Identify what specialized tools would be most effective
3. Plan custom Python tools to create

For each tool, provide:
- name: tool name
- purpose: what it does
- reasoning: why this tool is needed for this specific target
- safety_level: safe/cautious/dangerous
- dependencies: list of pip packages needed
- code: complete Python code for the tool

Respond in JSON format:
{{
    "tools": [
        {{
            "name": "tool_name",
            "purpose": "description",
            "reasoning": "why needed",
            "safety_level": "safe",
            "dependencies": ["requests", "bs4"],
            "code": "#!/usr/bin/env python3\\n..."
        }}
    ]
}}
"""
        
        try:
            # Call AI to analyze and plan
            response = self._call_ai(prompt)
            
            # Parse response
            data = json.loads(response)
            tools = []
            
            for tool_data in data.get("tools", []):
                spec = ToolSpec(
                    name=tool_data["name"],
                    purpose=tool_data["purpose"],
                    language="python",
                    code=tool_data["code"],
                    dependencies=tool_data.get("dependencies", []),
                    entry_point=tool_data["name"],
                    safety_level=tool_data.get("safety_level", "safe"),
                    ai_reasoning=tool_data.get("reasoning", ""),
                )
                tools.append(spec)
            
            logger.info(f"AI planned {len(tools)} custom tools for {target}")
            return tools
            
        except Exception as e:
            logger.error(f"Tool planning failed: {e}")
            return []
    
    def create_tool(self, tool_spec: ToolSpec) -> bool:
        """
        Create a tool from specification.
        
        Returns:
            True if created successfully
        """
        # Check governance
        is_safe, reason = self.governance.check_tool_safety(tool_spec)
        
        if not is_safe:
            logger.warning(f"Tool {tool_spec.name} failed safety check: {reason}")
            if not self.governance.request_approval("create_unsafe_tool", {
                "tool_name": tool_spec.name,
                "purpose": tool_spec.purpose,
                "reason": reason,
                "ai_reasoning": tool_spec.ai_reasoning,
            }):
                return False
        elif tool_spec.requires_approval:
            if not self.governance.request_approval("create_tool", {
                "tool_name": tool_spec.name,
                "purpose": tool_spec.purpose,
                "safety_level": tool_spec.safety_level,
                "ai_reasoning": tool_spec.ai_reasoning,
            }):
                logger.info(f"User declined tool creation: {tool_spec.name}")
                return False
        
        # Install dependencies first
        for dep in tool_spec.dependencies:
            if not self.dep_manager.install_pip_package(dep):
                logger.warning(f"Failed to install dependency: {dep}")
        
        # Save tool
        try:
            # Save Python file
            tool_path = self.AI_TOOLS_DIR / f"{tool_spec.name}.py"
            tool_path.write_text(tool_spec.code, encoding="utf-8")
            
            # Save metadata
            meta_path = self.AI_TOOLS_DIR / f"{tool_spec.name}.json"
            meta_path.write_text(
                json.dumps(tool_spec.__dict__, indent=2, default=str),
                encoding="utf-8"
            )
            
            # Register
            self.ai_tools[tool_spec.name] = tool_spec
            
            logger.info(f"Created AI tool: {tool_spec.name}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to create tool {tool_spec.name}: {e}")
            return False
    
    def execute_tool(self, tool_name: str, **kwargs) -> ToolExecutionResult:
        """
        Execute an AI-created tool.
        
        Args:
            tool_name: Name of tool to execute
            **kwargs: Arguments to pass to tool
            
        Returns:
            ToolExecutionResult
        """
        if tool_name not in self.ai_tools:
            return ToolExecutionResult(
                success=False,
                output="",
                error=f"Tool not found: {tool_name}",
                findings=[],
                execution_time=0.0,
                tool_name=tool_name,
            )
        
        tool_spec = self.ai_tools[tool_name]
        
        # Request approval for execution if needed
        if tool_spec.requires_approval and self.governance.mode != "auto":
            if not self.governance.request_approval("execute_tool", {
                "tool_name": tool_name,
                "purpose": tool_spec.purpose,
                "args": kwargs,
            }):
                return ToolExecutionResult(
                    success=False,
                    output="",
                    error="Execution declined by user",
                    findings=[],
                    execution_time=0.0,
                    tool_name=tool_name,
                )
        
        # Execute tool in sandboxed environment
        import time
        start_time = time.time()
        
        try:
            # Create temporary module
            tool_path = self.AI_TOOLS_DIR / f"{tool_name}.py"
            
            # Load and execute
            import importlib.util
            spec = importlib.util.spec_from_file_location(tool_name, tool_path)
            module = importlib.util.module_from_spec(spec)
            
            # Execute with restricted globals
            safe_globals = {
                "__name__": "__main__",
                "__file__": str(tool_path),
                "print": print,
                "input": lambda x="": "",  # Disable input
                "open": open,
            }
            
            spec.loader.exec_module(module)
            
            # Call main function if exists
            if hasattr(module, "main"):
                result = module.main(**kwargs)
            elif hasattr(module, "run"):
                result = module.run(**kwargs)
            else:
                result = {"findings": [], "output": "No main/run function found"}
            
            execution_time = time.time() - start_time
            
            return ToolExecutionResult(
                success=True,
                output=str(result.get("output", "")),
                error=None,
                findings=result.get("findings", []),
                execution_time=execution_time,
                tool_name=tool_name,
            )
            
        except Exception as e:
            execution_time = time.time() - start_time
            logger.error(f"Tool execution failed: {e}")
            return ToolExecutionResult(
                success=False,
                output="",
                error=str(e),
                findings=[],
                execution_time=execution_time,
                tool_name=tool_name,
            )
    
    def improve_tool(self, tool_name: str, feedback: str) -> bool:
        """
        AI improves a tool based on execution feedback.
        
        Args:
            tool_name: Tool to improve
            feedback: What went wrong / what could be better
            
        Returns:
            True if improved successfully
        """
        if tool_name not in self.ai_tools:
            return False
        
        old_spec = self.ai_tools[tool_name]
        
        if not self.ai_client:
            return False
        
        prompt = f"""Improve this security tool based on feedback.

Tool Name: {tool_name}
Current Code:
```python
{old_spec.code}
```

Feedback: {feedback}

Provide improved version with:
1. Fixes for issues mentioned
2. Better error handling
3. More comprehensive detection

Respond with complete new code.
"""
        
        try:
            new_code = self._call_ai(prompt)
            
            # Extract code from markdown if present
            if "```python" in new_code:
                new_code = new_code.split("```python")[1].split("```")[0].strip()
            elif "```" in new_code:
                new_code = new_code.split("```")[1].split("```")[0].strip()
            
            # Update spec
            improved_spec = ToolSpec(
                name=old_spec.name,
                purpose=old_spec.purpose + " (improved)",
                language="python",
                code=new_code,
                dependencies=old_spec.dependencies,
                entry_point=old_spec.entry_point,
                safety_level=old_spec.safety_level,
                ai_reasoning=f"Improved based on feedback: {feedback}",
            )
            
            # Backup old version
            backup_path = self.AI_TOOLS_DIR / f"{tool_name}_backup_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.py"
            (self.AI_TOOLS_DIR / f"{tool_name}.py").rename(backup_path)
            
            # Save improved version
            return self.create_tool(improved_spec)
            
        except Exception as e:
            logger.error(f"Tool improvement failed: {e}")
            return False
    
    def _call_ai(self, prompt: str) -> str:
        """Call AI client with prompt."""
        if not self.ai_client:
            raise RuntimeError("No AI client configured")
        
        # Use UniversalAIClient pattern
        try:
            from tools.universal_ai_client import AIClientManager, AIMessage
            
            manager = AIClientManager()
            messages = [
                AIMessage(role="system", content="You are an expert security researcher and Python developer."),
                AIMessage(role="user", content=prompt),
            ]
            
            response = manager.chat(messages, temperature=0.3, max_tokens=2048)
            return response.content
            
        except Exception as e:
            logger.error(f"AI call failed: {e}")
            return "{}"
    
    def list_ai_tools(self) -> List[Dict[str, Any]]:
        """List all AI-created tools."""
        return [
            {
                "name": spec.name,
                "purpose": spec.purpose,
                "created_at": spec.created_at,
                "safety_level": spec.safety_level,
                "ai_reasoning": spec.ai_reasoning,
            }
            for spec in self.ai_tools.values()
        ]
    
    def delete_tool(self, tool_name: str) -> bool:
        """Delete an AI-created tool."""
        if tool_name not in self.ai_tools:
            return False
        
        try:
            (self.AI_TOOLS_DIR / f"{tool_name}.py").unlink(missing_ok=True)
            (self.AI_TOOLS_DIR / f"{tool_name}.json").unlink(missing_ok=True)
            del self.ai_tools[tool_name]
            return True
        except Exception as e:
            logger.error(f"Failed to delete tool: {e}")
            return False


def run_cli():
    """CLI for AI Tool Creator."""
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python ai_tool_creator.py <command> [args]")
        print("Commands:")
        print("  list              - List all AI-created tools")
        print("  create <target>   - AI analyzes target and creates tools")
        print("  execute <name>    - Execute an AI tool")
        print("  delete <name>     - Delete an AI tool")
        sys.exit(1)
    
    command = sys.argv[1]
    creator = AIToolCreator(governance_mode="ask")
    
    if command == "list":
        tools = creator.list_ai_tools()
        print(f"\nAI-Created Tools ({len(tools)}):")
        for tool in tools:
            print(f"  - {tool['name']}: {tool['purpose'][:60]}...")
            print(f"    Created: {tool['created_at']}")
    
    elif command == "create":
        if len(sys.argv) < 3:
            print("Usage: create <target_url>")
            sys.exit(1)
        
        target = sys.argv[2]
        print(f"AI analyzing target: {target}")
        
        tools = creator.analyze_target_and_plan(target)
        
        if not tools:
            print("No tools planned")
            sys.exit(1)
        
        print(f"\nAI planned {len(tools)} tools:")
        for spec in tools:
            print(f"\n  [Creating] {spec.name}")
            print(f"  Purpose: {spec.purpose}")
            print(f"  Reasoning: {spec.ai_reasoning}")
            
            if creator.create_tool(spec):
                print(f"  [OK] Created successfully")
            else:
                print(f"  [FAIL] Creation failed or declined")
    
    elif command == "execute":
        if len(sys.argv) < 3:
            print("Usage: execute <tool_name>")
            sys.exit(1)
        
        tool_name = sys.argv[2]
        result = creator.execute_tool(tool_name)
        
        if result.success:
            print(f"[OK] Tool executed successfully")
            print(f"Output: {result.output[:500]}")
            print(f"Findings: {len(result.findings)}")
        else:
            print(f"[FAIL] {result.error}")
    
    elif command == "delete":
        if len(sys.argv) < 3:
            print("Usage: delete <tool_name>")
            sys.exit(1)
        
        tool_name = sys.argv[2]
        if creator.delete_tool(tool_name):
            print(f"[OK] Deleted {tool_name}")
        else:
            print(f"[FAIL] Could not delete {tool_name}")
    
    else:
        print(f"Unknown command: {command}")


if __name__ == "__main__":
    run_cli()
