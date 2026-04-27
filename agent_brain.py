"""
agent_brain.py — Elengenix Intelligent Hunting Engine (v3.0.0)
- Strategic Planning Module (Attack Tree Generation)
- Chain of Thought Logging
- Tool Selection Intelligence
- High-security Subprocess Execution (Shell=False + Strict Allowlist)
"""

import os
import json
import re
import subprocess
import shlex
import time
import logging
from pathlib import Path
from collections import Counter
from dataclasses import dataclass, field
from typing import Optional, Callable, Dict, Any, List, Set
from enum import Enum

from llm_client import LLMClient
from tools.memory_manager import save_learning, get_summarized_learnings
from tools.tool_registry import registry, ToolCategory, ToolResult
from tools.cvss_calculator import CVSSCalculator, Severity
from tools.vector_memory import remember, recall, get_context_for_ai, get_vector_memory
from tools.universal_executor import UniversalExecutor, get_universal_executor
from tools.cve_database import get_cve_database, format_cve_for_ai, CVEEntry
from live_display import get_activity_logger, display_in_chat_mode
from bot_utils import send_telegram_notification

logger = logging.getLogger("elengenix.agent")


class AttackPhase(Enum):
    """Standard penetration testing phases."""
    RECONNAISSANCE = "recon"
    SCANNING = "scanning"
    ENUMERATION = "enumeration"
    EXPLOITATION = "exploitation"
    POST_EXPLOITATION = "post_exploitation"
    REPORTING = "reporting"


@dataclass
class AttackStep:
    """Single step in an attack tree."""
    phase: AttackPhase
    tool_name: str
    target: str
    purpose: str
    depends_on: List[str] = field(default_factory=list)
    completed: bool = False
    result: Optional[ToolResult] = None
    findings: List[Dict] = field(default_factory=list)


@dataclass
class AttackTree:
    """Strategic plan for penetration testing."""
    target: str
    objective: str
    steps: List[AttackStep] = field(default_factory=list)
    current_phase: AttackPhase = AttackPhase.RECONNAISSANCE
    reasoning: str = ""
    created_at: float = field(default_factory=time.time)


@dataclass
class AgentThought:
    """Chain of Thought logging entry."""
    step: int
    timestamp: float
    context: str
    reasoning: str
    action_taken: str
    result: str
    confidence: float = 0.0


class StrategicPlanner:
    """Generates and manages attack strategies."""
    
    def __init__(self, client: LLMClient):
        self.client = client
        self.cvss_calc = CVSSCalculator(use_ai=True)
    
    def generate_attack_tree(
        self, 
        target: str, 
        objective: str = "discover vulnerabilities"
    ) -> AttackTree:
        """
        Generate strategic attack plan using AI.
        
        Creates a structured approach based on target type and objectives.
        """
        tree = AttackTree(target=target, objective=objective)
        
        # Use AI to generate initial strategy
        planning_prompt = f"""You are a penetration testing strategist.

TARGET: {target}
OBJECTIVE: {objective}

Generate an attack tree as JSON with this structure:
{{
    "reasoning": "strategic analysis of the target",
    "phases": [
        {{
            "phase": "recon|scanning|enumeration|exploitation",
            "tools": ["tool_name"],
            "purpose": "what we want to achieve",
            "priority": 1
        }}
    ]
}}

Available tools: subfinder, httpx, naabu, nuclei, dalfox, arjun, ffuf, trufflehog, katana

Respond with valid JSON only."""

        try:
            response = self.client.chat(
                "Generate penetration testing strategy",
                planning_prompt
            )
            
            # Extract JSON plan
            json_match = re.search(r'\{.*\}', response, re.DOTALL)
            if json_match:
                plan_data = json.loads(json_match.group())
                tree.reasoning = plan_data.get("reasoning", "")
                
                # Convert plan to attack steps
                for phase_data in plan_data.get("phases", []):
                    phase = AttackPhase(phase_data.get("phase", "recon"))
                    
                    for tool_name in phase_data.get("tools", []):
                        step = AttackStep(
                            phase=phase,
                            tool_name=tool_name,
                            target=target,
                            purpose=phase_data.get("purpose", ""),
                        )
                        tree.steps.append(step)
                
        except Exception as e:
            logger.warning(f"AI planning failed: {e}, using default strategy")
            tree = self._default_attack_tree(target, objective)
        
        return tree
    
    def _default_attack_tree(self, target: str, objective: str) -> AttackTree:
        """Fallback default strategy when AI fails."""
        tree = AttackTree(
            target=target,
            objective=objective,
            reasoning="Default reconnaissance-to-exploitation pipeline"
        )
        
        # Standard web pentest flow
        default_steps = [
            AttackStep(AttackPhase.RECONNAISSANCE, "subfinder", target, "Discover subdomains"),
            AttackStep(AttackPhase.RECONNAISSANCE, "naabu", target, "Port scan discovered hosts"),
            AttackStep(AttackPhase.SCANNING, "httpx", target, "Probe live web services"),
            AttackStep(AttackPhase.ENUMERATION, "trufflehog", target, "Find secrets in code"),
            AttackStep(AttackPhase.ENUMERATION, "ffuf", target, "Discover hidden directories"),
            AttackStep(AttackPhase.EXPLOITATION, "nuclei", target, "Scan for CVEs and misconfigurations"),
            AttackStep(AttackPhase.EXPLOITATION, "dalfox", target, "Test for XSS vulnerabilities"),
            AttackStep(AttackPhase.ENUMERATION, "arjun", target, "Discover hidden parameters"),
        ]
        
        tree.steps = default_steps
        return tree
    
    def select_next_tool(
        self, 
        tree: AttackTree, 
        previous_results: List[ToolResult]
    ) -> Optional[str]:
        """
        Intelligent tool selection based on current state and findings.
        """
        # Check for high-impact findings that warrant immediate action
        for result in previous_results:
            if not result.success:
                continue
            
            for finding in result.findings:
                severity = finding.get("severity", "info")
                finding_type = finding.get("type", "")
                
                # Critical secrets found - prioritize exploitation
                if finding_type == "secret" and severity in ["critical", "high"]:
                    return "trufflehog"  # Deep scan for more secrets
                
                # Open database ports - test for misconfigurations
                if finding_type == "open_port" and finding.get("port") in [3306, 5432, 6379, 27017]:
                    return "nuclei"  # Scan for exposed databases
                
                # Live web services - fuzz for endpoints
                if finding_type == "open_port" and finding.get("port") in [80, 443, 8080, 3000]:
                    return "ffuf"
                
                # XSS found - verify and expand testing
                if finding_type == "xss":
                    return "dalfox"
        
        # Continue with planned sequence
        for step in tree.steps:
            if not step.completed:
                return step.tool_name
        
        return None
    
    def adapt_strategy(
        self, 
        tree: AttackTree, 
        new_finding: Dict[str, Any]
    ) -> List[AttackStep]:
        """
        Dynamically add steps based on new findings.
        """
        additional_steps = []
        finding_type = new_finding.get("type", "")
        
        if finding_type == "api_endpoint":
            # Add API-specific testing
            additional_steps.append(AttackStep(
                phase=AttackPhase.ENUMERATION,
                tool_name="arjun",
                target=new_finding.get("url", tree.target),
                purpose="Discover API parameters",
                depends_on=[]
            ))
        
        elif finding_type == "subdomain":
            subdomain = new_finding.get("subdomain", "")
            if subdomain:
                additional_steps.append(AttackStep(
                    phase=AttackPhase.SCANNING,
                    tool_name="httpx",
                    target=subdomain,
                    purpose=f"Probe new subdomain: {subdomain}",
                    depends_on=["subfinder"]
                ))
        
        elif finding_type == "hidden_parameter":
            additional_steps.append(AttackStep(
                phase=AttackPhase.EXPLOITATION,
                tool_name="dalfox",
                target=new_finding.get("url", tree.target),
                purpose="Test discovered parameters for XSS",
                depends_on=["arjun"]
            ))
        
        # Add new steps to tree
        tree.steps.extend(additional_steps)
        return additional_steps


class ChainOfThoughtLogger:
    """Logs agent reasoning for audit and debugging."""
    
    def __init__(self, log_dir: Path = None):
        self.log_dir = log_dir or Path("data/cot_logs")
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.current_session: List[AgentThought] = []
    
    def log(
        self,
        step: int,
        context: str,
        reasoning: str,
        action: str,
        result: str,
        confidence: float = 0.0
    ) -> None:
        """Log a single thought step."""
        thought = AgentThought(
            step=step,
            timestamp=time.time(),
            context=context,
            reasoning=reasoning,
            action_taken=action,
            result=result,
            confidence=confidence
        )
        self.current_session.append(thought)
    
    def save_session(self, target: str) -> Path:
        """Save session to file."""
        filename = f"cot_{target.replace('/', '_').replace('.', '_')}_{int(time.time())}.json"
        filepath = self.log_dir / filename
        
        session_data = {
            "target": target,
            "timestamp": time.time(),
            "thoughts": [
                {
                    "step": t.step,
                    "timestamp": t.timestamp,
                    "context": t.context,
                    "reasoning": t.reasoning,
                    "action": t.action_taken,
                    "result": t.result,
                    "confidence": t.confidence
                }
                for t in self.current_session
            ]
        }
        
        filepath.write_text(json.dumps(session_data, indent=2))
        logger.info(f"CoT session saved: {filepath}")
        return filepath
    
    def get_summary(self) -> str:
        """Get human-readable summary of reasoning."""
        lines = ["## Chain of Thought Summary\n"]
        
        for thought in self.current_session:
            lines.append(f"**Step {thought.step}** ({thought.confidence:.0%} confidence)")
            lines.append(f"- Context: {thought.context[:100]}...")
            lines.append(f"- Reasoning: {thought.reasoning[:150]}...")
            lines.append(f"- Action: {thought.action_taken}")
            lines.append(f"- Result: {thought.result[:100]}...\n")
        
        return "\n".join(lines)


class ElengenixAgent:
    """
    Relentless Security Research Agent v3.0.
    Features strategic planning, chain of thought logging, and adaptive tool selection.
    """
    
    # 🔒 GLOBAL SECURITY ALLOWLIST (Fixed Binaries Only)
    ALLOWED_TOOLS = {
        "subfinder", "httpx", "nuclei", "katana", 
        "waybackurls", "curl", "nmap", "ffuf", "gau",
        "grep", "cat", "ls", "echo", "whois", "dig",
        "dalfox", "arjun", "naabu", "trufflehog"
    }

    def __init__(
        self,
        max_steps: int = 25,
        loop_threshold: int = 3,
        history_limit: int = 5,
        max_output_len: int = 2000,
        enable_planning: bool = True,
        enable_cot_logging: bool = True
    ):
        self.client = LLMClient()
        self.max_steps = max_steps
        self.loop_threshold = loop_threshold
        self.history_limit = history_limit
        self.max_output_len = max_output_len
        self.enable_planning = enable_planning
        self.enable_cot_logging = enable_cot_logging
        
        # 📍 Absolute Path Resolution for Prompts
        self.base_dir = Path(__file__).parent.absolute()
        prompt_path = self.base_dir / "prompts" / "system_prompt.txt"
        
        if not prompt_path.exists():
            self.base_prompt = "You are a specialized security AI agent."
        else:
            self.base_prompt = prompt_path.read_text(encoding="utf-8")
        
        # 🧠 Strategic Planning
        self.planner = StrategicPlanner(self.client) if enable_planning else None
        self.current_tree: Optional[AttackTree] = None
        
        # 📝 Chain of Thought Logging
        self.cot_logger = ChainOfThoughtLogger() if enable_cot_logging else None
        
        # � Live Activity Display
        self.activity_logger = get_activity_logger()
        
        # 🛡️ CVSS Calculator
        self.cvss_calc = CVSSCalculator(use_ai=True)
        
        # 📚 CVE Database
        self.cve_db = get_cve_database(auto_update=False)
        
        # 📖 System Prompt Enhancement with CVE context
        self._enhance_prompt_with_cve_context()

    def _enhance_prompt_with_cve_context(self):
        """Enhance system prompt with CVE database capabilities."""
        cve_context = """
You have access to a local CVE (Common Vulnerabilities and Exposures) database with the following capabilities:

1. CVE Search: You can search for specific CVEs by ID (e.g., CVE-2021-44228)
2. Vulnerability Lookup: Find historical vulnerabilities by type (XSS, SQLi, RCE, etc.)
3. CVSS Comparison: Compare findings against known CVEs with similar CVSS scores
4. Exploit Availability: Check if public exploits exist for specific CVEs
5. CWE Categories: Use CWE (Common Weakness Enumeration) to categorize findings

When analyzing vulnerabilities:
- Compare findings against similar CVEs in the database
- Reference CVSS scores from historical data
- Identify if the vulnerability type is well-documented
- Check for existing exploits or proof-of-concepts
- Use CWE categories to properly classify the weakness

To use the CVE database, reference vulnerability types and ask for similar CVEs.
"""
        self.base_prompt = f"{self.base_prompt}\n\n{cve_context}"

    def _extract_json(self, text: str) -> Optional[Dict[str, Any]]:
        """🛠️ Extract JSON from LLM response, supporting Markdown and raw blocks."""
        json_match = re.search(r'```(?:json)?\s*([\s\S]*?)\s*```|({[\s\S]*})', text)
        if not json_match:
            return None
        
        json_str = json_match.group(1) or json_match.group(2)
        try:
            return json.loads(json_str)
        except json.JSONDecodeError:
            return None

    def _execute_tool(self, action_data: Dict[str, Any], callback: Optional[Callable] = None) -> str:
        """
        🔒 ENTERPRISE SECURITY: 
        Execute commands using list-based arguments without shell=True.
        """
        action = action_data.get("action", "").lower()
        cmd_raw = action_data.get("command", "")

        # 1. Action Validation
        if action == "finish": return "__FINISH__"
        if action == "save_memory":
            save_learning(action_data.get("target", "global"), action_data.get("learning", ""), action_data.get("category", "general"))
            return "Finding recorded in SQLite memory."
        
        if action != "run_shell":
            return f"Error: Unknown action '{action}'."

        # 2. Binary Validation (Whitelist)
        try:
            parts = shlex.split(cmd_raw)
            if not parts: return "Error: Empty command."
            
            binary = os.path.basename(parts[0])
            if binary not in self.ALLOWED_TOOLS:
                return f"Error: Tool '{binary}' is not in the security allowlist."
            
            # 3. Injection Prevention (Metacharacter block)
            forbidden = ["|", "&", ";", "`", "$(", ">", "<", "\\"]
            if any(char in cmd_raw for char in forbidden):
                return "Error: Command contains prohibited characters (redirection/piping)."

            if callback: callback(f"Executing: {cmd_raw}")

            # 4. Safe Execution
            result = subprocess.run(
                parts,
                shell=False,
                capture_output=True,
                text=True,
                timeout=180
            )
            return (result.stdout + result.stderr)[:self.max_output_len]

        except subprocess.TimeoutExpired:
            return "Error: Command timed out after 180 seconds."
        except Exception as e:
            return f"Error executing tool: {str(e)}"

    def _execute_tool_registry(
        self, 
        tool_name: str, 
        target: str,
        report_dir: Path,
        semaphore: asyncio.Semaphore = None
    ) -> ToolResult:
        """
        Execute tool via Tool Registry (modern approach).
        Fallback to subprocess if registry fails.
        """
        import asyncio
        
        if semaphore is None:
            semaphore = asyncio.Semaphore(5)
        
        tool = registry.get_tool(tool_name)
        if tool and tool.is_available:
            try:
                # Run async tool execution
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                result = loop.run_until_complete(
                    tool.execute(target, report_dir, semaphore)
                )
                loop.close()
                return result
            except Exception as e:
                logger.warning(f"Tool registry execution failed: {e}")
        
        # Fallback to subprocess
        return self._execute_tool_subprocess(tool_name, target)
    
    def _execute_tool_subprocess(self, tool_name: str, target: str) -> ToolResult:
        """Fallback subprocess execution."""
        from tools.tool_registry import ToolResult, ToolCategory
        
        # Map tool names to basic commands
        commands = {
            "subfinder": ["subfinder", "-d", target, "-silent"],
            "httpx": ["httpx", "-u", target, "-silent"],
            "nuclei": ["nuclei", "-u", target, "-silent", "-severity", "critical,high,medium"],
        }
        
        cmd = commands.get(tool_name, [tool_name, target])
        
        try:
            result = subprocess.run(
                cmd,
                shell=False,
                capture_output=True,
                text=True,
                timeout=180
            )
            
            return ToolResult(
                success=result.returncode == 0,
                tool_name=tool_name,
                category=ToolCategory.RECON,  # Default
                output=result.stdout + result.stderr,
            )
        except Exception as e:
            return ToolResult(
                success=False,
                tool_name=tool_name,
                category=ToolCategory.RECON,
                error_message=str(e),
            )

    def process_query(
        self, 
        user_input: str, 
        callback: Optional[Callable] = None, 
        target: str = ""
    ) -> str:
        """
        Process a single mission with strategic planning and tool registry.
        
        Features:
        - Strategic attack tree generation
        - Intelligent tool selection via registry
        - Chain of thought logging
        - CVSS scoring integration
        """
        import asyncio
        
        send_telegram_notification(f"🎯 Mission Started: \"{user_input}\"")
        logger.info(f"Starting mission: {user_input}")
        
        # 💾 REMEMBER: Store this mission start in vector memory
        mission_id = remember(
            f"Started mission: {user_input}. Target: {target or 'general'}",
            target or "global",
            "mission_start",
            session_type="ai_chat"
        )
        
        # 🧠 STRATEGIC PLANNING PHASE
        if self.enable_planning and target:
            self.current_tree = self.planner.generate_attack_tree(
                target, 
                objective=user_input
            )
            if callback:
                callback(f"Strategy: {self.current_tree.reasoning[:100]}...")
            logger.info(f"Attack tree generated: {len(self.current_tree.steps)} steps")
            
            # 📺 Log to activity display
            self.activity_logger.log_thought(f"Strategy: {self.current_tree.reasoning[:80]}...", step=0)
            display_in_chat_mode(f"Planning: {len(self.current_tree.steps)} steps ahead", "thought")
            
            # 💾 REMEMBER: Store the strategy
            remember(
                f"Strategy planned: {self.current_tree.reasoning}",
                target,
                "strategy",
                step_count=len(self.current_tree.steps)
            )
        
        # Setup report directory
        report_dir = Path("reports") / f"agent_{target.replace('.', '_')}_{int(time.time())}"
        report_dir.mkdir(parents=True, exist_ok=True)
        
        # 🔄 Reset mission state
        action_history = []
        history = [{"role": "user", "content": user_input}]
        previous_results: List[ToolResult] = []
        all_findings: List[Dict] = []
        
        for step in range(self.max_steps):
            # Determine next action
            if self.current_tree and step < len(self.current_tree.steps):
                # Follow strategic plan
                current_step = self.current_tree.steps[step]
                tool_name = current_step.tool_name
                action_data = {
                    "action": "run_shell",
                    "command": f"{tool_name} {target}",
                    "tool": tool_name,
                    "purpose": current_step.purpose,
                }
                reasoning = f"Strategic plan: {current_step.purpose}"
            else:
                # 🧠 AI-driven dynamic planning with SEMANTIC MEMORY
                
                # ดึง context จาก Vector Memory (จำได้ทุก session)
                semantic_context = get_context_for_ai(
                    current_query=user_input,
                    target=target or "global",
                    max_memories=15
                )
                
                # Recent conversation history (session only)
                recent_history = history[-self.history_limit:]
                history_text = "\n".join([f"{m['role'].capitalize()}: {m['content']}" for m in recent_history])
                
                # Available tools context
                available_tools = registry.list_available_tools()
                tool_list = ", ".join([
                    name for name, info in available_tools.items() 
                    if info["available"]
                ])
                
                # 🧠 SEMANTIC SEARCH: หา memories ที่คล้ายกับปัญหาปัจจุบัน
                related_memories = recall(
                    query=user_input,
                    target=target,
                    n_results=5
                )
                
                related_context = ""
                if related_memories:
                    related_context = "\n### SEMANTICALLY RELATED PAST MEMORIES:\n"
                    for mem in related_memories:
                        content = mem['content'][:100]
                        sim = mem.get('similarity', 0)
                        related_context += f"- {content}... (relevance: {sim:.0%})\n"
                
                full_prompt = f"""{self.base_prompt}

### AVAILABLE TOOLS:
{tool_list}

{semantic_context}
{related_context}

### CHAT HISTORY (Current Session):
{history_text}

### PREVIOUS RESULTS (Current Mission):
{self._summarize_results(previous_results)}

Plan your next move. Consider:
1. What do we know from previous sessions about this target?
2. Which tool from the registry would be most effective now?
3. Are there high-impact findings that need immediate follow-up?
4. Have we covered reconnaissance, scanning, and exploitation?

Use JSON format: {{"action": "run_shell|save_memory|finish", "command": "...", "tool": "...", "purpose": "..."}}"""

                response_text = self.client.chat(full_prompt, "Plan next action")
                action_data = self._extract_json(response_text) or {}
                reasoning = f"AI decision: {action_data.get('purpose', 'continue investigation')}"
            
            # 📝 Chain of Thought Logging
            if self.cot_logger:
                self.cot_logger.log(
                    step=step,
                    context=user_input,
                    reasoning=reasoning,
                    action=str(action_data),
                    result="",
                    confidence=0.8 if self.current_tree else 0.6
                )
            
            # Action Validation
            action = action_data.get("action", "").lower()
            
            if action == "finish":
                summary = action_data.get("summary", "Mission completed")
                
                # Calculate CVSS for findings
                cvss_results = []
                for finding in all_findings:
                    score = self.cvss_calc.from_finding(
                        finding.get("type", "unknown"),
                        finding.get("url", target),
                        finding.get("evidence", str(finding))
                    )
                    
                    # 📚 CVE Lookup: Find similar historical vulnerabilities
                    finding_type = finding.get("type", "unknown")
                    similar_cves = self.cve_db.find_similar_vulns(
                        finding_type=finding_type,
                        cvss_range=(max(0, score.base_score - 1.0), min(10, score.base_score + 1.0))
                    )
                    
                    cvss_results.append({
                        "finding": finding,
                        "cvss": score,
                        "similar_cves": similar_cves
                    })
                
                # 💾 REMEMBER: Store mission completion
                critical_count = len([c for c in cvss_results if c['cvss'].severity.value == 'Critical'])
                high_count = len([c for c in cvss_results if c['cvss'].severity.value == 'High'])
                
                remember(
                    f"Mission completed: {user_input}. "
                    f"Total findings: {len(all_findings)}. "
                    f"Critical: {critical_count}, High: {high_count}. "
                    f"Summary: {summary[:200]}",
                    target or "global",
                    "mission_complete",
                    total_findings=len(all_findings),
                    critical=critical_count,
                    high=high_count,
                    steps_taken=step
                )
                
                # 💾 REMEMBER: Store key findings for quick recall
                for cvss_item in cvss_results[:5]:  # Top 5 most severe
                    finding = cvss_item['finding']
                    score = cvss_item['cvss']
                    if score.severity.value in ['Critical', 'High']:
                        remember(
                            f"CRITICAL FINDING: {finding.get('type', 'unknown')} "
                            f"at {finding.get('url', target)} "
                            f"- CVSS {score.base_score} ({score.severity.value})",
                            target or "global",
                            "critical_finding",
                            cvss_score=score.base_score,
                            severity=score.severity.value
                        )
                
                # Save CoT log
                if self.cot_logger:
                    cot_file = self.cot_logger.save_session(target or user_input)
                    summary += f"\n\n📊 Chain of Thought: {cot_file}"
                
                # Generate findings report with CVE references
                if cvss_results:
                    summary += f"\n\n🎯 CRITICAL FINDINGS: {critical_count}"
                    summary += f"\n🔴 HIGH: {high_count}"
                    
                    # Add CVE references for top findings
                    summary += "\n\n📚 SIMILAR HISTORICAL VULNERABILITIES:"
                    for cvss_item in cvss_results[:3]:  # Top 3
                        finding = cvss_item['finding']
                        similar_cves = cvss_item.get('similar_cves', [])
                        if similar_cves:
                            finding_type = finding.get('type', 'unknown')
                            summary += f"\n  • {finding_type.upper()}:"
                            for cve in similar_cves[:3]:  # Top 3 similar CVEs
                                summary += f"\n    - {cve.cve_id} (CVSS: {cve.cvss_score})"
                                if cve.exploit_available:
                                    summary += " [EXPLOIT AVAILABLE]"
                
                send_telegram_notification(f"🏁 Mission Accomplished: {user_input}")
                return summary
            
            if action == "save_memory":
                save_learning(
                    action_data.get("target", "global"),
                    action_data.get("learning", ""),
                    action_data.get("category", "general")
                )
                history.append({"role": "assistant", "content": str(action_data)})
                history.append({"role": "user", "content": "Learning saved."})
                continue
            
            # 🛡️ Loop & Deadlock Protection
            action_sig = f"{action}:{action_data.get('command', '')}"
            action_history.append(action_sig)
            
            if Counter(action_history)[action_sig] > self.loop_threshold:
                msg = f"⚠️ DEADLOCK DETECTED: Agent is repeating '{action_sig}'. Terminating."
                send_telegram_notification(msg)
                logger.warning(msg)
                return msg
            
            # 🔧 EXECUTION via Tool Registry
            tool_name = action_data.get("tool", "")
            if tool_name:
                purpose = action_data.get('purpose', '')
                if callback:
                    callback(f"Running: {tool_name} - {purpose}")
                
                # 📺 Log activity
                self.activity_logger.log_action(f"Running {tool_name}", tool=tool_name, target=target, step=step)
                display_in_chat_mode(f"[{tool_name}] {purpose}", "action")
                
                result = self._execute_tool_registry(
                    tool_name, 
                    target or user_input,
                    report_dir
                )
                
                # 📺 Log result
                status = "success" if result.success else "error"
                self.activity_logger.log_result(f"{tool_name}: {len(result.findings)} findings", result.success, step=step)
                if result.success:
                    display_in_chat_mode(f"{tool_name}: {len(result.findings)} findings", "result")
                else:
                    display_in_chat_mode(f"{tool_name} failed: {result.error_message}", "error")
                
                previous_results.append(result)
                all_findings.extend(result.findings)
                
                # 💾 REMEMBER: Store tool result in vector memory
                remember(
                    f"Tool {tool_name} executed on {target}: {len(result.findings)} findings. "
                    f"Success: {result.success}. Category: {result.category.value}",
                    target or "global",
                    "tool_result",
                    tool=tool_name,
                    findings_count=len(result.findings),
                    success=result.success
                )
                
                # 💾 REMEMBER: Store each finding as separate memory
                for finding in result.findings:
                    finding_desc = f"Finding from {tool_name}: {finding.get('type', 'unknown')} "
                    finding_desc += f"at {finding.get('url', target)} "
                    finding_desc += f"(severity: {finding.get('severity', 'unknown')})"
                    
                    remember(
                        finding_desc,
                        target or "global",
                        "finding",
                        tool=tool_name,
                        severity=finding.get('severity', 'unknown'),
                        finding_type=finding.get('type', 'unknown'),
                        url=finding.get('url', '')
                    )
                
                # Mark step as completed in attack tree
                if self.current_tree and step < len(self.current_tree.steps):
                    self.current_tree.steps[step].completed = True
                    self.current_tree.steps[step].result = result
                    self.current_tree.steps[step].findings = result.findings
                
                # 🔄 ADAPTIVE STRATEGY
                if self.planner and result.findings:
                    for finding in result.findings:
                        new_steps = self.planner.adapt_strategy(self.current_tree, finding)
                        if new_steps and callback:
                            callback(f"🔄 Adapted strategy: +{len(new_steps)} new steps")
                            
                            # 💾 REMEMBER: Strategy adaptation
                            remember(
                                f"Strategy adapted based on finding: {finding.get('type', 'unknown')}. "
                                f"Added {len(new_steps)} new steps.",
                                target or "global",
                                "strategy_adaptation",
                                trigger_finding=finding.get('type', 'unknown')
                            )
                
                obs = f"Tool {tool_name}: {len(result.findings)} findings, success={result.success}"
                
                if self.cot_logger:
                    self.cot_logger.current_session[-1].result = obs
            else:
                # Fallback to legacy execution
                obs = self._execute_tool(action_data, callback)
            
            if obs == "__FINISH__":
                send_telegram_notification(f"🏁 Mission Accomplished: {user_input}")
                return action_data.get("summary", "Mission completed successfully.")
            
            # Feedback Loop
            history.append({"role": "assistant", "content": str(action_data)})
            history.append({"role": "user", "content": f"OBSERVATION: {obs}"})
        
        # Save CoT log on completion
        if self.cot_logger:
            self.cot_logger.save_session(target or user_input)
        
        return f"Task halted after {self.max_steps} steps. Findings: {len(all_findings)}"
    
    def _summarize_results(self, results: List[ToolResult]) -> str:
        """Summarize previous tool results for context."""
        if not results:
            return "No previous results."
        
        lines = []
        for r in results[-3:]:  # Last 3 results
            lines.append(f"- {r.tool_name}: {len(r.findings)} findings")
        
        return "\n".join(lines)
    
    def process_universal(
        self,
        user_input: str,
        callback: Optional[Callable] = None,
        target: str = "",
        mode: str = "auto"  # "auto", "bug_bounty", "general"
    ) -> str:
        """
        UNIVERSAL AGENT MODE — Flexible like Claude Code / Gemini CLI / OpenClaw
        but specialized for Bug Bounty when needed.
        
        Features:
        - File editing (read, write, edit, search)
        - Package installation (pip, npm, apt, go, gem)
        - Shell execution with safety
        - Web research
        - Multi-turn conversation with persistent context
        - Bug bounty specialization when target provided
        """
        import json
        
        send_telegram_notification(f"🤖 Universal Agent: \"{user_input}\"")
        logger.info(f"Universal mode started: {user_input}")
        
        # Initialize universal executor
        executor = get_universal_executor()
        
        # 💾 Remember this session start
        remember(
            f"Universal session: {user_input}. Mode: {mode}",
            target or "universal",
            "universal_session",
            session_type="universal"
        )
        
        # Determine if this is a bug bounty task
        is_security_task = mode == "bug_bounty" or (target and any(
            kw in user_input.lower() for kw in [
                "scan", "vulnerability", "exploit", "pentest", "security",
                "find", "bug", "bounty", "hack", "test"
            ]
        ))
        
        # Build system prompt based on mode
        if is_security_task and target:
            base_prompt = f"""{self.base_prompt}

### UNIVERSAL AGENT MODE — BUG BOUNTY SPECIALIST
You are now in Universal Agent mode with full system access.
Your primary mission: Find vulnerabilities on {target}

### CAPABILITIES:
1. **File Operations**: Read, write, edit any file in the project
2. **Package Management**: Install tools via pip, npm, apt, go install
3. **Shell Execution**: Run commands (security filtered)
4. **Web Research**: Search for CVEs, exploits, techniques
5. **Strategic Planning**: Create and adapt attack plans

### WORKFLOW:
1. First, explore the target environment
2. Install necessary tools if missing
3. Create custom scripts for specific attacks
4. Execute reconnaissance and scanning
5. Analyze findings and chain vulnerabilities
6. Generate comprehensive reports

### RESPONSE FORMAT:
Always respond with structured JSON:
{{
    "thought": "Your reasoning step-by-step",
    "action": {{
        "type": "read_file|write_file|edit_file|search_file|list_dir|shell|package|search_web|run_tool|finish",
        "params": {{...}}
    }},
    "next_step": "What you plan to do next"
}}

### CURRENT CONTEXT:
Target: {target}
Mode: Bug Bounty Specialist
Available Tools: {', '.join(name for name, info in registry.list_available_tools().items() if info['available'])}
"""
        else:
            base_prompt = f"""{self.base_prompt}

### UNIVERSAL AGENT MODE — GENERAL PURPOSE
You are a flexible AI agent that can help with any task.

### CAPABILITIES:
1. **File Operations**: Read, write, edit files
2. **Package Management**: pip install, npm install, apt install, etc.
3. **Shell Commands**: Execute safe commands
4. **Web Research**: Search internet
5. **Bug Bounty Tools**: Use when security task detected

### RESPONSE FORMAT:
{{
    "thought": "Your reasoning",
    "action": {{
        "type": "read_file|write_file|edit_file|shell|package|search_web|finish",
        "params": {{...}}
    }},
    "next_step": "Planned next action"
}}
"""
        
        # Get semantic context from memory
        semantic_context = ""
        if target:
            semantic_context = get_context_for_ai(user_input, target, max_memories=10)
        
        # Execution loop
        history = []
        step = 0
        max_universal_steps = 50  # More steps for complex tasks
        
        while step < max_universal_steps:
            step += 1
            
            # Build conversation context
            recent_history = "\n".join([
                f"Step {i+1}: {h['action']}\nResult: {h['result'][:200]}..."
                for i, h in enumerate(history[-5:])
            ])
            
            full_prompt = f"""{base_prompt}

{semantic_context}

### CONVERSATION HISTORY:
{recent_history}

### USER REQUEST:
{user_input}

### CURRENT STEP: {step}

Analyze the request and determine the next action.
If this is a complex multi-step task, break it down.
If you need to install tools, use package action.
If you need to create scripts, use write_file.
If the task is complete, use finish action.

Respond ONLY with valid JSON."""
            
            # Get AI decision
            response = self.client.chat(full_prompt, f"Universal step {step}")
            
            try:
                # Extract JSON action
                json_match = re.search(r'\{.*\}', response, re.DOTALL)
                if json_match:
                    action_data = json.loads(json_match.group())
                else:
                    action_data = {"action": {"type": "finish", "params": {}}, "thought": response}
                
                action = action_data.get("action", {})
                action_type = action.get("type", "finish")
                params = action.get("params", {})
                thought = action_data.get("thought", "No reasoning provided")
                
                # Log thought
                logger.info(f"Step {step}: {thought[:100]}...")
                if callback:
                    callback(f"🧠 Step {step}: {thought[:80]}...")
                
                # 💾 Remember the thought
                remember(
                    f"Step {step}: {thought}",
                    target or "universal",
                    "reasoning",
                    step=step,
                    action_type=action_type
                )
                
            except json.JSONDecodeError:
                # If not valid JSON, treat as direct response
                if callback:
                    callback(f"💬 {response[:200]}")
                return response
            
            # Execute action
            if action_type == "finish":
                summary = params.get("summary", "Task completed")
                logger.info(f"Universal session finished: {summary}")
                send_telegram_notification(f"✅ Universal Agent Complete: {summary[:100]}")
                return summary
            
            # Execute via universal executor
            result = executor.execute_action({"type": action_type, "params": params})
            
            # Store in history
            history.append({
                "step": step,
                "action": f"{action_type}: {json.dumps(params)[:100]}",
                "result": result.output if result.success else result.error,
                "success": result.success
            })
            
            # Callback
            if callback:
                status = "✅" if result.success else "❌"
                output_preview = (result.output if result.success else result.error)[:150]
                callback(f"{status} {action_type}: {output_preview}...")
            
            # 💾 Remember important results
            if result.success and action_type in ["shell", "run_tool", "search_web"]:
                remember(
                    f"Action {action_type} result: {result.output[:200]}",
                    target or "universal",
                    "action_result",
                    action=action_type,
                    step=step
                )
            
            # Check for findings in security mode
            if is_security_task and result.metadata.get("findings"):
                for finding in result.metadata.get("findings", []):
                    remember(
                        f"Finding: {finding.get('type', 'unknown')} at {finding.get('url', target)}",
                        target,
                        "finding",
                        severity=finding.get("severity", "unknown"),
                        step=step
                    )
        
        # Max steps reached
        return f"Universal session reached {max_universal_steps} steps. History: {len(history)} actions."
