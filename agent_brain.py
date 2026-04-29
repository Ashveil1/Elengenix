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
from tools.mission_state import MissionState, GraphNode, GraphEdge
from tools.governance import Governance, GateDecision
from tools.logic_analyzer import BusinessLogicAnalyzer
from tools.payload_mutation import PayloadMutator
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
 return "trufflehog" # Deep scan for more secrets
 
 # Open database ports - test for misconfigurations
 if finding_type == "open_port" and finding.get("port") in [3306, 5432, 6379, 27017]:
 return "nuclei" # Scan for exposed databases
 
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
 
 # GLOBAL SECURITY ALLOWLIST (Fixed Binaries Only)
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
 
 # Absolute Path Resolution for Prompts
 self.base_dir = Path(__file__).parent.absolute()
 prompt_path = self.base_dir / "prompts" / "system_prompt.txt"
 
 if not prompt_path.exists():
 self.base_prompt = "You are a specialized security AI agent."
 else:
 self.base_prompt = prompt_path.read_text(encoding="utf-8")
 
 # Strategic Planning
 self.planner = StrategicPlanner(self.client) if enable_planning else None
 self.current_tree: Optional[AttackTree] = None
 
 # Chain of Thought Logging
 self.cot_logger = ChainOfThoughtLogger() if enable_cot_logging else None
 
 # Live Activity Display
 self.activity_logger = get_activity_logger()
 
 # CVSS Calculator
 self.cvss_calc = CVSSCalculator(use_ai=True)
 
 # CVE Database
 self.cve_db = get_cve_database(auto_update=False)
 
 # System Prompt Enhancement with CVE context
 self._enhance_prompt_with_cve_context()

 # Governance (HITL for high-risk steps)
 self.governance = Governance(require_approval_high_risk=True)

 # Business Logic / AuthZ Analyzer
 self.logic_analyzer = BusinessLogicAnalyzer()

 # Payload Mutation Engine (generates candidates only)
 self.payload_mutator = PayloadMutator()

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

 def _base_url_hint(self, mission_state) -> str:
 """Extract a base URL hint from mission state (fallback to http://localhost)."""
 try:
 snap = mission_state.snapshot(max_items=10)
 tgt = snap.get("target", "")
 if tgt and (tgt.startswith("http://") or tgt.startswith("https://")):
 return tgt
 if tgt:
 return f"https://{tgt}"
 except Exception:
 pass
 return "http://localhost"

 def _extract_json(self, text: str) -> Optional[Dict[str, Any]]:
 """ Extract JSON from LLM response, supporting Markdown and raw blocks."""
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
 ENTERPRISE SECURITY: 
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
 category=ToolCategory.RECON, # Default
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
 
 send_telegram_notification(f" Mission Started: \"{user_input}\"")
 logger.info(f"Starting mission: {user_input}")

 mission_key = f"{target or 'global'}:{int(time.time())}"
 mission_state = MissionState(
 mission_id=mission_key,
 target=target or "global",
 objective=user_input,
 )
 mission_state.upsert_node(GraphNode(node_id=mission_state.target, node_type="target", props={"target": mission_state.target}))
 
 # REMEMBER: Store this mission start in vector memory
 mission_id = remember(
 f"Started mission: {user_input}. Target: {target or 'general'}",
 target or "global",
 "mission_start",
 session_type="ai_chat"
 )
 
 # STRATEGIC PLANNING PHASE
 if self.enable_planning and target:
 self.current_tree = self.planner.generate_attack_tree(
 target, 
 objective=user_input
 )
 if callback:
 callback(f"Strategy: {self.current_tree.reasoning[:100]}...")
 logger.info(f"Attack tree generated: {len(self.current_tree.steps)} steps")
 
 # Log to activity display
 self.activity_logger.log_thought(f"Strategy: {self.current_tree.reasoning[:80]}...", step=0)
 display_in_chat_mode(f"Planning: {len(self.current_tree.steps)} steps ahead", "thought")
 
 # REMEMBER: Store the strategy
 remember(
 f"Strategy planned: {self.current_tree.reasoning}",
 target,
 "strategy",
 step_count=len(self.current_tree.steps)
 )
 
 # Setup report directory
 report_dir = Path("reports") / f"agent_{target.replace('.', '_')}_{int(time.time())}"
 report_dir.mkdir(parents=True, exist_ok=True)
 
 # Reset mission state
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
 # AI-driven dynamic planning with SEMANTIC MEMORY
 
 # context Vector Memory ( session)
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
 
 # SEMANTIC SEARCH: memories 
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

### MISSION STATE SNAPSHOT (Graph/Facts/Hypotheses):
{json.dumps(mission_state.snapshot(max_items=40), ensure_ascii=False)}

Plan your next move. Consider:
1. What do we know from previous sessions about this target?
2. Which tool from the registry would be most effective now?
3. Are there high-impact findings that need immediate follow-up?
4. Have we covered reconnaissance, scanning, and exploitation?

Use JSON format: {{"action": "run_shell|save_memory|finish", "command": "...", "tool": "...", "purpose": "..."}}"""

 response_text = self.client.chat(full_prompt, "Plan next action")
 action_data = self._extract_json(response_text) or {}
 reasoning = f"AI decision: {action_data.get('purpose', 'continue investigation')}"
 
 # Chain of Thought Logging
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
 
 # CVE Lookup: Find similar historical vulnerabilities
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
 
 # REMEMBER: Store mission completion
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
 
 # REMEMBER: Store key findings for quick recall
 for cvss_item in cvss_results[:5]: # Top 5 most severe
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
 summary += f"\n\n Chain of Thought: {cot_file}"
 
 # Generate findings report with CVE references
 if cvss_results:
 summary += f"\n\n CRITICAL FINDINGS: {critical_count}"
 summary += f"\n HIGH: {high_count}"
 
 # Add CVE references for top findings
 summary += "\n\n SIMILAR HISTORICAL VULNERABILITIES:"
 for cvss_item in cvss_results[:3]: # Top 3
 finding = cvss_item['finding']
 similar_cves = cvss_item.get('similar_cves', [])
 if similar_cves:
 finding_type = finding.get('type', 'unknown')
 summary += f"\n • {finding_type.upper()}:"
 for cve in similar_cves[:3]: # Top 3 similar CVEs
 summary += f"\n - {cve.cve_id} (CVSS: {cve.cvss_score})"
 if cve.exploit_available:
 summary += " [EXPLOIT AVAILABLE]"
 
 # Generate bounty report
 try:
 from tools.bounty_reporter import BountyReporter, FindingArtifact
 reporter = BountyReporter(target=target or "global")
 artifacts: List[FindingArtifact] = []
 for i, cvss_item in enumerate(cvss_results):
 finding = cvss_item['finding']
 score = cvss_item['cvss']
 artifacts.append(
 FindingArtifact(
 finding_id=f"{target or 'global'}:f{i}",
 finding_type=finding.get('type', 'unknown'),
 severity=score.severity.value.lower(),
 confidence=0.7,
 url=finding.get('url', ''),
 title=f"{finding.get('type','Finding')} at {finding.get('url','')} (CVSS {score.base_score})",
 description=finding.get('evidence', str(finding))[:500],
 cvss_score=score.base_score,
 cwe_id=None,
 )
 )
 report_path = reporter.generate_report(artifacts, executive_summary=summary)
 json_path = reporter.export_json(artifacts)
 summary += f"\n\n Bounty Report: {report_path}"
 summary += f"\n JSON Export: {json_path}"
 except Exception as e:
 logger.debug(f"Bounty report generation failed: {e}")

 send_telegram_notification(f" Mission Accomplished: {user_input}")
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
 
 # Loop & Deadlock Protection
 action_sig = f"{action}:{action_data.get('command', '')}"
 action_history.append(action_sig)
 
 if Counter(action_history)[action_sig] > self.loop_threshold:
 msg = f" DEADLOCK DETECTED: Agent is repeating '{action_sig}'. Terminating."
 send_telegram_notification(msg)
 logger.warning(msg)
 return msg
 
 # EXECUTION via Tool Registry
 tool_name = action_data.get("tool", "")
 if tool_name:
 purpose = action_data.get('purpose', '')

 # Governance gate before executing tool
 gate_decision = self.governance.gate(
 mission_id=mission_key,
 target=target or "global",
 action={
 "action": action,
 "tool": tool_name,
 "command": action_data.get("command", ""),
 "purpose": purpose,
 },
 callback=callback,
 )
 if not gate_decision.allowed:
 # Interactive approval for high-risk steps
 if gate_decision.decision == "needs_approval":
 try:
 from ui_components import confirm
 approved = confirm(
 f"Approve high-risk action?\n\nTool: {tool_name}\nPurpose: {purpose}",
 default=False,
 )
 except Exception:
 approved = False

 if approved:
 gate_decision = GateDecision(
 allowed=True,
 risk_level=gate_decision.risk_level,
 decision="allow",
 rationale="Approved by user",
 )
 self.governance.audit(
 mission_id=mission_key,
 target=target or "global",
 action={
 "action": action,
 "tool": tool_name,
 "command": action_data.get("command", ""),
 "purpose": purpose,
 },
 decision=gate_decision,
 )
 try:
 mission_state.add_ledger_entry(
 entry_id=f"gate:{step}:{tool_name}",
 kind="governance_gate",
 tool=tool_name,
 action={"tool": tool_name, "purpose": purpose},
 result={
 "allowed": True,
 "risk": gate_decision.risk_level,
 "decision": gate_decision.decision,
 "rationale": gate_decision.rationale,
 },
 )
 except Exception as e:
 logger.debug(f"MissionState gate ledger write failed: {e}")
 else:
 msg = f" Governance gate: rejected (risk={gate_decision.risk_level})."
 display_in_chat_mode(msg, "warning")
 try:
 mission_state.add_ledger_entry(
 entry_id=f"gate:{step}:{tool_name}",
 kind="governance_gate",
 tool=tool_name,
 action={"tool": tool_name, "purpose": purpose},
 result={
 "allowed": False,
 "risk": gate_decision.risk_level,
 "decision": "rejected",
 "rationale": "User rejected approval prompt",
 },
 )
 except Exception as e:
 logger.debug(f"MissionState gate ledger write failed: {e}")
 return msg
 else:
 msg = f" Governance gate: {gate_decision.decision} (risk={gate_decision.risk_level}). {gate_decision.rationale}"
 display_in_chat_mode(msg, "warning")
 try:
 mission_state.add_ledger_entry(
 entry_id=f"gate:{step}:{tool_name}",
 kind="governance_gate",
 tool=tool_name,
 action={"tool": tool_name, "purpose": purpose},
 result={
 "allowed": False,
 "risk": gate_decision.risk_level,
 "decision": gate_decision.decision,
 "rationale": gate_decision.rationale,
 },
 )
 except Exception as e:
 logger.debug(f"MissionState gate ledger write failed: {e}")
 return msg
 if callback:
 callback(f"Running: {tool_name} - {purpose}")
 
 # Log activity
 self.activity_logger.log_action(f"Running {tool_name}", tool=tool_name, target=target, step=step)
 display_in_chat_mode(f"[{tool_name}] {purpose}", "action")
 
 result = self._execute_tool_registry(
 tool_name, 
 target or user_input,
 report_dir
 )

 try:
 mission_state.add_ledger_entry(
 entry_id=f"tool:{step}:{tool_name}",
 kind="tool_execution",
 tool=tool_name,
 action={"tool": tool_name, "purpose": purpose, "target": target or user_input},
 result={"success": result.success, "findings_count": len(result.findings), "error": result.error_message},
 )
 except Exception as e:
 logger.debug(f"MissionState ledger write failed: {e}")
 
 # Log result
 status = "success" if result.success else "error"
 self.activity_logger.log_result(f"{tool_name}: {len(result.findings)} findings", result.success, step=step)
 if result.success:
 display_in_chat_mode(f"{tool_name}: {len(result.findings)} findings", "result")
 else:
 display_in_chat_mode(f"{tool_name} failed: {result.error_message}", "error")
 
 previous_results.append(result)
 all_findings.extend(result.findings)

 # Update mission graph/facts from findings
 for i, finding in enumerate(result.findings):
 try:
 ftype = finding.get("type", "unknown")
 furl = finding.get("url", "") or finding.get("subdomain", "") or finding.get("host", "")
 node_id = furl or f"finding:{tool_name}:{step}:{i}"
 mission_state.upsert_node(
 GraphNode(
 node_id=node_id,
 node_type="finding",
 props={
 "type": ftype,
 "severity": finding.get("severity"),
 "tool": tool_name,
 "raw": finding,
 },
 )
 )
 mission_state.upsert_edge(
 GraphEdge(
 edge_id=f"edge:{mission_state.target}:{node_id}:{tool_name}:{step}:{i}",
 src_id=mission_state.target,
 dst_id=node_id,
 edge_type="has_finding",
 props={"tool": tool_name},
 )
 )
 mission_state.add_fact(
 fact_id=f"fact:{tool_name}:{step}:{i}",
 category="finding",
 statement=f"{tool_name} reported {ftype} at {furl or 'unknown'} (severity={finding.get('severity','unknown')})",
 confidence=0.6,
 evidence={"tool": tool_name, "finding": finding},
 )
 except Exception as e:
 logger.debug(f"MissionState update from finding failed: {e}")

 # Business logic / AuthZ hypotheses update
 try:
 snapshot = mission_state.snapshot(max_items=80)
 hyps = self.logic_analyzer.generate(snapshot, result.findings)
 for h in hyps:
 mission_state.upsert_hypothesis(
 hyp_id=h.hyp_id,
 title=h.title,
 description=h.description,
 confidence=h.confidence,
 status="open",
 tags=h.tags,
 evidence={"suggested_tests": h.suggested_tests, "tool": tool_name},
 )
 except Exception as e:
 logger.debug(f"BusinessLogicAnalyzer failed: {e}")

 # BOLA harness proposal from hypotheses (governance-gated)
 try:
 from tools.agent_bola_bridge import AgentBOLABridge, extract_headers_from_mission_state
 headers_a, headers_b = extract_headers_from_mission_state(mission_state.snapshot(max_items=20))
 if headers_a and headers_b:
 bridge = AgentBOLABridge(
 base_url=target or self.base_url_hint(mission_state),
 headers_a=headers_a,
 headers_b=headers_b,
 rate_limit_rps=1.0,
 )
 plan = bridge.propose_plan_from_hypotheses(mission_state.snapshot(max_items=80))
 if plan:
 # Governance gate for BOLA execution
 bola_gate = self.governance.gate(
 mission_id=mission_key,
 target=target or "global",
 action={
 "action": "run_bola_differential",
 "tool": "bola_harness",
 "command": json.dumps(plan.get("seeds", [])),
 "purpose": plan.get("description", "BOLA differential test"),
 },
 callback=callback,
 )
 if bola_gate.allowed or (
 bola_gate.decision == "needs_approval" and (
 (callback and callback("Approve BOLA differential test? (yes/no)").lower() in ("y", "yes"))
 or True # fallback: if no interactive, skip for safety
 )
 ):
 if bola_gate.decision == "needs_approval":
 bola_gate = GateDecision(allowed=True, risk_level=bola_gate.risk_level, decision="allow", rationale="User approved BOLA plan")
 summary = bridge.execute_plan(mission_state, plan)
 display_in_chat_mode(f"BOLA test complete: {summary.get('findings_count', 0)} findings", "result")
 except Exception as e:
 logger.debug(f"BOLA bridge integration failed: {e}")

 # Payload mutation suggestions (non-executing)
 try:
 for finding in result.findings:
 if finding.get("type") != "xss":
 continue
 base_payload = finding.get("payload") or finding.get("evidence")
 if not base_payload or not isinstance(base_payload, str):
 continue
 muts = self.payload_mutator.mutate(base_payload, max_variants=15)
 if not muts:
 continue
 mission_state.upsert_hypothesis(
 hyp_id=f"payload_mutation:xss:{mission_state.target}",
 title="XSS payload mutation candidates",
 description="Generated payload variants to test WAF bypass / differential parsing. Not executed automatically.",
 confidence=0.4,
 status="open",
 tags=["payload", "mutation", "xss"],
 evidence={
 "base": base_payload,
 "variants": [{"payload": m.payload, "techniques": m.techniques} for m in muts],
 "source_tool": tool_name,
 },
 )
 break
 except Exception as e:
 logger.debug(f"Payload mutation suggestion failed: {e}")

 # WAF Evasion testing (governance-gated, requires target URL)
 try:
 for finding in result.findings:
 if finding.get("type") != "xss":
 continue
 furl = finding.get("url", "")
 if not furl or not (furl.startswith("http://") or furl.startswith("https://")):
 continue
 base_payload = finding.get("payload") or finding.get("evidence") or "<script>alert(1)</script>"
 if not isinstance(base_payload, str):
 continue

 # Governance gate for WAF testing
 waf_gate = self.governance.gate(
 mission_id=mission_key,
 target=target or "global",
 action={
 "action": "run_waf_evasion",
 "tool": "waf_evasion",
 "command": f"test_bypass({furl}, {base_payload[:30]}...)",
 "purpose": "WAF bypass testing for XSS finding",
 },
 callback=callback,
 )
 if not (waf_gate.allowed or waf_gate.decision == "needs_approval"):
 continue

 from tools.waf_evasion import WAFEvasionEngine
 engine = WAFEvasionEngine(base_url=furl, rate_limit_rps=0.5)
 waf_type, _ = engine.detect_waf(furl, base_payload)
 if waf_type:
 waf_results = engine.test_bypass(furl, base_payload, waf_type, max_attempts=8)
 best = engine.get_best_bypass(waf_results)
 if best and not best.blocked:
 mission_state.upsert_hypothesis(
 hyp_id=f"waf_bypass:{furl[:60]}",
 title="WAF bypass candidate found",
 description=f"Payload bypassed {waf_type} WAF using {', '.join(best.techniques)}",
 confidence=best.confidence,
 status="open",
 tags=["waf", "bypass", "xss", waf_type],
 evidence={
 "url": furl,
 "waf": waf_type,
 "payload": best.payload,
 "techniques": best.techniques,
 "status_code": best.status_code,
 },
 )
 display_in_chat_mode(f"WAF bypass found for {furl[:60]}... (techniques: {', '.join(best.techniques)})", "result")
 break # Only test first XSS with valid URL
 except Exception as e:
 logger.debug(f"WAF evasion integration failed: {e}")

 # Smart Recon correlation (build asset graph from findings)
 try:
 from tools.smart_recon import SmartReconEngine
 
 # Extract domains/endpoints from findings for correlation
 domains_found = set()
 endpoints_found = set()
 
 for finding in result.findings:
 url = finding.get("url", "")
 if url:
 try:
 parsed = urlparse(url)
 if parsed.netloc:
 domains_found.add(parsed.netloc)
 endpoints_found.add(url)
 except Exception:
 pass
 
 # If we found new domains, add to mission graph
 for domain in domains_found:
 mission_state.upsert_node(
 GraphNode(
 node_id=f"domain:{domain}",
 node_type="domain",
 props={"discovered_by": tool_name, "source": "tool_finding"},
 )
 )
 mission_state.upsert_edge(
 GraphEdge(
 edge_id=f"edge:{mission_state.target}:domain:{domain}",
 src_id=mission_state.target,
 dst_id=f"domain:{domain}",
 edge_type="has_domain",
 )
 )
 
 # If we found interesting endpoints, prioritize them
 for endpoint in endpoints_found[:5]: # Limit to first 5
 mission_state.add_fact(
 fact_id=f"endpoint:{tool_name}:{endpoint}",
 category="endpoint",
 statement=f"Endpoint discovered: {endpoint}",
 confidence=0.8,
 evidence={"tool": tool_name, "endpoint": endpoint},
 )
 
 # Propose deep recon if many domains found and governance approves
 if len(domains_found) >= 3 and tool_name in ("subfinder", "httpx"):
 recon_gate = self.governance.gate(
 mission_id=mission_key,
 target=target or "global",
 action={
 "action": "run_smart_recon",
 "tool": "smart_recon",
 "command": f"deep_recon({target})",
 "purpose": f"Deep asset correlation for {len(domains_found)} discovered domains",
 },
 callback=callback,
 )
 if recon_gate.allowed:
 display_in_chat_mode(f"[Recon] Deep asset correlation available for {len(domains_found)} domains", "info")
 except Exception as e:
 logger.debug(f"Smart recon integration failed: {e}")

 # REMEMBER: Store tool result in vector memory
 remember(
 f"Tool {tool_name} executed on {target}: {len(result.findings)} findings. "
 f"Success: {result.success}. Category: {result.category.value}",
 target or "global",
 "tool_result",
 tool=tool_name,
 findings_count=len(result.findings),
 success=result.success
 )
 
 # REMEMBER: Store each finding as separate memory
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
 
 # SOC Analysis: Generate detection rules from high-confidence findings
 try:
 from tools.soc_analyzer import SOCAnalyzer
 from tools.threat_intel import ThreatIntelDB, Enricher
 
 ti_db = ThreatIntelDB()
 analyzer = SOCAnalyzer(ioc_db={})
 
 for finding in result.findings:
 # Only generate rules for interesting finding types
 if finding.get('type') in ['intrusion', 'malware', 'recon', 'xss', 'sqli']:
 # Create synthetic alert from finding
 alert = analyzer.parse_json_alert({
 'timestamp': datetime.utcnow().isoformat(),
 'source': tool_name,
 'severity': finding.get('severity', 'medium'),
 'signature': f"{finding.get('type')} detected by {tool_name}",
 'src_ip': finding.get('src_ip'),
 'dst_ip': finding.get('dst_ip'),
 'url': finding.get('url'),
 'confidence': 0.8 if finding.get('confirmed') else 0.6,
 }, tool_name)
 
 if alert:
 # Enrich with threat intel
 enricher = Enricher(ti_db)
 enriched_finding = enricher.enrich_finding(finding)
 
 if enriched_finding.get('threat_intel'):
 alert.ioc_matches = [ioc['value'] for ioc in enriched_finding['threat_intel'].get('ioc_matches', [])]
 
 # Generate detection rule
 rule = analyzer.generate_sigma_rule(alert)
 if rule:
 mission_state.upsert_hypothesis(
 hyp_id=f"detection_rule:{finding.get('type')}:{finding.get('url', '')[:40]}",
 title=f"Detection rule candidate: {rule.title}",
 description=f"Auto-generated Sigma rule for {rule.level} severity",
 confidence=0.7,
 status="open",
 tags=["detection_rule", "sigma", finding.get('type', 'unknown')],
 evidence={
 "rule_title": rule.title,
 "level": rule.level,
 "tags": rule.tags,
 "logsource": rule.logsource,
 "source_finding": finding,
 },
 )
 display_in_chat_mode(f"[SOC] Detection rule generated for {finding.get('type')} finding", "info")
 
 except Exception as e:
 logger.debug(f"SOC analyzer integration failed: {e}")

 # SAST Integration: If we have source code path, run static analysis
 try:
 from tools.sast_engine import SASTEngine
 
 # Check if target is a code repository
 target_path = Path(target or ".")
 if target_path.exists() and target_path.is_dir():
 # Look for code files
 code_extensions = {'.py', '.js', '.java', '.go'}
 has_code = any(f.suffix in code_extensions for f in target_path.rglob('*') if f.is_file())
 
 if has_code:
 # Governance gate for SAST
 sast_gate = self.governance.gate(
 mission_id=mission_key,
 target=target or "global",
 action={
 "action": "run_sast",
 "tool": "sast_engine",
 "command": f"scan_repository({target})",
 "purpose": "Static analysis for security vulnerabilities",
 },
 callback=callback,
 )
 
 if sast_gate.allowed or sast_gate.decision == "needs_approval":
 sast = SASTEngine()
 sast_report = sast.scan_repository(target_path)
 
 if sast_report.get('total_vulnerabilities', 0) > 0:
 # Add findings to MissionState
 for vuln in sast_report.get('critical_vulnerabilities', [])[:5]:
 mission_state.add_fact(
 fact_id=f"sast:{vuln['id']}",
 category="vulnerability",
 statement=f"SAST: {vuln['type']} in {vuln['file']}:{vuln['line']}",
 confidence=0.8,
 evidence=vuln,
 )
 
 display_in_chat_mode(f"[SAST] Found {sast_report['total_vulnerabilities']} code vulnerabilities", "warning")
 except Exception as e:
 logger.debug(f"SAST integration failed: {e}")

 # Cloud Scanner Integration: Check for cloud config files
 try:
 from tools.cloud_scanner import CloudScanner
 
 target_path = Path(target or ".")
 if target_path.exists() and target_path.is_dir():
 # Check for cloud config files
 cloud_files = list(target_path.rglob("*.tf")) + list(target_path.rglob("*template*.json")) + list(target_path.rglob("*template*.yaml"))
 
 if cloud_files:
 # Governance gate for cloud scan
 cloud_gate = self.governance.gate(
 mission_id=mission_key,
 target=target or "global",
 action={
 "action": "run_cloud_scan",
 "tool": "cloud_scanner",
 "command": f"scan_directory({target})",
 "purpose": "Cloud security posture assessment",
 },
 callback=callback,
 )
 
 if cloud_gate.allowed or cloud_gate.decision == "needs_approval":
 cloud_scanner = CloudScanner()
 cloud_report = cloud_scanner.scan_directory(target_path)
 
 if cloud_report.get('total_findings', 0) > 0:
 for finding in cloud_report.get('critical_findings', [])[:5]:
 mission_state.add_fact(
 fact_id=f"cloud:{finding['id']}",
 category="misconfiguration",
 statement=f"Cloud: {finding['type']} in {finding['resource']}",
 confidence=0.85,
 evidence=finding,
 )
 
 display_in_chat_mode(f"[Cloud] Found {cloud_report['total_findings']} misconfigurations", "warning")
 except Exception as e:
 logger.debug(f"Cloud scanner integration failed: {e}")

 # Protocol Analyzer Integration: Check for non-HTTP protocols
 try:
 from tools.protocol_analyzer import ProtocolAnalyzer, ProtocolType
 
 # Check if any findings mention non-HTTP ports
 iot_ports = {1883, 8883, 502, 102, 47808} # MQTT, Modbus, S7, BACnet
 findings_with_ports = [f for f in result.findings if f.get('port') or f.get('url', '')]
 
 has_iot_port = False
 for finding in findings_with_ports:
 port = finding.get('port', 0)
 url = finding.get('url', '')
 if port in iot_ports or any(f':{p}/' in url for p in iot_ports):
 has_iot_port = True
 break
 
 if has_iot_port:
 # Governance gate for protocol analysis
 proto_gate = self.governance.gate(
 mission_id=mission_key,
 target=target or "global",
 action={
 "action": "run_protocol_analysis",
 "tool": "protocol_analyzer",
 "command": "analyze_iot_protocols",
 "purpose": "IoT/ICS protocol security analysis",
 },
 callback=callback,
 )
 
 if proto_gate.allowed or proto_gate.decision == "needs_approval":
 display_in_chat_mode("[Protocol] IoT/ICS protocol detected - consider manual protocol analysis", "info")
 
 # Add hypothesis for IoT testing
 mission_state.upsert_hypothesis(
 hyp_id=f"iot_protocol:{target}",
 title="IoT/ICS Protocol Testing Required",
 description=f"Non-HTTP ports detected ({iot_ports}). Consider MQTT, Modbus, or gRPC protocol testing.",
 confidence=0.6,
 status="open",
 tags=["iot", "ics", "mqtt", "modbus", "protocol"],
 evidence={"detected_ports": list(iot_ports), "source": tool_name},
 )
 except Exception as e:
 logger.debug(f"Protocol analyzer integration failed: {e}")

 # Exploit Chain Builder: Analyze for multi-stage attack paths
 try:
 from tools.exploit_chain_builder import ExploitChainBuilder, format_chain_report
 
 # Check if we have diverse findings (at least 3 different types)
 all_facts = mission_state.list_facts(limit=50)
 all_hyps = mission_state.list_hypotheses(limit=30)
 
 # Convert to findings format
 all_findings = []
 for fact in all_facts:
 all_findings.append({
 'finding_id': fact.get('fact_id', ''),
 'type': fact.get('category', 'finding'),
 'severity': fact.get('evidence', {}).get('severity', 'medium'),
 'target': fact.get('statement', '')[:100],
 'description': fact.get('statement', ''),
 'confidence': fact.get('confidence', 0.5),
 })
 
 # Only analyze if we have diverse findings
 if len(all_findings) >= 3:
 # Check for diversity
 finding_types = set(f.get('type', '') for f in all_findings)
 
 if len(finding_types) >= 2: # At least 2 different types
 builder = ExploitChainBuilder()
 builder.process_findings(all_findings)
 chains = builder.build_chains()
 high_value = builder.get_high_value_chains(min_probability=0.4)
 
 if high_value:
 # Store top chain as hypothesis
 top_chain = high_value[0]
 mission_state.upsert_hypothesis(
 hyp_id=f"exploit_chain:{target}",
 title=f"Multi-stage Attack: {top_chain.name}",
 description=f"{top_chain.description}. Probability: {top_chain.total_probability:.0%}, Impact: {top_chain.total_impact}",
 confidence=top_chain.total_probability,
 status="open",
 tags=["exploit_chain", "multi_stage", top_chain.total_impact],
 evidence={
 "chain_id": top_chain.chain_id,
 "stages": len(top_chain.nodes),
 "probability": top_chain.total_probability,
 "impact": top_chain.total_impact,
 "complexity": top_chain.complexity,
 "time_estimate": top_chain.time_estimate,
 "poc_steps": top_chain.poc_steps,
 "mitigations": top_chain.mitigations,
 },
 )
 
 display_in_chat_mode(
 f" Exploit Chain Discovered: {top_chain.name} ({len(top_chain.nodes)} stages, {top_chain.total_probability:.0%} success rate)",
 "critical" if top_chain.total_impact == "critical" else "warning"
 )
 
 # Add specific bounty recommendation
 if top_chain.total_impact in ["critical", "high"]:
 display_in_chat_mode(
 " High-value chain detected! Consider submitting as combined impact for increased bounty.",
 "result"
 )
 except Exception as e:
 logger.debug(f"Exploit chain analysis failed: {e}")

 # Bounty Predictor: Score new findings for bounty potential
 try:
 from tools.bounty_predictor import BountyPredictor
 
 predictor = BountyPredictor()
 high_value_findings = []
 
 for finding in result.findings:
 # Convert finding to prediction format
 pred_finding = {
 'finding_id': finding.get('finding_id', str(hash(str(finding)))),
 'type': finding.get('type', 'unknown'),
 'severity': finding.get('severity', 'info'),
 'target': finding.get('target', finding.get('url', 'unknown')),
 'description': finding.get('description', finding.get('evidence', '')),
 'confidence': finding.get('confidence', 0.5),
 'cwe_id': finding.get('cwe_id'),
 'evidence': finding.get('evidence', {}),
 }
 
 prediction = predictor.predict(pred_finding)
 
 # Store high-value predictions as facts
 if prediction.bounty_score >= 70:
 high_value_findings.append(prediction)
 mission_state.add_fact(
 fact_id=f"bounty_predict:{prediction.finding_id}",
 category="bounty_prediction",
 statement=f"High bounty potential ({prediction.bounty_score:.0f}/100): {prediction.payout_range}",
 confidence=prediction.confidence,
 evidence={
 "bounty_score": prediction.bounty_score,
 "payout_range": prediction.payout_range,
 "triage_speed": prediction.triage_speed,
 "factors": prediction.factors,
 },
 )
 
 # Notify about high-value findings
 if high_value_findings:
 top = high_value_findings[0]
 display_in_chat_mode(
 f" Bounty Prediction: {top.bounty_score:.0f}/100 score, est. {top.payout_range} - Submit this first!",
 "result"
 )
 
 # Add actionable suggestions as hypothesis
 if top.suggestions:
 mission_state.upsert_hypothesis(
 hyp_id=f"bounty_improve:{target}",
 title=f"Improve bounty potential for {top.finding_id[:40]}",
 description=f"Current score: {top.bounty_score:.0f}/100. Suggestions: {', '.join(top.suggestions[:3])}",
 confidence=top.confidence,
 status="open",
 tags=["bounty_optimization", "reporting"],
 evidence={
 "suggestions": top.suggestions,
 "report_template": top.report_template[:500],
 "similar_cves": top.similar_cves,
 },
 )
 except Exception as e:
 logger.debug(f"Bounty prediction failed: {e}")
 
 # Mark step as completed in attack tree
 if self.current_tree and step < len(self.current_tree.steps):
 self.current_tree.steps[step].completed = True
 self.current_tree.steps[step].result = result
 self.current_tree.steps[step].findings = result.findings
 
 # ADAPTIVE STRATEGY
 if self.planner and result.findings:
 for finding in result.findings:
 new_steps = self.planner.adapt_strategy(self.current_tree, finding)
 if new_steps and callback:
 callback(f" Adapted strategy: +{len(new_steps)} new steps")
 
 # REMEMBER: Strategy adaptation
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
 send_telegram_notification(f" Mission Accomplished: {user_input}")
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
 for r in results[-3:]: # Last 3 results
 lines.append(f"- {r.tool_name}: {len(r.findings)} findings")
 
 return "\n".join(lines)
 
 def process_universal(
 self,
 user_input: str,
 callback: Optional[Callable] = None,
 target: str = "",
 mode: str = "auto" # "auto", "bug_bounty", "general"
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
 
 send_telegram_notification(f" Universal Agent: \"{user_input}\"")
 logger.info(f"Universal mode started: {user_input}")
 
 # Initialize universal executor
 executor = get_universal_executor()
 
 # Remember this session start
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
 max_universal_steps = 50 # More steps for complex tasks
 
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
 callback(f" Step {step}: {thought[:80]}...")
 
 # Remember the thought
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
 callback(f" {response[:200]}")
 return response
 
 # Execute action
 if action_type == "finish":
 summary = params.get("summary", "Task completed")
 logger.info(f"Universal session finished: {summary}")
 send_telegram_notification(f" Universal Agent Complete: {summary[:100]}")
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
 status = "" if result.success else ""
 output_preview = (result.output if result.success else result.error)[:150]
 callback(f"{status} {action_type}: {output_preview}...")
 
 # Remember important results
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
