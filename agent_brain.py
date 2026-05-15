"""
agent_brain.py — Elengenix Intelligent Hunting Engine (v99999 (god nine is the best))
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
import asyncio
import threading
import atexit
import logging
from datetime import datetime
from zoneinfo import ZoneInfo
from pathlib import Path
from collections import Counter
from dataclasses import dataclass, field
from typing import Optional, Callable, Dict, Any, List
from enum import Enum

from tools.universal_ai_client import AIClientManager, AIMessage
from tools.memory_manager import save_learning
from tools.tool_registry import registry, ToolCategory, ToolResult
from tools.cvss_calculator import CVSSCalculator
from tools.vector_memory import remember, recall, get_context_for_ai
from tools.memory_profile import read_memory
from tools.memory_persistence import save_message as _sqlite_save_message, load_conversation as _sqlite_load_conversation, clear_session as _sqlite_clear_session, get_context_status as _get_context_status
from tools.universal_executor import get_universal_executor
from tools.cve_database import get_cve_database
from tools.mission_state import MissionState, GraphNode, GraphEdge
from tools.governance import Governance, GateDecision
from tools.logic_analyzer import BusinessLogicAnalyzer
from tools.payload_mutation import PayloadMutator
from tools.agent_reflection import get_reflection
from live_display import get_activity_logger, display_in_chat_mode
from bot_utils import send_telegram_notification
from scan_engine_upgrade import SmartOrchestrator

logger = logging.getLogger("elengenix.agent")


def _get_now_context() -> str:
    tz_name = os.environ.get("ELENGENIX_TZ")
    tz = None
    if tz_name:
        try:
            tz = ZoneInfo(tz_name)
        except Exception:
            tz = None
    now = datetime.now(tz=tz)

    thai_weekdays = {
        0: "วันจันทร์",
        1: "วันอังคาร",
        2: "วันพุธ",
        3: "วันพฤหัสบดี",
        4: "วันศุกร์",
        5: "วันเสาร์",
        6: "วันอาทิตย์",
    }
    wd_th = thai_weekdays.get(now.weekday(), "")
    tz_display = now.tzname() or tz_name or "local"

    # Thai Buddhist Era year = CE year + 543
    be_year = now.year + 543
    thai_date_str = f"{now.day} {_thai_month_name(now.month)} {be_year}"

    return (
        "### CURRENT TIME CONTEXT (AUTHORITATIVE)\n"
        f"System time (CE): {now.isoformat()}\n"
        f"CE year: {now.year}  |  Thai Buddhist Era (BE) year: {be_year}\n"
        f"Thai date: {thai_date_str}\n"
        f"Timezone: {tz_display}\n"
        f"Thai weekday: {wd_th}\n"
        "RULE: When searching or answering in Thai, ALWAYS use the Buddhist Era year "
        f"({be_year}) not the CE year ({now.year}). "
        "If the user asks about the current date/day/time, use ONLY this context.\n"
    )


def _thai_month_name(month: int) -> str:
    """Return Thai month name for a given month number (1-12)."""
    names = [
        "มกราคม", "กุมภาพันธ์", "มีนาคม", "เมษายน",
        "พฤษภาคม", "มิถุนายน", "กรกฎาคม", "สิงหาคม",
        "กันยายน", "ตุลาคม", "พฤศจิกายน", "ธันวาคม",
    ]
    return names[month - 1] if 1 <= month <= 12 else str(month)


def _get_memory_profile_context() -> str:
    """Read and format the MEMORY.md profile for the AI."""
    profile = read_memory()
    if not profile:
        return ""
    
    lines = ["### USER PROFILE & LONG-TERM KNOWLEDGE (from MEMORY.md):"]
    for key, value in profile.items():
        formatted_key = key.replace("_", " ").title()
        lines.append(f"- {formatted_key}: {value}")
    
    return "\n".join(lines)


def _extract_json_object(text: str) -> Optional[Dict[str, Any]]:
    if text is None:
        return None
    if not isinstance(text, str):
        text = str(text)
    cleaned = text.strip()
    if not cleaned:
        return None

    if "```" in cleaned:
        if "```json" in cleaned:
            cleaned = cleaned.split("```json", 1)[1]
        else:
            cleaned = cleaned.split("```", 1)[1]
        cleaned = cleaned.split("```", 1)[0].strip()

    try:
        return json.loads(cleaned)
    except Exception:
        pass

    m = re.search(r"\{.*\}", cleaned, re.DOTALL)
    if not m:
        return None
    try:
        return json.loads(m.group())
    except Exception:
        return None


def _extract_target_from_text(text: str) -> str:
    if not text:
        return ""
    tokens = re.findall(r"[a-zA-Z0-9._-]+", text.lower())
    stop = {"scan", "recon", "pentest", "test", "bug", "bounty", "hunt", "please", "for"}
    candidates = [t for t in tokens if t not in stop and len(t) > 1]
    if not candidates:
        return ""
    t = candidates[-1]
    if "." not in t and t.isalnum() and len(t) >= 3:
        t = f"{t}.com"
    return t


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
    
    def __init__(self, client: AIClientManager):
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
            response = self.client.chat([
                AIMessage(role="system", content="Generate penetration testing strategy"),
                AIMessage(role="user", content=planning_prompt)
            ]).content
            
            # Extract JSON plan using shared helper (non-greedy, handles markdown fences)
            plan_data = _extract_json_object(response)
            if plan_data:
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
    
    #  GLOBAL SECURITY ALLOWLIST (removed — now uses Governance classification)
    #  The agent may execute any command.  Governance (tools/governance.py)
    #  classifies each action as DESTRUCTIVE / PRIVILEGED / SAFE.
    #     DESTRUCTIVE → blocked unconditionally
    #     PRIVILEGED  → requires interactive user approval
    #     SAFE        → allowed freely
    ALLOWED_TOOLS = set()  # kept as empty sentinel for backward compat

    #  SHARED PERSISTENT EVENT LOOP (prevents "coroutine never awaited" / loop leaks)
    _shared_loop: Optional[asyncio.AbstractEventLoop] = None
    _loop_thread: Optional[threading.Thread] = None
    _loop_lock: threading.Lock = threading.Lock()

    @classmethod
    def _get_shared_loop(cls) -> asyncio.AbstractEventLoop:
        """Get or create the singleton persistent event loop.

        Runs a daemon thread with `loop.run_forever()` so coroutines can be
        submitted via `asyncio.run_coroutine_threadsafe()` without creating
        and destroying loops on every tool execution.
        """
        with cls._loop_lock:
            if cls._shared_loop is None:
                cls._shared_loop = asyncio.new_event_loop()

                def _run_forever(loop: asyncio.AbstractEventLoop) -> None:
                    asyncio.set_event_loop(loop)
                    loop.run_forever()

                cls._loop_thread = threading.Thread(
                    target=_run_forever,
                    args=(cls._shared_loop,),
                    daemon=True,
                    name="elengenix-event-loop",
                )
                cls._loop_thread.start()

                # Register cleanup on interpreter exit
                atexit.register(cls._cleanup_shared_loop)
            return cls._shared_loop

    @classmethod
    def _cleanup_shared_loop(cls) -> None:
        """Shut down the shared event loop on process exit."""
        with cls._loop_lock:
            if cls._shared_loop is not None and cls._shared_loop.is_running():
                cls._shared_loop.call_soon_threadsafe(cls._shared_loop.stop)

    def __init__(
        self,
        max_steps: int = 25,
        loop_threshold: int = 3,
        history_limit: int = 5,
        max_output_len: int = 2000,
        enable_planning: bool = True,
        enable_cot_logging: bool = True,
        max_history_turns: int = 20
    ):
        self.client = AIClientManager()
        self.max_steps = max_steps
        self.loop_threshold = loop_threshold
        self.history_limit = history_limit
        self.max_output_len = max_output_len
        self.enable_planning = enable_planning
        self.enable_cot_logging = enable_cot_logging
        self.max_history_turns = max_history_turns
        
        #  In-session conversation history (ordered user/assistant pairs)
        #  Each entry is a dict: {"role": "user"|"assistant", "content": str}
        self.conversation_history: List[Dict[str, str]] = []
        
        #  Absolute Path Resolution for Prompts
        self.base_dir = Path(__file__).parent.absolute()
        prompt_path = self.base_dir / "prompts" / "system_prompt.txt"
        
        if not prompt_path.exists():
            self.base_prompt = "You are a specialized security AI agent."
        else:
            self.base_prompt = prompt_path.read_text(encoding="utf-8")
        
        #  Strategic Planning
        self.planner = StrategicPlanner(self.client) if enable_planning else None
        self.current_tree: Optional[AttackTree] = None
        
        #  Chain of Thought Logging
        self.cot_logger = ChainOfThoughtLogger() if enable_cot_logging else None
        
        # Live Activity Display
        self.activity_logger = get_activity_logger()
        
        #  CVSS Calculator
        self.cvss_calc = CVSSCalculator(use_ai=True)
        
        #  CVE Database
        self.cve_db = get_cve_database(auto_update=False)
        
        #  System Prompt Enhancement with CVE context
        self._enhance_prompt_with_cve_context()

        #  Governance (HITL for high-risk steps)
        self.governance = Governance(require_approval_high_risk=True)

        #  Business Logic / AuthZ Analyzer
        self.logic_analyzer = BusinessLogicAnalyzer()

        #  Payload Mutation Engine (generates candidates only)
        self.payload_mutator = PayloadMutator()

        #  Agent Reflection / Self-Feedback Tracker
        self.reflection_tracker = get_reflection()

        #  Smart Orchestrator (Upgraded Scan Engine)
        self.smart_orchestrator = SmartOrchestrator(max_concurrency=5)

        #  Skill Registry (Tool Awareness)
        try:
            from tools.skill_registry import get_skill_registry
            self.skill_registry = get_skill_registry()
            # Add available tools context to base prompt
            skill_context = self.skill_registry.get_skill_context()
            self.base_prompt = f"{self.base_prompt}\n\n{skill_context}"
        except ImportError:
            logger.warning("Skill registry not available")
            self.skill_registry = None

        # Load persistent conversation from SQLite (cross-session memory)
        self._load_persistent_conversation()

    def _load_persistent_conversation(self) -> None:
        """Restore previous session conversation from SQLite."""
        try:
            model_name = ""
            if hasattr(self, "client") and hasattr(self.client, "active_client"):
                model_name = getattr(self.client.active_client, "model", "")
            loaded = _sqlite_load_conversation("default")
            if loaded:
                self.conversation_history = loaded
                logger.info(f"Loaded {len(loaded)} messages from persistent memory")
        except Exception as e:
            logger.warning(f"Could not load persistent conversation: {e}")

    def _save_to_persistent_memory(self, role: str, content: str) -> None:
        """Save a message to SQLite for cross-session persistence."""
        try:
            from tools.token_counter import count_tokens
            model_name = ""
            if hasattr(self, "client") and hasattr(self.client, "active_client"):
                model_name = getattr(self.client.active_client, "model", "")
            token_est = count_tokens(content)
            _sqlite_save_message("default", role, content, model_name, token_est)
        except Exception as e:
            logger.warning(f"Could not save to persistent memory: {e}")

    def _check_context_overflow(self) -> bool:
        """
        Check if conversation is approaching context limit.
        Returns True if summarization was triggered.
        """
        try:
            model_name = ""
            if hasattr(self, "client") and hasattr(self.client, "active_client"):
                model_name = getattr(self.client.active_client, "model", "")
            status = _get_context_status("default", model_name)
            if status["is_near_full"]:
                logger.warning(
                    f"Context at {status['percent']:.1f}% "
                    f"({status['used_tokens']} / {status['capacity']} tokens) - "
                    "triggering auto-compress"
                )
                self._summarize_old_conversation()
                return True
        except Exception as e:
            logger.warning(f"Context check failed: {e}")
        return False

    def _summarize_old_conversation(self) -> None:
        """
        Compress old conversation turns into a summary to free context space.
        Keeps first and last few turns intact, summarizes the middle portion.
        """
        if len(self.conversation_history) <= 6:
            return

        try:
            kept_turns = 3
            middle_start = kept_turns
            middle_end = len(self.conversation_history) - kept_turns

            if middle_end <= middle_start:
                return

            middle_messages = self.conversation_history[middle_start:middle_end]
            if not middle_messages:
                return

            summary_parts = []
            for msg in middle_messages:
                label = "User" if msg["role"] == "user" else "Assistant"
                summary_parts.append(f"{label}: {msg['content'][:300]}")

            middle_text = "\n\n".join(summary_parts)

            model_name = ""
            if hasattr(self, "client") and hasattr(self.client, "active_client"):
                model_name = getattr(self.client.active_client, "model", "")

            if model_name and "claude" in model_name.lower():
                model_for_summary = model_name
            else:
                model_for_summary = model_name

            compress_prompt = (
                "Summarize the following conversation turns into a concise summary "
                "that preserves all important information, decisions, and findings. "
                "Keep it under 400 words. Write in English.\n\n"
                f"CONVERSATION TURNS TO SUMMARIZE:\n{middle_text}\n\n"
                "Provide a summary that captures:\n"
                "1. Main topics discussed and goals\n"
                "2. Key findings or discoveries\n"
                "3. Tools used and results\n"
                "4. Important decisions or next steps\n\n"
                "SUMMARY:"
            )

            summary_response = self.client.chat([
                AIMessage(role="user", content=compress_prompt)
            ])

            summary_text = summary_response.content if summary_response else ""
            if not summary_text or len(summary_text.strip()) < 20:
                logger.warning("Summarization returned empty, skipping compress")
                return

            summary_entry = {
                "role": "assistant",
                "content": (
                    f"[COMPRESSED SUMMARY of {len(middle_messages)} earlier turns]: "
                    f"{summary_text.strip()}"
                )
            }

            self.conversation_history = (
                self.conversation_history[:middle_start]
                + [summary_entry]
                + self.conversation_history[middle_end:]
            )

            total_msgs = len(self.conversation_history)
            logger.info(
                f"Compressed {len(middle_messages)} turns into summary. "
                f"History now has {total_msgs} messages."
            )

            try:
                _sqlite_clear_session("default")
                conv_tokens = 0
                for msg in self.conversation_history:
                    from tools.token_counter import count_tokens
                    token_est = count_tokens(msg["content"])
                    conv_tokens += token_est
                    _sqlite_save_message(
                        "default", msg["role"], msg["content"],
                        model_name, token_est
                    )
            except Exception as e:
                logger.warning(f"Failed to update SQLite after compress: {e}")

        except Exception as e:
            logger.error(f"Failed to summarize old conversation: {e}")

    def _append_history(self, role: str, content: str) -> None:
        """Append a message to the in-session conversation history and persist to SQLite."""
        self.conversation_history.append({"role": role, "content": content})
        max_messages = self.max_history_turns * 2
        if len(self.conversation_history) > max_messages:
            self.conversation_history = self.conversation_history[-max_messages:]

        self._save_to_persistent_memory(role, content)

        if len(self.conversation_history) % 8 == 0:
            self._persist_recent_conversation()
    
    def _persist_recent_conversation(self) -> None:
        """Save recent conversation turns to vector memory for long-term recall."""
        from tools.vector_memory import persist_conversation_turns
        
        # Get current target from current tree or default
        target = self.current_tree.target if self.current_tree else "universal"
        
        count = persist_conversation_turns(
            conversation_history=self.conversation_history,
            target=target,
            batch_size=4
        )
        
        if count > 0:
            logger.debug(f"Persisted {count} conversation turns to vector memory")
    
    def _check_for_negative_feedback(self, current_input: str) -> None:
        """
        Check if current user input is negative feedback about the previous AI response.
        If so, record it as a reflection mistake.

        Args:
            current_input: Current user message.
        """
        if not self.conversation_history:
            return
        
        # Get the last assistant response
        last_assistant = None
        last_user_query = None
        for turn in reversed(self.conversation_history):
            if turn["role"] == "assistant":
                last_assistant = turn["content"]
            elif turn["role"] == "user" and last_assistant is None:
                last_user_query = turn["content"]
        
        if not last_assistant:
            return
        
        # Check if current input looks like negative feedback
        sentiment = self.reflection_tracker.classify_sentiment(current_input)
        if sentiment == "negative" and last_user_query:
            logger.info(
                f"Detected negative feedback: '{current_input[:50]}...' "
                f"about query: '{last_user_query[:50]}...'"
            )
            self.reflection_tracker.record_mistake(
                original_query=last_user_query,
                ai_response=last_assistant,
                user_feedback=current_input,
            )

    def _build_chat_messages(self, system_prompt: str, user_input: str) -> List[AIMessage]:
        """
        Build the full message list to send to the AI, including prior conversation history.

        Args:
            system_prompt: The system-level instruction.
            user_input: The current user message.

        Returns:
            List of AIMessage objects ordered: system, [history...], user.
        """
        messages = [AIMessage(role="system", content=system_prompt)]
        for turn in self.conversation_history:
            messages.append(AIMessage(role=turn["role"], content=turn["content"]))
        messages.append(AIMessage(role="user", content=user_input))
        return messages

    def clear_conversation_history(self) -> None:
        """
        Clear the in-session conversation history.
        Call this when the user runs /clear to start fresh.
        """
        self.conversation_history = []
        logger.info("[OK] Conversation history cleared.")

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
        Execute a command with Governance-based security.

        The agent may run *any* command.  Governance (tools/governance.py)
        classifies each action as:
          DESTRUCTIVE → unconditionally denied
          PRIVILEGED  → shown to user for interactive approval
          SAFE        → executed immediately
        """
        action_val = action_data.get("action", "")
        if isinstance(action_val, dict):
            action_val = action_val.get("type", "")
        action = str(action_val).lower()
        cmd_raw = action_data.get("command", "")

        if action == "finish":
            return "__FINISH__"
        if action == "save_memory":
            save_learning(action_data.get("target", "global"), action_data.get("learning", ""), action_data.get("category", "general"))
            return "Finding recorded in SQLite memory."

        if action != "run_shell":
            return f"Error: Unknown action '{action}'."
        if not cmd_raw or not isinstance(cmd_raw, str):
            return "Error: Invalid or empty command."

        # ── Governance gate ──────────────────────────────────────────
        gate = self.governance.gate(
            mission_id="cli_tool_exec",
            target="local",
            action={"action": "run_shell", "command": cmd_raw},
            callback=callback,
        )

        if gate.decision == "deny":
            display_in_chat_mode(
                f"[red]BLOCKED: {gate.rationale}[/red]\n"
                f"  Command: [dim]{cmd_raw[:200]}[/dim]",
                "error",
            )
            return f"Command blocked by governance: {gate.rationale}"

        if gate.decision == "needs_approval":
            from ui_components import confirm
            display_in_chat_mode(
                f"[yellow]AI wants to run:[/yellow]\n"
                f"  [dim]{cmd_raw[:500]}[/dim]\n"
                f"[yellow]Allow this command?[/yellow]",
                "warning",
            )
            try:
                approved = confirm("Run this command?", default=False)
            except Exception:
                approved = False
            if not approved:
                return "Command rejected by user."

        # ── Execute ──────────────────────────────────────────────────
        try:
            import shutil
            from tools.safe_exec import execute_safely

            # Resolve binary (if first token has a name) for display
            try:
                parts = shlex.split(cmd_raw)
                if parts:
                    binary = os.path.basename(parts[0])
                    resolved = shutil.which(binary)
                    if resolved:
                        display_in_chat_mode(f"Running: [dim]{resolved}[/dim]", "info")
            except Exception:
                pass

            safe_result = execute_safely(cmd_raw, timeout=180)
            if not safe_result["success"]:
                err = safe_result["error"] or safe_result["stderr"][:500]
                return f"Command failed: {err}"
            return safe_result["stdout"][:self.max_output_len]

        except subprocess.TimeoutExpired:
            return "Error: Command timed out after 180 seconds."
        except ValueError as e:
            return f"Error: Invalid command syntax: {e}"
        except Exception as e:
            return f"Error executing tool: {str(e)}"

    def _execute_tool_registry(
        self, 
        tool_name: str, 
        target: str,
        report_dir: Path,
        semaphore: Optional[asyncio.Semaphore] = None
    ) -> ToolResult:
        """
        Execute tool via Tool Registry on the shared persistent event loop.
        Fallback to subprocess if registry fails.
        """
        tool = registry.get_tool(tool_name)
        if tool and tool.is_available:
            try:
                async def _run() -> ToolResult:
                    s = semaphore or asyncio.Semaphore(5)
                    return await tool.execute(target, report_dir, s)

                loop = self._get_shared_loop()
                future = asyncio.run_coroutine_threadsafe(_run(), loop)
                timeout = getattr(getattr(tool, "metadata", None), "timeout_seconds", 180)
                return future.result(timeout=timeout)
            except Exception as e:
                logger.warning(f"Tool registry execution failed: {e}")

        return self._execute_tool_subprocess(tool_name, target)
    
    def _execute_tool_subprocess(self, tool_name: str, target: str) -> ToolResult:
        """Fallback subprocess execution with PATH verification.

        Security is handled upstream by Governance (tools/governance.py).
        This method validates the binary exists and uses known command templates.
        """
        from tools.tool_registry import ToolResult, ToolCategory

        # Resolve via PATH (prevents PATH-hijack)
        import shutil
        resolved = shutil.which(tool_name)
        if resolved is None:
            return ToolResult(
                success=False,
                tool_name=tool_name,
                category=ToolCategory.UTILITY,
                error_message=f"Tool '{tool_name}' not found in PATH",
            )

        # Build command from known templates (safe list, not concatenation)
        commands = {
            "subfinder": ["subfinder", "-d", target, "-silent"],
            "httpx": ["httpx", "-u", target, "-silent"],
            "nuclei": ["nuclei", "-u", target, "-silent", "-severity", "critical,high,medium"],
        }

        cmd = commands.get(tool_name)

        # Only allow known templates — never fall back to [tool_name, target]
        if cmd is None:
            return ToolResult(
                success=False,
                tool_name=tool_name,
                category=ToolCategory.UTILITY,
                error_message=f"Tool '{tool_name}' has no known command template",
            )

        try:
            result = subprocess.run(
                cmd,
                shell=False,
                capture_output=True,
                text=True,
                timeout=180,
            )

            return ToolResult(
                success=result.returncode == 0,
                tool_name=tool_name,
                category=ToolCategory.RECON,
                output=result.stdout + result.stderr,
            )
        except Exception as e:
            return ToolResult(
                success=False,
                tool_name=tool_name,
                category=ToolCategory.RECON,
                error_message=str(e),
            )

    def _analyze_intent(self, query: str) -> str:
        """Use AI to intelligently classify user intent - AI-driven, not keyword-driven."""
        
        sys_prompt = """You are an intelligent intent classifier. Analyze the user's message and determine their TRUE intent.

### INTENT CATEGORIES:
1. **casual** - Social chat, greetings, asking who you are, what you can do
   - Examples: "hi", "สวัสดี", "คุณคือใคร", "what can you do", "help"
   - The user wants conversation, not information retrieval

2. **research** - Time-sensitive info that REQUIRES live web search
   - Examples: "ผลบอลวันนี้", "ข่าวล่าสุด", "ราคาหุ้นตอนนี้", "อากาศพรุ่งนี้"
   - MUST be: current events, sports scores, weather forecasts, stock prices, breaking news
   - Information that CHANGES constantly and needs fresh data
   - NOT for: definitions, explanations, how things work (those are security_chat)

3. **scan** - Requesting active security testing on a SPECIFIC target
   - Examples: "scan example.com", "attack 192.168.1.1", "pentest google.com"
   - MUST have a target domain/IP - not just talking about scanning in general
   - The user wants you to run security tools against a target

4. **security_chat** - Security questions, advice, code review without active scanning
   - Examples: "how does SQL injection work", "review this code", "explain XSS"
   - Security discussion without asking to attack a target
   - The user wants knowledge, not tool execution

### CLASSIFICATION RULES:
- **Ask yourself**: "Does this need TODAY's data from the internet?"
- **research** = Live sports scores, current news, weather now, stock prices TODAY (time-sensitive)
- **security_chat** = "CVE คืออะไร", "อธิบาย SQL injection", "how does XSS work" (knowledge questions)
- **casual** = "สวัสดี", "คุณเป็นใคร", "ช่วยอะไรได้" (social chat)
- **scan** = "scan example.com", "pentest 192.168.1.1" (has specific target)
- "วันนี้" + กีฬา/ข่าว/อากาศ = research (needs live data)
- "อธิบาย/what is/how does" = security_chat (knowledge, not live data)

### OUTPUT:
Reply with ONLY ONE word: casual, research, scan, or security_chat"""

        
        try:
            res = self.client.chat([
                AIMessage(role="system", content=sys_prompt),
                AIMessage(role="user", content=query)
            ]).content
            if res is None:
                return "security_chat"
            intent = str(res).strip().lower()
            
            for valid in ["casual", "research", "scan", "security_chat"]:
                if valid in intent:
                    return valid
                    
            return "security_chat"  # Default fallback to chat instead of scan
        except Exception as e:
            logger.warning(f"Intent classification failed: {e}")
            return "security_chat" # Fallback to chat for safety

    def run_smart_scan(self, target: str, report_dir: Path) -> str:
        """Run an intelligent smart scan using the upgraded scan engine.

        Runs on the shared persistent event loop to avoid loop leaks.

        Args:
            target: Target domain/IP to scan.
            report_dir: Directory to save scan reports.

        Returns:
            A summary string of the findings.
        """
        try:
            async def _run():
                return await self.smart_orchestrator.run_smart_scan(
                    target=target,
                    report_dir=report_dir,
                    tools=None,
                    rate_limit=5,
                    correlate=True,
                    use_smart_chain=True,
                )

            loop = self._get_shared_loop()
            future = asyncio.run_coroutine_threadsafe(_run(), loop)
            state, correlator = future.result(timeout=600)
        except Exception as e:
            logger.error(f"Smart scan failed: {e}")
            return f"Smart scan failed: {e}"

        summary_parts = ["Smart Scan Results:", "-" * 20]
        if state:
            summary_parts.extend([
                f"Total tools run: {len(state.results)}",
                f"Total findings: {len(state.findings)}",
                f"Scan duration: {state.duration:.1f} seconds"
            ])
        if correlator:
            clusters = correlator.get_clustered_report()
            if clusters:
                summary_parts.append(f"Correlated clusters: {len(clusters)}")
        return "\n".join(summary_parts)

    def process_query(
        self, 
        user_input: str, 
        callback: Optional[Callable] = None, 
        target: str = "",
        use_smart_scan: bool = False
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
        
        # 1. Use AI to classify user intent
        intent = self._analyze_intent(user_input)
        if callback:
            callback(f"AI classified intent as: {intent.upper()}")

        # Normalize scan target if user asked to scan but target wasn't set.
        # This keeps the agent autonomous without hardcoding specific domains.
        if intent == "scan" and not target:
            inferred = _extract_target_from_text(user_input)
            if inferred:
                target = inferred
        logger.info(f"AI classified intent: {intent}")
        
        # 2. If it's a conversation or research, handle it without starting a mission
        if intent in ["casual", "research", "security_chat"] and not target:
            # RETRIEVE MEMORY: Load past knowledge about the user/topic
            past_memories = get_context_for_ai(user_input, target="universal", max_memories=5)
            logger.info(f"Retrieved {len(past_memories.splitlines())} context lines from memory.")
            
            now_context = _get_now_context()
            chat_prompt = f"""You are Elengenix AI v3.0, an expert security assistant and conversational AI.
Intent category: {intent}

{now_context}

{past_memories}

If the intent is 'casual', be friendly and conversational.
If the intent is 'research', provide accurate information or web research.
If the intent is 'security_chat', provide expert cybersecurity advice or code examples.
Do NOT attempt to run a scan. Respond naturally in the user's language (English or Thai)."""
            
            messages = self._build_chat_messages(chat_prompt, user_input)
            response = (self.client.chat(messages).content or "").strip()

            if response:
                self._append_history("user", user_input)
                self._append_history("assistant", response)
            # SAVE TO MEMORY: Remember this interaction for next time
            remember(
                content=f"User said: {user_input} | AI responded: {response[:100]}...",
                target="universal",
                category="conversation"
            )
            
            return response
        
        # send_telegram_notification(f" Mission Started: \"{user_input}\"")
        logger.info(f"Starting mission: {user_input}")

        mission_key = f"{target or 'global'}:{int(time.time())}"
        mission_state = MissionState(
            mission_id=mission_key,
            target=target or "global",
            objective=user_input,
        )
        mission_state.upsert_node(GraphNode(node_id=mission_state.target, node_type="target", props={"target": mission_state.target}))
        
        #  REMEMBER: Store this mission start in vector memory
        mission_id = remember(
            f"Started mission: {user_input}. Target: {target or 'general'}",
            target or "global",
            "mission_start",
            session_type="ai_chat"
        )
        
        #  STRATEGIC PLANNING PHASE
        if self.enable_planning and target:
            self.current_tree = self.planner.generate_attack_tree(
                target, 
                objective=user_input
            )
            if callback:
                callback(f"Strategy: {self.current_tree.reasoning[:100]}...")
            logger.info(f"Attack tree generated: {len(self.current_tree.steps)} steps")
            
            #  Log to activity display
            self.activity_logger.log_thought(f"Strategy: {self.current_tree.reasoning[:80]}...", step=0)
            display_in_chat_mode(f"Planning: {len(self.current_tree.steps)} steps ahead", "thought")
            
            #  REMEMBER: Store the strategy
            remember(
                f"Strategy planned: {self.current_tree.reasoning}",
                target,
                "strategy",
                step_count=len(self.current_tree.steps)
            )
        
        # Setup report directory
        safe_target = target.replace('.', '_') if target else "global"
        report_dir = Path("reports") / f"agent_{safe_target}_{int(time.time())}"
        report_dir.mkdir(parents=True, exist_ok=True)

        #  Smart Scan Mode (Upgraded Engine)
        if use_smart_scan and intent == "scan":
            if callback:
                callback("Starting smart scan with file relationship analysis...")
            display_in_chat_mode("[Smart Scan] Starting upgraded scan engine", "system")
            return self.run_smart_scan(target, report_dir)
        
        #  Reset mission state
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
                #  AI-driven dynamic planning with SEMANTIC MEMORY
                
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
                
                #  SEMANTIC SEARCH: หา memories ที่คล้ายกับปัญหาปัจจุบัน
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

                response_text = self.client.chat([
                    AIMessage(role="system", content=full_prompt),
                    AIMessage(role="user", content="Plan next action")
                ]).content
                action_data = self._extract_json(response_text) or {}
                reasoning = f"AI decision: {action_data.get('purpose', 'continue investigation')}"
            
            #  Chain of Thought Logging
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
            action_val = action_data.get("action", "")
            if isinstance(action_val, dict):
                action_val = action_val.get("type", "")
            action = str(action_val).lower()
            
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
                    
                    #  CVE Lookup: Find similar historical vulnerabilities
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
                
                #  REMEMBER: Store mission completion
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
                
                #  REMEMBER: Store key findings for quick recall
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
                    summary += f"\n\n Chain of Thought: {cot_file}"
                
                # Generate findings report with CVE references
                if cvss_results:
                    summary += f"\n\n CRITICAL FINDINGS: {critical_count}"
                    summary += f"\n HIGH: {high_count}"
                    
                    # Add CVE references for top findings
                    summary += "\n\n SIMILAR HISTORICAL VULNERABILITIES:"
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

                # send_telegram_notification(f" Mission Accomplished: {user_input}")
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
            
            #  Loop & Deadlock Protection
            action_sig = f"{action}:{action_data.get('command', '')}"
            action_history.append(action_sig)
            
            if Counter(action_history)[action_sig] > self.loop_threshold:
                msg = f" DEADLOCK DETECTED: Agent is repeating '{action_sig}'. Terminating."
                send_telegram_notification(msg)
                logger.warning(msg)
                return msg
            
            #  EXECUTION via Tool Registry
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
                                logger.warning(f"MissionState gate ledger write failed: {e}")
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
                                logger.warning(f"MissionState gate ledger write failed: {e}")
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
                            logger.warning(f"MissionState gate ledger write failed: {e}")
                        return msg
                if callback:
                    callback(f"Running: {tool_name} - {purpose}")
                
                #  Log activity
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
                    logger.warning(f"MissionState ledger write failed: {e}")
                
                #  Log result
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
                        logger.warning(f"MissionState update from finding failed: {e}")

                # ── ANALYSIS PIPELINE (13 analyzers) ─────────────────────
                from tools.analysis_pipeline import AnalysisPipeline
                pipeline = AnalysisPipeline(self)
                pipeline.run_all(
                    result=result,
                    tool_name=tool_name,
                    target=target,
                    step=step,
                    mission_key=mission_key,
                    mission_state=mission_state,
                    callback=callback,
                )
                
                # Mark step as completed in attack tree
                if self.current_tree and step < len(self.current_tree.steps):
                    self.current_tree.steps[step].completed = True
                    self.current_tree.steps[step].result = result
                    self.current_tree.steps[step].findings = result.findings
                
                #  ADAPTIVE STRATEGY
                if self.planner and result.findings:
                    for finding in result.findings:
                        new_steps = self.planner.adapt_strategy(self.current_tree, finding)
                        if new_steps and callback:
                            callback(f" Adapted strategy: +{len(new_steps)} new steps")
                            
                            #  REMEMBER: Strategy adaptation
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
                # send_telegram_notification(f" Mission Accomplished: {user_input}")
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

    def process_team_scan(
        self,
        user_input: str,
        model_names: List[str],
        target: str,
        callback: Optional[Callable] = None,
    ) -> str:
        """
        TEAM AEGIS — Multi-Agent Collaborative Scan.
        
        Multiple AI models work as a team: discussing strategies,
        assigning tasks, sharing results, and collaborating to find
        vulnerabilities on the target.
        
        Args:
            user_input: The user's scan request
            model_names: List of model identifiers (provider/model or just model)
            target: Target domain/IP
            callback: Live output callback
        """
        from tools.multi_agent import TeamAegis
        from tools.universal_ai_client import UniversalAIClient
        from tools.universal_executor import get_universal_executor
        
        logger.info(f"Team Aegis scan started: {len(model_names)} models, target={target}")
        
        # Build team clients
        team_clients = []
        
        for model_str in model_names:
            try:
                # Parse provider/model
                if "/" in model_str:
                    provider, model_name = model_str.split("/", 1)
                else:
                    provider = os.environ.get("ACTIVE_AI_PROVIDER", "auto")
                    model_name = model_str
                    
                # Create a fresh client for each model
                new_client = UniversalAIClient(
                    provider=provider, 
                    model=model_name
                )
                if new_client.is_available():
                    team_clients.append(new_client)
            except Exception as e:
                logger.warning(f"Failed to load team client {model_name}: {e}")
        
        # Fallback: if we couldn't build enough clients, use what we have
        if len(team_clients) < 2:
            # Use all available clients from the manager
            for provider, client in self.client.clients.items():
                if client.is_available() and client not in team_clients:
                    team_clients.append(client)
                    if len(team_clients) >= 3:
                        break
        
        if len(team_clients) < 2:
            if callback:
                callback("Team Aegis requires at least 2 available AI models. Falling back to single agent.")
            return self.process_universal(user_input, callback=callback, target=target, mode="bug_bounty")
        
        # Initialize executor for tool execution
        executor = get_universal_executor()
        
        # Create and run Team Aegis
        team = TeamAegis(
            clients=team_clients[:3],
            target=target,
            callback=callback,
            max_rounds=30,
        )
        
        # Add the user's request as initial context
        from tools.multi_agent import TeamMessage
        team.discussion.append(TeamMessage(
            round=0,
            agent_id=-1,
            agent_role="Operator",
            model_name="human",
            content=f"Mission briefing: {user_input}",
            msg_type="discussion"
        ))
        
        # Run the engagement
        return team.run_full_engagement(executor=executor)

    def request_tool_install(self, tool_name: str, ask_first: bool = True) -> str:
        """
        Request to install a missing security tool.
        
        Args:
            tool_name: Name of the tool to install
            ask_first: If True, only create a pending request (don't install until user confirms)
            
        Returns:
            Status message — either "Please confirm: ..." or "[OK] Installed"
        """
        if not self.skill_registry:
            return "[FAIL] Skill registry not available."
        
        skill = self.skill_registry.skills.get(tool_name)
        if not skill:
            return f"[FAIL] Unknown tool: {tool_name}"
        
        if skill.status.value == "available":
            return f"[OK] {tool_name} is already installed."
        
        from tools.install_request import get_install_manager
        mgr = get_install_manager()
        
        # Check if already pending
        for r in mgr.get_pending_requests():
            if r.tool_name == tool_name:
                return f"[PENDING] {tool_name} is already waiting for install confirmation."
        
        req = mgr.request(
            tool_name=tool_name,
            description=skill.description,
            install_command=skill.install_command,
            reason=f"AI recommended for current scenario: {skill.description}"
        )
        
        if ask_first:
            return (
                f"[INSTALL REQUEST] {tool_name}\n"
                f"  Description: {skill.description}\n"
                f"  Install: {skill.install_command}\n"
                f"  To confirm: type '/install confirm {tool_name}' or 'y'"
            )
        
        # Auto-install without asking
        success = mgr.confirm_install(req)
        if success:
            return f"[OK] Successfully installed {tool_name}"
        return f"[FAIL] Could not install {tool_name}. Manual: {skill.install_command}"

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

        # Phase 2: Check context overflow before processing (auto-compress at 80%)
        self._check_context_overflow()

        # send_telegram_notification(f" Universal Agent: \"{user_input}\"")
        logger.info(f"Universal mode started: {user_input}")

        # AI intent classification (single source of truth)
        intent = "security_chat"
        try:
            intent = self._analyze_intent(user_input)
        except Exception as e:
            logger.debug(f"Universal intent classification failed: {e}")
            intent = "security_chat"
        if callback:
            callback(f"AI classified intent as: {intent.upper()}")
        
        # 🧠 SELF-REFLECTION: Check if current input is negative feedback about previous response
        self._check_for_negative_feedback(user_input)
        
        # Initialize universal executor
        executor = get_universal_executor()
        
        # Redundant session remember removed to prevent clogging memory history

        
        # Determine if this is a bug bounty task
        # Use intent first; fall back to explicit mode/target.
        is_security_task = (
            mode == "bug_bounty"
            or intent == "scan"
            or (bool(target) and intent in ("scan", "security_chat"))
        )

        # For casual/security_chat (no target), respond without tool loop.
        # RESEARCH intent enters tool loop to use web search.
        if intent in ["casual", "security_chat"] and not target:
            # 🧠 MEMORY RETRIEVAL (Hybrid Approach - Increased context)
            past_memories = get_context_for_ai(
                user_input, 
                target=target or "universal", 
                max_memories=12,
                conversation_history=self.conversation_history
            )
            logger.info(f"Retrieved {len(past_memories.splitlines())} memories from the cloud.")
            
            # 🧠 SELF-REFLECTION CHECK: Look for past mistakes
            reflection_caution = self.reflection_tracker.retrieve_caution(user_input)
            if reflection_caution:
                logger.info(f"AgentReflection warning retrieved for query")
            
            now_context = _get_now_context()
            profile_context = _get_memory_profile_context()
            
            # Get available tools for capability questions
            available_tools = registry.list_available_tools()
            tool_names = [name for name, info in available_tools.items() if info.get('available')]
            tool_list = ", ".join(tool_names[:10]) + ("..." if len(tool_names) > 10 else "")
            
            # Detect language from input
            has_thai = bool(re.search(r"[\u0E00-\u0E7F]", user_input))
            detected_lang = "Thai" if has_thai else "English"
            lang_instruction = "Respond in Thai language." if has_thai else "Respond in English language."
            
            chat_prompt = f"""You are Elengenix AI v99999 (god nine is the best) — A Universal AI Agent specialized for Bug Bounty and Security Research.
Intent category: {intent}
Detected user language: {detected_lang}

{now_context}

### 🧠 LONG-TERM PROFILE:
{profile_context}

### 🧠 PAST CONVERSATIONS (RELEVANT CONTEXT):
{past_memories}

{reflection_caution}

### YOUR IDENTITY & CAPABILITIES:
- Name: Elengenix AI (อีเลนเจนิกซ์ เอไอ)
- Version: v99999 (god nine is the best)
- Primary role: Security researcher and penetration testing assistant

### WHAT YOU CAN DO:

[LIVE INTERNET ACCESS - Real-time data:]
- Search Google for current news, sports scores, weather, stock prices
- Get TODAY's information - no knowledge cutoff!
- Research CVEs, exploits, and security advisories

[SECURITY TOOLS:]
{tool_list}
Plus: nmap, nuclei, ffuf, dalfox, sqlmap, and 40+ security tools

[GENERAL CAPABILITIES:]
- File editing, shell commands, package installation
- Code review and script generation
- Web research and OSINT

### LANGUAGE RULE:
- Detect the language of the user's input
- If user wrote Thai → respond in Thai
- If user wrote English → respond in English
- Respond naturally in the detected language

### OTHER RULES:
1. Do not use emojis.
2. Do not attempt to run scans or use tools for this casual query.
3. Answer directly based on your knowledge above.
4. If asked what you can do, explain your capabilities including LIVE WEB SEARCH."""

            messages = self._build_chat_messages(chat_prompt, user_input)
            direct = (self.client.chat(messages).content or "").strip()

            if direct:
                # Store this turn in conversation history for context
                self._append_history("user", user_input)
                self._append_history("assistant", direct)
                # MEMORY STORAGE: Remember this interaction in vector store
                remember(
                    content=f"User interaction: {user_input} | AI Response: {direct[:150]}...",
                    target=target or "universal",
                    category="conversation"
                )
                return direct
            # Hard fallback - deterministic based on Thai detection
            if has_thai:
                return "สวัสดีครับ! ผมเป็น Elengenix AI ผู้ช่วยด้านความปลอดภัย มีอะไรให้ช่วยเหลือไหมครับ?"
            return "Hello! I'm Elengenix AI, your security research assistant. How can I help you today?"

        # RESEARCH intent with no target: quick web search mode
        if intent == "research" and not target:
            # Allow AI to use tools for research, but stay focused on the query
            pass
        
        # Check if this is a simple conversational query (no loop needed)
        simple_greetings = [
            "hi", "hello", "hey", "hiya", "yo",
            "สวัสดี", "สวัสดีครับ", "สวัสดีค่ะ",
            "หวัดดี", "หวัดดีครับ", "หวัดดีค่ะ",
            "สัวสดี", "สวัส", "สวัดดี", "สวัสดีจ้า",
            "ไง", "ไงครับ", "ไงค่ะ", "ไงจ้า", "ว่าไง",
            "sawasdee", "sawasdee krub", "sawasdee krap",
        ]
        simple_questions = ["how are you", "what can you do", "help", "?", "who are you"]
        normalized = user_input.lower().strip()
        normalized_no_spaces = normalized.replace(" ", "")
        
        # Check if starts with Thai greeting (handle mixed Thai-English like "สวัสดี Elengenix")
        starts_with_thai_greeting = any(
            normalized.replace(" ", "").startswith(g.replace(" ", "")) 
            for g in simple_greetings if re.search(r"[\u0E00-\u0E7F]", g)
        )
        
        thai_only = bool(re.fullmatch(r"[\s\u0E00-\u0E7F\.!?]+", user_input.strip()))
        is_thai_greeting = starts_with_thai_greeting or (
            bool(re.fullmatch(r"[\s\u0E00-\u0E7F\.!?]+", user_input.strip())) and any(
                g in user_input.strip() for g in ["สวั", "หวัด", "ดี"]
            )
        )
        is_short_thai_chat = thai_only and 0 < len(user_input.strip()) <= 8
        is_simple_query = (
            any(normalized.startswith(g) for g in simple_greetings) or
            any(q in normalized for q in simple_questions) or
            is_thai_greeting or
            is_short_thai_chat
        ) and not is_security_task and not target and intent not in ("research", "scan")
        
        # For simple queries, respond directly without loop
        if is_simple_query:
            wants_thai = bool(re.search(r"[\u0E00-\u0E7F]", user_input))
            if wants_thai:
                # Deterministic Thai response to avoid provider-dependent language drift.
                return "สวัสดีครับ! มีอะไรให้ช่วยเหลือไหม?"
            lang_rule = "Respond in Thai ONLY." if wants_thai else "Respond in English ONLY."
            simple_prompt = f"""You are Elengenix AI v5.0.
User input: "{user_input}"
Contains Thai characters: {wants_thai}

### LANGUAGE RULE (STRICT):
{lang_rule}
- If Thai detected in input → respond in Thai language
- If English detected → respond in English language  
- ABSOLUTELY NO other languages (no Turkish, Spanish, French, etc.)
- This is a HARD requirement

### RESPONSE:
Keep it short and conversational. No tools. No emojis."""
            
            response = (self.client.chat([
                AIMessage(role="system", content=simple_prompt),
                AIMessage(role="user", content="Greeting")
            ]).content or "")
            if not response.strip():
                return "สวัสดีครับ! มีอะไรให้ช่วยเหลือไหม?" if wants_thai else "Hello! How can I help you today?"
            return response.strip()
        
        # Build system prompt based on mode
        now_context = _get_now_context()
        if intent == "research" and not target:
            # RESEARCH mode: simple information retrieval - NOT a security task
            base_prompt = f"""You are Elengenix AI in RESEARCH MODE.

### USER QUERY:
"{user_input}"

{now_context}

### YOUR ROLE:
Research Assistant with LIVE INTERNET ACCESS via DuckDuckGo / Tavily search.

### ANTI-HALLUCINATION RULES (CRITICAL):
- You MUST call search_web before answering any live/current question.
- ONLY report facts that appear in the actual search results returned to you.
- Do NOT invent scores, results, prices, or any data.
- If search results are incomplete or unclear, say so honestly.
- Always include the source URL when citing a result.

### IMPORTANT - THIS IS NOT A SECURITY TASK:
- NO target domain/IP to scan
- NO penetration testing required
- NO 5-phase methodology
- This is simple INFORMATION RETRIEVAL for the user's question

### YOUR CAPABILITIES:
- `search_web`: Search live internet (DuckDuckGo/Tavily) for current information
- `finish`: Complete the task and provide the answer

### WHEN TO USE search_web:
- Current events, news, sports scores, weather, stock prices
- Any query with "today", "now", "latest", "วันนี้", "ล่าสุด"
- Time-sensitive information that changes constantly
- When the user asks about something happening RIGHT NOW
- Follow-up questions referencing the previous search topic (e.g. "แล้วยูฟ่าล่ะ")

### WORKFLOW (Simple):
1. Analyze what the user wants (including follow-up context from conversation history)
2. Use search_web with the most specific query including the Thai BE year if relevant
3. Summarize ONLY what the search results actually say — cite sources
4. Use finish action with the real answer

### RESPONSE FORMAT:
{{
    "thought": "User wants [topic]. This requires live data, so I'll search Google for current information...",
    "action": {{
        "type": "search_web",
        "params": {{"query": "specific search terms", "num_results": 5}}
    }},
    "next_step": "After getting search results, I will summarize them in the user's language"
}}

Or when done:
{{
    "thought": "I have the information from search results. Now I'll provide the answer.",
    "action": {{
        "type": "finish",
        "params": {{"summary": "Your answer here in the user's language"}}
    }},
    "next_step": "Task complete"
}}"""

        elif is_security_task and target:
            # Get available tools from skill registry
            available_skills = self.skill_registry.get_available_skills() if self.skill_registry else []
            missing_skills = self.skill_registry.get_missing_skills() if self.skill_registry else []
            
            available_tools = registry.list_available_tools()
            tool_descriptions = []
            for name, info in available_tools.items():
                if info.get('available'):
                    desc = info.get('description', name)
                    tool_descriptions.append(f"  - {name}: {desc}")
            
            # Add skill registry info
            available_list = "\n".join([f"  - {s.name}: {s.description}" for s in available_skills]) if available_skills else "  (No additional tools registered)"
            missing_list = "\n".join([f"  - {s.name}: {s.description} [MISSING - install: {s.install_command}]" for s in missing_skills[:5]]) if missing_skills else ""
            
            tools_list_str = "\n".join(tool_descriptions)
            
            base_prompt = f"""{self.base_prompt}

### UNIVERSAL AGENT MODE — BUG BOUNTY SPECIALIST
You are an autonomous AI security researcher. Your mission: Find vulnerabilities on {target}

{now_context}

### AVAILABLE TOOLS & CAPABILITIES:
You have access to these security tools. CHOOSE which to use based on the situation:
{tools_list_str}

### SKILL REGISTRY:
Additional tools available:
{available_list}

{"MISSING TOOLS (can request install):" + "\n" + missing_list if missing_list else ""}

### TOOL RECOMMENDATION:
If a tool is missing and would be useful, ask the user with a format like:
"Tool [name] is useful for [purpose] but not installed. Shall I install it? (Command: [install_command])"

### VULNERABILITY DISCOVERY METHODOLOGY (Apply as needed):
Think step-by-step which tools fit each phase:

**PHASE 1: RECONNAISSANCE**
- Subdomain enumeration: Use tools like subfinder, assetfinder, amass, or findomain
- DNS analysis: dnsx, dnsrecon, or dig
- Technology fingerprinting: httpx, whatweb, or webanalyze
- Choose based on: target size, rate limits, accuracy needs

**PHASE 2: PORT & SERVICE SCANNING**
- Port scanning: nmap (comprehensive), masscan (fast wide scans), or rustscan (modern fast)
- Service detection: nmap -sV or httpx for web services
- Choose based on: target scope, speed requirements, stealth needs

**PHASE 3: CONTENT DISCOVERY**
- Directory brute force: ffuf, dirsearch, gobuster, or feroxbuster
- API endpoint discovery: ffuf with wordlists or kiterunner
- Parameter discovery: arjun or x8
- Choose based on: target technology, rate limiting, wordlist size

**PHASE 4: VULNERABILITY SCANNING**
- General vuln scan: nuclei (templates), nuclei_scripts (custom)
- Specific tests: dalfox (XSS), sqlmap (SQLi), crlfuzz (CRLF)
- SSL/TLS: testssl, sslscan
- Choose based on: initial findings, vulnerability class priorities

**PHASE 5: EXPLOITATION & CHAINING**
- Manual testing support: Create custom scripts
- Report generation: Combine findings with CVSS scoring

### YOUR FULL CAPABILITIES:
You have access to ALL of these. Choose what fits the task:

**🔍 RECONNAISSANCE & SCANNING** (use `run_tool`):
- `subfinder`: Discover subdomains for a target
- `httpx`: Probe live web servers, detect technologies
- `nuclei`: Vulnerability scan with 10,000+ templates
- `naabu`: Fast port scanning
- `katana`: Web crawling & spidering
- `ffuf`: Directory & parameter fuzzing
- `dalfox`: XSS vulnerability scanning
- `arjun`: Hidden parameter discovery

**🌐 WEB RESEARCH** (use `search_web`):
- Search Google/DuckDuckGo/Tavily for live information
- Get current news, CVE details, exploit PoCs
- Research target technologies and vulnerabilities

**🔑 THREAT INTELLIGENCE** (use `cve_lookup`):
- `cve_lookup`: Search local CVE database by ID or keyword
- Example: `{{"cve_id": "CVE-2024-21626"}}` or `{{"keyword": "rce"}}`
- Returns description, CVSS score, exploit availability

**💰 BOUNTY INTELLIGENCE** (use `bounty_intel`):
- Search HackerOne programs by name
- Get bounty range, scope, program details
- Example: `{{"program": "facebook"}}`

**🔬 GITHUB OSINT** (use `github_search`):
- Search GitHub for leaked secrets, API keys, credentials
- Find exposed configuration files
- Example: `{{"query": "api_key 1win.com"}}`

**💻 SHELL & SYSTEM** (use `shell` or `run_tool`):
- `shell`: Execute any command with `{{"command": "..."}}`
- `package`: Install tools via pip, npm, apt, go
- `read_file` / `write_file`: Read and write files
- **Custom scripts**: Write Python/bash scripts with `write_file` → run with `shell python3 script.py`
  Example: write a custom exploit/PoC script and execute it immediately

### 💡 YOU HAVE THESE CAPABILITIES — use them as you see fit:
- `subfinder`, `httpx`, `nuclei`, `naabu`, `katana`, `ffuf`, `dalfox`, `arjun`: Security tools for recon, scanning, fuzzing (use `run_tool` — run multiple at once with `"tools": ["subfinder","naabu"]`)
- `search_web`: Google/DuckDuckGo — research company, find CVEs, PoCs, tech details
- `cve_lookup`: Search local CVE database by ID or keyword
- `github_search`: Find leaked secrets, credentials, configs on GitHub
- `bounty_intel`: Look up HackerOne programs
- `js_analyze`: Analyze JavaScript files for secrets, API keys, hidden endpoints
- `check_takeover`: Check if a subdomain is vulnerable to takeover
- `shell`: Run any command
- `package`: Install tools via pip, npm, apt, go
- `read_file` / `write_file`: File operations
- **Write custom scripts**: Use `write_file` to create Python/bash scripts for any testing scenario, then `shell` to run them with `python3 script.py` or `bash script.sh`

### DECISION PRINCIPLES:
1. **You decide** which tool fits the current task - no fixed sequences
2. Adapt based on results: if one tool fails, try another approach
3. Consider stealth vs speed tradeoffs
4. Chain findings: one discovery leads to focused testing with specific tools
5. Install missing tools via 'package' action

### RESPONSE FORMAT:
Always respond with structured JSON showing your reasoning:
{{
    "thought": "Based on current findings, I should use [tool] because...",
    "action": {{
        "type": "run_tool|shell|search_web|package|read_file|bounty_intel|github_search|cve_lookup|js_analyze|check_takeover|finish",
        "params": {{
            // For shell: use "command" (not tool/target)
            //   e.g. "command": "subfinder -d 1win.com"
            // For run_tool: use "tool", "target", "args"
            //   e.g. "tool": "subfinder", "target": "1win.com"
        }}
    }},
    "next_step": "Based on results, I'll likely need to..."
}}

### CURRENT CONTEXT:
Target: {target}
Intent: {intent}
"""
        else:
            # General mode with security tool knowledge
            available_tools = registry.list_available_tools()
            tool_descriptions = []
            for name, info in available_tools.items():
                if info.get('available'):
                    desc = info.get('description', name)
                    tool_descriptions.append(f"  - {name}: {desc}")
            tools_list_str = "\n".join(tool_descriptions) if tool_descriptions else "  (No specialized tools loaded)"
            
            base_prompt = f"""{self.base_prompt}

### UNIVERSAL AGENT MODE — GENERAL PURPOSE
You are a flexible AI agent with LIVE INTERNET ACCESS and system tool capabilities.

{now_context}

### AVAILABLE TOOLS (Use as needed):
{tools_list_str}

### YOUR FULL CAPABILITIES:
Choose what fits the task:

**🌐 WEB RESEARCH** (use `search_web`):
- Search Google/DuckDuckGo/Tavily for live info
- News, weather, stocks, CVE details, exploit PoCs

**🔍 SECURITY SCANNING** (use `run_tool`):
- `subfinder`: Subdomain discovery
- `httpx`: Web server probing & tech detection
- `nuclei`: Vulnerability scanning (10,000+ templates)
- `naabu`: Port scanning
- `katana`: Web crawling
- `ffuf`: Directory/parameter fuzzing
- `dalfox`: XSS scanning
- `arjun`: Parameter discovery

**🔑 THREAT INTEL** (use `cve_lookup`):
- Search CVE by ID: `{{"cve_id": "CVE-2024-21626"}}`
- Search by keyword: `{{"keyword": "rce"}}`
- Returns description, CVSS score, exploits

**💰 BOUNTY INTEL** (use `bounty_intel`):
- Search HackerOne programs: `{{"program": "facebook"}}`

**🔬 GITHUB OSINT** (use `github_search`):
- Search GitHub for secrets/keys: `{{"query": "..."}}`

**💻 SHELL & SYSTEM** (use `shell` or `run_tool`):
- Execute commands, install packages, read/write files

### RESPONSE FORMAT:
{{
    "thought": "Your reasoning about what to do and why...",
    "action": {{
        "type": "search_web|run_tool|shell|package|read_file|write_file|bounty_intel|github_search|cve_lookup|js_analyze|check_takeover|finish",
        "params": {{}}
    }},
    "next_step": "What you plan to do next"
}}

### PRINCIPLES:
- **TIME-SENSITIVE QUERIES**: Always use search_web (news, sports, weather, "today")
- **GENERAL KNOWLEDGE**: Can answer directly or search if uncertain
- **SECURITY**: Suggest or run appropriate security tools when asked
- **EXPLAIN**: Always explain your tool/action choices in reasoning
"""
        
        # Get semantic context from memory
        semantic_context = ""
        if target:
            semantic_context = get_context_for_ai(user_input, target, max_memories=10)
        
        # Execution loop - adjust max steps based on intent
        history = []
        step = 0
        # Research queries need fewer steps (search → summarize)
        # Security tasks need more steps (recon → scan → exploit)
        max_universal_steps = 5 if (intent == "research" and not target) else 50
        empty_shell_count = 0
        
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

Rules:
1. Do not use emojis.
2. Never output an action of type 'shell' with an empty command.

Analyze the request and determine the next action.
If this is a complex multi-step task, break it down.
If you need to install tools, use package action.
If you need to create scripts, use write_file.
If the task is complete, use finish action.

Respond ONLY with valid JSON."""
            
            # Get AI decision
            response = (self.client.chat([
                AIMessage(role="system", content=full_prompt),
                AIMessage(role="user", content=f"Universal step {step}")
            ]).content or "")
            
            try:
                action_data = _extract_json_object(response)
                if action_data is None:
                    action_data = {"action": {"type": "finish", "params": {}}, "thought": response}

                if isinstance(action_data, str):
                    try:
                        action_data = json.loads(action_data)
                    except Exception:
                        action_data = {"action": {"type": "finish", "params": {}}, "thought": response}

                if not isinstance(action_data, dict):
                    action_data = {"action": {"type": "finish", "params": {}}, "thought": str(action_data)}
                
                action = action_data.get("action", {})
                if not isinstance(action, dict):
                    action = {"type": "finish", "params": {"summary": str(action)}}
                action_type = action.get("type", "finish")
                params = action.get("params", {})
                if not isinstance(params, dict):
                    params = {"summary": str(params)}
                thought = action_data.get("thought", "No reasoning provided")
                
                # Log thought
                logger.info(f"Step {step}: {thought[:100]}...")
                if callback:
                    callback(f" Step {step}: {thought[:80]}...")
                
                #  Remember the thought
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
                # Score findings in history with CVSS
                scored = []
                for h in history:
                    if h.get("success") and "findings" in h.get("result", "").lower():
                        from tools.cvss_calculator import CVSSCalculator
                        calc = CVSSCalculator(use_ai=False)
                        score = calc.from_finding(h.get("action", "unknown"), target or "", h.get("result", "")[:200])
                        scored.append(f"  [{score.severity.value:10s}] CVSS {score.base_score:.1f} — {h.get('action','')[:60]}")
                if scored and callback:
                    callback("### CVSS SCORES:\n" + "\n".join(scored))
                # Auto-export report
                if scored and target:
                    report_path = Path(f"reports/scan_{target}_{int(time.time())}.md")
                    report_path.parent.mkdir(parents=True, exist_ok=True)
                    report_lines = [
                        f"# Scan Report: {target}",
                        f"**Date**: {datetime.now(timezone.utc).isoformat()}",
                        f"**Summary**: {summary}",
                        "",
                        "## Findings",
                    ]
                    for s in scored:
                        report_lines.append(s)
                    report_lines.append(f"\n\n*Generated by Elengenix v99999*")
                    report_path.write_text("\n".join(report_lines), encoding="utf-8")
                    if callback:
                        callback(f"Report saved: {report_path}")
                # Store this exchange in session history
                self._append_history("user", user_input)
                self._append_history("assistant", summary)
                if scored:
                    summary += "\n\nCVSS Scores:\n" + "\n".join(scored)
                return summary

            if action_type == "shell":
                cmd = (params.get("command") or "").strip()
                if not cmd:
                    tool = (params.get("tool") or "").strip()
                    target_val = (params.get("target") or target or "").strip()
                    if tool:
                        cmd = tool
                        if target_val:
                            cmd += f" -d {target_val}" if "subfinder" in tool else f" {target_val}"
                    else:
                        empty_shell_count += 1
                        if callback:
                            callback(" shell: Empty command blocked. Use shell with a command param.")
                        history.append({
                            "step": step,
                            "action": "shell: <empty>",
                            "result": "Blocked empty command. Use shell with: {\"command\": \"your command here\"}",
                            "success": False,
                        })
                        if empty_shell_count >= 5:
                            return "Too many empty shell commands. Try using 'run_tool' with tool name and target, or 'shell' with a real command like subfinder -d target.com"
                        continue

                # Governance gate for shell commands
                gate = self.governance.classify_risk({"command": cmd})
                if gate == "DESTRUCTIVE":
                    if callback:
                        callback(f"[BLOCKED] Destructive command: {cmd[:80]}")
                    history.append({
                        "step": step, "action": f"shell: {cmd[:80]}",
                        "result": "Blocked by governance: destructive command.", "success": False,
                    })
                    continue
                elif gate == "PRIVILEGED":
                    if callback:
                        callback(f"__PRIVILEGED__:{cmd[:200]}")
                    # Ask user directly
                    try:
                        print(f"\n[PRIVILEGED] AI wants to run:")
                        print(f"  {cmd[:200]}")
                        ans = input("Allow? [y/N]: ").strip().lower()
                        if ans not in ("y", "yes"):
                            history.append({
                                "step": step, "action": f"shell: {cmd[:80]}",
                                "result": "Rejected by user.", "success": False,
                            })
                            continue
                    except Exception:
                        history.append({
                            "step": step, "action": f"shell: {cmd[:80]}",
                            "result": "Skipped (non-interactive).", "success": False,
                        })
                        continue
            
            # Execute via universal executor
            result = executor.execute_action({"type": action_type, "params": params})
            
            # Store in history
            history.append({
                "step": step,
                "action": f"{action_type}: {json.dumps(params)[:100]}",
                "result": result.output if result.success else result.error,
                "success": result.success
            })
            
            # Callback — show actual command executed
            if callback:
                status = "[OK]" if result.success else "[FAIL]"
                cmd_preview = ""
                if action_type == "shell":
                    cmd_preview = params.get("command", "")[:80]
                elif action_type == "run_tool":
                    t = params.get("tool", "")
                    tg = params.get("target", "")
                    cmd_preview = f"{t} {tg}"[:80] if t else params.get("tools", str(params))[:80]
                elif action_type == "search_web":
                    cmd_preview = params.get("query", "")[:80]
                elif action_type == "cve_lookup":
                    cmd_preview = params.get("cve_id", "") or params.get("keyword", "")
                cmd_tag = f" [{cmd_preview}]" if cmd_preview else ""
                if action_type == "search_web":
                    preview = (result.output if result.success else result.error)[:300]
                else:
                    preview = (result.output if result.success else result.error)[:150]
                callback(f"{status} {action_type}{cmd_tag}: {preview}")
            
            #  Remember important results
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
