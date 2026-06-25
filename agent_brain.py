"""
agent_brain.py — Elengenix Intelligent Hunting Engine
- Strategic Planning Module (Attack Tree Generation)
- Chain of Thought Logging
- Tool Selection Intelligence
- High-security Subprocess Execution (Shell=False + Strict Allowlist)
"""

import os
import json
import re
import time
import asyncio
import logging
from pathlib import Path
from collections import Counter
from typing import Optional, Callable, Dict, Any, List

# Core imports (always needed)
from tools.universal_ai_client import AIClientManager, AIMessage
from tools.tool_registry import registry, ToolResult
from tools.cvss_calculator import CVSSCalculator
from tools.governance import Governance, GateDecision
from live_display import get_activity_logger, display_in_chat_mode
from bot_utils import send_telegram_notification

# Lazy imports (deferred until needed)
_vector_memory = None
_memory_persistence = None
_cve_database = None
_mission_state = None
_logic_analyzer = None
_payload_mutation = None
_agent_reflection = None
_smart_orchestrator = None
_hybrid_agent = None


def _get_vector_memory():
    global _vector_memory
    if _vector_memory is None:
        from tools import vector_memory
        _vector_memory = vector_memory
    return _vector_memory


def _get_memory_persistence():
    global _memory_persistence
    if _memory_persistence is None:
        from tools import memory_persistence
        _memory_persistence = memory_persistence
    return _memory_persistence


def _get_cve_database():
    global _cve_database
    if _cve_database is None:
        from tools import cve_database
        _cve_database = cve_database
    return _cve_database


def _get_mission_state():
    global _mission_state
    if _mission_state is None:
        from tools import mission_state
        _mission_state = mission_state
    return _mission_state


logger = logging.getLogger("elengenix.agent")

# ── Re-export shared helpers from agents/ modules ──────────────────────
from agents.agent_helpers import (
    _get_now_context,
    _extract_target_from_text,
    _safe_operation,
)
from agents.agent_dataclasses import AttackTree
from agents.agent_planner import StrategicPlanner
from agents.agent_logger import ChainOfThoughtLogger
from agents.agent_executor import (
    execute_tool,
    execute_tool_registry,
    execute_tool_subprocess,
    handle_ask_user,
)
from agents.agent_intent import analyze_intent as _analyze_intent
from agents.agent_conversation import ConversationManager
from agents.agent_modes import ModeProcessor


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
    @staticmethod
    def _get_shared_loop():
        from tools.event_loop import get_shared_loop
        return get_shared_loop()

    def __init__(
        self,
        max_steps: int = 25,
        loop_threshold: int = 3,
        history_limit: int = 5,
        max_output_len: int = 2000,
        enable_planning: bool = True,
        enable_cot_logging: bool = True,
        max_history_turns: int = 20,
        verbose_thoughts: bool = True
    ):
        self.client = AIClientManager()

        # ── TeamAegis v2: per-role AI clients ───────────────────────────────────
        # Reads config.yaml team_aegis section. Falls back to self.client if not set.
        self._team_aegis_clients = self._init_team_aegis_clients()
        self.max_steps = max_steps
        self.loop_threshold = loop_threshold
        self.history_limit = history_limit
        self.max_output_len = max_output_len
        self.enable_planning = enable_planning
        self.enable_cot_logging = enable_cot_logging
        self.max_history_turns = max_history_turns
        self.verbose_thoughts = verbose_thoughts
        
        #  Conversation Manager (handles history, persistence, summarization)
        self.conversation_manager = ConversationManager(
            client=self.client,
            max_history_turns=max_history_turns,
            history_limit=history_limit,
        )
        # Backward compatibility: expose conversation_history directly
        self.conversation_history = self.conversation_manager.conversation_history
        
        #  Mode Processor (handles universal, hybrid, team modes)
        self.mode_processor = ModeProcessor(
            client=self.client,
            governance=None,  # Set after governance is initialized
            cvss_calc=None,   # Set after cvss_calc is initialized
            cve_db=None,      # Set after cve_db is initialized
        )
        
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

        #  Tech-stack fingerprint cache: target -> {fingerprint, probed_at}
        #  Populated by _fingerprint_target_for_planning() before each
        #  attack tree generation, so the planner sees the detected stack
        #  instead of relying purely on the AI prompt.
        self._fingerprint_cache: Dict[str, Dict[str, Any]] = {}
        
        #  CVE Database
        self.cve_db = _get_cve_database().get_cve_database(auto_update=False)
        
        #  System Prompt Enhancement with CVE context
        self._enhance_prompt_with_cve_context()

        #  Governance (HITL for high-risk steps)
        self.governance = Governance(require_approval_high_risk=True)

        #  Business Logic / AuthZ Analyzer (lazy)
        self._logic_analyzer = None

        #  Payload Mutation Engine (lazy)
        self._payload_mutator = None
        self.smart_payload_generator = None

        #  M5: Active Fuzzing Harness — sends real payloads to live targets
        #  and measures response deltas. This is what makes fuzzing ACTUAL
        #  (vs just generating candidates).
        try:
            from tools.active_fuzzer import ActiveFuzzer
            self.active_fuzzer = ActiveFuzzer()
        except Exception as e:
            logger.debug(f"ActiveFuzzer unavailable: {e}")
            self.active_fuzzer = None

        #  M6: Coverage Analyzer — tracks every endpoint/param/method tested
        #  so we can answer "what did we actually test?" honestly.
        try:
            from tools.coverage_analyzer import CoverageAnalyzer
            self.coverage_analyzer = CoverageAnalyzer()
        except Exception as e:
            logger.debug(f"CoverageAnalyzer unavailable: {e}")
            self.coverage_analyzer = None

        #  M7: Cross-Session Learning — remembers what worked on past
        #  targets and suggests tools/payloads with high success rate
        #  for the current tech stack.
        try:
            from tools.learning_engine import LearningEngine
            self.learning_engine = LearningEngine(use_chroma=False)
        except Exception as e:
            logger.debug(f"LearningEngine unavailable: {e}")
            self.learning_engine = None

        #  M8: BOLA / IDOR Tester — replays requests with two sessions
        #  to detect broken object-level authorization.
        try:
            from tools.bola_tester import BOLATester
            self.bola_tester = BOLATester()
        except Exception as e:
            logger.debug(f"BOLATester unavailable: {e}")
            self.bola_tester = None

        #  M9: Smart WAF Detector — probe-based detection that identifies
        #  Cloudflare / ModSecurity / AWS WAF etc. and suggests evasions.
        try:
            from tools.waf_detector import SmartWAFDetector
            self.waf_detector = SmartWAFDetector()
        except Exception as e:
            logger.debug(f"SmartWAFDetector unavailable: {e}")
            self.waf_detector = None

        #  Agent Reflection / Self-Feedback Tracker
        self.reflection_tracker = get_reflection()

        #  Smart Orchestrator (Upgraded Scan Engine) - lazy import
        self._smart_orchestrator = None

        #  Analysis Pipeline (13+ post-finding analyzers)
        try:
            from tools.analysis_pipeline import AnalysisPipeline
            self.analysis_pipeline = AnalysisPipeline(self)
        except Exception as e:
            logger.warning(f"Failed to initialize centralized AnalysisPipeline: {e}")
            self.analysis_pipeline = None

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

        #  Wire up mode processor with initialized dependencies
        self.mode_processor.governance = self.governance
        self.mode_processor.cvss_calc = self.cvss_calc
        self.mode_processor.cve_db = self.cve_db

        # Load persistent conversation from SQLite (cross-session memory)
        self.conversation_manager.load_persistent_conversation()

    @property
    def logic_analyzer(self):
        """Lazy-initialize BusinessLogicAnalyzer on first access."""
        if self._logic_analyzer is None:
            from tools.logic_analyzer import BusinessLogicAnalyzer
            self._logic_analyzer = BusinessLogicAnalyzer()
        return self._logic_analyzer

    @property
    def payload_mutator(self):
        """Lazy-initialize PayloadMutator on first access."""
        if self._payload_mutator is None:
            from tools.payload_mutation import PayloadMutator
            self._payload_mutator = PayloadMutator()
        return self._payload_mutator

    @property
    def smart_orchestrator(self):
        """Lazy-initialize SmartOrchestrator on first access."""
        if self._smart_orchestrator is None:
            from scan_engine_upgrade import SmartOrchestrator
            self._smart_orchestrator = SmartOrchestrator(max_concurrency=5)
        return self._smart_orchestrator

    def _fingerprint_target_for_planning(
        self,
        target: str,
        max_probe_seconds: int = 8,
    ) -> Optional[Dict[str, Any]]:
        """Probe the target with a lightweight HTTP request and return a
        tech-stack fingerprint dict suitable for planner.generate_attack_tree.

        Uses the ``TargetFingerprinter`` from ``agents.agent_planner``.
        The result is cached in ``self._fingerprint_cache`` so repeated
        planning calls don't re-probe.

        Returns ``None`` if probing fails (network down, invalid target).
        """
        if not target:
            return None
        # Cache hit
        cached = self._fingerprint_cache.get(target)
        if cached is not None:
            return cached

        # Only probe http(s) targets; skip bare hostnames / IP-only inputs
        probe_url = target
        if not probe_url.startswith(("http://", "https://")):
            probe_url = "http://" + probe_url

        try:
            import requests
            resp = requests.get(
                probe_url,
                timeout=max_probe_seconds,
                allow_redirects=True,
                verify=False,  # many bug-bounty hosts have broken certs
            )
            headers = {k: v for k, v in resp.headers.items()}
            cookies: Dict[str, str] = {}
            for c in resp.cookies:
                if c.value is not None:
                    cookies[c.name] = c.value
            body_sample = (resp.text or "")[:8192]
        except Exception as e:
            logger.debug(f"Pre-plan fingerprint probe failed for {target}: {e}")
            return None

        try:
            from agents.agent_planner import TargetFingerprinter
            fp = TargetFingerprinter().fingerprint(
                headers=headers,
                body=body_sample,
                cookies=cookies,
                url=probe_url,
            )
        except Exception as e:
            logger.warning(f"Fingerprinter failed for {target}: {e}")
            return None

        # Cache and log
        self._fingerprint_cache[target] = fp
        techs = ", ".join(fp.get("technologies", [])) or "none"
        logger.info(
            f"[Fingerprint] {target} -> server={fp.get('server')} "
            f"lang={fp.get('language')} cms={fp.get('cms')} "
            f"db={fp.get('db')} techs=[{techs}]"
        )
        if self.activity_logger:
            try:
                self.activity_logger.log_thought(
                    f"Fingerprint: server={fp.get('server')} "
                    f"lang={fp.get('language')} cms={fp.get('cms')}",
                    step=0,
                )
            except Exception:
                pass
        return fp

    def _init_team_aegis_clients(self) -> dict:
        """Initialize per-role AI clients for TeamAegis v2 from config.

        Reads config.yaml team_aegis section:
          team_aegis:
            enabled: true
            strategist:
              provider: gemini
              model: gemini-2.0-flash
            specialist:
              provider: anthropic
              model: claude-3-5-haiku-20241022
            critic:
              provider: openai
              model: gpt-4o-mini

        Returns:
            Dict with keys: strategist_client, specialist_client, critic_client,
            strategist_label, specialist_label, critic_label, enabled.
        """
        defaults = {
            "enabled": False,
            "strategist_client": None,
            "specialist_client": None,
            "critic_client": None,
            "strategist_label": "Strategist AI",
            "specialist_label": "Specialist AI",
            "critic_label": "Critic AI",
        }

        try:
            import yaml
            config_path = Path(__file__).parent / "config.yaml"
            if not config_path.exists():
                return defaults

            with open(config_path, encoding="utf-8") as fh:
                config = yaml.safe_load(fh) or {}

            ta = config.get("team_aegis", {})
            if not ta.get("enabled", False):
                return defaults

            result = {"enabled": True}

            for role in ("strategist", "specialist", "critic"):
                role_cfg = ta.get(role, {})
                provider = role_cfg.get("provider", "")
                model = role_cfg.get("model", "")

                if provider:
                    client = AIClientManager(preferred_order=[provider])
                    if model and client.active_client:
                        client.active_client.model = model
                    result[f"{role}_client"] = client
                    result[f"{role}_label"] = model or provider
                else:
                    result[f"{role}_client"] = None
                    result[f"{role}_label"] = f"{role.capitalize()} AI"

            return {**defaults, **result}

        except Exception as exc:
            logger.debug(f"[TeamAegis] Config load failed: {exc}")
            return defaults


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
                pass
            else:
                pass

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
        self.conversation_manager.append_history(role, content)
        # Sync the backward-compatible reference
        self.conversation_history = self.conversation_manager.conversation_history
    
    def _persist_recent_conversation(self) -> None:
        """Save recent conversation turns to vector memory for long-term recall."""
        self.conversation_manager._persist_recent_conversation()
    
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
        return self.conversation_manager.build_chat_messages(system_prompt, user_input)

    def clear_conversation_history(self) -> None:
        """
        Clear the in-session conversation history.
        Call this when the user runs /clear to start fresh.
        """
        self.conversation_manager.clear()
        self.conversation_history = self.conversation_manager.conversation_history

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
        return execute_tool(
            action_data, self.governance, self.max_output_len, callback,
        )

    def _handle_ask_user(self, action_data: Dict[str, Any], callback: Optional[Callable] = None) -> str:
        return handle_ask_user(action_data, callback)

    def _execute_tool_registry(
        self,
        tool_name: str,
        target: str,
        report_dir: Path,
        semaphore: Optional[asyncio.Semaphore] = None,
    ) -> ToolResult:
        return execute_tool_registry(
            tool_name, target, report_dir, self._get_shared_loop, semaphore,
        )

    def _execute_tool_subprocess(self, tool_name: str, target: str) -> ToolResult:
        return execute_tool_subprocess(tool_name, target)

    def _analyze_intent(self, query: str) -> str:
        return _analyze_intent(self.client, query)

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
        remember(
            f"Started mission: {user_input}. Target: {target or 'general'}",
            target or "global",
            "mission_start",
            session_type="ai_chat"
        )
        
        #  STRATEGIC PLANNING PHASE
        if self.enable_planning and target:
            # ── W2: probe target with a lightweight HTTP request to get a
            #    tech-stack fingerprint, then pass it to the planner so the
            #    attack tree is built from the detected stack rather than
            #    purely from the AI prompt.
            fingerprint = self._fingerprint_target_for_planning(target)
            try:
                self.current_tree = self.planner.generate_attack_tree(
                    target,
                    objective=user_input,
                    fingerprint=fingerprint,
                )
            except TypeError:
                # Backward compat: older planner signatures don't accept fingerprint
                self.current_tree = self.planner.generate_attack_tree(
                    target,
                    objective=user_input,
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
                reasoning = f"{current_step.purpose}"
            else:
                #  AI-driven dynamic planning with SEMANTIC MEMORY
                
                # Retrieve context from Vector Memory (remembers across sessions)
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
                
                #  SEMANTIC SEARCH: find memories similar to current problem
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
2. What shell command would be most effective now? (Think freely — use pipes, redirects, scripting)
3. Do you need to research a vulnerability or tech stack? Use web_search.
4. Have you found any vulnerabilities? Use submit_findings to report them IMMEDIATELY!
5. Is a tool missing? Use ask_user to request installation.

Use JSON format: {{"action": "run_shell|ask_user|web_search|submit_findings|save_memory|finish", "command": "...", "query": "...", "findings": [...], "purpose": "...", "question": "..."}}"""

                from ui_components import show_spinner
                with show_spinner("AI Agent is planning its next move...", spinner_style="#ffffff"):
                    response_text = self.client.chat([
                        AIMessage(role="system", content=full_prompt),
                        AIMessage(role="user", content="Plan next action")
                    ]).content
                action_data = self._extract_json(response_text) or {}
                reasoning = action_data.get('purpose', 'continue investigation')
            
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
                
            if self.verbose_thoughts and reasoning:
                display_in_chat_mode(f"[Thought] {reasoning}", "thought")
            
            # Action Validation
            action_val = action_data.get("action", "")
            if isinstance(action_val, dict):
                params = action_val.get("params", {})
                if isinstance(params, dict):
                    action_data.update(params)
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
                remember(
                    action_data.get("learning", ""),
                    action_data.get("target", "global"),
                    action_data.get("category", "general"),
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
            
            #  EXECUTION via Tool Registry or Submit Findings
            tool_name = action_data.get("tool", "")
            skip_execution = False
            result = None

            if action == "submit_findings":
                tool_name = "ai_manual_analysis"
                skip_execution = True
                
                findings_data = action_data.get("findings", [])
                if not isinstance(findings_data, list):
                    findings_data = [findings_data]
                
                from tools.tool_registry import ToolResult, ToolCategory
                result = ToolResult(
                    success=True,
                    tool_name=tool_name,
                    category=ToolCategory.VULNERABILITY,
                    findings=findings_data,
                    error_message=""
                )
                purpose = action_data.get("purpose", "Reporting manually discovered findings")
                
                if callback:
                    callback(f" Reporting {len(findings_data)} findings to system...")
                display_in_chat_mode(f"AI reported {len(findings_data)} findings.", "success")
                
                # Note: We still want to run the analysis pipeline and update mission graph!

            if tool_name:
                if not skip_execution:
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

                _safe_operation(
                    "MissionState ledger write",
                    mission_state.add_ledger_entry,
                    entry_id=f"tool:{step}:{tool_name}",
                    kind="tool_execution",
                    tool=tool_name,
                    action={"tool": tool_name, "purpose": purpose, "target": target or user_input},
                    result={"success": result.success, "findings_count": len(result.findings), "error": result.error_message},
                )
                
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
                    ftype = finding.get("type", "unknown")
                    furl = finding.get("url", "") or finding.get("subdomain", "") or finding.get("host", "")
                    node_id = furl or f"finding:{tool_name}:{step}:{i}"
                    
                    _safe_operation(
                        "MissionState upsert_node",
                        mission_state.upsert_node,
                        GraphNode(
                            node_id=node_id,
                            node_type="finding",
                            props={
                                "type": ftype,
                                "severity": finding.get("severity"),
                                "tool": tool_name,
                                "raw": finding,
                            },
                        ),
                    )
                    _safe_operation(
                        "MissionState upsert_edge",
                        mission_state.upsert_edge,
                        GraphEdge(
                            edge_id=f"edge:{mission_state.target}:{node_id}:{tool_name}:{step}:{i}",
                            src_id=mission_state.target,
                            dst_id=node_id,
                            edge_type="has_finding",
                            props={"tool": tool_name},
                        ),
                    )
                    _safe_operation(
                        "MissionState add_fact",
                        mission_state.add_fact,
                        fact_id=f"fact:{tool_name}:{step}:{i}",
                        category="finding",
                        statement=f"{tool_name} reported {ftype} at {furl or 'unknown'} (severity={finding.get('severity','unknown')})",
                        confidence=0.6,
                        evidence={"tool": tool_name, "finding": finding},
                    )

                # ── ANALYSIS PIPELINE (13 analyzers) ─────────────────────
                if self.analysis_pipeline:
                    self.analysis_pipeline.run_all(
                        result=result,
                        tool_name=tool_name,
                        target=target,
                        step=step,
                        mission_key=mission_key,
                        mission_state=mission_state,
                        callback=callback,
                    )
                else:
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
        
        # Build team clients using ai_config (single source of truth)
        from tools.ai_config import parse_active_models, _KNOWN_PROVIDER_PREFIXES
        team_clients = []

        # If model_names is empty, use config.yaml active_models
        if not model_names:
            model_names = [f"{p}/{m}" for p, m in parse_active_models()]

        for model_str in model_names:
            try:
                # Parse "provider/model" — but NVIDIA models can have '/' in name
                # Use ai_config's known prefixes to detect Format B
                provider = None
                model_name = model_str
                if "/" in model_str:
                    first, rest = model_str.split("/", 1)
                    if first.lower() in _KNOWN_PROVIDER_PREFIXES:
                        provider = first.lower()
                        model_name = rest

                # Create a fresh client — ai_config will fill in base_url/api_key
                if provider:
                    new_client = UniversalAIClient(provider=provider, model=model_name)
                else:
                    # No provider prefix — use active_provider from config.yaml
                    from tools.ai_config import get_active_provider
                    new_client = UniversalAIClient(
                        provider=get_active_provider(),
                        model=model_name,
                    )
                if new_client.is_available():
                    team_clients.append(new_client)
                    logger.info(f"Team member added: {new_client.provider} / {new_client.model}")
                else:
                    logger.warning(
                        f"Skipped team member {provider or 'active'}/{model_name}: "
                        f"client not available (no API key?)"
                    )
            except Exception as e:
                logger.warning(f"Failed to load team client {model_str}: {e}")
        
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
        mode: str = "auto",
        preflight_findings: Optional[List[Dict]] = None,
    ) -> str:
        """Universal mode — delegates to agents/agent_universal.py.

        Args:
            preflight_findings: Optional list of finding dicts from
                `run_elengenix_modules()`. When provided, these are injected
                as context so the AI focuses on confirming vulnerabilities
                rather than re-discovering what the framework already found.
        """
        if check_context := getattr(self, "_check_context_overflow", None):
            check_context()

        return self.mode_processor.process_universal(
            user_input=user_input,
            conversation_history=self.conversation_history,
            base_prompt=self.base_prompt,
            callback=callback,
            target=target,
            mode=mode,
            preflight_findings=preflight_findings,
        )

    def process_hybrid(
        self,
        user_input: str,
        callback: Optional[Callable] = None,
        target: str = "",
        mode: str = "auto",
    ) -> str:
        """
        HYBRID MODE — Combines redteam_agent's flexible AI-driven shell execution
        with Elengixen's structured AnalysisPipeline and ToolRegistry.

        Strategist (AI 1) plans at a high level.
        Specialist (AI 2) executes actions in a loop with full shell freedom.
        Results feed into 13 analyzers, CVSS, MissionState, and VectorMemory.
        """
        # 1. Classify intent (reuse existing AI classifier)
        try:
            intent = self._analyze_intent(user_input)
        except Exception as e:
            logger.debug(f"Intent classification failed: {e}")
            intent = "security_chat"

        if callback:
            callback(f"AI classified intent as: {intent.upper()}")

        # 2. Non-mission queries go to universal handler
        if intent in ("casual", "research", "security_chat") and not target:
            return self.process_universal(
                user_input, callback=callback, target=target, mode=mode
            )

        # 3. Extract target if needed
        if not target and intent == "scan":
            inferred = _extract_target_from_text(user_input)
            if inferred:
                target = inferred

        if not target:
            return "No target specified. Use 'hunt <target>' or provide a domain/IP."

        return self.mode_processor.process_hybrid(
            user_input=user_input,
            callback=callback,
            target=target,
            mode=mode,
            team_aegis_clients=self._team_aegis_clients,
        )

    def _activity_log(self, msg: str, callback: Optional[Callable] = None):
        """Log activity and optionally notify callback."""
        logger.info(msg)
        if callback:
            try:
                safe = re.sub(r"\[/?[^\]]+\]", "", str(msg))
                callback(safe[:200])
            except Exception:
                pass

    def resume_mission(
        self,
        mission_id: str,
        callback: Optional[Callable] = None,
        use_smart_scan: bool = False,
    ) -> str:
        """Resume a previously interrupted mission from its MissionState ledger.

        Loads past state and findings, recovers the strategic attack tree, and continues
        from the next uncompleted step.
        """
        from tools.mission_state import open_mission, _get_conn, _uj, _now
        mission_state = open_mission(mission_id)
        if not mission_state:
            return f"Error: Mission '{mission_id}' not found in database."

        target = mission_state.target
        objective = mission_state.objective

        if callback:
            callback(f"Resuming mission: {mission_id}")
            callback(f"Target: {target} | Objective: {objective}")

        # Fetch ledger history from DB
        ledger_entries = []
        try:
            with _get_conn() as conn:
                rows = conn.execute(
                    "SELECT tool, action_json, result_json, ts FROM ledger WHERE mission_id = ? ORDER BY ts ASC",
                    (mission_id,),
                ).fetchall()
                for r in rows:
                    ledger_entries.append({
                        "tool": r[0],
                        "action": _uj(r[1]),
                        "result": _uj(r[2]),
                        "ts": r[3]
                    })
        except Exception as e:
            logger.warning(f"Could not load mission ledger: {e}")

        completed_steps_count = len(ledger_entries)
        if callback:
            callback(f"Recovered {completed_steps_count} previously executed ledger steps.")

        # Re-initialize the strategic attack tree
        if self.enable_planning and target:
            # ── W2: also re-fingerprint on resume so a previously-unseen
            #    target stack is still discovered even when the mission
            #    ledger is partially populated.
            fingerprint = self._fingerprint_target_for_planning(target)
            try:
                self.current_tree = self.planner.generate_attack_tree(
                    target, objective=objective, fingerprint=fingerprint
                )
            except TypeError:
                self.current_tree = self.planner.generate_attack_tree(
                    target, objective=objective
                )
            # Mark completed steps as completed in tree
            for i, entry in enumerate(ledger_entries):
                if self.current_tree and i < len(self.current_tree.steps):
                    self.current_tree.steps[i].completed = True

        # Now launch standard process_query scan loop but skipping completed steps
        # Setup report directory
        safe_target = target.replace('.', '_') if target else "global"
        report_dir = Path("reports") / f"agent_{safe_target}_resumed_{int(time.time())}"
        report_dir.mkdir(parents=True, exist_ok=True)

        action_history = [e["action"] for e in ledger_entries]
        previous_results = []
        for e in ledger_entries:
            res_data = e["result"] or {}
            # Reconstruct dummy ToolResult for context
            try:
                from tools.tool_registry import ToolResult, ToolCategory
                dummy_res = ToolResult(
                    success=res_data.get("success", True),
                    tool_name=e["tool"] or "shell",
                    category=ToolCategory.UTILITY,
                    output=res_data.get("output", ""),
                    findings=res_data.get("findings", []),
                    error_message=res_data.get("error_message", ""),
                )
                previous_results.append(dummy_res)
            except Exception:
                pass

        # Update status
        mission_state.resume_mission()

        # Execute remaining steps
        start_step = min(completed_steps_count, self.max_steps - 1)
        if start_step >= self.max_steps:
            return f"Mission '{mission_id}' is already fully completed (executed {completed_steps_count} steps)."

        display_in_chat_mode(f"Resuming scan starting at step {start_step + 1}", "system")

        # Reuse execution loop of process_query starting from start_step
        for step in range(start_step, self.max_steps):
            # Determine next action
            if self.current_tree and step < len(self.current_tree.steps):
                current_step = self.current_tree.steps[step]
                tool_name = current_step.tool_name
                action_data = {
                    "action": "run_shell",
                    "command": f"{tool_name} {target}",
                    "tool": tool_name,
                    "purpose": current_step.purpose,
                }
                reasoning = f"{current_step.purpose}"
            else:
                semantic_context = get_context_for_ai(objective, target=target, max_memories=5)
                now_context = _get_now_context()
                prompt = f"""You are the dynamic specialist. Decide the next scanning action.
Objective: {objective}
Target: {target}
Step: {step + 1}/{self.max_steps}

{now_context}
{semantic_context}

Return a single JSON block representing the action. Example:
{{"action": "run_shell", "command": "nuclei -t cves/ -u {target}", "tool": "nuclei", "purpose": "Vulnerability scan"}}"""
                messages = [
                    AIMessage(role="system", content=prompt),
                    AIMessage(role="user", content=f"Last results: {[r.tool_name for r in previous_results[-3:]]}")
                ]
                res_content = (self.client.chat(messages).content or "").strip()
                action_data = self._extract_json(res_content) or {"action": "finish", "purpose": "Scan completed"}
                reasoning = action_data.get("purpose", "Dynamic execution")

            if action_data.get("action") == "finish":
                break

            display_in_chat_mode(f"Step {step+1}: {reasoning}", "thought")

            # Execute tool safely
            if callback:
                callback(f"Executing: {action_data.get('command')}")
            
            tool_name = action_data.get("tool", "shell")
            result_str = self._execute_tool(action_data, callback)

            # Reconstruct structured result
            from tools.tool_registry import ToolResult, ToolCategory
            dummy_findings = []
            if "finding" in result_str.lower() or "vuln" in result_str.lower():
                dummy_findings.append({"title": "Discovered vulnerability", "severity": "medium", "evidence": result_str})

            res_obj = ToolResult(
                success=True,
                tool_name=tool_name,
                category=ToolCategory.UTILITY,
                output=result_str[:self.max_output_len],
                findings=dummy_findings,
            )

            # Record finding to database
            mission_state.add_ledger_entry(
                entry_id=f"entry:{tool_name}:{step}",
                kind="tool_execution",
                tool=tool_name,
                action=action_data,
                result={"success": True, "output": result_str[:400], "findings": dummy_findings}
            )

            # Trigger analysis pipeline
            if self.analysis_pipeline:
                self.analysis_pipeline.run_all(
                    result=res_obj,
                    tool_name=tool_name,
                    target=target,
                    step=step,
                    mission_key=mission_id,
                    mission_state=mission_state,
                    callback=callback,
                )

            previous_results.append(res_obj)

        mission_state.touch()
        # Set to completed state
        try:
            with _get_conn() as conn:
                conn.execute(
                    "UPDATE missions SET status = 'completed', updated_at = ? WHERE mission_id = ?",
                    (_now(), mission_id),
                )
        except Exception:
            pass

        return f"Resumed mission '{mission_id}' completed successfully."