"""
multi_agent.py — Team Aegis: Multi-Agent Collaboration Engine (v99999 (god nine is the best))

Enables up to 3 AI models to work as a team during security scanning.
Agents communicate through a shared discussion board, assign tasks,
share tool results, debate strategies, and collaboratively build
custom tools to find vulnerabilities.

Architecture:
    Round-Table Discussion → Task Assignment → Parallel Execution →
    Results Sharing → Collaborative Analysis → Repeat until done

Author: Elengenix Project
"""

import os
import json
import time
import logging
import threading
import concurrent.futures
from typing import List, Dict, Any, Optional, Callable
from dataclasses import dataclass, field
from heapq import heappush, heappop

from tools.universal_ai_client import UniversalAIClient, AIMessage, AIResponse

# Try to import skill registry
try:
    from tools.skill_registry import get_skill_registry, recommend_tools_for_scenario
    SKILL_REGISTRY_AVAILABLE = True
except ImportError:
    SKILL_REGISTRY_AVAILABLE = False
    def get_skill_registry(): return None
    def recommend_tools_for_scenario(s): return []

logger = logging.getLogger("elengenix.team_aegis")


# ---------------------------------------------------------------------------
# Data Structures
# ---------------------------------------------------------------------------

@dataclass
class TeamMessage:
    """A single message in the team discussion."""
    round: int
    agent_id: int
    agent_role: str
    model_name: str
    content: str
    timestamp: float = field(default_factory=time.time)
    msg_type: str = "discussion"  # discussion, task_result, proposal, consensus


@dataclass  
class TaskAssignment:
    """A task assigned to a specific agent during execution."""
    agent_id: int
    action_type: str      # shell, run_tool, search_web, write_file
    params: Dict[str, Any]
    description: str
    result: Optional[str] = None
    success: bool = False
    completed: bool = False


@dataclass
class Finding:
    """A confirmed vulnerability or interesting discovery."""
    source_agent: str
    description: str
    severity: str = "info"     # critical, high, medium, low, info
    evidence: str = ""
    confirmed_by: List[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Agent Roles
# ---------------------------------------------------------------------------

AGENT_ROLES = [
    {
        "name": "Strategist",
        "icon": "S",
        "focus": "Attack planning, prioritization, vulnerability analysis, CVSS scoring",
        "personality": (
            "You are the team leader. You create the overall attack plan, "
            "assign tasks to teammates, and prioritize which areas to investigate. "
            "When teammates report results, you decide what to do next. "
            "You have a broad view of the entire engagement."
        ),
    },
    {
        "name": "Recon Lead",
        "icon": "R",
        "focus": "Subdomain enumeration, port scanning, content discovery, OSINT",
        "personality": (
            "You are the reconnaissance specialist. You run scanning tools "
            "(subfinder, httpx, naabu, ffuf, arjun) and report what you find. "
            "You are thorough and methodical. You look for hidden attack surfaces "
            "that others might miss."
        ),
    },
    {
        "name": "Exploit Analyst",
        "icon": "E",
        "focus": "Vulnerability verification, PoC creation, exploit chaining, custom tools",
        "personality": (
            "You are the exploitation expert. You take findings from teammates "
            "and verify if they are actually exploitable. You write custom scripts "
            "and PoCs. When the team hits a dead end, you think creatively about "
            "alternative attack vectors."
        ),
    },
]


# ---------------------------------------------------------------------------
# Team Aegis Engine
# ---------------------------------------------------------------------------

class TeamAegis:
    """
    Multi-Agent Collaboration Engine.
    
    Enables up to 3 AI models to work as a security research team.
    They communicate through a shared discussion board, assign tasks,
    share results, and collaboratively analyze findings.
    """

    def __init__(
        self,
        clients: List[UniversalAIClient],
        target: str,
        callback: Optional[Callable] = None,
        async_callback: Optional[Callable] = None,
        max_rounds: int = 30,
        parallel_mode: bool = True,
    ):
        """
        Initialize the team.
        
        Args:
            clients: List of 2-3 UniversalAIClient instances
            target: Target domain/IP for scanning
            callback: Optional callback for live UI updates (sequential mode)
            async_callback: Optional streaming callback per agent (parallel mode)
                          Signature: async_callback(agent_id, role_name, status, message)
            max_rounds: Maximum discussion rounds before auto-finish
            parallel_mode: If True, agents run in parallel for faster execution
        """
        if len(clients) < 2:
            raise ValueError("Team Aegis requires at least 2 AI models.")
        if len(clients) > 3:
            clients = clients[:3]
        
        self.clients = clients
        self.target = target
        self.callback = callback
        self.async_callback = async_callback
        self.max_rounds = max_rounds
        self.parallel_mode = parallel_mode
        
        # Shared state
        self.discussion: List[TeamMessage] = []
        self.findings: List[Finding] = []
        self.tasks: List[TaskAssignment] = []
        self.task_queue: List[tuple] = []  # Priority queue: (priority, task) tuples
        self._task_queue_lock: threading.Lock = threading.Lock()
        self.shared_intel: List[str] = []  # intelligence shared across agents
        self.round = 0
        # Context compression
        self._compress_threshold = 3500   # tokens — compress when discussion exceeds this
        self._compress_check_interval = 3  # check every N rounds
        self.team_size = len(clients)
        self.finished = False
        
        # Assign roles
        self.roles = AGENT_ROLES[:self.team_size]
        
        # Initialize skill registry for tool awareness
        self.skill_registry = get_skill_registry() if SKILL_REGISTRY_AVAILABLE else None
        
        # Thread pool for parallel execution
        self._executor = concurrent.futures.ThreadPoolExecutor(max_workers=self.team_size)
        
        # Vector memory for cross-session learning
        self._memories: Dict[str, str] = {}
        if target:
            try:
                from tools.vector_memory import recall
                recalled = recall(query=f"target:{target}", target=target, category="finding", n_results=3)
                if recalled:
                    self._memories[target] = str(recalled)
                    logger.info(f"Recalled {len(recalled)} prior memories for {target}")
            except Exception:
                pass
        
        logger.info(f"Team Aegis initialized: {self.team_size} agents targeting {target} (parallel={parallel_mode})")

    def _format_available_tools_for_agent(self) -> str:
        """Format available tools from skill registry for agent prompt."""
        if not self.skill_registry:
            return "(Tool registry not available)"
        
        lines = []
        available = self.skill_registry.get_available_skills()
        missing = self.skill_registry.get_missing_skills()
        
        if available:
            lines.append("READY TO USE:")
            for skill in available:
                lines.append(f"  - {skill.name} ({skill.category}): {skill.description}")
        
        if missing:
            lines.append("\nMISSING (can request install):")
            for skill in missing:
                lines.append(f"  - {skill.name}: {skill.description}")
                lines.append(f"    Install: {skill.install_command}")
        
        return "\n".join(lines) if lines else "(No tools registered)"

    def _format_discussion_history(self, max_messages: int = 30) -> str:
        """Format the discussion board for agent context."""
        if not self.discussion:
            return "(No previous discussion. You are starting the engagement.)"
        
        recent = self.discussion[-max_messages:]
        lines = []
        
        for msg in recent:
            header = f"[{msg.agent_role}] ({msg.model_name}) — Round {msg.round}"
            if msg.msg_type == "task_result":
                header += " [TOOL RESULT]"
            elif msg.msg_type == "proposal":
                header += " [PROPOSAL]"
            elif msg.msg_type == "consensus":
                header += " [CONSENSUS]"
            
            lines.append(f"{header}:")
            lines.append(msg.content)
            lines.append("")
        
        return "\n".join(lines)

    def _format_findings(self) -> str:
        """Format current findings for agent context."""
        if not self.findings:
            return "(No confirmed findings yet.)"
        
        lines = []
        for i, f in enumerate(self.findings, 1):
            confirmed = ", ".join(f.confirmed_by) if f.confirmed_by else "unconfirmed"
            lines.append(f"{i}. [{f.severity.upper()}] {f.description}")
            lines.append(f"   Found by: {f.source_agent} | Confirmed by: {confirmed}")
            if f.evidence:
                lines.append(f"   Evidence: {f.evidence[:200]}")
        
        return "\n".join(lines)

    def _format_team_roster(self) -> str:
        """Format team composition for display."""
        lines = []
        for i, client in enumerate(self.clients):
            role = self.roles[i]
            lines.append(f"  [{role['icon']}] {role['name']}: {client.provider}/{client.model}")
        return "\n".join(lines)

    def _format_prior_memories(self) -> str:
        """Format prior vector memories for agent context."""
        if not self._memories:
            return "(No prior memories for this target)"
        lines = ["### PRIOR SCAN MEMORIES (from previous sessions):"]
        for target, memory in self._memories.items():
            lines.append(f"{target}: {str(memory)[:500]}")
        return "\n".join(lines)

    # ── Shared Intelligence (cross-agent awareness) ───────────────────

    def _share_intel(self, agent_id: int, insight: str) -> None:
        """Share a key insight from one agent to the entire team.

        Called automatically after a tool returns findings.  Other agents
        will see this in their ``_format_shared_intel()`` context.
        """
        role = self.roles[agent_id]["name"] if agent_id < len(self.roles) else f"Agent{agent_id}"
        entry = f"[{role}] {insight[:300]}"
        if entry not in self.shared_intel:
            self.shared_intel.append(entry)
            logger.info(f"Shared intel from {role}: {insight[:80]}...")

    def _format_shared_intel(self) -> str:
        """Format shared intelligence and pending tasks for agent prompt."""
        lines = []

        if self.shared_intel:
            lines.append("### SHARED INTELLIGENCE (from teammates):")
            for entry in self.shared_intel[-10:]:
                lines.append(f"  {entry}")

        # Show pending tasks from the queue (thread-safe read)
        with self._task_queue_lock:
            pending = [t for t in self.task_queue if t[3].get("type") != "suggested"]
            suggested = [t for t in self.task_queue if t[3].get("type") == "suggested"]
        if suggested:
            lines.append("\n### PENDING TASKS (suggested by teammates — claim one):")
            for _, _, agent_id, action in suggested:
                desc = action.get("description", "Unknown task")[:150]
                lines.append(f"  - {desc}")

        return "\n".join(lines)

    def _push_task(self, priority: int, agent_id: int, action: Dict):
        """Add a task to the priority queue (lower number = higher priority)."""
        if priority < 0:
            priority = 0
        with self._task_queue_lock:
            heappush(self.task_queue, (priority, time.time(), agent_id, action))

    def _pop_task(self) -> Optional[tuple]:
        """Pop the highest priority task."""
        with self._task_queue_lock:
            if not self.task_queue:
                return None
            return heappop(self.task_queue)

    def _save_memory(self, finding: Finding):
        """Save a finding to vector memory for future sessions."""
        try:
            from tools.vector_memory import remember
            remember(
                content=f"[{finding.severity}] {finding.description} — {finding.evidence[:300]}",
                target=self.target,
                category="finding",
                source_agent=finding.source_agent,
                severity=finding.severity,
            )
            self._memories[self.target] = finding.description[:500]
        except Exception as e:
            logger.debug(f"Memory save failed: {e}")

    # ── Context Compression ────────────────────────────────────────────

    def _estimate_discussion_tokens(self) -> int:
        """Estimate total tokens in the discussion board."""
        from tools.token_counter import count_tokens
        total = 0
        for msg in self.discussion:
            total += count_tokens(msg.content)
            total += count_tokens(msg.agent_role)
        return total

    def _compress_discussion(self) -> None:
        """Compress middle portion of discussion when token count is high.

        Keeps the first 2 and last 8 messages intact.  The remainder is
        summarised by the first available AI client.
        """
        total = self._estimate_discussion_tokens()
        if total < self._compress_threshold:
            return
        if len(self.discussion) <= 12:
            return  # too few messages to bother

        keep_head = 2
        keep_tail = 8
        middle = self.discussion[keep_head:-keep_tail]
        if not middle:
            return

        head_msgs = self.discussion[:keep_head]
        tail_msgs = self.discussion[-keep_tail:]

        middle_text = "\n---\n".join(
            f"[{m.agent_role}] R{m.round}: {m.content[:400]}"
            for m in middle
        )

        try:
            client = self.clients[0]  # first available AI
            summary = client.simple_chat(
                f"Summarise the following team discussion in 3-5 sentences. "
                f"Focus on: key findings, tools used, decisions made, and next steps.\n\n"
                f"{middle_text}",
                system_prompt="You are a concise summariser. Output only the summary, no preamble.",
            )
            summary_text = summary.strip() if summary else ""
            if len(summary_text) < 20:
                return  # garbage summary, skip

            compressed = TeamMessage(
                round=self.round,
                agent_id=-1,
                agent_role="[COMPRESSED]",
                model_name="system",
                content=f"Earlier discussion compressed:\n{summary_text}",
                msg_type="discussion",
            )
            self.discussion = head_msgs + [compressed] + tail_msgs
            logger.info(
                f"Compressed {len(middle)} discussion messages into summary "
                f"(was {total} tokens)"
            )
        except Exception as e:
            logger.debug(f"Discussion compression failed: {e}")

    def _build_agent_prompt(self, agent_id: int, phase: str = "discuss") -> str:
        """Build the full prompt for a specific agent."""
        role = self.roles[agent_id]
        client = self.clients[agent_id]
        
        teammates = []
        for i, r in enumerate(self.roles):
            if i != agent_id:
                teammates.append(f"- {r['name']} ({self.clients[i].provider}/{self.clients[i].model}): {r['focus']}")
        teammates_str = "\n".join(teammates)
        
        discussion_history = self._format_discussion_history()
        findings_summary = self._format_findings()
        shared_intel = self._format_shared_intel()
        
        # Get available tools from registries
        tools_context = ""
        if SKILL_REGISTRY_AVAILABLE and self.skill_registry:
            tools_context = self._format_available_tools_for_agent()
        # Add ToolRegistry tools
        try:
            from tools.tool_registry import registry
            avail = registry.list_available_tools()
            tool_names = [name for name, info in avail.items() if info.get("available")]
            if tool_names:
                tools_context += "\n### SECURITY TOOLS AVAILABLE:\n"
                tools_context += "\n".join(f"  - {name}" for name in sorted(tool_names))
        except Exception:
            pass
        
        prompt = f"""## TEAM AEGIS — Security Research Team Collaboration

### YOUR IDENTITY
- Role: {role['name']}
- Model: {client.provider}/{client.model}
- Specialty: {role['focus']}

### YOUR PERSONALITY
{role['personality']}

### TARGET
{self.target}

### YOUR TEAMMATES
{teammates_str}

### CURRENT FINDINGS
{findings_summary}

### SHARED INTELLIGENCE
{shared_intel}

### TEAM DISCUSSION HISTORY
{discussion_history}

### AVAILABLE TOOLS & SKILLS
{tools_context}

### CURRENT ROUND: {self.round}

### INSTRUCTIONS FOR THIS TURN
You are in a team meeting. Read what your teammates said, then contribute:

1. **React** to teammates' findings or suggestions
2. **Propose** your next action or share analysis
3. **Help** if a teammate is stuck — suggest alternative approaches
4. **Disagree** respectfully if you think a different approach is better
5. **Report** any findings clearly with evidence
6. **Recommend tools** from the available list that teammates should use

### RESPONSE FORMAT
Respond with JSON:
```json
{{
    "discussion": "Your natural team discussion message (what you say to teammates)",
    "action": {{
        "type": "run_tool|shell|search_web|write_file|read_file|package|bounty_intel|github_search|cve_lookup|js_analyze|check_takeover|none|finish",
        "params": {{}},
        "tool_name": "specific tool name from available list",
        "description": "What this action does"
    }},
    "findings": [
        {{
            "description": "Vulnerability or discovery description",
            "severity": "critical|high|medium|low|info",
            "evidence": "Proof or details"
        }}
    ],
    "tool_recommendation": "Suggest a specific tool from the available list for teammates to try",
        "needs_help": false,
        "help_request": "",
        "suggest_task": ""  // Optional: suggest a task for teammates (e.g., "Run nuclei on api.1win.com")
    }}
    ```
    
    - Set `action.type` to `"none"` if you just want to discuss without executing anything
    - Set `action.type` to `"finish"` if you believe the scan is complete
    - Set `needs_help` to `true` if you are stuck and need teammates' input
    - Set `suggest_task` to recommend a task for a teammate (it goes into the team task queue)
    - `findings` is optional — only include if you discovered something
      - **IMPORTANT**: If you're confirming a FINDING another agent reported, add `"confirmed_by": "your_agent_name"` to the finding
      - New findings start unconfirmed until at least one other agent confirms them

### RULES
1. Be concise and actionable — no fluff
2. Always reference specific data from teammates' findings
3. **DO NOT repeat work a teammate already did** — check the discussion history and shared intelligence first
4. If proposing a tool, specify exact command parameters from the available tools list
5. Do not use emojis
6. Respond ONLY with valid JSON
7. If a tool you need is marked [MISSING], suggest it with install command
8. **COORDINATION**: If a teammate already ran a specific tool on a target, do NOT run it again. Instead, build upon their results.
9. **UNIQUE OUTPUT FILES**: When saving output to files, include your role name to avoid conflicts (e.g., `subfinder_recon_lead.txt` not `subfinder.txt`).
10. You have full native shell access — you can use pipes (|), redirects (>), command chaining (&&), subshells ($()) freely."""

        return prompt

    # ---------------------------------------------------------------------------
    # Parallel Execution Engine
    # ---------------------------------------------------------------------------
    
    def _run_single_agent(self, agent_id: int, executor=None) -> Dict[str, Any]:
        """Run a single agent in parallel (thread-safe)."""
        role = self.roles[agent_id]
        client = self.clients[agent_id]
        
        # Notify that this agent is starting
        if self.async_callback:
            self.async_callback(agent_id, role["name"], "thinking", "")
        
        try:
            # Build prompt from latest state
            prompt = self._build_agent_prompt(agent_id)
            
            # Call AI
            response_text = client.simple_chat(
                f"Team discussion round {self.round}. Your turn to contribute.",
                system_prompt=prompt
            )
            
            # Parse response
            action_data = self._parse_agent_response(response_text)
            
            return {
                "agent_id": agent_id,
                "success": True,
                "action_data": action_data,
                "response_text": response_text,
            }
            
        except Exception as e:
            logger.error(f"Agent {role['name']} error: {e}")
            return {
                "agent_id": agent_id,
                "success": False,
                "error": str(e),
            }
    
    def _process_agent_result(self, result: Dict, executor=None) -> bool:
        """Process a single agent's result (thread-safe). Returns True if voted to finish."""
        agent_id = result.get("agent_id", 0)
        role = self.roles[agent_id]
        client = self.clients[agent_id]
        
        if not result["success"]:
            # Handle error
            error_msg = result.get("error", "Unknown error")
            self.discussion.append(TeamMessage(
                round=self.round,
                agent_id=agent_id,
                agent_role=role["name"],
                model_name=f"{client.provider}/{client.model}",
                content=f"[ERROR] Agent encountered an issue: {error_msg[:200]}",
                msg_type="discussion"
            ))
            if self.callback:
                self.callback(f"    [ERROR] {role['name']}: {error_msg[:100]}")
            if self.async_callback:
                self.async_callback(agent_id, role["name"], "error", error_msg[:200])
            return False
        
        action_data = result["action_data"]
        discussion_msg = action_data.get("discussion", result["response_text"][:500])
        
        # Add to discussion board
        self.discussion.append(TeamMessage(
            round=self.round,
            agent_id=agent_id,
            agent_role=role["name"],
            model_name=f"{client.provider}/{client.model}",
            content=discussion_msg,
            msg_type="discussion"
        ))
        
        # Show to user
        if self.callback:
            self.callback(f"\n[{role['icon']}] {role['name']}:")
            for line in discussion_msg.split("\n"):
                self.callback(f"    {line}")
        if self.async_callback:
            self.async_callback(agent_id, role["name"], "done", discussion_msg)
        
        # Handle action
        action = action_data.get("action", {})
        action_type = action.get("type", "none")
        
        finish_vote = False
        if action_type == "finish":
            finish_vote = True
            if self.callback:
                self.callback(f"    >> {role['name']} votes to FINISH the scan.")
            if self.async_callback:
                self.async_callback(agent_id, role["name"], "finish", "")
        
        elif action_type not in ("none", ""):
            # Execute action in background
            if executor:
                exec_result = self._execute_agent_action(agent_id, action, executor)
                
                result_msg = f"[TOOL RESULT] {action.get('description', action_type)}: {exec_result[:500]}"
                self.discussion.append(TeamMessage(
                    round=self.round,
                    agent_id=agent_id,
                    agent_role=role["name"],
                    model_name=f"{client.provider}/{client.model}",
                    content=result_msg,
                    msg_type="task_result"
                ))
                
                if self.callback:
                    self.callback(f"    >> Executed: {action.get('description', action_type)}")
                    for line in exec_result[:300].split("\n")[:5]:
                        self.callback(f"       {line}")
                if self.async_callback:
                    self.async_callback(agent_id, role["name"], "executed", exec_result[:300])

                # Share key intel with the team
                if exec_result and len(exec_result) > 10:
                    action_desc = action.get("description", action_type)
                    self._share_intel(agent_id, f"{action_desc} → {exec_result[:200]}")

        # Handle findings
        for finding_data in action_data.get("findings", []):
            if isinstance(finding_data, dict) and finding_data.get("description"):
                # Check if this is a confirmation of an existing unconfirmed finding
                confirmed_by = finding_data.get("confirmed_by", "")
                existing = None
                if confirmed_by:
                    for f in self.findings:
                        if f.description.strip().lower() == finding_data["description"].strip().lower() and not f.confirmed_by:
                            existing = f
                            break

                if existing:
                    # Confirmed by another agent
                    existing.confirmed_by.append(confirmed_by)
                    existing.severity = finding_data.get("severity", existing.severity)
                    if self.callback:
                        sev = existing.severity.upper()
                        self.callback(f"    ** CONFIRMED [{sev}] by {confirmed_by}: {existing.description}")
                    self._share_intel(agent_id, f"CONFIRMED [{existing.severity.upper()}] {existing.description} (confirmed by {confirmed_by})")
                else:
                    # New finding (starts unconfirmed)
                    finding = Finding(
                        source_agent=role["name"],
                        description=finding_data["description"],
                        severity=finding_data.get("severity", "info"),
                        evidence=finding_data.get("evidence", ""),
                    )
                    self.findings.append(finding)
                    self._save_memory(finding)
                    sev = finding_data.get("severity", "info").upper()
                    self._share_intel(agent_id, f"UNCONFIRMED [{sev}] {finding_data['description']} — waiting for teammate confirmation")
                    if self.callback:
                        self.callback(f"    ** UNCONFIRMED [{sev}]: {finding_data['description']}")
                if self.async_callback:
                    self.async_callback(agent_id, role["name"], "finding", finding_data["description"])

        # Handle task suggestions
        suggested = action_data.get("suggest_task", "").strip()
        if suggested and len(suggested) > 5:
            self._push_task(priority=3, agent_id=agent_id, action={"type": "suggested", "description": suggested})
            self._share_intel(agent_id, f"SUGGESTED TASK: {suggested[:200]}")
            if self.callback:
                self.callback(f"    >> TASK SUGGESTED: {suggested[:200]}")

        # Handle help request
        if action_data.get("needs_help"):
            help_req = action_data.get("help_request", "Need input from teammates")
            self.discussion.append(TeamMessage(
                round=self.round,
                agent_id=agent_id,
                agent_role=role["name"],
                model_name=f"{client.provider}/{client.model}",
                content=f"[HELP NEEDED] {help_req}",
                msg_type="proposal"
            ))
            if self.callback:
                self.callback(f"    ?? NEEDS HELP: {help_req}")
            if self.async_callback:
                self.async_callback(agent_id, role["name"], "help", help_req)
        
    def run_round(self, executor=None) -> bool:
        """Run one discussion round — delegates to parallel or sequential."""
        if self.parallel_mode:
            return self.run_round_parallel(executor=executor)
        return self.run_round_sequential(executor=executor)

    def run_round_parallel(self, executor=None) -> bool:
        """Run one discussion round where all agents contribute in parallel."""
        self.round += 1
        finish_votes = 0
        
        if self.callback:
            self.callback(f"\n{'='*60}")
            self.callback(f" TEAM AEGIS — Round {self.round} | Target: {self.target} (PARALLEL)")
            self.callback(f"{'='*60}")
        
        # Run all agents concurrently
        agent_results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.team_size) as pool:
            future_to_id = {
                pool.submit(self._run_single_agent, i, executor): i 
                for i in range(self.team_size)
            }
            for future in concurrent.futures.as_completed(future_to_id):
                agent_id = future_to_id[future]
                try:
                    result = future.result()
                    agent_results.append(result)
                except Exception as e:
                    logger.error(f"Agent {agent_id} failed: {e}")
                    agent_results.append({
                        "agent_id": agent_id,
                        "success": False,
                        "error": str(e),
                    })
        
        # Sort results by agent_id to keep order consistent
        agent_results.sort(key=lambda r: r.get("agent_id", 0))
        
        # Process results sequentially (shared state needs ordering)
        for result in agent_results:
            voted_finish = self._process_agent_result(result, executor=executor)
            if voted_finish:
                finish_votes += 1
        
        # Check if majority wants to finish
        if finish_votes > self.team_size / 2:
            self.finished = True
            if self.callback:
                self.callback(f"\n>> Team consensus: SCAN COMPLETE ({finish_votes}/{self.team_size} voted finish)")
            return False
        
        return True

    def run_round_sequential(self, executor=None) -> bool:
        """Run one discussion round where each agent takes a turn (original behavior)."""
        self.round += 1
        finish_votes = 0
        
        if self.callback:
            self.callback(f"\n{'='*60}")
            self.callback(f" TEAM AEGIS — Round {self.round} | Target: {self.target}")
            self.callback(f"{'='*60}")
        
        for agent_id in range(self.team_size):
            result = self._run_single_agent(agent_id, executor=executor)
            voted_finish = self._process_agent_result(result, executor=executor)
            if voted_finish:
                finish_votes += 1
        
        # Check if majority wants to finish
        if finish_votes > self.team_size / 2:
            self.finished = True
            if self.callback:
                self.callback(f"\n>> Team consensus: SCAN COMPLETE ({finish_votes}/{self.team_size} voted finish)")
            return False
        
        return True

    def _execute_agent_action(self, agent_id: int, action: Dict, executor) -> str:
        """Execute a tool action requested by an agent.
        
        Passes agent_id to the executor for workspace isolation,
        preventing file conflicts between parallel agents.
        """
        action_type = action.get("type", "none")
        params = action.get("params", {})
        
        if action_type in ("none", "finish", ""):
            return ""
        
        try:
            # Inject agent_id for shell workspace isolation
            if action_type == "shell":
                params["agent_id"] = agent_id
            
            result = executor.execute_action({"type": action_type, "params": params})
            output = result.output if result.success else f"Error: {result.error}"
            
            # Track task
            self.tasks.append(TaskAssignment(
                agent_id=agent_id,
                action_type=action_type,
                params=params,
                description=action.get("description", ""),
                result=output[:1000],
                success=result.success,
                completed=True,
            ))
            
            return output[:2000]
            
        except Exception as e:
            return f"Execution failed: {str(e)[:200]}"

    def _parse_agent_response(self, text: str) -> Dict[str, Any]:
        """Parse agent response, handling both JSON and plain text."""
        if not text:
            return {"discussion": "(No response)", "action": {"type": "none"}}
        
        # Try to extract JSON
        import re
        
        # Try ```json blocks first
        json_match = re.search(r'```json\s*(.*?)\s*```', text, re.DOTALL)
        if json_match:
            try:
                return json.loads(json_match.group(1))
            except json.JSONDecodeError:
                pass
        
        # Try raw JSON
        json_match = re.search(r'\{.*\}', text, re.DOTALL)
        if json_match:
            try:
                parsed = json.loads(json_match.group())
                if "discussion" in parsed or "action" in parsed:
                    return parsed
            except json.JSONDecodeError:
                pass
        
        # Fallback: treat entire text as discussion
        return {
            "discussion": text[:1000],
            "action": {"type": "none"},
            "findings": [],
        }

    def run_full_engagement(self, executor=None) -> str:
        """
        Run the complete team engagement until done.
        
        Returns:
            Final merged report as string
        """
        if self.callback:
            self.callback(f"\n{'='*60}")
            self.callback(f" TEAM AEGIS ACTIVATED")
            self.callback(f" Target: {self.target}")
            self.callback(f" Team Size: {self.team_size} agents")
            self.callback(f"{'='*60}")
            self.callback(self._format_team_roster())
            self.callback(f"{'='*60}\n")
        
        while self.round < self.max_rounds and not self.finished:
            should_continue = self.run_round(executor=executor)
            if not should_continue:
                break

            # Auto-compress discussion if it gets too long
            if self.round > 0 and self.round % self._compress_check_interval == 0:
                self._compress_discussion()
        
        # Generate final report
        return self._generate_final_report()

    def _generate_final_report(self) -> str:
        """Generate a merged report from all agents' findings."""
        lines = [
            f"{'='*60}",
            f" TEAM AEGIS — ENGAGEMENT REPORT",
            f" Target: {self.target}",
            f" Rounds: {self.round}",
            f" Team: {', '.join(r['name'] for r in self.roles)}",
            f"{'='*60}",
            "",
        ]
        
        # Findings by severity
        if self.findings:
            severity_order = ["critical", "high", "medium", "low", "info"]
            lines.append("FINDINGS:")
            lines.append("-" * 40)
            
            for sev in severity_order:
                sev_findings = [f for f in self.findings if f.severity == sev]
                if sev_findings:
                    lines.append(f"\n[{sev.upper()}]")
                    for f in sev_findings:
                        lines.append(f"  - {f.description}")
                        if f.evidence:
                            lines.append(f"    Evidence: {f.evidence[:300]}")
                        lines.append(f"    Found by: {f.source_agent}")
        else:
            lines.append("No confirmed vulnerabilities found during this engagement.")
        
        # Tasks executed
        lines.append(f"\n\nACTIONS EXECUTED: {len(self.tasks)}")
        lines.append("-" * 40)
        for t in self.tasks:
            status = "OK" if t.success else "FAIL"
            role_name = self.roles[t.agent_id]["name"] if t.agent_id < len(self.roles) else "Unknown"
            lines.append(f"  [{status}] {role_name}: {t.description or t.action_type}")
        
        # Discussion highlights
        lines.append(f"\n\nDISCUSSION ROUNDS: {self.round}")
        lines.append(f"TOTAL MESSAGES: {len(self.discussion)}")
        
        lines.append(f"\n{'='*60}")
        lines.append(f" END OF REPORT")
        lines.append(f"{'='*60}")
        
        return "\n".join(lines)
