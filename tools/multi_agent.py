"""
multi_agent.py — Team Aegis: Multi-Agent Collaboration Engine (v1.0.0)

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
from typing import List, Dict, Any, Optional, Callable
from dataclasses import dataclass, field

from tools.universal_ai_client import UniversalAIClient, AIMessage, AIResponse

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
        max_rounds: int = 30,
    ):
        """
        Initialize the team.
        
        Args:
            clients: List of 2-3 UniversalAIClient instances
            target: Target domain/IP for scanning
            callback: Optional callback for live UI updates
            max_rounds: Maximum discussion rounds before auto-finish
        """
        if len(clients) < 2:
            raise ValueError("Team Aegis requires at least 2 AI models.")
        if len(clients) > 3:
            clients = clients[:3]
        
        self.clients = clients
        self.target = target
        self.callback = callback
        self.max_rounds = max_rounds
        
        # Shared state
        self.discussion: List[TeamMessage] = []
        self.findings: List[Finding] = []
        self.tasks: List[TaskAssignment] = []
        self.round = 0
        self.team_size = len(clients)
        self.finished = False
        
        # Assign roles
        self.roles = AGENT_ROLES[:self.team_size]
        
        logger.info(f"Team Aegis initialized: {self.team_size} agents targeting {target}")

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

### TEAM DISCUSSION HISTORY
{discussion_history}

### CURRENT ROUND: {self.round}

### INSTRUCTIONS FOR THIS TURN
You are in a team meeting. Read what your teammates said, then contribute:

1. **React** to teammates' findings or suggestions
2. **Propose** your next action or share analysis
3. **Help** if a teammate is stuck — suggest alternative approaches
4. **Disagree** respectfully if you think a different approach is better
5. **Report** any findings clearly with evidence

### RESPONSE FORMAT
Respond with JSON:
```json
{{
    "discussion": "Your natural team discussion message (what you say to teammates)",
    "action": {{
        "type": "run_tool|shell|search_web|write_file|none|finish",
        "params": {{}},
        "description": "What this action does"
    }},
    "findings": [
        {{
            "description": "Vulnerability or discovery description",
            "severity": "critical|high|medium|low|info",
            "evidence": "Proof or details"
        }}
    ],
    "needs_help": false,
    "help_request": ""
}}
```

- Set `action.type` to `"none"` if you just want to discuss without executing anything
- Set `action.type` to `"finish"` if you believe the scan is complete
- Set `needs_help` to `true` if you are stuck and need teammates' input
- `findings` is optional — only include if you discovered something

### RULES
1. Be concise and actionable — no fluff
2. Always reference specific data from teammates' findings
3. Do not repeat work a teammate already did
4. If proposing a tool, specify exact command parameters
5. Do not use emojis
6. Respond ONLY with valid JSON"""

        return prompt

    def run_round(self, executor=None) -> bool:
        """
        Run one discussion round where each agent takes a turn.
        
        Args:
            executor: UniversalExecutor instance for running tools
            
        Returns:
            True if team wants to continue, False if finished
        """
        self.round += 1
        finish_votes = 0
        
        if self.callback:
            self.callback(f"\n{'='*60}")
            self.callback(f" TEAM AEGIS — Round {self.round} | Target: {self.target}")
            self.callback(f"{'='*60}")
        
        for agent_id in range(self.team_size):
            role = self.roles[agent_id]
            client = self.clients[agent_id]
            
            if self.callback:
                self.callback(f"\n[{role['icon']}] {role['name']} ({client.provider}/{client.model}) is thinking...")
            
            # Build and send prompt
            prompt = self._build_agent_prompt(agent_id)
            
            try:
                response_text = client.simple_chat(
                    f"Team discussion round {self.round}. Your turn to contribute.",
                    system_prompt=prompt
                )
                
                # Parse response
                action_data = self._parse_agent_response(response_text)
                
                # Extract discussion message
                discussion_msg = action_data.get("discussion", response_text[:500])
                
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
                    # Show discussion in manageable chunks
                    for line in discussion_msg.split("\n"):
                        self.callback(f"    {line}")
                
                # Handle action
                action = action_data.get("action", {})
                action_type = action.get("type", "none")
                
                if action_type == "finish":
                    finish_votes += 1
                    if self.callback:
                        self.callback(f"    >> {role['name']} votes to FINISH the scan.")
                
                elif action_type not in ("none", ""):
                    # Execute the action
                    if executor:
                        result = self._execute_agent_action(agent_id, action, executor)
                        
                        # Share result with team
                        result_msg = f"[TOOL RESULT] {action.get('description', action_type)}: {result[:500]}"
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
                            # Show result preview
                            for line in result[:300].split("\n")[:5]:
                                self.callback(f"       {line}")
                
                # Handle findings
                for finding_data in action_data.get("findings", []):
                    if isinstance(finding_data, dict) and finding_data.get("description"):
                        self.findings.append(Finding(
                            source_agent=role["name"],
                            description=finding_data["description"],
                            severity=finding_data.get("severity", "info"),
                            evidence=finding_data.get("evidence", ""),
                        ))
                        if self.callback:
                            sev = finding_data.get("severity", "info").upper()
                            self.callback(f"    ** FINDING [{sev}]: {finding_data['description']}")
                
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
                
            except Exception as e:
                logger.error(f"Agent {role['name']} error: {e}")
                self.discussion.append(TeamMessage(
                    round=self.round,
                    agent_id=agent_id,
                    agent_role=role["name"],
                    model_name=f"{client.provider}/{client.model}",
                    content=f"[ERROR] Agent encountered an issue: {str(e)[:200]}",
                    msg_type="discussion"
                ))
                if self.callback:
                    self.callback(f"    [ERROR] {role['name']}: {str(e)[:100]}")
        
        # Check if majority wants to finish
        if finish_votes > self.team_size / 2:
            self.finished = True
            if self.callback:
                self.callback(f"\n>> Team consensus: SCAN COMPLETE ({finish_votes}/{self.team_size} voted finish)")
            return False
        
        return True

    def _execute_agent_action(self, agent_id: int, action: Dict, executor) -> str:
        """Execute a tool action requested by an agent."""
        action_type = action.get("type", "none")
        params = action.get("params", {})
        
        if action_type in ("none", "finish", ""):
            return ""
        
        try:
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
