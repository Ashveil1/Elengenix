"""
agents/redteam/captain.py — REDTEAM Captain Agent (Mission Commander)

The Captain is the mission commander who:
- Orchestrates the entire mission lifecycle
- Makes Go/No-Go decisions
- Allocates resources and manages scope
- Resolves conflicts between agents
- Tracks mission progress and timeline
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional
from uuid import uuid4

from .base import (
    AgentRole,
    AgentStatus,
    MessageBus,
    MessageType,
    MissionPhase,
    MissionContext,
    AgentMessage,
)

logger = logging.getLogger("elengenix.redteam.captain")


@dataclass
class AgentRegistry:
    """Registry of all agents in the mission"""
    agents: Dict[str, AgentStatus] = field(default_factory=dict)

    def register(self, agent_name: str, role: AgentRole):
        self.agents[agent_name] = AgentStatus(role=role, status="idle")

    def update_status(self, agent_name: str, status: str, task: Optional[str] = None):
        if agent_name in self.agents:
            self.agents[agent_name].status = status
            self.agents[agent_name].current_task = task
            self.agents[agent_name].last_heartbeat = time.time()

    def get_available_agents(self, role: Optional[str] = None) -> List[str]:
        available = []
        for name, status in self.agents.items():
            if status.status == "idle":
                if role is None or status.role == role:
                    available.append(name)
        return available

    def get_agent_load(self) -> Dict[str, int]:
        """Get current task count per agent"""
        return {name: 1 if s.status == "busy" else 0 for name, s in self.agents.items()}


@dataclass
class DecisionRecord:
    """Record of a captain decision"""
    decision_id: str
    timestamp: float
    decision_type: str
    payload: Dict[str, Any]
    decision: Dict[str, Any]
    rationale: str


class CaptainAgent:
    """Mission Commander - orchestrates the entire REDTEAM mission"""

    def __init__(self, message_bus: MessageBus):
        self.name = "captain"
        self.role = AgentRole.CAPTAIN
        self.bus = message_bus
        self.registry = AgentRegistry()
        self.mission_context: Optional[MissionContext] = None
        self.phase = MissionPhase.INIT
        self.decisions_log: List[DecisionRecord] = []
        self.phase_start_time = 0.0
        self.mission_start_time = 0.0
        self._shutdown_event = asyncio.Event()
        self._phase_complete_events: Dict[MissionPhase, asyncio.Event] = {}

        # Subscribe to messages
        self.bus.subscribe(self.name, self._handle_message)
        self.bus.subscribe("all", self._handle_message)

    # Agent registration
    def register_agent(self, agent_name: str, role: AgentRole):
        self.registry.register(agent_name, role.value)

    # Main mission loop
    async def run_mission(self, context: MissionContext) -> Dict[str, Any]:
        """Run the complete autonomous mission"""
        self.mission_context = context
        self.mission_start_time = time.time()

        logger.info(f"[CAPTAIN] Mission {context.mission_id} started for target: {context.target}")

        # Register all agents
        for role in AgentRole:
            if role != AgentRole.CAPTAIN:
                self.registry.register(role.value, role.value)

        try:
            # Dynamic phase order — the Captain can reorder/skip phases
            # based on what was already discovered. This replaces the old
            # hard-coded RECON→PLANNING→SCANNING→EXPLOITATION→VERIFICATION→
            # REPORTING sequence that defeated agent autonomy.
            phase_order: List[MissionPhase] = [
                MissionPhase.RECON,
                MissionPhase.PLANNING,
                MissionPhase.SCANNING,
                MissionPhase.EXPLOITATION,
                MissionPhase.VERIFICATION,
                MissionPhase.REPORTING,
            ]

            while phase_order:
                phase = phase_order.pop(0)
                await self._execute_phase(phase)

                # After each phase, check AI-driven transition decision
                # (e.g. skip scanning if already covered, jump to exploit).
                if phase_order:
                    decision = await self._decide_phase_transition({
                        "current_phase": phase.value,
                        "remaining_phases": [p.value for p in phase_order],
                        "coverage_score": 0,
                        "time_elapsed": time.time() - self.phase_start_time,
                    })
                    if decision.get("decision") == "transition" and decision.get("next_phase"):
                        next_phase_name = decision["next_phase"]
                        try:
                            target_phase = MissionPhase(next_phase_name)
                            while phase_order and phase_order[0] != target_phase:
                                skipped = phase_order.pop(0)
                                logger.info(f"[CAPTAIN] Skipping {skipped.value} → fast-forward to {target_phase.value}")
                        except ValueError:
                            pass

            self.phase = MissionPhase.COMPLETE
            return await self._generate_mission_report()

        except asyncio.CancelledError:
            logger.info("[CAPTAIN] Mission cancelled")
            self.phase = MissionPhase.ABORTED
            raise
        except Exception as e:
            logger.error(f"[CAPTAIN] Mission failed: {e}")
            self.phase = MissionPhase.ABORTED
            return {"status": "failed", "error": str(e)}

    async def _execute_phase(self, phase: MissionPhase):
        """Execute a mission phase"""
        self.phase = phase
        self.phase_start_time = time.time()
        self._phase_complete_events[phase] = asyncio.Event()

        logger.info(f"[CAPTAIN] Starting phase: {phase.value}")

        # Broadcast phase change to all agents
        await self.bus.publish(AgentMessage(
            from_agent=self.name,
            to_agent="all",
            message_type=MessageType.PHASE_CHANGE,
            payload={"phase": phase.value, "action": "start"},
            priority=1
        ))

        # Wait for phase completion (agents signal completion)
        try:
            await asyncio.wait_for(
                self._phase_complete_events[phase].wait(),
                timeout=3600  # 1 hour max per phase
            )
        except asyncio.TimeoutError:
            logger.warning(f"[CAPTAIN] Phase {phase.value} timed out, proceeding")

        elapsed = time.time() - self.phase_start_time
        logger.info(f"[CAPTAIN] Phase {phase.value} completed in {elapsed:.1f}s")

    # Phase completion handlers (called by agents)
    async def _handle_phase_complete(self, payload: Dict[str, Any]):
        phase = MissionPhase(payload.get("phase"))
        if phase in self._phase_complete_events:
            self._phase_complete_events[phase].set()

    # Message handling
    async def _handle_message(self, msg):
        """Handle incoming messages"""
        if msg.message_type == MessageType.TASK:
            # Captain doesn't execute tasks, delegates
            pass
        elif msg.message_type == MessageType.RESULT:
            await self._handle_result(msg)
        elif msg.message_type == MessageType.INTEL:
            await self._handle_intel(msg)
        elif msg.message_type == MessageType.ALERT:
            await self._handle_alert(msg)
        elif msg.message_type == MessageType.PHASE_CHANGE:
            if msg.payload.get("action") == "complete":
                await self._handle_phase_complete(msg.payload)

    async def _handle_result(self, msg):
        """Handle task results from agents"""
        logger.debug(f"[CAPTAIN] Result from {msg.from_agent}: {msg.payload.get('status', 'unknown')}")

    async def _handle_intel(self, msg):
        """Handle intelligence shared by agents"""
        intel_type = msg.payload.get("type", "unknown")
        logger.info(f"[CAPTAIN] Intel from {msg.from_agent}: {intel_type}")

        # Broadcast important intel to relevant agents
        if msg.payload.get("broadcast", False):
            await self.bus.publish(msg)

    async def _handle_alert(self, msg):
        """Handle alerts from agents (WAF detected, scope boundary, etc.)"""
        alert_type = msg.payload.get("type", "unknown")
        severity = msg.payload.get("severity", "medium")

        logger.warning(f"[CAPTAIN] ALERT from {msg.from_agent}: {alert_type} [{severity}]")

        # Make decision based on alert
        decision = await self._make_decision({
            "type": "alert_response",
            "alert_type": alert_type,
            "severity": severity,
            "source": msg.from_agent,
            "details": msg.payload
        })

        # Send decision back to agent
        await self.bus.publish(AgentMessage(
            from_agent=self.name,
            to_agent=msg.from_agent,
            message_type=MessageType.DECISION,
            payload=decision,
            priority=1
        ))

    # Decision making
    async def _make_decision(self, decision_request: Dict[str, Any]) -> Dict[str, Any]:
        """Make a Go/No-Go or strategic decision"""
        decision_type = decision_request.get("type", "unknown")
        payload = decision_request

        decision = {}

        if decision_type == "waf_bypass_strategy":
            decision = await self._decide_waf_bypass(payload)
        elif decision_type == "exploit_risk":
            decision = await self._assess_exploit_risk(payload)
        elif decision_type == "scope_boundary":
            decision = await self._check_scope_boundary(payload)
        elif decision_type == "resource_allocation":
            decision = await self._allocate_resources(payload)
        elif decision_type == "phase_transition":
            decision = await self._decide_phase_transition(payload)
        elif decision_type == "exploit_chain":
            decision = await self._decide_exploit_chain(payload)
        else:
            decision = {"decision": "defer", "reason": "unknown_decision_type"}

        # Log decision
        record = DecisionRecord(
            decision_id=str(uuid4()),
            timestamp=time.time(),
            decision_type=decision_type,
            payload=payload,
            decision=decision,
            rationale=decision.get("rationale", "")
        )
        self.decisions_log.append(record)

        return decision

    async def _decide_waf_bypass(self, payload: Dict) -> Dict:
        """Decide on WAF bypass strategy"""
        waf_name = payload.get("waf_name", "unknown")
        blocked_payloads = payload.get("blocked_payloads", [])
        current_phase = self.phase.value

        # Strategy matrix
        if waf_name.lower() in ["cloudflare", "akamai", "imperva"]:
            return {
                "decision": "proceed",
                "strategy": "encoding_fragmentation",
                "techniques": ["unicode_encoding", "case_variation", "comment_injection"],
                "rationale": f"{waf_name} vulnerable to encoding bypasses",
                "max_attempts": 5
            }
        elif "modsecurity" in waf_name.lower():
            return {
                "decision": "proceed",
                "strategy": "fragmentation_polymorphism",
                "techniques": ["whitespace_manipulation", "inline_comments", "hex_encoding"],
                "rationale": "ModSecurity rules bypassable via fragmentation",
                "max_attempts": 10
            }
        else:
            return {
                "decision": "proceed",
                "strategy": "adaptive_mutation",
                "techniques": ["random_case", "url_encoding", "double_encoding"],
                "rationale": "Unknown WAF, use adaptive approach",
                "max_attempts": 15
            }

    async def _assess_exploit_risk(self, payload: Dict) -> Dict:
        """Risk assessment for exploitation attempt"""
        exploit_type = payload.get("exploit_type", "unknown")
        target = payload.get("target", "unknown")
        potential_impact = payload.get("impact", "unknown")
        exploit_maturity = payload.get("maturity", "poc")  # poc, weaponized, reliable

        # Risk scoring
        risk_factors = {
            "destructive_potential": {"low": 1, "medium": 3, "high": 5, "critical": 7}.get(potential_impact, 3),
            "exploit_reliability": {"poc": 2, "weaponized": 4, "reliable": 5}.get(exploit_maturity, 2),
            "target_sensitivity": 3,  # default
            "reversibility": {"high": 1, "medium": 3, "low": 5}.get(payload.get("reversibility", "medium"), 3)
        }

        risk_score = sum(risk_factors.values()) / len(risk_factors)

        if risk_score >= 5:
            return {"decision": "deny", "reason": "risk_too_high", "score": risk_score, "factors": risk_factors}
        elif risk_score >= 3:
            return {"decision": "proceed_with_caution", "conditions": ["monitor", "capture_evidence", "limit_scope"], "score": risk_score}
        else:
            return {"decision": "approve", "score": risk_score}

    async def _check_scope_boundary(self, payload: Dict) -> Dict:
        """Check if target is within scope"""
        target = payload.get("target", "")
        scope = self.mission_context.scope if self.mission_context else []

        # Simple scope check (can be enhanced with proper scope matching)
        in_scope = any(s in target or target in s for s in scope)

        if not in_scope:
            return {"decision": "deny", "reason": "out_of_scope", "target": target, "scope": scope}
        return {"decision": "approve"}

    async def _allocate_resources(self, payload: Dict) -> Dict:
        """Allocate agents to tasks based on current load"""
        task_type = payload.get("task_type", "scan")
        available = self.registry.get_available_agents()

        # Map task types to agent roles
        role_mapping = {
            "recon": ["recon"],
            "scan": ["scanner", "recon"],
            "exploit": ["exploiter", "scanner"],
            "verify": ["verifier"],
            "report": ["reporter", "intel"]
        }

        preferred_roles = role_mapping.get(task_type, ["scanner"])
        candidates = [a for a in available if a in preferred_roles]

        if candidates:
            return {"decision": "assign", "agent": candidates[0]}
        else:
            # Queue task
            return {"decision": "queue", "reason": "no_available_agents"}

    async def _decide_phase_transition(self, payload: Dict) -> Dict:
        """Decide when to transition to next phase"""
        current_phase = self.phase
        findings_count = payload.get("findings_count", 0)
        coverage_score = payload.get("coverage_score", 0)
        time_elapsed = time.time() - self.phase_start_time

        # Transition criteria
        if current_phase == MissionPhase.RECON:
            if payload.get("tech_stack_identified", False):
                return {"decision": "transition", "next_phase": "planning", "reason": "tech_stack_identified"}

        elif current_phase == MissionPhase.PLANNING:
            if payload.get("attack_tree_generated", False):
                return {"decision": "transition", "next_phase": "scanning", "reason": "attack_tree_ready"}

        elif current_phase == MissionPhase.SCANNING:
            if coverage_score >= 0.8 or time_elapsed > 1800:  # 80% coverage or 30 min
                return {"decision": "transition", "next_phase": "exploitation", "reason": "coverage_or_timeout"}

        elif current_phase == MissionPhase.EXPLOITATION:
            if findings_count == 0 and time_elapsed > 1200:  # 20 min no findings
                return {"decision": "transition", "next_phase": "verification", "reason": "no_new_findings"}

        elif current_phase == MissionPhase.VERIFICATION:
            if payload.get("all_findings_verified", False):
                return {"decision": "transition", "next_phase": "reporting", "reason": "verification_complete"}

        return {"decision": "continue", "reason": "criteria_not_met"}

    async def _decide_exploit_chain(self, payload: Dict) -> Dict:
        """Decide on exploit chaining strategy"""
        findings = payload.get("findings", [])
        target = payload.get("target", "")

        # Analyze findings for chain potential
        chain_potential = self._analyze_chain_potential(findings)

        if chain_potential["score"] > 0.7:
            return {
                "decision": "chain",
                "chain": chain_potential["chain"],
                "rationale": chain_potential["rationale"]
            }
        else:
            return {"decision": "individual", "reason": "insufficient_chain_potential"}

    def _analyze_chain_potential(self, findings: List[Dict]) -> Dict:
        """Analyze findings for exploit chain potential"""
        # Simple heuristic - can be enhanced
        vuln_types = [f.get("type", "") for f in findings]

        chains = {
            "sqli_to_rce": {"requires": ["sqli", "file_upload"], "score": 0.9},
            "xss_to_session_hijack": {"requires": ["xss", "auth_bypass"], "score": 0.8},
            "ssrf_to_rce": {"requires": ["ssrf", "deserialization"], "score": 0.85},
            "auth_bypass_to_rce": {"requires": ["auth_bypass", "file_upload"], "score": 0.95},
        }

        best_chain = None
        best_score = 0

        for chain_name, chain_info in chains.items():
            if all(req in vuln_types for req in chain_info["requires"]):
                if chain_info["score"] > best_score:
                    best_score = chain_info["score"]
                    best_chain = chain_name

        return {
            "score": best_score,
            "chain": best_chain,
            "rationale": f"Chain {best_chain} possible" if best_chain else "No viable chain"
        }

    async def _generate_mission_report(self) -> Dict[str, Any]:
        """Generate final mission report"""
        return {
            "mission_id": self.mission_context.mission_id if self.mission_context else "unknown",
            "target": self.mission_context.target if self.mission_context else "unknown",
            "duration_seconds": time.time() - self.mission_start_time,
            "phases_completed": [p.value for p in MissionPhase if p in [MissionPhase.RECON, MissionPhase.PLANNING, MissionPhase.SCANNING, MissionPhase.EXPLOITATION, MissionPhase.VERIFICATION, MissionPhase.REPORTING]],
            "decisions_made": len(self.decisions_log),
            "decisions_log": [
                {
                    "type": d.decision_type,
                    "decision": d.decision.get("decision"),
                    "rationale": d.rationale
                }
                for d in self.decisions_log
            ],
            "agents_used": list(self.registry.agents.keys()),
            "status": "completed"
        }