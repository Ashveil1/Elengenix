"""elengenix/loop.py - True Agentic Loop (Autonomous Loop)"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Callable, Set
from uuid import uuid4

from elengenix.constitution import Constitution
from elengenix.constitution_engine import ConstitutionalAIEngine
from elengenix.types import (
    AIAction, ActionType, RiskLevel, MissionContext,
    MissionResult, Finding, ConstitutionalGuidance
)
from elengenix.brain import TrueAIBrain, CognitiveState, ReasoningResult
from elengenix.memory import CognitiveMemoryManager
from elengenix.governance import GovernanceGate
from elengenix.tools import ToolRegistry
from elengenix.types import MissionContext, Finding, ConstitutionalGuidance

logger = logging.getLogger("elengenix.loop")


@dataclass
class LoopConfig:
    """การตั้งค่าลูป"""
    max_steps: int = 100
    max_duration: int = 86400  # 24 hours
    max_cost: float = 100.0
    replan_threshold: float = 0.3  # Replan if confidence < 0.3
    reflection_interval: int = 10  # Reflect every N steps
    constitutional_check: bool = True
    auto_replan: bool = True
    max_consecutive_failures: int = 3


@dataclass
class LoopMetrics:
    """เมทริกของลูป"""
    steps_taken: int = 0
    successful_actions: int = 0
    failed_actions: int = 0
    replans: int = 0
    constitutional_violations: int = 0
    human_interventions: int = 0
    total_duration: float = 0.0
    total_cost: float = 0.0
    findings_discovered: int = 0
    findings_verified: int = 0
    unique_vuln_types: Set[str] = field(default_factory=set)


class TrueAgenticLoop:
    """
    True Agentic Loop - ลูป Agentic จริง
    - ไม่มี Fixed Pipeline
    - AI เป็น Sovereign
    - Constitutional Guidance at Every Step
    - Self-Correction | Self-Improvement | Emergence
    """

    def __init__(
        self,
        brain: "TrueAIBrain",
        constitution: Constitution,
        governance: GovernanceGate,
        tools: ToolRegistry,
        memory: CognitiveMemoryManager,
        config: Optional[LoopConfig] = None,
        metrics: Optional[Any] = None,
        callback: Optional[Callable] = None,
    ):
        self.brain = brain
        self.constitution = constitution
        self.constitutional_engine = ConstitutionalAIEngine(constitution)
        self.governance = governance
        self.tools = tools
        self.memory = memory
        self.config = config or LoopConfig()
        self.metrics = metrics or MetricsCollector()
        self.callback = callback

        self.mission_context: Optional[MissionContext] = None
        self.cognitive_state = CognitiveState()
        self.metrics_data = LoopMetrics()
        self._shutdown = False
        self._step_callbacks: List[Callable] = []

    async def run_mission(self, goal: str, context: MissionContext) -> MissionResult:
        """
        Run Mission - Fully Autonomous
        """
        self.mission_context = context
        start_time = time.time()

        logger.info(f"🚀 Mission started: {goal}")
        logger.info(f"   Target: {context.target}")
        logger.info(f"   Scope: {context.scope}")

        # 1. CONSTITUTIONAL OATH
        await self._constitutional_oath()

        # 2. GOAL UNDERSTANDING
        goal_understanding = await self.brain.understand_goal(goal, context)

        # 3. SOVEREIGN PLANNING
        plan = await self.brain.planner.plan(goal, context)

        # 4. INITIALIZE COGNITIVE STATE
        self.cognitive_state.current_goal = goal
        self.cognitive_state.active_plan = plan
        self.cognitive_state.step_count = 0

        # 5. AUTONOMOUS EXECUTION LOOP
        while not self._should_stop():

            step_start = time.time()

            # 4.1 PERCEPTION
            situation = await self.brain.perceive(self.mission_context)
            self.cognitive_state.situation_awareness = situation

            # 4.2 REASONING
            reasoning = await self.brain.reason(situation, self.cognitive_state.current_goal)

            # 4.3 DECISION (with Constitutional Guidance)
            action = await self.brain.decide(situation, self.cognitive_state.active_plan)

            # 4.4 CONSTITUTIONAL CHECK
            if self.config.constitutional_check:
                guidance = await self.constitutional_engine.review_action(action)
                action.constitutional_guidance = guidance

                if guidance.requires_human_review:
                    await self._request_human_review(action, guidance)

            # 4.5 EXECUTION
            result = await self._execute_action(action)

            # 4.6 REFLECTION & LEARNING
            await self._reflect_and_learn(action, result)

            # 4.7 UPDATE COGNITIVE STATE
            self._update_cognitive_state(action, result)

            # 4.8 REPLANNING CHECK
            if self.config.auto_replan and self._needs_replanning(result):
                await self._replan()

            # 4.9 CHECK COMPLETION
            if self._mission_complete(result):
                break

            # 4.9 UPDATE METRICS
            self._update_metrics(action, result, time.time() - step_start)

            # CALLBACK
            if self.callback:
                await self.callback(self._get_loop_status())

        # FINALIZE
        return await self._compile_mission_result(time.time() - start_time)

    async def _constitutional_oath(self):
        """Constitutional Oath - AI รับสัตยาบัน"""
        oath = """
        I, as an autonomous AI agent, solemnly swear to:
        1. Uphold the AI Constitution as Supreme Law
        2. Do No Harm, Respect Scope, Be Truthful
        3. Act with Proportionality, Transparency, Accountability
        4. Minimize Intrusion, Maximize Learning
        5. Be Accountable for Every Decision
        """
        logger.info(f"⚖️ Constitutional Oath Taken")
        await self.memory.remember(
            content=oath,
            category="constitutional_oath",
            importance=1.0
        )

    async def _execute_action(self, action: "AIAction") -> Dict[str, Any]:
        """Execute action with governance"""
        logger.info(f"⚡ Executing: {action.description}")

        # Governance Gate
        gate = await self.governance.gate(
            mission_id=self.mission_context.mission_id,
            target=action.target,
            action=action
        )

        if gate.decision == "deny":
            return {"success": False, "error": "Blocked by governance", "rationale": gate.rationale}

        if gate.decision == "needs_approval":
            # In autonomous mode, we might escalate or skip
            logger.warning(f"Action requires approval: {action.description}")
            return {"success": False, "error": "Requires approval", "gate": gate.decision}

        # Execute via Tool Registry
        try:
            result = await self.tools.execute(
                tool_name=action.tool,
                target=action.target,
                parameters=action.parameters
            )

            return {
                "success": result.success,
                "output": result.output,
                "findings": result.findings,
                "error": result.error_message,
                "duration": result.duration
            }
        except Exception as e:
            logger.error(f"Execution error: {e}")
            return {"success": False, "error": str(e)}

    async def _reflect_and_learn(self, action: "AIAction", result: Dict):
        """สะท้อนและเรียนรู้จากผลลัพธ์"""
        reflection = {
            "action": action.description,
            "expected": action.expected_outcome,
            "actual": result.get("output", ""),
            "success": result.get("success", False),
            "lessons": [],
            "adjustments": []
        }

        if not result.get("success"):
            reflection["lessons"].append(f"Action failed: {result.get('error')}")
            reflection["adjustments"].append("Try alternative approach or tool")
        else:
            reflection["lessons"].append("Action succeeded as expected")

        logger.info(f"Reflection result for {action.description}: {'Success' if result.get('success') else 'Failed'}")

        # Store in episodic memory
        await self.memory.remember(
            content=f"Action: {action.description} -> {'Success' if result.get('success') else 'Failed'}: {result.get('output', '')[:200]}",
            category="episodic",
            importance=0.7,
            metadata={"action": action.action_type.value, "success": result.get("success")}
        )

        # If findings, store in semantic memory
        if result.get("findings"):
            for finding in result["findings"]:
                await self.memory.remember(
                    content=f"Finding: {finding.get('type')} at {finding.get('location')} with payload {finding.get('payload')}",
                    category="semantic",
                    importance=0.8,
                    metadata=finding
                )

    def _update_cognitive_state(self, action: "AIAction", result: Dict):
        """อัปเดตสถานะทางการรู้"""
        self.cognitive_state.step_count += 1
        self.cognitive_state.last_reflection = time.time()

        if result.get("success"):
            self.cognitive_state.confidence = min(1.0, self.cognitive_state.confidence + 0.05)
        else:
            self.cognitive_state.confidence = max(0.1, self.cognitive_state.confidence - 0.1)
            self.cognitive_state.stress_level = min(1.0, self.cognitive_state.stress_level + 0.1)

    def _needs_replanning(self, result: Dict) -> bool:
        """ตรวจสอบว่าต้อง Replan หรือไม่"""
        if not self.config.auto_replan:
            return False

        # Replan if:
        # 1. Confidence too low
        # 2. Multiple consecutive failures
        # 3. Major unexpected finding
        # 4. Constitutional violation

        if self.cognitive_state.confidence < self.config.replan_threshold:
            return True

        if self.metrics_data.failed_actions >= self.config.max_consecutive_failures:
            return True

        return False

    async def _replan(self):
        """Replan - วางแผนใหม่"""
        logger.warning("🔄 Replanning triggered")
        self.metrics_data.replans += 1

        # Get current state
        context = self._get_current_context()

        # Generate new plan
        new_plan = await self.brain.planner.replan(
            failure_reason="replan_triggered",
            current_context=self.mission_context,
            current_plan=self.cognitive_state.active_plan
        )

        self.cognitive_state.active_plan = new_plan
        logger.info(f"📋 New plan generated: {len(new_plan.phases)} phases")

    def _mission_complete(self, result: Dict) -> bool:
        """ตรวจสอบว่าภารกิจเสร็จแล้วหรือไม่"""
        if self._shutdown:
            return True

        if self.metrics_data.steps_taken >= self.config.max_steps:
            logger.warning("Max steps reached")
            return True

        # Check if all plan phases completed
        if self.cognitive_state.active_plan:
            completed = all(s.completed for s in self.cognitive_state.active_plan.phases)
            if completed:
                return True

        # Check time/cost limits
        # ... implementation

        return False

    def _should_stop(self) -> bool:
        return self._shutdown or self._mission_complete({})

    def _update_metrics(self, action: "AIAction", result: Dict, duration: float):
        self.metrics_data.steps_taken += 1
        self.metrics_data.total_duration += duration

        if result.get("success"):
            self.metrics_data.successful_actions += 1
        else:
            self.metrics_data.failed_actions += 1

        if result.get("findings"):
            self.metrics_data.findings_discovered += len(result["findings"])
            for f in result["findings"]:
                self.metrics_data.unique_vuln_types.add(f.get("type", "unknown"))

    def _get_loop_status(self) -> Dict:
        return {
            "step": self.metrics_data.steps_taken,
            "phase": self.cognitive_state.active_plan.phases[self.cognitive_state.current_step].name if self.cognitive_state.active_plan and self.cognitive_state.current_step < len(self.cognitive_state.active_plan.phases) else "unknown",
            "confidence": self.cognitive_state.confidence,
            "stress": self.cognitive_state.stress_level,
            "findings": self.metrics_data.findings_discovered,
            "duration": self.metrics_data.total_duration
        }

    async def _compile_mission_result(self, duration: float) -> MissionResult:
        """รวบรวมผลลัพธ์ภารกิจ"""
        return MissionResult(
            mission_id=self.mission_context.mission_id,
            target=self.mission_context.target,
            duration_seconds=duration,
            phases_completed=[p.name for p in self.cognitive_state.active_plan.phases] if self.cognitive_state.active_plan else [],
            findings=self.memory.get_recent_findings(),
            verified_findings=self.memory.get_verified_findings(),
            coverage_score=0.0,  # Calculate
            risk_score=0.0,  # Calculate
            report_paths={},
            status="completed" if self._mission_complete({}) else "incomplete",
            summary=f"Mission completed in {duration:.1f}s with {self.metrics_data.steps_taken} steps",
            metadata={
                "steps": self.metrics_data.steps_taken,
                "replans": self.metrics_data.replans,
                "constitutional_violations": self.metrics_data.constitutional_violations,
                "unique_vuln_types": list(self.metrics_data.unique_vuln_types)
            }
        )

    async def _request_human_review(self, action: "AIAction", guidance: "ConstitutionalGuidance"):
        """Request human review for constitutional violation"""
        logger.warning(f"⚠️ Human review requested for: {action.description}")
        logger.warning(f"   Guidance: {guidance.ruling.considerations}")

        # In production, this would integrate with notification system
        # For now, log and continue

    def shutdown(self):
        """Shutdown gracefully"""
        self._shutdown = True
        logger.info("🛑 Shutdown signal received")


class MetricsCollector:
    """เก็บและแสดงเมทริก"""

    def __init__(self):
        self.counters: Dict[str, int] = {}
        self.gauges: Dict[str, float] = {}
        self.histograms: Dict[str, List[float]] = {}

    def increment(self, name: str, value: int = 1):
        self.counters[name] = self.counters.get(name, 0) + value

    def gauge(self, name: str, value: float):
        self.gauges[name] = value

    def histogram(self, name: str, value: float):
        if name not in self.histograms:
            self.histograms[name] = []
        self.histograms[name].append(value)

    def get_summary(self) -> Dict:
        return {
            "counters": self.counters,
            "gauges": self.gauges,
            "histograms": {k: {"count": len(v), "avg": sum(v)/len(v) if v else 0} for k, v in self.histograms.items()}
        }