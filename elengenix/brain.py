"""elengenix/brain.py - True AI Brain (Cognitive Core)"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Callable, Awaitable
from uuid import uuid4

from elengenix.types import (
    AIAction, ActionType, RiskLevel, MissionContext,
    Finding, ConstitutionalGuidance
)
from elengenix.constitution_engine import ConstitutionalAIEngine
from elengenix.memory import CognitiveMemoryManager
from elengenix.governance import GovernanceGate
from elengenix.tools import ToolRegistry

logger = logging.getLogger("elengenix.brain")


@dataclass
class CognitiveState:
    """สถานะทางการรู้ (Cognitive State)"""
    current_goal: str = ""
    active_plan: Optional["AttackPlan"] = None
    current_step: int = 0
    situation_awareness: Dict[str, Any] = field(default_factory=dict)
    working_memory: Dict[str, Any] = field(default_factory=dict)
    confidence: float = 0.5
    stress_level: float = 0.0  # 0-1
    focus_area: str = ""
    last_reflection: float = 0


@dataclass
class ReasoningResult:
    """ผลลัพธ์การให้เหตุผล"""
    reasoning_type: str  # deductive, inductive, abductive, analogical
    premise: str
    conclusion: str
    confidence: float
    evidence: List[Dict] = field(default_factory=list)
    alternative_hypotheses: List[str] = field(default_factory=list)
    reasoning_trace: List[str] = field(default_factory=list)


@dataclass
class AttackPlan:
    """แผนการโจมตี (Attack Plan)"""
    plan_id: str = field(default_factory=lambda: str(uuid4()))
    goal: str = ""
    target: str = ""
    phases: List["PlanPhase"] = field(default_factory=list)
    risk_assessment: Dict = field(default_factory=dict)
    resource_requirements: Dict = field(default_factory=dict)
    success_criteria: List[str] = field(default_factory=list)
    contingencies: List[str] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)


@dataclass
class PlanPhase:
    """ขั้นตอนในแผน"""
    phase_id: str = field(default_factory=lambda: str(uuid4()))
    name: str = ""
    objective: str = ""
    actions: List[Dict] = field(default_factory=list)
    dependencies: List[str] = field(default_factory=list)  # phase_ids
    tools: List[str] = field(default_factory=list)
    estimated_duration: int = 0  # seconds
    risk_level: str = "medium"
    success_criteria: List[str] = field(default_factory=list)


class PerceptionModule:
    """โมดูลรับรู้ (Perception) - รับรู้สถานการณ์"""

    def __init__(self, memory: "CognitiveMemoryManager", tools: "ToolRegistry"):
        self.memory = memory
        self.tools = tools

    async def perceive(self, context: "MissionContext") -> Dict[str, Any]:
        """รับรู้สถานการณ์ปัจจุบัน"""
        perception = {
            "timestamp": datetime.now().timestamp(),
            "target_status": await self._assess_target(context.target),
            "findings_summary": self._summarize_findings(),
            "coverage_gaps": self._identify_coverage_gaps(),
            "threat_landscape": await self._assess_threat_landscape(),
            "resource_status": self._assess_resources(),
            "threat_level": self._assess_threat_level(),
        }
        return perception

    async def _assess_target(self, target: str) -> Dict:
        return {"target": target, "status": "active", "last_seen": "now"}

    def _summarize_findings(self) -> Dict:
        return {"total": 0, "by_severity": {}, "by_type": {}}

    def _identify_coverage_gaps(self) -> List[str]:
        return []

    async def _assess_threat_landscape(self) -> Dict:
        return {"waf_detected": False, "rate_limits": []}

    def _assess_resources(self) -> Dict:
        return {"api_calls_remaining": 1000, "time_remaining": 3600}

    def _assess_threat_level(self) -> str:
        return "low"


class ReasoningEngine:
    """เครื่องมือให้เหตุผล (Reasoning Engine)

    Uses LLM to reason about situations using 6 different strategies.
    Each strategy generates a prompt and parses the response into a
    ReasoningResult with structured output.
    """

    def __init__(self, llm_client: Any, memory: "CognitiveMemoryManager"):
        self.llm = llm_client
        self.memory = memory
        self.reasoning_strategies = {
            "deductive": self._deductive_reasoning,
            "inductive": self._inductive_reasoning,
            "abductive": self._abductive_reasoning,
            "analogical": self._analogical_reasoning,
            "causal": self._causal_reasoning,
            "counterfactual": self._counterfactual_reasoning,
        }

    async def reason(
        self,
        situation: Dict[str, Any],
        goal: str,
        strategy: str = "abductive"
    ) -> ReasoningResult:
        """ให้เหตุผลเกี่ยวกับสถานการณ์"""
        strategy_func = self.reasoning_strategies.get(strategy, self._abductive_reasoning)
        return await strategy_func(situation, goal)

    def _call_llm(self, prompt: str) -> str:
        """Call LLM with a prompt string, returning the response text."""
        try:
            from tools.universal_ai_client import AIMessage
            response = self.llm.chat(
                [AIMessage(role="user", content=prompt)],
                temperature=0.3,
            )
            return response.content or ""
        except Exception as e:
            logger.warning(f"LLM call failed: {e}")
            return ""

    async def _abductive_reasoning(self, situation: Dict, goal: str) -> ReasoningResult:
        """Abductive Reasoning - หาคำอธิบายที่ดีที่สุดสำหรับการสังเกต"""
        prompt = f"""You are a security researcher using abductive reasoning.

Situation: {json.dumps(situation, default=str)}
Goal: {goal}

Using abductive reasoning, what is the best explanation for the observed situation?
What hypotheses best explain the observations?
What predictions do these hypotheses make?

Return JSON:
{{"premise": "what we observe", "conclusion": "best explanation", "confidence": 0.0-1.0, "evidence": ["evidence items"], "alternative_hypotheses": ["other explanations"]}}"""
        response = self._call_llm(prompt)
        return self._parse_reasoning(response, "abductive")

    async def _deductive_reasoning(self, situation: Dict, goal: str) -> ReasoningResult:
        """Deductive Reasoning - จากกฎทั่วไปสู่กรณีเฉพาะ"""
        prompt = f"""You are a security researcher using deductive reasoning.

Situation: {json.dumps(situation, default=str)}
Goal: {goal}

Using deductive reasoning, what logically follows from the known premises?
What must be true given the established facts?

Return JSON:
{{"premise": "known facts", "conclusion": "what logically follows", "confidence": 0.0-1.0, "evidence": ["supporting facts"], "alternative_hypotheses": ["other deductions"]}}"""
        response = self._call_llm(prompt)
        return self._parse_reasoning(response, "deductive")

    async def _inductive_reasoning(self, situation: Dict, goal: str) -> ReasoningResult:
        """Inductive Reasoning - จากตัวอย่างสู่กฎทั่วไป"""
        prompt = f"""You are a security researcher using inductive reasoning.

Situation: {json.dumps(situation, default=str)}
Goal: {goal}

Using inductive reasoning, what patterns emerge from the observations?
What general principles can be inferred?

Return JSON:
{{"premise": "observed patterns", "conclusion": "general principle", "confidence": 0.0-1.0, "evidence": ["pattern observations"], "alternative_hypotheses": ["other patterns"]}}"""
        response = self._call_llm(prompt)
        return self._parse_reasoning(response, "inductive")

    async def _analogical_reasoning(self, situation: Dict, goal: str) -> ReasoningResult:
        """Analogical Reasoning - เปรียบเทียบกับกรณีที่คล้ายกัน"""
        prompt = f"""You are a security researcher using analogical reasoning.

Situation: {json.dumps(situation, default=str)}
Goal: {goal}

What similar situations have been encountered before?
What worked/didn't work in those cases?
What analogies can guide the current approach?

Return JSON:
{{"premise": "similar cases", "conclusion": "recommended approach", "confidence": 0.0-1.0, "evidence": ["analogies found"], "alternative_hypotheses": ["other analogies"]}}"""
        response = self._call_llm(prompt)
        return self._parse_reasoning(response, "analogical")

    async def _causal_reasoning(self, situation: Dict, goal: str) -> ReasoningResult:
        """Causal Reasoning - หาสาเหตุและผล"""
        prompt = f"""You are a security researcher using causal reasoning.

Situation: {json.dumps(situation, default=str)}
Goal: {goal}

What are the causal relationships in this situation?
What causes what? What are the mechanisms?
What interventions would produce desired effects?

Return JSON:
{{"premise": "observed effects", "conclusion": "root causes", "confidence": 0.0-1.0, "evidence": ["causal chains"], "alternative_hypotheses": ["other causes"]}}"""
        response = self._call_llm(prompt)
        return self._parse_reasoning(response, "causal")

    async def _counterfactual_reasoning(self, situation: Dict, goal: str) -> ReasoningResult:
        """Counterfactual Reasoning - ถ้า...แล้วจะเกิดอะไร"""
        prompt = f"""You are a security researcher using counterfactual reasoning.

Situation: {json.dumps(situation, default=str)}
Goal: {goal}

What if we took a different approach?
What would happen if we didn't take the obvious action?
What are the alternative scenarios?

Return JSON:
{{"premise": "current plan", "conclusion": "alternative scenario", "confidence": 0.0-1.0, "evidence": ["counterfactual analysis"], "alternative_hypotheses": ["other scenarios"]}}"""
        response = self._call_llm(prompt)
        return self._parse_reasoning(response, "counterfactual")

    def _parse_reasoning(self, response: str, rtype: str) -> ReasoningResult:
        """Parse LLM response into structured ReasoningResult."""
        # Try to extract JSON from response
        try:
            # Try direct JSON parse
            data = json.loads(response)
        except (json.JSONDecodeError, TypeError):
            # Try to find JSON in markdown code block
            m = re.search(r"```(?:json)?\s*([\s\S]*?)\s*```", response)
            if m:
                try:
                    data = json.loads(m.group(1))
                except (json.JSONDecodeError, TypeError):
                    data = {}
            else:
                data = {}

        return ReasoningResult(
            reasoning_type=rtype,
            premise=data.get("premise", response[:200] if response else ""),
            conclusion=data.get("conclusion", response[:500] if response else ""),
            confidence=float(data.get("confidence", 0.7)),
            evidence=data.get("evidence", []),
            alternative_hypotheses=data.get("alternative_hypotheses", []),
            reasoning_trace=[response[:200]] if response else [],
        )


class PlanningEngine:
    """เครื่องมือวางแผน (Planning Engine)

    Generates AttackPlan from a high-level goal using LLM reasoning.
    Produces structured phases with actions, tools, and risk assessment.
    """

    def __init__(self, llm_client: Any, reasoning: "ReasoningEngine", memory: "CognitiveMemoryManager"):
        self.llm = llm_client
        self.reasoning = reasoning
        self.memory = memory

    def _call_llm(self, prompt: str) -> str:
        """Call LLM with a prompt, returning response text."""
        try:
            from tools.universal_ai_client import AIMessage
            response = self.llm.chat(
                [AIMessage(role="user", content=prompt)],
                temperature=0.3,
            )
            return response.content or ""
        except Exception as e:
            logger.warning(f"LLM call failed in planning: {e}")
            return ""

    async def plan(
        self,
        goal: str,
        context: "MissionContext",
        constraints: Optional[Dict] = None
    ) -> "AttackPlan":
        """สร้างแผนการโจมตีจากเป้าหมายระดับสูง"""

        # 1. Understand goal deeply
        goal_analysis = await self._analyze_goal(goal, context)

        # 2. Generate strategic plan via LLM
        plan = await self._generate_strategic_plan(goal_analysis, {}, context)

        # 3. Risk assessment
        plan.risk_assessment = {"overall": "medium", "by_phase": {}}

        return plan

    async def _analyze_goal(self, goal: str, context: "MissionContext") -> Dict:
        target = getattr(context, "target", "unknown")
        objectives = getattr(context, "objectives", [])
        objective_str = objectives[0] if objectives else "discover vulnerabilities"

        prompt = f"""Analyze this security testing goal for an AI-driven penetration test.

Goal: {goal}
Target: {target}
Objective: {objective_str}

Provide a brief analysis covering:
1. Primary attack vectors to investigate
2. Key tools needed (nmap, curl, ffuf, sqlmap, etc.)
3. Risk level and expected duration

Return JSON:
{{"attack_vectors": ["vector1", "vector2"], "tools_needed": ["tool1"], "risk": "low/medium/high", "duration_minutes": 30}}"""

        response = self._call_llm(prompt)
        try:
            return json.loads(response)
        except (json.JSONDecodeError, TypeError):
            # Fallback: parse JSON from text
            m = re.search(r"\{[\s\S]*\}", response)
            if m:
                try:
                    return json.loads(m.group(0))
                except json.JSONDecodeError:
                    pass
            return {"analysis": response, "attack_vectors": [], "tools_needed": [], "risk": "medium", "duration_minutes": 30}

    async def _assess_current_state(self, context: "MissionContext") -> Dict:
        return {"recon_complete": False, "scan_complete": False}

    async def _map_attack_surface(self, context: "MissionContext") -> Dict:
        return {"endpoints": [], "parameters": [], "auth_mechanisms": []}

    async def _generate_strategic_plan(
        self,
        goal_analysis: Dict,
        attack_surface: Dict,
        context: "MissionContext"
    ) -> "AttackPlan":
        target = getattr(context, "target", "unknown")
        objective = getattr(context, "objectives", ["discover vulnerabilities"])[0]

        prompt = f"""You are a security planning AI. Create an attack plan for a penetration test.

Target: {target}
Objective: {objective}
Goal Analysis: {json.dumps(goal_analysis, default=str)}

Generate a prioritized attack plan as JSON:
{{
  "phases": [
    {{"name": "Reconnaissance", "objective": "...", "tools": ["nmap", "dig"], "risk_level": "low", "actions": [{{"tool": "nmap", "params": {{}}}}]}},
    {{"name": "Scanning", "objective": "...", "tools": ["curl", "ffuf"], "risk_level": "medium", "actions": [{{"tool": "ffuf", "params": {{}}}}]}},
    {{"name": "Vulnerability Analysis", "objective": "...", "tools": ["python_scanner"], "risk_level": "medium", "actions": [{{"tool": "scanner", "params": {{}}}}]}}
  ],
  "risk_assessment": {{"overall": "medium"}},
  "success_criteria": ["Find at least one confirmed vulnerability"]
}}"""

        response = self._call_llm(prompt)

        # Parse the plan
        plan = AttackPlan(goal=objective, target=target)
        try:
            data = json.loads(response)
        except (json.JSONDecodeError, TypeError):
            m = re.search(r"\{[\s\S]*\}", response)
            if m:
                try:
                    data = json.loads(m.group(0))
                except json.JSONDecodeError:
                    data = {}
            else:
                data = {}

        plan.risk_assessment = data.get("risk_assessment", {"overall": "medium"})
        plan.success_criteria = data.get("success_criteria", ["Find vulnerabilities"])

        # Convert phases
        for phase_data in data.get("phases", []):
            phase = PlanPhase(
                name=phase_data.get("name", ""),
                objective=phase_data.get("objective", ""),
                tools=phase_data.get("tools", []),
                risk_level=phase_data.get("risk_level", "medium"),
                actions=phase_data.get("actions", []),
            )
            plan.phases.append(phase)

        return plan

    async def _generate_attack_steps(self, plan: "AttackPlan") -> List:
        """Generate attack steps from plan phases."""
        return []

    async def _decompose_into_phases(self, plan: "AttackPlan", context: "MissionContext") -> List:
        """Phases are already set in _generate_strategic_plan."""
        return plan.phases

    async def _assess_plan_risk(self, plan: "AttackPlan") -> Dict:
        return plan.risk_assessment or {"overall": "medium", "by_phase": {}}

    async def replan(self, failure: Dict, context: "MissionContext") -> "AttackPlan":
        """Replan after failure"""
        target = getattr(context, "target", "unknown")
        prompt = f"""The previous attack plan failed. Generate a recovery plan.

Failure details: {json.dumps(failure, default=str)[:500]}
Target: {target}

What went wrong? What alternative approaches exist?
Generate a new plan as JSON:
{{"phases": [{{"name": "...", "objective": "...", "tools": [...], "risk_level": "medium", "actions": []}}], "success_criteria": [...]}}"""

        response = self._call_llm(prompt)

        plan = AttackPlan(goal="recovery", target=target)
        try:
            data = json.loads(response)
        except (json.JSONDecodeError, TypeError):
            m = re.search(r"\{[\s\S]*\}", response)
            if m:
                try:
                    data = json.loads(m.group(0))
                except json.JSONDecodeError:
                    data = {}
            else:
                data = {}

        plan.success_criteria = data.get("success_criteria", ["Recover from failure"])
        for phase_data in data.get("phases", []):
            phase = PlanPhase(
                name=phase_data.get("name", "Recovery"),
                objective=phase_data.get("objective", ""),
                tools=phase_data.get("tools", []),
                risk_level=phase_data.get("risk_level", "medium"),
                actions=phase_data.get("actions", []),
            )
            plan.phases.append(phase)

        return plan


class DecisionEngine:
    """เครื่องตัดสินใจ (Decision Engine)"""

    def __init__(
        self,
        llm_client: Any,
        reasoning: "ReasoningEngine",
        constitutional_engine: "ConstitutionalAIEngine",
        governance: "GovernanceGate"
    ):
        self.llm = llm_client
        self.reasoning = reasoning
        self.constitutional = constitutional_engine
        self.governance = governance

    async def decide(
        self,
        situation: Dict[str, Any],
        available_actions: List[Dict],
        context: "MissionContext"
    ) -> "AIAction":
        """ตัดสินใจเลือกการกระทำ"""

        # 1. Filter by governance
        allowed_actions = await self._filter_by_governance(available_actions, context)

        if not allowed_actions:
            return AIAction(
                action_type=ActionType.REPORTING,
                description="No allowed actions available"
            )

        # 2. Constitutional Review
        votes = []
        for action in allowed_actions:
            try:
                vote = self.constitutional.review_action(action)
                action["constitutional_guidance"] = vote
                votes.append((action, vote))
            except Exception as e:
                logger.warning(f"Constitutional review failed for {action}: {e}")
                votes.append((action, None))

        # 3. AI decides with full context
        decision = await self._make_sovereign_decision(
            allowed_actions, context
        )

        return decision

    async def _filter_by_governance(self, actions: List[Dict], context) -> List[Dict]:
        allowed = []
        for action in actions:
            gate = self.governance.gate("mission", context.target, action)
            if gate.decision != "deny":
                action["governance_gate"] = gate
                allowed.append(action)
        return allowed

    async def _make_sovereign_decision(
        self,
        actions: List[Dict],
        context: "MissionContext"
    ) -> "AIAction":
        """AI เป็น Sovereign - ตัดสินใจเอง"""

        # Score each action
        scored_actions = []
        for action in actions:
            score = await self._score_action(action, context)
            action["score"] = score
            scored_actions.append(action)

        # Sort by score
        scored_actions.sort(key=lambda a: a["score"], reverse=True)

        # Check constitutional alignment for top choice
        top_choice = scored_actions[0]
        guidance = top_choice.get("constitutional_guidance")

        if guidance and not guidance.is_constitutional and guidance.requires_human_review:
            # Try next best
            for action in scored_actions[1:]:
                g = action.get("constitutional_guidance")
                if g and g.is_constitutional:
                    return self._create_action(action)
            # If all require human review, escalate
            return AIAction(
                action_type=ActionType.REPORTING,
                description="All options require human review"
            )

        return self._create_action(top_choice)

    async def _score_action(self, action: Dict, context: "MissionContext") -> float:
        """Score an action based on multiple factors."""
        score = 0.0

        # Constitutional alignment (0-0.3)
        guidance = action.get("constitutional_guidance")
        if guidance and guidance.is_constitutional:
            score += 0.3 * guidance.confidence

        # Mission alignment (0-0.25) - how relevant is this action to the goal
        score += 0.25 * self._mission_alignment(action, context)

        # Expected value (0-0.2) - potential impact
        score += 0.2 * self._expected_value(action, context)

        # Risk adjusted (0-0.15) - prefer lower risk
        score += 0.15 * (1.0 - self._risk_score(action))

        # Learning value (0-0.1) - novel exploration value
        score += 0.1 * self._learning_value(action)

        return score

    def _mission_alignment(self, action: Dict, context: "MissionContext") -> float:
        """Score how well action aligns with mission goal (0-1)."""
        target = getattr(context, "target", "")
        tool = action.get("tool", "")
        params = action.get("params", {})

        score = 0.5  # base

        # Higher score if tool targets the mission target
        if target and target in str(params):
            score += 0.2

        # Security tools get higher alignment for pentest missions
        security_tools = {"nmap", "ffuf", "sqlmap", "nikto", "curl", "dig", "subfinder",
                          "httpx", "nuclei", "ffuf", "gobuster", "dirsearch"}
        if tool.lower() in security_tools:
            score += 0.2

        return min(1.0, score)

    def _expected_value(self, action: Dict, context: "MissionContext") -> float:
        """Score expected value of action (0-1)."""
        tool = action.get("tool", "")
        params = action.get("params", {})

        score = 0.3  # base value

        # Higher value for tools that typically find vulnerabilities
        high_value_tools = {"sqlmap", "nuclei", "nikto", "ffuf", "gobuster"}
        if tool.lower() in high_value_tools:
            score += 0.3

        # Higher value for actions with specific targets/endpoints
        if params.get("endpoint") or params.get("url"):
            score += 0.2

        # Higher value for actions with payloads/techniques
        if params.get("payload") or params.get("technique"):
            score += 0.2

        return min(1.0, score)

    def _risk_score(self, action: Dict) -> float:
        """Score risk level of action (0-1, higher = riskier)."""
        tool = action.get("tool", "")
        params = action.get("params", {})
        risk_level = action.get("risk_level", "safe")

        score = 0.3  # base

        if risk_level == "high":
            score += 0.4
        elif risk_level == "medium":
            score += 0.2

        # Destructive tools
        destructive = {"rm", "mkfs", "dd", "shred"}
        if tool.lower() in destructive:
            score += 0.3

        return min(1.0, score)

    def _learning_value(self, action: Dict) -> float:
        """Score how much we can learn from this action (0-1)."""
        tool = action.get("tool", "")

        # Recon tools provide high learning value
        high_learning = {"nmap", "dig", "curl", "httpx", "whatweb", "wappalyzer"}
        if tool.lower() in high_learning:
            return 0.8

        # Scanning tools provide medium learning value
        medium_learning = {"ffuf", "gobuster", "nuclei", "nikto"}
        if tool.lower() in medium_learning:
            return 0.6

        return 0.4  # default

    def _create_action(self, action_dict: Dict) -> AIAction:
        return AIAction(
            action_type=ActionType(action_dict.get("action_type", "recon")),
            tool=action_dict.get("tool", ""),
            target=action_dict.get("target", ""),
            parameters=action_dict.get("parameters", {}),
            description=action_dict.get("description", ""),
            purpose=action_dict.get("purpose", ""),
            risk_level=RiskLevel(action_dict.get("risk_level", "safe"))
        )


class TrueAIBrain:
    """True AI Brain - Cognitive Core for Autonomous Agents"""

    def __init__(
        self,
        llm_client: Any,
        memory: "CognitiveMemoryManager",
        tools: "ToolRegistry",
        governance: "GovernanceGate",
        constitutional_engine: "ConstitutionalAIEngine",
        config: Optional[Dict] = None
    ):
        self.llm = llm_client
        self.memory = memory
        self.tools = tools
        self.governance = governance
        self.constitutional_engine = constitutional_engine
        self.config = config or {}

        # Initialize sub-modules
        self.perception = PerceptionModule(memory, tools)
        self.reasoning = ReasoningEngine(llm_client, memory)
        self.planner = PlanningEngine(llm_client, self.reasoning, memory)
        self.decision_engine = DecisionEngine(
            llm_client,
            self.reasoning,
            self.constitutional_engine,
            governance
        )

        self.logger = logging.getLogger("elengenix.brain.TrueAIBrain")

    async def understand_goal(self, goal: str, context: MissionContext) -> Dict:
        """Understand and analyze the mission goal"""
        return await self.planner._analyze_goal(goal, context)

    async def perceive(self, context: MissionContext) -> Dict:
        """Perceive the current situation"""
        return await self.perception.perceive(context)

    async def reason(self, situation: Dict, goal: str, strategy: str = "abductive") -> ReasoningResult:
        """Reason about the situation"""
        return await self.reasoning.reason(situation, goal, strategy)

    async def decide(
        self,
        context: MissionContext,
        available_actions: List[Dict],
        reflection: Optional[ReasoningResult] = None
    ) -> AIAction:
        """Decide on next action"""
        return await self.decision_engine.decide(
            self, context, available_actions, reflection
        )

    async def plan(self, goal: str, context: MissionContext) -> AttackPlan:
        """Generate attack plan"""
        return await self.planner.plan(goal, context)

    async def replan(self, failure: Dict, context: MissionContext) -> AttackPlan:
        """Replan after failure"""
        return await self.planner.replan(failure, context)

    async def verify_finding(self, finding: Finding) -> ConstitutionalGuidance:
        """Verify a finding using constitutional engine"""
        return await self.constitutional_engine.verify_action(finding)