"""
agents/decision_engine.py — AI Decision Engine

Decides what the AI should do next in each step of the scan loop.
Combines reflection (coverage/belief/velocity check) with attack tree
following and AI dynamic planning.

Extracted from agent_brain.py process_query() lines 1046-1181.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Callable, Dict, List, Optional

if TYPE_CHECKING:
    from elengenix.scanning.prompt_builder import PromptBuilder
    from elengenix.scanning.scan_context import ScanContext

logger = logging.getLogger("elengenix.decision_engine")


@dataclass
class Reflection:
    """Result of the reflection phase."""

    status: str = "on_track"  # on_track, needs_adaptation, stuck
    switch_strategy: bool = False
    recommendation: str = ""
    coverage_gaps: int = 0
    active_beliefs: int = 0


@dataclass
class Decision:
    """A decision about what to do next.

    Attributes:
        action_data: The action dict to execute (matches ACTION_TOOLS schema).
        reasoning: Why this action was chosen.
        source: How the decision was made ("attack_tree", "ai_dynamic", "reflection").
        reflection: The reflection result that influenced this decision.
    """

    action_data: Dict[str, Any] = field(default_factory=dict)
    reasoning: str = ""
    source: str = ""
    reflection: Optional[Reflection] = None


class DecisionEngine:
    """Decides what the AI should do next in each scan step.

    Combines three decision sources with AI having ultimate authority:
    1. Reflection — checks coverage gaps and velocity
    2. Attack tree — provides suggested steps (AI can override)
    3. AI dynamic planning — AI decides based on full context

    Key principle: AI has final say on strategy, not hardcoded rules.

    Args:
        ai_client: The AI client for dynamic planning calls.
        prompt_builder: For building scan prompts.
        base_prompt: The system prompt text.
        cot_logger: Optional chain-of-thought logger.
        activity_logger: Optional activity display logger.
        callback: Optional callback for live output.
    """

    def __init__(
        self,
        ai_client=None,
        prompt_builder: Optional[PromptBuilder] = None,
        base_prompt: str = "",
        cot_logger=None,
        activity_logger=None,
        callback: Optional[Callable] = None,
    ):
        self.ai_client = ai_client
        self.prompt_builder = prompt_builder
        self.base_prompt = base_prompt
        self.cot_logger = cot_logger
        self.activity_logger = activity_logger
        self.callback = callback
        self.last_reflection: Optional[Reflection] = None
        # Hypothesis boost used when the scan gets stuck on known patterns
        # (off-script, creative exploration per PentestPad 2026 insight).
        from elengenix.scanning.hypothesis_boost import HypothesisBoost
        self._hypothesis_boost = HypothesisBoost()

    def decide(
        self,
        ctx: "ScanContext",
        user_input: str,
        reflect_engine=None,
    ) -> Decision:
        """Decide what to do next.

        AI has final authority on strategy. The attack tree is a suggestion,
        not a command. AI can override it based on context.

        Flow:
        1. Get reflection status (coverage gaps, velocity)
        2. Build context for AI (attack tree, findings, beliefs)
        3. AI decides: follow tree, override, or new approach
        4. Return decision with reasoning

        Args:
            ctx: The scan context (all state).
            user_input: The user's original request.
            reflect_engine: The reflection engine instance.

        Returns:
            Decision with action_data, reasoning, and source.
        """
        step = ctx.step_count

        # Phase 1: Reflection
        reflection = self._reflect(ctx, reflect_engine, step, user_input)
        self.last_reflection = reflection

        # Phase 2: AI decides with full context
        # Always ask AI, even if attack tree has steps
        # AI can choose to follow tree or override
        guidance = None
        if reflection.status == "stuck":
            # PentestPad insight: AI is weak at creative, hypothesis-driven
            # discovery. When stuck, push the agent off recognised patterns
            # onto a fresh, untested attack path.
            from elengenix.scanning.hypothesis_boost import build_stuck_guidance
            guidance = build_stuck_guidance(self._hypothesis_boost, stuck_count=0)
        decision = self._ai_dynamic_planning(ctx, user_input, reflection, guidance=guidance)

        decision.reflection = reflection
        return decision

    def _reflect(
        self,
        ctx: "ScanContext",
        reflect_engine,
        step: int,
        user_input: str,
    ) -> Reflection:
        """Run the reflection phase.

        Checks coverage gaps, belief state, and velocity to determine
        if the current strategy is working.

        Args:
            ctx: The scan context.
            reflect_engine: The reflection engine instance.
            step: Current step number.
            user_input: The user's original request.

        Returns:
            Reflection result with status and recommendation.
        """
        if reflect_engine is None:
            return Reflection(status="on_track")

        try:
            # Get coverage and belief state from context
            coverage_map = ctx.coverage_map
            belief_state = ctx.belief_state

            if coverage_map is None or belief_state is None:
                return Reflection(status="on_track")

            reflection_result = reflect_engine.reflect(
                cycle=step,
                coverage_map=coverage_map,
                belief_state=belief_state,
                recent_findings_count=ctx.cycle_findings_count,
            )

            # Extract info from the reflection result
            status = getattr(reflection_result, "status", "on_track")
            switch = getattr(reflection_result, "switch_strategy", False)
            recommendation = getattr(reflection_result, "recommendation", "")

            # Count coverage gaps and beliefs
            try:
                gaps = len(coverage_map.get_gaps())
            except Exception:
                gaps = 0
            try:
                beliefs = len(belief_state.get_active_beliefs())
            except Exception:
                beliefs = 0

            reflection = Reflection(
                status=status,
                switch_strategy=switch,
                recommendation=recommendation,
                coverage_gaps=gaps,
                active_beliefs=beliefs,
            )

            # Log to chain of thought
            if self.cot_logger:
                self.cot_logger.log(
                    step=step,
                    context=user_input,
                    reasoning=f"Reflection: {status} — {recommendation[:80]}",
                    action="reflect",
                    result=f"coverage_gaps={gaps}, beliefs={beliefs}",
                    confidence=0.9,
                )

            # Display strategy switch warning
            if switch and self.callback:
                self.callback(f"[Reflection] Strategy switch needed: {recommendation[:100]}")

            return reflection

        except Exception as e:
            logger.debug(f"Reflection failed: {e}")
            return Reflection(status="on_track")

    def _follow_attack_tree(self, ctx: "ScanContext", step: int) -> Decision:
        """Follow the pre-planned attack tree.

        Args:
            ctx: The scan context.
            step: Current step number.

        Returns:
            Decision with the attack tree step's action.
        """
        current_step = ctx.attack_tree.steps[step]
        tool_name = current_step.tool_name

        action_data = {
            "action": "run_shell",
            "command": f"{tool_name} {ctx.target}",
            "tool": tool_name,
            "purpose": current_step.purpose,
        }
        reasoning = f"{current_step.purpose}"

        return Decision(
            action_data=action_data,
            reasoning=reasoning,
            source="attack_tree",
        )

    def _ai_dynamic_planning(
        self, ctx: "ScanContext", user_input: str, reflection=None, guidance: Optional[str] = None
    ) -> Decision:
        """Use AI to decide the next action.

        AI has full authority to:
        - Follow the attack tree (if it agrees with the plan)
        - Override the attack tree (if it has a better idea)
        - Create a completely new approach
        - Declare stuck or finished

        The attack tree is a SUGGESTION, not a command.

        Args:
            ctx: The scan context.
            user_input: The user's original request.
            reflection: The reflection result.

        Returns:
            Decision with the AI's chosen action.
        """
        if self.ai_client is None or self.prompt_builder is None:
            logger.warning("AI client or prompt builder not available")
            return Decision(
                action_data={"action": "finish", "summary": "No AI client available"},
                reasoning="AI client unavailable, finishing mission",
                source="fallback",
            )

        # Build the prompt with enhanced strategy context
        full_prompt = self._build_strategy_prompt(ctx, user_input, reflection)
        if guidance:
            full_prompt = (
                full_prompt
                + "\n\n"
                + guidance
            )

        # Make the AI call
        try:
            from tools.universal_ai_client import ACTION_TOOLS, AIMessage

            messages = [
                AIMessage(role="system", content=full_prompt),
                AIMessage(role="user", content="Plan next action"),
            ]

            # Show spinner during AI call
            try:
                from cli.ui_components import show_spinner

                with show_spinner("AI Agent is planning its next move...", spinner_style="#ffffff"):
                    response = self.ai_client.chat(
                        messages,
                        temperature=0.3,  # Slightly higher temp for creative strategy
                        tools=ACTION_TOOLS,
                    )
            except ImportError:
                response = self.ai_client.chat(
                    messages,
                    temperature=0.3,
                    tools=ACTION_TOOLS,
                )

            # Parse response: prefer native tool_calls, fallback to JSON
            if response.tool_calls:
                tc = response.tool_calls[0]
                action_data = {
                    "action": tc.name,
                    **tc.arguments,
                }
            else:
                action_data = self._extract_json(response.content) or {}

            reasoning = action_data.get("purpose", "continue investigation")

            return Decision(
                action_data=action_data,
                reasoning=reasoning,
                source="ai_dynamic",
            )

        except Exception as e:
            logger.error(f"AI dynamic planning failed: {e}")
            return Decision(
                action_data={"action": "finish", "summary": f"AI planning error: {e}"},
                reasoning=f"AI planning failed: {e}",
                source="fallback",
            )

    def _build_strategy_prompt(self, ctx: "ScanContext", user_input: str, reflection=None) -> str:
        """Build a strategy-focused prompt for AI decision making.

        Gives AI full context and authority to override the attack tree.
        """
        # Get base prompt from prompt builder
        if self.prompt_builder:
            base = self.prompt_builder.build_scan_prompt(ctx, user_input)
        else:
            base = self.base_prompt

        # Add strategy-specific context
        strategy_context = "\n\n### STRATEGY AUTHORITY:\n"
        strategy_context += "You have FULL AUTHORITY to decide the attack strategy.\n"
        strategy_context += "The attack tree below is a SUGGESTION from the planning phase.\n"
        strategy_context += "You can:\n"
        strategy_context += "1. FOLLOW the attack tree (if the plan looks good)\n"
        strategy_context += "2. OVERRIDE the attack tree (if you have a better idea)\n"
        strategy_context += "3. CREATE a new approach (if the plan is wrong)\n"
        strategy_context += "4. SKIP steps (if they're not relevant)\n"
        strategy_context += "5. REPRIORITIZE (if findings change the picture)\n\n"

        # Add attack tree context
        if ctx.attack_tree and ctx.attack_tree.steps:
            remaining_steps = ctx.attack_tree.steps[ctx.step_count :]
            strategy_context += "### SUGGESTED ATTACK TREE (you can override):\n"
            for i, step in enumerate(remaining_steps[:5]):  # Show next 5 steps
                phase_name = step.phase.value if hasattr(step.phase, "value") else str(step.phase)
                strategy_context += f"  {i+1}. [{phase_name}] {step.tool_name}: {step.purpose}\n"
            strategy_context += "\n"

        # Add reflection context
        if reflection:
            strategy_context += f"### REFLECTION STATUS:\n"
            strategy_context += f"  - Status: {reflection.status}\n"
            strategy_context += f"  - Coverage gaps: {reflection.coverage_gaps} untested areas\n"
            strategy_context += f"  - Active beliefs: {reflection.active_beliefs} hypotheses\n"
            if reflection.switch_strategy:
                strategy_context += "  - RECOMMENDATION: Consider changing strategy\n"
            strategy_context += "\n"

        # Add findings context
        if ctx.has_findings:
            strategy_context += f"### FINDINGS SO FAR ({ctx.finding_count} total):\n"
            severity_count = {}
            for f in ctx.all_findings:
                sev = f.get("severity", "unknown")
                severity_count[sev] = severity_count.get(sev, 0) + 1
            for sev, count in sorted(severity_count.items()):
                strategy_context += f"  - {sev}: {count}\n"
            strategy_context += "\n"

        # Add velocity context
        strategy_context += f"### VELOCITY:\n"
        strategy_context += f"  - Steps taken: {ctx.step_count}/{ctx.max_steps}\n"
        strategy_context += f"  - Consecutive no-findings: {ctx.consecutive_no_findings}\n"
        strategy_context += f"  - Steps remaining: {ctx.steps_remaining}\n\n"

        # Add instructions
        strategy_context += "### YOUR DECISION:\n"
        strategy_context += "Based on all the above context, decide your next action.\n"
        strategy_context += "Consider:\n"
        strategy_context += "- What has NOT been tested yet? (coverage gaps)\n"
        strategy_context += "- What findings suggest? (escalate? chain? pivot?)\n"
        strategy_context += "- What would be most efficient? (don't waste steps)\n"
        strategy_context += "- Is the attack tree still relevant? (override if needed)\n"

        return base + strategy_context

    def _extract_json(self, text: str) -> Optional[Dict[str, Any]]:
        """Extract JSON from AI response text.

        Uses the hardened extract_json from agent_helpers if available,
        falls back to basic parsing.
        """
        if not text:
            return None

        # Try the hardened extractor first
        try:
            from elengenix.scanning.helpers import extract_json

            return extract_json(text)
        except ImportError:
            pass

        # Fallback: basic JSON extraction
        import json

        # Try direct parse
        try:
            return json.loads(text)
        except (json.JSONDecodeError, TypeError):
            pass

        # Try to find JSON in markdown code block
        import re

        json_match = re.search(r"```(?:json)?\s*\n?(.*?)\n?\s*```", text, re.DOTALL)
        if json_match:
            try:
                return json.loads(json_match.group(1))
            except (json.JSONDecodeError, TypeError):
                pass

        # Try to find JSON object in text
        brace_match = re.search(r"\{[^{}]*\}", text, re.DOTALL)
        if brace_match:
            try:
                return json.loads(brace_match.group(0))
            except (json.JSONDecodeError, TypeError):
                pass

        return None
