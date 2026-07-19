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

        # Phase 1b: Forced strategy pivot.
        # When reflection says we should switch strategy, do not just
        # *suggest* the switch in the prompt (advisory only — the AI can
        # ignore it and keep looping). Instead, actuate a concrete mutation:
        # mark previously-used tools/vuln_classes as "deprioritized" so the
        # AI is nudged onto a fresh attack surface. This closes the gap
        # between "reflection recommends" and "reflection acts".
        forced_pivot = self._apply_forced_strategy_pivot(ctx, reflection)

        # Phase 2: AI decides with full context
        # Always ask AI, even if attack tree has steps
        # AI can choose to follow tree or override
        guidance = None
        if reflection.status == "stuck" or forced_pivot:
            # PentestPad insight: AI is weak at creative, hypothesis-driven
            # discovery. When stuck, push the agent off recognised patterns
            # onto a fresh, untested attack path. Use the *real* stuck
            # count (consecutive steps without findings) — not a hardcoded 0
            # (which was a bug that left the hypothesis boost idle).
            stuck_count = max(0, int(getattr(ctx, "consecutive_no_findings", 0)))
            from elengenix.scanning.hypothesis_boost import build_stuck_guidance
            guidance = build_stuck_guidance(self._hypothesis_boost, stuck_count=stuck_count)
            if forced_pivot:
                guidance = (guidance or "") + "\n\n" + forced_pivot
        decision = self._ai_dynamic_planning(ctx, user_input, reflection, guidance=guidance)

        decision.reflection = reflection
        return decision

    def _apply_forced_strategy_pivot(self, ctx: "ScanContext", reflection) -> Optional[str]:
        """Actuate a concrete strategy mutation when reflection asks for one.

        Previously, ``reflection.switch_strategy=True`` was only *suggested*
        in the prompt — the AI was free to ignore it and keep looping on
        the same low-value tool/endpoint. This method turns the suggestion
        into a concrete, machine-readable pivot:

        - Inspects ``ctx.action_history`` to find tools/vuln_classes that
          have dominated the last N steps.
        - Produces a "FORCED PIVOT" directive appended to the AI prompt
          instructing it to pick a *different* tool and/or vuln_class.
        - Records the pivot on the context so downstream observability
          (TUI, logs) can show that the strategy was force-changed.

        Returns:
            A guidance string to append to the AI prompt, or ``None``
            when no pivot is needed (reflection on-track / no history).
        """
        if reflection is None or not getattr(reflection, "switch_strategy", False):
            return None

        try:
            history = list(getattr(ctx, "action_history", []) or [])
            if not history:
                return None

            # Tally tools + purposes/actions from recent history
            from collections import Counter

            recent = history[-10:]
            tool_counts: Counter = Counter()
            action_counts: Counter = Counter()
            for entry in recent:
                if not isinstance(entry, dict):
                    continue
                tool = entry.get("tool") or entry.get("action") or "unknown"
                purpose = entry.get("purpose") or ""
                tool_counts[tool] += 1
                if purpose:
                    action_counts[purpose] += 1

            # Identify the most-repeated tool and purpose (the loop pattern)
            dominant_tool = tool_counts.most_common(1)[0][0] if tool_counts else None
            dominant_purpose = action_counts.most_common(1)[0][0] if action_counts else None

            parts = [
                "FORCED STRATEGY PIVOT (actuated by reflection):",
                "Reflection flagged the current strategy as not working. "
                "You must NOT repeat the most-recent tool/purpose.",
            ]
            if dominant_tool:
                parts.append(f"- Avoid tool/action: '{dominant_tool}' "
                             f"(used {tool_counts[dominant_tool]}x in last 10 steps)")
            if dominant_purpose:
                parts.append(f"- Avoid purpose: '{dominant_purpose}' "
                             f"(repeated {action_counts[dominant_purpose]}x)")
            parts.append(
                "- Pick a DIFFERENT vuln_class OR a DIFFERENT endpoint OR "
                "invent a novel probe you have not used yet. If you cannot, "
                "submit_findings for what you have, then finish."
            )

            # Record on ctx for observability / downstream consumption
            try:
                pivots = getattr(ctx, "strategy_pivots", None)
                if pivots is None:
                    pivots = []
                    setattr(ctx, "strategy_pivots", pivots)
                pivots.append({
                    "step": getattr(ctx, "step_count", 0),
                    "dominant_tool": dominant_tool,
                    "dominant_purpose": dominant_purpose,
                    "reason": getattr(reflection, "recommendation", "") or "reflection.switch_strategy",
                })
            except Exception:
                pass

            return "\n".join(parts)
        except Exception as e:
            logger.debug(f"forced pivot skipped: {e}")
            return None

    def _react_think_phase(
        self,
        ctx: "ScanContext",
        user_input: str,
        reflection,
        guidance: Optional[str] = None,
    ) -> Optional[str]:
        """Run a ReAct-style "think" turn before the decision call.

        The classical single-shot decision call asks the LLM to jump
        straight from context → JSON action. Modern agent design (ReAct,
        chain-of-thought, "think before you act") shows that giving the
        model a dedicated reasoning turn first — and then feeding that
        reasoning back into the decision call as assistant context —
        measurably improves action quality on hard targets.

        This method makes one extra (cheap) LLM call asking the model
        to reason step-by-step about what we know, what's most promising,
        and what to test next. The result is then attached to the
        decision call as assistant context.

        Returns:
            The model's free-form reasoning text, or ``None`` if the
            think phase should be skipped (no client, error, empty
            response, or disabled via config).
        """
        if self.ai_client is None:
            return None

        # Allow callers to disable the think phase if they want to skip
        # the extra LLM call (e.g. tight token budget). Default: enabled.
        if not getattr(self, "enable_react_think", True):
            return None

        try:
            from tools.universal_ai_client import AIMessage

            # Pull a compact summary of where we are so the think call
            # doesn't re-derive everything from scratch.
            try:
                findings_count = len(ctx.all_findings)
            except Exception:
                findings_count = 0
            try:
                step = ctx.step_count
            except Exception:
                step = 0
            try:
                gaps = len(ctx.coverage_map.get_gaps()) if ctx.coverage_map else 0
            except Exception:
                gaps = 0
            try:
                no_find = int(getattr(ctx, "consecutive_no_findings", 0))
            except Exception:
                no_find = 0

            reflection_summary = "on_track"
            if reflection is not None:
                reflection_summary = (
                    f"{getattr(reflection, 'status', 'on_track')} — "
                    f"{getattr(reflection, 'recommendation', '')[:200]}"
                )

            last_output_excerpt = ""
            try:
                lo = getattr(ctx, "last_output", "") or ""
                last_output_excerpt = lo[:1500]
            except Exception:
                pass

            think_prompt = _REACT_THINK_PROMPT.format(
                step=step,
                findings_count=findings_count,
                coverage_gaps=gaps,
                consecutive_no_findings=no_find,
                reflection=reflection_summary,
                last_output=last_output_excerpt,
                guidance=(guidance or "").strip() or "(none)",
                user_input=(user_input or "")[:300],
            )

            think_response = self.ai_client.chat(
                [
                    AIMessage(role="system", content=_REACT_THINK_SYSTEM),
                    AIMessage(role="user", content=think_prompt),
                ],
                temperature=0.2,
            )
            text = (think_response.content or "").strip()
            if not text:
                return None

            # Record trace for observability (TUI / logs / debugging).
            try:
                trace = getattr(self, "reasoning_trace", None)
                if trace is None:
                    trace = []
                    setattr(self, "reasoning_trace", trace)
                trace.append({"phase": "react_think", "content": text})
            except Exception:
                pass
            return text
        except Exception as e:
            logger.debug(f"ReAct think phase skipped: {e}")
            return None

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

        # ── Interactive mode: show last command output at the TOP ──
        # This makes the AI see the most recent shell output immediately,
        # like a human typing commands in a terminal.
        if ctx.last_output:
            interactive_section = "\n\n### LAST COMMAND OUTPUT (you just ran this):\n"
            interactive_section += f"Command: `{ctx.last_command}`\n"
            interactive_section += f"Success: {'Yes' if ctx.last_command_success else 'No'}\n"
            interactive_section += f"Output:\n```\n{ctx.last_output[:4000]}\n```\n"
            interactive_section += "\nBased on this output, decide your next move.\n"
            full_prompt = interactive_section + full_prompt
        if guidance:
            full_prompt = (
                full_prompt
                + "\n\n"
                + guidance
            )

        # Make the AI call
        try:
            from tools.universal_ai_client import ACTION_TOOLS, AIMessage

            # ── ReAct "think" phase ──
            # Before the AI commits to an action, give it a dedicated
            # reasoning turn: think step-by-step about what we know,
            # what's most promising, what to test next. This grounds the
            # subsequent decision call in actual reasoning rather than
            # jumping straight to a single-shot JSON action.
            think_text = self._react_think_phase(ctx, user_input, reflection, guidance)

            messages = [
                AIMessage(role="system", content=full_prompt),
            ]
            if think_text:
                # Provide the AI's own prior reasoning as assistant context
                messages.append(AIMessage(role="assistant", content=think_text))
                messages.append(AIMessage(
                    role="user",
                    content="Based on your reasoning above, choose the single best next action. Use the provided action tools.",
                ))
            else:
                messages.append(AIMessage(role="user", content="Plan next action"))

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

        # Add Learning Engine context (cross-session patterns)
        try:
            from tools.learning_engine import LearningEngine
            engine = LearningEngine()
            tech_stack = ctx.assets.get("tech_stack", []) if hasattr(ctx, 'assets') and ctx.assets else []
            tool_rankings = engine.rank_tools(tech_stack=tech_stack or None, vuln_class=None, limit=5)
            if tool_rankings:
                strategy_context += "### RECOMMENDED TOOLS (from past experience):\n"
                for tool, rate, samples in tool_rankings:
                    strategy_context += f"  - {tool}: {rate:.0%} success rate ({samples} samples)\n"
                strategy_context += "\n"
        except Exception as e:
            logger.debug(f"Could not load learning context: {e}")

        # Add instructions
        strategy_context += "### YOUR DECISION:\n"
        strategy_context += "Based on all the above context, decide your next action.\n"
        strategy_context += "Consider:\n"
        strategy_context += "- What has NOT been tested yet? (coverage gaps)\n"
        strategy_context += "- What findings suggest? (escalate? chain? pivot?)\n"
        strategy_context += "- What would be most efficient? (don't waste steps)\n"
        strategy_context += "- Is the attack tree still relevant? (override if needed)\n"
        strategy_context += "- What tools worked best in the past? (check RECOMMENDED TOOLS)\n"

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


# ═══════════════════════════════════════════════════════════════════════════
# ReAct "think" phase prompts
# ═══════════════════════════════════════════════════════════════════════════

_REACT_THINK_SYSTEM = """You are the reasoning step of an autonomous security agent.

This turn is for THINKING ONLY. Do NOT produce an action JSON, do NOT
call any tools. Reason step-by-step like a senior pentester who is
explaining their thinking out loud before they type the next command.

Your reasoning will be fed back into the next turn as your own prior
context, so the decision call is grounded in actual analysis rather
than a single-shot guess.

Be honest about uncertainty. Surface what is NOT known. Identify the
single highest-value next probe and justify why."""


_REACT_THINK_PROMPT = """Reason step-by-step about the current state of this security scan
before any action is chosen.

## Mission
{user_input}

## Where we are
- Step: {step}
- Findings so far: {findings_count}
- Coverage gaps: {coverage_gaps}
- Consecutive steps without new findings: {consecutive_no_findings}
- Reflection says: {reflection}
- Forced guidance (if any): {guidance}

## Most recent command output (if any)
```
{last_output}
```

## Your job (THINK ONLY — no action JSON)

1. What do we actually KNOW from the evidence so far? List 2-3 concrete facts.
2. What is the most promising attack vector RIGHT NOW, and why?
3. What is the single highest-value next probe? Be specific: command or endpoint.
4. What could go wrong with that probe? What's the fallback?
5. Are we stuck on a pattern? Should we pivot — and to what?
6. If you had ONE more command to run, what is it and what would the
   output tell us?

Reply as plain prose. Do NOT call tools. Do NOT output JSON."""

