"""
agents/prompt_builder.py — AI Prompt Assembly

Builds prompts for the AI decision engine. Centralizes all context
sources (memory, mission state, coverage, beliefs, reflection, etc.)
into a single, well-structured prompt with token budget management.

Extracted from agent_brain.py process_query() lines 1086-1157.
"""

from __future__ import annotations

import json
import logging
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Tuple

if TYPE_CHECKING:
    from agents.scan_context import ScanContext

logger = logging.getLogger("elengenix.prompt_builder")

# Rough token estimate: ~4 chars per token (English)
CHARS_PER_TOKEN = 4


def _estimate_tokens(text: str) -> int:
    """Rough token estimate."""
    return len(text) // CHARS_PER_TOKEN


class PromptBuilder:
    """Builds prompts for the AI decision engine.

    Reads from ScanContext (shared reference) without modifying it.
    Manages token budget by truncating lower-priority sections when
    the prompt gets too long.

    Args:
        base_prompt: The system prompt text (from prompts/system_prompt.txt).
        max_tokens: Maximum tokens for the full prompt (default 8000).
    """

    def __init__(self, base_prompt: str, max_tokens: int = 8000):
        self.base_prompt = base_prompt
        self.max_tokens = max_tokens

    def build_scan_prompt(self, ctx: "ScanContext", user_input: str) -> str:
        """Build the full prompt for scan/reasoning mode.

        Assembles 13 context sources into a single prompt:
        1. System prompt + planning instructions
        2. Available tools list
        3. Semantic memory context
        4. Related memories
        5. Chat history
        6. Previous results summary
        7. Mission state snapshot
        8. Coverage gaps
        9. Active hypotheses
        10. Reflection status
        11. Negative results

        Args:
            ctx: The scan context (all state).
            user_input: The user's original request.

        Returns:
            The assembled prompt string.
        """
        sections: List[Tuple[str, int]] = []

        # Priority 1: System prompt (always full)
        sections.append((self.base_prompt, 0))  # 0 = never truncate

        # Priority 2: Tool list (always full)
        tool_list = self._build_tool_list()
        sections.append((tool_list, 0))

        # Priority 3: Strategy authority (high priority - NEW)
        strategy_section = self._build_strategy_authority(ctx)
        sections.append((strategy_section, 600))

        # Priority 4: Attack tree suggestion (high priority - NEW)
        attack_tree_section = self._build_attack_tree_context(ctx)
        sections.append((attack_tree_section, 500))

        # Priority 5: Mission state (high priority)
        mission_section = self._build_mission_state(ctx)
        sections.append((mission_section, 800))

        # Priority 6: Coverage gaps (high priority)
        coverage_section = self._build_coverage(ctx)
        sections.append((coverage_section, 400))

        # Priority 7: Active hypotheses (high priority)
        beliefs_section = self._build_beliefs(ctx)
        sections.append((beliefs_section, 400))

        # Priority 8: Reflection (medium priority)
        reflection_section = self._build_reflection(ctx)
        sections.append((reflection_section, 300))

        # Priority 9: Negative results (medium priority)
        negative_section = self._build_negative_results(ctx)
        sections.append((negative_section, 300))

        # Priority 10: Previous results (medium priority)
        results_section = self._build_results_summary(ctx)
        sections.append((results_section, 500))

        # Priority 11: Semantic memory (lower priority)
        memory_section = self._build_memory_context(ctx, user_input)
        sections.append((memory_section, 600))

        # Priority 12: Related memories (lower priority)
        related_section = self._build_related_memories(ctx, user_input)
        sections.append((related_section, 400))

        # Priority 11: Chat history (lowest priority)
        history_section = self._build_history(ctx)
        sections.append((history_section, 400))

        # Assemble with budget management
        prompt = self._assemble_with_budget(sections)

        # Add planning instructions (always at the end, always full)
        prompt += _PLANNING_INSTRUCTIONS

        return prompt

    def build_chat_prompt(
        self, ctx: "ScanContext", user_input: str, intent: str
    ) -> str:
        """Build prompt for casual/security chat mode.

        Simpler than scan mode — just system prompt + memory + history.

        Args:
            ctx: The scan context.
            user_input: The user's message.
            intent: Intent category (casual, research, security_chat).

        Returns:
            The chat prompt string.
        """
        now_context = self._get_now_context()
        past_memories = self._build_memory_context(ctx, user_input)

        return f"""You are Elengenix AI v3.0, an expert security assistant and conversational AI.
Intent category: {intent}

{now_context}

{past_memories}

If the intent is 'casual', be friendly and conversational.
If the intent is 'research', provide accurate information or web research.
If the intent is 'security_chat', provide expert cybersecurity advice or code examples.
Do NOT attempt to run a scan. Respond naturally in the user's language (English or Thai)."""

    def _build_tool_list(self) -> str:
        """Get available tools from the registry."""
        try:
            from tools.tool_registry import registry

            available_tools = registry.list_available_tools()
            tool_names = [
                name
                for name, info in available_tools.items()
                if info.get("available", False)
            ]
            tool_list = ", ".join(tool_names) if tool_names else "No tools currently available"
        except Exception as e:
            logger.debug(f"Could not load tool registry: {e}")
            tool_list = "Tool registry unavailable"

        return f"### AVAILABLE TOOLS:\n{tool_list}"

    def _build_strategy_authority(self, ctx: "ScanContext") -> str:
        """Build strategy authority context for AI decision making."""
        lines = ["### STRATEGY AUTHORITY:"]
        lines.append("You have FULL AUTHORITY to decide the attack strategy.")
        lines.append("The attack tree below is a SUGGESTION from the planning phase.")
        lines.append("You can:")
        lines.append("1. FOLLOW the attack tree (if the plan looks good)")
        lines.append("2. OVERRIDE the attack tree (if you have a better idea)")
        lines.append("3. CREATE a new approach (if the plan is wrong)")
        lines.append("4. SKIP steps (if they're not relevant)")
        lines.append("5. REPRIORITIZE (if findings change the picture)")
        lines.append("")

        # Add velocity context
        lines.append(f"### VELOCITY:")
        lines.append(f"  - Steps taken: {ctx.step_count}/{ctx.max_steps}")
        lines.append(f"  - Consecutive no-findings: {ctx.consecutive_no_findings}")
        lines.append(f"  - Steps remaining: {ctx.steps_remaining}")
        lines.append("")

        # Add findings summary
        if ctx.has_findings:
            lines.append(f"### FINDINGS SO FAR ({ctx.finding_count} total):")
            severity_count = {}
            for f in ctx.all_findings:
                sev = f.get("severity", "unknown")
                severity_count[sev] = severity_count.get(sev, 0) + 1
            for sev, count in sorted(severity_count.items()):
                lines.append(f"  - {sev}: {count}")
            lines.append("")

        return "\n".join(lines)

    def _build_attack_tree_context(self, ctx: "ScanContext") -> str:
        """Build attack tree context for AI decision making."""
        if not ctx.attack_tree or not ctx.attack_tree.steps:
            return "### ATTACK TREE:\nNo attack tree available. You have full freedom to choose your approach.\n"

        remaining_steps = ctx.attack_tree.steps[ctx.step_count:]
        if not remaining_steps:
            return "### ATTACK TREE:\nAttack tree completed. You have full freedom to choose your approach.\n"

        lines = ["### SUGGESTED ATTACK TREE (you can override):"]
        for i, step in enumerate(remaining_steps[:5]):  # Show next 5 steps
            phase_name = step.phase.value if hasattr(step.phase, 'value') else str(step.phase)
            lines.append(f"  {i+1}. [{phase_name}] {step.tool_name}: {step.purpose}")
        lines.append("")
        lines.append("Remember: This is a SUGGESTION. You can override it if you have a better idea.")
        lines.append("")

        return "\n".join(lines)

    def _build_memory_context(self, ctx: "ScanContext", user_input: str) -> str:
        """Build semantic memory + related memories context."""
        try:
            from tools.vector_memory import get_context_for_ai, recall

            semantic_context = get_context_for_ai(
                current_query=user_input,
                target=ctx.target or "universal",
                max_memories=15,
            )
        except Exception as e:
            logger.debug(f"Could not load semantic memory: {e}")
            semantic_context = ""

        return semantic_context

    def _build_related_memories(self, ctx: "ScanContext", user_input: str) -> str:
        """Build semantically related memories context."""
        try:
            from tools.vector_memory import recall

            related_memories = recall(
                query=user_input, target=ctx.target, n_results=5
            )
        except Exception as e:
            logger.debug(f"Could not load related memories: {e}")
            related_memories = []

        if not related_memories:
            return ""

        lines = ["### SEMANTICALLY RELATED PAST MEMORIES:"]
        for mem in related_memories:
            content = mem["content"][:100]
            sim = mem.get("similarity", 0)
            lines.append(f"- {content}... (relevance: {sim:.0%})")
        return "\n".join(lines)

    def _build_history(self, ctx: "ScanContext") -> str:
        """Build chat history section."""
        recent = ctx.history[-10:] if ctx.history else []
        if not recent:
            return ""

        lines = ["### CHAT HISTORY (Current Session):"]
        for msg in recent:
            lines.append(f"{msg['role'].capitalize()}: {msg['content']}")
        return "\n".join(lines)

    def _build_results_summary(self, ctx: "ScanContext") -> str:
        """Build previous results summary."""
        if not ctx.previous_results:
            return ""

        lines = ["### PREVIOUS RESULTS (Current Mission):"]
        for result in ctx.previous_results[-10:]:  # Last 10 results
            if hasattr(result, "tool_name"):
                status = "OK" if result.success else "FAIL"
                findings = len(result.findings) if result.findings else 0
                lines.append(
                    f"- {result.tool_name}: {status} ({findings} findings)"
                )
            elif isinstance(result, dict):
                tool = result.get("tool", "unknown")
                success = result.get("success", False)
                lines.append(f"- {tool}: {'OK' if success else 'FAIL'}")
        return "\n".join(lines)

    def _build_mission_state(self, ctx: "ScanContext") -> str:
        """Build mission state snapshot section."""
        if ctx.mission_state is None:
            return ""

        try:
            snapshot = ctx.mission_state.snapshot(max_items=40)
            snapshot_json = json.dumps(snapshot, ensure_ascii=False)
        except Exception as e:
            logger.debug(f"Could not get mission snapshot: {e}")
            return ""

        return f"### MISSION STATE SNAPSHOT (Graph/Facts/Hypotheses):\n{snapshot_json}"

    def _build_coverage(self, ctx: "ScanContext") -> str:
        """Build coverage gaps section."""
        if ctx.coverage_map is None:
            return ""

        try:
            return ctx.coverage_map.prompt_context(max_gaps=8)
        except Exception as e:
            logger.debug(f"Could not get coverage context: {e}")
            return ""

    def _build_beliefs(self, ctx: "ScanContext") -> str:
        """Build active hypotheses section."""
        if ctx.belief_state is None:
            return ""

        try:
            return ctx.belief_state.prompt_context()
        except Exception as e:
            logger.debug(f"Could not get belief context: {e}")
            return ""

    def _build_reflection(self, ctx: "ScanContext") -> str:
        """Build reflection status section."""
        if ctx.reflect_engine is None:
            return ""

        try:
            return ctx.reflect_engine.prompt_context(recent=3)
        except Exception as e:
            logger.debug(f"Could not get reflection context: {e}")
            return ""

    def _build_negative_results(self, ctx: "ScanContext") -> str:
        """Build negative results section."""
        if ctx.negative_results is None:
            return ""

        try:
            return ctx.negative_results.get_prompt_context(max_items=5)
        except Exception as e:
            logger.debug(f"Could not get negative results: {e}")
            return ""

    def _get_now_context(self) -> str:
        """Get current date/time context."""
        import datetime

        now = datetime.datetime.now()
        return f"Current date/time: {now.strftime('%Y-%m-%d %H:%M:%S')}"

    def _assemble_with_budget(
        self, sections: List[Tuple[str, int]]
    ) -> str:
        """Assemble sections into a prompt, respecting token budget.

        Sections with max_tokens=0 are always included (never truncated).
        Other sections are truncated in priority order (lowest priority first)
        when the total exceeds the budget.

        Args:
            sections: List of (text, max_tokens) tuples, in priority order.
                      max_tokens=0 means "never truncate".

        Returns:
            The assembled prompt string.
        """
        # First pass: calculate total without truncation
        total = sum(_estimate_tokens(text) for text, _ in sections)

        if total <= self.max_tokens:
            # No truncation needed
            return "\n\n".join(text for text, _ in sections if text)

        # Need to truncate — calculate how much to cut
        over_budget = total - self.max_tokens

        # Build list of truncatable sections (max_tokens > 0) in reverse priority
        truncatable = []
        for text, max_tokens in reversed(sections):
            if max_tokens > 0 and text:
                current_tokens = _estimate_tokens(text)
                if current_tokens > max_tokens:
                    truncatable.append((text, max_tokens, current_tokens))

        # Truncate lowest-priority sections first
        for text, max_tokens, current_tokens in truncatable:
            if over_budget <= 0:
                break
            excess = current_tokens - max_tokens
            if excess > 0:
                cut_chars = min(excess * CHARS_PER_TOKEN, over_budget * CHARS_PER_TOKEN)
                # Truncate from the end, keep beginning
                truncated = text[: -cut_chars] if cut_chars < len(text) else text[:100]
                over_budget -= (current_tokens - _estimate_tokens(truncated))

        # Rebuild sections with truncated versions
        result_parts = []
        for text, max_tokens in sections:
            if not text:
                continue
            if max_tokens > 0:
                estimated = _estimate_tokens(text)
                if estimated > max_tokens:
                    cut_chars = (estimated - max_tokens) * CHARS_PER_TOKEN
                    text = text[: -cut_chars] if cut_chars < len(text) else text[:100]
            result_parts.append(text)

        return "\n\n".join(result_parts)


# ── Planning Instructions (always appended to scan prompts) ─────

_PLANNING_INSTRUCTIONS = """

Plan your next move. Consider:
1. What do we know from previous sessions about this target?
2. What shell command would be most effective now? (Think freely — use pipes, redirects, scripting)
3. Do you need to research a vulnerability or tech stack? Use web_search.
4. Have you found any vulnerabilities? Use submit_findings to report them IMMEDIATELY!
5. Is a tool missing? Use ask_user to request installation.
6. Check COVERAGE GAPS above — are there untested vulnerability classes on known endpoints?
7. Check ACTIVE HYPOTHESES above — prioritize testing hypotheses with HIGH confidence.
8. Check REFLECTION above — if strategy is stuck, try a completely different approach.
9. Check PREVIOUSLY TESTED above — don't repeat the same test on the same endpoint.
10. When you report a finding submit_findings, include the SPECIFIC endpoint and vulnerability type so coverage tracking can update.

Use JSON format:
{"action": "run_shell|ask_user|web_search|submit_findings|save_memory|finish",
"command": "...", "query": "...", "findings": [...],
"purpose": "...", "question": "..."}"""
