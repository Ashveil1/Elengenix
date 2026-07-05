"""
agents/scan_loop.py — Main Scan Loop

The core execution loop that ties together DecisionEngine, PostProcessor,
and the action executor. Runs for max_steps iterations, deciding and
executing actions until termination.

Extracted from agent_brain.py process_query() lines 1045-1857.
"""

from __future__ import annotations

import logging
from collections import Counter
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Callable, Dict, List, Optional

if TYPE_CHECKING:
    from agents.decision_engine import DecisionEngine
    from agents.post_processor import PostExecutionProcessor
    from agents.scan_context import ScanContext

logger = logging.getLogger("elengenix.scan_loop")


@dataclass
class ScanResult:
    """Result of a completed scan mission.

    Attributes:
        summary: Human-readable summary of the mission.
        findings: All verified findings discovered.
        steps_taken: Number of reasoning steps executed.
        success: Whether the mission completed successfully.
        action_history: List of actions taken (for debugging).
    """

    summary: str = ""
    findings: List[Dict[str, Any]] = field(default_factory=list)
    steps_taken: int = 0
    success: bool = False
    action_history: List[str] = field(default_factory=list)


class ScanLoop:
    """Main scan execution loop.

    Composes DecisionEngine (for choosing actions), PostProcessor
    (for handling results), and an injected executor (for running actions).

    Args:
        decision_engine: For deciding what to do next.
        post_processor: For processing results after execution.
        executor: Callable that executes an action. Signature:
            executor(action_data, ctx) -> (success: bool, result: Any, observation: str)
        loop_threshold: Max times the same action can repeat before deadlock.
        cot_logger: Optional chain-of-thought logger.
        callback: Optional callback for live output.
    """

    def __init__(
        self,
        decision_engine: DecisionEngine,
        post_processor: PostExecutionProcessor,
        executor: Callable = None,
        loop_threshold: int = 3,
        cot_logger=None,
        callback: Optional[Callable] = None,
    ):
        self.decision_engine = decision_engine
        self.post_processor = post_processor
        self.executor = executor
        self.loop_threshold = loop_threshold
        self.cot_logger = cot_logger
        self.callback = callback

    def run(
        self,
        ctx: "ScanContext",
        user_input: str,
        reflect_engine=None,
    ) -> ScanResult:
        """Run the scan loop until termination.

        This is the main entry point. It loops for max_steps iterations,
        each time: reflecting → deciding → executing → processing.

        Args:
            ctx: The scan context (will be updated in place).
            user_input: The user's original request.
            reflect_engine: The reflection engine instance.

        Returns:
            ScanResult with summary, findings, and stats.
        """
        action_history: List[str] = []

        for step in range(ctx.max_steps):
            # Phase 1: Decide
            decision = self.decision_engine.decide(ctx, user_input, reflect_engine)

            # Phase 2: Validate action
            validation = self._validate_action(ctx, decision, user_input, step)
            if validation is not None:
                return validation

            # Phase 3: Handle save_memory (no execution needed)
            if self._is_save_memory(decision):
                self._handle_save_memory(ctx, decision)
                continue

            # Phase 4: Loop detection
            action_sig = self._action_signature(decision)
            action_history.append(action_sig)

            if Counter(action_history)[action_sig] > self.loop_threshold:
                msg = f"DEADLOCK DETECTED: Agent is repeating '{action_sig}'. Terminating."
                logger.warning(msg)
                return ScanResult(
                    summary=msg,
                    findings=ctx.all_findings,
                    steps_taken=step,
                    success=False,
                    action_history=action_history,
                )

            # Phase 5: Execute
            success, result, observation = self._execute(ctx, decision, step)

            # Phase 6: Post-process
            if result is not None:
                self.post_processor.process(
                    ctx, result, decision.action_data.get("tool", "unknown"),
                    decision.action_data, step
                )

            # Phase 7: Update context counters
            ctx.update_after_step(ctx.all_findings if result and result.findings else [])

            # Phase 8: Update history
            self._update_history(ctx, decision, observation)

            # Phase 9: Check for __FINISH__ sentinel
            if observation == "__FINISH__":
                summary = decision.action_data.get("summary", "Mission completed successfully.")
                return ScanResult(
                    summary=summary,
                    findings=ctx.all_findings,
                    steps_taken=step + 1,
                    success=True,
                    action_history=action_history,
                )

        # Max steps reached
        summary = f"Task halted after {ctx.max_steps} steps. Findings: {len(ctx.all_findings)}"
        return ScanResult(
            summary=summary,
            findings=ctx.all_findings,
            steps_taken=ctx.max_steps,
            success=False,
            action_history=action_history,
        )

    def _validate_action(
        self,
        ctx: "ScanContext",
        decision,
        user_input: str,
        step: int,
    ) -> Optional[ScanResult]:
        """Validate the chosen action.

        Returns:
            ScanResult if the mission should terminate, None to continue.
        """
        action_data = dict(decision.action_data)  # Work on a copy
        action_val = action_data.get("action", "")

        # Handle nested action format
        if isinstance(action_val, dict):
            params = action_val.get("params", {})
            if isinstance(params, dict):
                action_data.update(params)
            action_val = action_val.get("type", "")

        action = str(action_val).lower()

        # Finish action → return summary
        if action == "finish":
            summary = action_data.get("summary", "Mission completed")
            return ScanResult(
                summary=summary,
                findings=ctx.all_findings,
                steps_taken=step + 1,
                success=True,
            )

        return None

    def _is_save_memory(self, decision) -> bool:
        """Check if the action is save_memory."""
        action = str(decision.action_data.get("action", "")).lower()
        return action == "save_memory"

    def _handle_save_memory(self, ctx: "ScanContext", decision) -> None:
        """Handle save_memory action (no execution needed)."""
        action_data = decision.action_data
        try:
            from tools.vector_memory import remember

            remember(
                action_data.get("learning", ""),
                action_data.get("target", "global"),
                action_data.get("category", "general"),
            )
        except Exception as e:
            logger.debug(f"save_memory failed: {e}")

        ctx.append_history("assistant", str(action_data))
        ctx.append_history("user", "Learning saved.")

    def _action_signature(self, decision) -> str:
        """Create a signature for loop detection."""
        action = str(decision.action_data.get("action", ""))
        command = decision.action_data.get("command", "")
        return f"{action}:{command}"

    def _execute(
        self,
        ctx: "ScanContext",
        decision,
        step: int,
    ) -> tuple:
        """Execute the chosen action.

        Returns:
            Tuple of (success, result, observation).
        """
        action_data = decision.action_data
        action = str(action_data.get("action", "")).lower()

        # Handle submit_findings (no execution needed)
        if action == "submit_findings":
            return self._handle_submit_findings(ctx, action_data)

        # Handle web_search
        if action == "web_search":
            return self._handle_web_search(action_data)

        # Normal execution via injected executor
        if self.executor:
            try:
                return self.executor(action_data, ctx)
            except Exception as e:
                logger.error(f"Executor failed: {e}")
                return False, None, f"Execution error: {e}"

        # Fallback: no executor
        return False, None, "No executor available"

    def _handle_submit_findings(
        self, ctx: "ScanContext", action_data: Dict
    ) -> tuple:
        """Handle submit_findings action (creates ToolResult from findings)."""
        from tools.tool_registry import ToolCategory, ToolResult

        findings_data = action_data.get("findings", [])
        if not isinstance(findings_data, list):
            findings_data = [findings_data]

        result = ToolResult(
            success=True,
            tool_name="ai_manual_analysis",
            category=ToolCategory.SCANNER,
            findings=findings_data,
        )

        if self.callback:
            self.callback(f"Reporting {len(findings_data)} findings to system...")

        return True, result, f"Reported {len(findings_data)} findings"

    def _handle_web_search(self, action_data: Dict) -> tuple:
        """Handle web_search action."""
        query = action_data.get("query", "")
        try:
            from tools.research_tool import search_web

            result_text = search_web(query)
            return True, None, result_text[:500] if result_text else "No results"
        except Exception as e:
            return False, None, f"Web search failed: {e}"

    def _update_history(
        self,
        ctx: "ScanContext",
        decision,
        observation: str,
    ) -> None:
        """Update conversation history with the action and observation.

        Implements the self-reinforcing chain-of-thought pattern:
        the AI's own reasoning is prepended to history so it sees
        its previous decisions in context.
        """
        action_data = decision.action_data

        # Add AI's thought + action as assistant message
        _thought = action_data.get("thought", "")
        _history_entry = str(action_data)
        if _thought:
            _history_entry = f"[Thought: {_thought}]\n{_history_entry}"
        ctx.append_history("assistant", _history_entry)

        # Add observation as user message
        ctx.append_history("user", f"OBSERVATION: {observation}")
