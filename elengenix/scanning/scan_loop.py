"""
agents/scan_loop.py — Main Scan Loop

The core execution loop that ties together DecisionEngine, PostProcessor,
and the action executor. Runs for max_steps iterations, deciding and
executing actions until termination.

Extracted from agent_brain.py process_query() lines 1045-1857.
"""

from __future__ import annotations

import asyncio
import logging
from collections import Counter
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Callable, Dict, List, Optional

if TYPE_CHECKING:
    from elengenix.scanning.decision_engine import DecisionEngine
    from elengenix.scanning.post_processor import PostExecutionProcessor
    from elengenix.scanning.scan_context import ScanContext

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
        client: Any = None,
        replan_every: int = 5,
    ):
        self.decision_engine = decision_engine
        self.post_processor = post_processor
        self.executor = executor
        self.loop_threshold = loop_threshold
        self.cot_logger = cot_logger
        self.callback = callback

        # Lazy LLM client for the reasoning phase. Without this the
        # "autonomous AI reasoning" falls back to regex heuristics.
        if client is None:
            try:
                from tools.universal_ai_client import AIClientManager

                client = AIClientManager()
            except Exception:
                pass
        self._llm_client = client

        # Periodic re-planning: every N steps, regenerate the attack tree
        # from the current findings/fingerprint so the AI's strategy
        # adapts to what it has learned, instead of being locked to the
        # initial plan generated before any tool ran.
        # replan_every=0 disables the feature.
        self.replan_every = max(0, int(replan_every))
        self._replan_count = 0

    async def run(
        self,
        ctx: "ScanContext",
        user_input: str,
        reflect_engine=None,
        interactive: bool = True,
    ) -> ScanResult:
        """Run the scan loop until termination.

        This is the main entry point. It loops for max_steps iterations,
        each time: reflecting -> deciding -> executing -> processing.

        Args:
            ctx: The scan context (will be updated in place).
            user_input: The user's original request.
            reflect_engine: The reflection engine instance.
            interactive: If True, the AI sees each command output immediately
                before deciding the next action (like a human using a terminal).
                If False, uses the legacy batch mode.

        Returns:
            ScanResult with summary, findings, and stats.
        """
        action_history: List[str] = []

        for step in range(ctx.max_steps):
            # Phase 1: Decide
            # In interactive mode, show the last output to the user before deciding
            # Only show for actual shell commands (not submit_findings, save_memory, etc.)
            last_output = getattr(ctx, "last_output", "")
            last_command = getattr(ctx, "last_command", "")
            if (interactive and isinstance(last_output, str) and last_output and
                    isinstance(last_command, str) and last_command and
                    self.callback and step > 0):
                last_success = getattr(ctx, "last_command_success", True)
                self.callback(
                    f"\n[Interactive] Last command: {last_command}\n"
                    f"[Interactive] Output ({'success' if last_success else 'failed'}):\n"
                    f"{last_output[:2000]}\n"
                    f"[Interactive] AI is analyzing output and planning next move...\n"
                )

            # Phase 0: Periodic re-planning.
            # Every N steps, regenerate the attack tree from the current
            # findings/fingerprint so the strategy adapts to what the AI
            # has actually learned. The AI still has full authority to
            # override the new tree on the next decision turn — this
            # only refreshes the SUGGESTION the AI sees.
            if (self.replan_every > 0 and step > 0
                    and step % self.replan_every == 0
                    and getattr(ctx, "planner", None) is not None):
                self._maybe_replan(ctx, user_input, step)

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

            # Phase 5b: Autonomous AI reasoning phase.
            # The AI reasons about the raw evidence from this step and may
            # author vulnerability hypotheses on its own authority -- no
            # deterministic tool required. This is what makes Elengenix an
            # *agent* rather than a tool-chainer.
            raw_output = getattr(result, "output", "") if result else ""
            ai_findings = self._run_reasoning_phase(
                ctx, raw_output or observation, step
            )
            # AI hypotheses must pass the same multi-perspective verification
            # gate as deterministic tool findings before reaching the report.
            ai_findings = self.post_processor.verify_ai_findings(ctx, ai_findings)
            for f in ai_findings:
                if hasattr(ctx, "add_finding"):
                    ctx.add_finding(f)
                else:
                    ctx.all_findings.append(f)

            # Phase 5c: Store to LearningEngine for cross-session learning
            tool_name = decision.action_data.get("tool", "unknown")
            command = decision.action_data.get("command", "")
            findings_to_store = []
            if result and hasattr(result, "findings") and result.findings:
                findings_to_store = result.findings
            findings_to_store.extend(ai_findings)
            self._store_to_learning_engine(ctx, tool_name, command, result, findings_to_store)

            # Phase 5d: Record adaptation if strategy changed and found something
            if findings_to_store and getattr(decision, "source", "") == "ai_dynamic":
                self._record_adaptation(ctx, decision, findings_to_store)

            # Phase 6: Post-process (deterministic tool findings)
            if result is not None:
                await self.post_processor.process(
                    ctx,
                    result,
                    decision.action_data.get("tool", "unknown"),
                    decision.action_data,
                    step,
                )

            # Phase 7: Update context counters
            has_findings = bool(result is not None and hasattr(result, "findings") and result.findings)
            ctx.update_after_step(ctx.all_findings if has_findings else [])

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

    def _store_to_learning_engine(
        self,
        ctx: "ScanContext",
        tool_name: str,
        command: str,
        result: Any,
        findings: List[Dict[str, Any]],
    ) -> None:
        """Store successful exploit to LearningEngine for cross-session learning.

        Records each finding as an ExploitRecord so future scans can recall
        what worked on similar targets.
        """
        try:
            from tools.learning_engine import LearningEngine, ExploitRecord

            engine = LearningEngine()

            # Determine tech stack from context
            tech_stack = []
            if hasattr(ctx, 'assets') and ctx.assets:
                tech_stack = ctx.assets.get("tech_stack", []) or []
            if not tech_stack:
                tech_stack = ["web"]

            # Store each finding
            for finding in (findings or []):
                record = ExploitRecord(
                    target=ctx.target,
                    tech_stack=tech_stack,
                    vuln_class=finding.get("type", "unknown"),
                    tool=tool_name,
                    payload=command[:500] if command else "",
                    success=True,
                    confidence=finding.get("confidence", 0.5),
                    severity=finding.get("severity", "unknown"),
                    notes=f"Discovered via {tool_name}: {finding.get('description', '')[:200]}"
                )
                engine.remember(record)

            # If no findings but tool succeeded, store as negative result
            if not findings and result and hasattr(result, 'success') and result.success:
                record = ExploitRecord(
                    target=ctx.target,
                    tech_stack=tech_stack,
                    vuln_class="unknown",
                    tool=tool_name,
                    payload=command[:500] if command else "",
                    success=False,
                    confidence=0.3,
                    severity="none",
                    notes=f"Tool {tool_name} ran successfully but found no vulnerabilities"
                )
                engine.remember(record)

        except Exception as e:
            logger.debug(f"Could not store to LearningEngine: {e}")

    def _record_adaptation(
        self,
        ctx: "ScanContext",
        decision,
        findings: List[Dict[str, Any]],
    ) -> None:
        """Record successful strategy adaptation for future reference.

        When the AI changes strategy and discovers findings, record the
        adaptation chain (trigger -> change -> result) for reuse.
        """
        try:
            from tools.learning_engine import LearningEngine

            engine = LearningEngine()

            # Determine trigger from findings
            finding_types = [f.get("type", "unknown") for f in findings[:3]]
            trigger = f"Found {', '.join(finding_types)}"

            # Determine strategy change from decision reasoning
            strategy_change = decision.reasoning or decision.action_data.get("purpose", "unknown")

            # Record the adaptation
            engine.record_adaptation(
                trigger_finding=trigger,
                strategy_change=strategy_change,
                result=f"Discovered {len(findings)} findings",
                success=True,
            )

        except Exception as e:
            logger.debug(f"Could not record adaptation: {e}")

    def _maybe_replan(self, ctx: "ScanContext", user_input: str, step: int) -> None:
        """Periodically regenerate the attack tree from current findings.

        This is the adaptive re-planning loop: instead of locking the
        AI to a single attack tree generated before any tool ran, we
        periodically ask the planner to re-generate the tree from the
        CURRENT findings + fingerprint. The AI keeps full authority to
        override the new tree on the next decision turn.

        Idempotent & safe: any failure falls back to keeping the old tree.
        Records re-plan events on ctx for observability.
        """
        planner = getattr(ctx, "planner", None)
        if planner is None:
            return
        try:
            target = getattr(ctx, "target", "") or user_input or ""
            # Build a fingerprint-aware re-plan if the planner exposes
            # generate_attack_tree; fall back to default otherwise.
            findings = list(getattr(ctx, "all_findings", []) or [])
            try:
                from elengenix.scanning.planner import StrategicPlanner
                if isinstance(planner, StrategicPlanner):
                    new_tree = planner.generate_attack_tree(
                        target=target,
                        objective=getattr(ctx, "objective", "") or user_input,
                    )
                else:
                    new_tree = planner.generate_attack_tree(target)  # type: ignore
            except Exception:
                new_tree = None

            if new_tree is not None:
                # Keep the old tree for diffing/observability.
                old_tree = getattr(ctx, "attack_tree", None)
                ctx.attack_tree = new_tree
                self._replan_count += 1
                # Record on ctx for downstream consumption (TUI / logs).
                try:
                    replans = getattr(ctx, "replan_history", None)
                    if replans is None:
                        replans = []
                        setattr(ctx, "replan_history", replans)
                    replans.append({
                        "step": step,
                        "findings_count": len(findings),
                        "new_steps": len(getattr(new_tree, "steps", []) or []),
                        "old_steps": len(getattr(old_tree, "steps", []) or []),
                    })
                except Exception:
                    pass
                logger.info(
                    f"re-planned attack tree at step {step} "
                    f"(findings={len(findings)}, new_steps="
                    f"{len(getattr(new_tree, 'steps', []) or [])})"
                )
                if self.callback:
                    try:
                        self.callback(
                            f"[RE-PLAN] step {step}: regenerated attack tree "
                            f"with {len(getattr(new_tree, 'steps', []) or [])} steps "
                            f"based on {len(findings)} findings so far."
                        )
                    except Exception:
                        pass
        except Exception as e:
            logger.debug(f"re-planning skipped: {e}")

    def _run_reasoning_phase(self, ctx: "ScanContext", evidence: str, step: int) -> List[Dict[str, Any]]:
        """Run the autonomous vulnerability-reasoning phase for this step.

        Delegates to agents.vuln_reasoning_phase. Kept as a small wrapper so
        the loop stays readable and the phase can be disabled/extended later.
        """
        try:
            from elengenix.scanning.vuln_reasoning_phase import run_reasoning_phase

            return run_reasoning_phase(
                ctx=ctx,
                raw_output=evidence,
                observation="",
                step=step,
                target=getattr(ctx, "target", "") or "",
                client=self._llm_client,
            )
        except Exception as e:
            logger.debug(f"reasoning phase skipped: {e}")
            return []

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

        # Finish action -> return summary
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
                success, result, observation = self.executor(action_data, ctx)

                # Store last command output for interactive feedback
                command = action_data.get("command", "")
                if command and result is not None:
                    raw_output = getattr(result, "output", "") if result else observation or ""
                    ctx.set_last_command_output(
                        command=command,
                        output=raw_output[:5000] if raw_output else "",
                        success=success,
                    )

                return success, result, observation
            except Exception as e:
                logger.error(f"Executor failed: {e}")
                return False, None, f"Execution error: {e}"

        # Fallback: no executor
        return False, None, "No executor available"

    def _handle_submit_findings(self, ctx: "ScanContext", action_data: Dict) -> tuple:
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
