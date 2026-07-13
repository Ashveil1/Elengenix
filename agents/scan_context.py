"""
agents/scan_context.py — Scan Context Data Object

Holds all state that the AI decision engine, prompt builder, and
post-processor need during a scan mission. Created once at mission
start, passed by reference to all components.

Design:
- Immutable config fields (target, base_url, etc.) set at creation
- Mutable state objects (MissionState, CoverageMap, etc.) accessed
  through their own APIs — ScanContext just holds references
- Simple counters (step_count, consecutive_no_findings) updated directly
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from elengenix.paths import get_reports_path
from typing import (

logger = logging.getLogger("elengenix.scan_context")


@dataclass
class ScanContext:
    """Central context object for a scan mission.

    All components (PromptBuilder, DecisionEngine, PostProcessor,
    ScanLoop) receive this object and read/write through it.

    Attributes:
        target: Normalized target domain or IP.
        base_url: Full URL with scheme (http:// or https://).
        report_dir: Directory for scan reports.
        objective: The user's original scan request.
        mission_key: Unique mission identifier.
        max_steps: Maximum reasoning steps allowed.
        rate_limit: Max concurrent operations.
        timeout: Global timeout in seconds.
        mission_state: SQLite-backed mission graph (shared reference).
        coverage_map: Endpoint x vulnerability coverage tracker.
        belief_state: Active hypotheses with confidence scores.
        negative_results: Store of failed tests (avoid repetition).
        verification_pipeline: Dual-model finding verification.
        vector_memory: ChromaDB semantic recall instance.
        conversation_manager: Chat history manager.
        planner: Strategic planner for attack tree generation.
        attack_tree: The current attack plan.
        reflect_engine: Reflection/strategy-switch engine.
        step_count: Current step number (0-indexed).
        consecutive_no_findings: Steps without new findings.
        token_usage: Total tokens consumed this mission.
        all_findings: All findings accumulated this mission.
        previous_results: All tool execution results this mission.
        action_history: All actions taken this mission.
        history: Conversation history for this mission.
    """

    # ── Immutable config (set once at creation) ──
    target: str = ""
    base_url: str = ""
    report_dir: Path = field(default_factory=lambda: get_reports_path())
    objective: str = ""
    mission_key: str = ""
    max_steps: int = 25
    rate_limit: int = 5
    timeout: int = 600

    # ── Mutable state objects (shared references) ──
    mission_state: Any = None
    coverage_map: Any = None
    belief_state: Any = None
    negative_results: Any = None
    verification_pipeline: Any = None
    vector_memory: Any = None
    conversation_manager: Any = None
    planner: Any = None
    attack_tree: Any = None
    reflect_engine: Any = None

    # ── Mutable counters ──
    step_count: int = 0
    consecutive_no_findings: int = 0
    token_usage: int = 0
    cycle_findings_count: int = 0

    # ── Accumulation lists ──
    all_findings: List[Dict[str, Any]] = field(default_factory=list)
    previous_results: List[Any] = field(default_factory=list)
    action_history: List[Dict[str, Any]] = field(default_factory=list)
    history: List[Dict[str, str]] = field(default_factory=list)

    # ── Reflection state ──
    last_reflection: Any = None

    def __post_init__(self):
        if not self.target:
            raise ValueError("ScanContext.target must not be empty")
        if self.max_steps < 1:
            raise ValueError("ScanContext.max_steps must be >= 1")

    @classmethod
    def from_target(
        cls,
        target: str,
        objective: str = "",
        report_dir: Optional[Path] = None,
        max_steps: int = 25,
        rate_limit: int = 5,
        timeout: int = 600,
    ) -> ScanContext:
        """Factory: create a ScanContext from a target string.

        Args:
            target: Domain or IP to scan.
            objective: User's scan request.
            report_dir: Where to save reports (auto-created if None).
            max_steps: Maximum reasoning steps.
            rate_limit: Max concurrent operations.
            timeout: Global timeout in seconds.

        Returns:
            ScanContext with target normalized and report_dir set.
        """
        from core.orchestrator import normalize_target

        normalized = normalize_target(target)
        if not normalized:
            raise ValueError(f"Cannot normalize target: {target!r}")

        safe_name = normalized.replace(".", "_").replace(":", "_")
        if report_dir is None:
            report_dir = get_reports_path(f"agent_{safe_name}_{int(time.time())}")

        base_url = target if target.startswith(("http://", "https://")) else f"http://{target}"

        mission_key = f"{normalized}:{int(time.time())}"

        report_dir.mkdir(parents=True, exist_ok=True)

        return cls(
            target=normalized,
            base_url=base_url,
            report_dir=report_dir,
            objective=objective,
            mission_key=mission_key,
            max_steps=max_steps,
            rate_limit=rate_limit,
            timeout=timeout,
            history=[{"role": "user", "content": objective}] if objective else [],
        )

    def update_after_step(self, findings: List[Dict[str, Any]]) -> None:
        """Update counters after each reasoning step.

        Args:
            findings: Findings produced by this step (empty list = no findings).
        """
        self.step_count += 1
        if findings:
            self.consecutive_no_findings = 0
            self.cycle_findings_count = len(findings)
        else:
            self.consecutive_no_findings += 1
            self.cycle_findings_count = 0

    def add_finding(self, finding: Dict[str, Any]) -> None:
        """Add a single finding to the accumulated list."""
        self.all_findings.append(finding)

    def add_findings(self, findings: List[Dict[str, Any]]) -> None:
        """Add multiple findings to the accumulated list."""
        self.all_findings.extend(findings)

    def add_result(self, result: Any) -> None:
        """Add a tool execution result to history."""
        self.previous_results.append(result)

    def add_action(self, action: Dict[str, Any]) -> None:
        """Add an action to the action history."""
        self.action_history.append(action)

    def append_history(self, role: str, content: str) -> None:
        """Append a message to the conversation history."""
        self.history.append({"role": role, "content": content})

    @property
    def has_findings(self) -> bool:
        """Whether any findings have been accumulated."""
        return len(self.all_findings) > 0

    @property
    def finding_count(self) -> int:
        """Total number of findings."""
        return len(self.all_findings)

    @property
    def is_stuck(self) -> bool:
        """Whether the agent is stuck (many steps without findings)."""
        return self.consecutive_no_findings >= 5

    @property
    def steps_remaining(self) -> int:
        """How many steps are left."""
        return max(0, self.max_steps - self.step_count)
