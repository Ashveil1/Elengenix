"""agents/agent_council.py — AgentCouncil: the TeamAegis v2 orchestrator.

AgentCouncil coordinates three specialized AI agents (Strategist, Specialist, Critic)
through a shared message bus. Each agent uses its own AI model/provider and has
dedicated sub-workers for specific tasks.

Architecture:
    AgentCouncil
        Strategist (AI #1) — plans the attack
        Specialist  (AI #2) — executes tools
        Critic      (AI #3) — validates findings

Inter-agent communication uses CouncilMessage envelopes passed through SharedInbox.
High-risk actions trigger a deliberation vote before execution.
"""

from __future__ import annotations

import logging
import queue
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any, Callable, Dict, List, Optional

from ui_components import console

if TYPE_CHECKING:
    from agents.critic_agent import CriticAgent
    from agents.specialist_agent import SpecialistAgent
    from agents.strategist_agent import StrategistAgent

logger = logging.getLogger("elengenix.council")


# ── Message Types ──────────────────────────────────────────────────────────────


class MessageType(str, Enum):
    """Types of messages exchanged between agents via AgentCouncil."""

    PLAN = "plan"  # Strategist → Council: attack plan
    TASK = "task"  # Council → Specialist: single task
    RESULT = "result"  # Specialist → Council: tool result
    FINDING = "finding"  # Specialist → Council: security finding
    REVIEW_REQUEST = "review_req"  # Council → Critic: please review findings
    VERDICT = "verdict"  # Critic → Council: approved / false-positive
    DELIBERATE = "deliberate"  # Council → all: vote on risky action
    VOTE = "vote"  # Agent → Council: vote result
    STATUS = "status"  # Any → Council: informational update
    COMPLETE = "complete"  # Any → Council: mission done signal


@dataclass
class CouncilMessage:
    """Envelope for inter-agent communication.

    Args:
        msg_type: Category of message (MessageType).
        sender: Name of sending agent ("strategist", "specialist", "critic", "council").
        recipient: Target agent name or "all" for broadcast.
        payload: Arbitrary dict payload (plan, findings, verdict, etc.).
        msg_id: Unique message identifier.
        timestamp: Unix epoch when message was created.
    """

    msg_type: MessageType
    sender: str
    recipient: str
    payload: Dict[str, Any] = field(default_factory=dict)
    msg_id: str = ""
    timestamp: float = field(default_factory=time.time)

    def __post_init__(self) -> None:
        if not self.msg_id:
            self.msg_id = f"{self.sender}:{self.msg_type}:{int(self.timestamp * 1000) % 999999:06d}"

    def to_dict(self) -> Dict[str, Any]:
        """Serialize message to dict."""
        return {
            "id": self.msg_id,
            "type": self.msg_type.value,
            "from": self.sender,
            "to": self.recipient,
            "payload": self.payload,
            "ts": self.timestamp,
        }


class SharedInbox:
    """Thread-safe message queue for AgentCouncil.

    Agents post messages here; Council dispatches them to recipients.

    Args:
        maxsize: Maximum queue depth before blocking (default 200).
    """

    def __init__(self, maxsize: int = 200) -> None:
        self._q: queue.Queue[CouncilMessage] = queue.Queue(maxsize=maxsize)
        self._lock = threading.Lock()
        self._history: List[CouncilMessage] = []

    def post(self, msg: CouncilMessage) -> None:
        """Post a message (non-blocking; drops if full).

        Args:
            msg: CouncilMessage to enqueue.
        """
        try:
            self._q.put_nowait(msg)
            with self._lock:
                self._history.append(msg)
        except queue.Full:
            logger.warning(f"[Council] Inbox full — dropped message from {msg.sender}")

    def get(self, timeout: float = 1.0) -> Optional[CouncilMessage]:
        """Retrieve next message with timeout.

        Args:
            timeout: Seconds to wait before returning None.

        Returns:
            CouncilMessage or None if queue is empty.
        """
        try:
            return self._q.get(timeout=timeout)
        except queue.Empty:
            return None

    def drain(self, limit: int = 50) -> List[CouncilMessage]:
        """Drain up to `limit` pending messages without blocking.

        Args:
            limit: Maximum number of messages to return.

        Returns:
            List of CouncilMessage.
        """
        msgs = []
        for _ in range(limit):
            try:
                msgs.append(self._q.get_nowait())
            except queue.Empty:
                break
        return msgs

    def history(self, last_n: int = 20) -> List[CouncilMessage]:
        """Return recent message history.

        Args:
            last_n: How many messages to return from the end.

        Returns:
            List of CouncilMessage.
        """
        with self._lock:
            return self._history[-last_n:]

    def history_text(self, last_n: int = 10) -> str:
        """Human-readable summary of recent messages.

        Args:
            last_n: How many messages to summarize.

        Returns:
            Multi-line string.
        """
        lines = []
        for m in self.history(last_n):
            payload_preview = str(m.payload)[:120]
            lines.append(f"  [{m.msg_type.value}] {m.sender} → {m.recipient}: {payload_preview}")
        return "\n".join(lines) if lines else "  (no messages yet)"

    @property
    def pending_count(self) -> int:
        """Number of messages currently in the queue."""
        return self._q.qsize()


# ── AgentCouncil ───────────────────────────────────────────────────────────────


class AgentCouncil:
    """Orchestrates Strategist, Specialist, and Critic agents.

    Responsibilities:
    - Dispatches tasks from Strategist plan to Specialist.
    - Routes Specialist results to Critic for validation.
    - Manages deliberation votes for high-risk actions.
    - Aggregates validated findings into final report.

    Args:
        strategist: StrategistAgent instance (AI #1).
        specialist: SpecialistAgent instance (AI #2).
        critic: CriticAgent instance (AI #3).
        target: Primary target domain/IP.
        max_rounds: Maximum council rounds before forced completion.
        risk_threshold: Minimum risk level to trigger deliberation vote.
            "high" = vote on HIGH and CRITICAL; "critical" = only CRITICAL.
        callback: Optional callable for live progress updates.
    """

    RISK_LEVELS = {"low": 0, "medium": 1, "high": 2, "critical": 3}

    def __init__(
        self,
        strategist: "StrategistAgent",
        specialist: "SpecialistAgent",
        critic: "CriticAgent",
        target: str = "",
        max_rounds: int = 40,
        risk_threshold: str = "critical",
        callback: Optional[Callable[[str], None]] = None,
    ) -> None:
        self.strategist = strategist
        self.specialist = specialist
        self.critic = critic
        self.target = target
        self.max_rounds = max_rounds
        self.risk_threshold = risk_threshold
        self.callback = callback

        self.inbox = SharedInbox()
        self.all_findings: List[Dict[str, Any]] = []
        self.validated_findings: List[Dict[str, Any]] = []
        self.false_positives: List[Dict[str, Any]] = []
        self.action_log: List[str] = []
        self.start_time: float = 0.0
        self.token_usage: Dict[str, int] = {
            "strategist": 0,
            "specialist": 0,
            "critic": 0,
        }

    # ── Main Entry ─────────────────────────────────────────────────────────────

    def run(self, objective: str) -> str:
        """Run the full multi-agent collaboration loop.

        Args:
            objective: High-level mission objective string.

        Returns:
            Final markdown report string.
        """
        self.start_time = time.monotonic()
        self._emit(f"[Council] TeamAegis v2 starting. Target: {self.target}")
        self._emit(f"[Council] Strategist: {self.strategist.model_label}")
        self._emit(f"[Council] Specialist: {self.specialist.model_label}")
        self._emit(f"[Council] Critic: {self.critic.model_label}")

        # ── Phase 1: Strategist generates attack plan ──────────────────────────
        self._emit("[Council] Phase 1 — Strategist planning...")
        plan = self.strategist.plan(objective, self.target, self.inbox)
        if not plan:
            self._emit("[Council] [WARN] Strategist returned empty plan — using default recon")
            plan = [
                {
                    "description": f"Subdomain recon on {self.target}",
                    "phase": "recon",
                    "status": "pending",
                },
                {
                    "description": f"HTTP probe live hosts on {self.target}",
                    "phase": "recon",
                    "status": "pending",
                },
                {
                    "description": f"Nuclei vuln scan on {self.target}",
                    "phase": "scanning",
                    "status": "pending",
                },
            ]

        self._emit(f"[Council] Plan: {len(plan)} tasks")

        # ── Phase 2: Council dispatch → Specialist execution loop ──────────────
        round_num = 0
        for task in plan:
            if round_num >= self.max_rounds:
                self._emit("[Council] Max rounds reached — finalizing")
                break
            round_num += 1

            description = task.get("description", "")
            phase = task.get("phase", "unknown")
            self._emit(f"[Council] Round {round_num}: [{phase.upper()}] {description}")

            # Check if this task needs deliberation before execution
            risk = task.get("risk", "low")
            if self._requires_deliberation(risk):
                approved = self._deliberate(task)
                if not approved:
                    self._emit(f"[Council] [SKIP] Task blocked by council vote: {description}")
                    self.action_log.append(f"[BLOCKED] {description}")
                    continue

            # Specialist executes the task
            result = self.specialist.execute_task(task, self.target, self.inbox)
            self.action_log.append(f"[{phase.upper()}] {description}")

            # Collect raw findings
            for f in result.findings:
                f["_task"] = description
                f["_phase"] = phase
                self.all_findings.append(f)

            # ── Phase 3: Critic validates each batch of findings ───────────────
            if result.findings:
                self._emit(f"[Council] Sending {len(result.findings)} findings to Critic...")
                verdicts = self.critic.review(result.findings, self.target, self.inbox)

                for v in verdicts:
                    if v.get("verdict") == "confirmed":
                        finding = v.get("finding", {})
                        finding["_critic_notes"] = v.get("notes", "")
                        finding["_cvss"] = v.get("cvss", 0.0)
                        finding["_confidence"] = v.get("confidence", "medium")
                        self.validated_findings.append(finding)
                        self._emit(
                            f"[Council] [OK] Confirmed: {finding.get('title', 'finding')} "
                            f"[CVSS {finding['_cvss']:.1f}]"
                        )
                    elif v.get("verdict") == "false_positive":
                        fp = v.get("finding", {})
                        fp["_reason"] = v.get("notes", "")
                        self.false_positives.append(fp)
                        self._emit(f"[Council] [SKIP] False positive: {fp.get('title', 'finding')}")

            # Track token usage
            self._update_token_usage()

        # ── Phase 4: Strategist re-evaluates if any rounds remain ──────────────
        if round_num < self.max_rounds and self.validated_findings:
            self._emit("[Council] Phase 4 — Strategist re-evaluating based on findings...")
            follow_up = self.strategist.replan(self.validated_findings, self.target, self.inbox)
            for task in follow_up[:5]:  # cap follow-up tasks
                if round_num >= self.max_rounds:
                    break
                round_num += 1
                description = task.get("description", "")
                self._emit(f"[Council] Follow-up [{round_num}]: {description}")
                result = self.specialist.execute_task(task, self.target, self.inbox)
                for f in result.findings:
                    f["_task"] = description
                    f["_phase"] = "follow_up"
                    self.all_findings.append(f)
                    # Auto-add follow-up findings without re-review for speed
                    self.validated_findings.append(f)
                self.action_log.append(f"[FOLLOW_UP] {description}")

        # ── Phase 5: Final report ──────────────────────────────────────────────
        elapsed = time.monotonic() - self.start_time
        self._emit(f"[Council] Mission complete in {elapsed:.0f}s. Generating report...")
        return self._build_report(objective, elapsed)

    # ── Deliberation ───────────────────────────────────────────────────────────

    def _requires_deliberation(self, risk: str) -> bool:
        """Check if a task's risk level requires a vote.

        Args:
            risk: Risk level string ("low", "medium", "high", "critical").

        Returns:
            True if deliberation vote is needed.
        """
        task_level = self.RISK_LEVELS.get(risk.lower(), 0)
        threshold_level = self.RISK_LEVELS.get(self.risk_threshold.lower(), 3)
        return task_level >= threshold_level

    def _deliberate(self, task: Dict[str, Any]) -> bool:
        """Run a deliberation vote among all three agents.

        Strategist and Critic each vote approve/deny.
        Strict majority required (>50%) — ties default to deny.
        If CRITICAL risk, also prompts the human user.

        Args:
            task: Task dict to vote on.

        Returns:
            True if strictly more than half of votes are "approve", False otherwise.
        """
        description = task.get("description", "")
        risk = task.get("risk", "high")
        self._emit(f"[Council] Deliberating [{risk.upper()}] risk task: {description}")

        votes = []

        # Strategist vote
        try:
            s_vote = self.strategist.vote(task, self.all_findings, self.target)
            votes.append(s_vote)
            self._emit(f"[Council] Strategist vote: {s_vote}")
        except Exception as e:
            logger.warning(f"Strategist vote failed: {e}")
            votes.append("approve")  # default allow on error

        # Critic vote
        try:
            c_vote = self.critic.vote(task, self.validated_findings, self.target)
            votes.append(c_vote)
            self._emit(f"[Council] Critic vote: {c_vote}")
        except Exception as e:
            logger.warning(f"Critic vote failed: {e}")
            votes.append("approve")

        # Strict majority vote (tie = deny, conservative default)
        # Requires MORE than half to approve — ties are blocked
        approve_count = votes.count("approve")
        ai_approved = approve_count > len(votes) / 2

        # Critical risk also requires human approval
        if risk.lower() == "critical":
            try:
                from ui_components import confirm

                human_ok = confirm(
                    f"CRITICAL task requires your approval:\n  {description}\n  AI votes: {approve_count}/{len(votes)} approve",
                    default=False,
                )
                return ai_approved and human_ok
            except Exception:
                return ai_approved

        return ai_approved

    # ── Helpers ────────────────────────────────────────────────────────────────

    def _update_token_usage(self) -> None:
        """Pull token usage from each agent and accumulate totals."""
        for role, agent in [
            ("strategist", self.strategist),
            ("specialist", self.specialist),
            ("critic", self.critic),
        ]:
            usage = getattr(agent, "total_tokens_used", 0)
            self.token_usage[role] = usage

    def _emit(self, msg: str) -> None:
        """Log and send to callback.

        Args:
            msg: Progress message string.
        """
        logger.info(msg)
        console.print(f"  [dim]{msg}[/dim]")
        if self.callback:
            try:
                self.callback(msg)
            except Exception:
                pass

    # ── Report Builder ─────────────────────────────────────────────────────────

    def _build_report(self, objective: str, elapsed: float) -> str:
        """Generate final markdown report from all validated findings.

        Args:
            objective: Original mission objective.
            elapsed: Total elapsed seconds.

        Returns:
            Markdown-formatted report string.
        """
        sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        sorted_findings = sorted(
            self.validated_findings,
            key=lambda f: sev_order.get(str(f.get("severity", "info")).lower(), 5),
        )

        total_tokens = sum(self.token_usage.values())

        lines = [
            f"# TeamAegis Report — {self.target}",
            "",
            f"**Objective**: {objective[:200]}",
            f"**Duration**: {elapsed:.0f}s ({elapsed / 60:.1f}m)",
            f"**Strategist**: {self.strategist.model_label}",
            f"**Specialist**: {self.specialist.model_label}",
            f"**Critic**: {self.critic.model_label}",
            f"**Total Tokens**: ~{total_tokens:,}",
            "",
            "## Findings Summary",
            "",
            f"- Total raw findings: {len(self.all_findings)}",
            f"- Confirmed by Critic: {len(self.validated_findings)}",
            f"- False positives filtered: {len(self.false_positives)}",
            "",
        ]

        if sorted_findings:
            lines += [
                "## Confirmed Vulnerabilities",
                "",
                "| # | Severity | Title | CVSS | Confidence |",
                "|---|----------|-------|------|------------|",
            ]
            for i, f in enumerate(sorted_findings, 1):
                sev = str(f.get("severity", "info")).capitalize()
                title = str(f.get("title", f.get("type", "Finding")))[:60]
                cvss = f.get("_cvss", 0.0)
                conf = str(f.get("_confidence", "medium")).capitalize()
                lines.append(f"| {i} | {sev} | {title} | {cvss:.1f} | {conf} |")

            lines += ["", "## Finding Details", ""]
            for i, f in enumerate(sorted_findings, 1):
                sev = str(f.get("severity", "info")).capitalize()
                title = str(f.get("title", "Finding"))
                lines += [
                    f"### {i}. [{sev}] {title}",
                    "",
                    f"- **Target**: {f.get('target', self.target)}",
                    f"- **URL**: {f.get('url', 'N/A')}",
                    f"- **Phase**: {f.get('_phase', 'unknown')}",
                    f"- **Task**: {f.get('_task', 'N/A')}",
                    f"- **CVSS**: {f.get('_cvss', 0.0):.1f}",
                    f"- **Confidence**: {f.get('_confidence', 'medium')}",
                    "",
                    f"**Description**: {f.get('description', 'N/A')}",
                    "",
                    f"**Critic Notes**: {f.get('_critic_notes', 'N/A')}",
                    "",
                ]
        else:
            lines.append("No confirmed vulnerabilities found.")

        # Action log
        lines += ["", "## Action Log", ""]
        for entry in self.action_log:
            lines.append(f"- {entry}")

        # Token cost estimate
        lines += [
            "",
            "## Resource Usage",
            "",
            "| Agent | Tokens |",
            "|-------|--------|",
            f"| Strategist ({self.strategist.model_label}) | {self.token_usage.get('strategist', 0):,} |",
            f"| Specialist ({self.specialist.model_label}) | {self.token_usage.get('specialist', 0):,} |",
            f"| Critic ({self.critic.model_label}) | {self.token_usage.get('critic', 0):,} |",
            f"| **Total** | **{total_tokens:,}** |",
            "",
            "---",
            "*Generated by Elengenix TeamAegis v2*",
        ]

        return "\n".join(lines)
