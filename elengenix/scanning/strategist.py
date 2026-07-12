"""agents/strategist_agent.py — StrategistAgent for TeamAegis v2.

The Strategist uses AI model #1 (default: Gemini) to:
- Generate an attack plan (list of ordered tasks).
- Re-plan based on discovered findings.
- Vote on high-risk tasks during deliberation.

Sub-workers:
- ReconWorker  — runs subdomain/DNS recon tools.
- OsintWorker  — searches web for target intelligence.
"""

from __future__ import annotations

import json
import logging
import re
from typing import TYPE_CHECKING, Any, Dict, List, Optional

from elengenix.scanning.worker import BaseWorker, WorkerResult
from tools.universal_ai_client import AIMessage

if TYPE_CHECKING:
    from elengenix.scanning.agent_council import SharedInbox

logger = logging.getLogger("elengenix.strategist")


# ── Sub-Workers ────────────────────────────────────────────────────────────────


class ReconWorker(BaseWorker):
    """Runs subdomain and DNS enumeration tools.

    Args:
        timeout_seconds: Max execution time in seconds.
    """

    def __init__(self, timeout_seconds: int = 180) -> None:
        super().__init__(
            name="ReconWorker",
            description="Subdomain and DNS enumeration",
            timeout_seconds=timeout_seconds,
        )

    def run(self, target: str, params: Optional[Dict[str, Any]] = None) -> WorkerResult:
        """Run DNS enumeration against target.

        Args:
            target: Domain to enumerate.
            params: Unused by this worker.

        Returns:
            WorkerResult with discovered findings.
        """
        import subprocess

        findings = []
        output_lines = []

        # Use DNS tools for enumeration
        try:
            cmd = ["dig", target, "ANY"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                output_lines.append(result.stdout)
                findings.append(
                    {
                        "type": "dns_enumeration",
                        "target": target,
                        "output": result.stdout[:500],
                    }
                )
        except Exception as e:
            output_lines.append(f"DNS lookup failed: {e}")

        return WorkerResult(
            success=len(findings) > 0,
            worker_name=self.name,
            output="\n".join(output_lines),
            findings=findings,
        )

        return WorkerResult(
            success=bool(findings),
            worker_name=self.name,
            output="\n".join(output_lines),
            findings=findings,
            error="" if findings else "No recon tool available",
        )


class OsintWorker(BaseWorker):
    """Searches the web for OSINT intelligence about the target.

    Args:
        timeout_seconds: Max execution time in seconds.
    """

    def __init__(self, timeout_seconds: int = 60) -> None:
        super().__init__(
            name="OsintWorker",
            description="Web search OSINT for target intelligence",
            timeout_seconds=timeout_seconds,
        )

    def run(self, target: str, params: Optional[Dict[str, Any]] = None) -> WorkerResult:
        """Search web for target technology stack, CVEs, and past leaks.

        Args:
            target: Domain or company name to research.
            params: Optional dict with key "queries" (List[str]).

        Returns:
            WorkerResult with OSINT findings.
        """
        params = params or {}
        queries = params.get(
            "queries",
            [
                f"{target} CVE vulnerability",
                f"{target} technology stack",
                f"site:github.com {target} leaked",
            ],
        )

        findings = []
        output_parts = []

        try:
            from tools.research_tool import search_web

            for query in queries[:3]:
                results = search_web(query, num_results=3)
                if results:
                    snippet = json.dumps(results, ensure_ascii=False)[:800]
                    output_parts.append(f"[Query: {query}]\n{snippet}")
                    findings.append(
                        {
                            "type": "osint_result",
                            "severity": "info",
                            "title": f"OSINT: {query[:60]}",
                            "description": snippet[:400],
                            "target": target,
                        }
                    )
        except Exception as exc:
            self.logger.debug(f"OSINT search failed: {exc}")

        return WorkerResult(
            success=bool(findings),
            worker_name=self.name,
            output="\n\n".join(output_parts),
            findings=findings,
        )


# ── StrategistAgent ────────────────────────────────────────────────────────────


class StrategistAgent:
    """AI agent responsible for attack planning and re-planning.

    Uses AI client #1 (Gemini by default) to generate and update attack plans.
    Coordinates ReconWorker and OsintWorker to gather initial intelligence.

    Args:
        client: AIClientManager-compatible client with .chat() method.
        model_label: Human-readable label for display (e.g. "Gemini 2.0").
        enable_workers: If True, run sub-workers during planning phase.
        max_tasks: Maximum number of tasks per plan.
    """

    PLAN_PROMPT = """You are the Lead Strategist for an elite security assessment AI team.

Your role: Generate a PRIORITIZED attack plan for the target.

Mission Objective: {objective}
Target: {target}
OSINT Context: {osint_context}
Past missions context: {memory_context}

Rules:
- Tasks flow: reconnaissance → enumeration → vulnerability detection → exploitation → reporting
- Max {max_tasks} tasks, highest impact first
- Each task MUST specify risk level: low / medium / high / critical
- "critical" risk = destructive or likely to trigger IDS

Respond ONLY with valid JSON array:
[
  {{"description": "DNS enumeration for target", "phase": "recon", "risk": "low", "tool_hint": "dig"}},
  {{"description": "HTTP service discovery", "phase": "recon", "risk": "low", "tool_hint": "curl"}},
  {{"description": "Vulnerability scanning", "phase": "scanning", "risk": "medium", "tool_hint": "python_scanner"}}
]

No extra text. Only the JSON array."""

    REPLAN_PROMPT = """You are the Lead Strategist reviewing mission progress.

Target: {target}
Confirmed findings so far:
{findings_summary}

Generate FOLLOW-UP tasks based on these findings. Focus on:
- Exploiting confirmed vulnerabilities deeper
- Testing adjacent attack surface exposed by findings
- Verifying impact / business logic flaws

Max 5 follow-up tasks. Respond ONLY with valid JSON array (same format as before):
[{{"description": "...", "phase": "follow_up", "risk": "...", "tool_hint": "..."}}]"""

    VOTE_PROMPT = """You are the Strategist voting on a proposed action.

Proposed task: {description}
Risk level: {risk}
Current findings: {findings_count} confirmed
Target: {target}

Should we proceed? Consider:
- Will this yield significantly better results?
- Is the risk proportional to expected gain?
- Could this alert the target and end the assessment?

Respond with ONLY one word: "approve" or "deny" (no punctuation, no explanation)."""

    def __init__(
        self,
        client: Any,
        model_label: str = "Strategist AI",
        enable_workers: bool = True,
        max_tasks: int = 10,
    ) -> None:
        self.client = client
        self.model_label = model_label
        self.enable_workers = enable_workers
        self.max_tasks = max_tasks
        self.total_tokens_used: int = 0

        # Sub-workers
        self.recon_worker = ReconWorker()
        self.osint_worker = OsintWorker()

    def plan(
        self,
        objective: str,
        target: str,
        inbox: "SharedInbox",
    ) -> List[Dict[str, Any]]:
        """Generate initial attack plan.

        Args:
            objective: Mission objective string.
            target: Primary target domain/IP.
            inbox: SharedInbox for posting status messages.

        Returns:
            List of task dicts.
        """
        from elengenix.scanning.agent_council import CouncilMessage, MessageType

        # Gather OSINT context via workers
        osint_context = ""
        if self.enable_workers:
            osint_result = self.osint_worker.execute(target)
            if osint_result.success:
                osint_context = osint_result.output[:600]

        # Memory context
        memory_context = ""
        try:
            from tools.vector_memory import get_context_for_ai

            memory_context = get_context_for_ai(objective, target, max_memories=5)[:400]
        except Exception:
            pass

        prompt = self.PLAN_PROMPT.format(
            objective=objective,
            target=target,
            osint_context=osint_context or "(none)",
            memory_context=memory_context or "(none)",
            max_tasks=self.max_tasks,
        )

        tasks = self._call_ai_for_json(prompt, "Generate attack plan.")

        # Post to inbox
        inbox.post(
            CouncilMessage(
                msg_type=MessageType.PLAN,
                sender="strategist",
                recipient="council",
                payload={"tasks": tasks, "target": target},
            )
        )

        return tasks if isinstance(tasks, list) else []

    def replan(
        self,
        confirmed_findings: List[Dict[str, Any]],
        target: str,
        inbox: "SharedInbox",
    ) -> List[Dict[str, Any]]:
        """Generate follow-up tasks based on validated findings.

        Args:
            confirmed_findings: List of Critic-verified findings.
            target: Primary target.
            inbox: SharedInbox for status messages.

        Returns:
            List of follow-up task dicts.
        """
        from elengenix.scanning.agent_council import CouncilMessage, MessageType

        findings_summary = (
            "\n".join(
                [
                    f"- [{f.get('severity', 'info').upper()}] {f.get('title', 'Finding')}: {f.get('description', '')[:100]}"
                    for f in confirmed_findings[:10]
                ]
            )
            or "(none)"
        )

        prompt = self.REPLAN_PROMPT.format(
            target=target,
            findings_summary=findings_summary,
        )

        tasks = self._call_ai_for_json(prompt, "Generate follow-up tasks.")

        inbox.post(
            CouncilMessage(
                msg_type=MessageType.PLAN,
                sender="strategist",
                recipient="council",
                payload={"tasks": tasks, "stage": "follow_up"},
            )
        )

        return tasks if isinstance(tasks, list) else []

    def vote(
        self,
        task: Dict[str, Any],
        current_findings: List[Dict[str, Any]],
        target: str,
    ) -> str:
        """Vote on a high-risk task during deliberation.

        Args:
            task: Task dict with description and risk.
            current_findings: Findings accumulated so far.
            target: Primary target.

        Returns:
            "approve" or "deny".
        """
        prompt = self.VOTE_PROMPT.format(
            description=task.get("description", ""),
            risk=task.get("risk", "high"),
            findings_count=len(current_findings),
            target=target,
        )
        try:
            response = (
                self.client.chat(
                    [
                        AIMessage(role="user", content=prompt),
                    ]
                ).content
                or ""
            )
            decision = response.strip().lower().split()[0] if response.strip() else "approve"
            return "approve" if "approve" in decision else "deny"
        except Exception as exc:
            logger.warning(f"Strategist vote AI call failed: {exc}")
            return "approve"

    def _call_ai_for_json(self, prompt: str, user_msg: str) -> Any:
        """Call AI and parse JSON response.

        Args:
            prompt: System prompt string.
            user_msg: User message to send.

        Returns:
            Parsed JSON (list or dict) or empty list on failure.
        """
        if not self.client:
            return []
        try:
            response = (
                self.client.chat(
                    [
                        AIMessage(role="system", content=prompt),
                        AIMessage(role="user", content=user_msg),
                    ]
                ).content
                or ""
            )

            # Track usage
            self.total_tokens_used += len(response) // 4

            return _extract_json(response)
        except Exception as exc:
            logger.error(f"[Strategist] AI call failed: {exc}")
            return []


# ── JSON Helper ────────────────────────────────────────────────────────────────


def _extract_json(text: str) -> Any:
    """Extract JSON array or object from LLM response text.

    Args:
        text: Raw LLM response string.

    Returns:
        Parsed Python object (list/dict) or empty list on failure.
    """
    # Try markdown fence
    match = re.search(r"```(?:json)?\s*([\s\S]*?)\s*```", text)
    candidate = match.group(1).strip() if match else text.strip()

    for parser in [json.loads]:
        try:
            return parser(candidate)
        except (json.JSONDecodeError, ValueError):
            pass

    # Find outermost [ ... ] or { ... }
    for start, end in [("[", "]"), ("{", "}")]:
        si = candidate.find(start)
        ei = candidate.rfind(end)
        if si != -1 and ei > si:
            try:
                return json.loads(candidate[si : ei + 1])
            except (json.JSONDecodeError, ValueError):
                continue

    logger.warning(f"[Strategist] No valid JSON in response: {text[:200]}")
    return []
