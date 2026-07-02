"""tools/adaptive_planner.py — Adaptive planner for dynamic attack path selection.

Helps AI rank targets and decide next actions based on current state.
Based on Mythos research: "rank files by bug likelihood, start with highest."

Public API:
    AdaptivePlanner - Main planner class
    ActionType - Enum for action types
    AttackPath - Data class for attack paths
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List

logger = logging.getLogger("elengenix.adaptive_planner")


class ActionType(Enum):
    """Types of actions the planner can suggest."""

    RECON = "recon"
    SCAN = "scan"
    EXPLOIT = "exploit"
    ESCALATE = "escalate"
    CHAIN = "chain"
    VERIFY = "verify"
    REPORT = "report"


@dataclass
class AttackPath:
    """Represents a ranked attack path.

    Attributes:
        target: The target URL or endpoint.
        path_type: Type of target (e.g., "api_endpoint", "auth").
        rank: Priority rank (5=highest, 1=lowest).
        tools: List of tools suitable for this path.
        expected_impact: Expected impact if successful.
    """

    target: str
    path_type: str
    rank: int
    tools: List[str]
    expected_impact: str


class AdaptivePlanner:
    """Adaptive planner for dynamic attack path selection.

    This planner helps AI:
    - Rank targets by attack surface (Mythos-style ranking)
    - Decide next actions based on current state
    - Determine when to replan or stop

    Based on Mythos research:
    - Rank files 1-5 by bug likelihood
    - Start with highest-ranked files
    - Verify findings with confirmation agent

    Example:
        planner = AdaptivePlanner()
        targets = [
            {"url": "http://test.com/api", "type": "api_endpoint"},
            {"url": "http://test.com/static", "type": "static"},
        ]
        ranked = planner.rank_targets(targets)
        # ranked[0] will be the API endpoint (rank 5)
    """

    def __init__(self) -> None:
        """Initialize planner with rank weights."""
        self.rank_weights = {
            "api_endpoint": 5,
            "auth": 5,
            "file_upload": 4,
            "dynamic_content": 4,
            "form_input": 3,
            "standard_page": 2,
            "static": 1,
            "config": 1,
        }

    def rank_targets(self, targets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Rank targets by attack surface likelihood.

        Args:
            targets: List of target dictionaries with 'url' and 'type' fields.

        Returns:
            Sorted list of targets with 'rank' field added.
        """
        ranked = []
        for target in targets:
            path_type = target.get("type", "standard_page")
            rank = self.rank_weights.get(path_type, 2)
            target_copy = target.copy()
            target_copy["rank"] = rank
            ranked.append(target_copy)

        return sorted(ranked, key=lambda x: x["rank"], reverse=True)

    def decide_next(self, state: Dict[str, Any]) -> Dict[str, Any]:
        """Decide the next action based on current state.

        Args:
            state: Current mission state with findings, tried_paths, budget_remaining.

        Returns:
            Dictionary with 'action' and related fields.
        """
        findings = state.get("findings", [])
        tried = state.get("tried_paths", [])
        budget = state.get("budget_remaining", 1.0)

        if budget < 0.1:
            return {"action": ActionType.REPORT.value, "reason": "budget_low"}

        if not findings and not tried:
            return {"action": ActionType.RECON.value, "reason": "initial_scan"}

        if findings:
            high_findings = [f for f in findings if f.get("severity") in ["HIGH", "CRITICAL"]]
            if high_findings:
                return {
                    "action": ActionType.ESCALATE.value,
                    "finding": high_findings[0],
                    "reason": "high_severity_found",
                }

            medium_findings = [f for f in findings if f.get("severity") == "MEDIUM"]
            if len(medium_findings) >= 2:
                return {
                    "action": ActionType.CHAIN.value,
                    "findings": medium_findings[:2],
                    "reason": "multiple_medium_findings",
                }

        return {
            "action": ActionType.SCAN.value,
            "reason": "continue_scanning",
            "tried": tried,
        }

    def should_replan(self, state: Dict[str, Any]) -> bool:
        """Determine if replanning is needed.

        Args:
            state: Current mission state.

        Returns:
            True if replanning is recommended.
        """
        findings = state.get("findings", [])
        gaps = state.get("gaps", [])
        return len(gaps) > 0 or len(findings) == 0

    def should_stop(self, state: Dict[str, Any]) -> bool:
        """Determine if the mission should stop.

        Args:
            state: Current mission state.

        Returns:
            True if mission should stop.
        """
        budget = state.get("budget_remaining", 1.0)
        steps = state.get("steps", 0)
        max_steps = state.get("max_steps", 100)

        if budget < 0.05:
            return True
        if steps >= max_steps:
            return True
        return False

    def get_rank_description(self, rank: int) -> str:
        """Get human-readable description of a rank.

        Args:
            rank: The rank value (1-5).

        Returns:
            Description string.
        """
        descriptions = {
            5: "Very High - raw data from internet, parses user input",
            4: "High - handles auth, file upload, API endpoints",
            3: "Medium - standard web pages, forms",
            2: "Low - static content, read-only",
            1: "Very Low - constants, config, no attack surface",
        }
        return descriptions.get(rank, "Unknown rank")
