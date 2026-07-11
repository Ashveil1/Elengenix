"""tools/escalation_engine.py — Engine for escalating low-severity findings.

Helps AI understand how to turn low-severity bugs into high/critical impacts.
Based on Mythos research: "chain vulnerabilities for privilege escalation."

Public API:
    EscalationEngine - Main escalation engine
    EscalationPath - Data class for escalation paths
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

logger = logging.getLogger("elengenix.escalation_engine")


@dataclass
class EscalationPath:
    """Defines how to escalate a finding type to higher severity.

    Attributes:
        finding_type: The type of vulnerability (e.g., "XSS", "SQLi").
        current_severity: Typical initial severity.
        next_steps: Ordered list of escalation steps.
        expected_severity: Expected severity after full escalation.
        description: Human-readable description of the escalation path.
    """

    finding_type: str
    current_severity: str
    next_steps: List[str]
    expected_severity: str
    description: str


class EscalationEngine:
    """Engine for escalating low-severity findings to higher severity.

    This engine helps AI understand how to turn low-severity bugs into
    high/critical impacts by trying additional exploitation techniques.

    Based on Mythos research:
    - XSS → stored XSS → cookie theft → account takeover
    - SQLi → UNION-based → file read → RCE
    - IDOR → sequential IDs → bulk extraction → privilege escalation

    Example:
        engine = EscalationEngine()
        finding = {"type": "XSS", "severity": "LOW", "url": "http://test.com"}
        path = engine.can_escalate(finding)
        if path:
            print(f"Try: {path.next_steps}")
    """

    def __init__(self) -> None:
        """Initialize escalation engine with known escalation paths."""
        self.escalation_map = self._build_escalation_map()

    def _build_escalation_map(self) -> Dict[str, EscalationPath]:
        """Build the escalation path database.

        Returns:
            Dictionary mapping finding types to escalation paths.
        """
        return {
            "XSS": EscalationPath(
                finding_type="XSS",
                current_severity="LOW",
                next_steps=[
                    "stored_xss",
                    "cookie_theft",
                    "session_hijack",
                    "account_takeover",
                ],
                expected_severity="CRITICAL",
                description="Escalate reflected XSS to stored XSS, then cookie theft, then account takeover",
            ),
            "SQLi": EscalationPath(
                finding_type="SQLi",
                current_severity="MEDIUM",
                next_steps=[
                    "union_based",
                    "file_read",
                    "command_execution",
                    "rce",
                ],
                expected_severity="CRITICAL",
                description="Escalate error-based SQLi to UNION, then file read, then RCE",
            ),
            "IDOR": EscalationPath(
                finding_type="IDOR",
                current_severity="LOW",
                next_steps=[
                    "sequential_ids",
                    "bulk_extraction",
                    "privilege_escalation",
                ],
                expected_severity="HIGH",
                description="Escalate single IDOR to bulk data extraction",
            ),
            "SSRF": EscalationPath(
                finding_type="SSRF",
                current_severity="MEDIUM",
                next_steps=[
                    "internal_scan",
                    "cloud_metadata",
                    "rce",
                ],
                expected_severity="CRITICAL",
                description="Escalate SSRF to internal network scan, then cloud metadata, then RCE",
            ),
            "info_disclosure": EscalationPath(
                finding_type="info_disclosure",
                current_severity="LOW",
                next_steps=[
                    "combine_with_other",
                    "increase_impact",
                ],
                expected_severity="MEDIUM",
                description="Combine with other findings to increase impact",
            ),
            "XXE": EscalationPath(
                finding_type="XXE",
                current_severity="MEDIUM",
                next_steps=[
                    "file_read",
                    "ssrf",
                    "rce",
                ],
                expected_severity="CRITICAL",
                description="Escalate XXE to file read, then SSRF, then RCE",
            ),
            "SSTI": EscalationPath(
                finding_type="SSTI",
                current_severity="HIGH",
                next_steps=[
                    "information_leak",
                    "rce",
                ],
                expected_severity="CRITICAL",
                description="Escalate SSTI to information leak, then RCE",
            ),
            "race_condition": EscalationPath(
                finding_type="race_condition",
                current_severity="MEDIUM",
                next_steps=[
                    "double_spend",
                    "privilege_escalation",
                ],
                expected_severity="HIGH",
                description="Escalate race condition to double spend or privilege escalation",
            ),
        }

    def can_escalate(self, finding: Dict[str, Any]) -> Optional[EscalationPath]:
        """Check if a finding can be escalated.

        Args:
            finding: Finding dictionary with 'type' field.

        Returns:
            EscalationPath if escalation is possible, None otherwise.
        """
        finding_type = finding.get("type", "")
        return self.escalation_map.get(finding_type)

    def get_escalation_steps(self, finding: Dict[str, Any]) -> List[str]:
        """Get escalation steps for a finding.

        Args:
            finding: Finding dictionary with 'type' field.

        Returns:
            List of escalation steps, or empty list if not escalable.
        """
        path = self.can_escalate(finding)
        return path.next_steps if path else []

    def get_expected_severity(self, finding: Dict[str, Any]) -> Optional[str]:
        """Get expected severity after full escalation.

        Args:
            finding: Finding dictionary with 'type' field.

        Returns:
            Expected severity string, or None if not escalable.
        """
        path = self.can_escalate(finding)
        return path.expected_severity if path else None

    def suggest_next_action(
        self, finding: Dict[str, Any], completed_steps: List[str]
    ) -> Optional[str]:
        """Suggest the next escalation step.

        Args:
            finding: Finding dictionary with 'type' field.
            completed_steps: List of escalation steps already attempted.

        Returns:
            Next step to try, or None if escalation is complete.
        """
        path = self.can_escalate(finding)
        if not path:
            return None

        for step in path.next_steps:
            if step not in completed_steps:
                return step

        return None
