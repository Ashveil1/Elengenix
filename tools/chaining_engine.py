"""tools/chaining_engine.py — Engine for chaining multiple findings.

Helps AI combine low-severity findings into critical impacts.
Based on Mythos research: "chain 2-4 vulnerabilities for privilege escalation."

Public API:
    ChainingEngine - Main chaining engine
    AttackChain - Data class for attack chains
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("elengenix.chaining_engine")


@dataclass
class AttackChain:
    """Represents a chain of findings that combine for higher impact.

    Attributes:
        findings: List of findings in the chain.
        combined_severity: Severity after chaining.
        impact_description: Description of the combined impact.
        chain_type: Category of the chain (e.g., "data_exfiltration").
    """

    findings: List[Dict[str, Any]]
    combined_severity: str
    impact_description: str
    chain_type: str


class ChainingEngine:
    """Engine for chaining multiple low-severity findings into critical impacts.

    This engine helps AI understand how multiple low-severity bugs can be
    combined to create critical impacts.

    Based on Mythos research:
    - IDOR + info_disclosure → Full account takeover
    - XSS + session_fixation → Session hijacking
    - SSRF + cloud_metadata → Cloud credential theft

    Example:
        engine = ChainingEngine()
        findings = [
            {"type": "IDOR", "severity": "LOW"},
            {"type": "info_disclosure", "severity": "LOW"}
        ]
        chain = engine.analyze_chain(findings)
        if chain:
            print(f"Combined severity: {chain.combined_severity}")
    """

    def __init__(self) -> None:
        """Initialize chaining engine with known chain rules."""
        self.chain_rules = self._build_chain_rules()

    def _build_chain_rules(self) -> Dict[str, Dict[str, Any]]:
        """Build the chain rule database.

        Returns:
            Dictionary mapping chain names to rules.
        """
        return {
            "IDOR+info_disclosure": {
                "findings": ["IDOR", "info_disclosure"],
                "combined_severity": "CRITICAL",
                "impact": "Full account takeover via IDOR + information disclosure",
                "chain_type": "data_exfiltration",
            },
            "XSS+session_fixation": {
                "findings": ["XSS", "session_fixation"],
                "combined_severity": "HIGH",
                "impact": "Session hijacking via XSS + session fixation",
                "chain_type": "session_attack",
            },
            "SSRF+cloud_metadata": {
                "findings": ["SSRF", "cloud_metadata_access"],
                "combined_severity": "CRITICAL",
                "impact": "Cloud credential theft via SSRF",
                "chain_type": "cloud_attack",
            },
            "SQLi+info_disclosure": {
                "findings": ["SQLi", "info_disclosure"],
                "combined_severity": "HIGH",
                "impact": "Full database extraction",
                "chain_type": "data_exfiltration",
            },
            "XSS+CSRF": {
                "findings": ["XSS", "CSRF"],
                "combined_severity": "HIGH",
                "impact": "Account takeover via XSS + CSRF",
                "chain_type": "session_attack",
            },
            "IDOR+privilege_escalation": {
                "findings": ["IDOR", "privilege_escalation"],
                "combined_severity": "CRITICAL",
                "impact": "Full system compromise",
                "chain_type": "privilege_escalation",
            },
            "SSRF+SQLi": {
                "findings": ["SSRF", "SQLi"],
                "combined_severity": "CRITICAL",
                "impact": "Internal network database extraction",
                "chain_type": "data_exfiltration",
            },
            "XXE+SSRF": {
                "findings": ["XXE", "SSRF"],
                "combined_severity": "CRITICAL",
                "impact": "Internal network access via XXE + SSRF",
                "chain_type": "network_attack",
            },
        }

    def analyze_chain(self, findings: List[Dict[str, Any]]) -> Optional[AttackChain]:
        """Analyze if findings can be chained together.

        Args:
            findings: List of finding dictionaries with 'type' field.

        Returns:
            AttackChain if chaining is possible, None otherwise.
        """
        finding_types = [f.get("type", "") for f in findings]

        for rule_name, rule in self.chain_rules.items():
            if all(ft in finding_types for ft in rule["findings"]):
                return AttackChain(
                    findings=findings,
                    combined_severity=rule["combined_severity"],
                    impact_description=rule["impact"],
                    chain_type=rule["chain_type"],
                )

        return None

    def find_chainable_findings(self, findings: List[Dict[str, Any]]) -> List[Tuple[Dict[str, Any], Dict[str, Any]]]:
        """Find pairs of findings that can be chained.

        Args:
            findings: List of finding dictionaries.

        Returns:
            List of (finding1, finding2) tuples that can be chained.
        """
        chainable = []
        for i, f1 in enumerate(findings):
            for f2 in findings[i + 1 :]:
                chain = self.analyze_chain([f1, f2])
                if chain:
                    chainable.append((f1, f2))
        return chainable

    def suggest_chain(self, findings: List[Dict[str, Any]]) -> Optional[AttackChain]:
        """Suggest the best chain from available findings.

        Args:
            findings: List of finding dictionaries.

        Returns:
            Best AttackChain found, or None.
        """
        best_chain = None
        best_severity_order = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

        for i, f1 in enumerate(findings):
            for f2 in findings[i + 1 :]:
                chain = self.analyze_chain([f1, f2])
                if chain:
                    severity_rank = best_severity_order.get(chain.combined_severity, 0)
                    if best_chain is None or severity_rank > best_severity_order.get(best_chain.combined_severity, 0):
                        best_chain = chain

        return best_chain
