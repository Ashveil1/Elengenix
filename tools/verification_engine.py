"""tools/verification_engine.py — Dual-model verification engine.

Validates findings using two independent AI models to reduce false positives.
Based on Mythos research: "verification agent confirms if bugs are real."

Public API:
    VerificationEngine - Main verification engine
    VerificationResult - Data class for verification results
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Dict

logger = logging.getLogger("elengenix.verification_engine")


@dataclass
class VerificationResult:
    """Result of dual-model verification.

    Attributes:
        finding: The original finding.
        verified: Whether both models confirmed the finding.
        severity: Severity after verification.
        model_a_response: Response from model A.
        model_b_response: Response from model B.
        requires_human_review: Whether human review is needed.
        confidence: Confidence score (0.0 to 1.0).
    """

    finding: Dict[str, Any]
    verified: bool
    severity: str
    model_a_response: str
    model_b_response: str
    requires_human_review: bool
    confidence: float


class VerificationEngine:
    """Dual-model verification engine for validating findings.

    This engine uses two independent AI models to verify findings,
    reducing false positives and improving confidence.

    Based on Mythos research:
    - Model A confirms if finding is real
    - Model B validates impact assessment
    - Disagreements flagged for human review

    Example:
        engine = VerificationEngine()
        finding = {"type": "XSS", "severity": "HIGH", "url": "http://test.com"}
        result = engine.verify(finding, "confirmed", "confirmed")
        if result.verified:
            print("Finding is real!")
    """

    def __init__(self) -> None:
        """Initialize verification engine."""
        self.severity_levels = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]

    def verify(
        self,
        finding: Dict[str, Any],
        model_a_response: str,
        model_b_response: str,
    ) -> VerificationResult:
        """Verify a finding using dual-model verification.

        Args:
            finding: The finding to verify.
            model_a_response: Response from model A (confirmation or denial).
            model_b_response: Response from model B (confirmation or denial).

        Returns:
            VerificationResult with verification status.
        """
        a_confirms = self._is_confirmation(model_a_response)
        b_confirms = self._is_confirmation(model_b_response)

        if a_confirms and b_confirms:
            return VerificationResult(
                finding=finding,
                verified=True,
                severity=finding.get("severity", "MEDIUM"),
                model_a_response=model_a_response,
                model_b_response=model_b_response,
                requires_human_review=False,
                confidence=0.95,
            )
        elif a_confirms or b_confirms:
            return VerificationResult(
                finding=finding,
                verified=False,
                severity=finding.get("severity", "MEDIUM"),
                model_a_response=model_a_response,
                model_b_response=model_b_response,
                requires_human_review=True,
                confidence=0.5,
            )
        else:
            return VerificationResult(
                finding=finding,
                verified=False,
                severity="INFO",
                model_a_response=model_a_response,
                model_b_response=model_b_response,
                requires_human_review=False,
                confidence=0.1,
            )

    def _is_confirmation(self, response: str) -> bool:
        """Check if a response is a confirmation.

        Args:
            response: The model response string.

        Returns:
            True if the response indicates confirmation.
        """
        response_lower = response.lower()
        confirmation_keywords = ["confirm", "true", "yes", "real", "valid", "vulnerable"]
        denial_keywords = ["false", "no", "not", "invalid", "hallucination", "fake"]

        has_confirmation = any(kw in response_lower for kw in confirmation_keywords)
        has_denial = any(kw in response_lower for kw in denial_keywords)

        return has_confirmation and not has_denial

    def get_verification_prompt(self, finding: Dict[str, Any]) -> str:
        """Generate a verification prompt for a model.

        Args:
            finding: The finding to verify.

        Returns:
            Prompt string for the model.
        """
        return f"""Please verify if this security finding is real and not a false positive.

Finding:
- Type: {finding.get('type', 'Unknown')}
- Severity: {finding.get('severity', 'Unknown')}
- URL: {finding.get('url', 'Unknown')}
- Description: {finding.get('description', 'No description')}
- Evidence: {finding.get('evidence', 'No evidence')}

Questions:
1. Is this finding real (not a hallucination)?
2. Is the severity assessment accurate?
3. Could this be a false positive?

Respond with:
- "confirmed" if the finding is real and severity is accurate
- "false_positive" if it's not a real vulnerability
- "severity_adjustment: [new_severity]" if the severity should be different
"""
