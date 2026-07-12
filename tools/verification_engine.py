"""tools/verification_engine.py — Multi-perspective verification engine.

Validates findings by querying the configured AI provider from multiple
angles (different temperatures, system prompts, role framing) to reduce
false positives without depending on multiple separate model endpoints.

Design:
- Single AI provider (whatever is configured — OpenRouter, Ollama, etc.)
- Multiple "perspective" passes with different temperatures & role frames
- Weighted consensus on the set of perspectives
- Low-consensus results always flagged for human review
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from tools.universal_ai_client import AIClientManager, AIMessage

logger = logging.getLogger("elengenix.verification_engine")


@dataclass
class ModelVote:
    """Single model's vote on a finding."""

    model_name: str
    model_weight: float
    verdict: str  # "confirmed", "false_positive", "severity_adjustment"
    confidence: float  # 0.0-1.0
    reasoning: str
    severity_adjustment: Optional[str] = None


@dataclass
class VerificationResult:
    """Result of verification.

    Attributes:
        finding: The original finding.
        verified: Whether consensus confirms the finding.
        consensus_verdict: The agreed verdict.
        severity: Final severity after consensus.
        model_votes: List of individual perspective votes.
        requires_human_review: Whether human review is needed.
        confidence: Aggregate confidence score (0.0 to 1.0).
        consensus_strength: How strong the consensus is (0.0-1.0).
    """

    finding: Dict[str, Any]
    verified: bool
    consensus_verdict: str
    severity: str
    model_votes: List[ModelVote]
    requires_human_review: bool
    confidence: float
    consensus_strength: float


# Default perspective configurations
# Queries the AI provider from multiple angles to simulate multi-model consensus
# without requiring multiple separate model endpoints.
DEFAULT_VERIFICATION_MODELS = [
    {"name": "default", "provider": None, "weight": 1.0, "role": "primary", "temperature": 0.1},
    {"name": "default", "provider": None, "weight": 0.8, "role": "conservative", "temperature": 0.05},
    {"name": "default", "provider": None, "weight": 0.6, "role": "strict", "temperature": 0.2},
]


class VerificationEngine:
    """Multi-perspective verification engine for validating findings.

    Queries the configured AI provider from multiple angles (different role
    frames and temperatures) to build a weighted consensus on whether a
    finding is a real vulnerability, a false positive, or needs a severity
    adjustment.

    Based on Mythos research:
    - Multiple perspectives vote with different weights
    - Consensus determines if finding is real
    - Severity adjustments via weighted majority
    - Low consensus flagged for human review

    Example:
        engine = VerificationEngine(ai_client=client)
        finding = {"type": "XSS", "severity": "HIGH", "url": "http://test.com"}
        result = engine.verify_with_consensus(finding)
        if result.verified:
            print("Finding is real!")
    """

    def __init__(
        self,
        models: Optional[List[Dict[str, Any]]] = None,
        ai_client: Optional[AIClientManager] = None,
    ) -> None:
        """Initialize verification engine.

        Args:
            models: List of perspective configs with name, provider, weight, role, temperature.
            ai_client: Optional AIClientManager for making verification calls.
        """
        self.models = models or DEFAULT_VERIFICATION_MODELS
        self.ai_client = ai_client
        self.severity_levels = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]

    def verify_with_consensus(
        self,
        finding: Dict[str, Any],
        max_perspectives: int = 3,
    ) -> VerificationResult:
        """Verify a finding using multi-perspective consensus.

        Queries the AI provider from multiple angles (different temperatures,
        role frames). If the AI client is unavailable, falls back to a
        clearly-marked manual-review result (not silent rejection).

        Args:
            finding: The finding to verify.
            max_perspectives: Maximum number of perspectives to use (default 3).

        Returns:
            VerificationResult with consensus verdict, severity, and confidence.
        """
        if not self.ai_client:
            logger.warning(
                "No AI client configured — returning requires_human_review=True "
                "(not silently rejecting)"
            )
            return self._fallback_verification(finding)

        votes = []
        prompt = self.get_verification_prompt(finding)

        # Query each perspective
        for model_config in self.models[:max_perspectives]:
            try:
                vote = self._query_perspective(model_config, prompt, finding)
                votes.append(vote)
            except Exception as e:
                logger.warning(f"Perspective '{model_config.get('role', '?')}' failed: {e}")

        if not votes:
            logger.warning(
                "All AI queries failed — returning requires_human_review=True "
                "(not silently rejecting)"
            )
            return self._fallback_verification(finding)

        # Compute consensus
        return self._compute_consensus(finding, votes)

    # ── Fallback ──────────────────────────────────────────────────────────

    def _fallback_verification(self, finding: Dict[str, Any]) -> VerificationResult:
        """Fallback when no AI client is available or all queries fail.

        This result is *always* marked requires_human_review=True so the caller
        knows the finding was NOT automatically verified.  The engine never
        silently rejects findings — it escalates them.
        """
        return VerificationResult(
            finding=finding,
            verified=False,
            consensus_verdict="insufficient_evidence",
            severity=finding.get("severity", "MEDIUM"),
            model_votes=[],
            requires_human_review=True,
            confidence=0.3,
            consensus_strength=0.0,
        )

    # ── Single perspective query ──────────────────────────────────────────

    def _query_perspective(
        self,
        config: Dict[str, Any],
        prompt: str,
        finding: Dict[str, Any],
    ) -> ModelVote:
        """Query the AI provider from one perspective and return the vote.

        Each config specifies a role frame and temperature so the same
        underlying provider gives differently-weighted opinions, simulating
        multi-model consensus without multiple endpoints.
        """
        role = config.get("role", "primary")
        weight = config.get("weight", 1.0)
        temperature = config.get("temperature", 0.1)

        # Role-appropriate system prompt
        role_prompts = {
            "primary": "You are a security verification expert. Be thorough but balanced.",
            "conservative": "You are a skeptical security auditor. You must see strong evidence before confirming any finding.",
            "strict": "You are a strict severity reviewer. Focus on whether the severity rating is accurate and whether this finding warrants action.",
        }
        system_prompt = role_prompts.get(role, role_prompts["primary"])

        messages = [
            AIMessage(role="system", content=system_prompt),
            AIMessage(role="user", content=prompt),
        ]

        try:
            response = self.ai_client.chat(
                messages=messages,
                temperature=temperature,
                max_tokens=500,
            )
            content = response.content if hasattr(response, "content") else str(response)
        except Exception as e:
            logger.error(f"Perspective '{role}' query failed: {e}")
            raise

        # Parse response
        verdict, confidence, reasoning, severity_adj = self._parse_verification_response(content)

        return ModelVote(
            model_name=role,
            model_weight=weight,
            verdict=verdict,
            confidence=confidence,
            reasoning=reasoning,
            severity_adjustment=severity_adj,
        )

    def _parse_verification_response(self, response: str) -> tuple:
        """Parse model response into verdict, confidence, reasoning, severity_adjustment."""
        response_lower = response.lower().strip()

        # Check for severity adjustment
        severity_adj = None
        if "severity_adjustment:" in response_lower:
            parts = response_lower.split("severity_adjustment:")
            if len(parts) > 1:
                severity_adj = parts[1].strip().split()[0].upper()

        # Determine verdict
        if "false_positive" in response_lower or "not a real" in response_lower:
            verdict = "false_positive"
            confidence = 0.8
        elif "severity_adjustment" in response_lower:
            verdict = "severity_adjustment"
            confidence = 0.7
        elif "confirmed" in response_lower or "real" in response_lower or "valid" in response_lower:
            verdict = "confirmed"
            confidence = 0.85
        else:
            verdict = "inconclusive"
            confidence = 0.4

        return verdict, confidence, response, severity_adj

    def _compute_consensus(self, finding: Dict[str, Any], votes: List[ModelVote]) -> VerificationResult:
        """Compute consensus from model votes."""
        if not votes:
            return self._fallback_verification(finding)

        # Weighted voting
        total_weight = sum(v.model_weight for v in votes)
        confirmed_weight = sum(v.model_weight for v in votes if v.verdict == "confirmed")
        false_positive_weight = sum(v.model_weight for v in votes if v.verdict == "false_positive")
        severity_adj_weight = sum(v.model_weight for v in votes if v.verdict == "severity_adjustment")

        # Determine consensus
        if false_positive_weight / total_weight > 0.5:
            consensus_verdict = "false_positive"
            verified = False
            severity = "INFO"
        elif confirmed_weight / total_weight > 0.5:
            consensus_verdict = "confirmed"
            verified = True
            # Check for severity adjustment
            severity = finding.get("severity", "MEDIUM")
            severity_votes = [v for v in votes if v.verdict == "severity_adjustment" and v.severity_adjustment]
            if severity_votes:
                # Weighted majority for severity adjustment
                severity = max(
                    set(v.severity_adjustment for v in severity_votes),
                    key=lambda s: sum(v.model_weight for v in severity_votes if v.severity_adjustment == s)
                )
        else:
            consensus_verdict = "inconclusive"
            verified = False
            severity = finding.get("severity", "MEDIUM")

        # Calculate aggregate confidence
        weighted_confidence = sum(v.confidence * v.model_weight for v in votes) / total_weight if total_weight > 0 else 0.0

        # Consensus strength: how much the majority outweighs minority
        max_weight = max(confirmed_weight, false_positive_weight, severity_adj_weight)
        consensus_strength = max_weight / total_weight if total_weight > 0 else 0.0

        # Requires human review if inconclusive or low consensus
        requires_human_review = consensus_strength < 0.6 or consensus_verdict == "inconclusive"

        return VerificationResult(
            finding=finding,
            verified=verified,
            consensus_verdict=consensus_verdict,
            severity=severity,
            model_votes=votes,
            requires_human_review=requires_human_review,
            confidence=weighted_confidence,
            consensus_strength=consensus_strength,
        )

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
- "severity_adjustment: [new_severity]" if the severity should be different"""