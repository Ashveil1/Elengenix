"""tools/verification_engine.py — Multi-model verification engine.

Validates findings using multiple independent AI models to reduce false positives.
Based on Mythos research: "verification agent confirms if bugs are real."

Public API:
    VerificationEngine - Main verification engine
    VerificationResult - Data class for verification results
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
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
    """Result of multi-model verification.

    Attributes:
        finding: The original finding.
        verified: Whether consensus confirms the finding.
        consensus_verdict: The agreed verdict.
        severity: Final severity after consensus.
        model_votes: List of individual model votes.
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


# Default model configurations for verification
DEFAULT_VERIFICATION_MODELS = [
    {"name": "claude-opus-4-8", "provider": "anthropic", "weight": 3.0, "role": "primary"},
    {"name": "claude-sonnet-5", "provider": "anthropic", "weight": 2.0, "role": "secondary"},
    {"name": "claude-haiku-4-5-20251001", "provider": "anthropic", "weight": 1.0, "role": "tertiary"},
]


class VerificationEngine:
    """Multi-model verification engine for validating findings.

    This engine uses 3 independent AI models (Opus, Sonnet, Haiku) to verify findings,
    reducing false positives and improving confidence through weighted consensus.

    Based on Mythos research:
    - Multiple models vote with different weights
    - Consensus determines if finding is real
    - Severity adjustments via weighted majority
    - Low consensus flagged for human review

    Example:
        engine = VerificationEngine(ai_client=client)
        finding = {"type": "XSS", "severity": "HIGH", "url": "http://test.com"}
        result = await engine.verify_with_consensus(finding)
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
            models: List of model configs with name, provider, weight, role.
            ai_client: Optional AIClientManager for making verification calls.
        """
        self.models = models or DEFAULT_VERIFICATION_MODELS
        self.ai_client = ai_client
        self.severity_levels = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]

    async def verify_with_consensus(
        self,
        finding: Dict[str, Any],
        max_models: int = 3,
    ) -> VerificationResult:
        """Verify a finding using multi-model consensus.

        Args:
            finding: The finding to verify.
            max_models: Maximum number of models to use (default 3).

        Returns:
            VerificationResult with consensus verdict, severity, and confidence.
        """
        if not self.ai_client:
            logger.warning("No AI client available, using fallback verification")
            return self._fallback_verification(finding)

        votes = []
        prompt = self.get_verification_prompt(finding)

        # Query each model
        for model_config in self.models[:max_models]:
            try:
                vote = await self._query_model(model_config, prompt, finding)
                votes.append(vote)
            except Exception as e:
                logger.warning(f"Model {model_config['name']} failed: {e}")

        if not votes:
            logger.warning("All models failed, using fallback")
            return self._fallback_verification(finding)

        # Compute consensus
        return self._compute_consensus(finding, votes)

    def _fallback_verification(self, finding: Dict[str, Any]) -> VerificationResult:
        """Fallback verification when no AI client available."""
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

    async def _query_model(
        self,
        model_config: Dict[str, Any],
        prompt: str,
        finding: Dict[str, Any],
    ) -> ModelVote:
        """Query a single model for verification."""
        model_name = model_config["name"]
        provider = model_config["provider"]
        weight = model_config["weight"]

        messages = [
            AIMessage(role="system", content="You are a security verification expert. Respond concisely."),
            AIMessage(role="user", content=prompt),
        ]

        try:
            response = await self.ai_client.chat(
                model=model_name,
                messages=messages,
                temperature=0.1,
                max_tokens=500,
            )
            content = response.content if hasattr(response, "content") else str(response)
        except Exception as e:
            logger.error(f"Model {model_name} query failed: {e}")
            raise

        # Parse response
        verdict, confidence, reasoning, severity_adj = self._parse_verification_response(content)

        return ModelVote(
            model_name=model_name,
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