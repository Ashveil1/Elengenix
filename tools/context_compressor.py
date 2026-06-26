"""tools/context_compressor.py

Smart Context Compression for Long Sessions (Tier 2 Upgrade)

Purpose:
- Compress conversation history when it gets too long
- Summarize older turns while keeping recent ones detailed
- Prevent token overflow and reduce API costs
- Maintain critical context even in very long sessions

Usage:
    compressor = ContextCompressor()
    compressed = compressor.compress(conversation_history, max_tokens=4000)
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger("elengenix.compressor")

# Minimum characters to keep for recent turns
RECENT_TURN_CHARS = 500

# Minimum characters to keep for summarized turns
SUMMARIZED_TURN_CHARS = 150


@dataclass
class CompressionResult:
    """Result of context compression."""

    original_turns: int
    compressed_turns: int
    original_tokens: int
    estimated_compressed_tokens: int
    compression_ratio: float
    summary: str


class ContextCompressor:
    """
    Smart context compressor for long conversation sessions.

    Strategy:
    - Keep last N turns in full detail
    - Summarize older turns to key points
    - Preserve security findings and tool results
    - Drop redundant/low-value conversational filler
    """

    def __init__(
        self,
        recent_turns_full: int = 6,
        max_tokens: int = 4000,
        aggressive: bool = False,
    ):
        """
        Initialize compressor.

        Args:
            recent_turns_full: Number of recent turns to keep in full.
            max_tokens: Target max tokens after compression.
            aggressive: If True, compress more aggressively.
        """
        self.recent_turns_full = recent_turns_full
        self.max_tokens = max_tokens
        self.aggressive = aggressive

    def estimate_tokens(self, text: str) -> int:
        """Estimate token count for a string."""
        from tools.token_counter import count_tokens

        return count_tokens(text)

    def is_security_relevant(self, content: str) -> bool:
        """Check if content contains security-relevant information."""
        security_keywords = {
            "vulnerability",
            "vuln",
            "exploit",
            "cve",
            "xss",
            "sqli",
            "injection",
            "bypass",
            "rce",
            "reverse shell",
            "payload",
            "findings",
            "finding",
            "discovered",
            "detected",
            "flag",
            "subdomain",
            "endpoint",
            "api",
            "auth",
            "token",
            "credential",
            "scan",
            "nuclei",
            "subfinder",
            "httpx",
            "ffuf",
            "nmap",
            "critical",
            "high",
            "medium",
            "low",
            "severity",
            "cvss",
            "authentication",
            "authorization",
            "bypass",
            "idor",
            "bola",
            "ssrf",
            "csrf",
            "idor",
            "lfi",
            "rfi",
            "xxe",
        }
        content_lower = content.lower()
        return any(kw in content_lower for kw in security_keywords)

    def summarize_turn(self, content: str, max_chars: int = SUMMARIZED_TURN_CHARS) -> str:
        """
        Summarize a single turn to key points.

        Args:
            content: Original turn content.
            max_chars: Maximum characters for summary.

        Returns:
            Summarized content.
        """
        if len(content) <= max_chars:
            return content

        # If security-relevant, keep more
        if self.is_security_relevant(content):
            max_chars = max_chars * 2

        # Simple summarization: keep first N chars + "..."
        # In production, this could use LLM summarization
        summary = content[:max_chars]

        # Try to end at a word boundary
        last_space = summary.rfind(" ")
        if last_space > max_chars * 0.7:
            summary = summary[:last_space]

        return summary + "..."

    def compress(
        self,
        conversation_history: List[Dict[str, str]],
        target_tokens: int = None,
    ) -> CompressionResult:
        """
        Compress conversation history to fit within token budget.

        Args:
            conversation_history: List of {"role": ..., "content": ...} dicts.
            target_tokens: Target max tokens (overrides self.max_tokens).

        Returns:
            CompressionResult with compressed history and stats.
        """
        if target_tokens is None:
            target_tokens = self.max_tokens

        original_turns = len(conversation_history)
        if original_turns == 0:
            return CompressionResult(
                original_turns=0,
                compressed_turns=0,
                original_tokens=0,
                estimated_compressed_tokens=0,
                compression_ratio=1.0,
                summary="No conversation to compress.",
            )

        # Calculate original tokens
        original_text = " ".join(turn.get("content", "") for turn in conversation_history)
        original_tokens = self.estimate_tokens(original_text)

        if original_tokens <= target_tokens:
            # No compression needed
            return CompressionResult(
                original_turns=original_turns,
                compressed_turns=original_turns,
                original_tokens=original_tokens,
                estimated_compressed_tokens=original_tokens,
                compression_ratio=1.0,
                summary="No compression needed.",
            )

        # Compression strategy
        compressed_history = []

        # Calculate how many turns to keep full
        recent_to_keep = self.recent_turns_full

        # If aggressive, keep fewer recent turns
        if self.aggressive:
            recent_to_keep = max(2, recent_to_keep // 2)

        # Split into older and recent
        older_turns = (
            conversation_history[:-recent_to_keep]
            if len(conversation_history) > recent_to_keep
            else []
        )
        recent_turns = conversation_history[-recent_to_keep:]

        # Compress older turns
        for turn in older_turns:
            role = turn.get("role", "unknown")
            content = turn.get("content", "")

            # Security-relevant content gets less compression
            if self.is_security_relevant(content):
                max_chars = RECENT_TURN_CHARS
            else:
                max_chars = SUMMARIZED_TURN_CHARS

            compressed_content = self.summarize_turn(content, max_chars)
            compressed_history.append({"role": role, "content": compressed_content})

        # Keep recent turns in full
        compressed_history.extend(recent_turns)

        # Calculate compressed tokens
        compressed_text = " ".join(turn.get("content", "") for turn in compressed_history)
        compressed_tokens = self.estimate_tokens(compressed_text)

        compression_ratio = original_tokens / max(compressed_tokens, 1)

        return CompressionResult(
            original_turns=original_turns,
            compressed_turns=len(compressed_history),
            original_tokens=original_tokens,
            estimated_compressed_tokens=compressed_tokens,
            compression_ratio=compression_ratio,
            summary=(
                f"Compressed {original_turns} turns ({original_tokens} tokens) → "
                f"{len(compressed_history)} turns ({compressed_tokens} tokens). "
                f"Ratio: {compression_ratio:.1f}x"
            ),
        )

    def compress_and_return_history(
        self,
        conversation_history: List[Dict[str, str]],
        target_tokens: int = None,
    ) -> List[Dict[str, str]]:
        """
        Compress and return the compressed history list.

        Args:
            conversation_history: Original conversation history.
            target_tokens: Target max tokens.

        Returns:
            Compressed conversation history list.
        """
        result = self.compress(conversation_history, target_tokens)

        if result.compression_ratio <= 1.0:
            return conversation_history

        # Rebuild compressed history
        recent_to_keep = self.recent_turns_full
        if self.aggressive:
            recent_to_keep = max(2, recent_to_keep // 2)

        older_turns = (
            conversation_history[:-recent_to_keep]
            if len(conversation_history) > recent_to_keep
            else []
        )
        recent_turns = conversation_history[-recent_to_keep:]

        compressed_history = []
        for turn in older_turns:
            role = turn.get("role", "unknown")
            content = turn.get("content", "")
            max_chars = (
                RECENT_TURN_CHARS if self.is_security_relevant(content) else SUMMARIZED_TURN_CHARS
            )
            compressed_history.append(
                {"role": role, "content": self.summarize_turn(content, max_chars)}
            )

        compressed_history.extend(recent_turns)
        return compressed_history


# Module-level singleton
_compressor_instance: Optional[ContextCompressor] = None


def get_compressor(aggressive: bool = False) -> ContextCompressor:
    """Get or create the global ContextCompressor singleton."""
    global _compressor_instance
    if _compressor_instance is None:
        _compressor_instance = ContextCompressor(aggressive=aggressive)
    return _compressor_instance


def compress_context(
    conversation_history: List[Dict[str, str]],
    max_tokens: int = 4000,
    aggressive: bool = False,
) -> Tuple[List[Dict[str, str]], str]:
    """
    Convenience function to compress context and return both history and summary.

    Args:
        conversation_history: Original conversation history.
        max_tokens: Target max tokens.
        aggressive: Use aggressive compression.

    Returns:
        Tuple of (compressed_history, summary_string).
    """
    compressor = ContextCompressor(max_tokens=max_tokens, aggressive=aggressive)
    compressed = compressor.compress_and_return_history(conversation_history)
    result = compressor.compress(conversation_history)
    return compressed, result.summary
