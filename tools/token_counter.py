"""tools/token_counter.py — Accurate token counting with optional tiktoken.

Usage:
    from tools.token_counter import count_tokens
    tokens = count_tokens("some text")
"""

from __future__ import annotations

import logging

logger = logging.getLogger("elengenix.token_counter")

try:
    import tiktoken

    _enc = tiktoken.get_encoding("cl100k_base")
    TIKTOKEN_AVAILABLE = True
except ImportError:
    TIKTOKEN_AVAILABLE = False

# Characters-per-token ratio used when tiktoken is unavailable.
# English prose: ~4, Thai: ~2, Chinese/Japanese: ~1.5,
# Security scan output (mixed URLs + text): ~3.5.
_CHARS_PER_TOKEN = 3.5


def count_tokens(text: str) -> int:
    """Return an accurate token count for *text*.

    Uses ``tiktoken`` (cl100k_base) when available; falls back to a
    character-based heuristic otherwise.
    """
    if not text:
        return 0
    if TIKTOKEN_AVAILABLE:
        try:
            return len(_enc.encode(text))
        except Exception as e:
            logger.debug(f"tiktoken encoding failed, falling back: {e}")
    return max(1, int(len(text) / _CHARS_PER_TOKEN))
