"""agents/agent_helpers.py — Standalone helper functions extracted from agent_brain.py."""

from __future__ import annotations

import json
import logging
import os
import re
from datetime import datetime
from typing import Any, Dict, Optional
from zoneinfo import ZoneInfo

from tools.memory_profile import read_memory

logger = logging.getLogger("elengenix.agent")


def _get_now_context() -> str:
    tz_name = os.environ.get("ELENGENIX_TZ")
    tz = None
    if tz_name:
        try:
            tz = ZoneInfo(tz_name)
        except Exception:
            tz = None
    now = datetime.now(tz=tz)

    thai_weekdays = {
        0: "วันจันทร์",
        1: "วันอังคาร",
        2: "วันพุธ",
        3: "วันพฤหัสบดี",
        4: "วันศุกร์",
        5: "วันเสาร์",
        6: "วันอาทิตย์",
    }
    wd_th = thai_weekdays.get(now.weekday(), "")
    tz_display = now.tzname() or tz_name or "local"

    be_year = now.year + 543
    thai_date_str = f"{now.day} {_thai_month_name(now.month)} {be_year}"

    return (
        "### CURRENT TIME CONTEXT (AUTHORITATIVE)\n"
        f"System time (CE): {now.isoformat()}\n"
        f"CE year: {now.year}  |  Thai Buddhist Era (BE) year: {be_year}\n"
        f"Thai date: {thai_date_str}\n"
        f"Timezone: {tz_display}\n"
        f"Thai weekday: {wd_th}\n"
        "RULE: When searching or answering in Thai, ALWAYS use the Buddhist Era year "
        f"({be_year}) not the CE year ({now.year}). "
        "If the user asks about the current date/day/time, use ONLY this context.\n"
    )


def _thai_month_name(month: int) -> str:
    """Return Thai month name for a given month number (1-12)."""
    names = [
        "มกราคม",
        "กุมภาพันธ์",
        "มีนาคม",
        "เมษายน",
        "พฤษภาคม",
        "มิถุนายน",
        "กรกฎาคม",
        "สิงหาคม",
        "กันยายน",
        "ตุลาคม",
        "พฤศจิกายน",
        "ธันวาคม",
    ]
    return names[month - 1] if 1 <= month <= 12 else str(month)


def _get_memory_profile_context() -> str:
    """Read and format the MEMORY.md profile for the AI."""
    profile = read_memory()
    if not profile:
        return ""

    lines = ["### USER PROFILE & LONG-TERM KNOWLEDGE (from MEMORY.md):"]
    for key, value in profile.items():
        formatted_key = key.replace("_", " ").title()
        lines.append(f"- {formatted_key}: {value}")
    return "\n".join(lines)


def _strip_code_fences(text: str) -> str:
    """Return the inside of the first ```json ...``` (or ``` ... ```) fence, else the text."""
    m = re.search(r"```(?:json|JSON)?\s*([\s\S]*?)\s*```", text)
    if m:
        return m.group(1).strip()
    return text.strip()


def _scan_balanced(text: str, open_ch: str, close_ch: str) -> Optional[str]:
    """Return the first top-level balanced ``open_ch..close_ch`` span, respecting strings.

    Walks the text tracking string context (single/double quotes with backslash
    escapes) so that braces inside string literals do not affect nesting depth.
    """
    start = text.find(open_ch)
    if start == -1:
        return None
    depth = 0
    in_str: Optional[str] = None
    escaped = False
    for i in range(start, len(text)):
        ch = text[i]
        if in_str is not None:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == in_str:
                in_str = None
            continue
        if ch in ("'", '"'):
            in_str = ch
        elif ch == open_ch:
            depth += 1
        elif ch == close_ch:
            depth -= 1
            if depth == 0:
                return text[start : i + 1]
    return None


def _repair_json(candidate: str) -> str:
    """Best-effort repair of common LLM JSON mistakes.

    Handles: smart/curly quotes, trailing commas before ``}``/``]``. Single-quote
    repair is intentionally conservative — only applied to the whole-document
    fallback in :func:`extract_json` — to avoid corrupting apostrophes inside
    legitimately double-quoted strings.
    """
    repaired = candidate
    # Normalize smart quotes to straight quotes.
    repaired = repaired.translate(
        {
            0x201C: '"',
            0x201D: '"',
            0x2018: "'",
            0x2019: "'",
        }
    )
    # Remove trailing commas:  {"a": 1,}  ->  {"a": 1}
    repaired = re.sub(r",(\s*[}\]])", r"\1", repaired)
    return repaired


def extract_json(
    text: Any,
    *,
    expect: str = "object",
    repair_client: Any = None,
) -> Optional[Any]:
    """Robustly extract a JSON value from an LLM response.

    This is the single, hardened JSON extractor for the whole codebase. It
    supersedes the older per-module extractors (which now delegate here).

    Strategy (each step falls through to the next on failure):
      1. Strip ``` markdown code fences.
      2. ``json.loads`` the stripped text directly.
      3. Scan for the first *balanced* ``{...}`` (and ``[...]`` when arrays are
         acceptable), string-aware so braces inside strings don't break nesting.
      4. Apply :func:`_repair_json` (smart quotes, trailing commas) and retry 2-3.
      5. Optionally ask ``repair_client`` to re-emit valid JSON (one shot, bounded).

    Args:
        text: Raw model output (any type; coerced to str).
        expect: ``"object"`` to prefer/`{}`, ``"array"`` to prefer ``[]``, or
            ``"any"`` to accept whichever balanced span parses first.
        repair_client: Optional object with ``.chat([...])`` used as a last-resort
            "return ONLY valid JSON" repair call. Left ``None`` by callers that
            must stay offline/cheap.

    Returns:
        The parsed JSON value, or ``None`` if nothing parseable was found.
    """
    if text is None:
        return None
    if not isinstance(text, str):
        text = str(text)
    if not text.strip():
        return None

    cleaned = _strip_code_fences(text)

    # Order of bracket types to try, based on what the caller expects.
    if expect == "array":
        bracket_order = [("[", "]"), ("{", "}")]
    else:  # "object" or "any"
        bracket_order = [("{", "}"), ("[", "]")]

    def _try_loads(s: str) -> Optional[Any]:
        for candidate in (s, _repair_json(s)):
            try:
                return json.loads(candidate)
            except (json.JSONDecodeError, ValueError):
                continue
        return None

    # 2. Whole stripped text.
    result = _try_loads(cleaned)
    if result is not None:
        return result

    # 3-4. First balanced span of each bracket type.
    for open_ch, close_ch in bracket_order:
        span = _scan_balanced(cleaned, open_ch, close_ch)
        if span:
            result = _try_loads(span)
            if result is not None:
                return result

    # 4b. Last-ditch greedy regex (old behavior) on the repaired text.
    repaired = _repair_json(cleaned)
    for pattern in (r"\{[\s\S]*\}", r"\[[\s\S]*\]"):
        m = re.search(pattern, repaired)
        if m:
            try:
                return json.loads(m.group())
            except (json.JSONDecodeError, ValueError):
                continue

    # 5. Optional LLM repair pass (bounded to one shot).
    if repair_client is not None and hasattr(repair_client, "chat"):
        try:
            from tools.universal_ai_client import AIMessage

            repair_msg = (
                "The following text was supposed to be a single valid JSON "
                f"{'array' if expect == 'array' else 'object'} but could not be "
                "parsed. Return ONLY the corrected JSON, with no commentary, no "
                "markdown fences, and nothing before or after it:\n\n" + text[:4000]
            )
            fixed = (
                repair_client.chat(
                    [AIMessage(role="user", content=repair_msg)],
                    temperature=0.0,
                ).content
                or ""
            )
            if fixed.strip():
                # Recurse once without a repair_client to avoid loops.
                return extract_json(fixed, expect=expect, repair_client=None)
        except Exception as e:  # pragma: no cover - defensive
            logger.debug(f"JSON repair call failed: {e}")

    logger.debug(f"extract_json: no parseable JSON in: {text[:120]!r}")
    return None


def _extract_json_object(text: str) -> Optional[Dict[str, Any]]:
    """Backward-compatible object extractor — delegates to :func:`extract_json`."""
    result = extract_json(text, expect="object")
    return result if isinstance(result, dict) else None


def _extract_target_from_text(text: str) -> str:
    if not text:
        return ""
    tokens = re.findall(r"[a-zA-Z0-9._-]+", text.lower())
    stop = {"scan", "recon", "pentest", "test", "bug", "bounty", "hunt", "please", "for"}
    candidates = [t for t in tokens if t not in stop and len(t) > 1]
    if not candidates:
        return ""
    t = candidates[-1]
    if "." not in t and t.isalnum() and len(t) >= 3:
        t = f"{t}.com"
    return t


def _safe_operation(
    operation_name: str,
    func: Any,
    *args: Any,
    default: Any = None,
    log_level: str = "warning",
    **kwargs: Any,
) -> Any:
    """Execute a function with consistent error handling.

    Args:
        operation_name: Description of the operation for logging.
        func: Function to execute.
        *args: Positional arguments to pass to func.
        default: Value to return on failure.
        log_level: Logging level ('debug', 'info', 'warning', 'error').
        **kwargs: Keyword arguments to pass to func.

    Returns:
        Result of func() or default on failure.
    """
    try:
        return func(*args, **kwargs)
    except Exception as e:
        log_func = getattr(logger, log_level, logger.warning)
        log_func(f"{operation_name} failed: {e}")
        return default
