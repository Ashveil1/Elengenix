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
        0: "วันจันทร์", 1: "วันอังคาร", 2: "วันพุธ", 3: "วันพฤหัสบดี",
        4: "วันศุกร์", 5: "วันเสาร์", 6: "วันอาทิตย์",
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
        "มกราคม", "กุมภาพันธ์", "มีนาคม", "เมษายน",
        "พฤษภาคม", "มิถุนายน", "กรกฎาคม", "สิงหาคม",
        "กันยายน", "ตุลาคม", "พฤศจิกายน", "ธันวาคม",
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


def _extract_json_object(text: str) -> Optional[Dict[str, Any]]:
    if text is None:
        return None
    if not isinstance(text, str):
        text = str(text)
    cleaned = text.strip()
    if not cleaned:
        return None

    if "```" in cleaned:
        if "```json" in cleaned:
            cleaned = cleaned.split("```json", 1)[1]
        else:
            cleaned = cleaned.split("```", 1)[1]
        cleaned = cleaned.split("```", 1)[0].strip()

    try:
        return json.loads(cleaned)
    except Exception:
        logger.debug(f"JSON parse failed, trying regex fallback: {cleaned[:80]}")

    m = re.search(r"\{.*\}", cleaned, re.DOTALL)
    if not m:
        return None
    try:
        return json.loads(m.group())
    except Exception:
        return None


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
