"""tools/payload_db.py — Lazy loader for the curated payload database.

Reads ``data/payloads/<class>.json`` files (schema::

    {
      "metadata": {"source": ..., "curation_date": ..., "description": ...},
      "payloads": [{"value", "context", "target", "detect": {...}?}, ...]
    }

Design:
  - Stdlib ``json`` only; files are parsed once and cached in-process.
  - Never raises for a missing/corrupt file — callers fall back to their
    inline payload lists, keeping the repo runnable without ``data/``.

Public API:
    get_payloads(kind)         -> list[dict]  (raw DB entries, or [])
    get_payload_values(kind, context=None, target=None) -> list[str]
    get_metadata(kind)         -> dict
    available()                -> list[str]   (classes with a DB file)
"""

from __future__ import annotations

import json
import logging
import os
import threading
from typing import Dict, List, Optional

logger = logging.getLogger("elengenix.payload_db")

_PAYLOAD_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "payloads")

_cache: Dict[str, dict] = {}
_lock = threading.Lock()


def _load(kind: str) -> dict:
    """Load and cache one payload file; {} if missing/invalid. Never raises."""
    with _lock:
        if kind in _cache:
            return _cache[kind]
        doc: dict = {}
        path = os.path.join(_PAYLOAD_DIR, f"{kind}.json")
        try:
            with open(path, encoding="utf-8") as fh:
                data = json.load(fh)
            if isinstance(data, dict) and isinstance(data.get("payloads"), list):
                doc = data
            else:
                logger.warning("payload DB %s has unexpected schema; ignoring", path)
        except FileNotFoundError:
            logger.debug("payload DB %s not found; caller falls back to inline lists", path)
        except Exception as e:  # corrupt JSON etc.
            logger.warning("payload DB %s unreadable (%s); ignoring", path, e)
        _cache[kind] = doc
        return doc


def get_payloads(kind: str) -> List[dict]:
    """Return raw payload entries for *kind* ([] => caller uses inline fallback)."""
    return list(_load(kind).get("payloads") or [])


def get_payload_values(
    kind: str,
    context: Optional[str] = None,
    target: Optional[str] = None,
) -> List[str]:
    """Return payload values, optionally filtered by context and/or target.

    ``target='generic'`` requests generic + matches; filtering never excludes
    an entry whose own ``target`` is ``generic``.
    """
    out: List[str] = []
    for entry in get_payloads(kind):
        value = entry.get("value")
        if not isinstance(value, str):
            continue
        if context and entry.get("context") != context:
            continue
        if target and target != "generic" and entry.get("target") not in (target, "generic"):
            continue
        out.append(value)
    return out


def get_metadata(kind: str) -> dict:
    return dict(_load(kind).get("metadata") or {})


def available() -> List[str]:
    """List payload classes that ship a parseable DB file."""
    out = []
    try:
        for name in sorted(os.listdir(_PAYLOAD_DIR)):
            if name.endswith(".json") and get_payloads(name[:-5]):
                out.append(name[:-5])
    except OSError:
        pass
    return out


def reset_cache() -> None:
    """Drop the in-process cache (tests / hot reload)."""
    with _lock:
        _cache.clear()
