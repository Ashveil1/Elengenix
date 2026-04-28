"""tools/api_schema_diff.py

API Contract / Schema Diff for web/API bug bounty.

Goal:
- Load OpenAPI (swagger/openapi.json) from URL or file
- Extract endpoint+method surface
- Compare two schemas (diff): added/removed/changed endpoints

Safety:
- Read-only (GET) for URL fetching
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin

import requests

logger = logging.getLogger("elengenix.api_schema_diff")


@dataclass
class SchemaSurface:
    title: str
    version: str
    endpoints: List[Tuple[str, str]]  # (method, path)


@dataclass
class SchemaDiff:
    added: List[Tuple[str, str]]
    removed: List[Tuple[str, str]]
    common: int


class OpenAPISchemaDiff:
    def __init__(self, timeout: int = 20):
        self.timeout = timeout

    def load_from_path(self, p: Path) -> Dict[str, Any]:
        return json.loads(p.read_text(encoding="utf-8"))

    def load_from_url(self, url: str, headers: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        r = requests.get(url, headers=headers or {}, timeout=self.timeout, allow_redirects=True)
        r.raise_for_status()
        return r.json()

    def surface(self, schema: Dict[str, Any]) -> SchemaSurface:
        info = schema.get("info", {}) if isinstance(schema, dict) else {}
        title = info.get("title", "OpenAPI")
        version = info.get("version", "")
        paths = schema.get("paths", {}) if isinstance(schema, dict) else {}
        eps: List[Tuple[str, str]] = []
        for path, methods in paths.items():
            if not isinstance(methods, dict):
                continue
            for method in methods.keys():
                m = method.upper()
                if m in ("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"):
                    eps.append((m, path))
        eps.sort()
        return SchemaSurface(title=title, version=version, endpoints=eps)

    def diff(self, a: SchemaSurface, b: SchemaSurface) -> SchemaDiff:
        sa = set(a.endpoints)
        sb = set(b.endpoints)
        added = sorted(list(sb - sa))
        removed = sorted(list(sa - sb))
        common = len(sa & sb)
        return SchemaDiff(added=added, removed=removed, common=common)


def format_schema_diff(d: SchemaDiff, max_items: int = 50) -> str:
    lines: List[str] = []
    lines.append(f"Common endpoints: {d.common}")
    lines.append(f"Added: {len(d.added)} | Removed: {len(d.removed)}")
    if d.added:
        lines.append("\n[Added]")
        for m, p in d.added[:max_items]:
            lines.append(f"- {m} {p}")
    if d.removed:
        lines.append("\n[Removed]")
        for m, p in d.removed[:max_items]:
            lines.append(f"- {m} {p}")
    return "\n".join(lines)
