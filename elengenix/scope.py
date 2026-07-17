"""elengenix/scope.py — Scope Management

Handles target validation, scope enforcement, and normalization.
Loads allowed domains from scope.txt or ELENGENIX_SCOPE env var.

Migrated from pipeline/scope.py (legacy pipeline removed).
"""

from __future__ import annotations

import ipaddress
import logging
import os
import re
from pathlib import Path
from typing import Optional, Set
from urllib.parse import urlparse

logger = logging.getLogger("elengenix.scope")


class ScopeManager:
    """Manages target scope enforcement.

    Loads allowed domains from scope.txt or ELENGENIX_SCOPE env var.
    Supports lazy loading and dynamic reload.

    Args:
        scope_file: Path to scope file (default: "scope.txt").
    """

    def __init__(self, scope_file: str = "scope.txt"):
        self.scope_file = scope_file
        self._domains: Optional[Set[str]] = None

    @property
    def allowed_domains(self) -> Set[str]:
        """Lazy load scope on first access."""
        if self._domains is None:
            self._domains = self._load_scope()
        return self._domains

    def reload(self) -> None:
        """Force reload of scope file on next access."""
        self._domains = None

    def _load_scope(self) -> Set[str]:
        """Load allowed domains from scope file or env var."""
        domains: Set[str] = set()

        # Try environment variable first
        env_scope = os.environ.get("ELENGENIX_SCOPE", "")
        if env_scope:
            for d in env_scope.split(","):
                d = d.strip().lower()
                if d and d.startswith("."):
                    domains.add(d.lstrip("."))
                elif d:
                    domains.add(d)

        # Try scope file
        scope_file_candidates = [
            Path(self.scope_file),
            Path.cwd() / self.scope_file,
            Path.home() / ".elengenix" / self.scope_file,
        ]
        for sf in scope_file_candidates:
            if sf.exists():
                try:
                    text = sf.read_text()
                    for line in text.splitlines():
                        line = line.strip()
                        if line and not line.startswith("#"):
                            domain = line.lower().lstrip(".")
                            domains.add(domain)
                except Exception as e:
                    logger.warning("Failed to read scope file %s: %s", sf, e)

        if not domains:
            logger.debug("No scope configured — all targets allowed")
        else:
            logger.debug("Loaded %d domains into scope", len(domains))

        return domains

    def is_in_scope(self, target: str) -> bool:
        """Check if a target is within the configured scope.

        Args:
            target: Target URL or domain.

        Returns:
            True if target is in scope, or if scope is empty (no restrictions).
        """
        if not self._domains:
            self.allowed_domains  # Trigger lazy load
        if not self._domains:
            return True  # No scope configured = all targets allowed

        # Extract domain from target
        domain = self._extract_domain(target)
        if not domain:
            return False

        # Direct match
        if domain in self._domains:
            return True

        # Subdomain match
        for allowed in self._domains:
            if domain.endswith("." + allowed):
                return True

        return False

    def normalize_target(self, target: str) -> str:
        """Normalize a target string: strip protocol, port, path.

        Args:
            target: Raw target string (URL or domain).

        Returns:
            Normalized domain string.

        Example:
            >>> sm = ScopeManager()
            >>> sm.normalize_target("https://example.com:8080/path")
            'example.com'
        """
        # Strip protocol
        domain = re.sub(r"^https?://", "", target.strip().lower())
        # Strip path/query/fragment
        domain = domain.split("/")[0].split("?")[0].split("#")[0]
        # Strip port (handle IPv6 vs IPv4)
        if domain.count(":") > 1:
            # Likely IPv6 — don't strip
            return domain
        # Strip port for IPv4 or hostname
        domain = domain.split(":")[0]
        return domain.rstrip("/")

    def _extract_domain(self, target: str) -> str:
        """Extract the domain from a target string.

        Args:
            target: URL or domain string.

        Returns:
            Clean domain.
        """
        return self.normalize_target(target)

    def sanitize_path(self, path: str) -> str:
        """Sanitize a path to prevent path traversal.

        Args:
            path: Raw path string.

        Returns:
            Sanitized path string.
        """
        # Normalize path separators
        sanitized = os.path.normpath(path)
        # Remove all parent directory traversal components
        while sanitized.startswith("..") or sanitized.startswith("/"):
            if sanitized.startswith("/"):
                sanitized = sanitized.lstrip("/")
            if sanitized.startswith(".."):
                sanitized = sanitized.replace("..", "", 1).lstrip("/")
        # Prevent absolute paths
        if sanitized.startswith("/"):
            sanitized = sanitized.lstrip("/")
        return sanitized


# ── Module-level convenience functions ──────────────────────────────


def is_in_scope(target: str) -> bool:
    """Convenience: check if target is in scope."""
    return ScopeManager().is_in_scope(target)


def is_valid_target(target: str) -> bool:
    """Convenience: check if target is valid.

    Accepts domain names, IPv4/IPv6 addresses, and URLs.
    """
    if not target or not isinstance(target, str):
        return False
    target = target.strip().lower()
    if not target:
        return False
    if target.startswith(("http://", "https://")):
        return True
    # Simple domain validation
    return bool(re.match(r"^[a-z0-9.-]+(\.[a-z]{2,})+$", target)) or bool(
        _is_ip(target)
    )


def _is_ip(value: str) -> bool:
    """Check if a string is a valid IP address (v4 or v6)."""
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def load_allowed_domains() -> Set[str]:
    """Convenience: load allowed domains from scope."""
    return ScopeManager().allowed_domains


def normalize_target(target: str) -> str:
    """Convenience: normalize target to domain."""
    return ScopeManager().normalize_target(target)


def sanitize_path(path: str) -> str:
    """Convenience: sanitize path."""
    return ScopeManager().sanitize_path(path)
