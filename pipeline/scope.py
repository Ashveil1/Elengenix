"""
pipeline/scope.py — Scope Management

Handles target validation, scope enforcement, and normalization.
Loads allowed domains from scope.txt or ELENGENIX_SCOPE env var.

Key improvements over orchestrator.py:
- Lazy loading (scope loaded on first access, not at import time)
- IPv6 support in validation and normalization
- reload() method for dynamic scope updates
- ScopeManager class for testability and flexibility

Extracted from orchestrator.py lines 49-111.
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
        """Force reload scope from file/env."""
        self._domains = self._load_scope()
        logger.debug(f"Scope reloaded: {len(self._domains)} domains")

    def _load_scope(self) -> Set[str]:
        """Load authorized domains/IPs from environment or file.

        Returns:
            Set of normalized domain strings.
        """
        domains: Set[str] = set()

        # Load from env var
        env_scope = os.getenv("ELENGENIX_SCOPE")
        if env_scope:
            domains.update(
                d.strip().lower() for d in env_scope.split(",") if d.strip()
            )

        # Load from file
        scope_path = Path(self.scope_file)
        if scope_path.exists():
            try:
                with open(scope_path, "r", encoding="utf-8") as f:
                    for line in f:
                        clean_line = line.strip().lower()
                        if clean_line and not clean_line.startswith("#"):
                            domains.add(clean_line)
            except Exception as e:
                logger.warning(f"Failed to read scope file {scope_path}: {e}")

        return domains

    def normalize_target(self, target: str) -> str:
        """Normalize a target URL or domain.

        Handles:
        - URLs with scheme (http://, https://)
        - IPv4 addresses with ports
        - IPv6 addresses with brackets and ports
        - Bare domains

        Args:
            target: The target to normalize.

        Returns:
            Normalized target string (lowercase, no scheme, no port).
        """
        if not target:
            return ""

        target = target.strip().lower()

        # Handle URLs with scheme
        if target.startswith(("http://", "https://")):
            parsed = urlparse(target)
            target = parsed.netloc or parsed.path.split("/")[0]

        # Handle IPv6 with brackets: [::1]:8080 → ::1
        if target.startswith("["):
            # Strip brackets and port
            bracket_end = target.find("]")
            if bracket_end > 0:
                target = target[1:bracket_end]

        # Handle IPv4 with port: 1.2.3.4:80 → 1.2.3.4
        # But NOT IPv6 addresses (which contain multiple colons)
        elif ":" in target and target.count(":") == 1:
            target = target.split(":")[0]

        return target.rstrip(".")

    def is_valid_target(self, target: str) -> bool:
        """Validate target format.

        Accepts:
        - IPv4 addresses (not private, not loopback)
        - IPv6 addresses (not private, not loopback)
        - Domain names (RFC-compliant labels)

        Args:
            target: The target to validate.

        Returns:
            True if target is valid and not private/loopback.
        """
        if not target:
            return False

        # Try IP address (handles both IPv4 and IPv6)
        try:
            ip = ipaddress.ip_address(target)
            return not (ip.is_private or ip.is_loopback)
        except ValueError:
            pass

        # Domain validation
        if len(target) > 253 or "." not in target:
            return False

        return all(
            re.match(r"^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?$", part)
            for part in target.split(".")
        )

    def is_in_scope(self, target: str) -> bool:
        """Check if a target is in the allowed scope.

        Args:
            target: The target to check.

        Returns:
            True if target is valid and in scope (or scope is empty).
        """
        if not target:
            return False

        normalized = self.normalize_target(target)

        # Handle IPv6 with brackets for validation
        validation_target = normalized
        if ":" in normalized and not normalized.startswith("["):
            # IPv6 — validate as IP
            try:
                ip = ipaddress.ip_address(normalized)
                if ip.is_private or ip.is_loopback:
                    return False
            except ValueError:
                pass

        if not self.is_valid_target(validation_target):
            return False

        # If scope is empty, allow everything
        if not self.allowed_domains:
            return True

        # Check exact match or subdomain
        return normalized in self.allowed_domains or any(
            normalized.endswith(f".{a}") for a in self.allowed_domains
        )


def sanitize_path(target: str) -> str:
    """Create a safe directory name from a target.

    Args:
        target: The target to sanitize.

    Returns:
        Sanitized string safe for use as a directory name.
    """
    return re.sub(r"[^a-zA-Z0-9.-]", "_", target)[:100]


# ── Module-level convenience functions (backward compatible) ─────

_default_scope = ScopeManager()


def normalize_target(target: str) -> str:
    """Normalize a target. Module-level convenience wrapper."""
    return _default_scope.normalize_target(target)


def is_valid_target(target: str) -> bool:
    """Validate a target. Module-level convenience wrapper."""
    return _default_scope.is_valid_target(target)


def is_in_scope(target: str) -> bool:
    """Check if target is in scope. Module-level convenience wrapper."""
    return _default_scope.is_in_scope(target)


def load_allowed_domains(scope_file: str = "scope.txt") -> Set[str]:
    """Load allowed domains. Module-level convenience wrapper."""
    sm = ScopeManager(scope_file)
    return sm.allowed_domains
