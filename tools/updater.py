"""
Elengenix Auto-Updater — Check and apply updates for the core framework.

Compares local version against the latest GitHub release and offers to
upgrade. Uses semver for version comparison. Falls back to git pull if
the local install is a git checkout. Never auto-updates (always asks first).

For plugins, use the Marketplace class in tools/marketplace.py.
"""

from __future__ import annotations

import json
import logging
import os
import re
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("elengenix.updater")

# Where to check for updates
GITHUB_REPO = "Elengenix/Elengenix"
GITHUB_API_LATEST = f"https://api.github.com/repos/{GITHUB_REPO}/releases/latest"
GITHUB_RELEASES_PAGE = f"https://github.com/{GITHUB_REPO}/releases"
CACHE_FILE = Path.home() / ".elengenix" / "update_check.json"
CACHE_TTL_S = 86400  # 24 hours

# Local version (read from package metadata or constants)
CURRENT_VERSION = "1.0.0"


@dataclass
class ReleaseInfo:
    """A GitHub release."""

    tag: str  # e.g. "v1.2.3"
    version: str  # e.g. "1.2.3" (tag without 'v')
    name: str = ""
    body: str = ""
    published_at: str = ""
    url: str = ""
    prerelease: bool = False

    @property
    def is_newer(self) -> bool:
        return compare_versions(self.version, CURRENT_VERSION) > 0


def parse_version(version: str) -> Tuple[int, int, int, str]:
    """Parse a semver string into (major, minor, patch, prerelease_tag).

    Examples:
        "1.2.3" -> (1, 2, 3, "")
        "v1.2.3" -> (1, 2, 3, "")
        "1.2.3-rc.1" -> (1, 2, 3, "rc.1")
        "1.2.3-beta" -> (1, 2, 3, "beta")
    """
    v: str = version.strip()
    if v.startswith("v"):
        v = v[1:]
    # Split on '-' to separate prerelease
    if "-" in v:
        base, pre = v.split("-", 1)
    else:
        base, pre = v, ""
    # Parse major.minor.patch
    parts: List[str] = base.split(".")
    try:
        major: int = int(parts[0]) if len(parts) > 0 else 0
        minor: int = int(parts[1]) if len(parts) > 1 else 0
        patch: int = int(parts[2]) if len(parts) > 2 else 0
    except ValueError:
        return 0, 0, 0, pre
    return major, minor, patch, pre


def compare_versions(v1: str, v2: str) -> int:
    """Compare two semver strings.

    Returns:
        -1 if v1 < v2
         0 if v1 == v2
         1 if v1 > v2
    """
    a_major, a_minor, a_patch, a_pre = parse_version(v1)
    b_major, b_minor, b_patch, b_pre = parse_version(v2)
    # Compare major.minor.patch
    if a_major < b_major:
        return -1
    if a_major > b_major:
        return 1
    if a_minor < b_minor:
        return -1
    if a_minor > b_minor:
        return 1
    if a_patch < b_patch:
        return -1
    if a_patch > b_patch:
        return 1
    # If base is equal, prerelease < release (e.g. "1.0.0-rc.1" < "1.0.0")
    if a_pre == "" and b_pre != "":
        return 1
    if a_pre != "" and b_pre == "":
        return -1
    if a_pre < b_pre:
        return -1
    if a_pre > b_pre:
        return 1
    return 0


class Updater:
    """Check for and apply Elengenix core updates.

    Usage:
        u = Updater()
        release = u.check_for_updates()
        if release and release.is_newer:
            print(f"New version available: {release.version}")
            u.apply_update(release)
    """

    def __init__(self, repo: str = GITHUB_REPO, current_version: str = CURRENT_VERSION):
        self.repo = repo
        self.current_version = current_version
        self.api_url = f"https://api.github.com/repos/{repo}/releases/latest"

    # ── Version check ────────────────────────────────────────────────────

    def check_for_updates(self, use_cache: bool = True) -> Optional[ReleaseInfo]:
        """Check GitHub for the latest release.

        Args:
            use_cache: If True, use cached result if fresh (< CACHE_TTL_S)

        Returns: ReleaseInfo if newer, None if up-to-date or fetch failed.
        """
        if use_cache and self._is_cache_fresh():
            try:
                cached = json.loads(CACHE_FILE.read_text(encoding="utf-8"))
                tag = cached.get("tag", "")
                if tag:
                    version = tag.lstrip("v")
                    rel = ReleaseInfo(
                        tag=tag,
                        version=version,
                        name=cached.get("name", ""),
                        body=cached.get("body", ""),
                        published_at=cached.get("published_at", ""),
                        url=cached.get("url", ""),
                        prerelease=cached.get("prerelease", False),
                    )
                    if rel.is_newer:
                        return rel
                    return None
            except Exception as e:  # noqa: BLE001
                logger.warning("Bad update cache: %s", e)

        # Fetch from GitHub
        try:
            import urllib.request

            req = urllib.request.Request(
                self.api_url,
                headers={
                    "User-Agent": "Elengenix-Updater/1.0",
                    "Accept": "application/vnd.github+json",
                },
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            tag = data.get("tag_name", "")
            if not tag:
                logger.warning("No tag_name in release response")
                return None
            version = tag.lstrip("v")
            rel = ReleaseInfo(
                tag=tag,
                version=version,
                name=data.get("name", ""),
                body=data.get("body", ""),
                published_at=data.get("published_at", ""),
                url=data.get("html_url", ""),
                prerelease=data.get("prerelease", False),
            )
            # Cache
            CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
            CACHE_FILE.write_text(
                json.dumps(
                    {
                        "tag": rel.tag,
                        "name": rel.name,
                        "body": rel.body,
                        "published_at": rel.published_at,
                        "url": rel.url,
                        "prerelease": rel.prerelease,
                        "checked_at": time.time(),
                    }
                ),
                encoding="utf-8",
            )
            if rel.is_newer:
                return rel
            return None
        except Exception as e:  # noqa: BLE001
            logger.warning("Failed to check for updates: %s", e)
            return None

    def _is_cache_fresh(self) -> bool:
        if not CACHE_FILE.exists():
            return False
        try:
            data = json.loads(CACHE_FILE.read_text(encoding="utf-8"))
            checked_at = float(data.get("checked_at", 0))
            return (time.time() - checked_at) < CACHE_TTL_S
        except Exception:  # noqa: BLE001
            return False

    def is_git_install(self) -> bool:
        """Check if Elengenix is installed as a git checkout (so we can git pull)."""
        # Heuristic: parent dir contains .git
        # The Elengenix package itself is at /mnt/data/Elengenix
        return Path(__file__).parent.parent.joinpath(".git").exists()

    # ── Apply update ─────────────────────────────────────────────────────

    def apply_update(self, release: ReleaseInfo) -> Tuple[bool, str]:
        """Apply an update (git pull if git install, else pip install --upgrade).

        Args:
            release: ReleaseInfo to apply

        Returns: (success, message)
        """
        if self.is_git_install():
            return self._git_pull(release)
        return self._pip_upgrade(release)

    def _git_pull(self, release: ReleaseInfo) -> Tuple[bool, str]:
        """git pull in the repo root."""
        repo_root = Path(__file__).parent.parent
        try:
            result = subprocess.run(
                ["git", "pull", "origin", "main"],
                cwd=str(repo_root),
                capture_output=True,
                text=True,
                timeout=120,
            )
            if result.returncode != 0:
                return False, f"git pull failed: {result.stderr.strip()}"
            return True, f"Updated via git pull: {result.stdout.strip()[:200]}"
        except FileNotFoundError:
            return False, "git not installed"
        except subprocess.TimeoutExpired:
            return False, "git pull timed out"

    def _pip_upgrade(self, release: ReleaseInfo) -> Tuple[bool, str]:
        """pip install --upgrade the package."""
        # Use sys.executable -m pip to ensure correct interpreter
        import sys

        try:
            result = subprocess.run(
                [sys.executable, "-m", "pip", "install", "--upgrade", "elengenix"],
                capture_output=True,
                text=True,
                timeout=180,
            )
            if result.returncode != 0:
                return False, f"pip upgrade failed: {result.stderr.strip()[:500]}"
            return True, f"Updated via pip: {result.stdout.strip()[:200]}"
        except subprocess.TimeoutExpired:
            return False, "pip upgrade timed out"

    # ── Changelog / release notes ───────────────────────────────────────

    def get_changelog(self, max_chars: int = 2000) -> str:
        """Get changelog text (release notes) for the latest release."""
        release = self.check_for_updates()
        if not release:
            return ""
        body = release.body or "(no release notes)"
        if len(body) > max_chars:
            body = body[:max_chars] + "..."
        return f"## {release.tag} ({release.published_at[:10]})\n\n{body}\n\nFull release: {release.url}"

    # ── Stats ───────────────────────────────────────────────────────────

    def stats(self) -> Dict[str, Any]:
        return {
            "current_version": self.current_version,
            "repo": self.repo,
            "is_git_install": self.is_git_install(),
            "cache_fresh": self._is_cache_fresh(),
        }
