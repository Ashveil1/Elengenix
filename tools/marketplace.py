"""
Elengenix Plugin Marketplace — Search, install, and manage community plugins.

Uses GitHub as the registry backend (free, no server needed):
- Plugins live in `github.com/Elengenix/plugins-<name>` (community repos)
- Marketplace index is `github.com/Elengenix/marketplace-index` (a JSON list)
- Install = git clone into ~/.elengenix/plugins/<name>
- Update = git pull
- Uninstall = remove the directory

This means:
- No central server required
- Community can self-publish (just push to GitHub with plugin.yaml)
- Free for everyone
- Works offline (cached index)

All operations are local + git; no API keys needed.
"""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("elengenix.marketplace")

# Default marketplace index (a JSON file in a known GitHub repo)
DEFAULT_INDEX_URL = (
    "https://raw.githubusercontent.com/Elengenix/marketplace-index/main/plugins.json"
)
LOCAL_INDEX_CACHE = Path.home() / ".elengenix" / "marketplace_index.json"
INDEX_TTL_S = 3600  # 1 hour

# Default plugin install dir (matches DEFAULT_PLUGIN_PATHS in ecosystem.py)
DEFAULT_INSTALL_DIR = Path.home() / ".elengenix" / "plugins"


@dataclass
class PluginEntry:
    """A plugin in the marketplace index."""

    name: str
    version: str
    author: str = ""
    description: str = ""
    repo_url: str = ""  # git clone URL
    homepage: str = ""
    tags: List[str] = field(default_factory=list)
    downloads: int = 0
    stars: int = 0
    verified: bool = False  # Official Elengenix team
    min_elengenix_version: str = ""
    sdk_version: str = "1.0.0"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "author": self.author,
            "description": self.description,
            "repo_url": self.repo_url,
            "tags": self.tags,
            "downloads": self.downloads,
            "stars": self.stars,
            "verified": self.verified,
            "sdk_version": self.sdk_version,
        }


class Marketplace:
    """Plugin marketplace client.

    Usage:
        m = Marketplace()
        results = m.search("shodan")
        m.install("shodan_recon")
        m.list_installed()
        m.uninstall("shodan_recon")
    """

    def __init__(
        self,
        index_url: str = DEFAULT_INDEX_URL,
        install_dir: Optional[Path] = None,
    ):
        self.index_url = index_url
        self.install_dir = install_dir or DEFAULT_INSTALL_DIR
        self.install_dir.mkdir(parents=True, exist_ok=True)
        self._index: List[PluginEntry] = []
        self._index_loaded_at: float = 0.0

    # ── Index management ─────────────────────────────────────────────────

    def refresh_index(self, force: bool = False) -> List[PluginEntry]:
        """Load marketplace index (from cache if fresh, else fetch).

        Args:
            force: If True, always re-fetch even if cache is fresh.

        Returns: list of available plugins.
        """
        if not force and self._is_cache_fresh() and self._index:
            return self._index
        # Try to load from cache first (offline-friendly)
        if LOCAL_INDEX_CACHE.exists() and not force:
            try:
                self._index = self._parse_index(LOCAL_INDEX_CACHE.read_text(encoding="utf-8"))
                self._index_loaded_at = time.time()
                logger.info("Loaded %d plugins from cache %s", len(self._index), LOCAL_INDEX_CACHE)
                return self._index
            except Exception as e:  # noqa: BLE001
                logger.warning("Bad cache, will re-fetch: %s", e)
        # Fetch from URL
        try:
            import urllib.request

            req = urllib.request.Request(
                self.index_url, headers={"User-Agent": "Elengenix-Marketplace/1.0"}
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                text = resp.read().decode("utf-8")
            self._index = self._parse_index(text)
            self._index_loaded_at = time.time()
            # Save to cache
            LOCAL_INDEX_CACHE.parent.mkdir(parents=True, exist_ok=True)
            LOCAL_INDEX_CACHE.write_text(text, encoding="utf-8")
            logger.info("Fetched %d plugins from %s", len(self._index), self.index_url)
        except Exception as e:  # noqa: BLE001
            logger.warning("Failed to fetch marketplace index (%s), using cache if available", e)
            if self._index:
                return self._index
        return self._index

    def _is_cache_fresh(self) -> bool:
        if not LOCAL_INDEX_CACHE.exists():
            return False
        age = time.time() - LOCAL_INDEX_CACHE.stat().st_mtime
        return age < INDEX_TTL_S

    def _parse_index(self, text: str) -> List[PluginEntry]:
        """Parse the marketplace index JSON."""
        data = json.loads(text)
        if isinstance(data, dict) and "plugins" in data:
            data = data["plugins"]
        if not isinstance(data, list):
            logger.warning("Unexpected index format: not a list")
            return []
        entries: List[PluginEntry] = []
        for item in data:
            try:
                entries.append(
                    PluginEntry(
                        name=item.get("name", ""),
                        version=str(item.get("version", "0.1.0")),
                        author=item.get("author", ""),
                        description=item.get("description", ""),
                        repo_url=item.get("repo_url", ""),
                        homepage=item.get("homepage", ""),
                        tags=item.get("tags", []),
                        downloads=int(item.get("downloads", 0)),
                        stars=int(item.get("stars", 0)),
                        verified=bool(item.get("verified", False)),
                        min_elengenix_version=item.get("min_elengenix_version", ""),
                        sdk_version=str(item.get("sdk_version", "1.0.0")),
                    )
                )
            except Exception as e:  # noqa: BLE001
                logger.warning("Skipping bad index entry: %s", e)
        return entries

    # ── Search ───────────────────────────────────────────────────────────

    def search(
        self,
        query: str = "",
        tag: Optional[str] = None,
        verified_only: bool = False,
    ) -> List[PluginEntry]:
        """Search the marketplace.

        Args:
            query: Free-text query (matches name + description + tags)
            tag: Filter to plugins with this tag
            verified_only: Only show Elengenix-team-verified plugins

        Returns: list of matching PluginEntry, sorted by downloads (desc).
        """
        self.refresh_index()
        q = query.lower().strip()
        results: List[PluginEntry] = []
        for entry in self._index:
            if verified_only and not entry.verified:
                continue
            if tag and tag.lower() not in [t.lower() for t in entry.tags]:
                continue
            if q:
                haystack = " ".join([entry.name, entry.description] + entry.tags).lower()
                if q not in haystack:
                    continue
            results.append(entry)
        results.sort(key=lambda e: (-e.verified, -e.downloads, -e.stars, e.name))
        return results

    def get(self, name: str) -> Optional[PluginEntry]:
        """Get a specific plugin by name from the marketplace index."""
        self.refresh_index()
        for entry in self._index:
            if entry.name == name:
                return entry
        return None

    # ── Install / Uninstall ──────────────────────────────────────────────

    def install(
        self,
        name: str,
        upgrade: bool = False,
        target_dir: Optional[Path] = None,
    ) -> Tuple[bool, str]:
        """Install a plugin from the marketplace.

        Args:
            name: Plugin name (must be in the index)
            upgrade: If True, re-install even if already present
            target_dir: Override install dir (for testing)

        Returns: (success, message)
        """
        entry = self.get(name)
        if entry is None:
            return False, f"Plugin {name!r} not found in marketplace"
        if not entry.repo_url:
            return False, f"Plugin {name!r} has no repo_url"
        dest = (target_dir or self.install_dir) / name
        if dest.exists():
            if not upgrade:
                return (
                    False,
                    f"Plugin {name!r} already installed at {dest} (use upgrade=True to force)",
                )
            # Re-install: remove first
            shutil.rmtree(dest, ignore_errors=True)
        # Git clone
        try:
            result = subprocess.run(
                ["git", "clone", "--depth=1", entry.repo_url, str(dest)],
                capture_output=True,
                text=True,
                timeout=120,
            )
            if result.returncode != 0:
                return False, f"git clone failed: {result.stderr.strip()}"
        except FileNotFoundError:
            return False, "git is not installed. Install git to use the marketplace."
        except subprocess.TimeoutExpired:
            return False, f"git clone timed out for {entry.repo_url}"
        return True, f"Installed {name} v{entry.version} to {dest}"

    def uninstall(self, name: str) -> Tuple[bool, str]:
        """Uninstall a plugin by removing its directory."""
        dest = self.install_dir / name
        if not dest.exists():
            return False, f"Plugin {name!r} is not installed"
        try:
            shutil.rmtree(dest)
        except Exception as e:  # noqa: BLE001
            return False, f"Failed to remove {dest}: {e}"
        return True, f"Uninstalled {name}"

    def upgrade(self, name: str) -> Tuple[bool, str]:
        """Upgrade a plugin (git pull in its directory)."""
        return self.install(name, upgrade=True)

    # ── Listing ──────────────────────────────────────────────────────────

    def list_installed(self) -> List[Dict[str, str]]:
        """List installed plugins (reads plugin.yaml from each subdir)."""
        results: List[Dict[str, str]] = []
        if not self.install_dir.exists():
            return results
        for entry in sorted(self.install_dir.iterdir()):
            if not entry.is_dir() or entry.name.startswith(("_", ".")):
                continue
            manifest_path = entry / "plugin.yaml"
            if not manifest_path.exists():
                manifest_path = entry / "plugin.json"
            if not manifest_path.exists():
                continue
            try:
                if manifest_path.suffix == ".yaml":
                    import yaml

                    with open(manifest_path, "r", encoding="utf-8") as f:
                        m = yaml.safe_load(f) or {}
                else:
                    with open(manifest_path, "r", encoding="utf-8") as f:
                        m = json.load(f)
                results.append(
                    {
                        "name": m.get("name", entry.name),
                        "version": str(m.get("version", "?")),
                        "author": m.get("author", ""),
                        "description": m.get("description", ""),
                        "path": str(entry),
                    }
                )
            except Exception as e:  # noqa: BLE001
                logger.warning("Bad manifest in %s: %s", manifest_path, e)
        return results

    def list_available(self) -> List[PluginEntry]:
        """List all available plugins in the marketplace (sorted)."""
        self.refresh_index()
        return sorted(self._index, key=lambda e: (-e.verified, -e.downloads, e.name))

    # ── Stats ───────────────────────────────────────────────────────────

    def stats(self) -> Dict[str, Any]:
        return {
            "index_url": self.index_url,
            "index_size": len(self._index),
            "index_loaded_at": self._index_loaded_at,
            "install_dir": str(self.install_dir),
            "installed_count": len(self.list_installed()),
        }
