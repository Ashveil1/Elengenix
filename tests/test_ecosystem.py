"""
Tests for the Elengenix Ecosystem SDK (Pillar 6).

Covers:
- Plugin manifest parsing (YAML + JSON)
- Plugin discovery and loading
- Tool/command/AI/hook registration
- Version compatibility checks
- Marketplace search/parsing
- Updater version comparison
- Lifecycle (unload, reload)
- Error handling (bad manifest, import failure, etc.)

Note: Some tests hit the network and are marked as integration.
"""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.integration

import json
import sys
from pathlib import Path

import pytest

# Make tools importable
sys.path.insert(0, str(Path(__file__).parent.parent))

from tools.ecosystem import (
    SDK_VERSION,
    Capability,
    PluginAPI,
    PluginHost,
    PluginManifest,
    PluginState,
    ToolResult,
    get_host,
    reset_host,
)
from tools.marketplace import Marketplace, PluginEntry
from tools.updater import ReleaseInfo, Updater, compare_versions, parse_version

# ──────────────────────────────────────────────────────────────────────────
# Fixtures
# ──────────────────────────────────────────────────────────────────────────


@pytest.fixture
def temp_plugin_dir(tmp_path):
    """Create a temporary plugin directory with a working plugin."""
    plugin_dir = tmp_path / "test_plugin"
    plugin_dir.mkdir()
    # Manifest
    (plugin_dir / "plugin.yaml").write_text(
        """name: test_plugin
version: 1.0.0
author: Test Author
description: A test plugin
sdk_version: {SDK_VERSION}
capabilities:
  - network
  - subprocess
dependencies: []
enabled: true
tags:
  - test
  - demo
""",
        encoding="utf-8",
    )
    # Entry point
    (plugin_dir / "__init__.py").write_text(
        """from tools.ecosystem import ToolResult

def register(api):
    api.register_tool("greet", _greet, description="Say hello", tags=["demo"])
    api.register_command("hello", _hello_cmd, description="Print hello", usage="hello")
    api.register_finding_hook("tag", _tag_hook, priority=10)

def _greet(name="world"):
    return ToolResult(success=True, data={"message": f"Hello, {name}!"})

def _hello_cmd(args):
    print("Hello from plugin!")
    return 0

def _tag_hook(finding):
    finding["tagged_by_test_plugin"] = True
    return finding
""",
        encoding="utf-8",
    )
    return plugin_dir


@pytest.fixture
def temp_disabled_plugin(tmp_path):
    plugin_dir = tmp_path / "disabled_plugin"
    plugin_dir.mkdir()
    (plugin_dir / "plugin.yaml").write_text(
        """name: disabled_plugin
version: 1.0.0
enabled: false
sdk_version: {SDK_VERSION}
""",
        encoding="utf-8",
    )
    (plugin_dir / "__init__.py").write_text(
        "def register(api): api.register_tool('never', lambda: None)",
        encoding="utf-8",
    )
    return plugin_dir


@pytest.fixture
def temp_bad_plugin(tmp_path):
    """Plugin that raises during register()."""
    plugin_dir = tmp_path / "bad_plugin"
    plugin_dir.mkdir()
    (plugin_dir / "plugin.yaml").write_text(
        """name: bad_plugin
version: 1.0.0
sdk_version: {SDK_VERSION}
""",
        encoding="utf-8",
    )
    (plugin_dir / "__init__.py").write_text(
        "def register(api): raise RuntimeError('intentional failure')",
        encoding="utf-8",
    )
    return plugin_dir


@pytest.fixture
def temp_no_register(tmp_path):
    """Plugin missing register() function."""
    plugin_dir = tmp_path / "no_register"
    plugin_dir.mkdir()
    (plugin_dir / "plugin.yaml").write_text(
        """name: no_register
version: 1.0.0
sdk_version: {SDK_VERSION}
""",
        encoding="utf-8",
    )
    (plugin_dir / "__init__.py").write_text(
        "# no register function",
        encoding="utf-8",
    )
    return plugin_dir


@pytest.fixture
def host_with_plugins(tmp_path, temp_plugin_dir, temp_disabled_plugin, temp_bad_plugin):
    """Create a host with good, disabled, and bad plugins."""
    return PluginHost(search_paths=[tmp_path])


# ──────────────────────────────────────────────────────────────────────────
# PluginManifest
# ──────────────────────────────────────────────────────────────────────────


class TestPluginManifest:
    def test_parse_yaml_minimal(self, tmp_path):
        path = tmp_path / "p"
        path.mkdir()
        (path / "plugin.yaml").write_text(
            """name: minimal
version: 0.1.0
sdk_version: {SDK_VERSION}
""",
            encoding="utf-8",
        )
        host = PluginHost(search_paths=[tmp_path])
        # Use private method for direct testing
        manifest = host._parse_manifest(path)
        assert manifest is not None
        assert manifest.name == "minimal"
        assert manifest.version == "0.1.0"
        assert manifest.enabled is True
        assert manifest.capabilities == []
        assert manifest.entry_point == "__init__.py"

    def test_parse_json(self, tmp_path):
        path = tmp_path / "p"
        path.mkdir()
        (path / "plugin.json").write_text(
            json.dumps(
                {
                    "name": "json_plugin",
                    "version": "2.0.0",
                    "author": "JSON Author",
                    "capabilities": ["network", "filesystem"],
                }
            ),
            encoding="utf-8",
        )
        host = PluginHost(search_paths=[tmp_path])
        manifest = host._parse_manifest(path)
        assert manifest is not None
        assert manifest.name == "json_plugin"
        assert manifest.author == "JSON Author"
        assert Capability.NETWORK in manifest.capabilities
        assert Capability.FILESYSTEM in manifest.capabilities

    def test_parse_no_manifest(self, tmp_path):
        path = tmp_path / "p"
        path.mkdir()
        host = PluginHost(search_paths=[tmp_path])
        assert host._parse_manifest(path) is None

    def test_parse_bad_yaml(self, tmp_path):
        path = tmp_path / "p"
        path.mkdir()
        (path / "plugin.yaml").write_text("invalid: yaml: [unclosed", encoding="utf-8")
        host = PluginHost(search_paths=[tmp_path])
        assert host._parse_manifest(path) is None

    def test_compatible_same_version(self):
        m = PluginManifest(name="x", version="1.0.0", sdk_version=SDK_VERSION)
        ok, reason = m.is_compatible()
        assert ok is True
        assert reason == "compatible"

    def test_compatible_disabled(self):
        m = PluginManifest(name="x", version="1.0.0", sdk_version=SDK_VERSION, enabled=False)
        ok, reason = m.is_compatible()
        assert ok is False
        assert "disabled" in reason

    def test_compatible_major_mismatch(self):
        m = PluginManifest(name="x", version="1.0.0", sdk_version="2.0.0")
        ok, reason = m.is_compatible()
        assert ok is False
        assert "major mismatch" in reason

    def test_compatible_minor_downgrade(self):
        m = PluginManifest(name="x", version="1.0.0", sdk_version="1.5.0")
        ok, reason = m.is_compatible()
        assert ok is False
        assert "needs SDK" in reason

    def test_to_dict(self):
        m = PluginManifest(
            name="x",
            version="1.0.0",
            author="me",
            description="desc",
            capabilities=[Capability.NETWORK],
            tags=["t1"],
        )
        d = m.to_dict()
        assert d["name"] == "x"
        assert d["capabilities"] == ["network"]
        assert d["tags"] == ["t1"]


# ──────────────────────────────────────────────────────────────────────────
# PluginHost discovery & loading
# ──────────────────────────────────────────────────────────────────────────


class TestPluginHost:
    def test_empty_search_paths(self, tmp_path):
        host = PluginHost(search_paths=[tmp_path])
        assert host.discover() == []
        assert host.load_all() == {}

    def test_discover_finds_plugins(self, host_with_plugins):
        found = host_with_plugins.discover()
        names = [p.name for p in found]
        assert any(p.name == "test_plugin" for p in found)
        assert any(p.name == "disabled_plugin" for p in found)
        assert any(p.name == "bad_plugin" for p in found)

    def test_load_all_success_and_skip_disabled(self, host_with_plugins):
        result = host_with_plugins.load_all()
        assert "test_plugin" in result
        assert result["test_plugin"].state == PluginState.ACTIVE
        # Disabled plugin is skipped (not loaded as ACTIVE)
        assert "disabled_plugin" in result
        assert result["disabled_plugin"].state == PluginState.DISABLED
        # Bad plugin is marked failed
        assert "bad_plugin" in result
        assert result["bad_plugin"].state == PluginState.FAILED
        assert "intentional failure" in result["bad_plugin"].error

    def test_load_all_continues_on_failure(self, host_with_plugins):
        # fail_fast=False (default) — bad plugin doesn't stop others
        result = host_with_plugins.load_all(fail_fast=False)
        assert "test_plugin" in result
        assert result["test_plugin"].state == PluginState.ACTIVE

    def test_load_all_fail_fast(self, host_with_plugins):
        # With fail_fast=True, a failing plugin should re-raise
        # host_with_plugins already has bad_plugin in its search path
        with pytest.raises(RuntimeError, match="intentional failure"):
            host_with_plugins.load_all(fail_fast=True)

    def test_missing_register_function(self, tmp_path):
        path = tmp_path / "noreg"
        path.mkdir()
        (path / "plugin.yaml").write_text(
            f"name: noreg\nversion: 1.0.0\nsdk_version: {SDK_VERSION}\n", encoding="utf-8"
        )
        (path / "__init__.py").write_text("x = 1\n", encoding="utf-8")
        host = PluginHost(search_paths=[tmp_path])
        host.load_all()
        info = host.get_plugin("noreg")
        assert info is not None
        assert info.state == PluginState.FAILED
        assert info.error is not None
        assert "missing register" in info.error

    def test_entry_point_override(self, tmp_path):
        path = tmp_path / "custom_entry"
        path.mkdir()
        (path / "plugin.yaml").write_text(
            """name: custom_entry
version: 1.0.0
sdk_version: {SDK_VERSION}
entry_point: my_register.py
""",
            encoding="utf-8",
        )
        (path / "my_register.py").write_text(
            "def register(api): api.register_tool('custom', lambda: 'ok')",
            encoding="utf-8",
        )
        host = PluginHost(search_paths=[tmp_path])
        host.load_all()
        assert host.get_tool("custom_entry.custom") is not None

    def test_search_path_env(self, tmp_path, monkeypatch):
        p = tmp_path / "from_env"
        p.mkdir()
        (p / "test.yaml").write_text("not a real dir", encoding="utf-8")  # no actual plugin
        monkeypatch.setenv("ELENGENIX_PLUGIN_PATH", str(p))
        host = PluginHost(search_paths=[tmp_path])
        assert any(str(p) == str(x) for x in host._search_paths)

    def test_search_path_ignores_dotfiles(self, tmp_path):
        (tmp_path / ".hidden_plugin").mkdir()
        (tmp_path / "_underscore_plugin").mkdir()
        host = PluginHost(search_paths=[tmp_path])
        # Both should be ignored
        names = [p.name for p in host.discover()]
        assert ".hidden_plugin" not in names
        assert "_underscore_plugin" not in names


# ──────────────────────────────────────────────────────────────────────────
# Tool / Command / Hook / AI registration
# ──────────────────────────────────────────────────────────────────────────


class TestRegistrations:
    def test_register_tool(self, host_with_plugins):
        host_with_plugins.load_all()
        tool = host_with_plugins.get_tool("test_plugin.greet")
        assert tool is not None
        result = tool(name="Alice")
        assert result["success"] is True
        assert result["data"]["message"] == "Hello, Alice!"

    def test_register_command(self, host_with_plugins):
        host_with_plugins.load_all()
        cmd = host_with_plugins.get_command("test_plugin-hello")
        assert cmd is not None
        assert cmd([]) == 0

    def test_register_finding_hook(self, host_with_plugins):
        host_with_plugins.load_all()
        finding = {"severity": "High", "title": "test"}
        result = host_with_plugins.run_finding_hooks(finding)
        assert result is not None
        assert result.get("tagged_by_test_plugin") is True

    def test_hook_can_drop_finding(self, tmp_path):
        # Plugin with hook that returns None to drop
        p = tmp_path / "dropper"
        p.mkdir()
        (p / "plugin.yaml").write_text(
            f"name: dropper\nversion: 1.0.0\nsdk_version: {SDK_VERSION}\n", encoding="utf-8"
        )
        (p / "__init__.py").write_text(
            "def register(api): api.register_finding_hook('dropper', lambda f: None)",
            encoding="utf-8",
        )
        host = PluginHost(search_paths=[tmp_path])
        host.load_all()
        result = host.run_finding_hooks({"title": "x"})
        assert result is None

    def test_hook_exception_doesnt_break_pipeline(self, host_with_plugins):
        host_with_plugins.load_all()

        # Add a hook that raises
        def bad_hook(f):
            raise ValueError("intentional")

        host_with_plugins._register_finding_hook("bad", bad_hook, priority=5)
        # Should still return a finding (just with tag from good hook)
        result = host_with_plugins.run_finding_hooks({"title": "x"})
        assert result is not None
        assert result.get("tagged_by_test_plugin") is True

    def test_register_ai_provider(self, host_with_plugins):
        host_with_plugins.load_all()

        def chat(msgs, model):
            return "ok"

        def list_models():
            return ["m1", "m2"]

        host_with_plugins._register_ai_provider("test_provider", chat, list_models)
        assert "test_provider" in host_with_plugins.list_ai_providers()
        p = host_with_plugins.get_ai_provider("test_provider")
        assert p[0] is chat
        assert p[1]() == ["m1", "m2"]

    def test_invalid_tool_name_rejected(self, host_with_plugins):
        host_with_plugins.load_all()
        api = host_with_plugins.get_plugin("test_plugin")
        assert api is not None
        api_obj = PluginAPI(api, host_with_plugins)

        def _ok_tool() -> ToolResult:
            return ToolResult(success=True)

        with pytest.raises(ValueError, match="Invalid tool name"):
            api_obj.register_tool("Bad-Name", _ok_tool)
        with pytest.raises(ValueError, match="Invalid tool name"):
            api_obj.register_tool("", _ok_tool)

    def test_duplicate_tool_rejected(self, host_with_plugins):
        host_with_plugins.load_all()
        info = host_with_plugins.get_plugin("test_plugin")
        assert info is not None
        api_obj = PluginAPI(info, host_with_plugins)

        def _ok_tool() -> ToolResult:
            return ToolResult(success=True)

        with pytest.raises(ValueError, match="already registered"):
            api_obj.register_tool("greet", _ok_tool)


# ──────────────────────────────────────────────────────────────────────────
# Hook priority ordering
# ──────────────────────────────────────────────────────────────────────────


class TestHookOrdering:
    def test_hooks_run_in_priority_order(self, tmp_path):
        p = tmp_path / "order_test"
        p.mkdir()
        (p / "plugin.yaml").write_text(
            f"name: order_test\nversion: 1.0.0\nsdk_version: {SDK_VERSION}\n", encoding="utf-8"
        )
        (p / "__init__.py").write_text(
            """def register(api):
    api.register_finding_hook('high', lambda f: {**f, 'order': f.get('order', []) + ['high']}, priority=100)
    api.register_finding_hook('low', lambda f: {**f, 'order': f.get('order', []) + ['low']}, priority=10)
    api.register_finding_hook('mid', lambda f: {**f, 'order': f.get('order', []) + ['mid']}, priority=50)
""",
            encoding="utf-8",
        )
        host = PluginHost(search_paths=[tmp_path])
        host.load_all()
        result = host.run_finding_hooks({})
        assert result is not None
        assert result["order"] == ["low", "mid", "high"]


# ──────────────────────────────────────────────────────────────────────────
# Lifecycle: unload, reload
# ──────────────────────────────────────────────────────────────────────────


class TestLifecycle:
    def test_unload_removes_registrations(self, host_with_plugins):
        host_with_plugins.load_all()
        assert host_with_plugins.get_tool("test_plugin.greet") is not None
        assert host_with_plugins.get_command("test_plugin-hello") is not None
        assert host_with_plugins.unload("test_plugin") is True
        assert host_with_plugins.get_tool("test_plugin.greet") is None
        assert host_with_plugins.get_command("test_plugin-hello") is None
        # Hooks also removed
        result = host_with_plugins.run_finding_hooks({})
        assert "tagged_by_test_plugin" not in (result or {})

    def test_unload_nonexistent_returns_false(self, host_with_plugins):
        assert host_with_plugins.unload("doesnt_exist") is False

    def test_reload(self, host_with_plugins):
        host_with_plugins.load_all()
        # Reload should not lose the plugin
        reloaded = host_with_plugins.reload("test_plugin")
        assert reloaded is not None
        assert host_with_plugins.get_tool("test_plugin.greet") is not None

    def test_stats(self, host_with_plugins):
        host_with_plugins.load_all()
        stats = host_with_plugins.stats()
        assert stats["total_plugins"] >= 3
        assert stats["active_plugins"] >= 1
        assert stats["failed_plugins"] >= 1
        assert stats["disabled_plugins"] >= 1
        assert stats["total_tools"] >= 1
        assert stats["total_commands"] >= 1


# ──────────────────────────────────────────────────────────────────────────
# Config access
# ──────────────────────────────────────────────────────────────────────────


class TestConfig:
    def test_get_config_from_dict(self):
        host = PluginHost(search_paths=[])
        host.set_config({"api_key": "secret123", "region": "us"})
        assert host._get_config("api_key") == "secret123"
        assert host._get_config("region") == "us"

    def test_get_config_from_env(self, monkeypatch):
        monkeypatch.setenv("ELENGENIX_FOO", "bar")
        host = PluginHost(search_paths=[])
        assert host._get_config("foo") == "bar"

    def test_get_config_default(self):
        host = PluginHost(search_paths=[])
        assert host._get_config("missing") is None
        assert host._get_config("missing", "default") == "default"


# ──────────────────────────────────────────────────────────────────────────
# PluginAPI capability check
# ──────────────────────────────────────────────────────────────────────────


class TestCapabilities:
    def test_has_capability_declared(self, host_with_plugins):
        host_with_plugins.load_all()
        api = PluginAPI(host_with_plugins.get_plugin("test_plugin"), host_with_plugins)
        assert api.has_capability("network") is True
        assert api.has_capability(Capability.NETWORK) is True
        assert api.has_capability("elevated") is False

    def test_plugin_name_property(self, host_with_plugins):
        host_with_plugins.load_all()
        api = PluginAPI(host_with_plugins.get_plugin("test_plugin"), host_with_plugins)
        assert api.plugin_name == "test_plugin"


# ──────────────────────────────────────────────────────────────────────────
# ToolResult
# ──────────────────────────────────────────────────────────────────────────


class TestToolResult:
    def test_default_success(self):
        r = ToolResult()
        assert r["success"] is True
        assert r["findings"] == []
        assert r["error"] is None

    def test_with_findings(self):
        r = ToolResult(findings=[{"id": "V1"}], data={"x": 1})
        assert len(r["findings"]) == 1
        assert r["data"]["x"] == 1


# ──────────────────────────────────────────────────────────────────────────
# Marketplace
# ──────────────────────────────────────────────────────────────────────────


class TestMarketplace:
    def test_parse_index(self):
        m = Marketplace()
        text = json.dumps(
            [
                {
                    "name": "a",
                    "version": "1.0.0",
                    "author": "alice",
                    "downloads": 100,
                    "verified": True,
                },
                {"name": "b", "version": "0.5.0", "author": "bob", "tags": ["recon"]},
            ]
        )
        entries = m._parse_index(text)
        assert len(entries) == 2
        assert entries[0].name == "a"
        assert entries[0].verified is True
        assert entries[1].tags == ["recon"]

    def test_parse_index_wrapped(self):
        m = Marketplace()
        text = json.dumps({"plugins": [{"name": "a", "version": "1.0.0"}]})
        entries = m._parse_index(text)
        assert len(entries) == 1

    def test_search_empty_index(self):
        m = Marketplace()
        m._index = []
        # Even with no fetch, search returns []
        assert m.search("anything") == []

    def test_search_with_query(self):
        m = Marketplace()
        m._index = [
            PluginEntry(
                name="shodan_recon",
                version="1.0.0",
                description="Shodan integration",
                downloads=1000,
            ),
            PluginEntry(name="github_enum", version="1.0.0", description="GitHub recon"),
        ]
        results = m.search("shodan")
        assert len(results) == 1
        assert results[0].name == "shodan_recon"

    def test_search_by_tag(self):
        m = Marketplace()
        m._index = [
            PluginEntry(name="a", version="1.0.0", tags=["recon"]),
            PluginEntry(name="b", version="1.0.0", tags=["exploit"]),
        ]
        results = m.search(tag="recon")
        assert len(results) == 1
        assert results[0].name == "a"

    def test_search_verified_only(self):
        m = Marketplace()
        m._index = [
            PluginEntry(name="a", version="1.0.0", verified=True),
            PluginEntry(name="b", version="1.0.0", verified=False),
        ]
        results = m.search(verified_only=True)
        assert len(results) == 1
        assert results[0].name == "a"

    def test_search_sorted_by_downloads(self):
        m = Marketplace()
        m._index = [
            PluginEntry(name="a", version="1.0.0", downloads=10),
            PluginEntry(name="b", version="1.0.0", downloads=1000),
            PluginEntry(name="c", version="1.0.0", downloads=100),
        ]
        results = m.search()
        assert results[0].name == "b"
        assert results[1].name == "c"
        assert results[2].name == "a"

    def test_get_existing(self):
        m = Marketplace()
        m._index = [PluginEntry(name="x", version="1.0.0")]
        result = m.get("x")
        assert result is not None
        assert result.name == "x"

    def test_get_missing(self):
        m = Marketplace()
        m._index = []
        assert m.get("missing") is None

    def test_install_unknown_plugin(self):
        m = Marketplace()
        m._index = []
        ok, msg = m.install("nope")
        assert ok is False
        assert "not found" in msg

    def test_install_no_repo_url(self):
        m = Marketplace()
        m._index = [PluginEntry(name="x", version="1.0.0", repo_url="")]
        ok, msg = m.install("x")
        assert ok is False
        assert "no repo_url" in msg

    def test_uninstall_nonexistent(self, tmp_path):
        m = Marketplace(install_dir=tmp_path)
        ok, msg = m.uninstall("nope")
        assert ok is False
        assert "not installed" in msg

    def test_list_installed(self, tmp_path):
        # Create a fake installed plugin
        plugin_dir = tmp_path / "my_plugin"
        plugin_dir.mkdir()
        (plugin_dir / "plugin.yaml").write_text(
            "name: my_plugin\nversion: 1.0.0\nauthor: me\ndescription: test\n",
            encoding="utf-8",
        )
        m = Marketplace(install_dir=tmp_path)
        installed = m.list_installed()
        assert len(installed) == 1
        assert installed[0]["name"] == "my_plugin"
        assert installed[0]["version"] == "1.0.0"

    def test_stats(self):
        m = Marketplace()
        stats = m.stats()
        assert "index_url" in stats
        assert "install_dir" in stats
        assert "installed_count" in stats

    def test_to_dict(self):
        e = PluginEntry(name="x", version="1.0.0", author="me", downloads=100, verified=True)
        d = e.to_dict()
        assert d["name"] == "x"
        assert d["downloads"] == 100
        assert d["verified"] is True


# ──────────────────────────────────────────────────────────────────────────
# Updater — version comparison
# ──────────────────────────────────────────────────────────────────────────


class TestUpdater:
    def test_parse_version_basic(self):
        assert parse_version("1.2.3") == (1, 2, 3, "")
        assert parse_version("v1.2.3") == (1, 2, 3, "")
        assert parse_version("0.0.1") == (0, 0, 1, "")

    def test_parse_version_prerelease(self):
        assert parse_version("1.0.0-rc.1") == (1, 0, 0, "rc.1")
        assert parse_version("2.0.0-beta") == (2, 0, 0, "beta")
        assert parse_version("1.0.0-alpha.1") == (1, 0, 0, "alpha.1")

    def test_parse_version_invalid(self):
        # Bad version falls back to (0, 0, 0, pre)
        # "abc" has no prerelease tag, so pre is empty
        assert parse_version("abc") == (0, 0, 0, "")
        # "1.x.0-bad" — x fails int conversion, returns (0,0,0,pre)
        assert parse_version("1.x.0-bad") == (0, 0, 0, "bad")
        # Prerelease tag with valid version
        assert parse_version("2.0.0-rc.1") == (2, 0, 0, "rc.1")

    def test_compare_equal(self):
        assert compare_versions("1.0.0", "1.0.0") == 0
        assert compare_versions("v1.0.0", "1.0.0") == 0

    def test_compare_less(self):
        assert compare_versions("1.0.0", "2.0.0") == -1
        assert compare_versions("1.0.0", "1.1.0") == -1
        assert compare_versions("1.0.0", "1.0.1") == -1

    def test_compare_greater(self):
        assert compare_versions("2.0.0", "1.0.0") == 1
        assert compare_versions("1.1.0", "1.0.0") == 1
        assert compare_versions("1.0.1", "1.0.0") == 1

    def test_compare_prerelease_less_than_release(self):
        # 1.0.0-rc.1 < 1.0.0
        assert compare_versions("1.0.0-rc.1", "1.0.0") == -1
        assert compare_versions("1.0.0", "1.0.0-rc.1") == 1

    def test_compare_prerelease_ordering(self):
        # alpha < beta < rc < release
        assert compare_versions("1.0.0-alpha", "1.0.0-beta") == -1
        assert compare_versions("1.0.0-beta", "1.0.0-rc.1") == -1

    def test_release_info_is_newer(self):
        # Release newer than current
        r = ReleaseInfo(tag="v99.0.0", version="99.0.0")
        assert r.is_newer is True

    def test_release_info_not_newer(self):
        r = ReleaseInfo(tag="v0.1.0", version="0.1.0")
        assert r.is_newer is False

    def test_updater_check_no_network(self):
        # With a bad URL and no cache, should return None gracefully
        u = Updater(repo="nonexistent/repo")
        # This will fail to fetch (returns None) — should not raise
        result = u.check_for_updates(use_cache=False)
        # Either None (no update or fetch failed) or some result — just don't crash
        assert result is None or isinstance(result, ReleaseInfo)

    def test_updater_stats(self):
        u = Updater()
        stats = u.stats()
        assert "current_version" in stats
        assert "repo" in stats
        assert "is_git_install" in stats

    def test_updater_is_git_install(self):
        u = Updater()
        # The Elengenix project is a git repo, so this should be True
        assert u.is_git_install() is True


# ──────────────────────────────────────────────────────────────────────────
# Global host singleton
# ──────────────────────────────────────────────────────────────────────────


class TestGlobalHost:
    def test_get_host_returns_singleton(self):
        reset_host()
        h1 = get_host()
        h2 = get_host()
        assert h1 is h2

    def test_reset_host(self):
        h1 = get_host()
        reset_host()
        h2 = get_host()
        assert h1 is not h2
