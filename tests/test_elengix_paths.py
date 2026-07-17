"""Tests for elengenix/paths.py — Path resolution."""
from __future__ import annotations

import os
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

from elengenix.paths import (
    ELENGENIX_HOME,
    ELENGENIX_DIRS,
    get_data_path,
    get_reports_path,
    get_data_dir,
    get_log_dir,
    get_tools_path,
)


class TestPathConstants:
    def test_elengenix_home(self):
        """ELENGENIX_HOME should point to ~/.elengenix."""
        expected = Path("~/.elengenix").expanduser()
        assert ELENGENIX_HOME == expected

    def test_elengenix_dirs_contains_all_keys(self):
        assert "data" in ELENGENIX_DIRS
        assert "tools" in ELENGENIX_DIRS
        assert "reports" in ELENGENIX_DIRS
        assert "scripts" in ELENGENIX_DIRS
        assert "plugins" in ELENGENIX_DIRS


class TestGetDataPath:
    def test_returns_path_under_data(self):
        p = get_data_path("test.txt")
        assert str(p).endswith(".elengenix/data/test.txt")

    def test_creates_parent_dir(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch("elengenix.paths.ELENGENIX_DIRS", {
                "data": Path(tmp) / ".elengenix" / "data",
                "tools": Path(tmp) / ".elengenix" / "tools",
                "reports": Path(tmp) / ".elengenix" / "reports",
                "scripts": Path(tmp) / ".elengenix" / "scripts",
                "plugins": Path(tmp) / ".elengenix" / "plugins",
            }):
                p = get_data_path("nested/deep/file.json")
                assert p.parent.exists()


class TestGetReportsPath:
    def test_returns_reports_root(self):
        p = get_reports_path()
        assert "reports" in str(p)

    def test_returns_reports_with_subdir(self):
        p = get_reports_path("pentest1")
        assert "pentest1" in str(p)

    def test_creates_dir(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch("elengenix.paths.ELENGENIX_DIRS", {
                "data": Path(tmp) / ".elengenix" / "data",
                "tools": Path(tmp) / ".elengenix" / "tools",
                "reports": Path(tmp) / ".elengenix" / "reports",
                "scripts": Path(tmp) / ".elengenix" / "scripts",
                "plugins": Path(tmp) / ".elengenix" / "plugins",
            }):
                p = get_reports_path("subdir")
                assert p.exists()


class TestGetDataDir:
    def test_returns_data_root(self):
        p = get_data_dir()
        assert str(p).endswith(".elengenix/data")

    def test_returns_data_with_subdir(self):
        p = get_data_dir("chroma")
        assert "chroma" in str(p)


class TestGetLogDir:
    def test_returns_log_dir_under_data(self):
        p = get_log_dir()
        assert "logs" in str(p)

    def test_returns_log_dir_with_subdir(self):
        p = get_log_dir("scans")
        assert "scans" in str(p)


class TestGetToolsPath:
    def test_returns_path_under_tools(self):
        p = get_tools_path("nmap_wrapper.py")
        assert "tools" in str(p)

    def test_creates_parent_dir(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch("elengenix.paths.ELENGENIX_DIRS", {
                "data": Path(tmp) / ".elengenix" / "data",
                "tools": Path(tmp) / ".elengenix" / "tools",
                "reports": Path(tmp) / ".elengenix" / "reports",
                "scripts": Path(tmp) / ".elengenix" / "scripts",
                "plugins": Path(tmp) / ".elengenix" / "plugins",
            }):
                p = get_tools_path("sub/tool.py")
                assert p.parent.exists()


class TestEnsureDirs:
    def test_ensure_dirs_creates_all_dirs(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch("elengenix.paths.ELENGENIX_DIRS", {
                "data": Path(tmp) / ".elengenix" / "data",
                "tools": Path(tmp) / ".elengenix" / "tools",
                "reports": Path(tmp) / ".elengenix" / "reports",
                "scripts": Path(tmp) / ".elengenix" / "scripts",
                "plugins": Path(tmp) / ".elengenix" / "plugins",
            }):
                from elengenix.paths import ensure_dirs
                ensure_dirs()
                for d in ELENGENIX_DIRS.values():
                    assert d.exists(), f"{d} was not created"


class TestFindEnv:
    def test_env_override_exists(self):
        with tempfile.TemporaryDirectory() as tmp:
            env_path = Path(tmp) / ".env.override"
            env_path.write_text("TEST=1\n")
            with patch("elengenix.paths.ENV_OVERRIDE", str(env_path)):
                from elengenix.paths import find_env
                result = find_env()
                assert result == env_path

    def test_env_override_not_found_falls_through(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch("elengenix.paths.ENV_OVERRIDE", "/nonexistent/.env"):
                with patch("elengenix.paths.ELENGENIX_HOME", Path(tmp)):
                    with patch("pathlib.Path.exists", return_value=False):
                        from elengenix.paths import find_env
                        result = find_env()
                        assert result is None


class TestFindConfig:
    def test_config_override_exists(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg_path = Path(tmp) / "config.override.yaml"
            cfg_path.write_text("key: value\n")
            with patch("elengenix.paths.CONFIG_OVERRIDE", str(cfg_path)):
                from elengenix.paths import find_config
                result = find_config()
                assert result == cfg_path

    def test_config_override_not_found_falls_through(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch("elengenix.paths.CONFIG_OVERRIDE", "/nonexistent/config.yaml"):
                with patch("elengenix.paths.ELENGENIX_HOME", Path(tmp)):
                    with patch("pathlib.Path.exists", return_value=False):
                        from elengenix.paths import find_config
                        result = find_config()
                        assert result is None
