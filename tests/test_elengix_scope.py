"""Tests for elengenix/scope.py — Scope management."""
from __future__ import annotations

import os
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

from elengenix.scope import ScopeManager, is_in_scope, is_valid_target, normalize_target, sanitize_path


class TestScopeManager:
    def test_default_scope_allows_all(self):
        """No scope configured = all targets allowed."""
        sm = ScopeManager()
        assert sm.is_in_scope("example.com") is True
        assert sm.is_in_scope("10.0.0.1") is True

    def test_in_scope_direct_match(self):
        with patch.object(
            ScopeManager, "_load_scope", return_value={"example.com"}
        ):
            sm = ScopeManager()
            assert sm.is_in_scope("example.com") is True

    def test_in_scope_subdomain_match(self):
        with patch.object(
            ScopeManager, "_load_scope", return_value={"example.com"}
        ):
            sm = ScopeManager()
            assert sm.is_in_scope("sub.example.com") is True
            assert sm.is_in_scope("deep.sub.example.com") is True

    def test_out_of_scope(self):
        with patch.object(
            ScopeManager, "_load_scope", return_value={"example.com"}
        ):
            sm = ScopeManager()
            assert sm.is_in_scope("other.com") is False
            assert sm.is_in_scope("10.0.0.1") is False

    def test_invalid_target_returns_false(self):
        with patch.object(
            ScopeManager, "_load_scope", return_value={"example.com"}
        ):
            sm = ScopeManager()
            assert sm.is_in_scope("") is False
            # None/empty input causes normalize_target to handle gracefully
            assert sm.is_in_scope(" ") is False

    def test_reload_resets_domains(self):
        sm = ScopeManager()
        sm._domains = {"old.com"}
        sm.reload()
        assert sm._domains is None

    def test_lazy_load_on_first_access(self):
        sm = ScopeManager()
        assert sm._domains is None
        _ = sm.allowed_domains
        assert sm._domains is not None

    def test_load_scope_from_env(self):
        with patch.dict(
            os.environ, {"ELENGENIX_SCOPE": "example.com, test.org"}, clear=True
        ):
            sm = ScopeManager()
            domains = sm.allowed_domains
            assert "example.com" in domains
            assert "test.org" in domains

    def test_load_scope_from_env_with_dot_prefix(self):
        with patch.dict(
            os.environ, {"ELENGENIX_SCOPE": ".example.com"}, clear=True
        ):
            sm = ScopeManager()
            domains = sm.allowed_domains
            assert "example.com" in domains

    def test_load_scope_from_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            scope_file = Path(tmp) / "scope.txt"
            scope_file.write_text("example.com\n# comment\ntest.org\n")
            sm = ScopeManager(str(scope_file))
            domains = sm.allowed_domains
            assert "example.com" in domains
            assert "test.org" in domains
            assert "comment" not in domains

    def test_normalize_target_strips_protocol(self):
        assert normalize_target("https://example.com") == "example.com"

    def test_normalize_target_strips_port(self):
        assert normalize_target("example.com:8080") == "example.com"

    def test_normalize_target_strips_path(self):
        assert normalize_target("https://example.com/path/to/resource") == "example.com"

    def test_normalize_target_strips_query(self):
        assert normalize_target("https://example.com/page?a=1&b=2") == "example.com"

    def test_normalize_target_preserves_ipv6(self):
        assert "[::1]" in normalize_target("http://[::1]:8080/path")

    def test_sanitize_path_no_traversal(self):
        assert sanitize_path("safe/path/file.txt") == "safe/path/file.txt"

    def test_sanitize_path_prevents_traversal(self):
        result = sanitize_path("../../../etc/passwd")
        assert ".." not in result

    def test_sanitize_path_prevents_absolute(self):
        result = sanitize_path("/etc/passwd")
        assert not result.startswith("/")

    def test_load_scope_from_file_with_dot_prefix(self):
        with tempfile.TemporaryDirectory() as tmp:
            scope_file = Path(tmp) / "scope.txt"
            scope_file.write_text(".example.com\n.test.org\n")
            sm = ScopeManager(str(scope_file))
            domains = sm.allowed_domains
            assert "example.com" in domains
            assert "test.org" in domains

    def test_is_valid_target_domain(self):
        assert is_valid_target("example.com") is True

    def test_is_valid_target_url(self):
        assert is_valid_target("https://example.com") is True

    def test_is_valid_target_ip(self):
        assert is_valid_target("10.0.0.1") is True
        assert is_valid_target("::1") is True

    def test_is_valid_target_empty(self):
        assert is_valid_target("") is False
        assert is_valid_target(None) is False

    def test_is_valid_target_invalid(self):
        assert is_valid_target("not_a_domain") is False
