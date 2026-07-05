"""tests/test_scope.py — Tests for pipeline.scope.ScopeManager"""

import os
import tempfile
from pathlib import Path

import pytest

from pipeline.scope import (
    ScopeManager,
    is_in_scope,
    is_valid_target,
    load_allowed_domains,
    normalize_target,
    sanitize_path,
)


# ── ScopeManager Creation Tests ────────────────────────────────


class TestScopeManagerCreation:
    def test_create_with_defaults(self):
        sm = ScopeManager()
        assert sm.scope_file == "scope.txt"
        assert sm._domains is None  # Lazy — not loaded yet

    def test_create_with_custom_file(self):
        sm = ScopeManager(scope_file="custom_scope.txt")
        assert sm.scope_file == "custom_scope.txt"


# ── Lazy Loading Tests ────────────────────────────────────────


class TestLazyLoading:
    def test_domains_loaded_on_first_access(self):
        sm = ScopeManager()
        assert sm._domains is None
        _ = sm.allowed_domains  # Trigger lazy load
        assert sm._domains is not None

    def test_domains_cached_after_first_load(self):
        sm = ScopeManager()
        d1 = sm.allowed_domains
        d2 = sm.allowed_domains
        assert d1 is d2  # Same object — cached

    def test_reload_clears_cache(self):
        sm = ScopeManager()
        d1 = sm.allowed_domains
        sm.reload()
        d2 = sm.allowed_domains
        assert d1 is not d2  # Different objects — reloaded


# ── Scope File Loading Tests ──────────────────────────────────


class TestScopeFileLoading:
    def test_loads_from_env_var(self, monkeypatch):
        monkeypatch.setenv("ELENGENIX_SCOPE", "example.com,test.org")
        sm = ScopeManager()
        domains = sm.allowed_domains
        assert "example.com" in domains
        assert "test.org" in domains

    def test_loads_from_file(self, tmp_path):
        scope_file = tmp_path / "scope.txt"
        scope_file.write_text("example.com\ntest.org\n# comment\n")
        sm = ScopeManager(scope_file=str(scope_file))
        domains = sm.allowed_domains
        assert "example.com" in domains
        assert "test.org" in domains

    def test_empty_env_and_missing_file(self):
        sm = ScopeManager(scope_file="nonexistent.txt")
        domains = sm.allowed_domains
        assert len(domains) == 0

    def test_comments_ignored(self, tmp_path):
        scope_file = tmp_path / "scope.txt"
        scope_file.write_text("# This is a comment\nexample.com\n")
        sm = ScopeManager(scope_file=str(scope_file))
        assert "example.com" in sm.allowed_domains


# ── Normalize Target Tests ────────────────────────────────────


class TestNormalizeTarget:
    def test_empty_string(self):
        sm = ScopeManager()
        assert sm.normalize_target("") == ""

    def test_none_input(self):
        sm = ScopeManager()
        assert sm.normalize_target(None) == ""

    def test_bare_domain(self):
        sm = ScopeManager()
        assert sm.normalize_target("Example.COM") == "example.com"

    def test_http_url(self):
        sm = ScopeManager()
        assert sm.normalize_target("http://example.com/path") == "example.com"

    def test_https_url(self):
        sm = ScopeManager()
        assert sm.normalize_target("https://example.com:8080/path") == "example.com"

    def test_ipv4_with_port(self):
        sm = ScopeManager()
        assert sm.normalize_target("1.2.3.4:8080") == "1.2.3.4"

    def test_ipv4_bare(self):
        sm = ScopeManager()
        assert sm.normalize_target("1.2.3.4") == "1.2.3.4"

    def test_ipv6_with_brackets(self):
        sm = ScopeManager()
        assert sm.normalize_target("[::1]:8080") == "::1"

    def test_ipv6_bare(self):
        sm = ScopeManager()
        assert sm.normalize_target("::1") == "::1"

    def test_strips_trailing_dot(self):
        sm = ScopeManager()
        assert sm.normalize_target("example.com.") == "example.com"

    def test_strips_whitespace(self):
        sm = ScopeManager()
        assert sm.normalize_target("  example.com  ") == "example.com"


# ── Is Valid Target Tests ─────────────────────────────────────


class TestIsValidTarget:
    def test_empty_string(self):
        sm = ScopeManager()
        assert sm.is_valid_target("") is False

    def test_valid_ipv4(self):
        sm = ScopeManager()
        assert sm.is_valid_target("93.184.216.34") is True

    def test_private_ipv4_rejected(self):
        sm = ScopeManager()
        assert sm.is_valid_target("192.168.1.1") is False

    def test_loopback_ipv4_rejected(self):
        sm = ScopeManager()
        assert sm.is_valid_target("127.0.0.1") is False

    def test_valid_ipv6(self):
        sm = ScopeManager()
        # 2607:f8b0:4004:800::200e is Google's public IPv6
        assert sm.is_valid_target("2607:f8b0:4004:800::200e") is True

    def test_loopback_ipv6_rejected(self):
        sm = ScopeManager()
        assert sm.is_valid_target("::1") is False

    def test_valid_domain(self):
        sm = ScopeManager()
        assert sm.is_valid_target("example.com") is True

    def test_invalid_domain_no_dot(self):
        sm = ScopeManager()
        assert sm.is_valid_target("localhost") is False

    def test_invalid_domain_too_long(self):
        sm = ScopeManager()
        assert sm.is_valid_target("a" * 254) is False

    def test_valid_subdomain(self):
        sm = ScopeManager()
        assert sm.is_valid_target("sub.example.com") is True


# ── Is In Scope Tests ─────────────────────────────────────────


class TestIsInScope:
    def test_empty_target(self):
        sm = ScopeManager()
        assert sm.is_in_scope("") is False

    def test_empty_scope_allows_all(self):
        sm = ScopeManager(scope_file="nonexistent.txt")
        assert sm.is_in_scope("example.com") is True

    def test_exact_match(self, tmp_path):
        scope_file = tmp_path / "scope.txt"
        scope_file.write_text("example.com\n")
        sm = ScopeManager(scope_file=str(scope_file))
        assert sm.is_in_scope("example.com") is True

    def test_subdomain_match(self, tmp_path):
        scope_file = tmp_path / "scope.txt"
        scope_file.write_text("example.com\n")
        sm = ScopeManager(scope_file=str(scope_file))
        assert sm.is_in_scope("sub.example.com") is True

    def test_no_match(self, tmp_path):
        scope_file = tmp_path / "scope.txt"
        scope_file.write_text("example.com\n")
        sm = ScopeManager(scope_file=str(scope_file))
        assert sm.is_in_scope("evil.com") is False

    def test_private_ip_rejected(self, tmp_path):
        scope_file = tmp_path / "scope.txt"
        scope_file.write_text("192.168.1.1\n")
        sm = ScopeManager(scope_file=str(scope_file))
        assert sm.is_in_scope("192.168.1.1") is False

    def test_env_var_scope(self, monkeypatch):
        monkeypatch.setenv("ELENGENIX_SCOPE", "example.com")
        sm = ScopeManager()
        assert sm.is_in_scope("example.com") is True
        assert sm.is_in_scope("evil.com") is False


# ── Module-Level Functions Tests ──────────────────────────────


class TestModuleLevelFunctions:
    def test_normalize_target(self):
        assert normalize_target("Example.COM") == "example.com"

    def test_is_valid_target(self):
        assert is_valid_target("example.com") is True
        assert is_valid_target("192.168.1.1") is False

    def test_is_in_scope(self):
        # Default scope (empty) allows everything
        assert is_in_scope("example.com") is True

    def test_load_allowed_domains(self):
        domains = load_allowed_domains("nonexistent.txt")
        assert isinstance(domains, set)

    def test_sanitize_path(self):
        assert sanitize_path("example.com") == "example.com"
        assert sanitize_path("example.com:8080") == "example.com_8080"
        assert len(sanitize_path("a" * 200)) == 100


# ── Backward Compatibility Tests ──────────────────────────────


class TestBackwardCompatibility:
    def test_orchestrator_imports_still_work(self):
        """Verify orchestrator.py's imports still work."""
        from core.orchestrator import is_in_scope, is_valid_target, normalize_target

        assert normalize_target("example.com") == "example.com"
        assert is_valid_target("example.com") is True
        # is_in_scope returns False when no scope configured (fail-closed)
        # This is correct behavior — configure scope.txt or ELENGENIX_SCOPE
        assert is_in_scope("example.com") is False
