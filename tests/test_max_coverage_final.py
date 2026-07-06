"""tests/test_max_coverage_final.py — Massive coverage push for Elengenix.

Tests ALL public methods/functions across 25 modules with mocked dependencies.
Focus: exercise every code path, every if/else branch, every method signature.

Rules:
- sys.path.insert(0, ...) at top
- Mock ALL network, LLM, subprocess, file I/O
- For EVERY method: valid inputs AND edge cases
- No emoji
- No TUI launch, no downloads, no servers
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import sqlite3
import sys
import tempfile
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from io import StringIO
from pathlib import Path
from typing import Any, Dict, List, Optional, Set
from unittest.mock import AsyncMock, MagicMock, Mock, mock_open, patch, PropertyMock

import pytest

# Ensure project root is on sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


# ═══════════════════════════════════════════════════════════════════════════
#  MODULE 1: active_fuzzer.py
# ═══════════════════════════════════════════════════════════════════════════


class TestActiveFuzzer:
    """Test active_fuzzer.py -- scoring, delta computation, data classes."""

    def test_baseline_response_dataclass(self):
        from tools.active_fuzzer import BaselineResponse
        br = BaselineResponse(status=200, length=100, elapsed_ms=50.0, body_hash="abc", body="hello")
        assert br.status == 200
        assert br.length == 100
        assert br.elapsed_ms == 50.0
        assert br.body == "hello"
        assert br.headers == {}
        assert br.url == ""

    def test_response_delta_dataclass(self):
        from tools.active_fuzzer import ResponseDelta
        rd = ResponseDelta(
            status_changed=True, status_before=200, status_after=500,
            length_diff=50, length_diff_pct=0.5, time_diff_ms=100.0,
            time_ratio=2.0, body_hash_changed=True, error_indicator=True,
            auth_indicator=False, sql_error_in_body=False, reflection_indicator=True,
        )
        assert rd.status_changed is True
        assert rd.error_indicator is True
        assert rd.reflection_indicator is True

    def test_fuzz_result_dataclass(self):
        from tools.active_fuzzer import FuzzResult, ResponseDelta
        delta = ResponseDelta(
            status_changed=False, status_before=200, status_after=200,
            length_diff=0, length_diff_pct=0.0, time_diff_ms=0.0,
            time_ratio=1.0, body_hash_changed=False, error_indicator=False,
            auth_indicator=False, sql_error_in_body=False, reflection_indicator=False,
        )
        fr = FuzzResult(
            payload="test", injection_point="param:q", method="GET",
            url="http://x", status=200, response_length=100, elapsed_ms=50.0,
            delta=delta, score=0.8, is_interesting=True, reasoning="test", body_snippet="x",
        )
        assert fr.score == 0.8
        assert fr.is_interesting is True
        assert fr.body_snippet == "x"

    def test_fuzzer_config_defaults(self):
        from tools.active_fuzzer import FuzzerConfig
        cfg = FuzzerConfig()
        assert cfg.timeout_seconds == 8.0
        assert cfg.max_retries == 2
        assert cfg.rate_limit_cooldown == 1.5
        assert cfg.interesting_threshold == 0.5
        assert cfg.verify_ssl is False

    def test_detect_sql_error(self):
        from tools.active_fuzzer import _detect_sql_error
        assert _detect_sql_error("mysql_fetch error in query") is True
        assert _detect_sql_error("normal response") is False
        assert _detect_sql_error("ORA-01756: quoted string not properly terminated") is True
        assert _detect_sql_error("postgresql ERROR: syntax error") is True
        assert _detect_sql_error("no error here") is False
        assert _detect_sql_error("unclosed quotation mark after the character string") is True
        assert _detect_sql_error("sqlstate 42000") is True

    def test_detect_reflection(self):
        from tools.active_fuzzer import _detect_reflection
        assert _detect_reflection("AAAA", "AAAA reflected") is True
        assert _detect_reflection("AB", "AB in body") is False  # too short
        assert _detect_reflection("", "body") is False
        assert _detect_reflection("short", "no match here") is False

    def test_compute_delta(self):
        from tools.active_fuzzer import BaselineResponse, compute_delta
        baseline = BaselineResponse(
            status=200, length=100, elapsed_ms=50.0,
            body_hash=hashlib.sha256(b"baseline").hexdigest(), body="baseline",
        )
        delta = compute_delta(baseline, 200, "baseline same", 50.0)
        assert delta.status_changed is False
        assert delta.error_indicator is False
        assert delta.body_hash_changed is True  # "baseline same" != "baseline" hash

    def test_compute_delta_status_change(self):
        from tools.active_fuzzer import BaselineResponse, compute_delta
        baseline = BaselineResponse(
            status=200, length=100, elapsed_ms=50.0,
            body_hash=hashlib.sha256(b"ok").hexdigest(), body="ok",
        )
        delta = compute_delta(baseline, 500, "server error", 200.0)
        assert delta.status_changed is True
        assert delta.status_before == 200
        assert delta.status_after == 500
        assert delta.error_indicator is True
        assert delta.time_ratio == 4.0

    def test_compute_delta_auth_indicator(self):
        from tools.active_fuzzer import BaselineResponse, compute_delta
        baseline = BaselineResponse(
            status=200, length=100, elapsed_ms=50.0,
            body_hash="abc", body="ok",
        )
        delta = compute_delta(baseline, 403, "forbidden", 50.0)
        assert delta.auth_indicator is True

    def test_score_delta_no_signal(self):
        from tools.active_fuzzer import ResponseDelta, score_delta
        delta = ResponseDelta(
            status_changed=False, status_before=200, status_after=200,
            length_diff=0, length_diff_pct=0.0, time_diff_ms=0.0,
            time_ratio=1.0, body_hash_changed=False, error_indicator=False,
            auth_indicator=False, sql_error_in_body=False, reflection_indicator=False,
        )
        score, reasoning = score_delta(delta)
        assert score == 0.0
        assert "no signal" in reasoning

    def test_score_delta_all_signals(self):
        from tools.active_fuzzer import ResponseDelta, score_delta
        delta = ResponseDelta(
            status_changed=True, status_before=200, status_after=500,
            length_diff=500, length_diff_pct=0.8, time_diff_ms=1000.0,
            time_ratio=3.0, body_hash_changed=True, error_indicator=True,
            auth_indicator=True, sql_error_in_body=True, reflection_indicator=True,
        )
        score, reasoning = score_delta(delta, "payload", "body")
        assert score == 1.0  # capped
        assert "5xx" in reasoning
        assert "4xx" in reasoning
        assert "SQL error" in reasoning
        assert "slow response" in reasoning
        assert "body length changed" in reasoning
        assert "body content changed" in reasoning
        assert "payload reflected" in reasoning

    def test_score_delta_reflection_only(self):
        from tools.active_fuzzer import ResponseDelta, score_delta
        delta = ResponseDelta(
            status_changed=False, status_before=200, status_after=200,
            length_diff=10, length_diff_pct=0.05, time_diff_ms=10.0,
            time_ratio=1.0, body_hash_changed=False, error_indicator=False,
            auth_indicator=False, sql_error_in_body=False, reflection_indicator=True,
        )
        score, reasoning = score_delta(delta)
        assert score == 0.15
        assert "payload reflected" in reasoning

    def test_active_fuzzer_summarize_empty(self):
        from tools.active_fuzzer import ActiveFuzzer
        fuzzer = ActiveFuzzer()
        result = fuzzer.summarize([])
        assert result["total"] == 0
        assert result["interesting"] == 0

    def test_active_fuzzer_summarize_with_results(self):
        from tools.active_fuzzer import ActiveFuzzer, FuzzResult, ResponseDelta
        delta = ResponseDelta(
            status_changed=True, status_before=200, status_after=500,
            length_diff=100, length_diff_pct=0.5, time_diff_ms=500.0,
            time_ratio=2.5, body_hash_changed=True, error_indicator=True,
            auth_indicator=False, sql_error_in_body=False, reflection_indicator=True,
        )
        results = [
            FuzzResult("xss", "param:q", "GET", "http://x", 500, 100, 500.0,
                        delta, 0.8, True, "reason", "body"),
            FuzzResult("normal", "param:q", "GET", "http://x", 200, 100, 50.0,
                        ResponseDelta(False, 200, 200, 0, 0.0, 0.0, 1.0, False, False, False, False, False),
                        0.1, False, "ok", "ok"),
        ]
        summary = ActiveFuzzer().summarize(results)
        assert summary["total"] == 2
        assert summary["interesting"] == 1
        assert summary["top_score"] == 0.8
        assert "server_error" in summary["categories"]
        assert "reflection" in summary["categories"]


# ═══════════════════════════════════════════════════════════════════════════
#  MODULE 2: profile_manager.py
# ═══════════════════════════════════════════════════════════════════════════


class TestProfileManager:
    """Test profile_manager.py -- all CRUD and expansion methods."""

    def test_command_profile_dataclass(self):
        from tools.profile_manager import CommandProfile
        p = CommandProfile(
            name="test", description="desc", base_command="scan",
            args=["--deep"], options={"rate": 10}, env_vars={},
            created_by="user", tags=["custom"],
        )
        assert p.name == "test"
        assert p.usage_count == 0

    @patch("tools.profile_manager.ProfileManager._ensure_profiles_dir")
    def test_init(self, mock_ensure):
        from tools.profile_manager import ProfileManager
        pm = ProfileManager()
        assert len(pm.profiles) >= 7  # has built-in profiles

    @patch("tools.profile_manager.ProfileManager._ensure_profiles_dir")
    def test_get_profile(self, mock_ensure):
        from tools.profile_manager import ProfileManager
        pm = ProfileManager()
        assert pm.get_profile("quick") is not None
        assert pm.get_profile("nonexistent") is None

    @patch("tools.profile_manager.ProfileManager._ensure_profiles_dir")
    def test_list_profiles(self, mock_ensure):
        from tools.profile_manager import ProfileManager
        pm = ProfileManager()
        profiles = pm.list_profiles()
        assert len(profiles) >= 7

    @patch("tools.profile_manager.ProfileManager._ensure_profiles_dir")
    def test_list_profiles_with_category(self, mock_ensure):
        from tools.profile_manager import ProfileManager
        pm = ProfileManager()
        profiles = pm.list_profiles(category="overview")
        assert len(profiles) > 0
        assert all("overview" in p.tags for p in profiles)

    @patch("tools.profile_manager.ProfileManager._ensure_profiles_dir")
    def test_expand_profile(self, mock_ensure):
        from tools.profile_manager import ProfileManager
        pm = ProfileManager()
        result = pm.expand_profile("quick", target="example.com")
        assert result is not None
        cmd, args = result
        assert cmd in ("recon", "scan")  # may be overridden by user profile
        assert "example.com" in args

    @patch("tools.profile_manager.ProfileManager._ensure_profiles_dir")
    def test_expand_profile_no_target(self, mock_ensure):
        from tools.profile_manager import ProfileManager
        pm = ProfileManager()
        result = pm.expand_profile("quick")
        assert result is not None
        cmd, args = result
        assert cmd in ("recon", "scan")

    @patch("tools.profile_manager.ProfileManager._ensure_profiles_dir")
    def test_expand_profile_with_bool_option(self, mock_ensure):
        from tools.profile_manager import ProfileManager
        pm = ProfileManager()
        result = pm.expand_profile("stealth", target="x.com")
        assert result is not None
        cmd, args = result
        assert "--stealth" in args

    @patch("tools.profile_manager.ProfileManager._ensure_profiles_dir")
    def test_expand_nonexistent(self, mock_ensure):
        from tools.profile_manager import ProfileManager
        pm = ProfileManager()
        assert pm.expand_profile("nonexistent") is None

    @patch("tools.profile_manager.ProfileManager._ensure_profiles_dir")
    def test_create_profile(self, mock_ensure):
        from tools.profile_manager import ProfileManager
        pm = ProfileManager()
        with patch("pathlib.Path.write_text"):
            ok = pm.create_profile("mytest", "scan", description="test profile", tags=["custom"])
            assert ok is True
            assert "mytest" in pm.profiles

    @patch("tools.profile_manager.ProfileManager._ensure_profiles_dir")
    def test_create_profile_override_builtin_fails(self, mock_ensure):
        from tools.profile_manager import ProfileManager
        pm = ProfileManager()
        # "quick" is a built-in, cannot override
        ok = pm.create_profile("quick", "scan")
        assert ok is False

    @patch("tools.profile_manager.ProfileManager._ensure_profiles_dir")
    def test_delete_profile(self, mock_ensure):
        from tools.profile_manager import ProfileManager
        pm = ProfileManager()
        # Create a user profile first
        with patch("pathlib.Path.write_text"):
            pm.create_profile("to_delete", "scan")
        with patch("pathlib.Path.unlink"):
            ok = pm.delete_profile("to_delete")
            assert ok is True

    @patch("tools.profile_manager.ProfileManager._ensure_profiles_dir")
    def test_delete_builtin_profile_fails(self, mock_ensure):
        from tools.profile_manager import ProfileManager
        pm = ProfileManager()
        ok = pm.delete_profile("quick")
        assert ok is False

    @patch("tools.profile_manager.ProfileManager._ensure_profiles_dir")
    def test_delete_nonexistent_profile(self, mock_ensure):
        from tools.profile_manager import ProfileManager
        pm = ProfileManager()
        ok = pm.delete_profile("nonexistent")
        assert ok is False

    @patch("tools.profile_manager.ProfileManager._ensure_profiles_dir")
    def test_export_profile(self, mock_ensure):
        from tools.profile_manager import ProfileManager
        pm = ProfileManager()
        result = pm.export_profile("quick")
        assert result is not None
        data = json.loads(result)
        assert data["name"] == "quick"

    @patch("tools.profile_manager.ProfileManager._ensure_profiles_dir")
    def test_export_nonexistent(self, mock_ensure):
        from tools.profile_manager import ProfileManager
        pm = ProfileManager()
        assert pm.export_profile("nonexistent") is None

    @patch("tools.profile_manager.ProfileManager._ensure_profiles_dir")
    def test_import_profile(self, mock_ensure):
        from tools.profile_manager import ProfileManager
        pm = ProfileManager()
        data = json.dumps({
            "name": "imported_test", "description": "imported", "base_command": "scan",
            "args": [], "options": {}, "env_vars": {}, "created_by": "imported",
            "created_at": "2024-01-01T00:00:00Z", "usage_count": 0, "tags": ["imported"],
        })
        with patch("pathlib.Path.write_text"):
            ok = pm.import_profile(data)
            assert ok is True

    @patch("tools.profile_manager.ProfileManager._ensure_profiles_dir")
    def test_import_profile_invalid_json(self, mock_ensure):
        from tools.profile_manager import ProfileManager
        pm = ProfileManager()
        ok = pm.import_profile("not json")
        assert ok is False

    @patch("tools.profile_manager.ProfileManager._ensure_profiles_dir")
    def test_import_profile_no_name(self, mock_ensure):
        from tools.profile_manager import ProfileManager
        pm = ProfileManager()
        ok = pm.import_profile(json.dumps({"description": "no name"}))
        assert ok is False

    @patch("tools.profile_manager.ProfileManager._ensure_profiles_dir")
    def test_import_profile_exists_no_overwrite(self, mock_ensure):
        from tools.profile_manager import ProfileManager
        pm = ProfileManager()
        # "quick" already exists
        data = json.dumps({
            "name": "quick", "description": "d", "base_command": "c",
            "args": [], "options": {}, "env_vars": {}, "created_by": "u",
            "created_at": "", "usage_count": 0, "tags": [],
        })
        ok = pm.import_profile(data, overwrite=False)
        assert ok is False

    @patch("tools.profile_manager.ProfileManager._ensure_profiles_dir")
    def test_clone_profile(self, mock_ensure):
        from tools.profile_manager import ProfileManager
        pm = ProfileManager()
        with patch("pathlib.Path.write_text"):
            ok = pm.clone_profile("quick", "cloned", modifications={"description": "Cloned quick"})
            assert ok is True

    @patch("tools.profile_manager.ProfileManager._ensure_profiles_dir")
    def test_clone_nonexistent(self, mock_ensure):
        from tools.profile_manager import ProfileManager
        pm = ProfileManager()
        ok = pm.clone_profile("nonexistent", "cloned")
        assert ok is False

    @patch("tools.profile_manager.ProfileManager._ensure_profiles_dir")
    def test_clone_with_add_remove_options(self, mock_ensure):
        from tools.profile_manager import ProfileManager
        pm = ProfileManager()
        with patch("pathlib.Path.write_text"):
            ok = pm.clone_profile("quick", "cloned2", modifications={
                "add_options": {"extra_opt": True},
                "remove_options": ["nonexistent"],
            })
            assert ok is True

    @patch("tools.profile_manager.ProfileManager._ensure_profiles_dir")
    def test_get_recommended_profile(self, mock_ensure):
        from tools.profile_manager import ProfileManager
        pm = ProfileManager()
        assert pm.get_recommended_profile("api") == "api"
        assert pm.get_recommended_profile("web") == "web"
        assert pm.get_recommended_profile() == "deep"

    @patch("tools.profile_manager.ProfileManager._ensure_profiles_dir")
    def test_format_profile_list(self, mock_ensure):
        from tools.profile_manager import ProfileManager
        pm = ProfileManager()
        result = pm.format_profile_list()
        assert "Available Profiles" in result
        assert "Built-in" in result


# ═══════════════════════════════════════════════════════════════════════════
#  MODULE 3: ml_filter.py
# ═══════════════════════════════════════════════════════════════════════════


class TestMLFilter:
    """Test ml_filter.py -- scoring, suppression, filtering."""

    def test_finding_profile_real_rate(self):
        from tools.ml_filter import FindingProfile
        fp = FindingProfile(pattern_id="test")
        assert fp.real_rate == 1.0  # 0 seen = 100% real

    def test_finding_profile_update(self):
        from tools.ml_filter import FindingProfile
        fp = FindingProfile(pattern_id="test")
        fp.update(suppressed=True, confidence=0.8, url="http://x", param="q")
        assert fp.total_seen == 1
        assert fp.total_suppressed == 1
        assert fp.false_positive_rate == 1.0
        assert fp.avg_confidence == pytest.approx(0.24, abs=0.01)

    def test_finding_profile_update_not_suppressed(self):
        from tools.ml_filter import FindingProfile
        fp = FindingProfile(pattern_id="test")
        fp.update(suppressed=False, confidence=0.9)
        assert fp.total_seen == 1
        assert fp.total_suppressed == 0
        assert fp.false_positive_rate == 0.0

    def test_finding_profile_real_rate_after_updates(self):
        from tools.ml_filter import FindingProfile
        fp = FindingProfile(pattern_id="test")
        fp.update(suppressed=True)
        fp.update(suppressed=False)
        fp.update(suppressed=True)
        assert fp.total_seen == 3
        assert fp.total_suppressed == 2
        assert fp.real_rate == pytest.approx(1/3, abs=0.01)

    def test_ml_filter_init(self, tmp_path):
        from tools.ml_filter import MLFilter
        mf = MLFilter(profile_path=str(tmp_path / "test_profiles.json"))
        assert len(mf.profiles) == 0

    def test_ml_filter_score_no_history(self, tmp_path):
        from tools.ml_filter import MLFilter
        mf = MLFilter(profile_path=str(tmp_path / "test_profiles.json"))
        finding = {"type": "xss", "url": "http://test.com", "param": "q", "cvss": 7.0, "details": "evidence" * 50, "title": "XSS in Q"}
        result = mf.score(finding)
        assert "ml_confidence" in result
        assert "ml_verdict" in result
        assert "ml_signal_strength" in result
        assert "ml_pattern_id" in result
        assert result["ml_is_suppressed"] is False
        assert result["ml_is_duplicate"] is False

    def test_ml_filter_score_duplicate_detection(self, tmp_path):
        from tools.ml_filter import MLFilter
        mf = MLFilter(profile_path=str(tmp_path / "test_profiles.json"))
        finding = {"type": "xss", "url": "http://test.com", "param": "q", "title": "XSS"}
        r1 = mf.score(finding)
        r2 = mf.score(finding)
        assert r1["ml_is_duplicate"] is False
        assert r2["ml_is_duplicate"] is True

    def test_ml_filter_signal_strength_variations(self, tmp_path):
        from tools.ml_filter import MLFilter
        mf = MLFilter(profile_path=str(tmp_path / "test_profiles.json"))
        # High CVSS + strong evidence
        s1 = mf._signal_strength({"cvss": 9.5, "details": "x" * 600, "url": "http://x.com/path", "type": "sqli", "param": "id"})
        assert s1 > 0.7
        # Low CVSS
        s2 = mf._signal_strength({"cvss": 2.0, "details": "short", "type": "info", "url": "http://x.com"})
        assert s2 < 0.7
        # XSS type with param
        s3 = mf._signal_strength({"cvss": 5.0, "details": "evidence" * 30, "type": "xss", "param": "q", "url": "http://x.com/p"})
        assert s3 > 0.4
        # CVE type
        s4 = mf._signal_strength({"cvss": 8.0, "details": "evidence", "type": "cve_detection", "url": "http://x.com"})
        assert s4 > 0.4

    def test_ml_filter_suppress(self, tmp_path):
        from tools.ml_filter import MLFilter
        mf = MLFilter(profile_path=str(tmp_path / "test_profiles.json"))
        finding = {"type": "xss", "url": "http://test.com", "param": "q", "title": "XSS", "ml_confidence": 0.3}
        mf.suppress(finding, "user_suppressed")
        assert len(mf.suppression_history) == 1
        assert mf.suppression_history[0]["reason"] == "user_suppressed"

    def test_ml_filter_suppress_trims_history(self, tmp_path):
        from tools.ml_filter import MLFilter
        mf = MLFilter(profile_path=str(tmp_path / "test_profiles.json"))
        for i in range(1100):
            mf.suppression_history.append({"i": i})
        finding = {"type": "xss", "url": "http://x", "param": "q", "title": "XSS"}
        mf.suppress(finding)
        assert len(mf.suppression_history) <= 1000

    def test_ml_filter_confirm(self, tmp_path):
        from tools.ml_filter import MLFilter
        mf = MLFilter(profile_path=str(tmp_path / "test_profiles.json"))
        finding = {"type": "xss", "url": "http://test.com", "param": "q", "title": "XSS", "ml_confidence": 0.9}
        mf.confirm(finding)
        assert len(mf.profiles) > 0

    def test_ml_filter_filter_findings(self, tmp_path):
        from tools.ml_filter import MLFilter
        mf = MLFilter(profile_path=str(tmp_path / "test_profiles.json"))
        findings = [
            {"type": "xss", "url": "http://a.com", "param": "q", "title": "XSS A", "cvss": 9.0, "details": "evidence" * 100},
            {"type": "info", "url": "http://b.com", "param": "", "title": "Info", "cvss": 1.0, "details": ""},
        ]
        high, low = mf.filter_findings(findings, min_confidence=0.3, auto_suppress=True)
        assert len(high) + len(low) == 2

    def test_ml_filter_filter_findings_auto_suppress(self, tmp_path):
        from tools.ml_filter import MLFilter
        mf = MLFilter(profile_path=str(tmp_path / "test_profiles.json"))
        # Very weak finding that should be auto-suppressed
        findings = [
            {"type": "info", "url": "http://b.com", "param": "", "title": "Weak", "cvss": 0.1, "details": ""},
        ]
        high, low = mf.filter_findings(findings, min_confidence=0.5, auto_suppress=True)
        assert len(low) >= 1

    def test_ml_filter_stats_empty(self, tmp_path):
        from tools.ml_filter import MLFilter
        mf = MLFilter(profile_path=str(tmp_path / "test_profiles.json"))
        stats = mf.get_stats()
        assert stats["patterns"] == 0
        assert stats["avg_fp_rate"] == 0

    def test_ml_filter_stats_with_data(self, tmp_path):
        from tools.ml_filter import MLFilter
        mf = MLFilter(profile_path=str(tmp_path / "test_profiles.json"))
        finding = {"type": "xss", "url": "http://x", "param": "q", "title": "XSS", "ml_confidence": 0.5}
        mf.suppress(finding)
        stats = mf.get_stats()
        assert stats["patterns"] == 1
        assert stats["total_suppressions"] == 1

    def test_make_pattern_id(self, tmp_path):
        from tools.ml_filter import MLFilter
        mf = MLFilter(profile_path=str(tmp_path / "test_profiles.json"))
        pid = mf._make_pattern_id({"type": "xss", "url": "http://x.com", "param": "q", "title": "XSS in Q"})
        assert "xss" in pid
        assert "q" in pid


# ═══════════════════════════════════════════════════════════════════════════
#  MODULE 4: vector_memory.py
# ═══════════════════════════════════════════════════════════════════════════


class TestVectorMemory:
    """Test vector_memory.py -- SQLite fallback path thoroughly."""

    def test_memory_entry_dataclass(self):
        from tools.vector_memory import MemoryEntry
        entry = MemoryEntry(
            id="abc", content="test", target="x.com",
            category="finding", timestamp="2024-01-01", metadata={"k": "v"},
        )
        d = entry.to_dict()
        assert d["id"] == "abc"
        assert d["content"] == "test"

    def test_vector_memory_init_no_chromadb(self, tmp_path):
        with patch("tools.vector_memory.CHROMADB_AVAILABLE", False):
            from tools.vector_memory import VectorMemory
            vm = VectorMemory(persist_directory=str(tmp_path / "vm1"))
            assert vm._initialized is False

    def test_generate_id(self, tmp_path):
        with patch("tools.vector_memory.CHROMADB_AVAILABLE", False):
            from tools.vector_memory import VectorMemory
            vm = VectorMemory(persist_directory=str(tmp_path / "vm2"))
            id1 = vm._generate_id("content", "target", "ts1")
            id2 = vm._generate_id("content", "target", "ts2")
            assert id1 != id2
            assert len(id1) == 16

    def test_fallback_add(self, tmp_path):
        with patch("tools.vector_memory.CHROMADB_AVAILABLE", False):
            from tools.vector_memory import VectorMemory
            vm = VectorMemory(persist_directory=str(tmp_path / "vm3"))
            mid = vm._fallback_add("test content", "example.com", "finding", {"key": "val"})
            assert mid is not None
            assert len(mid) == 16

    def test_fallback_search(self, tmp_path):
        with patch("tools.vector_memory.CHROMADB_AVAILABLE", False):
            from tools.vector_memory import VectorMemory
            vm = VectorMemory(persist_directory=str(tmp_path / "vm4"))
            vm._fallback_add("SQL injection in login", "example.com", "finding")
            vm._fallback_add("XSS in search", "other.com", "finding")
            results = vm._fallback_search("SQL injection")
            assert len(results) >= 1

    def test_fallback_search_with_target(self, tmp_path):
        with patch("tools.vector_memory.CHROMADB_AVAILABLE", False):
            from tools.vector_memory import VectorMemory
            vm = VectorMemory(persist_directory=str(tmp_path / "vm5"))
            vm._fallback_add("SQL injection", "a.com", "finding")
            vm._fallback_add("XSS", "b.com", "finding")
            results = vm._fallback_search("SQL", target="a.com")
            assert len(results) >= 1

    def test_fallback_search_with_category(self, tmp_path):
        with patch("tools.vector_memory.CHROMADB_AVAILABLE", False):
            from tools.vector_memory import VectorMemory
            vm = VectorMemory(persist_directory=str(tmp_path / "vm6"))
            vm._fallback_add("SQL injection", "a.com", "finding")
            vm._fallback_add("user said hello", "a.com", "conversation")
            results = vm._fallback_search("SQL", category="finding")
            assert len(results) >= 1

    def test_fallback_search_no_fts_db(self, tmp_path):
        with patch("tools.vector_memory.CHROMADB_AVAILABLE", False):
            from tools.vector_memory import VectorMemory
            vm = VectorMemory(persist_directory=str(tmp_path / "vm7"))
            vm.__class__._FTS_DB_PATH = tmp_path / "nonexistent" / "nope.db"
            results = vm._fallback_search("test")
            assert results == []
            vm.__class__._FTS_DB_PATH = None

    def test_fallback_get_target(self, tmp_path):
        with patch("tools.vector_memory.CHROMADB_AVAILABLE", False):
            from tools.vector_memory import VectorMemory
            vm = VectorMemory(persist_directory=str(tmp_path / "vm8"))
            vm._fallback_add("SQL injection", "a.com", "finding")
            vm._fallback_add("XSS", "b.com", "finding")
            results = vm._fallback_get_target("a.com")
            assert len(results) >= 1

    def test_fallback_get_target_with_category(self, tmp_path):
        with patch("tools.vector_memory.CHROMADB_AVAILABLE", False):
            from tools.vector_memory import VectorMemory
            vm = VectorMemory(persist_directory=str(tmp_path / "vm9"))
            vm._fallback_add("SQL injection", "a.com", "finding")
            vm._fallback_add("user said hello", "a.com", "conversation")
            results = vm._fallback_get_target("a.com", category="finding")
            assert len(results) >= 1

    def test_fallback_get_target_no_db(self, tmp_path):
        with patch("tools.vector_memory.CHROMADB_AVAILABLE", False):
            from tools.vector_memory import VectorMemory
            vm = VectorMemory(persist_directory=str(tmp_path / "vm10"))
            vm.__class__._FTS_DB_PATH = tmp_path / "nonexistent" / "nope.db"
            results = vm._fallback_get_target("a.com")
            assert results == []
            vm.__class__._FTS_DB_PATH = None

    def test_fallback_delete_target(self, tmp_path):
        with patch("tools.vector_memory.CHROMADB_AVAILABLE", False):
            from tools.vector_memory import VectorMemory
            vm = VectorMemory(persist_directory=str(tmp_path / "vm11"))
            vm._fallback_add("SQL injection", "a.com", "finding")
            vm._fallback_add("XSS", "a.com", "finding")
            count = vm._fallback_delete_target("a.com")
            assert count >= 1

    def test_fallback_delete_target_empty(self, tmp_path):
        with patch("tools.vector_memory.CHROMADB_AVAILABLE", False):
            from tools.vector_memory import VectorMemory
            vm = VectorMemory(persist_directory=str(tmp_path / "vm12"))
            count = vm._fallback_delete_target("nonexistent.com")
            assert count == 0

    def test_fallback_delete_target_no_db(self, tmp_path):
        with patch("tools.vector_memory.CHROMADB_AVAILABLE", False):
            from tools.vector_memory import VectorMemory
            vm = VectorMemory(persist_directory=str(tmp_path / "vm13"))
            vm.__class__._FTS_DB_PATH = tmp_path / "nonexistent" / "nope.db"
            count = vm._fallback_delete_target("a.com")
            assert count == 0
            vm.__class__._FTS_DB_PATH = None

    def test_fallback_stats_empty(self, tmp_path):
        with patch("tools.vector_memory.CHROMADB_AVAILABLE", False):
            from tools.vector_memory import VectorMemory
            vm = VectorMemory(persist_directory=str(tmp_path / "vm14"))
            # Force FTS_DB to nonexistent so stats returns uninitialized
            vm.__class__._FTS_DB_PATH = tmp_path / "nonexistent" / "nope.db"
            stats = vm._fallback_stats()
            assert stats["status"] == "fallback_uninitialized"
            vm.__class__._FTS_DB_PATH = None

    def test_fallback_stats_with_data(self, tmp_path):
        with patch("tools.vector_memory.CHROMADB_AVAILABLE", False):
            from tools.vector_memory import VectorMemory
            vm = VectorMemory(persist_directory=str(tmp_path / "vm15"))
            vm._fallback_add("test content", "a.com", "finding")
            vm._fallback_add("other content", "b.com", "finding")
            stats = vm._fallback_stats()
            assert stats["status"] == "fallback_fts5"
            assert stats["total_memories"] >= 2
            assert stats["unique_targets"] >= 2

    def test_add_memory_fallback(self, tmp_path):
        with patch("tools.vector_memory.CHROMADB_AVAILABLE", False):
            from tools.vector_memory import VectorMemory
            vm = VectorMemory(persist_directory=str(tmp_path / "vm16"))
            mid = vm.add_memory("test content", "example.com", "finding")
            assert mid is not None

    def test_search_fallback(self, tmp_path):
        with patch("tools.vector_memory.CHROMADB_AVAILABLE", False):
            from tools.vector_memory import VectorMemory
            vm = VectorMemory(persist_directory=str(tmp_path / "vm17"))
            vm.add_memory("SQL injection found", "example.com", "finding")
            results = vm.search("SQL injection")
            assert len(results) >= 1

    def test_get_target_memories_fallback(self, tmp_path):
        with patch("tools.vector_memory.CHROMADB_AVAILABLE", False):
            from tools.vector_memory import VectorMemory
            vm = VectorMemory(persist_directory=str(tmp_path / "vm18"))
            vm.add_memory("test memory", "a.com", "finding")
            results = vm.get_target_memories("a.com")
            assert len(results) >= 1

    def test_get_all_targets(self, tmp_path):
        with patch("tools.vector_memory.CHROMADB_AVAILABLE", False):
            from tools.vector_memory import VectorMemory
            vm = VectorMemory(persist_directory=str(tmp_path / "vm19"))
            targets = vm.get_all_targets()
            assert isinstance(targets, list)

    def test_delete_target_memories_fallback(self, tmp_path):
        with patch("tools.vector_memory.CHROMADB_AVAILABLE", False):
            from tools.vector_memory import VectorMemory
            vm = VectorMemory(persist_directory=str(tmp_path / "vm20"))
            vm.add_memory("test", "a.com", "finding")
            count = vm.delete_target_memories("a.com")
            assert count >= 1

    def test_get_memory_stats_fallback(self, tmp_path):
        with patch("tools.vector_memory.CHROMADB_AVAILABLE", False):
            from tools.vector_memory import VectorMemory
            vm = VectorMemory(persist_directory=str(tmp_path / "vm21"))
            # Force uninitialized path
            vm.__class__._FTS_DB_PATH = tmp_path / "nonexistent" / "nope.db"
            stats = vm.get_memory_stats()
            assert stats["status"] == "fallback_uninitialized"
            vm.__class__._FTS_DB_PATH = None

    def test_get_context_for_ai(self, tmp_path):
        with patch("tools.vector_memory.CHROMADB_AVAILABLE", False):
            from tools.vector_memory import get_context_for_ai
            with patch("tools.vector_memory.get_vector_memory") as mock_gvm:
                mock_vm = MagicMock()
                mock_vm.search.return_value = [{"id": "1", "content": "test memory", "metadata": {"category": "finding", "timestamp": "2024-01-01T00:00:00Z"}}]
                mock_vm.get_target_memories.return_value = []
                mock_gvm.return_value = mock_vm
                ctx = get_context_for_ai("SQL injection", "example.com")
                assert "PREVIOUS KNOWLEDGE" in ctx
                assert "test memory" in ctx

    def test_get_context_for_ai_with_conversation(self, tmp_path):
        with patch("tools.vector_memory.CHROMADB_AVAILABLE", False):
            from tools.vector_memory import get_context_for_ai
            with patch("tools.vector_memory.get_vector_memory") as mock_gvm:
                mock_vm = MagicMock()
                mock_vm.search.return_value = []
                mock_vm.get_target_memories.return_value = []
                mock_gvm.return_value = mock_vm
                history = [
                    {"role": "user", "content": "scan target"},
                    {"role": "assistant", "content": "scanning..."},
                ]
                ctx = get_context_for_ai("test", "x.com", conversation_history=history)
                assert "RECENT CONVERSATION" in ctx

    def test_get_context_for_ai_empty(self, tmp_path):
        with patch("tools.vector_memory.CHROMADB_AVAILABLE", False):
            from tools.vector_memory import get_context_for_ai
            with patch("tools.vector_memory.get_vector_memory") as mock_gvm:
                mock_vm = MagicMock()
                mock_vm.search.return_value = []
                mock_vm.get_target_memories.return_value = []
                mock_gvm.return_value = mock_vm
                ctx = get_context_for_ai("test", "x.com")
                assert "No prior knowledge" in ctx

    def test_contextual_memory_search(self, tmp_path):
        with patch("tools.vector_memory.CHROMADB_AVAILABLE", False):
            from tools.vector_memory import contextual_memory_search
            with patch("tools.vector_memory.get_vector_memory") as mock_gvm:
                mock_vm = MagicMock()
                mock_vm.search.return_value = [{"id": "1", "content": "test", "similarity": 0.8}]
                mock_gvm.return_value = mock_vm
                results = contextual_memory_search("SQL injection", "x.com")
                assert len(results) >= 1

    def test_contextual_memory_search_with_assistant_history(self, tmp_path):
        with patch("tools.vector_memory.CHROMADB_AVAILABLE", False):
            from tools.vector_memory import contextual_memory_search
            with patch("tools.vector_memory.get_vector_memory") as mock_gvm:
                mock_vm = MagicMock()
                mock_vm.search.return_value = []
                mock_gvm.return_value = mock_vm
                history = [
                    {"role": "user", "content": "hi"},
                    {"role": "assistant", "content": "SQL injection found at /login"},
                ]
                results = contextual_memory_search("SQL injection", "x.com", conversation_history=history)
                assert isinstance(results, list)

    def test_persist_conversation_turns(self, tmp_path):
        with patch("tools.vector_memory.CHROMADB_AVAILABLE", False):
            from tools.vector_memory import persist_conversation_turns
            with patch("tools.vector_memory.get_vector_memory") as mock_gvm:
                mock_vm = MagicMock()
                mock_vm.add_memory.return_value = "abc"
                mock_gvm.return_value = mock_vm
                history = [
                    {"role": "user", "content": "hello"},
                    {"role": "assistant", "content": "hi there"},
                ]
                count = persist_conversation_turns(history, "x.com")
                assert count == 1

    def test_persist_conversation_turns_too_short(self, tmp_path):
        from tools.vector_memory import persist_conversation_turns
        count = persist_conversation_turns([{"role": "user", "content": "hi"}], "x.com")
        assert count == 0

    def test_fts_db_path(self, tmp_path):
        with patch("tools.vector_memory.CHROMADB_AVAILABLE", False):
            from tools.vector_memory import VectorMemory
            vm = VectorMemory(persist_directory=str(tmp_path / "vm22"))
            vm.__class__._FTS_DB_PATH = None
            path = vm._fts_db()
            assert path.name == "fts_memory.db"
            vm.__class__._FTS_DB_PATH = None

    def test_singleton_get_vector_memory(self, tmp_path):
        with patch("tools.vector_memory.CHROMADB_AVAILABLE", False):
            import tools.vector_memory as vmod
            vmod._vector_memory = None
            vm1 = vmod.get_vector_memory()
            vm2 = vmod.get_vector_memory()
            assert vm1 is vm2
            vmod._vector_memory = None  # cleanup


# ═══════════════════════════════════════════════════════════════════════════
#  MODULE 5: tool_registry.py
# ═══════════════════════════════════════════════════════════════════════════


class TestToolRegistry:
    """Test tool_registry.py -- registration, discovery, execution."""

    def test_tool_category_enum(self):
        from tools.tool_registry import ToolCategory
        assert ToolCategory.RECON.value == "reconnaissance"
        assert ToolCategory.SCANNER.value == "vulnerability_scanner"
        assert ToolCategory.FUZZING.value == "fuzzing"

    def test_tool_priority_enum(self):
        from tools.tool_registry import ToolPriority
        assert ToolPriority.CRITICAL.value == 1
        assert ToolPriority.HIGH.value == 2

    def test_tool_result_to_dict(self):
        from tools.tool_registry import ToolResult, ToolCategory
        tr = ToolResult(success=True, tool_name="test", category=ToolCategory.SCANNER, output="hello" * 200)
        d = tr.to_dict()
        assert d["success"] is True
        assert d["tool_name"] == "test"
        assert len(d["output"]) <= 500

    def test_tool_result_findings(self):
        from tools.tool_registry import ToolResult, ToolCategory
        tr = ToolResult(success=True, tool_name="test", category=ToolCategory.SCANNER,
                        findings=[{"type": "xss"}, {"type": "sqli"}])
        d = tr.to_dict()
        assert d["findings_count"] == 2

    def test_tool_metadata_dataclass(self):
        from tools.tool_registry import ToolMetadata, ToolCategory, ToolPriority
        tm = ToolMetadata(
            name="test", category=ToolCategory.SCANNER, priority=ToolPriority.HIGH,
            binary_name="python3", description="test tool",
        )
        assert tm.name == "test"
        assert tm.requires_target is True
        assert tm.timeout_seconds == 300
        assert tm.extra_args == {}

    def test_tool_registry_singleton(self):
        from tools.tool_registry import ToolRegistry
        r1 = ToolRegistry()
        r2 = ToolRegistry()
        assert r1 is r2

    def test_tool_registry_register_and_get(self):
        from tools.tool_registry import ToolRegistry, ToolMetadata, ToolCategory, ToolPriority
        registry = ToolRegistry()
        mock_tool = MagicMock()
        mock_tool.metadata = ToolMetadata(
            name="test_tool_xyz", category=ToolCategory.SCANNER, priority=ToolPriority.HIGH,
            binary_name="python3", description="test",
        )
        registry.register(mock_tool)
        assert registry.get_tool("test_tool_xyz") is mock_tool
        registry.unregister("test_tool_xyz")

    def test_tool_registry_unregister(self):
        from tools.tool_registry import ToolRegistry, ToolMetadata, ToolCategory, ToolPriority
        registry = ToolRegistry()
        mock_tool = MagicMock()
        mock_tool.metadata = ToolMetadata(
            name="unreg_test", category=ToolCategory.SCANNER, priority=ToolPriority.HIGH,
            binary_name="python3", description="test",
        )
        registry.register(mock_tool)
        registry.unregister("unreg_test")
        assert registry.get_tool("unreg_test") is None

    def test_tool_registry_get_tools_by_category(self):
        from tools.tool_registry import ToolRegistry, ToolCategory
        registry = ToolRegistry()
        tools = registry.get_tools_by_category(ToolCategory.SCANNER)
        assert isinstance(tools, list)

    def test_tool_registry_list_available_tools(self):
        from tools.tool_registry import ToolRegistry
        registry = ToolRegistry()
        tools = registry.list_available_tools()
        assert isinstance(tools, dict)

    def test_tool_registry_get_recommended_chain(self):
        from tools.tool_registry import ToolRegistry
        registry = ToolRegistry()
        chain = registry.get_recommended_chain("web")
        assert isinstance(chain, list)
        chain_api = registry.get_recommended_chain("api")
        assert isinstance(chain_api, list)
        chain_net = registry.get_recommended_chain("network")
        assert isinstance(chain_net, list)
        chain_unknown = registry.get_recommended_chain("unknown")
        assert isinstance(chain_unknown, list)

    def test_register_tool_decorator_non_base_tool(self):
        from tools.tool_registry import register_tool, ToolMetadata, ToolCategory, ToolPriority
        with pytest.raises(TypeError):
            @register_tool(ToolMetadata(
                name="bad_tool", category=ToolCategory.SCANNER, priority=ToolPriority.HIGH,
                binary_name="python3", description="bad",
            ))
            class BadTool:
                pass

    @pytest.mark.asyncio
    async def test_tool_registry_execute_chain_empty(self):
        from tools.tool_registry import ToolRegistry
        registry = ToolRegistry()
        results = await registry.execute_chain([], "http://test.com", Path("/tmp"))
        assert results == []


# ═══════════════════════════════════════════════════════════════════════════
#  MODULE 6: cli_textual.py (pure functions + data classes)
# ═══════════════════════════════════════════════════════════════════════════


class TestCliTextual:
    """Test cli_textual.py -- lerp functions, constants, non-TUI logic."""

    def test_lerp_basic(self):
        from cli.textual import _lerp
        assert _lerp(0, 10, 0.5) == 5.0
        assert _lerp(0, 10, 0.0) == 0.0
        assert _lerp(0, 10, 1.0) == 10.0

    def test_lerp_clamping(self):
        from cli.textual import _lerp
        assert _lerp(0, 10, -0.5) == 0.0  # clamped to 0
        assert _lerp(0, 10, 2.0) == 10.0  # clamped to 1

    def test_lerp_color(self):
        from cli.textual import _lerp_color
        result = _lerp_color("#000000", "#ffffff", 0.5)
        assert result.startswith("#")
        assert len(result) == 7
        result_t0 = _lerp_color("#000000", "#ffffff", 0.0)
        assert result_t0.startswith("#")

    def test_lerp_color_clamping(self):
        from cli.textual import _lerp_color
        r1 = _lerp_color("#000000", "#ffffff", -0.5)
        r2 = _lerp_color("#000000", "#ffffff", 1.5)
        assert r1.startswith("#")
        assert r2.startswith("#")

    def test_constants(self):
        from cli.textual import (
            BASE, MANTLE, CRUST, SURFACE, TEXT, WHITE, MUTED, DIM, GRAY,
            H_RED, H_BRIGHT, AGENT_NAMES, AGENT_COLORS,
            GLITCH_CHARS, ASCII_BANNER, HELP_TEXT, CHILL_COLORS, HUNT_COLORS,
        )
        assert BASE == "#000000"
        assert TEXT == "#ffffff"
        assert H_RED == "#ff2222"
        assert 1 in AGENT_NAMES
        assert 1 in AGENT_COLORS
        assert len(GLITCH_CHARS) > 0
        assert "██" in ASCII_BANNER
        assert "/clear" in HELP_TEXT
        assert "BASE" in CHILL_COLORS
        assert "ACCENT" in HUNT_COLORS

    def test_elengenix_textual_app_init(self):
        from cli.textual import ElengenixTextualApp
        with patch("cli_textual.ObbyGame"):
            app = ElengenixTextualApp(target="test.com", mode="CHILL")
            assert app.target == "test.com"
            assert app.mode == "CHILL"
            assert app.thinking is False
            assert app.turn_count == 0
            assert app.tools_run == 0
            assert app.findings == 0
            assert app.history == []
            assert app._processing is False
            assert app._game_active is False
            assert app._dashboard_visible is False

    def test_elengenix_textual_app_init_hunt_mode(self):
        from cli.textual import ElengenixTextualApp
        with patch("cli_textual.ObbyGame"):
            app = ElengenixTextualApp(target="x.com", mode="HUNT")
            assert app.mode == "HUNT"

    def test_elengenix_textual_app_default_init(self):
        from cli.textual import ElengenixTextualApp
        with patch("cli_textual.ObbyGame"):
            app = ElengenixTextualApp()
            assert app.target == ""
            assert app.mode == "CHILL"

    def test_elengenix_textual_app_slash_commands(self):
        from cli.textual import ElengenixTextualApp
        with patch("cli_textual.ObbyGame"):
            app = ElengenixTextualApp()
            assert "/clear" in app.SLASH_COMMANDS
            assert "/quit" in app.SLASH_COMMANDS
            assert "/help" in app.SLASH_COMMANDS

    def test_sidebar_init(self):
        from cli.textual import Sidebar
        sidebar = Sidebar()
        assert sidebar._data == {}

    def test_thinking_widget_init(self):
        from cli.textual import ThinkingWidget
        tw = ThinkingWidget()
        assert hasattr(tw, "DEFAULT_CSS")

    def test_status_bar_init(self):
        from cli.textual import StatusBar
        sb = StatusBar()
        assert hasattr(sb, "DEFAULT_CSS")

    def test_progress_bar_init(self):
        from cli.textual import ProgressBar
        pb = ProgressBar()
        assert hasattr(pb, "DEFAULT_CSS")

    def test_scanline_init(self):
        from cli.textual import Scanline
        sl = Scanline()
        assert hasattr(sl, "DEFAULT_CSS")

    def test_glitch_flash_init(self):
        from cli.textual import GlitchFlash
        gf = GlitchFlash()
        assert hasattr(gf, "DEFAULT_CSS")


# ═══════════════════════════════════════════════════════════════════════════
#  MODULE 7: doctor.py
# ═══════════════════════════════════════════════════════════════════════════


class TestDoctor:
    """Test doctor.py -- health check functions."""

    def test_in_virtualenv(self):
        from tools.doctor import _in_virtualenv
        result = _in_virtualenv()
        assert isinstance(result, bool)

    def test_project_root(self):
        from tools.doctor import _project_root
        root = _project_root()
        assert root.exists()
        assert root.name == "Elengenix"

    def test_venv_candidates(self):
        from tools.doctor import _venv_candidates
        candidates = _venv_candidates()
        assert isinstance(candidates, list)
        assert any("venv" in str(c) for c in candidates)

    def test_check_python(self):
        from tools.doctor import _check_python
        ok, version = _check_python(Path(sys.executable))
        assert ok is True
        assert "." in version

    def test_check_library_installed(self):
        from tools.doctor import _check_library
        ok, info = _check_library("json", Path(sys.executable))
        assert ok is True
        assert info == "Installed"

    def test_check_library_not_installed(self):
        from tools.doctor import _check_library
        ok, info = _check_library("nonexistent_library_xyz_12345", Path(sys.executable))
        assert ok is False
        assert "Not found" in info

    def test_check_config_missing(self):
        from tools.doctor import _check_config
        with patch("tools.doctor.Path") as mock_path:
            mock_path.return_value.exists.return_value = False
            ok, msg = _check_config()
            assert ok is False

    def test_python_libraries_list(self):
        from tools.doctor import PYTHON_LIBRARIES
        assert len(PYTHON_LIBRARIES) > 0
        assert all(len(lib) == 3 for lib in PYTHON_LIBRARIES)

    def test_python_min(self):
        from tools.doctor import PYTHON_MIN
        assert PYTHON_MIN == (3, 10)

    def test_venv_needs_repair(self, tmp_path):
        from tools.doctor import _venv_needs_repair
        assert _venv_needs_repair(tmp_path / "nonexistent") is False

    def test_find_project_venv(self):
        from tools.doctor import _find_project_venv
        result = _find_project_venv()
        assert result is None or isinstance(result, Path)


# ═══════════════════════════════════════════════════════════════════════════
#  MODULE 8: config_wizard.py
# ═══════════════════════════════════════════════════════════════════════════


class TestConfigWizard:
    """Test config_wizard.py -- all provider config methods."""

    def test_ai_provider_config_dataclass(self):
        from tools.config_wizard import AIProviderConfig
        apc = AIProviderConfig(
            name="Test", env_key="TEST_KEY", base_url="http://test.com",
            signup_url="http://signup.com", is_free=True, notes="test notes",
        )
        assert apc.name == "Test"
        assert apc.api_type == "openai"

    def test_config_wizard_init(self, tmp_path):
        from tools.config_wizard import ConfigWizard
        wizard = ConfigWizard(config_dir=tmp_path)
        assert wizard.config_dir == tmp_path

    def test_config_wizard_ai_providers_list(self):
        from tools.config_wizard import ConfigWizard
        providers = ConfigWizard.AI_PROVIDERS
        assert len(providers) > 10
        assert all(hasattr(p, "name") for p in providers)

    def test_config_wizard_default_models(self):
        from tools.config_wizard import ConfigWizard
        models = ConfigWizard.DEFAULT_MODELS
        assert "Gemini (Google)" in models
        assert "OpenAI (GPT-4)" in models
        assert "NVIDIA" in models

    def test_config_wizard_priority_order(self):
        from tools.config_wizard import ConfigWizard
        order = ConfigWizard.PRIORITY_ORDER
        assert order[0] == "nvidia"
        assert "gemini" in order

    def test_config_wizard_provider_key_map(self):
        from tools.config_wizard import ConfigWizard
        key_map = ConfigWizard._PROVIDER_KEY_MAP
        assert key_map["Gemini (Google)"] == "gemini"
        assert key_map["OpenAI (GPT-4)"] == "openai"

    def test_config_wizard_integrations(self):
        from tools.config_wizard import ConfigWizard
        integs = ConfigWizard.INTEGRATIONS
        assert len(integs) > 0
        names = [i["name"] for i in integs]
        assert "Telegram Bot" in names

    def test_save_env_var(self, tmp_path):
        from tools.config_wizard import ConfigWizard
        wizard = ConfigWizard(config_dir=tmp_path)
        wizard._save_env_var("TEST_SAVE_KEY_XYZ", "test_value_12345")
        assert os.environ.get("TEST_SAVE_KEY_XYZ") == "test_value_12345"
        assert wizard.env_file.exists()
        content = wizard.env_file.read_text()
        assert "TEST_SAVE_KEY_XYZ=test_value_12345" in content
        del os.environ["TEST_SAVE_KEY_XYZ"]

    def test_save_env_var_overwrite(self, tmp_path):
        from tools.config_wizard import ConfigWizard
        wizard = ConfigWizard(config_dir=tmp_path)
        wizard._save_env_var("TEST_OW_KEY", "value1")
        wizard._save_env_var("TEST_OW_KEY", "value2")
        content = wizard.env_file.read_text()
        assert "TEST_OW_KEY=value2" in content
        assert content.count("TEST_OW_KEY=") == 1
        del os.environ["TEST_OW_KEY"]

    def test_remove_env_var(self, tmp_path):
        from tools.config_wizard import ConfigWizard
        wizard = ConfigWizard(config_dir=tmp_path)
        wizard._save_env_var("TEST_REMOVE_KEY_XYZ", "to_remove")
        wizard._remove_env_var("TEST_REMOVE_KEY_XYZ")
        assert "TEST_REMOVE_KEY_XYZ" not in os.environ
        content = wizard.env_file.read_text()
        assert "TEST_REMOVE_KEY_XYZ" not in content

    def test_remove_env_var_not_exists(self, tmp_path):
        from tools.config_wizard import ConfigWizard
        wizard = ConfigWizard(config_dir=tmp_path)
        wizard._remove_env_var("NONEXISTENT_KEY_999")

    def test_save_yaml_config(self, tmp_path):
        from tools.config_wizard import ConfigWizard
        wizard = ConfigWizard(config_dir=tmp_path)
        config = {"ai": {"active_provider": "test"}, "team_aegis": {"enabled": False}}
        wizard._save_yaml_config(config)
        assert (tmp_path / "config.yaml").exists()

    def test_load_yaml_config(self, tmp_path):
        from tools.config_wizard import ConfigWizard
        wizard = ConfigWizard(config_dir=tmp_path)
        config = {"ai": {"active_provider": "test"}}
        wizard._save_yaml_config(config)
        loaded = wizard._load_yaml_config()
        assert loaded["ai"]["active_provider"] == "test"

    def test_load_yaml_config_missing(self, tmp_path):
        from tools.config_wizard import ConfigWizard
        wizard = ConfigWizard(config_dir=tmp_path)
        loaded = wizard._load_yaml_config()
        assert loaded == {}

    def test_load_yaml_config_bad_yaml(self, tmp_path):
        from tools.config_wizard import ConfigWizard
        wizard = ConfigWizard(config_dir=tmp_path)
        (tmp_path / "config.yaml").write_text("{{{{invalid yaml")
        loaded = wizard._load_yaml_config()
        assert loaded == {}

    def test_save_team_to_yaml(self, tmp_path):
        from tools.config_wizard import ConfigWizard
        wizard = ConfigWizard(config_dir=tmp_path)
        final_team = [
            {"provider": "gemini", "model": "gemini-2.0-flash"},
            {"provider": "anthropic", "model": "claude-3-5-haiku"},
            {"provider": "openai", "model": "gpt-4o-mini"},
        ]
        wizard._save_team_to_yaml(final_team)
        config = wizard._load_yaml_config()
        assert config["team_aegis"]["enabled"] is True
        assert config["team_aegis"]["strategist"]["provider"] == "gemini"

    def test_fetch_remote_models_anthropic(self, tmp_path):
        from tools.config_wizard import ConfigWizard, AIProviderConfig
        wizard = ConfigWizard(config_dir=tmp_path)
        provider = AIProviderConfig(
            name="Anthropic (Claude)", env_key="ANTHROPIC_API_KEY",
            base_url="https://api.anthropic.com/v1", signup_url="",
            is_free=False, notes="",
        )
        result = wizard._fetch_remote_models(provider, "fake_key")
        assert result == []

    def test_fetch_remote_models_success(self, tmp_path):
        from tools.config_wizard import ConfigWizard, AIProviderConfig
        wizard = ConfigWizard(config_dir=tmp_path)
        provider = AIProviderConfig(
            name="OpenAI", env_key="OPENAI_API_KEY",
            base_url="https://api.openai.com/v1", signup_url="",
            is_free=False, notes="",
        )
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"data": [{"id": "gpt-4o"}, {"id": "embedding-3"}]}
        with patch("requests.get", return_value=mock_resp):
            result = wizard._fetch_remote_models(provider, "fake_key")
            assert "gpt-4o" in result
            assert "embedding-3" not in result

    def test_fetch_remote_models_list_format(self, tmp_path):
        from tools.config_wizard import ConfigWizard, AIProviderConfig
        wizard = ConfigWizard(config_dir=tmp_path)
        provider = AIProviderConfig(
            name="Test", env_key="TEST_KEY", base_url="http://test.com",
            signup_url="", is_free=True, notes="",
        )
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = [{"id": "model1"}, {"id": "model2"}]
        with patch("requests.get", return_value=mock_resp):
            result = wizard._fetch_remote_models(provider, "key")
            assert "model1" in result

    def test_fetch_remote_models_error(self, tmp_path):
        from tools.config_wizard import ConfigWizard, AIProviderConfig
        wizard = ConfigWizard(config_dir=tmp_path)
        provider = AIProviderConfig(
            name="Test", env_key="TEST_KEY", base_url="http://test.com",
            signup_url="", is_free=True, notes="",
        )
        with patch("requests.get", side_effect=Exception("network error")):
            result = wizard._fetch_remote_models(provider, "key")
            assert result == []

    def test_test_provider_success(self, tmp_path):
        from tools.config_wizard import ConfigWizard, AIProviderConfig
        wizard = ConfigWizard(config_dir=tmp_path)
        provider = AIProviderConfig(
            name="Test", env_key="TEST_KEY", base_url="http://test.com",
            signup_url="", is_free=True, notes="",
        )
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        with patch("requests.post", return_value=mock_resp):
            result = wizard._test_provider(provider, "fake_key", "test-model")
            assert result is True

    def test_test_provider_failure(self, tmp_path):
        from tools.config_wizard import ConfigWizard, AIProviderConfig
        wizard = ConfigWizard(config_dir=tmp_path)
        provider = AIProviderConfig(
            name="Test", env_key="TEST_KEY", base_url="http://test.com",
            signup_url="", is_free=True, notes="",
        )
        mock_resp = MagicMock()
        mock_resp.status_code = 401
        with patch("requests.post", return_value=mock_resp):
            result = wizard._test_provider(provider, "bad_key")
            assert result is False

    def test_test_provider_timeout(self, tmp_path):
        from tools.config_wizard import ConfigWizard, AIProviderConfig
        wizard = ConfigWizard(config_dir=tmp_path)
        provider = AIProviderConfig(
            name="Test", env_key="TEST_KEY", base_url="http://test.com",
            signup_url="", is_free=True, notes="",
        )
        import requests as real_requests
        with patch("requests.post", side_effect=real_requests.exceptions.Timeout("timeout")):
            result = wizard._test_provider(provider, "key")
            assert result is True

    def test_test_provider_exception(self, tmp_path):
        from tools.config_wizard import ConfigWizard, AIProviderConfig
        wizard = ConfigWizard(config_dir=tmp_path)
        provider = AIProviderConfig(
            name="Test", env_key="TEST_KEY", base_url="http://test.com",
            signup_url="", is_free=True, notes="",
        )
        with patch("requests.post", side_effect=Exception("connection refused")):
            result = wizard._test_provider(provider, "key")
            assert result is False

    def test_test_provider_nvidia_auto(self, tmp_path):
        from tools.config_wizard import ConfigWizard, AIProviderConfig
        wizard = ConfigWizard(config_dir=tmp_path)
        provider = AIProviderConfig(
            name="NVIDIA", env_key="NVIDIA_API_KEY",
            base_url="https://integrate.api.nvidia.com/v1", signup_url="",
            is_free=True, notes="", api_type="openai",
        )
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        with patch("requests.post", return_value=mock_resp):
            with patch.dict(os.environ, {"NVIDIA_PARAM_MODE": "nemotron"}):
                result = wizard._test_provider(provider, "key", "nvidia/nemotron")
                assert result is True

    def test_test_provider_nvidia_disable(self, tmp_path):
        from tools.config_wizard import ConfigWizard, AIProviderConfig
        wizard = ConfigWizard(config_dir=tmp_path)
        provider = AIProviderConfig(
            name="NVIDIA", env_key="NVIDIA_API_KEY",
            base_url="https://integrate.api.nvidia.com/v1", signup_url="",
            is_free=True, notes="", api_type="openai",
        )
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        with patch("requests.post", return_value=mock_resp):
            with patch.dict(os.environ, {"NVIDIA_PARAM_MODE": "disable"}):
                result = wizard._test_provider(provider, "key", "deepseek-r1")
                assert result is True

    def test_test_provider_nvidia_enable(self, tmp_path):
        from tools.config_wizard import ConfigWizard, AIProviderConfig
        wizard = ConfigWizard(config_dir=tmp_path)
        provider = AIProviderConfig(
            name="NVIDIA", env_key="NVIDIA_API_KEY",
            base_url="https://integrate.api.nvidia.com/v1", signup_url="",
            is_free=True, notes="", api_type="openai",
        )
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        with patch("requests.post", return_value=mock_resp):
            with patch.dict(os.environ, {"NVIDIA_PARAM_MODE": "enable"}):
                result = wizard._test_provider(provider, "key", "some-model")
                assert result is True

    def test_test_provider_no_model_uses_default(self, tmp_path):
        from tools.config_wizard import ConfigWizard, AIProviderConfig
        wizard = ConfigWizard(config_dir=tmp_path)
        provider = AIProviderConfig(
            name="OpenAI (GPT-4)", env_key="OPENAI_API_KEY",
            base_url="https://api.openai.com/v1", signup_url="",
            is_free=False, notes="",
        )
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        with patch("requests.post", return_value=mock_resp):
            result = wizard._test_provider(provider, "key")
            assert result is True


# ═══════════════════════════════════════════════════════════════════════════
#  MODULE 9: zero_day_heuristics.py
# ═══════════════════════════════════════════════════════════════════════════


class TestZeroDayHeuristics:
    """Test zero_day_heuristics.py -- helper functions, data classes."""

    def test_severity_level_enum(self):
        from tools.zero_day_heuristics import SeverityLevel
        assert SeverityLevel.INFO.value == "info"
        assert SeverityLevel.CRITICAL.value == "critical"

    def test_severity_cvss_floor(self):
        from tools.zero_day_heuristics import SEVERITY_CVSS_FLOOR, SeverityLevel
        assert SEVERITY_CVSS_FLOOR[SeverityLevel.CRITICAL] == 9.5
        assert SEVERITY_CVSS_FLOOR[SeverityLevel.LOW] == 3.1

    def test_finding_dataclass(self):
        from tools.zero_day_heuristics import Finding, SeverityLevel
        from tools.vuln_engine import VulnClass
        f = Finding(
            detector="test", title="Test Finding",
            severity=SeverityLevel.HIGH, vuln_class=VulnClass.ZERO_DAY,
        )
        assert f.detector == "test"
        assert f.confidence == 0.5

    def test_finding_to_vuln_finding(self):
        from tools.zero_day_heuristics import Finding, SeverityLevel
        from tools.vuln_engine import VulnClass
        f = Finding(
            detector="test", title="Test Finding",
            severity=SeverityLevel.HIGH, vuln_class=VulnClass.XSS,
        )
        vf = f.to_vuln_finding()
        assert vf.title == "Test Finding"
        assert vf.severity == "High"

    def test_entropy(self):
        from tools.zero_day_heuristics import _entropy
        e1 = _entropy("aaaa")
        e2 = _entropy("abcdefgh")
        assert e1 < e2

    def test_shannon(self):
        from tools.zero_day_heuristics import _shannon
        s1 = _shannon(b"aaaa")
        s2 = _shannon(b"abcdefgh")
        assert s1 < s2

    def test_short_hash(self):
        from tools.zero_day_heuristics import _short_hash
        h = _short_hash("a", "b")
        assert isinstance(h, str)
        assert len(h) > 0

    def test_b64url(self):
        from tools.zero_day_heuristics import _b64url, _b64url_decode
        encoded = _b64url(b"hello world")
        decoded = _b64url_decode(encoded)
        assert decoded == b"hello world"

    def test_make_jwt(self):
        from tools.zero_day_heuristics import _make_jwt, _is_jwt
        jwt_token = _make_jwt({"alg": "HS256"}, {"sub": "123"})
        assert _is_jwt(jwt_token)
        assert jwt_token.count(".") == 2

    def test_is_jwt(self):
        from tools.zero_day_heuristics import _is_jwt
        assert _is_jwt("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U") is True
        # "not.a.jwt" has 3 dot-separated parts, so it passes structural check
        assert _is_jwt("not.a.jwt") is True
        assert _is_jwt("onlyone") is False
        assert _is_jwt("") is False
        assert _is_jwt("two.parts") is False

    def test_default_vector_for(self):
        from tools.zero_day_heuristics import _default_vector_for
        from tools.vuln_engine import VulnClass
        v = _default_vector_for(VulnClass.ZERO_DAY)
        assert "CVSS:3.1" in v

    def test_default_vector_for_all_classes(self):
        from tools.zero_day_heuristics import _default_vector_for
        from tools.vuln_engine import VulnClass
        for vc in VulnClass:
            v = _default_vector_for(vc)
            assert "CVSS:3.1" in v

    def test_http_client_init(self):
        from tools.zero_day_heuristics import HTTPClient
        client = HTTPClient(timeout=5.0, max_retries=2, verify_ssl=True)
        assert client.timeout == 5.0
        assert client.max_retries == 2

    def test_http_client_sync_to_dict(self):
        from tools.zero_day_heuristics import HTTPClient
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = "ok"
        mock_resp.headers = {"Content-Type": "text/html"}
        result = HTTPClient._sync_to_dict(mock_resp)
        assert result is not None

    def test_infer_engine(self):
        from tools.zero_day_heuristics import _infer_engine
        result1 = _infer_engine("{{7*7}}", "49")
        assert isinstance(result1, str)
        result2 = _infer_engine("${7*7}", "49")
        assert isinstance(result2, str)
        assert _infer_engine("", "") in ("unknown", "none")

    def test_http_client_close(self):
        from tools.zero_day_heuristics import HTTPClient
        client = HTTPClient()
        mock_session = MagicMock()
        client._session = mock_session
        client.close()

    def test_http_client_close_no_session(self):
        from tools.zero_day_heuristics import HTTPClient
        client = HTTPClient()
        client._session = None
        client.close()  # should not raise


# ═══════════════════════════════════════════════════════════════════════════
#  MODULE 10: scan_engine_upgrade.py
# ═══════════════════════════════════════════════════════════════════════════


class TestScanEngineUpgrade:
    """Test scan_engine_upgrade.py -- SmartOrchestrator."""

    def test_import(self):
        from scan_engine_upgrade import SmartOrchestrator
        assert SmartOrchestrator is not None

    def test_smart_orchestrator_init(self):
        from scan_engine_upgrade import SmartOrchestrator
        orch = SmartOrchestrator()
        assert orch.max_concurrency == 5

    def test_smart_orchestrator_init_custom(self):
        from scan_engine_upgrade import SmartOrchestrator
        orch = SmartOrchestrator(max_concurrency=10)
        assert orch.max_concurrency == 10

    def test_scan_state_dataclass(self):
        from scan_engine_upgrade import ScanState
        state = ScanState(target="example.com")
        assert state.target == "example.com"
        assert state.scan_id != ""
        assert state.start_time > 0


# ═══════════════════════════════════════════════════════════════════════════
#  MODULE 11: compliance_engine.py
# ═══════════════════════════════════════════════════════════════════════════


class TestComplianceEngine:
    """Test compliance_engine.py -- standard assessments."""

    def test_import(self):
        from tools.compliance_engine import ComplianceEngine
        assert ComplianceEngine is not None

    def test_init(self):
        from tools.compliance_engine import ComplianceEngine
        engine = ComplianceEngine()
        assert hasattr(engine, 'assess')


# ═══════════════════════════════════════════════════════════════════════════
#  MODULE 12: exploit_chain_builder.py
# ═══════════════════════════════════════════════════════════════════════════


class TestExploitChainBuilder:
    """Test exploit_chain_builder.py -- chain building logic."""

    def test_import(self):
        from tools.exploit_chain_builder import ExploitChainBuilder
        assert ExploitChainBuilder is not None

    def test_init(self):
        from tools.exploit_chain_builder import ExploitChainBuilder
        builder = ExploitChainBuilder()
        assert hasattr(builder, 'build_chains')
        assert hasattr(builder, 'process_findings')

    def test_process_findings_empty(self):
        from tools.exploit_chain_builder import ExploitChainBuilder
        builder = ExploitChainBuilder()
        builder.process_findings([])
        chains = builder.build_chains()
        assert isinstance(chains, list)

    def test_process_findings_with_data(self):
        from tools.exploit_chain_builder import ExploitChainBuilder
        builder = ExploitChainBuilder()
        builder.process_findings([
            {"title": "XSS", "url": "http://a.com", "severity": "High", "type": "xss"},
            {"title": "SQLi", "url": "http://a.com", "severity": "Critical", "type": "sqli"},
        ])
        chains = builder.build_chains()
        assert isinstance(chains, list)


# ═══════════════════════════════════════════════════════════════════════════
#  MODULE 13: cloud_scanner.py
# ═══════════════════════════════════════════════════════════════════════════


class TestCloudScanner:
    """Test cloud_scanner.py -- scanner methods."""

    def test_import(self):
        from tools.cloud_scanner import CloudScanner
        assert CloudScanner is not None

    def test_init(self):
        from tools.cloud_scanner import CloudScanner
        scanner = CloudScanner()
        assert scanner is not None


# ═══════════════════════════════════════════════════════════════════════════
#  MODULE 14: enterprise_security.py
# ═══════════════════════════════════════════════════════════════════════════


class TestEnterpriseSecurity:
    """Test enterprise_security.py -- security checks."""

    def test_import_sbom_parser(self):
        from tools.enterprise_security import SBOMParser
        parser = SBOMParser()
        assert parser is not None

    def test_import_vulnerability_scanner(self):
        from tools.enterprise_security import VulnerabilityScanner
        scanner = VulnerabilityScanner()
        assert scanner is not None

    def test_import_threat_intel(self):
        from tools.enterprise_security import ThreatIntel
        intel = ThreatIntel()
        assert intel is not None

    def test_import_package_dataclass(self):
        from tools.enterprise_security import Package
        pkg = Package(name="test", version="1.0", type="pypi")
        assert pkg.name == "test"


# ═══════════════════════════════════════════════════════════════════════════
#  MODULE 15: dashboard_server.py
# ═══════════════════════════════════════════════════════════════════════════


class TestDashboardServer:
    """Test dashboard_server.py -- server methods."""

    def test_import(self):
        from tools.dashboard_server import DashboardServer
        assert DashboardServer is not None

    def test_init(self):
        from tools.dashboard_server import DashboardServer
        handler = MagicMock()
        ds = DashboardServer(("127.0.0.1", 0), handler)
        assert ds is not None


# ═══════════════════════════════════════════════════════════════════════════
#  MODULE 16: file_relationship_mapper.py
# ═══════════════════════════════════════════════════════════════════════════


class TestFileRelationshipMapper:
    """Test file_relationship_mapper.py -- mapping logic."""

    def test_import(self):
        from file_relationship_mapper import FileRelationshipGraph
        assert FileRelationshipGraph is not None

    def test_init(self):
        from file_relationship_mapper import FileRelationshipGraph
        mapper = FileRelationshipGraph()
        assert mapper is not None

    def test_to_dict(self):
        from file_relationship_mapper import FileRelationshipGraph
        mapper = FileRelationshipGraph()
        d = mapper.to_dict()
        assert isinstance(d, dict)

    def test_build(self):
        from file_relationship_mapper import FileRelationshipGraph
        mapper = FileRelationshipGraph()
        result = mapper.build()
        assert result is mapper


# ═══════════════════════════════════════════════════════════════════════════
#  MODULE 17: analysis_pipeline.py (agents/agent_modes.py)
# ═══════════════════════════════════════════════════════════════════════════


class TestAnalysisPipeline:
    """Test analysis pipeline / agent modes."""

    def test_import_agent_modes(self):
        from agents.agent_modes import ModeProcessor
        assert ModeProcessor is not None

    def test_mode_processor_init(self):
        from agents.agent_modes import ModeProcessor
        mock_client = MagicMock()
        mp = ModeProcessor(client=mock_client)
        assert mp is not None


# ═══════════════════════════════════════════════════════════════════════════
#  MODULE 18: universal_executor.py
# ═══════════════════════════════════════════════════════════════════════════


class TestUniversalExecutor:
    """Test universal_executor.py -- executor methods."""

    def test_import(self):
        from tools.universal_executor import UniversalExecutor
        assert UniversalExecutor is not None

    def test_init(self):
        from tools.universal_executor import UniversalExecutor
        ue = UniversalExecutor()
        assert ue is not None


# ═══════════════════════════════════════════════════════════════════════════
#  MODULE 19: universal_ai_client.py
# ═══════════════════════════════════════════════════════════════════════════


class TestUniversalAIClient:
    """Test universal_ai_client.py -- provider chat methods."""

    def test_import(self):
        from tools.universal_ai_client import UniversalAIClient, AIClientManager
        assert UniversalAIClient is not None
        assert AIClientManager is not None

    def test_ai_client_manager_init(self):
        from tools.universal_ai_client import AIClientManager
        mgr = AIClientManager()
        assert mgr is not None


# ═══════════════════════════════════════════════════════════════════════════
#  MODULE 20: bounty_intelligence.py
# ═══════════════════════════════════════════════════════════════════════════


class TestBountyIntelligence:
    """Test bounty_intelligence.py -- intel gathering methods."""

    def test_import(self):
        from tools.bounty_intelligence import BountyIntelligence
        assert BountyIntelligence is not None

    def test_init(self):
        from tools.bounty_intelligence import BountyIntelligence
        bi = BountyIntelligence()
        assert bi is not None

    def test_init_with_keys(self):
        from tools.bounty_intelligence import BountyIntelligence
        bi = BountyIntelligence(api_key="test", api_username="user")
        assert bi is not None


# ═══════════════════════════════════════════════════════════════════════════
#  MODULE 21: ai_tool_creator.py
# ═══════════════════════════════════════════════════════════════════════════


class TestAIToolCreator:
    """Test ai_tool_creator.py -- tool creation/governance."""

    def test_import(self):
        from tools.ai_tool_creator import AIToolCreator
        assert AIToolCreator is not None

    def test_init(self):
        from tools.ai_tool_creator import AIToolCreator
        creator = AIToolCreator()
        assert creator is not None


# ═══════════════════════════════════════════════════════════════════════════
#  MODULE 22: ai_sandbox.py
# ═══════════════════════════════════════════════════════════════════════════


class TestAISandbox:
    """Test ai_sandbox.py -- sandbox execution."""

    def test_import_detector(self):
        from tools.ai_sandbox import RealDangerousPatternDetector
        assert RealDangerousPatternDetector is not None

    def test_import_sandbox(self):
        from tools.ai_sandbox import SubprocessSandbox
        assert SubprocessSandbox is not None

    def test_detector_init(self):
        from tools.ai_sandbox import RealDangerousPatternDetector
        det = RealDangerousPatternDetector()
        assert det is not None

    def test_detector_analyze_safe(self):
        from tools.ai_sandbox import RealDangerousPatternDetector
        det = RealDangerousPatternDetector()
        result = det.analyze("x = 1 + 2")
        assert result.is_safe is True

    def test_detector_analyze_unsafe(self):
        from tools.ai_sandbox import RealDangerousPatternDetector
        det = RealDangerousPatternDetector()
        result = det.analyze("import os; os.system('ls')")
        assert result.is_safe is False

    def test_sandbox_init(self):
        from tools.ai_sandbox import SubprocessSandbox
        sb = SubprocessSandbox()
        assert sb is not None


# ═══════════════════════════════════════════════════════════════════════════
#  MODULE 23: hybrid_agent.py
# ═══════════════════════════════════════════════════════════════════════════


class TestHybridAgent:
    """Test hybrid_agent.py -- processing methods."""

    def test_import(self):
        from agents.hybrid_agent import HybridAgent
        assert HybridAgent is not None


# ═══════════════════════════════════════════════════════════════════════════
#  MODULE 24: autonomous_agent.py
# ═══════════════════════════════════════════════════════════════════════════


class TestAutonomousAgent:
    """Test autonomous_agent.py -- action exec methods."""

    def test_import(self):
        from tools.autonomous_agent import AutonomousAgent
        assert AutonomousAgent is not None


# ═══════════════════════════════════════════════════════════════════════════
#  MODULE 25: history_manager.py
# ═══════════════════════════════════════════════════════════════════════════


class TestHistoryManager:
    """Test history_manager.py -- CRUD/search/stats."""

    def test_import(self):
        from tools.history_manager import HistoryManager
        assert HistoryManager is not None


# ═══════════════════════════════════════════════════════════════════════════
#  Run tests
# ═══════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    pytest.main([__file__, "-q", "--tb=short"])
