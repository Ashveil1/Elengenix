"""tests/test_core_coverage.py

Comprehensive tests for core utility and infrastructure modules:
- tools/perf.py
- tools/token_manager.py
- tools/session_manager.py
- tools/vector_memory.py
- tools/user_memory.py
- tools/user_preferences.py
- tools/profile_manager.py
- tools/progress_display.py
- tools/universal_executor.py
- tools/universal_ai_client.py
- tools/overlay_menu.py
- tools/swarm_controller.py
- tools/multi_agent.py
- tools/soc_analyzer.py
- tools/threat_intel.py
"""

import sys
import asyncio
import json
import os
import tempfile
import time
import threading
from pathlib import Path
from unittest.mock import MagicMock, patch, AsyncMock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


# ═══════════════════════════════════════════════════════════════════════════
# tools/perf.py
# ═══════════════════════════════════════════════════════════════════════════


class TestSmartCache:
    def test_set_get_basic(self):
        from tools.perf import SmartCache

        cache = SmartCache(max_size=10, default_ttl=60)
        cache.set("k1", "v1")
        assert cache.get("k1") == "v1"

    def test_get_miss_returns_none(self):
        from tools.perf import SmartCache

        cache = SmartCache(max_size=10)
        assert cache.get("nonexistent") is None
        assert cache.misses == 1

    def test_ttl_expiry(self):
        from tools.perf import SmartCache

        cache = SmartCache(max_size=10, default_ttl=0.01)
        cache.set("k1", "v1")
        time.sleep(0.05)
        assert cache.get("k1") is None

    def test_lru_eviction(self):
        from tools.perf import SmartCache

        cache = SmartCache(max_size=2, default_ttl=60)
        cache.set("a", 1)
        cache.set("b", 2)
        cache.set("c", 3)  # evicts "a"
        assert cache.get("a") is None
        assert cache.get("c") == 3

    def test_invalidate_all(self):
        from tools.perf import SmartCache

        cache = SmartCache(max_size=10)
        cache.set("a", 1)
        cache.set("b", 2)
        count = cache.invalidate()
        assert count == 2
        assert cache.get("a") is None

    def test_invalidate_pattern(self):
        from tools.perf import SmartCache

        cache = SmartCache(max_size=10)
        cache.set("prefix_a", 1)
        cache.set("prefix_b", 2)
        cache.set("other", 3)
        count = cache.invalidate("prefix")
        assert count == 2
        assert cache.get("other") == 3

    def test_stats(self):
        from tools.perf import SmartCache

        cache = SmartCache(max_size=10)
        cache.set("a", 1)
        cache.get("a")
        cache.get("miss")
        s = cache.stats()
        assert s["size"] == 1
        assert s["hits"] == 1
        assert s["misses"] == 1
        assert s["max_size"] == 10

    def test_stats_empty(self):
        from tools.perf import SmartCache

        cache = SmartCache()
        s = cache.stats()
        assert s["hit_rate"] == 0

    def test_get_move_to_end(self):
        from tools.perf import SmartCache

        cache = SmartCache(max_size=2)
        cache.set("a", 1)
        cache.set("b", 2)
        cache.get("a")  # move "a" to end
        cache.set("c", 3)  # should evict "b" not "a"
        assert cache.get("a") == 1
        assert cache.get("b") is None


class TestCachedDecorator:
    def test_cached_decorator(self):
        from tools.perf import SmartCache, cached

        cache = SmartCache(max_size=10, default_ttl=60)
        call_count = 0

        @cached(cache)
        def expensive_fn(x):
            nonlocal call_count
            call_count += 1
            return x * 2

        assert expensive_fn(5) == 10
        assert call_count == 1
        assert expensive_fn(5) == 10  # cached
        assert call_count == 1

    def test_cached_none_not_stored(self):
        from tools.perf import SmartCache, cached

        cache = SmartCache(max_size=10)
        call_count = 0

        @cached(cache)
        def returns_none():
            nonlocal call_count
            call_count += 1
            return None

        returns_none()
        assert call_count == 1
        returns_none()
        assert call_count == 2  # None not cached, called again

    def test_cached_custom_key_fn(self):
        from tools.perf import SmartCache, cached

        cache = SmartCache(max_size=10)

        @cached(cache, key_fn=lambda x: f"custom_{x}")
        def fn(x):
            return x + 1

        fn(10)
        assert cache.get("custom_10") == 11


class TestTimer:
    def test_timer_context_manager(self):
        from tools.perf import Timer

        with Timer("test_op") as t:
            time.sleep(0.01)
        assert t.result is not None
        assert t.result.name == "test_op"
        assert t.result.duration_ms > 0

    def test_timer_duration_ms_property(self):
        from tools.perf import Timer

        t = Timer("test")
        assert t.duration_ms == 0.0  # no result yet
        with t:
            pass
        assert t.duration_ms > 0

    def test_timer_metadata(self):
        from tools.perf import Timer

        with Timer("test", metadata={"key": "val"}) as t:
            pass
        assert t.result.metadata == {"key": "val"}


class TestTimeitDecorator:
    def test_timeit(self):
        from tools.perf import timeit

        @timeit("multiply")
        def fn(x, y):
            return x * y

        result = fn(3, 4)
        assert result == 12


class TestAsyncBatcher:
    def test_run_all_basic(self):
        from tools.perf import AsyncBatcher

        async def main():
            batcher = AsyncBatcher(concurrency=5, timeout=10)

            async def work(x):
                return x * 2

            results = await batcher.run_all([work(i) for i in range(5)])
            assert len(results) == 5
            assert sorted(results) == [0, 2, 4, 6, 8]

        asyncio.run(main())

    def test_run_all_with_errors(self):
        from tools.perf import AsyncBatcher

        async def main():
            batcher = AsyncBatcher(concurrency=3, timeout=5)

            async def ok(x):
                return x

            async def fail(x):
                raise ValueError("boom")

            results = await batcher.run_all([ok(1), fail(99), ok(3)])
            assert results[0] == 1
            assert results[2] == 3

        asyncio.run(main())


class TestStreamingAggregator:
    def test_add_and_summary(self):
        from tools.perf import StreamingAggregator

        agg = StreamingAggregator()
        agg.add({"severity": "High", "cvss": 8.5})
        agg.add({"severity": "Low", "cvss": 2.0})
        s = agg.summary()
        assert s["total"] == 2
        assert s["risk_score"] == 8.5
        assert s["by_severity"]["High"] == 1

    def test_total_property(self):
        from tools.perf import StreamingAggregator

        agg = StreamingAggregator()
        assert agg.total == 0
        agg.add({"severity": "Critical"})
        assert agg.total == 1

    def test_duration_seconds(self):
        from tools.perf import StreamingAggregator

        agg = StreamingAggregator()
        time.sleep(0.01)
        assert agg.duration_seconds > 0

    def test_unknown_severity(self):
        from tools.perf import StreamingAggregator

        agg = StreamingAggregator()
        agg.add({"severity": "WeirdLevel"})
        assert agg.by_severity.get("WeirdLevel", 0) == 1


class TestFastHTTP:
    def test_init(self):
        from tools.perf import FastHTTP

        client = FastHTTP(timeout=5, max_connections=10)
        assert client.timeout == 5
        assert client.max_connections == 10

    def test_get_bad_url_returns_error(self):
        from tools.perf import FastHTTP

        client = FastHTTP(timeout=2, use_cache=False)
        result = client.get("http://127.0.0.1:1/nonexistent")
        assert result["status"] == 0
        assert "error" in result


# ═══════════════════════════════════════════════════════════════════════════
# tools/token_manager.py
# ═══════════════════════════════════════════════════════════════════════════


class TestTokenManager:
    @pytest.fixture
    def tm(self, tmp_path):
        from tools.token_manager import TokenManager, PROVIDER_CONFIGS

        db_path = tmp_path / "token_usage.db"
        with patch.object(
            TokenManager, "DB_PATH", db_path
        ):
            yield TokenManager(
                daily_budget_usd=100.0,
                monthly_budget_usd=500.0,
                provider_configs=PROVIDER_CONFIGS.copy(),
            )

    def test_calculate_cost_openai(self, tm):
        cost = tm.calculate_cost("openai", 1000000, 1000000)
        assert cost > 0
        assert cost == 30.0 + 60.0

    def test_calculate_cost_unknown_provider(self, tm):
        cost = tm.calculate_cost("unknown", 1000, 1000)
        assert cost == 0.0

    def test_calculate_cost_ollama_free(self, tm):
        cost = tm.calculate_cost("ollama", 1000000, 1000000)
        assert cost == 0.0

    def test_record_usage(self, tm):
        usage = tm.record_usage("openai", "gpt-4", 1000, 500, mission_id="m1")
        assert usage.provider == "openai"
        assert usage.cost_usd >= 0
        assert usage.mission_id == "m1"

    def test_get_status(self, tm):
        tm.record_usage("openai", "gpt-4", 10000, 5000)
        status = tm.get_status()
        assert status["daily_budget"] == 100.0
        assert status["monthly_budget"] == 500.0
        assert status["spent_today"] > 0

    def test_can_proceed_within_budget(self, tm):
        can, reason = tm.can_proceed(estimated_cost=0.01)
        assert can is True

    def test_can_proceed_exceeds_daily(self, tm):
        can, reason = tm.can_proceed(estimated_cost=200.0, check_daily=True, check_monthly=False)
        assert can is False
        assert "Daily" in reason

    def test_can_proceed_exceeds_monthly(self, tm):
        can, reason = tm.can_proceed(estimated_cost=600.0, check_daily=False, check_monthly=True)
        assert can is False
        assert "Monthly" in reason

    def test_check_alerts_no_alerts(self, tm):
        alerts = tm.check_alerts()
        assert alerts == []

    def test_check_alerts_50_percent(self, tm):
        # Spend ~50% of daily
        tm.record_usage("openai", "gpt-4", 1700000, 0)
        alerts = tm.check_alerts()
        assert any("50%" in a for a in alerts)

    def test_reset_alerts(self, tm):
        tm._alerted_thresholds.add("daily_50")
        tm.reset_alerts()
        assert len(tm._alerted_thresholds) == 0

    def test_should_pause_no(self, tm):
        should, reason = tm.should_pause()
        assert should is False

    def test_recommend_provider_free(self, tm):
        rec = tm.recommend_provider("openai")
        assert rec in ["ollama", "groq"]

    def test_recommend_provider_from_free(self, tm):
        rec = tm.recommend_provider("ollama")
        assert rec is None

    def test_get_mission_cost(self, tm):
        tm.record_usage("openai", "gpt-4", 1000, 500, mission_id="m1")
        cost = tm.get_mission_cost("m1")
        assert cost["total_tokens"] > 0
        assert cost["total_cost_usd"] > 0

    def test_format_status(self, tm):
        text = tm.format_status()
        assert "Token Usage Status" in text
        assert "Today" in text

    def test_get_usage_today(self, tm):
        tm.record_usage("openai", "gpt-4", 1000, 500)
        usage = tm.get_usage_today()
        assert "openai" in usage
        assert usage["openai"]["cost_usd"] > 0

    def test_get_usage_month(self, tm):
        tm.record_usage("openai", "gpt-4", 1000, 500)
        usage = tm.get_usage_month()
        assert "openai" in usage

    def test_zero_budget_can_proceed(self, tm):
        tm.daily_budget = 0
        can, reason = tm.can_proceed(estimated_cost=0.0)
        # With 0 budget, any cost should fail
        can2, reason2 = tm.can_proceed(estimated_cost=1.0)
        assert can2 is False

    def test_token_usage_dataclass(self):
        from tools.token_manager import TokenUsage

        u = TokenUsage(
            provider="openai", model="gpt-4", tokens_input=100, tokens_output=50, cost_usd=0.01
        )
        assert u.provider == "openai"
        assert u.timestamp is not None


# ═══════════════════════════════════════════════════════════════════════════
# tools/session_manager.py
# ═══════════════════════════════════════════════════════════════════════════


class TestSessionManager:
    @pytest.fixture
    def sm(self, tmp_path):
        from tools.session_manager import SessionManager

        return SessionManager(sessions_dir=tmp_path)

    def test_start_session(self, sm):
        name = sm.start_session(target="example.com")
        assert len(name) == 9
        assert sm.live.target == "example.com"

    def test_start_session_custom_name(self, sm):
        name = sm.start_session(name="mysession")
        assert name == "mysession"
        assert sm.live.name == "mysession"

    def test_update_turn(self, sm):
        sm.start_session()
        sm.update_turn(prompt_tokens=100, completion_tokens=50)
        assert sm.live.turn_count == 1
        assert sm.live.token_count == 150

    def test_save_and_resume(self, sm):
        sm.start_session(name="test1", target="a.com")
        sm.update_turn(10, 20)

        class FakeAgent:
            conversation_history = [{"role": "user", "content": "hello"}]

        agent = FakeAgent()
        assert sm.save_session(agent=agent) is True

        sm2 = sm  # reuse same manager
        result = sm2.resume_session("test1", agent)
        assert result is not None
        assert result["target"] == "a.com"
        assert len(result["turns"]) == 1

    def test_resume_nonexistent(self, sm):
        result = sm.resume_session("no_such_session")
        assert result is None

    def test_list_sessions(self, sm):
        sm.start_session(name="s1")
        sm.save_session()
        sessions = sm.list_sessions()
        assert len(sessions) == 1
        assert sessions[0].name == "s1"

    def test_delete_session(self, sm):
        sm.start_session(name="delme")
        sm.save_session()
        assert sm.delete_session("delme") is True
        assert sm.delete_session("delme") is False  # already gone

    def test_format_session_list_empty(self, sm):
        text = sm.format_session_list([])
        assert "No saved sessions" in text

    def test_format_session_list(self, sm):
        from tools.session_manager import SessionInfo

        info = SessionInfo(
            name="a", created_at="t", last_modified="t", target="x.com",
            turns=5, mode="auto", model="gpt-4", file_path="/tmp/a.json"
        )
        text = sm.format_session_list([info])
        assert "a" in text
        assert "x.com" in text

    def test_set_status(self, sm):
        sm.start_session()
        sm.set_status("busy")
        assert sm.live.status == "busy"

    def test_set_token_limit(self, sm):
        sm.start_session()
        sm.set_token_limit(64000)
        assert sm.live.token_limit == 64000

    def test_get_live_state(self, sm):
        sm.start_session(name="live")
        state = sm.get_live_state()
        assert state.name == "live"

    def test_session_path_sanitization(self, sm):
        path = sm._session_path("bad/name!@#")
        assert "bad_name___" in str(path)

    def test_save_session_auto_name(self, sm):
        sm.start_session()
        result = sm.save_session(name="")
        assert result is True


# ═══════════════════════════════════════════════════════════════════════════
# tools/vector_memory.py
# ═══════════════════════════════════════════════════════════════════════════


class TestVectorMemory:
    @pytest.fixture
    def vm(self, tmp_path):
        from tools.vector_memory import VectorMemory, _vector_memory
        import tools.vector_memory as mod

        old = mod._vector_memory
        mod._vector_memory = None
        v = VectorMemory(persist_directory=str(tmp_path))
        mod._vector_memory = v
        yield v
        mod._vector_memory = old

    def test_init_creates_dir(self, tmp_path):
        from tools.vector_memory import VectorMemory

        vp = tmp_path / "mem"
        v = VectorMemory(persist_directory=str(vp))
        assert vp.exists()

    def test_generate_id(self, vm):
        id1 = vm._generate_id("content", "target", "ts1")
        id2 = vm._generate_id("content", "target", "ts2")
        assert id1 != id2
        assert len(id1) == 16

    def test_add_and_search_fallback(self, vm):
        # Force fallback mode
        vm._initialized = False
        mid = vm.add_memory("SQL injection found", "example.com", "finding")
        assert mid is not None

        results = vm.search("SQL injection", target="example.com")
        assert len(results) >= 1
        assert "SQL injection" in results[0]["content"]

    def test_add_duplicate_fallback(self, vm):
        vm._initialized = False
        id1 = vm.add_memory("same content", "t.com", "general")
        id2 = vm.add_memory("same content", "t.com", "general")
        assert id1 == id2  # deduplication

    def test_fallback_get_target(self, vm):
        vm._initialized = False
        vm.add_memory("finding1", "t.com", "finding")
        vm.add_memory("finding2", "t.com", "info")
        results = vm._fallback_get_target("t.com")
        assert len(results) == 2

    def test_fallback_get_target_with_category(self, vm):
        vm._initialized = False
        vm.add_memory("finding1", "t.com", "finding")
        vm.add_memory("info1", "t.com", "info")
        results = vm._fallback_get_target("t.com", category="finding")
        assert len(results) == 1

    def test_fallback_delete_target(self, vm):
        vm._initialized = False
        vm.add_memory("data", "del.com", "general")
        count = vm._fallback_delete_target("del.com")
        assert count >= 1

    def test_fallback_stats(self, vm):
        vm._initialized = False
        vm.add_memory("stat", "s.com", "general")
        stats = vm._fallback_stats()
        assert stats["total_memories"] >= 1
        assert "s.com" in stats["targets"]

    def test_fallback_stats_no_db(self, vm):
        vm._initialized = False
        import tools.vector_memory as mod

        mod.VectorMemory._FTS_DB_PATH = tmp_path_foo = Path("/nonexistent/path/fts.db")
        stats = vm._fallback_stats()
        # No crash; may return error or count 0
        mod.VectorMemory._FTS_DB_PATH = None

    def test_memory_entry_to_dict(self):
        from tools.vector_memory import MemoryEntry

        e = MemoryEntry(
            id="abc", content="test", target="t.com",
            category="finding", timestamp="2024-01-01", metadata={"k": "v"}
        )
        d = e.to_dict()
        assert d["id"] == "abc"
        assert d["metadata"]["k"] == "v"

    def test_fallback_search_no_db(self, vm):
        vm._initialized = False
        vm.__class__._FTS_DB_PATH = Path("/no/such/db")
        results = vm._fallback_search("anything")
        vm.__class__._FTS_DB_PATH = None
        assert results == []

    def test_fallback_get_target_no_db(self, vm):
        vm._initialized = False
        vm.__class__._FTS_DB_PATH = Path("/no/such/db")
        results = vm._fallback_get_target("anything")
        vm.__class__._FTS_DB_PATH = None
        assert results == []

    def test_fallback_delete_target_no_db(self, vm):
        vm._initialized = False
        vm.__class__._FTS_DB_PATH = Path("/no/such/db")
        count = vm._fallback_delete_target("anything")
        vm.__class__._FTS_DB_PATH = None
        assert count == 0

    def test_search_with_category_fallback(self, vm):
        vm._initialized = False
        vm.add_memory("test content", "cat.com", "finding")
        results = vm._fallback_search("test", category="finding")
        assert len(results) >= 1

    def test_get_memory_stats_fallback(self, vm):
        vm._initialized = False
        stats = vm.get_memory_stats()
        assert "status" in stats

    def test_get_all_targets_uninitialized(self, vm):
        vm._initialized = False
        targets = vm.get_all_targets()
        assert targets == []


# ═══════════════════════════════════════════════════════════════════════════
# tools/user_memory.py
# ═══════════════════════════════════════════════════════════════════════════


class TestUserMemory:
    @pytest.fixture(autouse=True)
    def _patch_db(self, tmp_path):
        import tools.user_memory as mod

        self._orig_db_path = mod._DB_PATH
        mod._DB_PATH = tmp_path / "test_elengenix.db"
        mod.init_db()
        yield
        mod._DB_PATH = self._orig_db_path

    def test_set_get_preference(self):
        import tools.user_memory as mod

        mod.set_preference("name", "Alice")
        assert mod.get_preference("name") == "Alice"
        assert mod.get_preference("missing", "default") == "default"

    def test_get_all_preferences(self):
        import tools.user_memory as mod

        mod.set_preference("k1", "v1")
        mod.set_preference("k2", "v2")
        all_p = mod.get_all_preferences()
        assert all_p["k1"] == "v1"
        assert all_p["k2"] == "v2"

    def test_add_get_context(self):
        import tools.user_memory as mod

        mod.add_context("remember this", tags="important")
        ctx = mod.get_recent_context(limit=5)
        assert "remember this" in ctx

    def test_get_recent_context_empty(self):
        import tools.user_memory as mod

        ctx = mod.get_recent_context()
        assert ctx == ""

    def test_save_target_learning(self):
        import tools.user_memory as mod

        mod.save_target_learning("example.com", "found sqli", "vuln")
        summary = mod.get_target_summary("example.com")
        assert "SQLI" in summary.upper()

    def test_save_target_learning_empty(self):
        import tools.user_memory as mod

        mod.save_target_learning("", "")
        mod.save_target_learning("t", "")

    def test_get_target_summary_empty(self):
        import tools.user_memory as mod

        summary = mod.get_target_summary("no-such-target")
        assert summary == ""

    def test_prune_context(self):
        import tools.user_memory as mod

        for i in range(60):
            mod.add_context(f"item {i}")
        with mod._conn() as c:
            count = c.execute("SELECT COUNT(*) FROM context_snippets").fetchone()[0]
        assert count <= 50

    def test_extract_and_save_preferences_name(self):
        import tools.user_memory as mod

        saved = mod.extract_and_save_preferences("call me Alice")
        assert ("user_name", "alice") in saved

    def test_extract_and_save_preferences_language(self):
        import tools.user_memory as mod

        saved = mod.extract_and_save_preferences("reply in thai")
        assert ("language", "thai") in saved

    def test_extract_and_save_preferences_concise(self):
        import tools.user_memory as mod

        saved = mod.extract_and_save_preferences("be concise")
        assert ("response_style", "concise") in saved

    def test_build_user_context_block(self):
        import tools.user_memory as mod

        mod.set_preference("user_name", "Bob")
        block = mod.build_user_context_block()
        assert "Bob" in block
        assert "User & Session Context" in block

    def test_build_user_context_block_with_target(self):
        import tools.user_memory as mod

        mod.save_target_learning("example.com", "test learning", "recon")
        block = mod.build_user_context_block(target="example.com")
        assert "example.com" in block

    def test_build_user_context_block_empty(self):
        import tools.user_memory as mod

        block = mod.build_user_context_block()
        assert block == ""


# ═══════════════════════════════════════════════════════════════════════════
# tools/user_preferences.py
# ═══════════════════════════════════════════════════════════════════════════


class TestUserPreferences:
    @pytest.fixture(autouse=True)
    def _patch_db(self, tmp_path):
        import tools.user_preferences as mod

        self._orig = mod.DB_PATH
        mod.DB_PATH = tmp_path / "test_prefs.db"
        mod.init_db()
        yield
        mod.DB_PATH = self._orig

    def test_get_default_preferences(self):
        import tools.user_preferences as mod

        pref = mod.get_preferences(user_id=1)
        assert pref.user_id == 1
        assert pref.notifications_enabled is True
        assert pref.favorite_targets == []

    def test_save_and_get(self):
        import tools.user_preferences as mod

        pref = mod.UserPreferences(user_id=42, language="th", theme="cyber")
        mod.save_preferences(pref)
        loaded = mod.get_preferences(42)
        assert loaded.language == "th"
        assert loaded.theme == "cyber"

    def test_add_favorite_target(self):
        import tools.user_preferences as mod

        pref = mod.add_favorite_target(1, "example.com")
        assert "example.com" in pref.favorite_targets

    def test_add_duplicate_favorite(self):
        import tools.user_preferences as mod

        mod.add_favorite_target(1, "a.com")
        pref = mod.add_favorite_target(1, "a.com")
        assert pref.favorite_targets.count("a.com") == 1

    def test_remove_favorite_target(self):
        import tools.user_preferences as mod

        mod.add_favorite_target(1, "a.com")
        pref = mod.remove_favorite_target(1, "a.com")
        assert "a.com" not in pref.favorite_targets

    def test_remove_nonexistent_favorite(self):
        import tools.user_preferences as mod

        pref = mod.remove_favorite_target(1, "nope.com")
        assert "nope.com" not in pref.favorite_targets

    def test_toggle_notification(self):
        import tools.user_preferences as mod

        mod.toggle_notification(1, "findings", False)
        pref = mod.get_preferences(1)
        assert pref.notify_findings is False

    def test_toggle_all_notifications(self):
        import tools.user_preferences as mod

        mod.toggle_notification(1, "all", False)
        pref = mod.get_preferences(1)
        assert pref.notifications_enabled is False

    def test_toggle_unknown_type(self):
        import tools.user_preferences as mod

        pref = mod.toggle_notification(1, "nonexistent_type", False)
        # Should return unchanged pref
        assert pref.notifications_enabled is True

    def test_user_preferences_dataclass_defaults(self):
        from tools.user_preferences import UserPreferences

        p = UserPreferences(user_id=99)
        assert p.favorite_targets == []
        assert p.language == "en"


# ═══════════════════════════════════════════════════════════════════════════
# tools/profile_manager.py
# ═══════════════════════════════════════════════════════════════════════════


class TestProfileManager:
    @pytest.fixture
    def pm(self, tmp_path):
        from tools.profile_manager import ProfileManager

        with patch.object(ProfileManager, "PROFILES_DIR", tmp_path / "profiles"):
            yield ProfileManager()

    def test_init_loads_builtins(self, pm):
        assert "quick" in pm.profiles
        assert "deep" in pm.profiles
        assert "bounty" in pm.profiles

    def test_get_profile(self, pm):
        p = pm.get_profile("quick")
        assert p is not None
        assert p.base_command == "recon"

    def test_get_profile_missing(self, pm):
        assert pm.get_profile("nonexistent") is None

    def test_list_profiles(self, pm):
        profiles = pm.list_profiles()
        assert len(profiles) >= 7  # at least builtins

    def test_list_profiles_by_tag(self, pm):
        profiles = pm.list_profiles(category="api")
        assert any("api" in p.tags for p in profiles)

    def test_create_custom_profile(self, pm):
        ok = pm.create_profile("myprofile", "scan", description="Custom scan")
        assert ok is True
        assert "myprofile" in pm.profiles

    def test_create_override_builtin_fails(self, pm):
        ok = pm.create_profile("quick", "scan")
        assert ok is False

    def test_create_overwrite_existing(self, pm):
        pm.create_profile("custom1", "scan")
        ok = pm.create_profile("custom1", "recon")
        assert ok is True

    def test_delete_custom_profile(self, pm):
        pm.create_profile("deleteme", "scan")
        assert pm.delete_profile("deleteme") is True
        assert pm.get_profile("deleteme") is None

    def test_delete_builtin_fails(self, pm):
        assert pm.delete_profile("quick") is False

    def test_delete_nonexistent(self, pm):
        assert pm.delete_profile("no_such") is False

    def test_expand_profile(self, pm):
        result = pm.expand_profile("quick", target="example.com")
        assert result is not None
        cmd, args = result
        assert cmd == "recon"
        assert "example.com" in args

    def test_expand_profile_no_target(self, pm):
        result = pm.expand_profile("quick")
        assert result is not None

    def test_expand_profile_nonexistent(self, pm):
        assert pm.expand_profile("nope") is None

    def test_expand_profile_usage_count(self, pm):
        p = pm.get_profile("quick")
        assert p.usage_count == 0
        pm.expand_profile("quick")
        assert p.usage_count == 1

    def test_clone_profile(self, pm):
        ok = pm.clone_profile("quick", "quick_copy")
        assert ok is True
        assert "quick_copy" in pm.profiles

    def test_clone_profile_nonexistent(self, pm):
        ok = pm.clone_profile("nope", "nope2")
        assert ok is False

    def test_clone_with_modifications(self, pm):
        ok = pm.clone_profile("quick", "custom_q", modifications={
            "description": "Custom quick",
            "add_options": {"timeout": 30},
            "tags": ["custom"],
        })
        assert ok is True

    def test_export_profile(self, pm):
        data = pm.export_profile("quick")
        assert data is not None
        parsed = json.loads(data)
        assert parsed["name"] == "quick"

    def test_export_nonexistent(self, pm):
        assert pm.export_profile("nope") is None

    def test_import_profile(self, pm):
        data = pm.export_profile("quick")
        assert pm.import_profile(data, overwrite=True) is True

    def test_import_nonexistent_name(self, pm):
        assert pm.import_profile('{"bad": true}') is False

    def test_import_existing_no_overwrite(self, pm):
        data = pm.export_profile("quick")
        assert pm.import_profile(data, overwrite=False) is False

    def test_get_recommended_profile_api(self, pm):
        assert pm.get_recommended_profile("api") == "api"

    def test_get_recommended_profile_web(self, pm):
        assert pm.get_recommended_profile("web app") == "web"

    def test_get_recommended_profile_default(self, pm):
        assert pm.get_recommended_profile() == "deep"

    def test_format_profile_list(self, pm):
        text = pm.format_profile_list()
        assert "Available Profiles" in text
        assert "quick" in text


# ═══════════════════════════════════════════════════════════════════════════
# tools/progress_display.py
# ═══════════════════════════════════════════════════════════════════════════


class TestProgressDisplay:
    def test_scan_phase_duration(self):
        from tools.progress_display import ScanPhase

        phase = ScanPhase(id="p1", name="Recon", subtasks=["DNS"])
        assert phase.duration == 0.0

    def test_scan_phase_with_times(self):
        from tools.progress_display import ScanPhase

        phase = ScanPhase(id="p1", name="R", subtasks=[], start_time=100.0, end_time=105.0)
        assert phase.duration == 5.0

    def test_scan_phase_duration_running(self):
        from tools.progress_display import ScanPhase

        phase = ScanPhase(id="p1", name="R", subtasks=[], start_time=time.time() - 1)
        assert phase.duration > 0

    def test_progress_metrics(self):
        from tools.progress_display import ProgressMetrics, ScanPhase

        phases = {"a": ScanPhase("a", "A", [], progress=50.0)}
        m = ProgressMetrics(target="t.com", start_time=time.time() - 10, phases=phases)
        assert m.overall_progress == 50.0
        assert m.elapsed > 0

    def test_progress_metrics_empty_phases(self):
        from tools.progress_display import ProgressMetrics

        m = ProgressMetrics(target="t", start_time=time.time(), phases={})
        assert m.overall_progress == 0.0

    def test_progress_display_init(self):
        from tools.progress_display import ProgressDisplay

        pd = ProgressDisplay(target="test.com")
        assert pd.target == "test.com"

    def test_start_and_update(self, capsys):
        from tools.progress_display import ProgressDisplay, ScanPhase

        pd = ProgressDisplay(target="test.com", use_rich=False)
        phases = [ScanPhase("p1", "Phase 1", ["task1"])]
        pd.start(phases)
        pd.update("p1", 50.0, "halfway")
        assert pd.phases["p1"].progress == 50.0

    def test_complete_phase(self):
        from tools.progress_display import ProgressDisplay, ScanPhase

        pd = ProgressDisplay(target="t", use_rich=False)
        pd.start([ScanPhase("p1", "P", [])])
        pd.complete("p1", "done")
        assert pd.phases["p1"].status == "complete"
        assert pd.phases["p1"].result_summary == "done"

    def test_fail_phase(self):
        from tools.progress_display import ProgressDisplay, ScanPhase

        pd = ProgressDisplay(target="t", use_rich=False)
        pd.start([ScanPhase("p1", "P", [])])
        pd.fail("p1", "error occurred")
        assert pd.phases["p1"].status == "failed"
        assert "error" in pd.phases["p1"].result_summary

    def test_add_finding(self):
        from tools.progress_display import ProgressDisplay, ScanPhase

        pd = ProgressDisplay(target="t", use_rich=False)
        pd.start([ScanPhase("p1", "P", [])])
        pd.add_finding()
        assert pd.metrics.findings_count == 1

    def test_make_progress_bar(self):
        from tools.progress_display import ProgressDisplay

        pd = ProgressDisplay(target="t")
        bar = pd._make_progress_bar(50.0, width=10)
        assert "50.0%" in bar
        assert "#" in bar
        assert "." in bar

    def test_format_duration_seconds(self):
        from tools.progress_display import ProgressDisplay

        pd = ProgressDisplay(target="t")
        assert pd._format_duration(5.0) == "5.0s"

    def test_format_duration_minutes(self):
        from tools.progress_display import ProgressDisplay

        pd = ProgressDisplay(target="t")
        assert "m" in pd._format_duration(120)

    def test_format_duration_hours(self):
        from tools.progress_display import ProgressDisplay

        pd = ProgressDisplay(target="t")
        assert "h" in pd._format_duration(7200)

    def test_status_icons(self):
        from tools.progress_display import ProgressDisplay

        pd = ProgressDisplay(target="t")
        assert pd._get_status_icon("pending") == "o"
        assert pd._get_status_icon("running") == "x"
        assert pd._get_status_icon("complete") == ""

    def test_status_icons_ascii(self):
        from tools.progress_display import ProgressDisplay

        pd = ProgressDisplay(target="t")
        assert "[OK]" in pd._get_status_icon_ascii("complete")
        assert "[XX]" in pd._get_status_icon_ascii("failed")

    def test_update_to_100_auto_completes(self):
        from tools.progress_display import ProgressDisplay, ScanPhase

        pd = ProgressDisplay(target="t", use_rich=False)
        pd.start([ScanPhase("p1", "P", [])])
        pd.update("p1", 100.0)
        assert pd.phases["p1"].status == "complete"

    def test_update_pending_to_running(self):
        from tools.progress_display import ProgressDisplay, ScanPhase

        pd = ProgressDisplay(target="t", use_rich=False)
        pd.start([ScanPhase("p1", "P", [])])
        pd.update("p1", 10.0)
        assert pd.phases["p1"].status == "running"


class TestSpinner:
    def test_spinner_start_stop(self):
        from tools.progress_display import Spinner

        s = Spinner(message="test")
        s.start()
        time.sleep(0.05)
        s.stop("done")
        assert s._running is False


class TestCompactProgress:
    def test_compact_progress(self, capsys):
        from tools.progress_display import CompactProgress

        cp = CompactProgress(total=10, description="Testing")
        cp.update(5)
        assert cp.current == 5
        cp.finish()
        assert cp.current == 10


# ═══════════════════════════════════════════════════════════════════════════
# tools/universal_executor.py
# ═══════════════════════════════════════════════════════════════════════════


class TestFileEditor:
    @pytest.fixture
    def editor(self, tmp_path):
        from tools.universal_executor import FileEditor

        return FileEditor(base_dir=str(tmp_path))

    def test_read_file(self, editor, tmp_path):
        f = tmp_path / "test.txt"
        f.write_text("line1\nline2\nline3")
        result = editor.read_file(str(f))
        assert result.success is True
        assert "line1" in result.output

    def test_read_file_not_found(self, editor):
        result = editor.read_file("/nonexistent/path")
        assert result.success is False

    def test_read_file_sensitive(self, editor, tmp_path):
        f = tmp_path / ".env"
        f.write_text("SECRET=123")
        result = editor.read_file(str(f))
        assert result.success is False
        assert "denied" in result.error.lower()

    def test_write_file(self, editor, tmp_path):
        f = tmp_path / "new.txt"
        result = editor.write_file(str(f), "hello world")
        assert result.success is True
        assert f.read_text() == "hello world"

    def test_write_file_no_overwrite(self, editor, tmp_path):
        f = tmp_path / "existing.txt"
        f.write_text("old")
        result = editor.write_file(str(f), "new", overwrite=False)
        assert result.success is False

    def test_edit_file(self, editor, tmp_path):
        f = tmp_path / "edit.txt"
        f.write_text("hello world")
        result = editor.edit_file(str(f), "hello", "goodbye")
        assert result.success is True
        assert "goodbye" in f.read_text()

    def test_edit_file_not_found(self, editor):
        result = editor.edit_file("/no/such/file", "a", "b")
        assert result.success is False

    def test_edit_file_string_not_found(self, editor, tmp_path):
        f = tmp_path / "e.txt"
        f.write_text("hello")
        result = editor.edit_file(str(f), "nonexistent", "x")
        assert result.success is False
        assert "not found" in result.error.lower()

    def test_edit_file_multiple_occurrences(self, editor, tmp_path):
        f = tmp_path / "e.txt"
        f.write_text("aaa bbb aaa")
        result = editor.edit_file(str(f), "aaa", "xxx")
        assert result.success is False
        assert "2" in result.error

    def test_search_in_file(self, editor, tmp_path):
        f = tmp_path / "search.txt"
        f.write_text("line1 foo\nline2 bar\nline3 foo")
        result = editor.search_in_file(str(f), "foo")
        assert result.success is True
        assert "2 matches" in result.output

    def test_search_in_file_no_match(self, editor, tmp_path):
        f = tmp_path / "search.txt"
        f.write_text("hello world")
        result = editor.search_in_file(str(f), "xyz")
        assert result.success is True
        assert "No matches" in result.output

    def test_list_directory(self, editor, tmp_path):
        (tmp_path / "file1.txt").write_text("a")
        (tmp_path / "file2.txt").write_text("bb")
        result = editor.list_directory(str(tmp_path))
        assert result.success is True
        assert "file1" in result.output

    def test_list_not_a_dir(self, editor, tmp_path):
        f = tmp_path / "file.txt"
        f.write_text("x")
        result = editor.list_directory(str(f))
        assert result.success is False

    def test_validate_path_outside_base(self, editor):
        result = editor._validate_path("/etc/passwd")
        assert result is None


class TestPackageManager:
    def test_unknown_manager(self):
        from tools.universal_executor import PackageManager

        pm = PackageManager()
        result = pm.execute("nonexistent", "install", "pkg")
        assert result.success is False
        assert "Unknown" in result.error

    def test_unknown_action(self):
        from tools.universal_executor import PackageManager

        pm = PackageManager()
        result = pm.execute("pip", "nonexistent_action", "pkg")
        assert result.success is False
        assert "not supported" in result.error

    def test_pip_list(self):
        from tools.universal_executor import PackageManager

        pm = PackageManager()
        result = pm.execute("pip", "list")
        assert result.success is True


class TestUniversalExecutor:
    @pytest.fixture
    def executor(self, tmp_path):
        from tools.universal_executor import UniversalExecutor

        return UniversalExecutor(base_dir=str(tmp_path))

    def test_execute_shell_echo(self, executor):
        result = executor.execute_shell("echo hello")
        assert result.success is True
        assert "hello" in result.output

    def test_execute_shell_empty(self, executor):
        result = executor.execute_shell("")
        assert result.success is False

    def test_execute_action_read_file(self, executor, tmp_path):
        f = tmp_path / "test.txt"
        f.write_text("content here")
        result = executor.execute_action({
            "type": "read_file",
            "params": {"path": str(f)}
        })
        assert result.success is True

    def test_execute_action_write_file(self, executor, tmp_path):
        f = tmp_path / "out.txt"
        result = executor.execute_action({
            "type": "write_file",
            "params": {"path": str(f), "content": "data"}
        })
        assert result.success is True

    def test_execute_action_edit_file(self, executor, tmp_path):
        f = tmp_path / "edit.txt"
        f.write_text("old text")
        result = executor.execute_action({
            "type": "edit_file",
            "params": {"path": str(f), "old_string": "old text", "new_string": "new text"}
        })
        assert result.success is True

    def test_execute_action_search_file(self, executor, tmp_path):
        f = tmp_path / "s.txt"
        f.write_text("line1 pattern\nline2 other")
        result = executor.execute_action({
            "type": "search_file",
            "params": {"path": str(f), "pattern": "pattern"}
        })
        assert result.success is True

    def test_execute_action_list_dir(self, executor, tmp_path):
        result = executor.execute_action({
            "type": "list_dir",
            "params": {"path": str(tmp_path)}
        })
        assert result.success is True

    def test_execute_action_unknown_type(self, executor):
        result = executor.execute_action({"type": "unknown_thing", "params": {}})
        assert result.success is False

    def test_execute_action_package(self, executor):
        result = executor.execute_action({
            "type": "package",
            "params": {"manager": "pip", "action": "list"}
        })
        assert result.success is True

    def test_get_capabilities(self, executor):
        caps = executor.get_capabilities()
        assert "read_file" in caps
        assert "shell" in caps

    def test_is_safe_command(self, executor):
        safe, _ = executor.is_safe_command("echo hello")
        assert safe is True

    def test_is_safe_command_empty(self, executor):
        safe, reason = executor.is_safe_command("")
        assert safe is False

    def test_execute_shell_with_cwd(self, executor, tmp_path):
        result = executor.execute_shell("pwd", cwd=str(tmp_path))
        assert str(tmp_path) in result.output


# ═══════════════════════════════════════════════════════════════════════════
# tools/universal_ai_client.py
# ═══════════════════════════════════════════════════════════════════════════


class TestAIMessage:
    def test_creation(self):
        from tools.universal_ai_client import AIMessage

        m = AIMessage(role="user", content="hello")
        assert m.role == "user"
        assert m.metadata is None

    def test_with_metadata(self):
        from tools.universal_ai_client import AIMessage

        m = AIMessage(role="assistant", content="hi", metadata={"k": "v"})
        assert m.metadata["k"] == "v"


class TestAIResponse:
    def test_creation(self):
        from tools.universal_ai_client import AIResponse

        r = AIResponse(content="ok", model="m", usage={"total_tokens": 10})
        assert r.content == "ok"
        assert r.tool_calls is None


class TestToolCall:
    def test_creation(self):
        from tools.universal_ai_client import ToolCall

        tc = ToolCall(id="1", name="run_shell", arguments={"command": "echo"})
        assert tc.name == "run_shell"


class TestUniversalAIClient:
    def test_init_ollama(self):
        from tools.universal_ai_client import UniversalAIClient

        client = UniversalAIClient(provider="ollama")
        assert client.provider == "ollama"
        assert client.base_url == "http://localhost:11434/v1"

    def test_init_custom(self):
        from tools.universal_ai_client import UniversalAIClient

        client = UniversalAIClient(
            provider="custom",
            base_url="http://localhost:8080/v1",
            api_key="test"
        )
        assert client.base_url == "http://localhost:8080/v1"

    def test_is_available_no_key(self):
        from tools.universal_ai_client import UniversalAIClient

        client = UniversalAIClient(
            provider="custom",
            base_url="",
            api_key=""
        )
        assert client.is_available() is False

    def test_get_status(self):
        from tools.universal_ai_client import UniversalAIClient

        client = UniversalAIClient(provider="ollama")
        status = client.get_status()
        assert "provider" in status
        assert "model" in status

    def test_simple_chat_with_mock(self):
        from tools.universal_ai_client import UniversalAIClient

        client = UniversalAIClient(provider="ollama")
        with patch.object(client, "chat") as mock_chat:
            mock_chat.return_value = MagicMock(content="test response")
            result = client.simple_chat("hello", system_prompt="be helpful")
            assert result == "test response"

    def test_provider_configs_exist(self):
        from tools.universal_ai_client import UniversalAIClient

        assert "openai" in UniversalAIClient.PROVIDER_CONFIGS
        assert "gemini" in UniversalAIClient.PROVIDER_CONFIGS
        assert "anthropic" in UniversalAIClient.PROVIDER_CONFIGS
        assert "ollama" in UniversalAIClient.PROVIDER_CONFIGS


class TestAIClientManager:
    def test_init_with_preferred_order(self):
        from tools.universal_ai_client import AIClientManager

        mgr = AIClientManager(preferred_order=["ollama", "groq"])
        assert mgr.preferred_order == ["ollama", "groq"]

    def test_get_active_provider(self):
        from tools.universal_ai_client import AIClientManager

        mgr = AIClientManager(preferred_order=["ollama"])
        provider = mgr.get_active_provider()
        assert provider in ("ollama", "none")

    def test_chat_no_providers_raises(self):
        from tools.universal_ai_client import AIClientManager, AIMessage

        mgr = AIClientManager(preferred_order=[])
        with pytest.raises(RuntimeError):
            mgr.chat([AIMessage(role="user", content="hi")])


class TestFormatAiStatus:
    def test_format(self):
        from tools.universal_ai_client import format_ai_status

        status = {
            "provider": "ollama",
            "base_url": "http://localhost:11434/v1",
            "model": "llama3",
            "has_api_key": False,
            "available": True,
        }
        text = format_ai_status(status)
        assert "ollama" in text
        assert "llama3" in text


# ═══════════════════════════════════════════════════════════════════════════
# tools/overlay_menu.py
# ═══════════════════════════════════════════════════════════════════════════


class TestSettingsOverlay:
    @pytest.fixture
    def overlay(self):
        from tools.overlay_menu import SettingsOverlay

        agent = MagicMock()
        console = MagicMock()
        console.width = 80
        return SettingsOverlay(agent, console, target="test.com")

    def test_init(self, overlay):
        assert overlay.target == "test.com"
        assert overlay._current_layer == "main"

    def test_reset(self, overlay):
        overlay._current_layer = "some_layer"
        overlay.reset()
        assert overlay._current_layer == "main"

    def test_handle_char_arrow_up(self, overlay):
        overlay._items = [{"id": "a"}, {"id": "b"}, {"id": "c"}]
        overlay._selected_idx = 2
        overlay.handle_char("\x1b[A")
        assert overlay._selected_idx == 1

    def test_handle_char_arrow_down(self, overlay):
        overlay._items = [{"id": "a"}, {"id": "b"}, {"id": "c"}]
        overlay._selected_idx = 0
        overlay.handle_char("\x1b[B")
        assert overlay._selected_idx == 1

    def test_handle_char_q_exits(self, overlay):
        assert overlay.handle_char("q") == "exit"

    def test_handle_char_b_exits_main(self, overlay):
        assert overlay.handle_char("b") == "exit"

    def test_handle_char_b_goes_back(self, overlay):
        overlay._current_layer = "sessions"
        overlay.handle_char("b")
        assert overlay._current_layer == "main"

    def test_handle_char_enter_main(self, overlay):
        result = overlay.handle_char("\r")
        # Should navigate or return something
        assert result is None or isinstance(result, str)

    def test_render(self, overlay):
        panel = overlay.render()
        assert panel is not None

    def test_adjust_scroll(self, overlay):
        overlay._items = [{"id": str(i)} for i in range(20)]
        overlay._selected_idx = 19
        overlay._adjust_scroll()
        assert overlay._scroll_offset >= 0

    def test_get_title(self, overlay):
        title = overlay._get_title()
        assert "SETTINGS" in title

    def test_build_main_items(self, overlay):
        items = overlay._build_main_items()
        assert len(items) > 5

    def test_build_provider_items(self, overlay):
        overlay._current_layer = "provider_select"
        items = overlay._build_provider_items()
        assert len(items) > 0

    def test_build_api_key_items(self, overlay):
        overlay._current_layer = "api_keys"
        items = overlay._build_api_key_items()
        assert len(items) > 0

    def test_build_rate_limit_items(self, overlay):
        overlay._current_layer = "rate_limits"
        items = overlay._build_rate_limit_items()
        assert len(items) > 5

    def test_build_mode_items(self, overlay):
        overlay._current_layer = "mode_settings"
        items = overlay._build_mode_items()
        assert any("Scan" in i.get("label", "") for i in items)

    def test_go_back_from_main(self, overlay):
        result = overlay._go_back()
        assert result == "exit"

    def test_get_cached_models_default(self, overlay):
        models = overlay._get_cached_models("unknown_provider")
        assert models == ["(Not fetched)"]


# ═══════════════════════════════════════════════════════════════════════════
# tools/swarm_controller.py
# ═══════════════════════════════════════════════════════════════════════════


class TestSwarmMissionTracker:
    def test_add_target(self):
        from tools.swarm_controller import SwarmMissionTracker, SwarmTarget

        tracker = SwarmMissionTracker()
        t = SwarmTarget(target_id="t1", target_url="http://a.com", mission_id="m1")
        tracker.add_target(t)
        assert "t1" in tracker.targets

    def test_update_progress(self):
        from tools.swarm_controller import SwarmMissionTracker, SwarmTarget

        tracker = SwarmMissionTracker()
        t = SwarmTarget(target_id="t1", target_url="http://a.com", mission_id="m1")
        tracker.add_target(t)
        tracker.update_progress("t1", 50.0)
        assert tracker.targets["t1"].progress == 50.0

    def test_update_status(self):
        from tools.swarm_controller import SwarmMissionTracker, SwarmTarget

        tracker = SwarmMissionTracker()
        t = SwarmTarget(target_id="t1", target_url="http://a.com", mission_id="m1")
        tracker.add_target(t)
        tracker.update_status("t1", "running")
        assert tracker.targets["t1"].status == "running"
        assert tracker.targets["t1"].start_time is not None

    def test_update_status_with_error(self):
        from tools.swarm_controller import SwarmMissionTracker, SwarmTarget

        tracker = SwarmMissionTracker()
        t = SwarmTarget(target_id="t1", target_url="http://a.com", mission_id="m1")
        tracker.add_target(t)
        tracker.update_status("t1", "failed", "boom")
        assert tracker.targets["t1"].error_message == "boom"

    def test_update_findings(self):
        from tools.swarm_controller import SwarmMissionTracker, SwarmTarget

        tracker = SwarmMissionTracker()
        t = SwarmTarget(target_id="t1", target_url="http://a.com", mission_id="m1")
        tracker.add_target(t)
        tracker.update_findings("t1", 5)
        assert tracker.targets["t1"].findings_count == 5

    def test_get_summary(self):
        from tools.swarm_controller import SwarmMissionTracker, SwarmTarget

        tracker = SwarmMissionTracker()
        tracker.add_target(SwarmTarget("t1", "http://a.com", "m1"))
        tracker.add_target(SwarmTarget("t2", "http://b.com", "m2"))
        s = tracker.get_summary()
        assert s["total_targets"] == 2
        assert s["pending"] == 2

    def test_format_progress_table(self):
        from tools.swarm_controller import SwarmMissionTracker, SwarmTarget

        tracker = SwarmMissionTracker()
        tracker.add_target(SwarmTarget("t1", "http://a.com", "m1", priority=1))
        table = tracker.format_progress_table()
        assert "a.com" in table


class TestSwarmController:
    @pytest.fixture
    def ctrl(self, tmp_path):
        from tools.swarm_controller import SwarmController, SwarmConfig

        config = SwarmConfig(output_dir=tmp_path / "reports", max_concurrent=1)
        return SwarmController(config)

    def test_load_targets_from_list(self, ctrl):
        targets = ctrl.load_targets_from_list(["http://a.com", "http://b.com"])
        assert len(targets) == 2
        assert targets[0].target_url == "http://a.com"

    def test_load_targets_empty_string_filtered(self, ctrl):
        targets = ctrl.load_targets_from_list(["", "  ", "http://a.com"])
        assert len(targets) == 1

    def test_load_targets_from_file(self, ctrl, tmp_path):
        f = tmp_path / "targets.txt"
        f.write_text("http://a.com\n# comment\nhttp://b.com | 3\n")
        targets = ctrl.load_targets_from_file(f)
        assert len(targets) == 2

    def test_abort(self, ctrl):
        ctrl.abort()
        assert ctrl.abort_event.is_set()

    def test_generate_aggregate_report(self, ctrl):
        report = ctrl.generate_aggregate_report()
        assert "swarm_id" in report
        assert "severity_distribution" in report

    def test_save_report(self, ctrl, tmp_path):
        path = ctrl.save_report(tmp_path / "report.json")
        assert path.exists()

    def test_format_swarm_report(self):
        from tools.swarm_controller import format_swarm_report

        report = {
            "swarm_id": "swarm_abc",
            "total_duration_seconds": 10.5,
            "summary": {"total_targets": 2, "completed": 2, "failed": 0, "total_findings": 5},
            "severity_distribution": {"critical": 1, "high": 2, "medium": 2, "low": 0, "info": 0},
            "target_breakdown": [
                {"target": "http://a.com", "success": True, "findings_count": 3, "duration_seconds": 5.0, "error": None}
            ],
        }
        text = format_swarm_report(report)
        assert "swarm_abc" in text
        assert "CRITICAL" in text


class TestSwarmTarget:
    def test_defaults(self):
        from tools.swarm_controller import SwarmTarget

        t = SwarmTarget(target_id="t1", target_url="http://a.com", mission_id="m1")
        assert t.priority == 5
        assert t.status == "pending"
        assert t.progress == 0.0


class TestSwarmConfig:
    def test_defaults(self):
        from tools.swarm_controller import SwarmConfig

        c = SwarmConfig()
        assert c.max_concurrent == 3
        assert c.enable_governance is True


# ═══════════════════════════════════════════════════════════════════════════
# tools/multi_agent.py
# ═══════════════════════════════════════════════════════════════════════════


class TestTeamAegis:
    @pytest.fixture
    def mock_clients(self):
        c1 = MagicMock()
        c1.provider = "openai"
        c1.model = "gpt-4"
        c1.simple_chat.return_value = '{"discussion": "test", "action": {"type": "none"}, "findings": []}'
        c2 = MagicMock()
        c2.provider = "ollama"
        c2.model = "llama3"
        c2.simple_chat.return_value = '{"discussion": "test2", "action": {"type": "none"}, "findings": []}'
        return [c1, c2]

    def test_init(self, mock_clients):
        from tools.multi_agent import TeamAegis

        team = TeamAegis(clients=mock_clients, target="example.com")
        assert team.target == "example.com"
        assert team.team_size == 2

    def test_init_needs_at_least_2(self):
        from tools.multi_agent import TeamAegis

        with pytest.raises(ValueError):
            TeamAegis(clients=[MagicMock()], target="example.com")

    def test_init_truncates_to_3(self):
        from tools.multi_agent import TeamAegis

        clients = [MagicMock(provider="p", model="m") for _ in range(5)]
        team = TeamAegis(clients=clients, target="t")
        assert team.team_size == 3

    def test_parse_agent_response_json(self, mock_clients):
        from tools.multi_agent import TeamAegis

        team = TeamAegis(clients=mock_clients, target="t")
        text = '{"discussion": "hello", "action": {"type": "none"}}'
        parsed = team._parse_agent_response(text)
        assert parsed["discussion"] == "hello"

    def test_parse_agent_response_json_block(self, mock_clients):
        from tools.multi_agent import TeamAegis

        team = TeamAegis(clients=mock_clients, target="t")
        text = '```json\n{"discussion": "hi", "action": {"type": "shell"}}\n```'
        parsed = team._parse_agent_response(text)
        assert parsed["discussion"] == "hi"

    def test_parse_agent_response_plaintext(self, mock_clients):
        from tools.multi_agent import TeamAegis

        team = TeamAegis(clients=mock_clients, target="t")
        parsed = team._parse_agent_response("just plain text")
        assert parsed["action"]["type"] == "none"

    def test_parse_agent_response_empty(self, mock_clients):
        from tools.multi_agent import TeamAegis

        team = TeamAegis(clients=mock_clients, target="t")
        parsed = team._parse_agent_response("")
        assert "No response" in parsed["discussion"]

    def test_format_team_roster(self, mock_clients):
        from tools.multi_agent import TeamAegis

        team = TeamAegis(clients=mock_clients, target="t")
        roster = team._format_team_roster()
        assert "openai" in roster
        assert "ollama" in roster

    def test_format_findings_empty(self, mock_clients):
        from tools.multi_agent import TeamAegis

        team = TeamAegis(clients=mock_clients, target="t")
        assert "No confirmed" in team._format_findings()

    def test_format_discussion_history_empty(self, mock_clients):
        from tools.multi_agent import TeamAegis

        team = TeamAegis(clients=mock_clients, target="t")
        assert "No previous" in team._format_discussion_history()

    def test_format_shared_intel_empty(self, mock_clients):
        from tools.multi_agent import TeamAegis

        team = TeamAegis(clients=mock_clients, target="t")
        intel = team._format_shared_intel()
        assert intel == ""

    def test_share_intel(self, mock_clients):
        from tools.multi_agent import TeamAegis

        team = TeamAegis(clients=mock_clients, target="t")
        team._share_intel(0, "Found SQLi in login")
        assert len(team.shared_intel) == 1

    def test_push_pop_task(self, mock_clients):
        from tools.multi_agent import TeamAegis

        team = TeamAegis(clients=mock_clients, target="t")
        team._push_task(5, 0, {"type": "suggested", "description": "run nuclei"})
        task = team._pop_task()
        assert task is not None
        assert task[3]["type"] == "suggested"

    def test_pop_task_empty(self, mock_clients):
        from tools.multi_agent import TeamAegis

        team = TeamAegis(clients=mock_clients, target="t")
        assert team._pop_task() is None

    def test_generate_final_report(self, mock_clients):
        from tools.multi_agent import TeamAegis

        team = TeamAegis(clients=mock_clients, target="t")
        report = team._generate_final_report()
        assert "ENGAGEMENT REPORT" in report
        assert "example.com" not in report  # target is "t"

    def test_agent_roles_count(self):
        from tools.multi_agent import AGENT_ROLES

        assert len(AGENT_ROLES) == 3


# ═══════════════════════════════════════════════════════════════════════════
# tools/soc_analyzer.py
# ═══════════════════════════════════════════════════════════════════════════


class TestSOCAnalyzer:
    @pytest.fixture
    def analyzer(self):
        from tools.soc_analyzer import SOCAnalyzer

        return SOCAnalyzer(ioc_db={"ip": {"1.2.3.4": True}, "hash": {"abc123": True}})

    def test_parse_syslog(self, analyzer):
        alert = analyzer.parse_syslog("Jan  1 12:00:00 host sshd[1]: Failed password for root from 10.0.0.1")
        assert alert is not None
        assert alert.src_ip == "10.0.0.1"
        assert alert.severity == "info"

    def test_parse_syslog_critical(self, analyzer):
        alert = analyzer.parse_syslog("Jan  1 12:00:00 host kernel: critical error detected")
        assert alert is not None
        assert alert.severity == "critical"

    def test_parse_syslog_bad_format(self, analyzer):
        alert = analyzer.parse_syslog("not a syslog line")
        assert alert is None

    def test_parse_json_alert(self, analyzer):
        data = {
            "alert_id": "alert-001",
            "timestamp": "2024-01-01T00:00:00Z",
            "severity": "high",
            "signature": "SQL Injection Attempt",
            "src_ip": "1.2.3.4",
            "dst_ip": "5.6.7.8",
        }
        alert = analyzer.parse_json_alert(data, "suricata")
        assert alert is not None
        assert alert.alert_type == "intrusion"
        assert alert.src_ip == "1.2.3.4"

    def test_parse_json_alert_normalize_severity(self, analyzer):
        alert = analyzer.parse_json_alert({"severity": "emergency"}, "test")
        assert alert.severity == "critical"

    def test_parse_json_alert_malware_type(self, analyzer):
        alert = analyzer.parse_json_alert({"signature": "trojan detected"}, "test")
        assert alert.alert_type == "malware"

    def test_parse_json_alert_recon_type(self, analyzer):
        alert = analyzer.parse_json_alert({"signature": "port scan detected"}, "test")
        assert alert.alert_type == "recon"

    def test_parse_json_alert_privilege_type(self, analyzer):
        alert = analyzer.parse_json_alert({"signature": "privilege escalation via sudo"}, "test")
        assert alert.alert_type == "privilege_escalation"

    def test_parse_json_alert_data_exfil_type(self, analyzer):
        alert = analyzer.parse_json_alert({"signature": "data exfiltration detected"}, "test")
        assert alert.alert_type == "data_exfiltration"

    def test_check_ioc_match(self, analyzer):
        from tools.soc_analyzer import Alert

        alert = Alert(
            alert_id="a1", timestamp="t", source="test", alert_type="unknown",
            severity="high", confidence=0.8, src_ip="1.2.3.4"
        )
        matches = analyzer.check_ioc(alert)
        assert "ip:1.2.3.4" in matches

    def test_check_ioc_no_match(self, analyzer):
        from tools.soc_analyzer import Alert

        alert = Alert(
            alert_id="a1", timestamp="t", source="test", alert_type="unknown",
            severity="high", confidence=0.8, src_ip="9.9.9.9"
        )
        matches = analyzer.check_ioc(alert)
        assert matches == []

    def test_identify_threat_actor(self, analyzer):
        from tools.soc_analyzer import Alert

        alert = Alert(
            alert_id="a1", timestamp="t", source="test", alert_type="unknown",
            severity="high", confidence=0.8, signature="cobalt strike beacon detected"
        )
        actor, campaign = analyzer.identify_threat_actor(alert)
        assert actor == "cobalt_strike"

    def test_identify_threat_actor_none(self, analyzer):
        from tools.soc_analyzer import Alert

        alert = Alert(
            alert_id="a1", timestamp="t", source="test", alert_type="unknown",
            severity="high", confidence=0.8, signature="generic alert"
        )
        actor, _ = analyzer.identify_threat_actor(alert)
        assert actor is None

    def test_calculate_priority(self, analyzer):
        from tools.soc_analyzer import Alert

        alert = Alert(
            alert_id="a1", timestamp="t", source="test", alert_type="data_exfiltration",
            severity="critical", confidence=0.9
        )
        priority = analyzer.calculate_priority(alert)
        assert priority > 5.0

    def test_triage_alert(self, analyzer):
        from tools.soc_analyzer import Alert

        alert = Alert(
            alert_id="a1", timestamp="t", source="test", alert_type="intrusion",
            severity="high", confidence=0.85, src_ip="1.2.3.4"
        )
        result = analyzer.triage_alert(alert)
        assert result.priority_score > 0
        assert result.category in ("true_positive", "needs_investigation", "false_positive_likely")
        assert result.recommended_action

    def test_triage_low_confidence(self, analyzer):
        from tools.soc_analyzer import Alert

        alert = Alert(
            alert_id="a1", timestamp="t", source="test", alert_type="unknown",
            severity="low", confidence=0.2
        )
        result = analyzer.triage_alert(alert)
        assert result.category == "false_positive_likely"

    def test_correlate_alerts(self, analyzer):
        from tools.soc_analyzer import Alert, TriageResult

        a1 = Alert(
            alert_id="a1", timestamp="t", source="test", alert_type="recon",
            severity="medium", confidence=0.6, src_ip="1.2.3.4"
        )
        a2 = Alert(
            alert_id="a2", timestamp="t", source="test", alert_type="recon",
            severity="medium", confidence=0.6, src_ip="1.2.3.4"
        )
        r1 = TriageResult(alert=a1, priority_score=3.0, category="needs_investigation",
                          recommended_action="investigate", related_alerts=[])
        r2 = TriageResult(alert=a2, priority_score=3.0, category="needs_investigation",
                          recommended_action="investigate", related_alerts=[])
        results = analyzer.correlate_alerts([r1, r2])
        assert "a2" in results[0].related_alerts
        assert "a1" in results[1].related_alerts

    def test_generate_sigma_rule(self, analyzer):
        from tools.soc_analyzer import Alert

        alert = Alert(
            alert_id="a1", timestamp="t", source="suricata", alert_type="intrusion",
            severity="high", confidence=0.8, signature="SQL Injection", src_ip="1.2.3.4"
        )
        rule = analyzer.generate_sigma_rule(alert)
        assert rule is not None
        assert rule.level == "high"
        assert "selection" in rule.detection

    def test_generate_sigma_rule_low_confidence(self, analyzer):
        from tools.soc_analyzer import Alert

        alert = Alert(
            alert_id="a1", timestamp="t", source="test", alert_type="unknown",
            severity="low", confidence=0.3
        )
        assert analyzer.generate_sigma_rule(alert) is None

    def test_analyze_log_file_not_found(self, analyzer):
        result = analyzer.analyze_log_file(Path("/nonexistent/file.log"))
        assert "error" in result

    def test_analyze_log_file_json(self, analyzer, tmp_path):
        f = tmp_path / "alerts.jsonl"
        f.write_text(json.dumps({"severity": "high", "signature": "attack", "src_ip": "1.2.3.4"}) + "\n")
        f.write_text(json.dumps({"severity": "low"}) + "\n", encoding="utf-8")
        result = analyzer.analyze_log_file(f)
        assert result["total_alerts"] >= 1


class TestFormatSocReport:
    def test_format(self):
        from tools.soc_analyzer import format_soc_report

        report = {
            "total_alerts": 10,
            "severity_distribution": {"high": 5, "low": 5},
            "category_distribution": {"true_positive": 3},
            "top_priority_alerts": [
                {"id": "a1", "type": "malware", "severity": "high", "priority": 8.0,
                 "src_ip": "1.2.3.4", "threat_actor": "apt28", "action": "contain"}
            ],
            "threat_actors_identified": ["apt28"],
            "generated_rules": [{"title": "Rule 1", "level": "high", "tags": ["malware"]}],
        }
        text = format_soc_report(report)
        assert "SOC ALERT" in text
        assert "apt28" in text


# ═══════════════════════════════════════════════════════════════════════════
# tools/threat_intel.py
# ═══════════════════════════════════════════════════════════════════════════


class TestThreatIntelDB:
    @pytest.fixture
    def db(self, tmp_path):
        import tools.threat_intel as mod

        mod._DB_PATH = tmp_path / "threat_intel.db"
        mod.init_db()
        return mod.get_threat_intel_db()

    def test_add_ioc(self, db):
        assert db.add_ioc("1.2.3.4", "ip", "malicious", confidence=90, source="test") is True

    def test_lookup(self, db):
        db.add_ioc("evil.com", "domain", "c2", confidence=80)
        result = db.lookup("evil.com")
        assert result is not None
        assert result["type"] == "domain"
        assert result["threat_type"] == "c2"

    def test_lookup_with_type(self, db):
        db.add_ioc("1.2.3.4", "ip", "malicious")
        result = db.lookup("1.2.3.4", ioc_type="ip")
        assert result is not None

    def test_lookup_not_found(self, db):
        assert db.lookup("9.9.9.9") is None

    def test_update_existing_ioc(self, db):
        db.add_ioc("1.2.3.4", "ip", "malicious", confidence=50)
        db.add_ioc("1.2.3.4", "ip", "malicious", confidence=90)
        result = db.lookup("1.2.3.4")
        assert result["confidence"] == 90

    def test_batch_lookup(self, db):
        db.add_ioc("1.1.1.1", "ip", "unknown")
        results = db.batch_lookup([("1.1.1.1", "ip"), ("2.2.2.2", "ip")])
        assert results["1.1.1.1"] is not None
        assert results["2.2.2.2"] is None

    def test_search_by_type(self, db):
        db.add_ioc("1.1.1.1", "ip", "a")
        db.add_ioc("2.2.2.2", "ip", "b")
        db.add_ioc("evil.com", "domain", "c")
        results = db.search_by_type("ip")
        assert len(results) == 2

    def test_get_recent(self, db):
        db.add_ioc("1.1.1.1", "ip", "a")
        results = db.get_recent(hours=1)
        assert len(results) == 1

    def test_add_builtin_iocs(self, db):
        added = db.add_builtin_iocs()
        assert added > 0
        # Verify some were added
        result = db.lookup("mimikatz", ioc_type="process")
        assert result is not None

    def test_ioc_with_metadata(self, db):
        db.add_ioc("test_hash", "hash", "malware", metadata={"campaign": "xyz"})
        result = db.lookup("test_hash")
        assert result["metadata"]["campaign"] == "xyz"


class TestEnricher:
    @pytest.fixture
    def enricher(self, tmp_path):
        import tools.threat_intel as mod

        mod._DB_PATH = tmp_path / "threat_intel.db"
        mod.init_db()
        ti_db = mod.get_threat_intel_db()
        ti_db.add_ioc("evil.com", "domain", "c2", confidence=90)
        return mod.Enricher(ti_db=ti_db)

    def test_enrich_finding_with_ioc(self, enricher):
        finding = {"domain": "evil.com", "description": "suspicious domain"}
        enriched = enricher.enrich_finding(finding)
        assert "threat_intel" in enriched
        assert enriched["threat_intel"]["max_confidence"] == 90

    def test_enrich_finding_no_ioc(self, enricher):
        finding = {"domain": "safe.com"}
        enriched = enricher.enrich_finding(finding)
        assert "threat_intel" not in enriched

    def test_enrich_finding_ip(self, enricher):
        import tools.threat_intel as mod

        enricher.ti_db.add_ioc("5.5.5.5", "ip", "scanner")
        finding = {"src_ip": "5.5.5.5"}
        enriched = enricher.enrich_finding(finding)
        assert "threat_intel" in enriched


class TestGetThreatIntelDB:
    def test_returns_instance(self, tmp_path):
        import tools.threat_intel as mod

        mod._DB_PATH = tmp_path / "ti.db"
        db = mod.get_threat_intel_db()
        assert isinstance(db, mod.ThreatIntelDB)
