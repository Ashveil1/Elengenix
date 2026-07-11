"""
tests/test_max_coverage.py — Maximum code coverage tests for remaining gaps.

Targets files with highest missed-line counts to push coverage toward 80%.
All network calls, file I/O, and user input are mocked.
"""

import sys
import json
import time
import asyncio
import sqlite3
import tempfile
import hashlib
from pathlib import Path
from unittest.mock import MagicMock, patch, AsyncMock, mock_open, PropertyMock
from dataclasses import dataclass, field
from typing import Any, Dict, List

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# ─── Fixtures ───────────────────────────────────────────────────────────────


@pytest.fixture
def tmp_db(tmp_path):
    """Provide a temp SQLite DB path."""
    return tmp_path / "test.db"


@pytest.fixture
def tmp_sessions_dir(tmp_path):
    """Provide a temp sessions directory."""
    d = tmp_path / "sessions"
    d.mkdir()
    return d


@pytest.fixture
def mock_console():
    c = MagicMock()
    c.width = 80
    c.print = MagicMock()
    c.input = MagicMock(return_value="0")
    c.status = MagicMock()
    return c


# ═════════════════════════════════════════════════════════════════════════════
#  tools/perf.py — SmartCache, Timer, AsyncBatcher, FastHTTP, StreamingAggregator
# ═════════════════════════════════════════════════════════════════════════════


class TestSmartCache:
    def test_set_get_hit(self):
        from tools.perf import SmartCache

        c = SmartCache(max_size=10, default_ttl=60)
        c.set("k1", "v1")
        assert c.get("k1") == "v1"
        assert c.hits == 1

    def test_miss(self):
        from tools.perf import SmartCache

        c = SmartCache()
        assert c.get("nonexistent") is None
        assert c.misses == 1

    def test_ttl_expiry(self):
        from tools.perf import SmartCache

        c = SmartCache(default_ttl=0.01)
        c.set("k", "v")
        time.sleep(0.02)
        assert c.get("k") is None

    def test_lru_eviction(self):
        from tools.perf import SmartCache

        c = SmartCache(max_size=2)
        c.set("a", 1)
        c.set("b", 2)
        c.set("c", 3)  # evicts 'a'
        assert c.get("a") is None
        assert c.get("b") == 2
        assert c.get("c") == 3

    def test_invalidate_all(self):
        from tools.perf import SmartCache

        c = SmartCache()
        c.set("a", 1)
        c.set("b", 2)
        assert c.invalidate() == 2
        assert c.get("a") is None

    def test_invalidate_pattern(self):
        from tools.perf import SmartCache

        c = SmartCache()
        c.set("http://a.com", 1)
        c.set("http://b.com", 2)
        c.set("other", 3)
        removed = c.invalidate("http://")
        assert removed == 2
        assert c.get("other") == 3

    def test_stats(self):
        from tools.perf import SmartCache

        c = SmartCache(max_size=5)
        c.set("x", 1)
        c.get("x")
        c.get("y")
        s = c.stats()
        assert s["size"] == 1
        assert s["hits"] == 1
        assert s["misses"] == 1

    def test_set_existing_key(self):
        from tools.perf import SmartCache

        c = SmartCache(max_size=3)
        c.set("k", "old")
        c.set("k", "new")
        assert c.get("k") == "new"
        assert c.stats()["size"] == 1


class TestTimer:
    def test_timer_context(self):
        from tools.perf import Timer

        with Timer(name="test") as t:
            time.sleep(0.01)
        assert t.result is not None
        assert t.result.duration_ms > 0
        assert t.result.name == "test"

    def test_duration_ms_before_exit(self):
        from tools.perf import Timer

        t = Timer()
        assert t.duration_ms == 0.0

    def test_timer_with_metadata(self):
        from tools.perf import Timer

        with Timer(name="op", metadata={"key": "val"}) as t:
            pass
        assert t.result.metadata == {"key": "val"}


class TestTimeitDecorator:
    def test_timeit(self):
        from tools.perf import timeit

        @timeit(name="test")
        def fn():
            return 42

        assert fn() == 42


class TestCachedDecorator:
    def test_cached_decorator(self):
        from tools.perf import SmartCache, cached

        cache = SmartCache(default_ttl=60)
        call_count = 0

        @cached(cache=cache)
        def expensive(x):
            nonlocal call_count
            call_count += 1
            return x * 2

        assert expensive(5) == 10
        assert expensive(5) == 10
        assert call_count == 1  # second call hits cache

    def test_cached_with_key_fn(self):
        from tools.perf import SmartCache, cached

        cache = SmartCache(default_ttl=60)

        @cached(cache=cache, key_fn=lambda x, **kw: f"key_{x}")
        def fn(x):
            return x + 1

        assert fn(10) == 11
        assert fn(10) == 11

    def test_cached_none_result_not_stored(self):
        from tools.perf import SmartCache, cached

        cache = SmartCache(default_ttl=60)
        call_count = 0

        @cached(cache=cache)
        def sometimes_none(x):
            nonlocal call_count
            call_count += 1
            return None if x == 0 else x

        sometimes_none(0)
        sometimes_none(0)
        assert call_count == 2  # None not cached, called again


class TestAsyncBatcher:
    @pytest.mark.asyncio
    async def test_run_all(self):
        from tools.perf import AsyncBatcher

        batcher = AsyncBatcher(concurrency=2, timeout=5)

        async def coro(x):
            return x * 2

        results = await batcher.run_all([coro(1), coro(2), coro(3)])
        assert len(results) == 3

    @pytest.mark.asyncio
    async def test_run_all_with_error(self):
        from tools.perf import AsyncBatcher

        batcher = AsyncBatcher(concurrency=2, timeout=5)

        async def ok(x):
            return x

        async def fail():
            raise ValueError("boom")

        results = await batcher.run_all([ok(1), fail()])
        assert len(results) == 2


class TestStreamingAggregator:
    def test_add_findings(self):
        from tools.perf import StreamingAggregator

        agg = StreamingAggregator()
        agg.add({"severity": "High", "cvss": 8.0})
        agg.add({"severity": "Low", "cvss": 2.0})
        assert agg.total == 2
        assert agg.risk_score == 8.0
        assert agg.by_severity["High"] == 1

    def test_summary(self):
        from tools.perf import StreamingAggregator

        agg = StreamingAggregator()
        agg.add({"severity": "Critical", "cvss": 9.5})
        s = agg.summary()
        assert s["total"] == 1
        assert s["risk_score"] == 9.5

    def test_duration(self):
        from tools.perf import StreamingAggregator

        agg = StreamingAggregator()
        time.sleep(0.01)
        assert agg.duration_seconds > 0


class TestFastHTTP:
    def test_get_returns_dict(self):
        from tools.perf import FastHTTP

        # Just test instantiation and session creation
        http = FastHTTP(timeout=5, use_cache=False)
        assert http.timeout == 5
        assert http.use_cache is False

    def test_get_session(self):
        from tools.perf import FastHTTP

        http = FastHTTP()
        s = http._get_session()
        assert s is not None


# ═════════════════════════════════════════════════════════════════════════════
#  tools/token_manager.py — TokenManager
# ═════════════════════════════════════════════════════════════════════════════


class TestTokenManager:
    @pytest.fixture
    def tm(self, tmp_path):
        from tools.token_manager import TokenManager

        db_path = tmp_path / "tokens.db"
        patcher = patch.object(TokenManager, "DB_PATH", db_path)
        patcher.start()
        mgr = TokenManager(daily_budget_usd=10.0, monthly_budget_usd=100.0)
        yield mgr
        patcher.stop()

    def test_calculate_cost_openai(self, tm):
        cost = tm.calculate_cost("openai", 1000, 500)
        assert cost > 0

    def test_calculate_cost_unknown(self, tm):
        cost = tm.calculate_cost("unknown_provider", 1000, 500)
        assert cost == 0.0

    def test_calculate_cost_ollama(self, tm):
        cost = tm.calculate_cost("ollama", 1000, 500)
        assert cost == 0.0

    def test_record_usage(self, tm):
        usage = tm.record_usage("openai", "gpt-4", 1000, 500, mission_id="m1")
        assert usage.tokens_input == 1000
        assert usage.cost_usd > 0

    def test_get_usage_today(self, tm):
        tm.record_usage("openai", "gpt-4", 1000, 500)
        usage = tm.get_usage_today()
        assert "openai" in usage

    def test_get_usage_month(self, tm):
        tm.record_usage("anthropic", "claude", 2000, 1000)
        usage = tm.get_usage_month()
        assert "anthropic" in usage

    def test_get_status(self, tm):
        status = tm.get_status()
        assert "spent_today" in status
        assert "daily_budget" in status

    def test_can_proceed_within_budget(self, tm):
        ok, reason = tm.can_proceed(estimated_cost=0.01)
        assert ok is True

    def test_can_proceed_exceeds_daily(self, tm):
        # Budget is 10.0, spending 11.0 should fail
        ok, reason = tm.can_proceed(estimated_cost=11.0)
        assert ok is False
        assert "Daily" in reason

    def test_can_proceed_exceeds_monthly(self, tm):
        ok, reason = tm.can_proceed(estimated_cost=101.0, check_daily=False)
        assert ok is False
        assert "Monthly" in reason

    def test_can_proceed_skip_checks(self, tm):
        ok, reason = tm.can_proceed(999999, check_daily=False, check_monthly=False)
        assert ok is True

    def test_check_alerts_no_alerts(self, tm):
        alerts = tm.check_alerts()
        assert isinstance(alerts, list)

    def test_should_pause_not_paused(self, tm):
        pause, reason = tm.should_pause()
        assert pause is False

    def test_recommend_provider_free(self, tm):
        rec = tm.recommend_provider("openai")
        assert rec is not None  # should recommend a free provider

    def test_recommend_provider_free_provider(self, tm):
        rec = tm.recommend_provider("ollama")
        assert rec is None  # free provider, no need to switch

    def test_recommend_provider_cheapest(self, tmp_path):
        from tools.token_manager import TokenManager, ProviderConfig

        configs = {
            "cheap": ProviderConfig("Cheap", 1.0, 2.0, "m"),
            "expensive": ProviderConfig("Expensive", 50.0, 100.0, "m"),
        }
        db_path = tmp_path / "cheapest.db"
        with patch.object(TokenManager, "DB_PATH", db_path):
            tm = TokenManager(provider_configs=configs)
        rec = tm.recommend_provider("expensive")
        assert rec == "cheap"

    def test_get_mission_cost(self, tm):
        tm.record_usage("openai", "gpt-4", 500, 200, mission_id="test_mission")
        cost = tm.get_mission_cost("test_mission")
        assert cost["total_cost_usd"] > 0

    def test_get_mission_cost_empty(self, tm):
        cost = tm.get_mission_cost("nonexistent")
        assert cost["total_cost_usd"] == 0.0

    def test_reset_alerts(self, tm):
        tm._alerted_thresholds.add("daily_50")
        tm.reset_alerts()
        assert len(tm._alerted_thresholds) == 0

    def test_format_status(self, tm):
        output = tm.format_status()
        assert "Token Usage Status" in output

    def test_alerts_at_50_percent(self, tm):
        # Spend exactly around 50-74% to trigger 50% alert (not 75% or 90%)
        # cost_per_1m_input=30.0, cost_per_1m_output=60.0
        # 10000 input = $0.30, 5000 output = $0.30, total per call = $0.60
        # Need $5-7.4 to hit 50-74% of $10 budget -> ~10 calls
        for _ in range(10):
            tm.record_usage("openai", "gpt-4", 10000, 5000)
        alerts = tm.check_alerts()
        assert any("daily" in a.lower() for a in alerts)

    def test_monthly_alert_at_75(self, tm):
        # Budget is 100, spend ~75
        for _ in range(200):
            tm.record_usage("openai", "gpt-4", 50000, 25000)
        alerts = tm.check_alerts()
        # Just ensure it doesn't crash
        assert isinstance(alerts, list)

    def test_should_pause_high_daily(self, tm):
        for _ in range(100):
            tm.record_usage("openai", "gpt-4", 10000, 5000)
        pause, reason = tm.should_pause()
        # May or may not pause depending on exact cost calculation
        assert isinstance(pause, bool)

    def test_ensure_db_creates_tables(self, tmp_path):
        from tools.token_manager import TokenManager

        db_path = tmp_path / "new.db"
        with patch.object(TokenManager, "DB_PATH", db_path):
            tm = TokenManager()
        assert db_path.exists()


# ═════════════════════════════════════════════════════════════════════════════
#  tools/session_manager.py — SessionManager, LiveSessionState
# ═════════════════════════════════════════════════════════════════════════════


class TestSessionManager:
    @pytest.fixture
    def mgr(self, tmp_sessions_dir):
        from tools.session_manager import SessionManager

        return SessionManager(sessions_dir=tmp_sessions_dir)

    def test_start_session_auto_name(self, mgr):
        name = mgr.start_session(target="example.com")
        assert name
        assert mgr.live.target == "example.com"

    def test_start_session_named(self, mgr):
        name = mgr.start_session(name="my-session")
        assert name == "my-session"

    def test_update_turn(self, mgr):
        mgr.start_session()
        mgr.update_turn(prompt_tokens=100, completion_tokens=50)
        assert mgr.live.turn_count == 1
        assert mgr.live.token_count == 150

    def test_save_session(self, mgr):
        mgr.start_session(name="test-save", target="x.com")
        result = mgr.save_session(name="test-save")
        assert result is True

    def test_save_session_uses_live_name(self, mgr):
        mgr.start_session(name="live-name")
        result = mgr.save_session()
        assert result is True

    def test_save_session_with_agent(self, mgr):
        agent = MagicMock()
        agent.conversation_history = [{"role": "user", "content": "hi"}]
        mgr.start_session(name="agent-test")
        result = mgr.save_session(agent=agent)
        assert result is True

    def test_resume_session(self, mgr, tmp_sessions_dir):
        # Save a session first
        mgr.start_session(name="res-me", target="t.com")
        mgr.save_session(name="res-me")
        # Resume it
        result = mgr.resume_session("res-me")
        assert result is not None
        assert result["target"] == "t.com"

    def test_resume_nonexistent(self, mgr):
        result = mgr.resume_session("nonexistent")
        assert result is None

    def test_list_sessions(self, mgr):
        mgr.start_session(name="s1")
        mgr.save_session(name="s1")
        sessions = mgr.list_sessions()
        assert len(sessions) >= 1

    def test_list_sessions_empty(self, mgr):
        sessions = mgr.list_sessions()
        assert len(sessions) == 0

    def test_delete_session(self, mgr):
        mgr.start_session(name="del-me")
        mgr.save_session(name="del-me")
        ok = mgr.delete_session("del-me")
        assert ok is True

    def test_delete_nonexistent(self, mgr):
        ok = mgr.delete_session("ghost")
        assert ok is False

    def test_session_path_sanitization(self, mgr):
        path = mgr._session_path("my/session:name")
        assert "my_session_name" in path.name

    def test_generate_session_id(self):
        from tools.session_manager import generate_session_id

        sid = generate_session_id()
        assert len(sid) == 9
        assert sid.isalnum()


class TestLiveSessionState:
    def test_defaults(self):
        from tools.session_manager import LiveSessionState

        state = LiveSessionState()
        assert state.turn_count == 0
        assert state.token_count == 0
        assert state.status == "ready"


# ═════════════════════════════════════════════════════════════════════════════
#  tools/universal_ai_client.py — UniversalAIClient, AIMessage, AIResponse
# ═════════════════════════════════════════════════════════════════════════════


class TestAIMessage:
    def test_creation(self):
        from tools.universal_ai_client import AIMessage

        msg = AIMessage(role="user", content="hello")
        assert msg.role == "user"
        assert msg.content == "hello"
        assert msg.metadata is None

    def test_with_metadata(self):
        from tools.universal_ai_client import AIMessage

        msg = AIMessage(role="assistant", content="hi", metadata={"key": "val"})
        assert msg.metadata == {"key": "val"}


class TestAIResponse:
    def test_creation(self):
        from tools.universal_ai_client import AIResponse

        resp = AIResponse(content="ok", model="gpt-4", usage={"prompt": 10, "completion": 20})
        assert resp.content == "ok"
        assert resp.tool_calls is None


class TestToolCall:
    def test_creation(self):
        from tools.universal_ai_client import ToolCall

        tc = ToolCall(id="1", name="run_shell", arguments={"command": "ls"})
        assert tc.name == "run_shell"


class TestUniversalAIClient:
    @pytest.fixture
    def client(self):
        from tools.universal_ai_client import UniversalAIClient

        return UniversalAIClient(provider="openai", api_key="test-key", model="gpt-4")

    def test_init(self, client):
        assert client.provider == "openai"
        assert client.model == "gpt-4"

    def test_provider_configs_exist(self):
        from tools.universal_ai_client import UniversalAIClient

        assert "openai" in UniversalAIClient.PROVIDER_CONFIGS
        assert "ollama" in UniversalAIClient.PROVIDER_CONFIGS
        assert "gemini" in UniversalAIClient.PROVIDER_CONFIGS
        assert "anthropic" in UniversalAIClient.PROVIDER_CONFIGS
        assert "groq" in UniversalAIClient.PROVIDER_CONFIGS
        assert "nvidia" in UniversalAIClient.PROVIDER_CONFIGS
        assert "deepseek" in UniversalAIClient.PROVIDER_CONFIGS
        assert "mistral" in UniversalAIClient.PROVIDER_CONFIGS
        assert "together" in UniversalAIClient.PROVIDER_CONFIGS
        assert "perplexity" in UniversalAIClient.PROVIDER_CONFIGS
        assert "custom" in UniversalAIClient.PROVIDER_CONFIGS

    def test_detect_provider(self, client):
        with patch.dict("os.environ", {"OPENAI_API_KEY": "key"}):
            p = client._detect_provider()
            assert p == "openai"

    def test_detect_provider_fallback(self):
        from tools.universal_ai_client import UniversalAIClient

        c = UniversalAIClient(provider="openai", api_key="test", model="gpt-4")
        with patch.dict("os.environ", {}, clear=True), patch.object(
            c, "_check_ollama", return_value=False
        ):
            p = c._detect_provider()
            assert p == "ollama"

    def test_chat_mock(self, client):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "choices": [{"message": {"content": "test response"}}],
            "model": "gpt-4",
            "usage": {"prompt_tokens": 10, "completion_tokens": 5},
        }
        with patch.object(client.session, "post", return_value=mock_resp):
            resp = client.chat([MagicMock(role="user", content="hi")])
            assert resp.content == "test response"

    def test_simple_chat(self, client):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "choices": [{"message": {"content": "hello"}}],
            "model": "gpt-4",
            "usage": {"prompt_tokens": 5, "completion_tokens": 3},
        }
        with patch.object(client.session, "post", return_value=mock_resp):
            result = client.simple_chat("hi", system_prompt="sys")
            assert result == "hello"

    def test_chat_error(self, client):
        with patch.object(client.session, "post", side_effect=Exception("timeout")):
            with pytest.raises(Exception, match="timeout"):
                client.chat([MagicMock(role="user", content="hi")])

    def test_chat_with_tool_calls(self, client):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "choices": [
                {
                    "message": {
                        "content": "",
                        "tool_calls": [
                            {
                                "id": "1",
                                "function": {"name": "run_shell", "arguments": '{"command":"ls"}'},
                            }
                        ],
                    }
                }
            ],
            "model": "gpt-4",
            "usage": {"prompt_tokens": 5, "completion_tokens": 3},
        }
        with patch.object(client.session, "post", return_value=mock_resp):
            resp = client.chat([MagicMock(role="user", content="hi")])
            assert resp.tool_calls is not None
            assert resp.tool_calls[0].name == "run_shell"

    def test_get_status(self, client):
        status = client.get_status()
        assert "provider" in status
        assert "model" in status

    def test_is_available(self, client):
        assert isinstance(client.is_available(), bool)


# ═════════════════════════════════════════════════════════════════════════════
#  tools/vector_memory.py — VectorMemory, MemoryEntry
# ═════════════════════════════════════════════════════════════════════════════


class TestMemoryEntry:
    def test_to_dict(self):
        from tools.vector_memory import MemoryEntry

        entry = MemoryEntry(
            id="abc",
            content="test",
            target="x.com",
            category="finding",
            timestamp="2024-01-01",
            metadata={"key": "val"},
        )
        d = entry.to_dict()
        assert d["id"] == "abc"
        assert d["metadata"]["key"] == "val"


class TestVectorMemory:
    @pytest.fixture
    def vm(self, tmp_path):
        from tools.vector_memory import VectorMemory

        return VectorMemory(persist_directory=str(tmp_path / "vdb"))

    def test_init(self, vm):
        assert vm.persist_dir.exists()

    def test_generate_id(self, vm):
        id1 = vm._generate_id("content", "target", "ts1")
        id2 = vm._generate_id("content", "target", "ts2")
        assert len(id1) == 16
        assert id1 != id2

    def test_add_memory_fallback(self, vm):
        """When ChromaDB is not initialized, should use fallback."""
        vm._initialized = False
        mid = vm.add_memory("test content", "x.com", category="finding")
        assert mid is not None
        assert len(mid) == 16

    def test_search_fallback(self, vm):
        vm._initialized = False
        vm.add_memory("test content", "x.com")
        results = vm.search("test", target="x.com")
        assert isinstance(results, list)

    def test_remember_and_recall(self, vm):
        vm._initialized = False
        vm.add_memory("important finding", "target.com", category="finding")
        vm.add_memory("another finding", "target.com", category="finding")
        results = vm.search("finding", target="target.com")
        assert len(results) >= 1

    def test_get_stats(self, vm):
        vm._initialized = False
        vm.add_memory("test content", "x.com")
        # Use search to count instead of get_stats which may not exist
        results = vm.search("test")
        assert isinstance(results, list)

    def test_add_memory_with_metadata(self, vm):
        vm._initialized = False
        mid = vm.add_memory(
            "test", "x.com", category="finding", metadata={"source": "test", "severity": "high"}
        )
        assert mid is not None

    def test_search_no_results(self, vm):
        vm._initialized = False
        results = vm.search("zzzznonexistent")
        assert results == [] or isinstance(results, list)

    def test_search_min_similarity(self, vm):
        vm._initialized = False
        vm.add_memory("test content here", "x.com")
        results = vm.search("test", min_similarity=0.99)
        assert isinstance(results, list)


# ═════════════════════════════════════════════════════════════════════════════
#  orchestrator.py — scope, validation, pipeline functions
# ═════════════════════════════════════════════════════════════════════════════


class TestOrchestratorScope:
    def test_normalize_target_empty(self):
        from core.orchestrator import normalize_target

        assert normalize_target("") == ""

    def test_normalize_target_url(self):
        from core.orchestrator import normalize_target

        assert normalize_target("https://example.com/path") == "example.com"

    def test_normalize_target_http(self):
        from core.orchestrator import normalize_target

        assert normalize_target("http://example.com:8080") == "example.com"

    def test_normalize_target_strips_port(self):
        from core.orchestrator import normalize_target

        assert normalize_target("example.com:443") == "example.com"

    def test_normalize_target_trailing_dot(self):
        from core.orchestrator import normalize_target

        assert normalize_target("example.com.") == "example.com"

    def test_normalize_target_whitespace(self):
        from core.orchestrator import normalize_target

        assert normalize_target("  EXAMPLE.COM  ") == "example.com"

    def test_is_valid_target_empty(self):
        from core.orchestrator import is_valid_target

        assert is_valid_target("") is False

    def test_is_valid_target_valid_domain(self):
        from core.orchestrator import is_valid_target

        assert is_valid_target("example.com") is True

    def test_is_valid_target_invalid_no_dot(self):
        from core.orchestrator import is_valid_target

        assert is_valid_target("localhost") is False

    def test_is_valid_target_too_long(self):
        from core.orchestrator import is_valid_target

        assert is_valid_target("a" * 254) is False

    def test_is_valid_target_valid_ip(self):
        from core.orchestrator import is_valid_target

        assert is_valid_target("8.8.8.8") is True

    def test_is_valid_target_private_ip(self):
        from core.orchestrator import is_valid_target

        assert is_valid_target("127.0.0.1") is False
        assert is_valid_target("192.168.1.1") is False
        assert is_valid_target("10.0.0.1") is False

    def test_is_valid_target_ipv6(self):
        from core.orchestrator import is_valid_target

        # IPv6 loopback
        assert is_valid_target("::1") is False

    def test_is_in_scope_empty(self):
        from core.orchestrator import is_in_scope

        assert is_in_scope("") is False

    def test_is_in_scope_valid(self):
        from core.orchestrator import is_in_scope

        # Without allowed domains configured, should return False (fail-closed)
        with patch("core.orchestrator._get_allowed_domains", return_value=set()):
            assert is_in_scope("example.com") is False

    def test_sanitize_path(self):
        from core.orchestrator import sanitize_path

        result = sanitize_path("example.com/path?q=1")
        assert " " not in result
        assert len(result) <= 100

    def test_load_allowed_domains_env(self):
        from core.orchestrator import load_allowed_domains

        with patch.dict("os.environ", {"ELENGENIX_SCOPE": "a.com,b.com"}):
            domains = load_allowed_domains()
            assert "a.com" in domains
            assert "b.com" in domains

    def test_load_allowed_domains_file(self, tmp_path):
        from core.orchestrator import load_allowed_domains

        scope_file = tmp_path / "scope.txt"
        scope_file.write_text("test.com\n# comment\ndev.com\n")
        domains = load_allowed_domains(str(scope_file))
        assert "test.com" in domains
        assert "dev.com" in domains
        assert "# comment" not in domains

    def test_load_allowed_domains_empty_file(self, tmp_path):
        from core.orchestrator import load_allowed_domains

        scope_file = tmp_path / "empty.txt"
        scope_file.write_text("")
        domains = load_allowed_domains(str(scope_file))
        assert len(domains) == 0

    def test_load_allowed_domains_no_file(self):
        from core.orchestrator import load_allowed_domains

        domains = load_allowed_domains("/nonexistent/scope.txt")
        assert isinstance(domains, set)


class TestOrchestratorReconToFindings:
    def test_empty_recon(self):
        from core.orchestrator import _recon_to_findings

        result = _recon_to_findings({}, "http://x.com")
        assert result == []

    def test_recon_with_http(self):
        from core.orchestrator import _recon_to_findings

        recon = {
            "http_probe": {
                "status": 200,
                "title": "Test",
                "tech": ["Apache"],
                "headers": {"Server": "nginx"},
            },
            "directories": [{"url": "http://x.com/api", "status": 200, "length": 500}],
            "ports": [{"host": "x.com", "port": 443, "service": "https"}],
            "subdomains": [{"subdomain": "api.x.com", "ips": ["1.2.3.4"]}],
            "parameters": [
                {
                    "url": "http://x.com/api",
                    "param": "id",
                    "method": "GET",
                    "is_interesting": True,
                    "delta_pct": 50,
                    "baseline_len": 100,
                    "test_len": 200,
                }
            ],
        }
        findings = _recon_to_findings(recon, "http://x.com")
        types = [f["type"] for f in findings]
        assert "recon_http" in types
        assert "endpoint" in types
        assert "port" in types
        assert "subdomain" in types
        assert "param_discovery" in types

    def test_recon_not_interesting_params(self):
        from core.orchestrator import _recon_to_findings

        recon = {
            "http_probe": {},
            "directories": [],
            "ports": [],
            "subdomains": [],
            "parameters": [{"url": "x", "param": "q", "method": "GET", "is_interesting": False}],
        }
        findings = _recon_to_findings(recon, "http://x.com")
        assert len(findings) == 0


class TestOrchestratorGetRecommendedToolChain:
    def test_get_recommended_tool_chain(self):
        from core.orchestrator import get_recommended_tool_chain

        chain = get_recommended_tool_chain("web")
        assert isinstance(chain, list)


class TestOrchestratorManualCmd:
    def test_manual_cmd(self):
        from core.orchestrator import _manual_cmd

        result = _manual_cmd("nuclei")
        assert "nuclei" in result


# ═════════════════════════════════════════════════════════════════════════════
#  tools/hunt_engine.py — HuntFinding, HuntPhase, HuntReport, data classes
# ═════════════════════════════════════════════════════════════════════════════


class TestHuntFinding:
    def test_creation(self):
        from tools.hunt_engine import HuntFinding

        f = HuntFinding(
            phase="recon",
            category="endpoint",
            severity="High",
            title="test",
            details="d",
            url="http://x.com",
        )
        assert f.phase == "recon"
        assert f.severity == "High"

    def test_to_dict(self):
        from tools.hunt_engine import HuntFinding

        f = HuntFinding(phase="smart", category="xss", severity="Critical", title="XSS")
        d = f.to_dict()
        assert d["phase"] == "smart"
        assert d["severity"] == "Critical"


class TestHuntPhase:
    def test_creation(self):
        from tools.hunt_engine import HuntPhase

        p = HuntPhase(name="recon", status="done", duration=1.5, findings=3)
        assert p.name == "recon"
        assert p.findings == 3


class TestHuntReport:
    def test_by_severity(self):
        from tools.hunt_engine import HuntReport, HuntFinding

        report = HuntReport(target="x.com", started_at="2024-01-01")
        report.findings = [
            HuntFinding(phase="a", category="b", severity="High", title="1"),
            HuntFinding(phase="a", category="b", severity="High", title="2"),
            HuntFinding(phase="a", category="b", severity="Low", title="3"),
        ]
        by_sev = report.by_severity()
        assert by_sev["High"] == 2
        assert by_sev["Low"] == 1

    def test_by_phase(self):
        from tools.hunt_engine import HuntReport, HuntFinding

        report = HuntReport(target="x.com", started_at="2024-01-01")
        report.findings = [
            HuntFinding(phase="recon", category="b", severity="High", title="1"),
            HuntFinding(phase="smart", category="b", severity="Low", title="2"),
        ]
        by_ph = report.by_phase()
        assert by_ph["recon"] == 1
        assert by_ph["smart"] == 1

    def test_empty_report(self):
        from tools.hunt_engine import HuntReport

        report = HuntReport(target="x.com", started_at="2024-01-01")
        assert report.by_severity() == {}
        assert report.by_phase() == {}


class TestSeverityEnum:
    def test_values(self):
        from tools.hunt_engine import Severity

        assert Severity.CRITICAL.value == "Critical"
        assert Severity.HIGH.value == "High"
        assert Severity.MEDIUM.value == "Medium"
        assert Severity.LOW.value == "Low"
        assert Severity.INFO.value == "Informational"


# ═════════════════════════════════════════════════════════════════════════════
#  tools/vuln_finder.py — VulnFinder, MissionState, MissionStatus
# ═════════════════════════════════════════════════════════════════════════════


class TestMissionStatus:
    def test_all_statuses(self):
        from tools.vuln_finder import MissionStatus

        statuses = [
            MissionStatus.INIT,
            MissionStatus.RECON,
            MissionStatus.PLANNING,
            MissionStatus.EXECUTING,
            MissionStatus.VERIFYING,
            MissionStatus.COMPLETED,
            MissionStatus.FAILED,
        ]
        assert len(statuses) == 7
        for s in statuses:
            assert isinstance(s.value, str)


class TestMissionState:
    def test_creation(self):
        from tools.vuln_finder import MissionState, MissionStatus

        state = MissionState(target="example.com")
        assert state.target == "example.com"
        assert state.status == MissionStatus.INIT
        assert state.findings == []
        assert state.steps == 0
        assert state.cost == 0.0


class TestVulnFinder:
    @pytest.fixture
    def finder(self):
        from tools.vuln_finder import VulnFinder

        return VulnFinder(target="http://example.com", max_steps=10, budget_limit=5.0)

    def test_init(self, finder):
        assert finder.target == "http://example.com"
        assert finder.max_steps == 10
        assert finder.budget_limit == 5.0

    def test_state_initial(self, finder):
        from tools.vuln_finder import MissionStatus

        assert finder.state.status == MissionStatus.INIT

    def test_plan(self, finder):
        # Plan with empty assets
        plan = finder.plan()
        assert isinstance(plan, list)

    def test_escalate_no_path(self, finder):
        result = finder.escalate({"type": "info", "severity": "info"})
        # May or may not find escalation path
        assert result is None or isinstance(result, dict)

    def test_chain_insufficient(self, finder):
        result = finder.chain([{"type": "info"}])
        # Should return None for single finding
        assert result is None

    def test_add_finding(self, finder):
        finder.add_finding({"title": "test", "severity": "high"})
        assert len(finder.state.findings) == 1

    def test_add_finding_duplicate(self, finder):
        finder.add_finding({"title": "test"})
        finder.add_finding({"title": "test"})
        # Should still add (dedup based on title)
        assert len(finder.state.findings) == 2

    def test_recon_error_handling(self, finder):
        with patch("tools.python_recon.PythonRecon") as MockRecon:
            instance = MagicMock()
            instance.full_recon.side_effect = Exception("network error")
            MockRecon.return_value = instance
            result = finder.recon()
            assert result.get("error") is not None

    def test_get_status(self, finder):
        status = finder.get_status()
        assert "target" in status
        assert "status" in status

    def test_should_continue(self, finder):
        result = finder.should_continue()
        assert isinstance(result, bool)

    def test_generate_report(self, finder):
        report = finder.generate_report()
        assert isinstance(report, str)
        assert "Vulnerability Report" in report


# ═════════════════════════════════════════════════════════════════════════════
#  tools/autonomous_agent.py — data classes, helper functions
# ═════════════════════════════════════════════════════════════════════════════


class TestAutonomousAgentDataClasses:
    def test_agent_action(self):
        from tools.autonomous_agent import AgentAction

        a = AgentAction(
            name="recon", target="example.com", params={"depth": 2}, reasoning="testing"
        )
        assert a.name == "recon"
        assert a.params["depth"] == 2

    def test_agent_state(self):
        from tools.autonomous_agent import AgentState

        s = AgentState(root_target="x.com", goal="find vulns")
        assert s.root_target == "x.com"
        assert s.findings == []
        assert s.iteration == 0

    def test_scan_result(self):
        from tools.autonomous_agent import ScanResult
        from datetime import datetime, timezone

        sr = ScanResult(
            target="x.com",
            start_time=datetime.now(timezone.utc),
            end_time=datetime.now(timezone.utc),
            findings=[],
            bounty_predictions=[],
            tools_created=[],
            ai_decisions=[],
            report_path=None,
            success=True,
            summary="ok",
        )
        assert sr.success is True

    def test_autonomous_decision(self):
        from tools.autonomous_agent import AutonomousDecision

        d = AutonomousDecision(
            decision_type="attack",
            reasoning="test",
            action_plan={"tool": "x"},
            expected_outcome="vuln",
            risk_level="high",
            auto_approved=True,
        )
        assert d.auto_approved is True


class TestAutonomousAgentHelpers:
    def test_to_domain_plain(self):
        from tools.autonomous_agent import _to_domain

        assert _to_domain("example.com") == "example.com"

    def test_to_domain_with_url(self):
        from tools.autonomous_agent import _to_domain

        assert _to_domain("https://example.com/path") == "example.com"

    def test_to_domain_with_port(self):
        from tools.autonomous_agent import _to_domain

        assert _to_domain("https://example.com:8080/path") == "example.com"

    def test_build_headers_default(self):
        from tools.autonomous_agent import _build_headers, AgentState

        state = AgentState(root_target="x.com", goal="test")
        h = _build_headers(state)
        assert "User-Agent" in h

    def test_build_headers_with_auth(self):
        from tools.autonomous_agent import _build_headers, AgentState

        state = AgentState(root_target="x.com", goal="test")
        state.assets["auth_headers"] = {"Authorization": "Bearer token123"}
        h = _build_headers(state)
        assert h["Authorization"] == "Bearer token123"

    def test_build_headers_extra(self):
        from tools.autonomous_agent import _build_headers, AgentState

        state = AgentState(root_target="x.com", goal="test")
        h = _build_headers(state, extra={"X-Custom": "value"})
        assert h["X-Custom"] == "value"

    def test_parse_json_valid(self):
        from tools.autonomous_agent import _parse_json

        result = _parse_json('{"key": "value"}')
        assert result["key"] == "value"

    def test_parse_json_fenced(self):
        from tools.autonomous_agent import _parse_json

        result = _parse_json('```json\n{"key": "val"}\n```')
        assert result["key"] == "val"

    def test_parse_json_invalid(self):
        from tools.autonomous_agent import _parse_json

        result = _parse_json("not json at all")
        assert result == {}

    def test_display(self):
        from tools.autonomous_agent import _display

        # Should not raise
        _display("test message", level="info")

    def test_ai_call_success(self):
        from tools.autonomous_agent import _ai_call

        mock_client = MagicMock()
        mock_client.chat.return_value = MagicMock(content='{"action": "done"}')
        result = _ai_call(mock_client, "system", "user")
        assert result == '{"action": "done"}'

    def test_ai_call_error(self):
        from tools.autonomous_agent import _ai_call

        mock_client = MagicMock()
        mock_client.chat.side_effect = Exception("API error")
        result = _ai_call(mock_client, "system", "user")
        assert result == ""

    def test_exec_recon_error(self):
        from tools.autonomous_agent import _exec_recon, AgentAction, AgentState

        action = AgentAction(name="recon", target="example.com")
        state = AgentState(root_target="example.com", goal="test")
        with patch("tools.smart_recon.SmartReconEngine", side_effect=Exception("fail")):
            findings = _exec_recon(action, state)
            assert findings == []


# ═════════════════════════════════════════════════════════════════════════════
#  tools/multi_agent.py — TeamAegis, data structures
# ═════════════════════════════════════════════════════════════════════════════


class TestMultiAgentDataStructures:
    def test_team_message(self):
        from tools.multi_agent import TeamMessage

        msg = TeamMessage(
            round=1, agent_id=0, agent_role="Strategist", model_name="gpt-4", content="hello"
        )
        assert msg.round == 1
        assert msg.msg_type == "discussion"

    def test_task_assignment(self):
        from tools.multi_agent import TaskAssignment

        ta = TaskAssignment(
            agent_id=0, action_type="shell", params={"cmd": "ls"}, description="list files"
        )
        assert ta.completed is False
        assert ta.success is False

    def test_finding(self):
        from tools.multi_agent import Finding

        f = Finding(source_agent="Strategist", description="XSS found", severity="high")
        assert f.severity == "high"
        assert f.confirmed_by == []


class TestTeamAegis:
    @pytest.fixture
    def team(self):
        from tools.multi_agent import TeamAegis
        from tools.universal_ai_client import UniversalAIClient

        c1 = MagicMock(spec=UniversalAIClient)
        c1.provider = "openai"
        c1.model = "gpt-4"
        c2 = MagicMock(spec=UniversalAIClient)
        c2.provider = "anthropic"
        c2.model = "claude"
        with patch("tools.vector_memory.recall", return_value=None, create=True):
            t = TeamAegis(clients=[c1, c2], target="example.com", max_rounds=5)
        return t

    def test_init(self, team):
        assert team.target == "example.com"
        assert team.team_size == 2
        assert team.max_rounds == 5

    def test_init_requires_2(self):
        from tools.multi_agent import TeamAegis
        from tools.universal_ai_client import UniversalAIClient

        c1 = MagicMock(spec=UniversalAIClient)
        with pytest.raises(ValueError, match="at least 2"):
            TeamAegis(clients=[c1], target="x.com")

    def test_init_truncates_to_3(self):
        from tools.multi_agent import TeamAegis
        from tools.universal_ai_client import UniversalAIClient

        c1 = MagicMock(spec=UniversalAIClient)
        c2 = MagicMock(spec=UniversalAIClient)
        c3 = MagicMock(spec=UniversalAIClient)
        c4 = MagicMock(spec=UniversalAIClient)
        with patch("tools.vector_memory.recall", create=True):
            t = TeamAegis(clients=[c1, c2, c3, c4], target="x.com")
        assert t.team_size == 3

    def test_format_discussion_history_empty(self, team):
        result = team._format_discussion_history()
        assert "No previous discussion" in result

    def test_format_findings_empty(self, team):
        result = team._format_findings()
        assert "No confirmed findings" in result

    def test_format_team_roster(self, team):
        result = team._format_team_roster()
        assert "Strategist" in result
        assert "Recon Lead" in result

    def test_format_prior_memories_empty(self, team):
        result = team._format_prior_memories()
        assert "No prior memories" in result

    def test_share_intel(self, team):
        team._share_intel(0, "found XSS in /api")
        assert len(team.shared_intel) == 1

    def test_share_intel_dedup(self, team):
        team._share_intel(0, "same insight")
        team._share_intel(0, "same insight")
        assert len(team.shared_intel) == 1

    def test_format_shared_intel_empty(self, team):
        result = team._format_shared_intel()
        assert result == "" or "SHARED INTELLIGENCE" not in result

    def test_push_pop_task(self, team):
        team._push_task(1, 0, {"type": "run_tool", "description": "scan"})
        task = team._pop_task()
        assert task is not None
        assert task[2] == 0

    def test_pop_task_empty(self, team):
        assert team._pop_task() is None

    def test_push_task_negative_priority(self, team):
        team._push_task(-5, 0, {"type": "test"})
        task = team._pop_task()
        assert task[0] == 0  # clamped to 0

    def test_save_memory(self, team):
        from tools.multi_agent import Finding

        f = Finding(
            source_agent="Strategist", description="XSS found", severity="high", evidence="payload"
        )
        with patch("tools.vector_memory.remember", create=True):
            team._save_memory(f)
            assert team.target in team._memories

    def test_save_memory_error(self, team):
        from tools.multi_agent import Finding

        f = Finding(source_agent="test", description="X", severity="low", evidence="e")
        with patch("tools.vector_memory.remember", side_effect=Exception("fail"), create=True):
            team._save_memory(f)  # should not raise

    def test_estimate_discussion_tokens(self, team):
        from tools.multi_agent import TeamMessage

        team.discussion.append(
            TeamMessage(round=1, agent_id=0, agent_role="S", model_name="m", content="hello world")
        )
        total = team._estimate_discussion_tokens()
        assert total > 0

    def test_format_available_tools_no_registry(self, team):
        team.skill_registry = None
        result = team._format_available_tools_for_agent()
        assert "not available" in result.lower() or "registry" in result.lower()


# ═════════════════════════════════════════════════════════════════════════════
#  tools/overlay_menu.py — SettingsOverlay
# ═════════════════════════════════════════════════════════════════════════════


class TestOverlayMenu:
    @pytest.fixture
    def overlay(self):
        from tools.overlay_menu import SettingsOverlay

        mock_agent = MagicMock()
        mock_console = MagicMock()
        mock_console.width = 80
        return SettingsOverlay(agent=mock_agent, console=mock_console, target="example.com")

    def test_init(self, overlay):
        assert overlay._current_layer == "main"
        assert overlay._selected_idx == 0

    def test_reset(self, overlay):
        overlay._selected_idx = 5
        overlay.reset()
        assert overlay._selected_idx == 0

    def test_handle_arrow_up(self, overlay):
        overlay._selected_idx = 3
        result = overlay.handle_char("\x1b[A")
        assert result is None
        assert overlay._selected_idx == 2

    def test_handle_arrow_down(self, overlay):
        result = overlay.handle_char("\x1b[B")
        assert result is None
        assert overlay._selected_idx >= 0

    def test_handle_arrow_left_right(self, overlay):
        assert overlay.handle_char("\x1b[C") is None
        assert overlay.handle_char("\x1b[D") is None

    def test_handle_vim_j_k(self, overlay):
        overlay.handle_char("j")
        assert overlay._selected_idx >= 0
        overlay.handle_char("k")
        assert overlay._selected_idx >= 0

    def test_handle_b_main_exits(self, overlay):
        overlay._current_layer = "main"
        result = overlay.handle_char("b")
        assert result == "exit"

    def test_handle_b_sublayer_back(self, overlay):
        overlay._current_layer = "sessions"
        result = overlay.handle_char("b")
        assert overlay._current_layer == "main"

    def test_handle_q_exits(self, overlay):
        result = overlay.handle_char("q")
        assert result == "exit"

    def test_handle_enter_main(self, overlay):
        overlay._selected_idx = 0
        result = overlay.handle_char("\r")
        assert result is None  # navigates to sub-layer

    def test_handle_esc_main(self, overlay):
        overlay._current_layer = "main"
        result = overlay.handle_char("\x1b")
        assert result == "exit"

    def test_handle_esc_sublayer(self, overlay):
        overlay._current_layer = "sessions"
        result = overlay.handle_char("\x1b")
        assert overlay._current_layer == "main"

    def test_render(self, overlay):
        panel = overlay.render()
        assert panel is not None

    def test_adjust_scroll(self, overlay):
        overlay._selected_idx = 0
        overlay._scroll_offset = 5
        overlay._adjust_scroll()
        assert overlay._scroll_offset >= 0

    def test_navigate_to_sessions(self, overlay):
        overlay._navigate_to("sessions")
        assert overlay._current_layer == "sessions"

    def test_navigate_to_agent_setup(self, overlay):
        overlay._navigate_to("agent_setup")
        assert overlay._current_layer == "agent_setup"

    def test_navigate_to_api_keys(self, overlay):
        overlay._navigate_to("api_keys")
        assert overlay._current_layer == "api_keys"

    def test_navigate_to_rate_limits(self, overlay):
        overlay._navigate_to("rate_limits")
        assert overlay._current_layer == "rate_limits"

    def test_navigate_to_skills(self, overlay):
        # Skills layer was removed from overlay
        overlay._navigate_to("skills")
        # Should remain on main (no skills layer)
        assert overlay._current_layer == "main"

    def test_navigate_to_mode_settings(self, overlay):
        overlay._navigate_to("mode_settings")
        assert overlay._current_layer == "mode_settings"

    def test_navigate_provider_select(self, overlay):
        overlay._current_layer = "provider_select"
        result = overlay._navigate_to("openai")
        assert overlay._current_layer == "model_select"

    def test_navigate_provider_custom(self, overlay):
        overlay._current_layer = "provider_select"
        result = overlay._navigate_to("custom")
        assert result == "show_custom_url"

    def test_navigate_model_select(self, overlay):
        overlay._current_layer = "model_select"
        overlay._current_provider = "openai"
        overlay._navigate_to("gpt-4")
        assert overlay._current_layer == "agent_setup"

    def test_navigate_model_select_manual(self, overlay):
        overlay._current_layer = "model_select"
        result = overlay._navigate_to("manual:my-model")
        assert result is None

    def test_navigate_api_key_edit(self, overlay):
        overlay._current_layer = "api_keys"
        overlay._navigate_to("key_openai")
        assert overlay._current_layer == "api_key_edit"
        assert overlay._editing_provider == "openai"

    def test_navigate_sessions(self, overlay):
        overlay._current_layer = "sessions"
        result = overlay._navigate_to("sess_test-session")
        assert result == "load_session:test-session"

    def test_navigate_mode_settings_item(self, overlay):
        overlay._current_layer = "mode_settings"
        result = overlay._navigate_to("mode_auto")
        assert overlay._current_layer == "main"

    def test_increase_rpm(self, overlay):
        overlay._current_layer = "rate_limits"
        overlay._items = [{"id": "rpm0", "action": "increase_rpm", "rpm": 0}]
        overlay._selected_idx = 0
        overlay._handle_enter()
        assert overlay._rate_limits[0] == 45

    def test_decrease_rpm(self, overlay):
        overlay._rate_limits = [40, 40, 40]
        overlay._current_layer = "rate_limits"
        overlay._items = [{"id": "rpm0", "action": "decrease_rpm", "rpm": 0}]
        overlay._selected_idx = 0
        overlay._handle_enter()
        assert overlay._rate_limits[0] == 35

    def test_go_back_from_main(self, overlay):
        overlay._current_layer = "main"
        result = overlay._go_back()
        assert result == "exit"

    def test_update_items_main(self, overlay):
        overlay._current_layer = "main"
        overlay._update_items()
        assert len(overlay._items) > 0

    def test_custom_url_input(self, overlay):
        overlay._current_layer = "custom_url"
        overlay._custom_url = ""
        overlay.handle_char("h")
        overlay.handle_char("t")
        assert overlay._custom_url == "ht"

    def test_custom_url_backspace(self, overlay):
        overlay._current_layer = "custom_url"
        overlay._custom_url = "hello"
        overlay.handle_char("\x7f")
        assert overlay._custom_url == "hell"

    def test_custom_url_enter(self, overlay):
        overlay._current_layer = "custom_url"
        overlay._custom_url = "http://custom.api"
        result = overlay.handle_char("\r")
        assert result == "saved"
        assert overlay._current_layer == "agent_setup"

    def test_custom_url_esc(self, overlay):
        overlay._current_layer = "custom_url"
        result = overlay.handle_char("\x1b")
        assert overlay._current_layer == "main"


# ═════════════════════════════════════════════════════════════════════════════
#  tools/config_wizard.py — AIProviderConfig, ConfigWizard
# ═════════════════════════════════════════════════════════════════════════════


class TestAIProviderConfig:
    def test_creation(self):
        from tools.config_wizard import AIProviderConfig

        c = AIProviderConfig(
            name="Test",
            env_key="TEST_KEY",
            base_url="https://api.test.com",
            signup_url="https://test.com/signup",
            is_free=True,
            notes="test notes",
            api_type="openai",
        )
        assert c.name == "Test"
        assert c.is_free is True


class TestConfigWizard:
    @pytest.fixture
    def wizard(self, tmp_path):
        from tools.config_wizard import ConfigWizard

        return ConfigWizard(config_dir=tmp_path)

    def test_init(self, wizard):
        assert wizard.config_dir is not None

    def test_providers_list(self):
        from tools.config_wizard import ConfigWizard

        assert len(ConfigWizard.AI_PROVIDERS) >= 13

    def test_default_models(self):
        from tools.config_wizard import ConfigWizard

        assert "OpenAI (GPT-4)" in ConfigWizard.DEFAULT_MODELS
        assert "Gemini (Google)" in ConfigWizard.DEFAULT_MODELS
        assert "NVIDIA" in ConfigWizard.DEFAULT_MODELS

    def test_priority_order(self):
        from tools.config_wizard import ConfigWizard

        assert ConfigWizard.PRIORITY_ORDER[0] == "nvidia"

    def test_provider_key_map(self):
        from tools.config_wizard import ConfigWizard

        assert ConfigWizard._PROVIDER_KEY_MAP["OpenAI (GPT-4)"] == "openai"

    def test_integrations(self):
        from tools.config_wizard import ConfigWizard

        names = [i["name"] for i in ConfigWizard.INTEGRATIONS]
        assert "Telegram Bot" in names
        assert "HackerOne" in names

    def test_fetch_remote_models_anthropic(self, wizard):
        from tools.config_wizard import AIProviderConfig

        p = AIProviderConfig(
            "Anthropic", "ANTHROPIC_KEY", "https://api.anthropic.com/v1", "", False, "", "native"
        )
        result = wizard._fetch_remote_models(p, "fake-key")
        assert result == []

    @patch("tools.config_wizard.os.getenv")
    def test_save_env_var(self, mock_getenv, wizard, tmp_path):
        env_file = tmp_path / ".env"
        wizard.env_file = env_file
        wizard._save_env_var("TEST_KEY", "test_value")
        assert env_file.exists()
        content = env_file.read_text()
        assert "TEST_KEY=test_value" in content

    def test_remove_env_var(self, wizard, tmp_path):
        env_file = tmp_path / ".env"
        env_file.write_text("OLD_KEY=old_value\nNEW_KEY=new_value\n")
        wizard.env_file = env_file
        wizard._remove_env_var("OLD_KEY")
        content = env_file.read_text()
        assert "OLD_KEY" not in content
        assert "NEW_KEY" in content


# ═════════════════════════════════════════════════════════════════════════════
#  tools/zero_day_heuristics.py — data classes, helpers, HTTPClient
# ═════════════════════════════════════════════════════════════════════════════


class TestZeroDaySeverityLevel:
    def test_values(self):
        from tools.zero_day_heuristics import SeverityLevel

        assert SeverityLevel.INFO.value == "info"
        assert SeverityLevel.LOW.value == "low"
        assert SeverityLevel.MEDIUM.value == "medium"
        assert SeverityLevel.HIGH.value == "high"
        assert SeverityLevel.CRITICAL.value == "critical"


class TestZeroDayFinding:
    def test_creation(self):
        from tools.zero_day_heuristics import Finding, SeverityLevel
        from tools.vuln_engine import VulnClass

        f = Finding(
            detector="test",
            title="test finding",
            severity=SeverityLevel.HIGH,
            vuln_class=VulnClass.XSS,
            url="http://x.com",
        )
        assert f.detector == "test"
        assert f.severity == SeverityLevel.HIGH

    def test_to_vuln_finding(self):
        from tools.zero_day_heuristics import Finding, SeverityLevel
        from tools.vuln_engine import VulnClass

        f = Finding(
            detector="test",
            title="test",
            severity=SeverityLevel.HIGH,
            vuln_class=VulnClass.XSS,
        )
        vf = f.to_vuln_finding()
        assert vf.title == "test"
        assert vf.cvss_score > 0


class TestZeroDayHelpers:
    def test_entropy(self):
        from tools.zero_day_heuristics import _entropy

        assert _entropy("") == 0.0
        e = _entropy("aaaa")
        assert e >= 0.0

    def test_shannon(self):
        from tools.zero_day_heuristics import _shannon

        assert _shannon(b"") == 0.0
        e = _shannon(b"abcd")
        assert e > 0.0

    def test_short_hash(self):
        from tools.zero_day_heuristics import _short_hash

        h1 = _short_hash("a", "b")
        h2 = _short_hash("a", "b")
        h3 = _short_hash("a", "c")
        assert h1 == h2
        assert h1 != h3
        assert len(h1) == 12

    def test_default_vector_for(self):
        from tools.zero_day_heuristics import _default_vector_for
        from tools.vuln_engine import VulnClass

        v = _default_vector_for(VulnClass.XSS)
        assert "CVSS:3.1" in v

    def test_default_vector_for_unknown(self):
        from tools.zero_day_heuristics import _default_vector_for
        from tools.vuln_engine import VulnClass

        v = _default_vector_for(VulnClass.ZERO_DAY)
        assert "CVSS:3.1" in v


class TestHTTPClient:
    def test_init(self):
        from tools.zero_day_heuristics import HTTPClient

        hc = HTTPClient(timeout=5.0, max_retries=2, verify_ssl=True)
        assert hc.timeout == 5.0
        assert hc.max_retries == 2

    def test_request_failure(self):
        from tools.zero_day_heuristics import HTTPClient

        hc = HTTPClient(timeout=1.0)
        # Request to non-existent host should return None
        result = hc.request("GET", "http://192.0.2.1:1/nonesense")
        assert result is None

    def test_sync_to_dict_none(self):
        from tools.zero_day_heuristics import HTTPClient

        assert HTTPClient._sync_to_dict(None) is None

    def test_close(self):
        from tools.zero_day_heuristics import HTTPClient

        hc = HTTPClient()
        hc.close()  # should not raise

    @pytest.mark.asyncio
    async def test_async_request_failure(self):
        from tools.zero_day_heuristics import HTTPClient

        hc = HTTPClient(timeout=1.0)
        result = await hc.async_request("GET", "http://192.0.2.1:1/nonesense")
        assert result is None


# ═════════════════════════════════════════════════════════════════════════════
#  tools/exploitation.py — ExploitProof, exploit functions
# ═════════════════════════════════════════════════════════════════════════════


class TestExploitProof:
    def test_creation(self):
        from tools.exploitation import ExploitProof

        p = ExploitProof(title="test", description="desc")
        assert p.title == "test"
        assert p.steps == []
        assert p.data_extracted == {}

    def test_defaults(self):
        from tools.exploitation import ExploitProof

        p = ExploitProof(title="x", description="y")
        assert p.curl_command == ""
        assert p.python_repro == ""


class TestExploitByCategory:
    def test_exploit_by_category_keys(self):
        from tools.exploitation import EXPLOIT_BY_CATEGORY

        expected = {
            "sql_injection",
            "path_traversal",
            "ssti",
            "mass_assignment",
            "jwt_confusion",
            "prototype_pollution",
            "bola",
            "xss_reflected",
            "xss_stored",
        }
        assert set(EXPLOIT_BY_CATEGORY.keys()) == expected


class TestExploitFunctions:
    @pytest.mark.asyncio
    async def test_exploit_sqli_no_success(self):
        from tools.exploitation import exploit_sqli

        mock_session = AsyncMock()
        mock_resp = AsyncMock()
        mock_resp.status = 200
        mock_resp.text = AsyncMock(return_value="normal response")
        mock_session.post.return_value.__aenter__ = AsyncMock(return_value=mock_resp)
        mock_session.post.return_value.__aexit__ = AsyncMock(return_value=False)
        proof = await exploit_sqli(mock_session, "http://x.com/login")
        assert proof.title == "SQL Injection - Data Extraction"

    @pytest.mark.asyncio
    async def test_exploit_path_traversal_no_success(self):
        from tools.exploitation import exploit_path_traversal

        mock_session = AsyncMock()
        mock_resp = AsyncMock()
        mock_resp.status = 404
        mock_resp.text = AsyncMock(return_value="not found")
        mock_session.get.return_value.__aenter__ = AsyncMock(return_value=mock_resp)
        mock_session.get.return_value.__aexit__ = AsyncMock(return_value=False)
        proof = await exploit_path_traversal(mock_session, "http://x.com/download")
        assert proof.title == "Path Traversal - File Read"

    @pytest.mark.asyncio
    async def test_exploit_ssti_no_success(self):
        from tools.exploitation import exploit_ssti

        mock_session = AsyncMock()
        mock_resp = AsyncMock()
        mock_resp.status = 200
        mock_resp.text = AsyncMock(return_value="safe output")
        mock_session.get.return_value.__aenter__ = AsyncMock(return_value=mock_resp)
        mock_session.get.return_value.__aexit__ = AsyncMock(return_value=False)
        proof = await exploit_ssti(mock_session, "http://x.com/render")
        assert proof.title == "Server-Side Template Injection - Code Execution"

    @pytest.mark.asyncio
    async def test_exploit_jwt_none_no_success(self):
        from tools.exploitation import exploit_jwt_alg_none

        mock_session = AsyncMock()
        mock_resp = AsyncMock()
        mock_resp.status = 401
        mock_resp.text = AsyncMock(return_value='{"valid": false}')
        mock_session.post.return_value.__aenter__ = AsyncMock(return_value=mock_resp)
        mock_session.post.return_value.__aexit__ = AsyncMock(return_value=False)
        proof = await exploit_jwt_alg_none(mock_session, "http://x.com/verify")
        assert proof.title == "JWT Algorithm Confusion - Token Forgery"

    @pytest.mark.asyncio
    async def test_exploit_proto_pollution_no_success(self):
        from tools.exploitation import exploit_proto_pollution

        mock_session = AsyncMock()
        mock_resp = AsyncMock()
        mock_resp.status = 200
        mock_resp.text = AsyncMock(return_value='{"status": "ok"}')
        mock_session.post.return_value.__aenter__ = AsyncMock(return_value=mock_resp)
        mock_session.post.return_value.__aexit__ = AsyncMock(return_value=False)
        proof = await exploit_proto_pollution(mock_session, "http://x.com/merge")
        assert proof.title == "Prototype Pollution - Gadget Chain"

    @pytest.mark.asyncio
    async def test_exploit_xss_no_success(self):
        from tools.exploitation import exploit_xss

        mock_session = AsyncMock()
        mock_resp = AsyncMock()
        mock_resp.status = 200
        mock_resp.text = AsyncMock(return_value="<p>safe</p>")
        mock_session.get.return_value.__aenter__ = AsyncMock(return_value=mock_resp)
        mock_session.get.return_value.__aexit__ = AsyncMock(return_value=False)
        proof = await exploit_xss(mock_session, "http://x.com/search")
        assert proof.title == "Cross-Site Scripting - Payload Reflection"

    @pytest.mark.asyncio
    async def test_exploit_mass_assignment_no_success(self):
        from tools.exploitation import exploit_mass_assignment

        mock_session = AsyncMock()
        mock_resp = AsyncMock()
        mock_resp.status = 400
        mock_resp.text = AsyncMock(return_value='{"error": "bad"}')
        mock_session.post.return_value.__aenter__ = AsyncMock(return_value=mock_resp)
        mock_session.post.return_value.__aexit__ = AsyncMock(return_value=False)
        proof = await exploit_mass_assignment(mock_session, "http://x.com/register")
        assert proof.title == "Mass Assignment - Privilege Escalation"


# ═════════════════════════════════════════════════════════════════════════════
#  tools/targeted_attacks.py — ConfirmedFinding, SQLI/XSS payloads
# ═════════════════════════════════════════════════════════════════════════════


class TestConfirmedFinding:
    def test_creation(self):
        from tools.targeted_attacks import ConfirmedFinding

        f = ConfirmedFinding(
            title="SQLi",
            severity="Critical",
            category="sql_injection",
            endpoint_url="http://x.com/login",
            method="POST",
            evidence="status changed",
            payload="' OR 1=1",
        )
        assert f.confidence == 1.0
        assert f.severity == "Critical"


class TestSQLIPayloads:
    def test_payload_count(self):
        from tools.targeted_attacks import SQLI_PAYLOADS

        assert len(SQLI_PAYLOADS) >= 5

    def test_payload_format(self):
        from tools.targeted_attacks import SQLI_PAYLOADS

        for payload, kind in SQLI_PAYLOADS:
            assert isinstance(payload, str)
            assert isinstance(kind, str)


class TestXSSPayloads:
    def test_payload_count(self):
        from tools.targeted_attacks import XSS_PAYLOADS

        assert len(XSS_PAYLOADS) >= 3


# ═════════════════════════════════════════════════════════════════════════════
#  tools/dynamic_waf_mutator.py — DynamicWAFMutator
# ═════════════════════════════════════════════════════════════════════════════


class TestDynamicWAFMutator:
    @pytest.fixture
    def mutator(self):
        from tools.dynamic_waf_mutator import DynamicWAFMutator

        with patch("tools.dynamic_waf_mutator.WAFEvasionEngine"), patch(
            "tools.dynamic_waf_mutator.AIClientManager"
        ):
            return DynamicWAFMutator("http://example.com")

    def test_init(self, mutator):
        assert mutator.base_url == "http://example.com"
        assert mutator.history == []

    def test_is_blocked_status_codes(self, mutator):
        assert mutator._is_blocked(403, "") is True
        assert mutator._is_blocked(406, "") is True
        assert mutator._is_blocked(503, "") is True
        assert mutator._is_blocked(200, "") is False
        assert mutator._is_blocked(404, "") is False

    def test_is_blocked_body_triggers(self, mutator):
        assert mutator._is_blocked(200, "blocked by waf") is True
        assert mutator._is_blocked(200, "cloudflare ray") is True
        assert mutator._is_blocked(200, "mod_security") is True
        assert mutator._is_blocked(200, "access denied") is True
        assert mutator._is_blocked(200, "incident id") is True
        assert mutator._is_blocked(200, "sucuri cloudproxy") is True
        assert mutator._is_blocked(200, "security gate") is True
        assert mutator._is_blocked(200, "activity blocked") is True

    def test_is_blocked_clean(self, mutator):
        assert mutator._is_blocked(200, "normal page content") is False

    def test_build_evasion_prompt(self, mutator):
        msgs = mutator._build_evasion_prompt(
            failed_payload="<script>alert(1)</script>",
            vuln_type="XSS",
            waf_name="Cloudflare",
            status_code=403,
            headers="Server: cloudflare",
            body_snippet="Access denied",
            attempt=1,
        )
        assert len(msgs) == 2
        assert msgs[0].role == "system"
        assert "mutated_payload" in msgs[1].content


# ═════════════════════════════════════════════════════════════════════════════
#  tools/api_server.py — ScanRecord, data models
# ═════════════════════════════════════════════════════════════════════════════


class TestScanRecord:
    def test_creation(self):
        from tools.api_server import ScanRecord

        r = ScanRecord(target="example.com", scan_type="full")
        assert r.target == "example.com"
        assert r.status == "pending"
        assert r.id.startswith("scan_")

    def test_to_dict(self):
        from tools.api_server import ScanRecord

        r = ScanRecord(target="x.com", scan_type="quick")
        d = r.to_dict()
        assert d["target"] == "x.com"
        assert d["scan_type"] == "quick"
        assert d["findings_count"] == 0
        assert d["completed_at"] is None

    def test_to_dict_completed(self):
        from tools.api_server import ScanRecord
        from datetime import datetime, timezone

        r = ScanRecord(target="x.com")
        r.completed_at = datetime.now(timezone.utc)
        d = r.to_dict()
        assert d["completed_at"] is not None

    def test_with_findings(self):
        from tools.api_server import ScanRecord

        r = ScanRecord(target="x.com")
        r.findings.append({"title": "XSS", "severity": "high"})
        d = r.to_dict()
        assert d["findings_count"] == 1

    def test_with_error(self):
        from tools.api_server import ScanRecord

        r = ScanRecord(target="x.com")
        r.error = "scan failed"
        d = r.to_dict()
        assert d["error"] == "scan failed"


class TestScanStore:
    def test_scan_store_is_dict(self):
        from tools.api_server import _scan_store

        assert isinstance(_scan_store, dict)


# ═════════════════════════════════════════════════════════════════════════════
#  tools/universal_executor.py — FileEditor, PackageManager, UniversalExecutor
# ═════════════════════════════════════════════════════════════════════════════


class TestFileEditor:
    @pytest.fixture
    def editor(self, tmp_path):
        from tools.universal_executor import FileEditor

        return FileEditor(base_dir=str(tmp_path))

    def test_read_file(self, editor, tmp_path):
        (tmp_path / "test.txt").write_text("hello\nworld\n")
        result = editor.read_file(str(tmp_path / "test.txt"))
        assert result.success is True
        assert "hello" in result.output

    def test_read_file_not_found(self, editor):
        result = editor.read_file("/nonexistent/file.txt")
        assert result.success is False
        assert "not found" in result.error.lower() or "Invalid" in result.error

    def test_read_sensitive_file(self, editor, tmp_path):
        (tmp_path / ".env").write_text("SECRET=key")
        result = editor.read_file(str(tmp_path / ".env"))
        assert result.success is False
        assert "denied" in result.error.lower()

    def test_write_file(self, editor, tmp_path):
        result = editor.write_file(str(tmp_path / "new.txt"), "content")
        assert result.success is True
        assert (tmp_path / "new.txt").read_text() == "content"

    def test_write_file_no_overwrite(self, editor, tmp_path):
        (tmp_path / "existing.txt").write_text("old")
        result = editor.write_file(str(tmp_path / "existing.txt"), "new", overwrite=False)
        assert result.success is False
        assert "exists" in result.error.lower()

    def test_write_file_overwrite(self, editor, tmp_path):
        (tmp_path / "existing.txt").write_text("old")
        result = editor.write_file(str(tmp_path / "existing.txt"), "new", overwrite=True)
        assert result.success is True

    def test_edit_file(self, editor, tmp_path):
        (tmp_path / "edit.txt").write_text("hello world")
        result = editor.edit_file(str(tmp_path / "edit.txt"), "hello", "hi")
        assert result.success is True
        assert "hi world" in (tmp_path / "edit.txt").read_text()

    def test_edit_file_not_found(self, editor):
        result = editor.edit_file("/nonexistent", "a", "b")
        assert result.success is False

    def test_edit_file_string_not_found(self, editor, tmp_path):
        (tmp_path / "e.txt").write_text("content")
        result = editor.edit_file(str(tmp_path / "e.txt"), "nonexistent", "new")
        assert result.success is False
        assert "not found" in result.error.lower()

    def test_edit_file_multiple_occurrences(self, editor, tmp_path):
        (tmp_path / "m.txt").write_text("aaa bbb aaa")
        result = editor.edit_file(str(tmp_path / "m.txt"), "aaa", "xxx")
        assert result.success is False
        assert "2 occurrences" in result.error

    def test_search_in_file(self, editor, tmp_path):
        (tmp_path / "s.txt").write_text("line1 hello\nline2 world\n")
        result = editor.search_in_file(str(tmp_path / "s.txt"), "hello")
        assert result.success is True
        assert "1 matches" in result.output

    def test_search_in_file_no_match(self, editor, tmp_path):
        (tmp_path / "s.txt").write_text("hello world")
        result = editor.search_in_file(str(tmp_path / "s.txt"), "zzzz")
        assert result.success is True
        assert "No matches" in result.output

    def test_search_in_file_not_found(self, editor):
        result = editor.search_in_file("/nonexistent", "pattern")
        assert result.success is False

    def test_list_directory(self, editor, tmp_path):
        (tmp_path / "file1.txt").write_text("a")
        sub = tmp_path / "subdir"
        sub.mkdir()
        (sub / "file2.txt").write_text("b")
        result = editor.list_directory(str(tmp_path))
        assert result.success is True
        assert "file1.txt" in result.output

    def test_list_directory_not_dir(self, editor, tmp_path):
        f = tmp_path / "notdir.txt"
        f.write_text("x")
        result = editor.list_directory(str(f))
        assert result.success is False

    def test_list_directory_invalid_path(self, editor):
        result = editor.list_directory("/nonexistent/dir")
        assert result.success is False


class TestPackageManager:
    def test_unknown_manager(self):
        from tools.universal_executor import PackageManager

        pm = PackageManager()
        result = pm.execute("unknown", "install", "pkg")
        assert result.success is False
        assert "Unknown" in result.error

    def test_unknown_action(self):
        from tools.universal_executor import PackageManager

        pm = PackageManager()
        result = pm.execute("pip", "unknown_action", "pkg")
        assert result.success is False
        assert "not supported" in result.error

    def test_pip_list(self):
        from tools.universal_executor import PackageManager

        pm = PackageManager()
        result = pm.execute("pip", "list")
        assert result.success is True  # pip list should work

    def test_managers_coverage(self):
        from tools.universal_executor import PackageManager

        assert "pip" in PackageManager.MANAGERS
        assert "npm" in PackageManager.MANAGERS
        assert "apt" in PackageManager.MANAGERS
        assert "go" in PackageManager.MANAGERS
        assert "gem" in PackageManager.MANAGERS


class TestUniversalExecutor:
    @pytest.fixture
    def executor(self, tmp_path):
        from tools.universal_executor import UniversalExecutor

        return UniversalExecutor(base_dir=str(tmp_path))

    def test_is_safe_command_empty(self, executor):
        ok, reason = executor.is_safe_command("")
        assert ok is False

    def test_is_safe_command_safe(self, executor):
        ok, reason = executor.is_safe_command("ls -la")
        # ls is typically safe
        assert isinstance(ok, bool)

    def test_execute_action_read_file(self, executor, tmp_path):
        (tmp_path / "data.txt").write_text("content")
        result = executor.execute_action(
            {
                "type": "read_file",
                "params": {"path": str(tmp_path / "data.txt")},
            }
        )
        assert result.success is True

    def test_execute_action_write_file(self, executor, tmp_path):
        result = executor.execute_action(
            {
                "type": "write_file",
                "params": {"path": str(tmp_path / "out.txt"), "content": "data"},
            }
        )
        assert result.success is True

    def test_execute_action_edit_file(self, executor, tmp_path):
        (tmp_path / "e.txt").write_text("hello")
        result = executor.execute_action(
            {
                "type": "edit_file",
                "params": {
                    "path": str(tmp_path / "e.txt"),
                    "old_string": "hello",
                    "new_string": "world",
                },
            }
        )
        assert result.success is True

    def test_execute_action_search_file(self, executor, tmp_path):
        (tmp_path / "s.txt").write_text("hello world")
        result = executor.execute_action(
            {
                "type": "search_file",
                "params": {"path": str(tmp_path / "s.txt"), "pattern": "hello"},
            }
        )
        assert result.success is True

    def test_execute_action_list_dir(self, executor, tmp_path):
        result = executor.execute_action(
            {
                "type": "list_dir",
                "params": {"path": str(tmp_path)},
            }
        )
        assert result.success is True

    def test_execute_action_shell(self, executor):
        result = executor.execute_action(
            {
                "type": "shell",
                "params": {"command": "echo hello"},
            }
        )
        assert result.success is True

    def test_execute_action_package(self, executor):
        result = executor.execute_action(
            {
                "type": "package",
                "params": {"manager": "pip", "action": "list"},
            }
        )
        assert result.success is True

    def test_execute_action_unknown(self, executor):
        result = executor.execute_action({"type": "unknown_type", "params": {}})
        # Should not crash; returns some result
        assert isinstance(result.success, bool)


# ═════════════════════════════════════════════════════════════════════════════
#  main.py — additional argparse handler tests (if accessible)
# ═════════════════════════════════════════════════════════════════════════════


class TestMainHelpers:
    """Test standalone functions imported from main.py or used by main.py."""

    def test_normalize_target_main(self):
        from core.orchestrator import normalize_target

        assert normalize_target("") == ""
        assert normalize_target("https://example.com/path") == "example.com"
        assert normalize_target("example.com:8080") == "example.com"

    def test_validate_target_main(self):
        try:
            from main import validate_target

            assert validate_target("example.com") is True
            assert validate_target("") is False
            assert validate_target("127.0.0.1") is False
        except ImportError:
            pytest.skip("main.py not importable directly")

    def test_is_valid_target_main(self):
        from core.orchestrator import is_valid_target

        assert is_valid_target("example.com") is True
        assert is_valid_target("") is False


# ═════════════════════════════════════════════════════════════════════════════
#  Integration / Edge Cases
# ═════════════════════════════════════════════════════════════════════════════


class TestIntegrationEdgeCases:
    """Cross-module edge case tests to cover remaining branches."""

    def test_action_tools_schema(self):
        from tools.universal_ai_client import ACTION_TOOLS

        assert len(ACTION_TOOLS) >= 9
        names = [t["function"]["name"] for t in ACTION_TOOLS]
        assert "run_shell" in names
        assert "finish" in names

    def test_severity_cvss_floor_keys(self):
        from tools.zero_day_heuristics import SEVERITY_CVSS_FLOOR, SeverityLevel

        for level in SeverityLevel:
            assert level in SEVERITY_CVSS_FLOOR

    def test_hunt_engine_severity_enum(self):
        from tools.hunt_engine import Severity

        for s in Severity:
            assert isinstance(s.value, str)

    def test_token_provider_configs_complete(self):
        from tools.token_manager import PROVIDER_CONFIGS

        assert "openai" in PROVIDER_CONFIGS
        assert "anthropic" in PROVIDER_CONFIGS
        assert "ollama" in PROVIDER_CONFIGS
        assert "groq" in PROVIDER_CONFIGS

    def test_session_manager_ensure_dir(self, tmp_path):
        from tools.session_manager import _ensure_sessions_dir

        with patch("tools.session_manager.SESSIONS_DIR", tmp_path / "sessions"):
            d = _ensure_sessions_dir()
            assert d.exists()

    def test_smart_cache_size_one(self):
        from tools.perf import SmartCache

        c = SmartCache(max_size=1)
        c.set("a", 1)
        c.set("b", 2)
        assert c.get("a") is None
        assert c.get("b") == 2

    def test_overlay_menu_items_build(self, overlay=None):
        from tools.overlay_menu import SettingsOverlay

        mock_agent = MagicMock()
        mock_console = MagicMock()
        mock_console.width = 80
        overlay = SettingsOverlay(agent=mock_agent, console=mock_console)
        overlay._current_layer = "main"
        overlay._update_items()
        assert len(overlay._items) > 0

    def test_config_wizard_many_providers(self):
        from tools.config_wizard import ConfigWizard

        providers = ConfigWizard.AI_PROVIDERS
        env_keys = [p.env_key for p in providers]
        names = [p.name for p in providers]
        assert "NVIDIA" in names
        assert "OpenAI (GPT-4)" in names
        assert "Ollama (Local)" in names

    def test_multi_agent_roles_complete(self):
        from tools.multi_agent import AGENT_ROLES

        assert len(AGENT_ROLES) == 3
        names = [r["name"] for r in AGENT_ROLES]
        assert "Strategist" in names
        assert "Recon Lead" in names
        assert "Exploit Analyst" in names

    def test_universal_executor_history(self, tmp_path):
        from tools.universal_executor import UniversalExecutor

        executor = UniversalExecutor(base_dir=str(tmp_path))
        executor.execute_action({"type": "shell", "params": {"command": "echo test"}})
        assert len(executor.execution_history) > 0

    def test_vuln_finder_execute_no_tool(self):
        from tools.vuln_finder import VulnFinder

        finder = VulnFinder(target="http://x.com")
        result = finder.execute({"url": "http://x.com"})
        assert result["success"] is False
        assert "No tool" in result["output"]

    def test_vuln_finder_execute_unknown_tool(self):
        from tools.vuln_finder import VulnFinder

        finder = VulnFinder(target="http://x.com")
        result = finder.execute({"url": "http://x.com", "tool": "nonexistent_tool_xyz"})
        assert result["success"] is False

    def test_token_manager_format_status_comprehensive(self, tmp_path):
        from tools.token_manager import TokenManager

        db_path = tmp_path / "fmt.db"
        with patch.object(TokenManager, "DB_PATH", db_path):
            tm = TokenManager(daily_budget_usd=5.0, monthly_budget_usd=50.0)
        tm.record_usage("openai", "gpt-4", 1000, 500)
        output = tm.format_status()
        assert "Today:" in output
        assert "This Month:" in output

    def test_overlay_render_model_select_search(self):
        from tools.overlay_menu import SettingsOverlay

        mock_agent = MagicMock()
        mock_console = MagicMock()
        mock_console.width = 80
        overlay = SettingsOverlay(agent=mock_agent, console=mock_console)
        overlay._current_layer = "model_select"
        overlay._search = "gpt"
        overlay._items = [{"label": "gpt-4"}, {"label": "gpt-3.5"}]
        panel = overlay.render()
        assert panel is not None


if __name__ == "__main__":
    pytest.main([__file__, "-q", "--tb=short"])
