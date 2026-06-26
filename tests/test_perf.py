"""test_perf.py — Performance utilities tests."""

import asyncio
import sys
import time

sys.path.insert(0, "/mnt/data/Elengenix")

from tools.perf import (
    AsyncBatcher,
    FastHTTP,
    SmartCache,
    StreamingAggregator,
    Timer,
    cached,
    timeit,
)


def test_smart_cache_basic():
    c = SmartCache(max_size=10, default_ttl=10)
    c.set("a", 1)
    assert c.get("a") == 1
    assert c.get("b") is None
    assert c.hits == 1
    assert c.misses == 1
    print("[OK] test_smart_cache_basic")


def test_smart_cache_ttl():
    c = SmartCache(max_size=10, default_ttl=0.1)
    c.set("a", 1)
    assert c.get("a") == 1
    time.sleep(0.15)
    assert c.get("a") is None
    print("[OK] test_smart_cache_ttl")


def test_smart_cache_lru():
    c = SmartCache(max_size=3)
    c.set("a", 1)
    c.set("b", 2)
    c.set("c", 3)
    c.get("a")  # mark a as recent
    c.set("d", 4)  # should evict b
    assert c.get("a") == 1
    assert c.get("b") is None
    assert c.get("c") == 3
    print("[OK] test_smart_cache_lru")


def test_smart_cache_invalidate():
    c = SmartCache()
    c.set("user:1", "alice")
    c.set("user:2", "bob")
    c.set("post:1", "hello")
    n = c.invalidate("user:")
    assert n == 2
    assert c.get("user:1") is None
    assert c.get("post:1") == "hello"
    print("[OK] test_smart_cache_invalidate")


def test_cached_decorator():
    c = SmartCache(default_ttl=60)
    call_count = 0

    @cached(c, key_fn=lambda x: f"key:{x}")
    def expensive(x):
        nonlocal call_count
        call_count += 1
        return x * 2

    assert expensive(5) == 10
    assert expensive(5) == 10  # cached
    assert call_count == 1
    assert expensive(10) == 20
    assert call_count == 2
    print("[OK] test_cached_decorator")


def test_timer():
    with Timer("test") as t:
        time.sleep(0.05)
    assert t.duration_ms >= 50
    assert t.result.duration_ms >= 50
    print(f"[OK] test_timer ({t.duration_ms:.1f}ms)")


def test_timeit_decorator():
    @timeit("op")
    def slow():
        time.sleep(0.02)
        return "done"

    result = slow()
    assert result == "done"
    print("[OK] test_timeit_decorator")


def test_async_batcher():
    async def run():
        batcher = AsyncBatcher(concurrency=3, timeout=5)

        async def task(x):
            await asyncio.sleep(0.01)
            return x * 2

        results = await batcher.run_all([task(i) for i in range(10)])
        assert len(results) == 10
        return results

    results = asyncio.run(run())
    assert all(r is not None for r in results)
    print(f"[OK] test_async_batcher ({len(results)} tasks)")


def test_streaming_aggregator():
    s = StreamingAggregator()
    s.add({"severity": "Critical", "cvss": 9.8})
    s.add({"severity": "High", "cvss": 7.5})
    s.add({"severity": "Critical", "cvss": 10.0})
    assert s.total == 3
    assert s.by_severity["Critical"] == 2
    assert s.risk_score == 10.0
    summary = s.summary()
    assert summary["total"] == 3
    print("[OK] test_streaming_aggregator")


def test_cache_stats():
    c = SmartCache()
    c.set("a", 1)
    c.get("a")
    c.get("a")
    c.get("b")  # miss
    stats = c.stats()
    assert stats["hits"] == 2
    assert stats["misses"] == 1
    assert stats["hit_rate"] == 2 / 3
    print(f"[OK] test_cache_stats (hit_rate={stats['hit_rate']:.2f})")


if __name__ == "__main__":
    test_smart_cache_basic()
    test_smart_cache_ttl()
    test_smart_cache_lru()
    test_smart_cache_invalidate()
    test_cached_decorator()
    test_timer()
    test_timeit_decorator()
    test_async_batcher()
    test_streaming_aggregator()
    test_cache_stats()
    print("\n[OK] All 10 tests passed")
