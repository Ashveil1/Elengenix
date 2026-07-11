"""
perf.py — Elengenix Performance Utilities
Smart caching, async batch processing, timing, profiling.
Version: 1.0.0
"""

from __future__ import annotations

import asyncio
import functools
import hashlib
import logging
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger("elengenix.perf")


# ═══════════════════════════════════════════════════════════════════════════
# 1. SMART CACHE — TTL + LRU
# ═══════════════════════════════════════════════════════════════════════════


@dataclass
class CacheEntry:
    value: Any
    expires_at: float
    created_at: float
    hits: int = 0


class SmartCache:
    """LRU + TTL cache for expensive operations. Thread-safe."""

    def __init__(self, max_size: int = 256, default_ttl: float = 300.0):
        self.max_size = max_size
        self.default_ttl = default_ttl
        self._store: OrderedDict[str, CacheEntry] = OrderedDict()
        self.hits = 0
        self.misses = 0
        self._lock = threading.Lock()

    def get(self, key: str) -> Optional[Any]:
        with self._lock:
            if key not in self._store:
                self.misses += 1
                return None
            entry = self._store[key]
            if time.time() > entry.expires_at:
                del self._store[key]
                self.misses += 1
                return None
            entry.hits += 1
            self.hits += 1
            self._store.move_to_end(key)
            return entry.value

    def set(self, key: str, value: Any, ttl: Optional[float] = None) -> None:
        with self._lock:
            if key in self._store:
                self._store.move_to_end(key)
            if len(self._store) >= self.max_size:
                self._store.popitem(last=False)
            self._store[key] = CacheEntry(
                value=value,
                expires_at=time.time() + (ttl or self.default_ttl),
                created_at=time.time(),
            )

    def invalidate(self, pattern: Optional[str] = None) -> int:
        with self._lock:
            if pattern is None:
                n = len(self._store)
                self._store.clear()
                return n
            keys_to_del = [k for k in self._store if pattern in k]
            for k in keys_to_del:
                del self._store[k]
            return len(keys_to_del)

    def stats(self) -> Dict[str, Any]:
        with self._lock:
            total = self.hits + self.misses
            return {
                "size": len(self._store),
                "max_size": self.max_size,
                "hits": self.hits,
                "misses": self.misses,
                "hit_rate": self.hits / total if total > 0 else 0,
            }


# Global shared caches
_HTTP_CACHE = SmartCache(max_size=512, default_ttl=300)  # 5 min for HTTP responses
_AI_CACHE = SmartCache(max_size=128, default_ttl=1800)  # 30 min for AI responses


def cached(cache: SmartCache, key_fn: Optional[Callable] = None, ttl: Optional[float] = None):
    """Decorator for caching function results."""

    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            if key_fn:
                key = key_fn(*args, **kwargs)
            else:
                key = f"{func.__module__}.{func.__name__}:{hashlib.md5(repr((args, sorted(kwargs.items()))).encode()).hexdigest()[:16]}"
            result = cache.get(key)
            if result is not None:
                return result
            result = func(*args, **kwargs)
            if result is not None:
                cache.set(key, result, ttl)
            return result

        return wrapper

    return decorator


# ═══════════════════════════════════════════════════════════════════════════
# 2. ASYNC BATCH — Parallel with concurrency limit
# ═══════════════════════════════════════════════════════════════════════════


class AsyncBatcher:
    """Process async tasks in parallel with concurrency limit and progress."""

    def __init__(self, concurrency: int = 10, timeout: float = 30.0):
        self.concurrency = concurrency
        self.timeout = timeout
        self.semaphore = asyncio.Semaphore(concurrency)
        self.results: List[Any] = []
        self.errors: List[tuple] = []

    async def _run_one(self, coro, idx: int):
        try:
            async with self.semaphore:
                result = await asyncio.wait_for(coro, timeout=self.timeout)
                self.results.append((idx, result))
                return result
        except Exception as e:
            self.errors.append((idx, e))
            return None

    async def run_all(self, coros: List) -> List[Any]:
        """Run all coros with concurrency limit."""
        tasks = [self._run_one(c, i) for i, c in enumerate(coros)]
        return await asyncio.gather(*tasks, return_exceptions=True)


# ═══════════════════════════════════════════════════════════════════════════
# 3. TIMING & PROFILING
# ═══════════════════════════════════════════════════════════════════════════


@dataclass
class TimingResult:
    name: str
    duration_ms: float
    start: float
    end: float
    metadata: Dict[str, Any] = field(default_factory=dict)


class Timer:
    """Context manager for timing code blocks."""

    def __init__(
        self,
        name: str = "operation",
        logger_obj: Optional[logging.Logger] = None,
        metadata: Optional[Dict] = None,
    ):
        self.name = name
        self.logger = logger_obj or logger
        self.metadata = metadata or {}
        self.result: Optional[TimingResult] = None

    def __enter__(self):
        self.start = time.perf_counter()
        self.start_wall = time.time()
        return self

    def __exit__(self, *args):
        end = time.perf_counter()
        duration_ms = (end - self.start) * 1000
        self.result = TimingResult(
            name=self.name,
            duration_ms=duration_ms,
            start=self.start_wall,
            end=time.time(),
            metadata=self.metadata,
        )
        self.logger.debug(f"[PERF] {self.name}: {duration_ms:.1f}ms")

    @property
    def duration_ms(self) -> float:
        return self.result.duration_ms if self.result else 0.0


def timeit(name: str = "fn"):
    """Decorator to time function execution."""

    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            with Timer(name=f"{func.__name__}.{name}"):
                return func(*args, **kwargs)

        return wrapper

    return decorator


# ═══════════════════════════════════════════════════════════════════════════
# 4. HTTP CLIENT — Connection pooling + cache
# ═══════════════════════════════════════════════════════════════════════════


class FastHTTP:
    """HTTP client with connection pooling and caching."""

    def __init__(self, timeout: float = 10.0, max_connections: int = 50, use_cache: bool = True):
        import urllib3

        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        self.timeout = timeout
        self.max_connections = max_connections
        self.use_cache = use_cache
        self._session = None

    def _get_session(self):
        if self._session is None:
            import requests
            from requests.adapters import HTTPAdapter
            from urllib3.util.retry import Retry

            s = requests.Session()
            retries = Retry(total=2, backoff_factor=0.1, status_forcelist=[429, 500, 502, 503, 504])
            adapter = HTTPAdapter(max_retries=retries, pool_maxsize=self.max_connections)
            s.mount("http://", adapter)
            s.mount("https://", adapter)
            s.verify = False
            self._session = s
        return self._session

    def get(self, url: str, **kwargs) -> Optional[Dict]:
        """GET with cache. Returns dict with status, headers, body, elapsed_ms."""
        if self.use_cache:
            cached = _HTTP_CACHE.get(url)
            if cached:
                return cached
        try:
            s = self._get_session()
            start = time.perf_counter()
            r = s.get(url, timeout=self.timeout, **kwargs)
            elapsed_ms = (time.perf_counter() - start) * 1000
            result = {
                "status": r.status_code,
                "headers": dict(r.headers),
                "body": r.text[:65536],
                "url": r.url,
                "elapsed_ms": elapsed_ms,
            }
            if self.use_cache and r.status_code == 200:
                _HTTP_CACHE.set(url, result, ttl=300)
            return result
        except Exception as e:
            return {"status": 0, "error": str(e), "url": url, "elapsed_ms": 0}


# ═══════════════════════════════════════════════════════════════════════════
# 5. STREAMING AGGREGATOR — Process findings as they come
# ═══════════════════════════════════════════════════════════════════════════


class StreamingAggregator:
    """Aggregate findings in real-time with severity counts and risk score."""

    def __init__(self):
        self.by_severity: Dict[str, int] = {
            "Critical": 0,
            "High": 0,
            "Medium": 0,
            "Low": 0,
            "Informational": 0,
        }
        self.findings: List[Dict] = []
        self.risk_score: float = 0.0
        self.start_time = time.time()

    def add(self, finding: Dict):
        """Add a finding and update aggregates."""
        sev = finding.get("severity", "Informational")
        self.by_severity[sev] = self.by_severity.get(sev, 0) + 1
        self.findings.append(finding)
        cvss = finding.get("cvss", 0)
        # Risk score = weighted max
        self.risk_score = max(self.risk_score, cvss if isinstance(cvss, (int, float)) else 0)

    @property
    def total(self) -> int:
        return sum(self.by_severity.values())

    @property
    def duration_seconds(self) -> float:
        return time.time() - self.start_time

    def summary(self) -> Dict:
        return {
            "total": self.total,
            "by_severity": dict(self.by_severity),
            "risk_score": self.risk_score,
            "duration_s": self.duration_seconds,
        }


__all__ = [
    "SmartCache",
    "cached",
    "_HTTP_CACHE",
    "_AI_CACHE",
    "AsyncBatcher",
    "Timer",
    "timeit",
    "TimingResult",
    "FastHTTP",
    "StreamingAggregator",
]
