"""Caching utilities for the control plane.

LayeredCache: memory -> Redis -> loader (DB) lookup chain.
ThrottledWriter: coalesces repeated DB writes to a configurable interval.

Redis errors are caught and logged, never raised -- degrades gracefully.
"""

import json
import logging
import threading
import time as _time
from typing import Any, Callable, Optional

logger = logging.getLogger(__name__)


class LayeredCache:
    """Three-layer cache: process memory -> Redis -> loader callback."""

    def __init__(self, namespace: str, memory_ttl: int = 60, redis_ttl: int = 300):
        self._namespace = namespace
        self._memory_ttl = memory_ttl    # seconds
        self._redis_ttl = redis_ttl      # seconds
        self._memory: dict = {}          # key -> (value, cached_at_monotonic)
        self._lock = threading.Lock()

    def _redis_key(self, key: str) -> str:
        return f"lc:{self._namespace}:{key}"

    async def get(self, key: str, redis_client: Optional[Any], loader: Callable[[], Any]) -> Any:
        """Look up a value: memory -> Redis -> loader (DB).

        Args:
            key: Cache key (e.g. tenant_id as string).
            redis_client: Optional aioredis client. None skips the Redis layer.
            loader: Sync callable that returns the value from the source of truth.
                    Values must be JSON-serializable for Redis storage.
        """
        now = _time.monotonic()

        # Layer 1: in-memory (process-local, fastest)
        with self._lock:
            entry = self._memory.get(key)
            if entry is not None:
                value, cached_at = entry
                if (now - cached_at) < self._memory_ttl:
                    return value

        # Layer 2: Redis (shared across workers)
        if redis_client is not None:
            try:
                raw = await redis_client.get(self._redis_key(key))
                if raw is not None:
                    value = json.loads(raw)
                    with self._lock:
                        self._memory[key] = (value, now)
                    return value
            except Exception:
                logger.debug("Redis read failed for %s:%s, falling back to loader",
                             self._namespace, key, exc_info=True)

        # Layer 3: loader callback (source of truth -- DB query)
        value = loader()

        # Populate memory
        with self._lock:
            self._memory[key] = (value, _time.monotonic())

        # Populate Redis (best-effort)
        if redis_client is not None:
            try:
                await redis_client.set(
                    self._redis_key(key),
                    json.dumps(value),
                    ex=self._redis_ttl,
                )
            except Exception:
                logger.debug("Redis write failed for %s:%s",
                             self._namespace, key, exc_info=True)

        return value

    async def invalidate(self, key: str, redis_client: Optional[Any] = None) -> None:
        """Remove key from memory + Redis."""
        with self._lock:
            self._memory.pop(key, None)

        if redis_client is not None:
            try:
                await redis_client.delete(self._redis_key(key))
            except Exception:
                logger.debug("Redis delete failed for %s:%s",
                             self._namespace, key, exc_info=True)

    async def invalidate_by_prefix(self, prefix: str, redis_client: Optional[Any] = None) -> None:
        """Remove all keys matching *prefix* from memory + Redis.

        Useful when cache keys contain composite identifiers
        (e.g. ``tenant:42:agent:foo:export``) and you need to
        invalidate all entries for a given tenant.
        """
        with self._lock:
            to_remove = [k for k in self._memory if k.startswith(prefix)]
            for k in to_remove:
                del self._memory[k]

        if redis_client is not None:
            try:
                redis_prefix = self._redis_key(prefix)
                keys = []
                async for key in redis_client.scan_iter(match=f"{redis_prefix}*", count=200):
                    keys.append(key)
                if keys:
                    await redis_client.delete(*keys)
            except Exception:
                logger.debug("Redis prefix-delete failed for %s:%s*",
                             self._namespace, prefix, exc_info=True)

    def clear(self) -> None:
        """Remove all memory entries (for tests)."""
        with self._lock:
            self._memory.clear()


class ThrottledWriter:
    """Coalesces repeated writes to a configurable interval.

    Tracks per-key last-write timestamps and tells callers whether enough
    time has elapsed to justify another DB write (e.g. ``last_used_at``).
    """

    def __init__(self, interval: int = 600):
        self._interval = interval  # seconds between writes
        self._last_write: dict = {}  # key -> monotonic timestamp
        self._lock = threading.Lock()

    def should_write(self, key: str) -> bool:
        """Return True (and record the write) if >= interval since last write."""
        now = _time.monotonic()
        with self._lock:
            last = self._last_write.get(key, 0)
            if now - last >= self._interval:
                self._last_write[key] = now
                return True
        return False

    def mark_written(self, key: str) -> None:
        """Record that a write just happened (e.g. from a cache-miss loader)."""
        with self._lock:
            self._last_write[key] = _time.monotonic()

    def remove(self, key: str) -> None:
        """Remove tracking for a key (on invalidation)."""
        with self._lock:
            self._last_write.pop(key, None)

    def clear(self) -> None:
        """Remove all entries (for tests)."""
        with self._lock:
            self._last_write.clear()


# ---------------------------------------------------------------------------
# Module-level cache instances
# ---------------------------------------------------------------------------

# Security profile data (seccomp, resource limits) — rarely changes.
security_profile_cache = LayeredCache("sec_profile", memory_ttl=60, redis_ttl=300)

# Agent state metadata (existence, profile assignment, pending command).
# Shorter TTL since pending_command delivery is time-sensitive.
agent_state_cache = LayeredCache("agent_state", memory_ttl=30, redis_ttl=120)

# Token verification data (TokenInfo dict keyed by token_hash).
token_cache = LayeredCache("token", memory_ttl=60, redis_ttl=60)

# Domain policy export data (keyed by tenant:agent:export composite key).
domain_policy_cache = LayeredCache("domain_policy", memory_ttl=60, redis_ttl=300)

# Coalesces last_used_at writes to once per 10 minutes per token.
last_used_writer = ThrottledWriter(interval=600)
