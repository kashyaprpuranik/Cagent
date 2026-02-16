"""Tests for LayeredCache."""

import asyncio
import json
import time
from unittest.mock import AsyncMock, MagicMock

import pytest

from control_plane.cache import LayeredCache


class TestLayeredCache:
    """Test the LayeredCache memory -> Redis -> loader chain."""

    @pytest.fixture
    def cache(self):
        return LayeredCache("test", memory_ttl=1, redis_ttl=10)

    @pytest.fixture
    def mock_redis(self):
        """Fake Redis client with async get/set/delete."""
        store = {}

        class FakeRedis:
            async def get(self, key):
                return store.get(key)

            async def set(self, key, value, ex=None):
                store[key] = value

            async def delete(self, key):
                store.pop(key, None)

        redis = FakeRedis()
        redis._store = store  # expose for assertions
        return redis

    @pytest.mark.asyncio
    async def test_get_from_loader(self, cache):
        """Cache miss should call the loader and return its value."""
        loader = MagicMock(return_value=["10.0.0.0/8"])
        result = await cache.get("1", None, loader)
        assert result == ["10.0.0.0/8"]
        loader.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_from_memory(self, cache):
        """Second call should return from memory without calling loader again."""
        call_count = 0

        def loader():
            nonlocal call_count
            call_count += 1
            return ["10.0.0.0/8"]

        await cache.get("1", None, loader)
        assert call_count == 1

        result = await cache.get("1", None, loader)
        assert result == ["10.0.0.0/8"]
        assert call_count == 1  # loader not called again

    @pytest.mark.asyncio
    async def test_memory_ttl_expiry(self):
        """After memory TTL expires, loader should be called again."""
        cache = LayeredCache("test", memory_ttl=0, redis_ttl=10)  # 0s TTL = always expired
        call_count = 0

        def loader():
            nonlocal call_count
            call_count += 1
            return [f"value-{call_count}"]

        result1 = await cache.get("1", None, loader)
        assert result1 == ["value-1"]

        result2 = await cache.get("1", None, loader)
        assert result2 == ["value-2"]
        assert call_count == 2

    @pytest.mark.asyncio
    async def test_invalidate_clears_memory(self, cache):
        """After invalidate, loader should be called on next get."""
        call_count = 0

        def loader():
            nonlocal call_count
            call_count += 1
            return [f"value-{call_count}"]

        await cache.get("1", None, loader)
        assert call_count == 1

        await cache.invalidate("1")

        result = await cache.get("1", None, loader)
        assert result == ["value-2"]
        assert call_count == 2

    @pytest.mark.asyncio
    async def test_clear_clears_all(self, cache):
        """clear() should remove all entries from memory."""
        loader_a = MagicMock(return_value=["a"])
        loader_b = MagicMock(return_value=["b"])

        await cache.get("1", None, loader_a)
        await cache.get("2", None, loader_b)
        loader_a.reset_mock()
        loader_b.reset_mock()

        cache.clear()

        await cache.get("1", None, loader_a)
        await cache.get("2", None, loader_b)
        loader_a.assert_called_once()
        loader_b.assert_called_once()

    @pytest.mark.asyncio
    async def test_redis_none_graceful(self, cache):
        """With redis_client=None, should fall back to memory+loader."""
        loader = MagicMock(return_value=["value"])
        result = await cache.get("1", None, loader)
        assert result == ["value"]
        loader.assert_called_once()

        # Second call from memory
        loader.reset_mock()
        result = await cache.get("1", None, loader)
        assert result == ["value"]
        loader.assert_not_called()

    @pytest.mark.asyncio
    async def test_redis_populated_on_miss(self, cache, mock_redis):
        """On loader miss, value should be stored in Redis."""
        loader = MagicMock(return_value=["10.0.0.0/8"])
        await cache.get("1", mock_redis, loader)

        raw = await mock_redis.get("lc:test:1")
        assert json.loads(raw) == ["10.0.0.0/8"]

    @pytest.mark.asyncio
    async def test_redis_hit_populates_memory(self, cache, mock_redis):
        """Redis hit should populate memory and skip loader."""
        # Pre-populate Redis
        await mock_redis.set("lc:test:1", json.dumps(["from-redis"]))

        loader = MagicMock(return_value=["from-db"])
        result = await cache.get("1", mock_redis, loader)
        assert result == ["from-redis"]
        loader.assert_not_called()

    @pytest.mark.asyncio
    async def test_redis_error_falls_back_to_loader(self, cache):
        """Redis errors should be caught and loader used as fallback."""
        class BrokenRedis:
            async def get(self, key):
                raise ConnectionError("Redis down")

            async def set(self, key, value, ex=None):
                raise ConnectionError("Redis down")

        loader = MagicMock(return_value=["from-db"])
        result = await cache.get("1", BrokenRedis(), loader)
        assert result == ["from-db"]
        loader.assert_called_once()

    @pytest.mark.asyncio
    async def test_invalidate_clears_redis(self, cache, mock_redis):
        """Invalidate should remove from both memory and Redis."""
        loader = MagicMock(return_value=["value"])
        await cache.get("1", mock_redis, loader)

        assert await mock_redis.get("lc:test:1") is not None

        await cache.invalidate("1", mock_redis)

        assert await mock_redis.get("lc:test:1") is None

    @pytest.mark.asyncio
    async def test_concurrent_access(self, cache):
        """Multiple concurrent gets should not corrupt state."""
        call_count = 0

        def loader():
            nonlocal call_count
            call_count += 1
            return ["value"]

        results = await asyncio.gather(
            cache.get("1", None, loader),
            cache.get("1", None, loader),
            cache.get("1", None, loader),
        )

        assert all(r == ["value"] for r in results)
        # At least one call should hit the loader; subsequent may or may not
        # depending on timing, but all should get correct results
        assert call_count >= 1
