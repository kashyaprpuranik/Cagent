"""Unit tests for control_plane.redis_client helpers.

All tests use ``unittest.mock.AsyncMock`` — no real Redis instance is needed.
"""

import json
import pytest
from unittest.mock import AsyncMock, patch

from control_plane.redis_client import (
    create_redis_client,
    close_redis_client,
    write_heartbeat,
    read_heartbeat,
    is_agent_online,
    publish_policy_changed,
)


# ---------------------------------------------------------------------------
# Heartbeat helpers
# ---------------------------------------------------------------------------

class TestWriteHeartbeat:
    async def test_success(self):
        client = AsyncMock()
        result = await write_heartbeat(client, "agent-1", status="running", cpu_percent=42)
        assert result is True
        client.setex.assert_awaited_once()
        args = client.setex.await_args
        assert args[0][0] == "hb:agent-1"
        assert args[0][1] == 60
        payload = json.loads(args[0][2])
        assert payload["agent_id"] == "agent-1"
        assert payload["status"] == "running"
        assert payload["cpu_percent"] == 42
        assert "ts" in payload

    async def test_none_client_returns_false(self):
        result = await write_heartbeat(None, "agent-1", status="running")
        assert result is False

    async def test_redis_error_returns_false(self):
        client = AsyncMock()
        client.setex.side_effect = Exception("connection lost")
        result = await write_heartbeat(client, "agent-1", status="running")
        assert result is False

    async def test_none_metrics_excluded(self):
        client = AsyncMock()
        await write_heartbeat(client, "agent-1", status="running", cpu_percent=None)
        payload = json.loads(client.setex.await_args[0][2])
        assert "cpu_percent" not in payload


class TestReadHeartbeat:
    async def test_success(self):
        client = AsyncMock()
        stored = json.dumps({"agent_id": "agent-1", "status": "running", "ts": "2025-01-01T00:00:00+00:00"})
        client.get.return_value = stored
        result = await read_heartbeat(client, "agent-1")
        assert result["agent_id"] == "agent-1"
        assert result["status"] == "running"
        client.get.assert_awaited_once_with("hb:agent-1")

    async def test_missing_key(self):
        client = AsyncMock()
        client.get.return_value = None
        result = await read_heartbeat(client, "agent-1")
        assert result is None

    async def test_none_client(self):
        result = await read_heartbeat(None, "agent-1")
        assert result is None

    async def test_redis_error(self):
        client = AsyncMock()
        client.get.side_effect = Exception("timeout")
        result = await read_heartbeat(client, "agent-1")
        assert result is None


# ---------------------------------------------------------------------------
# is_agent_online
# ---------------------------------------------------------------------------

class TestIsAgentOnline:
    async def test_exists_returns_true(self):
        client = AsyncMock()
        client.exists.return_value = 1
        result = await is_agent_online(client, "agent-1")
        assert result is True
        client.exists.assert_awaited_once_with("hb:agent-1")

    async def test_not_exists_returns_false(self):
        client = AsyncMock()
        client.exists.return_value = 0
        result = await is_agent_online(client, "agent-1")
        assert result is False

    async def test_none_client_returns_none(self):
        result = await is_agent_online(None, "agent-1")
        assert result is None

    async def test_redis_error_returns_none(self):
        client = AsyncMock()
        client.exists.side_effect = Exception("connection refused")
        result = await is_agent_online(client, "agent-1")
        assert result is None


# ---------------------------------------------------------------------------
# Policy pub/sub
# ---------------------------------------------------------------------------

class TestPublishPolicyChanged:
    async def test_success(self):
        client = AsyncMock()
        result = await publish_policy_changed(client, 1, "created", "example.com")
        assert result is True
        client.publish.assert_awaited_once()
        channel, message = client.publish.await_args[0]
        assert channel == "policy_changed"
        payload = json.loads(message)
        assert payload["tenant_id"] == 1
        assert payload["action"] == "created"
        assert payload["domain"] == "example.com"
        assert "ts" in payload

    async def test_none_client_returns_false(self):
        result = await publish_policy_changed(None, 1, "created", "example.com")
        assert result is False

    async def test_redis_error_returns_false(self):
        client = AsyncMock()
        client.publish.side_effect = Exception("connection lost")
        result = await publish_policy_changed(client, 1, "deleted", "example.com")
        assert result is False


# ---------------------------------------------------------------------------
# Connection lifecycle
# ---------------------------------------------------------------------------

class TestCreateRedisClient:
    @patch("control_plane.redis_client.REDIS_URL", "")
    async def test_empty_url_returns_none(self):
        result = await create_redis_client()
        assert result is None

    @patch("control_plane.redis_client.REDIS_URL", "redis://localhost:6379")
    async def test_connection_failure_returns_none(self):
        mock_client = AsyncMock()
        mock_client.ping.side_effect = Exception("connection refused")
        with patch("redis.asyncio.from_url", return_value=mock_client):
            result = await create_redis_client()
        assert result is None


class TestCloseRedisClient:
    async def test_none_client_is_noop(self):
        await close_redis_client(None)  # should not raise

    async def test_close_success(self):
        client = AsyncMock()
        await close_redis_client(client)
        client.aclose.assert_awaited_once()

    async def test_close_error_is_swallowed(self):
        client = AsyncMock()
        client.aclose.side_effect = Exception("already closed")
        await close_redis_client(client)  # should not raise
