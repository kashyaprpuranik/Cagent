"""Redis helpers for heartbeat storage and policy change notifications.

Every public function accepts ``client: Optional[Redis]`` and silently returns
a safe fallback (``None``, ``False``, etc.) when the client is ``None`` or when
a Redis error occurs.  This keeps all callers backward-compatible with the
existing DB-only code path — no Redis required for tests or standalone setups.
"""

import json
import logging
from datetime import datetime, timezone
from typing import Optional

from control_plane.config import REDIS_URL

logger = logging.getLogger(__name__)

# Key prefix / TTL constants
_HEARTBEAT_PREFIX = "hb:"
_HEARTBEAT_TTL = 60  # seconds

# Pub/sub channel
_POLICY_CHANNEL = "policy_changed"


# ---------------------------------------------------------------------------
# Connection lifecycle
# ---------------------------------------------------------------------------

async def create_redis_client():
    """Create an async Redis client from ``REDIS_URL``.

    Returns ``None`` when the URL is empty or the connection fails.
    """
    if not REDIS_URL:
        return None

    try:
        import redis.asyncio as aioredis
        client = aioredis.from_url(REDIS_URL, decode_responses=True)
        await client.ping()
        logger.info("Redis client connected")
        return client
    except Exception as exc:
        logger.warning("Failed to connect to Redis — falling back to DB-only: %s", exc)
        return None


async def close_redis_client(client) -> None:
    """Gracefully close the Redis client (no-op when *client* is ``None``)."""
    if client is None:
        return
    try:
        await client.aclose()
        logger.info("Redis client closed")
    except Exception as exc:
        logger.warning("Error closing Redis client: %s", exc)


# ---------------------------------------------------------------------------
# Heartbeat helpers
# ---------------------------------------------------------------------------

async def write_heartbeat(client, agent_id: str, **metrics) -> bool:
    """Store a heartbeat in Redis with a 60 s TTL.

    *metrics* can include ``status``, ``cpu_percent``, ``memory_mb``, etc.
    Returns ``True`` on success, ``False`` otherwise (including ``client is None``).
    """
    if client is None:
        return False
    try:
        key = f"{_HEARTBEAT_PREFIX}{agent_id}"
        payload = {
            "agent_id": agent_id,
            "ts": datetime.now(timezone.utc).isoformat(),
            **{k: v for k, v in metrics.items() if v is not None},
        }
        await client.setex(key, _HEARTBEAT_TTL, json.dumps(payload))
        return True
    except Exception as exc:
        logger.warning("Redis write_heartbeat failed for %s: %s", agent_id, exc)
        return False


async def read_heartbeat(client, agent_id: str) -> Optional[dict]:
    """Read a heartbeat from Redis.

    Returns the parsed JSON dict, or ``None`` if the key is missing, expired,
    or the client is unavailable.
    """
    if client is None:
        return None
    try:
        key = f"{_HEARTBEAT_PREFIX}{agent_id}"
        raw = await client.get(key)
        if raw is None:
            return None
        return json.loads(raw)
    except Exception as exc:
        logger.warning("Redis read_heartbeat failed for %s: %s", agent_id, exc)
        return None


async def is_agent_online(client, agent_id: str) -> Optional[bool]:
    """Check whether a heartbeat key exists (O(1), no deserialization).

    Returns ``True`` / ``False`` when Redis is available, or ``None`` to signal
    that the caller should fall back to the DB check.
    """
    if client is None:
        return None
    try:
        key = f"{_HEARTBEAT_PREFIX}{agent_id}"
        return bool(await client.exists(key))
    except Exception as exc:
        logger.warning("Redis is_agent_online failed for %s: %s", agent_id, exc)
        return None


# ---------------------------------------------------------------------------
# Policy change notifications
# ---------------------------------------------------------------------------

async def publish_policy_changed(client, tenant_id, action: str, domain: str) -> bool:
    """Publish a policy-change event on the ``policy_changed`` channel.

    Returns ``True`` on success, ``False`` otherwise.
    """
    if client is None:
        return False
    try:
        message = json.dumps({
            "tenant_id": tenant_id,
            "action": action,
            "domain": domain,
            "ts": datetime.now(timezone.utc).isoformat(),
        })
        await client.publish(_POLICY_CHANNEL, message)
        return True
    except Exception as exc:
        logger.warning("Redis publish_policy_changed failed: %s", exc)
        return False
