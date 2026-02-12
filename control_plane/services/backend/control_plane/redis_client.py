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
_TOKEN_CACHE_PREFIX = "tc:"
_TOKEN_CACHE_TTL = 60  # seconds
_DOMAIN_POLICY_PREFIX = "dp:"
_DOMAIN_POLICY_TTL = 300  # seconds

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


# ---------------------------------------------------------------------------
# Token cache helpers
# ---------------------------------------------------------------------------

async def cache_token_info(client, token_hash: str, info_dict: dict) -> bool:
    """Cache a serialized TokenInfo dict in Redis (60 s TTL).

    Returns ``True`` on success, ``False`` otherwise.
    """
    if client is None:
        return False
    try:
        key = f"{_TOKEN_CACHE_PREFIX}{token_hash}"
        await client.setex(key, _TOKEN_CACHE_TTL, json.dumps(info_dict))
        return True
    except Exception as exc:
        logger.warning("Redis cache_token_info failed: %s", exc)
        return False


async def get_cached_token_info(client, token_hash: str) -> Optional[dict]:
    """Read a cached TokenInfo dict from Redis.

    Returns the parsed dict or ``None``.
    """
    if client is None:
        return None
    try:
        key = f"{_TOKEN_CACHE_PREFIX}{token_hash}"
        raw = await client.get(key)
        if raw is None:
            return None
        return json.loads(raw)
    except Exception as exc:
        logger.warning("Redis get_cached_token_info failed: %s", exc)
        return None


async def delete_cached_token(client, token_hash: str) -> bool:
    """Delete a cached token from Redis.

    Returns ``True`` on success, ``False`` otherwise.
    """
    if client is None:
        return False
    try:
        key = f"{_TOKEN_CACHE_PREFIX}{token_hash}"
        await client.delete(key)
        return True
    except Exception as exc:
        logger.warning("Redis delete_cached_token failed: %s", exc)
        return False


# ---------------------------------------------------------------------------
# Heartbeat scan helper
# ---------------------------------------------------------------------------

async def scan_all_heartbeats(client) -> list:
    """Iterate all heartbeat keys via SCAN and return parsed dicts.

    Returns an empty list when Redis is unavailable.
    """
    if client is None:
        return []
    try:
        results = []
        async for key in client.scan_iter(match=f"{_HEARTBEAT_PREFIX}*", count=200):
            raw = await client.get(key)
            if raw:
                results.append(json.loads(raw))
        return results
    except Exception as exc:
        logger.warning("Redis scan_all_heartbeats failed: %s", exc)
        return []


# ---------------------------------------------------------------------------
# Domain policy cache helpers
# ---------------------------------------------------------------------------

async def cache_domain_policies(client, cache_key: str, data: dict) -> bool:
    """Cache domain policy export data (300 s TTL).

    Returns ``True`` on success, ``False`` otherwise.
    """
    if client is None:
        return False
    try:
        key = f"{_DOMAIN_POLICY_PREFIX}{cache_key}"
        await client.setex(key, _DOMAIN_POLICY_TTL, json.dumps(data))
        return True
    except Exception as exc:
        logger.warning("Redis cache_domain_policies failed: %s", exc)
        return False


async def get_cached_domain_policies(client, cache_key: str) -> Optional[dict]:
    """Read cached domain policy export data.

    Returns the parsed dict or ``None``.
    """
    if client is None:
        return None
    try:
        key = f"{_DOMAIN_POLICY_PREFIX}{cache_key}"
        raw = await client.get(key)
        if raw is None:
            return None
        return json.loads(raw)
    except Exception as exc:
        logger.warning("Redis get_cached_domain_policies failed: %s", exc)
        return None


async def invalidate_domain_policy_cache(client, tenant_id) -> bool:
    """Delete all cached domain policy entries for a tenant.

    Returns ``True`` on success, ``False`` otherwise.
    """
    if client is None:
        return False
    try:
        keys = []
        async for key in client.scan_iter(match=f"{_DOMAIN_POLICY_PREFIX}tenant:{tenant_id}:*", count=200):
            keys.append(key)
        if keys:
            await client.delete(*keys)
        return True
    except Exception as exc:
        logger.warning("Redis invalidate_domain_policy_cache failed: %s", exc)
        return False
