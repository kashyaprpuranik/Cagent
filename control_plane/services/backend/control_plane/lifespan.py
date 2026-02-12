import asyncio
import json
import os
from contextlib import asynccontextmanager
from datetime import datetime, timezone

import httpx
from fastapi import FastAPI

from control_plane.config import logger, REDIS_URL, OPENOBSERVE_MULTI_TENANT
from control_plane.database import SessionLocal
from control_plane.seed import seed_bootstrap, seed_test_data
from control_plane.redis_client import (
    create_redis_client, close_redis_client,
    scan_all_heartbeats, invalidate_domain_policy_cache,
)

_HEARTBEAT_FLUSH_INTERVAL = 60  # seconds
_POLICY_CHANNEL = "policy_changed"


async def _provision_existing_tenants(db):
    """Provision OpenObserve orgs for existing tenants that don't have credentials yet."""
    from control_plane.models import Tenant
    from control_plane.openobserve import (
        get_tenant_settings, provision_tenant_org, store_org_credentials,
    )

    tenants = db.query(Tenant).filter(Tenant.deleted_at.is_(None)).all()
    for tenant in tenants:
        settings = get_tenant_settings(tenant)
        if settings and settings.get("openobserve_org"):
            continue  # Already provisioned

        try:
            writer_email, writer_pw, reader_email, reader_pw = await provision_tenant_org(tenant.slug)
            store_org_credentials(tenant, db, writer_email, writer_pw, reader_email, reader_pw)
            logger.info(f"Provisioned OpenObserve org for existing tenant '{tenant.slug}'")
        except Exception as e:
            logger.warning(f"Failed to provision OpenObserve org for tenant '{tenant.slug}': {e}")


async def _heartbeat_flush_loop(app: FastAPI):
    """Periodically flush Redis heartbeats to the DB in batch."""
    from control_plane.models import AgentState
    while True:
        try:
            await asyncio.sleep(_HEARTBEAT_FLUSH_INTERVAL)
            redis_client = getattr(app.state, "redis", None)
            heartbeats = await scan_all_heartbeats(redis_client)
            if not heartbeats:
                continue

            db = SessionLocal()
            try:
                for hb in heartbeats:
                    agent_id = hb.get("agent_id")
                    if not agent_id:
                        continue
                    db.query(AgentState).filter(
                        AgentState.agent_id == agent_id
                    ).update({
                        AgentState.status: hb.get("status", "unknown"),
                        AgentState.container_id: hb.get("container_id"),
                        AgentState.uptime_seconds: hb.get("uptime_seconds"),
                        AgentState.cpu_percent: int(hb["cpu_percent"]) if hb.get("cpu_percent") is not None else None,
                        AgentState.memory_mb: int(hb["memory_mb"]) if hb.get("memory_mb") is not None else None,
                        AgentState.memory_limit_mb: int(hb["memory_limit_mb"]) if hb.get("memory_limit_mb") is not None else None,
                        AgentState.last_heartbeat: datetime.fromisoformat(hb["ts"]) if hb.get("ts") else datetime.now(timezone.utc),
                    }, synchronize_session=False)
                db.commit()
                logger.debug("Flushed %d heartbeats to DB", len(heartbeats))
            except Exception as exc:
                logger.warning("Heartbeat flush failed: %s", exc)
                db.rollback()
            finally:
                db.close()
        except asyncio.CancelledError:
            break
        except Exception as exc:
            logger.warning("Heartbeat flush loop error: %s", exc)


async def _policy_subscriber_loop(app: FastAPI):
    """Subscribe to ``policy_changed`` Redis channel and invalidate caches."""
    redis_client = getattr(app.state, "redis", None)
    if redis_client is None:
        return
    try:
        import redis.asyncio as aioredis
        pubsub = redis_client.pubsub()
        await pubsub.subscribe(_POLICY_CHANNEL)
        while True:
            msg = await pubsub.get_message(ignore_subscribe_messages=True, timeout=1.0)
            if msg and msg["type"] == "message":
                try:
                    data = json.loads(msg["data"])
                    tenant_id = data.get("tenant_id")
                    if tenant_id is not None:
                        await invalidate_domain_policy_cache(redis_client, tenant_id)
                except Exception as exc:
                    logger.warning("Policy subscriber parse error: %s", exc)
            await asyncio.sleep(0.1)
    except asyncio.CancelledError:
        pass
    except Exception as exc:
        logger.warning("Policy subscriber loop error: %s", exc)


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Starting AI Devbox Control Plane")
    if REDIS_URL:
        logger.info(f"Rate limiting enabled with Redis: {REDIS_URL}")
    else:
        logger.info("Rate limiting enabled with in-memory storage (single instance only)")

    db = SessionLocal()
    try:
        seed_bootstrap(db)

        if os.environ.get("SEED_TOKENS", "false").lower() == "true":
            logger.info("SEED_TOKENS=true — seeding tenants and tokens")
            seed_test_data(db)

        if OPENOBSERVE_MULTI_TENANT:
            logger.info("OpenObserve multi-tenancy enabled — provisioning existing tenants")
            await _provision_existing_tenants(db)
    finally:
        db.close()

    # Shared HTTP client for OpenObserve calls — avoids per-request TLS setup
    app.state.http_client = httpx.AsyncClient(
        timeout=httpx.Timeout(15.0, connect=5.0),
        limits=httpx.Limits(max_connections=100, max_keepalive_connections=20),
    )

    # Redis client for heartbeats and policy notifications
    app.state.redis = await create_redis_client()

    # Start background tasks if Redis is available
    background_tasks = []
    if app.state.redis is not None:
        background_tasks.append(asyncio.create_task(_heartbeat_flush_loop(app)))
        background_tasks.append(asyncio.create_task(_policy_subscriber_loop(app)))

    yield

    # Cancel background tasks
    for task in background_tasks:
        task.cancel()
    for task in background_tasks:
        try:
            await task
        except asyncio.CancelledError:
            pass

    await close_redis_client(app.state.redis)
    await app.state.http_client.aclose()
    logger.info("Shutting down")
