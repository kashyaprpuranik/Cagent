import os
from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI

from control_plane.config import logger, REDIS_URL, OPENOBSERVE_MULTI_TENANT
from control_plane.database import SessionLocal
from control_plane.seed import seed_bootstrap, seed_test_data
from control_plane.redis_client import create_redis_client, close_redis_client


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

    yield

    await close_redis_client(app.state.redis)
    await app.state.http_client.aclose()
    logger.info("Shutting down")
