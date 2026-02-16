from datetime import datetime, timezone
from typing import List

from fastapi import APIRouter, HTTPException, Depends, Query, Request
from sqlalchemy import func
from sqlalchemy.orm import Session

from control_plane.database import get_db
from control_plane.models import Tenant, AgentState, ApiToken, AuditTrail
from control_plane.schemas import TenantCreate, TenantResponse
from control_plane.auth import TokenInfo, require_super_admin, _get_redis_client
from control_plane.cache import agent_state_cache
from control_plane.rate_limit import limiter
from control_plane.config import OPENOBSERVE_MULTI_TENANT, logger
from control_plane.openobserve import provision_tenant_org, delete_tenant_org, store_org_credentials

router = APIRouter()


@router.get("/api/v1/tenants")
@limiter.limit("60/minute")
async def list_tenants(
    request: Request,
    limit: int = Query(default=100, le=1000),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    token_info: TokenInfo = Depends(require_super_admin)
):
    """List all tenants (super admin only). Excludes soft-deleted tenants."""
    # Single query with subquery to avoid N+1
    agent_count_subq = (
        db.query(
            AgentState.tenant_id,
            func.count(AgentState.id).label("cnt"),
        )
        .filter(
            AgentState.deleted_at.is_(None),
            AgentState.agent_id != "__default__",
        )
        .group_by(AgentState.tenant_id)
        .subquery()
    )

    base_query = (
        db.query(Tenant, func.coalesce(agent_count_subq.c.cnt, 0))
        .outerjoin(agent_count_subq, Tenant.id == agent_count_subq.c.tenant_id)
        .filter(Tenant.deleted_at.is_(None))
    )

    total = db.query(Tenant).filter(Tenant.deleted_at.is_(None)).count()
    rows = base_query.offset(offset).limit(limit).all()

    items = [
        TenantResponse(
            id=t.id,
            name=t.name,
            slug=t.slug,
            created_at=t.created_at,
            agent_count=cnt,
        )
        for t, cnt in rows
    ]
    return {"items": items, "total": total, "limit": limit, "offset": offset}


@router.post("/api/v1/tenants", response_model=TenantResponse)
@limiter.limit("10/minute")
async def create_tenant(
    request: Request,
    body: TenantCreate,
    db: Session = Depends(get_db),
    token_info: TokenInfo = Depends(require_super_admin)
):
    """Create a new tenant (super admin only).

    Also creates a __default__ agent for tenant-global configuration.
    """
    # Check if slug already exists (only check non-deleted tenants)
    existing = db.query(Tenant).filter(
        Tenant.deleted_at.is_(None),
        (Tenant.name == body.name) | (Tenant.slug == body.slug)
    ).first()
    if existing:
        raise HTTPException(
            status_code=400,
            detail="Tenant with this name or slug already exists"
        )

    # Create tenant
    tenant = Tenant(name=body.name, slug=body.slug)
    db.add(tenant)
    db.commit()
    db.refresh(tenant)

    # Create __default__ agent for tenant-global config
    default_agent = AgentState(
        agent_id="__default__",
        tenant_id=tenant.id,
        status="virtual",
        approved=True,
        approved_at=datetime.now(timezone.utc),
        approved_by="system"
    )
    db.add(default_agent)

    # Log tenant creation — target is the newly created tenant
    log = AuditTrail(
        event_type="tenant_created",
        user=token_info.token_name,
        action=f"Created tenant '{body.name}' (slug: {body.slug})",
        severity="info",
        tenant_id=tenant.id
    )
    db.add(log)
    db.commit()

    # Provision OpenObserve org for this tenant
    if OPENOBSERVE_MULTI_TENANT:
        try:
            writer_email, writer_pw, reader_email, reader_pw = await provision_tenant_org(tenant.slug)
            store_org_credentials(tenant, db, writer_email, writer_pw, reader_email, reader_pw)
        except Exception as e:
            logger.error(f"Failed to provision OpenObserve org for tenant {tenant.slug}: {e}")
            # Rollback: delete the tenant we just created
            db.delete(default_agent)
            db.delete(tenant)
            db.commit()
            raise HTTPException(
                status_code=502,
                detail=f"Failed to provision log storage for tenant: {e}"
            )

    return TenantResponse(
        id=tenant.id,
        name=tenant.name,
        slug=tenant.slug,
        created_at=tenant.created_at,
        agent_count=1  # The __default__ agent
    )


@router.get("/api/v1/tenants/{tenant_id}", response_model=TenantResponse)
@limiter.limit("60/minute")
async def get_tenant(
    request: Request,
    tenant_id: int,
    db: Session = Depends(get_db),
    token_info: TokenInfo = Depends(require_super_admin)
):
    """Get a tenant by ID (super admin only). Returns 404 for soft-deleted tenants."""
    tenant = db.query(Tenant).filter(
        Tenant.id == tenant_id,
        Tenant.deleted_at.is_(None)
    ).first()
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")

    # Count only non-deleted agents (excluding __default__)
    agent_count = db.query(AgentState).filter(
        AgentState.tenant_id == tenant.id,
        AgentState.deleted_at.is_(None),
        AgentState.agent_id != "__default__"
    ).count()
    return TenantResponse(
        id=tenant.id,
        name=tenant.name,
        slug=tenant.slug,
        created_at=tenant.created_at,
        agent_count=agent_count
    )


@router.delete("/api/v1/tenants/{tenant_id}")
@limiter.limit("10/minute")
async def delete_tenant(
    request: Request,
    tenant_id: int,
    db: Session = Depends(get_db),
    token_info: TokenInfo = Depends(require_super_admin)
):
    """Soft-delete a tenant and all its agents (super admin only)."""
    tenant = db.query(Tenant).filter(
        Tenant.id == tenant_id,
        Tenant.deleted_at.is_(None)
    ).first()
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")

    # Best-effort cleanup of OpenObserve org
    if OPENOBSERVE_MULTI_TENANT:
        try:
            await delete_tenant_org(tenant.slug)
        except Exception as e:
            logger.warning(f"Failed to clean up OpenObserve org for tenant {tenant.slug}: {e}")

    now = datetime.now(timezone.utc)

    # Soft-delete all agents for this tenant
    agents = db.query(AgentState).filter(
        AgentState.tenant_id == tenant_id,
        AgentState.deleted_at.is_(None)
    ).all()
    agent_count = len(agents)
    for agent in agents:
        agent.deleted_at = now
        agent.approved = False

    # Disable tokens for this tenant (but don't delete)
    db.query(ApiToken).filter(ApiToken.tenant_id == tenant_id).update(
        {"enabled": False}
    )

    # Soft-delete tenant
    tenant.deleted_at = now

    # Log deletion — target is the tenant being deleted
    log = AuditTrail(
        event_type="tenant_deleted",
        user=token_info.token_name,
        action=f"Soft-deleted tenant '{tenant.name}' and {agent_count} agents",
        severity="warning",
        tenant_id=tenant_id
    )
    db.add(log)
    db.commit()

    # Invalidate cached agent state for all soft-deleted agents
    redis_client = _get_redis_client(request)
    for agent in agents:
        await agent_state_cache.invalidate(agent.agent_id, redis_client)

    return {"status": "deleted", "tenant_id": tenant_id, "agents_deleted": agent_count}
