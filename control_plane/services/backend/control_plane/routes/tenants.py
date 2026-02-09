from datetime import datetime
from typing import List

from fastapi import APIRouter, HTTPException, Depends, Request
from sqlalchemy.orm import Session

from control_plane.database import get_db
from control_plane.models import Tenant, AgentState, ApiToken, AuditTrail
from control_plane.schemas import TenantCreate, TenantResponse
from control_plane.auth import TokenInfo, require_super_admin
from control_plane.rate_limit import limiter

router = APIRouter()


@router.get("/api/v1/tenants", response_model=List[TenantResponse])
@limiter.limit("60/minute")
async def list_tenants(
    request: Request,
    db: Session = Depends(get_db),
    token_info: TokenInfo = Depends(require_super_admin)
):
    """List all tenants (super admin only). Excludes soft-deleted tenants."""
    tenants = db.query(Tenant).filter(
        Tenant.deleted_at.is_(None)
    ).all()
    result = []
    for t in tenants:
        # Count only non-deleted agents (excluding __default__)
        agent_count = db.query(AgentState).filter(
            AgentState.tenant_id == t.id,
            AgentState.deleted_at.is_(None),
            AgentState.agent_id != "__default__"
        ).count()
        result.append(TenantResponse(
            id=t.id,
            name=t.name,
            slug=t.slug,
            created_at=t.created_at,
            agent_count=agent_count
        ))
    return result


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
        approved_at=datetime.utcnow(),
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

    now = datetime.utcnow()

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

    return {"status": "deleted", "tenant_id": tenant_id, "agents_deleted": agent_count}
