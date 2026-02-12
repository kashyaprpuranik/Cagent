from datetime import datetime, timedelta, timezone
from typing import Optional, List

from fastapi import APIRouter, HTTPException, Depends, Query, Request
from sqlalchemy.orm import Session

from control_plane.database import get_db
from control_plane.models import AgentState, ApiToken, AuditTrail
from control_plane.schemas import ApiTokenCreate, ApiTokenResponse, ApiTokenCreatedResponse
from control_plane.crypto import generate_token, hash_token
from control_plane.auth import TokenInfo, require_admin_role, require_admin_role_with_ip_check, invalidate_token_cache, invalidate_token_cache_async
from control_plane.rate_limit import limiter

router = APIRouter()


@router.get("/api/v1/tokens")
@limiter.limit("60/minute")
async def list_tokens(
    request: Request,
    tenant_id: Optional[int] = Query(default=None, description="Filter by tenant (super admin only)"),
    limit: int = Query(default=100, le=1000),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    token_info: TokenInfo = Depends(require_admin_role)
):
    """List all API tokens.

    Super admins can filter by tenant_id, or see all tokens if not specified.
    Tenant admins see only their tenant's tokens.
    """
    query = db.query(ApiToken)

    # Apply tenant filtering
    if token_info.is_super_admin:
        # Super admin can optionally filter by tenant
        if tenant_id is not None:
            query = query.filter(ApiToken.tenant_id == tenant_id)
        # else: no filter, see all tokens
    else:
        # Non-super-admin MUST be scoped to their tenant
        if not token_info.tenant_id:
            raise HTTPException(status_code=403, detail="Token must be scoped to a tenant")
        query = query.filter(ApiToken.tenant_id == token_info.tenant_id)

    total = query.count()
    tokens = query.offset(offset).limit(limit).all()
    items = [ApiTokenResponse(
        id=t.id,
        name=t.name,
        token_type=t.token_type,
        agent_id=t.agent_id,
        tenant_id=t.tenant_id,
        is_super_admin=t.is_super_admin or False,
        roles=t.roles if t.roles is not None else "admin",
        created_at=t.created_at,
        expires_at=t.expires_at,
        last_used_at=t.last_used_at,
        enabled=t.enabled
    ) for t in tokens]
    return {"items": items, "total": total, "limit": limit, "offset": offset}


@router.post("/api/v1/tokens", response_model=ApiTokenCreatedResponse)
@limiter.limit("10/minute")
async def create_token(
    request: Request,
    body: ApiTokenCreate,
    db: Session = Depends(get_db),
    token_info: TokenInfo = Depends(require_admin_role_with_ip_check)
):
    """Create a new API token (admin only).

    The token value is returned only once - save it securely!
    """
    # Validate token type
    if body.token_type not in ["admin", "agent"]:
        raise HTTPException(
            status_code=400,
            detail="token_type must be 'admin' or 'agent'"
        )

    # Agent tokens require agent_id
    if body.token_type == "agent" and not body.agent_id:
        raise HTTPException(
            status_code=400,
            detail="agent_id is required for agent tokens"
        )

    # Admin tokens should not have agent_id
    if body.token_type == "admin" and body.agent_id:
        raise HTTPException(
            status_code=400,
            detail="admin tokens should not have an agent_id"
        )

    # Super-admin tokens are bootstrap-only (created via direct DB insert at startup)
    if body.is_super_admin:
        raise HTTPException(
            status_code=400,
            detail="Super-admin tokens cannot be created via the API"
        )

    # Determine tenant_id for the new token
    new_tenant_id = body.tenant_id
    if body.token_type == "agent" and body.agent_id:
        # For agent tokens, try to get tenant from the agent (if it exists)
        # Allow pre-provisioning tokens for agents that don't exist yet
        agent = db.query(AgentState).filter(
            AgentState.agent_id == body.agent_id,
            AgentState.deleted_at.is_(None)
        ).first()
        if agent:
            new_tenant_id = agent.tenant_id

    # Fall back to creator's tenant if still unresolved
    if not new_tenant_id:
        new_tenant_id = token_info.tenant_id

    # Check for duplicate name
    existing = db.query(ApiToken).filter(ApiToken.name == body.name).first()
    if existing:
        raise HTTPException(status_code=400, detail="Token with this name already exists")

    # Generate token
    raw_token = generate_token()
    token_hash_value = hash_token(raw_token)

    # Calculate expiry
    expires_at = None
    if body.expires_in_days:
        expires_at = datetime.now(timezone.utc) + timedelta(days=body.expires_in_days)

    # Validate roles — agent tokens get no roles by default, admin tokens get "admin"
    valid_roles = {"admin", "developer"}
    if body.token_type == "agent":
        # Agent tokens get no roles unless explicitly specified
        raw_roles = body.roles.strip() if body.roles else ""
        if raw_roles:
            requested_roles = set(r.strip() for r in raw_roles.split(",") if r.strip())
            invalid_roles = requested_roles - valid_roles
            if invalid_roles:
                raise HTTPException(
                    status_code=400,
                    detail=f"Invalid roles: {invalid_roles}. Valid roles are: {valid_roles}"
                )
            roles_str = ",".join(sorted(requested_roles))
        else:
            roles_str = ""
    else:
        # Admin tokens default to "admin" role
        requested_roles = set(r.strip() for r in (body.roles or "admin").split(",") if r.strip())
        invalid_roles = requested_roles - valid_roles
        if invalid_roles:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid roles: {invalid_roles}. Valid roles are: {valid_roles}"
            )
        roles_str = ",".join(sorted(requested_roles))

    # Create token record
    db_token = ApiToken(
        name=body.name,
        token_hash=token_hash_value,
        token_type=body.token_type,
        agent_id=body.agent_id,
        tenant_id=new_tenant_id,
        is_super_admin=body.is_super_admin,
        roles=roles_str,
        expires_at=expires_at
    )
    db.add(db_token)

    # Log token creation — target is the tenant the token belongs to
    log = AuditTrail(
        event_type="token_created",
        user=token_info.token_name or "admin",
        action=f"Token '{body.name}' created (type={body.token_type}, roles={roles_str}, super_admin={body.is_super_admin})",
        details=f"agent_id={body.agent_id}, tenant_id={new_tenant_id}" if body.agent_id else f"tenant_id={new_tenant_id}",
        severity="INFO",
        tenant_id=new_tenant_id
    )
    db.add(log)
    db.commit()
    db.refresh(db_token)

    return ApiTokenCreatedResponse(
        id=db_token.id,
        name=db_token.name,
        token_type=db_token.token_type,
        agent_id=db_token.agent_id,
        tenant_id=db_token.tenant_id,
        is_super_admin=db_token.is_super_admin or False,
        roles=db_token.roles if db_token.roles is not None else "admin",
        token=raw_token,  # Only returned once!
        expires_at=db_token.expires_at
    )


@router.delete("/api/v1/tokens/{token_id}")
@limiter.limit("10/minute")
async def delete_token(
    request: Request,
    token_id: int,
    db: Session = Depends(get_db),
    token_info: TokenInfo = Depends(require_admin_role_with_ip_check)
):
    """Delete an API token (admin only)."""
    db_token = db.query(ApiToken).filter(ApiToken.id == token_id).first()
    if not db_token:
        raise HTTPException(status_code=404, detail="Token not found")

    if db_token.is_super_admin:
        raise HTTPException(status_code=400, detail="Super-admin tokens cannot be deleted via the API")

    token_name = db_token.name
    deleted_token_tenant_id = db_token.tenant_id
    redis_client = getattr(request.app.state, "redis", None)
    await invalidate_token_cache_async(db_token.token_hash, redis_client)

    # Log token deletion — target is the tenant the token belonged to
    log = AuditTrail(
        event_type="token_deleted",
        user=token_info.token_name or "admin",
        action=f"Token '{token_name}' deleted",
        severity="WARNING",
        tenant_id=deleted_token_tenant_id
    )
    db.add(log)

    db.delete(db_token)
    db.commit()

    return {"status": "deleted", "name": token_name}


@router.patch("/api/v1/tokens/{token_id}")
@limiter.limit("30/minute")
async def update_token(
    request: Request,
    token_id: int,
    enabled: Optional[bool] = None,
    db: Session = Depends(get_db),
    token_info: TokenInfo = Depends(require_admin_role)
):
    """Update an API token (enable/disable)."""
    db_token = db.query(ApiToken).filter(ApiToken.id == token_id).first()
    if not db_token:
        raise HTTPException(status_code=404, detail="Token not found")

    if db_token.is_super_admin:
        raise HTTPException(status_code=400, detail="Super-admin tokens cannot be modified via the API")

    if enabled is not None:
        db_token.enabled = enabled
        redis_client = getattr(request.app.state, "redis", None)
        await invalidate_token_cache_async(db_token.token_hash, redis_client)

        # Log the change — target is the tenant the token belongs to
        action = "enabled" if enabled else "disabled"
        log = AuditTrail(
            event_type=f"token_{action}",
            user=token_info.token_name or "admin",
            action=f"Token '{db_token.name}' {action}",
            severity="INFO",
            tenant_id=db_token.tenant_id
        )
        db.add(log)

    db.commit()
    db.refresh(db_token)

    return ApiTokenResponse(
        id=db_token.id,
        name=db_token.name,
        token_type=db_token.token_type,
        agent_id=db_token.agent_id,
        tenant_id=db_token.tenant_id,
        is_super_admin=db_token.is_super_admin or False,
        roles=db_token.roles if db_token.roles is not None else "admin",
        created_at=db_token.created_at,
        expires_at=db_token.expires_at,
        last_used_at=db_token.last_used_at,
        enabled=db_token.enabled
    )
