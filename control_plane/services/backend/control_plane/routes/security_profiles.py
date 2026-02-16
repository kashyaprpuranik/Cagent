import json
from datetime import datetime, timezone
from typing import Dict, List, Optional

from fastapi import APIRouter, HTTPException, Depends, Query, Request
from sqlalchemy import func
from sqlalchemy.orm import Session

from control_plane.database import get_db
from control_plane.models import SecurityProfile, AgentState, DomainPolicy, AuditTrail
from control_plane.schemas import (
    SecurityProfileCreate, SecurityProfileUpdate, SecurityProfileResponse,
    AgentProfileAssignment, BulkAgentProfileAssignment,
)
from control_plane.auth import TokenInfo, require_admin_role, require_admin_role_with_ip_check, _get_redis_client
from control_plane.cache import security_profile_cache, agent_state_cache, domain_policy_cache
from control_plane.rate_limit import limiter

router = APIRouter()


def _profile_to_response(
    profile: SecurityProfile,
    agent_counts: Dict[int, int],
    policy_counts: Dict[int, int],
) -> dict:
    """Convert SecurityProfile to response dict with precomputed counts."""
    return {
        "id": profile.id,
        "tenant_id": profile.tenant_id,
        "name": profile.name,
        "description": profile.description,
        "seccomp_profile": profile.seccomp_profile or "hardened",
        "cpu_limit": profile.cpu_limit,
        "memory_limit_mb": profile.memory_limit_mb,
        "pids_limit": profile.pids_limit,
        "agent_count": agent_counts.get(profile.id, 0),
        "policy_count": policy_counts.get(profile.id, 0),
        "created_at": profile.created_at,
        "updated_at": profile.updated_at,
    }


def _batch_counts(db: Session, profile_ids: List[int]) -> tuple:
    """Load agent and policy counts for a batch of profiles in 2 queries."""
    if not profile_ids:
        return {}, {}

    agent_rows = (
        db.query(AgentState.security_profile_id, func.count())
        .filter(
            AgentState.security_profile_id.in_(profile_ids),
            AgentState.deleted_at.is_(None),
        )
        .group_by(AgentState.security_profile_id)
        .all()
    )
    agent_counts = {pid: cnt for pid, cnt in agent_rows}

    policy_rows = (
        db.query(DomainPolicy.profile_id, func.count())
        .filter(DomainPolicy.profile_id.in_(profile_ids))
        .group_by(DomainPolicy.profile_id)
        .all()
    )
    policy_counts = {pid: cnt for pid, cnt in policy_rows}

    return agent_counts, policy_counts


@router.get("/api/v1/security-profiles")
@limiter.limit("60/minute")
async def list_security_profiles(
    request: Request,
    db: Session = Depends(get_db),
    token_info: TokenInfo = Depends(require_admin_role),
    tenant_id: Optional[int] = None,
    limit: int = Query(default=100, le=1000),
    offset: int = Query(default=0, ge=0),
):
    """List security profiles (tenant-scoped, paginated)."""
    query = db.query(SecurityProfile)

    if token_info.is_super_admin:
        if tenant_id is not None:
            query = query.filter(SecurityProfile.tenant_id == tenant_id)
    else:
        query = query.filter(SecurityProfile.tenant_id == token_info.tenant_id)

    total = query.count()
    profiles = query.order_by(SecurityProfile.name).offset(offset).limit(limit).all()
    agent_counts, policy_counts = _batch_counts(db, [p.id for p in profiles])
    return {
        "items": [_profile_to_response(p, agent_counts, policy_counts) for p in profiles],
        "total": total,
        "limit": limit,
        "offset": offset,
    }


@router.post("/api/v1/security-profiles", response_model=SecurityProfileResponse)
@limiter.limit("30/minute")
async def create_security_profile(
    request: Request,
    profile: SecurityProfileCreate,
    db: Session = Depends(get_db),
    token_info: TokenInfo = Depends(require_admin_role_with_ip_check),
    tenant_id: Optional[int] = None,
):
    """Create a new security profile."""
    if token_info.is_super_admin:
        if tenant_id is None:
            raise HTTPException(status_code=400, detail="tenant_id is required")
        effective_tenant_id = tenant_id
    else:
        effective_tenant_id = token_info.tenant_id

    # Check for duplicate name within tenant
    existing = db.query(SecurityProfile).filter(
        SecurityProfile.name == profile.name,
        SecurityProfile.tenant_id == effective_tenant_id,
    ).first()
    if existing:
        raise HTTPException(status_code=400, detail="A security profile with this name already exists")

    db_profile = SecurityProfile(
        tenant_id=effective_tenant_id,
        name=profile.name,
        description=profile.description,
        seccomp_profile=profile.seccomp_profile.value if profile.seccomp_profile else "hardened",
        cpu_limit=profile.cpu_limit,
        memory_limit_mb=profile.memory_limit_mb,
        pids_limit=profile.pids_limit,
    )
    db.add(db_profile)

    log = AuditTrail(
        event_type="security_profile_created",
        user=token_info.token_name or "admin",
        action=f"Security profile created: {profile.name}",
        details=json.dumps({"name": profile.name}),
        severity="INFO",
        tenant_id=effective_tenant_id,
    )
    db.add(log)
    db.commit()
    db.refresh(db_profile)

    return _profile_to_response(db_profile, *_batch_counts(db, [db_profile.id]))


@router.get("/api/v1/security-profiles/{profile_id}", response_model=SecurityProfileResponse)
@limiter.limit("60/minute")
async def get_security_profile(
    request: Request,
    profile_id: int,
    db: Session = Depends(get_db),
    token_info: TokenInfo = Depends(require_admin_role),
):
    """Get a single security profile."""
    profile = db.query(SecurityProfile).filter(SecurityProfile.id == profile_id).first()
    if not profile:
        raise HTTPException(status_code=404, detail="Security profile not found")
    if not token_info.is_super_admin and profile.tenant_id != token_info.tenant_id:
        raise HTTPException(status_code=404, detail="Security profile not found")
    return _profile_to_response(profile, *_batch_counts(db, [profile.id]))


@router.put("/api/v1/security-profiles/{profile_id}", response_model=SecurityProfileResponse)
@limiter.limit("30/minute")
async def update_security_profile(
    request: Request,
    profile_id: int,
    update: SecurityProfileUpdate,
    db: Session = Depends(get_db),
    token_info: TokenInfo = Depends(require_admin_role_with_ip_check),
):
    """Update a security profile."""
    profile = db.query(SecurityProfile).filter(SecurityProfile.id == profile_id).first()
    if not profile:
        raise HTTPException(status_code=404, detail="Security profile not found")
    if not token_info.is_super_admin and profile.tenant_id != token_info.tenant_id:
        raise HTTPException(status_code=404, detail="Security profile not found")

    if update.name is not None:
        # Check for duplicate name
        existing = db.query(SecurityProfile).filter(
            SecurityProfile.name == update.name,
            SecurityProfile.tenant_id == profile.tenant_id,
            SecurityProfile.id != profile_id,
        ).first()
        if existing:
            raise HTTPException(status_code=400, detail="A security profile with this name already exists")
        profile.name = update.name

    if update.description is not None:
        profile.description = update.description
    if update.seccomp_profile is not None:
        profile.seccomp_profile = update.seccomp_profile.value
    if update.cpu_limit is not None:
        profile.cpu_limit = update.cpu_limit if update.cpu_limit > 0 else None
    if update.memory_limit_mb is not None:
        profile.memory_limit_mb = update.memory_limit_mb if update.memory_limit_mb > 0 else None
    if update.pids_limit is not None:
        profile.pids_limit = update.pids_limit if update.pids_limit > 0 else None

    log = AuditTrail(
        event_type="security_profile_updated",
        user=token_info.token_name or "admin",
        action=f"Security profile updated: {profile.name}",
        details=json.dumps({"profile_id": profile_id, "name": profile.name}),
        severity="INFO",
        tenant_id=profile.tenant_id,
    )
    db.add(log)
    db.commit()
    db.refresh(profile)

    redis_client = _get_redis_client(request)
    await domain_policy_cache.invalidate_by_prefix(f"tenant:{profile.tenant_id}:", redis_client)
    await security_profile_cache.invalidate(str(profile_id), redis_client)

    return _profile_to_response(profile, *_batch_counts(db, [profile.id]))


@router.delete("/api/v1/security-profiles/{profile_id}")
@limiter.limit("30/minute")
async def delete_security_profile(
    request: Request,
    profile_id: int,
    db: Session = Depends(get_db),
    token_info: TokenInfo = Depends(require_admin_role_with_ip_check),
):
    """Delete a security profile. Rejects if default, has agents, or has policies."""
    profile = db.query(SecurityProfile).filter(SecurityProfile.id == profile_id).first()
    if not profile:
        raise HTTPException(status_code=404, detail="Security profile not found")
    if not token_info.is_super_admin and profile.tenant_id != token_info.tenant_id:
        raise HTTPException(status_code=404, detail="Security profile not found")

    if profile.name == "default":
        raise HTTPException(status_code=400, detail="Cannot delete the default security profile")

    policy_count = db.query(DomainPolicy).filter(
        DomainPolicy.profile_id == profile_id,
    ).count()
    if policy_count > 0:
        raise HTTPException(status_code=400, detail="Cannot delete profile with associated policies")

    # Find agents that will be reassigned (for cache invalidation)
    affected_agents = db.query(AgentState.agent_id).filter(
        AgentState.security_profile_id == profile_id,
        AgentState.deleted_at.is_(None),
    ).all()

    # Reassign agents to the "default" profile (or unassign if no default exists)
    default_profile = db.query(SecurityProfile).filter(
        SecurityProfile.name == "default",
        SecurityProfile.tenant_id == profile.tenant_id,
    ).first()
    new_profile_id = default_profile.id if default_profile else None
    db.query(AgentState).filter(
        AgentState.security_profile_id == profile_id,
        AgentState.deleted_at.is_(None),
    ).update({AgentState.security_profile_id: new_profile_id})
    db.flush()

    name = profile.name
    tenant_id = profile.tenant_id
    db.delete(profile)

    log = AuditTrail(
        event_type="security_profile_deleted",
        user=token_info.token_name or "admin",
        action=f"Security profile deleted: {name}",
        details=json.dumps({"profile_id": profile_id, "name": name}),
        severity="WARNING",
        tenant_id=tenant_id,
    )
    db.add(log)
    db.commit()

    redis_client = _get_redis_client(request)
    await domain_policy_cache.invalidate_by_prefix(f"tenant:{tenant_id}:", redis_client)
    await security_profile_cache.invalidate(str(profile_id), redis_client)
    for (aid,) in affected_agents:
        await agent_state_cache.invalidate(aid, redis_client)

    return {"deleted": True, "id": profile_id}


# =============================================================================
# Agent Profile Assignment
# =============================================================================

@router.put("/api/v1/agents/{agent_id}/profile")
@limiter.limit("30/minute")
async def assign_agent_profile(
    request: Request,
    agent_id: str,
    body: AgentProfileAssignment,
    db: Session = Depends(get_db),
    token_info: TokenInfo = Depends(require_admin_role_with_ip_check),
):
    """Assign a security profile to an agent."""
    agent = db.query(AgentState).filter(
        AgentState.agent_id == agent_id,
        AgentState.deleted_at.is_(None),
    ).first()
    if not agent:
        raise HTTPException(status_code=404, detail=f"Agent {agent_id} not found")
    if not token_info.is_super_admin and agent.tenant_id != token_info.tenant_id:
        raise HTTPException(status_code=404, detail=f"Agent {agent_id} not found")

    profile = db.query(SecurityProfile).filter(SecurityProfile.id == body.profile_id).first()
    if not profile:
        raise HTTPException(status_code=404, detail="Security profile not found")
    if profile.tenant_id != agent.tenant_id:
        raise HTTPException(status_code=400, detail="Profile and agent must belong to the same tenant")

    agent.security_profile_id = profile.id

    log = AuditTrail(
        event_type="agent_profile_assigned",
        user=token_info.token_name or "admin",
        action=f"Security profile '{profile.name}' assigned to agent {agent_id}",
        details=json.dumps({"agent_id": agent_id, "profile_id": profile.id, "profile_name": profile.name}),
        severity="INFO",
        tenant_id=agent.tenant_id,
    )
    db.add(log)
    db.commit()

    redis_client = _get_redis_client(request)
    await domain_policy_cache.invalidate_by_prefix(f"tenant:{agent.tenant_id}:", redis_client)
    await agent_state_cache.invalidate(agent_id, redis_client)

    return {"agent_id": agent_id, "profile_id": profile.id, "profile_name": profile.name}


@router.delete("/api/v1/agents/{agent_id}/profile")
@limiter.limit("30/minute")
async def unassign_agent_profile(
    request: Request,
    agent_id: str,
    db: Session = Depends(get_db),
    token_info: TokenInfo = Depends(require_admin_role_with_ip_check),
):
    """Unassign security profile from an agent (revert to tenant baseline)."""
    agent = db.query(AgentState).filter(
        AgentState.agent_id == agent_id,
        AgentState.deleted_at.is_(None),
    ).first()
    if not agent:
        raise HTTPException(status_code=404, detail=f"Agent {agent_id} not found")
    if not token_info.is_super_admin and agent.tenant_id != token_info.tenant_id:
        raise HTTPException(status_code=404, detail=f"Agent {agent_id} not found")

    old_profile_id = agent.security_profile_id
    agent.security_profile_id = None

    log = AuditTrail(
        event_type="agent_profile_unassigned",
        user=token_info.token_name or "admin",
        action=f"Security profile unassigned from agent {agent_id}",
        details=json.dumps({"agent_id": agent_id, "old_profile_id": old_profile_id}),
        severity="INFO",
        tenant_id=agent.tenant_id,
    )
    db.add(log)
    db.commit()

    redis_client = _get_redis_client(request)
    await domain_policy_cache.invalidate_by_prefix(f"tenant:{agent.tenant_id}:", redis_client)
    await agent_state_cache.invalidate(agent_id, redis_client)

    return {"agent_id": agent_id, "profile_id": None}


# =============================================================================
# Bulk Agent Profile Assignment
# =============================================================================

@router.post("/api/v1/agents/bulk-profile")
@limiter.limit("30/minute")
async def bulk_assign_agent_profile(
    request: Request,
    body: BulkAgentProfileAssignment,
    db: Session = Depends(get_db),
    token_info: TokenInfo = Depends(require_admin_role_with_ip_check),
):
    """Bulk assign or unassign a security profile to/from multiple agents."""
    if not body.agent_ids:
        raise HTTPException(status_code=400, detail="agent_ids must not be empty")

    # Load all agents
    agents = db.query(AgentState).filter(
        AgentState.agent_id.in_(body.agent_ids),
        AgentState.deleted_at.is_(None),
    ).all()

    found_ids = {a.agent_id for a in agents}
    missing = [aid for aid in body.agent_ids if aid not in found_ids]
    if missing:
        raise HTTPException(status_code=404, detail=f"Agents not found: {', '.join(missing)}")

    # Tenant check: all agents must belong to the caller's tenant (unless super admin)
    if not token_info.is_super_admin:
        for agent in agents:
            if agent.tenant_id != token_info.tenant_id:
                raise HTTPException(status_code=403, detail="All agents must belong to your tenant")

    profile_name = None
    if body.profile_id is not None:
        profile = db.query(SecurityProfile).filter(SecurityProfile.id == body.profile_id).first()
        if not profile:
            raise HTTPException(status_code=404, detail="Security profile not found")
        # Profile must belong to same tenant as agents
        agent_tenant_ids = {a.tenant_id for a in agents}
        if len(agent_tenant_ids) > 1:
            raise HTTPException(status_code=400, detail="All agents must belong to the same tenant")
        agent_tenant_id = agent_tenant_ids.pop()
        if profile.tenant_id != agent_tenant_id:
            raise HTTPException(status_code=400, detail="Profile and agents must belong to the same tenant")
        profile_name = profile.name

    # Update all agents in one transaction
    for agent in agents:
        agent.security_profile_id = body.profile_id

    action = (
        f"Security profile '{profile_name}' bulk-assigned to {len(agents)} agents: {', '.join(body.agent_ids)}"
        if body.profile_id is not None
        else f"Security profile bulk-unassigned from {len(agents)} agents: {', '.join(body.agent_ids)}"
    )
    log = AuditTrail(
        event_type="agent_profile_bulk_assigned" if body.profile_id is not None else "agent_profile_bulk_unassigned",
        user=token_info.token_name or "admin",
        action=action,
        details=json.dumps({"agent_ids": body.agent_ids, "profile_id": body.profile_id, "profile_name": profile_name}),
        severity="INFO",
        tenant_id=token_info.tenant_id or (agents[0].tenant_id if agents else None),
    )
    db.add(log)
    db.commit()

    redis_client = _get_redis_client(request)
    tenant_ids = {a.tenant_id for a in agents}
    for tid in tenant_ids:
        await domain_policy_cache.invalidate_by_prefix(f"tenant:{tid}:", redis_client)
    for agent in agents:
        await agent_state_cache.invalidate(agent.agent_id, redis_client)

    return {"updated": body.agent_ids, "profile_id": body.profile_id, "profile_name": profile_name}
