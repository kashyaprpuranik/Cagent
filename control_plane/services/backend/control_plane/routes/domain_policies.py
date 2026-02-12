import logging
import os
import json
from datetime import datetime, timezone

logger = logging.getLogger(__name__)
from typing import Optional, List

from fastapi import APIRouter, HTTPException, Depends, Query, Request
from sqlalchemy import or_
from sqlalchemy.orm import Session

from control_plane.database import get_db
from control_plane.models import DomainPolicy, AuditTrail
from control_plane.schemas import (
    DomainPolicyCreate, DomainPolicyUpdate, DomainPolicyResponse, DomainPolicyCredential,
)
from control_plane.crypto import encrypt_secret, decrypt_secret
from control_plane.auth import TokenInfo, verify_token, require_admin_role, require_admin_role_with_ip_check
from control_plane.rate_limit import limiter
from control_plane.redis_client import (
    publish_policy_changed,
    get_cached_domain_policies,
    cache_domain_policies,
)

router = APIRouter()


def _filter_not_expired(query):
    """Add filter to exclude expired policies (expires_at IS NULL OR expires_at > now)."""
    now = datetime.now(timezone.utc)
    return query.filter(or_(DomainPolicy.expires_at.is_(None), DomainPolicy.expires_at > now))


def match_domain(pattern: str, domain: str) -> bool:
    """Match domain against pattern (supports wildcard prefix)"""
    if not pattern:
        return False
    if pattern.startswith("*."):
        # Wildcard match: *.github.com matches api.github.com, raw.github.com
        suffix = pattern[1:]  # .github.com
        return domain.endswith(suffix) or domain == pattern[2:]
    return domain == pattern


def domain_policy_to_response(policy: DomainPolicy) -> dict:
    """Convert DomainPolicy to response dict with has_credential flag."""
    return {
        "id": policy.id,
        "tenant_id": policy.tenant_id,
        "domain": policy.domain,
        "alias": policy.alias,
        "description": policy.description,
        "enabled": policy.enabled,
        "agent_id": policy.agent_id,
        "allowed_paths": policy.allowed_paths or [],
        "requests_per_minute": policy.requests_per_minute,
        "burst_size": policy.burst_size,
        "bytes_per_hour": policy.bytes_per_hour,
        "timeout": policy.timeout,
        "read_only": policy.read_only,
        "expires_at": policy.expires_at,
        "has_credential": policy.credential_value_encrypted is not None,
        "credential_header": policy.credential_header,
        "credential_format": policy.credential_format,
        "credential_rotated_at": policy.credential_rotated_at,
        "created_at": policy.created_at,
        "updated_at": policy.updated_at,
    }


def build_policy_response(policy: DomainPolicy) -> dict:
    """Build a policy response with decrypted credential."""
    result = {
        "matched": True,
        "domain": policy.domain,
        "alias": policy.alias,
        "allowed_paths": policy.allowed_paths or [],
        "requests_per_minute": policy.requests_per_minute or int(os.environ.get('DEFAULT_RATE_LIMIT_RPM', '120')),
        "burst_size": policy.burst_size or int(os.environ.get('DEFAULT_RATE_LIMIT_BURST', '20')),
        "bytes_per_hour": policy.bytes_per_hour or int(os.environ.get('DEFAULT_EGRESS_LIMIT_BYTES', '104857600')),
        "timeout": policy.timeout,
        "read_only": policy.read_only,
        "header_name": None,
        "header_value": None,
    }

    # Include credential if present
    if policy.credential_value_encrypted:
        try:
            decrypted = decrypt_secret(policy.credential_value_encrypted)
            formatted_value = policy.credential_format.replace("{value}", decrypted)
            result["header_name"] = policy.credential_header
            result["header_value"] = formatted_value
        except Exception as e:
            logger.error(f"Failed to decrypt credential for policy {policy.id}: {e}")

    return result


@router.get("/api/v1/domain-policies")
@limiter.limit("60/minute")
async def list_domain_policies(
    request: Request,
    db: Session = Depends(get_db),
    token_info: TokenInfo = Depends(require_admin_role),
    agent_id: Optional[str] = None,
    tenant_id: Optional[int] = None,
    limit: int = Query(default=100, le=1000),
    offset: int = Query(default=0, ge=0),
):
    """List domain policies. Filter by tenant_id (super admin) or agent_id."""
    query = db.query(DomainPolicy)

    # Tenant filtering
    if token_info.is_super_admin:
        # Super admin can filter by tenant_id or see all
        if tenant_id is not None:
            query = query.filter(DomainPolicy.tenant_id == tenant_id)
    else:
        # Non-super-admin sees only their tenant's policies
        query = query.filter(DomainPolicy.tenant_id == token_info.tenant_id)

    if agent_id:
        query = query.filter(
            (DomainPolicy.agent_id == agent_id) | (DomainPolicy.agent_id.is_(None))
        )

    # Filter out expired policies
    query = _filter_not_expired(query)

    total = query.count()
    policies = query.order_by(DomainPolicy.domain).offset(offset).limit(limit).all()
    return {"items": [domain_policy_to_response(p) for p in policies], "total": total, "limit": limit, "offset": offset}


@router.post("/api/v1/domain-policies", response_model=DomainPolicyResponse)
@limiter.limit("30/minute")
async def create_domain_policy(
    request: Request,
    policy: DomainPolicyCreate,
    db: Session = Depends(get_db),
    token_info: TokenInfo = Depends(require_admin_role_with_ip_check),
    tenant_id: Optional[int] = None
):
    """Create a new domain policy."""
    # Determine tenant_id - every policy must belong to a tenant
    if token_info.is_super_admin:
        if tenant_id is None:
            raise HTTPException(status_code=400, detail="tenant_id is required")
        effective_tenant_id = tenant_id
    else:
        # Non-super-admin policies are always scoped to their tenant
        effective_tenant_id = token_info.tenant_id

    # Check for duplicates within same tenant
    existing = db.query(DomainPolicy).filter(
        DomainPolicy.domain == policy.domain,
        DomainPolicy.agent_id == policy.agent_id,
        DomainPolicy.tenant_id == effective_tenant_id
    ).first()
    if existing:
        raise HTTPException(status_code=400, detail="Policy for this domain already exists")

    # Encrypt credential if provided
    encrypted_value = None
    if policy.credential:
        encrypted_value = encrypt_secret(policy.credential.value)

    db_policy = DomainPolicy(
        tenant_id=effective_tenant_id,
        domain=policy.domain,
        alias=policy.alias,
        description=policy.description,
        agent_id=policy.agent_id,
        allowed_paths=policy.allowed_paths or [],
        requests_per_minute=policy.requests_per_minute,
        burst_size=policy.burst_size,
        bytes_per_hour=policy.bytes_per_hour,
        timeout=policy.timeout,
        read_only=policy.read_only or False,
        expires_at=policy.expires_at,
        credential_header=policy.credential.header if policy.credential else None,
        credential_format=policy.credential.format if policy.credential else None,
        credential_value_encrypted=encrypted_value,
        credential_rotated_at=datetime.now(timezone.utc) if policy.credential else None,
    )
    db.add(db_policy)

    # Audit log
    log = AuditTrail(
        event_type="domain_policy_created",
        user=token_info.token_name or "admin",
        action=f"Domain policy created: {policy.domain}",
        details=json.dumps({"domain": policy.domain, "agent_id": policy.agent_id, "has_credential": policy.credential is not None}),
        severity="INFO",
        tenant_id=effective_tenant_id
    )
    db.add(log)
    db.commit()
    db.refresh(db_policy)

    redis_client = getattr(request.app.state, "redis", None)
    await publish_policy_changed(redis_client, effective_tenant_id, "created", policy.domain)

    return domain_policy_to_response(db_policy)


@router.get("/api/v1/domain-policies/for-domain")
@limiter.limit("120/minute")
async def get_policy_for_domain(
    request: Request,
    domain: str,
    db: Session = Depends(get_db),
    token_info: TokenInfo = Depends(verify_token)
):
    """Get complete policy for a domain (used by Envoy).

    Returns all policy settings: paths, rate limits, egress limits, credentials.
    Agent tokens receive policies scoped to their agent + global policies.
    """
    query = db.query(DomainPolicy).filter(DomainPolicy.enabled == True)

    # Tenant isolation
    if token_info.token_type == "agent" and token_info.agent_id:
        # Agent tokens only see their agent's policies + global policies
        query = query.filter(
            (DomainPolicy.agent_id == token_info.agent_id) | (DomainPolicy.agent_id.is_(None))
        )
    elif not token_info.is_super_admin:
        # Non-super-admin sees only their tenant's policies
        if not token_info.tenant_id:
            raise HTTPException(status_code=403, detail="Token must be scoped to a tenant")
        query = query.filter(DomainPolicy.tenant_id == token_info.tenant_id)

    # Filter out expired policies
    query = _filter_not_expired(query)

    policies = query.all()

    # Check for alias match first (devbox.local)
    if domain.endswith(".devbox.local"):
        alias = domain.replace(".devbox.local", "")
        for policy in policies:
            if policy.alias == alias:
                # Build response with credential
                result = build_policy_response(policy)
                if policy.domain.startswith("*."):
                    result["target_domain"] = policy.domain[2:]
                else:
                    result["target_domain"] = policy.domain
                return result

    # Find matching policy (agent-specific takes precedence)
    matching_policy = None
    for policy in policies:
        if match_domain(policy.domain, domain):
            if matching_policy is None or (policy.agent_id is not None and matching_policy.agent_id is None):
                matching_policy = policy

    if not matching_policy:
        # Return defaults
        default_rpm = int(os.environ.get('DEFAULT_RATE_LIMIT_RPM', '120'))
        default_burst = int(os.environ.get('DEFAULT_RATE_LIMIT_BURST', '20'))
        default_bytes = int(os.environ.get('DEFAULT_EGRESS_LIMIT_BYTES', '104857600'))
        return {
            "matched": False,
            "domain": domain,
            "allowed_paths": [],
            "requests_per_minute": default_rpm,
            "burst_size": default_burst,
            "bytes_per_hour": default_bytes,
            "header_name": None,
            "header_value": None,
        }

    return build_policy_response(matching_policy)


@router.get("/api/v1/domain-policies/export")
@limiter.limit("120/minute")
async def export_domain_policies(
    request: Request,
    db: Session = Depends(get_db),
    token_info: TokenInfo = Depends(verify_token)
):
    """Export all domains for CoreDNS allowlist.

    Returns list of domains (without credentials) for DNS filtering.
    Uses Redis cache (300 s TTL) when available.
    """
    # Build cache key from token context
    redis_client = getattr(request.app.state, "redis", None)
    agent_part = token_info.agent_id or "all"
    tenant_part = token_info.tenant_id or "global"
    cache_key = f"tenant:{tenant_part}:agent:{agent_part}:export"

    # Check Redis cache first
    cached = await get_cached_domain_policies(redis_client, cache_key)
    if cached is not None:
        return cached

    query = db.query(DomainPolicy).filter(DomainPolicy.enabled == True)

    # Tenant isolation
    if token_info.token_type == "agent" and token_info.agent_id:
        # Agent tokens only see their agent's policies + global policies
        query = query.filter(
            (DomainPolicy.agent_id == token_info.agent_id) | (DomainPolicy.agent_id.is_(None))
        )
    elif not token_info.is_super_admin:
        # Non-super-admin sees only their tenant's policies
        if not token_info.tenant_id:
            raise HTTPException(status_code=403, detail="Token must be scoped to a tenant")
        query = query.filter(DomainPolicy.tenant_id == token_info.tenant_id)

    # Filter out expired policies
    query = _filter_not_expired(query)

    policies = query.all()
    domains = [p.domain for p in policies]

    result = {
        "domains": domains,
        "generated_at": datetime.now(timezone.utc).isoformat()
    }

    # Populate Redis cache
    await cache_domain_policies(redis_client, cache_key, result)

    return result


@router.get("/api/v1/domain-policies/{policy_id}", response_model=DomainPolicyResponse)
@limiter.limit("60/minute")
async def get_domain_policy(
    request: Request,
    policy_id: int,
    db: Session = Depends(get_db),
    token_info: TokenInfo = Depends(require_admin_role)
):
    """Get a domain policy by ID."""
    policy = db.query(DomainPolicy).filter(DomainPolicy.id == policy_id).first()
    if not policy:
        raise HTTPException(status_code=404, detail="Policy not found")
    if not token_info.is_super_admin and policy.tenant_id != token_info.tenant_id:
        raise HTTPException(status_code=404, detail="Policy not found")
    return domain_policy_to_response(policy)


@router.put("/api/v1/domain-policies/{policy_id}", response_model=DomainPolicyResponse)
@limiter.limit("30/minute")
async def update_domain_policy(
    request: Request,
    policy_id: int,
    update: DomainPolicyUpdate,
    db: Session = Depends(get_db),
    token_info: TokenInfo = Depends(require_admin_role_with_ip_check)
):
    """Update a domain policy."""
    policy = db.query(DomainPolicy).filter(DomainPolicy.id == policy_id).first()
    if not policy:
        raise HTTPException(status_code=404, detail="Policy not found")
    if not token_info.is_super_admin and policy.tenant_id != token_info.tenant_id:
        raise HTTPException(status_code=404, detail="Policy not found")

    # Update fields if provided
    if update.alias is not None:
        policy.alias = update.alias
    if update.description is not None:
        policy.description = update.description
    if update.enabled is not None:
        policy.enabled = update.enabled
    if update.allowed_paths is not None:
        policy.allowed_paths = update.allowed_paths
    if update.requests_per_minute is not None:
        policy.requests_per_minute = update.requests_per_minute
    if update.burst_size is not None:
        policy.burst_size = update.burst_size
    if update.bytes_per_hour is not None:
        policy.bytes_per_hour = update.bytes_per_hour
    if update.timeout is not None:
        policy.timeout = update.timeout
    if update.read_only is not None:
        policy.read_only = update.read_only

    # Handle expires_at
    if update.clear_expires_at:
        policy.expires_at = None
    elif update.expires_at is not None:
        policy.expires_at = update.expires_at

    # Handle credential update
    if update.clear_credential:
        policy.credential_header = None
        policy.credential_format = None
        policy.credential_value_encrypted = None
        policy.credential_rotated_at = None
    elif update.credential:
        policy.credential_header = update.credential.header
        policy.credential_format = update.credential.format
        policy.credential_value_encrypted = encrypt_secret(update.credential.value)
        policy.credential_rotated_at = datetime.now(timezone.utc)

    # Audit log
    log = AuditTrail(
        event_type="domain_policy_updated",
        user=token_info.token_name or "admin",
        action=f"Domain policy updated: {policy.domain}",
        details=json.dumps({"policy_id": policy_id, "domain": policy.domain}),
        severity="INFO",
        tenant_id=policy.tenant_id
    )
    db.add(log)
    db.commit()
    db.refresh(policy)

    redis_client = getattr(request.app.state, "redis", None)
    await publish_policy_changed(redis_client, policy.tenant_id, "updated", policy.domain)

    return domain_policy_to_response(policy)


@router.delete("/api/v1/domain-policies/{policy_id}")
@limiter.limit("30/minute")
async def delete_domain_policy(
    request: Request,
    policy_id: int,
    db: Session = Depends(get_db),
    token_info: TokenInfo = Depends(require_admin_role_with_ip_check)
):
    """Delete a domain policy."""
    policy = db.query(DomainPolicy).filter(DomainPolicy.id == policy_id).first()
    if not policy:
        raise HTTPException(status_code=404, detail="Policy not found")
    if not token_info.is_super_admin and policy.tenant_id != token_info.tenant_id:
        raise HTTPException(status_code=404, detail="Policy not found")

    # Capture details before deletion
    domain = policy.domain
    tenant_id = policy.tenant_id

    db.delete(policy)

    # Audit log
    log = AuditTrail(
        event_type="domain_policy_deleted",
        user=token_info.token_name or "admin",
        action=f"Domain policy deleted: {domain}",
        details=json.dumps({"policy_id": policy_id, "domain": domain}),
        severity="WARNING",
        tenant_id=tenant_id
    )
    db.add(log)
    db.commit()

    redis_client = getattr(request.app.state, "redis", None)
    await publish_policy_changed(redis_client, tenant_id, "deleted", domain)

    return {"deleted": True, "id": policy_id}


@router.post("/api/v1/domain-policies/{policy_id}/rotate-credential", response_model=DomainPolicyResponse)
@limiter.limit("10/minute")
async def rotate_domain_policy_credential(
    request: Request,
    policy_id: int,
    credential: DomainPolicyCredential,
    db: Session = Depends(get_db),
    token_info: TokenInfo = Depends(require_admin_role_with_ip_check)
):
    """Rotate the credential for a domain policy."""
    policy = db.query(DomainPolicy).filter(DomainPolicy.id == policy_id).first()
    if not policy:
        raise HTTPException(status_code=404, detail="Policy not found")
    if not token_info.is_super_admin and policy.tenant_id != token_info.tenant_id:
        raise HTTPException(status_code=404, detail="Policy not found")

    policy.credential_header = credential.header
    policy.credential_format = credential.format
    policy.credential_value_encrypted = encrypt_secret(credential.value)
    policy.credential_rotated_at = datetime.now(timezone.utc)

    log = AuditTrail(
        event_type="domain_policy_credential_rotated",
        user=token_info.token_name or "admin",
        action=f"Domain policy credential rotated: {policy.domain}",
        details=json.dumps({"policy_id": policy_id, "domain": policy.domain}),
        severity="WARNING",
        tenant_id=policy.tenant_id
    )
    db.add(log)
    db.commit()
    db.refresh(policy)

    redis_client = getattr(request.app.state, "redis", None)
    await publish_policy_changed(redis_client, policy.tenant_id, "updated", policy.domain)

    return domain_policy_to_response(policy)
