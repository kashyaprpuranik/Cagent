import ipaddress
import threading
import time as _time
from datetime import datetime
from typing import Optional, List

from fastapi import HTTPException, Depends, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session

from control_plane.database import get_db
from control_plane.models import ApiToken, AgentState, TenantIpAcl
from control_plane.crypto import hash_token
from slowapi.util import get_remote_address

security = HTTPBearer(auto_error=False)

# ---------------------------------------------------------------------------
# Token verification cache
# ---------------------------------------------------------------------------
# Maps token_hash -> (TokenInfo, cached_at_monotonic, last_db_write_monotonic)
# TTL: 60 s — avoids a DB round-trip on every request.
# last_used_at is only flushed to the DB when the previous write was >10 min ago.
#
# TODO: Move to Redis so invalidation works across multiple API workers.
# ---------------------------------------------------------------------------
_TOKEN_CACHE_TTL = 60          # seconds
_LAST_USED_WRITE_INTERVAL = 600  # 10 minutes

_token_cache: dict = {}        # token_hash -> (TokenInfo, float, float)
_token_cache_lock = threading.Lock()


def invalidate_token_cache(token_hash: str) -> None:
    """Remove a token from the verification cache.

    Call this when a token is deleted, disabled, or modified.
    """
    with _token_cache_lock:
        _token_cache.pop(token_hash, None)


def clear_token_cache() -> None:
    """Remove all entries — useful in tests."""
    with _token_cache_lock:
        _token_cache.clear()


class TokenInfo:
    """Information about the authenticated token."""
    def __init__(
        self,
        token_type: str,
        agent_id: Optional[str] = None,
        token_name: str = "",
        tenant_id: Optional[int] = None,
        is_super_admin: bool = False,
        roles: List[str] = None,
        api_token_id: Optional[int] = None,
    ):
        self.token_type = token_type  # "admin" or "agent"
        self.agent_id = agent_id  # For agent tokens, the associated agent_id
        self.token_name = token_name
        self.tenant_id = tenant_id  # Tenant this token belongs to
        self.is_super_admin = is_super_admin  # Can access all tenants
        self.roles = roles or ["admin"]  # Default to admin for backwards compat
        self.api_token_id = api_token_id  # DB primary key of the ApiToken

    def has_role(self, role: str) -> bool:
        """Check if token has a specific role."""
        return role in self.roles or self.is_super_admin


async def verify_token(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db)
) -> TokenInfo:
    """Verify token and return token info with type and permissions.

    Uses an in-memory cache (60 s TTL) to avoid a DB round-trip on every
    request.  ``last_used_at`` is only flushed to the DB when the previous
    write was more than 10 minutes ago.
    """
    if not credentials:
        raise HTTPException(status_code=401, detail="Not authenticated")

    token = credentials.credentials
    token_hash_value = hash_token(token)
    now = _time.monotonic()

    # --- cache lookup ---
    with _token_cache_lock:
        cached = _token_cache.get(token_hash_value)
    if cached is not None:
        info, cached_at, last_write = cached
        if now - cached_at < _TOKEN_CACHE_TTL:
            # Lazily update last_used_at if stale
            if now - last_write >= _LAST_USED_WRITE_INTERVAL:
                db.execute(
                    ApiToken.__table__.update()
                    .where(ApiToken.token_hash == token_hash_value)
                    .values(last_used_at=datetime.utcnow())
                )
                db.commit()
                with _token_cache_lock:
                    _token_cache[token_hash_value] = (info, cached_at, now)
            return info

    # --- cache miss: full DB lookup ---
    db_token = db.query(ApiToken).filter(
        ApiToken.token_hash == token_hash_value,
        ApiToken.enabled == True
    ).first()

    if db_token:
        # Check expiry
        if db_token.expires_at and db_token.expires_at < datetime.utcnow():
            raise HTTPException(status_code=403, detail="Token expired")

        # Update last used timestamp
        db_token.last_used_at = datetime.utcnow()
        db.commit()

        # For agent tokens, get tenant_id from the agent
        tenant_id = db_token.tenant_id
        if db_token.token_type == "agent" and db_token.agent_id:
            agent = db.query(AgentState).filter(AgentState.agent_id == db_token.agent_id).first()
            if agent:
                tenant_id = agent.tenant_id

        # Parse roles (comma-separated string to list)
        roles = (db_token.roles or "admin").split(",")

        info = TokenInfo(
            token_type=db_token.token_type,
            agent_id=db_token.agent_id,
            token_name=db_token.name,
            tenant_id=tenant_id,
            is_super_admin=db_token.is_super_admin or False,
            roles=roles,
            api_token_id=db_token.id,
        )

        # Populate cache
        with _token_cache_lock:
            _token_cache[token_hash_value] = (info, now, now)

        return info

    raise HTTPException(status_code=403, detail="Invalid token")


async def require_admin(token_info: TokenInfo = Depends(verify_token)) -> TokenInfo:
    """Require admin token for management operations."""
    if token_info.token_type != "admin":
        raise HTTPException(
            status_code=403,
            detail="Admin token required for this operation"
        )
    return token_info


async def require_agent(token_info: TokenInfo = Depends(verify_token)) -> TokenInfo:
    """Require agent token for data plane operations."""
    if token_info.token_type != "agent":
        raise HTTPException(
            status_code=403,
            detail="Agent token required for this operation"
        )
    return token_info


async def require_super_admin(token_info: TokenInfo = Depends(verify_token)) -> TokenInfo:
    """Require super admin token for cross-tenant operations."""
    if not token_info.is_super_admin:
        raise HTTPException(
            status_code=403,
            detail="Super admin token required for this operation"
        )
    return token_info


def require_role(role: str):
    """Factory for role-based dependency.

    Usage: Depends(require_role("admin")) or Depends(require_role("developer"))
    """
    async def dependency(token_info: TokenInfo = Depends(verify_token)) -> TokenInfo:
        if not token_info.has_role(role):
            raise HTTPException(
                status_code=403,
                detail=f"Role '{role}' required for this operation"
            )
        return token_info
    return dependency


async def require_admin_role(token_info: TokenInfo = Depends(verify_token)) -> TokenInfo:
    """Require admin role for management operations (allowlist, secrets, rate limits)."""
    if not token_info.has_role("admin"):
        raise HTTPException(
            status_code=403,
            detail="Admin role required for this operation"
        )
    return token_info


async def require_developer_role(token_info: TokenInfo = Depends(verify_token)) -> TokenInfo:
    """Require developer role for development operations (terminal, logs view)."""
    if not token_info.has_role("developer"):
        raise HTTPException(
            status_code=403,
            detail="Developer role required for this operation"
        )
    return token_info


# =============================================================================
# IP ACL Validation
# =============================================================================

def validate_ip_in_cidr(ip_str: str, cidr_str: str) -> bool:
    """Check if an IP address is within a CIDR range."""
    try:
        ip = ipaddress.ip_address(ip_str)
        network = ipaddress.ip_network(cidr_str, strict=False)
        return ip in network
    except ValueError:
        return False


def get_client_ip(request: Request) -> str:
    """Get client IP, respecting X-Forwarded-For for proxied requests."""
    return get_remote_address(request)


async def verify_ip_acl(
    request: Request,
    token_info: TokenInfo = Depends(verify_token),
    db: Session = Depends(get_db)
) -> TokenInfo:
    """Verify client IP against tenant's IP ACL (for admin tokens only).

    IP ACL checks are:
    - Skipped for super admins (logged for audit)
    - Skipped for agent tokens (data planes may have dynamic IPs)
    - Applied only when tenant has IP ACLs configured
    - If tenant has ACLs but IP doesn't match any, request is denied
    """
    # Skip for super admins
    if token_info.is_super_admin:
        return token_info

    # Skip for agent tokens (heartbeat, allowlist export, etc.)
    if token_info.token_type == "agent":
        return token_info

    # Only apply to admin tokens with a tenant
    if token_info.token_type != "admin" or not token_info.tenant_id:
        return token_info

    # Get enabled IP ACLs for this tenant
    ip_acls = db.query(TenantIpAcl).filter(
        TenantIpAcl.tenant_id == token_info.tenant_id,
        TenantIpAcl.enabled == True
    ).all()

    # No ACLs configured = allow all (backwards compatible)
    if not ip_acls:
        return token_info

    # Get client IP
    client_ip = get_client_ip(request)

    # Check if IP matches any allowed CIDR
    for acl in ip_acls:
        if validate_ip_in_cidr(client_ip, acl.cidr):
            return token_info

    # IP not in any allowed range — deny.
    # TODO: Log IP ACL denials to a proper audit log (append-only / external),
    # not the transactional audit trail table.

    raise HTTPException(
        status_code=403,
        detail=f"Access denied: IP address {client_ip} is not in the allowed range for this tenant"
    )


async def require_admin_with_ip_check(
    request: Request,
    token_info: TokenInfo = Depends(verify_token),
    db: Session = Depends(get_db)
) -> TokenInfo:
    """Require admin token AND verify IP ACL."""
    # First check admin
    if token_info.token_type != "admin":
        raise HTTPException(
            status_code=403,
            detail="Admin token required for this operation"
        )

    # Then verify IP ACL
    return await verify_ip_acl(request, token_info, db)


async def require_admin_role_with_ip_check(
    request: Request,
    token_info: TokenInfo = Depends(verify_token),
    db: Session = Depends(get_db)
) -> TokenInfo:
    """Require admin role AND verify IP ACL for sensitive operations.

    Use this for endpoints that modify security-sensitive resources:
    - Allowlist entries
    - Secrets
    - Rate limits
    - Agent commands (wipe, restart, etc.)
    - Token management
    """
    # First check admin role
    if not token_info.has_role("admin"):
        raise HTTPException(
            status_code=403,
            detail="Admin role required for this operation"
        )

    # Then verify IP ACL (skips for super admin and agent tokens)
    return await verify_ip_acl(request, token_info, db)
