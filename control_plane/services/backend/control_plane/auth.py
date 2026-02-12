import ipaddress
import threading
import time as _time
from datetime import datetime, timezone
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
    """Remove a token from the in-memory verification cache.

    Call this when a token is deleted, disabled, or modified.
    For Redis invalidation, use ``invalidate_token_cache_async``.
    """
    with _token_cache_lock:
        _token_cache.pop(token_hash, None)


async def invalidate_token_cache_async(token_hash: str, redis_client) -> None:
    """Remove a token from both in-memory and Redis caches."""
    invalidate_token_cache(token_hash)
    from control_plane.redis_client import delete_cached_token
    await delete_cached_token(redis_client, token_hash)


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
        self.roles = roles if roles is not None else ["admin"]  # Default to admin for backwards compat
        self.api_token_id = api_token_id  # DB primary key of the ApiToken

    def has_role(self, role: str) -> bool:
        """Check if token has a specific role."""
        return role in self.roles or self.is_super_admin

    def to_dict(self) -> dict:
        """Serialize to a dict for Redis cache storage."""
        return {
            "token_type": self.token_type,
            "agent_id": self.agent_id,
            "token_name": self.token_name,
            "tenant_id": self.tenant_id,
            "is_super_admin": self.is_super_admin,
            "roles": self.roles,
            "api_token_id": self.api_token_id,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "TokenInfo":
        """Deserialize from a dict (Redis cache)."""
        return cls(
            token_type=d["token_type"],
            agent_id=d.get("agent_id"),
            token_name=d.get("token_name", ""),
            tenant_id=d.get("tenant_id"),
            is_super_admin=d.get("is_super_admin", False),
            roles=d.get("roles"),
            api_token_id=d.get("api_token_id"),
        )


async def verify_token(
    request: Request,
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db)
) -> TokenInfo:
    """Verify token and return token info with type and permissions.

    Lookup order:
    1. Redis cache (shared across workers) — fastest
    2. In-memory cache (per-worker fallback when Redis unavailable)
    3. DB lookup — populates both caches on miss

    ``last_used_at`` is only flushed to the DB when the previous
    write was more than 10 minutes ago.
    """
    if not credentials:
        raise HTTPException(status_code=401, detail="Not authenticated")

    token = credentials.credentials
    token_hash_value = hash_token(token)
    now = _time.monotonic()

    # --- Redis cache lookup ---
    app = getattr(request, "app", None)
    state = getattr(app, "state", None) if app else None
    redis_client = getattr(state, "redis", None) if state else None
    from control_plane.redis_client import get_cached_token_info, cache_token_info

    redis_hit = await get_cached_token_info(redis_client, token_hash_value)
    if redis_hit is not None:
        info = TokenInfo.from_dict(redis_hit)
        # Lazily update last_used_at if stale
        with _token_cache_lock:
            cached = _token_cache.get(token_hash_value)
        last_write = cached[2] if cached else 0
        if now - last_write >= _LAST_USED_WRITE_INTERVAL:
            db.execute(
                ApiToken.__table__.update()
                .where(ApiToken.token_hash == token_hash_value)
                .values(last_used_at=datetime.now(timezone.utc))
            )
            db.commit()
            with _token_cache_lock:
                _token_cache[token_hash_value] = (info, now, now)
        elif cached is None:
            with _token_cache_lock:
                _token_cache[token_hash_value] = (info, now, last_write)
        return info

    # --- In-memory cache lookup (fallback when Redis is None) ---
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
                    .values(last_used_at=datetime.now(timezone.utc))
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
        # Check expiry (handle naive datetimes from legacy DB entries)
        token_exp = db_token.expires_at
        if token_exp and token_exp.tzinfo is None:
            token_exp = token_exp.replace(tzinfo=timezone.utc)
        if token_exp and token_exp < datetime.now(timezone.utc):
            raise HTTPException(status_code=403, detail="Token expired")

        # Update last used timestamp
        db_token.last_used_at = datetime.now(timezone.utc)
        db.commit()

        # For agent tokens, get tenant_id from the agent
        tenant_id = db_token.tenant_id
        if db_token.token_type == "agent" and db_token.agent_id:
            agent = db.query(AgentState).filter(AgentState.agent_id == db_token.agent_id).first()
            if agent:
                tenant_id = agent.tenant_id

        # Parse roles (comma-separated string to list)
        # Empty string = no roles; None = backwards-compat default to admin
        if db_token.roles is not None:
            roles = [r for r in db_token.roles.split(",") if r]
        else:
            roles = ["admin"]

        info = TokenInfo(
            token_type=db_token.token_type,
            agent_id=db_token.agent_id,
            token_name=db_token.name,
            tenant_id=tenant_id,
            is_super_admin=db_token.is_super_admin or False,
            roles=roles,
            api_token_id=db_token.id,
        )

        # Populate in-memory cache
        with _token_cache_lock:
            _token_cache[token_hash_value] = (info, now, now)

        # Populate Redis cache (non-blocking, failure is safe)
        await cache_token_info(redis_client, token_hash_value, info.to_dict())

        return info

    raise HTTPException(status_code=403, detail="Invalid token")


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
