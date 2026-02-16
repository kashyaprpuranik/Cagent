import ipaddress
import logging
from datetime import datetime, timezone
from typing import Optional, List

from fastapi import HTTPException, Depends, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session

from control_plane.database import get_db
from control_plane.models import ApiToken, AgentState, TenantIpAcl
from control_plane.crypto import hash_token
from control_plane.config import TRUSTED_PROXY_COUNT
from control_plane.cache import LayeredCache, token_cache, last_used_writer

logger = logging.getLogger(__name__)

security = HTTPBearer(auto_error=False)

# ---------------------------------------------------------------------------
# IP ACL cache — avoids a DB query on every admin request.
# Uses LayeredCache: memory (60s) -> Redis (300s) -> DB loader.
# ---------------------------------------------------------------------------
ip_acl_cache = LayeredCache("ip_acl", memory_ttl=60, redis_ttl=300)


async def invalidate_token_cache_async(token_hash: str, redis_client) -> None:
    """Remove a token from both in-memory and Redis caches."""
    await token_cache.invalidate(token_hash, redis_client)
    last_used_writer.remove(token_hash)


def clear_token_cache() -> None:
    """Remove all entries — useful in tests."""
    token_cache.clear()
    last_used_writer.clear()


def _get_redis_client(request: Request):
    """Extract the Redis client from the request's app state, or None."""
    app = getattr(request, "app", None)
    state = getattr(app, "state", None) if app else None
    return getattr(state, "redis", None) if state else None


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

    Lookup order (via LayeredCache):
    1. In-memory cache (per-worker, 60 s TTL)
    2. Redis cache (shared across workers, 60 s TTL)
    3. DB lookup — populates both caches on miss

    ``last_used_at`` is flushed to DB at most once per 10 minutes
    (via ThrottledWriter).
    """
    if not credentials:
        raise HTTPException(status_code=401, detail="Not authenticated")

    token = credentials.credentials
    token_hash_value = hash_token(token)
    redis_client = _get_redis_client(request)

    info_dict = await token_cache.get(
        token_hash_value, redis_client,
        loader=lambda: _load_token_from_db(db, token_hash_value)
    )
    info = TokenInfo.from_dict(info_dict)

    # Throttled last_used_at update — once per 10 minutes per token
    if last_used_writer.should_write(token_hash_value):
        db.execute(
            ApiToken.__table__.update()
            .where(ApiToken.token_hash == token_hash_value)
            .values(last_used_at=datetime.now(timezone.utc))
        )
        db.commit()

    return info


def _load_token_from_db(db: Session, token_hash_value: str) -> dict:
    """Cache-miss loader: look up token in DB and return serializable dict.

    Raises HTTPException(403) for invalid or expired tokens.
    Writes ``last_used_at`` on first load and records the write in
    the throttled writer so it isn't repeated for 10 minutes.
    """
    db_token = db.query(ApiToken).filter(
        ApiToken.token_hash == token_hash_value,
        ApiToken.enabled == True
    ).first()

    if not db_token:
        raise HTTPException(status_code=403, detail="Invalid token")

    # Check expiry (handle naive datetimes from legacy DB entries)
    token_exp = db_token.expires_at
    if token_exp and token_exp.tzinfo is None:
        token_exp = token_exp.replace(tzinfo=timezone.utc)
    if token_exp and token_exp < datetime.now(timezone.utc):
        raise HTTPException(status_code=403, detail="Token expired")

    # Update last used timestamp (first access after cache miss)
    db_token.last_used_at = datetime.now(timezone.utc)
    db.commit()
    last_used_writer.mark_written(token_hash_value)

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

    return TokenInfo(
        token_type=db_token.token_type,
        agent_id=db_token.agent_id,
        token_name=db_token.name,
        tenant_id=tenant_id,
        is_super_admin=db_token.is_super_admin or False,
        roles=roles,
        api_token_id=db_token.id,
    ).to_dict()


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
    """Get client IP address.

    When TRUSTED_PROXY_COUNT > 0, extracts the real client IP from the
    X-Forwarded-For header (Nth-from-right entry, where N = proxy count).
    When 0 (default), uses the TCP peer address — safe against header spoofing.
    """
    if TRUSTED_PROXY_COUNT > 0:
        xff = request.headers.get("x-forwarded-for", "")
        if xff:
            parts = [p.strip() for p in xff.split(",") if p.strip()]
            # Nth-from-right: with 1 proxy, take the last entry (added by the proxy)
            idx = max(0, len(parts) - TRUSTED_PROXY_COUNT)
            return parts[idx]
    # Default: TCP peer address (no proxy trust)
    if request.client and request.client.host:
        return request.client.host
    return "127.0.0.1"


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

    # Get enabled IP ACLs for this tenant (LayeredCache: memory -> Redis -> DB)
    redis_client = _get_redis_client(request)
    cidrs = await ip_acl_cache.get(
        str(token_info.tenant_id),
        redis_client,
        loader=lambda: [
            acl.cidr for acl in db.query(TenantIpAcl).filter(
                TenantIpAcl.tenant_id == token_info.tenant_id,
                TenantIpAcl.enabled == True
            ).all()
        ]
    )

    # No ACLs configured = allow all (backwards compatible)
    if not cidrs:
        return token_info

    # Get client IP
    client_ip = get_client_ip(request)

    # Check if IP matches any allowed CIDR
    for cidr in cidrs:
        if validate_ip_in_cidr(client_ip, cidr):
            return token_info

    # IP not in any allowed range — deny.
    # TODO: Log IP ACL denials to a proper audit log (append-only / external),
    # not the transactional audit trail table.

    logger.warning(f"IP ACL denied: {client_ip} not in allowed range for tenant {token_info.tenant_id}")
    raise HTTPException(
        status_code=403,
        detail="Access denied: your IP address is not in the allowed range for this tenant"
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
