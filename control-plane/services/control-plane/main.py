"""
AI Devbox Control Plane - Backend API
FastAPI application for managing the secure AI devbox
"""

import os
import json
import logging
import hashlib
import secrets
import asyncio
import uuid
import ipaddress
from datetime import datetime, timedelta
from typing import Optional, List
from contextlib import asynccontextmanager

from cryptography.fernet import Fernet
from fastapi import FastAPI, HTTPException, Depends, Query, Request, Response, WebSocket, WebSocketDisconnect
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from starlette.responses import RedirectResponse
from starlette.websockets import WebSocketState
from pydantic import BaseModel
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Text, Boolean, ForeignKey, UniqueConstraint, JSON
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session, relationship, joinedload
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# =============================================================================
# Database Models
# =============================================================================

DATABASE_URL = os.environ.get('DATABASE_URL', 'sqlite:///./control_plane.db')
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False} if 'sqlite' in DATABASE_URL else {})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Sentinel tenant for super admin/system actions
SYSTEM_TENANT_SLUG = "__system__"
Base = declarative_base()


class Tenant(Base):
    """Multi-tenancy: isolated tenant workspaces."""
    __tablename__ = "tenants"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), unique=True, index=True)
    slug = Column(String(50), unique=True, index=True)  # URL-safe identifier
    created_at = Column(DateTime, default=datetime.utcnow)
    deleted_at = Column(DateTime, nullable=True, index=True)  # Soft delete
    settings = Column(Text, nullable=True)  # JSON for tenant-specific settings

    # Relationships
    agents = relationship("AgentState", back_populates="tenant")
    tokens = relationship("ApiToken", back_populates="tenant")
    ip_acls = relationship("TenantIpAcl", back_populates="tenant", cascade="all, delete-orphan")


class TenantIpAcl(Base):
    """IP ACL entries scoped to tenant for control plane access."""
    __tablename__ = "tenant_ip_acls"

    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(Integer, ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    cidr = Column(String(50), nullable=False)  # CIDR notation: "10.0.0.0/8" or "192.168.1.1/32"
    description = Column(String(500))
    enabled = Column(Boolean, default=True, index=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    created_by = Column(String(100))
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationship
    tenant = relationship("Tenant", back_populates="ip_acls")

    __table_args__ = (
        UniqueConstraint('tenant_id', 'cidr', name='uq_tenant_ip_acl'),
    )


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    event_type = Column(String(50), index=True)
    user = Column(String(100), index=True)
    container_id = Column(String(100))
    action = Column(String(200))
    details = Column(Text)
    severity = Column(String(20), index=True)
    # Tenant context - uses __system__ tenant (slug="__system__") for super admin actions
    tenant_id = Column(Integer, ForeignKey("tenants.id"), nullable=False, index=True)


class DomainPolicy(Base):
    """Unified domain policy: allowlist + paths + rate limits + egress limits + credentials."""
    __tablename__ = "domain_policies"

    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(Integer, ForeignKey("tenants.id"), nullable=False, index=True)
    domain = Column(String(200), nullable=False, index=True)  # e.g., "api.openai.com", "*.github.com"
    alias = Column(String(50))  # e.g., "openai" -> openai.devbox.local
    description = Column(String(500))
    enabled = Column(Boolean, default=True, index=True)
    agent_id = Column(String(100), nullable=True, index=True)  # NULL = tenant-global

    # Path restrictions (JSON array of patterns, empty = all paths allowed)
    allowed_paths = Column(JSON, default=list)  # ["/v1/chat/*", "/v1/models"]

    # Rate limiting (NULL = use defaults)
    requests_per_minute = Column(Integer)
    burst_size = Column(Integer)

    # Egress limiting (NULL = use defaults)
    bytes_per_hour = Column(Integer)

    # Credential injection (all NULL = no credential)
    credential_header = Column(String(100))  # e.g., "Authorization", "x-api-key"
    credential_format = Column(String(100))  # e.g., "Bearer {value}", "{value}"
    credential_value_encrypted = Column(Text)  # Fernet-encrypted secret
    credential_rotated_at = Column(DateTime)

    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    __table_args__ = (
        # Unique constraint: one policy per domain per agent per tenant
        UniqueConstraint('domain', 'agent_id', 'tenant_id', name='uq_domain_policy_tenant'),
    )


class AgentState(Base):
    """Stores agent status (from heartbeats) and pending commands."""
    __tablename__ = "agent_state"

    id = Column(Integer, primary_key=True, index=True)
    agent_id = Column(String(100), unique=True, index=True, default="default")
    # Multi-tenancy - every agent belongs to exactly one tenant
    tenant_id = Column(Integer, ForeignKey("tenants.id"), nullable=False, index=True)
    tenant = relationship("Tenant", back_populates="agents")
    # Soft delete
    deleted_at = Column(DateTime, nullable=True, index=True)
    # Approval status
    approved = Column(Boolean, default=False)
    approved_at = Column(DateTime)
    approved_by = Column(String(100))
    # Status from heartbeat
    status = Column(String(20), default="unknown")  # running, stopped, unknown
    container_id = Column(String(100))
    uptime_seconds = Column(Integer)
    cpu_percent = Column(Integer)  # Stored as int (e.g., 25 for 25%)
    memory_mb = Column(Integer)
    memory_limit_mb = Column(Integer)
    last_heartbeat = Column(DateTime)
    # Pending command for agent to pick up
    pending_command = Column(String(50))  # wipe, restart, stop, start, None
    pending_command_args = Column(Text)  # JSON args
    pending_command_at = Column(DateTime)
    # Last command result
    last_command = Column(String(50))
    last_command_result = Column(String(20))  # success, failed
    last_command_message = Column(Text)
    last_command_at = Column(DateTime)
    # STCP configuration for P2P SSH tunneling
    stcp_secret_key = Column(String(256), nullable=True)  # Encrypted STCP secret


class TerminalSession(Base):
    """Audit log for terminal sessions."""
    __tablename__ = "terminal_sessions"

    id = Column(Integer, primary_key=True, index=True)
    session_id = Column(String(36), unique=True, index=True)  # UUID
    agent_id = Column(String(100), index=True)
    user = Column(String(100), index=True)  # Token name
    tenant_id = Column(Integer, ForeignKey("tenants.id"), nullable=True)
    started_at = Column(DateTime, default=datetime.utcnow)
    ended_at = Column(DateTime, nullable=True)
    duration_seconds = Column(Integer, nullable=True)
    bytes_sent = Column(Integer, default=0)
    bytes_received = Column(Integer, default=0)
    client_ip = Column(String(45))  # IPv4 or IPv6


class ApiToken(Base):
    """API tokens for authentication with type-based permissions."""
    __tablename__ = "api_tokens"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), unique=True, index=True)
    token_hash = Column(String(64), unique=True, index=True)  # SHA-256 hash
    token_type = Column(String(20))  # "admin" or "agent"
    agent_id = Column(String(100), nullable=True)  # Required for agent tokens
    # Multi-tenancy
    tenant_id = Column(Integer, ForeignKey("tenants.id"), nullable=True, index=True)
    tenant = relationship("Tenant", back_populates="tokens")
    is_super_admin = Column(Boolean, default=False)  # Can access all tenants
    # RBAC: comma-separated roles (e.g., "admin,developer")
    # Roles: admin (full access), developer (read + terminal access)
    roles = Column(String(200), default="admin")
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=True)
    last_used_at = Column(DateTime, nullable=True)
    enabled = Column(Boolean, default=True)


# Create tables
Base.metadata.create_all(bind=engine)


# =============================================================================
# Pydantic Models
# =============================================================================

class AuditLogResponse(BaseModel):
    id: int
    timestamp: datetime
    event_type: str
    user: str
    container_id: Optional[str]
    action: str
    details: Optional[str]
    severity: str
    
    class Config:
        from_attributes = True


class DataPlaneResponse(BaseModel):
    """Summary of a data plane (agent) for listing."""
    agent_id: str
    status: str
    online: bool
    approved: bool
    tenant_id: Optional[int]
    last_heartbeat: Optional[datetime]

    class Config:
        from_attributes = True


class ApiTokenCreate(BaseModel):
    """Request to create a new API token."""
    name: str
    token_type: str  # "admin" or "agent"
    agent_id: Optional[str] = None  # Required if token_type is "agent"
    tenant_id: Optional[int] = None  # Required for admin tokens (not super_admin)
    is_super_admin: bool = False  # Super admin can access all tenants
    roles: Optional[str] = "admin"  # Comma-separated roles: "admin", "developer", "admin,developer"
    expires_in_days: Optional[int] = None  # Optional expiry


class ApiTokenResponse(BaseModel):
    """API token info (without the actual token value)."""
    id: int
    name: str
    token_type: str
    agent_id: Optional[str]
    tenant_id: Optional[int]
    is_super_admin: bool
    roles: Optional[str] = "admin"  # Comma-separated roles
    created_at: datetime
    expires_at: Optional[datetime]
    last_used_at: Optional[datetime]
    enabled: bool

    class Config:
        from_attributes = True


class ApiTokenCreatedResponse(BaseModel):
    """Response when creating a token - includes the token value (shown once)."""
    id: int
    name: str
    token_type: str
    agent_id: Optional[str]
    tenant_id: Optional[int]
    is_super_admin: bool
    roles: str  # Comma-separated roles
    token: str  # The actual token - only shown once!
    expires_at: Optional[datetime]


class TenantCreate(BaseModel):
    """Request to create a new tenant."""
    name: str
    slug: str  # URL-safe identifier


class TenantResponse(BaseModel):
    """Tenant info."""
    id: int
    name: str
    slug: str
    created_at: datetime
    agent_count: int = 0  # Computed field

    class Config:
        from_attributes = True


class TenantIpAclCreate(BaseModel):
    """Request to create a new IP ACL entry."""
    cidr: str  # e.g., "10.0.0.0/8", "192.168.1.0/24", "203.0.113.50/32"
    description: Optional[str] = None


class TenantIpAclUpdate(BaseModel):
    """Request to update an IP ACL entry."""
    description: Optional[str] = None
    enabled: Optional[bool] = None


class TenantIpAclResponse(BaseModel):
    """IP ACL entry response."""
    id: int
    tenant_id: int
    cidr: str
    description: Optional[str]
    enabled: bool
    created_at: datetime
    created_by: Optional[str]
    updated_at: datetime

    class Config:
        from_attributes = True


# =============================================================================
# Domain Policy Models (Unified)
# =============================================================================

class DomainPolicyCredential(BaseModel):
    """Credential configuration for a domain."""
    header: str = "Authorization"  # Header name
    format: str = "Bearer {value}"  # Format string
    value: str  # Plain text value (encrypted at rest)


class DomainPolicyCreate(BaseModel):
    """Create a new domain policy."""
    domain: str  # e.g., "api.openai.com", "*.github.com"
    alias: Optional[str] = None  # e.g., "openai" -> openai.devbox.local
    description: Optional[str] = None
    agent_id: Optional[str] = None  # NULL = global

    # Path restrictions (empty = all paths allowed)
    allowed_paths: Optional[List[str]] = None  # ["/v1/chat/*", "/v1/models"]

    # Rate limiting
    requests_per_minute: Optional[int] = None
    burst_size: Optional[int] = None

    # Egress limiting
    bytes_per_hour: Optional[int] = None

    # Credential (optional)
    credential: Optional[DomainPolicyCredential] = None


class DomainPolicyUpdate(BaseModel):
    """Update an existing domain policy."""
    alias: Optional[str] = None
    description: Optional[str] = None
    enabled: Optional[bool] = None
    allowed_paths: Optional[List[str]] = None
    requests_per_minute: Optional[int] = None
    burst_size: Optional[int] = None
    bytes_per_hour: Optional[int] = None
    credential: Optional[DomainPolicyCredential] = None
    clear_credential: Optional[bool] = None  # Set to true to remove credential


class DomainPolicyResponse(BaseModel):
    """Domain policy response (credential value hidden)."""
    id: int
    tenant_id: Optional[int]
    domain: str
    alias: Optional[str]
    description: Optional[str]
    enabled: bool
    agent_id: Optional[str]
    allowed_paths: List[str]
    requests_per_minute: Optional[int]
    burst_size: Optional[int]
    bytes_per_hour: Optional[int]
    has_credential: bool  # True if credential configured
    credential_header: Optional[str]
    credential_format: Optional[str]
    credential_rotated_at: Optional[datetime]
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class AgentHeartbeat(BaseModel):
    """Heartbeat sent by agent-manager to control plane."""
    agent_id: str = "default"
    status: str  # running, stopped, not_found
    container_id: Optional[str] = None
    uptime_seconds: Optional[int] = None
    cpu_percent: Optional[float] = None
    memory_mb: Optional[float] = None
    memory_limit_mb: Optional[float] = None
    # Report result of last command execution
    last_command: Optional[str] = None
    last_command_result: Optional[str] = None  # success, failed
    last_command_message: Optional[str] = None


class AgentHeartbeatResponse(BaseModel):
    """Response to heartbeat, may include a pending command."""
    ack: bool = True
    command: Optional[str] = None  # wipe, restart, stop, start
    command_args: Optional[dict] = None  # e.g., {"wipe_workspace": true}


class AgentStatusResponse(BaseModel):
    """Agent status for admin UI."""
    agent_id: str
    status: str
    container_id: Optional[str]
    uptime_seconds: Optional[int]
    cpu_percent: Optional[int]
    memory_mb: Optional[int]
    memory_limit_mb: Optional[int]
    last_heartbeat: Optional[datetime]
    pending_command: Optional[str]
    last_command: Optional[str]
    last_command_result: Optional[str]
    last_command_at: Optional[datetime]
    online: bool  # True if heartbeat received within last 60s

    class Config:
        from_attributes = True


class AgentCommandRequest(BaseModel):
    """Request to queue a command for the agent."""
    wipe_workspace: bool = False  # Only used for wipe command


class STCPSecretResponse(BaseModel):
    """Response when generating STCP secret."""
    agent_id: str
    secret_key: str  # Only returned once on generation
    message: str


class STCPVisitorConfig(BaseModel):
    """Configuration for STCP visitor (used to connect to agent SSH)."""
    server_addr: str
    server_port: int
    proxy_name: str  # "{agent_id}-ssh"
    secret_key: str


class TerminalSessionResponse(BaseModel):
    """Terminal session info for audit logs."""
    session_id: str
    agent_id: str
    user: str
    started_at: datetime
    ended_at: Optional[datetime] = None
    duration_seconds: Optional[int] = None
    bytes_sent: int
    bytes_received: int

    class Config:
        from_attributes = True


class LogEntry(BaseModel):
    """Single log entry from data plane."""
    timestamp: Optional[datetime] = None  # Defaults to server time if not provided
    message: str
    source: str  # envoy, agent, coredns, gvisor
    level: Optional[str] = "info"
    extra: Optional[dict] = None  # Additional fields passed through


class LogBatch(BaseModel):
    """Batch of log entries for ingestion."""
    logs: List[LogEntry]


# =============================================================================
# Dependencies
# =============================================================================

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# Encryption key for secrets - generate with: Fernet.generate_key()
# In production, load from secure storage (e.g., environment variable, mounted secret)
ENCRYPTION_KEY = os.environ.get('ENCRYPTION_KEY', Fernet.generate_key().decode())
_fernet = Fernet(ENCRYPTION_KEY.encode() if isinstance(ENCRYPTION_KEY, str) else ENCRYPTION_KEY)


def encrypt_secret(value: str) -> str:
    """Encrypt a secret value"""
    return _fernet.encrypt(value.encode()).decode()


def decrypt_secret(encrypted_value: str) -> str:
    """Decrypt a secret value"""
    return _fernet.decrypt(encrypted_value.encode()).decode()


security = HTTPBearer(auto_error=False)


def hash_token(token: str) -> str:
    """Hash a token using SHA-256 for secure storage."""
    return hashlib.sha256(token.encode()).hexdigest()


def generate_token() -> str:
    """Generate a secure random token."""
    return secrets.token_urlsafe(32)


class TokenInfo:
    """Information about the authenticated token."""
    def __init__(
        self,
        token_type: str,
        agent_id: Optional[str] = None,
        token_name: str = "",
        tenant_id: Optional[int] = None,
        is_super_admin: bool = False,
        roles: List[str] = None
    ):
        self.token_type = token_type  # "admin" or "agent"
        self.agent_id = agent_id  # For agent tokens, the associated agent_id
        self.token_name = token_name
        self.tenant_id = tenant_id  # Tenant this token belongs to
        self.is_super_admin = is_super_admin  # Can access all tenants
        self.roles = roles or ["admin"]  # Default to admin for backwards compat

    def has_role(self, role: str) -> bool:
        """Check if token has a specific role."""
        return role in self.roles or self.is_super_admin


async def verify_token(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db)
) -> TokenInfo:
    """Verify token and return token info with type and permissions.

    Tokens are looked up by SHA-256 hash in the database.
    Falls back to legacy env var tokens for backwards compatibility.
    """
    if not credentials:
        raise HTTPException(status_code=401, detail="Not authenticated")

    token = credentials.credentials
    token_hash = hash_token(token)

    # Look up token in database
    db_token = db.query(ApiToken).filter(
        ApiToken.token_hash == token_hash,
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

        return TokenInfo(
            token_type=db_token.token_type,
            agent_id=db_token.agent_id,
            token_name=db_token.name,
            tenant_id=tenant_id,
            is_super_admin=db_token.is_super_admin or False,
            roles=roles
        )

    # Fallback to legacy env var tokens (treated as super admin for backwards compat)
    legacy_tokens = os.environ.get('API_TOKENS', 'dev-token').split(',')
    if token in legacy_tokens:
        return TokenInfo(token_type="admin", token_name="legacy", is_super_admin=True, roles=["admin", "developer"])

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


def verify_agent_access(token_info: TokenInfo, agent_id: str, db: Session):
    """Verify that a token has access to the specified agent."""
    if token_info.is_super_admin:
        return  # Super admin can access any agent

    if token_info.token_type == "admin":
        # Admin can only access agents in their tenant
        if token_info.tenant_id:
            agent = db.query(AgentState).filter(AgentState.agent_id == agent_id).first()
            if agent and agent.tenant_id != token_info.tenant_id:
                raise HTTPException(
                    status_code=403,
                    detail=f"Agent '{agent_id}' belongs to a different tenant"
                )
        return

    # Agent tokens can only access their own agent
    if token_info.agent_id != agent_id:
        raise HTTPException(
            status_code=403,
            detail=f"Token does not have access to agent '{agent_id}'"
        )


def get_tenant_agent_ids(db: Session, tenant_id: int) -> List[str]:
    """Get all agent IDs belonging to a tenant."""
    agents = db.query(AgentState.agent_id).filter(AgentState.tenant_id == tenant_id).all()
    return [a.agent_id for a in agents]


def get_system_tenant_id(db: Session) -> int:
    """Get the __system__ tenant ID (sentinel for super admin/system actions).

    This tenant is used for audit logs when the action is performed by:
    - Super admins (who have no tenant restriction)
    - System/seed scripts
    - Agent heartbeats (before tenant context is established)
    """
    system_tenant = db.query(Tenant).filter(
        Tenant.slug == SYSTEM_TENANT_SLUG,
        Tenant.deleted_at.is_(None)
    ).first()
    if not system_tenant:
        # Create if missing (shouldn't happen after seeding)
        system_tenant = Tenant(name="System", slug=SYSTEM_TENANT_SLUG)
        db.add(system_tenant)
        db.flush()
    return system_tenant.id


def get_audit_tenant_id(token_info: TokenInfo, db: Session, agent_state: AgentState = None) -> int:
    """Get the tenant ID to use for audit logging.

    Priority:
    1. If agent_state is provided, use its tenant_id
    2. If token has a tenant_id, use it
    3. Otherwise use __system__ tenant (for super admins)
    """
    if agent_state and agent_state.tenant_id:
        return agent_state.tenant_id
    if token_info.tenant_id:
        return token_info.tenant_id
    return get_system_tenant_id(db)


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

    # IP not in any allowed range - deny and log
    log = AuditLog(
        event_type="ip_acl_denied",
        user=token_info.token_name,
        action=f"Access denied: IP {client_ip} not in tenant's allowed ranges",
        details=json.dumps({
            "client_ip": client_ip,
            "tenant_id": token_info.tenant_id,
            "allowed_cidrs": [acl.cidr for acl in ip_acls]
        }),
        severity="WARNING",
        tenant_id=token_info.tenant_id  # Must have tenant_id since IP ACL check only applies to tenant admins
    )
    db.add(log)
    db.commit()

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


# =============================================================================
# Application
# =============================================================================

# -----------------------------------------------------------------------------
# Rate Limiting Setup (Redis-backed for horizontal scaling)
# -----------------------------------------------------------------------------
REDIS_URL = os.environ.get('REDIS_URL', '')


def get_token_identifier(request: Request) -> str:
    """Rate limit by API token (not IP) for meaningful limiting."""
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        # Use first 16 chars of token as identifier (enough to be unique)
        return f"token:{auth[7:23]}"
    # Fall back to IP for unauthenticated requests
    return f"ip:{get_remote_address(request)}"


# Initialize limiter - use Redis if configured, otherwise in-memory
# In-memory is fine for single-instance deploys and tests
limiter = Limiter(
    key_func=get_token_identifier,
    storage_uri=REDIS_URL if REDIS_URL else "memory://",
    strategy="fixed-window",  # or "moving-window" for stricter limiting
)


def seed_tokens(db: Session):
    """Seed default data for development/testing.

    Creates:
    - Default tenant with tokens, domain policies, and IP ACLs
    - Acme Corp tenant (for testing multi-tenancy)
    - super-admin-token: Super admin (cross-tenant access) - direct DB insert
    - Other tokens, domain policies, IP ACLs with audit logs

    These are only created if they don't already exist. The actual token
    values are deterministic for easy testing but should be replaced in production.
    """
    # Check if we should seed (controlled by env var)
    if os.environ.get('SEED_TOKENS', 'true').lower() != 'true':
        return

    # Create or get __system__ tenant (sentinel for super admin/system actions)
    system_tenant = db.query(Tenant).filter(
        Tenant.slug == "__system__",
        Tenant.deleted_at.is_(None)
    ).first()

    if not system_tenant:
        system_tenant = Tenant(name="System", slug="__system__")
        db.add(system_tenant)
        db.flush()
        logger.info("Seeded __system__ tenant (sentinel for super admin actions)")

    system_tenant_id = system_tenant.id

    def audit_log(event_type: str, action: str, details: dict, container_id: str = None, tenant_id: int = None):
        """Create audit log entry for seeded data."""
        log = AuditLog(
            event_type=event_type,
            user="seed-script",
            container_id=container_id,
            action=action,
            details=json.dumps(details),
            severity="INFO",
            tenant_id=tenant_id or system_tenant_id  # Default to __system__ tenant
        )
        db.add(log)

    # Create or get default tenant
    default_tenant = db.query(Tenant).filter(
        Tenant.slug == "default",
        Tenant.deleted_at.is_(None)
    ).first()

    if not default_tenant:
        default_tenant = Tenant(name="Default", slug="default")
        db.add(default_tenant)
        db.flush()  # Get the ID
        audit_log("tenant_created", f"Seeded tenant 'Default' (slug: default)", {"id": default_tenant.id, "name": "Default", "slug": "default"})
        logger.info("Seeded default tenant")

    default_tenant_id = default_tenant.id

    # Create or get Acme Corp tenant (for testing multi-tenancy)
    acme_tenant = db.query(Tenant).filter(
        Tenant.slug == "acme",
        Tenant.deleted_at.is_(None)
    ).first()

    if not acme_tenant:
        acme_tenant = Tenant(name="Acme Corp", slug="acme")
        db.add(acme_tenant)
        db.flush()
        audit_log("tenant_created", f"Seeded tenant 'Acme Corp' (slug: acme)", {"id": acme_tenant.id, "name": "Acme Corp", "slug": "acme"})
        logger.info("Seeded Acme Corp tenant")

    acme_tenant_id = acme_tenant.id

    # Well-known test tokens (deterministic for testing)
    # Super admin token uses direct DB (bootstrap - no audit log needed)
    test_tokens = [
        {
            "name": "super-admin-token",
            "raw_token": "super-admin-test-token-do-not-use-in-production",
            "token_type": "admin",
            "roles": "admin",
            "is_super_admin": True,
            "tenant_id": None,  # Super admin has no tenant restriction
        },
        {
            "name": "admin-token",
            "raw_token": "admin-test-token-do-not-use-in-production",
            "token_type": "admin",
            "roles": "admin",
            "is_super_admin": False,
            "tenant_id": default_tenant_id,  # Scoped to default tenant
        },
        {
            "name": "dev-token",
            "raw_token": "dev-test-token-do-not-use-in-production",
            "token_type": "admin",
            "roles": "developer",
            "is_super_admin": False,
            "tenant_id": default_tenant_id,  # Scoped to default tenant
        },
        {
            "name": "acme-admin-token",
            "raw_token": "acme-admin-test-token-do-not-use-in-production",
            "token_type": "admin",
            "roles": "admin",
            "is_super_admin": False,
            "tenant_id": acme_tenant_id,  # Scoped to Acme Corp tenant
        },
    ]

    for token_def in test_tokens:
        existing = db.query(ApiToken).filter(ApiToken.name == token_def["name"]).first()
        if not existing:
            db_token = ApiToken(
                name=token_def["name"],
                token_hash=hash_token(token_def["raw_token"]),
                token_type=token_def["token_type"],
                roles=token_def["roles"],
                is_super_admin=token_def["is_super_admin"],
                tenant_id=token_def["tenant_id"],
            )
            db.add(db_token)
            db.flush()
            # Audit log for non-super-admin tokens
            if not token_def["is_super_admin"]:
                audit_log(
                    "token_created",
                    f"Seeded token '{token_def['name']}' (roles: {token_def['roles']})",
                    {"id": db_token.id, "name": token_def["name"], "roles": token_def["roles"], "tenant_id": token_def["tenant_id"]}
                )
            logger.info(f"Seeded token: {token_def['name']} (roles: {token_def['roles']}, tenant: {token_def['tenant_id']})")

    # Seed sample domain policies for default tenant
    default_policies = [
        {"domain": "api.openai.com", "alias": "openai", "description": "OpenAI API"},
        {"domain": "api.anthropic.com", "alias": "anthropic", "description": "Anthropic Claude API"},
        {"domain": "api.github.com", "alias": "github", "description": "GitHub API"},
        {"domain": "pypi.org", "description": "Python Package Index"},
        {"domain": "files.pythonhosted.org", "description": "Python package downloads"},
        {"domain": "registry.npmjs.org", "description": "NPM Registry"},
        {"domain": "*.githubusercontent.com", "description": "GitHub raw content"},
    ]

    for policy_def in default_policies:
        existing = db.query(DomainPolicy).filter(
            DomainPolicy.domain == policy_def["domain"],
            DomainPolicy.tenant_id == default_tenant_id,
            DomainPolicy.agent_id.is_(None)
        ).first()
        if not existing:
            policy = DomainPolicy(
                tenant_id=default_tenant_id,
                domain=policy_def["domain"],
                alias=policy_def.get("alias"),
                description=policy_def.get("description"),
                enabled=True,
            )
            db.add(policy)
            db.flush()
            audit_log(
                "domain_policy_created",
                f"Seeded domain policy '{policy_def['domain']}' for tenant default",
                {"id": policy.id, "domain": policy_def["domain"], "alias": policy_def.get("alias"), "tenant_id": default_tenant_id}
            )
            logger.info(f"Seeded domain policy: {policy_def['domain']} (tenant: default)")

    # Seed sample domain policies for Acme Corp tenant (different policies to differentiate)
    acme_policies = [
        {"domain": "api.openai.com", "alias": "openai", "description": "OpenAI API"},
        {"domain": "api.stripe.com", "alias": "stripe", "description": "Stripe Payments API"},
        {"domain": "api.twilio.com", "alias": "twilio", "description": "Twilio Communications API"},
    ]

    for policy_def in acme_policies:
        existing = db.query(DomainPolicy).filter(
            DomainPolicy.domain == policy_def["domain"],
            DomainPolicy.tenant_id == acme_tenant_id,
            DomainPolicy.agent_id.is_(None)
        ).first()
        if not existing:
            policy = DomainPolicy(
                tenant_id=acme_tenant_id,
                domain=policy_def["domain"],
                alias=policy_def.get("alias"),
                description=policy_def.get("description"),
                enabled=True,
            )
            db.add(policy)
            db.flush()
            audit_log(
                "domain_policy_created",
                f"Seeded domain policy '{policy_def['domain']}' for tenant acme",
                {"id": policy.id, "domain": policy_def["domain"], "alias": policy_def.get("alias"), "tenant_id": acme_tenant_id}
            )
            logger.info(f"Seeded domain policy: {policy_def['domain']} (tenant: acme)")

    # Seed IP ACLs with universal range (allow all IPs) for each tenant
    for tenant_id, tenant_name in [(default_tenant_id, "default"), (acme_tenant_id, "acme")]:
        existing_acl = db.query(TenantIpAcl).filter(
            TenantIpAcl.tenant_id == tenant_id,
            TenantIpAcl.cidr == "0.0.0.0/0"
        ).first()
        if not existing_acl:
            acl = TenantIpAcl(
                tenant_id=tenant_id,
                cidr="0.0.0.0/0",
                description="Allow all IPv4 addresses (development default)",
                enabled=True,
                created_by="seed-script"
            )
            db.add(acl)
            db.flush()
            audit_log(
                "ip_acl_created",
                f"Seeded IP ACL '0.0.0.0/0' for tenant {tenant_name}",
                {"id": acl.id, "cidr": "0.0.0.0/0", "tenant_id": tenant_id}
            )
            logger.info(f"Seeded IP ACL: 0.0.0.0/0 (tenant: {tenant_name})")

    db.commit()


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Starting AI Devbox Control Plane")
    if REDIS_URL:
        logger.info(f"Rate limiting enabled with Redis: {REDIS_URL}")
    else:
        logger.info("Rate limiting enabled with in-memory storage (single instance only)")

    # Seed default tokens for development/testing
    db = SessionLocal()
    try:
        seed_tokens(db)
    finally:
        db.close()

    yield
    logger.info("Shutting down")


app = FastAPI(
    title="AI Devbox Control Plane",
    description="Management API for Secure AI Devbox",
    version="1.0.0",
    lifespan=lifespan,
    openapi_url="/openapi.json",
    docs_url="/docs",
    redoc_url="/redoc"
)

# Register rate limiter with app
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure properly in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# =============================================================================
# Health & Info Endpoints
# =============================================================================

@app.get("/")
async def root():
    return RedirectResponse(url="/docs")


@app.get("/health")
async def health_check():
    return {"status": "healthy", "timestamp": datetime.utcnow().isoformat()}


@app.get("/api/v1/info")
async def get_info():
    return {
        "name": "AI Devbox Control Plane",
        "version": "1.0.0",
        "features": [
            "audit_logs",
            "allowlist_management",
            "secret_management",
            "container_monitoring",
            "usage_reporting"
        ]
    }


@app.get("/api/v1/auth/me")
async def get_current_user(
    token_info: TokenInfo = Depends(verify_token),
    db: Session = Depends(get_db)
):
    """Get current user info from token"""
    # Get tenant name if user has a tenant
    tenant_name = None
    tenant_slug = None
    if token_info.tenant_id:
        tenant = db.query(Tenant).filter(Tenant.id == token_info.tenant_id).first()
        if tenant:
            tenant_name = tenant.name
            tenant_slug = tenant.slug

    return {
        "token_type": token_info.token_type,
        "agent_id": token_info.agent_id,
        "tenant_id": token_info.tenant_id,
        "tenant_name": tenant_name,
        "tenant_slug": tenant_slug,
        "is_super_admin": token_info.is_super_admin,
        "roles": token_info.roles
    }


# =============================================================================
# OpenObserve Log Ingestion & Query
# =============================================================================

OPENOBSERVE_URL = os.environ.get('OPENOBSERVE_URL', 'http://openobserve:5080')
OPENOBSERVE_USER = os.environ.get('OPENOBSERVE_USER', 'admin@cagent.local')
OPENOBSERVE_PASSWORD = os.environ.get('OPENOBSERVE_PASSWORD', 'admin')


@app.post("/api/v1/logs/ingest")
@limiter.limit("100/minute")
async def ingest_logs(
    request: Request,
    batch: LogBatch,
    token_info: TokenInfo = Depends(verify_token),
    db: Session = Depends(get_db)
):
    """Ingest logs from data plane agents.

    Requires agent token. Injects trusted agent_id and tenant_id from database.
    This ensures data planes cannot spoof their identity in logs.
    """
    import httpx

    # Only agent tokens can ingest logs
    if token_info.token_type != "agent":
        raise HTTPException(
            status_code=403,
            detail="Only agent tokens can ingest logs"
        )

    if not token_info.agent_id:
        raise HTTPException(
            status_code=403,
            detail="Agent token must have agent_id"
        )

    # Get tenant_id from agent state (trusted source, not from request)
    agent = db.query(AgentState).filter(
        AgentState.agent_id == token_info.agent_id,
        AgentState.deleted_at.is_(None)
    ).first()

    if not agent:
        raise HTTPException(
            status_code=404,
            detail=f"Agent {token_info.agent_id} not found"
        )

    if not agent.approved:
        raise HTTPException(
            status_code=403,
            detail=f"Agent {token_info.agent_id} is not approved"
        )

    tenant_id = agent.tenant_id

    # Transform logs for OpenObserve, injecting trusted identity
    enriched_logs = []
    for log in batch.logs:
        entry = {
            "_timestamp": int((log.timestamp or datetime.utcnow()).timestamp() * 1_000_000),
            "message": log.message,
            "source": log.source,
            "level": log.level or "info",
            "agent_id": token_info.agent_id,  # Trusted, from verified token
            "tenant_id": tenant_id,            # Trusted, from database
        }
        if log.extra:
            # Filter out any attempt to override trusted fields
            safe_extra = {k: v for k, v in log.extra.items()
                         if k not in ("agent_id", "tenant_id", "_timestamp")}
            entry.update(safe_extra)
        enriched_logs.append(entry)

    # Forward to OpenObserve
    async with httpx.AsyncClient() as client:
        response = await client.post(
            f"{OPENOBSERVE_URL}/api/default/default/_json",
            json=enriched_logs,
            auth=(OPENOBSERVE_USER, OPENOBSERVE_PASSWORD),
            timeout=30.0
        )

        if response.status_code not in (200, 201):
            logger.error(f"OpenObserve ingestion failed: {response.status_code} {response.text}")
            raise HTTPException(
                status_code=502,
                detail=f"Failed to store logs: {response.text}"
            )

    return {"status": "ok", "count": len(enriched_logs)}


@app.get("/api/v1/logs/query")
@limiter.limit("30/minute")
async def query_agent_logs(
    request: Request,
    query: str = "",
    source: Optional[str] = None,
    agent_id: Optional[str] = None,
    tenant_id: Optional[int] = Query(default=None, description="Filter by tenant (super admin only)"),
    limit: int = Query(default=100, le=1000),
    start: Optional[str] = None,
    end: Optional[str] = None,
    token_info: TokenInfo = Depends(require_developer_role),
    db: Session = Depends(get_db)
):
    """Query agent logs from OpenObserve.

    Tenant filtering:
    - Super admins can query any tenant (optional tenant_id filter)
    - Tenant users can only query their tenant's logs
    - If agent_id specified, verifies user has access to that agent's tenant

    Args:
        query: Search text (full-text search in message field)
        source: Filter by source (envoy, agent, coredns, gvisor)
        agent_id: Filter by agent ID
        tenant_id: Filter by tenant (super admin only)
        limit: Max number of log lines to return (max 1000)
        start: Start time (RFC3339, e.g., 2024-01-01T00:00:00Z)
        end: End time (RFC3339)
    """
    import httpx

    # Determine effective tenant filter
    if token_info.is_super_admin:
        effective_tenant_id = tenant_id  # Optional filter for super admins
    else:
        # Non-super-admin MUST be scoped to their tenant
        if not token_info.tenant_id:
            raise HTTPException(status_code=403, detail="Token must be scoped to a tenant")
        effective_tenant_id = token_info.tenant_id

    # If agent_id specified, verify access to that agent's tenant
    if agent_id:
        agent = db.query(AgentState).filter(
            AgentState.agent_id == agent_id,
            AgentState.deleted_at.is_(None)
        ).first()

        if not agent:
            raise HTTPException(status_code=404, detail=f"Agent {agent_id} not found")

        # Non-super-admin must have access to agent's tenant
        if not token_info.is_super_admin and agent.tenant_id != token_info.tenant_id:
            raise HTTPException(status_code=403, detail=f"Access denied to agent {agent_id}")

    # Build SQL query for OpenObserve with SQL injection prevention
    conditions = []

    # Tenant filter (always applied for non-super-admins)
    if effective_tenant_id is not None:
        conditions.append(f"tenant_id = {int(effective_tenant_id)}")

    if query:
        # Escape single quotes to prevent SQL injection
        safe_query = query.replace("'", "''")
        conditions.append(f"message LIKE '%{safe_query}%'")
    if source:
        # Validate source is alphanumeric
        if not source.replace("_", "").replace("-", "").isalnum():
            raise HTTPException(status_code=400, detail="Invalid source parameter")
        conditions.append(f"source = '{source}'")
    if agent_id:
        # Validate agent_id is alphanumeric with hyphens/underscores
        if not agent_id.replace("_", "").replace("-", "").isalnum():
            raise HTTPException(status_code=400, detail="Invalid agent_id parameter")
        conditions.append(f"agent_id = '{agent_id}'")

    # Time range
    if not end:
        end_time = datetime.utcnow()
    else:
        end_time = datetime.fromisoformat(end.replace('Z', '+00:00'))

    if not start:
        start_time = end_time - timedelta(hours=1)
    else:
        start_time = datetime.fromisoformat(start.replace('Z', '+00:00'))

    # Convert to microseconds for OpenObserve
    start_us = int(start_time.timestamp() * 1_000_000)
    end_us = int(end_time.timestamp() * 1_000_000)

    where_clause = " AND ".join(conditions) if conditions else "1=1"
    sql = f"SELECT * FROM default WHERE {where_clause} ORDER BY _timestamp DESC LIMIT {limit}"

    async with httpx.AsyncClient() as client:
        response = await client.post(
            f"{OPENOBSERVE_URL}/api/default/_search",
            json={
                "query": {
                    "sql": sql,
                    "start_time": start_us,
                    "end_time": end_us,
                }
            },
            auth=(OPENOBSERVE_USER, OPENOBSERVE_PASSWORD),
            timeout=30.0
        )

        if response.status_code != 200:
            # Return 502 Bad Gateway for upstream errors - don't pass through status
            # (passing through 401 would make frontend think user token is invalid)
            raise HTTPException(
                status_code=502,
                detail=f"OpenObserve query failed (status {response.status_code}): {response.text}"
            )

        result = response.json()

        # Transform to consistent format for UI
        return {
            "status": "success",
            "data": {
                "resultType": "streams",
                "result": result.get("hits", [])
            }
        }


# =============================================================================
# Audit Log Endpoints
# =============================================================================

@app.get("/api/v1/audit-logs", response_model=List[AuditLogResponse])
async def get_audit_logs(
    db: Session = Depends(get_db),
    token_info: TokenInfo = Depends(require_admin_role),
    tenant_id: Optional[int] = Query(default=None, description="Filter by tenant (super admin only)"),
    event_type: Optional[str] = None,
    user: Optional[str] = None,
    severity: Optional[str] = None,
    container_id: Optional[str] = None,
    start_time: Optional[datetime] = None,
    end_time: Optional[datetime] = None,
    search: Optional[str] = None,
    limit: int = Query(default=100, le=1000),
    offset: int = 0
):
    """Search and retrieve audit logs (admin only).

    Super admins can filter by tenant_id, or see all logs if not specified.
    Tenant admins see only their tenant's logs.
    """
    query = db.query(AuditLog)

    # Apply tenant filtering
    if token_info.is_super_admin:
        # Super admin can optionally filter by tenant
        if tenant_id is not None:
            query = query.filter(AuditLog.tenant_id == tenant_id)
        # else: no filter, see all logs
    else:
        # Non-super-admin MUST be scoped to their tenant
        if not token_info.tenant_id:
            raise HTTPException(status_code=403, detail="Token must be scoped to a tenant")
        query = query.filter(AuditLog.tenant_id == token_info.tenant_id)

    if event_type:
        query = query.filter(AuditLog.event_type == event_type)
    if user:
        query = query.filter(AuditLog.user.contains(user))
    if severity:
        query = query.filter(AuditLog.severity == severity)
    if container_id:
        query = query.filter(AuditLog.container_id == container_id)
    if start_time:
        query = query.filter(AuditLog.timestamp >= start_time)
    if end_time:
        query = query.filter(AuditLog.timestamp <= end_time)
    if search:
        query = query.filter(
            AuditLog.action.contains(search) |
            AuditLog.details.contains(search)
        )

    return query.order_by(AuditLog.timestamp.desc()).offset(offset).limit(limit).all()


def match_domain(pattern: str, domain: str) -> bool:
    """Match domain against pattern (supports wildcard prefix)"""
    if not pattern:
        return False
    if pattern.startswith("*."):
        # Wildcard match: *.github.com matches api.github.com, raw.github.com
        suffix = pattern[1:]  # .github.com
        return domain.endswith(suffix) or domain == pattern[2:]
    return domain == pattern


# =============================================================================
# Domain Policy Endpoints (Unified)
# =============================================================================

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
        "has_credential": policy.credential_value_encrypted is not None,
        "credential_header": policy.credential_header,
        "credential_format": policy.credential_format,
        "credential_rotated_at": policy.credential_rotated_at,
        "created_at": policy.created_at,
        "updated_at": policy.updated_at,
    }


@app.get("/api/v1/domain-policies", response_model=List[DomainPolicyResponse])
async def list_domain_policies(
    db: Session = Depends(get_db),
    token_info: TokenInfo = Depends(require_admin_role),
    agent_id: Optional[str] = None,
    tenant_id: Optional[int] = None
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

    policies = query.order_by(DomainPolicy.domain).all()
    return [domain_policy_to_response(p) for p in policies]


@app.post("/api/v1/domain-policies", response_model=DomainPolicyResponse)
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
        credential_header=policy.credential.header if policy.credential else None,
        credential_format=policy.credential.format if policy.credential else None,
        credential_value_encrypted=encrypted_value,
        credential_rotated_at=datetime.utcnow() if policy.credential else None,
    )
    db.add(db_policy)
    db.commit()
    db.refresh(db_policy)
    return domain_policy_to_response(db_policy)


@app.get("/api/v1/domain-policies/for-domain")
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

    # Agent tokens only see their agent's policies + global policies
    if token_info.token_type == "agent" and token_info.agent_id:
        query = query.filter(
            (DomainPolicy.agent_id == token_info.agent_id) | (DomainPolicy.agent_id.is_(None))
        )

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
        except Exception:
            pass

    return result


@app.get("/api/v1/domain-policies/export")
async def export_domain_policies(
    db: Session = Depends(get_db),
    token_info: TokenInfo = Depends(verify_token)
):
    """Export all domains for CoreDNS allowlist.

    Returns list of domains (without credentials) for DNS filtering.
    """
    query = db.query(DomainPolicy).filter(DomainPolicy.enabled == True)

    # Agent tokens only see their agent's policies + global policies
    if token_info.token_type == "agent" and token_info.agent_id:
        query = query.filter(
            (DomainPolicy.agent_id == token_info.agent_id) | (DomainPolicy.agent_id.is_(None))
        )

    policies = query.all()
    domains = [p.domain for p in policies]

    return {
        "domains": domains,
        "generated_at": datetime.utcnow().isoformat()
    }


@app.get("/api/v1/domain-policies/{policy_id}", response_model=DomainPolicyResponse)
async def get_domain_policy(
    policy_id: int,
    db: Session = Depends(get_db),
    token_info: TokenInfo = Depends(require_admin_role)
):
    """Get a domain policy by ID."""
    policy = db.query(DomainPolicy).filter(DomainPolicy.id == policy_id).first()
    if not policy:
        raise HTTPException(status_code=404, detail="Policy not found")
    return domain_policy_to_response(policy)


@app.put("/api/v1/domain-policies/{policy_id}", response_model=DomainPolicyResponse)
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
        policy.credential_rotated_at = datetime.utcnow()

    db.commit()
    db.refresh(policy)
    return domain_policy_to_response(policy)


@app.delete("/api/v1/domain-policies/{policy_id}")
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

    db.delete(policy)
    db.commit()
    return {"deleted": True, "id": policy_id}


@app.post("/api/v1/domain-policies/{policy_id}/rotate-credential", response_model=DomainPolicyResponse)
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

    policy.credential_header = credential.header
    policy.credential_format = credential.format
    policy.credential_value_encrypted = encrypt_secret(credential.value)
    policy.credential_rotated_at = datetime.utcnow()
    db.commit()
    db.refresh(policy)
    return domain_policy_to_response(policy)


# =============================================================================
# Data Plane (Agent) Listing Endpoint
# =============================================================================

@app.get("/api/v1/agents", response_model=List[DataPlaneResponse])
async def list_agents(
    tenant_id: Optional[int] = Query(default=None, description="Filter by tenant (super admin only)"),
    db: Session = Depends(get_db),
    token_info: TokenInfo = Depends(verify_token)
):
    """List all connected data planes (agents).

    Super admins can filter by tenant_id, or see all agents if not specified.
    Tenant admins see only their tenant's agents.
    Excludes __default__ virtual agents and soft-deleted agents from listing.
    """
    query = db.query(AgentState).filter(
        AgentState.agent_id != "__default__",
        AgentState.deleted_at.is_(None)  # Exclude soft-deleted
    )

    # Apply tenant filtering
    if token_info.is_super_admin:
        # Super admin can optionally filter by tenant
        if tenant_id is not None:
            query = query.filter(AgentState.tenant_id == tenant_id)
        # else: no filter, see all agents
    else:
        # Non-super-admin MUST be scoped to their tenant
        if not token_info.tenant_id:
            raise HTTPException(status_code=403, detail="Token must be scoped to a tenant")
        query = query.filter(AgentState.tenant_id == token_info.tenant_id)

    agents = query.all()
    result = []
    for agent in agents:
        # Check if agent is online (heartbeat within last 60s)
        online = False
        if agent.last_heartbeat:
            online = (datetime.utcnow() - agent.last_heartbeat).total_seconds() < 60

        result.append(DataPlaneResponse(
            agent_id=agent.agent_id,
            status=agent.status or "unknown",
            online=online,
            approved=agent.approved or False,
            tenant_id=agent.tenant_id,
            last_heartbeat=agent.last_heartbeat
        ))
    return result


# =============================================================================
# Agent Management Endpoints (Polling-based)
# Agent-manager polls these endpoints, no inbound connection to data plane needed
# =============================================================================

def get_or_create_agent_state(db: Session, agent_id: str = "default", tenant_id: Optional[int] = None) -> AgentState:
    """Get or create agent state record.

    If an agent was soft-deleted and tries to reconnect, it is restored
    but needs re-approval.

    tenant_id is required when creating a new agent. Existing agents already
    have tenant_id in the database.
    """
    state = db.query(AgentState).filter(AgentState.agent_id == agent_id).first()
    if not state:
        if tenant_id is None:
            raise ValueError(f"tenant_id is required when creating new agent: {agent_id}")
        state = AgentState(agent_id=agent_id, tenant_id=tenant_id)
        db.add(state)
        db.commit()
        db.refresh(state)
    elif state.deleted_at:
        # Restore soft-deleted agent but require re-approval
        state.deleted_at = None
        state.approved = False
        state.approved_at = None
        state.approved_by = None
        db.commit()
        db.refresh(state)
    return state


@app.post("/api/v1/agent/heartbeat", response_model=AgentHeartbeatResponse)
@limiter.limit("5/second")  # Agents poll every 30s, allow burst
async def agent_heartbeat(
    request: Request,
    heartbeat: AgentHeartbeat,
    db: Session = Depends(get_db),
    token_info: TokenInfo = Depends(verify_token)
):
    """Receive heartbeat from agent-manager, return any pending command.

    Called by agent-manager every 30s. Updates agent status and returns
    any pending command (wipe, restart, etc.) for the agent to execute.

    Agent tokens can only send heartbeats for their associated agent.
    Unapproved agents can send heartbeats but will not receive commands.
    """
    # Verify agent token has access to this agent
    if token_info.token_type == "agent":
        verify_agent_access(token_info, heartbeat.agent_id, db)

    # Get or create agent with tenant from token
    state = get_or_create_agent_state(db, heartbeat.agent_id, token_info.tenant_id)

    # Update status from heartbeat
    state.status = heartbeat.status
    state.container_id = heartbeat.container_id
    state.uptime_seconds = heartbeat.uptime_seconds
    state.cpu_percent = int(heartbeat.cpu_percent) if heartbeat.cpu_percent else None
    state.memory_mb = int(heartbeat.memory_mb) if heartbeat.memory_mb else None
    state.memory_limit_mb = int(heartbeat.memory_limit_mb) if heartbeat.memory_limit_mb else None
    state.last_heartbeat = datetime.utcnow()

    # Update last command result if reported
    if heartbeat.last_command:
        state.last_command = heartbeat.last_command
        state.last_command_result = heartbeat.last_command_result
        state.last_command_message = heartbeat.last_command_message
        state.last_command_at = datetime.utcnow()

        # Log command completion
        log = AuditLog(
            event_type=f"agent_{heartbeat.last_command}",
            user="agent-manager",
            action=f"Agent {heartbeat.last_command}: {heartbeat.last_command_result}",
            details=heartbeat.last_command_message,
            severity="INFO" if heartbeat.last_command_result == "success" else "WARNING",
            tenant_id=state.tenant_id
        )
        db.add(log)

    # Get pending command and clear it (only for approved agents)
    response = AgentHeartbeatResponse(ack=True)

    # Only deliver commands to approved agents
    if state.approved and state.pending_command:
        response.command = state.pending_command
        if state.pending_command_args:
            response.command_args = json.loads(state.pending_command_args)

        # Clear pending command (agent will report result in next heartbeat)
        state.pending_command = None
        state.pending_command_args = None
        state.pending_command_at = None

    db.commit()
    return response


@app.post("/api/v1/agents/{agent_id}/wipe")
async def queue_agent_wipe(
    request: Request,
    agent_id: str,
    body: AgentCommandRequest,
    db: Session = Depends(get_db),
    token_info: TokenInfo = Depends(require_admin_role_with_ip_check)
):
    """Queue a wipe command for the specified agent (admin only).

    The command will be delivered to agent-manager on next heartbeat.
    """
    state = get_or_create_agent_state(db, agent_id)

    if state.pending_command:
        raise HTTPException(
            status_code=409,
            detail=f"Command already pending: {state.pending_command}"
        )

    state.pending_command = "wipe"
    state.pending_command_args = json.dumps({"wipe_workspace": body.wipe_workspace})
    state.pending_command_at = datetime.utcnow()

    # Log the wipe request
    log = AuditLog(
        event_type="agent_wipe_requested",
        user=token_info.token_name or "admin",
        action=f"Wipe requested for {agent_id} (workspace={'wipe' if body.wipe_workspace else 'preserve'})",
        severity="WARNING",
        tenant_id=get_audit_tenant_id(token_info, db, state)
    )
    db.add(log)
    db.commit()

    return {
        "status": "queued",
        "command": "wipe",
        "message": f"Wipe command queued for {agent_id}. Will execute on next agent heartbeat."
    }


@app.post("/api/v1/agents/{agent_id}/restart")
async def queue_agent_restart(
    request: Request,
    agent_id: str,
    db: Session = Depends(get_db),
    token_info: TokenInfo = Depends(require_admin_role_with_ip_check)
):
    """Queue a restart command for the specified agent (admin only)."""
    state = get_or_create_agent_state(db, agent_id)

    if state.pending_command:
        raise HTTPException(
            status_code=409,
            detail=f"Command already pending: {state.pending_command}"
        )

    state.pending_command = "restart"
    state.pending_command_at = datetime.utcnow()
    db.commit()

    return {
        "status": "queued",
        "command": "restart",
        "message": f"Restart command queued for {agent_id}. Will execute on next agent heartbeat."
    }


@app.post("/api/v1/agents/{agent_id}/stop")
async def queue_agent_stop(
    request: Request,
    agent_id: str,
    db: Session = Depends(get_db),
    token_info: TokenInfo = Depends(require_admin_role_with_ip_check)
):
    """Queue a stop command for the specified agent (admin only)."""
    state = get_or_create_agent_state(db, agent_id)

    if state.pending_command:
        raise HTTPException(
            status_code=409,
            detail=f"Command already pending: {state.pending_command}"
        )

    state.pending_command = "stop"
    state.pending_command_at = datetime.utcnow()
    db.commit()

    return {
        "status": "queued",
        "command": "stop",
        "message": f"Stop command queued for {agent_id}. Will execute on next agent heartbeat."
    }


@app.post("/api/v1/agents/{agent_id}/start")
async def queue_agent_start(
    request: Request,
    agent_id: str,
    db: Session = Depends(get_db),
    token_info: TokenInfo = Depends(require_admin_role_with_ip_check)
):
    """Queue a start command for the specified agent (admin only)."""
    state = get_or_create_agent_state(db, agent_id)

    if state.pending_command:
        raise HTTPException(
            status_code=409,
            detail=f"Command already pending: {state.pending_command}"
        )

    state.pending_command = "start"
    state.pending_command_at = datetime.utcnow()
    db.commit()

    return {
        "status": "queued",
        "command": "start",
        "message": f"Start command queued for {agent_id}. Will execute on next agent heartbeat."
    }


@app.get("/api/v1/agents/{agent_id}/status", response_model=AgentStatusResponse)
async def get_agent_status(
    agent_id: str,
    db: Session = Depends(get_db),
    token_info: TokenInfo = Depends(verify_token)
):
    """Get agent status from last heartbeat."""
    state = db.query(AgentState).filter(
        AgentState.agent_id == agent_id,
        AgentState.deleted_at.is_(None)
    ).first()
    if not state:
        raise HTTPException(status_code=404, detail=f"Agent {agent_id} not found")

    # Check if agent is online (heartbeat within last 60s)
    online = False
    if state.last_heartbeat:
        online = (datetime.utcnow() - state.last_heartbeat).total_seconds() < 60

    return AgentStatusResponse(
        agent_id=state.agent_id,
        status=state.status or "unknown",
        container_id=state.container_id,
        uptime_seconds=state.uptime_seconds,
        cpu_percent=state.cpu_percent,
        memory_mb=state.memory_mb,
        memory_limit_mb=state.memory_limit_mb,
        last_heartbeat=state.last_heartbeat,
        pending_command=state.pending_command,
        last_command=state.last_command,
        last_command_result=state.last_command_result,
        last_command_at=state.last_command_at,
        online=online
    )


# =============================================================================
# Agent Approval Endpoints
# =============================================================================

@app.post("/api/v1/agents/{agent_id}/approve")
async def approve_agent(
    request: Request,
    agent_id: str,
    db: Session = Depends(get_db),
    token_info: TokenInfo = Depends(require_admin_role_with_ip_check)
):
    """Approve an agent to connect to the control plane."""
    state = db.query(AgentState).filter(
        AgentState.agent_id == agent_id,
        AgentState.deleted_at.is_(None)
    ).first()
    if not state:
        raise HTTPException(status_code=404, detail=f"Agent {agent_id} not found")

    if state.approved:
        return {"status": "already_approved", "agent_id": agent_id}

    state.approved = True
    state.approved_at = datetime.utcnow()
    state.approved_by = token_info.token_name or "admin"

    # Log the approval
    log = AuditLog(
        event_type="agent_approved",
        user=token_info.token_name or "admin",
        action=f"Agent {agent_id} approved",
        severity="INFO",
        tenant_id=get_audit_tenant_id(token_info, db, state)
    )
    db.add(log)
    db.commit()

    return {
        "status": "approved",
        "agent_id": agent_id,
        "approved_at": state.approved_at.isoformat()
    }


@app.post("/api/v1/agents/{agent_id}/reject")
async def reject_agent(
    request: Request,
    agent_id: str,
    db: Session = Depends(get_db),
    token_info: TokenInfo = Depends(require_admin_role_with_ip_check)
):
    """Reject and soft-delete a pending agent."""
    state = db.query(AgentState).filter(
        AgentState.agent_id == agent_id,
        AgentState.deleted_at.is_(None)
    ).first()
    if not state:
        raise HTTPException(status_code=404, detail=f"Agent {agent_id} not found")

    # Log the rejection
    log = AuditLog(
        event_type="agent_rejected",
        user=token_info.token_name or "admin",
        action=f"Agent {agent_id} rejected and soft-deleted",
        severity="WARNING",
        tenant_id=get_audit_tenant_id(token_info, db, state)
    )
    db.add(log)

    # Soft delete the agent
    state.deleted_at = datetime.utcnow()
    state.approved = False
    db.commit()

    return {"status": "rejected", "agent_id": agent_id}


@app.post("/api/v1/agents/{agent_id}/revoke")
async def revoke_agent(
    request: Request,
    agent_id: str,
    db: Session = Depends(get_db),
    token_info: TokenInfo = Depends(require_admin_role_with_ip_check)
):
    """Revoke approval for an agent (set approved=False)."""
    state = db.query(AgentState).filter(
        AgentState.agent_id == agent_id,
        AgentState.deleted_at.is_(None)
    ).first()
    if not state:
        raise HTTPException(status_code=404, detail=f"Agent {agent_id} not found")

    state.approved = False
    state.approved_at = None
    state.approved_by = None

    # Log the revocation
    log = AuditLog(
        event_type="agent_revoked",
        user=token_info.token_name or "admin",
        action=f"Agent {agent_id} approval revoked",
        severity="WARNING",
        tenant_id=get_audit_tenant_id(token_info, db, state)
    )
    db.add(log)
    db.commit()

    return {"status": "revoked", "agent_id": agent_id}


# =============================================================================
# STCP Configuration Endpoints
# =============================================================================

@app.post("/api/v1/agents/{agent_id}/stcp-secret", response_model=STCPSecretResponse)
async def generate_stcp_secret(
    agent_id: str,
    db: Session = Depends(get_db),
    token_info: TokenInfo = Depends(require_admin_role)
):
    """Generate a new STCP secret for an agent (admin only).

    This secret is used by:
    1. FRP client on data plane (in STCP_SECRET_KEY env var)
    2. STCP visitor on control plane (for terminal access)

    The secret is returned only once - save it securely!
    """
    verify_agent_access(token_info, agent_id, db)

    state = db.query(AgentState).filter(
        AgentState.agent_id == agent_id,
        AgentState.deleted_at.is_(None)
    ).first()
    if not state:
        raise HTTPException(status_code=404, detail=f"Agent {agent_id} not found")

    # Generate cryptographically secure secret
    secret = secrets.token_urlsafe(32)
    state.stcp_secret_key = encrypt_secret(secret)
    db.commit()

    # Log the action
    log = AuditLog(
        event_type="stcp_secret_generated",
        user=token_info.token_name or "admin",
        action=f"STCP secret generated for agent {agent_id}",
        severity="INFO",
        tenant_id=get_audit_tenant_id(token_info, db, state)
    )
    db.add(log)
    db.commit()

    return STCPSecretResponse(
        agent_id=agent_id,
        secret_key=secret,  # Only returned once!
        message="Save this secret - it will not be shown again. Use it as STCP_SECRET_KEY in data plane .env"
    )


@app.get("/api/v1/agents/{agent_id}/stcp-config", response_model=STCPVisitorConfig)
async def get_stcp_visitor_config(
    agent_id: str,
    db: Session = Depends(get_db),
    token_info: TokenInfo = Depends(require_developer_role)
):
    """Get STCP visitor configuration for terminal access (developer role).

    Used by the WebSocket terminal handler to establish SSH connection.
    """
    verify_agent_access(token_info, agent_id, db)

    state = db.query(AgentState).filter(
        AgentState.agent_id == agent_id,
        AgentState.deleted_at.is_(None),
        AgentState.approved == True
    ).first()
    if not state:
        raise HTTPException(status_code=404, detail=f"Agent {agent_id} not found or not approved")

    if not state.stcp_secret_key:
        raise HTTPException(status_code=404, detail="STCP not configured for this agent. Generate a secret first.")

    return STCPVisitorConfig(
        server_addr=os.environ.get("FRP_SERVER_ADDR", "frps"),
        server_port=7000,
        proxy_name=f"{agent_id}-ssh",
        secret_key=decrypt_secret(state.stcp_secret_key)
    )


# =============================================================================
# Web Terminal Endpoints (WebSocket)
# =============================================================================

@app.websocket("/api/v1/terminal/{agent_id}/ws")
async def terminal_websocket(
    websocket: WebSocket,
    agent_id: str
):
    """WebSocket endpoint for terminal access to an agent.

    Authentication:
    - Token passed as query param: ?token=xxx
    - Requires developer role

    Messages:
    - Binary: Terminal data (stdin/stdout)
    - Text JSON: Control messages (resize, ping)

    Note: This is a simplified implementation. For production, implement
    proper SSH connection via paramiko with STCP visitor subprocess.
    """
    # Get database session
    db = SessionLocal()

    try:
        # Accept connection first
        await websocket.accept()

        # Authenticate via query param
        token = websocket.query_params.get("token")
        if not token:
            await websocket.close(code=4001, reason="Authentication required - pass token as query param")
            return

        # Verify token
        token_hash_value = hash_token(token)
        db_token = db.query(ApiToken).filter(
            ApiToken.token_hash == token_hash_value,
            ApiToken.enabled == True
        ).first()

        if not db_token:
            await websocket.close(code=4003, reason="Invalid token")
            return

        # Check expiry
        if db_token.expires_at and db_token.expires_at < datetime.utcnow():
            await websocket.close(code=4003, reason="Token expired")
            return

        # Check developer role
        roles = (db_token.roles or "").split(",")
        if "developer" not in roles and not db_token.is_super_admin:
            await websocket.close(code=4003, reason="Developer role required")
            return

        # Check agent access (multi-tenancy)
        if not db_token.is_super_admin:
            if db_token.token_type == "agent" and db_token.agent_id != agent_id:
                await websocket.close(code=4003, reason="Access denied to this agent")
                return
            if db_token.tenant_id:
                agent = db.query(AgentState).filter(AgentState.agent_id == agent_id).first()
                if agent and agent.tenant_id != db_token.tenant_id:
                    await websocket.close(code=4003, reason="Agent belongs to different tenant")
                    return

        # Get agent state
        agent = db.query(AgentState).filter(
            AgentState.agent_id == agent_id,
            AgentState.deleted_at.is_(None),
            AgentState.approved == True
        ).first()

        if not agent:
            await websocket.close(code=4004, reason="Agent not found or not approved")
            return

        if not agent.stcp_secret_key:
            await websocket.close(code=4004, reason="STCP not configured for agent")
            return

        # Check if agent is online
        if not agent.last_heartbeat or (datetime.utcnow() - agent.last_heartbeat).total_seconds() > 60:
            await websocket.close(code=4004, reason="Agent is offline")
            return

        # Get client IP
        client_ip = websocket.client.host if websocket.client else "unknown"

        # Create terminal session record
        session_id = str(uuid.uuid4())
        session_record = TerminalSession(
            session_id=session_id,
            agent_id=agent_id,
            user=db_token.name,
            tenant_id=db_token.tenant_id,
            client_ip=client_ip
        )
        db.add(session_record)

        # Audit log - use agent's tenant or token's tenant or system tenant
        audit_tenant_id = db_token.tenant_id or get_system_tenant_id(db)
        log = AuditLog(
            event_type="terminal_session_start",
            user=db_token.name,
            container_id=agent_id,
            action=f"Terminal session started for agent {agent_id}",
            details=json.dumps({"session_id": session_id, "client_ip": client_ip}),
            severity="INFO",
            tenant_id=audit_tenant_id
        )
        db.add(log)
        db.commit()

        started_at = datetime.utcnow()
        bytes_sent = 0
        bytes_received = 0

        # Send welcome message
        await websocket.send_text(json.dumps({
            "type": "connected",
            "session_id": session_id,
            "agent_id": agent_id,
            "message": "Connected to agent terminal"
        }))

        # Terminal relay loop
        # NOTE: For full SSH implementation, use paramiko here
        # This simplified version echoes commands (placeholder for real SSH)
        try:
            while True:
                data = await websocket.receive()

                if "text" in data:
                    msg = json.loads(data["text"])
                    if msg.get("type") == "resize":
                        # Handle terminal resize
                        cols = msg.get("cols", 80)
                        rows = msg.get("rows", 24)
                        logger.debug(f"Terminal resize: {cols}x{rows}")
                    elif msg.get("type") == "ping":
                        await websocket.send_text(json.dumps({"type": "pong"}))

                elif "bytes" in data:
                    # Forward to SSH (placeholder - echo for now)
                    bytes_sent += len(data["bytes"])
                    # In real implementation: ssh_channel.send(data["bytes"])
                    # For now, echo back
                    response = data["bytes"]
                    bytes_received += len(response)
                    await websocket.send_bytes(response)

        except WebSocketDisconnect:
            logger.info(f"Terminal session {session_id} disconnected")

    except Exception as e:
        logger.error(f"Terminal error: {e}")
        if websocket.client_state == WebSocketState.CONNECTED:
            await websocket.close(code=4005, reason=str(e))

    finally:
        # Update session record
        ended_at = datetime.utcnow()
        duration = int((ended_at - started_at).total_seconds()) if 'started_at' in locals() else 0

        if 'session_id' in locals():
            session = db.query(TerminalSession).filter(
                TerminalSession.session_id == session_id
            ).first()
            if session:
                session.ended_at = ended_at
                session.duration_seconds = duration
                session.bytes_sent = bytes_sent if 'bytes_sent' in locals() else 0
                session.bytes_received = bytes_received if 'bytes_received' in locals() else 0

            # Audit log
            log = AuditLog(
                event_type="terminal_session_end",
                user=db_token.name if 'db_token' in locals() else "unknown",
                container_id=agent_id,
                action=f"Terminal session ended for agent {agent_id}",
                details=json.dumps({
                    "session_id": session_id,
                    "duration_seconds": duration,
                    "bytes_sent": bytes_sent if 'bytes_sent' in locals() else 0,
                    "bytes_received": bytes_received if 'bytes_received' in locals() else 0
                }),
                severity="INFO",
                tenant_id=audit_tenant_id if 'audit_tenant_id' in locals() else get_system_tenant_id(db)
            )
            db.add(log)
            db.commit()

        db.close()


@app.get("/api/v1/terminal/sessions", response_model=List[TerminalSessionResponse])
async def list_terminal_sessions(
    agent_id: Optional[str] = None,
    limit: int = Query(default=50, le=200),
    db: Session = Depends(get_db),
    token_info: TokenInfo = Depends(require_admin_role)
):
    """List terminal sessions (admin only).

    Filter by agent_id to see sessions for a specific agent.
    """
    query = db.query(TerminalSession).order_by(TerminalSession.started_at.desc())

    if agent_id:
        query = query.filter(TerminalSession.agent_id == agent_id)

    # Tenant isolation
    if not token_info.is_super_admin:
        if not token_info.tenant_id:
            raise HTTPException(status_code=403, detail="Token must be scoped to a tenant")
        query = query.filter(TerminalSession.tenant_id == token_info.tenant_id)

    return query.limit(limit).all()


# =============================================================================
# Tenant Management Endpoints (Super Admin Only)
# =============================================================================

@app.get("/api/v1/tenants", response_model=List[TenantResponse])
async def list_tenants(
    db: Session = Depends(get_db),
    token_info: TokenInfo = Depends(require_super_admin)
):
    """List all tenants (super admin only). Excludes soft-deleted tenants."""
    tenants = db.query(Tenant).filter(Tenant.deleted_at.is_(None)).all()
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


@app.post("/api/v1/tenants", response_model=TenantResponse)
async def create_tenant(
    request: TenantCreate,
    db: Session = Depends(get_db),
    token_info: TokenInfo = Depends(require_super_admin)
):
    """Create a new tenant (super admin only).

    Also creates a __default__ agent for tenant-global configuration.
    """
    # Check if slug already exists (only check non-deleted tenants)
    existing = db.query(Tenant).filter(
        Tenant.deleted_at.is_(None),
        (Tenant.name == request.name) | (Tenant.slug == request.slug)
    ).first()
    if existing:
        raise HTTPException(
            status_code=400,
            detail="Tenant with this name or slug already exists"
        )

    # Create tenant
    tenant = Tenant(name=request.name, slug=request.slug)
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

    # Log tenant creation (super admin action - use __system__ tenant)
    log = AuditLog(
        event_type="tenant_created",
        user=token_info.token_name,
        action=f"Created tenant '{request.name}' (slug: {request.slug})",
        severity="info",
        tenant_id=get_system_tenant_id(db)
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


@app.get("/api/v1/tenants/{tenant_id}", response_model=TenantResponse)
async def get_tenant(
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


@app.delete("/api/v1/tenants/{tenant_id}")
async def delete_tenant(
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

    # Log deletion (super admin action - use __system__ tenant)
    log = AuditLog(
        event_type="tenant_deleted",
        user=token_info.token_name,
        action=f"Soft-deleted tenant '{tenant.name}' and {agent_count} agents",
        severity="warning",
        tenant_id=get_system_tenant_id(db)
    )
    db.add(log)
    db.commit()

    return {"status": "deleted", "tenant_id": tenant_id, "agents_deleted": agent_count}


# =============================================================================
# Tenant IP ACL Endpoints
# =============================================================================

@app.get("/api/v1/tenants/{tenant_id}/ip-acls", response_model=List[TenantIpAclResponse])
async def list_tenant_ip_acls(
    tenant_id: int,
    db: Session = Depends(get_db),
    token_info: TokenInfo = Depends(require_admin_role)
):
    """List IP ACL entries for a tenant (admin only).

    Non-super-admins can only view ACLs for their own tenant.
    """
    # Verify tenant access
    if not token_info.is_super_admin and token_info.tenant_id != tenant_id:
        raise HTTPException(status_code=403, detail="Access denied to this tenant")

    # Verify tenant exists
    tenant = db.query(Tenant).filter(
        Tenant.id == tenant_id,
        Tenant.deleted_at.is_(None)
    ).first()
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")

    return db.query(TenantIpAcl).filter(
        TenantIpAcl.tenant_id == tenant_id
    ).order_by(TenantIpAcl.created_at.desc()).all()


@app.post("/api/v1/tenants/{tenant_id}/ip-acls", response_model=TenantIpAclResponse)
@limiter.limit("30/minute")
async def create_tenant_ip_acl(
    request: Request,
    tenant_id: int,
    acl: TenantIpAclCreate,
    db: Session = Depends(get_db),
    token_info: TokenInfo = Depends(require_admin_role)
):
    """Create an IP ACL entry for a tenant (admin only).

    CIDR format: "10.0.0.0/8", "192.168.1.0/24", "203.0.113.50/32"
    Use /32 for single IP addresses.
    """
    # Verify tenant access
    if not token_info.is_super_admin and token_info.tenant_id != tenant_id:
        raise HTTPException(status_code=403, detail="Access denied to this tenant")

    # Verify tenant exists
    tenant = db.query(Tenant).filter(
        Tenant.id == tenant_id,
        Tenant.deleted_at.is_(None)
    ).first()
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")

    # Validate CIDR format
    try:
        ipaddress.ip_network(acl.cidr, strict=False)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"Invalid CIDR format: {e}")

    # Check for duplicates
    existing = db.query(TenantIpAcl).filter(
        TenantIpAcl.tenant_id == tenant_id,
        TenantIpAcl.cidr == acl.cidr
    ).first()
    if existing:
        raise HTTPException(status_code=400, detail="IP ACL entry already exists for this CIDR")

    db_acl = TenantIpAcl(
        tenant_id=tenant_id,
        cidr=acl.cidr,
        description=acl.description,
        created_by=token_info.token_name or "admin"
    )
    db.add(db_acl)

    # Audit log (use the tenant being modified)
    log = AuditLog(
        event_type="ip_acl_created",
        user=token_info.token_name or "admin",
        action=f"IP ACL created for tenant {tenant_id}: {acl.cidr}",
        details=json.dumps({"tenant_id": tenant_id, "cidr": acl.cidr}),
        severity="INFO",
        tenant_id=tenant_id
    )
    db.add(log)
    db.commit()
    db.refresh(db_acl)

    return db_acl


@app.patch("/api/v1/tenants/{tenant_id}/ip-acls/{acl_id}", response_model=TenantIpAclResponse)
@limiter.limit("30/minute")
async def update_tenant_ip_acl(
    request: Request,
    tenant_id: int,
    acl_id: int,
    acl: TenantIpAclUpdate,
    db: Session = Depends(get_db),
    token_info: TokenInfo = Depends(require_admin_role)
):
    """Update an IP ACL entry (admin only)."""
    # Verify tenant access
    if not token_info.is_super_admin and token_info.tenant_id != tenant_id:
        raise HTTPException(status_code=403, detail="Access denied to this tenant")

    db_acl = db.query(TenantIpAcl).filter(
        TenantIpAcl.id == acl_id,
        TenantIpAcl.tenant_id == tenant_id
    ).first()
    if not db_acl:
        raise HTTPException(status_code=404, detail="IP ACL entry not found")

    if acl.description is not None:
        db_acl.description = acl.description
    if acl.enabled is not None:
        db_acl.enabled = acl.enabled

    # Audit log (use the tenant being modified)
    log = AuditLog(
        event_type="ip_acl_updated",
        user=token_info.token_name or "admin",
        action=f"IP ACL updated for tenant {tenant_id}: {db_acl.cidr}",
        details=json.dumps({"acl_id": acl_id, "changes": acl.dict(exclude_unset=True)}),
        severity="INFO",
        tenant_id=tenant_id
    )
    db.add(log)
    db.commit()
    db.refresh(db_acl)

    return db_acl


@app.delete("/api/v1/tenants/{tenant_id}/ip-acls/{acl_id}")
async def delete_tenant_ip_acl(
    tenant_id: int,
    acl_id: int,
    db: Session = Depends(get_db),
    token_info: TokenInfo = Depends(require_admin_role)
):
    """Delete an IP ACL entry (admin only)."""
    # Verify tenant access
    if not token_info.is_super_admin and token_info.tenant_id != tenant_id:
        raise HTTPException(status_code=403, detail="Access denied to this tenant")

    db_acl = db.query(TenantIpAcl).filter(
        TenantIpAcl.id == acl_id,
        TenantIpAcl.tenant_id == tenant_id
    ).first()
    if not db_acl:
        raise HTTPException(status_code=404, detail="IP ACL entry not found")

    cidr = db_acl.cidr  # Save for logging
    db.delete(db_acl)

    # Audit log (use the tenant being modified)
    log = AuditLog(
        event_type="ip_acl_deleted",
        user=token_info.token_name or "admin",
        action=f"IP ACL deleted for tenant {tenant_id}: {cidr}",
        details=json.dumps({"acl_id": acl_id, "cidr": cidr}),
        severity="WARNING",
        tenant_id=tenant_id
    )
    db.add(log)
    db.commit()

    return {"status": "deleted"}


# =============================================================================
# API Token Management Endpoints
# =============================================================================

@app.get("/api/v1/tokens", response_model=List[ApiTokenResponse])
async def list_tokens(
    tenant_id: Optional[int] = Query(default=None, description="Filter by tenant (super admin only)"),
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

    tokens = query.all()
    return [ApiTokenResponse(
        id=t.id,
        name=t.name,
        token_type=t.token_type,
        agent_id=t.agent_id,
        tenant_id=t.tenant_id,
        is_super_admin=t.is_super_admin or False,
        roles=t.roles or "admin",
        created_at=t.created_at,
        expires_at=t.expires_at,
        last_used_at=t.last_used_at,
        enabled=t.enabled
    ) for t in tokens]


@app.post("/api/v1/tokens", response_model=ApiTokenCreatedResponse)
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

    # Only super admins can create super admin tokens
    if body.is_super_admin and not token_info.is_super_admin:
        raise HTTPException(
            status_code=403,
            detail="Only super admins can create super admin tokens"
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
    elif not body.is_super_admin and not new_tenant_id:
        # Non-super-admin tokens default to creator's tenant
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
        expires_at = datetime.utcnow() + timedelta(days=body.expires_in_days)

    # Validate roles
    valid_roles = {"admin", "developer"}
    requested_roles = set(r.strip() for r in (body.roles or "admin").split(","))
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

    # Log token creation (use the token's tenant or system tenant for super admin actions)
    log = AuditLog(
        event_type="token_created",
        user=token_info.token_name or "admin",
        action=f"Token '{body.name}' created (type={body.token_type}, roles={roles_str}, super_admin={body.is_super_admin})",
        details=f"agent_id={body.agent_id}, tenant_id={new_tenant_id}" if body.agent_id else f"tenant_id={new_tenant_id}",
        severity="INFO",
        tenant_id=new_tenant_id if new_tenant_id else get_system_tenant_id(db)
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
        roles=db_token.roles or "admin",
        token=raw_token,  # Only returned once!
        expires_at=db_token.expires_at
    )


@app.delete("/api/v1/tokens/{token_id}")
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

    token_name = db_token.name
    deleted_token_tenant_id = db_token.tenant_id

    # Log token deletion (use the deleted token's tenant or system tenant)
    log = AuditLog(
        event_type="token_deleted",
        user=token_info.token_name or "admin",
        action=f"Token '{token_name}' deleted",
        severity="WARNING",
        tenant_id=deleted_token_tenant_id if deleted_token_tenant_id else get_system_tenant_id(db)
    )
    db.add(log)

    db.delete(db_token)
    db.commit()

    return {"status": "deleted", "name": token_name}


@app.patch("/api/v1/tokens/{token_id}")
async def update_token(
    token_id: int,
    enabled: Optional[bool] = None,
    db: Session = Depends(get_db),
    token_info: TokenInfo = Depends(require_admin_role)
):
    """Update an API token (enable/disable)."""
    db_token = db.query(ApiToken).filter(ApiToken.id == token_id).first()
    if not db_token:
        raise HTTPException(status_code=404, detail="Token not found")

    if enabled is not None:
        db_token.enabled = enabled

        # Log the change (use the token's tenant or system tenant)
        action = "enabled" if enabled else "disabled"
        log = AuditLog(
            event_type=f"token_{action}",
            user=token_info.token_name or "admin",
            action=f"Token '{db_token.name}' {action}",
            severity="INFO",
            tenant_id=db_token.tenant_id if db_token.tenant_id else get_system_tenant_id(db)
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
        roles=db_token.roles or "admin",
        created_at=db_token.created_at,
        expires_at=db_token.expires_at,
        last_used_at=db_token.last_used_at,
        enabled=db_token.enabled
    )


# =============================================================================
# Main
# =============================================================================

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
