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
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Text, Boolean, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session, relationship
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


class AllowlistEntry(Base):
    __tablename__ = "allowlist"

    id = Column(Integer, primary_key=True, index=True)
    entry_type = Column(String(20))  # 'domain', 'ip', 'command'
    value = Column(String(500), index=True)
    description = Column(String(500))
    created_at = Column(DateTime, default=datetime.utcnow)
    created_by = Column(String(100))
    enabled = Column(Boolean, default=True)
    # Per-agent scoping: NULL = global (applies to all agents)
    agent_id = Column(String(100), nullable=True, index=True)


class Secret(Base):
    __tablename__ = "secrets"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), index=True)
    encrypted_value = Column(Text)  # Fernet-encrypted secret value
    description = Column(String(500))
    domain_pattern = Column(String(200))  # e.g., "api.openai.com", "*.github.com"
    alias = Column(String(50))  # e.g., "openai" -> openai.devbox.local
    header_name = Column(String(100), default="Authorization")  # e.g., "Authorization", "x-api-key"
    header_format = Column(String(100), default="Bearer {value}")  # e.g., "Bearer {value}", "{value}"
    created_at = Column(DateTime, default=datetime.utcnow)
    last_rotated = Column(DateTime)
    rotation_days = Column(Integer, default=90)
    # Per-agent scoping: NULL = global (applies to all agents)
    agent_id = Column(String(100), nullable=True, index=True)


class RateLimit(Base):
    __tablename__ = "rate_limits"

    id = Column(Integer, primary_key=True, index=True)
    domain_pattern = Column(String(200), index=True)  # e.g., "api.openai.com", "*.github.com"
    requests_per_minute = Column(Integer, default=60)
    burst_size = Column(Integer, default=10)  # Max tokens in bucket
    description = Column(String(500))
    enabled = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    # Per-agent scoping: NULL = global (applies to all agents)
    agent_id = Column(String(100), nullable=True, index=True)


class AgentState(Base):
    """Stores agent status (from heartbeats) and pending commands."""
    __tablename__ = "agent_state"

    id = Column(Integer, primary_key=True, index=True)
    agent_id = Column(String(100), unique=True, index=True, default="default")
    # Multi-tenancy
    tenant_id = Column(Integer, ForeignKey("tenants.id"), nullable=True, index=True)
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


class AllowlistEntryCreate(BaseModel):
    entry_type: str
    value: str
    description: Optional[str] = None
    agent_id: Optional[str] = None  # NULL = global (applies to all agents)


class AllowlistEntryResponse(BaseModel):
    id: int
    entry_type: str
    value: str
    description: Optional[str]
    enabled: bool
    created_at: datetime
    agent_id: Optional[str] = None  # NULL = global

    class Config:
        from_attributes = True


class SecretCreate(BaseModel):
    name: str
    value: str
    domain_pattern: str  # e.g., "api.openai.com", "*.github.com"
    alias: Optional[str] = None  # e.g., "openai" -> openai.devbox.local
    header_name: str = "Authorization"  # e.g., "Authorization", "x-api-key"
    header_format: str = "Bearer {value}"  # e.g., "Bearer {value}", "{value}"
    description: Optional[str] = None
    rotation_days: int = 90
    agent_id: Optional[str] = None  # NULL = global (applies to all agents)


class RotateSecretRequest(BaseModel):
    new_value: str


class SecretResponse(BaseModel):
    id: int
    name: str
    domain_pattern: Optional[str]
    alias: Optional[str]
    header_name: Optional[str]
    header_format: Optional[str]
    description: Optional[str]
    created_at: datetime
    last_rotated: Optional[datetime]
    rotation_days: int
    needs_rotation: bool
    agent_id: Optional[str] = None  # NULL = global

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


class RateLimitCreate(BaseModel):
    domain_pattern: str  # e.g., "api.openai.com", "*.github.com"
    requests_per_minute: int = 60
    burst_size: int = 10
    description: Optional[str] = None
    agent_id: Optional[str] = None  # NULL = global (applies to all agents)


class RateLimitUpdate(BaseModel):
    requests_per_minute: Optional[int] = None
    burst_size: Optional[int] = None
    description: Optional[str] = None
    enabled: Optional[bool] = None


class RateLimitResponse(BaseModel):
    id: int
    domain_pattern: str
    requests_per_minute: int
    burst_size: int
    description: Optional[str]
    enabled: bool
    created_at: datetime
    updated_at: datetime
    agent_id: Optional[str] = None  # NULL = global

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
    """Seed default tokens for development/testing.

    Creates:
    - admin-token: Admin role (full access to allowlist, secrets, etc.)
    - dev-token: Developer role (read access, terminal access)

    These are only created if they don't already exist. The actual token
    values are deterministic for easy testing but should be replaced in production.
    """
    # Check if we should seed (controlled by env var)
    if os.environ.get('SEED_TOKENS', 'true').lower() != 'true':
        return

    # Well-known test tokens (deterministic for testing)
    test_tokens = [
        {
            "name": "admin-token",
            "raw_token": "admin-test-token-do-not-use-in-production",
            "token_type": "admin",
            "roles": "admin",
            "is_super_admin": True,
        },
        {
            "name": "dev-token",
            "raw_token": "dev-test-token-do-not-use-in-production",
            "token_type": "admin",
            "roles": "developer",
            "is_super_admin": False,
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
            )
            db.add(db_token)
            logger.info(f"Seeded token: {token_def['name']} (roles: {token_def['roles']})")

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
async def get_current_user(token_info: TokenInfo = Depends(verify_token)):
    """Get current user info from token"""
    return {
        "token_type": token_info.token_type,
        "agent_id": token_info.agent_id,
        "tenant_id": token_info.tenant_id,
        "is_super_admin": token_info.is_super_admin,
        "roles": token_info.roles
    }


# =============================================================================
# OpenObserve Log Query (for DP audit logs)
# =============================================================================

OPENOBSERVE_URL = os.environ.get('OPENOBSERVE_URL', 'http://openobserve:5080')
OPENOBSERVE_USER = os.environ.get('OPENOBSERVE_USER', 'admin@maltbox.local')
OPENOBSERVE_PASSWORD = os.environ.get('OPENOBSERVE_PASSWORD', 'admin')


@app.get("/api/v1/logs/query")
@limiter.limit("30/minute")
async def query_agent_logs(
    request: Request,
    query: str = "",
    source: Optional[str] = None,
    agent_id: Optional[str] = None,
    limit: int = 100,
    start: Optional[str] = None,
    end: Optional[str] = None,
    token_info: TokenInfo = Depends(require_admin)
):
    """Query agent logs from OpenObserve (admin only).

    Args:
        query: Search text (full-text search in message field)
        source: Filter by source (envoy, agent, coredns, gvisor)
        agent_id: Filter by agent ID
        limit: Max number of log lines to return
        start: Start time (RFC3339, e.g., 2024-01-01T00:00:00Z)
        end: End time (RFC3339)
    """
    import httpx
    from datetime import datetime, timedelta

    # Build SQL query for OpenObserve
    conditions = []
    if query:
        conditions.append(f"message LIKE '%{query}%'")
    if source:
        conditions.append(f"source = '{source}'")
    if agent_id:
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
            raise HTTPException(
                status_code=response.status_code,
                detail=f"OpenObserve query failed: {response.text}"
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
    token_info: TokenInfo = Depends(require_admin),
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
    """Search and retrieve audit logs (admin only)"""
    query = db.query(AuditLog)
    
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


# =============================================================================
# Allowlist Management Endpoints
# =============================================================================

@app.get("/api/v1/allowlist", response_model=List[AllowlistEntryResponse])
async def get_allowlist(
    db: Session = Depends(get_db),
    token_info: TokenInfo = Depends(require_admin),
    entry_type: Optional[str] = None,
    agent_id: Optional[str] = None
):
    """Get all allowlist entries (admin only).

    Filter by agent_id to see entries for a specific agent.
    Super admins see all entries. Tenant admins see only their tenant's entries.
    """
    query = db.query(AllowlistEntry)

    # Filter by tenant for non-super-admin
    if not token_info.is_super_admin and token_info.tenant_id:
        tenant_agent_ids = get_tenant_agent_ids(db, token_info.tenant_id)
        query = query.filter(AllowlistEntry.agent_id.in_(tenant_agent_ids))

    if entry_type:
        query = query.filter(AllowlistEntry.entry_type == entry_type)
    if agent_id:
        # Show only entries for this specific agent
        query = query.filter(AllowlistEntry.agent_id == agent_id)

    return query.all()


@app.post("/api/v1/allowlist", response_model=AllowlistEntryResponse)
@limiter.limit("30/minute")  # Admin write operations
async def add_allowlist_entry(
    request: Request,
    entry: AllowlistEntryCreate,
    db: Session = Depends(get_db),
    token_info: TokenInfo = Depends(require_admin)
):
    """Add a new allowlist entry (admin only).

    Set agent_id to scope the entry to a specific agent.
    Leave agent_id as null/empty for global entries that apply to all agents.
    """
    # Check for duplicates (same value + same agent scope)
    existing = db.query(AllowlistEntry).filter(
        AllowlistEntry.value == entry.value,
        AllowlistEntry.agent_id == entry.agent_id
    ).first()
    if existing:
        raise HTTPException(status_code=400, detail="Entry already exists for this agent scope")

    db_entry = AllowlistEntry(
        entry_type=entry.entry_type,
        value=entry.value,
        description=entry.description,
        agent_id=entry.agent_id,
        created_by="api"
    )
    db.add(db_entry)
    db.commit()
    db.refresh(db_entry)

    # Allowlist changes are picked up by agent-manager via polling
    # (GET /api/v1/allowlist/export)

    return db_entry


@app.delete("/api/v1/allowlist/{entry_id}")
async def delete_allowlist_entry(
    entry_id: int,
    db: Session = Depends(get_db),
    token_info: TokenInfo = Depends(require_admin)
):
    """Delete an allowlist entry (admin only)"""
    entry = db.query(AllowlistEntry).filter(AllowlistEntry.id == entry_id).first()
    if not entry:
        raise HTTPException(status_code=404, detail="Entry not found")

    db.delete(entry)
    db.commit()
    return {"status": "deleted"}


@app.patch("/api/v1/allowlist/{entry_id}", response_model=AllowlistEntryResponse)
@limiter.limit("30/minute")
async def update_allowlist_entry(
    request: Request,
    entry_id: int,
    enabled: Optional[bool] = None,
    description: Optional[str] = None,
    db: Session = Depends(get_db),
    token_info: TokenInfo = Depends(require_admin)
):
    """Update an allowlist entry (admin only)"""
    entry = db.query(AllowlistEntry).filter(AllowlistEntry.id == entry_id).first()
    if not entry:
        raise HTTPException(status_code=404, detail="Entry not found")

    if enabled is not None:
        entry.enabled = enabled
    if description is not None:
        entry.description = description

    db.commit()
    db.refresh(entry)
    return entry


@app.get("/api/v1/allowlist/export")
async def export_allowlist(
    entry_type: str,
    format: str = "json",
    db: Session = Depends(get_db),
    token_info: TokenInfo = Depends(verify_token)
):
    """Export allowlist for container configuration (admin or agent).

    Agent tokens receive entries scoped to their agent + global entries.
    Admin tokens receive all entries unless agent_id query param is specified.

    Args:
        entry_type: Type of entries to export (domain, ip, command)
        format: Output format - 'json' (default) or 'hosts' (plain text, one per line)
    """
    query = db.query(AllowlistEntry).filter(
        AllowlistEntry.entry_type == entry_type,
        AllowlistEntry.enabled == True
    )

    # Agent tokens only see their agent's entries + global entries
    if token_info.token_type == "agent" and token_info.agent_id:
        query = query.filter(
            (AllowlistEntry.agent_id == token_info.agent_id) | (AllowlistEntry.agent_id.is_(None))
        )

    entries = query.all()
    values = [e.value for e in entries]

    # Plain text format for CoreDNS/hosts files
    if format == "hosts":
        content = "\n".join(values)
        return Response(
            content=content,
            media_type="text/plain",
            headers={"X-Generated-At": datetime.utcnow().isoformat()}
        )

    # JSON format
    if entry_type == "domain":
        return {
            "domains": values,
            "generated_at": datetime.utcnow().isoformat()
        }
    elif entry_type == "ip":
        return {
            "ips": values,
            "generated_at": datetime.utcnow().isoformat()
        }
    elif entry_type == "command":
        return {
            "commands": values,
            "generated_at": datetime.utcnow().isoformat()
        }


# =============================================================================
# Secret Management Endpoints
# =============================================================================

@app.get("/api/v1/secrets", response_model=List[SecretResponse])
@limiter.limit("60/minute")  # Read operations
async def get_secrets(
    request: Request,
    db: Session = Depends(get_db),
    token_info: TokenInfo = Depends(require_admin),
    agent_id: Optional[str] = None
):
    """List all managed secrets (metadata only, not values) - admin only.

    Filter by agent_id to see secrets for a specific agent.
    Super admins see all secrets. Tenant admins see only their tenant's secrets.
    """
    query = db.query(Secret)

    # Filter by tenant for non-super-admin
    if not token_info.is_super_admin and token_info.tenant_id:
        tenant_agent_ids = get_tenant_agent_ids(db, token_info.tenant_id)
        query = query.filter(Secret.agent_id.in_(tenant_agent_ids))

    if agent_id:
        # Show only secrets for this specific agent
        query = query.filter(Secret.agent_id == agent_id)

    secrets = query.all()

    result = []
    for s in secrets:
        needs_rotation = False
        if s.last_rotated:
            days_since_rotation = (datetime.utcnow() - s.last_rotated).days
            needs_rotation = days_since_rotation >= s.rotation_days

        result.append(SecretResponse(
            id=s.id,
            name=s.name,
            domain_pattern=s.domain_pattern,
            alias=s.alias,
            header_name=s.header_name,
            header_format=s.header_format,
            description=s.description,
            created_at=s.created_at,
            last_rotated=s.last_rotated,
            rotation_days=s.rotation_days,
            needs_rotation=needs_rotation,
            agent_id=s.agent_id
        ))

    return result


@app.post("/api/v1/secrets")
@limiter.limit("30/minute")  # Admin write operations
async def create_secret(
    request: Request,
    secret: SecretCreate,
    db: Session = Depends(get_db),
    token_info: TokenInfo = Depends(require_admin)
):
    """Create a new secret (encrypted in database) - admin only.

    Set agent_id to scope the secret to a specific agent.
    Leave agent_id as null/empty for global secrets that apply to all agents.
    """
    # Check if secret already exists (same name + same agent scope)
    existing = db.query(Secret).filter(
        Secret.name == secret.name,
        Secret.agent_id == secret.agent_id
    ).first()
    if existing:
        raise HTTPException(status_code=400, detail="Secret already exists for this agent scope")

    try:
        # Encrypt and store in database
        db_secret = Secret(
            name=secret.name,
            encrypted_value=encrypt_secret(secret.value),
            domain_pattern=secret.domain_pattern,
            alias=secret.alias,
            header_name=secret.header_name,
            header_format=secret.header_format,
            description=secret.description,
            rotation_days=secret.rotation_days,
            agent_id=secret.agent_id,
            last_rotated=datetime.utcnow()
        )
        db.add(db_secret)
        db.commit()

        return {
            "status": "created",
            "name": secret.name,
            "domain_pattern": secret.domain_pattern,
            "alias": secret.alias,
            "agent_id": secret.agent_id,
            "devbox_url": f"http://{secret.alias}.devbox.local" if secret.alias else None
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/v1/secrets/{secret_name}/rotate")
async def rotate_secret(
    secret_name: str,
    request: RotateSecretRequest,
    db: Session = Depends(get_db),
    token_info: TokenInfo = Depends(require_admin)
):
    """Rotate a secret (admin only)"""
    secret = db.query(Secret).filter(Secret.name == secret_name).first()
    if not secret:
        raise HTTPException(status_code=404, detail="Secret not found")

    try:
        # Update encrypted value
        secret.encrypted_value = encrypt_secret(request.new_value)
        secret.last_rotated = datetime.utcnow()
        db.commit()

        return {"status": "rotated", "rotated_at": secret.last_rotated.isoformat()}

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/secrets/{secret_name}/value")
async def get_secret_value(
    secret_name: str,
    db: Session = Depends(get_db),
    token_info: TokenInfo = Depends(require_admin)
):
    """Get decrypted secret value (admin only, for credential-injector)"""
    secret = db.query(Secret).filter(Secret.name == secret_name).first()
    if not secret:
        raise HTTPException(status_code=404, detail="Secret not found")

    try:
        return {"name": secret_name, "value": decrypt_secret(secret.encrypted_value)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to decrypt secret: {str(e)}")


@app.delete("/api/v1/secrets/{secret_name}")
async def delete_secret(
    secret_name: str,
    db: Session = Depends(get_db),
    token_info: TokenInfo = Depends(require_admin)
):
    """Delete a secret by name (admin only)."""
    secret = db.query(Secret).filter(Secret.name == secret_name).first()
    if not secret:
        raise HTTPException(status_code=404, detail="Secret not found")

    db.delete(secret)
    db.commit()

    # Log the deletion
    log = AuditLog(
        event_type="secret_deleted",
        user=token_info.token_name or "admin",
        action=f"Secret '{secret_name}' deleted",
        severity="WARNING"
    )
    db.add(log)
    db.commit()

    return {"status": "deleted", "name": secret_name}


def match_domain(pattern: str, domain: str) -> bool:
    """Match domain against pattern (supports wildcard prefix)"""
    if not pattern:
        return False
    if pattern.startswith("*."):
        # Wildcard match: *.github.com matches api.github.com, raw.github.com
        suffix = pattern[1:]  # .github.com
        return domain.endswith(suffix) or domain == pattern[2:]
    return domain == pattern


@app.get("/api/v1/secrets/for-domain")
@limiter.limit("120/minute")  # Envoy calls this frequently (cached 5min client-side)
async def get_credential_for_domain(
    request: Request,
    domain: str,
    db: Session = Depends(get_db),
    token_info: TokenInfo = Depends(verify_token)
):
    """Get credential for a domain (used by Envoy Lua filter - admin or agent).

    Agent tokens receive secrets scoped to their agent + global secrets.
    Agent-specific secrets take precedence over global secrets.

    Handles both:
    - Real domains: api.openai.com -> returns credentials
    - Devbox aliases: openai.devbox.local -> returns real domain + credentials

    Response includes 'target_domain' which is the actual domain to connect to.
    """
    query = db.query(Secret).filter(Secret.domain_pattern.isnot(None))

    # Agent tokens only see their agent's secrets + global secrets
    if token_info.token_type == "agent" and token_info.agent_id:
        query = query.filter(
            (Secret.agent_id == token_info.agent_id) | (Secret.agent_id.is_(None))
        )

    secrets = query.all()

    # Sort so agent-specific secrets come first (take precedence)
    secrets.sort(key=lambda s: (s.agent_id is None, s.id))

    # Check if this is a devbox.local alias lookup
    if domain.endswith(".devbox.local"):
        alias = domain.replace(".devbox.local", "")
        for secret in secrets:
            if secret.alias == alias:
                try:
                    value = decrypt_secret(secret.encrypted_value)
                    header_value = secret.header_format.replace("{value}", value)
                    # For wildcard patterns like *.github.com, use the base domain
                    target_domain = secret.domain_pattern.lstrip("*.")
                    return {
                        "matched": True,
                        "name": secret.name,
                        "domain_pattern": secret.domain_pattern,
                        "target_domain": target_domain,
                        "header_name": secret.header_name,
                        "header_value": header_value
                    }
                except Exception as e:
                    raise HTTPException(status_code=500, detail=f"Failed to decrypt secret: {str(e)}")
        return {"matched": False, "domain": domain}

    # Regular domain lookup
    for secret in secrets:
        if match_domain(secret.domain_pattern, domain):
            try:
                value = decrypt_secret(secret.encrypted_value)
                header_value = secret.header_format.replace("{value}", value)
                return {
                    "matched": True,
                    "name": secret.name,
                    "domain_pattern": secret.domain_pattern,
                    "target_domain": domain,
                    "header_name": secret.header_name,
                    "header_value": header_value
                }
            except Exception as e:
                raise HTTPException(status_code=500, detail=f"Failed to decrypt secret: {str(e)}")

    return {"matched": False, "domain": domain}


# =============================================================================
# Rate Limit Management Endpoints
# =============================================================================

@app.get("/api/v1/rate-limits", response_model=List[RateLimitResponse])
async def get_rate_limits(
    db: Session = Depends(get_db),
    token_info: TokenInfo = Depends(require_admin),
    agent_id: Optional[str] = None
):
    """List all rate limit configurations (admin only).

    Filter by agent_id to see rate limits for a specific agent.
    Super admins see all rate limits. Tenant admins see only their tenant's rate limits.
    """
    query = db.query(RateLimit)

    # Filter by tenant for non-super-admin
    if not token_info.is_super_admin and token_info.tenant_id:
        tenant_agent_ids = get_tenant_agent_ids(db, token_info.tenant_id)
        query = query.filter(RateLimit.agent_id.in_(tenant_agent_ids))

    if agent_id:
        # Show only rate limits for this specific agent
        query = query.filter(RateLimit.agent_id == agent_id)

    return query.all()


@app.post("/api/v1/rate-limits", response_model=RateLimitResponse)
async def create_rate_limit(
    rate_limit: RateLimitCreate,
    db: Session = Depends(get_db),
    token_info: TokenInfo = Depends(require_admin)
):
    """Create a new rate limit configuration (admin only).

    Set agent_id to scope the rate limit to a specific agent.
    Leave agent_id as null/empty for global rate limits that apply to all agents.
    """
    existing = db.query(RateLimit).filter(
        RateLimit.domain_pattern == rate_limit.domain_pattern,
        RateLimit.agent_id == rate_limit.agent_id
    ).first()
    if existing:
        raise HTTPException(status_code=400, detail="Rate limit for this domain already exists for this agent scope")

    db_rate_limit = RateLimit(
        domain_pattern=rate_limit.domain_pattern,
        requests_per_minute=rate_limit.requests_per_minute,
        burst_size=rate_limit.burst_size,
        description=rate_limit.description,
        agent_id=rate_limit.agent_id
    )
    db.add(db_rate_limit)
    db.commit()
    db.refresh(db_rate_limit)
    return db_rate_limit


@app.put("/api/v1/rate-limits/{rate_limit_id}", response_model=RateLimitResponse)
async def update_rate_limit(
    rate_limit_id: int,
    rate_limit: RateLimitUpdate,
    db: Session = Depends(get_db),
    token_info: TokenInfo = Depends(require_admin)
):
    """Update a rate limit configuration (admin only)"""
    db_rate_limit = db.query(RateLimit).filter(RateLimit.id == rate_limit_id).first()
    if not db_rate_limit:
        raise HTTPException(status_code=404, detail="Rate limit not found")

    if rate_limit.requests_per_minute is not None:
        db_rate_limit.requests_per_minute = rate_limit.requests_per_minute
    if rate_limit.burst_size is not None:
        db_rate_limit.burst_size = rate_limit.burst_size
    if rate_limit.description is not None:
        db_rate_limit.description = rate_limit.description
    if rate_limit.enabled is not None:
        db_rate_limit.enabled = rate_limit.enabled

    db.commit()
    db.refresh(db_rate_limit)
    return db_rate_limit


@app.delete("/api/v1/rate-limits/{rate_limit_id}")
async def delete_rate_limit(
    rate_limit_id: int,
    db: Session = Depends(get_db),
    token_info: TokenInfo = Depends(require_admin)
):
    """Delete a rate limit configuration (admin only)"""
    db_rate_limit = db.query(RateLimit).filter(RateLimit.id == rate_limit_id).first()
    if not db_rate_limit:
        raise HTTPException(status_code=404, detail="Rate limit not found")

    db.delete(db_rate_limit)
    db.commit()
    return {"status": "deleted"}


@app.get("/api/v1/rate-limits/for-domain")
@limiter.limit("120/minute")  # Envoy calls this frequently (cached 5min client-side)
async def get_rate_limit_for_domain(
    request: Request,
    domain: str,
    db: Session = Depends(get_db),
    token_info: TokenInfo = Depends(verify_token)
):
    """Get rate limit for a domain (used by Envoy Lua filter - admin or agent).

    Agent tokens receive rate limits scoped to their agent + global rate limits.
    Agent-specific rate limits take precedence over global rate limits.
    """
    query = db.query(RateLimit).filter(RateLimit.enabled == True)

    # Agent tokens only see their agent's rate limits + global rate limits
    if token_info.token_type == "agent" and token_info.agent_id:
        query = query.filter(
            (RateLimit.agent_id == token_info.agent_id) | (RateLimit.agent_id.is_(None))
        )

    rate_limits = query.all()

    # Sort so agent-specific rate limits come first (take precedence)
    rate_limits.sort(key=lambda rl: (rl.agent_id is None, rl.id))

    for rl in rate_limits:
        if match_domain(rl.domain_pattern, domain):
            return {
                "matched": True,
                "domain_pattern": rl.domain_pattern,
                "requests_per_minute": rl.requests_per_minute,
                "burst_size": rl.burst_size
            }

    # Return default rate limit if no specific match
    default_rpm = int(os.environ.get('DEFAULT_RATE_LIMIT_RPM', '120'))
    default_burst = int(os.environ.get('DEFAULT_RATE_LIMIT_BURST', '20'))
    return {
        "matched": False,
        "domain": domain,
        "requests_per_minute": default_rpm,
        "burst_size": default_burst
    }


# =============================================================================
# Data Plane (Agent) Listing Endpoint
# =============================================================================

@app.get("/api/v1/agents", response_model=List[DataPlaneResponse])
async def list_agents(
    db: Session = Depends(get_db),
    token_info: TokenInfo = Depends(verify_token)
):
    """List all connected data planes (agents).

    Super admins see all agents. Tenant admins see only their tenant's agents.
    Excludes __default__ virtual agents and soft-deleted agents from listing.
    """
    query = db.query(AgentState).filter(
        AgentState.agent_id != "__default__",
        AgentState.deleted_at.is_(None)  # Exclude soft-deleted
    )

    # Non-super-admin can only see agents for their tenant
    if not token_info.is_super_admin and token_info.tenant_id:
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
    """
    state = db.query(AgentState).filter(AgentState.agent_id == agent_id).first()
    if not state:
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
            severity="INFO" if heartbeat.last_command_result == "success" else "WARNING"
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
    agent_id: str,
    request: AgentCommandRequest,
    db: Session = Depends(get_db),
    token_info: TokenInfo = Depends(require_admin)
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
    state.pending_command_args = json.dumps({"wipe_workspace": request.wipe_workspace})
    state.pending_command_at = datetime.utcnow()

    # Log the wipe request
    log = AuditLog(
        event_type="agent_wipe_requested",
        user=token_info.token_name or "admin",
        action=f"Wipe requested for {agent_id} (workspace={'wipe' if request.wipe_workspace else 'preserve'})",
        severity="WARNING"
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
    agent_id: str,
    db: Session = Depends(get_db),
    token_info: TokenInfo = Depends(require_admin)
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
    agent_id: str,
    db: Session = Depends(get_db),
    token_info: TokenInfo = Depends(require_admin)
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
    agent_id: str,
    db: Session = Depends(get_db),
    token_info: TokenInfo = Depends(require_admin)
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
    agent_id: str,
    db: Session = Depends(get_db),
    token_info: TokenInfo = Depends(require_admin)
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
        severity="INFO"
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
    agent_id: str,
    db: Session = Depends(get_db),
    token_info: TokenInfo = Depends(require_admin)
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
        severity="WARNING"
    )
    db.add(log)

    # Soft delete the agent
    state.deleted_at = datetime.utcnow()
    state.approved = False
    db.commit()

    return {"status": "rejected", "agent_id": agent_id}


@app.post("/api/v1/agents/{agent_id}/revoke")
async def revoke_agent(
    agent_id: str,
    db: Session = Depends(get_db),
    token_info: TokenInfo = Depends(require_admin)
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
        severity="WARNING"
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
    token_info: TokenInfo = Depends(require_admin)
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
        severity="INFO"
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

        # Audit log
        log = AuditLog(
            event_type="terminal_session_start",
            user=db_token.name,
            container_id=agent_id,
            action=f"Terminal session started for agent {agent_id}",
            details=json.dumps({"session_id": session_id, "client_ip": client_ip}),
            severity="INFO"
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
                severity="INFO"
            )
            db.add(log)
            db.commit()

        db.close()


@app.get("/api/v1/terminal/sessions", response_model=List[TerminalSessionResponse])
async def list_terminal_sessions(
    agent_id: Optional[str] = None,
    limit: int = Query(default=50, le=200),
    db: Session = Depends(get_db),
    token_info: TokenInfo = Depends(require_admin)
):
    """List terminal sessions (admin only).

    Filter by agent_id to see sessions for a specific agent.
    """
    query = db.query(TerminalSession).order_by(TerminalSession.started_at.desc())

    if agent_id:
        query = query.filter(TerminalSession.agent_id == agent_id)

    # Tenant isolation
    if not token_info.is_super_admin and token_info.tenant_id:
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

    # Log tenant creation
    log = AuditLog(
        event_type="tenant_created",
        user=token_info.token_name,
        action=f"Created tenant '{request.name}' (slug: {request.slug})",
        severity="info"
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

    # Log deletion
    log = AuditLog(
        event_type="tenant_deleted",
        user=token_info.token_name,
        action=f"Soft-deleted tenant '{tenant.name}' and {agent_count} agents",
        severity="warning"
    )
    db.add(log)
    db.commit()

    return {"status": "deleted", "tenant_id": tenant_id, "agents_deleted": agent_count}


# =============================================================================
# API Token Management Endpoints
# =============================================================================

@app.get("/api/v1/tokens", response_model=List[ApiTokenResponse])
async def list_tokens(
    db: Session = Depends(get_db),
    token_info: TokenInfo = Depends(require_admin)
):
    """List all API tokens.

    Super admins see all tokens. Tenant admins see only their tenant's tokens.
    """
    query = db.query(ApiToken)

    # Non-super-admin can only see tokens for their tenant
    if not token_info.is_super_admin and token_info.tenant_id:
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
    request: ApiTokenCreate,
    db: Session = Depends(get_db),
    token_info: TokenInfo = Depends(require_admin)
):
    """Create a new API token (admin only).

    The token value is returned only once - save it securely!
    """
    # Validate token type
    if request.token_type not in ["admin", "agent"]:
        raise HTTPException(
            status_code=400,
            detail="token_type must be 'admin' or 'agent'"
        )

    # Agent tokens require agent_id
    if request.token_type == "agent" and not request.agent_id:
        raise HTTPException(
            status_code=400,
            detail="agent_id is required for agent tokens"
        )

    # Admin tokens should not have agent_id
    if request.token_type == "admin" and request.agent_id:
        raise HTTPException(
            status_code=400,
            detail="admin tokens should not have an agent_id"
        )

    # Only super admins can create super admin tokens
    if request.is_super_admin and not token_info.is_super_admin:
        raise HTTPException(
            status_code=403,
            detail="Only super admins can create super admin tokens"
        )

    # Determine tenant_id for the new token
    new_tenant_id = request.tenant_id
    if request.token_type == "agent" and request.agent_id:
        # For agent tokens, try to get tenant from the agent (if it exists)
        # Allow pre-provisioning tokens for agents that don't exist yet
        agent = db.query(AgentState).filter(
            AgentState.agent_id == request.agent_id,
            AgentState.deleted_at.is_(None)
        ).first()
        if agent:
            new_tenant_id = agent.tenant_id
    elif not request.is_super_admin and not new_tenant_id:
        # Non-super-admin tokens default to creator's tenant
        new_tenant_id = token_info.tenant_id

    # Check for duplicate name
    existing = db.query(ApiToken).filter(ApiToken.name == request.name).first()
    if existing:
        raise HTTPException(status_code=400, detail="Token with this name already exists")

    # Generate token
    raw_token = generate_token()
    token_hash_value = hash_token(raw_token)

    # Calculate expiry
    expires_at = None
    if request.expires_in_days:
        expires_at = datetime.utcnow() + timedelta(days=request.expires_in_days)

    # Validate roles
    valid_roles = {"admin", "developer"}
    requested_roles = set(r.strip() for r in (request.roles or "admin").split(","))
    invalid_roles = requested_roles - valid_roles
    if invalid_roles:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid roles: {invalid_roles}. Valid roles are: {valid_roles}"
        )
    roles_str = ",".join(sorted(requested_roles))

    # Create token record
    db_token = ApiToken(
        name=request.name,
        token_hash=token_hash_value,
        token_type=request.token_type,
        agent_id=request.agent_id,
        tenant_id=new_tenant_id,
        is_super_admin=request.is_super_admin,
        roles=roles_str,
        expires_at=expires_at
    )
    db.add(db_token)

    # Log token creation
    log = AuditLog(
        event_type="token_created",
        user=token_info.token_name or "admin",
        action=f"Token '{request.name}' created (type={request.token_type}, roles={roles_str}, super_admin={request.is_super_admin})",
        details=f"agent_id={request.agent_id}, tenant_id={new_tenant_id}" if request.agent_id else f"tenant_id={new_tenant_id}",
        severity="INFO"
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
    token_id: int,
    db: Session = Depends(get_db),
    token_info: TokenInfo = Depends(require_admin)
):
    """Delete an API token (admin only)."""
    db_token = db.query(ApiToken).filter(ApiToken.id == token_id).first()
    if not db_token:
        raise HTTPException(status_code=404, detail="Token not found")

    token_name = db_token.name

    # Log token deletion
    log = AuditLog(
        event_type="token_deleted",
        user=token_info.token_name or "admin",
        action=f"Token '{token_name}' deleted",
        severity="WARNING"
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
    token_info: TokenInfo = Depends(require_admin)
):
    """Update an API token (enable/disable)."""
    db_token = db.query(ApiToken).filter(ApiToken.id == token_id).first()
    if not db_token:
        raise HTTPException(status_code=404, detail="Token not found")

    if enabled is not None:
        db_token.enabled = enabled

        # Log the change
        action = "enabled" if enabled else "disabled"
        log = AuditLog(
            event_type=f"token_{action}",
            user=token_info.token_name or "admin",
            action=f"Token '{db_token.name}' {action}",
            severity="INFO"
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
