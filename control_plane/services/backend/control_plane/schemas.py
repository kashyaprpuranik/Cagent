from datetime import datetime
from typing import Optional, List

from pydantic import BaseModel


class AuditTrailResponse(BaseModel):
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
    created_at: Optional[datetime] = None
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
    proxy_name: str  # FRP proxy name ("{agent_id}-ssh")
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


class TerminalTicketResponse(BaseModel):
    """Response when creating a WebSocket terminal ticket."""
    ticket: str
    expires_in_seconds: int


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
