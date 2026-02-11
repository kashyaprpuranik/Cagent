from datetime import datetime

from sqlalchemy import Column, Integer, String, DateTime, Text, Boolean, ForeignKey, UniqueConstraint, JSON
from sqlalchemy.orm import relationship

from control_plane.database import Base


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


class AuditTrail(Base):
    __tablename__ = "audit_trail"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    event_type = Column(String(50), index=True)
    user = Column(String(100), index=True)
    container_id = Column(String(100))
    action = Column(String(200))
    details = Column(Text)
    severity = Column(String(20), index=True)
    # Target tenant whose data was affected (every auditable action has a target tenant).
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

    # Envoy config options
    timeout = Column(String(20))  # e.g., "30s", "120s", "5m"
    read_only = Column(Boolean, default=False)  # Block POST/PUT/DELETE

    # Temporary allowlist: auto-expire after this timestamp
    expires_at = Column(DateTime, nullable=True, index=True)

    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    __table_args__ = (
        # Unique constraint: one policy per domain per agent per tenant
        UniqueConstraint('domain', 'agent_id', 'tenant_id', name='uq_domain_policy_tenant'),
    )


class EmailPolicy(Base):
    """Email account policy: provider, allowlists, rate limits, encrypted credentials."""
    __tablename__ = "email_policies"

    id = Column(Integer, primary_key=True, index=True)
    tenant_id = Column(Integer, ForeignKey("tenants.id"), nullable=False, index=True)
    name = Column(String(100), nullable=False)  # Unique per tenant, e.g. "work-gmail"
    provider = Column(String(20), nullable=False)  # gmail, outlook, generic
    email = Column(String(200), nullable=False)  # e.g. agent@company.com
    enabled = Column(Boolean, default=True, index=True)
    agent_id = Column(String(100), nullable=True, index=True)  # NULL = tenant-global

    # Server overrides (NULL = use provider defaults)
    imap_server = Column(String(200))
    imap_port = Column(Integer)
    smtp_server = Column(String(200))
    smtp_port = Column(Integer)

    # Policy
    allowed_recipients = Column(JSON, default=list)  # ["*@company.com", "user@ext.com"]
    allowed_senders = Column(JSON, default=list)  # ["*"] = any
    sends_per_hour = Column(Integer)
    reads_per_hour = Column(Integer)

    # Encrypted credentials (OAuth2 or password)
    credential_type = Column(String(20))  # oauth2, password
    credential_data_encrypted = Column(Text)  # Fernet-encrypted JSON blob

    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    __table_args__ = (
        UniqueConstraint('name', 'tenant_id', name='uq_email_policy_name_tenant'),
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


class WebSocketTicket(Base):
    """Short-lived, single-use tickets for WebSocket authentication.

    Instead of passing long-lived API tokens as query params (which get logged
    by proxies), clients obtain a ticket via a proper REST call with Authorization
    header, then pass the ticket to the WebSocket.
    """
    __tablename__ = "websocket_tickets"

    id = Column(Integer, primary_key=True, index=True)
    ticket_hash = Column(String(64), unique=True, index=True)  # SHA-256 hash
    api_token_id = Column(Integer, ForeignKey("api_tokens.id"), nullable=False)
    agent_id = Column(String(100), nullable=False)
    tenant_id = Column(Integer, ForeignKey("tenants.id"), nullable=True)
    # Cached from the creating token for use during WS validation
    token_name = Column(String(100), nullable=False)
    roles = Column(String(200), nullable=False)
    is_super_admin = Column(Boolean, default=False)
    used = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=False)


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
