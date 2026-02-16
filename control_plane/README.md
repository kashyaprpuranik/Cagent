# Cagent - Control Plane

The control plane provides centralized management, policy enforcement, secrets storage, and observability for the AI Devbox platform.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                       Control Plane                              │
│                                                                  │
│  ┌─────────────┐    ┌──────────────┐    ┌─────────────┐        │
│  │  Admin UI   │───►│ Control Plane│───►│  PostgreSQL │        │
│  │  (React)    │    │     API      │    │  (state)    │        │
│  └─────────────┘    └──────────────┘    └─────────────┘        │
│        │                   │                                    │
│        │                   │ (read/write logs)                  │
│        │                   ▼                                    │
│        │            ┌─────────────┐                             │
│        └───────────►│  Log Store  │                             │
│                     │ (logs + UI) │                             │
│                     └─────────────┘                             │
│                            ▲                                    │
└────────────────────────────│────────────────────────────────────┘
                             │ (CP forwards logs with trusted identity)
        ┌────────────────────┼────────────────────────────────┐
        │                    │                                │
┌───────┴──────┐  ┌──────────┴────┐  ┌───────────────┐
│ Data Plane 1 │  │ Data Plane 2  │  │ Data Plane N  │
│ (agent-mgr)  │  │ (agent-mgr)   │  │ (agent-mgr)   │
└──────────────┘  └───────────────┘  └───────────────┘
      │                  │                   │
      └──────── heartbeat/poll + logs (outbound) ───┘
```

**Log Flow**:
- **Write**: Data plane → Control Plane API → OpenObserve (CP-mediated for security)
- **Read**: Admin UI → Control Plane API → OpenObserve (proxied queries with tenant filtering)

**Multi-Data Plane Management**:
- Each data plane has a unique `agent_id`
- Admin UI shows data plane selector to switch between managed instances
- All commands (start/stop/restart/wipe) are per-agent

**Multi-Tenancy**:
- Tenants are organizational units that group agents
- Each agent belongs to exactly one tenant
- Domain policies can be:
  - **Tenant-global**: Uses special `__default__` agent ID, applies to all agents in tenant
  - **Agent-specific**: Scoped to a single agent, takes precedence over tenant-global
- Token scoping:
  - **Super admin**: Access to all tenants (platform operators)
  - **Admin**: Scoped to a single tenant
  - **Agent**: Scoped to a single agent within a tenant

## Services

| Service | Port | Description |
|---------|------|-------------|
| backend | 8002 | FastAPI REST API |
| frontend | 9080 | React admin console |
| log-store | 5080 | Log storage & UI (OpenObserve) |
| db | 5432 | State storage (internal) |
| cache | 6379 | Rate limiting store (internal) |
| tunnel-server | 7000 | Tunnel server for STCP access |

## STCP Tunnel Management

The CP manages STCP secrets for FRP-based SSH tunnels but does not relay terminal traffic. Terminal access is via direct SSH (port 2222) or the data plane's local admin web terminal.

**STCP Mode**: Uses FRP's Secret TCP mode — all tunnels go through a single port (7000) with secret-key authentication. No port-per-agent allocation needed. Traffic is relayed through the FRP server.

**API Endpoints:**

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/agents/{agent_id}/stcp-secret` | Generate new STCP secret (admin) |
| GET | `/api/v1/agents/{agent_id}/stcp-config` | Get STCP visitor config (developer) |

## Quick Start

```bash
cd control_plane

# Create .env with encryption key
cp .env.example .env
export ENCRYPTION_KEY=$(python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())")
# Add ENCRYPTION_KEY to .env

# Start control plane
docker compose up -d

# Access services:
# - Admin UI:     http://localhost:9080
# - API Docs:     http://localhost:8002/docs
# - Log Store:    http://localhost:5080 (admin@cagent.local/admin)
```

## API Documentation

The control plane API is built with FastAPI and auto-generates OpenAPI documentation:

- **Swagger UI**: http://localhost:8002/docs
- **ReDoc**: http://localhost:8002/redoc
- **OpenAPI JSON**: http://localhost:8002/openapi.json

## API Endpoints

### Health & Info

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health` | Health check |
| GET | `/api/v1/info` | System information |
| GET | `/api/v1/auth/me` | Current user info from token |

### Domain Policies (Unified)

Domain policies combine allowlist, path filtering, rate limits, and credentials in one resource.

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/domain-policies` | List all domain policies |
| POST | `/api/v1/domain-policies` | Create domain policy |
| GET | `/api/v1/domain-policies/{id}` | Get domain policy |
| PUT | `/api/v1/domain-policies/{id}` | Update domain policy |
| DELETE | `/api/v1/domain-policies/{id}` | Delete domain policy |
| POST | `/api/v1/domain-policies/{id}/rotate-credential` | Rotate credential |
| GET | `/api/v1/domain-policies/for-domain` | Lookup policy by domain (for Envoy) |
| GET | `/api/v1/domain-policies/export` | Export policies (CoreDNS format) |

### Audit Logs (Admin/CP Operations)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/audit-trail` | Query audit trail (tenant-filtered) |

### Agent Logs (Data Plane Operations)

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/logs/ingest` | Ingest logs from data plane (agent token) |
| GET | `/api/v1/logs/query` | Query agent logs (tenant-filtered) |

**Log Ingestion Security**:
- Only agent tokens can ingest logs
- CP injects trusted `agent_id` and `tenant_id` from the verified token
- Data planes never have direct access to OpenObserve credentials
- Prevents identity spoofing (agents cannot claim to be other agents/tenants)

### Multi-Data Plane Management (Polling-based)

The control plane can manage multiple data planes. Each data plane has an agent-manager that polls the control plane for commands.

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/agents` | List all connected data planes |
| POST | `/api/v1/agent/heartbeat` | Receive heartbeat from agent-manager, return pending command |
| GET | `/api/v1/agents/{agent_id}/status` | Get agent status from last heartbeat |
| POST | `/api/v1/agents/{agent_id}/wipe` | Queue wipe command (admin) |
| POST | `/api/v1/agents/{agent_id}/restart` | Queue restart command (admin) |
| POST | `/api/v1/agents/{agent_id}/stop` | Queue stop command (admin) |
| POST | `/api/v1/agents/{agent_id}/start` | Queue start command (admin) |

All connections are outbound from data plane - no inbound ports needed on data plane.

### API Token Management

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/tokens` | List all API tokens (admin) |
| POST | `/api/v1/tokens` | Create new token (admin) |
| DELETE | `/api/v1/tokens/{id}` | Delete token (admin) |
| PATCH | `/api/v1/tokens/{id}` | Enable/disable token (admin) |

### Tenant Management

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/tenants` | List all tenants (super admin) |
| POST | `/api/v1/tenants` | Create new tenant (super admin) |
| GET | `/api/v1/tenants/{id}` | Get tenant details (super admin) |
| DELETE | `/api/v1/tenants/{id}` | Delete tenant (super admin) |

### IP Access Control (IP ACLs)

Restrict control plane access to specific IP ranges per tenant.

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/tenants/{tenant_id}/ip-acls` | List IP ACLs for tenant |
| POST | `/api/v1/tenants/{tenant_id}/ip-acls` | Create IP ACL entry |
| PATCH | `/api/v1/tenants/{tenant_id}/ip-acls/{acl_id}` | Update IP ACL entry |
| DELETE | `/api/v1/tenants/{tenant_id}/ip-acls/{acl_id}` | Delete IP ACL entry |

**How IP ACLs work:**
- If no IP ACLs are configured for a tenant, all IPs are allowed (default)
- Once any ACL is added, only matching IPs can access the control plane
- Agent tokens (used by data planes) are not affected by IP ACLs
- CIDR notation: use `/32` for single IP, `/24` for subnet, etc.

## Authentication

All API endpoints (except `/health` and `/api/v1/info`) require Bearer token authentication:

```bash
curl -H "Authorization: Bearer $TOKEN" http://localhost:8002/api/v1/domain-policies
```

### Token Types & Roles

| Type | Role | Super Admin | Access |
|------|------|-------------|--------|
| `admin` | `admin` | Yes | **All access** - tenants, all endpoints, OpenObserve link |
| `admin` | `admin` | No | **Tenant admin** - domain policies, agents, tokens, IP ACLs, audit trail (tenant-scoped) |
| `admin` | `developer` | No | **Developer** - dashboard (read-only), agent logs, web terminal, settings |
| `agent` | - | No | **Data plane** - heartbeat, domain-policies/for-domain (agent-scoped) |

**UI Access by Role:**

| Page | Super Admin | Admin | Developer |
|------|-------------|-------|-----------|
| Dashboard | ✓ | ✓ | ✓ (read-only) |
| Domain Policies | ✓ | ✓ | ✗ |
| IP ACLs | ✓ | ✓ | ✗ |
| API Tokens | ✓ | ✓ | ✗ |
| Tenants | ✓ | ✗ | ✗ |
| Admin Logs | ✓ | ✓ | ✗ |
| Agent Logs | ✓ | ✓ | ✓ |
| Settings | ✓ | ✓ | ✓ |
| Web Terminal | ✓ | ✓ | ✓ |
| OpenObserve Link | ✓ | ✗ | ✗ |

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `DATABASE_URL` | - | PostgreSQL connection string |
| `ENCRYPTION_KEY` | - | Fernet key for secret encryption (required) |
| `CORS_ORIGINS` | `*` | Allowed CORS origins (comma-separated) |
| `OPENOBSERVE_URL` | `http://log-store:5080` | OpenObserve URL for log queries |
| `REDIS_URL` | `redis://cache:6379` | Redis URL for rate limiting |
| `DEFAULT_RATE_LIMIT_RPM` | `120` | Default requests per minute for unlisted domains |
| `DEFAULT_RATE_LIMIT_BURST` | `20` | Default burst size for unlisted domains |

## Cross-Machine Deployment

The control plane manages multiple data planes, which can run on different machines.

**Architecture (polling-based):**
```
Data Plane 1                            Control Plane
┌─────────────┐                        ┌─────────────┐
│ HTTP Proxy  │ ────── :8002 ───────►  │     API     │
│agent-manager│ ────── :8002 ───────►  │  (manages)  │
└─────────────┘   (heartbeat + logs)   │             │
                                       │  Multiple   │
Data Plane 2                           │   Agents    │
┌─────────────┐                        │             │
│ HTTP Proxy  │ ────── :8002 ───────►  │     ▼       │
│agent-manager│ ────── :8002 ───────►  │  Log Store  │
└─────────────┘   (heartbeat + logs)   └─────────────┘
```

Logs are sent to the Control Plane API (`/api/v1/logs/ingest`), which injects trusted `agent_id` and `tenant_id` before forwarding to OpenObserve. Data planes never have direct access to OpenObserve credentials.

All connections are outbound from data planes - no inbound ports needed on data planes.

**Network requirements (control plane perspective):**

| From | To | Port | Purpose |
|------|-----|------|---------|
| Data plane (Envoy) | Control plane | 8002 | Credential/rate-limit lookups |
| Data plane (agent-manager) | Control plane | 8002 | Heartbeat polling + log ingestion |
| Data plane (frpc) | Control plane | 7000 | STCP tunnel for terminal |

Note: Logs are shipped via the Control Plane API (port 8002), not directly to OpenObserve. This ensures agent identity is verified and prevents credential exposure on data planes.

**Data plane configuration:**
Each data plane authenticates with its agent token (which maps to a unique agent_id on the control plane):
```bash
CONTROL_PLANE_URL=http://control-plane-host:8002
CONTROL_PLANE_TOKEN=your-token  # Agent token (encodes agent_id)
```

**Tenant-global configuration:**
Each tenant has a virtual `__default__` agent that holds tenant-wide defaults. Configuration attached to `__default__` applies to all agents in the tenant unless overridden by agent-specific config.

## Data Models

### Domain Policy

```json
{
  "id": 1,
  "domain": "api.openai.com",
  "alias": "openai",
  "description": "OpenAI API",
  "allowed_paths": ["/v1/chat/*", "/v1/models", "/v1/embeddings"],
  "requests_per_minute": 60,
  "burst_size": 10,
  "credential_header": "Authorization",
  "credential_format": "Bearer {value}",
  "agent_id": null,
  "tenant_id": 1
}
```

The `alias` field creates a `*.devbox.local` mapping:
- `alias: "openai"` → Agent uses `http://openai.devbox.local/...`
- Envoy maps to `api.openai.com` and injects credentials

The `agent_id` field scopes the policy:
- `null` or `"__default__"`: Tenant-global (applies to all agents)
- `"agent-id"`: Agent-specific (overrides tenant-global for that agent)

### Tenant

```json
{
  "id": 1,
  "name": "Acme Corporation",
  "slug": "acme-corp",
  "created_at": "2024-01-15T10:30:00Z",
  "agent_count": 5
}
```

Tenants are organizational units. Each tenant automatically gets a `__default__` agent for tenant-global configuration.

### Tenant IP ACL

```json
{
  "id": 1,
  "tenant_id": 1,
  "cidr": "192.168.1.0/24",
  "description": "Office network",
  "enabled": true,
  "created_at": "2024-01-15T10:30:00Z",
  "created_by": "admin-token"
}
```

IP ACLs restrict which IP addresses can access the control plane for a given tenant. Uses CIDR notation for IP ranges.

## Development

See [docs/development.md](../docs/development.md) for local development setup, database seeding, testing, and dev tooling.

## Files

```
control_plane/
├── docker-compose.yml          # Service orchestration
├── .env.example                # Environment template
├── configs/
│   └── frps/
│       └── frps.toml           # FRP server config (STCP mode)
└── services/
    ├── backend/
    │   ├── main.py             # FastAPI application (facade)
    │   ├── control_plane/      # Python package (routes, models, auth, etc.)
    │   ├── seed.py             # Database seeder (auth infrastructure)
    │   ├── post_seed.py        # Post-seed (domain policies, IP ACLs via API)
    │   ├── entrypoint.sh       # Docker entrypoint (migrations + auto-seed)
    │   ├── requirements.txt
    │   └── Dockerfile
    └── frontend/
        ├── src/                # React application
        ├── package.json
        └── Dockerfile
```
