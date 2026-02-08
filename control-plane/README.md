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
│        └───────────►│ OpenObserve │                             │
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
- Configuration (secrets, allowlist, rate limits) can be:
  - **Tenant-global**: Uses special `__default__` agent ID, applies to all agents in tenant
  - **Agent-specific**: Scoped to a single agent, takes precedence over tenant-global
- Token scoping:
  - **Super admin**: Access to all tenants (platform operators)
  - **Admin**: Scoped to a single tenant
  - **Agent**: Scoped to a single agent within a tenant

## Services

| Service | Port | Description |
|---------|------|-------------|
| control-plane-api | 8002 | FastAPI REST API |
| admin-ui | 9080 | React admin console |
| openobserve | 5080 | Log storage & UI |
| postgres | 5432 | State storage (internal) |
| redis | 6379 | Rate limiting store (internal) |
| frps | 7000 | FRP server for STCP tunnels |

## Web Terminal

The Admin UI includes a browser-based terminal (xterm.js) for accessing agent containers. This requires the `developer` role.

**Architecture:**
```
Browser (xterm.js) → WebSocket → Control Plane API → STCP → FRP → Agent:22
```

**STCP Mode**: Uses FRP's Secret TCP mode - all tunnels go through a single port (7000) with secret-key authentication. No port-per-agent allocation needed.

**Setup:**

1. Generate STCP secret for the agent:
   ```bash
   curl -X POST http://localhost:8002/api/v1/agents/my-agent/stcp-secret \
     -H "Authorization: Bearer admin-token"
   ```

2. Configure data plane with the secret (see data-plane README)

3. Access terminal from Admin UI Dashboard

**API Endpoints:**

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/agents/{agent_id}/stcp-secret` | Generate new STCP secret (admin) |
| GET | `/api/v1/agents/{agent_id}/stcp-config` | Get STCP visitor config (developer) |
| WS | `/api/v1/terminal/{agent_id}/ws` | WebSocket terminal endpoint |
| GET | `/api/v1/terminal/sessions` | List terminal sessions (audit) |

## Quick Start

```bash
# Generate encryption key for secrets
export ENCRYPTION_KEY=$(python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())")

# Start control plane
docker-compose up -d

# Access services:
# - Admin UI:     http://localhost:9080
# - API Docs:     http://localhost:8002/docs
# - OpenObserve:  http://localhost:5080 (admin@cagent.local/admin)
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

### Secrets Management

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/secrets` | List all secrets (metadata only) |
| POST | `/api/v1/secrets` | Create a new secret |
| POST | `/api/v1/secrets/{name}/rotate` | Rotate a secret |
| DELETE | `/api/v1/secrets/{name}` | Delete a secret |
| GET | `/api/v1/secrets/{name}/value` | Get decrypted secret value |
| GET | `/api/v1/secrets/for-domain` | Lookup secret by domain or alias (for Envoy) |

Domain aliases (e.g., `openai.devbox.local` → `api.openai.com`) are configured via the `alias` field on secrets. See [Data Models](#data-models) below.

### Rate Limits

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/rate-limits` | List all rate limits |
| POST | `/api/v1/rate-limits` | Create rate limit |
| PUT | `/api/v1/rate-limits/{id}` | Update rate limit |
| DELETE | `/api/v1/rate-limits/{id}` | Delete rate limit |
| GET | `/api/v1/rate-limits/for-domain` | Lookup rate limit by domain (for Envoy) |

### Allowlist

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/allowlist` | List allowlist entries |
| POST | `/api/v1/allowlist` | Add allowlist entry |
| DELETE | `/api/v1/allowlist/{id}` | Remove allowlist entry |
| GET | `/api/v1/allowlist/export` | Export allowlist (CoreDNS format) |

### Audit Logs (Admin/CP Operations)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/audit-logs` | Query audit logs (tenant-filtered) |
| POST | `/api/v1/audit-logs` | Create audit log entry |

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
| POST | `/api/v1/agents/{agent_id}/wipe` | Queue wipe command (picked up on next heartbeat) |
| POST | `/api/v1/agents/{agent_id}/restart` | Queue restart command |
| POST | `/api/v1/agents/{agent_id}/stop` | Queue stop command |
| POST | `/api/v1/agents/{agent_id}/start` | Queue start command |

All connections are outbound from data plane - no inbound ports needed on data plane.

### API Token Management

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/tokens` | List all API tokens (admin only) |
| POST | `/api/v1/tokens` | Create new token (admin only) |
| DELETE | `/api/v1/tokens/{id}` | Delete token (admin only) |
| PATCH | `/api/v1/tokens/{id}` | Enable/disable token (admin only) |

### Tenant Management

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/tenants` | List all tenants (super admin only) |
| POST | `/api/v1/tenants` | Create new tenant (super admin only) |
| DELETE | `/api/v1/tenants/{id}` | Delete tenant (super admin only) |

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

### Agent Approval

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/v1/agents/{agent_id}/approve` | Approve agent (admin only) |
| POST | `/api/v1/agents/{agent_id}/reject` | Reject and remove agent (admin only) |
| POST | `/api/v1/agents/{agent_id}/revoke` | Revoke agent approval (admin only) |

## Authentication

All API endpoints (except `/health` and `/api/v1/info`) require Bearer token authentication:

```bash
curl -H "Authorization: Bearer your-token" http://localhost:8002/api/v1/secrets
```

### Token Types & Roles

| Type | Role | Super Admin | Access |
|------|------|-------------|--------|
| `admin` | `admin` | Yes | **All access** - tenants, all endpoints, OpenObserve link |
| `admin` | `admin` | No | **Tenant admin** - secrets, allowlist, agents, tokens, rate-limits, IP ACLs, audit-logs (tenant-scoped) |
| `admin` | `developer` | No | **Developer** - dashboard, agent logs, web terminal, settings only |
| `agent` | - | No | **Data plane** - heartbeat, secrets/for-domain, rate-limits/for-domain (agent-scoped) |

**UI Access by Role:**

| Page | Super Admin | Admin | Developer |
|------|-------------|-------|-----------|
| Dashboard | ✓ | ✓ | ✓ |
| Secrets | ✓ | ✓ | ✗ |
| Allowlist | ✓ | ✓ | ✗ |
| Rate Limits | ✓ | ✓ | ✗ |
| IP ACLs | ✓ | ✓ | ✗ |
| API Tokens | ✓ | ✓ | ✗ |
| Tenants | ✓ | ✗ | ✗ |
| Admin Logs | ✓ | ✓ | ✗ |
| Agent Logs | ✓ | ✓ | ✓ |
| Settings | ✓ | ✓ | ✓ |
| Web Terminal | ✓ | ✓ | ✓ |
| OpenObserve Link | ✓ | ✗ | ✗ |

### Default Development Tokens

The following tokens are automatically seeded for development:

| Token Name | Raw Token | Role | Super Admin | Tenant |
|------------|-----------|------|-------------|--------|
| `super-admin-token` | `super-admin-test-token-do-not-use-in-production` | admin | Yes | All |
| `admin-token` | `admin-test-token-do-not-use-in-production` | admin | No | default |
| `dev-token` | `dev-test-token-do-not-use-in-production` | developer | No | default |

### Token Sources

1. **Database tokens** (recommended): Created via API or Admin UI
2. **Legacy tokens** (dev only): `API_TOKENS` environment variable (treated as admin tokens)

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `DATABASE_URL` | - | PostgreSQL connection string |
| `ENCRYPTION_KEY` | - | Fernet key for secret encryption |
| `API_TOKENS` | `dev-token` | Comma-separated allowed API tokens |
| `OPENOBSERVE_URL` | `http://openobserve:5080` | OpenObserve URL for log queries |
| `REDIS_URL` | `redis://redis:6379` | Redis URL for rate limiting |
| `DEFAULT_RATE_LIMIT_RPM` | `120` | Default requests per minute for unlisted domains |
| `DEFAULT_RATE_LIMIT_BURST` | `20` | Default burst size for unlisted domains |

## Cross-Machine Deployment

The control plane manages multiple data planes, which can run on different machines.

**Architecture (polling-based):**
```
Data Plane 1                            Control Plane
┌─────────────┐                        ┌─────────────┐
│   Envoy     │ ────── :8002 ───────►  │     API     │
│agent-manager│ ────── :8002 ───────►  │  (manages)  │
└─────────────┘   (heartbeat + logs)   │             │
                                       │  Multiple   │
Data Plane 2                           │   Agents    │
┌─────────────┐                        │             │
│   Envoy     │ ────── :8002 ───────►  │     ▼       │
│agent-manager│ ────── :8002 ───────►  │ OpenObserve │
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
Each data plane needs a unique `AGENT_ID` in its `.env` file:
```bash
AGENT_ID=workstation-1  # Unique identifier for this data plane
CONTROL_PLANE_URL=http://control-plane-host:8002
CONTROL_PLANE_TOKEN=your-token  # Agent token scoped to this agent_id
```

**Tenant-global configuration:**
Each tenant has a virtual `__default__` agent that holds tenant-wide defaults. Configuration attached to `__default__` applies to all agents in the tenant unless overridden by agent-specific config.

## Data Models

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

### Secret

```json
{
  "name": "openai-api-key",
  "domain_pattern": "api.openai.com",
  "alias": "openai",
  "header_name": "Authorization",
  "header_format": "Bearer {value}",
  "rotation_days": 90,
  "agent_id": null
}
```

The `alias` field creates a `*.devbox.local` mapping:
- `alias: "openai"` → Agent uses `http://openai.devbox.local/...`
- Envoy maps to `api.openai.com` and injects credentials

The `agent_id` field scopes the secret:
- `null` or `"__default__"`: Tenant-global (applies to all agents)
- `"agent-id"`: Agent-specific (overrides tenant-global for that agent)

### Rate Limit

```json
{
  "domain_pattern": "api.openai.com",
  "requests_per_minute": 60,
  "burst_size": 10,
  "enabled": true,
  "agent_id": null
}
```

### Allowlist Entry

```json
{
  "entry_type": "domain",
  "value": "api.openai.com",
  "description": "OpenAI API",
  "enabled": true,
  "agent_id": null
}
```

Entry types: `domain`, `ip`, `command`

All configuration models support `agent_id` for scoping (null = tenant-global, specific ID = agent-only).

## Development

```bash
# Run locally (requires PostgreSQL)
cd services/control-plane
pip install -r requirements.txt
uvicorn main:app --reload --port 8000

# Run tests
pytest tests/ -v
```

## Database Seeding

The database is automatically seeded on first startup (when no agents exist). You can also seed manually:

```bash
cd services/control-plane

# Seed with defaults
python seed.py

# Reset and reseed
python seed.py --reset

# Show generated tokens
python seed.py --show-token
```

Default seed data includes:
- Default tenant with slug `default`
- `__default__` agent for tenant-global config
- `admin-token` - Super admin token (role: admin)
- `dev-token` - Developer token (role: developer)
- Test agents (`test-agent`, `pending-agent`)
- Sample allowlist entries, rate limits, and secrets

## Files

```
control-plane/
├── docker-compose.yml          # Service orchestration
├── deploy.sh                   # Deploy script (down, build, up)
├── configs/
│   └── frps/
│       └── frps.toml           # FRP server config (STCP mode)
└── services/
    ├── control-plane/
    │   ├── main.py             # FastAPI application
    │   ├── seed.py             # Database seeder
    │   ├── entrypoint.sh       # Docker entrypoint (migrations + auto-seed)
    │   ├── requirements.txt
    │   └── Dockerfile
    └── admin-ui/
        ├── src/                # React application
        ├── package.json
        └── Dockerfile
```
