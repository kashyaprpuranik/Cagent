# AI Devbox

Secure development environment for AI agents with isolated networking and centralized control.

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                           CONTROL PLANE (control-net)                            │
│                           (runs on provider/cloud)                               │
│                                                                                  │
│  ┌───────────┐  ┌───────────┐  ┌───────────┐  ┌───────────┐  ┌───────────────┐ │
│  │ Postgres  │  │ Admin UI  │  │   Loki    │  │  Grafana  │  │  FRP Server   │ │
│  │ (secrets) │  │  (:9080)  │  │  (:3100)  │  │  (:3000)  │  │ (:7000,:6000+)│ │
│  └─────┬─────┘  └─────┬─────┘  └─────┬─────┘  └─────┬─────┘  └───────┬───────┘ │
│        │              │              │              │                 │         │
│        ▼              ▼              │              │                 │         │
│  ┌────────────────────────────────┐  │              │                 │         │
│  │     Control Plane API (:8002)  │  │              │                 │         │
│  │                                │  │              │                 │         │
│  │  /api/v1/secrets    Secrets    │  │              │                 │         │
│  │  /api/v1/allowlist  Allowlist  │  │              │                 │         │
│  │  /api/v1/agents     Agent Mgmt │  │              │                 │         │
│  │  /api/v1/rate-limits Rate Limits│ │              │                 │         │
│  └────────────────────────────────┘  │              │                 │         │
│                 ▲                     │              │                 │         │
└─────────────────┼─────────────────────┼──────────────┼─────────────────┼─────────┘
                  │                     │              │                 │
                  │ Heartbeat/Commands  │ Logs         │ Dashboards      │ SSH Tunnels
                  │                     │              │                 │
┌─────────────────┼─────────────────────┼──────────────┼─────────────────┼─────────┐
│                 │          DATA PLANE │              │                 │         │
│                 │     (runs on client)│              │                 │         │
│                 │                     │              │                 ▼         │
│  ┌──────────────┴───────────┐  ┌──────┴───────┐            ┌─────────────────┐  │
│  │      Agent Manager       │  │  Fluent-Bit  │────────┘   │   FRP Client    │  │
│  │  (polls CP, syncs DNS)   │  │   (logs)     │            │ (connects to CP)│  │
│  └──────────────────────────┘  └──────────────┘            └────────┬────────┘  │
│                                                                      │          │
│  ┌───────────────────────────────────────────────────────────────────┼────────┐ │
│  │                        agent-net (isolated)                       │        │ │
│  │  ┌────────────────────────────────────────────────────────────────┼──────┐ │ │
│  │  │                     Agent Container                            │      │ │ │
│  │  │  • Isolated network (no direct internet access)                │      │ │ │
│  │  │  • All HTTP(S) via Envoy proxy                              SSH:22    │ │ │
│  │  │  • DNS via CoreDNS filter (allowlist enforced)                 │      │ │ │
│  │  └────────────────────────────────────────────────────────────────┼──────┘ │ │
│  │              │                           │                        │        │ │
│  │              ▼                           ▼                        │        │ │
│  │       ┌─────────────┐             ┌─────────────┐                 │        │ │
│  │       │   Envoy     │             │   CoreDNS   │                 │        │ │
│  │       │  (+ creds)  │             │  (filter)   │                 │        │ │
│  │       └─────────────┘             └─────────────┘                 │        │ │
│  └───────────────────────────────────────────────────────────────────┼────────┘ │
└──────────────────────────────────────────────────────────────────────┼──────────┘
                                                                       │
                                                            User SSH ──┘
```

## Security Model

### Network Isolation
- **agent-net**: Internal network, no external access. Agent can only reach Envoy and CoreDNS.
- **infra-net**: Can reach external services. Used by Envoy (credentials), Fluent-Bit (logs → Loki), and Agent Manager (polls CP).

### Polling Architecture (No Inbound Ports)
- Data plane has **no inbound ports** - control plane cannot initiate connections
- Agent Manager polls control plane every 30s for commands (wipe, restart, stop, start)
- Fluent-Bit pushes logs directly to Loki (not through CP API)
- Allowlist synced from CP to CoreDNS every 5 minutes

### Agent Container Hardening
- Read-only root filesystem
- Dropped all capabilities
- No privilege escalation (`no-new-privileges`)
- Resource limits (CPU, memory, pids)
- DNS forced through CoreDNS filter
- All HTTP(S) traffic forced through Envoy proxy

### Credential Security
- Secrets encrypted with Fernet (AES) and stored in Postgres
- Envoy Lua filter fetches and injects credentials (cached for 5 min)
- Agent never sees the actual credentials

## Quick Start

### 1. Start Control Plane

```bash
cd control-plane

# Generate encryption key (first time only)
export ENCRYPTION_KEY=$(python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())")

docker-compose up -d

# Access points:
# - Admin UI: http://localhost:9080
# - API docs: http://localhost:8002/docs
# - Grafana:  http://localhost:3000 (admin/admin)
```

### 2. Start Data Plane

```bash
cd data-plane

# Standalone mode (no control plane):
docker-compose up -d
# Uses static config from configs/coredns/allowlist.hosts and environment variables

# Connected mode (with control plane):
export CONTROL_PLANE_URL=http://<control-plane-ip>:8002
export CONTROL_PLANE_TOKEN=dev-token  # Must match API_TOKENS in control plane
export AGENT_ID=my-agent-01           # Optional: unique ID (default: "default")
docker-compose up -d

# With log shipping to Loki:
export LOKI_HOST=<control-plane-ip>
docker-compose --profile auditing up -d
```

### 3. SSH Access to Agents (Optional)

For interactive SSH access to isolated agent containers, the system uses [FRP (Fast Reverse Proxy)](https://github.com/fatedier/frp) to establish secure tunnels without requiring inbound ports on the data plane.

```
User SSH → Control Plane:6000-6099 → frps → frpc → Agent:22
           (tunnel ports)                         (data plane)
```

**Control Plane** (already configured in docker-compose.yml):
- FRP server listens on port 7000 (control) and exposes ports 6000-6099 for SSH tunnels
- Dashboard available at port 7500

**Data Plane** setup:
```bash
# Add to data-plane/.env
FRP_SERVER_ADDR=<control-plane-ip>
FRP_AUTH_TOKEN=<token>              # Must match control plane
FRP_REMOTE_PORT=6000                # Unique per agent (6000, 6001, ...)
SSH_AUTHORIZED_KEYS="ssh-rsa AAAA... user@host"

# Start with SSH profile
docker-compose --profile ssh up -d
```

**Connect**:
```bash
ssh -p 6000 agent@<control-plane-ip>
```

See [control-plane/README.md](control-plane/README.md#ssh-access-to-agents) and [data-plane/README.md](data-plane/README.md#ssh-access-via-frp) for detailed configuration.

## Features

| Feature | Description |
|---------|-------------|
| **Admin UI** | Web console for managing agents, secrets, allowlists |
| **Multi-Agent Support** | Manage multiple data planes from a single control plane |
| **Agent Control** | Start/stop/restart/wipe agent containers from UI |
| **Domain Allowlist** | Only approved domains can be accessed (synced to CoreDNS) |
| **Egress Proxy** | All HTTP(S) traffic routed through Envoy with logging |
| **Credential Injection** | API keys injected by proxy, never exposed to agent |
| **Domain Aliases** | Use `*.devbox.local` shortcuts (e.g., `openai.devbox.local`) |
| **Centralized Logging** | All agent activity logged to Loki |
| **Secret Management** | Encrypted secrets in Postgres (Fernet/AES) |
| **Rate Limiting** | Per-domain rate limits to control API usage |
| **Audit Logs** | Full audit trail of all actions |
| **SSH Access** | Secure SSH tunnels to agents via FRP (no inbound ports on data plane) |

## Directory Structure

```
.
├── control-plane/
│   ├── docker-compose.yml      # Control plane services
│   ├── configs/
│   │   ├── grafana/            # Grafana dashboards
│   │   └── frps/               # FRP server config (SSH tunnels)
│   └── services/
│       ├── control-plane/      # Control plane API (secrets, allowlist, audit)
│       └── admin-ui/           # React admin console
│
└── data-plane/
    ├── docker-compose.yml          # Data plane services
    ├── configs/
    │   ├── coredns/            # DNS allowlist
    │   ├── envoy/              # Proxy + credential injection (Lua filter)
    │   ├── fluent-bit/         # Log forwarding
    │   └── frpc/               # FRP client config (SSH tunnels)
    ├── services/
    │   └── agent-manager/      # Manages agent container lifecycle
    └── tests/                  # Unit and E2E tests
```

## Configuration

### Adding Allowed Domains

Domains can be managed via the Admin UI (http://localhost:9080) or API:
```bash
# Add domain via API
curl -X POST http://localhost:8002/api/v1/allowlist \
  -H "Authorization: Bearer dev-token" \
  -H "Content-Type: application/json" \
  -d '{"entry_type": "domain", "value": "api.openai.com", "description": "OpenAI API"}'
```

The agent-manager syncs the allowlist from the control plane to CoreDNS every 5 minutes.
A static fallback allowlist is available at `data-plane/configs/coredns/allowlist.hosts` for when the control plane is unreachable.

### Adding Secrets (Domain-Scoped)

Secrets are scoped to specific domains. Envoy's Lua filter automatically injects the correct credential based on the request destination.

**Domain Aliases**: You can optionally set an `alias` to create a `*.devbox.local` shortcut. For example, `alias: "openai"` allows the agent to use `http://openai.devbox.local` instead of the real domain - Envoy resolves the alias and injects credentials automatically.

Via Admin UI (http://localhost:9080) or API:
```bash
# OpenAI API key (with alias)
curl -X POST http://localhost:8002/api/v1/secrets \
  -H "Authorization: Bearer dev-token" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "OPENAI_API_KEY",
    "value": "sk-...",
    "domain_pattern": "api.openai.com",
    "alias": "openai",
    "header_name": "Authorization",
    "header_format": "Bearer {value}",
    "description": "OpenAI API key"
  }'
# Agent can now use: curl http://openai.devbox.local/v1/models

# GitHub token (wildcard domain)
curl -X POST http://localhost:8002/api/v1/secrets \
  -H "Authorization: Bearer dev-token" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "GITHUB_TOKEN",
    "value": "ghp_...",
    "domain_pattern": "*.github.com",
    "alias": "github",
    "header_name": "Authorization",
    "header_format": "token {value}"
  }'

# Anthropic API key
curl -X POST http://localhost:8002/api/v1/secrets \
  -H "Authorization: Bearer dev-token" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "ANTHROPIC_API_KEY",
    "value": "sk-ant-...",
    "domain_pattern": "api.anthropic.com",
    "alias": "anthropic",
    "header_name": "x-api-key",
    "header_format": "{value}"
  }'
```

### Agent Management

Via Admin UI dashboard or API. Agent ID is set via `AGENT_ID` environment variable in the data plane (defaults to "default").

```bash
# List all connected agents
curl http://localhost:8002/api/v1/agents \
  -H "Authorization: Bearer dev-token"

# Get agent status
curl http://localhost:8002/api/v1/agents/default/status \
  -H "Authorization: Bearer dev-token"

# Wipe agent (preserves workspace)
curl -X POST http://localhost:8002/api/v1/agents/default/wipe \
  -H "Authorization: Bearer dev-token" \
  -H "Content-Type: application/json" \
  -d '{"wipe_workspace": false}'

# Wipe agent and workspace
curl -X POST http://localhost:8002/api/v1/agents/default/wipe \
  -H "Authorization: Bearer dev-token" \
  -H "Content-Type: application/json" \
  -d '{"wipe_workspace": true}'

# Stop/Start/Restart agent
curl -X POST http://localhost:8002/api/v1/agents/default/stop \
  -H "Authorization: Bearer dev-token"
curl -X POST http://localhost:8002/api/v1/agents/default/start \
  -H "Authorization: Bearer dev-token"
curl -X POST http://localhost:8002/api/v1/agents/default/restart \
  -H "Authorization: Bearer dev-token"
```

## Authentication & API Tokens

### Token Types

| Type | Purpose | Access |
|------|---------|--------|
| `admin` | UI/Management operations | Full API access (secrets, allowlist, agents, tokens, rate-limits, audit-logs) |
| `agent` | Data plane operations | Heartbeat, secrets/for-domain, allowlist/export, rate-limits/for-domain (scoped to agent_id) |

### Legacy Tokens (Backwards Compatible)

For development, legacy tokens from the `API_TOKENS` environment variable still work and are treated as admin tokens:
- `dev-token`
- `admin-token`

### Creating API Tokens

Tokens are managed via the Admin UI (`/tokens`) or API:

```bash
# Create an admin token
curl -X POST http://localhost:8002/api/v1/tokens \
  -H "Authorization: Bearer dev-token" \
  -H "Content-Type: application/json" \
  -d '{"name": "my-admin-token", "token_type": "admin"}'

# Create an agent token (scoped to specific agent)
curl -X POST http://localhost:8002/api/v1/tokens \
  -H "Authorization: Bearer dev-token" \
  -H "Content-Type: application/json" \
  -d '{"name": "prod-agent-token", "token_type": "agent", "agent_id": "prod-agent-01"}'

# Create token with expiry
curl -X POST http://localhost:8002/api/v1/tokens \
  -H "Authorization: Bearer dev-token" \
  -H "Content-Type: application/json" \
  -d '{"name": "temp-token", "token_type": "admin", "expires_in_days": 30}'
```

**Important**: The raw token is only returned once on creation. Store it securely!

### Agent Approval Workflow

New agents that connect via heartbeat start in a "pending" state and must be approved before they receive commands:

```bash
# List agents (shows approval status)
curl http://localhost:8002/api/v1/agents \
  -H "Authorization: Bearer dev-token"

# Approve an agent
curl -X POST http://localhost:8002/api/v1/agents/my-agent/approve \
  -H "Authorization: Bearer dev-token"

# Reject an agent (removes it)
curl -X POST http://localhost:8002/api/v1/agents/my-agent/reject \
  -H "Authorization: Bearer dev-token"

# Revoke approval (agent must be re-approved)
curl -X POST http://localhost:8002/api/v1/agents/my-agent/revoke \
  -H "Authorization: Bearer dev-token"
```

Unapproved agents can still send heartbeats but will not receive commands (wipe, restart, etc.).

## Database Seeding

The database is **automatically seeded on first startup** if empty. The control plane API checks for existing agents and seeds default data if none exist.

For manual seeding (e.g., to reset or re-seed):

```bash
cd control-plane/services/control-plane

# Seed with default data (test agents, allowlist entries, rate limits)
python seed.py

# Seed and show generated tokens
python seed.py --show-token

# Reset database and re-seed
python seed.py --reset --show-token
```

This creates:
- `test-agent` - An approved agent for UI testing (with agent-specific config examples)
- `pending-agent` - A pending agent to test the approval flow
- `default-admin` - An admin token
- `test-agent-token` - An agent token for test-agent
- Sample allowlist entries and rate limits (both global and agent-specific)

## Per-Agent Configuration

You can create agent-specific secrets, allowlist entries, and rate limits that only apply to a particular agent. Global entries (without `agent_id`) apply to all agents.

### How it works

- **Global entries** (`agent_id` = null): Apply to all agents
- **Agent-specific entries** (`agent_id` = "my-agent"): Only apply to that agent
- **Precedence**: Agent-specific entries take precedence over global entries for the same domain

### Creating agent-specific configuration

```bash
# Agent-specific allowlist entry
curl -X POST http://localhost:8002/api/v1/allowlist \
  -H "Authorization: Bearer dev-token" \
  -H "Content-Type: application/json" \
  -d '{
    "entry_type": "domain",
    "value": "internal-api.example.com",
    "description": "Internal API for prod-agent only",
    "agent_id": "prod-agent"
  }'

# Agent-specific secret
curl -X POST http://localhost:8002/api/v1/secrets \
  -H "Authorization: Bearer dev-token" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "PROD_API_KEY",
    "value": "sk-prod-...",
    "domain_pattern": "api.example.com",
    "header_name": "Authorization",
    "header_format": "Bearer {value}",
    "agent_id": "prod-agent"
  }'

# Agent-specific rate limit (overrides global rate limit)
curl -X POST http://localhost:8002/api/v1/rate-limits \
  -H "Authorization: Bearer dev-token" \
  -H "Content-Type: application/json" \
  -d '{
    "domain_pattern": "api.openai.com",
    "requests_per_minute": 120,
    "burst_size": 20,
    "description": "Higher limit for prod-agent",
    "agent_id": "prod-agent"
  }'
```

### Agent token scoping

Agent tokens only see configuration for their assigned agent plus global configuration:

```bash
# Create agent token
curl -X POST http://localhost:8002/api/v1/tokens \
  -H "Authorization: Bearer dev-token" \
  -H "Content-Type: application/json" \
  -d '{"name": "prod-token", "token_type": "agent", "agent_id": "prod-agent"}'

# Using the agent token to fetch secrets
# - Returns prod-agent's secrets + global secrets
# - Does NOT return other agents' secrets
curl http://localhost:8002/api/v1/secrets/for-domain?domain=api.example.com \
  -H "Authorization: Bearer <prod-agent-token>"
```

## Testing

### Control Plane Tests

```bash
cd control-plane/services/control-plane
./run_tests.sh

# Or with pytest directly:
pip install -r requirements-test.txt
pytest -v

# Run specific test class:
pytest -v tests/test_api.py::TestSecrets
```

### Data Plane Tests

```bash
cd data-plane
./run_tests.sh

# Unit tests only (no containers needed):
pytest tests/ -v --ignore=tests/test_e2e.py

# E2E tests (requires data plane running):
docker-compose up -d
pytest tests/test_e2e.py -v
```

## TODO

- [ ] TLS between data plane and control plane
- [ ] mTLS for DP→CP communication
- [x] Multi-data plane support (multiple agents per control plane)
- [x] Allowlist sync from control plane to CoreDNS
- [x] Agent registration (approve/reject new agents, revoke access)
- [x] API token management (generate, delete, enable/disable tokens via UI)
- [x] Per-agent configuration (different allowlists/secrets/rate-limits per agent)
- [x] Multi-tenancy (isolated tenant workspaces)
- [ ] Package registry proxy/allowlist

## License

MIT
