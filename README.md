# AI Devbox

Secure development environment for AI agents with isolated networking and centralized control.

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                           CONTROL PLANE (control-net)                            │
│                           (runs on provider/cloud)                               │
│                                                                                  │
│  ┌───────────┐  ┌───────────┐  ┌───────────┐  ┌───────────────┐                │
│  │ Postgres  │  │ Admin UI  │  │OpenObserve│  │  FRP Server   │                │
│  │ (secrets) │  │  (:9080)  │  │  (:5080)  │  │    (:7000)    │                │
│  └─────┬─────┘  └─────┬─────┘  └─────┬─────┘  └───────┬───────┘                │
│        │              │              │                 │                        │
│        ▼              ▼              │                 │                        │
│  ┌────────────────────────────────┐  │                 │                        │
│  │     Control Plane API (:8002)  │  │                 │                        │
│  │                                │  │                 │                        │
│  │  /api/v1/secrets    Secrets    │  │                 │                        │
│  │  /api/v1/allowlist  Allowlist  │  │                 │                        │
│  │  /api/v1/agents     Agent Mgmt │  │                 │                        │
│  │  /api/v1/terminal   Web Term   │  │                 │                        │
│  └────────────────────────────────┘  │                 │                        │
│                 ▲                     │                 │                        │
└─────────────────┼─────────────────────┼─────────────────┼────────────────────────┘
                  │                     │                 │
                  │ Heartbeat/Commands  │ Logs            │ STCP Tunnels
                  │                     │                 │
┌─────────────────┼─────────────────────┼─────────────────┼────────────────────────┐
│                 │          DATA PLANE │                 │                        │
│                 │     (runs on client)│                 │                        │
│                 │                     │                 ▼                        │
│  ┌──────────────┴───────────┐  ┌──────┴───────┐  ┌─────────────────┐           │
│  │      Agent Manager       │  │    Vector    │  │   FRP Client    │           │
│  │  (polls CP, syncs DNS)   │  │   (logs)     │  │ (STCP to CP)    │           │
│  └──────────────────────────┘  └──────────────┘  └────────┬────────┘           │
│                                                            │                    │
│  ┌─────────────────────────────────────────────────────────┼──────────────────┐ │
│  │                        agent-net (isolated)             │                  │ │
│  │  ┌──────────────────────────────────────────────────────┼────────────────┐ │ │
│  │  │                     Agent Container                  │                │ │ │
│  │  │  • Isolated network (no direct internet access)      │                │ │ │
│  │  │  • All HTTP(S) via Envoy proxy                    SSH:22             │ │ │
│  │  │  • DNS via CoreDNS filter (allowlist enforced)       │                │ │ │
│  │  └──────────────────────────────────────────────────────┼────────────────┘ │ │
│  │              │                           │              │                  │ │
│  │              ▼                           ▼              │                  │ │
│  │       ┌─────────────┐             ┌─────────────┐       │                  │ │
│  │       │   Envoy     │             │   CoreDNS   │       │                  │ │
│  │       │  (+ creds)  │             │  (filter)   │       │                  │ │
│  │       └─────────────┘             └─────────────┘       │                  │ │
│  └─────────────────────────────────────────────────────────┼──────────────────┘ │
└────────────────────────────────────────────────────────────┼────────────────────┘
                                                             │
                                              Web Terminal ──┘
                                              (via Admin UI)
```

## Security Model

### Network Isolation
- **agent-net**: Internal network, no external access. Agent can only reach Envoy and CoreDNS.
- **infra-net**: Can reach external services. Used by Envoy (credentials), Vector (logs → OpenObserve), and Agent Manager (polls CP).
- **IPv6 disabled**: Prevents bypass of IPv4 egress controls.

### Polling Architecture (No Inbound Ports)
- Data plane has **no inbound ports** - control plane cannot initiate connections
- Agent Manager polls control plane every 30s for commands (wipe, restart, stop, start)
- Vector pushes logs directly to OpenObserve (not through CP API)
- Allowlist synced from CP to CoreDNS every 5 minutes

### Agent Container Hardening
- Read-only root filesystem
- Dropped all capabilities
- No privilege escalation (`no-new-privileges`)
- Resource limits (CPU, memory, pids)
- DNS forced through CoreDNS filter
- All HTTP(S) traffic forced through Envoy proxy
- Optional [gVisor](https://gvisor.dev) kernel isolation (`CONTAINER_RUNTIME=runsc`)

### Credential Security
- Secrets encrypted with Fernet (AES) and stored in Postgres
- Envoy Lua filter fetches and injects credentials (cached for 5 min)
- Agent never sees the actual credentials

## Quick Start

### Standalone Mode

Run the data plane without a control plane. Uses static configuration files.

```bash
cd data-plane

docker-compose up -d

# Allowlist: configs/coredns/allowlist.hosts
# Secrets: environment variables or configs/envoy/envoy.yaml
```

### Connected Mode

Run with centralized management via the control plane.

**1. Start Control Plane**

```bash
cd control-plane

# Generate encryption key (first time only)
export ENCRYPTION_KEY=$(python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())")

docker-compose up -d

# Access points:
# - Admin UI:     http://localhost:9080
# - API docs:     http://localhost:8002/docs
# - OpenObserve:  http://localhost:5080 (admin@maltbox.local/admin)
```

**2. Start Data Plane**

```bash
cd data-plane

export CONTROL_PLANE_URL=http://<control-plane-ip>:8002
export CONTROL_PLANE_TOKEN=dev-token
export AGENT_ID=my-agent-01  # Unique ID for this data plane

docker-compose up -d

# With log shipping to OpenObserve:
export OPENOBSERVE_HOST=<control-plane-ip>
docker-compose --profile auditing up -d
```

**3. Web Terminal (Optional)**

Browser-based SSH access to agent containers via STCP tunnels.

```
Browser → Admin UI → WebSocket → Control Plane API → STCP → FRP → Agent:22
```

Setup:
1. Generate STCP secret: `curl -X POST http://localhost:8002/api/v1/agents/my-agent/stcp-secret -H "Authorization: Bearer admin-token"`
2. Add to `data-plane/.env`:
   ```bash
   FRP_SERVER_ADDR=<control-plane-ip>
   STCP_SECRET_KEY=<secret-from-step-1>
   SSH_AUTHORIZED_KEYS="ssh-rsa AAAA... user@host"
   ```
3. Start with SSH profile: `docker-compose --profile ssh up -d`
4. Access terminal from Admin UI Dashboard (requires `developer` role)

See [control-plane/README.md](control-plane/README.md#web-terminal) and [data-plane/README.md](data-plane/README.md#ssh-access-via-frp) for details.

## Features

| Feature | Description |
|---------|-------------|
| **Admin UI** | Web console for managing agents, secrets, allowlists |
| **Web Terminal** | Browser-based SSH access to agents (xterm.js) |
| **Multi-Agent Support** | Manage multiple data planes from a single control plane |
| **Agent Control** | Start/stop/restart/wipe agent containers from UI |
| **Domain Allowlist** | Only approved domains can be accessed (synced to CoreDNS) |
| **Egress Proxy** | All HTTP(S) traffic routed through Envoy with logging |
| **Credential Injection** | API keys injected by proxy, never exposed to agent |
| **Domain Aliases** | Use `*.devbox.local` shortcuts (e.g., `openai.devbox.local`) |
| **Centralized Logging** | All agent activity logged to OpenObserve (Vector collector) |
| **Secret Management** | Encrypted secrets in Postgres (Fernet/AES) |
| **Rate Limiting** | Per-domain rate limits to control API usage |
| **Audit Logs** | Full audit trail of all actions |
| **RBAC** | Role-based access control (admin, developer roles) |
| **STCP Tunnels** | Secure tunnels via single port (no port-per-agent allocation) |
| **gVisor Isolation** | Optional kernel-level syscall isolation (`CONTAINER_RUNTIME=runsc`) |
| **IPv6 Disabled** | Prevents bypass of IPv4 egress controls |

## Directory Structure

```
.
├── control-plane/
│   ├── docker-compose.yml      # Control plane services
│   ├── configs/
│   │   └── frps/               # FRP server config (STCP tunnels)
│   └── services/
│       ├── control-plane/      # Control plane API (secrets, allowlist, audit)
│       └── admin-ui/           # React admin console
│
└── data-plane/
    ├── docker-compose.yml          # Data plane services
    ├── run.sh                      # Launcher (--gvisor, --ssh, --auditing)
    ├── configs/
    │   ├── coredns/            # DNS allowlist
    │   ├── envoy/              # Proxy + credential injection (Lua filter)
    │   ├── vector/             # Log collection & forwarding
    │   ├── gvisor/             # gVisor runtime config
    │   └── frpc/               # FRP client config (STCP tunnels)
    ├── services/
    │   └── agent-manager/      # Manages agent container lifecycle
    └── tests/                  # Unit and E2E tests
```

## Configuration

See [docs/configuration.md](docs/configuration.md) for detailed configuration including:
- Adding allowed domains
- Adding secrets (domain-scoped, with aliases)
- Agent management commands
- Per-agent configuration (agent-specific secrets, allowlists, rate limits)

## Authentication & API Tokens

### Token Types & Roles

| Type | Role | Access |
|------|------|--------|
| `admin` | `admin` | Full API access (secrets, allowlist, agents, tokens, rate-limits, audit-logs) |
| `admin` | `developer` | Read access + web terminal access |
| `agent` | - | Heartbeat, secrets/for-domain, allowlist/export, rate-limits/for-domain (scoped to agent_id) |

### Default Development Tokens

The following tokens are automatically seeded for development:

| Token Name | Raw Token | Role | Super Admin |
|------------|-----------|------|-------------|
| `super-admin-token` | `super-admin-test-token-do-not-use-in-production` | admin | Yes |
| `admin-token` | `admin-test-token-do-not-use-in-production` | admin | No |
| `dev-token` | `dev-test-token-do-not-use-in-production` | developer | No |

### Creating API Tokens

Tokens are managed via the Admin UI (`/tokens`) or API:

```bash
# Create an admin token
curl -X POST http://localhost:8002/api/v1/tokens \
  -H "Authorization: Bearer admin-token" \
  -H "Content-Type: application/json" \
  -d '{"name": "my-admin-token", "token_type": "admin", "roles": "admin"}'

# Create a developer token (can access web terminal)
curl -X POST http://localhost:8002/api/v1/tokens \
  -H "Authorization: Bearer admin-token" \
  -H "Content-Type: application/json" \
  -d '{"name": "my-dev-token", "token_type": "admin", "roles": "developer"}'

# Create an agent token (scoped to specific agent)
curl -X POST http://localhost:8002/api/v1/tokens \
  -H "Authorization: Bearer admin-token" \
  -H "Content-Type: application/json" \
  -d '{"name": "prod-agent-token", "token_type": "agent", "agent_id": "prod-agent-01"}'

# Create token with expiry
curl -X POST http://localhost:8002/api/v1/tokens \
  -H "Authorization: Bearer admin-token" \
  -H "Content-Type: application/json" \
  -d '{"name": "temp-token", "token_type": "admin", "roles": "admin", "expires_in_days": 30}'
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
  -H "Authorization: Bearer admin-token"

# Reject an agent (removes it)
curl -X POST http://localhost:8002/api/v1/agents/my-agent/reject \
  -H "Authorization: Bearer admin-token"

# Revoke approval (agent must be re-approved)
curl -X POST http://localhost:8002/api/v1/agents/my-agent/revoke \
  -H "Authorization: Bearer admin-token"
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
- `admin-token` - Admin role token (super admin)
- `dev-token` - Developer role token (terminal access)
- Sample allowlist entries and rate limits (both global and agent-specific)

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

## Roadmap

- [ ] mTLS for data plane ↔ control plane communication (step-ca)
- [ ] Package registry proxy/allowlist (npm, pip, cargo)
- [ ] Alert rules for security events (gVisor syscall denials, rate limit hits)

## License

MIT
