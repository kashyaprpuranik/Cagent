# Maltbox

Secure development environment for AI agents with isolated networking and centralized control.

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

Run the data plane without a control plane. Uses local admin UI for management.

```
┌─────────────────────────────────────────────────────────────────┐
│                     DATA PLANE (standalone)                      │
│                                                                  │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │                 Local Admin UI (:8080)                      ││
│  │  • Structured config editor    • Health checks              ││
│  │  • Log viewer + analytics      • Web terminal               ││
│  │  • SSH tunnel setup                                         ││
│  └─────────────────────────────────────────────────────────────┘│
│                              │                                   │
│                              ▼                                   │
│  ┌──────────────┐    ┌─────────────┐                            │
│  │Agent Manager │    │ maltbox.yaml│ ─── generates ──┐          │
│  │(config sync) │    │  (config)   │                 │          │
│  └──────────────┘    └─────────────┘                 │          │
│                                                      ▼          │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │                    agent-net (isolated)                     ││
│  │  ┌─────────────────────────────────────────────────────┐   ││
│  │  │                  Agent Container                     │   ││
│  │  │  • Isolated network (no direct internet)             │   ││
│  │  │  • All HTTP(S) via Envoy    • DNS via CoreDNS        │   ││
│  │  └─────────────────────────────────────────────────────┘   ││
│  │              │                         │                    ││
│  │              ▼                         ▼                    ││
│  │       ┌───────────┐             ┌───────────┐              ││
│  │       │   Envoy   │             │  CoreDNS  │              ││
│  │       │ (+ creds) │             │ (filter)  │              ││
│  │       └───────────┘             └───────────┘              ││
│  └─────────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────┘
```

```bash
cd data-plane

# Start with local admin UI
docker-compose --profile admin up -d

# Access local admin at http://localhost:8080
# Features:
#   - Structured config editor (domains, rate limits, credentials)
#   - Container status with health checks
#   - Log viewer with traffic analytics
#   - Browser-based web terminal
#   - SSH tunnel setup
```

### Connected Mode

Run with centralized management via the control plane.

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
4. Access terminal from Admin UI Dashboard

See [control-plane/README.md](control-plane/README.md#web-terminal) and [data-plane/README.md](data-plane/README.md#ssh-access) for details.

## Features

| Feature | Description |
|---------|-------------|
| **Admin UI** | Web console for managing agents, secrets, allowlists (both modes) |
| **Web Terminal** | Browser-based shell access to agents (xterm.js) in both modes |
| **Local Admin UI** | Standalone mode management with structured config editor |
| **Multi-Agent Support** | Manage multiple data planes from a single control plane |
| **Agent Control** | Start/stop/restart/wipe agent containers from UI |
| **Domain Allowlist** | Only approved domains can be accessed (synced to CoreDNS) |
| **Egress Proxy** | All HTTP(S) traffic routed through Envoy with logging |
| **Credential Injection** | API keys injected by proxy, never exposed to agent |
| **Domain Aliases** | Use `*.devbox.local` shortcuts (e.g., `openai.devbox.local`) |
| **Unified Config** | Single `maltbox.yaml` generates CoreDNS and Envoy configs |
| **Config Validation** | Form-based editor with domain/CIDR validation |
| **Health Checks** | DNS resolution, Envoy ready status monitoring |
| **Traffic Analytics** | Requests/sec, top domains, error rates in log viewer |
| **Centralized Logging** | All agent activity logged to OpenObserve (Vector collector) |
| **Secret Management** | Encrypted secrets in Postgres (Fernet/AES) |
| **Rate Limiting** | Per-domain rate limits to control API usage |
| **IP ACLs** | Restrict control plane access by IP range per tenant |
| **Audit Logs** | Full audit trail of all actions |
| **RBAC** | Role-based access control (superadmin, admin, dev) |
| **STCP Tunnels** | Secure tunnels via single port (no port-per-agent allocation) |
| **Auto-STCP Setup** | Configure SSH tunnels from local admin UI |
| **gVisor Isolation** | Optional kernel-level syscall isolation (`CONTAINER_RUNTIME=runsc`) |
| **IPv6 Disabled** | Prevents bypass of IPv4 egress controls |

## Configuration

See [docs/configuration.md](docs/configuration.md) for detailed configuration including:
- Adding allowed domains
- Adding secrets (domain-scoped, with aliases)
- Agent management commands
- Per-agent configuration (agent-specific secrets, allowlists, rate limits)

## Authentication & API Tokens

### Token Types

| Type | Description | Access |
|------|-------------|--------|
| `superadmin` | Platform operator | All tenants, all endpoints, OpenObserve link |
| `admin` | Tenant administrator | Secrets, allowlist, agents, tokens, rate-limits, IP ACLs, audit-logs (tenant-scoped) |
| `dev` | Developer | Dashboard, agent logs, web terminal, settings only |
| `agent` | Data plane token | Heartbeat, secrets/for-domain, rate-limits/for-domain (agent-scoped) |

Tokens are managed via the Admin UI (`/tokens`) or API. See [docs/development.md](docs/development.md) for default development tokens.

## Documentation

- [Configuration Guide](docs/configuration.md) - Domains, secrets, rate limits, per-agent config
- [Development Guide](docs/development.md) - Database seeding, testing, API token creation

## Roadmap

- [ ] mTLS for data plane ↔ control plane communication (step-ca)
- [ ] Package registry proxy/allowlist (npm, pip, cargo)
- [ ] Alert rules for security events (gVisor syscall denials, rate limit hits)

## License

MIT
