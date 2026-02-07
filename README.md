# Maltbox

Secure development environment for AI agents with isolated networking and centralized control.

## Problem

AI agents need network access to be useful—fetching documentation, calling APIs, installing packages. But unrestricted access creates serious risks:

- **Data exfiltration**: Agent sends proprietary code or secrets to unauthorized endpoints. Example: [Google's Gemini exfiltrating data via markdown image rendering](https://www.promptarmor.com/resources/google-antigravity-exfiltrates-data)
- **Credential theft**: Agent extracts API keys from environment and leaks them
- **Supply chain attacks**: Agent installs malicious packages, compromised plugins, or executes untrusted code. Example: [Hundreds of malicious MCP skills discovered in ClawHub](https://www.esecurityplanet.com/threats/hundreds-of-malicious-skills-found-in-openclaws-clawhub/)
- **Runaway costs**: Agent makes unlimited API calls, racking up unexpected bills
- **Lateral movement**: Compromised agent pivots to internal services

The core tension: agents need enough access to work, but not so much that a misaligned or compromised agent can cause damage.

## Threat Model

Maltbox assumes the AI agent is **untrusted by default**. The agent may be:

| Threat | Description |
|--------|-------------|
| **Misaligned** | Pursues goals that don't match user intent (prompt injection, jailbreak) |
| **Compromised** | Executes malicious code from a poisoned dependency or hostile input |
| **Overly capable** | Has access to credentials/APIs it shouldn't, even if behaving correctly |
| **Unpredictable** | Makes unexpected network requests due to hallucination or bugs |

**Not in scope**: Maltbox does not protect against attacks from the host machine, malicious administrators, or physical access. It assumes the control plane and infrastructure operators are trusted.

## Security Model

### Network Isolation
- **agent-net**: Internal network, no external access. Agent can only reach Envoy and CoreDNS.
- **infra-net**: Can reach external services. Used by Envoy, Agent Manager, and Local Admin (standalone) or Vector (control plane mode).
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

### Kernel Isolation (Recommended for Production)

For high-security deployments, use the `secure` profile which enables [gVisor](https://gvisor.dev) to intercept syscalls in user-space:

```bash
# Install gVisor first: https://gvisor.dev/docs/user_guide/install/
docker-compose --profile secure --profile admin up -d
```

The `secure` profile enables:
- **gVisor runtime** (`runsc`) - agent syscalls never reach host kernel
- **Stricter resource limits** - 1 CPU, 2GB memory, 128 PIDs (vs 2 CPU, 4GB, 256 PIDs)
- **Reduced log retention** - smaller attack surface

### Credential Security
- Secrets encrypted with Fernet (AES) and stored in Postgres
- Envoy Lua filter fetches and injects credentials (cached for 5 min)
- Agent never sees the actual credentials

## Quick Start

### Standalone Mode

Run the data plane without a control plane. Uses a stateless local admin UI for management.

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
│  │Agent Manager │◄───│ maltbox.yaml│ ─── generates ──┐          │
│  │(watch+reload)│    │  (config)   │                 │          │
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

# Static config (no agent-manager, edit configs directly)
docker-compose --profile standard up -d

# Dynamic config (agent-manager watches maltbox.yaml and regenerates configs)
docker-compose --profile standard --profile managed up -d

# With local admin UI (includes agent-manager)
docker-compose --profile standard --profile admin up -d

# With gVisor isolation (requires gVisor installed)
docker-compose --profile secure --profile admin up -d
```

**Local Admin UI** (http://localhost:8080):
- Structured config editor (domains, rate limits, credentials)
- Container status with health checks
- Log viewer with traffic analytics
- Browser-based web terminal

### Control Plane Mode

Run with centralized management via the control plane. Supports multiple tenants and agents.

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                          CONTROL PLANE (control-net)                            │
│                          (can run on provider/cloud)                            │
│                                                                                 │
│   ┌───────────┐  ┌───────────┐  ┌───────────┐  ┌───────────────┐                │
│   │ Postgres  │  │ Admin UI  │  │OpenObserve│  │  FRP Server   │                │
│   │ (secrets) │  │  (:9080)  │  │  (:5080)  │  │    (:7000)    │                │
│   └────┬────-─┘  └────┬─-────┘  └────┬─-────┘  └───────┬───────┘                │
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
│                ▲                     │                 │                        │
└────────────────┼─────────────────────┼─────────────────┼────────────────────────┘
                 │ Heartbeat/Commands  │ Logs            │ STCP Tunnels
                 │                     │                 │
┌────────────────┼─────────────────────┼─────────────────┼────────────────────────┐
│                │          DATA PLANE │                 │                        │
|                |                     |                 |                        |
│             (can run on client laptop or server or provider servers)            │
│                │                     │                 ▼                        │
│  ┌─────────────┴────────-───┐  ┌─────┴─-──────┐  ┌─────────────────┐            │
│  │      Agent Manager       │  │    Vector    │  │   FRP Client    │            │
│  │  (polls CP, syncs DNS)   │  │   (logs)     │  │ (STCP to CP)    │            │
│  └──────────────────────────┘  └──────────────┘  └────────-┬───────┘            │
│                                                            │                    │
│  ┌─────────────────────────────────────────────────────────┼──────────────────┐ │
│  │                        agent-net (isolated)             │                  │ │
│  │  ┌──────────────────────────────────────────────────────┼────────────────┐ │ │
│  │  │                     Agent Container                  │                │ │ │
│  │  │  • Isolated network (no direct internet access)      │                │ │ │
│  │  │  • All HTTP(S) via Envoy proxy (allowlist enforced) SSH:22            │ │ │
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

**3. Accessing the Agent**

| Method | Standalone | Control Plane Mode |
|--------|------------|-------------------|
| **Web Terminal** | http://localhost:8080 → Terminal | http://localhost:9080 → Dashboard → Terminal |
| **Docker exec** | `docker exec -it agent bash` | Same (requires host access) |
| **SSH** | Configure via Local Admin UI | Configure via CP API |

The web terminal is the easiest - just open the Admin UI and click Terminal.

For SSH access in Control Plane Mode (remote data planes):
1. Generate STCP secret: `curl -X POST http://localhost:8002/api/v1/agents/my-agent/stcp-secret -H "Authorization: Bearer admin-token"`
2. Add to `data-plane/.env`: `STCP_SECRET_KEY=<secret>`, `FRP_SERVER_ADDR=<control-plane-ip>`
3. Start with SSH profile: `docker-compose --profile standard --profile ssh up -d`

See [data-plane/README.md](data-plane/README.md#ssh-access) for details.

## Features

| Feature | Description |
|---------|-------------|
| **Domain Allowlist** | Only approved domains can be accessed (enforced by CoreDNS and Envoy) |
| **Credential Injection** | API keys injected by proxy, never exposed to agent |
| **Domain Aliases** | Use `*.devbox.local` shortcuts (e.g., `openai.devbox.local`) |
| **Rate Limiting** | Per-domain rate limits to control API usage |
| **Centralized Logging** | HTTP requests, DNS queries, and gVisor syscalls logged to OpenObserve |
| **Traffic Analytics** | Requests/sec, top domains, error rates in log viewer |
| **Web Terminal** | Browser-based shell access to agents (xterm.js) |
| **Multi-Agent Management** | Manage multiple data planes with start/stop/restart/wipe from UI |
| **IP ACLs** | Restrict control plane access by IP range per tenant |
| **STCP Tunnels** | Secure remote access via single port with auto-configuration |
| **gVisor Isolation** | Optional kernel-level syscall isolation for defense in depth |

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

- [ ] Improved secret management in standalone mode (encrypted local storage)
- [ ] mTLS for data plane ↔ control plane communication (step-ca)
- [ ] Package registry proxy/allowlist (npm, pip, cargo)
- [ ] Alert rules for security events (gVisor syscall denials, rate limit hits)

## License

MIT
