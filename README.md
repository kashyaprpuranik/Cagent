# Cagent

Secure development and execution environment for AI agents with isolated networking and centralized control.

## Problem

AI agents need network access to be useful—fetching documentation, calling APIs, installing packages. But unrestricted access creates serious risks:

- **Data exfiltration**: Agent sends proprietary code or leaks secrets (credential theft) to unauthorized endpoints. Example: [Google's Gemini exfiltrating data via markdown image rendering](https://www.promptarmor.com/resources/google-antigravity-exfiltrates-data)
- **Supply chain attacks**: Agent installs malicious packages, compromised plugins, or executes untrusted code. Example: [Hundreds of malicious MCP skills discovered in ClawHub](https://www.esecurityplanet.com/threats/hundreds-of-malicious-skills-found-in-openclaws-clawhub/)
- **Runaway costs**: Agent makes unlimited API calls, racking up unexpected bills
- **Lateral movement**: Compromised agent pivots to internal services

The core tension: agents need enough access to work, but not so much that a misaligned or compromised agent can cause damage.

## Threat Model

Cagent assumes the AI agent is **untrusted by default**. The agent may be:

| Threat | Description |
|--------|-------------|
| **Misaligned** | Pursues goals that don't match user intent (prompt injection, jailbreak) |
| **Compromised** | Executes malicious code from a poisoned dependency or hostile input |
| **Overly capable** | Has access to credentials/APIs it shouldn't, even if behaving correctly |
| **Unpredictable** | Makes unexpected network requests due to hallucination or bugs |

### Trust Boundaries

Cagent has layered trust boundaries with different levels of protection:

| Boundary | Trusted | Defended Against | Current Controls |
|----------|---------|------------------|------------------|
| **Infrastructure operators** | Yes | - | None (full access assumed) |
| **Super admins** | Yes | - | None (can access all tenants) |
| **Tenant admins** | Partially | Other tenants, unauthorized access | Tenant isolation, API tokens, IP ACLs |
| **Developers** | Partially | Privileged operations | Role-based access (read-only dashboard) |
| **Agent tokens** | No | Cross-agent access, CP modification | Scoped to agent, read-only for config |
| **AI agents** | No | All threats listed above | Network isolation, credential hiding, allowlists |

**What current controls provide:**
- **Multi-tenancy isolation**: Tenant A cannot access Tenant B's secrets, agents, or configuration
- **Network-based restrictions**: IP ACLs limit where admin operations can originate
- **Least-privilege agents**: Agent tokens can only read their own configuration, not modify it
- **Rate limiting**: Incoming requests are rate limited per token.

**What is NOT currently defended:**
- Malicious or compromised super admins (full platform access)
- Infrastructure-level attacks (host compromise, container escape, supply chain)
- Physical access to control plane servers
- Insider threats from infrastructure operators

### Production Hardening

For production deployments, consider adding: API gateway with WAF, mandatory MFA, SIEM integration for audit logs, mTLS between data plane and control plane, and network segmentation to isolate the control plane from public internet.

## Security Principles

| Principle | Description |
|-----------|-------------|
| **Network Isolation** | Agent can only reach Envoy (proxy) and CoreDNS (DNS filter) - no direct internet access |
| **No Inbound Ports** | Data plane initiates all connections; control plane cannot push to agents |
| **Credential Hiding** | Agent never sees API keys; credentials injected by proxy at egress |
| **Defense in Depth** | Multiple layers: network, container, optional kernel (gVisor) isolation |
| **Least Privilege** | Minimal capabilities, read-only filesystem, resource limits |
| **Audit Everything** | All HTTP requests, DNS queries, and syscalls logged (via CP for trusted identity) |

## Hardening Details

### Container Security
| Control | Implementation |
|---------|----------------|
| No privilege escalation | `no-new-privileges` security option |
| Seccomp profile | Blocks raw sockets (prevents packet-crafting bypass) |
| Resource limits | CPU, memory, PID limits enforced |
| Forced proxy | `HTTP_PROXY`/`HTTPS_PROXY` environment variables |
| Forced DNS | Container DNS set to CoreDNS filter IP |

### Network Security
| Control | Implementation |
|---------|----------------|
| Internal network | `agent-net` marked as `internal: true` (no default gateway) |
| Protocol restriction | Agent can ONLY reach Envoy (HTTP) and CoreDNS (DNS) |
| IPv6 disabled | Prevents bypass of IPv4 egress controls |
| Allowlist enforcement | CoreDNS blocks resolution of non-allowed domains |
| Egress proxy | All HTTP(S) routed through Envoy |
| Egress volume limits | Per-domain byte budgets (in-memory, see note) |
| iptables fallback | Explicit DROP rules if proxy crashes (see below) |
| Raw socket blocked | Seccomp profile prevents packet crafting |

**Protocol Smuggling Prevention**: Raw TCP/UDP to external hosts is impossible. The agent can only reach two IPs on the internal network: Envoy (port 8443, HTTP only) and CoreDNS (port 53, DNS only). The iptables script DROPs all other traffic. Seccomp blocks raw socket creation (AF_PACKET), preventing packet crafting.

**Residual Exfiltration Channels**: Small amounts of data could theoretically be exfiltrated via DNS queries or HTTPS traffic to allowlisted domains. Mitigations: DNS tunneling detection (blocks long subdomains), egress volume limits, and audit logging.

**Defense in Depth**: Network isolation doesn't depend solely on Envoy/CoreDNS being healthy. The `internal: true` network flag removes the default gateway at the Docker level. For additional hardening, run the iptables script:

**Egress Volume Limits**: Prevents large-scale data exfiltration by tracking bytes sent per domain per hour. Configure via `STATIC_EGRESS_LIMITS` environment variable:

**Limitation**: Byte counts are in-memory and reset when Envoy restarts. See roadmap for persistent state.

### Kernel Isolation (Default)

The `standard` profile uses [gVisor](https://gvisor.dev) to intercept syscalls in user-space. This is the recommended default for production:

```bash
# Requires gVisor installation: https://gvisor.dev/docs/user_guide/install/
docker-compose --profile standard --profile admin up -d

# Use --profile dev if gVisor is not installed (development only)
docker-compose --profile dev --profile admin up -d
```

| Control | Implementation |
|---------|----------------|
| gVisor runtime | `runsc` - syscalls never reach host kernel |
| Stricter limits | 1 CPU, 2GB memory, 128 PIDs |

### Credential Security
| Control | Implementation |
|---------|----------------|
| Encryption at rest | Fernet (AES) encryption in Postgres |
| Injection at proxy | Envoy Lua filter adds headers at egress |
| Short-lived cache | Credentials cached for 5 minutes |

## Quick Start

### Standalone Mode

Run the data plane without a control plane - ideal for local use of one agent.

#### Minimal (Static Config)

Lightweight setup with just 3 containers. Edit `cagent.yaml` and run the config generator, or edit raw `coredns/Corefile` and `envoy/envoy.yaml` directly for advanced use. Ideal for simple static domain policies on one agent.

```
┌───────────────────────────────────────────────────────┐
│                  agent-net (isolated)                  │
│                                                        │
│    ┌────────────────────────────────────────────┐     │
│    │              Agent Container                │     │
│    │  • Isolated network (no direct internet)    │     │
│    │  • All HTTP(S) via Envoy                    │     │
│    │  • DNS via CoreDNS                          │     │
│    └────────────────────────────────────────────┘     │
│                 │                   │                  │
│                 ▼                   ▼                  │
│          ┌───────────┐       ┌───────────┐            │
│          │   Envoy   │       │  CoreDNS  │            │
│          │  (~50MB)  │       │  (~20MB)  │            │
│          └───────────┘       └───────────┘            │
└───────────────────────────────────────────────────────┘
```

```bash
cd data-plane

# Recommended: with gVisor (requires installation: https://gvisor.dev/docs/user_guide/install/)
docker-compose --profile standard up -d

# Development: without gVisor (if not installed)
docker-compose --profile dev up -d
```

#### Locally Managed (With Admin UI)

Adds agent-manager (watches `cagent.yaml`) and local admin UI for browser-based management and observability. Ideal for complex and changing domain policies on one agent.

```
┌─────────────────────────────────────────────────────────────────┐
│                     DATA PLANE (managed)                         │
│                                                                  │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │                 Local Admin UI (:8080)                      ││
│  │  • Config editor    • Health checks    • Web terminal       ││
│  └─────────────────────────────────────────────────────────────┘│
│                              │                                   │
│  ┌──────────────┐    ┌──────┴──────┐                            │
│  │Agent Manager │◄───│ cagent.yaml│──── generates ───┐         │
│  └──────────────┘    └─────────────┘                  │         │
│                                                       ▼         │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │                    agent-net (isolated)                     ││
│  │    ┌─────────────────────────────────────────────────┐     ││
│  │    │                 Agent Container                  │     ││
│  │    └─────────────────────────────────────────────────┘     ││
│  │                 │                       │                   ││
│  │          ┌──────┴──────┐         ┌──────┴──────┐           ││
│  │          │    Envoy    │         │   CoreDNS   │           ││
│  │          └─────────────┘         └─────────────┘           ││
│  └─────────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────┘
```

```bash
cd data-plane

# Recommended: with gVisor (requires installation)
docker-compose --profile standard --profile admin up -d

# Development: without gVisor
docker-compose --profile dev --profile admin up -d
```

**Local Admin UI** (http://localhost:8080):
- Structured config editor (domains, rate limits, credentials)
- Container status with health checks
- Log viewer with traffic analytics
- Browser-based web terminal

### Control Plane Mode

Run with centralized management via the control plane. Ideal for multiple tenants and agents.

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
│  ┌─────────────┴────────-───┐                   ┌─────────────────┐            │
│  │      Agent Manager       │                   │   FRP Client    │            │
│  │ polls CP, syncs configs  │                   │ (STCP to CP)    │            │
│  │ ships logs to CP         │                   └────────-┬───────┘            │
│  └──────────────────────────┘                             │                    │
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
# - OpenObserve:  http://localhost:5080 (admin@cagent.local/admin)
```

**2. Start Data Plane**

```bash
cd data-plane

export CONTROL_PLANE_URL=http://<control-plane-ip>:8002
export CONTROL_PLANE_TOKEN=dev-token
export AGENT_ID=my-agent-01  # Unique ID for this data plane

docker-compose up -d

# Log shipping is automatic - logs are sent to CP which forwards to OpenObserve
# No OPENOBSERVE credentials needed on data plane (CP-mediated for security)
docker-compose --profile standard up -d
```

**3. Accessing the Agent**

| Method | Standalone | Control Plane Mode |
|--------|------------|-------------------|
| **Web Terminal** | http://<local-admin-ui>:8080 → Terminal | http://<admin-ui>:9080 → Dashboard → Terminal |
| **Docker exec** | `docker exec -it agent bash` | Same (requires host access) |
| **SSH** | Configure via Local Admin UI | Configure via CP API |

The web terminal is the easiest - just open the Admin UI and click Terminal.

For SSH access in Control Plane Mode (remote data planes):
```bash
cd data-plane
./scripts/setup-ssh-tunnel.sh --control-plane http://<cp-ip>:8002 --token admin-token
```

Or manually:
1. Generate STCP secret: `curl -X POST http://localhost:8002/api/v1/agents/my-agent/stcp-secret -H "Authorization: Bearer admin-token"`
2. Add to `data-plane/.env`: `STCP_SECRET_KEY=<secret>`, `FRP_SERVER_ADDR=<control-plane-ip>`
3. Start with SSH profile: `docker-compose --profile standard --profile ssh up -d`

See [data-plane/README.md](data-plane/README.md#ssh-access) for details.

## Features

| Feature | Description |
|---------|-------------|
| **Domain Allowlist** | Only approved domains can be accessed (enforced by CoreDNS and Envoy) |
| **Credential Injection** | API keys injected by proxy, never exposed to agent |
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
- Domain policies
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

- [ ] Persistent egress volume tracking (Redis backend for byte counts across restarts)
- [ ] Improved secret management in standalone mode (encrypted local storage)
- [ ] mTLS for data plane ↔ control plane communication (step-ca)
- [ ] Package registry proxy/allowlist (npm, pip, cargo)
- [ ] Alert rules for security events (gVisor syscall denials, rate limit hits)

## License

MIT
