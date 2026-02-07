# Maltbox - Data Plane

The data plane provides a secure, isolated execution environment for AI agents with controlled network egress, credential injection, and audit logging.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        Data Plane                                │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │                    agent-net (isolated)                  │    │
│  │  ┌─────────┐                                            │    │
│  │  │  Agent  │ ──HTTP──► ┌───────────┐                    │    │
│  │  │Container│           │   Envoy   │ ──HTTPS──► Internet│    │
│  │  └─────────┘           │   Proxy   │                    │    │
│  │       │                └───────────┘                    │    │
│  │       │                      │                          │    │
│  │       └──────► ┌─────────────┴───┐                      │    │
│  │                │   DNS Filter    │                      │    │
│  │                │   (CoreDNS)     │                      │    │
│  │                └─────────────────┘                      │    │
│  └─────────────────────────────────────────────────────────┘    │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │                    infra-net                             │    │
│  │  ┌───────────┐    ┌─────────────┐                       │    │
│  │  │  Vector   │    │ Local Admin │ (standalone mode)     │    │
│  │  │  (logs)   │    │    :8080    │                       │    │
│  │  └───────────┘    └─────────────┘                       │    │
│  └─────────────────────────────────────────────────────────┘    │
│                                                                  │
│  Envoy ──► Control Plane API (credentials, rate limits)         │
└─────────────────────────────────────────────────────────────────┘
```

## Features

- **Network Isolation**: Agent container can only reach Envoy proxy and DNS filter
- **Domain Allowlist**: DNS filtering blocks unapproved domains
- **Credential Injection**: Automatic API key injection via `*.devbox.local` aliases
- **Rate Limiting**: Per-domain rate limits with token bucket algorithm
- **Audit Logging**: All requests logged with optional forwarding to OpenObserve
- **Standalone Mode**: Run without control plane using local admin UI
- **Web Terminal**: Browser-based shell access to containers
- **Unified Configuration**: Single `maltbox.yaml` generates CoreDNS and Envoy configs

## Operation Modes

### Connected Mode (with Control Plane)

Features:
- Credentials, rate limits, allowlist synced from control plane
- Agent management via heartbeat polling
- Audit logs shipped to OpenObserve
- Web terminal via control plane admin UI

```bash
export CONTROL_PLANE_URL=http://<control-plane-ip>:8002
export CONTROL_PLANE_TOKEN=your-token
docker-compose up -d
```

### Standalone Mode (Local Admin UI)

Features:
- **Local Admin UI** at http://localhost:8080 with:
  - Structured config editor (domains, rate limits, credentials)
  - Config validation before save
  - Container status monitoring with health checks
  - Log viewer with traffic analytics
  - Browser-based web terminal
  - SSH tunnel setup (Auto-STCP)
- Single `maltbox.yaml` configuration file
- No external dependencies

```bash
# Start with local admin UI
docker-compose --profile admin up -d

# Access at http://localhost:8080
```

## Local Admin UI Features

The local admin UI provides full management capabilities for standalone deployments:

| Feature | Description |
|---------|-------------|
| **Status Dashboard** | Container status, health checks (DNS, Envoy ready), CPU/memory |
| **Structured Config Editor** | Form-based editing for domains, rate limits, credentials |
| **Config Validation** | Domain format, CIDR syntax, required fields validated |
| **Log Viewer** | Live log streaming with traffic analytics (requests/sec, top domains) |
| **Web Terminal** | Browser-based shell into containers (xterm.js) |
| **SSH Tunnel Setup** | Configure STCP tunnel with auto-generated secret keys |

### Config Editor Tabs

| Tab | Description |
|-----|-------------|
| **Domains** | Add/edit/delete allowed domains with aliases, timeouts, rate limits, credentials |
| **Settings** | DNS servers, cache TTL, default rate limits, operation mode |
| **Raw YAML** | Direct maltbox.yaml editing for advanced users |

## Unified Configuration (maltbox.yaml)

All configuration is in a single YAML file that generates both CoreDNS and Envoy configs:

```yaml
# configs/maltbox.yaml
mode: standalone

dns:
  upstream:
    - 8.8.8.8
    - 8.8.4.4
  cache_ttl: 300

rate_limits:
  default:
    requests_per_minute: 120
    burst_size: 20

domains:
  - domain: api.openai.com
    alias: openai           # Creates openai.devbox.local shortcut
    timeout: 120s
    rate_limit:
      requests_per_minute: 60
      burst_size: 10
    credential:
      header: Authorization
      format: "Bearer {value}"
      env: OPENAI_API_KEY

  - domain: github.com
  - domain: api.github.com
    alias: github
    credential:
      header: Authorization
      format: "token {value}"
      env: GITHUB_TOKEN

  - domain: pypi.org
    read_only: true         # Block POST/PUT/DELETE
```

The agent-manager watches `maltbox.yaml` and regenerates CoreDNS Corefile and Envoy config on changes.

## Docker Compose Profiles

```bash
# Base services (agent, envoy, dns-filter, agent-manager)
docker compose up -d

# With local admin UI (standalone mode)
docker compose --profile admin up -d

# With audit logging (adds vector → OpenObserve)
docker compose --profile auditing up -d

# With SSH access via STCP tunnel
docker compose --profile ssh up -d

# Combined
docker compose --profile admin --profile ssh up -d
```

## SSH Access

### Via Web Terminal (Recommended)

The local admin UI includes a browser-based terminal:
1. Go to http://localhost:8080/terminal
2. Select container (agent, dns-filter, envoy-proxy)
3. Click Connect

### Via STCP Tunnel

For SSH client access, configure an STCP tunnel:

1. **Configure tunnel** in Local Admin UI → SSH Tunnel page
2. **Start tunnel** - creates frpc container
3. **Get visitor config** - download frpc-visitor.toml for your local machine
4. **Connect**: `ssh -p 2222 agent@127.0.0.1`

Or configure manually:
```bash
# In .env
FRP_SERVER_ADDR=frp-server-host
FRP_AUTH_TOKEN=your-token
AGENT_ID=my-agent
STCP_SECRET_KEY=generated-secret

# Start with SSH profile
docker-compose --profile ssh up -d
```

## Agent Image Variants

| Variant | Contents | Size |
|---------|----------|------|
| `lean` | SSH, Python, Node.js, git, build tools, curl, jq | ~1.5GB |
| `dev` | Lean + Go, Rust, AWS CLI, Docker CLI | ~3GB |
| `ml` | Dev + PyTorch, numpy, pandas, scikit-learn, transformers | ~6GB |

Set in `.env`:
```bash
AGENT_VARIANT=lean  # or dev, ml
```

## Security Controls

- **Network Isolation**: Agent on internal-only network, cannot reach internet directly
- **IPv6 Disabled**: Prevents bypass of IPv4 egress controls
- **DNS Filtering**: Only allowlisted domains resolve
- **No Credential Exposure**: Agent never sees API keys
- **Rate Limiting**: Prevents runaway API usage
- **Audit Trail**: All egress requests logged
- **Read-only Filesystem**: Agent container has read-only root
- **Resource Limits**: CPU, memory, and PID limits on agent
- **gVisor Isolation** (optional): Kernel-level syscall isolation

## Services

| Service | Port | Network | Description |
|---------|------|---------|-------------|
| agent | 22 | agent-net | Isolated execution environment with SSH |
| envoy-proxy | 8443 | agent-net, infra-net | Egress proxy with credential injection |
| dns-filter | 53 | agent-net, infra-net | CoreDNS with domain allowlist |
| agent-manager | - | infra-net | Container lifecycle, config generation |
| local-admin | 8080 | infra-net | Web UI for standalone mode (optional) |
| vector | - | infra-net | Log collection (optional) |
| frpc | - | agent-net, infra-net | FRP client for STCP tunnel (optional) |

## Files

```
data-plane/
├── docker-compose.yml          # Docker Compose configuration
├── configs/
│   ├── maltbox.yaml            # Main configuration file
│   ├── envoy/
│   │   └── envoy-enhanced.yaml # Envoy proxy (generated from maltbox.yaml)
│   ├── coredns/
│   │   ├── Corefile            # CoreDNS config (generated from maltbox.yaml)
│   │   └── allowlist.hosts     # Static fallback allowlist
│   ├── vector/
│   │   └── vector.yaml         # Log collection config
│   └── frpc/
│       └── frpc.toml           # FRP client configuration
├── services/
│   ├── agent-manager/          # Container lifecycle + config generation
│   ├── local-admin/            # Local admin UI (React + FastAPI)
│   │   ├── frontend/           # React app
│   │   └── backend/            # FastAPI backend
│   └── config-generator/       # maltbox.yaml → CoreDNS/Envoy configs
└── tests/
```
