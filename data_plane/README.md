# Cagent - Data Plane

The data plane provides a secure, isolated execution environment for AI agents with controlled network egress, credential injection, and audit logging.

## Roadmap

- **Network content restrictions** - Deep packet inspection and response body filtering for HTTP egress (e.g., block downloads over N bytes, restrict content types, PII detection in outbound requests)

## Architecture

### Minimal (Static Config)

Lightweight 3-container setup (~70MB overhead). Edit configs directly.

```
┌───────────────────────────────────────────────────────┐
│                  agent-net (isolated)                  │
│                                                        │
│    ┌────────────────────────────────────────────┐     │
│    │              Agent Container                │     │
│    │  • Isolated network (no direct internet)    │     │
│    │  • All HTTP(S) via HTTP Proxy                │     │
│    │  • DNS via DNS Filter                       │     │
│    └────────────────────────────────────────────┘     │
│                 │                   │                  │
│                 ▼                   ▼                  │
│          ┌───────────┐       ┌───────────┐            │
│          │HTTP Proxy │       │DNS Filter │            │
│          │  (~50MB)  │       │  (~20MB)  │            │
│          └─────┬─────┘       └───────────┘            │
│                │                                       │
└────────────────┼───────────────────────────────────────┘
                 │
                 ▼ HTTPS (allowlisted domains only)
              Internet
```

### Managed (With Admin UI)

Adds agent-manager and local admin UI for browser-based management.

```
┌─────────────────────────────────────────────────────────────────┐
│                         DATA PLANE                               │
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
│  │          │ HTTP Proxy  │         │ DNS Filter  │           ││
│  │          └──────┬──────┘         └─────────────┘           ││
│  └─────────────────┼───────────────────────────────────────────┘│
│                    │                                             │
└────────────────────┼─────────────────────────────────────────────┘
                     │
                     ▼ HTTPS (allowlisted domains only)
                  Internet
```

### Control Plane Mode

Connects to centralized control plane for configuration and log shipping.

**Log Flow**: Agent logs are shipped to the Control Plane API, which injects trusted `agent_id` and `tenant_id` before forwarding to OpenObserve. This ensures data planes cannot spoof their identity and prevents exposure of OpenObserve credentials.

```
┌─────────────────────────────────────────────────────────────────┐
│                         DATA PLANE                               │
│                                                                  │
│  ┌──────────────┐    ┌──────────┐    ┌──────────┐              │
│  │Agent Manager │    │Log Ship. │    │ Tunnel   │              │
│  │ (polls CP)   │    │  (logs)  │    │  (STCP)  │              │
│  └──────┬───────┘    └────┬─────┘    └────┬─────┘              │
│         │                  │               │                    │
│         │    ┌─────────────┼───────────────┼──────────────┐    │
│         │    │         agent-net           │              │    │
│         │    │  ┌─────────────────────┐    │              │    │
│         │    │  │   Agent Container   │◄───┘ SSH:22       │    │
│         │    │  └─────────────────────┘                   │    │
│         │    │         │           │                      │    │
│         │    │    ┌────┴────┐ ┌────┴────┐                │    │
│         │    │    │HTTP Prxy│ │DNS Fltr │                │    │
│         │    │    └────┬────┘ └─────────┘                │    │
│         │    └─────────┼──────────────────────────────────┘    │
└─────────┼──────────────┼───────────────────────────────────────┘
          │              │
          ▼              ▼
    Control Plane    Internet
     (API + logs)
```

## Features

- **Network Isolation**: Agent container can only reach Envoy proxy and DNS filter
- **Domain Allowlist**: DNS filtering blocks unapproved domains
- **Credential Injection**: Automatic API key injection via `*.devbox.local` aliases
- **Rate Limiting**: Per-domain rate limits with token bucket algorithm
- **Audit Logging**: All requests logged with optional forwarding to OpenObserve
- **Standalone Mode**: Run without control plane using local admin UI
- **Web Terminal**: Browser-based shell access to containers
- **Unified Configuration**: Single `cagent.yaml` generates CoreDNS and Envoy configs

## Operation Modes

### Control Plane Mode

Features:
- Credentials, rate limits, allowlist synced from control plane
- Agent management via heartbeat polling
- Audit logs shipped to OpenObserve
- Web terminal via control plane admin UI

```bash
export CONTROL_PLANE_URL=http://<control-plane-ip>:8002
export CONTROL_PLANE_TOKEN=your-token
docker compose --profile standard --profile managed up -d  # or --profile dev if no gVisor
```

### Standalone Mode

#### Minimal (Static Config)

Lightweight 3-container setup with two config options:

**Option A: Edit cagent.yaml and regenerate** (recommended)
```bash
# Edit configs/cagent.yaml, then generate CoreDNS and Envoy configs
python services/config_generator/config_generator.py \
  --config configs/cagent.yaml \
  --coredns configs/coredns/Corefile \
  --envoy configs/envoy/envoy.yaml

# Start containers
docker compose --profile standard up -d  # or --profile dev if no gVisor
```

**Option B: Edit raw configs directly** (advanced)
```bash
# Edit configs/coredns/Corefile and configs/envoy/envoy-enhanced.yaml directly
docker compose --profile standard up -d  # or --profile dev if no gVisor
```

#### Managed (With Admin UI)

Adds agent-manager (watches `cagent.yaml`) and local admin UI.

```bash
# With gVisor (recommended)
docker compose --profile standard --profile admin up -d

# Without gVisor (development)
docker compose --profile dev --profile admin up -d

# Access at http://localhost:8080
```

Features:
- **Local Admin UI** at http://localhost:8080 with:
  - Structured config editor (domains, rate limits, credentials)
  - Config validation before save
  - Container status monitoring with health checks
  - Log viewer with traffic analytics
  - Browser-based web terminal
  - SSH tunnel setup (Auto-STCP)
- Single `cagent.yaml` configuration file
- No external dependencies

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
| **Raw YAML** | Direct cagent.yaml editing for advanced users |

## Unified Configuration (cagent.yaml)

All configuration is in a single YAML file that generates both CoreDNS and Envoy configs:

```yaml
# configs/cagent.yaml
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

With `--profile managed` or `--profile admin`, agent-manager watches `cagent.yaml` and regenerates CoreDNS/Envoy configs on changes. Without it, edit configs directly.

### Email Configuration (Beta)

Add `--profile email` to enable controlled email access. Agent accesses email via `http://email.devbox.local/...`.

```yaml
# In configs/cagent.yaml
email:
  accounts:
    - name: work-gmail
      provider: gmail              # gmail | outlook | generic
      email: agent@company.com
      credential:
        client_id_env: GMAIL_CLIENT_ID
        client_secret_env: GMAIL_CLIENT_SECRET
        refresh_token_env: GMAIL_REFRESH_TOKEN
      policy:
        allowed_recipients:
          - "*@company.com"
        allowed_senders:
          - "*"
        sends_per_hour: 50
        reads_per_hour: 200
```

```bash
# Set credentials in .env or shell
export GMAIL_CLIENT_ID=...
export GMAIL_CLIENT_SECRET=...
export GMAIL_REFRESH_TOKEN=...

# Start with email profile
docker compose --profile dev --profile email up -d
```

## Docker Compose Profiles

| Profile | Services Added | Description |
|---------|----------------|-------------|
| `standard` | agent (gVisor) | **Recommended** - kernel-level syscall isolation |
| `dev` | agent (runc) | For development or when gVisor unavailable |
| `managed` | agent-manager | Config file watching |
| `admin` | agent-manager + local-admin UI | Web-based management |
| `auditing` | log-shipper | Forward logs to control plane |
| `ssh` | tunnel-client (STCP tunnel) | Remote SSH access |
| `email` | email-proxy | Controlled email access (IMAP/SMTP) - **beta** |

```bash
# Standard mode with gVisor (RECOMMENDED - requires gVisor installed)
docker compose --profile standard up -d

# Development mode without gVisor
docker compose --profile dev up -d

# With local admin UI
docker compose --profile standard --profile admin up -d

# Development with admin UI
docker compose --profile dev --profile admin up -d

# With audit logging
docker compose --profile standard --profile admin --profile auditing up -d

# With SSH access via STCP tunnel
docker compose --profile standard --profile admin --profile ssh up -d
```

## SSH Access

### Direct SSH (Recommended)

SSH is exposed on host port 2222 by default. Set your public key and connect:

```bash
# Start with SSH key
SSH_AUTHORIZED_KEYS="$(cat ~/.ssh/id_ed25519.pub)" docker compose --profile dev up -d

# Connect
ssh -p 2222 agent@localhost
```

Configure the host port with `SSH_PORT` (default: 2222). Sessions auto-attach to tmux for persistence across disconnects.

### Via Web Terminal

The local admin UI includes a browser-based terminal:
1. Go to http://localhost:8080/terminal
2. Select container (agent, dns-filter, http-proxy)
3. Click Connect

### Via STCP Tunnel (Remote Access)

For SSH access to agents on remote hosts, configure an STCP tunnel:

1. **Configure tunnel** in Local Admin UI → SSH Tunnel page
2. **Start tunnel** - creates frpc container
3. **Get visitor config** - download frpc-visitor.toml for your local machine
4. **Connect**: `ssh -p 2222 agent@127.0.0.1`

Or configure manually:
```bash
# In .env
FRP_SERVER_ADDR=frp-server-host
FRP_AUTH_TOKEN=your-token
STCP_PROXY_NAME=my-agent-ssh    # From setup_ssh_tunnel.sh
STCP_SECRET_KEY=generated-secret

# Start with SSH profile
docker compose --profile ssh up -d
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

- **Network Isolation**: Agent on internal-only network (`internal: true`), no default gateway
- **iptables Fallback**: Optional script adds explicit DROP rules (run `sudo ./scripts/network_hardening.sh`)
- **Seccomp Profile**: Blocks raw socket creation to prevent packet-crafting bypass
- **IPv6 Disabled**: Prevents bypass of IPv4 egress controls
- **DNS Filtering**: Only allowlisted domains resolve
- **No Credential Exposure**: Agent never sees API keys
- **Rate Limiting**: Prevents runaway API usage
- **Audit Trail**: All proxy requests logged
- **Resource Limits**: CPU, memory, and PID limits on agent
- **gVisor Isolation** (optional): Kernel-level syscall isolation

## Services

| Service | Port | Network | Profile | Description |
|---------|------|---------|---------|-------------|
| agent | 22 | agent-net | standard/secure | Isolated execution environment |
| http-proxy | 8443 | agent-net, infra-net | - | Egress proxy with credential injection |
| dns-filter | 53 | agent-net, infra-net | - | DNS filter with domain allowlist |
| agent-manager | - | infra-net | managed/admin | Config watching and regeneration |
| local-admin | 8080 | infra-net | admin | Web UI for standalone mode |
| log-shipper | - | infra-net | auditing | Log forwarding to control plane |
| tunnel-client | - | agent-net, infra-net | ssh | STCP tunnel for SSH access |
| email-proxy | 8025 | infra-net | email | Email proxy (IMAP/SMTP with OAuth) - **beta** |

## Files

```
data_plane/
├── docker-compose.yml          # Docker Compose configuration
├── configs/
│   ├── cagent.yaml            # Main configuration file
│   ├── envoy/
│   │   └── envoy-enhanced.yaml # HTTP proxy config (generated from cagent.yaml)
│   ├── coredns/
│   │   ├── Corefile            # DNS filter config (generated from cagent.yaml)
│   │   └── allowlist.hosts     # Static fallback allowlist
│   ├── vector/
│   │   └── vector.yaml         # Log collection config
│   └── frpc/
│       └── frpc.toml           # FRP client configuration
├── services/
│   ├── agent_manager/          # Container lifecycle + config generation
│   ├── email_proxy/            # Email proxy (IMAP/SMTP with OAuth)
│   │   ├── providers/          # Gmail, Outlook, generic providers
│   │   └── tests/              # Unit tests
│   ├── local_admin/            # Local admin UI (React + FastAPI)
│   │   ├── frontend/           # React app
│   │   └── backend/            # FastAPI backend
│   └── config_generator/       # cagent.yaml → DNS filter/HTTP proxy configs
└── tests/
```
