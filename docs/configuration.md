# Configuration Guide

This guide covers configuring domain policies, agent management, and per-agent settings.

## Configuration Methods

| Mode | Method | Description |
|------|--------|-------------|
| **Standalone** | Local Admin UI | http://localhost:8080 - structured form editor |
| **Standalone** | cagent.yaml | Edit `configs/cagent.yaml` directly |
| **Connected** | Control Plane UI | http://localhost:9080 - full admin console |
| **Connected** | Control Plane API | REST API endpoints |

## Standalone Mode: cagent.yaml

In standalone mode, all configuration is in a single YAML file:

```yaml
# data_plane/configs/cagent.yaml
mode: standalone

dns:
  upstream: [8.8.8.8, 8.8.4.4]
  cache_ttl: 300

rate_limits:
  default:
    requests_per_minute: 120
    burst_size: 20

domains:
  - domain: api.openai.com
    alias: openai              # Creates openai.devbox.local
    timeout: 120s
    rate_limit:
      requests_per_minute: 60
      burst_size: 10
    credential:
      header: Authorization
      format: "Bearer {value}"
      env: OPENAI_API_KEY      # Read from environment

  - domain: pypi.org
    read_only: true            # Block POST/PUT/DELETE
```

The Local Admin UI at http://localhost:8080 provides a structured editor:
- **Domains tab**: Add/edit/delete with validation
- **Settings tab**: DNS, rate limits, mode
- **Raw YAML tab**: Direct editing

## Connected Mode: Control Plane

### Domain Policies (Unified)

Domain policies combine all settings for a domain in one place: allowlist, path filtering, rate limits, and credentials.

```bash
# Create a domain policy with all settings
curl -X POST http://localhost:8002/api/v1/domain-policies \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "domain": "api.openai.com",
    "alias": "openai",
    "description": "OpenAI API",
    "allowed_paths": ["/v1/chat/*", "/v1/models", "/v1/embeddings"],
    "requests_per_minute": 60,
    "burst_size": 10,
    "credential": {
      "header": "Authorization",
      "format": "Bearer {value}",
      "value": "sk-..."
    }
  }'

# List all domain policies
curl http://localhost:8002/api/v1/domain-policies \
  -H "Authorization: Bearer $TOKEN"

# Get a single policy
curl http://localhost:8002/api/v1/domain-policies/1 \
  -H "Authorization: Bearer $TOKEN"

# Update a policy
curl -X PUT http://localhost:8002/api/v1/domain-policies/1 \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"requests_per_minute": 120}'

# Delete a policy
curl -X DELETE http://localhost:8002/api/v1/domain-policies/1 \
  -H "Authorization: Bearer $TOKEN"

# Rotate a credential
curl -X POST http://localhost:8002/api/v1/domain-policies/1/rotate-credential \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"value": "sk-new-..."}'

# Lookup policy for a domain (used by Envoy/agent-manager)
curl "http://localhost:8002/api/v1/domain-policies/for-domain?domain=api.openai.com" \
  -H "Authorization: Bearer $TOKEN"

# Export policies (CoreDNS format for DNS filtering)
curl http://localhost:8002/api/v1/domain-policies/export \
  -H "Authorization: Bearer $TOKEN"
```

The agent-manager syncs policies from the control plane to CoreDNS (for DNS filtering) and Envoy (for rate limits, path filtering, and credentials).

### Domain Policy Fields

| Field | Type | Description |
|-------|------|-------------|
| `domain` | string | Domain pattern (e.g., `api.openai.com`, `*.github.com`) |
| `alias` | string | Creates `{alias}.devbox.local` shortcut |
| `description` | string | Human-readable description |
| `allowed_paths` | list | Path patterns to allow (default: all) |
| `requests_per_minute` | int | Rate limit (requests per minute) |
| `burst_size` | int | Rate limit burst allowance |
| `credential` | object | Credential to inject (`header`, `format`, `value`) |
| `agent_id` | string | Scope to specific agent (null = tenant-global) |

### Path Filtering

By default, all paths are allowed for a domain. You can restrict access to specific paths using the `allowed_paths` field.

**Pattern syntax:**
- `/v1/chat/completions` - exact match
- `/v1/chat/*` - prefix match (matches `/v1/chat/completions`, `/v1/chat/stream`)
- `/api/v2*` - prefix match without slash (matches `/api/v2/users`, `/api/v2`)

**Use cases:**
- Block file upload endpoints (exfiltration risk)
- Restrict to read-only API operations
- Allow specific API versions only

### Credential Injection

Credentials are stored on domain policies and injected by Envoy at the proxy layer. The agent never sees API keys.

**Domain aliases**: Setting `alias: "openai"` creates an `openai.devbox.local` shortcut. The agent can use `http://openai.devbox.local/v1/models` and Envoy resolves it to `api.openai.com` with credentials injected.

```bash
# Domain policy with credential
curl -X POST http://localhost:8002/api/v1/domain-policies \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "domain": "api.openai.com",
    "alias": "openai",
    "credential": {
      "header": "Authorization",
      "format": "Bearer {value}",
      "value": "sk-..."
    }
  }'
# Agent can now use: curl http://openai.devbox.local/v1/models
```

## Agent Management

Via Admin UI dashboard or API. Agent identity is derived from the agent token — each token maps to a unique agent_id on the control plane.

```bash
# List all connected agents
curl http://localhost:8002/api/v1/agents \
  -H "Authorization: Bearer $TOKEN"

# Get agent status
curl http://localhost:8002/api/v1/agents/my-agent/status \
  -H "Authorization: Bearer $TOKEN"

# Wipe agent (admin only)
curl -X POST http://localhost:8002/api/v1/agents/my-agent/wipe \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"wipe_workspace": false}'

# Stop/Start/Restart agent (admin only)
curl -X POST http://localhost:8002/api/v1/agents/my-agent/stop \
  -H "Authorization: Bearer $TOKEN"
curl -X POST http://localhost:8002/api/v1/agents/my-agent/start \
  -H "Authorization: Bearer $TOKEN"
curl -X POST http://localhost:8002/api/v1/agents/my-agent/restart \
  -H "Authorization: Bearer $TOKEN"

```

## Per-Agent Configuration

Domain policies can be scoped to specific agents. Global policies (without `agent_id`) apply to all agents in the tenant.

### How it works

- **Global policies** (`agent_id` = null): Apply to all agents in the tenant
- **Agent-specific policies** (`agent_id` = "my-agent"): Only apply to that agent
- **Precedence**: Agent-specific policies take precedence over global policies for the same domain

### Creating agent-specific configuration

```bash
# Agent-specific domain policy
curl -X POST http://localhost:8002/api/v1/domain-policies \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "domain": "internal-api.example.com",
    "description": "Internal API for prod-agent only",
    "agent_id": "prod-agent",
    "credential": {
      "header": "Authorization",
      "format": "Bearer {value}",
      "value": "sk-prod-..."
    }
  }'

# Agent-specific rate limit override
curl -X POST http://localhost:8002/api/v1/domain-policies \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "domain": "api.openai.com",
    "requests_per_minute": 120,
    "burst_size": 20,
    "description": "Higher limits for prod-agent",
    "agent_id": "prod-agent"
  }'
```

### Agent token scoping

Agent tokens only see domain policies for their assigned agent plus global policies:

```bash
# Create agent token
curl -X POST http://localhost:8002/api/v1/tokens \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name": "prod-token", "token_type": "agent", "agent_id": "prod-agent"}'

# Using the agent token to fetch policies
# - Returns prod-agent's policies + global policies
# - Does NOT return other agents' policies
curl "http://localhost:8002/api/v1/domain-policies/for-domain?domain=api.example.com" \
  -H "Authorization: Bearer <prod-agent-token>"
```

## SSH Access

Agent containers run an SSH server (key-auth only, no passwords, no root login). SSH is exposed on host port 2222 by default.

### Quick Start

```bash
# Set your public key and start the agent
SSH_AUTHORIZED_KEYS="$(cat ~/.ssh/id_ed25519.pub)" docker compose --profile dev up -d

# Connect
ssh -p 2222 agent@localhost
```

### Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `SSH_AUTHORIZED_KEYS` | (empty) | Public key(s) to authorize, newline-separated |
| `SSH_PORT` | `2222` | Host port mapped to container SSH (port 22) |

You can also mount a keys file instead of (or in addition to) the environment variable:

```yaml
# In docker-compose.yml, uncomment:
volumes:
  - ./ssh-keys/authorized_keys:/ssh-keys/authorized_keys:ro
```

### Persistent Sessions (tmux)

SSH sessions auto-attach to a tmux session. Work persists across SSH disconnects and container restarts (the tmux socket is stored on the persistent `/workspace` volume).

```bash
# List sessions
ssh -p 2222 agent@localhost session list

# Detach from tmux: Ctrl+B, then D
# Reconnect: ssh again — auto-attaches to existing session
```

### Multiple Agents

When scaling agents (`--scale agent-dev=N`), each container needs a unique host port. Use a port range:

```bash
# In .env or shell
SSH_PORT=2222-2232

# Find which port maps to which container
docker compose port --index 1 agent-dev 22
docker compose port --index 2 agent-dev 22
```

### Remote SSH (via STCP Tunnel)

For agents on remote hosts not directly reachable, use the FRP STCP tunnel instead of port mapping. See the [STCP tunnel configuration](#) in the data plane docker-compose (`--profile ssh`).

## Log Querying

Agent logs (Envoy, CoreDNS, gVisor, container stdout/stderr) are queryable via the Control Plane API.

### Tenant Filtering

Logs are automatically filtered by tenant:
- **Super admins**: Can query all logs, optionally filter by `tenant_id`
- **Tenant admins/developers**: Only see logs from their tenant's agents
- **Agent-specific queries**: Verified against user's tenant access

```bash
# Query logs (filtered to your tenant automatically)
curl "http://localhost:8002/api/v1/logs/query?source=envoy&limit=100" \
  -H "Authorization: Bearer $TOKEN"

# Super admin: query specific tenant
curl "http://localhost:8002/api/v1/logs/query?tenant_id=1&source=gvisor" \
  -H "Authorization: Bearer $TOKEN"

# Query specific agent (must have access)
curl "http://localhost:8002/api/v1/logs/query?agent_id=prod-agent&source=agent" \
  -H "Authorization: Bearer $TOKEN"
```

### Log Sources

| Source | Description |
|--------|-------------|
| `envoy` | HTTP proxy access logs (method, path, response code) |
| `coredns` | DNS query logs |
| `gvisor` | Syscall audit logs (if using gVisor runtime) |
| `agent` | Container stdout/stderr |
| `agent-manager` | Agent manager service logs |

### Log Ingestion (Agent Tokens)

Data planes send logs to the Control Plane, which injects trusted identity before forwarding to OpenObserve:

```bash
# Agent token sends logs to CP (not directly to OpenObserve)
curl -X POST http://localhost:8002/api/v1/logs/ingest \
  -H "Authorization: Bearer $AGENT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "logs": [
      {"message": "Request completed", "source": "envoy", "level": "info"},
      {"message": "DNS query: api.openai.com", "source": "coredns"}
    ]
  }'
```

This architecture ensures:
- Data planes never have OpenObserve credentials
- `agent_id` and `tenant_id` are injected from verified token
- Agents cannot spoof their identity in logs
