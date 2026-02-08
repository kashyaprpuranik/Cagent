# Configuration Guide

This guide covers configuring allowlists, secrets, rate limits, and per-agent settings.

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
# data-plane/configs/cagent.yaml
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

## Domain Policies (Unified)

Domain policies combine all settings for a domain in one place: allowlist, paths, rate limits, egress limits, and credentials.

```bash
# Create a domain policy with all settings
curl -X POST http://localhost:8002/api/v1/domain-policies \
  -H "Authorization: Bearer admin-token" \
  -H "Content-Type: application/json" \
  -d '{
    "domain": "api.openai.com",
    "alias": "openai",
    "description": "OpenAI API",
    "allowed_paths": ["/v1/chat/*", "/v1/models", "/v1/embeddings"],
    "requests_per_minute": 60,
    "burst_size": 10,
    "bytes_per_hour": 10485760,
    "credential": {
      "header": "Authorization",
      "format": "Bearer {value}",
      "value": "sk-..."
    }
  }'

# List all domain policies
curl http://localhost:8002/api/v1/domain-policies \
  -H "Authorization: Bearer admin-token"

# Update a policy
curl -X PUT http://localhost:8002/api/v1/domain-policies/1 \
  -H "Authorization: Bearer admin-token" \
  -H "Content-Type: application/json" \
  -d '{"requests_per_minute": 120}'

# Delete a policy
curl -X DELETE http://localhost:8002/api/v1/domain-policies/1 \
  -H "Authorization: Bearer admin-token"
```

The agent-manager syncs policies from the control plane to CoreDNS (for DNS filtering) and Envoy (for all other policies).

## Path Filtering

By default, all paths are allowed for a domain. You can restrict access to specific paths by adding path patterns when creating or updating an allowlist entry.

**Behavior:**
- No paths defined → all paths allowed (backwards compatible)
- Paths defined → only matching paths allowed (allowlist)

**Pattern syntax:**
- `/v1/chat/completions` - exact match
- `/v1/chat/*` - prefix match (matches `/v1/chat/completions`, `/v1/chat/stream`)
- `/api/v2*` - prefix match without slash (matches `/api/v2/users`, `/api/v2`)

```bash
# Add domain with path restrictions
curl -X POST http://localhost:8002/api/v1/allowlist \
  -H "Authorization: Bearer admin-token" \
  -H "Content-Type: application/json" \
  -d '{
    "entry_type": "domain",
    "value": "api.openai.com",
    "description": "OpenAI API - chat only",
    "paths": [
      {"pattern": "/v1/chat/*", "description": "Chat completions"},
      {"pattern": "/v1/models", "description": "List models"},
      {"pattern": "/v1/embeddings", "description": "Embeddings"}
    ]
  }'
# Blocks: /v1/files (upload), /v1/fine-tuning, etc.

# Add path to existing domain
curl -X POST http://localhost:8002/api/v1/allowlist/1/paths \
  -H "Authorization: Bearer admin-token" \
  -H "Content-Type: application/json" \
  -d '{"pattern": "/v1/audio/transcriptions", "description": "Whisper API"}'

# Remove path from domain
curl -X DELETE http://localhost:8002/api/v1/allowlist/1/paths/5 \
  -H "Authorization: Bearer admin-token"
```

**Use cases:**
- Block file upload endpoints (exfiltration risk)
- Restrict to read-only API operations
- Allow specific API versions only

## Adding Secrets (Domain-Scoped)

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

## Agent Management

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
  -H "Authorization: Bearer admin-token" \
  -H "Content-Type: application/json" \
  -d '{
    "entry_type": "domain",
    "value": "internal-api.example.com",
    "description": "Internal API for prod-agent only",
    "agent_id": "prod-agent"
  }'

# Agent-specific secret
curl -X POST http://localhost:8002/api/v1/secrets \
  -H "Authorization: Bearer admin-token" \
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
  -H "Authorization: Bearer admin-token" \
  -H "Content-Type: application/json" \
  -d '{
    "domain_pattern": "api.openai.com",
    "requests_per_minute": 120,
    "burst_size": 20,
    "description": "Higher limit for prod-agent",
    "agent_id": "prod-agent"
  }'

# Agent-specific egress limit
curl -X POST http://localhost:8002/api/v1/egress-limits \
  -H "Authorization: Bearer admin-token" \
  -H "Content-Type: application/json" \
  -d '{
    "domain_pattern": "api.openai.com",
    "bytes_per_hour": 52428800,
    "description": "50MB/hour for prod-agent",
    "agent_id": "prod-agent"
  }'
```

### Agent token scoping

Agent tokens only see configuration for their assigned agent plus global configuration:

```bash
# Create agent token
curl -X POST http://localhost:8002/api/v1/tokens \
  -H "Authorization: Bearer admin-token" \
  -H "Content-Type: application/json" \
  -d '{"name": "prod-token", "token_type": "agent", "agent_id": "prod-agent"}'

# Using the agent token to fetch secrets
# - Returns prod-agent's secrets + global secrets
# - Does NOT return other agents' secrets
curl http://localhost:8002/api/v1/secrets/for-domain?domain=api.example.com \
  -H "Authorization: Bearer <prod-agent-token>"
```

## Egress Limits

Egress limits control the amount of data (bytes per hour) that can be sent to each domain. This helps prevent data exfiltration and runaway costs.

**Limitation**: Byte counts are tracked in-memory by Envoy and reset when Envoy restarts. See the roadmap for persistent state support.

### Standalone Mode

Configure via environment variable:
```bash
# Format: domain:bytes_per_hour (comma-separated)
STATIC_EGRESS_LIMITS="api.openai.com:10485760,default:104857600"  # 10MB for OpenAI, 100MB default
```

### Connected Mode (Control Plane)

```bash
# List all egress limits
curl http://localhost:8002/api/v1/egress-limits \
  -H "Authorization: Bearer admin-token"

# Create egress limit (global)
curl -X POST http://localhost:8002/api/v1/egress-limits \
  -H "Authorization: Bearer admin-token" \
  -H "Content-Type: application/json" \
  -d '{
    "domain_pattern": "api.openai.com",
    "bytes_per_hour": 10485760,
    "description": "10MB/hour for OpenAI"
  }'

# Create agent-specific egress limit
curl -X POST http://localhost:8002/api/v1/egress-limits \
  -H "Authorization: Bearer admin-token" \
  -H "Content-Type: application/json" \
  -d '{
    "domain_pattern": "*.github.com",
    "bytes_per_hour": 52428800,
    "description": "50MB/hour for GitHub",
    "agent_id": "prod-agent"
  }'

# Update egress limit
curl -X PUT http://localhost:8002/api/v1/egress-limits/1 \
  -H "Authorization: Bearer admin-token" \
  -H "Content-Type: application/json" \
  -d '{"bytes_per_hour": 20971520}'

# Delete egress limit
curl -X DELETE http://localhost:8002/api/v1/egress-limits/1 \
  -H "Authorization: Bearer admin-token"
```

### Common byte values

| Size | Bytes |
|------|-------|
| 1 MB | 1048576 |
| 10 MB | 10485760 |
| 50 MB | 52428800 |
| 100 MB | 104857600 |
| 500 MB | 524288000 |
| 1 GB | 1073741824 |

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
  -H "Authorization: Bearer $SUPER_ADMIN_TOKEN"

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
