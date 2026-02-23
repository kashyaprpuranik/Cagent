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
# configs/cagent.yaml
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

The Admin UI at http://localhost:8081 provides a structured editor:
- **Domains tab**: Add/edit/delete with validation
- **Settings tab**: DNS, rate limits, mode
- **Raw YAML tab**: Direct editing

## Connected Mode

For connected mode (centralized management via control plane), see the [cagent-control](https://github.com/kashyaprpuranik/cagent-control) repo.

## Domain Policy Fields

| Field | Type | Description |
|-------|------|-------------|
| `domain` | string | Domain pattern (e.g., `api.openai.com`, `*.github.com`) |
| `alias` | string | Creates `{alias}.devbox.local` shortcut |
| `description` | string | Human-readable description |
| `allowed_paths` | list | Path patterns to allow (default: all) |
| `requests_per_minute` | int | Rate limit (requests per minute) |
| `burst_size` | int | Rate limit burst allowance |
| `credential` | object | Credential to inject (`header`, `format`, `value`) |
| `cell_id` | string | Scope to specific cell (null = tenant-global) |

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

Credentials are stored on domain policies and injected by Envoy at the proxy layer. The cell never sees API keys.

**Domain aliases**: Setting `alias: "openai"` creates an `openai.devbox.local` shortcut. The cell can use `http://openai.devbox.local/v1/models` and Envoy resolves it to `api.openai.com` with credentials injected.

```bash
# In cagent.yaml:
# - domain: api.openai.com
#   alias: openai
#   credential:
#     header: Authorization
#     format: "Bearer {value}"
#     env: OPENAI_API_KEY
#
# Cell can use: curl http://openai.devbox.local/v1/models
```

## SSH Access

Cell containers run an SSH server (key-auth only, no passwords, no root login). SSH is exposed on host port 2222 by default.

### Quick Start

```bash
# Set your public key and start the cell
SSH_AUTHORIZED_KEYS="$(cat ~/.ssh/id_ed25519.pub)" docker compose --profile dev up -d

# Connect
ssh -p 2222 cell@localhost
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
ssh -p 2222 cell@localhost session list

# Detach from tmux: Ctrl+B, then D
# Reconnect: ssh again — auto-attaches to existing session
```

### Multiple Cells

When scaling cells (`--scale cell-dev=N`), each container needs a unique host port. Use a port range:

```bash
# In .env or shell
SSH_PORT=2222-2232

# Find which port maps to which container
docker compose port --index 1 cell-dev 22
docker compose port --index 2 cell-dev 22
```

## Log Collection

In standalone mode with auditing (`--profile auditing`), Vector collects logs from Docker, Envoy, and CoreDNS. Logs are written to local files by default. Configure S3 or Elasticsearch sinks in `configs/vector/sinks/standalone.yaml`.

In connected mode, logs are shipped to the control plane API. See [cagent-control](https://github.com/kashyaprpuranik/cagent-control) for log querying.
