# CLAUDE.md

This file provides guidance for AI assistants working with the Cagent codebase.

## Project Overview

Cagent is a secure development and execution environment for AI agents with isolated networking. It prevents data exfiltration, supply chain attacks, and lateral movement from untrusted AI agents through network-isolated sandboxes with controlled egress, domain allowlists, rate limiting, and credential injection.

The control plane (centralized multi-tenant management) lives in a separate private repo: [cagent-control](https://github.com/kashyaprpuranik/cagent-control).

## Architecture

This repo contains the **data plane** — the secure agent execution environment:

- **Cell**: Network-isolated sandbox where AI agents run
- **HTTP Proxy** (Envoy): Egress gateway with domain allowlist, rate limiting, path filtering, and credential injection
- **DNS Filter** (CoreDNS): Domain allowlist enforcement at DNS level
- **Warden**: Config sync daemon + local admin UI (FastAPI + React)
- **Log Shipper** (Vector): Log collection with mode-specific sinks (file, S3, Elasticsearch, or CP)
- **Email Proxy**: IMAP/SMTP proxy with per-recipient policies (beta)

### Related Repos

| Repo | Description |
|------|-------------|
| [cagent-control](https://github.com/kashyaprpuranik/cagent-control) (private) | Control plane — API, frontend, e2e tests, full-stack orchestration |
| [cagent-ui](https://github.com/kashyaprpuranik/cagent-ui) | Shared React components consumed by both frontends |

### Deployment Modes

- **Standalone**: Single data plane with local admin UI, configured via `cagent.yaml`
- **Connected**: Data plane synced to a control plane via API (see cagent-control repo)

## Repository Structure

```
.
├── docker-compose.yml              # DP services (cell, envoy, coredns, vector, warden, email-proxy)
├── cell.Dockerfile                 # Cell container image
├── configs/
│   ├── cagent.yaml                 # Unified config (source of truth for DNS + proxy)
│   ├── coredns/Corefile            # DNS filter config (generated from cagent.yaml)
│   ├── envoy/                      # HTTP proxy config (generated from cagent.yaml)
│   ├── vector/                     # Log collection (sources/transforms + mode-specific sinks)
│   ├── seccomp/                    # Seccomp profile for cell container
│   └── gvisor/runsc.toml           # gVisor runtime config
├── services/
│   ├── warden/               # Config sync, admin UI, domain policy API
│   │   └── frontend/               # React admin UI (built into warden image)
│   └── email_proxy/                # Email egress control (beta)
├── tests/                          # Unit and E2E tests
├── scripts/
│   ├── local.sh                    # Dev environment orchestration
│   ├── run_tests.sh                # Test runner
│   └── seed_traffic.py             # Traffic seeding utility
├── docs/                           # Configuration guide
```

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Warden | Python, FastAPI |
| Frontend | React 18, TypeScript, Vite, TailwindCSS, TanStack React Query |
| Terminal | xterm.js (local admin WebSocket terminal), direct SSH (port 2222) |
| Proxy | Envoy (HTTP egress gateway with credential injection) |
| DNS | CoreDNS (domain allowlist enforcement) |
| Logging | Vector (log collection) |
| Containers | Docker, Docker Compose, gVisor (optional) |
| Shared UI | @cagent/ui (installed from git URL) |

## Common Commands

### Development Environment

```bash
# Standalone with admin UI (default)
./scripts/local.sh

# Minimal (no warden, static config)
./scripts/local.sh --minimal

# Stop everything
./scripts/local.sh down
```

### Running Tests

```bash
# DP unit/config tests + frontend type-check (default)
./scripts/run_tests.sh

# All tests including E2E (requires Docker)
./scripts/run_tests.sh --e2e
```

#### DP Tests Directly

```bash
pip install -r requirements-test.txt
pytest tests/ -v --ignore=tests/test_e2e.py    # unit + config tests
pytest tests/test_e2e.py -v                     # E2E (requires Docker)
```

### Docker Operations

```bash
# Rebuild and restart a single service
docker compose build warden && docker compose up -d warden

# View logs
docker compose logs -f warden

# Enter cell container shell
docker exec -it cell bash
```

### Frontend Development

```bash
# Admin UI (built into warden)
cd services/warden/frontend && npm install && npm run dev

# Lint (fails on any warning)
npm run lint
```

## Key Conventions

### Warden

- **Framework**: FastAPI with background polling loop (main_loop in separate thread)
- **Config generation**: `config_generator.py` reads `cagent.yaml` and generates CoreDNS Corefile + Envoy config (with ext_authz + local_ratelimit filters)
- **Routers**: health, config, containers, logs, terminal, analytics, ssh_tunnel, domain_policy, ext_authz
- **ext_authz endpoint**: Implements Envoy ext_authz HTTP protocol for credential injection (connected: proxy to CP, standalone: resolve from cagent.yaml)
- **Domain policy API**: Serves domain policy lookups (connected: proxy to CP, standalone: resolve from cagent.yaml)
- **Beta features**: Gated by `BETA_FEATURES` env var (comma-separated). Currently: `email`

### Testing

- **Framework**: pytest
- **DP tests**: Unit tests for config generator, DNS filter rules, Envoy config, credential injection. E2E tests require Docker
- **Markers**: `@pytest.mark.e2e` for tests requiring Docker containers

### Frontend

- **Build**: `tsc && vite build` (TypeScript checked before bundling)
- **Linting**: ESLint with `--max-warnings 0` (zero tolerance for warnings)
- **State**: TanStack React Query for server state
- **Routing**: React Router v6
- **Styling**: TailwindCSS with PostCSS/Autoprefixer
- **Shared components**: `@cagent/ui` package (from github:kashyaprpuranik/cagent-ui)

### Docker / Infrastructure

- **Networks**: `cell-net` (10.200.1.0/24, internal, no external access) and `infra-net` (10.200.2.0/24, can reach external). IPv6 disabled to prevent bypass
- **Static IPs**: dns-filter=10.200.1.5, http-proxy=10.200.1.10, cell=10.200.1.20
- **Profiles**: `dev` (runc), `standard` (gVisor), `admin` (admin UI via warden), `managed` (warden without UI), `auditing` (log shipping), `ssh` (FRP tunnel), `email` (email proxy - beta)
- **Config generation**: `cagent.yaml` is the primary source. In connected mode, warden merges CP domain policies into config generation (see Config Sources below)
- **Security layers**: Seccomp profile blocks raw sockets, gVisor intercepts syscalls, Envoy enforces domain allowlist/rate limits/path filtering, CoreDNS blocks unauthorized DNS
- **Vector sinks**: `configs/vector/sinks/standalone.yaml` (file backup + optional S3/ES) or `sinks/connected.yaml` (CP API + file backup), selected via `DATAPLANE_MODE` env var

## Data Flow

1. Cell makes HTTP request via `HTTP_PROXY` (Envoy at 10.200.1.10:8443)
2. Envoy ext_authz calls warden for credential injection (returns credential headers if configured)
3. Envoy local_ratelimit enforces per-domain rate limits (global default + per-route overrides)
4. Envoy router matches domain (virtual host) and path (route rules), forwards to upstream or returns 403
5. DNS queries go through CoreDNS (10.200.1.5) which only resolves allowed domains
6. Vector collects logs from Docker/Envoy/CoreDNS and writes to file (standalone) or ships to CP (connected)
7. In connected mode, warden polls CP for policy updates and regenerates configs

## Config Sources (Standalone vs Connected)

In standalone mode, `cagent.yaml` is the sole config source. In connected mode, warden syncs additional data from the control plane and merges it. The full breakdown:

| Config Section | Source | Notes |
|----------------|--------|-------|
| `domains[]` | yaml + CP (merged) | CP domains synced via `GET /api/v1/domain-policies`; yaml entries take precedence. Credentials are NOT in config — ext_authz resolves them per-request. |
| `dns` (upstream, cache_ttl) | yaml only | No CP equivalent |
| `internal_services[]` | yaml only | devbox.local, etc. |
| `circuit_breakers` | yaml only | No CP equivalent |
| `rate_limits.default` | yaml only | Global fallback; per-domain overrides come from domains[] |
| `security.seccomp_profile` | CP via heartbeat | Pushed in heartbeat response, not config generation |
| `resources` (cpu/mem) | CP via heartbeat | Pushed in heartbeat response, not config generation |
| `email.accounts[]` | yaml only (**gap**) | CP has `/api/v1/email-policies` but warden doesn't sync them yet |

## Important Files

| File | Purpose |
|------|---------|
| `configs/cagent.yaml` | Unified data plane config |
| `services/warden/config_generator.py` | Generates CoreDNS + Envoy configs |
| `services/warden/main.py` | Warden: FastAPI app, polling loop, admin UI |
| `services/warden/routers/domain_policy.py` | Domain policy API for domain lookups |
| `services/warden/routers/ext_authz.py` | ext_authz endpoint for Envoy credential injection |
| `docker-compose.yml` | Service definitions |
| `scripts/local.sh` | Dev environment orchestration |
| `scripts/run_tests.sh` | Test runner |

## Gotchas

- `cagent.yaml` and `Corefile` are modified at runtime by warden; DP E2E tests back up and restore these files
- Frontend lint runs with `--max-warnings 0`; any ESLint warning fails the build
- E2E tests start/stop Docker containers and require Docker socket access
- IPv6 is disabled on Docker networks to prevent egress control bypass
- Vector sinks are split by mode: `standalone.yaml` vs `connected.yaml`, selected via volume mount in docker-compose
