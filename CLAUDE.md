# CLAUDE.md

This file provides guidance for AI assistants working with the Cagent codebase.

## Project Overview

Cagent is a secure development and execution environment for AI agents with isolated networking and centralized control. It prevents data exfiltration, supply chain attacks, and lateral movement from untrusted AI agents through network-isolated sandboxes with controlled egress, domain allowlists, rate limiting, and credential injection.

## Architecture

The system has two main components:

- **Control Plane** (`control_plane/`): Centralized management API with multi-tenant policy enforcement, secrets storage, audit logging, and an admin UI. Runs PostgreSQL, Redis, OpenObserve, and an FRP tunnel server.
- **Data Plane** (`data_plane/`): Secure agent execution environment with network isolation via Envoy (HTTP proxy) and CoreDNS (DNS filter). The agent container sits on an internal-only Docker network and can only reach the proxy and DNS filter.

There is also:
- **Shared UI** (`packages/shared-ui/`): Reusable React components shared between the CP frontend and the local admin frontend.
- **E2E tests** (`e2e/`): Integration tests that spin up both CP and DP together.
- **Docs** (`docs/`): Configuration and development guides.

### Deployment Modes

- **Standalone**: Single data plane with local admin UI, configured via `cagent.yaml`
- **Connected**: Multiple data planes synced to a control plane via API
- **Full stack (dev)**: `./dev_up.sh` orchestrates both CP + DP with seeding

## Repository Structure

```
.
├── control_plane/
│   ├── docker-compose.yml          # CP services (backend, db, redis, log-store, frontend, tunnel-server)
│   ├── dev_up.sh                   # CP dev environment setup
│   ├── configs/frps/               # FRP server config
│   └── services/
│       ├── backend/                # FastAPI REST API (Python)
│       │   ├── control_plane/      # Python package
│       │   │   ├── app.py          # FastAPI app, router registration
│       │   │   ├── config.py       # Environment-driven configuration
│       │   │   ├── auth.py         # Token auth, RBAC, IP ACL verification
│       │   │   ├── models.py       # SQLAlchemy ORM models
│       │   │   ├── schemas.py      # Pydantic request/response schemas
│       │   │   ├── database.py     # DB connection setup
│       │   │   └── routes/         # API endpoint routers
│       │   ├── seed.py             # Pre-seed (direct DB inserts for auth bootstrap)
│       │   ├── post_seed.py        # Post-seed (API calls for domain policies, audit-logged)
│       │   └── tests/              # pytest test suite
│       └── frontend/               # React admin UI (Vite + TypeScript + TailwindCSS)
│
├── data_plane/
│   ├── docker-compose.yml          # DP services (agent, envoy, coredns, vector, local-admin, email-proxy)
│   ├── agent.Dockerfile            # Agent container image
│   ├── configs/
│   │   ├── cagent.yaml             # Unified config (source of truth for DNS + proxy)
│   │   ├── coredns/Corefile        # DNS filter config (generated from cagent.yaml)
│   │   ├── envoy/                  # HTTP proxy config (generated from cagent.yaml)
│   │   ├── vector/vector.yaml      # Log collection/forwarding
│   │   ├── seccomp/                # Seccomp profile for agent container
│   │   └── gvisor/runsc.toml       # gVisor runtime config
│   ├── services/
│   │   ├── agent_manager/          # Polls CP, generates CoreDNS + Envoy configs
│   │   ├── local_admin/            # Standalone mode admin UI (FastAPI + React)
│   │   └── email_proxy/            # Email egress control (beta)
│   └── tests/                      # Unit and E2E tests
│
├── packages/shared-ui/             # Shared React components (npm workspace)
├── e2e/                            # CP+DP integration tests
├── docs/                           # Configuration and development guides
├── dev_up.sh                       # Full stack dev orchestration
└── run_tests.sh                    # Unified test runner
```

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | Python, FastAPI, SQLAlchemy, Pydantic |
| Database | PostgreSQL (production), SQLite (dev/test) |
| Cache | Redis (rate limiting) |
| Frontend | React 18, TypeScript, Vite, TailwindCSS, TanStack React Query |
| Terminal | xterm.js (WebSocket-based browser terminal) |
| Proxy | Envoy (HTTP egress gateway with credential injection) |
| DNS | CoreDNS (domain allowlist enforcement) |
| Logging | Vector (log collection), OpenObserve (storage/query) |
| Containers | Docker, Docker Compose, gVisor (optional) |
| Tunneling | FRP (STCP mode for SSH access) |

## Common Commands

### Development Environment

```bash
# Full stack (CP + DP with seeding)
./dev_up.sh

# Control plane only
./dev_up.sh --cp-only

# Data plane standalone with admin UI
./dev_up.sh --dp-only --admin

# Stop everything
./dev_up.sh down
```

### Running Tests

```bash
# CP + DP unit tests + frontend type-check (default)
./run_tests.sh

# CP backend tests only
./run_tests.sh --cp

# DP unit/config tests only
./run_tests.sh --dp

# Frontend type-check only (tsc --noEmit for both UIs)
./run_tests.sh --frontend

# All tests including E2E (requires Docker)
./run_tests.sh --e2e

# CP+DP integration E2E only
./run_tests.sh --cp-dp-e2e
```

#### CP Backend Tests Directly

```bash
cd control_plane/services/backend
pip install -r requirements.txt -r requirements-test.txt
pytest tests/ -v
```

#### DP Tests Directly

```bash
cd data_plane
pip install -r requirements-test.txt
./run_tests.sh              # unit + config tests
./run_tests.sh --e2e        # includes E2E (starts Docker containers)
```

### Docker Operations

```bash
# Rebuild and restart a single service
cd control_plane && docker compose build backend && docker compose up -d backend

# View logs
docker compose logs -f backend

# Enter agent container shell
docker exec -it agent bash

# Reset database (wipes volumes)
cd control_plane && docker compose down -v
```

### Frontend Development

```bash
# CP admin UI
cd control_plane/services/frontend && npm install && npm run dev

# Local admin UI
cd data_plane/services/local_admin/frontend && npm install && npm run dev

# Lint (fails on any warning)
npm run lint
```

## Key Conventions

### Python Backend

- **Framework**: FastAPI with dependency injection for auth, DB sessions, and IP ACL checks
- **ORM**: SQLAlchemy declarative models in `models.py`, Pydantic schemas in `schemas.py`
- **Auth**: Bearer token auth via `verify_token` dependency. Tokens are SHA-256 hashed in DB. Role hierarchy: super-admin > admin > developer > agent
- **Auth dependencies** (in `auth.py`): `verify_token`, `require_admin`, `require_agent`, `require_super_admin`, `require_role("...")`, `require_admin_role_with_ip_check`
- **Multi-tenancy**: All resources scoped by `tenant_id`. Agent tokens derive tenant from agent. Super-admin tokens can access all tenants
- **Secrets**: Fernet encryption for credential values. Encryption key from `ENCRYPTION_KEY` env var
- **Audit logging**: All mutations go through API (not direct DB) so they are audit-logged. Pre-seed is the exception (bootstrap tokens)
- **Configuration**: Environment variables, loaded in `config.py`. No dotenv auto-loading in production
- **Beta features**: Gated by `BETA_FEATURES` env var (comma-separated). Currently: `email`

### Testing

- **Framework**: pytest with pytest-asyncio
- **CP tests**: Use `FastAPI.TestClient` with SQLite in-memory DB. Fixtures in `conftest.py` provide `client`, `db_session`, and auth header fixtures (`auth_headers`, `super_admin_headers`, `dev_headers`, `acme_admin_headers`)
- **DB per test**: Each test gets fresh tables (created in fixture, dropped after). Token cache is cleared between tests
- **Mocking**: OpenObserve HTTP calls are mocked via `mock_openobserve` fixture. Rate limiting is disabled in tests
- **DP tests**: Unit tests for config generator, DNS filter rules, Envoy config, credential injection. E2E tests require Docker
- **Test tokens**: Deterministic seed tokens (e.g., `admin-test-token-do-not-use-in-production`). Never use in production
- **Markers**: `@pytest.mark.e2e` for tests requiring full stack

### Frontend

- **Build**: `tsc && vite build` (TypeScript checked before bundling)
- **Linting**: ESLint with `--max-warnings 0` (zero tolerance for warnings)
- **State**: TanStack React Query for server state
- **Routing**: React Router v6
- **Styling**: TailwindCSS with PostCSS/Autoprefixer
- **Shared components**: `@cagent/shared-ui` package via npm workspaces

### Docker / Infrastructure

- **Networks**: `agent-net` (10.200.1.0/24, internal, no external access) and `infra-net` (10.200.2.0/24, can reach CP). IPv6 disabled to prevent bypass
- **Static IPs**: dns-filter=10.200.1.5, http-proxy=10.200.1.10, agent=10.200.1.20
- **Profiles**: `dev` (runc), `standard` (gVisor), `admin` (local admin UI), `auditing` (log shipping), `ssh` (FRP tunnel), `email` (email proxy), `managed` (agent manager)
- **Config generation**: `cagent.yaml` is the source of truth. Agent manager generates CoreDNS Corefile and Envoy config from it
- **Security layers**: Seccomp profile blocks raw sockets, gVisor intercepts syscalls, Envoy enforces domain allowlist/rate limits/path filtering, CoreDNS blocks unauthorized DNS

## Data Flow

1. Agent makes HTTP request via `HTTP_PROXY` (Envoy at 10.200.1.10:8443)
2. Envoy checks domain against allowlist, enforces rate limits and path filtering
3. Envoy injects credentials (if configured) and forwards request upstream
4. DNS queries go through CoreDNS (10.200.1.5) which only resolves allowed domains
5. Vector collects logs from Docker/Envoy/CoreDNS and ships to CP (or OpenObserve directly)
6. In connected mode, agent-manager polls CP for policy updates and regenerates configs

## Important Files

| File | Purpose |
|------|---------|
| `control_plane/services/backend/control_plane/app.py` | FastAPI app setup, router registration |
| `control_plane/services/backend/control_plane/models.py` | All SQLAlchemy ORM models |
| `control_plane/services/backend/control_plane/auth.py` | Token verification, RBAC, IP ACL |
| `control_plane/services/backend/control_plane/routes/` | API endpoint routers |
| `control_plane/services/backend/seed.py` | Database pre-seeding (bootstrap) |
| `control_plane/services/backend/post_seed.py` | API-based seeding (domain policies) |
| `data_plane/configs/cagent.yaml` | Unified data plane config |
| `data_plane/services/agent_manager/config_generator.py` | Generates CoreDNS + Envoy configs |
| `data_plane/services/agent_manager/main.py` | Agent manager service (polling, heartbeat) |
| `dev_up.sh` | Full stack dev orchestration |
| `run_tests.sh` | Unified test runner |

## Gotchas

- The CP backend listens on port 8000 internally but is mapped to 8002 on the host
- `cagent.yaml` and `Corefile` are modified at runtime by agent-manager; DP E2E tests back up and restore these files
- The `SEED_TOKENS` env var triggers pre-seeding on startup. Seed tokens are deterministic and must never be used in production
- All caches (token, IP ACL, agent state, security profile, domain policy) use `LayeredCache` in `cache.py` and must be cleared between tests — see `conftest.py`
- OpenObserve uses a distroless image with no shell, so Docker healthchecks are not available for it
- Frontend lint runs with `--max-warnings 0`; any ESLint warning fails the build
- E2E tests start/stop Docker containers and require Docker socket access
- IPv6 is disabled on Docker networks to prevent egress control bypass
