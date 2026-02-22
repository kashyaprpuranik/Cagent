# Development Guide

This guide covers local development setup, testing, and Docker workflows for the Cagent data plane.

## Quick Start

```bash
# Standalone with admin UI
./scripts/local.sh

# After startup:
# - Admin UI: http://localhost:8081
# - Cell shell: docker exec -it cell bash
```

## Directory Structure

```
.
├── docker-compose.yml              # All DP services
├── cell.Dockerfile                 # Cell container image
├── configs/
│   ├── cagent.yaml                 # Source of truth for domain policies
│   ├── coredns/Corefile            # DNS filter (generated)
│   ├── envoy/                      # HTTP proxy config (generated)
│   │   └── envoy-enhanced.yaml     # Envoy config with ext_authz + local_ratelimit
│   ├── vector/                     # Log collection
│   │   ├── vector.yaml             # Sources and transforms
│   │   └── sinks/                  # Mode-specific sinks
│   │       ├── standalone.yaml     # File backup + optional S3/ES
│   │       └── connected.yaml      # CP API + file backup
│   ├── seccomp/                    # Cell container seccomp profile
│   └── gvisor/runsc.toml           # gVisor config
├── services/
│   ├── warden/               # FastAPI app + config generator
│   │   ├── main.py                 # App entry point
│   │   ├── config_generator.py     # Generates DNS + proxy configs
│   │   ├── constants.py            # Shared constants
│   │   ├── models.py               # Pydantic schemas
│   │   └── routers/                # API endpoints
│   │   └── frontend/               # React admin UI (TypeScript + Vite)
│   └── email_proxy/                # Email proxy (beta)
├── tests/                          # pytest tests
├── docs/
│   └── configuration.md            # Config guide
├── scripts/
│   ├── local.sh                    # Dev environment orchestration
│   ├── test.sh                # Test runner
│   └── seed_traffic.py             # Traffic seeding utility
└── package.json                    # npm workspace (frontend)
```

## Running Tests

```bash
# DP unit/config tests + frontend type-check (default)
./scripts/test.sh

# All tests including E2E (requires Docker)
./scripts/test.sh --e2e
```

### DP Tests Directly

```bash
pip install -r requirements-test.txt
pytest tests/ -v --ignore=tests/test_e2e.py    # unit + config tests
```

### E2E Tests

E2E tests bring up the full data plane stack (cell, proxy, DNS, warden), run tests against it, and tear everything down.

```bash
./scripts/test.sh --e2e
```

Tests include:
- Domain allowlist enforcement
- Credential injection
- Rate limiting
- DNS filtering
- Log collection (file backup sink)
- Container management

## Docker Compose Profiles

| Profile | Description |
|---------|-------------|
| `dev` | Cell with runc runtime (development) |
| `standard` | Cell with gVisor runtime (production) |
| `admin` | Warden with admin UI |
| `managed` | Warden without admin UI (connected mode) |
| `auditing` | Log shipper (Vector) |
| `ssh` | FRP tunnel client |
| `email` | Email proxy (beta) |

```bash
# Minimal (just proxy + DNS + cell)
docker compose --profile dev up -d

# With admin UI
docker compose --profile dev --profile admin up -d

# With auditing
docker compose --profile dev --profile admin --profile auditing up -d

# Full connected mode
CONTROL_PLANE_URL=http://... CONTROL_PLANE_TOKEN=... \
docker compose --profile dev --profile managed --profile auditing up -d
```

## Frontend Development

The admin UI frontend lives at `services/warden/frontend/`.

```bash
cd services/warden/frontend
npm install
npm run dev          # Vite dev server on :3000, proxies /api to :8080
npm run lint         # ESLint (--max-warnings 0)
npx tsc --noEmit     # Type-check
```

Shared components come from [@cagent/ui](https://github.com/kashyaprpuranik/cagent-ui).

## Config Generation

The warden watches `cagent.yaml` and generates:
- `coredns/Corefile` — DNS filter rules
- `envoy/envoy-enhanced.yaml` — Envoy config with ext_authz + local_ratelimit filters

Changes to `cagent.yaml` trigger automatic regeneration and service restart.

## Control Plane Integration

For full-stack development (CP + DP), see the [cagent-control](https://github.com/kashyaprpuranik/cagent-control) repo. Clone it as a sibling:

```bash
# Clone both repos
git clone https://github.com/kashyaprpuranik/cagent.git
git clone https://github.com/kashyaprpuranik/cagent-control.git

# Start full stack from CP repo
cd cagent-control
./dev_up.sh
```
