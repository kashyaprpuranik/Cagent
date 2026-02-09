# Development Guide

This guide covers local development setup, database seeding, testing, and dev tooling.

## Quick Start (Dev Environment)

The `dev_up.sh` script automates a clean dev environment:

```bash
cd control_plane
bash dev_up.sh
```

This script:
1. Generates `.env` from `.env.example` (with a real Fernet encryption key)
2. Stops and removes existing containers (wipes volumes for clean state)
3. Builds all images from scratch
4. Starts services with `SEED_TOKENS=true`
5. Waits for the API to become healthy
6. Runs `post_seed.py` to create domain policies and set up IP ACLs via the API (so all actions are audit-logged)

After it completes:
- Admin UI: http://localhost:9080
- API Docs: http://localhost:8002/docs

## Database Seeding

Seeding is split into two phases to ensure audit log coverage.

### Bootstrap (`seed_bootstrap`)

Always runs on startup. Creates the super-admin token (direct DB insert, no audit log needed). This is the only direct DB write — everything else goes through the API.

### Pre-Seed (`seed_test_data`)

Runs before uvicorn starts when `SEED_TOKENS=true`. Creates tenants and tokens with deterministic values (needed by tests and dev scripts):

| Type | Name | Description |
|------|------|-------------|
| Tenant | `default` | Default tenant (slug: `default`) |
| Tenant | `Acme Corp` | Test tenant for multi-tenancy (slug: `acme`) |
| Token | `admin-token` | Admin token scoped to default tenant |
| Token | `dev-token` | Developer token scoped to default tenant |
| Token | `acme-admin-token` | Admin token scoped to Acme Corp tenant |

These must be direct DB inserts because the API generates random tokens. The super-admin token value is written to `/tmp/seed-token` for post-seed to use.

### Post-Seed (`post_seed.py`)

Runs after uvicorn is healthy (called by `dev_up.sh`). Creates all resources via the API so actions are audit-logged:

| Tenant | Type | Resource | Details |
|--------|------|----------|---------|
| default | Domain policy | `api.openai.com` | 60 rpm, path filtering |
| default | Domain policy | `api.anthropic.com` | 60 rpm, path filtering |
| default | Domain policy | `api.github.com` | 100 rpm |
| default | Domain policy | `pypi.org`, `files.pythonhosted.org`, `registry.npmjs.org` | Package registries |
| default | Domain policy | `*.githubusercontent.com` | GitHub raw content |
| default | Domain policy | `huggingface.co` | Agent-specific (test-agent), with credential |
| default | Domain policy | `*.aws.amazon.com` | Agent-specific (test-agent) |
| acme | Domain policy | `api.openai.com`, `api.stripe.com`, `api.twilio.com` | Acme Corp APIs |
| both | IP ACL | `0.0.0.0/0` | Allow all (development default) |
| default | IP ACL | `10.0.0.0/8`, `203.0.113.50/32` | Sample ACLs |

Post-seed reads the super-admin token from `/tmp/seed-token`, uses it for all API calls, then deletes the file.

## Testing

### Control Plane Tests

```bash
cd control_plane/services/backend

# Install test dependencies
pip install -r requirements.txt
pip install pytest pytest-asyncio httpx

# Run all tests
pytest tests/ -v

# Run specific test file
pytest tests/test_api.py -v

# Run with coverage
pytest tests/ -v --cov=. --cov-report=html
```

### Data Plane Tests

```bash
cd data_plane

# Unit tests for config generator
pytest services/config_generator/tests/ -v

# Unit tests for agent manager
pytest services/agent_manager/tests/ -v
```

### End-to-End Tests

```bash
cd data_plane/tests

# Run E2E tests (requires running services)
pytest e2e/ -v

# Test DNS filtering
./test_dns.sh

# Test credential injection
./test_credentials.sh
```

## Local Development

### Control Plane

```bash
cd control_plane/services/backend

# Create virtual environment
python -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Set required environment variables
export ENCRYPTION_KEY=$(python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())")
export DATABASE_URL=sqlite:///./dev.db

# Run with auto-reload
uvicorn main:app --reload --port 8002
```

### Admin UI

```bash
cd control_plane/services/frontend

# Install dependencies
npm install

# Run development server
npm run dev

# Build for production
npm run build
```

### Local Admin UI (Standalone Mode)

```bash
cd data_plane/services/local_admin

# Backend
cd backend
pip install -r requirements.txt
uvicorn main:app --reload --port 8080

# Frontend (separate terminal)
cd ../frontend
npm install
npm run dev
```

## API Testing with curl

### Authentication

All API endpoints require Bearer token authentication. Use `--show-token` when seeding to get the admin token:

```bash
python seed.py --show-token
# Admin Token: <random-token>

export TOKEN="<paste-token-here>"

curl -H "Authorization: Bearer $TOKEN" http://localhost:8002/api/v1/domain-policies
```

### Common Operations

```bash
# List agents
curl -H "Authorization: Bearer $TOKEN" http://localhost:8002/api/v1/agents

# Create a domain policy (allowlist + rate limit + credential in one call)
curl -X POST http://localhost:8002/api/v1/domain-policies \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "domain": "api.example.com",
    "alias": "example",
    "description": "Example API",
    "allowed_paths": ["/v1/*"],
    "requests_per_minute": 60,
    "burst_size": 10,
    "bytes_per_hour": 10485760,
    "credential": {
      "header": "Authorization",
      "format": "Bearer {value}",
      "value": "sk-..."
    }
  }'

# List domain policies
curl -H "Authorization: Bearer $TOKEN" http://localhost:8002/api/v1/domain-policies

# Rotate a credential
curl -X POST http://localhost:8002/api/v1/domain-policies/1/rotate-credential \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"value": "sk-new-..."}'

# View audit logs
curl -H "Authorization: Bearer $TOKEN" http://localhost:8002/api/v1/audit-logs
```

## Docker Development

### Rebuild Single Service

```bash
cd control_plane
docker compose build backend
docker compose up -d backend
```

### View Logs

```bash
# All services
docker compose logs -f

# Specific service
docker compose logs -f backend
```

### Enter Container Shell

```bash
docker compose exec backend /bin/bash
docker compose exec frontend /bin/sh
```

### Reset Database

```bash
# Stop and remove volumes
docker compose down -v

# Restart (will auto-seed if SEED_TOKENS=true)
SEED_TOKENS=true docker compose up -d
```

## Directory Structure

```
.
├── control_plane/
│   ├── docker-compose.yml      # Control plane services
│   ├── dev_up.sh               # Dev environment setup (not for production)
│   ├── configs/
│   │   └── frps/               # FRP server config (STCP tunnels)
│   └── services/
│       ├── backend/            # Control plane API (domain policies, audit, IP ACLs)
│       │   ├── control_plane/  # Python package (routes, models, auth, etc.)
│       │   ├── seed.py         # Pre-seed (auth infrastructure, direct DB)
│       │   └── post_seed.py    # Post-seed (domain policies, IP ACLs, via API)
│       └── frontend/           # React admin console with web terminal
│
└── data_plane/
    ├── docker-compose.yml          # Data plane services
    ├── configs/
    │   ├── cagent.yaml        # Unified config (generates DNS filter + HTTP proxy)
    │   ├── coredns/            # DNS config (generated from cagent.yaml)
    │   ├── envoy/              # Proxy config (generated from cagent.yaml)
    │   ├── vector/             # Log collection & forwarding
    │   └── frpc/               # FRP client config (STCP tunnels)
    ├── services/
    │   ├── agent_manager/      # Container lifecycle + config generation
    │   ├── local_admin/        # Local admin UI (standalone mode)
    │   │   ├── frontend/       # React app with web terminal
    │   │   └── backend/        # FastAPI backend
    │   └── config_generator/   # cagent.yaml → DNS filter/HTTP proxy configs
    └── tests/                  # Unit and E2E tests
```
