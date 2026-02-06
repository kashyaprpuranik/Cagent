# Development Guide

This guide covers database seeding, testing, and local development setup.

## Database Seeding

The database is automatically seeded on first startup (when no agents exist). You can also seed manually:

```bash
cd control-plane/services/control-plane

# Seed with defaults
python seed.py

# Reset and reseed
python seed.py --reset

# Show generated tokens
python seed.py --show-token
```

### Default Seed Data

| Type | Name | Description |
|------|------|-------------|
| Tenant | `default` | Default tenant (slug: `default`) |
| Agent | `__default__` | Virtual agent for tenant-global config |
| Agent | `test-agent` | Test agent (approved) |
| Agent | `pending-agent` | Test agent (pending approval) |

### Default Development Tokens

| Token Name | Raw Token | Type | Super Admin |
|------------|-----------|------|-------------|
| `super-admin-token` | `super-admin-test-token-do-not-use-in-production` | superadmin | Yes |
| `admin-token` | `admin-test-token-do-not-use-in-production` | admin | No |
| `dev-token` | `dev-test-token-do-not-use-in-production` | dev | No |

### Sample Configuration

The seeder also creates:
- Sample allowlist entries (api.openai.com, api.anthropic.com, github.com)
- Sample rate limits (60 req/min for OpenAI, 120 for Anthropic)
- Sample secrets with domain aliases

## Testing

### Control Plane Tests

```bash
cd control-plane/services/control-plane

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
cd data-plane

# Unit tests for config generator
pytest services/config-generator/tests/ -v

# Unit tests for agent manager
pytest services/agent-manager/tests/ -v
```

### End-to-End Tests

```bash
cd data-plane/tests

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
cd control-plane/services/control-plane

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
cd control-plane/services/admin-ui

# Install dependencies
npm install

# Run development server
npm run dev

# Build for production
npm run build
```

### Local Admin UI (Standalone Mode)

```bash
cd data-plane/services/local-admin

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

All API endpoints require Bearer token authentication:

```bash
# Use super admin token for full access
export TOKEN="super-admin-test-token-do-not-use-in-production"

curl -H "Authorization: Bearer $TOKEN" http://localhost:8002/api/v1/secrets
```

### Common Operations

```bash
# List agents
curl -H "Authorization: Bearer $TOKEN" http://localhost:8002/api/v1/agents

# Create a secret
curl -X POST http://localhost:8002/api/v1/secrets \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "test-api-key",
    "value": "sk-test-12345",
    "domain_pattern": "api.example.com",
    "header_name": "Authorization",
    "header_format": "Bearer {value}"
  }'

# Add domain to allowlist
curl -X POST http://localhost:8002/api/v1/allowlist \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"entry_type": "domain", "value": "api.example.com"}'

# Create rate limit
curl -X POST http://localhost:8002/api/v1/rate-limits \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "domain_pattern": "api.example.com",
    "requests_per_minute": 60,
    "burst_size": 10
  }'
```

## Docker Development

### Rebuild Single Service

```bash
cd control-plane
docker-compose build control-plane-api
docker-compose up -d control-plane-api
```

### View Logs

```bash
# All services
docker-compose logs -f

# Specific service
docker-compose logs -f control-plane-api
```

### Enter Container Shell

```bash
docker-compose exec control-plane-api /bin/bash
docker-compose exec admin-ui /bin/sh
```

### Reset Database

```bash
# Stop and remove volumes
docker-compose down -v

# Restart (will auto-seed)
docker-compose up -d
```

## Directory Structure

```
.
├── control-plane/
│   ├── docker-compose.yml      # Control plane services
│   ├── configs/
│   │   └── frps/               # FRP server config (STCP tunnels)
│   └── services/
│       ├── control-plane/      # Control plane API (secrets, allowlist, audit, IP ACLs)
│       └── admin-ui/           # React admin console with web terminal
│
└── data-plane/
    ├── docker-compose.yml          # Data plane services
    ├── configs/
    │   ├── maltbox.yaml        # Unified config (generates CoreDNS + Envoy)
    │   ├── coredns/            # DNS config (generated from maltbox.yaml)
    │   ├── envoy/              # Proxy config (generated from maltbox.yaml)
    │   ├── vector/             # Log collection & forwarding
    │   └── frpc/               # FRP client config (STCP tunnels)
    ├── services/
    │   ├── agent-manager/      # Container lifecycle + config generation
    │   ├── local-admin/        # Local admin UI (standalone mode)
    │   │   ├── frontend/       # React app with web terminal
    │   │   └── backend/        # FastAPI backend
    │   └── config-generator/   # maltbox.yaml → CoreDNS/Envoy configs
    └── tests/                  # Unit and E2E tests
```
