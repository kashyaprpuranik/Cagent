#!/bin/bash
set -e
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
REPO_ROOT=$(dirname "$SCRIPT_DIR")

# 1. Create shared bridge network
docker network create e2e-bridge 2>/dev/null || true

# 2. Start CP dependencies (postgres + redis)
cd "$REPO_ROOT/control_plane"
SEED_TOKENS=true docker compose up -d postgres redis
# Wait for health
echo "Waiting for postgres..."
until docker compose exec -T postgres pg_isready -U aidevbox -d control_plane 2>/dev/null; do sleep 1; done
echo "Waiting for redis..."
until docker compose exec -T redis redis-cli ping 2>/dev/null | grep -q PONG; do sleep 1; done

# 3. Start OpenObserve mock on CP network
docker rm -f openobserve-mock 2>/dev/null || true
docker run -d --name openobserve-mock \
  --network control_plane_control-net \
  python:3.11-alpine python3 -c "
from http.server import HTTPServer, BaseHTTPRequestHandler
import json
class H(BaseHTTPRequestHandler):
    def do_POST(self):
        self.rfile.read(int(self.headers.get('Content-Length',0)))
        self.send_response(200)
        self.send_header('Content-Type','application/json')
        self.end_headers()
        self.wfile.write(json.dumps({'status':200}).encode())
    def log_message(self,*a): pass
HTTPServer(('0.0.0.0',5080),H).serve_forever()
"

# 4. Start CP API (with mock OpenObserve URL, test seed enabled)
SEED_TOKENS=true \
OPENOBSERVE_URL=http://openobserve-mock:5080 \
docker compose up -d control-plane-api

# Wait for CP health
echo "Waiting for CP API..."
until curl -sf http://localhost:8002/health >/dev/null 2>&1; do sleep 1; done
echo "CP API healthy."

# 5. Connect CP API to bridge
docker network connect e2e-bridge control-plane-api 2>/dev/null || true

# 6. Create agent token via API
ADMIN_TOKEN="admin-test-token-do-not-use-in-production"
AGENT_TOKEN=$(curl -sf -X POST "http://localhost:8002/api/v1/tokens" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"e2e-agent-token","token_type":"agent","agent_id":"e2e-agent"}' \
  | python3 -c "import sys,json; print(json.loads(sys.stdin.read())['token'])")

if [ -z "$AGENT_TOKEN" ]; then echo "ERROR: Failed to create agent token"; exit 1; fi
echo "$AGENT_TOKEN" > "$SCRIPT_DIR/.agent-token"
echo "Agent token created."

# 7. Patch cagent.yaml to add echo-server domain for credential injection testing
CAGENT_YAML="$REPO_ROOT/data_plane/configs/cagent.yaml"
cp "$CAGENT_YAML" "$SCRIPT_DIR/.cagent.yaml.bak"
python3 - "$CAGENT_YAML" << 'PYEOF'
import sys
path = sys.argv[1]
with open(path) as f:
    content = f.read()
entry = """
  # E2E echo server (added by e2e/run.sh)
  - domain: echo-server
    alias: echo
    credential:
      header: Authorization
      format: "Bearer {value}"
      env: E2E_ECHO_CREDENTIAL

"""
marker = "# =============================================================================\n# Internal Services"
content = content.replace(marker, entry + marker)
with open(path, 'w') as f:
    f.write(content)
PYEOF
echo "Patched cagent.yaml with echo-server domain."

# 8. Start DP in connected mode (fast intervals for testing)
#    Uses docker-compose.e2e.yml override to pass E2E_ECHO_CREDENTIAL to agent-manager
cd "$REPO_ROOT/data_plane"
E2E_ECHO_CREDENTIAL=test-e2e-injected-cred \
DATAPLANE_MODE=connected \
CONTROL_PLANE_URL=http://control-plane-api:8000 \
CONTROL_PLANE_TOKEN="$AGENT_TOKEN" \
HEARTBEAT_INTERVAL=5 \
CONFIG_SYNC_INTERVAL=10 \
docker compose -f docker-compose.yml -f "$SCRIPT_DIR/docker-compose.e2e.yml" \
  --profile dev --profile managed up -d

# 9. Connect agent-manager to bridge
docker network connect e2e-bridge agent-manager 2>/dev/null || true

# 10. Start HTTPS echo server on DP's infra-net for credential injection testing
docker rm -f echo-server 2>/dev/null || true
docker run -d --name echo-server \
  --network data_plane_infra-net \
  -v "$SCRIPT_DIR/echo-server.py:/app/echo-server.py:ro" \
  python:3.11-alpine sh -c "apk add --no-cache openssl >/dev/null 2>&1 && python3 /app/echo-server.py"

echo "Waiting for echo server..."
for i in $(seq 1 15); do
  if docker logs echo-server 2>&1 | grep -q "Echo server ready"; then
    echo "Echo server ready."
    break
  fi
  sleep 1
done

# 11. Wait for first heartbeat + config generation
echo "Waiting for first heartbeat and config sync..."
sleep 8

echo ""
echo "=== E2E ready ==="
echo "Run: cd e2e && pytest test_cp_dp_e2e.py -v"
