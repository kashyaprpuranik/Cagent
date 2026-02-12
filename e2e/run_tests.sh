#!/bin/bash
# Run CP + DP end-to-end integration tests.
#
# This script brings up the full stack (CP in test mode, DP in connected mode),
# runs the e2e tests, and tears everything down.
#
# Usage:
#   ./run_tests.sh          # setup, test, teardown
#   ./run_tests.sh --no-teardown   # keep containers running after tests

set -e

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
REPO_ROOT=$(dirname "$SCRIPT_DIR")
TEARDOWN=true
INFRA_STARTED=false
REUSE=false

for arg in "$@"; do
    case "$arg" in
        --no-teardown) TEARDOWN=false ;;
        --reuse)       REUSE=true ;;
    esac
done

# Strip our flags before passing remaining args to pytest
PYTEST_ARGS=()
for arg in "$@"; do
    case "$arg" in
        --no-teardown|--reuse) ;;
        *) PYTEST_ARGS+=("$arg") ;;
    esac
done

# ── Teardown ────────────────────────────────────────────────────────────────
teardown() {
    echo ""
    echo "=== Tearing down e2e infrastructure ==="
    cd "$REPO_ROOT/data_plane" && docker compose -f docker-compose.yml -f "$SCRIPT_DIR/docker-compose.e2e.yml" \
        --profile dev --profile managed --profile email --profile auditing down 2>/dev/null || true
    cd "$REPO_ROOT/control_plane" && docker compose down -v 2>/dev/null || true
    docker rm -f openobserve-mock echo-server 2>/dev/null || true
    docker network rm e2e-bridge 2>/dev/null || true
    rm -f "$SCRIPT_DIR/.agent-token"
    rm -f "$SCRIPT_DIR/.cagent.e2e.yaml"
    rm -f "$SCRIPT_DIR/.cagent.yaml.bak"

    # Restore tracked config files modified by agent-manager at runtime
    cd "$REPO_ROOT/data_plane"
    mv configs/.cagent.yaml.bak configs/cagent.yaml 2>/dev/null || true
    mv configs/coredns/.Corefile.bak configs/coredns/Corefile 2>/dev/null || true

    echo "Torn down."
}

# ── Setup ───────────────────────────────────────────────────────────────────
setup() {
    echo "=== Setting up e2e infrastructure ==="
    INFRA_STARTED=true

    # Snapshot tracked config files that containers modify at runtime
    cp "$REPO_ROOT/data_plane/configs/cagent.yaml" "$REPO_ROOT/data_plane/configs/.cagent.yaml.bak"
    cp "$REPO_ROOT/data_plane/configs/coredns/Corefile" "$REPO_ROOT/data_plane/configs/coredns/.Corefile.bak"

    # 1. Shared bridge network for CP ↔ DP communication
    docker network create e2e-bridge 2>/dev/null || true

    # 2. CP dependencies (postgres + redis)
    cd "$REPO_ROOT/control_plane"
    SEED_TOKENS=true docker compose up -d db cache
    echo "Waiting for db..."
    until docker compose exec -T db pg_isready -U aidevbox -d control_plane 2>/dev/null; do sleep 1; done
    echo "Waiting for cache..."
    until docker compose exec -T cache redis-cli ping 2>/dev/null | grep -q PONG; do sleep 1; done

    # 3. OpenObserve mock (stores ingested logs, returns them on search)
    docker rm -f openobserve-mock 2>/dev/null || true
    docker run -d --name openobserve-mock \
        --network control_plane_control-net \
        python:3.11-alpine python3 -c "
import json, re, threading
from http.server import HTTPServer, BaseHTTPRequestHandler

logs = []
lock = threading.Lock()

class H(BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get('Content-Length',0)))
        data = json.loads(body) if body else {}
        path = self.path

        # Search endpoint: /api/<org>/_search
        if '/_search' in path:
            sql = ''
            if isinstance(data, dict) and 'query' in data:
                sql = data['query'].get('sql', '')
            with lock:
                hits = list(logs)
            # Apply basic WHERE filters from SQL
            for m in re.finditer(r\"(\w+)\s*=\s*'([^']+)'\", sql):
                k, v = m.group(1), m.group(2)
                hits = [h for h in hits if str(h.get(k, '')) == v]
            self._json_response({'hits': hits})
        else:
            # Ingest endpoint: /api/<org>/<stream>/_json
            if isinstance(data, list):
                with lock:
                    logs.extend(data)
            self._json_response({'status': 200})

    def _json_response(self, obj):
        body = json.dumps(obj).encode()
        self.send_response(200)
        self.send_header('Content-Type','application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self,*a): pass

HTTPServer(('0.0.0.0',5080),H).serve_forever()
"

    # 4. CP API (--build ensures code changes are picked up)
    SEED_TOKENS=true \
    OPENOBSERVE_URL=http://openobserve-mock:5080 \
    docker compose up -d --build backend
    echo "Waiting for CP API..."
    until curl -sf http://localhost:8002/health >/dev/null 2>&1; do sleep 1; done
    echo "CP API healthy."

    # 5. Connect CP to bridge network
    docker network connect e2e-bridge backend 2>/dev/null || true

    # 6. Create agent token
    local ADMIN_TOKEN="admin-test-token-do-not-use-in-production"
    local TOKEN_RESPONSE
    TOKEN_RESPONSE=$(curl -s -X POST "http://localhost:8002/api/v1/tokens" \
        -H "Authorization: Bearer $ADMIN_TOKEN" \
        -H "Content-Type: application/json" \
        -d '{"name":"e2e-agent-token","token_type":"agent","agent_id":"e2e-agent"}')
    AGENT_TOKEN=$(echo "$TOKEN_RESPONSE" | python3 -c "import sys,json; data=json.loads(sys.stdin.read()); print(data.get('token',''))" 2>/dev/null)
    if [ -z "$AGENT_TOKEN" ]; then echo "ERROR: Failed to create agent token. Response: $TOKEN_RESPONSE"; exit 1; fi
    echo "$AGENT_TOKEN" > "$SCRIPT_DIR/.agent-token"
    echo "Agent token created."

    # 7. Create a patched cagent.yaml with echo-server domain for credential
    #    injection testing.  Write to a SEPARATE file (.cagent.e2e.yaml) so we
    #    don't touch the tracked config — VS Code's YAML extension reformats
    #    it on change, stripping comments and the echo-server entry.
    local CAGENT_YAML="$REPO_ROOT/data_plane/configs/cagent.yaml"
    python3 - "$CAGENT_YAML" "$SCRIPT_DIR/.cagent.e2e.yaml" << 'PYEOF'
import sys, yaml
src, dst = sys.argv[1], sys.argv[2]
with open(src) as f:
    config = yaml.safe_load(f)
# Ensure echo-server domain with credential is present
domains = config.get("domains") or []
if not any(d.get("domain") == "echo-server" for d in domains):
    domains.append({
        "domain": "echo-server",
        "alias": "echo",
        "credential": {
            "header": "Authorization",
            "format": "Bearer {value}",
            "env": "E2E_ECHO_CREDENTIAL",
        },
    })
    config["domains"] = domains
with open(dst, 'w') as f:
    yaml.dump(config, f, default_flow_style=False, sort_keys=False)
PYEOF
    echo "Created patched config at .cagent.e2e.yaml."

    # 8. Start DP in connected mode
    cd "$REPO_ROOT/data_plane"
    E2E_CAGENT_YAML="$SCRIPT_DIR/.cagent.e2e.yaml" \
    E2E_ECHO_CREDENTIAL=test-e2e-injected-cred \
    DATAPLANE_MODE=connected \
    CONTROL_PLANE_URL=http://backend:8000 \
    CONTROL_PLANE_TOKEN="$AGENT_TOKEN" \
    HEARTBEAT_INTERVAL=5 \
    CONFIG_SYNC_INTERVAL=10 \
    docker compose -f docker-compose.yml -f "$SCRIPT_DIR/docker-compose.e2e.yml" \
        --profile dev --profile managed --profile auditing up -d --build --scale agent-dev=2

    # 9. Connect agent-manager and log-shipper to bridge so they can reach CP
    docker network connect e2e-bridge agent-manager 2>/dev/null || true
    docker network connect e2e-bridge log-shipper 2>/dev/null || true

    # 10. HTTPS echo server on DP infra-net
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

    # 11. Wait for proxy readiness (agent-manager writes configs and restarts services)
    echo "Waiting for proxy readiness..."
    AGENT_CONTAINER=$(docker ps --filter "label=cagent.role=agent" --format "{{.Names}}" | head -1)
    for i in $(seq 1 30); do
        if docker exec "$AGENT_CONTAINER" curl -sf -x http://10.200.1.10:8443 --connect-timeout 2 \
            http://api.github.com/ -o /dev/null 2>/dev/null; then
            echo "Proxy ready."
            break
        fi
        if [ "$i" -eq 30 ]; then
            echo "WARNING: Proxy readiness check timed out (continuing anyway)"
            echo "--- agent-manager logs ---"
            docker logs agent-manager --tail 10 2>&1 || true
            echo "--- dns-filter status ---"
            docker ps --filter name=dns-filter --format "{{.Status}}" 2>/dev/null || true
            echo "--- http-proxy status ---"
            docker ps --filter name=http-proxy --format "{{.Status}}" 2>/dev/null || true
        fi
        sleep 2
    done

    # Wait for first heartbeat
    echo "Waiting for first heartbeat..."
    sleep 5

    # 12. Wait for log pipeline (Vector → CP → OpenObserve) to be functional.
    #     Vector starts before the e2e-bridge connect, so its initial requests
    #     fail with DNS errors and get dropped as non-retriable.
    #
    #     Step A: Verify Vector can reach the CP API.
    #     Step B: Generate canary traffic and verify it appears end-to-end in
    #             the CP analytics endpoint. This proves the full pipeline works:
    #             agent → Envoy → Docker logs → Vector → CP ingest → OpenObserve.
    echo "Waiting for log pipeline..."
    for i in $(seq 1 20); do
        if docker exec log-shipper wget -q -O /dev/null --timeout=2 \
            http://backend:8000/health 2>/dev/null; then
            echo "  Log-shipper can reach CP."
            break
        fi
        if [ "$i" -eq 20 ]; then
            echo "  WARNING: log-shipper cannot reach CP (continuing anyway)"
        fi
        sleep 2
    done

    # Step B: end-to-end canary — generate blocked traffic and verify it
    # reaches the CP analytics endpoint.  Retry traffic generation every 15s
    # in case the first batch is dropped during Vector startup.
    local CANARY_DOMAIN="pipeline-canary.example.com"
    echo "  Verifying end-to-end log pipeline with canary traffic..."
    for attempt in $(seq 1 4); do
        # Generate canary blocked request
        docker exec "$AGENT_CONTAINER" curl -s -o /dev/null \
            -x http://10.200.1.10:8443 --connect-timeout 5 \
            "http://${CANARY_DOMAIN}/canary-${attempt}" 2>/dev/null || true

        # Poll CP analytics for the canary domain (up to 20s per attempt)
        for i in $(seq 1 10); do
            if curl -sf "http://localhost:8002/api/v1/analytics/blocked-domains" \
                -H "Authorization: Bearer $ADMIN_TOKEN" \
                -G --data-urlencode "agent_id=e2e-agent" --data-urlencode "hours=1" \
                2>/dev/null | python3 -c "
import sys, json
data = json.load(sys.stdin)
domains = [d['domain'] for d in data.get('blocked_domains', [])]
sys.exit(0 if '${CANARY_DOMAIN}' in domains else 1)
" 2>/dev/null; then
                echo "  Log pipeline verified (canary appeared on attempt $attempt)."
                break 2
            fi
            sleep 2
        done

        if [ "$attempt" -eq 4 ]; then
            echo "  WARNING: canary never appeared in analytics (continuing anyway)"
        fi
    done

    echo "Infrastructure ready."
}

# ── Check if already running correctly ──────────────────────────────────────
is_ready() {
    # CP API reachable
    curl -sf http://localhost:8002/health >/dev/null 2>&1 || return 1
    # Agent token exists
    [ -f "$SCRIPT_DIR/.agent-token" ] || return 1
    # Agent container(s) running with dev profile (discovered by label)
    local agent_cid
    agent_cid=$(docker ps --filter "label=cagent.role=agent" -q 2>/dev/null | head -1)
    [ -n "$agent_cid" ] || return 1
    local svc
    svc=$(docker inspect "$agent_cid" --format '{{index .Config.Labels "com.docker.compose.service"}}' 2>/dev/null || true)
    [ "$svc" = "agent-dev" ] || return 1
    # Agent-manager running
    docker ps --filter "name=^agent-manager$" --format "{{.Names}}" 2>/dev/null | grep -q agent-manager || return 1
    # Echo server running
    docker ps --filter "name=^echo-server$" --format "{{.Names}}" 2>/dev/null | grep -q echo-server || return 1
    return 0
}

# ── Main ────────────────────────────────────────────────────────────────────
echo "=== CP + DP End-to-End Tests ==="
echo ""

if [ "$REUSE" = true ] && is_ready; then
    echo "Infrastructure already running, reusing existing setup (--reuse)."
else
    # Tear down any partial state before fresh setup
    teardown 2>/dev/null || true
    echo ""
    setup
fi

echo ""
echo "=== Running e2e tests ==="
cd "$SCRIPT_DIR"
set +e
pytest test_cp_dp_e2e.py -v "${PYTEST_ARGS[@]}"
TEST_EXIT=$?
set -e

if [ "$TEARDOWN" = true ] && [ "$INFRA_STARTED" = true ]; then
    teardown
elif [ "$TEARDOWN" = false ]; then
    echo ""
    echo "Containers left running (--no-teardown). To tear down:"
    echo "  $SCRIPT_DIR/run_tests.sh --teardown-only"
fi

exit $TEST_EXIT
