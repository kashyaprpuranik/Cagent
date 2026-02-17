#!/bin/bash
# Run tests for the Cagent data plane.
#
# Usage:
#   ./run_tests.sh          # DP unit/config + frontend type-check
#   ./run_tests.sh --e2e    # All tests including DP e2e

set -e

REPO_ROOT=$(cd "$(dirname "$0")" && pwd)

RUN_E2E=false

for arg in "$@"; do
    case "$arg" in
        --e2e) RUN_E2E=true ;;
    esac
done

FAILED=()

# ── DP Unit / Config Tests ──────────────────────────────────────────────────
echo "=== DP Unit / Config Tests ==="
echo ""
cd "$REPO_ROOT"
pip install -q -r requirements-test.txt
if pytest tests/ -v --ignore=tests/test_e2e.py; then
    echo ""
    echo "DP unit/config tests: PASSED"
else
    echo ""
    echo "DP unit/config tests: FAILED"
    FAILED+=("DP unit/config")
fi
echo ""

# ── Frontend Type-Check (tsc) ─────────────────────────────────────────────
echo "=== Frontend Type-Check ==="
echo ""

# Ensure dependencies are installed
cd "$REPO_ROOT"
npm install --workspaces --include-workspace-root --silent 2>/dev/null || true

echo "--- DP local admin UI (tsc) ---"
if (cd "$REPO_ROOT/services/agent_manager/frontend" && npx tsc --noEmit 2>&1); then
    echo "  DP local admin frontend: OK"
else
    echo "  DP local admin frontend: FAILED"
    FAILED+=("Frontend type-check")
fi
echo ""

# ── DP E2E Tests (standalone mode) ──────────────────────────────────────────
if [ "$RUN_E2E" = true ]; then
    echo "=== DP E2E Tests (standalone mode) ==="
    echo ""

    cd "$REPO_ROOT"
    CONTAINERS_STARTED=false

    # E2E tests require: agent-dev (profile dev), agent-manager (profile admin),
    # standalone mode. Bring up or restart as needed.
    NEED_RESTART=false

    # Check agent is running with the dev profile (runc), not standard (gVisor)
    AGENT_CID=$(docker ps --filter "label=cagent.role=agent" --format "{{.ID}}" -q 2>/dev/null | head -1)
    if [ -n "$AGENT_CID" ]; then
        AGENT_SERVICE=$(docker inspect "$AGENT_CID" --format '{{index .Config.Labels "com.docker.compose.service"}}' 2>/dev/null || true)
        if [ "$AGENT_SERVICE" = "agent" ]; then
            echo "Agent is running with standard profile (gVisor), tearing down to restart with dev profile..."
            docker compose --profile standard --profile admin --profile email --profile auditing down 2>/dev/null || true
            NEED_RESTART=true
        fi
    else
        NEED_RESTART=true
    fi

    # Check agent-manager and log-shipper are running (admin profile)
    if [ "$NEED_RESTART" = false ]; then
        for svc in agent-manager log-shipper; do
            if ! docker ps --filter "name=^${svc}$" --format "{{.Names}}" 2>/dev/null | grep -q "$svc"; then
                NEED_RESTART=true
                break
            fi
        done
    fi

    # Check agent-manager is running in standalone mode
    if [ "$NEED_RESTART" = false ]; then
        ADMIN_MODE=$(curl -sf http://localhost:8081/api/info 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin).get('mode',''))" 2>/dev/null || true)
        if [ "$ADMIN_MODE" = "connected" ]; then
            echo "Data plane is running in connected mode, restarting in standalone mode..."
            docker compose --profile dev --profile admin --profile email --profile auditing down 2>/dev/null || true
            NEED_RESTART=true
        fi
    fi

    # Snapshot tracked config files that containers modify at runtime
    cp configs/cagent.yaml configs/.cagent.yaml.bak
    cp configs/coredns/Corefile configs/coredns/.Corefile.bak

    # Always clean up stale networks (may have wrong labels from previous runs)
    for net in cagent-infra-net cagent-agent-net; do
        if docker network inspect "$net" >/dev/null 2>&1; then
            for cid in $(docker network inspect "$net" --format '{{range .Containers}}{{.Name}} {{end}}' 2>/dev/null); do
                echo "  Removing orphan container $cid from $net..."
                docker stop "$cid" 2>/dev/null || true
                docker rm "$cid" 2>/dev/null || true
            done
            docker network rm "$net" 2>/dev/null || true
        fi
    done

    if [ "$NEED_RESTART" = true ]; then
        echo "Stopping any existing containers first..."
        docker compose --profile dev --profile admin --profile email --profile auditing down 2>/dev/null || true
        docker compose --profile standard --profile admin --profile email --profile auditing down 2>/dev/null || true
        echo "Starting data plane (standalone, --profile dev --profile admin --profile auditing, 2 agents)..."
        DATAPLANE_MODE=standalone docker compose --profile dev --profile admin --profile auditing up -d --build --scale agent-dev=2
        CONTAINERS_STARTED=true
        echo "Waiting for containers to stabilize..."
        sleep 5
    else
        echo "Data plane already running, rebuilding images in case code changed..."
        DATAPLANE_MODE=standalone docker compose --profile dev --profile admin --profile auditing up -d --build --scale agent-dev=2
        echo "Waiting for containers to stabilize..."
        sleep 5
    fi

    set +e
    pytest tests/test_e2e.py -v
    E2E_EXIT=$?
    set -e

    # Tear down containers only if we started them
    if [ "$CONTAINERS_STARTED" = true ]; then
        echo ""
        echo "Stopping containers started by this script..."
        docker compose --profile dev --profile admin --profile email --profile auditing down 2>/dev/null || true
    fi

    # Restore tracked config files modified by containers at runtime
    mv configs/.cagent.yaml.bak configs/cagent.yaml 2>/dev/null || true
    mv configs/coredns/.Corefile.bak configs/coredns/Corefile 2>/dev/null || true

    if [ $E2E_EXIT -ne 0 ]; then
        FAILED+=("DP e2e")
    else
        echo ""
        echo "DP e2e tests: PASSED"
    fi
    echo ""
fi

# ── Summary ─────────────────────────────────────────────────────────────────
echo "==========================================="
if [ ${#FAILED[@]} -eq 0 ]; then
    echo "All test suites passed."
else
    echo "FAILED suites: ${FAILED[*]}"
    exit 1
fi
