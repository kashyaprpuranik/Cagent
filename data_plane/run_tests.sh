#!/bin/bash
# Run data-plane tests
#
# Usage:
#   ./run_tests.sh            # unit + config tests only
#   ./run_tests.sh --e2e      # unit + config + e2e tests
#   ./run_tests.sh --e2e-only # e2e tests only

set -e

cd "$(dirname "$0")"

E2E=false
E2E_ONLY=false
CONTAINERS_STARTED=false

for arg in "$@"; do
    case "$arg" in
        --e2e)      E2E=true ;;
        --e2e-only) E2E=true; E2E_ONLY=true ;;
    esac
done

# Strip our flags before passing remaining args to pytest
PYTEST_ARGS=()
for arg in "$@"; do
    case "$arg" in
        --e2e|--e2e-only) ;;
        *) PYTEST_ARGS+=("$arg") ;;
    esac
done

# Install test dependencies
pip install -q -r requirements-test.txt

# --- Unit / config tests ---
if [ "$E2E_ONLY" = false ]; then
    echo "=== Running unit and config tests ==="
    pytest tests/ -v --ignore=tests/test_e2e.py "${PYTEST_ARGS[@]}"
fi

# --- E2E tests ---
if [ "$E2E" = true ]; then
    echo ""
    echo "=== Running e2e tests ==="

    # E2E tests require: agent-dev (profile dev), local-admin + agent-manager
    # (profile admin), standalone mode. Bring up or restart as needed.
    NEED_RESTART=false

    # Check agent is running with the dev profile (runc), not standard (gVisor)
    # Discover agent containers by label (no fixed container_name)
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

    # Check local-admin and agent-manager are running (admin profile)
    if [ "$NEED_RESTART" = false ]; then
        for svc in local-admin agent-manager log-shipper; do
            if ! docker ps --filter "name=^${svc}$" --format "{{.Names}}" 2>/dev/null | grep -q "$svc"; then
                NEED_RESTART=true
                break
            fi
        done
    fi

    # Check local-admin is running in standalone mode
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

    if [ "$NEED_RESTART" = true ]; then
        echo "Stopping any existing containers first..."
        docker compose --profile dev --profile admin --profile email --profile auditing down 2>/dev/null || true
        docker compose --profile standard --profile admin --profile email --profile auditing down 2>/dev/null || true
        # Remove orphan containers (e.g. echo-server from e2e tests) that may hold network IPs
        for net in data_plane_infra-net data_plane_agent-net; do
            for cid in $(docker network inspect "$net" --format '{{range .Containers}}{{.Name}} {{end}}' 2>/dev/null); do
                echo "  Removing orphan container $cid from $net..."
                docker stop "$cid" 2>/dev/null || true
                docker rm "$cid" 2>/dev/null || true
            done
            docker network rm "$net" 2>/dev/null || true
        done
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
    pytest tests/test_e2e.py -v "${PYTEST_ARGS[@]}"
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

    exit $E2E_EXIT
else
    echo ""
    echo "=== E2E tests ==="
    echo "To include e2e tests, run:"
    echo "  ./run_tests.sh --e2e"
fi
