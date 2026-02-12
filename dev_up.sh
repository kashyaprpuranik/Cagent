#!/bin/bash
# =============================================================================
# Unified Development Environment
# =============================================================================
#
# Orchestrates Control Plane (CP) and Data Plane (DP) for development and demos.
#
# Usage:
#   ./dev_up.sh                     # Full stack: CP + DP (kept running after seeding)
#   ./dev_up.sh --cp-only           # Control plane only
#   ./dev_up.sh --dp-only           # Data plane only (standalone)
#   ./dev_up.sh --dp-only --admin   # Data plane with local admin UI
#   ./dev_up.sh down                # Stop everything
#
# DP flags (passed through): --admin, --gvisor, --ssh, --beta
#
# NOT for production use.
# =============================================================================

set -e

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CP_DIR="$ROOT_DIR/control_plane"
DP_DIR="$ROOT_DIR/data_plane"

# Deterministic agent token — must match seed.py SEED_AGENT_TOKEN
SEED_AGENT_TOKEN="seed-agent-token-do-not-use-in-production"

# Defaults
MODE="full"          # full | cp-only | dp-only
DP_PROFILES=""
DP_AGENT_PROFILE="dev"
ACTION="up"

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --cp-only)
            MODE="cp-only"
            shift
            ;;
        --dp-only)
            MODE="dp-only"
            shift
            ;;
        --gvisor)
            if ! command -v runsc &> /dev/null; then
                echo "Error: gVisor (runsc) is not installed."
                exit 1
            fi
            DP_AGENT_PROFILE="standard"
            shift
            ;;
        --admin)
            DP_PROFILES="$DP_PROFILES --profile admin"
            shift
            ;;
        --ssh)
            DP_PROFILES="$DP_PROFILES --profile ssh"
            shift
            ;;
        --beta)
            export BETA_FEATURES="email"
            DP_PROFILES="$DP_PROFILES --profile email"
            shift
            ;;
        down)
            ACTION="down"
            shift
            ;;
        -h|--help)
            echo "Usage: $0 [OPTIONS] [ACTION]"
            echo ""
            echo "Modes:"
            echo "  (default)       Full stack: CP + DP (kept running after seeding)"
            echo "  --cp-only       Control plane only"
            echo "  --dp-only       Data plane only (standalone mode)"
            echo ""
            echo "DP options:"
            echo "  --admin         Include local admin UI"
            echo "  --gvisor        Use gVisor runtime (default: runc)"
            echo "  --ssh           Include SSH tunnel via FRP"
            echo "  --beta          Enable beta features (email proxy)"
            echo ""
            echo "Actions:"
            echo "  down            Stop all services (CP + DP)"
            echo ""
            echo "Examples:"
            echo "  $0                        # Full stack: CP + DP"
            echo "  $0 --cp-only              # Just the control plane"
            echo "  $0 --dp-only --admin      # Standalone DP with admin UI"
            echo "  $0 down                   # Stop everything"
            exit 0
            ;;
        *)
            echo "Unknown option: $1 (use --help for usage)"
            exit 1
            ;;
    esac
done

# =============================================================================
# Helpers
# =============================================================================

get_cp_network() {
    # Find the CP's Docker network so DP containers can be attached to it.
    # docker compose names it control_plane_control-net (project = directory name).
    docker network ls --filter name=control_plane_control-net --format '{{.Name}}' | head -1
}

start_cp() {
    # Delegate to the existing CP dev_up.sh script
    echo ""
    echo "=== Starting Control Plane ==="
    "$CP_DIR/dev_up.sh"
}

stop_cp() {
    echo "Stopping Control Plane..."
    cd "$CP_DIR"
    docker compose down -v --remove-orphans 2>/dev/null || true
    cd "$ROOT_DIR"
}

stop_dp() {
    echo "Stopping Data Plane..."
    cd "$DP_DIR"
    docker compose --profile dev --profile standard --profile admin --profile managed --profile auditing --profile ssh --profile email down --remove-orphans 2>/dev/null || true
    cd "$ROOT_DIR"
}

start_dp() {
    local dp_mode="${1:-standalone}"
    echo ""
    echo "=== Starting Data Plane (mode: $dp_mode) ==="

    # Tear down any existing DP containers (avoids docker compose v1 recreate bugs)
    stop_dp

    cd "$DP_DIR"
    local profiles="--profile $DP_AGENT_PROFILE $DP_PROFILES"

    if [ "$dp_mode" = "connected" ]; then
        # Add auditing + managed + admin profiles for connected mode
        # Admin UI runs in read-only mode when DATAPLANE_MODE=connected
        profiles="$profiles --profile auditing --profile managed --profile admin"

        # Use CP container name directly (we'll attach DP containers to CP network after start)
        export CONTROL_PLANE_URL="http://backend:8000"
        export CONTROL_PLANE_TOKEN="$SEED_AGENT_TOKEN"
        export DATAPLANE_MODE="connected"
        echo "  CP URL: $CONTROL_PLANE_URL"
    else
        export DATAPLANE_MODE="standalone"
    fi

    # Scale: 2 agent containers by default
    local agent_service="agent-dev"
    [ "$DP_AGENT_PROFILE" = "standard" ] && agent_service="agent"
    local scale_flag="--scale ${agent_service}=2"

    echo "Building DP images..."
    docker compose $profiles build

    echo "Starting DP services (2 agent containers)..."
    docker compose $profiles up -d $scale_flag

    # In connected mode, bridge DP containers to CP's Docker network.
    # This lets agent-manager and vector reach backend directly,
    # avoiding Docker iptables rules that block cross-bridge-network traffic to host ports.
    if [ "$dp_mode" = "connected" ]; then
        echo "Connecting DP services to CP network..."
        local cp_net
        cp_net=$(get_cp_network)
        if [ -n "$cp_net" ]; then
            docker network connect "$cp_net" agent-manager 2>/dev/null || true
            docker network connect "$cp_net" log-shipper 2>/dev/null || true
            docker network connect "$cp_net" local-admin 2>/dev/null || true
            echo "  Connected agent-manager + log-shipper + local-admin to $cp_net"
        else
            echo "  WARNING: CP network not found — agent-manager/log-shipper can't reach CP"
        fi
    fi

    # Wait for agent container(s) to be running (discovered by label)
    echo "Waiting for agent container(s)..."
    RETRIES=20
    until docker ps --filter "label=cagent.role=agent" -q 2>/dev/null | grep -q .; do
        RETRIES=$((RETRIES - 1))
        if [ $RETRIES -le 0 ]; then
            echo "  ERROR: Agent container(s) failed to start"
            docker compose $profiles logs 2>/dev/null | tail -20
            exit 1
        fi
        sleep 2
    done
    echo "  Agent container(s): OK"

    # Wait for HTTP proxy to be healthy (probe from agent container via proxy)
    echo "Waiting for HTTP proxy..."
    AGENT_CONTAINER=$(docker ps --filter "label=cagent.role=agent" --format "{{.Names}}" | head -1)
    RETRIES=15
    until docker exec "$AGENT_CONTAINER" curl -sf -x http://10.200.1.10:8443 --connect-timeout 2 http://api.github.com/ -o /dev/null 2>/dev/null; do
        RETRIES=$((RETRIES - 1))
        if [ $RETRIES -le 0 ]; then
            echo "  WARNING: HTTP proxy health check timed out (continuing anyway)"
            break
        fi
        sleep 2
    done
    echo "  HTTP proxy: OK"

    if [ "$dp_mode" = "connected" ]; then
        # Wait for log shipper to be running
        echo "Waiting for log shipper..."
        RETRIES=10
        until docker inspect -f '{{.State.Running}}' log-shipper 2>/dev/null | grep -q true; do
            RETRIES=$((RETRIES - 1))
            if [ $RETRIES -le 0 ]; then
                echo "  WARNING: Log shipper failed to start (continuing anyway)"
                break
            fi
            sleep 2
        done
        echo "  Log shipper: OK"
    fi

    cd "$ROOT_DIR"
}

seed_logs() {
    echo ""
    echo "=== Generating Log Traffic ==="

    # Run the seed traffic script inside an agent container
    # (baked into agent image at /seed_traffic.py)
    AGENT_CONTAINER=$(docker ps --filter "label=cagent.role=agent" --format "{{.Names}}" | head -1)
    docker exec "$AGENT_CONTAINER" python3 /seed_traffic.py

    # Wait for logs to propagate through Vector -> CP -> OpenObserve
    echo ""
    echo "Waiting for logs to propagate (20s)..."
    sleep 20
    echo "Log seeding complete."
}

# =============================================================================
# Main
# =============================================================================

echo "=== AI Devbox Development Environment ==="
echo "Root: $ROOT_DIR"

# --- Handle 'down' action ---
if [ "$ACTION" = "down" ]; then
    stop_dp
    stop_cp
    echo ""
    echo "=== All services stopped ==="
    exit 0
fi

# --- Execute based on mode ---
case $MODE in
    cp-only)
        start_cp

        echo ""
        echo "=== Control Plane ready ==="
        echo ""
        echo "Access:"
        echo "  Admin UI:  http://localhost:9080"
        echo "  API Docs:  http://localhost:8002/docs"
        ;;

    dp-only)
        start_dp "standalone"

        echo ""
        echo "=== Data Plane ready (standalone) ==="
        echo ""
        echo "Agent container: docker exec -it agent bash"
        if echo "$DP_PROFILES" | grep -q "admin"; then
            echo "Admin UI: http://localhost:${LOCAL_ADMIN_PORT:-8081}"
        fi
        ;;

    full)
        start_cp
        start_dp "connected"
        seed_logs

        echo ""
        echo "=== Full stack ready ==="
        echo ""
        echo "Access:"
        echo "  CP Admin:  http://localhost:9080"
        echo "  DP Admin:  http://localhost:${LOCAL_ADMIN_PORT:-8081}  (read-only in connected mode)"
        echo "  API Docs:  http://localhost:8002/docs"
        echo "  Agent:     docker exec -it agent bash"
        ;;
esac
