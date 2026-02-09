#!/bin/bash
# =============================================================================
# Data Plane Launcher
# =============================================================================
#
# Usage:
#   ./run.sh                              # Dev mode (runc)
#   ./run.sh --gvisor                     # Production mode (gVisor)
#   ./run.sh --admin                      # Dev + local admin UI
#   ./run.sh --gvisor --admin --ssh       # Production + admin + SSH
#   ./run.sh down                         # Stop all services
#
# Profiles (from docker-compose.yml):
#   dev        Agent with runc runtime (default)
#   standard   Agent with gVisor/runsc runtime
#   admin      Local admin UI + agent-manager
#   managed    Agent-manager only (no UI)
#   auditing   Vector log forwarding
#   ssh        FRP tunnel for SSH access
#
# =============================================================================

set -e

PROFILES=""
AGENT_PROFILE="dev"
ACTION="up -d"

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --gvisor)
            # Check if gVisor is installed
            if ! command -v runsc &> /dev/null; then
                echo "Error: gVisor (runsc) is not installed."
                echo "Install from: https://gvisor.dev/docs/user_guide/install/"
                exit 1
            fi
            # Check if Docker is configured with runsc runtime
            if ! docker info 2>/dev/null | grep -q "runsc"; then
                echo "Error: Docker is not configured with gVisor runtime."
                echo "Run: sudo runsc install && sudo systemctl restart docker"
                exit 1
            fi
            AGENT_PROFILE="standard"
            shift
            ;;
        --admin)
            PROFILES="$PROFILES --profile admin"
            shift
            ;;
        --managed)
            PROFILES="$PROFILES --profile managed"
            shift
            ;;
        --ssh)
            PROFILES="$PROFILES --profile ssh"
            shift
            ;;
        --auditing)
            PROFILES="$PROFILES --profile auditing"
            shift
            ;;
        up|down|restart|logs|ps|build)
            ACTION="$1"
            shift
            break
            ;;
        -h|--help)
            echo "Usage: $0 [OPTIONS] [ACTION] [ARGS...]"
            echo ""
            echo "Options:"
            echo "  --gvisor     Use gVisor runtime (default: runc)"
            echo "  --admin      Enable local admin UI + agent-manager"
            echo "  --managed    Enable agent-manager only (no UI)"
            echo "  --ssh        Enable SSH access via FRP tunnel"
            echo "  --auditing   Enable log forwarding via Vector"
            echo ""
            echo "Actions:"
            echo "  up           Start services (default, detached)"
            echo "  down         Stop and remove services"
            echo "  restart      Restart services"
            echo "  logs         View logs (e.g., logs -f agent)"
            echo "  ps           List running services"
            echo "  build        Build images"
            echo ""
            echo "Examples:"
            echo "  $0                              # Dev mode (runc)"
            echo "  $0 --gvisor                     # Production (gVisor)"
            echo "  $0 --admin                      # Dev + admin UI"
            echo "  $0 --gvisor --admin --ssh       # Full production stack"
            echo "  $0 --gvisor --auditing          # Production + logging"
            echo "  $0 down                         # Stop all"
            echo "  $0 logs -f agent                # Follow agent logs"
            exit 0
            ;;
        *)
            break
            ;;
    esac
done

# Handle action-specific behavior
case $ACTION in
    up)
        ACTION="up -d"
        ;;
esac

# Always include agent profile
PROFILES="--profile $AGENT_PROFILE $PROFILES"

# Build and run
CMD="docker compose $PROFILES $ACTION $@"
echo "Agent: $AGENT_PROFILE"
echo "Running: $CMD"
exec $CMD
