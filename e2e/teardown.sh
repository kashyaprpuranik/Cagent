#!/bin/bash
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
REPO_ROOT=$(dirname "$SCRIPT_DIR")

cd "$REPO_ROOT/data_plane" && docker compose --profile dev --profile managed down -v 2>/dev/null
cd "$REPO_ROOT/control_plane" && docker compose down -v 2>/dev/null
docker rm -f openobserve-mock 2>/dev/null
docker rm -f echo-server 2>/dev/null
docker network rm e2e-bridge 2>/dev/null
rm -f "$SCRIPT_DIR/.agent-token"

# Restore cagent.yaml if backup exists
if [ -f "$SCRIPT_DIR/.cagent.yaml.bak" ]; then
    cp "$SCRIPT_DIR/.cagent.yaml.bak" "$REPO_ROOT/data_plane/configs/cagent.yaml"
    rm -f "$SCRIPT_DIR/.cagent.yaml.bak"
    echo "Restored cagent.yaml."
fi

echo "Torn down."
