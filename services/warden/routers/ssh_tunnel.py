import json
import logging
from pathlib import Path
from urllib.request import Request, urlopen
from urllib.error import URLError

import docker
from fastapi import APIRouter, HTTPException

from constants import (
    FRPC_CONTAINER_NAME,
    DATA_PLANE_DIR,
    DATAPLANE_MODE,
    CONTROL_PLANE_URL,
    CONTROL_PLANE_TOKEN,
    docker_client,
)
from models import SshTunnelConfig

router = APIRouter()
# Separate router for the tunnel-config proxy (registered without /api prefix)
proxy_router = APIRouter()
logger = logging.getLogger(__name__)


def read_env_file() -> dict:
    """Read current .env file if it exists."""
    env_path = Path(DATA_PLANE_DIR) / ".env"
    env_vars = {}
    if env_path.exists():
        for line in env_path.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, value = line.split("=", 1)
                env_vars[key.strip()] = value.strip().strip('"').strip("'")
    return env_vars


def write_env_file(env_vars: dict):
    """Write .env file with updated variables."""
    env_path = Path(DATA_PLANE_DIR) / ".env"
    lines = []

    # Read existing file to preserve comments and order
    existing_keys = set()
    if env_path.exists():
        for line in env_path.read_text().splitlines():
            stripped = line.strip()
            if stripped.startswith("#") or not stripped:
                lines.append(line)
            elif "=" in stripped:
                key = stripped.split("=", 1)[0].strip()
                existing_keys.add(key)
                if key in env_vars:
                    lines.append(f"{key}={env_vars[key]}")
                else:
                    lines.append(line)

    # Add new keys
    for key, value in env_vars.items():
        if key not in existing_keys:
            lines.append(f"{key}={value}")

    env_path.write_text("\n".join(lines) + "\n")


def get_tunnel_client_status() -> dict:
    """Get tunnel client container status."""
    try:
        container = docker_client.containers.get(FRPC_CONTAINER_NAME)
        container.reload()
        return {
            "exists": True,
            "status": container.status,
            "id": container.short_id
        }
    except docker.errors.NotFound:
        return {"exists": False, "status": "not_found"}
    except Exception as e:
        return {"exists": False, "status": "error", "error": str(e)}


def _fetch_tunnel_config(cp_url: str, token: str) -> dict:
    """Call CP tunnel-config endpoint to get STCP credentials."""
    url = f"{cp_url}/api/v1/cell/tunnel-config"
    req = Request(url, data=b"", method="POST", headers={
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    })
    try:
        with urlopen(req, timeout=10) as resp:
            return json.loads(resp.read())
    except URLError as e:
        raise HTTPException(502, f"Failed to reach control plane: {e}")
    except json.JSONDecodeError:
        raise HTTPException(502, "Invalid response from control plane")


def _derive_frp_server(cp_url: str) -> str:
    """Derive FRP server address from control plane URL host."""
    # Strip protocol and port: http://host:8002 -> host
    host = cp_url.split("://", 1)[-1].split(":")[0].split("/")[0]
    return host


# =========================================================================
# Tunnel-config proxy (Phase 3: FRP talks to warden instead of CP)
# =========================================================================

@proxy_router.post("/api/v1/cell/tunnel-config")
async def proxy_tunnel_config():
    """Proxy tunnel-config request to control plane.

    In connected mode: forwards to CP.
    In standalone mode: returns 404 (no tunnel server).
    """
    if DATAPLANE_MODE == "standalone":
        raise HTTPException(404, "Tunnel config not available in standalone mode")

    if not CONTROL_PLANE_URL or not CONTROL_PLANE_TOKEN:
        raise HTTPException(503, "Control plane not configured")

    return _fetch_tunnel_config(CONTROL_PLANE_URL, CONTROL_PLANE_TOKEN)


# =========================================================================
# Local admin SSH tunnel management endpoints
# =========================================================================

@router.get("/ssh-tunnel")
async def get_ssh_tunnel_status():
    """Get SSH tunnel status and configuration."""
    env_vars = read_env_file()
    tunnel_status = get_tunnel_client_status()

    cp_url = env_vars.get("CONTROL_PLANE_URL", "")
    cp_token = env_vars.get("CONTROL_PLANE_TOKEN", "")
    frp_token = env_vars.get("FRP_AUTH_TOKEN", "")
    frp_server = env_vars.get("FRP_SERVER_ADDR") or (_derive_frp_server(cp_url) if cp_url else "")
    frp_port = env_vars.get("FRP_SERVER_PORT", "7000")

    configured = bool(cp_url and cp_token and frp_token)

    return {
        "enabled": tunnel_status.get("exists", False) and tunnel_status.get("status") == "running",
        "connected": tunnel_status.get("status") == "running",
        "frp_server": frp_server,
        "frp_server_port": frp_port,
        "container_status": tunnel_status.get("status"),
        "configured": configured,
        "control_plane_url": cp_url,
        "has_cp_token": bool(cp_token),
        "has_frp_token": bool(frp_token),
    }


@router.post("/ssh-tunnel/configure")
async def configure_ssh_tunnel(config: SshTunnelConfig):
    """Configure SSH tunnel FRP settings.

    CONTROL_PLANE_URL and CONTROL_PLANE_TOKEN should already be in .env
    from connected-mode setup. This endpoint sets the FRP-specific vars.
    """
    env_vars = read_env_file()

    if not env_vars.get("CONTROL_PLANE_URL"):
        raise HTTPException(400, "CONTROL_PLANE_URL not set in .env. Configure connected mode first.")
    if not env_vars.get("CONTROL_PLANE_TOKEN"):
        raise HTTPException(400, "CONTROL_PLANE_TOKEN not set in .env. Configure connected mode first.")

    env_updates = {
        "FRP_AUTH_TOKEN": config.frp_auth_token,
        "FRP_SERVER_PORT": str(config.frp_server_port),
    }
    if config.frp_server_addr:
        env_updates["FRP_SERVER_ADDR"] = config.frp_server_addr

    try:
        write_env_file(env_updates)
    except Exception as e:
        raise HTTPException(500, f"Failed to write .env file: {e}")

    return {
        "status": "configured",
        "message": "FRP configuration saved. STCP credentials will be auto-provisioned on start."
    }


def create_tunnel_client_container(env_vars: dict):
    """Create the tunnel client container using Docker SDK."""
    # Get or create networks
    try:
        agent_net = docker_client.networks.get("cagent-cell-net")
    except docker.errors.NotFound:
        raise HTTPException(500, "Network cagent-cell-net not found. Is the data plane running?")

    try:
        infra_net = docker_client.networks.get("cagent-infra-net")
    except docker.errors.NotFound:
        raise HTTPException(500, "Network cagent-infra-net not found. Is the data plane running?")

    container_env = {
        "FRP_AUTH_TOKEN": env_vars.get("FRP_AUTH_TOKEN"),
        "FRP_SERVER_PORT": env_vars.get("FRP_SERVER_PORT", "7000"),
    }
    frp_server = env_vars.get("FRP_SERVER_ADDR")
    if frp_server:
        container_env["FRP_SERVER_ADDR"] = frp_server

    # Create container with bootstrap entrypoint
    container = docker_client.containers.create(
        image="snowdreamtech/frpc:latest",
        name=FRPC_CONTAINER_NAME,
        entrypoint=["/bin/sh", "/bootstrap/entrypoint.sh"],
        environment=container_env,
        volumes={
            f"{DATA_PLANE_DIR}/configs/frpc/entrypoint.sh": {
                "bind": "/bootstrap/entrypoint.sh",
                "mode": "ro",
            }
        },
        restart_policy={"Name": "unless-stopped"},
        detach=True,
    )

    # Connect to networks with specific IPs
    agent_net.connect(container, ipv4_address="10.200.1.30")
    infra_net.connect(container, ipv4_address="10.200.2.30")

    return container


@router.post("/ssh-tunnel/start")
async def start_ssh_tunnel():
    """Start SSH tunnel by bringing up tunnel client container."""
    env_vars = read_env_file()
    required = ["CONTROL_PLANE_URL", "CONTROL_PLANE_TOKEN", "FRP_AUTH_TOKEN"]
    missing = [k for k in required if not env_vars.get(k)]

    if missing:
        raise HTTPException(400, f"Missing configuration: {', '.join(missing)}. Configure tunnel first.")

    # Try to start existing container or create new one
    tunnel_status = get_tunnel_client_status()

    try:
        if tunnel_status.get("exists"):
            container = docker_client.containers.get(FRPC_CONTAINER_NAME)
            if container.status != "running":
                container.start()
            return {"status": "started", "message": "Tunnel client container started"}
        else:
            # Container doesn't exist - create it using Docker SDK
            container = create_tunnel_client_container(env_vars)
            container.start()
            return {"status": "started", "message": "Tunnel client container created and started"}
    except docker.errors.ImageNotFound:
        # Pull the image first
        docker_client.images.pull("snowdreamtech/frpc:latest")
        container = create_tunnel_client_container(env_vars)
        container.start()
        return {"status": "started", "message": "Tunnel client image pulled and container started"}
    except docker.errors.APIError as e:
        raise HTTPException(500, f"Docker error: {e}")


@router.post("/ssh-tunnel/stop")
async def stop_ssh_tunnel():
    """Stop SSH tunnel by stopping tunnel client container."""
    tunnel_status = get_tunnel_client_status()

    if not tunnel_status.get("exists"):
        return {"status": "ok", "message": "Tunnel not running"}

    try:
        container = docker_client.containers.get(FRPC_CONTAINER_NAME)
        container.stop(timeout=10)
        return {"status": "stopped", "message": "Tunnel client container stopped"}
    except docker.errors.NotFound:
        return {"status": "ok", "message": "Container not found"}
    except Exception as e:
        raise HTTPException(500, f"Failed to stop container: {e}")


@router.get("/ssh-tunnel/connect-info")
async def get_connect_info():
    """Get SSH connection info by fetching STCP config from control plane."""
    env_vars = read_env_file()

    cp_url = env_vars.get("CONTROL_PLANE_URL")
    cp_token = env_vars.get("CONTROL_PLANE_TOKEN")
    if not cp_url or not cp_token:
        raise HTTPException(400, "Control plane not configured. Set CONTROL_PLANE_URL and CONTROL_PLANE_TOKEN.")

    # Fetch tunnel config from CP (idempotent — returns existing secret)
    tunnel_data = _fetch_tunnel_config(cp_url, cp_token)

    proxy_name = tunnel_data.get("proxy_name", "")
    secret_key = tunnel_data.get("secret_key", "")
    if not proxy_name or not secret_key:
        raise HTTPException(502, "Unexpected response from control plane tunnel-config endpoint")

    frp_server = env_vars.get("FRP_SERVER_ADDR") or _derive_frp_server(cp_url)
    frp_port = env_vars.get("FRP_SERVER_PORT", "7000")
    frp_token = env_vars.get("FRP_AUTH_TOKEN", "<YOUR_FRP_AUTH_TOKEN>")

    visitor_config = f"""# FRP Visitor Configuration - Save as frpc-visitor.toml
# Run: frpc -c frpc-visitor.toml
serverAddr = "{frp_server}"
serverPort = {frp_port}
auth.method = "token"
auth.token = "{frp_token}"

[[visitors]]
name = "{proxy_name}-visitor"
type = "stcp"
serverName = "{proxy_name}"
secretKey = "{secret_key}"
bindAddr = "127.0.0.1"
bindPort = 2222
"""

    return {
        "proxy_name": proxy_name,
        "frp_server": frp_server,
        "frp_port": frp_port,
        "secret_key": secret_key,
        "ssh_command": "ssh -p 2222 cell@127.0.0.1  # After starting visitor",
        "visitor_config": visitor_config,
    }
