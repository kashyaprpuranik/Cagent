from datetime import datetime

from fastapi import APIRouter

import docker

from ..constants import (
    AGENT_CONTAINER_NAME,
    COREDNS_CONTAINER_NAME,
    ENVOY_CONTAINER_NAME,
    FRPC_CONTAINER_NAME,
    CAGENT_CONFIG_PATH,
    DATA_PLANE_DIR,
    MANAGED_CONTAINERS,
    docker_client,
)

router = APIRouter()


@router.get("/health")
async def health():
    """Health check."""
    return {"status": "ok", "timestamp": datetime.utcnow().isoformat()}


@router.get("/health/detailed")
async def detailed_health():
    """Detailed health check for all components."""
    checks = {}

    # Check each container
    for name in MANAGED_CONTAINERS:
        try:
            container = docker_client.containers.get(name)
            container.reload()
            checks[name] = {
                "status": "healthy" if container.status == "running" else "unhealthy",
                "container_status": container.status,
                "uptime": container.attrs["State"].get("StartedAt") if container.status == "running" else None,
            }
        except docker.errors.NotFound:
            checks[name] = {"status": "missing", "container_status": "not_found"}
        except Exception as e:
            checks[name] = {"status": "error", "error": str(e)}

    # Test DNS resolution (via CoreDNS container)
    try:
        container = docker_client.containers.get(COREDNS_CONTAINER_NAME)
        if container.status == "running":
            # Try to resolve a test domain
            result = container.exec_run(["nslookup", "google.com", "127.0.0.1"], timeout=5)
            checks["dns_resolution"] = {
                "status": "healthy" if result.exit_code == 0 else "unhealthy",
                "test": "google.com",
            }
        else:
            checks["dns_resolution"] = {"status": "unhealthy", "reason": "container not running"}
    except Exception as e:
        checks["dns_resolution"] = {"status": "error", "error": str(e)}

    # Test Envoy health endpoint
    try:
        container = docker_client.containers.get(ENVOY_CONTAINER_NAME)
        if container.status == "running":
            result = container.exec_run(["wget", "-q", "-O", "-", "http://localhost:9901/ready"], timeout=5)
            checks["envoy_ready"] = {
                "status": "healthy" if result.exit_code == 0 else "unhealthy",
            }
        else:
            checks["envoy_ready"] = {"status": "unhealthy", "reason": "container not running"}
    except Exception as e:
        checks["envoy_ready"] = {"status": "error", "error": str(e)}

    # Overall status
    all_healthy = all(c.get("status") == "healthy" for c in checks.values())

    return {
        "status": "healthy" if all_healthy else "degraded",
        "timestamp": datetime.utcnow().isoformat(),
        "checks": checks,
    }


@router.get("/info")
async def info():
    """System info."""
    return {
        "mode": "standalone",
        "config_path": CAGENT_CONFIG_PATH,
        "data_plane_dir": DATA_PLANE_DIR,
        "containers": {
            "agent": AGENT_CONTAINER_NAME,
            "dns": COREDNS_CONTAINER_NAME,
            "envoy": ENVOY_CONTAINER_NAME,
            "frpc": FRPC_CONTAINER_NAME
        }
    }
