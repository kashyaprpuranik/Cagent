import socket
from datetime import datetime

import docker
from constants import (
    BETA_FEATURES,
    CAGENT_CONFIG_PATH,
    CELL_CONTAINER_NAME,
    COREDNS_CONTAINER_NAME,
    DATA_PLANE_DIR,
    DATAPLANE_MODE,
    ENVOY_CONTAINER_NAME,
    MANAGED_CONTAINERS,
    docker_client,
)
from fastapi import APIRouter

router = APIRouter()


@router.api_route("/health", methods=["GET", "HEAD"])
async def health():
    """Health check. Accepts HEAD for cloudflared tunnel origin health probes."""
    return {"status": "ok", "timestamp": datetime.utcnow().isoformat()}


@router.get("/health/detailed")
async def detailed_health():
    """Detailed health check for all components."""
    checks = {}

    # Check each container
    for name in MANAGED_CONTAINERS:
        try:
            container = docker_client.containers.get(name)
            # get() returns fresh attributes; no reload needed
            checks[name] = {
                "status": "healthy" if container.status == "running" else "unhealthy",
                "container_status": container.status,
                "uptime": container.attrs["State"].get("StartedAt") if container.status == "running" else None,
            }
        except docker.errors.NotFound:
            checks[name] = {"status": "missing", "container_status": "not_found"}
        except Exception as e:
            checks[name] = {"status": "error", "error": str(e)}

    # Test DNS resolution via CoreDNS (10.200.2.5 on infra-net)
    try:
        container = docker_client.containers.get(COREDNS_CONTAINER_NAME)
        if container.status == "running":
            # Resolve a test domain using the CoreDNS server directly
            resolver = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            resolver.settimeout(3)
            # Build a minimal DNS query for google.com A record
            query = b"\x12\x34"  # transaction ID
            query += b"\x01\x00"  # flags: standard query, recursion desired
            query += b"\x00\x01\x00\x00\x00\x00\x00\x00"  # 1 question
            query += b"\x06google\x03com\x00"  # google.com
            query += b"\x00\x01\x00\x01"  # type A, class IN
            resolver.sendto(query, ("10.200.2.5", 53))
            data, _ = resolver.recvfrom(512)
            resolver.close()
            # If we got a response, DNS is working
            checks["dns_resolution"] = {
                "status": "healthy",
                "test": "google.com",
            }
        else:
            checks["dns_resolution"] = {"status": "unhealthy", "reason": "container not running"}
    except Exception as e:
        checks["dns_resolution"] = {"status": "error", "error": str(e)}

    # Test Envoy readiness via admin port
    try:
        container = docker_client.containers.get(ENVOY_CONTAINER_NAME)
        if container.status == "running":
            result = container.exec_run(
                ["bash", "-c", "echo > /dev/tcp/localhost/9901"],
            )
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


@router.get("/health/deep")
async def deep_health():
    """Deep health check — verifies all services and local OpenObserve."""
    result = await detailed_health()

    # Also check local OpenObserve if configured
    try:
        from openobserve_client import is_openobserve_healthy

        result["checks"]["openobserve"] = {
            "status": "healthy" if is_openobserve_healthy() else "unhealthy",
        }
    except ImportError:
        result["checks"]["openobserve"] = {"status": "not_configured"}
    except Exception as e:
        result["checks"]["openobserve"] = {"status": "error", "error": str(e)}

    all_healthy = all(c.get("status") == "healthy" for c in result["checks"].values())
    result["status"] = "healthy" if all_healthy else "degraded"
    return result


@router.get("/info")
async def info():
    """System info."""
    return {
        "mode": DATAPLANE_MODE,
        "config_path": CAGENT_CONFIG_PATH,
        "data_plane_dir": DATA_PLANE_DIR,
        "features": sorted(BETA_FEATURES),
        "containers": {
            "cell": CELL_CONTAINER_NAME,
            "dns": COREDNS_CONTAINER_NAME,
            "http_proxy": ENVOY_CONTAINER_NAME,
        },
    }
