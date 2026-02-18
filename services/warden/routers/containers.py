import docker
from fastapi import APIRouter, HTTPException

from constants import MANAGED_CONTAINERS, READ_ONLY, docker_client, discover_cell_container_names
from models import ContainerAction

router = APIRouter()


def get_container_info(name: str) -> dict:
    """Get container status info."""
    try:
        container = docker_client.containers.get(name)
        container.reload()

        info = {
            "name": name,
            "status": container.status,
            "id": container.short_id,
            "image": container.image.tags[0] if container.image.tags else "unknown",
            "created": container.attrs["Created"],
        }

        if container.status == "running":
            info["started_at"] = container.attrs["State"]["StartedAt"]

            # Get stats
            try:
                stats = container.stats(stream=False)

                # CPU
                cpu_delta = stats["cpu_stats"]["cpu_usage"]["total_usage"] - \
                           stats["precpu_stats"]["cpu_usage"]["total_usage"]
                system_delta = stats["cpu_stats"]["system_cpu_usage"] - \
                              stats["precpu_stats"]["system_cpu_usage"]
                num_cpus = stats["cpu_stats"].get("online_cpus", 1)

                if system_delta > 0:
                    info["cpu_percent"] = round((cpu_delta / system_delta) * num_cpus * 100, 2)

                # Memory
                memory_usage = stats["memory_stats"].get("usage", 0)
                memory_limit = stats["memory_stats"].get("limit", 0)
                info["memory_mb"] = round(memory_usage / (1024 * 1024), 2)
                info["memory_limit_mb"] = round(memory_limit / (1024 * 1024), 2)
            except Exception:
                pass

        return info

    except docker.errors.NotFound:
        return {"name": name, "status": "not_found"}
    except Exception as e:
        return {"name": name, "status": "error", "error": str(e)}


@router.get("/containers")
async def list_containers():
    """Get status of all managed containers."""
    containers = {}

    for name in MANAGED_CONTAINERS:
        containers[name] = get_container_info(name)

    return {"containers": containers}


@router.get("/containers/{name}")
async def get_container(name: str):
    """Get status of a specific container."""
    return get_container_info(name)


@router.post("/containers/{name}")
async def control_container(name: str, action: ContainerAction):
    """Control a container (start/stop/restart).

    Only cell containers may be controlled. Infrastructure containers
    (dns-filter, http-proxy, warden, etc.) are protected.
    """
    if READ_ONLY:
        raise HTTPException(403, "Container control is disabled in connected mode (managed by control plane)")

    allowed = set(discover_cell_container_names())
    if name not in allowed:
        raise HTTPException(403, f"Cannot {action.action} infrastructure container '{name}'")

    try:
        container = docker_client.containers.get(name)

        if action.action == "start":
            container.start()
        elif action.action == "stop":
            container.stop(timeout=10)
        elif action.action == "restart":
            container.restart(timeout=10)
        else:
            raise HTTPException(400, f"Unknown action: {action.action}")

        return {"status": "ok", "action": action.action, "container": name}

    except docker.errors.NotFound:
        raise HTTPException(404, f"Container not found: {name}")
    except Exception as e:
        raise HTTPException(500, str(e))
