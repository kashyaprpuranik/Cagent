"""Command execution endpoints for interactive mode.

The CP pushes commands via Cloudflare Tunnel instead of queuing them
in the DB for the next heartbeat poll.
"""

import logging

import docker
from constants import docker_client
from fastapi import APIRouter, HTTPException
from main import discover_cell_containers

logger = logging.getLogger(__name__)

router = APIRouter()


def _get_cell_container():
    """Get the first discovered cell container."""
    containers = discover_cell_containers()
    if not containers:
        raise HTTPException(status_code=404, detail="No cell container found")
    return containers[0]


def _capture_container_config(container) -> dict:
    """Capture full container configuration for faithful recreation.

    Returns a kwargs dict suitable for ``docker_client.containers.create()``.
    """
    container.reload()
    attrs = container.attrs
    config = attrs.get("Config", {})
    host_config = attrs.get("HostConfig", {})
    network_settings = attrs.get("NetworkSettings", {})

    image = config.get("Image")
    env = config.get("Env", [])
    labels = dict(config.get("Labels", {}))
    binds = host_config.get("Binds", [])
    dns = host_config.get("Dns", [])
    cap_drop = host_config.get("CapDrop", [])
    security_opt = host_config.get("SecurityOpt", [])
    restart_policy = host_config.get("RestartPolicy", {})
    nano_cpus = host_config.get("NanoCpus")
    memory = host_config.get("Memory")
    mem_reservation = host_config.get("MemoryReservation")
    log_config = host_config.get("LogConfig", {})

    # Named volume mounts
    mounts = []
    for mount in attrs.get("Mounts", []):
        if mount.get("Type", "volume") == "volume":
            mounts.append(
                docker.types.Mount(
                    target=mount["Destination"],
                    source=mount["Name"],
                    type="volume",
                    read_only=not mount.get("RW", True),
                )
            )

    create_kwargs = {
        "image": image,
        "name": container.name,
        "environment": env,
        "labels": labels,
        "network_disabled": True,
        "detach": True,
    }
    if dns:
        create_kwargs["dns"] = dns
    if cap_drop:
        create_kwargs["cap_drop"] = cap_drop
    if security_opt:
        create_kwargs["security_opt"] = security_opt
    if binds:
        create_kwargs["volumes"] = binds
    if mounts:
        create_kwargs["mounts"] = mounts
    if restart_policy:
        create_kwargs["restart_policy"] = restart_policy
    if nano_cpus:
        create_kwargs["nano_cpus"] = nano_cpus
    if memory:
        create_kwargs["mem_limit"] = memory
    if mem_reservation:
        create_kwargs["mem_reservation"] = mem_reservation
    if log_config and log_config.get("Type"):
        create_kwargs["log_config"] = docker.types.LogConfig(
            type=log_config["Type"],
            config=log_config.get("Config", {}),
        )

    # Save network info separately (must be connected after create)
    create_kwargs["_networks"] = network_settings.get("Networks", {})

    return create_kwargs


def _recreate_container(create_kwargs: dict):
    """Create a container from captured config and reconnect networks."""
    networks = create_kwargs.pop("_networks", {})
    new_container = docker_client.containers.create(**create_kwargs)

    for net_name, net_config in networks.items():
        try:
            network = docker_client.networks.get(net_name)
            connect_kwargs = {}
            ip_addr = net_config.get("IPAddress")
            if ip_addr:
                connect_kwargs["ipv4_address"] = ip_addr
            network.connect(new_container, **connect_kwargs)
        except Exception as e:
            logger.warning("Could not reconnect to network %s: %s", net_name, e)

    new_container.start()
    return new_container


@router.post("/commands/restart")
async def restart_cell():
    """Restart the cell container."""
    container = _get_cell_container()
    try:
        container.restart(timeout=30)
        return {"status": "completed", "command": "restart", "message": f"Container {container.name} restarted"}
    except docker.errors.APIError as e:
        raise HTTPException(status_code=500, detail=f"Restart failed: {e}")


@router.post("/commands/stop")
async def stop_cell():
    """Stop the cell container."""
    container = _get_cell_container()
    try:
        container.stop(timeout=30)
        return {"status": "completed", "command": "stop", "message": f"Container {container.name} stopped"}
    except docker.errors.APIError as e:
        raise HTTPException(status_code=500, detail=f"Stop failed: {e}")


@router.post("/commands/start")
async def start_cell():
    """Start the cell container."""
    container = _get_cell_container()
    try:
        container.start()
        return {"status": "completed", "command": "start", "message": f"Container {container.name} started"}
    except docker.errors.APIError as e:
        raise HTTPException(status_code=500, detail=f"Start failed: {e}")


@router.post("/commands/wipe")
async def wipe_cell():
    """Stop, remove, and recreate the cell container with fresh filesystem.

    Preserves all container infrastructure config (env, volumes, mounts,
    DNS, capabilities, security options, networks, resource limits).
    """
    container = _get_cell_container()
    name = container.name
    try:
        create_kwargs = _capture_container_config(container)

        container.stop(timeout=10)
        container.remove(force=True)

        new_container = _recreate_container(create_kwargs)
        return {
            "status": "completed",
            "command": "wipe",
            "message": f"Container {name} wiped and recreated as {new_container.short_id}",
        }
    except docker.errors.APIError as e:
        raise HTTPException(status_code=500, detail=f"Wipe failed: {e}")
