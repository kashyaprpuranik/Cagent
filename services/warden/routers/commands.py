"""Command execution endpoints for interactive mode.

The CP pushes commands via Cloudflare Tunnel instead of queuing them
in the DB for the next heartbeat poll.
"""

import logging
from typing import Optional

import docker
from constants import docker_client
from fastapi import APIRouter, HTTPException
from main import discover_cell_containers
from pydantic import BaseModel

logger = logging.getLogger(__name__)

router = APIRouter()


def _get_cell_container():
    """Get the first discovered cell container."""
    containers = discover_cell_containers()
    if not containers:
        raise HTTPException(status_code=404, detail="No cell container found")
    return containers[0]


def _get_workspace_mount(container) -> Optional[dict]:
    """Return the /workspace mount info from container attrs, or None."""
    container.reload()
    for mount in container.attrs.get("Mounts", []):
        if mount.get("Destination") == "/workspace":
            return mount
    return None


def _wipe_workspace(container) -> None:
    """Clear the /workspace contents.  Container must be stopped.

    Handles both mount types:
    - Named volume: mount in throwaway container and delete contents
    - Bind mount: mount in throwaway container and delete contents
    """
    mount = _get_workspace_mount(container)
    if not mount:
        logger.warning("No /workspace mount found on %s — skipping workspace wipe", container.name)
        return

    mount_type = mount.get("Type", "volume")
    image = container.attrs.get("Config", {}).get("Image")

    if mount_type == "volume":
        vol_name = mount["Name"]
        logger.info("Wiping workspace: clearing volume %s using image %s", vol_name, image)
        docker_client.containers.run(
            image,
            entrypoint="/bin/sh",
            command=["-c", "find /workspace -mindepth 1 -delete"],
            mounts=[docker.types.Mount(target="/workspace", source=vol_name, type="volume")],
            remove=True,
            network_disabled=True,
        )

    elif mount_type == "bind":
        source = mount["Source"]
        logger.info("Wiping workspace: clearing bind mount %s using image %s", source, image)
        docker_client.containers.run(
            image,
            entrypoint="/bin/sh",
            command=["-c", "find /workspace -mindepth 1 -delete"],
            volumes={source: {"bind": "/workspace", "mode": "rw"}},
            remove=True,
            network_disabled=True,
        )

    else:
        logger.warning("Unknown mount type %s for /workspace on %s — skipping", mount_type, container.name)
        return

    logger.info("Workspace wiped for %s", container.name)


class WipeRequest(BaseModel):
    wipe_workspace: bool = False


@router.post("/commands/wipe")
async def wipe_cell(body: Optional[WipeRequest] = None):
    """Wipe the cell: stop, optionally clear workspace, restart.

    The same container is reused — no rename or recreation needed.
    """
    wipe_workspace = body.wipe_workspace if body else False
    container = _get_cell_container()
    name = container.name
    try:
        container.stop(timeout=10)

        if wipe_workspace:
            _wipe_workspace(container)

        container.start()
        return {
            "status": "completed",
            "command": "wipe",
            "message": f"Container {name} wiped (workspace={'wiped' if wipe_workspace else 'preserved'})",
        }
    except HTTPException:
        raise
    except docker.errors.APIError as e:
        raise HTTPException(status_code=500, detail=f"Wipe failed: {e}")


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
