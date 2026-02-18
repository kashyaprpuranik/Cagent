from typing import Optional

import docker
from fastapi import APIRouter, HTTPException, WebSocket, WebSocketDisconnect

from constants import docker_client

router = APIRouter()


@router.get("/containers/{name}/logs")
async def get_container_logs(name: str, tail: int = 100, since: Optional[str] = None):
    """Get container logs."""
    try:
        container = docker_client.containers.get(name)

        kwargs = {"tail": tail, "timestamps": True}
        if since:
            kwargs["since"] = since

        logs = container.logs(**kwargs).decode("utf-8")
        lines = logs.strip().split("\n") if logs.strip() else []

        return {"container": name, "lines": lines, "count": len(lines)}

    except docker.errors.NotFound:
        raise HTTPException(404, f"Container not found: {name}")
    except Exception as e:
        raise HTTPException(500, str(e))


@router.websocket("/containers/{name}/logs/stream")
async def stream_container_logs(websocket: WebSocket, name: str):
    """Stream container logs via WebSocket."""
    await websocket.accept()

    try:
        container = docker_client.containers.get(name)

        # Stream logs
        for log in container.logs(stream=True, follow=True, timestamps=True, tail=50):
            try:
                await websocket.send_text(log.decode("utf-8"))
            except WebSocketDisconnect:
                break

    except docker.errors.NotFound:
        await websocket.send_text(f"ERROR: Container not found: {name}")
    except Exception as e:
        await websocket.send_text(f"ERROR: {e}")
    finally:
        try:
            await websocket.close()
        except Exception:
            pass
