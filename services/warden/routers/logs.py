import logging
from datetime import datetime
from typing import Optional

import docker
from constants import ALLOWED_CORS_ORIGINS, docker_client, get_managed_containers
from fastapi import APIRouter, HTTPException, Query, WebSocket, WebSocketDisconnect
from utils import async_generator, validate_websocket_origin

logger = logging.getLogger(__name__)

router = APIRouter()


@router.get("/containers/{name}/logs")
def get_container_logs(name: str, tail: int = 100, since: Optional[str] = None):
    """Get container logs."""
    # Restrict access to managed containers only
    if name not in get_managed_containers():
        raise HTTPException(403, f"Access denied: {name} is not a managed container")

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
    if not validate_websocket_origin(websocket, ALLOWED_CORS_ORIGINS):
        await websocket.close(code=1008)
        return

    await websocket.accept()

    # Restrict access to managed containers only
    if name not in get_managed_containers():
        await websocket.send_text(f"ERROR: Access denied: {name} is not a managed container")
        await websocket.close()
        return

    try:
        container = docker_client.containers.get(name)

        # Stream logs (run blocking generator in thread to avoid blocking event loop)
        async for log in async_generator(container.logs(stream=True, follow=True, timestamps=True, tail=50)):
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


@router.get("/logs/search")
async def search_logs(
    query: str = "",
    source: Optional[str] = None,
    cell_id: Optional[str] = None,
    limit: int = Query(default=100, le=1000),
    start: Optional[str] = None,
    end: Optional[str] = None,
):
    """Search logs from local OpenObserve.

    Falls back to Docker logs if OO is unavailable.
    """
    try:
        from openobserve_client import datetime_to_us, now_us, query_openobserve

        # Build time range
        end_us = now_us()
        start_us = end_us - 6 * 3600 * 1_000_000  # default 6h

        if end:
            end_dt = datetime.fromisoformat(end.replace("Z", "+00:00"))
            end_us = datetime_to_us(end_dt)
        if start:
            start_dt = datetime.fromisoformat(start.replace("Z", "+00:00"))
            start_us = datetime_to_us(start_dt)

        # Build SQL query
        conditions = []
        if query:
            conditions.append(f"message LIKE '%{query}%'")
        if source:
            conditions.append(f"source = '{source}'")
        if cell_id:
            conditions.append(f"cell_id = '{cell_id}'")

        where = f" WHERE {' AND '.join(conditions)}" if conditions else ""
        sql = f"SELECT * FROM default{where} ORDER BY _timestamp DESC LIMIT {limit}"

        hits = query_openobserve(sql, start_us, end_us)
        return {"hits": hits, "total": len(hits)}

    except ImportError:
        logger.debug("OpenObserve client not available, returning empty results")
        return {"hits": [], "total": 0}
