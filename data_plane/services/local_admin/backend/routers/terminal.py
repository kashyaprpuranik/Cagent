import asyncio

import docker
from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from ..constants import docker_client

router = APIRouter()


@router.websocket("/terminal/{name}")
async def web_terminal(websocket: WebSocket, name: str):
    """Interactive terminal session via WebSocket."""
    await websocket.accept()

    try:
        container = docker_client.containers.get(name)

        if container.status != "running":
            await websocket.send_text(f"\r\nContainer '{name}' is not running.\r\n")
            await websocket.close()
            return

        # Create exec instance with TTY
        exec_id = docker_client.api.exec_create(
            container.id,
            cmd="/bin/bash",
            stdin=True,
            tty=True,
            stdout=True,
            stderr=True,
        )

        # Start exec with socket
        sock = docker_client.api.exec_start(
            exec_id["Id"],
            socket=True,
            tty=True,
        )

        # Get the raw socket
        raw_sock = sock._sock

        async def read_from_container():
            """Read output from container and send to websocket."""
            loop = asyncio.get_event_loop()
            while True:
                try:
                    data = await loop.run_in_executor(None, lambda: raw_sock.recv(4096))
                    if not data:
                        break
                    await websocket.send_text(data.decode("utf-8", errors="replace"))
                except Exception:
                    break

        async def write_to_container():
            """Read from websocket and send to container."""
            while True:
                try:
                    data = await websocket.receive_text()
                    raw_sock.sendall(data.encode("utf-8"))
                except WebSocketDisconnect:
                    break
                except Exception:
                    break

        # Run both tasks concurrently
        await asyncio.gather(
            read_from_container(),
            write_to_container(),
            return_exceptions=True
        )

    except docker.errors.NotFound:
        await websocket.send_text(f"\r\nContainer '{name}' not found.\r\n")
    except Exception as e:
        await websocket.send_text(f"\r\nError: {e}\r\n")
    finally:
        try:
            await websocket.close()
        except Exception:
            pass
