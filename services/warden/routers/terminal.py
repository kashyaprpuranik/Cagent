import asyncio
import json
import socket

import docker
from constants import ALLOWED_CORS_ORIGINS, discover_cell_container_names, docker_client
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from utils import validate_websocket_origin

router = APIRouter()


def _get_raw_socket(sock):
    """Extract the raw socket from a Docker exec_start(socket=True) response.

    docker-py 7.x returns the raw socket directly via _get_raw_response_socket.
    Earlier versions may wrap it differently.  Walk the chain until we find a
    real socket.socket, then return it (do NOT descend into _socket.socket via
    ._sock — that C-level object misbehaves in some Python versions).
    """
    # docker-py 7.x: sock is already a socket.socket
    if isinstance(sock, socket.socket):
        return sock

    # Older versions / wrapped objects: try common attributes
    for attr in ("_sock",):
        inner = getattr(sock, attr, None)
        if isinstance(inner, socket.socket):
            return inner

    # Last resort: use whatever we got
    return sock


@router.websocket("/terminal")
async def web_terminal_default(websocket: WebSocket, root: bool = False):
    """Interactive terminal session — auto-selects the first cell container."""
    containers = discover_cell_container_names()
    if not containers:
        await websocket.accept()
        await websocket.send_text("\r\nNo cell containers found.\r\n")
        await websocket.close()
        return
    await web_terminal(websocket, containers[0], root=root)


@router.websocket("/terminal/{name}")
async def web_terminal(websocket: WebSocket, name: str, root: bool = False):
    """Interactive terminal session via WebSocket."""
    if not validate_websocket_origin(websocket, ALLOWED_CORS_ORIGINS):
        await websocket.close(code=1008)
        return

    await websocket.accept()

    # Only allow terminal access to cell containers, not infrastructure
    allowed = set(discover_cell_container_names())
    if name not in allowed:
        await websocket.send_text(f"\r\nTerminal access denied: '{name}' is not a cell container.\r\n")
        await websocket.close()
        return

    raw_sock = None

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
            user="root" if root else "",
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

        # Get the raw socket — do NOT double-deref via ._sock
        raw_sock = _get_raw_socket(sock)
        # Ensure blocking mode with a generous timeout so reads don't hang forever
        raw_sock.setblocking(True)
        raw_sock.settimeout(30)

        async def read_from_container():
            """Read output from container and send to websocket."""
            loop = asyncio.get_event_loop()
            while True:
                try:
                    data = await loop.run_in_executor(None, lambda: raw_sock.recv(4096))
                    if not data:
                        break
                    await websocket.send_text(data.decode("utf-8", errors="replace"))
                except (OSError, socket.timeout):
                    break
                except Exception:
                    break

        async def write_to_container():
            """Read from websocket and send to container."""
            while True:
                try:
                    data = await websocket.receive_text()
                    # Detect JSON resize messages from the frontend
                    if data.startswith("{"):
                        try:
                            msg = json.loads(data)
                            if msg.get("type") == "resize":
                                cols = int(msg.get("cols", 80))
                                rows = int(msg.get("rows", 24))
                                docker_client.api.exec_resize(exec_id["Id"], height=rows, width=cols)
                                continue
                        except (json.JSONDecodeError, ValueError, KeyError):
                            pass  # Not a resize message — send as normal input
                    raw_sock.sendall(data.encode("utf-8"))
                except WebSocketDisconnect:
                    break
                except Exception:
                    break

        # Run both tasks concurrently
        await asyncio.gather(read_from_container(), write_to_container(), return_exceptions=True)

    except docker.errors.NotFound:
        await websocket.send_text(f"\r\nContainer '{name}' not found.\r\n")
    except Exception as e:
        await websocket.send_text(f"\r\nError: {e}\r\n")
    finally:
        if raw_sock is not None:
            try:
                raw_sock.close()
            except Exception:
                pass
        try:
            await websocket.close()
        except Exception:
            pass
