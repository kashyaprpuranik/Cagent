import asyncio
from typing import List
from urllib.parse import urlparse

from fastapi import WebSocket


async def async_generator(sync_generator):
    """Convert a blocking generator into an async one.

    Uses the default ThreadPoolExecutor to run the blocking ``next()`` calls,
    preventing the event loop from being blocked by synchronous I/O or delays.

    This is essential for operations like ``docker.Container.logs(stream=True)``
    which would otherwise block the entire application loop.
    """
    loop = asyncio.get_running_loop()
    iterator = iter(sync_generator)
    while True:
        try:
            # Run blocking next() in a thread.
            # StopIteration is raised by next() when done, which run_in_executor propagates.
            value = await loop.run_in_executor(None, next, iterator)
            yield value
        except StopIteration:
            break


def validate_websocket_origin(websocket: WebSocket, allowed_origins: List[str]) -> bool:
    """Validate WebSocket origin to prevent CSWSH.

    Allows connection if either of the following conditions is met:
    1. The Origin header matches the Host header (ignoring scheme).
    2. The Origin header is explicitly listed in the allowed_origins list.
    """
    origin = websocket.headers.get("origin")
    if not origin:
        # Browsers always send Origin. Require it for security.
        return False

    # Check explicit allowlist
    if origin in allowed_origins:
        return True

    # Check same-origin (Host header match)
    host = websocket.headers.get("host")
    if not host:
        return False

    # Strip scheme from origin
    origin_host = urlparse(origin).netloc

    if origin_host == host:
        return True

    return False
