import asyncio

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
