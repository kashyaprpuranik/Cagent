## 2024-05-23 - FastAPI Async Anti-Pattern
**Learning:** `async def` handlers with blocking I/O (like Docker API calls) block the entire event loop.
**Action:** Use `def` for synchronous handlers or `run_in_threadpool` for blocking calls inside `async def`.
