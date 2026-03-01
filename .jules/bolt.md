## 2024-05-23 - FastAPI Async Anti-Pattern
**Learning:** `async def` handlers with blocking I/O (like Docker API calls) block the entire event loop.
**Action:** Use `def` for synchronous handlers or `run_in_threadpool` for blocking calls inside `async def`.

## 2024-05-24 - Widespread Blocking I/O in Async Handlers
**Learning:** The codebase consistently used `async def` for endpoints performing blocking operations like Docker API calls, `requests.get`, and file I/O. This defeats the purpose of `async` and degrades performance by blocking the event loop.
**Action:** Systematically converted `async def` to `def` for handlers dominated by blocking I/O to leverage FastAPI's thread pool.

## 2026-03-01 - Cached cagent.yaml Parsing
**Learning:** Re-reading and re-parsing a YAML file on every API call (especially in the critical path like ext_authz via _build_standalone_policy) creates a massive performance bottleneck due to blocking file I/O and CPU-intensive parsing.
**Action:** Use an in-memory cache validated by the file's st_mtime to ensure the file is only read and parsed when it changes, drastically improving response times for cache misses.
