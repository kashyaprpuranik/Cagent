# Security Concerns

Known security concerns in the current codebase, organized by severity. Items already tracked in the [Roadmap](../README.md#roadmap) (mTLS, persistent egress tracking, improved secret management, alert rules, per-path rate limits) are excluded.

---

## High

### 1. No TLS certificate validation on Envoy upstream connections

Envoy upstream clusters configure TLS with SNI but do not set `validation_context` or `trusted_ca`. Without certificate verification, a network-level attacker who can intercept DNS or routing can MITM upstream API calls (GitHub, PyPI, OpenAI, Anthropic, etc.) and capture injected credentials.

- `data_plane/configs/envoy/envoy-enhanced.yaml:347-351` (github_api cluster, same pattern for all clusters through line 451)

**Recommendation:** Add `validation_context` with system CA bundle to each upstream `UpstreamTlsContext`.

### 2. Tap filter logs request and response bodies including injected credentials

The Envoy tap filter matches all requests (`any_match: true`) and writes up to 10KB of request and response bodies to disk. Since the Lua filter injects credentials into request headers before the request is forwarded, the tap sink captures those credentials in plaintext on disk.

- `data_plane/configs/envoy/envoy-enhanced.yaml:261-274`

**Recommendation:** Disable the tap filter in production, or restrict it to specific domains/paths and redact authorization headers from tap output.

### 3. Unsalted SHA-256 for token hashing

Tokens are hashed with plain SHA-256 and no salt. If the token hash database is compromised, an attacker can use precomputed rainbow tables to recover token values. The same token always produces the same hash, making bulk attacks efficient.

- `control_plane/services/backend/control_plane/crypto.py:28-30`

**Recommendation:** Use a purpose-built key derivation function (bcrypt, scrypt, or Argon2id) with per-token salt.

### 4. Auth tokens stored in localStorage

The frontend stores bearer tokens in `localStorage`, which is accessible to any JavaScript running on the same origin. A single XSS vulnerability would allow an attacker to exfiltrate the token silently. No Content Security Policy header is set to mitigate injection.

- `control_plane/services/frontend/src/api/client.ts:75-85`

**Recommendation:** Use `httpOnly` secure cookies for token transport, or at minimum add a strict CSP header and move to `sessionStorage`.

### 5. Credentials passed via container environment variables

Credentials such as `STATIC_CREDENTIALS`, database passwords, and API tokens are injected as environment variables in Docker Compose. These are visible in `docker inspect`, `/proc/<pid>/environ`, and core dumps. Any container escape or debug access exposes them.

- `data_plane/docker-compose.yml:446-454` (email proxy secrets)
- `control_plane/docker-compose.yml:35,39` (DATABASE_URL, ENCRYPTION_KEY)
- Lua filter reads `STATIC_CREDENTIALS` at `data_plane/configs/envoy/filter.lua:37-44`

**Recommendation:** Use Docker secrets or a secrets manager (Vault, SOPS) instead of environment variables for production deployments.

### 6. Docker socket mounted in data plane containers

Three services mount `/var/run/docker.sock` (read-only): log-shipper, agent-manager, and local-admin. Even read-only access allows full container enumeration and inspection, and is a well-documented privilege escalation vector. A compromised service on `infra-net` could inspect all containers, read their environment variables (including secrets), and potentially escape to the host.

- `data_plane/docker-compose.yml:313` (log-shipper)
- `data_plane/docker-compose.yml:378` (agent-manager)
- `data_plane/docker-compose.yml:415` (local-admin)

**Recommendation:** Use the Docker API over TCP with TLS client certs and restricted permissions, or use a socket proxy that filters allowed API calls.

---

## Medium

### 7. Tunnel client bridges agent-net and infra-net

When the `ssh` profile is active, the FRP tunnel client is attached to both `agent-net` (10.200.1.30) and `infra-net` (10.200.2.30). A compromised tunnel client could route traffic between the isolated agent network and the infrastructure network, breaking the core isolation boundary.

- `data_plane/docker-compose.yml:500-507`

**Recommendation:** Remove the tunnel client from `agent-net` and proxy SSH access through a dedicated service on `infra-net` only.

### 8. Permissive seccomp profile defeats sandboxing

The `permissive.json` seccomp profile uses `SCMP_ACT_ALLOW` as the default action, only blocking raw sockets. This effectively disables seccomp and allows the agent container to invoke arbitrary syscalls including those needed for container escape (ptrace, mount, unshare, setns).

- `data_plane/configs/seccomp/profiles/permissive.json`

**Recommendation:** Remove the permissive profile entirely, or gate it behind a prominent warning and never reference it from default compose configurations.

### 9. gVisor standard profile disables host seccomp

When running under gVisor (`standard` profile), the agent container sets `seccomp:unconfined`, relying entirely on gVisor's user-space syscall interception. If a gVisor sandbox escape occurs, no host seccomp profile exists as a fallback layer.

- `data_plane/docker-compose.yml:154`

**Recommendation:** Apply a host-level seccomp profile alongside gVisor to provide defense-in-depth.

### 10. gVisor debug logging enabled

The gVisor runtime config has `debug = true`, which logs detailed syscall traces and sandbox events to `/var/log/runsc/`. These logs may contain file paths, environment variable contents, and network details that could aid an attacker with filesystem access.

- `data_plane/configs/gvisor/runsc.toml:22-23`

**Recommendation:** Disable debug logging in production (`debug = false`). Use conditional enablement via a separate config file for troubleshooting.

### 11. Missing security headers

The FastAPI backend does not set `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`, or `Strict-Transport-Security` headers. The admin UI is vulnerable to clickjacking and MIME-sniffing attacks.

- `control_plane/services/backend/control_plane/app.py` (no security header middleware registered)

**Recommendation:** Add a middleware that sets `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Strict-Transport-Security`, and a restrictive `Content-Security-Policy`.

### 12. CORS allows all methods and headers with credentials

When `CORS_ORIGINS` is set, the middleware permits all HTTP methods and all headers while also allowing credentials. This increases the attack surface if an allowed origin is compromised.

- `control_plane/services/backend/control_plane/app.py:52-59`

**Recommendation:** Explicitly list the required methods (`GET, POST, PUT, DELETE, OPTIONS`) and headers (`Authorization, Content-Type`) instead of using wildcards.

### 13. Token cache allows 60-second revocation delay

The in-memory token cache has a 60-second TTL. A revoked or deleted token continues to authenticate successfully for up to 60 seconds. In a multi-worker deployment without shared Redis, each worker maintains its own cache.

- `control_plane/services/backend/control_plane/auth.py:27-28`

**Recommendation:** Implement immediate cache invalidation on token deletion/revocation via Redis pub/sub or a short-circuit check.

### 14. In-memory Lua rate limiting resets on Envoy restart

The Lua filter's token-bucket rate limiter stores all state in the Lua VM's memory. An Envoy restart (crash, config reload, deployment) resets all rate limit windows, allowing a burst of previously-limited requests.

- `data_plane/configs/envoy/filter.lua:13` (token_buckets table)
- `data_plane/configs/envoy/filter.lua:390-420` (rate limit function)

**Recommendation:** Back rate limit state with Redis or Envoy's built-in `envoy.filters.http.ratelimit` service with an external rate limit server.

### 15. No credential or key rotation mechanism

There is no tooling or process for rotating the Fernet `ENCRYPTION_KEY`, API tokens, database credentials, or FRP tunnel secrets. A compromised key requires manual intervention across all services.

- `control_plane/services/backend/control_plane/crypto.py:9` (ENCRYPTION_KEY loaded once at startup)

**Recommendation:** Implement key rotation support (dual-key decryption during transition) and document a rotation runbook.

### 16. X-Forwarded-For header spoofing risk

IP ACL verification uses `get_remote_address()` which respects `X-Forwarded-For`. If the backend is exposed without a trusted reverse proxy that sanitizes this header, clients can spoof their IP address to bypass tenant IP ACL restrictions.

- `control_plane/services/backend/control_plane/auth.py:298-299`

**Recommendation:** Configure a trusted proxy depth or validate `X-Forwarded-For` against a list of known proxy IPs. Reject requests with unexpected forwarded headers when no reverse proxy is configured.

---

## Low

### 17. WebSocket ticket passed as query parameter

Terminal access tickets are sent as a `?ticket=` query parameter during the WebSocket handshake. Query parameters may appear in access logs, load balancer logs, and HTTP `Referer` headers. The ticket is single-use and expires in 60 seconds, which limits the exposure window.

- `control_plane/services/backend/control_plane/routes/terminal.py:125`

**Recommendation:** Document the log-scrubbing requirement for any reverse proxy in front of the backend. Consider a two-step upgrade where the ticket is sent in the first WebSocket message instead.

### 18. DNS tunneling detection is heuristic-only

The Lua filter detects DNS tunneling via label length, hostname length, subdomain depth, and hex-pattern heuristics. These can be evaded with short labels, mixed encoding, or slow exfiltration over many queries.

- `data_plane/configs/envoy/filter.lua:136-170`

**Recommendation:** Supplement heuristics with per-domain query volume anomaly detection and consider integrating a dedicated DNS analytics tool.
