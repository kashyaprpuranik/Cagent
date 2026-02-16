# Cagent Technical Review

## 1. Architecture Overview

### Strengths

- **Defense-in-depth is real, not marketing.** Network isolation (no default gateway, internal-only Docker network), DNS allowlisting (CoreDNS NXDOMAIN for unlisted domains), HTTP proxy enforcement (Envoy with Lua filter), container hardening (seccomp, gVisor, no-new-privileges), and credential injection at egress — each layer independently prevents a class of attack.
- **Credential injection via Envoy Lua filter is a strong design choice.** The agent never sees raw API keys. Credentials are decrypted and injected at the proxy, which means a compromised agent process cannot exfiltrate secrets from its own environment.
- **Multi-tenancy is well-scoped.** Tenant isolation is enforced at the database layer, the API layer (token scoping), and the log layer (per-tenant OpenObserve organizations). Agent tokens cannot access cross-tenant data.
- **Audit trail is comprehensive.** Terminal sessions, policy changes, token lifecycle, and agent commands are all logged with tenant attribution.
- **The standalone/connected duality is practical.** Single-developer usage (static `cagent.yaml`) and enterprise usage (centralized control plane with multi-tenancy) share the same data plane code.

### Weaknesses

- **Control plane WebSocket terminal relay is not yet wired up.** The control plane's `terminal.py:206-229` echoes input back as a placeholder for a paramiko SSH relay. However, terminal access works through two other paths: in standalone mode, the local admin provides a fully functional `docker exec`-based terminal over WebSocket; in connected mode, the STCP tunnel (FRP) provides direct SSH access. The control plane WebSocket is a convenience path for browser-based remote access that hasn't been completed yet.
- **Token verification cache is per-process only.** `auth.py` uses an in-memory dict with a 60-second TTL. Redis is already deployed and used for rate limiting, but the token cache hasn't been moved to it yet (there's a TODO). In a multi-worker deployment, disabling a token on one worker won't be visible to others until the cache expires. The `LayeredCache` infrastructure is now in place (used by the IP ACL cache); migrating the token cache is a follow-up that requires careful handling of the `last_used_at` batching logic.

---

## 2. Security Concerns

Known security concerns in the current codebase, organized by severity. Items already tracked in the [Roadmap](#7-product-roadmap) (mTLS, improved secret management, alert rules) are excluded.

### High

#### 2.1 No TLS certificate validation on Envoy upstream connections

Envoy upstream clusters configure TLS with SNI but do not set `validation_context` or `trusted_ca`. Without certificate verification, a network-level attacker who can intercept DNS or routing can MITM upstream API calls (GitHub, PyPI, OpenAI, Anthropic, etc.) and capture injected credentials.

- `data_plane/configs/envoy/envoy-enhanced.yaml:347-351` (github_api cluster, same pattern for all clusters through line 451)

**Recommendation:** Add `validation_context` with system CA bundle to each upstream `UpstreamTlsContext`.

#### 2.2 Unsalted SHA-256 for token hashing

Tokens are hashed with plain SHA-256 and no salt. If the token hash database is compromised, an attacker can use precomputed rainbow tables to recover token values. The same token always produces the same hash, making bulk attacks efficient.

- `control_plane/services/backend/control_plane/crypto.py:28-30`

**Recommendation:** Use a purpose-built key derivation function (bcrypt, scrypt, or Argon2id) with per-token salt.

#### 2.3 Auth tokens stored in localStorage

The frontend stores bearer tokens in `localStorage`, which is accessible to any JavaScript running on the same origin. A single XSS vulnerability would allow an attacker to exfiltrate the token silently.

- `control_plane/services/frontend/src/api/client.ts:75-85`

**Recommendation:** Use `httpOnly` secure cookies for token transport, or at minimum move to `sessionStorage`.

#### 2.4 Credentials passed via container environment variables

Credentials such as `STATIC_CREDENTIALS`, database passwords, and API tokens are injected as environment variables in Docker Compose. These are visible in `docker inspect`, `/proc/<pid>/environ`, and core dumps. Any container escape or debug access exposes them.

- `data_plane/docker-compose.yml:446-454` (email proxy secrets)
- `control_plane/docker-compose.yml:35,39` (DATABASE_URL, ENCRYPTION_KEY)
- Lua filter reads `STATIC_CREDENTIALS` at `data_plane/configs/envoy/filter.lua:37-44`

**Recommendation:** Use Docker secrets or a secrets manager (Vault, SOPS) instead of environment variables for production deployments.

#### 2.5 Docker socket mounted in data plane containers

Three services mount `/var/run/docker.sock` (read-only): log-shipper, agent-manager, and local-admin. Even read-only access allows full container enumeration and inspection, and is a well-documented privilege escalation vector. A compromised service on `infra-net` could inspect all containers, read their environment variables (including secrets), and potentially escape to the host.

- `data_plane/docker-compose.yml:313` (log-shipper)
- `data_plane/docker-compose.yml:378` (agent-manager)
- `data_plane/docker-compose.yml:415` (local-admin)

**Recommendation:** Use the Docker API over TCP with TLS client certs and restricted permissions, or use a socket proxy that filters allowed API calls.

### Medium

#### 2.6 Tunnel client bridges agent-net and infra-net

When the `ssh` profile is active, the FRP tunnel client is attached to both `agent-net` (10.200.1.30) and `infra-net` (10.200.2.30). A compromised tunnel client could route traffic between the isolated agent network and the infrastructure network, breaking the core isolation boundary.

- `data_plane/docker-compose.yml:500-507`

**Recommendation:** Remove the tunnel client from `agent-net` and proxy SSH access through a dedicated service on `infra-net` only.

#### 2.7 Permissive seccomp profile defeats sandboxing — Mitigated

The `permissive.json` seccomp profile uses `SCMP_ACT_ALLOW` as the default action, only blocking raw sockets. This effectively disables seccomp and allows the agent container to invoke arbitrary syscalls including those needed for container escape (ptrace, mount, unshare, setns).

- `data_plane/configs/seccomp/profiles/permissive.json`

**Status**: Mitigated. The profile is retained for debugging but is now gated behind warnings at every layer: the JSON file itself contains a prominent security warning, the agent-manager logs a WARNING when applying it, both UIs show yellow alert banners when permissive is selected, `cagent.yaml` defaults to `standard` and labels permissive as "debug only", and `docker-compose.yml` does not reference the permissive profile.

#### 2.8 gVisor standard profile disables host seccomp

When running under gVisor (`standard` profile), the agent container sets `seccomp:unconfined`, relying entirely on gVisor's user-space syscall interception. If a gVisor sandbox escape occurs, no host seccomp profile exists as a fallback layer.

- `data_plane/docker-compose.yml:154`

**Recommendation:** Apply a host-level seccomp profile alongside gVisor to provide defense-in-depth.

#### 2.9 In-memory Lua rate limiting resets on Envoy restart

The Lua filter's token-bucket rate limiter stores all state in the Lua VM's memory. An Envoy restart (crash, config reload, deployment) resets all rate limit windows, allowing a burst of previously-limited requests. Note: this is a data-plane-specific concern — the control plane's rate limiter (`slowapi`) already supports Redis-backed storage.

- `data_plane/configs/envoy/filter.lua:13` (token_buckets table)
- `data_plane/configs/envoy/filter.lua:390-420` (rate limit function)

**Recommendation:** Back rate limit state with Redis or Envoy's built-in `envoy.filters.http.ratelimit` service with an external rate limit server.

#### 2.10 No credential or key rotation mechanism

There is no tooling or process for rotating the Fernet `ENCRYPTION_KEY`, API tokens, database credentials, or FRP tunnel secrets. A compromised key requires manual intervention across all services.

- `control_plane/services/backend/control_plane/crypto.py:9` (ENCRYPTION_KEY loaded once at startup)

**Recommendation:** Implement key rotation support (dual-key decryption during transition) and document a rotation runbook.

### Low

#### 2.11 WebSocket ticket passed as query parameter

Terminal access tickets are sent as a `?ticket=` query parameter during the WebSocket handshake. Query parameters may appear in access logs, load balancer logs, and HTTP `Referer` headers. The ticket is single-use and expires in 60 seconds, which limits the exposure window.

- `control_plane/services/backend/control_plane/routes/terminal.py:125`

**Recommendation:** Document the log-scrubbing requirement for any reverse proxy in front of the backend. Consider a two-step upgrade where the ticket is sent in the first WebSocket message instead.

#### 2.12 DNS tunneling detection is heuristic-only

The Lua filter detects DNS tunneling via label length, hostname length, subdomain depth, and hex-pattern heuristics. These can be evaded with short labels, mixed encoding, or slow exfiltration over many queries.

- `data_plane/configs/envoy/filter.lua:136-170`

**Recommendation:** Supplement heuristics with per-domain query volume anomaly detection and consider integrating a dedicated DNS analytics tool.

---

## 3. Scalability & Reliability

### Executive Summary

The system is well-architected for small deployments (10–50 agents) but faces structural constraints beyond ~100 agents. The most severe issues are single points of failure in the data plane networking layer, unbounded in-memory state, and polling-based synchronization that degrades linearly with agent count.

### 3.1 Control Plane Bottlenecks

#### 3.1.1 Token Cache (CRITICAL) — Resolved

**Location**: `control_plane/services/backend/control_plane/cache.py`, `auth.py`

Previously a per-worker Python dict with no shared invalidation across workers. Token revocation was invisible to other workers until TTL expired.

**Status**: **Resolved.** Now uses `LayeredCache` with memory (60s) and Redis (60s) layers. Invalidation on token delete/disable clears both layers across all workers. `last_used_at` writes are coalesced via `ThrottledWriter` (once per 10 minutes per token).

#### 3.1.2 IP ACL Verification (HIGH) — Resolved

**Location**: `control_plane/services/backend/control_plane/auth.py`

Previously fetched ALL ACLs for the tenant from DB on every admin request, then looped through in Python for CIDR matching. No composite index on `(tenant_id, enabled)`.

**Status**: **Resolved.** Now uses `LayeredCache` with memory (60s TTL) and Redis (300s TTL) layers, falling back to DB on miss. Invalidation on ACL create/update/delete clears both layers.

#### 3.1.3 Synchronous Last-Used Token Updates (MEDIUM) — Partially Resolved

Token `last_used_at` DB writes are now coalesced via `ThrottledWriter` (at most once per 10 minutes per token), reducing bookkeeping traffic significantly. Writes are still synchronous and inline with request processing.

**Recommendation**: For further optimization, move remaining writes to an async background batch job.

#### 3.1.4 In-Memory Rate Limiter (MEDIUM)

Falls back to in-memory storage when Redis URL is not configured. In-memory rate limiting does not work across multiple workers — requests can exceed limits by a factor equal to the worker count. Already supports Redis when configured.

**Recommendation**: Require Redis for rate limiting in production deployments.

#### 3.1.5 OpenObserve Integration Fragility (MEDIUM)

No retry logic on OpenObserve HTTP calls — transient failures return 502 immediately. Single shared HTTP client with 100-connection limit. No circuit breaker. 15-second timeout may be too short for large log queries.

**Recommendation**: Add exponential backoff retry (3 attempts). Implement circuit breaker pattern. Increase connection pool to 200+.

#### 3.1.6 Heartbeat Flush Inefficiency (MEDIUM)

Background task runs every 60s: scans ALL Redis heartbeat keys (O(N) SCAN), then issues individual UPDATE queries per agent. With 10,000 agents, this produces 10,000 UPDATE queries every 60 seconds.

**Recommendation**: Use batch UPDATE with VALUES clause. Implement incremental SCAN with cursor.

#### 3.1.7 Audit Trail Unbounded Growth (MEDIUM)

The `AuditTrail` table has a TEXT `details` column with no retention policy. Search queries use `.contains()` which requires full table scans on text fields.

**Recommendation**: Implement TTL-based cleanup (e.g., 90-day retention). Add GIN index on searchable fields for PostgreSQL.

#### 3.1.8 No Resource Limits on CP Services (HIGH)

Only OpenObserve has explicit resource limits in `control_plane/docker-compose.yml`. PostgreSQL and backend can consume all host resources under load.

**Recommendation**: Add `deploy.resources.limits` to all services.

### 3.2 Data Plane Bottlenecks

#### 3.2.1 Single Envoy Proxy — Static IP (CRITICAL)

Envoy runs as a single container with hardcoded static IP `10.200.1.10`. All agent traffic flows through this single proxy. No failover, no horizontal scaling.

**Recommendation**: Implement L4 load balancer in front of replicated Envoy instances. Remove static IP dependency.

#### 3.2.2 Single CoreDNS Instance — Static IP (CRITICAL)

CoreDNS runs as a single container with static IP `10.200.1.5`. All agent DNS queries depend on this single instance. No health check is configured.

**Recommendation**: Deploy redundant CoreDNS instances behind DNS round-robin or an L4 LB.

#### 3.2.3 Heartbeat Worker Limit (CRITICAL)

At most 20 concurrent heartbeat threads. With 1000 agents and a 30-second heartbeat interval, commands take 25+ minutes to reach all agents.

**Recommendation**: Increase default workers. Implement async I/O instead of thread pool. Add priority queue for pending commands.

#### 3.2.4 Unbounded Lua Filter State (CRITICAL)

The Envoy Lua filter maintains in-memory state (token buckets for rate limiting) with no eviction. Memory leak — Envoy OOM crash after sustained operation with diverse domain access patterns.

**Recommendation**: Add periodic eviction of stale entries. Cap table size with LRU eviction.

#### 3.2.5 Full Config Regeneration on Every Change (HIGH)

Config regeneration rewrites the entire CoreDNS Corefile and Envoy configuration even when a single domain is added. Hash comparison prevents unnecessary service restarts, but the generation work still occurs every 5 minutes.

**Recommendation**: Implement incremental config updates. Use Envoy xDS API for dynamic configuration.

#### 3.2.6 Blocking Docker Stats Collection (HIGH)

Each `container.stats()` call is a synchronous blocking Docker API call (~100ms). With 1000 agents, stats collection takes ~100 seconds.

**Recommendation**: Use async Docker API. Sample stats rather than collecting from all containers every cycle.

#### 3.2.7 Container Recreation for Seccomp Updates (HIGH)

Security profile changes require full container stop/remove/create. No blue-green deployment — agent experiences 10–30 seconds of downtime.

**Recommendation**: Implement blue-green container replacement.

#### 3.2.8 No Per-Agent Rate Limiting (HIGH)

Rate limits are per-domain, shared across all agents. A single agent can consume the entire rate limit quota, starving others.

**Recommendation**: Implement per-agent token buckets in the Lua filter.

#### 3.2.9 Lua Wildcard Matching O(n) (MEDIUM)

Wildcard domain matching scans the entire domain table linearly on every HTTP request.

**Recommendation**: Pre-compile wildcard patterns into a trie structure or use binary search on suffix.

#### 3.2.10 CP API Call Per Request in Connected Mode (MEDIUM)

In connected mode, the Lua filter can make a control plane API call on every proxied request with a 5-second timeout.

**Recommendation**: Batch CP lookups. Cache results locally with short TTL. Use async non-blocking calls.

#### 3.2.11 Vector Log Rate Limiting (MEDIUM)

Vector batches 200 events per request but is rate-limited to 500 requests/min. At 10,000 log events/sec, logs queue up and may be lost. Backup file sink has no rotation policy.

**Recommendation**: Increase rate limit or batch size. Add log rotation to backup sink.

#### 3.2.12 Network Subnet Limits (MEDIUM)

Both `agent-net` and `infra-net` use /24 subnets (254 usable IPs). Practical limit ~250 agents per data plane.

**Recommendation**: Expand to /22 or /21 subnets for larger deployments.

### 3.3 Cross-Cutting Concerns

#### Polling-Based Architecture

The entire system relies on polling for state synchronization:

| Component | Interval | Impact at 1000 Agents |
|-----------|----------|----------------------|
| Heartbeat (agent→CP) | 30s | 2000 heartbeats/min to CP |
| Config sync (DP→CP) | 300s | 5-min latency on policy changes |
| Docker container discovery | 30s | Full container list every cycle |
| Redis heartbeat flush (CP) | 60s | 10,000 UPDATE queries per flush |

**Recommendation**: Move to event-driven architecture (webhooks, SSE, or message queue) for config changes. Keep polling only as fallback.

#### No Horizontal Scaling Path

| Component | Current | Blocker |
|-----------|---------|---------|
| CP Backend | Single instance | No session affinity or shared cache |
| Envoy Proxy | Single instance | Static IP, no LB |
| CoreDNS | Single instance | Static IP, no replication |
| Agent Manager | Single instance | Docker socket coupling |
| Log Shipper | Single instance | No clustering |

#### Missing Health Checks

Services without health checks: dns-filter (CoreDNS), agent containers, local-admin, agent-manager, tunnel-client, log-store (OpenObserve), frontend, tunnel-server.

### 3.4 Priority Remediation Matrix

#### P0 — Service Availability Risk

| Issue | Effort |
|-------|--------|
| Single Envoy proxy (SPOF) | High |
| Single CoreDNS instance (SPOF) | High |
| Unbounded Lua filter memory | Medium |
| Token cache not shared across workers | Medium |
| No CP service resource limits | Low |
| Heartbeat worker limit (20) | Low |

#### P1 — Performance Degradation at Scale

| Issue | Effort | Status |
|-------|--------|--------|
| IP ACL loaded on every request | Medium | **Resolved** (LayeredCache) |
| Domain policy full table load | Medium | Open |
| Blocking Docker stats() calls | Medium | Open |
| Full config regeneration | High | Open |
| Container recreation for seccomp | High | Open |
| No per-agent rate limiting | High | Open |

#### P2 — Operational Risk Over Time

| Issue | Effort | Status |
|-------|--------|--------|
| In-memory rate limiter fallback | Low | Open |
| Vector log rate limiting | Low | Open |
| Synchronous token last-used writes | Medium | Open |
| OpenObserve no retry/circuit breaker | Medium | Open |
| Heartbeat flush inefficiency | Medium | Open |
| Audit trail unbounded growth | Medium | Open |
| Network subnet limits (/24) | Medium | Open |
| Missing health checks (8 services) | Medium | Open |
| Lua wildcard O(n) matching | Medium | Open |

### 3.5 Scaling Thresholds

| Metric | Current Limit | Bottleneck |
|--------|--------------|------------|
| Concurrent agents per DP | ~250 | /24 subnet exhaustion |
| Agents in connected mode | ~100 | Heartbeat worker limit (20 threads) |
| Requests/sec to CP | ~500 (configurable) | DB connection pool (tunable via `DB_POOL_SIZE`) |
| Domain policies per tenant | ~1000 | Full table load into memory |
| Concurrent Envoy connections | ~1000 | Global circuit breaker threshold |
| Log events/sec shipped | ~1600 | Vector rate limit (500 req/min × 200 batch) |
| Unique tokens in 60s window | ~10,000 | In-memory cache memory pressure |
| Days of continuous operation | ~7-14 | Lua filter memory leak (token_buckets) |

---

## 4. Container Hardening Plan

**Status: Planned (not yet implemented)**

### Overview

Add container-level hardening controls to security profiles, beyond the existing seccomp syscall filtering. These controls restrict filesystem access, privilege escalation, and available tooling inside agent containers.

### Design: Hardening Tier with Individual Overrides (Hybrid)

A `hardening_tier` field acts as a **preset** that pre-fills individual fields. Users can override any field, switching the tier to `custom`.

#### Tier Definitions

| Tier | Seccomp | Sudo | Root FS | tmpfs | Image |
|------|---------|------|---------|-------|-------|
| `permissive` | permissive | allowed | read-write | exec | full |
| `standard` | standard | allowed | read-write | exec | full |
| `hardened` | hardened | disabled | read-only | noexec | full |
| `locked` | hardened | disabled | read-only | noexec | minimal |
| `custom` | (any) | (any) | (any) | (any) | (any) |

#### New SecurityProfile Fields

```
hardening_tier:   permissive | standard | hardened | locked | custom
seccomp_profile:  standard | hardened | permissive           (existing)
disable_sudo:     bool                                       (new)
read_only_rootfs: bool                                       (new)
noexec_tmpfs:     bool                                       (new)
image_tier:       full | standard | minimal | locked         (new)
```

#### UI Behavior

- Profile creation/edit modal: tier dropdown at the top
- Selecting a tier pre-fills all individual fields
- Expandable "Advanced" section shows individual fields
- Changing any individual field switches dropdown to "Custom"
- Existing profiles get `hardening_tier = custom` (migration-safe)

### Individual Controls

#### disable_sudo (bool)

Prevents privilege escalation inside the container. When `true`: removes sudoers entry or mounts `/etc/sudoers.d` as empty read-only. Prevents `sudo apt install`, `sudo iptables`, etc.

#### read_only_rootfs (bool)

Makes the container's root filesystem read-only via Docker's `ReadonlyRootfs` flag. Prevents modification of system binaries, configs, cron dirs. Writable paths: `/workspace` (Docker volume), `/tmp` and `/var/tmp` (tmpfs). **Requires container restart** (not hot-updatable like CPU/memory).

#### noexec_tmpfs (bool)

Mounts `/tmp` and `/var/tmp` with `noexec` flag. Prevents execution of downloaded binaries in temp directories. Agent can still write files, just not execute them. Bypass: interpreted scripts (`python3 script.py`) still work — this is defense-in-depth.

#### image_tier (enum)

Controls which tools are available in the agent container image.

| Tier | Included | Excluded |
|------|----------|----------|
| `full` | Everything (current default) | Nothing |
| `standard` | python, node, git, vim | curl, wget, nc, build-essential, sudo |
| `minimal` | python, node | git, vim, curl, wget, nc, sudo, build-essential, go, rust |
| `locked` | python only | Everything else |

Requires building multiple image variants (can share base layers). Agent manager selects image based on this field. **Requires container recreation** (not hot-updatable).

### Implementation Notes

**Backend**: Add new columns to `SecurityProfile` model (with defaults for migration). Add `HardeningTier`, `ImageTier` enums. Handle tier preset logic in routes. Include new fields in heartbeat response.

**Agent Manager**: Apply `disable_sudo`, `read_only_rootfs`, `noexec_tmpfs` during container recreation. Extend existing container recreation logic. Select Docker image tag from `image_tier`.

**Frontend**: Add tier dropdown + advanced section to profile modal. Show hardening tier column in profile table.

**Image Build**: Add build stages/targets for each image tier in `agent.Dockerfile`. Build and tag all tier variants in CI.

### Enforcement Layers (Defense in Depth)

1. **Kernel** — Seccomp syscall filtering (existing)
2. **Container** — Read-only rootfs, noexec tmpfs, no sudo (new)
3. **Image** — Reduced toolset (new)
4. **Network** — DNS + HTTP proxy filtering (existing)
5. **gVisor** — User-space syscall interception (existing, optional)

### Other Policy Categories Considered (Future)

- Filesystem policies: Disk quotas, writable path allowlists, file type restrictions
- Time/session policies: Max session duration, idle timeout, scheduled windows
- DLP (Data Loss Prevention): Regex scanning of outbound request bodies
- Cost/budget policies: LLM API token tracking, budget ceilings
- Command execution policies: AppArmor profiles, restricted shell
- Outbound connection policies: Protocol allowlists, connection limits
- Package/dependency policies: Package name allowlists, vulnerability gates
- Secrets access policies: Per-agent secret visibility, usage logging
- Git/VCS policies: Repo allowlists, branch restrictions
- Inter-agent policies: Agent-to-agent communication rules

---

## 5. Observability Gaps

This section covers what Cagent shows its users (tenant admins, agent developers) about agent behavior — not infrastructure monitoring of Cagent itself.

### What Users Can See Today

| Capability | Where | Quality |
|-----------|-------|---------|
| Which domains the agent accessed | Logs & Traffic dashboard (top domains widget) | Good, but computed from live logs only — no historical aggregation |
| Request success/failure counts | Traffic stats (2xx/3xx/4xx/5xx counters) | Basic counts, no time-series |
| Average latency | Traffic stats dashboard | Average only — no p50/p95/p99 percentiles |
| Blocked requests (403) | "Blocked" counter + searchable in logs | Visible, but no explanation of *why* it was blocked |
| Rate-limited requests (429) | "Rate Limited" counter + searchable in logs | Visible after the fact |
| DNS resolution attempts | CoreDNS logs (source=coredns) | Raw log lines, not surfaced prominently |
| Agent status (online, CPU, memory) | Dashboard page, heartbeat API | Good real-time view |
| Administrative actions | Audit trail page | Comprehensive for compliance |

### What Users Cannot See

1. **No rate limit consumption gauge.** Domain policies define `requests_per_minute` and `burst_size`, but there is no indicator showing "you're at 80% of your limit for api.openai.com." Users discover they've hit a rate limit only when requests start returning 429.

2. **No credential usage tracking.** Envoy logs include a `credential_injected` flag per request, but there is no aggregated view showing "your GitHub API key was used 200 times today."

3. **No "why was this blocked?" explanation.** When a request fails, the agent sees a status code (403, 429, NXDOMAIN) but no structured reason. A developer debugging a failing agent cannot easily distinguish DNS-level block, path restriction, rate limit, credential injection failure, or upstream error.

4. **No agent activity timeline.** There is no waterfall or sequence view showing "the agent made these requests in this order during this task." Logs are a flat, searchable list.

5. **No alerting or notifications.** No webhooks, email alerts, or in-app notifications for notable events (blocked domain access, rate limit saturation, agent offline, credential usage spikes).

6. **No historical trends.** Traffic stats are computed in-memory from recent logs. No persistent time-series for capacity questions or behavioral drift detection.

---

## 6. Usability Friction

### Onboarding

- **First-run experience requires 5+ manual steps.** Generate encryption key, copy `.env.example`, run `dev_up.sh`, wait for health checks, then manually create domain policies.
- **No `cagent init` CLI.** Users must manually edit YAML and docker-compose files.
- **Agent variant selection is opaque.** `AGENT_VARIANT=lean|dev|ml` controls the base image but there is no documentation of what tools each variant includes.

### Day-to-Day Configuration

- **No configuration validation.** `cagent.yaml` is parsed with `yaml.safe_load()` but there is no schema validation. Typos silently produce broken configs.
- **Config changes require container restarts.** ~10-second wait-and-check cycle every time.
- **No diff preview for policy changes.** Accidental removal of a critical domain takes effect instantly with no confirmation.

### Agent Developer Experience

- **No way for agents to introspect their own permissions.** Developers discover permission gaps at runtime when requests fail.
- **Email proxy is undiscoverable.** No user-facing documentation on how to configure OAuth credentials, set up recipient allowlists, or verify email delivery.

### Control Plane UI Polish

- **Login error conflates two causes.** Invalid token and unreachable API both show "Invalid token or API unreachable."
- **No expiring-soon indicator for tokens.** Approaching expiry is invisible until authentication starts failing.
- **`burst_size` is unexplained** in the rate limiting form.
- **No unsaved-changes warning.** Navigating away from a partially-filled form silently discards input.
- **Inconsistent pagination.** Audit Trail has pagination; Tokens, Domain Policies, and Tenants do not.
- **No "last modified by" on policies.** Users must cross-reference the audit trail.

---

## 7. Product Roadmap

### Phase 1: Product Observability

| Priority | Item | Rationale |
|----------|------|-----------|
| P1 | Deny-reason header on blocked requests | Developers can instantly see *why* a request failed |
| P1 | Rate limit consumption gauge per domain | Show "X of Y requests used this minute" |
| P1 | Credential usage counters per domain policy | Surface "this credential was used N times today" |
| P2 | Agent activity timeline / session view | Chronological waterfall of requests per agent run |
| P2 | Historical traffic trends (per-domain time-series) | Answer "is usage going up or down?" |
| P2 | Webhook/alerting for notable events | Notify admins on blocked access, rate limit saturation, agent offline |

### Phase 2: Usability

| Priority | Item | Rationale |
|----------|------|-----------|
| P1 | Config validation with clear error messages | Catch `cagent.yaml` typos at save-time |
| P2 | `cagent init` CLI wizard | Guided setup instead of manual YAML editing |
| P2 | Policy diff preview (dry-run mode) | "Here's what will change" before applying |
| P2 | Agent introspection SDK / CLI | Let agents ask "can I reach X?" |
| P2 | Hot-reload for CoreDNS/Envoy configs | Eliminate restart-and-wait cycle |
| P2 | Distinguish login error causes | "Invalid token" vs "API unreachable" |
| P2 | Token expiry warnings | Highlight tokens expiring within 7 days |
| P3 | Pagination on all list views | Tokens, policies, and tenants don't paginate |
| P3 | Email proxy documentation and setup wizard | The feature exists but is undiscoverable |
| P3 | Agent variant documentation | Clarify what lean/dev/ml include |

### Phase 3: Scale & Enterprise

| Priority | Item | Rationale |
|----------|------|-----------|
| P3 | Encryption key rotation mechanism | Currently a single static Fernet key |
| P3 | Vault/AWS Secrets Manager integration | Enterprise secret management |
| P3 | Policy-as-code (GitOps) | Version-controlled domain policies with PR approval |
| P4 | Kubernetes operator | Deploy data planes as K8s pods with CRDs |
| P4 | SSO/OIDC integration for the admin console | Enterprise identity management |
