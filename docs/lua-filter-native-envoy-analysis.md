# Lua Filter → Native Envoy: Migration Analysis

Analysis of `configs/envoy/filter.lua` features and which can be replaced with native Envoy functionality.

## Features That CAN Be Replaced Natively

### 1. Rate Limiting (filter.lua lines 262-293)

**Current**: Per-domain token bucket rate limiter in Lua (`rpm / 60`, `burst_size`).

**Native replacement**: `envoy.filters.http.local_ratelimit`

Per-instance token bucket, configurable per route or virtual host. No external service needed.
Supports `token_bucket` with `tokens_per_fill`, `fill_interval`, and `max_tokens` — directly
equivalent to the Lua `rpm / 60` and `burst_size` logic. Can be set per-route, which maps
cleanly to per-domain enforcement via virtual hosts.

**Alternative**: `envoy.filters.http.ratelimit` delegates to an external rate limit service
(e.g., `envoyproxy/ratelimit`). Better for multi-instance deployments but adds a dependency.

---

### 2. Path Filtering (filter.lua lines 230-256)

**Current**: Lua checks request paths against an allowlist with exact and prefix matching.

**Native replacement**: Route configuration `match` rules

- Define explicit `match: { prefix: "/api/" }` or `match: { path: "/api/v1" }` routes
- Add a catch-all route with `direct_response: { status: 403 }` at the bottom of each virtual host

Already partially done in envoy-enhanced.yaml (e.g., PyPI POST/PUT blocking at lines 109-128).
Extending to full path allowlists per domain is straightforward route config.

---

### 3. Credential Injection — Static Case (filter.lua lines 360-365)

**Current**: Lua removes existing header, then adds credential header from policy.

**Native replacement**: `request_headers_to_add` and `request_headers_to_remove` in route config

Already used for `X-Source` on the GitHub route (envoy-enhanced.yaml line 93-96). For
credentials known at config generation time, this is a direct replacement.

---

### 4. Domain Rewriting / devbox.local (filter.lua lines 321-324)

**Current**: Lua sets `real_domain` from `policy.target_domain`.

**Native replacement**: `auto_host_rewrite: true` in route config

Already implemented in envoy-enhanced.yaml (lines 199, 213, 227, 241) for all devbox virtual
hosts. The Lua logic is redundant with the existing route config.

---

### 5. Tracking Headers (filter.lua lines 367-371)

**Current**: Lua adds `X-Credential-Injected`, `X-Rate-Limited`, `X-Real-Domain`, `X-Devbox-Timestamp`.

**Native replacement**:
- **Static headers**: `request_headers_to_add` per-route with known values
- **`X-Real-Domain`**: Set per-route with a static value matching the virtual host's upstream
- **`X-Devbox-Timestamp`**: Envoy supports `%START_TIME%` substitution in header values
- **`X-Credential-Injected`**: Set per-route (static "true" on routes with credentials, "false" otherwise)

---

### 6. Wildcard Domain Matching (filter.lua lines 104-123)

**Current**: Lua `match_domain_wildcard()` with `*.example.com` support.

**Native replacement**: Virtual host `domains` field

Envoy's virtual host `domains` already supports `*.example.com` wildcards natively.
Already used in envoy-enhanced.yaml (e.g., `*.huggingface.co` at line 143).

---

## Features That CANNOT Be Replaced Natively

### 7. DNS Tunneling Detection (filter.lua lines 54-88)

**Current**: Custom inspection logic:
- Subdomain label length > 63 chars
- Total hostname > 100 chars
- Subdomain depth > 6 levels
- Hex-encoded label detection (entropy heuristic)

**Why not native**: Envoy has no built-in filter for hostname structure analysis. Basic length
checks could use a header regex match in route config (reject `:authority` matching a long
pattern), but subdomain-depth counting and hex-label heuristics have no native equivalent.

**Options**: Keep in Lua, or move to an ext_authz service.

---

### 8. Dynamic Policy Lookup from Warden (filter.lua lines 126-224)

**Current**: HTTP call to warden (`/api/v1/domain-policies/for-domain`) with:
- 5-minute TTL cache
- 30-second failure backoff
- JSON response parsing
- Fallback deny policy on failure

**Why not native**: This is the dynamic glue that drives all per-domain decisions.

**Partial replacement**: `envoy.filters.http.ext_authz` is purpose-built for this pattern:
- Calls an external authorization service (warden)
- Can allow/deny the request
- Can inject headers (credentials) via response
- Can set dynamic metadata (for access log enrichment)

**Gaps**: The 5-minute caching and 30-second failure backoff would need to move to:
- Warden-side caching logic
- Envoy's ext_authz `failure_mode_allow` + circuit breaker settings

---

## Summary Table

| Feature | Lua Lines | Native Envoy Replacement | Fully Native? |
|---|---|---|---|
| Rate limiting | 262-293 | `local_ratelimit` filter | Yes |
| Path filtering | 230-256 | Route match config | Yes |
| Credential injection (static) | 360-365 | `request_headers_to_add/remove` | Yes |
| Credential injection (dynamic) | 360-365 | `ext_authz` filter | No (ext_authz) |
| Domain rewriting | 321-324 | `auto_host_rewrite` | Yes (already done) |
| Tracking headers | 367-371 | `request_headers_to_add` + `%START_TIME%` | Yes |
| Wildcard domain matching | 104-123 | Virtual host `domains` field | Yes (already done) |
| DNS tunneling detection | 54-88 | **No native equivalent** | No |
| Dynamic policy lookup + caching | 126-224 | `ext_authz` (partial) | No (ext_authz) |

## Recommendation

**Phase 1 — Move to native Envoy config (no new dependencies):**
- Rate limiting → `local_ratelimit` per virtual host
- Path filtering → route match rules with 403 catch-all
- Static credential injection → `request_headers_to_add/remove`
- Tracking headers → per-route `request_headers_to_add` with `%START_TIME%`

**Phase 2 — Replace dynamic Lua with ext_authz:**
- Warden becomes an ext_authz gRPC/HTTP service
- Dynamic credential injection via ext_authz response headers
- Policy caching moves to warden side

**Keep in Lua (or move to ext_authz):**
- DNS tunneling detection — too custom for native config
