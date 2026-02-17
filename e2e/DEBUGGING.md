# E2E Test Debugging Guide

Practical reference for debugging failures in `e2e/test_cp_dp_e2e.py` (CP+DP integration) and `data_plane/tests/test_e2e.py` (DP standalone).

## Retaining Containers After Failure

```bash
# CP+DP e2e: keep everything running for inspection
./e2e/run_tests.sh --no-teardown

# DP standalone: containers are only torn down if the script started them.
# If they were already running, they stay up after failure.
```

Manual cleanup after `--no-teardown`:
```bash
cd data_plane && docker compose --profile dev --profile managed --profile auditing down
cd control_plane && docker compose down -v
docker rm -f openobserve-mock echo-server 2>/dev/null
docker network rm e2e-bridge 2>/dev/null
# Restore config files modified at runtime
cd data_plane
mv configs/.cagent.yaml.bak configs/cagent.yaml 2>/dev/null || true
mv configs/coredns/.Corefile.bak configs/coredns/Corefile 2>/dev/null || true
```

## Inspecting Logs

### Envoy (HTTP Proxy) — most useful for request debugging
```bash
docker logs http-proxy --tail 50            # Recent logs
docker logs http-proxy --since 5m           # Last 5 minutes
docker logs -f http-proxy                   # Follow live

# Parse JSON access logs (domain, path, status)
docker logs http-proxy 2>/dev/null | python3 -c "
import json, sys
for line in sys.stdin:
    try:
        e = json.loads(line)
        if 'authority' in e:
            print(f\"{e['authority']} {e.get('path','')} -> {e.get('response_code','')} cred={e.get('credential_injected','')}\")
    except: pass
" | tail -20
```

### Other services
```bash
docker logs agent-manager --tail 30   # Config generation, CP polling
docker logs dns-filter --tail 30      # DNS queries and blocks
docker logs log-shipper --tail 30     # Log ingestion pipeline
docker logs agent-manager --tail 30   # Agent manager API + admin endpoints
docker logs backend --tail 30         # CP API (auth, policies, heartbeats)
```

## Network Topology

```
agent-net (10.200.1.0/24, internal — no external access)
├── agent containers  10.200.1.20+  (can only reach dns-filter and http-proxy)
├── dns-filter        10.200.1.5
└── http-proxy        10.200.1.10

infra-net (10.200.2.0/24 — can reach CP and external)
├── dns-filter        10.200.2.5
├── http-proxy        10.200.2.10
├── agent-manager     10.200.2.20+
├── log-shipper       10.200.2.30+
└── (agent-manager serves admin API on infra-net)

e2e-bridge (created by e2e/run_tests.sh for CP+DP tests)
└── Connects agent-manager, log-shipper, http-proxy to CP backend
```

## Container Discovery

Agent containers are discovered by Docker label, not name:
```bash
# Find all agents
docker ps --filter "label=cagent.role=agent" --format "{{.Names}}"

# Scaled agents get names like data_plane-agent-dev-1, data_plane-agent-dev-2
# The cagent.role=agent label is the reliable way to find them
```

## Common Failures

### Proxy not reachable from agent

**Symptom**: `nc -z 10.200.1.10 8443` times out, tests get `subprocess.TimeoutExpired`.

**Debug**:
```bash
# Is Envoy running?
docker ps --filter name=http-proxy --format "{{.Status}}"

# Check Envoy config is valid
docker exec http-proxy cat /etc/envoy/envoy.yaml | head -20

# agent-manager generates the config; check its logs
docker logs agent-manager | tail -30

# Common root cause: CONTROL_PLANE_URL is empty in standalone mode,
# producing an invalid Envoy config. Check config_generator.py handles
# empty env vars with `or "http://backend:8000"`.
```

### DNS resolution fails (NXDOMAIN)

**Symptom**: Curl from agent returns "Could not resolve host".

```bash
AGENT=$(docker ps --filter "label=cagent.role=agent" --format "{{.Names}}" | head -1)

# Test DNS directly
docker exec $AGENT nslookup api.github.com 10.200.1.5

# Check the generated Corefile
docker exec dns-filter cat /etc/coredns/Corefile | grep -A 3 "api.github.com"

# If domain is missing, check if agent-manager regenerated the Corefile
docker logs agent-manager | grep -i "corefile\|coredns" | tail -10
```

### Credential injection not working

**Symptom**: Echo-server response doesn't contain injected Authorization header.

```bash
# Check Lua filter exists and has credentials
docker exec http-proxy cat /etc/envoy/filter.lua | grep -i "credential\|header" | head -5

# Check Envoy access log for credential_injected field
docker logs http-proxy --since 1m | grep "echo" | tail -1

# In connected mode, Lua filter fetches credentials from CP.
# Check CP has the policy with credential:
curl http://localhost:8002/api/v1/domain-policies \
    -H "Authorization: Bearer admin-test-token-do-not-use-in-production" | \
    python3 -c "import json,sys; [print(p['domain'],p['has_credential']) for p in json.load(sys.stdin)['items']]"
```

### Lua filter in backoff (path filtering returns wrong response)

**Symptom**: Path filtering test expects `path_not_allowed` but gets `destination_not_allowed`.

**Root cause**: If the CP was unreachable at any point, the Lua filter enters a 30-second backoff (`CP_FAILURE_BACKOFF = 30`). During backoff, it falls back to static policy which has no path restrictions.

```bash
# Check if Lua filter is contacting CP
docker logs http-proxy --since 1m | grep -i "lua\|cp_call\|backoff"

# Wait 30s and retry, or restart Envoy to reset backoff
docker restart http-proxy
sleep 5
```

### Log pipeline not delivering (canary never appears)

**Symptom**: `test_logs_reach_cp` times out waiting for canary.

```bash
# 1. Did Envoy log the request?
docker logs http-proxy --since 2m | grep "canary"

# 2. Is Vector running and healthy?
docker logs log-shipper --since 2m | grep -i "error\|batch"

# 3. Can Vector reach CP?
docker exec log-shipper wget -q -O /dev/null http://backend:8000/health && echo "OK" || echo "FAIL"

# 4. Is log-shipper connected to the right network?
docker inspect log-shipper --format '{{json .NetworkSettings.Networks}}' | python3 -m json.tool | grep -o '"[^"]*net[^"]*"'
```

### Heartbeat not arriving at CP

**Symptom**: Agent shows in DP but not in CP's `/agents` list.

```bash
# Check agent-manager is sending heartbeats
docker logs agent-manager --since 1m | grep -i "heartbeat"

# Check CP receives them
docker logs backend --since 1m | grep -i "heartbeat"

# Check agent-manager can reach CP
docker exec agent-manager python3 -c "
import requests
r = requests.get('http://backend:8000/health', timeout=5)
print(r.status_code, r.text)
"
```

### Wipe command result never reported

**Symptom**: `test_wipe_command` times out polling for command result.

**Root cause**: Wipe destroys the container, so the next heartbeat cycle can't find it to report the result. The agent-manager should send a bare heartbeat immediately after wipe.

```bash
# Check if agent-manager logged the wipe
docker logs agent-manager | grep -i "wipe" | tail -10

# Check if container was actually removed
docker ps -a --filter "label=cagent.role=agent" --format "{{.Names}} {{.Status}}"
```

## Test Isolation

### Agent network isolation check
```bash
AGENT=$(docker ps --filter "label=cagent.role=agent" --format "{{.Names}}" | head -1)

# Should SUCCEED (proxy)
docker exec $AGENT nc -z -w 2 10.200.1.10 8443 && echo "Proxy: OK"

# Should SUCCEED (DNS)
docker exec $AGENT nc -z -w 2 10.200.1.5 53 && echo "DNS: OK"

# Should FAIL (external — network isolation)
docker exec $AGENT nc -z -w 2 8.8.8.8 53 && echo "FAIL: isolation broken!" || echo "External: blocked (good)"

# Should FAIL (infra network)
docker exec $AGENT nc -z -w 2 10.200.2.20 8000 && echo "FAIL: isolation broken!" || echo "Infra: blocked (good)"
```

## Config Files Modified at Runtime

These tracked files are overwritten by agent-manager at container startup:

| File | Modified by | Backed up by tests? |
|------|------------|---------------------|
| `data_plane/configs/cagent.yaml` | agent-manager (connected mode) | Yes (`.bak`) |
| `data_plane/configs/coredns/Corefile` | agent-manager (always) | Yes (`.bak`) |

Generated inside containers (not on host):
- `/etc/envoy/envoy.yaml` — Envoy proxy config (on `proxy-config` volume)
- `/etc/envoy/filter.lua` — Lua filter with credential injection logic

## Key Environment Variables

| Variable | Where | Purpose |
|----------|-------|---------|
| `DATAPLANE_MODE` | DP containers | `standalone` or `connected` |
| `CONTROL_PLANE_URL` | agent-manager, log-shipper | CP API endpoint |
| `CONTROL_PLANE_TOKEN` | agent-manager, log-shipper | Auth token for CP |
| `SEED_TOKENS` | CP backend | `true` enables test token seeding |
| `HEARTBEAT_INTERVAL` | agent-manager | Seconds between heartbeats (default 30, e2e uses 5) |
| `CONFIG_SYNC_INTERVAL` | agent-manager | Seconds between policy syncs (default 60, e2e uses 10) |

## Running a Single Test

```bash
# Run one specific test with verbose output
cd /path/to/cagent
python -m pytest e2e/test_cp_dp_e2e.py::TestCredentialInjection::test_credential_header_injected -v -s

# Run with print output visible (-s disables capture)
python -m pytest e2e/test_cp_dp_e2e.py -k "test_wipe" -v -s
```

## Full Reset

```bash
# Tear down everything and remove volumes
./dev_up.sh down

# Fresh start
./dev_up.sh

# Or just e2e:
./e2e/run_tests.sh   # Full teardown + setup + test
```
