"""
End-to-end tests for Control Plane + Data Plane integration.

These tests require the CP running in test mode and the DP in connected mode.
Run with:
    ./run_tests.sh              # setup, test, teardown
    ./run_tests.sh --no-teardown  # keep containers for debugging
"""

import json
import time
import subprocess
from pathlib import Path

import pytest
import requests

SCRIPT_DIR = Path(__file__).parent
CP_BASE = "http://localhost:8002"
ADMIN_TOKEN = "admin-test-token-do-not-use-in-production"
ACME_ADMIN_TOKEN = "acme-admin-test-token-do-not-use-in-production"
AGENT_ID = "e2e-agent"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def cp_running():
    """Verify CP is reachable (guaranteed by run_tests.sh)."""
    r = requests.get(f"{CP_BASE}/health", timeout=5)
    assert r.status_code == 200, \
        f"Control plane not reachable at {CP_BASE} — run_tests.sh should have started it"


@pytest.fixture(scope="session")
def agent_token():
    """Read the agent token written by run_tests.sh."""
    token_file = SCRIPT_DIR / ".agent-token"
    assert token_file.exists(), \
        f"{token_file} not found — run_tests.sh should have created it"
    return token_file.read_text().strip()


@pytest.fixture(scope="session")
def admin_headers():
    return {"Authorization": f"Bearer {ADMIN_TOKEN}"}


@pytest.fixture(scope="session")
def agent_headers(agent_token):
    return {"Authorization": f"Bearer {agent_token}"}


@pytest.fixture(scope="session")
def acme_admin_headers():
    return {"Authorization": f"Bearer {ACME_ADMIN_TOKEN}"}


@pytest.fixture(scope="session")
def default_profile_id(admin_headers):
    """Return the 'default' security profile ID (created by post_seed.py)."""
    return _get_default_profile_id(admin_headers)


PROXY = "http://10.200.1.10:8443"


def _get_default_profile_id(admin_headers) -> int:
    """Get or create the 'default' security profile for the default tenant."""
    r = requests.get(
        f"{CP_BASE}/api/v1/security-profiles",
        headers=admin_headers,
    )
    assert r.status_code == 200, f"Failed to list profiles: {r.text}"
    for p in r.json()["items"]:
        if p["name"] == "default":
            return p["id"]

    # Create it if post_seed.py hasn't run
    r = requests.post(
        f"{CP_BASE}/api/v1/security-profiles",
        headers=admin_headers,
        json={"name": "default", "description": "Default profile for e2e tests"},
    )
    assert r.status_code == 200, f"Failed to create default profile: {r.text}"
    return r.json()["id"]


def _discover_agent_container() -> str:
    """Discover an agent container by label, falling back to 'agent'."""
    try:
        result = subprocess.run(
            ["docker", "ps", "--filter", "label=cagent.role=agent",
             "--format", "{{.Names}}"],
            capture_output=True, text=True, timeout=5,
        )
        names = result.stdout.strip().splitlines()
        if names:
            return names[0]
    except Exception:
        pass
    return "agent"


def _discover_all_agent_containers() -> list[str]:
    """Discover all agent containers by label."""
    try:
        result = subprocess.run(
            ["docker", "ps", "--filter", "label=cagent.role=agent",
             "--format", "{{.Names}}"],
            capture_output=True, text=True, timeout=5,
        )
        names = result.stdout.strip().splitlines()
        if names:
            return sorted(names)
    except Exception:
        pass
    return ["agent"]


def exec_in_agent(command: str, container_name: str = None) -> subprocess.CompletedProcess:
    """Execute a command inside an agent container (discovered by label)."""
    name = container_name or _discover_agent_container()
    return subprocess.run(
        ["docker", "exec", name, "sh", "-c", command],
        capture_output=True,
        text=True,
        timeout=30,
    )


def get_envoy_access_logs(since: str | None = None) -> list[dict]:
    """Get Envoy access log entries (JSON lines) from docker logs.

    Uses ``docker logs --since`` to avoid the tail line-count issue where
    stderr startup lines crowd out stdout access-log lines.
    """
    cmd = ["docker", "logs", "--since", since or "120s", "http-proxy"]
    result = subprocess.run(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, timeout=10,
    )
    entries = []
    for line in result.stdout.strip().split("\n"):
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
            if isinstance(entry, dict) and "authority" in entry:
                entries.append(entry)
        except (json.JSONDecodeError, ValueError):
            continue
    return entries


def wait_for_access_log(marker: str, timeout: float = 15.0, poll: float = 1.0) -> list[dict]:
    """Poll ``get_envoy_access_logs`` until an entry whose path contains *marker* appears.

    Envoy buffers stdout writes and flushes every ~10 s, so a fixed sleep
    after a request is unreliable.  This helper polls until the entry shows up
    or *timeout* seconds elapse.
    """
    deadline = time.time() + timeout
    while True:
        entries = get_envoy_access_logs()
        matching = [e for e in entries if marker in e.get("path", "")]
        if matching:
            return matching
        if time.time() >= deadline:
            return []
        time.sleep(poll)


def _wait_for_command_result(agent_id, command, admin_headers, timeout=60, poll=5):
    """Poll agent status until ``last_command == command`` and a result is set.

    Returns the status dict on success, or ``None`` if *timeout* elapses.
    """
    deadline = time.time() + timeout
    while True:
        r = requests.get(
            f"{CP_BASE}/api/v1/agents/{agent_id}/status",
            headers=admin_headers,
        )
        if r.status_code == 200:
            data = r.json()
            if data.get("last_command") == command and data.get("last_command_result"):
                return data
        if time.time() >= deadline:
            return None
        time.sleep(poll)


# ---------------------------------------------------------------------------
# TestMultiAgentContainers
# ---------------------------------------------------------------------------

class TestMultiAgentContainers:
    """Verify multi-agent container discovery and isolation."""

    def test_multiple_agents_discovered(self, cp_running):
        """Should discover at least 2 agent containers by label."""
        names = _discover_all_agent_containers()
        assert len(names) >= 2, f"Expected >=2 agent containers, found {len(names)}: {names}"

    def test_all_agents_can_proxy(self, cp_running):
        """Every agent container should route traffic through the proxy."""
        for name in _discover_all_agent_containers():
            result = exec_in_agent(
                f"curl -s -o /dev/null -w '%{{http_code}}' -x {PROXY} "
                f"--connect-timeout 5 http://api.github.com/",
                container_name=name,
            )
            code = result.stdout.strip()
            assert code.isdigit() and int(code) < 500, \
                f"{name}: proxy request failed with {code}"

    def test_all_agents_isolated(self, cp_running):
        """Every agent container should be blocked from external IPs."""
        for name in _discover_all_agent_containers():
            result = exec_in_agent(
                "nc -z -w 2 8.8.8.8 53 && echo FAIL || echo BLOCKED",
                container_name=name,
            )
            assert "BLOCKED" in result.stdout, \
                f"{name} can reach external IPs directly — isolation broken!"


# ---------------------------------------------------------------------------
# TestHeartbeatAndRegistration
# ---------------------------------------------------------------------------

class TestHeartbeatAndRegistration:
    """Verify that agent-manager heartbeats register the agent on CP."""

    def test_agent_registered(self, cp_running, admin_headers):
        """Agent should appear in the agents list after heartbeat."""
        r = requests.get(f"{CP_BASE}/api/v1/agents", headers=admin_headers)
        assert r.status_code == 200
        agents = r.json()["items"]
        agent_ids = [a["agent_id"] for a in agents]
        assert AGENT_ID in agent_ids, f"Agent {AGENT_ID} not in {agent_ids}"

    def test_heartbeat_recent(self, cp_running, admin_headers):
        """Agent should show as online (heartbeat within 60s)."""
        r = requests.get(
            f"{CP_BASE}/api/v1/agents/{AGENT_ID}/status",
            headers=admin_headers,
        )
        assert r.status_code == 200
        data = r.json()
        assert data["online"] is True, f"Agent offline: {data}"

    def test_reports_resources(self, cp_running, admin_headers):
        """Heartbeat should include resource metrics."""
        r = requests.get(
            f"{CP_BASE}/api/v1/agents/{AGENT_ID}/status",
            headers=admin_headers,
        )
        assert r.status_code == 200
        data = r.json()
        assert data["status"] in ("running", "exited", "not_found", "unknown"), f"Unexpected status: {data['status']}"
        # container_id should be populated if running
        if data["status"] == "running":
            assert data["container_id"] is not None


# ---------------------------------------------------------------------------
# TestCommandExecution
# ---------------------------------------------------------------------------

class TestCommandExecution:
    """Verify that commands queued on CP are executed by agent-manager."""

    def test_restart_command(self, cp_running, admin_headers):
        """Queue restart via CP, wait for agent-manager to execute and report."""
        # Queue restart
        r = requests.post(
            f"{CP_BASE}/api/v1/agents/{AGENT_ID}/restart",
            headers=admin_headers,
        )
        assert r.status_code == 200
        assert r.json()["status"] == "queued"

        # Poll until command result is reported (up to 30s)
        for _ in range(15):
            time.sleep(2)
            r = requests.get(
                f"{CP_BASE}/api/v1/agents/{AGENT_ID}/status",
                headers=admin_headers,
            )
            if r.status_code == 200:
                data = r.json()
                if data.get("last_command") == "restart":
                    assert data["last_command_result"] == "success", f"Restart failed: {data}"
                    return
        pytest.fail("Restart command not completed within 30s")


# ---------------------------------------------------------------------------
# TestDomainPolicies
# ---------------------------------------------------------------------------

class TestDomainPolicies:
    """Verify domain policy CRUD via CP and scoping via agent token."""

    @pytest.fixture(autouse=True)
    def _cleanup_policy(self, admin_headers):
        """Clean up test policies after each test method."""
        yield
        # Delete any policies created during tests
        r = requests.get(
            f"{CP_BASE}/api/v1/domain-policies", headers=admin_headers
        )
        if r.status_code == 200:
            for p in r.json()["items"]:
                if p["domain"] == "e2e-test.example.com":
                    requests.delete(
                        f"{CP_BASE}/api/v1/domain-policies/{p['id']}",
                        headers=admin_headers,
                    )

    def test_create_policy(self, cp_running, admin_headers, default_profile_id):
        """Admin can create a domain policy."""
        r = requests.post(
            f"{CP_BASE}/api/v1/domain-policies",
            headers=admin_headers,
            json={
                "domain": "e2e-test.example.com",
                "alias": "e2etest",
                "description": "E2E test policy",
                "profile_id": default_profile_id,
            },
        )
        assert r.status_code == 200
        data = r.json()
        assert data["domain"] == "e2e-test.example.com"
        assert data["alias"] == "e2etest"
        assert data["enabled"] is True

    def test_agent_sees_policy(self, cp_running, admin_headers, agent_headers, default_profile_id):
        """Agent token can see exported domain policies."""
        # Create a policy first
        requests.post(
            f"{CP_BASE}/api/v1/domain-policies",
            headers=admin_headers,
            json={"domain": "e2e-test.example.com", "profile_id": default_profile_id},
        )

        # Agent should see it via export
        r = requests.get(
            f"{CP_BASE}/api/v1/domain-policies/export",
            headers=agent_headers,
        )
        assert r.status_code == 200
        data = r.json()
        assert "e2e-test.example.com" in data["domains"]

    def test_policy_export(self, cp_running, admin_headers, agent_headers, default_profile_id):
        """Export endpoint returns domains list for CoreDNS."""
        requests.post(
            f"{CP_BASE}/api/v1/domain-policies",
            headers=admin_headers,
            json={"domain": "e2e-test.example.com", "profile_id": default_profile_id},
        )

        r = requests.get(
            f"{CP_BASE}/api/v1/domain-policies/export",
            headers=agent_headers,
        )
        assert r.status_code == 200
        data = r.json()
        assert "domains" in data
        assert "generated_at" in data

    def test_policy_lookup(self, cp_running, admin_headers, agent_headers, default_profile_id):
        """for-domain endpoint returns policy details."""
        requests.post(
            f"{CP_BASE}/api/v1/domain-policies",
            headers=admin_headers,
            json={
                "domain": "e2e-test.example.com",
                "requests_per_minute": 42,
                "profile_id": default_profile_id,
            },
        )

        r = requests.get(
            f"{CP_BASE}/api/v1/domain-policies/for-domain",
            headers=agent_headers,
            params={"domain": "e2e-test.example.com"},
        )
        assert r.status_code == 200
        data = r.json()
        assert data["matched"] is True
        assert data["requests_per_minute"] == 42


# ---------------------------------------------------------------------------
# TestLogIngestion
# ---------------------------------------------------------------------------

class TestLogIngestion:
    """Verify log ingestion through CP to mock OpenObserve."""

    def test_ingest_with_agent_token(self, cp_running, agent_headers):
        """Agent token can ingest logs."""
        r = requests.post(
            f"{CP_BASE}/api/v1/logs/ingest",
            headers=agent_headers,
            json={
                "logs": [
                    {
                        "message": "e2e test log entry",
                        "source": "agent",
                        "level": "info",
                    }
                ]
            },
        )
        assert r.status_code == 200
        data = r.json()
        assert data["status"] == "ok"
        assert data["count"] == 1

    def test_ingest_rejects_admin(self, cp_running, admin_headers):
        """Admin tokens cannot ingest logs (agent-only endpoint)."""
        r = requests.post(
            f"{CP_BASE}/api/v1/logs/ingest",
            headers=admin_headers,
            json={
                "logs": [
                    {
                        "message": "should be rejected",
                        "source": "agent",
                    }
                ]
            },
        )
        assert r.status_code == 403


# ---------------------------------------------------------------------------
# TestTenantIsolation
# ---------------------------------------------------------------------------

class TestTenantIsolation:
    """Verify multi-tenant isolation between default and acme tenants."""

    def test_agent_cannot_see_other_tenant(self, cp_running, acme_admin_headers):
        """Acme admin cannot see default tenant's agent."""
        r = requests.get(
            f"{CP_BASE}/api/v1/agents", headers=acme_admin_headers
        )
        assert r.status_code == 200
        agents = r.json()["items"]
        agent_ids = [a["agent_id"] for a in agents]
        assert AGENT_ID not in agent_ids, (
            f"Acme tenant should not see {AGENT_ID}"
        )

    def test_agent_cannot_admin(self, cp_running, agent_headers):
        """Agent token cannot perform admin operations (create tokens)."""
        r = requests.post(
            f"{CP_BASE}/api/v1/tokens",
            headers=agent_headers,
            json={
                "name": "should-fail",
                "token_type": "admin",
            },
        )
        assert r.status_code == 403


# ---------------------------------------------------------------------------
# TestCredentialInjection
# ---------------------------------------------------------------------------

class TestCredentialInjection:
    """Verify credential injection through the full CP and Envoy flows."""

    @pytest.fixture(autouse=True)
    def _cleanup_cred_policy(self, admin_headers):
        """Clean up credential test policies after each test."""
        yield
        r = requests.get(
            f"{CP_BASE}/api/v1/domain-policies", headers=admin_headers
        )
        if r.status_code == 200:
            for p in r.json()["items"]:
                if p["domain"] == "e2e-cred-test.example.com":
                    requests.delete(
                        f"{CP_BASE}/api/v1/domain-policies/{p['id']}",
                        headers=admin_headers,
                    )

    def test_cp_stores_and_returns_credentials(
        self, cp_running, admin_headers, agent_headers, default_profile_id
    ):
        """CP should store credentials and return them via for-domain endpoint."""
        # Create domain policy with credential
        r = requests.post(
            f"{CP_BASE}/api/v1/domain-policies",
            headers=admin_headers,
            json={
                "domain": "e2e-cred-test.example.com",
                "alias": "e2ecred",
                "profile_id": default_profile_id,
                "credential": {
                    "header": "Authorization",
                    "format": "Bearer {value}",
                    "value": "test-e2e-secret-12345",
                },
            },
        )
        assert r.status_code == 200
        data = r.json()
        assert data["has_credential"] is True
        assert data["credential_header"] == "Authorization"

        # Agent queries for-domain — should get decrypted credential
        r = requests.get(
            f"{CP_BASE}/api/v1/domain-policies/for-domain",
            headers=agent_headers,
            params={"domain": "e2ecred.devbox.local"},
        )
        assert r.status_code == 200
        data = r.json()
        assert data["matched"] is True
        assert data["header_name"] == "Authorization"
        assert data["header_value"] == "Bearer test-e2e-secret-12345"

    def test_credential_injected_to_upstream(self, cp_running):
        """Echo server should receive the injected Authorization header.

        The echo-server domain is configured in cagent.yaml (patched by run.sh)
        with credential env E2E_ECHO_CREDENTIAL=test-e2e-injected-cred.
        Agent-manager bakes this into the generated Envoy Lua filter.
        """
        # Agent requests through envoy to echo.devbox.local
        result = exec_in_agent(
            f"curl -s --max-time 10 -x {PROXY} http://echo.devbox.local/headers"
        )
        if result.returncode != 0:
            pytest.fail(
                f"curl to echo.devbox.local failed (rc={result.returncode}): "
                f"{result.stderr}"
            )

        # Parse echo server response
        try:
            response = json.loads(result.stdout)
        except (json.JSONDecodeError, ValueError):
            pytest.fail(
                f"Echo server returned non-JSON: {result.stdout[:500]}"
            )

        # Verify the Authorization header was injected by Envoy's Lua filter
        headers = response.get("headers", {})
        auth = None
        for k, v in headers.items():
            if k.lower() == "authorization":
                auth = v
                break

        assert auth is not None, (
            f"No Authorization header in echo response. Headers: {headers}"
        )
        assert "test-e2e-injected-cred" in auth, (
            f"Unexpected credential value: {auth}"
        )


# ---------------------------------------------------------------------------
# TestLogContent
# ---------------------------------------------------------------------------

class TestLogContent:
    """Verify Envoy access log content and structure."""

    def test_envoy_access_log_fields(self, cp_running):
        """Access log entries should contain all expected JSON fields."""
        # Make a request with a unique path to identify in logs
        marker = f"/e2e-log-fields-{int(time.time())}"
        curl_result = exec_in_agent(f"curl -s -o /dev/null -w '%{{http_code}}' -x {PROXY} http://openai.devbox.local{marker}")

        matching = wait_for_access_log(marker)
        assert len(matching) > 0, (
            f"No log entry found for path {marker} (waited 15 s for Envoy flush). "
            f"curl status: {curl_result.stdout!r}"
        )

        entry = matching[-1]
        expected_fields = [
            "timestamp",
            "authority",
            "path",
            "method",
            "response_code",
            "duration_ms",
            "credential_injected",
        ]
        missing = [f for f in expected_fields if f not in entry]
        assert not missing, (
            f"Missing fields in access log: {missing}. "
            f"Available: {list(entry.keys())}"
        )

        # Verify field values are sensible
        assert entry["method"] == "GET"
        assert "openai" in entry["authority"], (
            f"Expected 'openai' in authority, got: {entry['authority']!r}"
        )

    def test_envoy_logs_credential_injection(self, cp_running):
        """Access log should show credential_injected=true for echo requests."""
        marker = f"/e2e-cred-log-{int(time.time())}"
        curl_result = exec_in_agent(
            f"curl -s -o /dev/null -w '%{{http_code}}' -x {PROXY} http://echo.devbox.local{marker}"
        )

        matching = wait_for_access_log(marker)
        assert len(matching) > 0, (
            f"No log entry found for echo request {marker} (waited 15 s for Envoy flush). "
            f"curl status: {curl_result.stdout!r}"
        )

        entry = matching[-1]
        assert entry.get("credential_injected") == "true", (
            f"Expected credential_injected=true, got: "
            f"{entry.get('credential_injected')}"
        )

    def test_envoy_logs_blocked_domain(self, cp_running):
        """Blocked domains should return 403 and appear in access logs."""
        marker = f"/e2e-blocked-{int(time.time())}"
        result = exec_in_agent(
            f"curl -s -o /dev/null -w '%{{http_code}}' -x {PROXY} "
            f"http://blocked.example.com{marker}"
        )
        # Envoy catch-all returns 403 for unlisted domains
        assert "403" in result.stdout, (
            f"Expected 403 for blocked domain, got: {result.stdout}"
        )

        matching = wait_for_access_log(marker)
        assert len(matching) > 0, (
            f"No log entry for blocked request {marker} (waited 15 s for Envoy flush)"
        )

        entry = matching[-1]
        # response_code may be int or string depending on envoy version
        assert str(entry.get("response_code")) == "403", (
            f"Expected response_code=403 in log, got: "
            f"{entry.get('response_code')}"
        )


# ---------------------------------------------------------------------------
# TestAnalytics
# ---------------------------------------------------------------------------

class TestAnalytics:
    """Verify analytics endpoints on the control plane."""

    BLOCKED_DOMAIN = "analytics-cp-e2e.example.com"

    @pytest.fixture(autouse=True)
    def _generate_traffic(self, cp_running):
        """Generate blocked traffic via the agent proxy before each test."""
        for _ in range(3):
            exec_in_agent(
                f"curl -s -o /dev/null -x {PROXY} "
                f"--connect-timeout 5 http://{self.BLOCKED_DOMAIN}/test"
            )
        # Also generate allowed traffic for bandwidth test
        exec_in_agent(
            f"curl -s -o /dev/null -x {PROXY} "
            f"--connect-timeout 5 http://openai.devbox.local/v1/models"
        )

    def _wait_for_blocked_in_cp(self, admin_headers, timeout=30.0, poll=2.0):
        """Poll the CP blocked-domains endpoint until our domain appears."""
        deadline = time.time() + timeout
        while True:
            r = requests.get(
                f"{CP_BASE}/api/v1/analytics/blocked-domains",
                headers=admin_headers,
                params={"agent_id": AGENT_ID, "hours": 1, "limit": 50},
                timeout=10,
            )
            if r.status_code == 200:
                for d in r.json().get("blocked_domains", []):
                    if d["domain"] == self.BLOCKED_DOMAIN:
                        return d
            if time.time() >= deadline:
                return None
            time.sleep(poll)

    def test_blocked_domains_via_cp(self, cp_running, admin_headers):
        """Blocked domains should appear in CP analytics after log ingestion."""
        # On fresh startup, Vector's initial requests may fail (DNS not ready
        # until e2e-bridge connect) and get dropped as non-retriable.  If the
        # first traffic batch isn't found, generate fresh traffic and retry.
        entry = self._wait_for_blocked_in_cp(admin_headers, timeout=30.0)
        if entry is None:
            for _ in range(3):
                exec_in_agent(
                    f"curl -s -o /dev/null -x {PROXY} "
                    f"--connect-timeout 5 http://{self.BLOCKED_DOMAIN}/retry"
                )
            entry = self._wait_for_blocked_in_cp(admin_headers, timeout=30.0)
        assert entry is not None, (
            f"{self.BLOCKED_DOMAIN} not found in CP analytics after traffic + wait. "
            "Logs may not have been ingested yet."
        )
        assert entry["count"] >= 1
        assert "last_seen" in entry

    def test_bandwidth_via_cp(self, cp_running, admin_headers):
        """Bandwidth endpoint should return data for agent traffic."""
        # Wait a bit for logs to be ingested
        time.sleep(5)
        r = requests.get(
            f"{CP_BASE}/api/v1/analytics/bandwidth",
            headers=admin_headers,
            params={"agent_id": AGENT_ID, "hours": 1, "limit": 20},
            timeout=10,
        )
        assert r.status_code == 200
        data = r.json()
        assert "domains" in data
        assert "window_hours" in data
        assert isinstance(data["domains"], list)
        # Verify entry structure if data is present
        if data["domains"]:
            entry = data["domains"][0]
            assert "domain" in entry
            assert "bytes_sent" in entry
            assert "bytes_received" in entry
            assert "total_bytes" in entry
            assert "request_count" in entry

    def test_timeseries_via_cp(self, cp_running, admin_headers):
        """Timeseries endpoint should return bucketed data."""
        time.sleep(5)
        r = requests.get(
            f"{CP_BASE}/api/v1/analytics/blocked-domains/timeseries",
            headers=admin_headers,
            params={"agent_id": AGENT_ID, "hours": 1, "buckets": 6},
            timeout=10,
        )
        assert r.status_code == 200
        data = r.json()
        assert "buckets" in data
        assert "window_hours" in data
        assert "bucket_minutes" in data
        assert len(data["buckets"]) == 6
        for bucket in data["buckets"]:
            assert "start" in bucket
            assert "end" in bucket
            assert "count" in bucket
            assert isinstance(bucket["count"], int)

    def test_diagnose_via_cp(self, cp_running, admin_headers):
        """Diagnose endpoint should return diagnostic result."""
        time.sleep(5)
        r = requests.get(
            f"{CP_BASE}/api/v1/analytics/diagnose",
            headers=admin_headers,
            params={"domain": self.BLOCKED_DOMAIN, "agent_id": AGENT_ID},
            timeout=10,
        )
        assert r.status_code == 200
        data = r.json()
        assert data["domain"] == self.BLOCKED_DOMAIN
        assert data["in_allowlist"] is False
        assert "recent_requests" in data
        assert "diagnosis" in data
        assert "not in the allowlist" in data["diagnosis"]

    def test_analytics_tenant_isolation(self, cp_running, acme_admin_headers):
        """Acme admin should not see default tenant's analytics data."""
        r = requests.get(
            f"{CP_BASE}/api/v1/analytics/blocked-domains",
            headers=acme_admin_headers,
            params={"agent_id": AGENT_ID, "hours": 1},
            timeout=10,
        )
        # Should either get 403 (agent not found for this tenant) or 404
        assert r.status_code in (403, 404), (
            f"Expected 403/404 for cross-tenant analytics, got {r.status_code}: {r.text}"
        )


# ---------------------------------------------------------------------------
# TestDomainPolicyTTL
# ---------------------------------------------------------------------------

class TestDomainPolicyTTL:
    """Verify domain policy TTL (expires_at) behavior."""

    TTL_DOMAIN = "ttl-e2e-test.example.com"

    @pytest.fixture(autouse=True)
    def _cleanup_ttl_policy(self, admin_headers):
        """Clean up TTL test policies after each test.

        Tracks policy IDs created during the test and deletes by ID directly,
        because the list endpoint filters out expired policies.
        """
        self._created_policy_ids = []
        yield
        for policy_id in self._created_policy_ids:
            requests.delete(
                f"{CP_BASE}/api/v1/domain-policies/{policy_id}",
                headers=admin_headers,
            )

    def _create_ttl_policy(self, admin_headers, expires_at, profile_id=None):
        """Helper: create a TTL policy and track its ID for cleanup."""
        body = {
            "domain": self.TTL_DOMAIN,
            "expires_at": expires_at,
        }
        if profile_id is not None:
            body["profile_id"] = profile_id
        r = requests.post(
            f"{CP_BASE}/api/v1/domain-policies",
            headers=admin_headers,
            json=body,
        )
        assert r.status_code == 200, f"Failed to create TTL policy: {r.text}"
        self._created_policy_ids.append(r.json()["id"])
        return r.json()

    def test_create_policy_with_expires_at(self, cp_running, admin_headers, agent_headers, default_profile_id):
        """Create a policy with expires_at, verify it appears in list and export."""
        from datetime import datetime, timedelta, timezone
        expires = (datetime.now(timezone.utc) + timedelta(seconds=60)).isoformat()

        data = self._create_ttl_policy(admin_headers, expires, profile_id=default_profile_id)
        assert data["domain"] == self.TTL_DOMAIN
        assert data["expires_at"] is not None

        # Should appear in list
        r = requests.get(
            f"{CP_BASE}/api/v1/domain-policies", headers=admin_headers
        )
        assert r.status_code == 200
        domains = [p["domain"] for p in r.json()["items"]]
        assert self.TTL_DOMAIN in domains

        # Should appear in export
        r = requests.get(
            f"{CP_BASE}/api/v1/domain-policies/export", headers=agent_headers
        )
        assert r.status_code == 200
        assert self.TTL_DOMAIN in r.json()["domains"]

    def test_expired_policy_filtered(self, cp_running, admin_headers, agent_headers, default_profile_id):
        """An expired policy should be filtered from list, export, and for-domain."""
        from datetime import datetime, timedelta, timezone
        expires = (datetime.now(timezone.utc) + timedelta(seconds=2)).isoformat()

        self._create_ttl_policy(admin_headers, expires, profile_id=default_profile_id)

        # Wait for expiry
        time.sleep(4)

        # Should NOT appear in list
        r = requests.get(
            f"{CP_BASE}/api/v1/domain-policies", headers=admin_headers
        )
        assert r.status_code == 200
        domains = [p["domain"] for p in r.json()["items"]]
        assert self.TTL_DOMAIN not in domains, (
            f"{self.TTL_DOMAIN} still in policy list after expiry"
        )

        # Should NOT appear in export
        r = requests.get(
            f"{CP_BASE}/api/v1/domain-policies/export", headers=agent_headers
        )
        assert r.status_code == 200
        assert self.TTL_DOMAIN not in r.json()["domains"], (
            f"{self.TTL_DOMAIN} still in export after expiry"
        )

    def test_policy_for_domain_respects_expiry(self, cp_running, admin_headers, agent_headers, default_profile_id):
        """for-domain lookup should not match an expired policy."""
        from datetime import datetime, timedelta, timezone
        expires = (datetime.now(timezone.utc) + timedelta(seconds=2)).isoformat()

        self._create_ttl_policy(admin_headers, expires, profile_id=default_profile_id)

        # Wait for expiry
        time.sleep(4)

        # for-domain should return matched=false
        r = requests.get(
            f"{CP_BASE}/api/v1/domain-policies/for-domain",
            headers=agent_headers,
            params={"domain": self.TTL_DOMAIN},
        )
        assert r.status_code == 200
        data = r.json()
        assert data["matched"] is False, (
            f"Expired policy still matched for {self.TTL_DOMAIN}: {data}"
        )


# ---------------------------------------------------------------------------
# TestPathFiltering
# ---------------------------------------------------------------------------

class TestPathFiltering:
    """Verify the Lua filter enforces path restrictions from CP policies.

    Uses a unique domain so the Lua cache (300s TTL) is cold.  The domain
    has no Envoy virtual host, so requests that *pass* Lua hit the catch-all
    403 with body ``destination_not_allowed``.  Requests blocked by Lua's
    path filter return ``path_not_allowed``.
    """

    DOMAIN = "pathtest-e2e.example.com"

    @pytest.fixture(autouse=True)
    def _cleanup_path_policy(self, admin_headers):
        """Delete test policies after each test."""
        yield
        r = requests.get(
            f"{CP_BASE}/api/v1/domain-policies", headers=admin_headers
        )
        if r.status_code == 200:
            for p in r.json()["items"]:
                if p["domain"] == self.DOMAIN:
                    requests.delete(
                        f"{CP_BASE}/api/v1/domain-policies/{p['id']}",
                        headers=admin_headers,
                    )

    def _ensure_policy(self, admin_headers, profile_id):
        """Create the path-filtered policy if it doesn't already exist."""
        r = requests.post(
            f"{CP_BASE}/api/v1/domain-policies",
            headers=admin_headers,
            json={
                "domain": self.DOMAIN,
                "allowed_paths": ["/allowed", "/allowed/*"],
                "profile_id": profile_id,
            },
        )
        assert r.status_code == 200
        return r.json()

    def _wait_for_path_response(self, path, expected_body, timeout=45, poll=3):
        """Retry curl until expected_body appears in response (or timeout)."""
        deadline = time.time() + timeout
        last_stdout = ""
        while True:
            result = exec_in_agent(
                f"curl -s -x {PROXY} http://{self.DOMAIN}{path}"
            )
            last_stdout = result.stdout
            if expected_body in last_stdout:
                return last_stdout
            if time.time() >= deadline:
                return last_stdout
            time.sleep(poll)

    def test_blocked_path_rejected(self, cp_running, admin_headers, default_profile_id):
        """A path not in allowed_paths should be rejected by the Lua filter."""
        self._ensure_policy(admin_headers, default_profile_id)
        body = self._wait_for_path_response("/blocked", "path_not_allowed")
        assert "path_not_allowed" in body, (
            f"Expected 'path_not_allowed' in response, got: {body[:300]}"
        )

    def test_allowed_path_passes_lua(self, cp_running, admin_headers, default_profile_id):
        """An allowed path should pass Lua but hit the Envoy catch-all 403."""
        self._ensure_policy(admin_headers, default_profile_id)
        body = self._wait_for_path_response("/allowed/test", "destination_not_allowed")
        assert "path_not_allowed" not in body, (
            f"Path filter blocked /allowed/test unexpectedly: {body[:300]}"
        )
        assert "destination_not_allowed" in body, (
            f"Expected 'destination_not_allowed' (Envoy catch-all), got: {body[:300]}"
        )


# ---------------------------------------------------------------------------
# TestPolicyPropagation
# ---------------------------------------------------------------------------

class TestPolicyPropagation:
    """Verify CP policy lifecycle is visible via the export endpoint."""

    DOMAIN = "proptest-e2e.example.com"

    @pytest.fixture(autouse=True)
    def _cleanup_prop_policy(self, admin_headers):
        """Delete test policies after each test."""
        yield
        r = requests.get(
            f"{CP_BASE}/api/v1/domain-policies", headers=admin_headers
        )
        if r.status_code == 200:
            for p in r.json()["items"]:
                if p["domain"] == self.DOMAIN:
                    requests.delete(
                        f"{CP_BASE}/api/v1/domain-policies/{p['id']}",
                        headers=admin_headers,
                    )

    def test_new_policy_in_export(self, cp_running, admin_headers, agent_headers, default_profile_id):
        """A newly created policy should appear in the export endpoint."""
        requests.post(
            f"{CP_BASE}/api/v1/domain-policies",
            headers=admin_headers,
            json={"domain": self.DOMAIN, "profile_id": default_profile_id},
        )
        r = requests.get(
            f"{CP_BASE}/api/v1/domain-policies/export",
            headers=agent_headers,
        )
        assert r.status_code == 200
        assert self.DOMAIN in r.json()["domains"], (
            f"{self.DOMAIN} not in export after creation"
        )

    def test_disabled_policy_hidden(self, cp_running, admin_headers, agent_headers, default_profile_id):
        """A disabled policy should not appear in the export endpoint."""
        r = requests.post(
            f"{CP_BASE}/api/v1/domain-policies",
            headers=admin_headers,
            json={"domain": self.DOMAIN, "profile_id": default_profile_id},
        )
        policy_id = r.json()["id"]

        # Disable
        r = requests.put(
            f"{CP_BASE}/api/v1/domain-policies/{policy_id}",
            headers=admin_headers,
            json={"enabled": False},
        )
        assert r.status_code == 200

        r = requests.get(
            f"{CP_BASE}/api/v1/domain-policies/export",
            headers=agent_headers,
        )
        assert r.status_code == 200
        assert self.DOMAIN not in r.json()["domains"], (
            f"{self.DOMAIN} still in export after disable"
        )

    def test_deleted_policy_removed(self, cp_running, admin_headers, agent_headers, default_profile_id):
        """A deleted policy should not appear in the export endpoint."""
        r = requests.post(
            f"{CP_BASE}/api/v1/domain-policies",
            headers=admin_headers,
            json={"domain": self.DOMAIN, "profile_id": default_profile_id},
        )
        policy_id = r.json()["id"]

        # Verify present
        r = requests.get(
            f"{CP_BASE}/api/v1/domain-policies/export",
            headers=agent_headers,
        )
        assert self.DOMAIN in r.json()["domains"]

        # Delete
        r = requests.delete(
            f"{CP_BASE}/api/v1/domain-policies/{policy_id}",
            headers=admin_headers,
        )
        assert r.status_code == 200

        r = requests.get(
            f"{CP_BASE}/api/v1/domain-policies/export",
            headers=agent_headers,
        )
        assert r.status_code == 200
        assert self.DOMAIN not in r.json()["domains"], (
            f"{self.DOMAIN} still in export after deletion"
        )


# ---------------------------------------------------------------------------
# TestCredentialRotation
# ---------------------------------------------------------------------------

class TestCredentialRotation:
    """Verify credential rotation via the CP API."""

    DOMAIN = "rotation-e2e.example.com"

    @pytest.fixture(autouse=True)
    def _cleanup_rotation_policy(self, admin_headers):
        """Delete test policies after each test."""
        yield
        r = requests.get(
            f"{CP_BASE}/api/v1/domain-policies", headers=admin_headers
        )
        if r.status_code == 200:
            for p in r.json()["items"]:
                if p["domain"] == self.DOMAIN:
                    requests.delete(
                        f"{CP_BASE}/api/v1/domain-policies/{p['id']}",
                        headers=admin_headers,
                    )

    def test_credential_rotation_via_api(
        self, cp_running, admin_headers, agent_headers, default_profile_id
    ):
        """Rotating a credential should update the value returned by for-domain."""
        # Create policy with initial credential
        r = requests.post(
            f"{CP_BASE}/api/v1/domain-policies",
            headers=admin_headers,
            json={
                "domain": self.DOMAIN,
                "profile_id": default_profile_id,
                "credential": {
                    "header": "Authorization",
                    "format": "Bearer {value}",
                    "value": "initial-secret",
                },
            },
        )
        assert r.status_code == 200
        data = r.json()
        assert data["has_credential"] is True
        policy_id = data["id"]

        # Verify initial credential via for-domain
        r = requests.get(
            f"{CP_BASE}/api/v1/domain-policies/for-domain",
            headers=agent_headers,
            params={"domain": self.DOMAIN},
        )
        assert r.status_code == 200
        assert "initial-secret" in r.json()["header_value"]

        # Rotate credential
        r = requests.post(
            f"{CP_BASE}/api/v1/domain-policies/{policy_id}/rotate-credential",
            headers=admin_headers,
            json={
                "header": "Authorization",
                "format": "Bearer {value}",
                "value": "rotated-secret",
            },
        )
        assert r.status_code == 200
        rotated = r.json()
        assert rotated["credential_rotated_at"] is not None

        # Verify rotated credential via for-domain
        r = requests.get(
            f"{CP_BASE}/api/v1/domain-policies/for-domain",
            headers=agent_headers,
            params={"domain": self.DOMAIN},
        )
        assert r.status_code == 200
        assert "rotated-secret" in r.json()["header_value"], (
            f"Expected 'rotated-secret' in header_value, got: {r.json()['header_value']}"
        )


# ---------------------------------------------------------------------------
# TestAuditTrail
# ---------------------------------------------------------------------------

class TestAuditTrail:
    """Verify audit trail entries for policy mutations."""

    DOMAIN = "audit-e2e.example.com"

    @pytest.fixture(autouse=True)
    def _cleanup_audit_policy(self, admin_headers):
        """Delete test policies after each test."""
        yield
        r = requests.get(
            f"{CP_BASE}/api/v1/domain-policies", headers=admin_headers
        )
        if r.status_code == 200:
            for p in r.json()["items"]:
                if p["domain"] == self.DOMAIN:
                    requests.delete(
                        f"{CP_BASE}/api/v1/domain-policies/{p['id']}",
                        headers=admin_headers,
                    )

    def test_policy_mutations_audited(self, cp_running, admin_headers):
        """Create, update, and delete should each produce an audit entry."""
        # Create
        r = requests.post(
            f"{CP_BASE}/api/v1/domain-policies",
            headers=admin_headers,
            json={"domain": self.DOMAIN, "description": "audit test"},
        )
        assert r.status_code == 200
        policy_id = r.json()["id"]

        # Update
        requests.put(
            f"{CP_BASE}/api/v1/domain-policies/{policy_id}",
            headers=admin_headers,
            json={"description": "audit test updated"},
        )

        # Delete
        requests.delete(
            f"{CP_BASE}/api/v1/domain-policies/{policy_id}",
            headers=admin_headers,
        )

        # Check audit trail for create event
        r = requests.get(
            f"{CP_BASE}/api/v1/audit-trail",
            headers=admin_headers,
            params={"event_type": "egress_policy_created"},
        )
        assert r.status_code == 200
        items = r.json()["items"]
        created = [e for e in items if self.DOMAIN in e.get("action", "")]
        assert len(created) >= 1, (
            f"No audit entry for egress_policy_created with {self.DOMAIN}"
        )
        assert created[0]["severity"] == "INFO"

        # Check audit trail for delete event
        r = requests.get(
            f"{CP_BASE}/api/v1/audit-trail",
            headers=admin_headers,
            params={"event_type": "egress_policy_deleted"},
        )
        assert r.status_code == 200
        items = r.json()["items"]
        deleted = [e for e in items if self.DOMAIN in e.get("action", "")]
        assert len(deleted) >= 1, (
            f"No audit entry for egress_policy_deleted with {self.DOMAIN}"
        )
        assert deleted[0]["severity"] == "WARNING"

    def test_audit_tenant_isolation(self, cp_running, admin_headers, acme_admin_headers):
        """Acme admin should not see default tenant's audit entries."""
        # Create a policy in default tenant
        r = requests.post(
            f"{CP_BASE}/api/v1/domain-policies",
            headers=admin_headers,
            json={"domain": self.DOMAIN},
        )
        assert r.status_code == 200

        # Acme admin reads audit trail
        r = requests.get(
            f"{CP_BASE}/api/v1/audit-trail",
            headers=acme_admin_headers,
        )
        assert r.status_code == 200
        items = r.json()["items"]
        leaked = [e for e in items if self.DOMAIN in e.get("action", "")]
        assert len(leaked) == 0, (
            f"Acme admin can see default tenant domain {self.DOMAIN} in audit trail"
        )


# ---------------------------------------------------------------------------
# TestPerAgentPolicies
# ---------------------------------------------------------------------------

class TestProfileScopedPolicies:
    """Verify profile-scoped policies appear only for agents with that profile."""

    @pytest.fixture(autouse=True)
    def _cleanup_profile_policies(self, admin_headers):
        """Track and delete policies and profiles created during tests."""
        self._created_policy_ids = []
        self._created_profile_ids = []
        yield
        for pid in self._created_policy_ids:
            requests.delete(
                f"{CP_BASE}/api/v1/domain-policies/{pid}",
                headers=admin_headers,
            )
        # Unassign agent profile before deleting profiles
        requests.delete(
            f"{CP_BASE}/api/v1/agents/{AGENT_ID}/profile",
            headers=admin_headers,
        )
        for pid in self._created_profile_ids:
            requests.delete(
                f"{CP_BASE}/api/v1/security-profiles/{pid}",
                headers=admin_headers,
            )

    def test_profile_policy_in_export(
        self, cp_running, admin_headers, agent_headers
    ):
        """A policy in the agent's assigned profile should appear in export."""
        # Create a dedicated profile
        r = requests.post(
            f"{CP_BASE}/api/v1/security-profiles",
            headers=admin_headers,
            json={"name": "e2e-scoped-profile"},
        )
        assert r.status_code == 200
        profile_id = r.json()["id"]
        self._created_profile_ids.append(profile_id)

        # Create a policy in that profile
        r = requests.post(
            f"{CP_BASE}/api/v1/domain-policies",
            headers=admin_headers,
            json={
                "domain": "profilescope-e2e.example.com",
                "profile_id": profile_id,
            },
        )
        assert r.status_code == 200
        self._created_policy_ids.append(r.json()["id"])

        # Assign the profile to the e2e agent
        r = requests.put(
            f"{CP_BASE}/api/v1/agents/{AGENT_ID}/profile",
            headers=admin_headers,
            json={"profile_id": profile_id},
        )
        assert r.status_code == 200

        # Agent should see it in export
        r = requests.get(
            f"{CP_BASE}/api/v1/domain-policies/export",
            headers=agent_headers,
        )
        assert r.status_code == 200
        assert "profilescope-e2e.example.com" in r.json()["domains"], (
            "Profile-scoped policy not in export for agent with that profile"
        )

    def test_other_profile_policy_hidden(
        self, cp_running, admin_headers, agent_headers, default_profile_id
    ):
        """A policy in a different profile should NOT appear in agent's export."""
        # Create a profile that will NOT be assigned to the agent
        r = requests.post(
            f"{CP_BASE}/api/v1/security-profiles",
            headers=admin_headers,
            json={"name": "e2e-other-profile"},
        )
        assert r.status_code == 200
        other_profile_id = r.json()["id"]
        self._created_profile_ids.append(other_profile_id)

        # Create a policy scoped to the other profile
        r = requests.post(
            f"{CP_BASE}/api/v1/domain-policies",
            headers=admin_headers,
            json={
                "domain": "otherprofile-e2e.example.com",
                "profile_id": other_profile_id,
            },
        )
        assert r.status_code == 200
        self._created_policy_ids.append(r.json()["id"])

        # Agent uses the default profile (not assigned to other)
        r = requests.get(
            f"{CP_BASE}/api/v1/domain-policies/export",
            headers=agent_headers,
        )
        assert r.status_code == 200
        assert "otherprofile-e2e.example.com" not in r.json()["domains"], (
            "Policy from another profile leaked into agent's export"
        )


# ---------------------------------------------------------------------------
# TestAgentLifecycle
# ---------------------------------------------------------------------------

class TestAgentLifecycle:
    """Verify stop, start, and wipe commands via the CP API.

    These tests are destructive (stop/start the agent container) so they
    are placed near the end of the file.
    """

    def test_stop_command(self, cp_running, admin_headers):
        """Queue a stop command and verify it succeeds."""
        r = requests.post(
            f"{CP_BASE}/api/v1/agents/{AGENT_ID}/stop",
            headers=admin_headers,
        )
        assert r.status_code == 200
        assert r.json()["status"] == "queued"

        data = _wait_for_command_result(AGENT_ID, "stop", admin_headers, timeout=60)
        assert data is not None, "Stop command not completed within 60s"
        assert data["last_command_result"] == "success", (
            f"Stop command failed: {data}"
        )

    def test_start_command(self, cp_running, admin_headers):
        """Queue a start command and verify it succeeds."""
        # Wait for previous command to clear
        time.sleep(8)
        r = requests.post(
            f"{CP_BASE}/api/v1/agents/{AGENT_ID}/start",
            headers=admin_headers,
        )
        assert r.status_code == 200
        assert r.json()["status"] == "queued"

        data = _wait_for_command_result(AGENT_ID, "start", admin_headers, timeout=60)
        assert data is not None, "Start command not completed within 60s"
        assert data["last_command_result"] == "success", (
            f"Start command failed: {data}"
        )

    def test_wipe_command(self, cp_running, admin_headers):
        """Queue a wipe (no workspace) command and verify it succeeds."""
        # Wait for previous command to clear
        time.sleep(8)
        r = requests.post(
            f"{CP_BASE}/api/v1/agents/{AGENT_ID}/wipe",
            headers=admin_headers,
            json={"wipe_workspace": False},
        )
        assert r.status_code == 200
        assert r.json()["status"] == "queued"

        data = _wait_for_command_result(AGENT_ID, "wipe", admin_headers, timeout=60)
        assert data is not None, "Wipe command not completed within 60s"
        assert data["last_command_result"] == "success", (
            f"Wipe command failed: {data}"
        )


# ---------------------------------------------------------------------------
# TestResourcePolicyPropagation
# ---------------------------------------------------------------------------

def _safe_int(s: str) -> int:
    """Parse an int from docker inspect output, returning 0 for non-numeric values like '<no value>'."""
    try:
        return int(s)
    except (ValueError, TypeError):
        return 0


def _get_container_resources(container_name: str) -> dict:
    """Read resource limits from a container via docker inspect."""
    result = subprocess.run(
        ["docker", "inspect", "--format",
         "{{json .HostConfig.NanoCpus}} {{json .HostConfig.Memory}} {{json .HostConfig.PidsLimit}}",
         container_name],
        capture_output=True, text=True, timeout=10,
    )
    parts = result.stdout.strip().split()
    nano_cpus = _safe_int(parts[0]) if len(parts) > 0 else 0
    memory_bytes = _safe_int(parts[1]) if len(parts) > 1 else 0
    pids = _safe_int(parts[2]) if len(parts) > 2 else 0
    return {
        "cpu_limit": nano_cpus / 1e9 if nano_cpus > 0 else None,
        "memory_limit_mb": memory_bytes // (1024 * 1024) if memory_bytes > 0 else None,
        "pids_limit": pids if pids > 0 else None,
    }


class TestResourcePolicyPropagation:
    """Verify resource limit updates flow from CP profile to DP container.

    Flow: admin updates SecurityProfile → heartbeat returns limits →
    agent-manager calls docker update → container reflects new limits.
    """

    PROFILE_NAME = "e2e-resource-test"
    # Heartbeat is 5s in e2e; allow several cycles for propagation
    PROPAGATION_TIMEOUT = 45
    POLL_INTERVAL = 5

    def _create_profile(self, admin_headers, **kwargs):
        payload = {"name": self.PROFILE_NAME, **kwargs}
        r = requests.post(
            f"{CP_BASE}/api/v1/security-profiles",
            headers=admin_headers,
            json=payload,
        )
        if r.status_code == 400 and "already exists" in r.text:
            # Profile exists from a prior run; fetch and return it
            r2 = requests.get(
                f"{CP_BASE}/api/v1/security-profiles",
                headers=admin_headers,
            )
            for p in r2.json()["items"]:
                if p["name"] == self.PROFILE_NAME:
                    return p
        assert r.status_code == 200, f"Failed to create profile: {r.text}"
        return r.json()

    def _assign_profile(self, admin_headers, profile_id):
        r = requests.put(
            f"{CP_BASE}/api/v1/agents/{AGENT_ID}/profile",
            headers=admin_headers,
            json={"profile_id": profile_id},
        )
        assert r.status_code == 200, f"Failed to assign profile: {r.text}"

    def _unassign_profile(self, admin_headers):
        requests.delete(
            f"{CP_BASE}/api/v1/agents/{AGENT_ID}/profile",
            headers=admin_headers,
        )

    def _delete_profile(self, admin_headers, profile_id):
        requests.delete(
            f"{CP_BASE}/api/v1/security-profiles/{profile_id}",
            headers=admin_headers,
        )

    def _wait_for_resource(self, container, field, expected, timeout=None):
        """Poll container resources until field matches expected value."""
        timeout = timeout or self.PROPAGATION_TIMEOUT
        deadline = time.time() + timeout
        actual = None
        while time.time() < deadline:
            resources = _get_container_resources(container)
            actual = resources.get(field)
            if expected is None:
                # "no limit" — accept None or very large values
                if actual is None:
                    return True
            elif actual is not None and abs(actual - expected) < 0.01:
                return True
            time.sleep(self.POLL_INTERVAL)
        return False

    def test_cpu_limit_propagates(self, cp_running, admin_headers):
        """Setting cpu_limit on profile should update container CPU quota."""
        container = _discover_agent_container()

        profile = self._create_profile(admin_headers, cpu_limit=0.5)
        profile_id = profile["id"]
        try:
            self._assign_profile(admin_headers, profile_id)

            assert self._wait_for_resource(container, "cpu_limit", 0.5), (
                f"CPU limit did not propagate to {container} within {self.PROPAGATION_TIMEOUT}s"
            )
        finally:
            self._unassign_profile(admin_headers)
            self._delete_profile(admin_headers, profile_id)

    def test_memory_limit_propagates(self, cp_running, admin_headers):
        """Setting memory_limit_mb on profile should update container memory."""
        container = _discover_agent_container()

        profile = self._create_profile(admin_headers, memory_limit_mb=256)
        profile_id = profile["id"]
        try:
            self._assign_profile(admin_headers, profile_id)

            assert self._wait_for_resource(container, "memory_limit_mb", 256), (
                f"Memory limit did not propagate to {container} within {self.PROPAGATION_TIMEOUT}s"
            )
        finally:
            self._unassign_profile(admin_headers)
            self._delete_profile(admin_headers, profile_id)

    def test_pids_limit_propagates(self, cp_running, admin_headers):
        """Setting pids_limit on profile should update container PID limit."""
        container = _discover_agent_container()

        profile = self._create_profile(admin_headers, pids_limit=100)
        profile_id = profile["id"]
        try:
            self._assign_profile(admin_headers, profile_id)

            assert self._wait_for_resource(container, "pids_limit", 100), (
                f"PIDs limit did not propagate to {container} within {self.PROPAGATION_TIMEOUT}s"
            )
        finally:
            self._unassign_profile(admin_headers)
            self._delete_profile(admin_headers, profile_id)

    def test_resource_update_propagates(self, cp_running, admin_headers):
        """Updating resource limits on an assigned profile should propagate."""
        container = _discover_agent_container()

        profile = self._create_profile(admin_headers, cpu_limit=0.5, memory_limit_mb=256)
        profile_id = profile["id"]
        try:
            self._assign_profile(admin_headers, profile_id)

            # Wait for initial limits
            assert self._wait_for_resource(container, "cpu_limit", 0.5), (
                "Initial CPU limit did not propagate"
            )

            # Update the profile
            r = requests.put(
                f"{CP_BASE}/api/v1/security-profiles/{profile_id}",
                headers=admin_headers,
                json={"cpu_limit": 1.0, "memory_limit_mb": 512},
            )
            assert r.status_code == 200

            # Wait for updated limits
            assert self._wait_for_resource(container, "cpu_limit", 1.0), (
                "Updated CPU limit did not propagate"
            )
            assert self._wait_for_resource(container, "memory_limit_mb", 512), (
                "Updated memory limit did not propagate"
            )
        finally:
            self._unassign_profile(admin_headers)
            self._delete_profile(admin_headers, profile_id)

    def test_unassign_profile_clears_limits(self, cp_running, admin_headers):
        """Unassigning a profile should stop enforcing resource limits."""
        container = _discover_agent_container()

        # Record baseline (no profile) limits
        baseline = _get_container_resources(container)

        profile = self._create_profile(admin_headers, cpu_limit=0.25, pids_limit=50)
        profile_id = profile["id"]
        try:
            self._assign_profile(admin_headers, profile_id)

            # Wait for limits to apply
            assert self._wait_for_resource(container, "cpu_limit", 0.25), (
                "CPU limit did not propagate before unassign test"
            )

            # Unassign
            self._unassign_profile(admin_headers)

            # Heartbeat without profile should return no resource limits;
            # agent-manager should clear cpu_limit (set NanoCpus=0)
            deadline = time.time() + self.PROPAGATION_TIMEOUT
            cleared = False
            while time.time() < deadline:
                resources = _get_container_resources(container)
                # After unassign, cpu_limit should revert (None means unrestricted)
                if resources["cpu_limit"] is None or resources["cpu_limit"] != 0.25:
                    cleared = True
                    break
                time.sleep(self.POLL_INTERVAL)
            assert cleared, "Resource limits were not cleared after profile unassignment"
        finally:
            self._delete_profile(admin_headers, profile_id)


# ---------------------------------------------------------------------------
# TestDynamicScaling
# ---------------------------------------------------------------------------

class TestDynamicScaling:
    """Verify dynamic agent container scaling.

    Placed last because it modifies the container count.
    """

    SCRIPT_DIR = Path(__file__).parent
    DP_DIR = Path(__file__).parent.parent / "data_plane"
    COMPOSE_CMD = [
        "docker", "compose",
        "-f", "docker-compose.yml",
        "-f", str(Path(__file__).parent / "docker-compose.e2e.yml"),
        "--profile", "dev",
        "--profile", "managed",
        "--profile", "auditing",
    ]

    @pytest.fixture(autouse=True)
    def _restore_scale(self):
        """Restore to 2 agents after each test."""
        yield
        subprocess.run(
            self.COMPOSE_CMD + ["up", "-d", "--scale", "agent-dev=2", "--no-recreate"],
            cwd=self.DP_DIR,
            capture_output=True,
            timeout=60,
        )
        # Wait for scale to stabilise
        deadline = time.time() + 30
        while time.time() < deadline:
            if len(_discover_all_agent_containers()) == 2:
                break
            time.sleep(2)

    def test_scale_up_agents(self, cp_running):
        """Scaling to 3 agents should create a third container that can proxy."""
        subprocess.run(
            self.COMPOSE_CMD + ["up", "-d", "--scale", "agent-dev=3", "--no-recreate"],
            cwd=self.DP_DIR,
            capture_output=True,
            timeout=60,
        )

        # Poll until 3 containers are discovered
        deadline = time.time() + 30
        names = []
        while time.time() < deadline:
            names = _discover_all_agent_containers()
            if len(names) >= 3:
                break
            time.sleep(2)
        assert len(names) >= 3, (
            f"Expected >=3 agent containers after scale-up, found {len(names)}: {names}"
        )

        # Verify all 3 can proxy
        for name in names:
            result = exec_in_agent(
                f"curl -s -o /dev/null -w '%{{http_code}}' -x {PROXY} "
                f"--connect-timeout 5 http://api.github.com/",
                container_name=name,
            )
            code = result.stdout.strip()
            assert code.isdigit() and int(code) < 500, (
                f"{name}: proxy request failed with {code}"
            )

    def test_scale_down_agents(self, cp_running):
        """Scaling from 3 to 2 should remove the extra container."""
        # First scale up to 3
        subprocess.run(
            self.COMPOSE_CMD + ["up", "-d", "--scale", "agent-dev=3", "--no-recreate"],
            cwd=self.DP_DIR,
            capture_output=True,
            timeout=60,
        )
        deadline = time.time() + 30
        while time.time() < deadline:
            if len(_discover_all_agent_containers()) >= 3:
                break
            time.sleep(2)

        # Scale down to 2
        subprocess.run(
            self.COMPOSE_CMD + ["up", "-d", "--scale", "agent-dev=2", "--no-recreate"],
            cwd=self.DP_DIR,
            capture_output=True,
            timeout=60,
        )

        deadline = time.time() + 30
        names = []
        while time.time() < deadline:
            names = _discover_all_agent_containers()
            if len(names) == 2:
                break
            time.sleep(2)
        assert len(names) == 2, (
            f"Expected 2 agent containers after scale-down, found {len(names)}: {names}"
        )
