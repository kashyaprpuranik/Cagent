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


PROXY = "http://10.200.1.10:8443"


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
        assert data["status"] in ("running", "exited", "not_found"), f"Unexpected status: {data['status']}"
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

    def test_create_policy(self, cp_running, admin_headers):
        """Admin can create a domain policy."""
        r = requests.post(
            f"{CP_BASE}/api/v1/domain-policies",
            headers=admin_headers,
            json={
                "domain": "e2e-test.example.com",
                "alias": "e2etest",
                "description": "E2E test policy",
            },
        )
        assert r.status_code == 200
        data = r.json()
        assert data["domain"] == "e2e-test.example.com"
        assert data["alias"] == "e2etest"
        assert data["enabled"] is True

    def test_agent_sees_policy(self, cp_running, admin_headers, agent_headers):
        """Agent token can see exported domain policies."""
        # Create a policy first
        requests.post(
            f"{CP_BASE}/api/v1/domain-policies",
            headers=admin_headers,
            json={"domain": "e2e-test.example.com"},
        )

        # Agent should see it via export
        r = requests.get(
            f"{CP_BASE}/api/v1/domain-policies/export",
            headers=agent_headers,
        )
        assert r.status_code == 200
        data = r.json()
        assert "e2e-test.example.com" in data["domains"]

    def test_policy_export(self, cp_running, admin_headers, agent_headers):
        """Export endpoint returns domains list for CoreDNS."""
        requests.post(
            f"{CP_BASE}/api/v1/domain-policies",
            headers=admin_headers,
            json={"domain": "e2e-test.example.com"},
        )

        r = requests.get(
            f"{CP_BASE}/api/v1/domain-policies/export",
            headers=agent_headers,
        )
        assert r.status_code == 200
        data = r.json()
        assert "domains" in data
        assert "generated_at" in data

    def test_policy_lookup(self, cp_running, admin_headers, agent_headers):
        """for-domain endpoint returns policy details."""
        requests.post(
            f"{CP_BASE}/api/v1/domain-policies",
            headers=admin_headers,
            json={
                "domain": "e2e-test.example.com",
                "requests_per_minute": 42,
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
        self, cp_running, admin_headers, agent_headers
    ):
        """CP should store credentials and return them via for-domain endpoint."""
        # Create domain policy with credential
        r = requests.post(
            f"{CP_BASE}/api/v1/domain-policies",
            headers=admin_headers,
            json={
                "domain": "e2e-cred-test.example.com",
                "alias": "e2ecred",
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
        entry = self._wait_for_blocked_in_cp(admin_headers, timeout=45.0)
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

    def _create_ttl_policy(self, admin_headers, expires_at):
        """Helper: create a TTL policy and track its ID for cleanup."""
        r = requests.post(
            f"{CP_BASE}/api/v1/domain-policies",
            headers=admin_headers,
            json={
                "domain": self.TTL_DOMAIN,
                "expires_at": expires_at,
            },
        )
        assert r.status_code == 200, f"Failed to create TTL policy: {r.text}"
        self._created_policy_ids.append(r.json()["id"])
        return r.json()

    def test_create_policy_with_expires_at(self, cp_running, admin_headers, agent_headers):
        """Create a policy with expires_at, verify it appears in list and export."""
        from datetime import datetime, timedelta, timezone
        expires = (datetime.now(timezone.utc) + timedelta(seconds=60)).isoformat()

        data = self._create_ttl_policy(admin_headers, expires)
        assert data["domain"] == self.TTL_DOMAIN
        assert data["expires_at"] is not None

        # Should appear in list
        r = requests.get(
            f"{CP_BASE}/api/v1/domain-policies", headers=admin_headers
        )
        assert r.status_code == 200
        domains = [p["domain"] for p in r.json()]
        assert self.TTL_DOMAIN in domains

        # Should appear in export
        r = requests.get(
            f"{CP_BASE}/api/v1/domain-policies/export", headers=agent_headers
        )
        assert r.status_code == 200
        assert self.TTL_DOMAIN in r.json()["domains"]

    def test_expired_policy_filtered(self, cp_running, admin_headers, agent_headers):
        """An expired policy should be filtered from list, export, and for-domain."""
        from datetime import datetime, timedelta, timezone
        expires = (datetime.now(timezone.utc) + timedelta(seconds=2)).isoformat()

        self._create_ttl_policy(admin_headers, expires)

        # Wait for expiry
        time.sleep(4)

        # Should NOT appear in list
        r = requests.get(
            f"{CP_BASE}/api/v1/domain-policies", headers=admin_headers
        )
        assert r.status_code == 200
        domains = [p["domain"] for p in r.json()]
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

    def test_policy_for_domain_respects_expiry(self, cp_running, admin_headers, agent_headers):
        """for-domain lookup should not match an expired policy."""
        from datetime import datetime, timedelta, timezone
        expires = (datetime.now(timezone.utc) + timedelta(seconds=2)).isoformat()

        self._create_ttl_policy(admin_headers, expires)

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
