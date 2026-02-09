"""
End-to-end tests for Control Plane + Data Plane integration.

These tests require both stacks to be running via ./run.sh.
Run with: pytest test_cp_dp_e2e.py -v
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
    """Skip all tests if CP is unreachable."""
    try:
        r = requests.get(f"{CP_BASE}/health", timeout=5)
        r.raise_for_status()
    except Exception:
        pytest.skip("Control plane not reachable — run ./run.sh first")


@pytest.fixture(scope="session")
def agent_token():
    """Read the agent token written by run.sh."""
    token_file = SCRIPT_DIR / ".agent-token"
    if not token_file.exists():
        pytest.skip(".agent-token not found — run ./run.sh first")
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


def exec_in_agent(command: str) -> subprocess.CompletedProcess:
    """Execute a command inside the agent container."""
    return subprocess.run(
        ["docker", "exec", "agent", "sh", "-c", command],
        capture_output=True,
        text=True,
        timeout=30,
    )


def get_envoy_access_logs(tail: int = 100) -> list[dict]:
    """Get recent Envoy access log entries (JSON lines from stdout)."""
    result = subprocess.run(
        ["docker", "logs", "--tail", str(tail), "envoy-proxy"],
        capture_output=True,
        text=True,
        timeout=10,
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


# ---------------------------------------------------------------------------
# TestHeartbeatAndRegistration
# ---------------------------------------------------------------------------

class TestHeartbeatAndRegistration:
    """Verify that agent-manager heartbeats register the agent on CP."""

    def test_agent_registered(self, cp_running, admin_headers):
        """Agent should appear in the agents list after heartbeat."""
        r = requests.get(f"{CP_BASE}/api/v1/agents", headers=admin_headers)
        assert r.status_code == 200
        agents = r.json()
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

        # Wait for 2 heartbeat cycles (HEARTBEAT_INTERVAL=5 in run.sh)
        time.sleep(12)

        # Check that command was executed and result reported
        r = requests.get(
            f"{CP_BASE}/api/v1/agents/{AGENT_ID}/status",
            headers=admin_headers,
        )
        assert r.status_code == 200
        data = r.json()
        assert data["last_command"] == "restart", f"Expected last_command=restart, got {data}"
        assert data["last_command_result"] == "success", f"Restart failed: {data}"


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
            for p in r.json():
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
        agents = r.json()
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
            for p in r.json():
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
            "curl -s --max-time 10 http://echo.devbox.local/headers"
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
        exec_in_agent(f"curl -s -o /dev/null http://openai.devbox.local{marker}")
        time.sleep(2)

        entries = get_envoy_access_logs()
        matching = [e for e in entries if marker in e.get("path", "")]
        assert len(matching) > 0, (
            f"No log entry found for path {marker}. "
            f"Total entries: {len(entries)}"
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
        assert "openai.devbox.local" in entry["authority"]

    def test_envoy_logs_credential_injection(self, cp_running):
        """Access log should show credential_injected=true for echo requests."""
        marker = f"/e2e-cred-log-{int(time.time())}"
        exec_in_agent(
            f"curl -s -o /dev/null http://echo.devbox.local{marker}"
        )
        time.sleep(2)

        entries = get_envoy_access_logs()
        matching = [e for e in entries if marker in e.get("path", "")]
        assert len(matching) > 0, (
            f"No log entry found for echo request {marker}"
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
            f"curl -s -o /dev/null -w '%{{http_code}}' "
            f"http://blocked.example.com{marker}"
        )
        # Envoy catch-all returns 403 for unlisted domains
        assert "403" in result.stdout, (
            f"Expected 403 for blocked domain, got: {result.stdout}"
        )

        time.sleep(2)
        entries = get_envoy_access_logs()
        matching = [e for e in entries if marker in e.get("path", "")]
        assert len(matching) > 0, (
            f"No log entry for blocked request {marker}"
        )

        entry = matching[-1]
        # response_code may be int or string depending on envoy version
        assert str(entry.get("response_code")) == "403", (
            f"Expected response_code=403 in log, got: "
            f"{entry.get('response_code')}"
        )
