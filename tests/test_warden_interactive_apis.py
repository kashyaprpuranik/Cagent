"""Unit tests for warden interactive-mode API endpoints.

Tests the new endpoints added for interactive mode:
- /api/commands/* (cell restart, stop, start, wipe)
- /api/status, /api/metrics, /api/disk, /api/processes, /api/network
- /api/policies/apply, /api/policies/active
- /api/logs/search
- /api/health/deep
"""

import os
import sys
from unittest.mock import MagicMock, patch

# Mock docker before importing warden modules
mock_docker = MagicMock()
sys.modules["docker"] = MagicMock()
sys.modules["docker"].from_env.return_value = mock_docker
sys.modules["docker"].errors = MagicMock()
sys.modules["docker"].errors.NotFound = Exception
mock_docker.containers.list.return_value = []

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "services", "warden")))

import main
from fastapi.testclient import TestClient

client = TestClient(main.app)


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------
class TestDeepHealth:
    """Test /api/health/deep endpoint (checks OpenObserve)."""

    def test_deep_health_oo_healthy(self):
        """Deep health should include OO check when OO is healthy."""
        mock_container = MagicMock()
        mock_container.status = "running"
        mock_container.attrs = {"State": {"StartedAt": "2026-01-01T00:00:00Z"}}
        mock_container.exec_run.return_value = MagicMock(exit_code=0)

        with (
            patch("routers.health.docker_client") as mock_dc,
            patch("openobserve_client.is_openobserve_healthy", return_value=True),
        ):
            mock_dc.containers.get.return_value = mock_container
            r = client.get("/api/health/deep")

        assert r.status_code == 200
        data = r.json()
        assert "checks" in data
        assert "openobserve" in data["checks"]
        assert data["checks"]["openobserve"]["status"] == "healthy"

    def test_deep_health_oo_unhealthy(self):
        """Deep health should show degraded when OO is down."""
        mock_container = MagicMock()
        mock_container.status = "running"
        mock_container.attrs = {"State": {"StartedAt": "2026-01-01T00:00:00Z"}}
        mock_container.exec_run.return_value = MagicMock(exit_code=0)

        with (
            patch("routers.health.docker_client") as mock_dc,
            patch("openobserve_client.is_openobserve_healthy", return_value=False),
        ):
            mock_dc.containers.get.return_value = mock_container
            r = client.get("/api/health/deep")

        assert r.status_code == 200
        data = r.json()
        assert data["checks"]["openobserve"]["status"] == "unhealthy"
        assert data["status"] == "degraded"


# ---------------------------------------------------------------------------
# Status endpoints
# ---------------------------------------------------------------------------
class TestStatusEndpoints:
    """Test system status and metrics endpoints.

    These endpoints call real psutil functions against the host system.
    We test through the FastAPI test client (unit-test style) and verify
    the response shapes. No psutil mocking needed — the real system provides
    valid data.
    """

    def test_status_endpoint(self):
        """GET /api/status should return system summary."""
        r = client.get("/api/status")
        assert r.status_code == 200
        data = r.json()
        assert "cpu_percent" in data
        assert isinstance(data["cpu_percent"], (int, float))
        assert "memory_mb" in data
        assert data["memory_mb"] > 0
        assert "disk_used_bytes" in data
        assert "load_average" in data
        assert len(data["load_average"]) == 3

    def test_metrics_endpoint(self):
        """GET /api/metrics should return detailed metrics."""
        r = client.get("/api/metrics")
        assert r.status_code == 200
        data = r.json()
        assert "cpu_count" in data
        assert data["cpu_count"] >= 1
        assert "memory_percent" in data
        assert "disk_free_bytes" in data

    def test_disk_endpoint(self):
        """GET /api/disk should return disk usage per mount."""
        r = client.get("/api/disk")
        assert r.status_code == 200
        data = r.json()
        assert "disks" in data
        assert isinstance(data["disks"], list)
        assert len(data["disks"]) >= 1
        assert "path" in data["disks"][0]
        assert "total_bytes" in data["disks"][0]

    def test_processes_endpoint(self):
        """GET /api/processes should return top processes."""
        r = client.get("/api/processes")
        assert r.status_code == 200
        data = r.json()
        assert "processes" in data
        assert isinstance(data["processes"], list)
        assert len(data["processes"]) >= 1
        proc = data["processes"][0]
        assert "pid" in proc
        assert "name" in proc

    def test_network_endpoint(self):
        """GET /api/network should return network stats."""
        r = client.get("/api/network")
        assert r.status_code == 200
        data = r.json()
        assert "interfaces" in data
        assert isinstance(data["interfaces"], list)

    def test_containers_status_endpoint(self):
        """GET /api/containers (status router) should return container statuses."""
        mock_container = MagicMock()
        mock_container.status = "running"
        mock_container.attrs = {"State": {"StartedAt": "2026-01-01T00:00:00Z", "Health": {"Status": "healthy"}}}
        mock_container.image = MagicMock(tags=["cell:lean"])

        with patch("routers.status.docker_client") as mock_dc:
            mock_dc.containers.get.return_value = mock_container
            r = client.get("/api/containers")

        assert r.status_code == 200
        data = r.json()
        assert "containers" in data


# ---------------------------------------------------------------------------
# Policies
# ---------------------------------------------------------------------------
class TestPolicyEndpoints:
    """Test policy push/query endpoints."""

    def test_get_active_policies(self):
        """GET /api/policies/active should return current policies."""
        mock_config = "domains:\n  - domain: api.openai.com\n  - domain: pypi.org\n"
        with patch("routers.policies.Path") as mock_path:
            mock_path_instance = MagicMock()
            mock_path_instance.read_text.return_value = mock_config
            mock_path.return_value = mock_path_instance
            r = client.get("/api/policies/active")

        assert r.status_code == 200
        data = r.json()
        assert "policies" in data
        assert "count" in data
        assert data["count"] == 2
        domains = [p["domain"] for p in data["policies"]]
        assert "api.openai.com" in domains
        assert "pypi.org" in domains

    def test_apply_policies_updates_config(self):
        """POST /api/policies/apply should update config and regenerate."""
        mock_config = "domains:\n  - domain: old.com\n"
        with (
            patch("routers.policies.Path") as mock_path,
            patch("routers.policies.ConfigGenerator"),
            patch("routers.policies.docker_client"),
        ):
            mock_path_instance = MagicMock()
            mock_path_instance.read_text.return_value = mock_config
            mock_path.return_value = mock_path_instance

            r = client.post(
                "/api/policies/apply",
                json={
                    "policies": [
                        {"domain": "api.github.com"},
                        {"domain": "pypi.org", "allowed_paths": ["/simple/"]},
                        {"domain": "api.openai.com", "requests_per_minute": 100, "burst_size": 20},
                    ]
                },
            )

        assert r.status_code == 200
        data = r.json()
        assert data["status"] == "applied"
        assert data["policy_count"] == 3

    def test_apply_policies_invalid_input(self):
        """POST /api/policies/apply with non-list policies should fail validation."""
        r = client.post("/api/policies/apply", json={"policies": "not-a-list"})
        assert r.status_code == 422

    def test_apply_policies_missing_domain(self):
        """POST /api/policies/apply with missing domain field should fail validation."""
        r = client.post("/api/policies/apply", json={"policies": [{"allowed_paths": ["/"]}]})
        assert r.status_code == 422

    def test_apply_policies_rejects_domain_injection(self):
        """Domains with newlines/braces/special chars should be rejected."""
        for bad_domain in [
            "evil.com\nforward . 8.8.8.8",
            "evil.com}",
            "evil.com{",
            "evil.com; rm -rf /",
            "evil.com\tevil",
            "",
        ]:
            r = client.post("/api/policies/apply", json={"policies": [{"domain": bad_domain}]})
            assert r.status_code == 422, f"Domain {bad_domain!r} was not rejected"

    def test_apply_policies_accepts_valid_domains(self):
        """Valid domain patterns should be accepted."""
        mock_config = "domains: []\n"
        with (
            patch("routers.policies.Path") as mock_path,
            patch("routers.policies.ConfigGenerator"),
            patch("routers.policies.docker_client"),
        ):
            mock_path_instance = MagicMock()
            mock_path_instance.read_text.return_value = mock_config
            mock_path.return_value = mock_path_instance

            r = client.post(
                "/api/policies/apply",
                json={
                    "policies": [
                        {"domain": "api.github.com"},
                        {"domain": "*.openai.com"},
                        {"domain": "my-service_v2.example.com"},
                    ]
                },
            )
        assert r.status_code == 200


# ---------------------------------------------------------------------------
# Log Search
# ---------------------------------------------------------------------------
class TestLogSearch:
    """Test log search endpoint (OO-backed).

    The search_logs endpoint uses lazy imports:
        from openobserve_client import datetime_to_us, now_us, query_openobserve
    so we must patch at the openobserve_client module level.
    """

    def test_search_logs_returns_hits(self):
        """GET /api/logs/search should return OO query results."""
        with (
            patch("openobserve_client.query_openobserve") as mock_query,
            patch("openobserve_client.now_us", return_value=9999999999),
            patch("openobserve_client.datetime_to_us", return_value=0),
        ):
            mock_query.return_value = [
                {"message": "test log", "source": "envoy", "_timestamp": 123456},
            ]
            r = client.get("/api/logs/search", params={"query": "test", "limit": 10})

        assert r.status_code == 200
        data = r.json()
        assert "hits" in data
        assert len(data["hits"]) == 1
        assert data["hits"][0]["message"] == "test log"

    def test_search_logs_with_source_filter(self):
        """Search with source filter should include WHERE clause."""
        with (
            patch("openobserve_client.query_openobserve") as mock_query,
            patch("openobserve_client.now_us", return_value=9999999999),
        ):
            mock_query.return_value = []
            r = client.get("/api/logs/search", params={"source": "envoy"})

            assert r.status_code == 200
            # Verify the SQL query includes the source filter
            call_args = mock_query.call_args
            sql = call_args[0][0]
            assert "source = 'envoy'" in sql

    def test_search_logs_with_time_range(self):
        """Search with explicit time range should use provided values."""
        with (
            patch("openobserve_client.query_openobserve") as mock_query,
            patch("openobserve_client.now_us", return_value=9999999999),
        ):
            mock_query.return_value = []
            r = client.get(
                "/api/logs/search",
                params={
                    "start": "2026-01-01T00:00:00+00:00",
                    "end": "2026-01-02T00:00:00+00:00",
                },
            )
            assert r.status_code == 200

    def test_search_logs_oo_import_error_returns_empty(self):
        """If openobserve_client is not importable, should return empty results.

        The endpoint catches ImportError (OO client not installed/available)
        and returns empty results gracefully.
        """
        import builtins

        original_import = builtins.__import__

        def mock_import(name, *args, **kwargs):
            if name == "openobserve_client":
                raise ImportError("No module named 'openobserve_client'")
            return original_import(name, *args, **kwargs)

        with patch("builtins.__import__", side_effect=mock_import):
            # Clear the cached module so the lazy import re-executes
            saved = sys.modules.pop("openobserve_client", None)
            try:
                r = client.get("/api/logs/search", params={"query": "test"})
            finally:
                if saved is not None:
                    sys.modules["openobserve_client"] = saved

        assert r.status_code == 200
        data = r.json()
        assert data["hits"] == []
        assert data["total"] == 0

    def test_search_logs_escapes_sql_injection(self):
        """User input with single quotes should be escaped in SQL."""
        with (
            patch("openobserve_client.query_openobserve") as mock_query,
            patch("openobserve_client.now_us", return_value=9999999999),
        ):
            mock_query.return_value = []
            r = client.get(
                "/api/logs/search",
                params={"query": "'; DROP TABLE default; --", "source": "x'y"},
            )

            assert r.status_code == 200
            sql = mock_query.call_args[0][0]
            # Single quotes must be doubled, not left raw
            assert "''; DROP TABLE" in sql
            assert "source = 'x''y'" in sql


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------
class TestCommandEndpoints:
    """Test cell command endpoints."""

    def test_restart_cell(self):
        """POST /api/commands/restart should restart the cell container."""
        mock_container = MagicMock()
        mock_container.name = "cell"

        with patch("routers.commands.discover_cell_containers", return_value=[mock_container]):
            r = client.post("/api/commands/restart")

        assert r.status_code == 200
        data = r.json()
        assert data["command"] == "restart"
        assert data["status"] == "completed"
        mock_container.restart.assert_called_once()

    def test_stop_cell(self):
        """POST /api/commands/stop should stop the cell container."""
        mock_container = MagicMock()
        mock_container.name = "cell"

        with patch("routers.commands.discover_cell_containers", return_value=[mock_container]):
            r = client.post("/api/commands/stop")

        assert r.status_code == 200
        assert r.json()["command"] == "stop"
        mock_container.stop.assert_called_once()

    def test_start_cell(self):
        """POST /api/commands/start should start the cell container."""
        mock_container = MagicMock()
        mock_container.name = "cell"

        with patch("routers.commands.discover_cell_containers", return_value=[mock_container]):
            r = client.post("/api/commands/start")

        assert r.status_code == 200
        assert r.json()["command"] == "start"
        mock_container.start.assert_called_once()

    def test_command_no_cell_returns_404(self):
        """Commands should return 404 when no cell container exists."""
        with patch("routers.commands.discover_cell_containers", return_value=[]):
            r = client.post("/api/commands/restart")

        assert r.status_code == 404
        assert "No cell" in r.json()["detail"]
