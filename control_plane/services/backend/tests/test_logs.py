"""Tests for audit trail, log ingestion/query hardening, and multi-tenant routing."""

from datetime import datetime, timedelta, timezone
from unittest.mock import patch


class TestAuditTrail:
    """Test audit trail endpoints."""

    def test_get_audit_trail(self, client, auth_headers):
        """Should retrieve audit trail entries."""
        response = client.get("/api/v1/audit-trail", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert "items" in data
        assert "total" in data
        assert isinstance(data["items"], list)

    def test_audit_trail_pagination(self, client, auth_headers):
        """Should support limit and offset."""
        response = client.get(
            "/api/v1/audit-trail?limit=10&offset=0",
            headers=auth_headers
        )
        assert response.status_code == 200


class TestLogEndpoints:
    """Test log ingestion and query endpoints."""

    def _create_agent_token(self, client, auth_headers, agent_id):
        """Helper: create agent via heartbeat and return an agent token."""
        client.post(
            f"/api/v1/agent/heartbeat?agent_id={agent_id}",
            headers=auth_headers,
            json={"status": "running"}
        )
        token_response = client.post(
            "/api/v1/tokens",
            headers=auth_headers,
            json={"name": f"{agent_id}-token", "token_type": "agent", "agent_id": agent_id}
        )
        return token_response.json()["token"]

    def test_log_ingest_requires_agent_token(self, client, auth_headers):
        """Admin tokens should not be able to ingest logs."""
        response = client.post(
            "/api/v1/logs/ingest",
            headers=auth_headers,
            json={"logs": [{"message": "test", "source": "agent"}]}
        )
        assert response.status_code == 403
        assert "agent tokens" in response.json()["detail"].lower()

    def test_audit_trail_filtering(self, client, auth_headers):
        """Should support audit trail filtering by event type."""
        response = client.get(
            "/api/v1/audit-trail?event_type=stcp_secret_generated",
            headers=auth_headers,
        )
        assert response.status_code == 200
        data = response.json()
        assert "items" in data
        assert "total" in data

    def test_audit_trail_search(self, client, auth_headers):
        """Should support text search in audit trail."""
        response = client.get(
            "/api/v1/audit-trail?search=agent",
            headers=auth_headers,
        )
        assert response.status_code == 200
        assert "items" in response.json()

    def test_log_query_requires_auth(self, client):
        """Log query should require authentication."""
        response = client.get("/api/v1/logs/query")
        assert response.status_code in (401, 403)


class TestLogIngestionHardening:
    """Test ingestion hardening (independent of multi-tenancy toggle)."""

    def _create_agent_token(self, client, auth_headers, agent_id):
        """Helper: create agent via heartbeat and return an agent token."""
        client.post(
            f"/api/v1/agent/heartbeat?agent_id={agent_id}",
            headers=auth_headers,
            json={"status": "running"}
        )
        token_response = client.post(
            "/api/v1/tokens",
            headers=auth_headers,
            json={"name": f"{agent_id}-token", "token_type": "agent", "agent_id": agent_id}
        )
        return token_response.json()["token"]

    def test_ingest_batch_too_large(self, client, auth_headers, mock_openobserve):
        """Batch with >500 logs should be rejected with 413."""
        agent_token = self._create_agent_token(client, auth_headers, "batch-test-agent")
        headers = {"Authorization": f"Bearer {agent_token}"}

        logs = [{"message": f"log {i}", "source": "agent"} for i in range(501)]
        response = client.post(
            "/api/v1/logs/ingest",
            headers=headers,
            json={"logs": logs}
        )
        assert response.status_code == 413
        assert "Batch too large" in response.json()["detail"]

    def test_ingest_old_log_rejected(self, client, auth_headers, mock_openobserve):
        """Logs older than LOG_INGEST_MAX_AGE_HOURS should be rejected with 400."""
        agent_token = self._create_agent_token(client, auth_headers, "old-log-agent")
        headers = {"Authorization": f"Bearer {agent_token}"}

        old_ts = (datetime.now(timezone.utc) - timedelta(hours=25)).isoformat()
        response = client.post(
            "/api/v1/logs/ingest",
            headers=headers,
            json={"logs": [{"message": "old log", "source": "agent", "timestamp": old_ts}]}
        )
        assert response.status_code == 400
        assert "older than" in response.json()["detail"]

    def test_ingest_within_limits(self, client, auth_headers, mock_openobserve):
        """Valid batch within limits should succeed."""
        agent_token = self._create_agent_token(client, auth_headers, "valid-agent")
        headers = {"Authorization": f"Bearer {agent_token}"}

        response = client.post(
            "/api/v1/logs/ingest",
            headers=headers,
            json={"logs": [{"message": "test log", "source": "agent"}]}
        )
        assert response.status_code == 200
        assert response.json()["status"] == "ok"
        assert response.json()["count"] == 1


class TestLogQueryHardening:
    """Test query hardening (independent of multi-tenancy toggle)."""

    def test_query_time_range_too_large(self, client, dev_headers, mock_openobserve):
        """Time range > LOG_QUERY_MAX_TIME_RANGE_DAYS should be rejected with 400."""
        start = (datetime.now(timezone.utc) - timedelta(days=31)).isoformat() + "Z"
        end = datetime.now(timezone.utc).isoformat() + "Z"
        response = client.get(
            f"/api/v1/logs/query?start={start}&end={end}",
            headers=dev_headers
        )
        assert response.status_code == 400
        assert "exceeds maximum" in response.json()["detail"]

    def test_query_within_time_range(self, client, dev_headers, mock_openobserve):
        """Query within allowed time range should succeed."""
        start = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat() + "Z"
        end = datetime.now(timezone.utc).isoformat() + "Z"
        response = client.get(
            f"/api/v1/logs/query?start={start}&end={end}",
            headers=dev_headers
        )
        assert response.status_code == 200


class TestMultiTenantIngestion:
    """Test multi-tenant log ingestion routing (OPENOBSERVE_MULTI_TENANT=true)."""

    def _create_agent_token(self, client, auth_headers, agent_id):
        """Helper: create agent via heartbeat and return an agent token."""
        client.post(
            f"/api/v1/agent/heartbeat?agent_id={agent_id}",
            headers=auth_headers,
            json={"status": "running"}
        )
        token_response = client.post(
            "/api/v1/tokens",
            headers=auth_headers,
            json={"name": f"{agent_id}-token", "token_type": "agent", "agent_id": agent_id}
        )
        return token_response.json()["token"]

    @patch("control_plane.routes.logs.OPENOBSERVE_MULTI_TENANT", True)
    @patch("control_plane.openobserve.OPENOBSERVE_MULTI_TENANT", True)
    def test_ingest_routes_to_tenant_org(self, client, auth_headers, mock_openobserve):
        """With multi-tenant enabled, ingest should route to tenant org URL."""
        agent_token = self._create_agent_token(client, auth_headers, "mt-ingest-agent")
        headers = {"Authorization": f"Bearer {agent_token}"}

        response = client.post(
            "/api/v1/logs/ingest",
            headers=headers,
            json={"logs": [{"message": "test", "source": "envoy"}]}
        )
        assert response.status_code == 200

        # Verify URL includes tenant slug (default tenant slug is "default")
        post_calls = [c for c in mock_openobserve if c["method"] == "POST"]
        ingest_calls = [c for c in post_calls if "/_json" in c["url"]]
        assert len(ingest_calls) >= 1
        # The URL should contain the tenant slug and 'logs' stream
        assert "/default/logs/_json" in ingest_calls[-1]["url"]

    @patch("control_plane.routes.logs.OPENOBSERVE_MULTI_TENANT", True)
    @patch("control_plane.openobserve.OPENOBSERVE_MULTI_TENANT", True)
    def test_ingest_uses_write_credentials(self, client, auth_headers, db_session, mock_openobserve):
        """With multi-tenant enabled and tenant settings, should use writer credentials."""
        from control_plane.models import Tenant
        from control_plane.openobserve import store_org_credentials

        # Set up credentials for the default tenant
        tenant = db_session.query(Tenant).filter(Tenant.slug == "default").first()
        assert tenant is not None
        store_org_credentials(
            tenant, db_session,
            "writer@default.cagent", "test-writer-pw",
            "reader@default.cagent", "test-reader-pw",
        )

        agent_token = self._create_agent_token(client, auth_headers, "mt-cred-agent")
        headers = {"Authorization": f"Bearer {agent_token}"}

        response = client.post(
            "/api/v1/logs/ingest",
            headers=headers,
            json={"logs": [{"message": "test", "source": "agent"}]}
        )
        assert response.status_code == 200

        # Verify writer email was used in auth
        ingest_calls = [c for c in mock_openobserve if c["method"] == "POST" and "/_json" in c["url"]]
        assert len(ingest_calls) >= 1
        auth = ingest_calls[-1].get("auth")
        assert auth is not None
        assert auth[0] == "writer@default.cagent"

    @patch("control_plane.routes.logs.OPENOBSERVE_MULTI_TENANT", True)
    @patch("control_plane.openobserve.OPENOBSERVE_MULTI_TENANT", True)
    def test_query_uses_read_credentials(self, client, dev_headers, db_session, mock_openobserve):
        """With multi-tenant enabled and tenant settings, should use reader credentials."""
        from control_plane.models import Tenant
        from control_plane.openobserve import store_org_credentials

        # Set up credentials for the default tenant
        tenant = db_session.query(Tenant).filter(Tenant.slug == "default").first()
        assert tenant is not None
        store_org_credentials(
            tenant, db_session,
            "writer@default.cagent", "test-writer-pw",
            "reader@default.cagent", "test-reader-pw",
        )

        response = client.get(
            "/api/v1/logs/query",
            headers=dev_headers
        )
        assert response.status_code == 200

        # Verify reader email was used in auth
        search_calls = [c for c in mock_openobserve if c["method"] == "POST" and "/_search" in c["url"]]
        assert len(search_calls) >= 1
        auth = search_calls[-1].get("auth")
        assert auth is not None
        assert auth[0] == "reader@default.cagent"


class TestMultiTenantLifecycle:
    """Test tenant create/delete with OpenObserve provisioning."""

    @patch("control_plane.routes.tenants.OPENOBSERVE_MULTI_TENANT", True)
    def test_create_tenant_provisions_org(self, client, super_admin_headers, mock_openobserve):
        """Creating a tenant should provision an OpenObserve org."""
        response = client.post(
            "/api/v1/tenants",
            headers=super_admin_headers,
            json={"name": "Test Org", "slug": "test-org"}
        )
        assert response.status_code == 200

        # Verify provisioning calls were made (2 user creation POSTs)
        user_calls = [c for c in mock_openobserve
                      if c["method"] == "POST" and "/users" in c["url"]]
        assert len(user_calls) == 2
        # Verify URLs include the tenant slug
        assert "test-org" in user_calls[0]["url"]
        assert "test-org" in user_calls[1]["url"]

    @patch("control_plane.routes.tenants.OPENOBSERVE_MULTI_TENANT", True)
    def test_create_tenant_rollback_on_failure(self, client, super_admin_headers, db_session):
        """If OpenObserve provisioning fails, tenant should be rolled back."""
        from control_plane.models import Tenant

        async def fail_provision(slug):
            raise RuntimeError("OpenObserve is down")

        with patch("control_plane.routes.tenants.provision_tenant_org", side_effect=fail_provision):
            response = client.post(
                "/api/v1/tenants",
                headers=super_admin_headers,
                json={"name": "Fail Org", "slug": "fail-org"}
            )
            assert response.status_code == 502

        # Verify tenant was not persisted
        tenant = db_session.query(Tenant).filter(Tenant.slug == "fail-org").first()
        assert tenant is None

    @patch("control_plane.routes.tenants.OPENOBSERVE_MULTI_TENANT", True)
    def test_delete_tenant_cleans_up_org(self, client, super_admin_headers, mock_openobserve, db_session):
        """Deleting a tenant should attempt to clean up OpenObserve users."""
        # First create a tenant
        create_resp = client.post(
            "/api/v1/tenants",
            headers=super_admin_headers,
            json={"name": "Delete Me", "slug": "delete-me"}
        )
        assert create_resp.status_code == 200
        tenant_id = create_resp.json()["id"]

        # Clear tracked calls from creation
        mock_openobserve.clear()

        # Now delete it
        delete_resp = client.delete(
            f"/api/v1/tenants/{tenant_id}",
            headers=super_admin_headers
        )
        assert delete_resp.status_code == 200

        # Verify cleanup calls (2 DELETE calls for writer + reader users)
        delete_calls = [c for c in mock_openobserve if c["method"] == "DELETE"]
        assert len(delete_calls) == 2
        assert "delete-me" in delete_calls[0]["url"]
        assert "delete-me" in delete_calls[1]["url"]
