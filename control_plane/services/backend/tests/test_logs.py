"""Tests for audit log and log ingestion endpoints."""


class TestAuditLogs:
    """Test audit log endpoints."""

    def test_get_audit_logs(self, client, auth_headers):
        """Should retrieve audit logs."""
        response = client.get("/api/v1/audit-logs", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert "items" in data
        assert "total" in data
        assert isinstance(data["items"], list)

    def test_audit_logs_pagination(self, client, auth_headers):
        """Should support limit and offset."""
        response = client.get(
            "/api/v1/audit-logs?limit=10&offset=0",
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

    def test_audit_logs_filtering(self, client, auth_headers):
        """Should support audit log filtering by event type."""
        response = client.get(
            "/api/v1/audit-logs?event_type=stcp_secret_generated",
            headers=auth_headers,
        )
        assert response.status_code == 200
        data = response.json()
        assert "items" in data
        assert "total" in data

    def test_audit_logs_search(self, client, auth_headers):
        """Should support text search in audit logs."""
        response = client.get(
            "/api/v1/audit-logs?search=agent",
            headers=auth_headers,
        )
        assert response.status_code == 200
        assert "items" in response.json()

    def test_log_query_requires_auth(self, client):
        """Log query should require authentication."""
        response = client.get("/api/v1/logs/query")
        assert response.status_code in (401, 403)
