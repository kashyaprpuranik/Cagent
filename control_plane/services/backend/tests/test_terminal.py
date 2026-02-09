"""Tests for terminal ticket creation and session listing."""


class TestTerminalTicketAndSessions:
    """Test terminal ticket creation and session listing."""

    def _create_online_agent_with_stcp(self, client, auth_headers, agent_id):
        """Helper: create an agent that is online and has STCP configured."""
        client.post(
            f"/api/v1/agent/heartbeat?agent_id={agent_id}",
            headers=auth_headers,
            json={"status": "running"}
        )
        client.post(f"/api/v1/agents/{agent_id}/stcp-secret", headers=auth_headers)

    def test_create_terminal_ticket(self, client, auth_headers, super_admin_headers):
        """Should create a terminal ticket for an online agent."""
        self._create_online_agent_with_stcp(client, auth_headers, "ticket-test-agent")

        response = client.post(
            "/api/v1/terminal/ticket-test-agent/ticket",
            headers=super_admin_headers,
        )
        assert response.status_code == 200
        data = response.json()
        assert "ticket" in data
        assert len(data["ticket"]) > 20
        assert data["expires_in_seconds"] > 0

    def test_create_terminal_ticket_agent_not_found(self, client, super_admin_headers):
        """Should return 404 for non-existent agent."""
        response = client.post(
            "/api/v1/terminal/nonexistent-agent/ticket",
            headers=super_admin_headers,
        )
        assert response.status_code == 404

    def test_create_terminal_ticket_no_stcp(self, client, auth_headers, super_admin_headers):
        """Should fail when STCP is not configured."""
        client.post(
            "/api/v1/agent/heartbeat?agent_id=no-stcp-ticket-agent",
            headers=auth_headers,
            json={"status": "running"}
        )

        response = client.post(
            "/api/v1/terminal/no-stcp-ticket-agent/ticket",
            headers=super_admin_headers,
        )
        assert response.status_code == 400
        assert "STCP" in response.json()["detail"]

    def test_list_terminal_sessions(self, client, auth_headers):
        """Should list terminal sessions."""
        response = client.get("/api/v1/terminal/sessions", headers=auth_headers)
        assert response.status_code == 200
        assert isinstance(response.json(), list)
