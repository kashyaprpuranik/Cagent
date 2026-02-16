"""Tests for agent management and heartbeat endpoints."""


class TestDataPlaneManagement:
    """Test multi-data plane management endpoints."""

    def _provision_agent(self, client, auth_headers, agent_id):
        """Provision an agent by creating an agent token (which auto-creates agent state)."""
        resp = client.post(
            "/api/v1/tokens",
            headers=auth_headers,
            json={"name": f"{agent_id}-token", "token_type": "agent", "agent_id": agent_id}
        )
        assert resp.status_code == 200, resp.text
        return resp.json()["token"]

    def _heartbeat(self, client, auth_headers, agent_id, **kwargs):
        """Send a heartbeat for an agent using admin token."""
        payload = {"status": "running"}
        payload.update(kwargs)
        return client.post(
            f"/api/v1/agent/heartbeat?agent_id={agent_id}",
            headers=auth_headers,
            json=payload,
        )

    def test_list_agents_empty(self, client, auth_headers):
        """Should return empty list when no agents connected."""
        response = client.get("/api/v1/agents", headers=auth_headers)
        assert response.status_code == 200
        assert isinstance(response.json()["items"], list)

    def test_heartbeat_requires_provisioned_agent(self, client, auth_headers):
        """Heartbeat should return 404 for an agent that hasn't been provisioned."""
        response = self._heartbeat(client, auth_headers, "unprovisioned-agent")
        assert response.status_code == 404
        assert "not found" in response.json()["detail"].lower()

    def test_agent_heartbeat(self, client, auth_headers):
        """Should accept heartbeat for a provisioned agent."""
        self._provision_agent(client, auth_headers, "test-agent-1")
        response = client.post(
            "/api/v1/agent/heartbeat?agent_id=test-agent-1",
            headers=auth_headers,
            json={
                "status": "running",
                "container_id": "abc123",
                "uptime_seconds": 3600,
                "cpu_percent": 25.5,
                "memory_mb": 512.0,
            }
        )
        assert response.status_code == 200
        data = response.json()
        assert data["ack"] is True
        assert data.get("command") is None

    def test_list_agents_after_heartbeat(self, client, auth_headers):
        """Should list agent after heartbeat."""
        self._provision_agent(client, auth_headers, "list-test-agent")
        self._heartbeat(client, auth_headers, "list-test-agent")

        response = client.get("/api/v1/agents", headers=auth_headers)
        assert response.status_code == 200
        agents = response.json()["items"]
        agent = next((a for a in agents if a["agent_id"] == "list-test-agent"), None)
        assert agent is not None
        assert agent["status"] == "running"
        assert agent["online"] is True

    def test_get_agent_status(self, client, auth_headers):
        """Should get specific agent status."""
        self._provision_agent(client, auth_headers, "status-test-agent")
        self._heartbeat(client, auth_headers, "status-test-agent", uptime_seconds=7200)

        response = client.get("/api/v1/agents/status-test-agent/status", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert data["agent_id"] == "status-test-agent"
        assert data["status"] == "running"
        assert data["uptime_seconds"] == 7200
        assert data["online"] is True

    def test_get_agent_status_not_found(self, client, auth_headers):
        """Should return 404 for non-existent agent."""
        response = client.get("/api/v1/agents/nonexistent-agent/status", headers=auth_headers)
        assert response.status_code == 404

    def test_queue_wipe_command(self, client, auth_headers):
        """Should queue wipe command for agent."""
        self._provision_agent(client, auth_headers, "wipe-test-agent")
        self._heartbeat(client, auth_headers, "wipe-test-agent")

        response = client.post(
            "/api/v1/agents/wipe-test-agent/wipe",
            headers=auth_headers,
            json={"wipe_workspace": True}
        )
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "queued"
        assert data["command"] == "wipe"

    def test_queue_restart_command(self, client, auth_headers):
        """Should queue restart command for agent."""
        self._provision_agent(client, auth_headers, "restart-test-agent")
        self._heartbeat(client, auth_headers, "restart-test-agent")

        response = client.post("/api/v1/agents/restart-test-agent/restart", headers=auth_headers)
        assert response.status_code == 200
        assert response.json()["command"] == "restart"

    def test_queue_stop_command(self, client, auth_headers):
        """Should queue stop command for agent."""
        self._provision_agent(client, auth_headers, "stop-test-agent")
        self._heartbeat(client, auth_headers, "stop-test-agent")

        response = client.post("/api/v1/agents/stop-test-agent/stop", headers=auth_headers)
        assert response.status_code == 200
        assert response.json()["command"] == "stop"

    def test_queue_start_command(self, client, auth_headers):
        """Should queue start command for agent."""
        self._provision_agent(client, auth_headers, "start-test-agent")
        self._heartbeat(client, auth_headers, "start-test-agent", status="stopped")

        response = client.post("/api/v1/agents/start-test-agent/start", headers=auth_headers)
        assert response.status_code == 200
        assert response.json()["command"] == "start"

    def test_heartbeat_receives_pending_command(self, client, auth_headers):
        """Should receive pending command via heartbeat."""
        self._provision_agent(client, auth_headers, "pending-cmd-agent")
        self._heartbeat(client, auth_headers, "pending-cmd-agent")

        # Queue command
        client.post("/api/v1/agents/pending-cmd-agent/restart", headers=auth_headers)

        # Next heartbeat should receive command
        response = self._heartbeat(client, auth_headers, "pending-cmd-agent")
        assert response.status_code == 200
        data = response.json()
        assert data["command"] == "restart"

        # Subsequent heartbeat should not receive command (already cleared)
        response = self._heartbeat(client, auth_headers, "pending-cmd-agent")
        assert response.json().get("command") is None

    def test_reject_duplicate_pending_command(self, client, auth_headers):
        """Should reject command when one is already pending."""
        self._provision_agent(client, auth_headers, "dup-cmd-agent")
        self._heartbeat(client, auth_headers, "dup-cmd-agent")
        client.post("/api/v1/agents/dup-cmd-agent/restart", headers=auth_headers)

        # Try to queue another command
        response = client.post("/api/v1/agents/dup-cmd-agent/stop", headers=auth_headers)
        assert response.status_code == 409
        assert "already pending" in response.json()["detail"]
