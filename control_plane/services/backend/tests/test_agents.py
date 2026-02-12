"""Tests for agent management and heartbeat endpoints."""


class TestDataPlaneManagement:
    """Test multi-data plane management endpoints."""

    def test_list_agents_empty(self, client, auth_headers):
        """Should return empty list when no agents connected."""
        response = client.get("/api/v1/agents", headers=auth_headers)
        assert response.status_code == 200
        assert isinstance(response.json()["items"], list)

    def test_agent_heartbeat_creates_agent(self, client, auth_headers):
        """Should create agent state on first heartbeat."""
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
        # Send heartbeat
        client.post(
            "/api/v1/agent/heartbeat?agent_id=list-test-agent",
            headers=auth_headers,
            json={"status": "running"}
        )

        response = client.get("/api/v1/agents", headers=auth_headers)
        assert response.status_code == 200
        agents = response.json()["items"]
        agent = next((a for a in agents if a["agent_id"] == "list-test-agent"), None)
        assert agent is not None
        assert agent["status"] == "running"
        assert agent["online"] is True

    def test_get_agent_status(self, client, auth_headers):
        """Should get specific agent status."""
        # Send heartbeat to create agent
        client.post(
            "/api/v1/agent/heartbeat?agent_id=status-test-agent",
            headers=auth_headers,
            json={"status": "running", "uptime_seconds": 7200}
        )

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
        # Create agent first
        client.post(
            "/api/v1/agent/heartbeat?agent_id=wipe-test-agent",
            headers=auth_headers,
            json={"status": "running"}
        )

        # Queue wipe
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
        # Create agent first
        client.post(
            "/api/v1/agent/heartbeat?agent_id=restart-test-agent",
            headers=auth_headers,
            json={"status": "running"}
        )

        # Queue restart
        response = client.post("/api/v1/agents/restart-test-agent/restart", headers=auth_headers)
        assert response.status_code == 200
        assert response.json()["command"] == "restart"

    def test_queue_stop_command(self, client, auth_headers):
        """Should queue stop command for agent."""
        # Create agent first
        client.post(
            "/api/v1/agent/heartbeat?agent_id=stop-test-agent",
            headers=auth_headers,
            json={"status": "running"}
        )

        # Queue stop
        response = client.post("/api/v1/agents/stop-test-agent/stop", headers=auth_headers)
        assert response.status_code == 200
        assert response.json()["command"] == "stop"

    def test_queue_start_command(self, client, auth_headers):
        """Should queue start command for agent."""
        # Create agent first
        client.post(
            "/api/v1/agent/heartbeat?agent_id=start-test-agent",
            headers=auth_headers,
            json={"status": "stopped"}
        )

        # Queue start
        response = client.post("/api/v1/agents/start-test-agent/start", headers=auth_headers)
        assert response.status_code == 200
        assert response.json()["command"] == "start"

    def test_heartbeat_receives_pending_command(self, client, auth_headers):
        """Should receive pending command via heartbeat."""
        # Create agent
        client.post(
            "/api/v1/agent/heartbeat?agent_id=pending-cmd-agent",
            headers=auth_headers,
            json={"status": "running"}
        )

        # Queue command
        client.post("/api/v1/agents/pending-cmd-agent/restart", headers=auth_headers)

        # Next heartbeat should receive command
        response = client.post(
            "/api/v1/agent/heartbeat?agent_id=pending-cmd-agent",
            headers=auth_headers,
            json={"status": "running"}
        )
        assert response.status_code == 200
        data = response.json()
        assert data["command"] == "restart"

        # Subsequent heartbeat should not receive command (already cleared)
        response = client.post(
            "/api/v1/agent/heartbeat?agent_id=pending-cmd-agent",
            headers=auth_headers,
            json={"status": "running"}
        )
        assert response.json().get("command") is None

    def test_reject_duplicate_pending_command(self, client, auth_headers):
        """Should reject command when one is already pending."""
        # Create agent and queue command
        client.post(
            "/api/v1/agent/heartbeat?agent_id=dup-cmd-agent",
            headers=auth_headers,
            json={"status": "running"}
        )
        client.post("/api/v1/agents/dup-cmd-agent/restart", headers=auth_headers)

        # Try to queue another command
        response = client.post("/api/v1/agents/dup-cmd-agent/stop", headers=auth_headers)
        assert response.status_code == 409
        assert "already pending" in response.json()["detail"]
