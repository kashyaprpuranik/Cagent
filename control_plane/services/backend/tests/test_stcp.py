"""Tests for STCP secret generation and config retrieval."""


class TestSTCPEndpoints:
    """Test STCP secret generation and config retrieval."""

    def _provision_agent(self, client, auth_headers, agent_id):
        """Helper: provision an agent via token creation."""
        client.post(
            "/api/v1/tokens",
            headers=auth_headers,
            json={"name": f"{agent_id}-provision-token", "token_type": "agent", "agent_id": agent_id},
        )

    def _create_agent_token(self, client, auth_headers, agent_id):
        """Helper: create agent token (also provisions agent) and return headers."""
        token_response = client.post(
            "/api/v1/tokens",
            headers=auth_headers,
            json={"name": f"{agent_id}-token", "token_type": "agent", "agent_id": agent_id}
        )
        token = token_response.json()["token"]
        return {"Authorization": f"Bearer {token}"}

    def test_generate_stcp_secret(self, client, auth_headers):
        """Should generate STCP secret for an agent."""
        self._provision_agent(client, auth_headers, "stcp-test-agent")

        response = client.post(
            "/api/v1/agents/stcp-test-agent/stcp-secret",
            headers=auth_headers,
        )
        assert response.status_code == 200
        data = response.json()
        assert data["agent_id"] == "stcp-test-agent"
        assert data["proxy_name"] == "stcp-test-agent-ssh"
        assert len(data["secret_key"]) > 20
        assert "message" in data

    def test_generate_stcp_secret_not_found(self, client, auth_headers):
        """Should return 404 for non-existent agent."""
        response = client.post(
            "/api/v1/agents/nonexistent-stcp-agent/stcp-secret",
            headers=auth_headers,
        )
        assert response.status_code == 404

    def test_generate_stcp_secret_from_token(self, client, auth_headers):
        """Should generate STCP secret using agent token (token-derived endpoint)."""
        self._provision_agent(client, auth_headers, "stcp-token-agent")
        agent_headers = self._create_agent_token(client, auth_headers, "stcp-token-agent")

        response = client.post(
            "/api/v1/agent/stcp-secret",
            headers=agent_headers,
        )
        assert response.status_code == 200
        data = response.json()
        assert data["agent_id"] == "stcp-token-agent"
        assert data["proxy_name"] == "stcp-token-agent-ssh"
        assert len(data["secret_key"]) > 20
        assert "message" in data

    def test_generate_stcp_secret_from_token_rejects_admin(self, client, auth_headers):
        """Token-derived endpoint should reject admin tokens."""
        response = client.post(
            "/api/v1/agent/stcp-secret",
            headers=auth_headers,
        )
        assert response.status_code == 403
        assert "agent token" in response.json()["detail"].lower()

    def test_get_stcp_config(self, client, auth_headers, super_admin_headers):
        """Should return STCP visitor config after secret is generated."""
        self._provision_agent(client, auth_headers, "stcp-config-agent")

        # Generate secret first (admin role)
        client.post("/api/v1/agents/stcp-config-agent/stcp-secret", headers=auth_headers)

        # Get config (developer role — use super admin)
        response = client.get(
            "/api/v1/agents/stcp-config-agent/stcp-config",
            headers=super_admin_headers,
        )
        assert response.status_code == 200
        data = response.json()
        assert data["proxy_name"] == "stcp-config-agent-ssh"
        assert len(data["secret_key"]) > 20
        assert "server_addr" in data
        assert "server_port" in data

    def test_get_stcp_config_without_secret(self, client, auth_headers, super_admin_headers):
        """Should return 404 when no secret has been generated."""
        self._provision_agent(client, auth_headers, "stcp-no-secret-agent")

        response = client.get(
            "/api/v1/agents/stcp-no-secret-agent/stcp-config",
            headers=super_admin_headers,
        )
        assert response.status_code == 404
        assert "STCP not configured" in response.json()["detail"]

    # ── tunnel-config (self-bootstrapping) ──────────────────────────────────

    def test_tunnel_config_creates_new(self, client, auth_headers):
        """tunnel-config should create a new secret when none exists."""
        agent_headers = self._create_agent_token(client, auth_headers, "tunnel-new-agent")

        response = client.post(
            "/api/v1/agent/tunnel-config",
            headers=agent_headers,
        )
        assert response.status_code == 200
        data = response.json()
        assert data["agent_id"] == "tunnel-new-agent"
        assert data["proxy_name"] == "tunnel-new-agent-ssh"
        assert len(data["secret_key"]) > 20

    def test_tunnel_config_idempotent(self, client, auth_headers):
        """tunnel-config should return the same secret on repeated calls."""
        agent_headers = self._create_agent_token(client, auth_headers, "tunnel-idem-agent")

        resp1 = client.post("/api/v1/agent/tunnel-config", headers=agent_headers)
        resp2 = client.post("/api/v1/agent/tunnel-config", headers=agent_headers)

        assert resp1.status_code == 200
        assert resp2.status_code == 200
        assert resp1.json()["secret_key"] == resp2.json()["secret_key"]
        assert resp1.json()["proxy_name"] == resp2.json()["proxy_name"]

    def test_tunnel_config_rejects_admin(self, client, auth_headers):
        """tunnel-config should reject admin tokens (agent only)."""
        response = client.post(
            "/api/v1/agent/tunnel-config",
            headers=auth_headers,
        )
        assert response.status_code == 403

    def test_tunnel_config_preserves_admin_secret(self, client, auth_headers):
        """tunnel-config should return the secret created by admin endpoint."""
        self._provision_agent(client, auth_headers, "tunnel-admin-agent")

        # Admin generates secret via the admin endpoint
        admin_resp = client.post(
            "/api/v1/agents/tunnel-admin-agent/stcp-secret",
            headers=auth_headers,
        )
        assert admin_resp.status_code == 200
        admin_secret = admin_resp.json()["secret_key"]

        # Agent calls tunnel-config — should get the same secret (not overwrite)
        agent_headers = self._create_agent_token(client, auth_headers, "tunnel-admin-agent")
        tunnel_resp = client.post(
            "/api/v1/agent/tunnel-config",
            headers=agent_headers,
        )
        assert tunnel_resp.status_code == 200
        assert tunnel_resp.json()["secret_key"] == admin_secret
