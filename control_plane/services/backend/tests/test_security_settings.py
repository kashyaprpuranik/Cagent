"""Tests for per-agent seccomp profile (security settings) endpoints."""


class TestSecuritySettings:
    """Test security settings GET/PUT endpoints."""

    def _create_agent(self, client, auth_headers, agent_id="sec-agent"):
        """Helper: provision an agent via token creation."""
        client.post(
            "/api/v1/tokens",
            headers=auth_headers,
            json={"name": f"{agent_id}-token", "token_type": "agent", "agent_id": agent_id},
        )

    def test_default_profile_is_standard(self, client, auth_headers):
        """New agents should default to 'standard' seccomp profile."""
        self._create_agent(client, auth_headers)

        response = client.get(
            "/api/v1/agents/sec-agent/security-settings",
            headers=auth_headers,
        )
        assert response.status_code == 200
        data = response.json()
        assert data["agent_id"] == "sec-agent"
        assert data["seccomp_profile"] == "hardened"

    def test_update_to_hardened(self, client, auth_headers):
        """Should update seccomp profile to hardened."""
        self._create_agent(client, auth_headers)

        response = client.put(
            "/api/v1/agents/sec-agent/security-settings",
            headers=auth_headers,
            json={"seccomp_profile": "hardened"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["seccomp_profile"] == "hardened"

        # Verify via GET
        response = client.get(
            "/api/v1/agents/sec-agent/security-settings",
            headers=auth_headers,
        )
        assert response.json()["seccomp_profile"] == "hardened"

    def test_update_to_permissive(self, client, auth_headers):
        """Should update seccomp profile to permissive."""
        self._create_agent(client, auth_headers)

        response = client.put(
            "/api/v1/agents/sec-agent/security-settings",
            headers=auth_headers,
            json={"seccomp_profile": "permissive"},
        )
        assert response.status_code == 200
        assert response.json()["seccomp_profile"] == "permissive"

    def test_invalid_profile_rejected(self, client, auth_headers):
        """Invalid seccomp profile should return 422."""
        self._create_agent(client, auth_headers)

        response = client.put(
            "/api/v1/agents/sec-agent/security-settings",
            headers=auth_headers,
            json={"seccomp_profile": "ultra_secure"},
        )
        assert response.status_code == 422

    def test_heartbeat_returns_profile(self, client, auth_headers):
        """Heartbeat response should include seccomp_profile."""
        self._create_agent(client, auth_headers)

        # Default profile
        response = client.post(
            "/api/v1/agent/heartbeat?agent_id=sec-agent",
            headers=auth_headers,
            json={"status": "running"},
        )
        assert response.status_code == 200
        assert response.json()["seccomp_profile"] == "hardened"

        # Update to hardened
        client.put(
            "/api/v1/agents/sec-agent/security-settings",
            headers=auth_headers,
            json={"seccomp_profile": "hardened"},
        )

        # Heartbeat should now return hardened
        response = client.post(
            "/api/v1/agent/heartbeat?agent_id=sec-agent",
            headers=auth_headers,
            json={"status": "running"},
        )
        assert response.json()["seccomp_profile"] == "hardened"

    def test_status_includes_profile(self, client, auth_headers):
        """Agent status should include seccomp_profile."""
        self._create_agent(client, auth_headers)

        response = client.get(
            "/api/v1/agents/sec-agent/status",
            headers=auth_headers,
        )
        assert response.status_code == 200
        assert response.json()["seccomp_profile"] == "hardened"

    def test_security_settings_not_found(self, client, auth_headers):
        """Should return 404 for unknown agent."""
        response = client.get(
            "/api/v1/agents/nonexistent-agent/security-settings",
            headers=auth_headers,
        )
        assert response.status_code == 404

    def test_update_not_found(self, client, auth_headers):
        """Should return 404 when updating unknown agent."""
        response = client.put(
            "/api/v1/agents/nonexistent-agent/security-settings",
            headers=auth_headers,
            json={"seccomp_profile": "hardened"},
        )
        assert response.status_code == 404

    def test_developer_cannot_update(self, client, auth_headers, dev_headers):
        """Developer role should be blocked from updating security settings."""
        self._create_agent(client, auth_headers)

        response = client.put(
            "/api/v1/agents/sec-agent/security-settings",
            headers=dev_headers,
            json={"seccomp_profile": "hardened"},
        )
        assert response.status_code == 403

    def test_cross_tenant_blocked(self, client, auth_headers, acme_admin_headers):
        """Admin from different tenant should not access another tenant's agent."""
        self._create_agent(client, auth_headers, agent_id="default-tenant-agent")

        response = client.get(
            "/api/v1/agents/default-tenant-agent/security-settings",
            headers=acme_admin_headers,
        )
        assert response.status_code == 403

    def test_audit_trail_entry(self, client, auth_headers):
        """Updating security settings should create an audit trail entry."""
        self._create_agent(client, auth_headers)

        client.put(
            "/api/v1/agents/sec-agent/security-settings",
            headers=auth_headers,
            json={"seccomp_profile": "hardened"},
        )

        # Check audit trail
        response = client.get("/api/v1/audit-trail", headers=auth_headers)
        assert response.status_code == 200
        entries = response.json()["items"]
        security_events = [
            e for e in entries if e["event_type"] == "security_settings_updated"
        ]
        assert len(security_events) >= 1
        assert "hardened" in security_events[0]["action"]
        assert security_events[0]["severity"] == "WARNING"
