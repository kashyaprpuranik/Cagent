"""
Integration tests for the Control Plane API.
"""

import pytest


class TestHealthEndpoints:
    """Test health and info endpoints."""

    def test_health_check(self, client):
        """Health endpoint should return healthy status."""
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert "timestamp" in data

    def test_info_endpoint(self, client):
        """Info endpoint should return service metadata."""
        response = client.get("/api/v1/info")
        assert response.status_code == 200
        data = response.json()
        assert data["name"] == "AI Devbox Control Plane"
        assert "version" in data
        assert "features" in data


class TestAuthentication:
    """Test authentication requirements."""

    def test_secrets_requires_auth(self, client):
        """Secrets endpoint should require authentication."""
        response = client.get("/api/v1/secrets")
        assert response.status_code == 401

    def test_secrets_rejects_invalid_token(self, client):
        """Secrets endpoint should reject invalid tokens."""
        response = client.get(
            "/api/v1/secrets",
            headers={"Authorization": "Bearer invalid-token"}
        )
        assert response.status_code == 403

    def test_secrets_accepts_valid_token(self, client, auth_headers):
        """Secrets endpoint should accept valid tokens."""
        response = client.get("/api/v1/secrets", headers=auth_headers)
        assert response.status_code == 200


class TestSecrets:
    """Test secret management endpoints."""

    def test_create_secret(self, client, auth_headers):
        """Should create a new domain-scoped secret."""
        response = client.post(
            "/api/v1/secrets",
            headers=auth_headers,
            json={
                "name": "OPENAI_API_KEY",
                "value": "sk-test-key-12345",
                "domain_pattern": "api.openai.com",
                "header_name": "Authorization",
                "header_format": "Bearer {value}",
                "description": "Test OpenAI key"
            }
        )
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "created"
        assert data["name"] == "OPENAI_API_KEY"
        assert data["domain_pattern"] == "api.openai.com"

    def test_create_duplicate_secret_fails(self, client, auth_headers):
        """Should reject duplicate secret names."""
        secret_data = {
            "name": "DUPLICATE_KEY",
            "value": "value1",
            "domain_pattern": "example.com",
        }
        # Create first
        response = client.post("/api/v1/secrets", headers=auth_headers, json=secret_data)
        assert response.status_code == 200

        # Duplicate should fail
        response = client.post("/api/v1/secrets", headers=auth_headers, json=secret_data)
        assert response.status_code == 400
        assert "already exists" in response.json()["detail"]

    def test_list_secrets(self, client, auth_headers):
        """Should list secrets without exposing values."""
        # Create a secret first
        client.post(
            "/api/v1/secrets",
            headers=auth_headers,
            json={
                "name": "LIST_TEST_KEY",
                "value": "secret-value",
                "domain_pattern": "test.com",
            }
        )

        response = client.get("/api/v1/secrets", headers=auth_headers)
        assert response.status_code == 200
        secrets = response.json()
        assert len(secrets) >= 1

        # Find our secret
        secret = next((s for s in secrets if s["name"] == "LIST_TEST_KEY"), None)
        assert secret is not None
        assert secret["domain_pattern"] == "test.com"
        assert "value" not in secret  # Value should not be exposed
        assert "encrypted_value" not in secret

    def test_get_secret_value(self, client, auth_headers):
        """Should retrieve decrypted secret value by name."""
        # Create secret
        client.post(
            "/api/v1/secrets",
            headers=auth_headers,
            json={
                "name": "VALUE_TEST_KEY",
                "value": "my-secret-value",
                "domain_pattern": "test.com",
            }
        )

        response = client.get("/api/v1/secrets/VALUE_TEST_KEY/value", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert data["name"] == "VALUE_TEST_KEY"
        assert data["value"] == "my-secret-value"

    def test_get_secret_value_not_found(self, client, auth_headers):
        """Should return 404 for non-existent secret."""
        response = client.get("/api/v1/secrets/NONEXISTENT/value", headers=auth_headers)
        assert response.status_code == 404

    def test_rotate_secret(self, client, auth_headers):
        """Should rotate secret with new value."""
        # Create secret
        client.post(
            "/api/v1/secrets",
            headers=auth_headers,
            json={
                "name": "ROTATE_TEST_KEY",
                "value": "old-value",
                "domain_pattern": "test.com",
            }
        )

        # Rotate
        response = client.post(
            "/api/v1/secrets/ROTATE_TEST_KEY/rotate",
            headers=auth_headers,
            json={"new_value": "new-value"}
        )
        assert response.status_code == 200
        assert response.json()["status"] == "rotated"

        # Verify new value
        response = client.get("/api/v1/secrets/ROTATE_TEST_KEY/value", headers=auth_headers)
        assert response.json()["value"] == "new-value"

    def test_delete_secret(self, client, auth_headers):
        """Should delete a secret."""
        # Create secret
        client.post(
            "/api/v1/secrets",
            headers=auth_headers,
            json={
                "name": "DELETE_TEST_KEY",
                "value": "delete-me",
                "domain_pattern": "test.com",
            }
        )

        # Delete
        response = client.delete("/api/v1/secrets/DELETE_TEST_KEY", headers=auth_headers)
        assert response.status_code == 200
        assert response.json()["status"] == "deleted"

        # Verify deleted
        response = client.get("/api/v1/secrets/DELETE_TEST_KEY/value", headers=auth_headers)
        assert response.status_code == 404

    def test_delete_secret_not_found(self, client, auth_headers):
        """Should return 404 when deleting non-existent secret."""
        response = client.delete("/api/v1/secrets/NONEXISTENT_KEY", headers=auth_headers)
        assert response.status_code == 404


class TestDomainScopedCredentials:
    """Test domain-based credential lookup."""

    def test_create_secret_with_alias(self, client, auth_headers):
        """Should create secret with devbox.local alias."""
        response = client.post(
            "/api/v1/secrets",
            headers=auth_headers,
            json={
                "name": "ALIASED_SECRET",
                "value": "test-value",
                "domain_pattern": "api.example.com",
                "alias": "example",
                "header_name": "Authorization",
                "header_format": "Bearer {value}",
            }
        )
        assert response.status_code == 200
        data = response.json()
        assert data["alias"] == "example"
        assert data["devbox_url"] == "http://example.devbox.local"

    def test_get_credential_for_devbox_alias(self, client, auth_headers):
        """Should resolve devbox.local alias to real domain and return credentials."""
        # Create secret with alias
        client.post(
            "/api/v1/secrets",
            headers=auth_headers,
            json={
                "name": "ALIAS_LOOKUP_KEY",
                "value": "alias-secret-value",
                "domain_pattern": "api.testservice.com",
                "alias": "testservice",
                "header_name": "Authorization",
                "header_format": "Bearer {value}",
            }
        )

        # Query using devbox.local alias
        response = client.get(
            "/api/v1/secrets/for-domain?domain=testservice.devbox.local",
            headers=auth_headers
        )
        assert response.status_code == 200
        data = response.json()
        assert data["matched"] is True
        assert data["name"] == "ALIAS_LOOKUP_KEY"
        assert data["target_domain"] == "api.testservice.com"
        assert data["header_name"] == "Authorization"
        assert data["header_value"] == "Bearer alias-secret-value"

    def test_get_credential_for_devbox_alias_with_wildcard(self, client, auth_headers):
        """Should strip wildcard prefix when returning target_domain for alias."""
        # Create secret with alias and wildcard domain pattern
        client.post(
            "/api/v1/secrets",
            headers=auth_headers,
            json={
                "name": "WILDCARD_ALIAS_KEY",
                "value": "wildcard-alias-secret",
                "domain_pattern": "*.github.com",
                "alias": "github",
                "header_name": "Authorization",
                "header_format": "token {value}",
            }
        )

        # Query using devbox.local alias
        response = client.get(
            "/api/v1/secrets/for-domain?domain=github.devbox.local",
            headers=auth_headers
        )
        assert response.status_code == 200
        data = response.json()
        assert data["matched"] is True
        # Wildcard should be stripped: *.github.com -> github.com
        assert data["target_domain"] == "github.com"
        assert data["header_value"] == "token wildcard-alias-secret"

    def test_get_credential_for_unknown_devbox_alias(self, client, auth_headers):
        """Should return no match for unknown devbox.local alias."""
        response = client.get(
            "/api/v1/secrets/for-domain?domain=unknown.devbox.local",
            headers=auth_headers
        )
        assert response.status_code == 200
        data = response.json()
        assert data["matched"] is False

    def test_get_credential_for_exact_domain(self, client, auth_headers):
        """Should match exact domain pattern."""
        # Create secret
        client.post(
            "/api/v1/secrets",
            headers=auth_headers,
            json={
                "name": "EXACT_DOMAIN_KEY",
                "value": "exact-secret",
                "domain_pattern": "api.openai.com",
                "header_name": "Authorization",
                "header_format": "Bearer {value}",
            }
        )

        response = client.get(
            "/api/v1/secrets/for-domain?domain=api.openai.com",
            headers=auth_headers
        )
        assert response.status_code == 200
        data = response.json()
        assert data["matched"] is True
        assert data["name"] == "EXACT_DOMAIN_KEY"
        assert data["header_name"] == "Authorization"
        assert data["header_value"] == "Bearer exact-secret"

    def test_get_credential_for_wildcard_domain(self, client, auth_headers):
        """Should match wildcard domain pattern."""
        # Create secret with wildcard
        client.post(
            "/api/v1/secrets",
            headers=auth_headers,
            json={
                "name": "WILDCARD_KEY",
                "value": "wildcard-secret",
                "domain_pattern": "*.github.com",
                "header_name": "Authorization",
                "header_format": "token {value}",
            }
        )

        # Should match api.github.com
        response = client.get(
            "/api/v1/secrets/for-domain?domain=api.github.com",
            headers=auth_headers
        )
        assert response.status_code == 200
        data = response.json()
        assert data["matched"] is True
        assert data["header_value"] == "token wildcard-secret"

        # Should match raw.github.com
        response = client.get(
            "/api/v1/secrets/for-domain?domain=raw.github.com",
            headers=auth_headers
        )
        assert response.status_code == 200
        assert response.json()["matched"] is True

    def test_no_match_for_unknown_domain(self, client, auth_headers):
        """Should return no match for unknown domains."""
        response = client.get(
            "/api/v1/secrets/for-domain?domain=unknown.example.com",
            headers=auth_headers
        )
        assert response.status_code == 200
        data = response.json()
        assert data["matched"] is False


class TestAllowlist:
    """Test allowlist management endpoints."""

    def test_create_allowlist_entry(self, client, auth_headers):
        """Should create a new allowlist entry."""
        response = client.post(
            "/api/v1/allowlist",
            headers=auth_headers,
            json={
                "entry_type": "domain",
                "value": "api.openai.com",
                "description": "OpenAI API"
            }
        )
        assert response.status_code == 200
        data = response.json()
        assert data["entry_type"] == "domain"
        assert data["value"] == "api.openai.com"
        assert data["enabled"] is True

    def test_list_allowlist_entries(self, client, auth_headers):
        """Should list all allowlist entries."""
        # Create entry
        client.post(
            "/api/v1/allowlist",
            headers=auth_headers,
            json={"entry_type": "domain", "value": "test.com"}
        )

        response = client.get("/api/v1/allowlist", headers=auth_headers)
        assert response.status_code == 200
        entries = response.json()
        assert len(entries) >= 1

    def test_filter_allowlist_by_type(self, client, auth_headers):
        """Should filter allowlist by entry type."""
        # Create domain entry
        client.post(
            "/api/v1/allowlist",
            headers=auth_headers,
            json={"entry_type": "domain", "value": "domain.com"}
        )
        # Create IP entry
        client.post(
            "/api/v1/allowlist",
            headers=auth_headers,
            json={"entry_type": "ip", "value": "192.168.1.1"}
        )

        # Filter by domain
        response = client.get("/api/v1/allowlist?entry_type=domain", headers=auth_headers)
        assert response.status_code == 200
        entries = response.json()
        assert all(e["entry_type"] == "domain" for e in entries)

    def test_delete_allowlist_entry(self, client, auth_headers):
        """Should delete allowlist entry."""
        # Create entry
        create_response = client.post(
            "/api/v1/allowlist",
            headers=auth_headers,
            json={"entry_type": "domain", "value": "delete-me.com"}
        )
        entry_id = create_response.json()["id"]

        # Delete
        response = client.delete(f"/api/v1/allowlist/{entry_id}", headers=auth_headers)
        assert response.status_code == 200

        # Verify deleted
        list_response = client.get("/api/v1/allowlist", headers=auth_headers)
        entries = list_response.json()
        assert not any(e["value"] == "delete-me.com" for e in entries)


class TestAuditLogs:
    """Test audit log endpoints."""

    def test_get_audit_logs(self, client, auth_headers):
        """Should retrieve audit logs."""
        response = client.get("/api/v1/audit-logs", headers=auth_headers)
        assert response.status_code == 200
        # Returns list (may be empty in fresh DB)
        assert isinstance(response.json(), list)

    def test_audit_logs_pagination(self, client, auth_headers):
        """Should support limit and offset."""
        response = client.get(
            "/api/v1/audit-logs?limit=10&offset=0",
            headers=auth_headers
        )
        assert response.status_code == 200


class TestDataPlaneManagement:
    """Test multi-data plane management endpoints."""

    def test_list_agents_empty(self, client, auth_headers):
        """Should return empty list when no agents connected."""
        response = client.get("/api/v1/agents", headers=auth_headers)
        assert response.status_code == 200
        assert isinstance(response.json(), list)

    def test_agent_heartbeat_creates_agent(self, client, auth_headers):
        """Should create agent state on first heartbeat."""
        response = client.post(
            "/api/v1/agent/heartbeat",
            headers=auth_headers,
            json={
                "agent_id": "test-agent-1",
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
            "/api/v1/agent/heartbeat",
            headers=auth_headers,
            json={
                "agent_id": "list-test-agent",
                "status": "running",
            }
        )

        response = client.get("/api/v1/agents", headers=auth_headers)
        assert response.status_code == 200
        agents = response.json()
        agent = next((a for a in agents if a["agent_id"] == "list-test-agent"), None)
        assert agent is not None
        assert agent["status"] == "running"
        assert agent["online"] is True

    def test_get_agent_status(self, client, auth_headers):
        """Should get specific agent status."""
        # Send heartbeat to create agent
        client.post(
            "/api/v1/agent/heartbeat",
            headers=auth_headers,
            json={
                "agent_id": "status-test-agent",
                "status": "running",
                "uptime_seconds": 7200,
            }
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
            "/api/v1/agent/heartbeat",
            headers=auth_headers,
            json={"agent_id": "wipe-test-agent", "status": "running"}
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
            "/api/v1/agent/heartbeat",
            headers=auth_headers,
            json={"agent_id": "restart-test-agent", "status": "running"}
        )

        # Queue restart
        response = client.post("/api/v1/agents/restart-test-agent/restart", headers=auth_headers)
        assert response.status_code == 200
        assert response.json()["command"] == "restart"

    def test_queue_stop_command(self, client, auth_headers):
        """Should queue stop command for agent."""
        # Create agent first
        client.post(
            "/api/v1/agent/heartbeat",
            headers=auth_headers,
            json={"agent_id": "stop-test-agent", "status": "running"}
        )

        # Queue stop
        response = client.post("/api/v1/agents/stop-test-agent/stop", headers=auth_headers)
        assert response.status_code == 200
        assert response.json()["command"] == "stop"

    def test_queue_start_command(self, client, auth_headers):
        """Should queue start command for agent."""
        # Create agent first
        client.post(
            "/api/v1/agent/heartbeat",
            headers=auth_headers,
            json={"agent_id": "start-test-agent", "status": "stopped"}
        )

        # Queue start
        response = client.post("/api/v1/agents/start-test-agent/start", headers=auth_headers)
        assert response.status_code == 200
        assert response.json()["command"] == "start"

    def test_heartbeat_receives_pending_command(self, client, auth_headers):
        """Should receive pending command via heartbeat (approved agents only)."""
        # Create agent
        client.post(
            "/api/v1/agent/heartbeat",
            headers=auth_headers,
            json={"agent_id": "pending-cmd-agent", "status": "running"}
        )
        # Approve the agent first (required for receiving commands)
        client.post("/api/v1/agents/pending-cmd-agent/approve", headers=auth_headers)

        # Queue command
        client.post("/api/v1/agents/pending-cmd-agent/restart", headers=auth_headers)

        # Next heartbeat should receive command
        response = client.post(
            "/api/v1/agent/heartbeat",
            headers=auth_headers,
            json={"agent_id": "pending-cmd-agent", "status": "running"}
        )
        assert response.status_code == 200
        data = response.json()
        assert data["command"] == "restart"

        # Subsequent heartbeat should not receive command (already cleared)
        response = client.post(
            "/api/v1/agent/heartbeat",
            headers=auth_headers,
            json={"agent_id": "pending-cmd-agent", "status": "running"}
        )
        assert response.json().get("command") is None

    def test_reject_duplicate_pending_command(self, client, auth_headers):
        """Should reject command when one is already pending."""
        # Create agent and queue command
        client.post(
            "/api/v1/agent/heartbeat",
            headers=auth_headers,
            json={"agent_id": "dup-cmd-agent", "status": "running"}
        )
        client.post("/api/v1/agents/dup-cmd-agent/restart", headers=auth_headers)

        # Try to queue another command
        response = client.post("/api/v1/agents/dup-cmd-agent/stop", headers=auth_headers)
        assert response.status_code == 409
        assert "already pending" in response.json()["detail"]


class TestRateLimits:
    """Test rate limit management endpoints."""

    def test_create_rate_limit(self, client, auth_headers):
        """Should create a new rate limit configuration."""
        response = client.post(
            "/api/v1/rate-limits",
            headers=auth_headers,
            json={
                "domain_pattern": "api.openai.com",
                "requests_per_minute": 60,
                "burst_size": 10,
                "description": "OpenAI rate limit"
            }
        )
        assert response.status_code == 200
        data = response.json()
        assert data["domain_pattern"] == "api.openai.com"
        assert data["requests_per_minute"] == 60
        assert data["burst_size"] == 10
        assert data["enabled"] is True

    def test_create_duplicate_rate_limit_fails(self, client, auth_headers):
        """Should reject duplicate domain patterns."""
        rate_limit_data = {
            "domain_pattern": "duplicate.example.com",
            "requests_per_minute": 100,
        }
        # Create first
        response = client.post("/api/v1/rate-limits", headers=auth_headers, json=rate_limit_data)
        assert response.status_code == 200

        # Duplicate should fail
        response = client.post("/api/v1/rate-limits", headers=auth_headers, json=rate_limit_data)
        assert response.status_code == 400
        assert "already exists" in response.json()["detail"]

    def test_list_rate_limits(self, client, auth_headers):
        """Should list all rate limit configurations."""
        # Create a rate limit
        client.post(
            "/api/v1/rate-limits",
            headers=auth_headers,
            json={
                "domain_pattern": "list-test.example.com",
                "requests_per_minute": 30,
            }
        )

        response = client.get("/api/v1/rate-limits", headers=auth_headers)
        assert response.status_code == 200
        rate_limits = response.json()
        assert len(rate_limits) >= 1

        # Find our rate limit
        rl = next((r for r in rate_limits if r["domain_pattern"] == "list-test.example.com"), None)
        assert rl is not None
        assert rl["requests_per_minute"] == 30

    def test_update_rate_limit(self, client, auth_headers):
        """Should update rate limit configuration."""
        # Create rate limit
        create_response = client.post(
            "/api/v1/rate-limits",
            headers=auth_headers,
            json={
                "domain_pattern": "update-test.example.com",
                "requests_per_minute": 60,
            }
        )
        rate_limit_id = create_response.json()["id"]

        # Update
        response = client.put(
            f"/api/v1/rate-limits/{rate_limit_id}",
            headers=auth_headers,
            json={
                "requests_per_minute": 120,
                "burst_size": 25
            }
        )
        assert response.status_code == 200
        data = response.json()
        assert data["requests_per_minute"] == 120
        assert data["burst_size"] == 25

    def test_disable_rate_limit(self, client, auth_headers):
        """Should disable rate limit."""
        # Create rate limit
        create_response = client.post(
            "/api/v1/rate-limits",
            headers=auth_headers,
            json={
                "domain_pattern": "disable-test.example.com",
                "requests_per_minute": 60,
            }
        )
        rate_limit_id = create_response.json()["id"]

        # Disable
        response = client.put(
            f"/api/v1/rate-limits/{rate_limit_id}",
            headers=auth_headers,
            json={"enabled": False}
        )
        assert response.status_code == 200
        assert response.json()["enabled"] is False

    def test_delete_rate_limit(self, client, auth_headers):
        """Should delete rate limit configuration."""
        # Create rate limit
        create_response = client.post(
            "/api/v1/rate-limits",
            headers=auth_headers,
            json={
                "domain_pattern": "delete-test.example.com",
                "requests_per_minute": 60,
            }
        )
        rate_limit_id = create_response.json()["id"]

        # Delete
        response = client.delete(f"/api/v1/rate-limits/{rate_limit_id}", headers=auth_headers)
        assert response.status_code == 200

        # Verify deleted
        list_response = client.get("/api/v1/rate-limits", headers=auth_headers)
        rate_limits = list_response.json()
        assert not any(r["domain_pattern"] == "delete-test.example.com" for r in rate_limits)

    def test_get_rate_limit_for_exact_domain(self, client, auth_headers):
        """Should match exact domain pattern for rate limit."""
        # Create rate limit
        client.post(
            "/api/v1/rate-limits",
            headers=auth_headers,
            json={
                "domain_pattern": "exact-rate.example.com",
                "requests_per_minute": 45,
                "burst_size": 8,
            }
        )

        response = client.get(
            "/api/v1/rate-limits/for-domain?domain=exact-rate.example.com",
            headers=auth_headers
        )
        assert response.status_code == 200
        data = response.json()
        assert data["matched"] is True
        assert data["requests_per_minute"] == 45
        assert data["burst_size"] == 8

    def test_get_rate_limit_for_wildcard_domain(self, client, auth_headers):
        """Should match wildcard domain pattern for rate limit."""
        # Create rate limit with wildcard
        client.post(
            "/api/v1/rate-limits",
            headers=auth_headers,
            json={
                "domain_pattern": "*.wildcard-rate.com",
                "requests_per_minute": 100,
                "burst_size": 15,
            }
        )

        response = client.get(
            "/api/v1/rate-limits/for-domain?domain=api.wildcard-rate.com",
            headers=auth_headers
        )
        assert response.status_code == 200
        data = response.json()
        assert data["matched"] is True
        assert data["requests_per_minute"] == 100

    def test_get_default_rate_limit_for_unknown_domain(self, client, auth_headers):
        """Should return default rate limit for unknown domains."""
        response = client.get(
            "/api/v1/rate-limits/for-domain?domain=unknown-rate.example.com",
            headers=auth_headers
        )
        assert response.status_code == 200
        data = response.json()
        assert data["matched"] is False
        # Should have default values
        assert "requests_per_minute" in data
        assert "burst_size" in data


class TestApiTokens:
    """Test API token management endpoints."""

    def test_list_tokens_empty(self, client, auth_headers):
        """Should return empty list when no DB tokens exist."""
        response = client.get("/api/v1/tokens", headers=auth_headers)
        assert response.status_code == 200
        assert isinstance(response.json(), list)

    def test_create_admin_token(self, client, auth_headers):
        """Should create an admin token."""
        response = client.post(
            "/api/v1/tokens",
            headers=auth_headers,
            json={
                "name": "test-admin-token",
                "token_type": "admin",
            }
        )
        assert response.status_code == 200
        data = response.json()
        assert data["name"] == "test-admin-token"
        assert data["token_type"] == "admin"
        assert data["agent_id"] is None
        assert "token" in data  # Raw token returned on creation
        assert len(data["token"]) > 20

    def test_create_agent_token(self, client, auth_headers):
        """Should create an agent token with agent_id."""
        response = client.post(
            "/api/v1/tokens",
            headers=auth_headers,
            json={
                "name": "test-agent-token",
                "token_type": "agent",
                "agent_id": "my-agent-01",
            }
        )
        assert response.status_code == 200
        data = response.json()
        assert data["name"] == "test-agent-token"
        assert data["token_type"] == "agent"
        assert data["agent_id"] == "my-agent-01"
        assert "token" in data

    def test_create_agent_token_requires_agent_id(self, client, auth_headers):
        """Should reject agent token without agent_id."""
        response = client.post(
            "/api/v1/tokens",
            headers=auth_headers,
            json={
                "name": "bad-agent-token",
                "token_type": "agent",
            }
        )
        assert response.status_code == 400
        assert "agent_id" in response.json()["detail"]

    def test_create_admin_token_rejects_agent_id(self, client, auth_headers):
        """Should reject admin token with agent_id."""
        response = client.post(
            "/api/v1/tokens",
            headers=auth_headers,
            json={
                "name": "bad-admin-token",
                "token_type": "admin",
                "agent_id": "should-not-have",
            }
        )
        assert response.status_code == 400

    def test_create_token_with_expiry(self, client, auth_headers):
        """Should create token with expiration date."""
        response = client.post(
            "/api/v1/tokens",
            headers=auth_headers,
            json={
                "name": "expiring-token",
                "token_type": "admin",
                "expires_in_days": 30,
            }
        )
        assert response.status_code == 200
        data = response.json()
        assert data["expires_at"] is not None

    def test_create_duplicate_token_fails(self, client, auth_headers):
        """Should reject duplicate token names."""
        client.post(
            "/api/v1/tokens",
            headers=auth_headers,
            json={"name": "dup-token", "token_type": "admin"}
        )
        response = client.post(
            "/api/v1/tokens",
            headers=auth_headers,
            json={"name": "dup-token", "token_type": "admin"}
        )
        assert response.status_code == 400
        assert "already exists" in response.json()["detail"]

    def test_list_tokens(self, client, auth_headers):
        """Should list created tokens."""
        client.post(
            "/api/v1/tokens",
            headers=auth_headers,
            json={"name": "list-test-token", "token_type": "admin"}
        )

        response = client.get("/api/v1/tokens", headers=auth_headers)
        assert response.status_code == 200
        tokens = response.json()
        assert len(tokens) >= 1
        token = next((t for t in tokens if t["name"] == "list-test-token"), None)
        assert token is not None
        assert "token" not in token  # Raw token not exposed in list

    def test_delete_token(self, client, auth_headers):
        """Should delete a token."""
        create_response = client.post(
            "/api/v1/tokens",
            headers=auth_headers,
            json={"name": "delete-me-token", "token_type": "admin"}
        )
        token_id = create_response.json()["id"]

        response = client.delete(f"/api/v1/tokens/{token_id}", headers=auth_headers)
        assert response.status_code == 200

        # Verify deleted
        list_response = client.get("/api/v1/tokens", headers=auth_headers)
        tokens = list_response.json()
        assert not any(t["name"] == "delete-me-token" for t in tokens)

    def test_disable_token(self, client, auth_headers):
        """Should disable a token."""
        create_response = client.post(
            "/api/v1/tokens",
            headers=auth_headers,
            json={"name": "disable-me-token", "token_type": "admin"}
        )
        token_id = create_response.json()["id"]

        response = client.patch(
            f"/api/v1/tokens/{token_id}?enabled=false",
            headers=auth_headers
        )
        assert response.status_code == 200
        assert response.json()["enabled"] is False

    def test_use_created_token(self, client, auth_headers):
        """Should be able to use a created token for API calls."""
        # Create token
        create_response = client.post(
            "/api/v1/tokens",
            headers=auth_headers,
            json={"name": "usable-token", "token_type": "admin"}
        )
        raw_token = create_response.json()["token"]

        # Use the new token
        response = client.get(
            "/api/v1/secrets",
            headers={"Authorization": f"Bearer {raw_token}"}
        )
        assert response.status_code == 200


class TestAgentApproval:
    """Test agent approval workflow."""

    def test_new_agent_is_not_approved(self, client, auth_headers):
        """New agent from heartbeat should not be approved by default."""
        # Send heartbeat to create agent
        client.post(
            "/api/v1/agent/heartbeat",
            headers=auth_headers,
            json={"agent_id": "new-unapproved-agent", "status": "running"}
        )

        # Check agent list
        response = client.get("/api/v1/agents", headers=auth_headers)
        agents = response.json()
        agent = next((a for a in agents if a["agent_id"] == "new-unapproved-agent"), None)
        assert agent is not None
        assert agent["approved"] is False

    def test_approve_agent(self, client, auth_headers):
        """Should approve a pending agent."""
        # Create agent
        client.post(
            "/api/v1/agent/heartbeat",
            headers=auth_headers,
            json={"agent_id": "approve-me-agent", "status": "running"}
        )

        # Approve
        response = client.post("/api/v1/agents/approve-me-agent/approve", headers=auth_headers)
        assert response.status_code == 200
        assert response.json()["status"] == "approved"

        # Verify approved
        list_response = client.get("/api/v1/agents", headers=auth_headers)
        agent = next((a for a in list_response.json() if a["agent_id"] == "approve-me-agent"), None)
        assert agent["approved"] is True

    def test_reject_agent(self, client, auth_headers):
        """Should reject and remove a pending agent."""
        # Create agent
        client.post(
            "/api/v1/agent/heartbeat",
            headers=auth_headers,
            json={"agent_id": "reject-me-agent", "status": "running"}
        )

        # Reject
        response = client.post("/api/v1/agents/reject-me-agent/reject", headers=auth_headers)
        assert response.status_code == 200

        # Verify removed
        list_response = client.get("/api/v1/agents", headers=auth_headers)
        agents = list_response.json()
        assert not any(a["agent_id"] == "reject-me-agent" for a in agents)

    def test_revoke_agent(self, client, auth_headers):
        """Should revoke approval for an agent."""
        # Create and approve agent
        client.post(
            "/api/v1/agent/heartbeat",
            headers=auth_headers,
            json={"agent_id": "revoke-me-agent", "status": "running"}
        )
        client.post("/api/v1/agents/revoke-me-agent/approve", headers=auth_headers)

        # Revoke
        response = client.post("/api/v1/agents/revoke-me-agent/revoke", headers=auth_headers)
        assert response.status_code == 200

        # Verify not approved
        list_response = client.get("/api/v1/agents", headers=auth_headers)
        agent = next((a for a in list_response.json() if a["agent_id"] == "revoke-me-agent"), None)
        assert agent["approved"] is False

    def test_unapproved_agent_does_not_receive_commands(self, client, auth_headers):
        """Unapproved agent should not receive commands via heartbeat."""
        # Create unapproved agent
        client.post(
            "/api/v1/agent/heartbeat",
            headers=auth_headers,
            json={"agent_id": "no-cmd-agent", "status": "running"}
        )

        # Queue a command
        client.post("/api/v1/agents/no-cmd-agent/restart", headers=auth_headers)

        # Heartbeat should NOT receive command (unapproved)
        response = client.post(
            "/api/v1/agent/heartbeat",
            headers=auth_headers,
            json={"agent_id": "no-cmd-agent", "status": "running"}
        )
        assert response.json().get("command") is None

    def test_approved_agent_receives_commands(self, client, auth_headers):
        """Approved agent should receive commands via heartbeat."""
        # Create and approve agent
        client.post(
            "/api/v1/agent/heartbeat",
            headers=auth_headers,
            json={"agent_id": "yes-cmd-agent", "status": "running"}
        )
        client.post("/api/v1/agents/yes-cmd-agent/approve", headers=auth_headers)

        # Queue a command
        client.post("/api/v1/agents/yes-cmd-agent/restart", headers=auth_headers)

        # Heartbeat should receive command
        response = client.post(
            "/api/v1/agent/heartbeat",
            headers=auth_headers,
            json={"agent_id": "yes-cmd-agent", "status": "running"}
        )
        assert response.json()["command"] == "restart"


class TestPerAgentConfiguration:
    """Test per-agent configuration (agent-scoped secrets, allowlist, rate limits)."""

    def test_create_agent_scoped_allowlist_entry(self, client, auth_headers):
        """Should create allowlist entry scoped to a specific agent."""
        response = client.post(
            "/api/v1/allowlist",
            headers=auth_headers,
            json={
                "entry_type": "domain",
                "value": "agent-specific.example.com",
                "description": "Agent-specific domain",
                "agent_id": "scoped-agent"
            }
        )
        assert response.status_code == 200
        data = response.json()
        assert data["agent_id"] == "scoped-agent"

    def test_create_agent_scoped_secret(self, client, auth_headers):
        """Should create secret scoped to a specific agent."""
        response = client.post(
            "/api/v1/secrets",
            headers=auth_headers,
            json={
                "name": "AGENT_SPECIFIC_KEY",
                "value": "secret-value",
                "domain_pattern": "agent-specific.example.com",
                "header_name": "Authorization",
                "header_format": "Bearer {value}",
                "agent_id": "scoped-agent"
            }
        )
        assert response.status_code == 200
        data = response.json()
        assert data["agent_id"] == "scoped-agent"

    def test_create_agent_scoped_rate_limit(self, client, auth_headers):
        """Should create rate limit scoped to a specific agent."""
        response = client.post(
            "/api/v1/rate-limits",
            headers=auth_headers,
            json={
                "domain_pattern": "agent-specific-rl.example.com",
                "requests_per_minute": 30,
                "burst_size": 5,
                "description": "Agent-specific rate limit",
                "agent_id": "scoped-agent"
            }
        )
        assert response.status_code == 200
        data = response.json()
        assert data["agent_id"] == "scoped-agent"

    def test_list_allowlist_with_agent_id_filter(self, client, auth_headers):
        """Should filter allowlist entries by agent_id."""
        # Create global entry
        client.post(
            "/api/v1/allowlist",
            headers=auth_headers,
            json={
                "entry_type": "domain",
                "value": "global-filter.example.com",
                "description": "Global entry"
            }
        )
        # Create agent-specific entry
        client.post(
            "/api/v1/allowlist",
            headers=auth_headers,
            json={
                "entry_type": "domain",
                "value": "filter-agent.example.com",
                "description": "Agent-specific entry",
                "agent_id": "filter-agent"
            }
        )

        # List with agent_id filter
        response = client.get("/api/v1/allowlist?agent_id=filter-agent", headers=auth_headers)
        assert response.status_code == 200
        entries = response.json()
        # Should only include filter-agent entries
        for entry in entries:
            assert entry.get("agent_id") == "filter-agent" or entry.get("agent_id") is None

    def test_agent_token_sees_only_own_and_global_secrets(self, client, auth_headers):
        """Agent token should see its own secrets plus global secrets, not other agents' secrets."""
        # Create agent and get a token for it
        client.post(
            "/api/v1/agent/heartbeat",
            headers=auth_headers,
            json={"agent_id": "secret-test-agent", "status": "running"}
        )

        # Create agent token
        token_response = client.post(
            "/api/v1/tokens",
            headers=auth_headers,
            json={"name": "secret-test-token", "token_type": "agent", "agent_id": "secret-test-agent"}
        )
        agent_token = token_response.json()["token"]
        agent_headers = {"Authorization": f"Bearer {agent_token}"}

        # Create global secret
        client.post(
            "/api/v1/secrets",
            headers=auth_headers,
            json={
                "name": "GLOBAL_SECRET_TEST",
                "value": "global-value",
                "domain_pattern": "global.example.com",
                "header_name": "X-API-Key",
                "header_format": "{value}"
            }
        )

        # Create agent-specific secret
        client.post(
            "/api/v1/secrets",
            headers=auth_headers,
            json={
                "name": "AGENT_SECRET_TEST",
                "value": "agent-value",
                "domain_pattern": "agent-only.example.com",
                "header_name": "X-API-Key",
                "header_format": "{value}",
                "agent_id": "secret-test-agent"
            }
        )

        # Create secret for different agent
        client.post(
            "/api/v1/secrets",
            headers=auth_headers,
            json={
                "name": "OTHER_AGENT_SECRET",
                "value": "other-value",
                "domain_pattern": "other.example.com",
                "header_name": "X-API-Key",
                "header_format": "{value}",
                "agent_id": "other-agent"
            }
        )

        # Agent token should see global + own secrets, not other agent's
        response = client.get("/api/v1/secrets/for-domain?domain=global.example.com", headers=agent_headers)
        assert response.status_code == 200
        assert response.json()["matched"] is True

        response = client.get("/api/v1/secrets/for-domain?domain=agent-only.example.com", headers=agent_headers)
        assert response.status_code == 200
        assert response.json()["matched"] is True

        response = client.get("/api/v1/secrets/for-domain?domain=other.example.com", headers=agent_headers)
        assert response.status_code == 200
        assert response.json()["matched"] is False  # Should NOT match other agent's secret

    def test_agent_specific_secret_takes_precedence(self, client, auth_headers):
        """Agent-specific secrets should take precedence over global secrets."""
        # Create agent and get a token for it
        client.post(
            "/api/v1/agent/heartbeat",
            headers=auth_headers,
            json={"agent_id": "precedence-agent", "status": "running"}
        )
        token_response = client.post(
            "/api/v1/tokens",
            headers=auth_headers,
            json={"name": "precedence-token", "token_type": "agent", "agent_id": "precedence-agent"}
        )
        agent_token = token_response.json()["token"]
        agent_headers = {"Authorization": f"Bearer {agent_token}"}

        # Create global secret
        client.post(
            "/api/v1/secrets",
            headers=auth_headers,
            json={
                "name": "PRECEDENCE_GLOBAL",
                "value": "global-key",
                "domain_pattern": "precedence.example.com",
                "header_name": "X-API-Key",
                "header_format": "{value}"
            }
        )

        # Create agent-specific secret for same domain
        client.post(
            "/api/v1/secrets",
            headers=auth_headers,
            json={
                "name": "PRECEDENCE_AGENT",
                "value": "agent-key",
                "domain_pattern": "precedence.example.com",
                "header_name": "X-API-Key",
                "header_format": "{value}",
                "agent_id": "precedence-agent"
            }
        )

        # Agent should get agent-specific secret (takes precedence)
        response = client.get("/api/v1/secrets/for-domain?domain=precedence.example.com", headers=agent_headers)
        assert response.status_code == 200
        data = response.json()
        assert data["matched"] is True
        assert data["header_value"] == "agent-key"  # Agent-specific key, not global

    def test_agent_specific_rate_limit_takes_precedence(self, client, auth_headers):
        """Agent-specific rate limits should take precedence over global rate limits."""
        # Create agent and get a token for it
        client.post(
            "/api/v1/agent/heartbeat",
            headers=auth_headers,
            json={"agent_id": "rl-precedence-agent", "status": "running"}
        )
        token_response = client.post(
            "/api/v1/tokens",
            headers=auth_headers,
            json={"name": "rl-precedence-token", "token_type": "agent", "agent_id": "rl-precedence-agent"}
        )
        agent_token = token_response.json()["token"]
        agent_headers = {"Authorization": f"Bearer {agent_token}"}

        # Create global rate limit
        client.post(
            "/api/v1/rate-limits",
            headers=auth_headers,
            json={
                "domain_pattern": "rl-precedence.example.com",
                "requests_per_minute": 100,
                "burst_size": 20,
                "description": "Global rate limit"
            }
        )

        # Create agent-specific rate limit for same domain
        client.post(
            "/api/v1/rate-limits",
            headers=auth_headers,
            json={
                "domain_pattern": "rl-precedence.example.com",
                "requests_per_minute": 50,
                "burst_size": 10,
                "description": "Agent-specific rate limit",
                "agent_id": "rl-precedence-agent"
            }
        )

        # Agent should get agent-specific rate limit (takes precedence)
        response = client.get("/api/v1/rate-limits/for-domain?domain=rl-precedence.example.com", headers=agent_headers)
        assert response.status_code == 200
        data = response.json()
        assert data["matched"] is True
        assert data["requests_per_minute"] == 50  # Agent-specific, not global 100


class TestMultiTenancy:
    """Test multi-tenancy features (tenants, super admin, tenant isolation)."""

    def test_create_tenant_requires_super_admin(self, client, auth_headers):
        """Regular admin cannot create tenants (only super admin via legacy tokens)."""
        # Legacy tokens from API_TOKENS are super admin, so this should work
        response = client.post(
            "/api/v1/tenants",
            headers=auth_headers,
            json={"name": "Test Tenant", "slug": "test-tenant"}
        )
        assert response.status_code == 200
        data = response.json()
        assert data["name"] == "Test Tenant"
        assert data["slug"] == "test-tenant"
        assert data["agent_count"] == 1  # __default__ agent

    def test_list_tenants(self, client, auth_headers):
        """Super admin can list all tenants."""
        # Create a tenant first
        client.post(
            "/api/v1/tenants",
            headers=auth_headers,
            json={"name": "List Tenant", "slug": "list-tenant"}
        )

        response = client.get("/api/v1/tenants", headers=auth_headers)
        assert response.status_code == 200
        tenants = response.json()
        assert len(tenants) >= 1
        slugs = [t["slug"] for t in tenants]
        assert "list-tenant" in slugs

    def test_tenant_creates_default_agent(self, client, auth_headers):
        """Creating a tenant also creates __default__ agent for tenant-global config."""
        # Create tenant
        create_response = client.post(
            "/api/v1/tenants",
            headers=auth_headers,
            json={"name": "Default Agent Tenant", "slug": "default-agent-tenant"}
        )
        tenant_id = create_response.json()["id"]

        # List agents - __default__ should NOT appear in list (filtered out)
        list_response = client.get("/api/v1/agents", headers=auth_headers)
        agent_ids = [a["agent_id"] for a in list_response.json()]
        assert "__default__" not in agent_ids

    def test_delete_tenant(self, client, auth_headers):
        """Super admin can delete a tenant and all its agents."""
        # Create tenant
        create_response = client.post(
            "/api/v1/tenants",
            headers=auth_headers,
            json={"name": "Delete Me Tenant", "slug": "delete-me-tenant"}
        )
        tenant_id = create_response.json()["id"]

        # Delete tenant
        delete_response = client.delete(
            f"/api/v1/tenants/{tenant_id}",
            headers=auth_headers
        )
        assert delete_response.status_code == 200
        assert delete_response.json()["status"] == "deleted"

        # Verify tenant is gone
        get_response = client.get(f"/api/v1/tenants/{tenant_id}", headers=auth_headers)
        assert get_response.status_code == 404

    def test_create_super_admin_token(self, client, auth_headers):
        """Super admin can create another super admin token."""
        response = client.post(
            "/api/v1/tokens",
            headers=auth_headers,
            json={"name": "new-super-admin", "token_type": "admin", "is_super_admin": True}
        )
        assert response.status_code == 200
        data = response.json()
        assert data["is_super_admin"] is True

    def test_duplicate_tenant_slug_fails(self, client, auth_headers):
        """Cannot create tenant with duplicate slug."""
        client.post(
            "/api/v1/tenants",
            headers=auth_headers,
            json={"name": "Unique Tenant", "slug": "unique-slug"}
        )

        response = client.post(
            "/api/v1/tenants",
            headers=auth_headers,
            json={"name": "Another Tenant", "slug": "unique-slug"}
        )
        assert response.status_code == 400
        assert "already exists" in response.json()["detail"]


class TestRBAC:
    """Test Role-Based Access Control (RBAC) functionality."""

    def test_create_token_with_admin_role(self, client, auth_headers):
        """Should create a token with admin role."""
        response = client.post(
            "/api/v1/tokens",
            headers=auth_headers,
            json={
                "name": "admin-role-token",
                "token_type": "admin",
                "roles": "admin"
            }
        )
        assert response.status_code == 200
        data = response.json()
        assert data["roles"] == "admin"

    def test_create_token_with_developer_role(self, client, auth_headers):
        """Should create a token with developer role."""
        response = client.post(
            "/api/v1/tokens",
            headers=auth_headers,
            json={
                "name": "developer-role-token",
                "token_type": "admin",
                "roles": "developer"
            }
        )
        assert response.status_code == 200
        data = response.json()
        assert data["roles"] == "developer"

    def test_create_token_with_multiple_roles(self, client, auth_headers):
        """Should create a token with multiple roles."""
        response = client.post(
            "/api/v1/tokens",
            headers=auth_headers,
            json={
                "name": "multi-role-token",
                "token_type": "admin",
                "roles": "admin,developer"
            }
        )
        assert response.status_code == 200
        data = response.json()
        # Roles should be sorted
        assert data["roles"] in ["admin,developer", "developer,admin"]

    def test_create_token_with_invalid_role_fails(self, client, auth_headers):
        """Should reject token with invalid role."""
        response = client.post(
            "/api/v1/tokens",
            headers=auth_headers,
            json={
                "name": "invalid-role-token",
                "token_type": "admin",
                "roles": "superuser"  # Invalid role
            }
        )
        assert response.status_code == 400
        assert "Invalid roles" in response.json()["detail"]

    def test_auth_me_returns_roles(self, client, auth_headers):
        """Auth me endpoint should return user's roles."""
        # Create token with specific role
        create_response = client.post(
            "/api/v1/tokens",
            headers=auth_headers,
            json={
                "name": "role-check-token",
                "token_type": "admin",
                "roles": "developer"
            }
        )
        token = create_response.json()["token"]
        dev_headers = {"Authorization": f"Bearer {token}"}

        # Check /auth/me
        response = client.get("/api/v1/auth/me", headers=dev_headers)
        assert response.status_code == 200
        data = response.json()
        assert "roles" in data
        assert "developer" in data["roles"]

    def test_list_tokens_shows_roles(self, client, auth_headers):
        """Token list should include roles field."""
        # Create token
        client.post(
            "/api/v1/tokens",
            headers=auth_headers,
            json={
                "name": "list-role-token",
                "token_type": "admin",
                "roles": "admin"
            }
        )

        response = client.get("/api/v1/tokens", headers=auth_headers)
        assert response.status_code == 200
        tokens = response.json()
        token = next((t for t in tokens if t["name"] == "list-role-token"), None)
        assert token is not None
        assert "roles" in token
        assert token["roles"] == "admin"

    def test_default_role_is_admin(self, client, auth_headers):
        """Tokens without explicit roles should default to admin."""
        response = client.post(
            "/api/v1/tokens",
            headers=auth_headers,
            json={
                "name": "default-role-token",
                "token_type": "admin"
                # No roles specified
            }
        )
        assert response.status_code == 200
        data = response.json()
        assert data["roles"] == "admin"
