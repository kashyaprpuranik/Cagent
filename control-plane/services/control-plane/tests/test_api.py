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

    def test_domain_policies_requires_auth(self, client):
        """Domain policies endpoint should require authentication."""
        response = client.get("/api/v1/domain-policies")
        assert response.status_code == 401

    def test_domain_policies_rejects_invalid_token(self, client):
        """Domain policies endpoint should reject invalid tokens."""
        response = client.get(
            "/api/v1/domain-policies",
            headers={"Authorization": "Bearer invalid-token"}
        )
        assert response.status_code == 403

    def test_domain_policies_accepts_valid_token(self, client, auth_headers):
        """Domain policies endpoint should accept valid tokens."""
        response = client.get("/api/v1/domain-policies", headers=auth_headers)
        assert response.status_code == 200


class TestDomainPolicies:
    """Test domain policy management endpoints."""

    def test_create_domain_policy(self, client, auth_headers):
        """Should create a new domain policy."""
        response = client.post(
            "/api/v1/domain-policies",
            headers=auth_headers,
            json={
                "domain": "api.newservice.com",
                "alias": "newservice",
                "description": "New service API access",
                "requests_per_minute": 60,
                "burst_size": 10,
            }
        )
        assert response.status_code == 200
        data = response.json()
        assert data["domain"] == "api.newservice.com"
        assert data["alias"] == "newservice"
        assert data["requests_per_minute"] == 60
        assert data["enabled"] is True

    def test_create_domain_policy_with_paths(self, client, auth_headers):
        """Should create domain policy with path restrictions."""
        response = client.post(
            "/api/v1/domain-policies",
            headers=auth_headers,
            json={
                "domain": "api.example.com",
                "allowed_paths": ["/v1/chat/*", "/v1/models"],
            }
        )
        assert response.status_code == 200
        data = response.json()
        assert data["allowed_paths"] == ["/v1/chat/*", "/v1/models"]

    def test_create_domain_policy_with_credential(self, client, auth_headers):
        """Should create domain policy with credential injection."""
        response = client.post(
            "/api/v1/domain-policies",
            headers=auth_headers,
            json={
                "domain": "api.secret.com",
                "credential": {
                    "header": "Authorization",
                    "format": "Bearer {value}",
                    "value": "sk-test-key-12345",
                },
            }
        )
        assert response.status_code == 200
        data = response.json()
        assert data["has_credential"] is True
        assert data["credential_header"] == "Authorization"
        assert data["credential_format"] == "Bearer {value}"

    def test_create_duplicate_domain_policy_fails(self, client, auth_headers):
        """Should reject duplicate domain (same domain + agent_id)."""
        policy_data = {
            "domain": "duplicate.example.com",
            "requests_per_minute": 60,
        }
        # Create first
        response = client.post("/api/v1/domain-policies", headers=auth_headers, json=policy_data)
        assert response.status_code == 200

        # Duplicate should fail
        response = client.post("/api/v1/domain-policies", headers=auth_headers, json=policy_data)
        assert response.status_code == 400
        assert "already exists" in response.json()["detail"]

    def test_list_domain_policies(self, client, auth_headers):
        """Should list all domain policies."""
        # Create a policy
        client.post(
            "/api/v1/domain-policies",
            headers=auth_headers,
            json={"domain": "list-test.example.com"}
        )

        response = client.get("/api/v1/domain-policies", headers=auth_headers)
        assert response.status_code == 200
        policies = response.json()
        assert len(policies) >= 1

        # Find our policy
        policy = next((p for p in policies if p["domain"] == "list-test.example.com"), None)
        assert policy is not None

    def test_update_domain_policy(self, client, auth_headers):
        """Should update domain policy."""
        # Create policy
        create_response = client.post(
            "/api/v1/domain-policies",
            headers=auth_headers,
            json={
                "domain": "update-test.example.com",
                "requests_per_minute": 60,
            }
        )
        policy_id = create_response.json()["id"]

        # Update
        response = client.put(
            f"/api/v1/domain-policies/{policy_id}",
            headers=auth_headers,
            json={
                "requests_per_minute": 120,
                "burst_size": 25,
                "description": "Updated description",
            }
        )
        assert response.status_code == 200
        data = response.json()
        assert data["requests_per_minute"] == 120
        assert data["burst_size"] == 25
        assert data["description"] == "Updated description"

    def test_disable_domain_policy(self, client, auth_headers):
        """Should disable domain policy."""
        # Create policy
        create_response = client.post(
            "/api/v1/domain-policies",
            headers=auth_headers,
            json={"domain": "disable-test.example.com"}
        )
        policy_id = create_response.json()["id"]

        # Disable
        response = client.put(
            f"/api/v1/domain-policies/{policy_id}",
            headers=auth_headers,
            json={"enabled": False}
        )
        assert response.status_code == 200
        assert response.json()["enabled"] is False

    def test_delete_domain_policy(self, client, auth_headers):
        """Should delete domain policy."""
        # Create policy
        create_response = client.post(
            "/api/v1/domain-policies",
            headers=auth_headers,
            json={"domain": "delete-test.example.com"}
        )
        policy_id = create_response.json()["id"]

        # Delete
        response = client.delete(f"/api/v1/domain-policies/{policy_id}", headers=auth_headers)
        assert response.status_code == 200

        # Verify deleted
        list_response = client.get("/api/v1/domain-policies", headers=auth_headers)
        policies = list_response.json()
        assert not any(p["domain"] == "delete-test.example.com" for p in policies)

    def test_rotate_credential(self, client, auth_headers):
        """Should rotate domain policy credential."""
        # Create policy with credential
        create_response = client.post(
            "/api/v1/domain-policies",
            headers=auth_headers,
            json={
                "domain": "rotate-cred.example.com",
                "credential": {
                    "header": "Authorization",
                    "format": "Bearer {value}",
                    "value": "old-secret",
                },
            }
        )
        policy_id = create_response.json()["id"]

        # Rotate
        response = client.post(
            f"/api/v1/domain-policies/{policy_id}/rotate-credential",
            headers=auth_headers,
            json={
                "header": "Authorization",
                "format": "Bearer {value}",
                "value": "new-secret",
            }
        )
        assert response.status_code == 200
        assert response.json()["has_credential"] is True


class TestDomainPolicyLookup:
    """Test domain-based policy lookup (for-domain endpoint)."""

    def test_get_policy_for_exact_domain(self, client, auth_headers):
        """Should match exact domain."""
        # Create policy
        client.post(
            "/api/v1/domain-policies",
            headers=auth_headers,
            json={
                "domain": "exact-lookup.example.com",
                "requests_per_minute": 45,
                "burst_size": 8,
                "credential": {
                    "header": "Authorization",
                    "format": "Bearer {value}",
                    "value": "exact-secret",
                },
            }
        )

        response = client.get(
            "/api/v1/domain-policies/for-domain?domain=exact-lookup.example.com",
            headers=auth_headers
        )
        assert response.status_code == 200
        data = response.json()
        assert data["matched"] is True
        assert data["requests_per_minute"] == 45
        assert data["header_name"] == "Authorization"
        assert data["header_value"] == "Bearer exact-secret"

    def test_get_policy_for_wildcard_domain(self, client, auth_headers):
        """Should match wildcard domain pattern."""
        # Create policy with wildcard
        client.post(
            "/api/v1/domain-policies",
            headers=auth_headers,
            json={
                "domain": "*.wildcard-lookup.com",
                "requests_per_minute": 100,
                "credential": {
                    "header": "Authorization",
                    "format": "token {value}",
                    "value": "wildcard-secret",
                },
            }
        )

        # Should match api.wildcard-lookup.com
        response = client.get(
            "/api/v1/domain-policies/for-domain?domain=api.wildcard-lookup.com",
            headers=auth_headers
        )
        assert response.status_code == 200
        data = response.json()
        assert data["matched"] is True
        assert data["requests_per_minute"] == 100
        assert data["header_value"] == "token wildcard-secret"

    def test_get_policy_for_alias(self, client, auth_headers):
        """Should resolve devbox.local alias to real domain."""
        # Create policy with alias
        client.post(
            "/api/v1/domain-policies",
            headers=auth_headers,
            json={
                "domain": "api.aliased.com",
                "alias": "myservice",
                "credential": {
                    "header": "Authorization",
                    "format": "Bearer {value}",
                    "value": "alias-secret",
                },
            }
        )

        # Query using devbox.local alias
        response = client.get(
            "/api/v1/domain-policies/for-domain?domain=myservice.devbox.local",
            headers=auth_headers
        )
        assert response.status_code == 200
        data = response.json()
        assert data["matched"] is True
        assert data["target_domain"] == "api.aliased.com"
        assert data["header_value"] == "Bearer alias-secret"

    def test_no_match_for_unknown_domain(self, client, auth_headers):
        """Should return no match for unknown domains."""
        response = client.get(
            "/api/v1/domain-policies/for-domain?domain=unknown.example.com",
            headers=auth_headers
        )
        assert response.status_code == 200
        data = response.json()
        assert data["matched"] is False


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
            "/api/v1/domain-policies",
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


class TestPerAgentDomainPolicies:
    """Test per-agent domain policy configuration."""

    def test_create_agent_scoped_policy(self, client, auth_headers):
        """Should create domain policy scoped to a specific agent."""
        response = client.post(
            "/api/v1/domain-policies",
            headers=auth_headers,
            json={
                "domain": "agent-specific.example.com",
                "description": "Agent-specific domain",
                "agent_id": "scoped-agent",
            }
        )
        assert response.status_code == 200
        data = response.json()
        assert data["agent_id"] == "scoped-agent"

    def test_filter_policies_by_agent_id(self, client, auth_headers):
        """Should filter domain policies by agent_id."""
        # Create global policy
        client.post(
            "/api/v1/domain-policies",
            headers=auth_headers,
            json={"domain": "global-filter.example.com"}
        )
        # Create agent-specific policy
        client.post(
            "/api/v1/domain-policies",
            headers=auth_headers,
            json={
                "domain": "filter-agent.example.com",
                "agent_id": "filter-agent",
            }
        )

        # List with agent_id filter
        response = client.get("/api/v1/domain-policies?agent_id=filter-agent", headers=auth_headers)
        assert response.status_code == 200
        policies = response.json()
        # Should only include filter-agent policies
        for policy in policies:
            assert policy.get("agent_id") == "filter-agent" or policy.get("agent_id") is None

    def test_agent_token_sees_own_and_global_policies(self, client, auth_headers):
        """Agent token should see its own policies plus global policies."""
        # Create agent and get a token for it
        client.post(
            "/api/v1/agent/heartbeat",
            headers=auth_headers,
            json={"agent_id": "policy-test-agent", "status": "running"}
        )

        # Create agent token
        token_response = client.post(
            "/api/v1/tokens",
            headers=auth_headers,
            json={"name": "policy-test-token", "token_type": "agent", "agent_id": "policy-test-agent"}
        )
        agent_token = token_response.json()["token"]
        agent_headers = {"Authorization": f"Bearer {agent_token}"}

        # Create global policy with credential
        client.post(
            "/api/v1/domain-policies",
            headers=auth_headers,
            json={
                "domain": "global-policy.example.com",
                "credential": {
                    "header": "X-API-Key",
                    "format": "{value}",
                    "value": "global-value",
                },
            }
        )

        # Create agent-specific policy with credential
        client.post(
            "/api/v1/domain-policies",
            headers=auth_headers,
            json={
                "domain": "agent-policy.example.com",
                "agent_id": "policy-test-agent",
                "credential": {
                    "header": "X-API-Key",
                    "format": "{value}",
                    "value": "agent-value",
                },
            }
        )

        # Create policy for different agent
        client.post(
            "/api/v1/domain-policies",
            headers=auth_headers,
            json={
                "domain": "other-policy.example.com",
                "agent_id": "other-agent",
                "credential": {
                    "header": "X-API-Key",
                    "format": "{value}",
                    "value": "other-value",
                },
            }
        )

        # Agent should see global policy
        response = client.get(
            "/api/v1/domain-policies/for-domain?domain=global-policy.example.com",
            headers=agent_headers
        )
        assert response.status_code == 200
        assert response.json()["matched"] is True

        # Agent should see its own policy
        response = client.get(
            "/api/v1/domain-policies/for-domain?domain=agent-policy.example.com",
            headers=agent_headers
        )
        assert response.status_code == 200
        assert response.json()["matched"] is True

        # Agent should NOT see other agent's policy
        response = client.get(
            "/api/v1/domain-policies/for-domain?domain=other-policy.example.com",
            headers=agent_headers
        )
        assert response.status_code == 200
        assert response.json()["matched"] is False

    def test_agent_specific_policy_takes_precedence(self, client, auth_headers):
        """Agent-specific policies should take precedence over global policies."""
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

        # Create global policy
        client.post(
            "/api/v1/domain-policies",
            headers=auth_headers,
            json={
                "domain": "precedence.example.com",
                "requests_per_minute": 100,
                "credential": {
                    "header": "X-API-Key",
                    "format": "{value}",
                    "value": "global-key",
                },
            }
        )

        # Create agent-specific policy for same domain
        client.post(
            "/api/v1/domain-policies",
            headers=auth_headers,
            json={
                "domain": "precedence.example.com",
                "agent_id": "precedence-agent",
                "requests_per_minute": 50,
                "credential": {
                    "header": "X-API-Key",
                    "format": "{value}",
                    "value": "agent-key",
                },
            }
        )

        # Agent should get agent-specific policy (takes precedence)
        response = client.get(
            "/api/v1/domain-policies/for-domain?domain=precedence.example.com",
            headers=agent_headers
        )
        assert response.status_code == 200
        data = response.json()
        assert data["matched"] is True
        assert data["requests_per_minute"] == 50  # Agent-specific, not global 100
        assert data["header_value"] == "agent-key"  # Agent-specific, not global


class TestMultiTenancy:
    """Test multi-tenancy features (tenants, super admin, tenant isolation)."""

    def test_create_tenant_requires_super_admin(self, client, super_admin_headers):
        """Super admin can create tenants."""
        response = client.post(
            "/api/v1/tenants",
            headers=super_admin_headers,
            json={"name": "Test Tenant", "slug": "test-tenant"}
        )
        assert response.status_code == 200
        data = response.json()
        assert data["name"] == "Test Tenant"
        assert data["slug"] == "test-tenant"
        assert data["agent_count"] == 1  # __default__ agent

    def test_list_tenants(self, client, super_admin_headers):
        """Super admin can list all tenants."""
        # Create a tenant first
        client.post(
            "/api/v1/tenants",
            headers=super_admin_headers,
            json={"name": "List Tenant", "slug": "list-tenant"}
        )

        response = client.get("/api/v1/tenants", headers=super_admin_headers)
        assert response.status_code == 200
        tenants = response.json()
        assert len(tenants) >= 1
        slugs = [t["slug"] for t in tenants]
        assert "list-tenant" in slugs

    def test_tenant_creates_default_agent(self, client, super_admin_headers):
        """Creating a tenant also creates __default__ agent for tenant-global config."""
        # Create tenant
        create_response = client.post(
            "/api/v1/tenants",
            headers=super_admin_headers,
            json={"name": "Default Agent Tenant", "slug": "default-agent-tenant"}
        )
        tenant_id = create_response.json()["id"]

        # List agents - __default__ should NOT appear in list (filtered out)
        list_response = client.get("/api/v1/agents", headers=super_admin_headers)
        agent_ids = [a["agent_id"] for a in list_response.json()]
        assert "__default__" not in agent_ids

    def test_delete_tenant(self, client, super_admin_headers):
        """Super admin can delete a tenant and all its agents."""
        # Create tenant
        create_response = client.post(
            "/api/v1/tenants",
            headers=super_admin_headers,
            json={"name": "Delete Me Tenant", "slug": "delete-me-tenant"}
        )
        tenant_id = create_response.json()["id"]

        # Delete tenant
        delete_response = client.delete(
            f"/api/v1/tenants/{tenant_id}",
            headers=super_admin_headers
        )
        assert delete_response.status_code == 200
        assert delete_response.json()["status"] == "deleted"

        # Verify tenant is gone
        get_response = client.get(f"/api/v1/tenants/{tenant_id}", headers=super_admin_headers)
        assert get_response.status_code == 404

    def test_create_super_admin_token(self, client, super_admin_headers):
        """Super admin can create another super admin token."""
        response = client.post(
            "/api/v1/tokens",
            headers=super_admin_headers,
            json={"name": "new-super-admin", "token_type": "admin", "is_super_admin": True}
        )
        assert response.status_code == 200
        data = response.json()
        assert data["is_super_admin"] is True

    def test_duplicate_tenant_slug_fails(self, client, super_admin_headers):
        """Cannot create tenant with duplicate slug."""
        client.post(
            "/api/v1/tenants",
            headers=super_admin_headers,
            json={"name": "Unique Tenant", "slug": "unique-slug"}
        )

        response = client.post(
            "/api/v1/tenants",
            headers=super_admin_headers,
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
