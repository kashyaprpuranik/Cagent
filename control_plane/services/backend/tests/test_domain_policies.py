"""Tests for domain policy management endpoints."""


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
        policies = response.json()["items"]
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
        policies = list_response.json()["items"]
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
        policies = response.json()["items"]
        # Should only include filter-agent policies
        for policy in policies:
            assert policy.get("agent_id") == "filter-agent" or policy.get("agent_id") is None

    def test_agent_token_sees_own_and_global_policies(self, client, auth_headers):
        """Agent token should see its own policies plus global policies."""
        # Create agent and get a token for it
        client.post(
            "/api/v1/agent/heartbeat?agent_id=policy-test-agent",
            headers=auth_headers,
            json={"status": "running"}
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
            "/api/v1/agent/heartbeat?agent_id=precedence-agent",
            headers=auth_headers,
            json={"status": "running"}
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


class TestDomainPolicyExportAndGetById:
    """Test domain policy export and get-by-id endpoints."""

    def test_export_domain_policies(self, client, auth_headers):
        """Should export domain list without credentials."""
        # Create a policy
        client.post(
            "/api/v1/domain-policies",
            headers=auth_headers,
            json={"domain": "export-test.example.com"}
        )

        response = client.get("/api/v1/domain-policies/export", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert "domains" in data
        assert "export-test.example.com" in data["domains"]
        assert "generated_at" in data

    def test_export_excludes_disabled_policies(self, client, auth_headers):
        """Export should only include enabled policies."""
        # Create and disable a policy
        create_response = client.post(
            "/api/v1/domain-policies",
            headers=auth_headers,
            json={"domain": "disabled-export.example.com"}
        )
        policy_id = create_response.json()["id"]
        client.put(
            f"/api/v1/domain-policies/{policy_id}",
            headers=auth_headers,
            json={"enabled": False}
        )

        response = client.get("/api/v1/domain-policies/export", headers=auth_headers)
        domains = response.json()["domains"]
        assert "disabled-export.example.com" not in domains

    def test_get_domain_policy_by_id(self, client, auth_headers):
        """Should get a specific domain policy by ID."""
        create_response = client.post(
            "/api/v1/domain-policies",
            headers=auth_headers,
            json={"domain": "get-by-id.example.com", "description": "Test policy"}
        )
        policy_id = create_response.json()["id"]

        response = client.get(f"/api/v1/domain-policies/{policy_id}", headers=auth_headers)
        assert response.status_code == 200
        data = response.json()
        assert data["domain"] == "get-by-id.example.com"
        assert data["id"] == policy_id

    def test_get_domain_policy_not_found(self, client, auth_headers):
        """Should return 404 for non-existent policy."""
        response = client.get("/api/v1/domain-policies/99999", headers=auth_headers)
        assert response.status_code == 404
