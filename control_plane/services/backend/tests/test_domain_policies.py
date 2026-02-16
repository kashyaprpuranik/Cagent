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
        """Should reject duplicate domain (same domain + profile_id + tenant)."""
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


class TestProfileScopedDomainPolicies:
    """Test profile-scoped domain policy configuration."""

    def test_create_profile_scoped_policy(self, client, auth_headers):
        """Should create domain policy scoped to a specific profile."""
        # Create a profile first
        profile_resp = client.post(
            "/api/v1/security-profiles",
            headers=auth_headers,
            json={"name": "dp-test-profile"},
        )
        profile_id = profile_resp.json()["id"]

        response = client.post(
            "/api/v1/domain-policies",
            headers=auth_headers,
            json={
                "domain": "profile-specific.example.com",
                "description": "Profile-scoped domain",
                "profile_id": profile_id,
            }
        )
        assert response.status_code == 200
        data = response.json()
        assert data["profile_id"] == profile_id

    def test_filter_policies_by_profile_id(self, client, auth_headers):
        """Should filter domain policies by profile_id."""
        profile_resp = client.post(
            "/api/v1/security-profiles",
            headers=auth_headers,
            json={"name": "dp-filter-profile"},
        )
        profile_id = profile_resp.json()["id"]

        # Create unscoped policy
        client.post(
            "/api/v1/domain-policies",
            headers=auth_headers,
            json={"domain": "unscoped-filter.example.com"}
        )
        # Create profile-scoped policy
        client.post(
            "/api/v1/domain-policies",
            headers=auth_headers,
            json={
                "domain": "scoped-filter.example.com",
                "profile_id": profile_id,
            }
        )

        # List with profile_id filter
        response = client.get(f"/api/v1/domain-policies?profile_id={profile_id}", headers=auth_headers)
        assert response.status_code == 200
        policies = response.json()["items"]
        domains = [p["domain"] for p in policies]
        assert "scoped-filter.example.com" in domains
        assert "unscoped-filter.example.com" not in domains

    def test_agent_token_sees_profile_policies(self, client, auth_headers):
        """Agent token should see policies from its assigned profile."""
        # Create agent token (which auto-provisions the agent)
        token_response = client.post(
            "/api/v1/tokens",
            headers=auth_headers,
            json={"name": "dp-profile-token", "token_type": "agent", "agent_id": "dp-profile-agent"}
        )
        agent_token = token_response.json()["token"]
        agent_headers = {"Authorization": f"Bearer {agent_token}"}

        # Create profiles
        profile_a_resp = client.post("/api/v1/security-profiles", headers=auth_headers, json={"name": "dp-prof-a"})
        profile_a_id = profile_a_resp.json()["id"]
        profile_b_resp = client.post("/api/v1/security-profiles", headers=auth_headers, json={"name": "dp-prof-b"})
        profile_b_id = profile_b_resp.json()["id"]

        # Assign profile-a to agent
        client.put(
            "/api/v1/agents/dp-profile-agent/profile",
            headers=auth_headers,
            json={"profile_id": profile_a_id},
        )

        # Create policy in profile-a with credential
        client.post(
            "/api/v1/domain-policies",
            headers=auth_headers,
            json={
                "domain": "in-profile.example.com",
                "profile_id": profile_a_id,
                "credential": {
                    "header": "X-API-Key",
                    "format": "{value}",
                    "value": "profile-value",
                },
            }
        )

        # Create policy in profile-b (agent should NOT see this)
        client.post(
            "/api/v1/domain-policies",
            headers=auth_headers,
            json={
                "domain": "other-profile.example.com",
                "profile_id": profile_b_id,
                "credential": {
                    "header": "X-API-Key",
                    "format": "{value}",
                    "value": "other-value",
                },
            }
        )

        # Agent should see profile-a policy
        response = client.get(
            "/api/v1/domain-policies/for-domain?domain=in-profile.example.com",
            headers=agent_headers
        )
        assert response.status_code == 200
        assert response.json()["matched"] is True

        # Agent should NOT see profile-b policy
        response = client.get(
            "/api/v1/domain-policies/for-domain?domain=other-profile.example.com",
            headers=agent_headers
        )
        assert response.status_code == 200
        assert response.json()["matched"] is False

    def test_agent_falls_back_to_default_profile(self, client, auth_headers):
        """Agent without assigned profile should see policies from 'default' profile."""
        # Create agent token (which auto-provisions the agent)
        token_response = client.post(
            "/api/v1/tokens",
            headers=auth_headers,
            json={"name": "dp-default-token", "token_type": "agent", "agent_id": "dp-default-agent"}
        )
        agent_token = token_response.json()["token"]
        agent_headers = {"Authorization": f"Bearer {agent_token}"}

        # Create "default" profile
        default_resp = client.post("/api/v1/security-profiles", headers=auth_headers, json={"name": "default"})
        default_profile_id = default_resp.json()["id"]

        # Create policy in default profile
        client.post(
            "/api/v1/domain-policies",
            headers=auth_headers,
            json={
                "domain": "default-profile-policy.example.com",
                "profile_id": default_profile_id,
                "requests_per_minute": 50,
                "credential": {
                    "header": "X-API-Key",
                    "format": "{value}",
                    "value": "default-key",
                },
            }
        )

        # Agent (no profile assigned) should see default profile policy
        response = client.get(
            "/api/v1/domain-policies/for-domain?domain=default-profile-policy.example.com",
            headers=agent_headers
        )
        assert response.status_code == 200
        data = response.json()
        assert data["matched"] is True
        assert data["requests_per_minute"] == 50
        assert data["header_value"] == "default-key"


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
