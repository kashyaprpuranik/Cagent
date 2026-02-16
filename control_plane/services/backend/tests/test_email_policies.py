"""Tests for email policy management endpoints."""


class TestEmailPolicies:
    """Test email policy CRUD endpoints."""

    def test_create_email_policy(self, client, auth_headers):
        """Should create a new email policy."""
        response = client.post(
            "/api/v1/email-policies",
            headers=auth_headers,
            json={
                "name": "work-gmail",
                "provider": "gmail",
                "email": "agent@company.com",
                "sends_per_hour": 50,
                "reads_per_hour": 200,
                "allowed_recipients": ["*@company.com"],
                "allowed_senders": ["*"],
            }
        )
        assert response.status_code == 200
        data = response.json()
        assert data["name"] == "work-gmail"
        assert data["provider"] == "gmail"
        assert data["email"] == "agent@company.com"
        assert data["sends_per_hour"] == 50
        assert data["enabled"] is True
        assert data["profile_id"] is None

    def test_create_email_policy_with_credential(self, client, auth_headers):
        """Should create email policy with OAuth2 credential."""
        response = client.post(
            "/api/v1/email-policies",
            headers=auth_headers,
            json={
                "name": "cred-gmail",
                "provider": "gmail",
                "email": "cred@company.com",
                "credential": {
                    "client_id": "test-client-id",
                    "client_secret": "test-secret",
                    "refresh_token": "test-refresh",
                },
            }
        )
        assert response.status_code == 200
        data = response.json()
        assert data["has_credential"] is True
        assert data["credential_type"] == "oauth2"

    def test_create_email_policy_generic_password(self, client, auth_headers):
        """Should create generic email policy with password credential."""
        response = client.post(
            "/api/v1/email-policies",
            headers=auth_headers,
            json={
                "name": "generic-mail",
                "provider": "generic",
                "email": "agent@mail.example.com",
                "imap_server": "imap.example.com",
                "smtp_server": "smtp.example.com",
                "credential": {"password": "secret123"},
            }
        )
        assert response.status_code == 200
        data = response.json()
        assert data["has_credential"] is True
        assert data["credential_type"] == "password"
        assert data["imap_server"] == "imap.example.com"

    def test_invalid_provider_rejected(self, client, auth_headers):
        """Should reject invalid provider."""
        response = client.post(
            "/api/v1/email-policies",
            headers=auth_headers,
            json={
                "name": "bad-provider",
                "provider": "yahoo",
                "email": "test@yahoo.com",
            }
        )
        assert response.status_code == 400
        assert "provider" in response.json()["detail"]

    def test_create_duplicate_fails(self, client, auth_headers):
        """Should reject duplicate name within same tenant + profile."""
        policy_data = {
            "name": "dup-test",
            "provider": "gmail",
            "email": "dup@company.com",
        }
        response = client.post("/api/v1/email-policies", headers=auth_headers, json=policy_data)
        assert response.status_code == 200

        response = client.post("/api/v1/email-policies", headers=auth_headers, json=policy_data)
        assert response.status_code == 400
        assert "already exists" in response.json()["detail"]

    def test_list_email_policies(self, client, auth_headers):
        """Should list email policies."""
        client.post(
            "/api/v1/email-policies",
            headers=auth_headers,
            json={"name": "list-test", "provider": "gmail", "email": "list@co.com"}
        )

        response = client.get("/api/v1/email-policies", headers=auth_headers)
        assert response.status_code == 200
        policies = response.json()
        assert len(policies) >= 1
        assert any(p["name"] == "list-test" for p in policies)

    def test_get_email_policy_by_id(self, client, auth_headers):
        """Should get a specific email policy by ID."""
        create = client.post(
            "/api/v1/email-policies",
            headers=auth_headers,
            json={"name": "get-by-id", "provider": "outlook", "email": "id@co.com"}
        )
        policy_id = create.json()["id"]

        response = client.get(f"/api/v1/email-policies/{policy_id}", headers=auth_headers)
        assert response.status_code == 200
        assert response.json()["name"] == "get-by-id"

    def test_get_email_policy_not_found(self, client, auth_headers):
        """Should return 404 for non-existent policy."""
        response = client.get("/api/v1/email-policies/99999", headers=auth_headers)
        assert response.status_code == 404

    def test_update_email_policy(self, client, auth_headers):
        """Should update email policy fields."""
        create = client.post(
            "/api/v1/email-policies",
            headers=auth_headers,
            json={"name": "update-test", "provider": "gmail", "email": "up@co.com"}
        )
        policy_id = create.json()["id"]

        response = client.put(
            f"/api/v1/email-policies/{policy_id}",
            headers=auth_headers,
            json={
                "sends_per_hour": 100,
                "reads_per_hour": 500,
                "allowed_recipients": ["*@newco.com"],
                "imap_server": "imap.custom.com",
                "imap_port": 993,
            }
        )
        assert response.status_code == 200
        data = response.json()
        assert data["sends_per_hour"] == 100
        assert data["reads_per_hour"] == 500
        assert data["allowed_recipients"] == ["*@newco.com"]
        assert data["imap_server"] == "imap.custom.com"

    def test_toggle_email_policy(self, client, auth_headers):
        """Should toggle enabled status."""
        create = client.post(
            "/api/v1/email-policies",
            headers=auth_headers,
            json={"name": "toggle-test", "provider": "gmail", "email": "toggle@co.com"}
        )
        policy_id = create.json()["id"]

        response = client.put(
            f"/api/v1/email-policies/{policy_id}",
            headers=auth_headers,
            json={"enabled": False}
        )
        assert response.status_code == 200
        assert response.json()["enabled"] is False

    def test_clear_credential(self, client, auth_headers):
        """Should clear credential from email policy."""
        create = client.post(
            "/api/v1/email-policies",
            headers=auth_headers,
            json={
                "name": "clear-cred",
                "provider": "generic",
                "email": "clear@co.com",
                "credential": {"password": "secret"},
            }
        )
        policy_id = create.json()["id"]
        assert create.json()["has_credential"] is True

        response = client.put(
            f"/api/v1/email-policies/{policy_id}",
            headers=auth_headers,
            json={"clear_credential": True}
        )
        assert response.status_code == 200
        assert response.json()["has_credential"] is False

    def test_delete_email_policy(self, client, auth_headers):
        """Should delete email policy."""
        create = client.post(
            "/api/v1/email-policies",
            headers=auth_headers,
            json={"name": "delete-test", "provider": "gmail", "email": "del@co.com"}
        )
        policy_id = create.json()["id"]

        response = client.delete(f"/api/v1/email-policies/{policy_id}", headers=auth_headers)
        assert response.status_code == 200
        assert response.json()["deleted"] is True

        # Verify deleted
        response = client.get(f"/api/v1/email-policies/{policy_id}", headers=auth_headers)
        assert response.status_code == 404


class TestProfileScopedEmailPolicies:
    """Test profile-scoped email policy configuration."""

    def test_create_profile_scoped_policy(self, client, auth_headers):
        """Should create email policy scoped to a specific profile."""
        profile_resp = client.post(
            "/api/v1/security-profiles",
            headers=auth_headers,
            json={"name": "ep-test-profile"},
        )
        profile_id = profile_resp.json()["id"]

        response = client.post(
            "/api/v1/email-policies",
            headers=auth_headers,
            json={
                "name": "profiled-gmail",
                "provider": "gmail",
                "email": "profiled@company.com",
                "profile_id": profile_id,
            }
        )
        assert response.status_code == 200
        data = response.json()
        assert data["profile_id"] == profile_id

    def test_same_name_different_profiles_allowed(self, client, auth_headers):
        """Should allow same name in different profiles."""
        profile_a = client.post(
            "/api/v1/security-profiles",
            headers=auth_headers,
            json={"name": "ep-prof-a"},
        ).json()["id"]
        profile_b = client.post(
            "/api/v1/security-profiles",
            headers=auth_headers,
            json={"name": "ep-prof-b"},
        ).json()["id"]

        # Same name in profile A
        resp_a = client.post(
            "/api/v1/email-policies",
            headers=auth_headers,
            json={
                "name": "shared-name",
                "provider": "gmail",
                "email": "a@co.com",
                "profile_id": profile_a,
            }
        )
        assert resp_a.status_code == 200

        # Same name in profile B - should succeed
        resp_b = client.post(
            "/api/v1/email-policies",
            headers=auth_headers,
            json={
                "name": "shared-name",
                "provider": "gmail",
                "email": "b@co.com",
                "profile_id": profile_b,
            }
        )
        assert resp_b.status_code == 200

    def test_filter_policies_by_profile_id(self, client, auth_headers):
        """Should filter email policies by profile_id."""
        profile_resp = client.post(
            "/api/v1/security-profiles",
            headers=auth_headers,
            json={"name": "ep-filter-profile"},
        )
        profile_id = profile_resp.json()["id"]

        # Create baseline (no profile) policy
        client.post(
            "/api/v1/email-policies",
            headers=auth_headers,
            json={"name": "ep-baseline", "provider": "gmail", "email": "base@co.com"}
        )

        # Create profile-scoped policy
        client.post(
            "/api/v1/email-policies",
            headers=auth_headers,
            json={
                "name": "ep-scoped",
                "provider": "gmail",
                "email": "scoped@co.com",
                "profile_id": profile_id,
            }
        )

        # Filter by profile_id
        response = client.get(
            f"/api/v1/email-policies?profile_id={profile_id}",
            headers=auth_headers,
        )
        assert response.status_code == 200
        policies = response.json()
        names = [p["name"] for p in policies]
        assert "ep-scoped" in names
        assert "ep-baseline" not in names

    def test_filter_baseline_policies(self, client, auth_headers):
        """Should filter baseline (no profile) policies with profile_id=0."""
        profile_resp = client.post(
            "/api/v1/security-profiles",
            headers=auth_headers,
            json={"name": "ep-baseline-filter"},
        )
        profile_id = profile_resp.json()["id"]

        client.post(
            "/api/v1/email-policies",
            headers=auth_headers,
            json={"name": "ep-base-only", "provider": "gmail", "email": "baseonly@co.com"}
        )
        client.post(
            "/api/v1/email-policies",
            headers=auth_headers,
            json={
                "name": "ep-profile-only",
                "provider": "gmail",
                "email": "profonly@co.com",
                "profile_id": profile_id,
            }
        )

        # profile_id=0 means baseline (NULL profile_id)
        response = client.get("/api/v1/email-policies?profile_id=0", headers=auth_headers)
        assert response.status_code == 200
        policies = response.json()
        names = [p["name"] for p in policies]
        assert "ep-base-only" in names
        assert "ep-profile-only" not in names

    def test_invalid_profile_id_rejected(self, client, auth_headers):
        """Should reject email policy with non-existent profile_id."""
        response = client.post(
            "/api/v1/email-policies",
            headers=auth_headers,
            json={
                "name": "bad-profile",
                "provider": "gmail",
                "email": "bad@co.com",
                "profile_id": 99999,
            }
        )
        assert response.status_code == 404
        assert "Security profile not found" in response.json()["detail"]


class TestEmailPolicyTenantIsolation:
    """Test tenant isolation for email policies."""

    def test_super_admin_requires_tenant_id(self, client, super_admin_headers):
        """Super admin must provide tenant_id when creating."""
        response = client.post(
            "/api/v1/email-policies",
            headers=super_admin_headers,
            json={
                "name": "no-tenant",
                "provider": "gmail",
                "email": "test@co.com",
            }
        )
        assert response.status_code == 400
        assert "tenant_id" in response.json()["detail"]

    def test_cross_tenant_invisible(self, client, auth_headers, acme_admin_headers):
        """Policies from one tenant should be invisible to another."""
        # Create policy as default tenant admin
        create = client.post(
            "/api/v1/email-policies",
            headers=auth_headers,
            json={"name": "tenant-iso", "provider": "gmail", "email": "iso@co.com"}
        )
        policy_id = create.json()["id"]

        # Acme admin should not see it
        response = client.get(f"/api/v1/email-policies/{policy_id}", headers=acme_admin_headers)
        assert response.status_code == 404
