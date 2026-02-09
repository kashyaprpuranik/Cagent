"""Tests for multi-tenancy features."""


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

    def test_create_super_admin_token_blocked(self, client, super_admin_headers):
        """Super admin tokens cannot be created via the API (bootstrap only)."""
        response = client.post(
            "/api/v1/tokens",
            headers=super_admin_headers,
            json={"name": "new-super-admin", "token_type": "admin", "is_super_admin": True}
        )
        assert response.status_code == 400
        assert "cannot be created via the API" in response.json()["detail"]

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
