"""Tests for tenant IP ACL management endpoints."""


class TestIpAcls:
    """Test tenant IP ACL management endpoints."""

    def _get_default_tenant_id(self, client, super_admin_headers):
        """Helper: get the default tenant ID."""
        response = client.get("/api/v1/tenants", headers=super_admin_headers)
        tenants = response.json()["items"]
        tenant = next(t for t in tenants if t["slug"] == "default")
        return tenant["id"]

    def test_list_ip_acls_empty(self, client, super_admin_headers):
        """Should return empty list when no ACLs exist."""
        tenant_id = self._get_default_tenant_id(client, super_admin_headers)
        response = client.get(f"/api/v1/tenants/{tenant_id}/ip-acls", headers=super_admin_headers)
        assert response.status_code == 200
        assert isinstance(response.json(), list)

    def test_create_ip_acl(self, client, super_admin_headers):
        """Should create an IP ACL entry."""
        tenant_id = self._get_default_tenant_id(client, super_admin_headers)
        response = client.post(
            f"/api/v1/tenants/{tenant_id}/ip-acls",
            headers=super_admin_headers,
            json={"cidr": "10.0.0.0/8", "description": "Internal network"}
        )
        assert response.status_code == 200
        data = response.json()
        assert data["cidr"] == "10.0.0.0/8"
        assert data["description"] == "Internal network"
        assert data["enabled"] is True
        assert data["tenant_id"] == tenant_id

    def test_create_ip_acl_single_ip(self, client, super_admin_headers):
        """Should accept /32 CIDR for single IPs."""
        tenant_id = self._get_default_tenant_id(client, super_admin_headers)
        response = client.post(
            f"/api/v1/tenants/{tenant_id}/ip-acls",
            headers=super_admin_headers,
            json={"cidr": "203.0.113.50/32"}
        )
        assert response.status_code == 200
        assert response.json()["cidr"] == "203.0.113.50/32"

    def test_create_ip_acl_invalid_cidr(self, client, super_admin_headers):
        """Should reject invalid CIDR format."""
        tenant_id = self._get_default_tenant_id(client, super_admin_headers)
        response = client.post(
            f"/api/v1/tenants/{tenant_id}/ip-acls",
            headers=super_admin_headers,
            json={"cidr": "not-a-cidr"}
        )
        assert response.status_code == 400
        assert "Invalid CIDR" in response.json()["detail"]

    def test_create_duplicate_ip_acl_fails(self, client, super_admin_headers):
        """Should reject duplicate CIDR for same tenant."""
        tenant_id = self._get_default_tenant_id(client, super_admin_headers)
        acl_data = {"cidr": "192.168.1.0/24"}
        client.post(f"/api/v1/tenants/{tenant_id}/ip-acls", headers=super_admin_headers, json=acl_data)
        response = client.post(f"/api/v1/tenants/{tenant_id}/ip-acls", headers=super_admin_headers, json=acl_data)
        assert response.status_code == 400
        assert "already exists" in response.json()["detail"]

    def test_update_ip_acl(self, client, super_admin_headers):
        """Should update an IP ACL entry."""
        tenant_id = self._get_default_tenant_id(client, super_admin_headers)
        create_response = client.post(
            f"/api/v1/tenants/{tenant_id}/ip-acls",
            headers=super_admin_headers,
            json={"cidr": "172.16.0.0/12", "description": "Old description"}
        )
        acl_id = create_response.json()["id"]

        response = client.patch(
            f"/api/v1/tenants/{tenant_id}/ip-acls/{acl_id}",
            headers=super_admin_headers,
            json={"description": "Updated description", "enabled": False}
        )
        assert response.status_code == 200
        data = response.json()
        assert data["description"] == "Updated description"
        assert data["enabled"] is False

    def test_delete_ip_acl(self, client, super_admin_headers):
        """Should delete an IP ACL entry."""
        tenant_id = self._get_default_tenant_id(client, super_admin_headers)
        create_response = client.post(
            f"/api/v1/tenants/{tenant_id}/ip-acls",
            headers=super_admin_headers,
            json={"cidr": "100.64.0.0/10"}
        )
        acl_id = create_response.json()["id"]

        response = client.delete(
            f"/api/v1/tenants/{tenant_id}/ip-acls/{acl_id}",
            headers=super_admin_headers,
        )
        assert response.status_code == 200
        assert response.json()["status"] == "deleted"

        # Verify it's gone
        list_response = client.get(f"/api/v1/tenants/{tenant_id}/ip-acls", headers=super_admin_headers)
        acls = list_response.json()
        assert not any(a["id"] == acl_id for a in acls)

    def test_ip_acl_tenant_isolation(self, client, super_admin_headers, auth_headers):
        """Tenant admin should not access another tenant's ACLs."""
        # Get acme tenant ID (auth_headers is scoped to default tenant)
        tenants = client.get("/api/v1/tenants", headers=super_admin_headers).json()["items"]
        acme_tenant = next(t for t in tenants if t["slug"] == "acme")

        response = client.get(
            f"/api/v1/tenants/{acme_tenant['id']}/ip-acls",
            headers=auth_headers,  # default tenant admin
        )
        assert response.status_code == 403

    def test_ip_acl_not_found_tenant(self, client, super_admin_headers):
        """Should return 404 for non-existent tenant."""
        response = client.get("/api/v1/tenants/99999/ip-acls", headers=super_admin_headers)
        assert response.status_code == 404

    def test_delete_nonexistent_ip_acl(self, client, super_admin_headers):
        """Should return 404 for non-existent ACL."""
        tenant_id = self._get_default_tenant_id(client, super_admin_headers)
        response = client.delete(
            f"/api/v1/tenants/{tenant_id}/ip-acls/99999",
            headers=super_admin_headers,
        )
        assert response.status_code == 404
