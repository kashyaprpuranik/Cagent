"""Tests for Role-Based Access Control (RBAC) functionality."""


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
        tokens = response.json()["items"]
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
