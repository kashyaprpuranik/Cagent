"""Tests for API token management endpoints."""


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
