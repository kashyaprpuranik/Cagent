"""Tests for authentication requirements."""


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
