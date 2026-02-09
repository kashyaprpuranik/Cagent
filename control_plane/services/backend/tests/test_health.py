"""Tests for health and info endpoints."""


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
