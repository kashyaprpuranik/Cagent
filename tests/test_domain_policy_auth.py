import sys
import os
from unittest.mock import patch, MagicMock

# Add services/warden to python path
sys.path.append(os.path.join(os.getcwd(), "services/warden"))

# Mock docker before importing warden modules
mock_docker = MagicMock()
sys.modules["docker"] = mock_docker

# Configure docker client mock to avoid IndexError in constants.py
# docker.from_env().containers.list returns a list of mocks
mock_client = MagicMock()
mock_docker.from_env.return_value = mock_client
mock_container = MagicMock()
mock_container.name = "cell"
mock_client.containers.list.return_value = [mock_container]

from services.warden.routers.domain_policy import get_domain_policy


def test_domain_policy_auth_success():
    """Test that valid token returns full policy."""
    with (
        patch("services.warden.routers.domain_policy.CONTROL_PLANE_TOKEN", "secret-token"),
        patch("services.warden.routers.domain_policy._cache_get") as mock_cache_get,
    ):
        # Mock policy with sensitive fields
        mock_policy = {
            "matched": True,
            "domain": "example.com",
            "header_name": "Authorization",
            "header_value": "Bearer secret",
            "target_domain": "example.com",
        }
        mock_cache_get.return_value = mock_policy

        # Valid token
        token = "Bearer secret-token"
        result = get_domain_policy(domain="example.com", authorization=token)

        assert result["header_value"] == "Bearer secret"
        assert result["header_name"] == "Authorization"


def test_domain_policy_auth_failure():
    """Test that invalid token returns redacted policy."""
    with (
        patch("services.warden.routers.domain_policy.CONTROL_PLANE_TOKEN", "secret-token"),
        patch("services.warden.routers.domain_policy._cache_get") as mock_cache_get,
    ):
        # Mock policy with sensitive fields
        mock_policy = {
            "matched": True,
            "domain": "example.com",
            "header_name": "Authorization",
            "header_value": "Bearer secret",
            "target_domain": "example.com",
        }
        mock_cache_get.return_value = mock_policy

        # Invalid token
        token = "Bearer wrong-token"
        result = get_domain_policy(domain="example.com", authorization=token)

        assert "header_value" not in result
        assert "header_name" not in result
        assert "target_domain" not in result
        assert result["matched"] is True


def test_domain_policy_auth_missing_header():
    """Test that missing authorization header returns redacted policy."""
    with (
        patch("services.warden.routers.domain_policy.CONTROL_PLANE_TOKEN", "secret-token"),
        patch("services.warden.routers.domain_policy._cache_get") as mock_cache_get,
    ):
        # Mock policy with sensitive fields
        mock_policy = {
            "matched": True,
            "domain": "example.com",
            "header_name": "Authorization",
            "header_value": "Bearer secret",
            "target_domain": "example.com",
        }
        mock_cache_get.return_value = mock_policy

        # Missing header (None)
        result = get_domain_policy(domain="example.com", authorization=None)

        assert "header_value" not in result
        assert "header_name" not in result
