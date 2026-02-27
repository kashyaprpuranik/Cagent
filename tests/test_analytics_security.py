import os
import sys
import unittest
from unittest.mock import MagicMock, patch

from fastapi import HTTPException

# Add services/warden to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "services", "warden")))

# Mock docker before importing analytics
mock_docker = MagicMock()
sys.modules["docker"] = MagicMock()
sys.modules["docker"].from_env.return_value = mock_docker
sys.modules["docker"].errors = MagicMock()
sys.modules["docker"].errors.NotFound = Exception
mock_docker.containers.list.return_value = []

from routers import analytics


class TestAnalyticsSecurity(unittest.TestCase):
    @patch("routers.analytics.subprocess.run")
    @patch("routers.analytics.docker_client")
    def test_diagnose_domain_argument_injection(self, mock_docker_client, mock_subprocess):
        """Test that domains starting with '-' are rejected to prevent argument injection."""

        # Mock container logs
        mock_container = MagicMock()
        mock_container.logs.return_value = b""
        mock_docker_client.containers.get.return_value = mock_container

        malicious_domains = [
            "-debug",
            "-type=ANY",
            "-",
            "-v",
        ]

        for domain in malicious_domains:
            with self.assertRaises(HTTPException) as cm:
                analytics.diagnose_domain(domain=domain)

            self.assertEqual(cm.exception.status_code, 400)
            self.assertIn("Invalid domain format", cm.exception.detail)

        # Verify subprocess was NOT called
        mock_subprocess.assert_not_called()

    @patch("routers.analytics.subprocess.run")
    @patch("routers.analytics.docker_client")
    def test_diagnose_domain_valid(self, mock_docker_client, mock_subprocess):
        """Test that valid domains are accepted."""

        # Mock container logs
        mock_container = MagicMock()
        mock_container.logs.return_value = b""
        mock_docker_client.containers.get.return_value = mock_container

        # Mock subprocess (dns lookup)
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = "Address: 1.2.3.4"
        mock_subprocess.return_value = mock_proc

        valid_domains = [
            "example.com",
            "sub.example.com",
            "my-domain.net",
            "123.com",
        ]

        for domain in valid_domains:
            analytics.diagnose_domain(domain=domain)

        # Verify subprocess WAS called (once per valid domain)
        self.assertEqual(mock_subprocess.call_count, len(valid_domains))


if __name__ == "__main__":
    unittest.main()
