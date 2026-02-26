import os
import sys
import unittest
from unittest.mock import Mock

# Add services/warden to sys.path to import modules
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../services/warden")))

from utils import validate_websocket_origin


class TestWebSocketOriginValidation(unittest.TestCase):
    def setUp(self):
        self.allowed_origins = ["http://localhost:3000", "http://localhost:5173", "http://127.0.0.1:3000"]

    def test_explicitly_allowed_origin(self):
        """Should allow origin if it's in the allowed list."""
        mock_ws = Mock()
        mock_ws.headers = {"origin": "http://localhost:3000"}
        self.assertTrue(validate_websocket_origin(mock_ws, self.allowed_origins))

    def test_same_origin_localhost(self):
        """Should allow if Origin matches Host (localhost)."""
        mock_ws = Mock()
        mock_ws.headers = {"origin": "http://localhost:8080", "host": "localhost:8080"}
        self.assertTrue(validate_websocket_origin(mock_ws, self.allowed_origins))

    def test_same_origin_custom_domain(self):
        """Should allow if Origin matches Host (custom domain)."""
        mock_ws = Mock()
        mock_ws.headers = {"origin": "https://my-warden.internal", "host": "my-warden.internal"}
        self.assertTrue(validate_websocket_origin(mock_ws, self.allowed_origins))

    def test_same_origin_custom_port(self):
        """Should allow if Origin matches Host (custom port)."""
        mock_ws = Mock()
        mock_ws.headers = {"origin": "http://10.0.0.5:9090", "host": "10.0.0.5:9090"}
        self.assertTrue(validate_websocket_origin(mock_ws, self.allowed_origins))

    def test_invalid_origin_cswjh_attempt(self):
        """Should deny if Origin does not match Host and is not in allowlist."""
        mock_ws = Mock()
        mock_ws.headers = {"origin": "http://malicious.com", "host": "localhost:8080"}
        self.assertFalse(validate_websocket_origin(mock_ws, self.allowed_origins))

    def test_missing_origin(self):
        """Non-browser clients omit Origin; allow them (not vulnerable to CSWSH)."""
        mock_ws = Mock()
        mock_ws.headers = {"host": "localhost:8080"}
        self.assertTrue(validate_websocket_origin(mock_ws, self.allowed_origins))

    def test_missing_host(self):
        """Should deny if Host header is missing (unless Origin is in allowlist)."""
        mock_ws = Mock()
        mock_ws.headers = {"origin": "http://unknown.com"}
        self.assertFalse(validate_websocket_origin(mock_ws, self.allowed_origins))

    def test_scheme_mismatch_allowed(self):
        """Should handle different schemes correctly (http vs https)."""
        # The function strips scheme, so https://host matching host is valid
        mock_ws = Mock()
        mock_ws.headers = {"origin": "https://localhost:8080", "host": "localhost:8080"}
        self.assertTrue(validate_websocket_origin(mock_ws, self.allowed_origins))


if __name__ == "__main__":
    unittest.main()
