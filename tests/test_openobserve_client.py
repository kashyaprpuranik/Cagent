"""Unit tests for the local OpenObserve client."""

import os
import sys
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

# Mock docker before importing warden modules
sys.modules["docker"] = MagicMock()
sys.modules["docker"].from_env.return_value = MagicMock(containers=MagicMock(list=MagicMock(return_value=[])))
sys.modules["docker"].errors = MagicMock()
sys.modules["docker"].errors.NotFound = Exception

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "services", "warden")))

from openobserve_client import datetime_to_us, is_openobserve_healthy, now_us, query_openobserve


class TestDatetimeConversion:
    """Test time conversion helpers."""

    def test_datetime_to_us_epoch(self):
        """Epoch should convert to 0."""
        epoch = datetime(1970, 1, 1, tzinfo=timezone.utc)
        assert datetime_to_us(epoch) == 0

    def test_datetime_to_us_known_value(self):
        """A known datetime should produce the correct microsecond value."""
        dt = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
        expected_us = int(dt.timestamp() * 1_000_000)
        assert datetime_to_us(dt) == expected_us

    def test_now_us_is_recent(self):
        """now_us() should return a value close to the current time."""
        before = int(datetime.now(timezone.utc).timestamp() * 1_000_000)
        result = now_us()
        after = int(datetime.now(timezone.utc).timestamp() * 1_000_000)
        assert before <= result <= after


class TestIsOpenObserveHealthy:
    """Test OO health check."""

    @patch("openobserve_client.requests.get")
    def test_healthy_returns_true(self, mock_get):
        mock_get.return_value = MagicMock(status_code=200)
        assert is_openobserve_healthy() is True

    @patch("openobserve_client.requests.get")
    def test_unhealthy_status_returns_false(self, mock_get):
        mock_get.return_value = MagicMock(status_code=503)
        assert is_openobserve_healthy() is False

    @patch("openobserve_client.requests.get")
    def test_connection_error_returns_false(self, mock_get):
        import requests

        mock_get.side_effect = requests.ConnectionError("Connection refused")
        assert is_openobserve_healthy() is False

    @patch("openobserve_client.requests.get")
    def test_timeout_returns_false(self, mock_get):
        import requests

        mock_get.side_effect = requests.Timeout("Timeout")
        assert is_openobserve_healthy() is False


class TestQueryOpenObserve:
    """Test OO SQL query execution."""

    @patch("openobserve_client.requests.post")
    def test_successful_query(self, mock_post):
        """Successful query should return hits list."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "hits": [
                {"message": "test log 1", "_timestamp": 1234567890},
                {"message": "test log 2", "_timestamp": 1234567891},
            ]
        }
        mock_post.return_value = mock_response

        result = query_openobserve("SELECT * FROM default LIMIT 10", 0, 9999999999)
        assert len(result) == 2
        assert result[0]["message"] == "test log 1"

    @patch("openobserve_client.requests.post")
    def test_query_sends_correct_payload(self, mock_post):
        """Query should send SQL and time range in the expected format."""
        mock_post.return_value = MagicMock(status_code=200, json=MagicMock(return_value={"hits": []}))

        query_openobserve("SELECT * FROM default WHERE source='envoy'", 1000, 2000)

        mock_post.assert_called_once()
        call_kwargs = mock_post.call_args
        payload = call_kwargs.kwargs.get("json") or call_kwargs[1].get("json")
        assert payload["query"]["sql"] == "SELECT * FROM default WHERE source='envoy'"
        assert payload["query"]["start_time"] == 1000
        assert payload["query"]["end_time"] == 2000

    @patch("openobserve_client.requests.post")
    def test_query_uses_auth(self, mock_post):
        """Query should authenticate with OO credentials."""
        mock_post.return_value = MagicMock(status_code=200, json=MagicMock(return_value={"hits": []}))

        query_openobserve("SELECT 1", 0, 1)

        call_kwargs = mock_post.call_args
        auth = call_kwargs.kwargs.get("auth") or call_kwargs[1].get("auth")
        assert auth is not None
        assert len(auth) == 2  # (user, password) tuple

    @patch("openobserve_client.requests.post")
    def test_failed_query_returns_empty(self, mock_post):
        """Non-200 response should return empty list."""
        mock_post.return_value = MagicMock(status_code=500, text="Internal error")
        result = query_openobserve("SELECT * FROM default", 0, 1)
        assert result == []

    @patch("openobserve_client.requests.post")
    def test_connection_error_returns_empty(self, mock_post):
        """Network error should return empty list, not raise."""
        import requests

        mock_post.side_effect = requests.ConnectionError("OO is down")
        result = query_openobserve("SELECT * FROM default", 0, 1)
        assert result == []

    @patch("openobserve_client.requests.post")
    def test_no_hits_key_returns_empty(self, mock_post):
        """Response without 'hits' key should return empty list."""
        mock_post.return_value = MagicMock(status_code=200, json=MagicMock(return_value={"total": 0}))
        result = query_openobserve("SELECT * FROM default", 0, 1)
        assert result == []
