"""Unit tests for warden bearer token authentication."""

import os
import sys
from unittest.mock import MagicMock

import pytest

# Mock docker before importing warden modules
sys.modules["docker"] = MagicMock()
sys.modules["docker"].from_env.return_value = MagicMock(containers=MagicMock(list=MagicMock(return_value=[])))
sys.modules["docker"].errors = MagicMock()
sys.modules["docker"].errors.NotFound = Exception

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "services", "warden")))


class FakeRequest:
    """Minimal Request stand-in for auth tests."""

    def __init__(self, client_host: str = "", auth_header: str = ""):
        self.client = type("Client", (), {"host": client_host})() if client_host else None
        self.headers = {"Authorization": auth_header} if auth_header else {}


class TestWardenAuthStandardMode:
    """When WARDEN_API_TOKEN is empty (standard mode), all requests pass."""

    def test_no_token_set_allows_all(self):
        from warden_auth import verify_warden_token

        with pytest.MonkeyPatch.context() as mp:
            mp.setattr("warden_auth.WARDEN_API_TOKEN", "")
            import asyncio

            # Remote IP, no auth header — should still pass
            req = FakeRequest(client_host="203.0.113.50", auth_header="")
            asyncio.get_event_loop().run_until_complete(verify_warden_token(req))


class TestWardenAuthLocalhostBypass:
    """Localhost and infra-net requests bypass auth even when token is set."""

    @pytest.fixture(autouse=True)
    def _set_token(self, monkeypatch):
        monkeypatch.setattr("warden_auth.WARDEN_API_TOKEN", "secret-token-123")

    @pytest.mark.parametrize(
        "ip",
        [
            "127.0.0.1",
            "127.0.0.2",
            "::1",
            "10.200.2.5",
            "10.200.2.10",
        ],
    )
    def test_local_ips_bypass_auth(self, ip):
        from warden_auth import verify_warden_token

        import asyncio

        req = FakeRequest(client_host=ip, auth_header="")
        asyncio.get_event_loop().run_until_complete(verify_warden_token(req))

    def test_cell_net_does_not_bypass_auth(self):
        """Cell-net IPs (10.200.1.*) must NOT bypass auth — untrusted cells."""
        from warden_auth import verify_warden_token

        import asyncio
        from fastapi import HTTPException

        for ip in ("10.200.1.10", "10.200.1.20", "10.200.1.1"):
            req = FakeRequest(client_host=ip, auth_header="")
            with pytest.raises(HTTPException) as exc_info:
                asyncio.get_event_loop().run_until_complete(verify_warden_token(req))
            assert exc_info.value.status_code == 401, f"Cell-net IP {ip} bypassed auth!"

    def test_no_client_info_requires_auth(self):
        """If client info is missing, auth should be required."""
        from warden_auth import verify_warden_token

        import asyncio
        from fastapi import HTTPException

        req = FakeRequest(client_host="", auth_header="")
        with pytest.raises(HTTPException) as exc_info:
            asyncio.get_event_loop().run_until_complete(verify_warden_token(req))
        assert exc_info.value.status_code == 401


class TestWardenAuthTokenValidation:
    """Remote requests must present a valid bearer token."""

    @pytest.fixture(autouse=True)
    def _set_token(self, monkeypatch):
        monkeypatch.setattr("warden_auth.WARDEN_API_TOKEN", "secret-token-123")

    def test_valid_token_passes(self):
        from warden_auth import verify_warden_token

        import asyncio

        req = FakeRequest(client_host="203.0.113.50", auth_header="Bearer secret-token-123")
        asyncio.get_event_loop().run_until_complete(verify_warden_token(req))

    def test_invalid_token_rejected(self):
        from warden_auth import verify_warden_token

        import asyncio
        from fastapi import HTTPException

        req = FakeRequest(client_host="203.0.113.50", auth_header="Bearer wrong-token")
        with pytest.raises(HTTPException) as exc_info:
            asyncio.get_event_loop().run_until_complete(verify_warden_token(req))
        assert exc_info.value.status_code == 401
        assert "Invalid" in exc_info.value.detail

    def test_missing_bearer_prefix_rejected(self):
        from warden_auth import verify_warden_token

        import asyncio
        from fastapi import HTTPException

        req = FakeRequest(client_host="203.0.113.50", auth_header="secret-token-123")
        with pytest.raises(HTTPException) as exc_info:
            asyncio.get_event_loop().run_until_complete(verify_warden_token(req))
        assert exc_info.value.status_code == 401

    def test_no_auth_header_rejected(self):
        from warden_auth import verify_warden_token

        import asyncio
        from fastapi import HTTPException

        req = FakeRequest(client_host="203.0.113.50", auth_header="")
        with pytest.raises(HTTPException) as exc_info:
            asyncio.get_event_loop().run_until_complete(verify_warden_token(req))
        assert exc_info.value.status_code == 401
