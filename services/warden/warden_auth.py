"""Bearer token authentication for warden API.

Interactive-mode DPs receive a WARDEN_API_TOKEN during provisioning.
The CP proxies requests via Cloudflare Tunnel with this token.

Localhost requests (SSH users on the host) bypass auth for convenience.
When WARDEN_API_TOKEN is empty (standard mode), all requests are allowed.
"""

import secrets

from constants import WARDEN_API_TOKEN
from fastapi import HTTPException, Request

_LOCALHOST_PREFIXES = ("127.", "::1", "10.200.2.")


async def verify_warden_token(request: Request):
    """FastAPI dependency that verifies the warden bearer token.

    Skips auth for:
    - Standard mode (no WARDEN_API_TOKEN set)
    - Localhost / infra-net requests (SSH user or Docker service)
    """
    if not WARDEN_API_TOKEN:
        return  # Standard mode — no auth required

    client_ip = request.client.host if request.client else ""
    if any(client_ip.startswith(p) for p in _LOCALHOST_PREFIXES):
        return  # Local access — trusted

    auth = request.headers.get("Authorization", "")
    expected = f"Bearer {WARDEN_API_TOKEN}"
    if not secrets.compare_digest(auth, expected):
        raise HTTPException(status_code=401, detail="Invalid warden API token")
