"""Backward-compatible facade. Implementation lives in control_plane/."""

from control_plane.app import app  # noqa: F401
from control_plane.database import engine, SessionLocal, Base, get_db  # noqa: F401
from control_plane.models import (  # noqa: F401
    Tenant, TenantIpAcl, AuditTrail, DomainPolicy, SecurityProfile,
    AgentState, ApiToken,
)
from control_plane.crypto import encrypt_secret, decrypt_secret, hash_token, generate_token  # noqa: F401
from control_plane.auth import TokenInfo, verify_token  # noqa: F401
from control_plane.schemas import *  # noqa: F401,F403

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
