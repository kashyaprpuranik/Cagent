import time
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from starlette.responses import RedirectResponse
from sqlalchemy import text
from sqlalchemy.orm import Session

from control_plane.database import get_db
from control_plane.models import Tenant
from control_plane.auth import TokenInfo, verify_token
from control_plane.rate_limit import limiter
from control_plane.config import BETA_FEATURES

router = APIRouter()

_START_TIME = time.monotonic()
_VERSION = "1.0.0"


@router.get("/")
async def root():
    return RedirectResponse(url="/docs")


@router.get("/health")
async def health_check(db: Session = Depends(get_db)):
    try:
        db.execute(text("SELECT 1"))
        db_status = "connected"
    except Exception:
        db_status = "disconnected"
        return JSONResponse(
            status_code=503,
            content={
                "status": "unhealthy",
                "database": db_status,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "version": _VERSION,
                "uptime": int(time.monotonic() - _START_TIME),
            },
        )
    return {
        "status": "healthy",
        "database": db_status,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "version": _VERSION,
        "uptime": int(time.monotonic() - _START_TIME),
    }


@router.get("/api/v1/info")
async def get_info():
    features = [
        "audit_trail",
        "allowlist_management",
        "secret_management",
        "container_monitoring",
        "usage_reporting",
    ]
    if "email" in BETA_FEATURES:
        features.append("email_policies")
    return {
        "name": "AI Devbox Control Plane",
        "version": "1.0.0",
        "features": features,
    }


@router.get("/api/v1/auth/me")
@limiter.limit("60/minute")
async def get_current_user(
    request: Request,
    token_info: TokenInfo = Depends(verify_token),
    db: Session = Depends(get_db)
):
    """Get current user info from token"""
    # Get tenant name if user has a tenant
    tenant_name = None
    tenant_slug = None
    if token_info.tenant_id:
        tenant = db.query(Tenant).filter(Tenant.id == token_info.tenant_id).first()
        if tenant:
            tenant_name = tenant.name
            tenant_slug = tenant.slug

    return {
        "token_type": token_info.token_type,
        "agent_id": token_info.agent_id,
        "tenant_id": token_info.tenant_id,
        "tenant_name": tenant_name,
        "tenant_slug": tenant_slug,
        "is_super_admin": token_info.is_super_admin,
        "roles": token_info.roles
    }
