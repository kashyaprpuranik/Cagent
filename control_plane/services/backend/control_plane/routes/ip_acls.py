import json
import ipaddress
from typing import List

from fastapi import APIRouter, HTTPException, Depends, Request
from sqlalchemy.orm import Session

from control_plane.database import get_db
from control_plane.models import Tenant, TenantIpAcl, AuditTrail
from control_plane.schemas import TenantIpAclCreate, TenantIpAclUpdate, TenantIpAclResponse
from control_plane.auth import TokenInfo, require_admin_role
from control_plane.rate_limit import limiter

router = APIRouter()


@router.get("/api/v1/tenants/{tenant_id}/ip-acls", response_model=List[TenantIpAclResponse])
@limiter.limit("60/minute")
async def list_tenant_ip_acls(
    request: Request,
    tenant_id: int,
    db: Session = Depends(get_db),
    token_info: TokenInfo = Depends(require_admin_role)
):
    """List IP ACL entries for a tenant (admin only).

    Non-super-admins can only view ACLs for their own tenant.
    """
    # Verify tenant access
    if not token_info.is_super_admin and token_info.tenant_id != tenant_id:
        raise HTTPException(status_code=403, detail="Access denied to this tenant")

    # Verify tenant exists
    tenant = db.query(Tenant).filter(
        Tenant.id == tenant_id,
        Tenant.deleted_at.is_(None)
    ).first()
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")

    return db.query(TenantIpAcl).filter(
        TenantIpAcl.tenant_id == tenant_id
    ).order_by(TenantIpAcl.created_at.desc()).all()


@router.post("/api/v1/tenants/{tenant_id}/ip-acls", response_model=TenantIpAclResponse)
@limiter.limit("30/minute")
async def create_tenant_ip_acl(
    request: Request,
    tenant_id: int,
    acl: TenantIpAclCreate,
    db: Session = Depends(get_db),
    token_info: TokenInfo = Depends(require_admin_role)
):
    """Create an IP ACL entry for a tenant (admin only).

    CIDR format: "10.0.0.0/8", "192.168.1.0/24", "203.0.113.50/32"
    Use /32 for single IP addresses.
    """
    # Verify tenant access
    if not token_info.is_super_admin and token_info.tenant_id != tenant_id:
        raise HTTPException(status_code=403, detail="Access denied to this tenant")

    # Verify tenant exists
    tenant = db.query(Tenant).filter(
        Tenant.id == tenant_id,
        Tenant.deleted_at.is_(None)
    ).first()
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")

    # Validate CIDR format
    try:
        ipaddress.ip_network(acl.cidr, strict=False)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"Invalid CIDR format: {e}")

    # Check for duplicates
    existing = db.query(TenantIpAcl).filter(
        TenantIpAcl.tenant_id == tenant_id,
        TenantIpAcl.cidr == acl.cidr
    ).first()
    if existing:
        raise HTTPException(status_code=400, detail="IP ACL entry already exists for this CIDR")

    db_acl = TenantIpAcl(
        tenant_id=tenant_id,
        cidr=acl.cidr,
        description=acl.description,
        created_by=token_info.token_name or "admin"
    )
    db.add(db_acl)

    # Audit log (use the tenant being modified)
    log = AuditTrail(
        event_type="ip_acl_created",
        user=token_info.token_name or "admin",
        action=f"IP ACL created for tenant {tenant_id}: {acl.cidr}",
        details=json.dumps({"tenant_id": tenant_id, "cidr": acl.cidr}),
        severity="INFO",
        tenant_id=tenant_id
    )
    db.add(log)
    db.commit()
    db.refresh(db_acl)

    return db_acl


@router.patch("/api/v1/tenants/{tenant_id}/ip-acls/{acl_id}", response_model=TenantIpAclResponse)
@limiter.limit("30/minute")
async def update_tenant_ip_acl(
    request: Request,
    tenant_id: int,
    acl_id: int,
    acl: TenantIpAclUpdate,
    db: Session = Depends(get_db),
    token_info: TokenInfo = Depends(require_admin_role)
):
    """Update an IP ACL entry (admin only)."""
    # Verify tenant access
    if not token_info.is_super_admin and token_info.tenant_id != tenant_id:
        raise HTTPException(status_code=403, detail="Access denied to this tenant")

    db_acl = db.query(TenantIpAcl).filter(
        TenantIpAcl.id == acl_id,
        TenantIpAcl.tenant_id == tenant_id
    ).first()
    if not db_acl:
        raise HTTPException(status_code=404, detail="IP ACL entry not found")

    if acl.description is not None:
        db_acl.description = acl.description
    if acl.enabled is not None:
        db_acl.enabled = acl.enabled

    # Audit log (use the tenant being modified)
    log = AuditTrail(
        event_type="ip_acl_updated",
        user=token_info.token_name or "admin",
        action=f"IP ACL updated for tenant {tenant_id}: {db_acl.cidr}",
        details=json.dumps({"acl_id": acl_id, "changes": acl.dict(exclude_unset=True)}),
        severity="INFO",
        tenant_id=tenant_id
    )
    db.add(log)
    db.commit()
    db.refresh(db_acl)

    return db_acl


@router.delete("/api/v1/tenants/{tenant_id}/ip-acls/{acl_id}")
@limiter.limit("30/minute")
async def delete_tenant_ip_acl(
    request: Request,
    tenant_id: int,
    acl_id: int,
    db: Session = Depends(get_db),
    token_info: TokenInfo = Depends(require_admin_role)
):
    """Delete an IP ACL entry (admin only)."""
    # Verify tenant access
    if not token_info.is_super_admin and token_info.tenant_id != tenant_id:
        raise HTTPException(status_code=403, detail="Access denied to this tenant")

    db_acl = db.query(TenantIpAcl).filter(
        TenantIpAcl.id == acl_id,
        TenantIpAcl.tenant_id == tenant_id
    ).first()
    if not db_acl:
        raise HTTPException(status_code=404, detail="IP ACL entry not found")

    cidr = db_acl.cidr  # Save for logging
    db.delete(db_acl)

    # Audit log (use the tenant being modified)
    log = AuditTrail(
        event_type="ip_acl_deleted",
        user=token_info.token_name or "admin",
        action=f"IP ACL deleted for tenant {tenant_id}: {cidr}",
        details=json.dumps({"acl_id": acl_id, "cidr": cidr}),
        severity="WARNING",
        tenant_id=tenant_id
    )
    db.add(log)
    db.commit()

    return {"status": "deleted"}
