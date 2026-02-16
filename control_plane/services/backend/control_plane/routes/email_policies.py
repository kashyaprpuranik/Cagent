import json
from datetime import datetime
from typing import Optional, List

from fastapi import APIRouter, HTTPException, Depends, Request, Query
from sqlalchemy.orm import Session

from control_plane.database import get_db
from control_plane.models import EmailPolicy, AuditTrail, SecurityProfile
from control_plane.schemas import (
    EmailPolicyCreate, EmailPolicyUpdate, EmailPolicyResponse, EmailPolicyCredential,
)
from control_plane.crypto import encrypt_secret, decrypt_secret
from control_plane.auth import TokenInfo, require_admin_role, require_admin_role_with_ip_check
from control_plane.rate_limit import limiter

router = APIRouter()


def email_policy_to_response(policy: EmailPolicy) -> dict:
    """Convert EmailPolicy to response dict."""
    return {
        "id": policy.id,
        "tenant_id": policy.tenant_id,
        "name": policy.name,
        "provider": policy.provider,
        "email": policy.email,
        "enabled": policy.enabled,
        "profile_id": policy.profile_id,
        "agent_id": policy.agent_id,
        "imap_server": policy.imap_server,
        "imap_port": policy.imap_port,
        "smtp_server": policy.smtp_server,
        "smtp_port": policy.smtp_port,
        "allowed_recipients": policy.allowed_recipients or [],
        "allowed_senders": policy.allowed_senders or [],
        "sends_per_hour": policy.sends_per_hour,
        "reads_per_hour": policy.reads_per_hour,
        "has_credential": policy.credential_data_encrypted is not None,
        "credential_type": policy.credential_type,
        "created_at": policy.created_at,
        "updated_at": policy.updated_at,
    }


@router.get("/api/v1/email-policies", response_model=List[EmailPolicyResponse])
@limiter.limit("60/minute")
async def list_email_policies(
    request: Request,
    db: Session = Depends(get_db),
    token_info: TokenInfo = Depends(require_admin_role),
    agent_id: Optional[str] = None,
    tenant_id: Optional[int] = None,
    profile_id: Optional[int] = Query(default=None, description="Filter by profile ID. Use 0 for baseline (no profile)."),
):
    """List email policies."""
    query = db.query(EmailPolicy)

    if token_info.is_super_admin:
        if tenant_id is not None:
            query = query.filter(EmailPolicy.tenant_id == tenant_id)
    else:
        query = query.filter(EmailPolicy.tenant_id == token_info.tenant_id)

    if agent_id:
        query = query.filter(
            (EmailPolicy.agent_id == agent_id) | (EmailPolicy.agent_id.is_(None))
        )

    if profile_id is not None:
        if profile_id == 0:
            query = query.filter(EmailPolicy.profile_id.is_(None))
        else:
            query = query.filter(EmailPolicy.profile_id == profile_id)

    policies = query.order_by(EmailPolicy.name).all()
    return [email_policy_to_response(p) for p in policies]


@router.post("/api/v1/email-policies", response_model=EmailPolicyResponse)
@limiter.limit("30/minute")
async def create_email_policy(
    request: Request,
    policy: EmailPolicyCreate,
    db: Session = Depends(get_db),
    token_info: TokenInfo = Depends(require_admin_role_with_ip_check),
    tenant_id: Optional[int] = None,
):
    """Create a new email policy."""
    if token_info.is_super_admin:
        if tenant_id is None:
            raise HTTPException(status_code=400, detail="tenant_id is required")
        effective_tenant_id = tenant_id
    else:
        effective_tenant_id = token_info.tenant_id

    if policy.provider not in ("gmail", "outlook", "generic"):
        raise HTTPException(status_code=400, detail="provider must be gmail, outlook, or generic")

    # Verify profile exists in same tenant if provided
    if policy.profile_id is not None:
        profile = db.query(SecurityProfile).filter(SecurityProfile.id == policy.profile_id).first()
        if not profile:
            raise HTTPException(status_code=404, detail="Security profile not found")
        if profile.tenant_id != effective_tenant_id:
            raise HTTPException(status_code=400, detail="Security profile must belong to the same tenant")

    # Check for duplicates (including profile_id)
    existing = db.query(EmailPolicy).filter(
        EmailPolicy.name == policy.name,
        EmailPolicy.profile_id == policy.profile_id,
        EmailPolicy.tenant_id == effective_tenant_id,
    ).first()
    if existing:
        raise HTTPException(status_code=400, detail="Email policy with this name already exists")

    # Encrypt credential if provided
    encrypted_data = None
    credential_type = None
    if policy.credential:
        cred_dict = policy.credential.model_dump(exclude_none=True)
        if cred_dict:
            encrypted_data = encrypt_secret(json.dumps(cred_dict))
            credential_type = "password" if policy.credential.password else "oauth2"

    db_policy = EmailPolicy(
        tenant_id=effective_tenant_id,
        name=policy.name,
        provider=policy.provider,
        email=policy.email,
        profile_id=policy.profile_id,
        agent_id=policy.agent_id,
        imap_server=policy.imap_server,
        imap_port=policy.imap_port,
        smtp_server=policy.smtp_server,
        smtp_port=policy.smtp_port,
        allowed_recipients=policy.allowed_recipients or [],
        allowed_senders=policy.allowed_senders or [],
        sends_per_hour=policy.sends_per_hour,
        reads_per_hour=policy.reads_per_hour,
        credential_type=credential_type,
        credential_data_encrypted=encrypted_data,
    )
    db.add(db_policy)

    log = AuditTrail(
        event_type="email_policy_created",
        user=token_info.token_name or "admin",
        action=f"Email policy created: {policy.name} ({policy.email})",
        details=json.dumps({"name": policy.name, "provider": policy.provider, "email": policy.email, "profile_id": policy.profile_id}),
        severity="INFO",
        tenant_id=effective_tenant_id,
    )
    db.add(log)
    db.commit()
    db.refresh(db_policy)
    return email_policy_to_response(db_policy)


@router.get("/api/v1/email-policies/{policy_id}", response_model=EmailPolicyResponse)
@limiter.limit("60/minute")
async def get_email_policy(
    request: Request,
    policy_id: int,
    db: Session = Depends(get_db),
    token_info: TokenInfo = Depends(require_admin_role),
):
    """Get an email policy by ID."""
    policy = db.query(EmailPolicy).filter(EmailPolicy.id == policy_id).first()
    if not policy:
        raise HTTPException(status_code=404, detail="Email policy not found")
    if not token_info.is_super_admin and policy.tenant_id != token_info.tenant_id:
        raise HTTPException(status_code=404, detail="Email policy not found")
    return email_policy_to_response(policy)


@router.put("/api/v1/email-policies/{policy_id}", response_model=EmailPolicyResponse)
@limiter.limit("30/minute")
async def update_email_policy(
    request: Request,
    policy_id: int,
    update: EmailPolicyUpdate,
    db: Session = Depends(get_db),
    token_info: TokenInfo = Depends(require_admin_role_with_ip_check),
):
    """Update an email policy."""
    policy = db.query(EmailPolicy).filter(EmailPolicy.id == policy_id).first()
    if not policy:
        raise HTTPException(status_code=404, detail="Email policy not found")
    if not token_info.is_super_admin and policy.tenant_id != token_info.tenant_id:
        raise HTTPException(status_code=404, detail="Email policy not found")

    if update.enabled is not None:
        policy.enabled = update.enabled
    if update.imap_server is not None:
        policy.imap_server = update.imap_server
    if update.imap_port is not None:
        policy.imap_port = update.imap_port
    if update.smtp_server is not None:
        policy.smtp_server = update.smtp_server
    if update.smtp_port is not None:
        policy.smtp_port = update.smtp_port
    if update.allowed_recipients is not None:
        policy.allowed_recipients = update.allowed_recipients
    if update.allowed_senders is not None:
        policy.allowed_senders = update.allowed_senders
    if update.sends_per_hour is not None:
        policy.sends_per_hour = update.sends_per_hour
    if update.reads_per_hour is not None:
        policy.reads_per_hour = update.reads_per_hour

    if update.clear_credential:
        policy.credential_type = None
        policy.credential_data_encrypted = None
    elif update.credential:
        cred_dict = update.credential.model_dump(exclude_none=True)
        if cred_dict:
            policy.credential_data_encrypted = encrypt_secret(json.dumps(cred_dict))
            policy.credential_type = "password" if update.credential.password else "oauth2"

    log = AuditTrail(
        event_type="email_policy_updated",
        user=token_info.token_name or "admin",
        action=f"Email policy updated: {policy.name}",
        details=json.dumps({"policy_id": policy_id, "name": policy.name}),
        severity="INFO",
        tenant_id=policy.tenant_id,
    )
    db.add(log)
    db.commit()
    db.refresh(policy)
    return email_policy_to_response(policy)


@router.delete("/api/v1/email-policies/{policy_id}")
@limiter.limit("30/minute")
async def delete_email_policy(
    request: Request,
    policy_id: int,
    db: Session = Depends(get_db),
    token_info: TokenInfo = Depends(require_admin_role_with_ip_check),
):
    """Delete an email policy."""
    policy = db.query(EmailPolicy).filter(EmailPolicy.id == policy_id).first()
    if not policy:
        raise HTTPException(status_code=404, detail="Email policy not found")
    if not token_info.is_super_admin and policy.tenant_id != token_info.tenant_id:
        raise HTTPException(status_code=404, detail="Email policy not found")

    name = policy.name
    tenant_id = policy.tenant_id

    db.delete(policy)

    log = AuditTrail(
        event_type="email_policy_deleted",
        user=token_info.token_name or "admin",
        action=f"Email policy deleted: {name}",
        details=json.dumps({"policy_id": policy_id, "name": name}),
        severity="WARNING",
        tenant_id=tenant_id,
    )
    db.add(log)
    db.commit()
    return {"deleted": True, "id": policy_id}
