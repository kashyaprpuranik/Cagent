import os
import json
import secrets
from datetime import datetime, timezone
from typing import Optional, List

from fastapi import APIRouter, HTTPException, Depends, Query, Request
from sqlalchemy import update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from control_plane.database import get_db
from control_plane.models import AgentState, AuditTrail
from control_plane.schemas import (
    DataPlaneResponse, AgentHeartbeat, AgentHeartbeatResponse,
    AgentStatusResponse, AgentCommandRequest, STCPSecretResponse, STCPVisitorConfig,
)
from control_plane.crypto import encrypt_secret, decrypt_secret
from control_plane.auth import (
    TokenInfo, verify_token, require_admin_role, require_developer_role,
    require_admin_role_with_ip_check,
)
from control_plane.utils import verify_agent_access, get_audit_tenant_id
from control_plane.rate_limit import limiter
from control_plane.redis_client import write_heartbeat, is_agent_online as redis_is_agent_online

router = APIRouter()


async def _check_agent_online(redis_client, agent: AgentState) -> bool:
    """Redis-first liveness check with DB fallback."""
    online = await redis_is_agent_online(redis_client, agent.agent_id)
    if online is not None:
        return online
    # Fallback: DB
    if agent.last_heartbeat:
        last_hb = agent.last_heartbeat
        if last_hb.tzinfo is None:
            last_hb = last_hb.replace(tzinfo=timezone.utc)
        return (datetime.now(timezone.utc) - last_hb).total_seconds() < 60
    return False


def get_or_create_agent_state(db: Session, agent_id: str = "default", tenant_id: Optional[int] = None) -> AgentState:
    """Get or create agent state record.

    If an agent was soft-deleted and tries to reconnect, it is restored
    as active (token creation is authorization).

    tenant_id is required when creating a new agent. Existing agents already
    have tenant_id in the database.

    Uses try/except IntegrityError to handle concurrent creation attempts
    (e.g. two heartbeats from a new agent arriving simultaneously).
    """
    state = db.query(AgentState).filter(AgentState.agent_id == agent_id).first()
    if not state:
        if tenant_id is None:
            raise ValueError(f"tenant_id is required when creating new agent: {agent_id}")
        state = AgentState(agent_id=agent_id, tenant_id=tenant_id, approved=True)
        db.add(state)
        try:
            db.commit()
        except IntegrityError:
            db.rollback()
            state = db.query(AgentState).filter(AgentState.agent_id == agent_id).first()
            if not state:
                raise
        db.refresh(state)
    elif state.deleted_at:
        # Restore soft-deleted agent as active
        state.deleted_at = None
        state.approved = True
        state.approved_at = datetime.now(timezone.utc)
        state.approved_by = "auto"
        db.commit()
        db.refresh(state)
    return state


@router.get("/api/v1/agents")
@limiter.limit("60/minute")
async def list_agents(
    request: Request,
    tenant_id: Optional[int] = Query(default=None, description="Filter by tenant (super admin only)"),
    limit: int = Query(default=100, le=1000),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    token_info: TokenInfo = Depends(verify_token)
):
    """List all connected data planes (agents).

    Super admins can filter by tenant_id, or see all agents if not specified.
    Tenant admins see only their tenant's agents.
    Excludes __default__ virtual agents and soft-deleted agents from listing.
    """
    query = db.query(AgentState).filter(
        AgentState.agent_id != "__default__",
        AgentState.deleted_at.is_(None)  # Exclude soft-deleted
    )

    # Apply tenant filtering
    if token_info.is_super_admin:
        # Super admin can optionally filter by tenant
        if tenant_id is not None:
            query = query.filter(AgentState.tenant_id == tenant_id)
        # else: no filter, see all agents
    else:
        # Non-super-admin MUST be scoped to their tenant
        if not token_info.tenant_id:
            raise HTTPException(status_code=403, detail="Token must be scoped to a tenant")
        query = query.filter(AgentState.tenant_id == token_info.tenant_id)

    total = query.count()
    agents = query.offset(offset).limit(limit).all()
    redis_client = getattr(request.app.state, "redis", None)
    items = []
    for agent in agents:
        online = await _check_agent_online(redis_client, agent)

        items.append(DataPlaneResponse(
            agent_id=agent.agent_id,
            status=agent.status or "unknown",
            online=online,
            tenant_id=agent.tenant_id,
            last_heartbeat=agent.last_heartbeat
        ))
    return {"items": items, "total": total, "limit": limit, "offset": offset}


@router.post("/api/v1/agent/heartbeat", response_model=AgentHeartbeatResponse)
@limiter.limit("5/second")  # Agents poll every 30s, allow burst
async def agent_heartbeat(
    request: Request,
    heartbeat: AgentHeartbeat,
    agent_id: Optional[str] = Query(default=None, description="Agent ID (required for admin tokens)"),
    db: Session = Depends(get_db),
    token_info: TokenInfo = Depends(verify_token)
):
    """Receive heartbeat from agent-manager, return any pending command.

    Called by agent-manager every 30s. Updates agent status and returns
    any pending command (wipe, restart, etc.) for the agent to execute.

    The agent_id is derived from the token (token creation is authorization).
    Admin tokens can provide agent_id as a query parameter (for dev/testing).
    """
    # Derive agent_id from token
    if token_info.token_type == "agent":
        agent_id = token_info.agent_id
        if not agent_id:
            raise HTTPException(status_code=400, detail="Agent token missing agent_id")
    else:
        # Admin tokens: fall back to query param (for dev/testing)
        if not agent_id:
            raise HTTPException(status_code=400, detail="agent_id query parameter required for admin tokens")

    # Get or create agent with tenant from token
    state = get_or_create_agent_state(db, agent_id, token_info.tenant_id)

    redis_client = getattr(request.app.state, "redis", None)

    # Update last command result if reported (infrequent, always DB)
    if heartbeat.last_command:
        state.last_command = heartbeat.last_command
        state.last_command_result = heartbeat.last_command_result
        state.last_command_message = heartbeat.last_command_message
        state.last_command_at = datetime.now(timezone.utc)

        # Log command completion
        log = AuditTrail(
            event_type=f"agent_{heartbeat.last_command}",
            user="agent-manager",
            action=f"Agent {heartbeat.last_command}: {heartbeat.last_command_result}",
            details=heartbeat.last_command_message,
            severity="INFO" if heartbeat.last_command_result == "success" else "WARNING",
            tenant_id=state.tenant_id
        )
        db.add(log)

    # Get pending command and clear it
    response = AgentHeartbeatResponse(ack=True)

    if state.pending_command:
        response.command = state.pending_command
        if state.pending_command_args:
            response.command_args = json.loads(state.pending_command_args)

        # Clear pending command (agent will report result in next heartbeat)
        state.pending_command = None
        state.pending_command_args = None
        state.pending_command_at = None

    # DB fallback: write status fields when Redis is unavailable
    if redis_client is None:
        state.status = heartbeat.status
        state.container_id = heartbeat.container_id
        state.uptime_seconds = heartbeat.uptime_seconds
        state.cpu_percent = int(heartbeat.cpu_percent) if heartbeat.cpu_percent else None
        state.memory_mb = int(heartbeat.memory_mb) if heartbeat.memory_mb else None
        state.memory_limit_mb = int(heartbeat.memory_limit_mb) if heartbeat.memory_limit_mb else None
        state.last_heartbeat = datetime.now(timezone.utc)

    db.commit()

    # Write heartbeat to Redis (primary path — background flush syncs to DB)
    await write_heartbeat(
        redis_client, agent_id,
        status=heartbeat.status,
        container_id=heartbeat.container_id,
        uptime_seconds=heartbeat.uptime_seconds,
        cpu_percent=heartbeat.cpu_percent,
        memory_mb=heartbeat.memory_mb,
        memory_limit_mb=heartbeat.memory_limit_mb,
    )

    return response


def _queue_command(
    agent_id: str,
    command: str,
    db: Session,
    token_info: TokenInfo,
    args: Optional[dict] = None,
    audit_event: Optional[str] = None,
    audit_action: Optional[str] = None,
    audit_severity: str = "INFO",
) -> dict:
    """Queue a command for an agent, with optimistic concurrency and optional audit.

    Shared implementation for wipe/restart/stop/start endpoints.
    Raises HTTPException on 404 (agent not found) or 409 (command already pending).
    """
    verify_agent_access(token_info, agent_id, db)

    state = db.query(AgentState).filter(
        AgentState.agent_id == agent_id,
        AgentState.deleted_at.is_(None)
    ).first()
    if not state:
        raise HTTPException(status_code=404, detail=f"Agent {agent_id} not found")

    values = {
        "pending_command": command,
        "pending_command_at": datetime.now(timezone.utc),
    }
    if args is not None:
        values["pending_command_args"] = json.dumps(args)

    rows = db.execute(
        update(AgentState)
        .where(AgentState.id == state.id)
        .where(AgentState.pending_command.is_(None))
        .values(**values)
    ).rowcount
    if rows == 0:
        db.refresh(state)
        raise HTTPException(
            status_code=409,
            detail=f"Command already pending: {state.pending_command}"
        )

    if audit_event:
        log = AuditTrail(
            event_type=audit_event,
            user=token_info.token_name or "admin",
            action=audit_action or f"{command} requested for {agent_id}",
            severity=audit_severity,
            tenant_id=get_audit_tenant_id(token_info, db, state)
        )
        db.add(log)

    db.commit()

    return {
        "status": "queued",
        "command": command,
        "message": f"{command.capitalize()} command queued for {agent_id}. Will execute on next agent heartbeat."
    }


@router.post("/api/v1/agents/{agent_id}/wipe")
@limiter.limit("10/minute")
async def queue_agent_wipe(
    request: Request,
    agent_id: str,
    body: AgentCommandRequest,
    db: Session = Depends(get_db),
    token_info: TokenInfo = Depends(require_admin_role_with_ip_check)
):
    """Queue a wipe command for the specified agent (admin only).

    The command will be delivered to agent-manager on next heartbeat.
    """
    return _queue_command(
        agent_id, "wipe", db, token_info,
        args={"wipe_workspace": body.wipe_workspace},
        audit_event="agent_wipe_requested",
        audit_action=f"Wipe requested for {agent_id} (workspace={'wipe' if body.wipe_workspace else 'preserve'})",
        audit_severity="WARNING",
    )


@router.post("/api/v1/agents/{agent_id}/restart")
@limiter.limit("10/minute")
async def queue_agent_restart(
    request: Request,
    agent_id: str,
    db: Session = Depends(get_db),
    token_info: TokenInfo = Depends(require_admin_role_with_ip_check)
):
    """Queue a restart command for the specified agent (admin only)."""
    return _queue_command(agent_id, "restart", db, token_info)


@router.post("/api/v1/agents/{agent_id}/stop")
@limiter.limit("10/minute")
async def queue_agent_stop(
    request: Request,
    agent_id: str,
    db: Session = Depends(get_db),
    token_info: TokenInfo = Depends(require_admin_role_with_ip_check)
):
    """Queue a stop command for the specified agent (admin only)."""
    return _queue_command(agent_id, "stop", db, token_info)


@router.post("/api/v1/agents/{agent_id}/start")
@limiter.limit("10/minute")
async def queue_agent_start(
    request: Request,
    agent_id: str,
    db: Session = Depends(get_db),
    token_info: TokenInfo = Depends(require_admin_role_with_ip_check)
):
    """Queue a start command for the specified agent (admin only)."""
    return _queue_command(agent_id, "start", db, token_info)


@router.get("/api/v1/agents/{agent_id}/status", response_model=AgentStatusResponse)
@limiter.limit("60/minute")
async def get_agent_status(
    request: Request,
    agent_id: str,
    db: Session = Depends(get_db),
    token_info: TokenInfo = Depends(verify_token)
):
    """Get agent status from last heartbeat."""
    verify_agent_access(token_info, agent_id, db)

    state = db.query(AgentState).filter(
        AgentState.agent_id == agent_id,
        AgentState.deleted_at.is_(None)
    ).first()
    if not state:
        raise HTTPException(status_code=404, detail=f"Agent {agent_id} not found")

    redis_client = getattr(request.app.state, "redis", None)
    online = await _check_agent_online(redis_client, state)

    return AgentStatusResponse(
        agent_id=state.agent_id,
        status=state.status or "unknown",
        container_id=state.container_id,
        uptime_seconds=state.uptime_seconds,
        cpu_percent=state.cpu_percent,
        memory_mb=state.memory_mb,
        memory_limit_mb=state.memory_limit_mb,
        last_heartbeat=state.last_heartbeat,
        pending_command=state.pending_command,
        last_command=state.last_command,
        last_command_result=state.last_command_result,
        last_command_at=state.last_command_at,
        online=online
    )


# =============================================================================
# STCP Configuration Endpoints
# =============================================================================

@router.post("/api/v1/agents/{agent_id}/stcp-secret", response_model=STCPSecretResponse)
@limiter.limit("10/minute")
async def generate_stcp_secret(
    request: Request,
    agent_id: str,
    db: Session = Depends(get_db),
    token_info: TokenInfo = Depends(require_admin_role)
):
    """Generate a new STCP secret for an agent (admin only).

    This secret is used by:
    1. FRP client on data plane (in STCP_SECRET_KEY env var)
    2. STCP visitor on control plane (for terminal access)

    The secret is returned only once - save it securely!
    """
    verify_agent_access(token_info, agent_id, db)

    state = db.query(AgentState).filter(
        AgentState.agent_id == agent_id,
        AgentState.deleted_at.is_(None)
    ).first()
    if not state:
        raise HTTPException(status_code=404, detail=f"Agent {agent_id} not found")

    # Generate cryptographically secure secret
    secret = secrets.token_urlsafe(32)
    state.stcp_secret_key = encrypt_secret(secret)

    # Log + save in single transaction (no partial state if audit fails)
    log = AuditTrail(
        event_type="stcp_secret_generated",
        user=token_info.token_name or "admin",
        action=f"STCP secret generated for agent {agent_id}",
        severity="INFO",
        tenant_id=get_audit_tenant_id(token_info, db, state)
    )
    db.add(log)
    db.commit()

    return STCPSecretResponse(
        agent_id=agent_id,
        secret_key=secret,  # Only returned once!
        proxy_name=f"{agent_id}-ssh",
        message="Save this secret - it will not be shown again. Use it as STCP_SECRET_KEY in data plane .env"
    )


@router.post("/api/v1/agent/stcp-secret", response_model=STCPSecretResponse)
@limiter.limit("10/minute")
async def generate_stcp_secret_from_token(
    request: Request,
    db: Session = Depends(get_db),
    token_info: TokenInfo = Depends(verify_token)
):
    """Generate STCP secret, deriving agent_id from token.

    For agent tokens, agent_id is embedded in the token.
    For admin tokens, agent_id can be passed as a query parameter.
    This is the preferred endpoint for data plane setup scripts.
    """
    if token_info.token_type == "agent":
        agent_id = token_info.agent_id
        if not agent_id:
            raise HTTPException(status_code=400, detail="Agent token missing agent_id")
    else:
        raise HTTPException(status_code=403, detail="This endpoint requires an agent token. Use /api/v1/agents/{agent_id}/stcp-secret with an admin token.")

    state = db.query(AgentState).filter(
        AgentState.agent_id == agent_id,
        AgentState.deleted_at.is_(None)
    ).first()
    if not state:
        raise HTTPException(status_code=404, detail=f"Agent {agent_id} not found")

    # Generate cryptographically secure secret
    secret = secrets.token_urlsafe(32)
    state.stcp_secret_key = encrypt_secret(secret)

    # Log + save in single transaction (no partial state if audit fails)
    log = AuditTrail(
        event_type="stcp_secret_generated",
        user=token_info.token_name or "agent",
        action=f"STCP secret generated for agent {agent_id}",
        severity="INFO",
        tenant_id=get_audit_tenant_id(token_info, db, state)
    )
    db.add(log)
    db.commit()

    return STCPSecretResponse(
        agent_id=agent_id,
        secret_key=secret,
        proxy_name=f"{agent_id}-ssh",
        message="Save this secret - it will not be shown again. Use it as STCP_SECRET_KEY in data plane .env"
    )


@router.get("/api/v1/agents/{agent_id}/stcp-config", response_model=STCPVisitorConfig)
@limiter.limit("30/minute")
async def get_stcp_visitor_config(
    request: Request,
    agent_id: str,
    db: Session = Depends(get_db),
    token_info: TokenInfo = Depends(require_developer_role)
):
    """Get STCP visitor configuration for terminal access (developer role).

    Used by the WebSocket terminal handler to establish SSH connection.
    """
    verify_agent_access(token_info, agent_id, db)

    state = db.query(AgentState).filter(
        AgentState.agent_id == agent_id,
        AgentState.deleted_at.is_(None),
    ).first()
    if not state:
        raise HTTPException(status_code=404, detail=f"Agent {agent_id} not found")

    if not state.stcp_secret_key:
        raise HTTPException(status_code=404, detail="STCP not configured for this agent. Generate a secret first.")

    return STCPVisitorConfig(
        server_addr=os.environ.get("FRP_SERVER_ADDR", "tunnel-server"),
        server_port=7000,
        proxy_name=f"{agent_id}-ssh",
        secret_key=decrypt_secret(state.stcp_secret_key)
    )
