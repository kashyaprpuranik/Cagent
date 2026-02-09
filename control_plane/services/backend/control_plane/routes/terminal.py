import json
import uuid
import logging
from datetime import datetime, timedelta
from typing import Optional, List

from fastapi import APIRouter, HTTPException, Depends, Query, Request, WebSocket, WebSocketDisconnect
from starlette.websockets import WebSocketState
from sqlalchemy.orm import Session

from control_plane.database import SessionLocal, get_db
from control_plane.models import AgentState, AuditTrail, TerminalSession, WebSocketTicket
from control_plane.schemas import TerminalSessionResponse, TerminalTicketResponse
from control_plane.crypto import generate_token, hash_token
from control_plane.auth import TokenInfo, require_admin_role, require_developer_role
from control_plane.rate_limit import limiter

logger = logging.getLogger(__name__)

router = APIRouter()

TICKET_EXPIRY_SECONDS = 60


@router.post("/api/v1/terminal/{agent_id}/ticket", response_model=TerminalTicketResponse)
@limiter.limit("30/minute")
async def create_terminal_ticket(
    request: Request,
    agent_id: str,
    db: Session = Depends(get_db),
    token_info: TokenInfo = Depends(require_developer_role),
):
    """Create a short-lived, single-use ticket for WebSocket authentication.

    The ticket replaces passing raw API tokens as query params, which get logged
    by reverse proxies. Clients call this endpoint with a proper Authorization
    header, then pass the returned ticket to the WebSocket URL.
    """
    # Verify agent exists and is online
    agent = db.query(AgentState).filter(
        AgentState.agent_id == agent_id,
        AgentState.deleted_at.is_(None),
    ).first()

    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")

    if not agent.stcp_secret_key:
        raise HTTPException(status_code=400, detail="STCP not configured for agent")

    if not agent.last_heartbeat or (datetime.utcnow() - agent.last_heartbeat).total_seconds() > 60:
        raise HTTPException(status_code=400, detail="Agent is offline")

    # Tenant isolation
    if not token_info.is_super_admin:
        if token_info.tenant_id and agent.tenant_id != token_info.tenant_id:
            raise HTTPException(status_code=403, detail="Agent belongs to different tenant")

    # Generate ticket
    raw_ticket = generate_token()
    ticket_hash_value = hash_token(raw_ticket)

    ticket = WebSocketTicket(
        ticket_hash=ticket_hash_value,
        api_token_id=token_info.api_token_id,
        agent_id=agent_id,
        tenant_id=token_info.tenant_id,
        token_name=token_info.token_name,
        roles=",".join(token_info.roles),
        is_super_admin=token_info.is_super_admin,
        expires_at=datetime.utcnow() + timedelta(seconds=TICKET_EXPIRY_SECONDS),
    )
    db.add(ticket)
    db.commit()

    return TerminalTicketResponse(
        ticket=raw_ticket,
        expires_in_seconds=TICKET_EXPIRY_SECONDS,
    )


@router.websocket("/api/v1/terminal/{agent_id}/ws")
async def terminal_websocket(
    websocket: WebSocket,
    agent_id: str
):
    """WebSocket endpoint for terminal access to an agent.

    Authentication:
    - Short-lived ticket passed as query param: ?ticket=xxx
    - Obtain a ticket via POST /api/v1/terminal/{agent_id}/ticket

    Messages:
    - Binary: Terminal data (stdin/stdout)
    - Text JSON: Control messages (resize, ping)

    Note: This is a simplified implementation. For production, implement
    proper SSH connection via paramiko with STCP visitor subprocess.
    """
    # Get database session
    db = SessionLocal()

    try:
        # Accept connection first
        await websocket.accept()

        # Authenticate via ticket query param
        ticket_raw = websocket.query_params.get("ticket")
        if not ticket_raw:
            await websocket.close(code=4001, reason="Authentication required - pass ticket as query param")
            return

        # Look up ticket by hash
        ticket_hash_value = hash_token(ticket_raw)
        ticket = db.query(WebSocketTicket).filter(
            WebSocketTicket.ticket_hash == ticket_hash_value,
        ).first()

        if not ticket:
            await websocket.close(code=4003, reason="Invalid ticket")
            return

        # Validate ticket is unused and not expired
        if ticket.used:
            await websocket.close(code=4003, reason="Ticket already used")
            return

        if ticket.expires_at < datetime.utcnow():
            await websocket.close(code=4003, reason="Ticket expired")
            return

        # Validate ticket is for this agent
        if ticket.agent_id != agent_id:
            await websocket.close(code=4003, reason="Ticket not valid for this agent")
            return

        # Mark ticket as used immediately (single-use)
        ticket.used = True
        db.commit()

        # Use cached fields from the ticket
        token_name = ticket.token_name
        tenant_id = ticket.tenant_id
        is_super_admin = ticket.is_super_admin

        # Get agent state
        agent = db.query(AgentState).filter(
            AgentState.agent_id == agent_id,
            AgentState.deleted_at.is_(None),
        ).first()

        if not agent:
            await websocket.close(code=4004, reason="Agent not found")
            return

        if not agent.stcp_secret_key:
            await websocket.close(code=4004, reason="STCP not configured for agent")
            return

        # Check if agent is online
        if not agent.last_heartbeat or (datetime.utcnow() - agent.last_heartbeat).total_seconds() > 60:
            await websocket.close(code=4004, reason="Agent is offline")
            return

        # Get client IP
        client_ip = websocket.client.host if websocket.client else "unknown"

        # Create terminal session record
        session_id = str(uuid.uuid4())
        session_record = TerminalSession(
            session_id=session_id,
            agent_id=agent_id,
            user=token_name,
            tenant_id=tenant_id,
            client_ip=client_ip
        )
        db.add(session_record)

        # Audit log — target is the agent's tenant
        audit_tenant_id = tenant_id
        log = AuditTrail(
            event_type="terminal_session_start",
            user=token_name,
            container_id=agent_id,
            action=f"Terminal session started for agent {agent_id}",
            details=json.dumps({"session_id": session_id, "client_ip": client_ip}),
            severity="INFO",
            tenant_id=audit_tenant_id
        )
        db.add(log)
        db.commit()

        started_at = datetime.utcnow()
        bytes_sent = 0
        bytes_received = 0

        # Send welcome message
        await websocket.send_text(json.dumps({
            "type": "connected",
            "session_id": session_id,
            "agent_id": agent_id,
            "message": "Connected to agent terminal"
        }))

        # Terminal relay loop
        # NOTE: For full SSH implementation, use paramiko here
        # This simplified version echoes commands (placeholder for real SSH)
        try:
            while True:
                data = await websocket.receive()

                if "text" in data:
                    msg = json.loads(data["text"])
                    if msg.get("type") == "resize":
                        # Handle terminal resize
                        cols = msg.get("cols", 80)
                        rows = msg.get("rows", 24)
                        logger.debug(f"Terminal resize: {cols}x{rows}")
                    elif msg.get("type") == "ping":
                        await websocket.send_text(json.dumps({"type": "pong"}))

                elif "bytes" in data:
                    # Forward to SSH (placeholder - echo for now)
                    bytes_sent += len(data["bytes"])
                    # In real implementation: ssh_channel.send(data["bytes"])
                    # For now, echo back
                    response = data["bytes"]
                    bytes_received += len(response)
                    await websocket.send_bytes(response)

        except WebSocketDisconnect:
            logger.info(f"Terminal session {session_id} disconnected")

    except Exception as e:
        logger.error(f"Terminal error: {e}")
        if websocket.client_state == WebSocketState.CONNECTED:
            await websocket.close(code=4005, reason=str(e))

    finally:
        # Update session record
        ended_at = datetime.utcnow()
        duration = int((ended_at - started_at).total_seconds()) if 'started_at' in locals() else 0

        if 'session_id' in locals():
            session = db.query(TerminalSession).filter(
                TerminalSession.session_id == session_id
            ).first()
            if session:
                session.ended_at = ended_at
                session.duration_seconds = duration
                session.bytes_sent = bytes_sent if 'bytes_sent' in locals() else 0
                session.bytes_received = bytes_received if 'bytes_received' in locals() else 0

            # Audit log
            log = AuditTrail(
                event_type="terminal_session_end",
                user=token_name if 'token_name' in locals() else "unknown",
                container_id=agent_id,
                action=f"Terminal session ended for agent {agent_id}",
                details=json.dumps({
                    "session_id": session_id,
                    "duration_seconds": duration,
                    "bytes_sent": bytes_sent if 'bytes_sent' in locals() else 0,
                    "bytes_received": bytes_received if 'bytes_received' in locals() else 0
                }),
                severity="INFO",
                tenant_id=audit_tenant_id if 'audit_tenant_id' in locals() else None
            )
            db.add(log)
            db.commit()

        db.close()


@router.get("/api/v1/terminal/sessions", response_model=List[TerminalSessionResponse])
@limiter.limit("60/minute")
async def list_terminal_sessions(
    request: Request,
    agent_id: Optional[str] = None,
    limit: int = Query(default=50, le=200),
    db: Session = Depends(get_db),
    token_info: TokenInfo = Depends(require_admin_role)
):
    """List terminal sessions (admin only).

    Filter by agent_id to see sessions for a specific agent.
    """
    query = db.query(TerminalSession).order_by(TerminalSession.started_at.desc())

    if agent_id:
        query = query.filter(TerminalSession.agent_id == agent_id)

    # Tenant isolation
    if not token_info.is_super_admin:
        if not token_info.tenant_id:
            raise HTTPException(status_code=403, detail="Token must be scoped to a tenant")
        query = query.filter(TerminalSession.tenant_id == token_info.tenant_id)

    return query.limit(limit).all()
