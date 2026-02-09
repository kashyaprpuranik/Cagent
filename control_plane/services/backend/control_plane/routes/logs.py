import re
from datetime import datetime, timedelta
from typing import Optional, List

from fastapi import APIRouter, HTTPException, Depends, Query, Request
from sqlalchemy.orm import Session

from control_plane.config import OPENOBSERVE_URL, OPENOBSERVE_USER, OPENOBSERVE_PASSWORD
from control_plane.database import get_db
from control_plane.models import AgentState, AuditTrail
from control_plane.schemas import LogBatch, AuditTrailResponse
from control_plane.auth import TokenInfo, verify_token, require_admin_role, require_developer_role
from control_plane.rate_limit import limiter
from control_plane.config import logger

router = APIRouter()

# Allowlist for log search queries: alphanumeric, whitespace, and common log punctuation.
# Rejects SQL metacharacters (quotes, semicolons, backslashes, parens, comments).
_SAFE_QUERY_RE = re.compile(r'^[a-zA-Z0-9\s\.\-_:/@=,\[\]{}|*+#]+$')


@router.post("/api/v1/logs/ingest")
@limiter.limit("100/minute")
async def ingest_logs(
    request: Request,
    batch: LogBatch,
    token_info: TokenInfo = Depends(verify_token),
    db: Session = Depends(get_db)
):
    """Ingest logs from data plane agents.

    Requires agent token. Injects trusted agent_id and tenant_id from database.
    This ensures data planes cannot spoof their identity in logs.
    """
    import httpx

    # Only agent tokens can ingest logs
    if token_info.token_type != "agent":
        raise HTTPException(
            status_code=403,
            detail="Only agent tokens can ingest logs"
        )

    if not token_info.agent_id:
        raise HTTPException(
            status_code=403,
            detail="Agent token must have agent_id"
        )

    # Get tenant_id from agent state (trusted source, not from request)
    agent = db.query(AgentState).filter(
        AgentState.agent_id == token_info.agent_id,
        AgentState.deleted_at.is_(None)
    ).first()

    if not agent:
        raise HTTPException(
            status_code=404,
            detail=f"Agent {token_info.agent_id} not found"
        )

    tenant_id = agent.tenant_id

    # Transform logs for OpenObserve, injecting trusted identity
    enriched_logs = []
    for log in batch.logs:
        entry = {
            "_timestamp": int((log.timestamp or datetime.utcnow()).timestamp() * 1_000_000),
            "message": log.message,
            "source": log.source,
            "level": log.level or "info",
            "agent_id": token_info.agent_id,  # Trusted, from verified token
            "tenant_id": tenant_id,            # Trusted, from database
        }
        if log.extra:
            # Filter out any attempt to override trusted fields
            safe_extra = {k: v for k, v in log.extra.items()
                         if k not in ("agent_id", "tenant_id", "_timestamp")}
            entry.update(safe_extra)
        enriched_logs.append(entry)

    # Forward to OpenObserve
    async with httpx.AsyncClient() as client:
        response = await client.post(
            f"{OPENOBSERVE_URL}/api/default/default/_json",
            json=enriched_logs,
            auth=(OPENOBSERVE_USER, OPENOBSERVE_PASSWORD),
            timeout=30.0
        )

        if response.status_code not in (200, 201):
            logger.error(f"OpenObserve ingestion failed: {response.status_code} {response.text}")
            raise HTTPException(
                status_code=502,
                detail=f"Failed to store logs: {response.text}"
            )

    return {"status": "ok", "count": len(enriched_logs)}


@router.get("/api/v1/logs/query")
@limiter.limit("30/minute")
async def query_agent_logs(
    request: Request,
    query: str = "",
    source: Optional[str] = None,
    agent_id: Optional[str] = None,
    tenant_id: Optional[int] = Query(default=None, description="Filter by tenant (super admin only)"),
    limit: int = Query(default=100, le=1000),
    start: Optional[str] = None,
    end: Optional[str] = None,
    token_info: TokenInfo = Depends(require_developer_role),
    db: Session = Depends(get_db)
):
    """Query agent logs from OpenObserve.

    Tenant filtering:
    - Super admins can query any tenant (optional tenant_id filter)
    - Tenant users can only query their tenant's logs
    - If agent_id specified, verifies user has access to that agent's tenant

    Args:
        query: Search text (full-text search in message field)
        source: Filter by source (envoy, agent, coredns, gvisor)
        agent_id: Filter by agent ID
        tenant_id: Filter by tenant (super admin only)
        limit: Max number of log lines to return (max 1000)
        start: Start time (RFC3339, e.g., 2024-01-01T00:00:00Z)
        end: End time (RFC3339)
    """
    import httpx

    # Determine effective tenant filter
    if token_info.is_super_admin:
        effective_tenant_id = tenant_id  # Optional filter for super admins
    else:
        # Non-super-admin MUST be scoped to their tenant
        if not token_info.tenant_id:
            raise HTTPException(status_code=403, detail="Token must be scoped to a tenant")
        effective_tenant_id = token_info.tenant_id

    # If agent_id specified, verify access to that agent's tenant
    if agent_id:
        agent = db.query(AgentState).filter(
            AgentState.agent_id == agent_id,
            AgentState.deleted_at.is_(None)
        ).first()

        if not agent:
            raise HTTPException(status_code=404, detail=f"Agent {agent_id} not found")

        # Non-super-admin must have access to agent's tenant
        if not token_info.is_super_admin and agent.tenant_id != token_info.tenant_id:
            raise HTTPException(status_code=403, detail=f"Access denied to agent {agent_id}")

    # Build SQL query for OpenObserve with SQL injection prevention
    conditions = []

    # Tenant filter (always applied for non-super-admins)
    if effective_tenant_id is not None:
        conditions.append(f"tenant_id = {int(effective_tenant_id)}")

    if query:
        if len(query) > 500:
            raise HTTPException(status_code=400, detail="Query too long (max 500 characters)")
        if not _SAFE_QUERY_RE.match(query):
            raise HTTPException(
                status_code=400,
                detail="Query contains disallowed characters. Use only letters, numbers, spaces, and common punctuation (. - _ : / @ = , [ ] { } | * + #)."
            )
        conditions.append(f"message LIKE '%{query}%'")
    if source:
        # Validate source is alphanumeric
        if not source.replace("_", "").replace("-", "").isalnum():
            raise HTTPException(status_code=400, detail="Invalid source parameter")
        conditions.append(f"source = '{source}'")
    if agent_id:
        # Validate agent_id is alphanumeric with hyphens/underscores
        if not agent_id.replace("_", "").replace("-", "").isalnum():
            raise HTTPException(status_code=400, detail="Invalid agent_id parameter")
        conditions.append(f"agent_id = '{agent_id}'")

    # Time range
    if not end:
        end_time = datetime.utcnow()
    else:
        end_time = datetime.fromisoformat(end.replace('Z', '+00:00'))

    if not start:
        start_time = end_time - timedelta(hours=1)
    else:
        start_time = datetime.fromisoformat(start.replace('Z', '+00:00'))

    # Convert to microseconds for OpenObserve
    start_us = int(start_time.timestamp() * 1_000_000)
    end_us = int(end_time.timestamp() * 1_000_000)

    where_clause = " AND ".join(conditions) if conditions else "1=1"
    sql = f"SELECT * FROM default WHERE {where_clause} ORDER BY _timestamp DESC LIMIT {limit}"

    async with httpx.AsyncClient() as client:
        response = await client.post(
            f"{OPENOBSERVE_URL}/api/default/_search",
            json={
                "query": {
                    "sql": sql,
                    "start_time": start_us,
                    "end_time": end_us,
                }
            },
            auth=(OPENOBSERVE_USER, OPENOBSERVE_PASSWORD),
            timeout=30.0
        )

        if response.status_code != 200:
            # Return 502 Bad Gateway for upstream errors - don't pass through status
            # (passing through 401 would make frontend think user token is invalid)
            raise HTTPException(
                status_code=502,
                detail=f"OpenObserve query failed (status {response.status_code}): {response.text}"
            )

        result = response.json()

        # Transform to consistent format for UI
        return {
            "status": "success",
            "data": {
                "resultType": "streams",
                "result": result.get("hits", [])
            }
        }


# =============================================================================
# Audit Log Endpoints
# =============================================================================

@router.get("/api/v1/audit-trail")
@limiter.limit("60/minute")
async def get_audit_trail(
    request: Request,
    db: Session = Depends(get_db),
    token_info: TokenInfo = Depends(require_admin_role),
    tenant_id: Optional[int] = Query(default=None, description="Filter by tenant (super admin only)"),
    event_type: Optional[str] = None,
    user: Optional[str] = None,
    severity: Optional[str] = None,
    container_id: Optional[str] = None,
    start_time: Optional[str] = Query(default=None, description="ISO datetime string"),
    end_time: Optional[str] = Query(default=None, description="ISO datetime string"),
    search: Optional[str] = None,
    limit: int = Query(default=100, le=1000),
    offset: int = 0
):
    """Search and retrieve audit trail entries (admin only).

    Super admins can filter by tenant_id, or see all logs if not specified.
    Tenant admins see only their tenant's logs.
    """
    query = db.query(AuditTrail)

    # Apply tenant filtering
    if token_info.is_super_admin:
        # Super admin can optionally filter by tenant
        if tenant_id is not None:
            query = query.filter(AuditTrail.tenant_id == tenant_id)
        # else: no filter, see all logs
    else:
        # Non-super-admin MUST be scoped to their tenant
        if not token_info.tenant_id:
            raise HTTPException(status_code=403, detail="Token must be scoped to a tenant")
        query = query.filter(AuditTrail.tenant_id == token_info.tenant_id)

    if event_type:
        query = query.filter(AuditTrail.event_type == event_type)
    if user:
        query = query.filter(AuditTrail.user.contains(user))
    if severity:
        query = query.filter(AuditTrail.severity == severity.upper())
    if container_id:
        query = query.filter(AuditTrail.container_id == container_id)
    if start_time:
        try:
            parsed = datetime.fromisoformat(start_time)
            query = query.filter(AuditTrail.timestamp >= parsed)
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid start_time format: {start_time}")
    if end_time:
        try:
            parsed = datetime.fromisoformat(end_time)
            query = query.filter(AuditTrail.timestamp <= parsed)
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid end_time format: {end_time}")
    if search:
        query = query.filter(
            AuditTrail.event_type.contains(search) |
            AuditTrail.action.contains(search) |
            AuditTrail.details.contains(search)
        )

    total = query.count()
    items = query.order_by(AuditTrail.timestamp.desc()).offset(offset).limit(limit).all()
    return {"items": items, "total": total}
