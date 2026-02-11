import json
import re
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Optional

import httpx
from fastapi import APIRouter, HTTPException, Depends, Query, Request

from control_plane.config import (
    OPENOBSERVE_URL, OPENOBSERVE_USER, OPENOBSERVE_PASSWORD,
    OPENOBSERVE_MULTI_TENANT,
    LOG_QUERY_TIMEOUT,
    logger,
)
from control_plane.database import SessionLocal
from control_plane.models import AgentState, Tenant
from control_plane.auth import TokenInfo, require_developer_role
from control_plane.rate_limit import limiter
from control_plane.openobserve import get_query_auth, get_query_url, get_tenant_settings

router = APIRouter()


@router.get("/api/v1/analytics/blocked-domains")
@limiter.limit("30/minute")
async def get_blocked_domains(
    request: Request,
    agent_id: Optional[str] = None,
    tenant_id: Optional[int] = Query(default=None, description="Filter by tenant (super admin only)"),
    hours: int = Query(default=1, le=24),
    limit: int = Query(default=10, le=50),
    token_info: TokenInfo = Depends(require_developer_role),
):
    """Get top blocked (403) domains from Envoy access logs in OpenObserve."""

    # Determine effective tenant filter
    if token_info.is_super_admin:
        effective_tenant_id = tenant_id
    else:
        if not token_info.tenant_id:
            raise HTTPException(status_code=403, detail="Token must be scoped to a tenant")
        effective_tenant_id = token_info.tenant_id

    # DB lookups — release connection before the slow HTTP call to OpenObserve
    query_url = f"{OPENOBSERVE_URL}/api/default/_search"
    auth = (OPENOBSERVE_USER, OPENOBSERVE_PASSWORD)

    db = SessionLocal()
    try:
        if agent_id:
            if not re.match(r'^[a-zA-Z0-9_-]+$', agent_id):
                raise HTTPException(status_code=400, detail="Invalid agent_id parameter")
            agent = db.query(AgentState).filter(
                AgentState.agent_id == agent_id,
                AgentState.deleted_at.is_(None),
            ).first()
            if not agent:
                raise HTTPException(status_code=404, detail=f"Agent {agent_id} not found")
            if not token_info.is_super_admin and agent.tenant_id != token_info.tenant_id:
                raise HTTPException(status_code=403, detail=f"Access denied to agent {agent_id}")

        if OPENOBSERVE_MULTI_TENANT and effective_tenant_id is not None:
            tenant = db.query(Tenant).filter(
                Tenant.id == effective_tenant_id,
                Tenant.deleted_at.is_(None),
            ).first()
            if tenant:
                tenant_settings = get_tenant_settings(tenant)
                query_url = get_query_url(tenant.slug)
                auth = get_query_auth(tenant_settings)
    finally:
        db.close()

    # Build SQL query for OpenObserve
    conditions = ["source = 'envoy'"]

    if effective_tenant_id is not None:
        conditions.append(f"tenant_id = {int(effective_tenant_id)}")
    if agent_id:
        conditions.append(f"agent_id = '{agent_id}'")

    # Time range
    end_time = datetime.now(timezone.utc)
    start_time = end_time - timedelta(hours=hours)
    start_us = int(start_time.timestamp() * 1_000_000)
    end_us = int(end_time.timestamp() * 1_000_000)

    # Stream name
    stream_name = "logs" if OPENOBSERVE_MULTI_TENANT else "default"
    where_clause = " AND ".join(conditions)
    sql = f"SELECT message FROM {stream_name} WHERE {where_clause} ORDER BY _timestamp DESC LIMIT 5000"

    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                query_url,
                json={
                    "query": {
                        "sql": sql,
                        "start_time": start_us,
                        "end_time": end_us,
                    }
                },
                auth=auth,
                timeout=LOG_QUERY_TIMEOUT,
            )

            if response.status_code != 200:
                raise HTTPException(
                    status_code=502,
                    detail=f"OpenObserve query failed (status {response.status_code}): {response.text}",
                )

            result = response.json()
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"OpenObserve connection error: {e}")
        raise HTTPException(status_code=502, detail=f"Log store unreachable: {e}")

    # Parse messages, filter 403s, group by authority
    domain_counts: dict[str, int] = defaultdict(int)
    domain_last_seen: dict[str, str] = {}

    for hit in result.get("hits", []):
        message = hit.get("message", "")
        if not message:
            continue

        # message is a JSON string from Envoy access log
        try:
            entry = json.loads(message) if isinstance(message, str) else message
        except (json.JSONDecodeError, ValueError):
            continue

        try:
            code = int(entry.get("response_code", 0))
        except (ValueError, TypeError):
            continue

        if code != 403:
            continue

        authority = entry.get("authority", "")
        if not authority or authority == "-":
            continue

        domain_counts[authority] += 1
        ts = entry.get("timestamp") or hit.get("_timestamp", "")
        if ts:
            domain_last_seen[authority] = str(ts)

    # Sort by count descending, take top N
    sorted_domains = sorted(domain_counts.items(), key=lambda x: x[1], reverse=True)[:limit]

    now_iso = datetime.now(timezone.utc).isoformat()
    blocked_domains = [
        {
            "domain": domain,
            "count": count,
            "last_seen": domain_last_seen.get(domain, now_iso),
        }
        for domain, count in sorted_domains
    ]

    return {
        "blocked_domains": blocked_domains,
        "window_hours": hours,
    }
