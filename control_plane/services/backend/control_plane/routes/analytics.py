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
from control_plane.models import AgentState, Tenant, DomainPolicy
from control_plane.auth import TokenInfo, require_developer_role
from control_plane.rate_limit import limiter
from control_plane.openobserve import get_query_auth, get_query_url, get_tenant_settings

router = APIRouter()


def _resolve_tenant_and_agent(token_info: TokenInfo, agent_id: Optional[str], tenant_id: Optional[int]):
    """Common logic: resolve effective tenant, validate agent access, return query params."""
    if token_info.is_super_admin:
        effective_tenant_id = tenant_id
    else:
        if not token_info.tenant_id:
            raise HTTPException(status_code=403, detail="Token must be scoped to a tenant")
        effective_tenant_id = token_info.tenant_id

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

    return effective_tenant_id, query_url, auth


async def _query_openobserve(
    http_client: httpx.AsyncClient, query_url: str, auth: tuple, sql: str, start_us: int, end_us: int,
) -> list:
    """Execute a query against OpenObserve and return hits."""
    try:
        response = await http_client.post(
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
        return result.get("hits", [])
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"OpenObserve connection error: {e}")
        raise HTTPException(status_code=502, detail=f"Log store unreachable: {e}")


def _escape_sql_string(value: str) -> str:
    """Escape a value for safe use in a SQL single-quoted string literal."""
    return value.replace("'", "''").replace("\\", "\\\\")


def _build_conditions(effective_tenant_id: Optional[int], agent_id: Optional[str]) -> list[str]:
    """Build common WHERE conditions for OpenObserve SQL."""
    conditions = ["source = 'envoy'"]
    if effective_tenant_id is not None:
        conditions.append(f"tenant_id = {int(effective_tenant_id)}")
    if agent_id:
        conditions.append(f"agent_id = '{_escape_sql_string(agent_id)}'")
    return conditions


def _time_range(hours: int) -> tuple[int, int, datetime, datetime]:
    """Return (start_us, end_us, start_time, end_time) for the given window."""
    end_time = datetime.now(timezone.utc)
    start_time = end_time - timedelta(hours=hours)
    start_us = int(start_time.timestamp() * 1_000_000)
    end_us = int(end_time.timestamp() * 1_000_000)
    return start_us, end_us, start_time, end_time


def _parse_envoy_message(hit: dict):
    """Parse the Envoy JSON message from an OpenObserve hit."""
    message = hit.get("message", "")
    if not message:
        return None
    try:
        return json.loads(message) if isinstance(message, str) else message
    except (json.JSONDecodeError, ValueError):
        return None


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
    effective_tenant_id, query_url, auth = _resolve_tenant_and_agent(token_info, agent_id, tenant_id)

    start_us, end_us, _, _ = _time_range(hours)
    conditions = _build_conditions(effective_tenant_id, agent_id)
    # Filter 403s in SQL to reduce data transfer
    conditions.append("str_match(message, '\"response_code\":\"403\"')")
    stream_name = "logs" if OPENOBSERVE_MULTI_TENANT else "default"
    where_clause = " AND ".join(conditions)
    sql = f"SELECT message FROM {stream_name} WHERE {where_clause} ORDER BY _timestamp DESC LIMIT 5000"

    http_client = request.app.state.http_client
    hits = await _query_openobserve(http_client, query_url, auth, sql, start_us, end_us)

    domain_counts: dict[str, int] = defaultdict(int)
    domain_last_seen: dict[str, str] = {}

    for hit in hits:
        entry = _parse_envoy_message(hit)
        if not entry:
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


@router.get("/api/v1/analytics/blocked-domains/timeseries")
@limiter.limit("30/minute")
async def get_blocked_timeseries(
    request: Request,
    agent_id: Optional[str] = None,
    tenant_id: Optional[int] = Query(default=None),
    hours: int = Query(default=1, ge=1, le=24),
    buckets: int = Query(default=12, ge=2, le=60),
    token_info: TokenInfo = Depends(require_developer_role),
):
    """Get blocked request counts bucketed by time interval."""
    effective_tenant_id, query_url, auth = _resolve_tenant_and_agent(token_info, agent_id, tenant_id)

    start_us, end_us, start_time, end_time = _time_range(hours)
    conditions = _build_conditions(effective_tenant_id, agent_id)
    # Filter 403s in SQL to reduce data transfer
    conditions.append("str_match(message, '\"response_code\":\"403\"')")
    stream_name = "logs" if OPENOBSERVE_MULTI_TENANT else "default"
    where_clause = " AND ".join(conditions)
    sql = f"SELECT message FROM {stream_name} WHERE {where_clause} ORDER BY _timestamp DESC LIMIT 5000"

    http_client = request.app.state.http_client
    hits = await _query_openobserve(http_client, query_url, auth, sql, start_us, end_us)

    bucket_duration = (end_time - start_time) / buckets
    bucket_counts = [0] * buckets
    bucket_starts = [start_time + bucket_duration * i for i in range(buckets)]
    bucket_ends = [start_time + bucket_duration * (i + 1) for i in range(buckets)]

    for hit in hits:
        entry = _parse_envoy_message(hit)
        if not entry:
            continue
        try:
            code = int(entry.get("response_code", 0))
        except (ValueError, TypeError):
            continue
        if code != 403:
            continue

        ts_str = entry.get("timestamp") or ""
        if not ts_str:
            continue
        try:
            ts = datetime.fromisoformat(str(ts_str).replace("Z", "+00:00"))
        except (ValueError, TypeError):
            continue

        if ts < start_time or ts > end_time:
            continue
        idx = int((ts - start_time) / bucket_duration)
        if idx >= buckets:
            idx = buckets - 1
        bucket_counts[idx] += 1

    bucket_minutes = int(bucket_duration.total_seconds() / 60)

    return {
        "buckets": [
            {
                "start": bucket_starts[i].isoformat(),
                "end": bucket_ends[i].isoformat(),
                "count": bucket_counts[i],
            }
            for i in range(buckets)
        ],
        "window_hours": hours,
        "bucket_minutes": bucket_minutes,
    }


@router.get("/api/v1/analytics/bandwidth")
@limiter.limit("30/minute")
async def get_bandwidth(
    request: Request,
    agent_id: Optional[str] = None,
    tenant_id: Optional[int] = Query(default=None),
    hours: int = Query(default=1, ge=1, le=24),
    limit: int = Query(default=10, le=50),
    token_info: TokenInfo = Depends(require_developer_role),
):
    """Get bandwidth usage per domain from Envoy access logs."""
    effective_tenant_id, query_url, auth = _resolve_tenant_and_agent(token_info, agent_id, tenant_id)

    start_us, end_us, _, _ = _time_range(hours)
    conditions = _build_conditions(effective_tenant_id, agent_id)
    stream_name = "logs" if OPENOBSERVE_MULTI_TENANT else "default"
    where_clause = " AND ".join(conditions)
    sql = f"SELECT message FROM {stream_name} WHERE {where_clause} ORDER BY _timestamp DESC LIMIT 5000"

    http_client = request.app.state.http_client
    hits = await _query_openobserve(http_client, query_url, auth, sql, start_us, end_us)

    domain_stats: dict[str, dict] = defaultdict(
        lambda: {"bytes_sent": 0, "bytes_received": 0, "request_count": 0}
    )

    for hit in hits:
        entry = _parse_envoy_message(hit)
        if not entry:
            continue

        authority = entry.get("authority", "")
        if not authority or authority == "-":
            continue

        try:
            bs = int(entry.get("bytes_sent", 0))
            br = int(entry.get("bytes_received", 0))
        except (ValueError, TypeError):
            continue

        stats = domain_stats[authority]
        stats["bytes_sent"] += bs
        stats["bytes_received"] += br
        stats["request_count"] += 1

    sorted_domains = sorted(
        domain_stats.items(),
        key=lambda x: x[1]["bytes_sent"] + x[1]["bytes_received"],
        reverse=True,
    )[:limit]

    return {
        "domains": [
            {
                "domain": domain,
                "bytes_sent": stats["bytes_sent"],
                "bytes_received": stats["bytes_received"],
                "total_bytes": stats["bytes_sent"] + stats["bytes_received"],
                "request_count": stats["request_count"],
            }
            for domain, stats in sorted_domains
        ],
        "window_hours": hours,
    }


@router.get("/api/v1/analytics/diagnose")
@limiter.limit("30/minute")
async def diagnose_domain(
    request: Request,
    domain: str = Query(..., min_length=1),
    agent_id: Optional[str] = None,
    tenant_id: Optional[int] = Query(default=None),
    token_info: TokenInfo = Depends(require_developer_role),
):
    """Diagnose why a domain was blocked. Checks DB policy and recent logs."""
    effective_tenant_id, query_url, auth = _resolve_tenant_and_agent(token_info, agent_id, tenant_id)

    # Check if domain has a policy in the DB
    in_allowlist = False
    db = SessionLocal()
    try:
        query = db.query(DomainPolicy).filter(
            DomainPolicy.enabled == True,
            DomainPolicy.domain == domain,
        )
        if effective_tenant_id is not None:
            query = query.filter(DomainPolicy.tenant_id == effective_tenant_id)
        in_allowlist = query.first() is not None
    finally:
        db.close()

    # Get recent log entries for this domain
    start_us, end_us, _, _ = _time_range(1)
    conditions = _build_conditions(effective_tenant_id, agent_id)
    stream_name = "logs" if OPENOBSERVE_MULTI_TENANT else "default"
    where_clause = " AND ".join(conditions)
    sql = f"SELECT message FROM {stream_name} WHERE {where_clause} ORDER BY _timestamp DESC LIMIT 1000"

    http_client = request.app.state.http_client
    hits = await _query_openobserve(http_client, query_url, auth, sql, start_us, end_us)

    recent_requests = []
    for hit in hits:
        entry = _parse_envoy_message(hit)
        if not entry:
            continue
        authority = entry.get("authority", "")
        if authority != domain:
            continue
        recent_requests.append({
            "timestamp": entry.get("timestamp", ""),
            "method": entry.get("method", ""),
            "path": entry.get("path", ""),
            "response_code": int(entry.get("response_code", 0)),
            "response_flags": entry.get("response_flags", ""),
            "duration_ms": int(entry.get("duration_ms", 0)),
        })
    # Most recent first, limit to 5
    recent_requests = recent_requests[:5]

    # Build diagnosis
    parts = []
    if in_allowlist:
        parts.append("Domain has an active policy in the allowlist.")
    else:
        parts.append("Domain is not in the allowlist.")

    if recent_requests:
        code = recent_requests[0]["response_code"]
        flags = recent_requests[0]["response_flags"]
        if code == 403:
            parts.append(f"Proxy returns 403 via Lua filter{f' (flags: {flags})' if flags else ''}.")
        else:
            parts.append(f"Most recent response: HTTP {code}.")

    return {
        "domain": domain,
        "in_allowlist": in_allowlist,
        "recent_requests": recent_requests,
        "diagnosis": " ".join(parts),
    }
