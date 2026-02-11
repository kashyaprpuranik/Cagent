import json
import time
from collections import defaultdict
from datetime import datetime, timezone

import docker
from fastapi import APIRouter, Query, HTTPException

from ..constants import ENVOY_CONTAINER_NAME, docker_client

router = APIRouter()


@router.get("/analytics/blocked-domains")
async def get_blocked_domains(
    hours: int = Query(default=1, le=24),
    limit: int = Query(default=10, le=50),
):
    """Get top blocked (403) domains from Envoy access logs."""
    try:
        container = docker_client.containers.get(ENVOY_CONTAINER_NAME)
    except docker.errors.NotFound:
        raise HTTPException(404, f"Container not found: {ENVOY_CONTAINER_NAME}")

    since = int(time.time()) - hours * 3600
    try:
        raw = container.logs(stdout=True, stderr=False, since=since).decode("utf-8")
    except Exception as e:
        raise HTTPException(500, f"Failed to read logs: {e}")

    # Parse JSON access log lines, filter 403s, group by authority
    domain_counts: dict[str, int] = defaultdict(int)
    domain_last_seen: dict[str, str] = {}

    for line in raw.strip().split("\n"):
        if not line:
            continue
        # Envoy logs may have a docker timestamp prefix before the JSON
        json_start = line.find("{")
        if json_start == -1:
            continue
        try:
            entry = json.loads(line[json_start:])
        except (json.JSONDecodeError, ValueError):
            continue

        # response_code can be string or int in Envoy JSON logs
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
        ts = entry.get("timestamp", "")
        if ts:
            domain_last_seen[authority] = ts

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
