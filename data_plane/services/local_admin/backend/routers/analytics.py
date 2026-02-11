import json
import subprocess
import time
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

import docker
import yaml
from fastapi import APIRouter, Query, HTTPException

from ..constants import ENVOY_CONTAINER_NAME, COREDNS_CONTAINER_NAME, CAGENT_CONFIG_PATH, docker_client

router = APIRouter()


def _get_envoy_logs(hours: int) -> str:
    """Read Envoy access log lines from Docker for the given time window."""
    try:
        container = docker_client.containers.get(ENVOY_CONTAINER_NAME)
    except docker.errors.NotFound:
        raise HTTPException(404, f"Container not found: {ENVOY_CONTAINER_NAME}")

    since = int(time.time()) - hours * 3600
    try:
        return container.logs(stdout=True, stderr=False, since=since).decode("utf-8")
    except Exception as e:
        raise HTTPException(500, f"Failed to read logs: {e}")


def _parse_log_entries(raw: str):
    """Parse all JSON access log lines from raw Envoy output."""
    for line in raw.strip().split("\n"):
        if not line:
            continue
        json_start = line.find("{")
        if json_start == -1:
            continue
        try:
            yield json.loads(line[json_start:])
        except (json.JSONDecodeError, ValueError):
            continue


@router.get("/analytics/blocked-domains")
async def get_blocked_domains(
    hours: int = Query(default=1, le=24),
    limit: int = Query(default=10, le=50),
):
    """Get top blocked (403) domains from Envoy access logs."""
    raw = _get_envoy_logs(hours)

    domain_counts: dict[str, int] = defaultdict(int)
    domain_last_seen: dict[str, str] = {}

    for entry in _parse_log_entries(raw):
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


@router.get("/analytics/blocked-domains/timeseries")
async def get_blocked_timeseries(
    hours: int = Query(default=1, ge=1, le=24),
    buckets: int = Query(default=12, ge=2, le=60),
):
    """Get blocked request counts bucketed by time interval."""
    raw = _get_envoy_logs(hours)

    end_time = datetime.now(timezone.utc)
    start_time = end_time - timedelta(hours=hours)
    bucket_duration = (end_time - start_time) / buckets

    # Initialize buckets
    bucket_counts = [0] * buckets
    bucket_starts = [start_time + bucket_duration * i for i in range(buckets)]
    bucket_ends = [start_time + bucket_duration * (i + 1) for i in range(buckets)]

    for entry in _parse_log_entries(raw):
        try:
            code = int(entry.get("response_code", 0))
        except (ValueError, TypeError):
            continue
        if code != 403:
            continue

        ts_str = entry.get("timestamp", "")
        if not ts_str:
            continue
        try:
            ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
        except (ValueError, TypeError):
            continue

        # Find bucket index
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


@router.get("/analytics/bandwidth")
async def get_bandwidth(
    hours: int = Query(default=1, ge=1, le=24),
    limit: int = Query(default=10, le=50),
):
    """Get bandwidth usage per domain from Envoy access logs."""
    raw = _get_envoy_logs(hours)

    domain_stats: dict[str, dict] = defaultdict(
        lambda: {"bytes_sent": 0, "bytes_received": 0, "request_count": 0}
    )

    for entry in _parse_log_entries(raw):
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

    # Sort by total bytes descending
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


@router.get("/analytics/diagnose")
async def diagnose_domain(
    domain: str = Query(..., min_length=1),
):
    """Diagnose why a domain was blocked. Checks allowlist, DNS, and recent logs."""
    # Check allowlist
    in_allowlist = False
    try:
        config_path = Path(CAGENT_CONFIG_PATH)
        if config_path.exists():
            config = yaml.safe_load(config_path.read_text()) or {}
            allowed_domains = [d.get("domain", "") for d in config.get("domains", [])]
            in_allowlist = domain in allowed_domains
    except Exception:
        pass

    # Check DNS resolution via CoreDNS
    dns_result = None
    try:
        container = docker_client.containers.get(COREDNS_CONTAINER_NAME)
        # Get CoreDNS IP from container networks
        dns_ip = "10.200.1.5"
        result = subprocess.run(
            ["docker", "exec", COREDNS_CONTAINER_NAME, "nslookup", domain, dns_ip],
            capture_output=True, text=True, timeout=5,
        )
        if "NXDOMAIN" in result.stdout or "NXDOMAIN" in result.stderr:
            dns_result = "NXDOMAIN"
        elif result.returncode == 0:
            # Extract first resolved address
            for line in result.stdout.split("\n"):
                line = line.strip()
                if line.startswith("Address") and ":" in line and dns_ip not in line:
                    dns_result = line.split(":")[-1].strip()
                    break
            if not dns_result:
                dns_result = "resolved"
        else:
            dns_result = "NXDOMAIN"
    except Exception:
        dns_result = "unknown"

    # Get recent log entries for this domain
    recent_requests = []
    try:
        raw = _get_envoy_logs(1)
        for entry in _parse_log_entries(raw):
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
        # Keep only last 5, most recent first
        recent_requests = recent_requests[-5:][::-1]
    except Exception:
        pass

    # Build human-readable diagnosis
    parts = []
    if in_allowlist:
        parts.append("Domain is in the allowlist.")
    else:
        parts.append("Domain is not in the allowlist.")

    if dns_result == "NXDOMAIN":
        parts.append("DNS returns NXDOMAIN (blocked by CoreDNS catch-all).")
    elif dns_result and dns_result != "unknown":
        parts.append(f"DNS resolves to {dns_result}.")

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
        "dns_result": dns_result,
        "recent_requests": recent_requests,
        "diagnosis": " ".join(parts),
    }
