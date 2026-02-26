"""Client for querying the local OpenObserve instance.

Used by warden analytics and log search endpoints when OO is running
on the data plane (auditing profile enabled).
"""

import logging
from datetime import datetime, timezone

import requests
from constants import OPENOBSERVE_PASSWORD, OPENOBSERVE_URL, OPENOBSERVE_USER

logger = logging.getLogger(__name__)

_STREAM = "cagent_logs"
_ORG = "default"


def is_openobserve_healthy() -> bool:
    """Check if the local OpenObserve instance is reachable."""
    try:
        resp = requests.get(f"{OPENOBSERVE_URL}/healthz", timeout=3)
        return resp.status_code == 200
    except requests.exceptions.RequestException:
        return False


def query_openobserve(sql: str, start_us: int, end_us: int) -> list[dict]:
    """Execute a SQL query against the local OpenObserve instance.

    Args:
        sql: SQL query string (e.g., "SELECT * FROM \"cagent-logs\" LIMIT 100")
        start_us: Start time in microseconds since epoch.
        end_us: End time in microseconds since epoch.

    Returns:
        List of hit dicts from the OO response.
    """
    url = f"{OPENOBSERVE_URL}/api/{_ORG}/_search"
    payload = {
        "query": {
            "sql": sql,
            "start_time": start_us,
            "end_time": end_us,
        },
    }
    try:
        resp = requests.post(
            url,
            json=payload,
            auth=(OPENOBSERVE_USER, OPENOBSERVE_PASSWORD),
            timeout=10,
        )
        if resp.status_code != 200:
            logger.warning("OO query failed: %s %s", resp.status_code, resp.text[:200])
            return []
        data = resp.json()
        return data.get("hits", [])
    except requests.exceptions.RequestException as e:
        logger.warning("OO query error: %s", e)
        return []


def datetime_to_us(dt: datetime) -> int:
    """Convert a datetime to microseconds since epoch."""
    return int(dt.timestamp() * 1_000_000)


def now_us() -> int:
    """Current time in microseconds since epoch."""
    return datetime_to_us(datetime.now(timezone.utc))
