"""Domain policy endpoint.

Serves GET /api/v1/domain-policies/for-domain?domain=X so the ext_authz
endpoint can look up credential injection, rate limits, and path filtering
from a single local endpoint instead of reaching the control plane directly.

- Connected mode: forwards to CP, caches 5 minutes.
- Standalone mode: builds response from cagent.yaml config.
"""

import logging
import os
import time

import requests
import yaml
from fastapi import APIRouter, Query, Header
from pathlib import Path

from constants import (
    DATAPLANE_MODE,
    CONTROL_PLANE_URL,
    CONTROL_PLANE_TOKEN,
    CAGENT_CONFIG_PATH,
)

router = APIRouter()
logger = logging.getLogger(__name__)

# In-memory cache: domain -> {response, expires_at}
_policy_cache: dict = {}
_CACHE_TTL = 300  # 5 minutes


def _cache_get(domain: str):
    """Return cached policy if still valid, else None."""
    entry = _policy_cache.get(domain)
    if entry and entry["expires_at"] > time.monotonic():
        return entry["response"]
    return None


def _cache_set(domain: str, response: dict):
    """Cache a policy response."""
    _policy_cache[domain] = {
        "response": response,
        "expires_at": time.monotonic() + _CACHE_TTL,
    }


def invalidate_cache():
    """Clear the policy cache (called when config is regenerated)."""
    _policy_cache.clear()


def _build_standalone_policy(domain: str) -> dict:
    """Build a policy response from cagent.yaml for standalone mode."""
    config_path = Path(CAGENT_CONFIG_PATH)
    if not config_path.exists():
        return {"matched": False, "domain": domain}

    try:
        config = yaml.safe_load(config_path.read_text()) or {}
    except Exception:
        return {"matched": False, "domain": domain}

    domains = config.get("domains", [])
    default_rl = config.get("rate_limits", {}).get("default", {})
    default_rpm = default_rl.get("requests_per_minute", 120)
    default_burst = default_rl.get("burst_size", 20)

    domain_lower = domain.lower()

    # For devbox.local domains, resolve by alias name instead of domain
    alias_name = _resolve_devbox_alias(domain_lower)

    # Find matching domain entry (alias, exact, or wildcard)
    matched_entry = None
    for entry in domains:
        # Alias match: echo.devbox.local → entry with alias "echo"
        if alias_name and entry.get("alias", "").lower() == alias_name:
            matched_entry = entry
            break
        entry_domain = entry.get("domain", "").lower()
        if entry_domain == domain_lower:
            matched_entry = entry
            break
        if entry_domain.startswith("*."):
            suffix = entry_domain[1:]  # e.g. ".github.com"
            bare = entry_domain[2:]    # e.g. "github.com"
            if domain_lower == bare or (
                len(domain_lower) > len(suffix)
                and domain_lower.endswith(suffix)
            ):
                matched_entry = entry
                break

    if not matched_entry:
        return {"matched": False, "domain": domain_lower}

    # Build response
    rl = matched_entry.get("rate_limit", {})
    allowed_paths = matched_entry.get("allowed_paths", [])

    response = {
        "matched": True,
        "domain": matched_entry.get("domain", domain_lower),
        "allowed_paths": allowed_paths,
        "requests_per_minute": rl.get("requests_per_minute", default_rpm),
        "burst_size": rl.get("burst_size", default_burst),
    }

    # Resolve credential from env var
    cred = matched_entry.get("credential")
    if cred:
        env_var = cred.get("env", "")
        value = os.environ.get(env_var, "") if env_var else ""
        if value:
            header_format = cred.get("format", "{value}")
            response["header_name"] = cred.get("header", "Authorization")
            response["header_value"] = header_format.replace("{value}", value)
            response["target_domain"] = matched_entry.get("domain", domain_lower)

    # Include alias if present
    alias = matched_entry.get("alias")
    if alias:
        response["alias"] = alias

    return response


def _is_devbox_local(domain: str) -> bool:
    """Check if domain is a *.devbox.local alias."""
    return domain.endswith(".devbox.local")


def _resolve_devbox_alias(domain: str) -> str | None:
    """Extract alias name from X.devbox.local → X."""
    if not _is_devbox_local(domain):
        return None
    return domain.removesuffix(".devbox.local")


@router.get("/api/v1/domain-policies/for-domain")
async def get_domain_policy(
    domain: str = Query(..., min_length=1),
    authorization: str | None = Header(default=None),
):
    """Get domain policy for a given domain.

    devbox.local domains: always resolve locally from cagent.yaml
      (CP doesn't know about devbox.local aliases).
    Connected mode: proxy to control plane (cached 5 min).
    Standalone mode: build from cagent.yaml.

    Authenticated requests (with CONTROL_PLANE_TOKEN) receive full policies.
    Unauthenticated requests receive policies with sensitive fields redacted.
    """
    domain_lower = domain.lower()

    # Helper to fetch policy (cached or fresh)
    policy = _cache_get(domain_lower)

    if policy is None:
        # devbox.local aliases are always resolved locally — the CP doesn't
        # know about them since they're a data-plane convenience for HTTP
        # credential injection.
        if _is_devbox_local(domain_lower):
            policy = _build_standalone_policy(domain_lower)
            _cache_set(domain_lower, policy)

        elif DATAPLANE_MODE == "connected" and CONTROL_PLANE_URL and CONTROL_PLANE_TOKEN:
            # Forward to control plane
            try:
                resp = requests.get(
                    f"{CONTROL_PLANE_URL}/api/v1/domain-policies/for-domain",
                    params={"domain": domain_lower},
                    headers={"Authorization": f"Bearer {CONTROL_PLANE_TOKEN}"},
                    timeout=5,
                )
                if resp.status_code == 200:
                    policy = resp.json()
                    _cache_set(domain_lower, policy)
                else:
                    logger.warning(
                        f"CP domain-policy lookup failed: {resp.status_code}, "
                        f"falling back to cagent.yaml"
                    )
                    # Fallback
                    policy = _build_standalone_policy(domain_lower)
                    _cache_set(domain_lower, policy)
            except requests.exceptions.RequestException as e:
                logger.warning(f"CP unreachable for domain-policy: {e}, falling back to cagent.yaml")
                # Fallback
                policy = _build_standalone_policy(domain_lower)
                _cache_set(domain_lower, policy)
        else:
            # Standalone mode or CP fallback
            policy = _build_standalone_policy(domain_lower)
            _cache_set(domain_lower, policy)

    if not policy:
        return {"matched": False, "domain": domain_lower}

    # Authentication check
    is_authenticated = False
    if CONTROL_PLANE_TOKEN and authorization:
        if authorization == f"Bearer {CONTROL_PLANE_TOKEN}":
            is_authenticated = True

    # Redaction for unauthenticated requests
    if not is_authenticated:
        # Create a shallow copy to avoid modifying the cached dictionary
        policy = policy.copy()
        policy.pop("header_name", None)
        policy.pop("header_value", None)
        policy.pop("target_domain", None)

    return policy
