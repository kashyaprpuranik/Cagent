"""Policy push/query endpoints for interactive mode.

The CP pushes updated domain policies via Cloudflare Tunnel.
Warden applies them by regenerating Envoy + CoreDNS configs.
"""

import logging
from pathlib import Path
from typing import Optional

import docker
import yaml
from config_generator import ConfigGenerator
from constants import CAGENT_CONFIG_PATH, COREDNS_COREFILE_PATH, ENVOY_CONFIG_PATH, docker_client
from fastapi import APIRouter, HTTPException

logger = logging.getLogger(__name__)

router = APIRouter()


@router.post("/policies/apply")
async def apply_policies(body: dict):
    """Apply updated domain policies.

    Accepts a list of domain policy objects, updates cagent.yaml,
    and regenerates Envoy + CoreDNS configs.
    """
    policies = body.get("policies", [])
    if not isinstance(policies, list):
        raise HTTPException(status_code=400, detail="policies must be a list")

    config_path = Path(CAGENT_CONFIG_PATH)
    try:
        config = yaml.safe_load(config_path.read_text()) or {}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to read config: {e}")

    # Convert CP domain policies to cagent.yaml domain format
    domains = []
    for p in policies:
        entry = {"domain": p["domain"]}
        if p.get("allowed_paths"):
            entry["allowed_paths"] = p["allowed_paths"]
        if p.get("requests_per_minute"):
            entry["rate_limit"] = {"requests_per_minute": p["requests_per_minute"]}
            if p.get("burst_size"):
                entry["rate_limit"]["burst_size"] = p["burst_size"]
        if p.get("read_only"):
            entry["read_only"] = True
        domains.append(entry)

    config["domains"] = domains

    try:
        config_path.write_text(yaml.dump(config, default_flow_style=False))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to write config: {e}")

    # Regenerate configs
    try:
        generator = ConfigGenerator(str(config_path))
        generator.generate_corefile(COREDNS_COREFILE_PATH)
        generator.generate_envoy_config(ENVOY_CONFIG_PATH)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Config generation failed: {e}")

    # Reload CoreDNS and Envoy
    _reload_service("dns-filter", "SIGUSR1")
    _reload_service("http-proxy", "SIGHUP")

    return {"status": "applied", "policy_count": len(domains)}


@router.get("/policies/active")
async def get_active_policies():
    """Get currently active domain policies from cagent.yaml."""
    config_path = Path(CAGENT_CONFIG_PATH)
    try:
        config = yaml.safe_load(config_path.read_text()) or {}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to read config: {e}")

    domains = config.get("domains", [])
    return {"policies": domains, "count": len(domains)}


def _reload_service(container_name: str, signal: str):
    """Send a signal to a container to trigger config reload."""
    try:
        container = docker_client.containers.get(container_name)
        container.kill(signal=signal)
        logger.info("Sent %s to %s", signal, container_name)
    except docker.errors.NotFound:
        logger.warning("Failed to reload %s: container not found", container_name)
    except docker.errors.APIError as e:
        logger.warning("Failed to reload %s: %s", container_name, e)
