from datetime import datetime
from pathlib import Path

import yaml
from fastapi import APIRouter, HTTPException

from constants import COREDNS_CONTAINER_NAME, ENVOY_CONTAINER_NAME, CAGENT_CONFIG_PATH, READ_ONLY, docker_client
from models import ConfigUpdate

router = APIRouter()


@router.get("/config")
async def get_config():
    """Get current cagent.yaml configuration."""
    config_path = Path(CAGENT_CONFIG_PATH)
    if not config_path.exists():
        raise HTTPException(404, f"Config file not found: {CAGENT_CONFIG_PATH}")

    content = config_path.read_text()
    config = yaml.safe_load(content)

    return {
        "config": config,
        "raw": content,
        "path": str(config_path),
        "modified": datetime.fromtimestamp(config_path.stat().st_mtime).isoformat(),
        "read_only": READ_ONLY,
    }


@router.put("/config")
async def update_config(update: ConfigUpdate):
    """Update cagent.yaml configuration."""
    if READ_ONLY:
        raise HTTPException(403, "Config is read-only in connected mode (managed by control plane)")
    config_path = Path(CAGENT_CONFIG_PATH)

    # Read current config
    if config_path.exists():
        current = yaml.safe_load(config_path.read_text())
    else:
        current = {}

    # Apply updates
    if update.domains is not None:
        current["domains"] = [d.model_dump(exclude_none=True) for d in update.domains]
    if update.dns is not None:
        current["dns"] = update.dns
    if update.rate_limits is not None:
        current["rate_limits"] = update.rate_limits
    if update.mode is not None:
        current["mode"] = update.mode
    if update.email is not None:
        current["email"] = update.email
    if update.security is not None:
        current["security"] = update.security

    # Write back
    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text(yaml.dump(current, default_flow_style=False, sort_keys=False))

    return {"status": "updated", "config": current}


@router.put("/config/raw")
async def update_config_raw(body: dict):
    """Update cagent.yaml with raw YAML content."""
    if READ_ONLY:
        raise HTTPException(403, "Config is read-only in connected mode (managed by control plane)")
    config_path = Path(CAGENT_CONFIG_PATH)
    content = body.get("content", "")

    # Validate YAML
    try:
        yaml.safe_load(content)
    except yaml.YAMLError as e:
        raise HTTPException(400, f"Invalid YAML: {e}")

    # Write
    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text(content)

    return {"status": "updated"}


@router.post("/config/reload")
async def reload_config():
    """Trigger config reload (regenerate CoreDNS + Envoy configs)."""
    if READ_ONLY:
        raise HTTPException(403, "Config reload is disabled in connected mode (managed by control plane)")
    # This would trigger warden to reload
    # For now, we restart the containers
    results = {}

    for name in [COREDNS_CONTAINER_NAME, ENVOY_CONTAINER_NAME]:
        try:
            container = docker_client.containers.get(name)
            container.restart(timeout=10)
            results[name] = "restarted"
        except docker.errors.NotFound:
            results[name] = "not_found"
        except Exception as e:
            results[name] = f"error: {e}"

    return {"status": "reload_triggered", "results": results}
