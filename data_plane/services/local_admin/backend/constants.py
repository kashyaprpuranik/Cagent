import os
from typing import List

import docker

# Agent discovery: label-based with fallback to fixed name
AGENT_LABEL = "cagent.role=agent"
AGENT_CONTAINER_FALLBACK = "agent"

COREDNS_CONTAINER_NAME = "dns-filter"
ENVOY_CONTAINER_NAME = "http-proxy"
EMAIL_PROXY_CONTAINER_NAME = "email-proxy"
FRPC_CONTAINER_NAME = "tunnel-client"
CAGENT_CONFIG_PATH = os.environ.get("CAGENT_CONFIG_PATH", "/etc/cagent/cagent.yaml")
DATA_PLANE_DIR = os.environ.get("DATA_PLANE_DIR", "/app/data_plane")
DATAPLANE_MODE = os.environ.get("DATAPLANE_MODE", "standalone")

# Read-only mode: when connected to control plane, local admin should not modify config
READ_ONLY = DATAPLANE_MODE == "connected"

docker_client = docker.from_env()

BETA_FEATURES = set(
    f.strip() for f in os.environ.get('BETA_FEATURES', '').split(',') if f.strip()
)


def discover_agent_container_names() -> List[str]:
    """Return names of agent containers discovered by label.

    Falls back to the fixed name ``agent`` when no labelled containers exist.
    """
    try:
        containers = docker_client.containers.list(
            all=True,
            filters={"label": AGENT_LABEL},
        )
        if containers:
            return [c.name for c in containers]
    except Exception:
        pass
    return [AGENT_CONTAINER_FALLBACK]


def get_managed_containers() -> List[str]:
    """Build the managed-container list dynamically.

    Agent containers are discovered by label; infrastructure containers are
    static.
    """
    names = discover_agent_container_names()
    names.extend([COREDNS_CONTAINER_NAME, ENVOY_CONTAINER_NAME])
    if "email" in BETA_FEATURES:
        names.append(EMAIL_PROXY_CONTAINER_NAME)
    return names


# Backward-compat alias used by the detailed health and container routers.
# Import sites that previously used ``MANAGED_CONTAINERS`` now get a list
# that is evaluated at import time.  For truly dynamic discovery (containers
# added while the process is running), callers can use
# ``get_managed_containers()`` directly.
AGENT_CONTAINER_NAME = discover_agent_container_names()[0]
MANAGED_CONTAINERS = get_managed_containers()
