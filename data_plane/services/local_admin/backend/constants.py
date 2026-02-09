import os

import docker

AGENT_CONTAINER_NAME = "agent"
COREDNS_CONTAINER_NAME = "dns-filter"
ENVOY_CONTAINER_NAME = "envoy-proxy"
FRPC_CONTAINER_NAME = "frpc"
CAGENT_CONFIG_PATH = os.environ.get("CAGENT_CONFIG_PATH", "/etc/cagent/cagent.yaml")
DATA_PLANE_DIR = os.environ.get("DATA_PLANE_DIR", "/app/data_plane")

docker_client = docker.from_env()

MANAGED_CONTAINERS = [AGENT_CONTAINER_NAME, COREDNS_CONTAINER_NAME, ENVOY_CONTAINER_NAME]
