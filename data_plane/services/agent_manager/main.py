"""
Agent Manager - Polls control plane for commands, manages agent containers.

Runs as a background service that:
1. Discovers agent containers by Docker label (cagent.role=agent)
2. Sends heartbeat to control plane every 30s per agent with status
3. Receives any pending commands (wipe, restart, stop, start)
4. Executes commands and reports results on next heartbeat
5. Syncs config from control plane OR generates from cagent.yaml
6. Regenerates CoreDNS and Envoy configs when allowlist changes

All agent containers share the same policy, DNS filter, and HTTP proxy.

Modes:
- standalone: Uses cagent.yaml as single source of truth
- connected: Syncs from control plane, uses cagent.yaml as fallback

No inbound ports required - only outbound to control plane.
"""

import os
import sys
import time
import json
import hashlib
import signal
import logging
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import Optional, List
from pathlib import Path

import docker
import requests
import yaml

from config_generator import ConfigGenerator

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Configuration
DATAPLANE_MODE = os.environ.get("DATAPLANE_MODE", "standalone")  # 'standalone' or 'connected'
CONTROL_PLANE_URL = os.environ.get("CONTROL_PLANE_URL", "http://backend:8000")
CONTROL_PLANE_TOKEN = os.environ.get("CONTROL_PLANE_TOKEN", "")
HEARTBEAT_INTERVAL = int(os.environ.get("HEARTBEAT_INTERVAL", "30"))

# Agent discovery: label-based with fallback to fixed name
AGENT_LABEL = "cagent.role=agent"
AGENT_CONTAINER_FALLBACK = "agent"

# Config paths
CAGENT_CONFIG_PATH = os.environ.get("CAGENT_CONFIG_PATH", "/etc/cagent/cagent.yaml")
COREDNS_COREFILE_PATH = os.environ.get("COREDNS_COREFILE_PATH", "/etc/coredns/Corefile")
ENVOY_CONFIG_PATH = os.environ.get("ENVOY_CONFIG_PATH", "/etc/envoy/envoy.yaml")
ENVOY_LUA_PATH = os.environ.get("ENVOY_LUA_PATH", "/etc/envoy/filter.lua")

# Sync configuration
CONFIG_SYNC_INTERVAL = int(os.environ.get("CONFIG_SYNC_INTERVAL", "300"))  # 5 minutes
MAX_HEARTBEAT_WORKERS = int(os.environ.get("HEARTBEAT_MAX_WORKERS", "20"))

# Config generator instance
config_generator = ConfigGenerator(CAGENT_CONFIG_PATH)

# Docker client
docker_client = docker.from_env()

# Thread-safe command result tracking (written from ThreadPoolExecutor workers,
# read from the heartbeat sender on the next cycle).
_command_results_lock = threading.Lock()
_last_command_results: dict = {}


# ---------------------------------------------------------------------------
# Container discovery
# ---------------------------------------------------------------------------

def discover_agent_containers() -> List:
    """Discover agent containers by the ``cagent.role=agent`` label.

    Falls back to looking up a container named ``agent`` when no labelled
    containers are found (backward compat with unlabelled setups).
    """
    try:
        containers = docker_client.containers.list(
            all=True,
            filters={"label": AGENT_LABEL},
        )
        if containers:
            return containers
    except docker.errors.APIError as e:
        logger.warning(f"Label-based discovery failed: {e}")

    # Fallback: try the fixed name
    try:
        container = docker_client.containers.get(AGENT_CONTAINER_FALLBACK)
        return [container]
    except docker.errors.NotFound:
        return []
    except docker.errors.APIError as e:
        logger.error(f"Docker API error during fallback discovery: {e}")
        return []


def _workspace_volume_for(container) -> Optional[str]:
    """Derive the workspace volume name for a container from its mounts."""
    for mount in container.attrs.get("Mounts", []):
        if mount.get("Destination") == "/workspace":
            return mount.get("Name")
    return None


# ---------------------------------------------------------------------------
# Status helpers
# ---------------------------------------------------------------------------

def get_container_status(container) -> dict:
    """Get status metrics for a single agent container."""
    try:
        container.reload()
    except docker.errors.APIError as e:
        logger.error(f"Docker API error reloading {container.name}: {e}")
        return {
            "status": "error",
            "container_id": None,
            "uptime_seconds": None,
            "cpu_percent": None,
            "memory_mb": None,
            "memory_limit_mb": None,
        }

    # Calculate uptime
    uptime_seconds = None
    if container.status == "running":
        started_at = container.attrs["State"]["StartedAt"]
        try:
            start_time = datetime.fromisoformat(started_at.replace("Z", "+00:00"))
            uptime_seconds = int((datetime.now(start_time.tzinfo) - start_time).total_seconds())
        except Exception:
            pass

    # Get resource stats
    cpu_percent = None
    memory_mb = None
    memory_limit_mb = None

    if container.status == "running":
        try:
            stats = container.stats(stream=False)

            # CPU calculation
            cpu_delta = stats["cpu_stats"]["cpu_usage"]["total_usage"] - \
                       stats["precpu_stats"]["cpu_usage"]["total_usage"]
            system_delta = stats["cpu_stats"]["system_cpu_usage"] - \
                          stats["precpu_stats"]["system_cpu_usage"]
            num_cpus = stats["cpu_stats"].get("online_cpus", 1)

            if system_delta > 0:
                cpu_percent = round((cpu_delta / system_delta) * num_cpus * 100, 2)

            # Memory calculation
            memory_usage = stats["memory_stats"].get("usage", 0)
            memory_limit = stats["memory_stats"].get("limit", 0)
            memory_mb = round(memory_usage / (1024 * 1024), 2)
            memory_limit_mb = round(memory_limit / (1024 * 1024), 2)

        except Exception as e:
            logger.warning(f"Could not get container stats for {container.name}: {e}")

    return {
        "status": container.status,
        "container_id": container.short_id,
        "uptime_seconds": uptime_seconds,
        "cpu_percent": cpu_percent,
        "memory_mb": memory_mb,
        "memory_limit_mb": memory_limit_mb,
    }


# ---------------------------------------------------------------------------
# Command execution
# ---------------------------------------------------------------------------

def execute_command(command: str, container, args: Optional[dict] = None) -> tuple:
    """Execute a command on a specific agent container.

    Returns (success: bool, message: str).
    """
    name = container.name
    logger.info(f"Executing command: {command} on {name} with args: {args}")

    try:
        if command == "restart":
            container.restart(timeout=10)
            return True, f"Agent container {name} restarted"

        elif command == "stop":
            container.stop(timeout=10)
            return True, f"Agent container {name} stopped"

        elif command == "start":
            container.start()
            return True, f"Agent container {name} started"

        elif command == "wipe":
            wipe_workspace = args.get("wipe_workspace", False) if args else False

            # Stop and remove container
            if container.status == "running":
                container.stop(timeout=10)
            container.remove(force=True)

            # Optionally wipe workspace
            if wipe_workspace:
                volume_name = _workspace_volume_for(container)
                if volume_name:
                    try:
                        docker_client.containers.run(
                            "alpine:latest",
                            command="rm -rf /workspace/*",
                            volumes={volume_name: {"bind": "/workspace", "mode": "rw"}},
                            remove=True,
                        )
                        logger.info(f"Cleared workspace volume {volume_name}")
                    except Exception as e:
                        logger.warning(f"Could not wipe workspace for {name}: {e}")

            return True, f"Agent {name} wiped (workspace={'wiped' if wipe_workspace else 'preserved'})"

        else:
            return False, f"Unknown command: {command}"

    except docker.errors.APIError as e:
        logger.error(f"Docker API error executing {command} on {name}: {e}")
        return False, str(e)
    except Exception as e:
        logger.error(f"Error executing {command} on {name}: {e}")
        return False, str(e)


# ---------------------------------------------------------------------------
# Infrastructure restarts (shared across all agents)
# ---------------------------------------------------------------------------

COREDNS_CONTAINER_NAME = "dns-filter"
ENVOY_CONTAINER_NAME = "http-proxy"


def restart_coredns():
    """Restart CoreDNS container to pick up new config."""
    try:
        container = docker_client.containers.get(COREDNS_CONTAINER_NAME)
        container.restart(timeout=10)
        logger.info("Restarted CoreDNS to apply new config")
        return True
    except docker.errors.NotFound:
        logger.warning(f"CoreDNS container '{COREDNS_CONTAINER_NAME}' not found")
        return False
    except Exception as e:
        logger.error(f"Failed to restart CoreDNS: {e}")
        return False


def reload_envoy():
    """Reload Envoy by restarting the container."""
    try:
        container = docker_client.containers.get(ENVOY_CONTAINER_NAME)
        container.restart(timeout=5)
        logger.info("Restarted Envoy to apply new config")
        return True
    except docker.errors.NotFound:
        logger.warning(f"Envoy container '{ENVOY_CONTAINER_NAME}' not found")
        return False
    except Exception as e:
        logger.error(f"Failed to restart Envoy: {e}")
        return False


# ---------------------------------------------------------------------------
# Config generation (shared — same Corefile / Envoy config for all agents)
# ---------------------------------------------------------------------------

def _stable_hash(content: str) -> str:
    """Hash content after stripping auto-generated timestamp lines."""
    stable = "\n".join(
        line for line in content.splitlines()
        if "Generated:" not in line
    )
    return hashlib.md5(stable.encode()).hexdigest()


class _ConfigState:
    """Track last-written config hashes to avoid unnecessary restarts.

    Encapsulated in a class instead of bare module globals so there is a
    single, obvious mutation point and no ``global`` statements needed.
    """
    def __init__(self):
        self.envoy_hash: Optional[str] = None
        self.corefile_hash: Optional[str] = None
        self.lua_hash: Optional[str] = None

_config_state = _ConfigState()


def regenerate_configs(additional_domains: list = None) -> bool:
    """Regenerate CoreDNS, Envoy, and Lua filter configs from cagent.yaml.

    Args:
        additional_domains: Extra domains to merge (e.g., from control plane sync)

    Returns:
        True if configs were regenerated, False otherwise.
    """
    try:
        config_changed = config_generator.load_config()

        if not config_changed and not additional_domains:
            logger.debug("Config unchanged, skipping regeneration")
            return False

        # Generate configs and compute stable hashes (ignoring timestamps)
        corefile_content = config_generator.generate_corefile()
        envoy_config = config_generator.generate_envoy_config()
        envoy_yaml = yaml.dump(envoy_config, default_flow_style=False, sort_keys=False)
        lua_content = config_generator.generate_lua_filter()

        corefile_hash = _stable_hash(corefile_content)
        envoy_hash = _stable_hash(envoy_yaml)
        lua_hash = _stable_hash(lua_content)

        corefile_changed = corefile_hash != _config_state.corefile_hash
        envoy_changed = envoy_hash != _config_state.envoy_hash
        lua_changed = lua_hash != _config_state.lua_hash

        if corefile_changed:
            config_generator.write_corefile(COREDNS_COREFILE_PATH)
            restart_coredns()
            _config_state.corefile_hash = corefile_hash

        if envoy_changed or lua_changed:
            if envoy_changed:
                config_generator.write_envoy_config(ENVOY_CONFIG_PATH)
            if lua_changed:
                config_generator.write_lua_filter(ENVOY_LUA_PATH)
            reload_envoy()
            _config_state.envoy_hash = envoy_hash
            _config_state.lua_hash = lua_hash

        if corefile_changed or envoy_changed or lua_changed:
            logger.info("Regenerated configs from cagent.yaml")
            return True
        else:
            logger.debug("Generated configs unchanged, skipping restart")
            return False

    except Exception as e:
        logger.error(f"Error regenerating configs: {e}")
        return False


def sync_config() -> bool:
    """Sync configuration and regenerate CoreDNS + Envoy configs.

    In standalone mode: regenerates from cagent.yaml only
    In connected mode: fetches domain policies from CP, merges with cagent.yaml

    Returns True if configs were updated, False otherwise.
    """
    if DATAPLANE_MODE == "standalone":
        # Standalone mode: just use cagent.yaml
        return regenerate_configs()

    # Connected mode: fetch from control plane and merge
    if not CONTROL_PLANE_URL or not CONTROL_PLANE_TOKEN:
        logger.warning("Control plane not configured, falling back to cagent.yaml")
        return regenerate_configs()

    try:
        # Fetch domain policies from control plane
        response = requests.get(
            f"{CONTROL_PLANE_URL}/api/v1/domain-policies",
            headers={"Authorization": f"Bearer {CONTROL_PLANE_TOKEN}"},
            timeout=10
        )

        if response.status_code != 200:
            logger.warning(f"Failed to fetch domain policies: {response.status_code}, using cagent.yaml")
            return regenerate_configs()

        # Parse domain policies
        policies = response.json()
        cp_domains = [p["domain"] for p in policies if p.get("enabled", True)]

        logger.info(f"Fetched {len(cp_domains)} domain policies from control plane")

        # Regenerate configs (cagent.yaml is still the primary source)
        return regenerate_configs(additional_domains=cp_domains)

    except requests.exceptions.RequestException as e:
        logger.warning(f"Could not reach control plane: {e}, using cagent.yaml")
        return regenerate_configs()
    except Exception as e:
        logger.error(f"Error syncing config: {e}")
        return False


# ---------------------------------------------------------------------------
# Heartbeat
# ---------------------------------------------------------------------------

def send_heartbeat(container) -> Optional[dict]:
    """Send heartbeat for a single agent container to control plane.

    Returns the parsed response (may contain a pending command), or None.
    """
    if not CONTROL_PLANE_URL or not CONTROL_PLANE_TOKEN:
        logger.warning("Control plane URL or token not configured, skipping heartbeat")
        return None

    name = container.name
    status = get_container_status(container)

    heartbeat = {
        "status": status["status"],
        "container_id": status["container_id"],
        "uptime_seconds": status["uptime_seconds"],
        "cpu_percent": status["cpu_percent"],
        "memory_mb": status["memory_mb"],
        "memory_limit_mb": status["memory_limit_mb"],
    }

    # Include last command result for this container if any
    with _command_results_lock:
        last_result = _last_command_results.get(name)
        if last_result and last_result["command"]:
            heartbeat["last_command"] = last_result["command"]
            heartbeat["last_command_result"] = last_result["result"]
            heartbeat["last_command_message"] = last_result["message"]
            # Clear after sending
            _last_command_results[name] = {"command": None, "result": None, "message": None}

    try:
        response = requests.post(
            f"{CONTROL_PLANE_URL}/api/v1/agent/heartbeat",
            json=heartbeat,
            headers={"Authorization": f"Bearer {CONTROL_PLANE_TOKEN}"},
            timeout=10,
        )

        if response.status_code == 200:
            return response.json()
        elif response.status_code in (401, 403):
            logger.error(f"Authentication failed: {response.status_code}")
            return None
        else:
            logger.warning(f"Heartbeat for {name} failed: {response.status_code} - {response.text}")
            return None

    except requests.exceptions.RequestException as e:
        logger.warning(f"Could not reach control plane: {e}")
        return None


# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------

def _heartbeat_and_handle(container):
    """Send heartbeat for one container and execute any pending command.

    Runs inside a ThreadPoolExecutor — must be thread-safe.
    """
    response = send_heartbeat(container)
    if response and response.get("command"):
        command = response["command"]
        cmd_args = response.get("command_args")
        logger.info(f"Received command for {container.name}: {command}")
        success, message = execute_command(command, container, cmd_args)
        with _command_results_lock:
            _last_command_results[container.name] = {
                "command": command,
                "result": "success" if success else "failed",
                "message": message,
            }
        logger.info(
            f"Command {command} on {container.name} "
            f"{'succeeded' if success else 'failed'}: {message}"
        )


def main_loop():
    """Main loop: discover agents, send heartbeats, execute commands, sync config."""
    logger.info("Agent manager starting")
    logger.info(f"  Mode: {DATAPLANE_MODE}")
    logger.info(f"  Config file: {CAGENT_CONFIG_PATH}")
    logger.info(f"  CoreDNS config: {COREDNS_COREFILE_PATH}")
    logger.info(f"  Envoy config: {ENVOY_CONFIG_PATH}")
    logger.info(f"  Envoy Lua filter: {ENVOY_LUA_PATH}")
    logger.info(f"  Agent discovery label: {AGENT_LABEL}")
    logger.info(f"  Config sync interval: {CONFIG_SYNC_INTERVAL}s")

    if DATAPLANE_MODE == "connected":
        logger.info(f"  Control plane: {CONTROL_PLANE_URL}")
        logger.info(f"  Heartbeat interval: {HEARTBEAT_INTERVAL}s")
        if not CONTROL_PLANE_TOKEN:
            logger.warning("CONTROL_PLANE_TOKEN not set - heartbeats will fail")
    else:
        logger.info("  Running in standalone mode (no control plane sync)")

    # Log initially discovered agents
    agents = discover_agent_containers()
    logger.info(f"  Discovered {len(agents)} agent container(s): {[c.name for c in agents]}")

    # Initial config generation from cagent.yaml (always write on startup)
    logger.info("Generating initial configs from cagent.yaml...")
    config_generator.load_config()
    config_generator.write_corefile(COREDNS_COREFILE_PATH)
    config_generator.write_envoy_config(ENVOY_CONFIG_PATH)
    config_generator.write_lua_filter(ENVOY_LUA_PATH)
    restart_coredns()
    reload_envoy()
    # Snapshot current state so regenerate_configs() can detect changes
    _config_state.corefile_hash = _stable_hash(config_generator.generate_corefile())
    _config_state.envoy_hash = _stable_hash(
        yaml.dump(config_generator.generate_envoy_config(), default_flow_style=False, sort_keys=False)
    )
    _config_state.lua_hash = _stable_hash(config_generator.generate_lua_filter())
    logger.info("Initial config generation complete")

    # Use wall-clock monotonic time for config sync scheduling so that
    # slow heartbeat cycles (e.g. Docker stats across many containers)
    # don't cause sync drift.
    last_sync_time = time.monotonic()

    while True:
        try:
            # Discover agent containers each cycle (handles containers
            # being added/removed at runtime)
            agents = discover_agent_containers()

            # In connected mode, send heartbeat and handle commands per agent (concurrent)
            if DATAPLANE_MODE == "connected" and CONTROL_PLANE_TOKEN:
                workers = min(MAX_HEARTBEAT_WORKERS, len(agents)) if agents else 1
                with ThreadPoolExecutor(max_workers=workers) as executor:
                    futures = {executor.submit(_heartbeat_and_handle, c): c for c in agents}
                    for f in as_completed(futures):
                        try:
                            f.result()
                        except Exception as exc:
                            container = futures[f]
                            logger.error(f"Heartbeat failed for {container.name}: {exc}")

            # Sync config periodically (wall-clock, not heartbeat-count)
            now = time.monotonic()
            if (now - last_sync_time) >= CONFIG_SYNC_INTERVAL:
                sync_config()
                last_sync_time = now

        except Exception as e:
            logger.error(f"Error in main loop: {e}")

        # Wait for next cycle
        time.sleep(HEARTBEAT_INTERVAL)


if __name__ == "__main__":
    try:
        # Verify Docker connection
        docker_client.ping()
        logger.info("Docker connection verified")
    except Exception as e:
        logger.error(f"Cannot connect to Docker: {e}")
        sys.exit(1)

    main_loop()
