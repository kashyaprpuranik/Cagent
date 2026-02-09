"""
Agent Manager - Polls control plane for commands, manages agent container.

Runs as a background service that:
1. Sends heartbeat to control plane every 30s with agent status
2. Receives any pending commands (wipe, restart, stop, start)
3. Executes commands and reports results on next heartbeat
4. Syncs config from control plane OR generates from cagent.yaml
5. Regenerates CoreDNS and Envoy configs when allowlist changes

Modes:
- standalone: Uses cagent.yaml as single source of truth
- connected: Syncs from control plane, uses cagent.yaml as fallback

No inbound ports required - only outbound to control plane.
"""

import os
import sys
import time
import json
import signal
import logging
from datetime import datetime
from typing import Optional
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
CONTROL_PLANE_URL = os.environ.get("CONTROL_PLANE_URL", "http://control-plane-api:8000")
CONTROL_PLANE_TOKEN = os.environ.get("CONTROL_PLANE_TOKEN", "")
AGENT_CONTAINER_NAME = "agent"
AGENT_WORKSPACE_VOLUME = "data_plane_agent-workspace"
HEARTBEAT_INTERVAL = int(os.environ.get("HEARTBEAT_INTERVAL", "30"))

# Config paths
CAGENT_CONFIG_PATH = os.environ.get("CAGENT_CONFIG_PATH", "/etc/cagent/cagent.yaml")
COREDNS_COREFILE_PATH = os.environ.get("COREDNS_COREFILE_PATH", "/etc/coredns/Corefile")
ENVOY_CONFIG_PATH = os.environ.get("ENVOY_CONFIG_PATH", "/etc/envoy/envoy.yaml")

# Sync configuration
CONFIG_SYNC_INTERVAL = int(os.environ.get("CONFIG_SYNC_INTERVAL", "300"))  # 5 minutes

# Config generator instance
config_generator = ConfigGenerator(CAGENT_CONFIG_PATH)

# Docker client
docker_client = docker.from_env()

# Track last command result to report on next heartbeat
last_command_result = {
    "command": None,
    "result": None,
    "message": None
}


def get_agent_container():
    """Get the agent container by name."""
    try:
        return docker_client.containers.get(AGENT_CONTAINER_NAME)
    except docker.errors.NotFound:
        return None
    except docker.errors.APIError as e:
        logger.error(f"Docker API error: {e}")
        return None


def get_agent_status() -> dict:
    """Get current agent container status."""
    container = get_agent_container()

    if not container:
        return {
            "status": "not_found",
            "container_id": None,
            "uptime_seconds": None,
            "cpu_percent": None,
            "memory_mb": None,
            "memory_limit_mb": None
        }

    container.reload()

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
            logger.warning(f"Could not get container stats: {e}")

    return {
        "status": container.status,
        "container_id": container.short_id,
        "uptime_seconds": uptime_seconds,
        "cpu_percent": cpu_percent,
        "memory_mb": memory_mb,
        "memory_limit_mb": memory_limit_mb
    }


def execute_command(command: str, args: Optional[dict] = None) -> tuple:
    """Execute a command and return (success, message)."""
    global last_command_result

    logger.info(f"Executing command: {command} with args: {args}")

    try:
        if command == "restart":
            container = get_agent_container()
            if not container:
                return False, "Agent container not found"
            container.restart(timeout=10)
            return True, "Agent container restarted"

        elif command == "stop":
            container = get_agent_container()
            if not container:
                return False, "Agent container not found"
            container.stop(timeout=10)
            return True, "Agent container stopped"

        elif command == "start":
            container = get_agent_container()
            if not container:
                return False, "Agent container not found"
            container.start()
            return True, "Agent container started"

        elif command == "wipe":
            container = get_agent_container()
            if not container:
                return False, "Agent container not found"

            wipe_workspace = args.get("wipe_workspace", False) if args else False

            # Stop and remove container
            if container.status == "running":
                container.stop(timeout=10)
            container.remove(force=True)

            # Optionally wipe workspace
            if wipe_workspace:
                try:
                    docker_client.containers.run(
                        "alpine:latest",
                        command="rm -rf /workspace/*",
                        volumes={AGENT_WORKSPACE_VOLUME: {"bind": "/workspace", "mode": "rw"}},
                        remove=True
                    )
                    logger.info(f"Cleared workspace volume {AGENT_WORKSPACE_VOLUME}")
                except Exception as e:
                    logger.warning(f"Could not wipe workspace: {e}")

            return True, f"Agent wiped (workspace={'wiped' if wipe_workspace else 'preserved'})"

        else:
            return False, f"Unknown command: {command}"

    except docker.errors.APIError as e:
        logger.error(f"Docker API error executing {command}: {e}")
        return False, str(e)
    except Exception as e:
        logger.error(f"Error executing {command}: {e}")
        return False, str(e)


COREDNS_CONTAINER_NAME = "dns-filter"
ENVOY_CONTAINER_NAME = "envoy-proxy"


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
    """Hot-reload Envoy config via SIGHUP or restart."""
    try:
        container = docker_client.containers.get(ENVOY_CONTAINER_NAME)
        # Send SIGHUP to trigger config reload (if Envoy supports it)
        # Otherwise restart the container
        container.kill(signal='SIGHUP')
        logger.info("Sent SIGHUP to Envoy for config reload")
        return True
    except docker.errors.NotFound:
        logger.warning(f"Envoy container '{ENVOY_CONTAINER_NAME}' not found")
        return False
    except Exception as e:
        # SIGHUP might not be supported, try restart
        try:
            container = docker_client.containers.get(ENVOY_CONTAINER_NAME)
            container.restart(timeout=10)
            logger.info("Restarted Envoy to apply new config")
            return True
        except Exception as e2:
            logger.error(f"Failed to reload Envoy: {e2}")
            return False


def regenerate_configs(additional_domains: list = None) -> bool:
    """Regenerate CoreDNS and Envoy configs from cagent.yaml.

    Args:
        additional_domains: Extra domains to merge (e.g., from control plane sync)

    Returns:
        True if configs were regenerated, False otherwise.
    """
    try:
        # Load config from cagent.yaml
        if not config_generator.load_config():
            # Config hasn't changed and no additional domains
            if not additional_domains:
                logger.debug("Config unchanged, skipping regeneration")
                return False

        # TODO: If additional_domains provided, merge them into config
        # For now, just regenerate from cagent.yaml

        # Generate CoreDNS Corefile
        config_generator.write_corefile(COREDNS_COREFILE_PATH)

        # Generate Envoy config
        config_generator.write_envoy_config(ENVOY_CONFIG_PATH)

        # Reload services
        restart_coredns()
        reload_envoy()

        logger.info("Regenerated configs from cagent.yaml")
        return True

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


def send_heartbeat() -> Optional[dict]:
    """Send heartbeat to control plane, return any pending command."""
    global last_command_result

    if not CONTROL_PLANE_URL or not CONTROL_PLANE_TOKEN:
        logger.warning("Control plane URL or token not configured, skipping heartbeat")
        return None

    status = get_agent_status()

    heartbeat = {
        "status": status["status"],
        "container_id": status["container_id"],
        "uptime_seconds": status["uptime_seconds"],
        "cpu_percent": status["cpu_percent"],
        "memory_mb": status["memory_mb"],
        "memory_limit_mb": status["memory_limit_mb"],
    }

    # Include last command result if any
    if last_command_result["command"]:
        heartbeat["last_command"] = last_command_result["command"]
        heartbeat["last_command_result"] = last_command_result["result"]
        heartbeat["last_command_message"] = last_command_result["message"]
        # Clear after sending
        last_command_result = {"command": None, "result": None, "message": None}

    try:
        response = requests.post(
            f"{CONTROL_PLANE_URL}/api/v1/agent/heartbeat",
            json=heartbeat,
            headers={"Authorization": f"Bearer {CONTROL_PLANE_TOKEN}"},
            timeout=10
        )

        if response.status_code == 200:
            return response.json()
        elif response.status_code == 401 or response.status_code == 403:
            logger.error(f"Authentication failed: {response.status_code}")
            return None
        else:
            logger.warning(f"Heartbeat failed: {response.status_code} - {response.text}")
            return None

    except requests.exceptions.RequestException as e:
        logger.warning(f"Could not reach control plane: {e}")
        return None


def main_loop():
    """Main loop: send heartbeat, execute commands, sync config."""
    global last_command_result

    logger.info("Agent manager starting")
    logger.info(f"  Mode: {DATAPLANE_MODE}")
    logger.info(f"  Config file: {CAGENT_CONFIG_PATH}")
    logger.info(f"  CoreDNS config: {COREDNS_COREFILE_PATH}")
    logger.info(f"  Envoy config: {ENVOY_CONFIG_PATH}")
    logger.info(f"  Agent container: {AGENT_CONTAINER_NAME}")
    logger.info(f"  Config sync interval: {CONFIG_SYNC_INTERVAL}s")

    if DATAPLANE_MODE == "connected":
        logger.info(f"  Control plane: {CONTROL_PLANE_URL}")
        logger.info(f"  Heartbeat interval: {HEARTBEAT_INTERVAL}s")
        if not CONTROL_PLANE_TOKEN:
            logger.warning("CONTROL_PLANE_TOKEN not set - heartbeats will fail")
    else:
        logger.info("  Running in standalone mode (no control plane sync)")

    # Track time since last config sync
    heartbeat_count = 0

    # Initial config generation from cagent.yaml
    logger.info("Generating initial configs from cagent.yaml...")
    config_generator.load_config()
    regenerate_configs()

    while True:
        try:
            # In connected mode, send heartbeat and handle commands
            if DATAPLANE_MODE == "connected" and CONTROL_PLANE_TOKEN:
                response = send_heartbeat()

                if response and response.get("command"):
                    command = response["command"]
                    args = response.get("command_args")

                    logger.info(f"Received command: {command}")

                    # Execute the command
                    success, message = execute_command(command, args)

                    # Store result to report on next heartbeat
                    last_command_result = {
                        "command": command,
                        "result": "success" if success else "failed",
                        "message": message
                    }

                    logger.info(f"Command {command} {'succeeded' if success else 'failed'}: {message}")

            # Sync config periodically
            heartbeat_count += 1
            elapsed_since_sync = heartbeat_count * HEARTBEAT_INTERVAL
            if elapsed_since_sync >= CONFIG_SYNC_INTERVAL:
                sync_config()
                heartbeat_count = 0

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
