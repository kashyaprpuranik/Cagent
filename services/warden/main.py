"""
Warden - Unified data plane service.

Combines the polling daemon (heartbeat, config sync, container management)
with the local admin HTTP API (config CRUD, container control, WebSocket
terminal, log streaming, analytics, domain policy, ext_authz credential
injection).

Runs as a FastAPI server with the polling loop in a background thread.
"""

import hashlib
import json
import logging
import os
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path
from typing import List, Optional

import docker
import requests
import yaml
from config_generator import ConfigGenerator
from constants import (
    CAGENT_CONFIG_PATH,
    CELL_CONTAINER_FALLBACK,
    CELL_LABEL,
    CONFIG_SYNC_INTERVAL,
    CONTROL_PLANE_TOKEN,
    CONTROL_PLANE_URL,
    COREDNS_CONTAINER_NAME,
    COREDNS_COREFILE_PATH,
    DATA_PLANE_DIR,
    DATAPLANE_MODE,
    ENVOY_CONFIG_PATH,
    ENVOY_CONTAINER_NAME,
    HEARTBEAT_INTERVAL,
    MAX_HEARTBEAT_WORKERS,
    SECCOMP_PROFILES_DIR,
    VALID_SECCOMP_PROFILES,
    docker_client,
)
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

# Path to .env file for docker-compose resource overrides
ENV_FILE_PATH = os.path.join(DATA_PLANE_DIR, ".env")

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# Config generator instance
config_generator = ConfigGenerator(CAGENT_CONFIG_PATH)

# Thread-safe command result tracking (written from ThreadPoolExecutor workers,
# read from the heartbeat sender on the next cycle).
_command_results_lock = threading.Lock()
_last_command_results: dict = {}

# Snapshot of original resource limits before profile-based updates,
# so we can restore them when the profile is unassigned.
# Maps container name → dict of original Docker API field values.
_container_original_resources: dict = {}


# ---------------------------------------------------------------------------
# Container discovery
# ---------------------------------------------------------------------------


def discover_cell_containers() -> List:
    """Discover cell containers by the ``cagent.role=cell`` label.

    Falls back to looking up a container named ``cell`` when no labelled
    containers are found (backward compat with unlabelled setups).
    """
    try:
        containers = docker_client.containers.list(
            all=True,
            filters={"label": CELL_LABEL},
        )
        if containers:
            return containers
    except docker.errors.APIError as e:
        logger.warning(f"Label-based discovery failed: {e}")

    # Fallback: try the fixed name
    try:
        container = docker_client.containers.get(CELL_CONTAINER_FALLBACK)
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
# Seccomp profile management
# ---------------------------------------------------------------------------


def _load_seccomp_profile(name: str) -> dict:
    """Read a seccomp profile JSON from disk.

    Args:
        name: Profile name (standard, hardened, permissive)

    Returns:
        Parsed JSON dict.

    Raises:
        FileNotFoundError: If profile does not exist.
        ValueError: If name is not valid.
    """
    if name not in VALID_SECCOMP_PROFILES:
        raise ValueError(f"Invalid seccomp profile: {name}")
    profile_path = Path(SECCOMP_PROFILES_DIR) / f"{name}.json"
    with open(profile_path, "r") as f:
        return json.load(f)


def _get_current_seccomp_label(container) -> Optional[str]:
    """Read the cagent.seccomp_profile label from a container.

    Returns None for unlabelled containers (including all existing ones
    before this feature was added).
    """
    try:
        container.reload()
        labels = container.labels or {}
        return labels.get("cagent.seccomp_profile")
    except Exception:
        return None


def recreate_container_with_seccomp(container, profile_name: str) -> tuple:
    """Recreate an cell container with a new seccomp profile.

    Stops the old container, removes it, creates a new one with the
    same configuration but the new seccomp profile, and starts it.

    Args:
        container: Docker container object
        profile_name: One of standard, hardened, permissive

    Returns:
        (success: bool, message: str)
    """
    name = container.name
    if profile_name == "permissive":
        logger.warning(
            f"Applying PERMISSIVE seccomp profile to {name}. "
            "This effectively disables syscall sandboxing and allows container-escape "
            "primitives (ptrace, mount, unshare, setns). Use only for temporary debugging."
        )
    logger.info(f"Recreating container {name} with seccomp profile: {profile_name}")

    try:
        # Load new profile
        profile_json = _load_seccomp_profile(profile_name)
        inline_json = json.dumps(profile_json)

        # Inspect old container to capture full config
        container.reload()
        attrs = container.attrs
        config = attrs.get("Config", {})
        host_config = attrs.get("HostConfig", {})
        network_settings = attrs.get("NetworkSettings", {})

        # Capture configuration
        image = config.get("Image")
        env = config.get("Env", [])
        old_labels = dict(config.get("Labels", {}))

        # Update labels with new seccomp profile
        old_labels["cagent.seccomp_profile"] = profile_name

        # Volumes/Binds
        binds = host_config.get("Binds", [])

        # Mounts (named volumes)
        mounts = []
        for mount in attrs.get("Mounts", []):
            mount_type = mount.get("Type", "volume")
            if mount_type == "volume":
                mounts.append(
                    docker.types.Mount(
                        target=mount["Destination"],
                        source=mount["Name"],
                        type="volume",
                        read_only=not mount.get("RW", True),
                    )
                )

        # DNS
        dns = host_config.get("Dns", [])

        # Cap drop
        cap_drop = host_config.get("CapDrop", [])

        # Security opts - keep non-seccomp entries, replace seccomp
        old_security_opt = host_config.get("SecurityOpt", [])
        new_security_opt = [
            opt for opt in old_security_opt if not opt.startswith("seccomp=") and not opt.startswith("seccomp:")
        ]
        new_security_opt.append(f"seccomp={inline_json}")

        # Restart policy
        restart_policy = host_config.get("RestartPolicy", {})

        # Resource limits
        nano_cpus = host_config.get("NanoCpus")
        memory = host_config.get("Memory")
        mem_reservation = host_config.get("MemoryReservation")

        # Log config
        log_config = host_config.get("LogConfig", {})

        # Networks
        networks_config = network_settings.get("Networks", {})

        # Stop + remove old container
        if container.status == "running":
            container.stop(timeout=10)
        container.remove(force=True)

        # Build create kwargs
        create_kwargs = {
            "image": image,
            "name": name,
            "environment": env,
            "labels": old_labels,
            "dns": dns if dns else None,
            "cap_drop": cap_drop if cap_drop else None,
            "security_opt": new_security_opt,
            "network_disabled": True,
            "detach": True,
        }

        if binds:
            create_kwargs["volumes"] = binds
        if mounts:
            create_kwargs["mounts"] = mounts
        if restart_policy:
            create_kwargs["restart_policy"] = restart_policy
        if nano_cpus:
            create_kwargs["nano_cpus"] = nano_cpus
        if memory:
            create_kwargs["mem_limit"] = memory
        if mem_reservation:
            create_kwargs["mem_reservation"] = mem_reservation
        if log_config and log_config.get("Type"):
            create_kwargs["log_config"] = docker.types.LogConfig(
                type=log_config["Type"],
                config=log_config.get("Config", {}),
            )

        # Create new container
        new_container = docker_client.containers.create(**create_kwargs)

        # Connect to original networks
        for net_name, net_config in networks_config.items():
            try:
                network = docker_client.networks.get(net_name)
                ip_addr = net_config.get("IPAddress")
                connect_kwargs = {}
                if ip_addr:
                    connect_kwargs["ipv4_address"] = ip_addr
                network.connect(new_container, **connect_kwargs)
            except Exception as e:
                logger.warning(f"Could not connect to network {net_name}: {e}")

        # Start
        new_container.start()

        msg = f"Container {name} recreated with seccomp profile: {profile_name}"
        logger.info(msg)
        return True, msg

    except Exception as e:
        logger.error(f"Failed to recreate container {name} with seccomp profile {profile_name}: {e}")
        return False, str(e)


def _get_current_resource_limits(container) -> dict:
    """Read current resource limits from a running container.

    Returns dict with cpu_limit (float, CPUs), memory_limit_mb (int), pids_limit (int).
    Values are None if not set / unlimited.
    """
    try:
        container.reload()
        host_config = container.attrs.get("HostConfig", {})

        # CPU: prefer NanoCpus (set by update and docker-compose --cpus),
        # fall back to CpuQuota/CpuPeriod
        nano_cpus = host_config.get("NanoCpus", 0) or 0
        cpu_quota = host_config.get("CpuQuota", 0) or 0
        cpu_period = host_config.get("CpuPeriod", 0) or 0
        if nano_cpus > 0:
            cpu_limit = round(nano_cpus / 1e9, 2)
        elif cpu_quota > 0 and cpu_period > 0:
            cpu_limit = round(cpu_quota / cpu_period, 2)
        else:
            cpu_limit = None

        # Memory: bytes → MB (0 means unlimited)
        memory = host_config.get("Memory", 0)
        memory_limit_mb = int(memory / (1024 * 1024)) if memory else None

        # PIDs
        pids_limit = host_config.get("PidsLimit", 0)
        # Docker returns 0 or -1 for unlimited
        if pids_limit is not None and pids_limit <= 0:
            pids_limit = None

        return {
            "cpu_limit": cpu_limit,
            "memory_limit_mb": memory_limit_mb,
            "pids_limit": pids_limit,
        }
    except Exception as e:
        logger.warning(f"Could not read resource limits for {container.name}: {e}")
        return {"cpu_limit": None, "memory_limit_mb": None, "pids_limit": None}


def update_container_resources(container, cpu_limit=None, memory_limit_mb=None, pids_limit=None) -> tuple:
    """Update resource limits on a running container without recreation.

    Uses Docker's low-level /containers/{id}/update API directly because
    the Python SDK's container.update() is missing support for NanoCPUs
    and PidsLimit. We use NanoCPUs (not CpuQuota/CpuPeriod) to avoid
    conflicts with containers created via docker-compose --cpus.

    Args:
        container: Docker container object
        cpu_limit: Number of CPUs (e.g., 1.0, 2.0). None = no change.
        memory_limit_mb: Memory limit in MB. None = no change.
        pids_limit: Max PIDs. None = no change.

    Returns:
        (success: bool, message: str)
    """
    name = container.name
    data = {}

    if cpu_limit is not None:
        data["NanoCPUs"] = int(cpu_limit * 1e9)

    if memory_limit_mb is not None:
        mem_bytes = memory_limit_mb * 1024 * 1024
        data["Memory"] = mem_bytes
        data["MemorySwap"] = mem_bytes  # Disable swap

    if pids_limit is not None:
        data["PidsLimit"] = pids_limit

    if not data:
        return True, "No resource changes needed"

    try:
        logger.info(f"Updating resource limits on {name}: {data}")
        url = container.client.api._url("/containers/{0}/update", container.id)
        res = container.client.api._post_json(url, data=data)
        container.client.api._result(res, True)
        msg = f"Resource limits updated on {name}"
        logger.info(msg)
        return True, msg
    except Exception as e:
        logger.error(f"Failed to update resource limits on {name}: {e}")
        return False, str(e)


# ---------------------------------------------------------------------------
# Status helpers
# ---------------------------------------------------------------------------


def get_container_status(container) -> dict:
    """Get status metrics for a single cell container."""
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
            cpu_delta = (
                stats["cpu_stats"]["cpu_usage"]["total_usage"] - stats["precpu_stats"]["cpu_usage"]["total_usage"]
            )
            system_delta = stats["cpu_stats"]["system_cpu_usage"] - stats["precpu_stats"]["system_cpu_usage"]
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
    """Execute a command on a specific cell container.

    Returns (success: bool, message: str).
    """
    name = container.name
    logger.info(f"Executing command: {command} on {name} with args: {args}")

    try:
        if command == "restart":
            container.restart(timeout=10)
            return True, f"Cell container {name} restarted"

        elif command == "stop":
            container.stop(timeout=10)
            return True, f"Cell container {name} stopped"

        elif command == "start":
            container.start()
            return True, f"Cell container {name} started"

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
# Infrastructure restarts (shared across all cells)
# ---------------------------------------------------------------------------


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
# Config generation (shared — same Corefile / Envoy config for all cells)
# ---------------------------------------------------------------------------


def _stable_hash(content: str) -> str:
    """Hash content after stripping auto-generated timestamp lines."""
    stable = "\n".join(line for line in content.splitlines() if "Generated:" not in line)
    return hashlib.md5(stable.encode()).hexdigest()


class _ConfigState:
    """Track last-written config hashes to avoid unnecessary restarts.

    Encapsulated in a class instead of bare module globals so there is a
    single, obvious mutation point and no ``global`` statements needed.
    """

    def __init__(self):
        self.envoy_hash: Optional[str] = None
        self.corefile_hash: Optional[str] = None
        self.last_policy_version: Optional[int] = None


_config_state = _ConfigState()


def regenerate_configs(additional_domains: list = None) -> bool:
    """Regenerate CoreDNS and Envoy configs from cagent.yaml.

    Args:
        additional_domains: Extra domain entries to merge (e.g., from control plane sync).
            Each entry is a dict with at least 'domain' key, matching cagent.yaml format.

    Returns:
        True if configs were regenerated, False otherwise.
    """
    try:
        config_changed = config_generator.load_config()
        config_generator.set_additional_domains(additional_domains or [])

        # Generate configs and compute stable hashes (ignoring timestamps)
        corefile_content = config_generator.generate_corefile()
        envoy_config = config_generator.generate_envoy_config()
        envoy_yaml = yaml.dump(envoy_config, default_flow_style=False, sort_keys=False)

        corefile_hash = _stable_hash(corefile_content)
        envoy_hash = _stable_hash(envoy_yaml)

        corefile_changed = corefile_hash != _config_state.corefile_hash
        envoy_changed = envoy_hash != _config_state.envoy_hash

        if corefile_changed:
            config_generator.write_corefile(COREDNS_COREFILE_PATH)
            restart_coredns()
            _config_state.corefile_hash = corefile_hash

        if envoy_changed:
            config_generator.write_envoy_config(ENVOY_CONFIG_PATH)
            reload_envoy()
            _config_state.envoy_hash = envoy_hash

        # Always update resource env vars when config changes
        if config_changed:
            config_generator.write_resource_env(ENV_FILE_PATH)

        if corefile_changed or envoy_changed:
            logger.info("Regenerated configs from cagent.yaml")
            # Invalidate caches when config changes
            from routers.domain_policy import invalidate_cache
            from routers.ext_authz import invalidate_cache as invalidate_ext_authz_cache

            invalidate_cache()
            invalidate_ext_authz_cache()
            return True
        else:
            logger.debug("Generated configs unchanged, skipping restart")
            return False

    except Exception as e:
        logger.error(f"Error regenerating configs: {e}")
        return False


def _cp_policy_to_domain_entry(policy: dict) -> dict:
    """Convert a CP domain policy response to a cagent.yaml domain entry."""
    entry = {"domain": policy["domain"]}
    if policy.get("allowed_paths"):
        entry["allowed_paths"] = policy["allowed_paths"]
    if policy.get("requests_per_minute") is not None:
        entry.setdefault("rate_limit", {})["requests_per_minute"] = policy["requests_per_minute"]
    if policy.get("burst_size") is not None:
        entry.setdefault("rate_limit", {})["burst_size"] = policy["burst_size"]
    if policy.get("timeout"):
        entry["timeout"] = policy["timeout"]
    if policy.get("read_only"):
        entry["read_only"] = True
    # Note: credentials are NOT included — ext_authz handles them dynamically
    return entry


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
        # Fetch domain policies from control plane (agent tokens are profile-scoped)
        response = requests.get(
            f"{CONTROL_PLANE_URL}/api/v1/domain-policies",
            headers={"Authorization": f"Bearer {CONTROL_PLANE_TOKEN}"},
            timeout=10,
        )

        if response.status_code != 200:
            logger.warning(f"Failed to fetch domain policies: {response.status_code}, using cagent.yaml")
            return regenerate_configs()

        # Parse domain policies (paginated response: {items: [...], total: N})
        data = response.json()
        policies = data.get("items", data) if isinstance(data, dict) else data
        cp_entries = [_cp_policy_to_domain_entry(p) for p in policies if p.get("enabled", True)]

        logger.info(f"Fetched {len(cp_entries)} domain policies from control plane")

        # Regenerate configs (cagent.yaml is still the primary source)
        return regenerate_configs(additional_domains=cp_entries)

    except requests.exceptions.RequestException as e:
        logger.warning(f"Could not reach control plane: {e}, using cagent.yaml")
        return regenerate_configs()
    except Exception as e:
        logger.error(f"Error syncing config: {e}")
        return False


# ---------------------------------------------------------------------------
# Heartbeat
# ---------------------------------------------------------------------------


def _send_bare_heartbeat(cell_name: str, command: str, result: str, message: str):
    """Send a heartbeat without a live container (e.g., after wipe).

    Used to report command results when the container no longer exists.
    """
    if not CONTROL_PLANE_URL or not CONTROL_PLANE_TOKEN:
        return
    heartbeat = {
        "status": "removed",
        "last_command": command,
        "last_command_result": result,
        "last_command_message": message,
    }
    try:
        requests.post(
            f"{CONTROL_PLANE_URL}/api/v1/cell/heartbeat",
            json=heartbeat,
            headers={"Authorization": f"Bearer {CONTROL_PLANE_TOKEN}"},
            timeout=10,
        )
    except Exception as e:
        logger.warning(f"Failed to send bare heartbeat for {cell_name}: {e}")


def send_heartbeat(container) -> Optional[dict]:
    """Send heartbeat for a single cell container to control plane.

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
            f"{CONTROL_PLANE_URL}/api/v1/cell/heartbeat",
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
    Commands take priority over seccomp updates — only one operation per cycle.
    Returns the policy_version from the heartbeat response (or None).
    """
    response = send_heartbeat(container)
    if not response:
        return None

    policy_version = response.get("policy_version")

    # Commands take priority — execute and return
    if response.get("command"):
        command = response["command"]
        cmd_args = response.get("command_args")
        logger.info(f"Received command for {container.name}: {command}")
        success, message = execute_command(command, container, cmd_args)
        result_str = "success" if success else "failed"
        with _command_results_lock:
            _last_command_results[container.name] = {
                "command": command,
                "result": result_str,
                "message": message,
            }
        logger.info(f"Command {command} on {container.name} {'succeeded' if success else 'failed'}: {message}")
        # Wipe removes the container, so it won't be discovered next cycle.
        # Send the result immediately via a bare heartbeat.
        if command == "wipe":
            _send_bare_heartbeat(container.name, command, result_str, message)
            with _command_results_lock:
                _last_command_results.pop(container.name, None)
        return policy_version

    # No command — check if seccomp profile needs updating
    seccomp_changed = False
    desired_profile = response.get("seccomp_profile")
    if desired_profile and desired_profile in VALID_SECCOMP_PROFILES:
        current_label = _get_current_seccomp_label(container)
        # Skip unlabelled containers (existing deployments) and gVisor containers
        if current_label is not None and current_label != desired_profile:
            logger.info(f"Seccomp mismatch on {container.name}: current={current_label}, desired={desired_profile}")
            success, message = recreate_container_with_seccomp(container, desired_profile)
            seccomp_changed = True
            with _command_results_lock:
                _last_command_results[container.name] = {
                    "command": "seccomp_update",
                    "result": "success" if success else "failed",
                    "message": message,
                }

    # Check resource limits (skip if seccomp just triggered a recreation)
    if not seccomp_changed:
        desired_cpu = response.get("cpu_limit")
        desired_mem = response.get("memory_limit_mb")
        desired_pids = response.get("pids_limit")

        if desired_cpu is not None or desired_mem is not None or desired_pids is not None:
            # Profile has resource limits — apply them
            current = _get_current_resource_limits(container)
            needs_update = False

            if desired_cpu is not None and current["cpu_limit"] != desired_cpu:
                needs_update = True
            if desired_mem is not None and current["memory_limit_mb"] != desired_mem:
                needs_update = True
            if desired_pids is not None and current["pids_limit"] != desired_pids:
                needs_update = True

            if needs_update:
                # Snapshot original values before first profile update
                if container.name not in _container_original_resources:
                    container.reload()
                    hc = container.attrs.get("HostConfig", {})
                    _container_original_resources[container.name] = {
                        "NanoCPUs": hc.get("NanoCpus", 0) or 0,
                        "Memory": hc.get("Memory", 0) or 0,
                        "MemorySwap": hc.get("MemorySwap", 0) or 0,
                        "PidsLimit": hc.get("PidsLimit", 0) or 0,
                    }

                success, message = update_container_resources(
                    container,
                    cpu_limit=desired_cpu,
                    memory_limit_mb=desired_mem,
                    pids_limit=desired_pids,
                )
                with _command_results_lock:
                    _last_command_results[container.name] = {
                        "command": "resource_update",
                        "result": "success" if success else "failed",
                        "message": message,
                    }
        elif container.name in _container_original_resources:
            # Profile unassigned — restore original resource limits.
            # Docker's update API ignores NanoCPUs=0, so we must restore
            # the original value (e.g. the compose-defined CPU limit).
            restore_data = _container_original_resources[container.name]
            try:
                logger.info(f"Restoring resource limits on {container.name}: {restore_data}")
                url = container.client.api._url("/containers/{0}/update", container.id)
                res = container.client.api._post_json(url, data=restore_data)
                container.client.api._result(res, True)
                logger.info(f"Resource limits restored on {container.name}")
            except Exception as e:
                logger.error(f"Failed to restore resource limits on {container.name}: {e}")
            _container_original_resources.pop(container.name, None)

    return policy_version


def _check_standalone_seccomp(agents):
    """In standalone mode, check cagent.yaml security.seccomp_profile against containers.

    Only recreates containers that have a cagent.seccomp_profile label
    (skips unlabelled/gVisor containers).
    """
    try:
        config_path = Path(CAGENT_CONFIG_PATH)
        if not config_path.exists():
            return
        with open(config_path, "r") as f:
            config = yaml.safe_load(f) or {}
        desired = config.get("security", {}).get("seccomp_profile", "hardened")
        if desired not in VALID_SECCOMP_PROFILES:
            logger.warning(f"Invalid seccomp_profile in cagent.yaml: {desired}")
            return

        for container in agents:
            current_label = _get_current_seccomp_label(container)
            if current_label is not None and current_label != desired:
                logger.info(
                    f"Standalone seccomp mismatch on {container.name}: current={current_label}, desired={desired}"
                )
                recreate_container_with_seccomp(container, desired)
    except Exception as e:
        logger.error(f"Error checking standalone seccomp profiles: {e}")


def _check_standalone_resources(agents):
    """In standalone mode, apply resource limits from cagent.yaml resources section."""
    try:
        config_path = Path(CAGENT_CONFIG_PATH)
        if not config_path.exists():
            return
        with open(config_path, "r") as f:
            config = yaml.safe_load(f) or {}
        resources = config.get("resources", {})
        if not resources:
            return

        desired_cpu = resources.get("cpu_limit")
        desired_mem = resources.get("memory_limit_mb")
        desired_pids = resources.get("pids_limit")

        if desired_cpu is None and desired_mem is None and desired_pids is None:
            return

        for container in agents:
            current = _get_current_resource_limits(container)
            needs_update = False
            if desired_cpu is not None and current["cpu_limit"] != desired_cpu:
                needs_update = True
            if desired_mem is not None and current["memory_limit_mb"] != desired_mem:
                needs_update = True
            if desired_pids is not None and current["pids_limit"] != desired_pids:
                needs_update = True
            if needs_update:
                update_container_resources(container, desired_cpu, desired_mem, desired_pids)
    except Exception as e:
        logger.error(f"Error checking standalone resource limits: {e}")


def main_loop(stop_event: Optional[threading.Event] = None):
    """Main loop: discover agents, send heartbeats, execute commands, sync config."""
    logger.info("Warden polling loop starting")
    logger.info(f"  Mode: {DATAPLANE_MODE}")
    logger.info(f"  Config file: {CAGENT_CONFIG_PATH}")
    logger.info(f"  CoreDNS config: {COREDNS_COREFILE_PATH}")
    logger.info(f"  Envoy config: {ENVOY_CONFIG_PATH}")
    logger.info(f"  Cell discovery label: {CELL_LABEL}")
    logger.info(f"  Config sync interval: {CONFIG_SYNC_INTERVAL}s")

    if DATAPLANE_MODE == "connected":
        logger.info(f"  Control plane: {CONTROL_PLANE_URL}")
        logger.info(f"  Heartbeat interval: {HEARTBEAT_INTERVAL}s")
        if not CONTROL_PLANE_TOKEN:
            logger.warning("CONTROL_PLANE_TOKEN not set - heartbeats will fail")
    else:
        logger.info("  Running in standalone mode (no control plane sync)")

    # Log initially discovered agents
    agents = discover_cell_containers()
    logger.info(f"  Discovered {len(agents)} cell container(s): {[c.name for c in agents]}")

    # Initial config generation from cagent.yaml (always write on startup)
    logger.info("Generating initial configs from cagent.yaml...")
    config_generator.load_config()
    config_generator.write_corefile(COREDNS_COREFILE_PATH)
    config_generator.write_envoy_config(ENVOY_CONFIG_PATH)
    config_generator.write_resource_env(ENV_FILE_PATH)
    restart_coredns()
    reload_envoy()
    # Snapshot current state so regenerate_configs() can detect changes
    _config_state.corefile_hash = _stable_hash(config_generator.generate_corefile())
    _config_state.envoy_hash = _stable_hash(
        yaml.dump(config_generator.generate_envoy_config(), default_flow_style=False, sort_keys=False)
    )
    logger.info("Initial config generation complete")

    # Use wall-clock monotonic time for config sync scheduling so that
    # slow heartbeat cycles (e.g. Docker stats across many containers)
    # don't cause sync drift.
    last_sync_time = time.monotonic()

    while not (stop_event and stop_event.is_set()):
        try:
            # Discover cell containers each cycle (handles containers
            # being added/removed at runtime)
            agents = discover_cell_containers()

            # In connected mode, send heartbeat and handle commands per cell (concurrent)
            policy_version = None
            if DATAPLANE_MODE == "connected" and CONTROL_PLANE_TOKEN:
                workers = min(MAX_HEARTBEAT_WORKERS, len(agents)) if agents else 1
                with ThreadPoolExecutor(max_workers=workers) as executor:
                    futures = {executor.submit(_heartbeat_and_handle, c): c for c in agents}
                    for f in as_completed(futures):
                        try:
                            pv = f.result()
                            # Use the first non-None policy_version (all cells in
                            # the same tenant share the same version).
                            if pv is not None and policy_version is None:
                                policy_version = pv
                        except Exception as exc:
                            container = futures[f]
                            logger.error(f"Heartbeat failed for {container.name}: {exc}")

            # Version-driven config sync: only fetch policies when CP signals a change
            now = time.monotonic()
            if policy_version is None:
                # No Redis on CP or old CP — fall back to interval polling
                if (now - last_sync_time) >= CONFIG_SYNC_INTERVAL:
                    sync_config()
                    last_sync_time = now
            elif policy_version != _config_state.last_policy_version:
                logger.info(
                    f"Policy version changed: {_config_state.last_policy_version} -> {policy_version}, syncing config"
                )
                sync_config()
                # Update last_policy_version ONLY after sync_config succeeds
                # (configs written and services restarted).  If sync_config
                # raises, the version stays stale and we retry next heartbeat.
                _config_state.last_policy_version = policy_version
                last_sync_time = now

            # Standalone mode: check seccomp profile and resource limits from cagent.yaml
            if DATAPLANE_MODE == "standalone" and agents:
                _check_standalone_seccomp(agents)
                _check_standalone_resources(agents)

        except Exception as e:
            logger.error(f"Error in main loop: {e}")

        # Wait for next cycle (use stop_event.wait for clean shutdown)
        if stop_event:
            stop_event.wait(HEARTBEAT_INTERVAL)
        else:
            time.sleep(HEARTBEAT_INTERVAL)


# ---------------------------------------------------------------------------
# FastAPI application
# ---------------------------------------------------------------------------


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Start the polling loop in a resilient background thread.

    The loop auto-restarts on any crash (including BaseException such as
    KeyboardInterrupt delivered by uvicorn's signal handler to a non-main
    thread that happens to hold the GIL).
    """
    stop_event = threading.Event()

    def _loop_with_restart():
        while not stop_event.is_set():
            try:
                main_loop(stop_event)
            except Exception:
                logger.exception("Polling loop crashed, restarting in 5s")
            except BaseException as exc:
                # KeyboardInterrupt, SystemExit, etc. — log and restart
                logger.error("Polling loop killed by %s: %s — restarting in 5s", type(exc).__name__, exc)
            if not stop_event.is_set():
                time.sleep(5)

    loop_thread = threading.Thread(target=_loop_with_restart, daemon=True, name="polling-loop")
    loop_thread.start()
    logger.info("Polling loop thread started")
    yield
    stop_event.set()


app = FastAPI(
    title="Cagent Warden",
    description="Unified data plane service: config management, container control, and CP sync",
    version="1.0.0",
    lifespan=lifespan,
)

# CORS for local development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:5173", "http://127.0.0.1:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register routers
from routers import analytics, config, containers, domain_policy, ext_authz, health, logs, terminal

app.include_router(health.router, prefix="/api", tags=["health"])
app.include_router(config.router, prefix="/api", tags=["config"])
app.include_router(containers.router, prefix="/api", tags=["containers"])
app.include_router(logs.router, prefix="/api", tags=["logs"])
app.include_router(terminal.router, prefix="/api", tags=["terminal"])
app.include_router(analytics.router, prefix="/api", tags=["analytics"])
app.include_router(domain_policy.router, tags=["domain-policy"])
app.include_router(ext_authz.router, tags=["ext-authz"])

# =============================================================================
# Static files (frontend)
# =============================================================================

FRONTEND_DIR = Path(__file__).parent / "frontend" / "dist"
if FRONTEND_DIR.exists():
    app.mount("/assets", StaticFiles(directory=FRONTEND_DIR / "assets"), name="assets")

    @app.get("/{path:path}")
    async def serve_frontend(path: str):
        """Serve frontend for all non-API routes."""
        if path.startswith("api/"):
            raise HTTPException(404)

        try:
            # Resolve the requested path relative to FRONTEND_DIR
            file_path = (FRONTEND_DIR / path).resolve()

            # Ensure the resolved path is still within FRONTEND_DIR
            # This prevents path traversal attacks (e.g., /../../etc/passwd)
            if not file_path.is_relative_to(FRONTEND_DIR.resolve()):
                # Path traversal detected - return index.html (SPA fallback)
                return FileResponse(FRONTEND_DIR / "index.html")

            if file_path.exists() and file_path.is_file():
                return FileResponse(file_path)
        except Exception:
            # Path resolution error or other issue
            pass

        return FileResponse(FRONTEND_DIR / "index.html")


if __name__ == "__main__":
    import uvicorn

    try:
        # Verify Docker connection
        docker_client.ping()
        logger.info("Docker connection verified")
    except Exception as e:
        logger.error(f"Cannot connect to Docker: {e}")
        sys.exit(1)

    uvicorn.run(app, host="0.0.0.0", port=8080)
