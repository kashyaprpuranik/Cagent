"""System status endpoints for interactive mode.

Exposes real-time metrics, disk usage, processes, network stats,
and container statuses — queried by the CP via Cloudflare Tunnel.
"""

import os
import shutil

import docker
import psutil
from constants import MANAGED_CONTAINERS, docker_client
from fastapi import APIRouter

router = APIRouter()


@router.get("/status")
async def get_status():
    """Overall system status summary."""
    mem = psutil.virtual_memory()
    disk = shutil.disk_usage("/")
    return {
        "cpu_percent": psutil.cpu_percent(interval=0.5),
        "memory_mb": round(mem.used / 1024 / 1024),
        "memory_limit_mb": round(mem.total / 1024 / 1024),
        "disk_used_bytes": disk.used,
        "disk_total_bytes": disk.total,
        "load_average": list(os.getloadavg()),
        "uptime_seconds": int(psutil.boot_time()),
    }


@router.get("/metrics")
async def get_metrics():
    """Detailed system metrics."""
    mem = psutil.virtual_memory()
    disk = shutil.disk_usage("/")
    cpu_freq = psutil.cpu_freq()
    return {
        "cpu_percent": psutil.cpu_percent(interval=0.5),
        "cpu_count": psutil.cpu_count(),
        "cpu_freq_mhz": round(cpu_freq.current) if cpu_freq else None,
        "memory_mb": round(mem.used / 1024 / 1024),
        "memory_limit_mb": round(mem.total / 1024 / 1024),
        "memory_percent": mem.percent,
        "disk_used_bytes": disk.used,
        "disk_total_bytes": disk.total,
        "disk_free_bytes": disk.free,
        "load_average": list(os.getloadavg()),
        "uptime_seconds": int(psutil.boot_time()),
    }


@router.get("/disk")
async def get_disk():
    """Disk usage per mount point."""
    partitions = psutil.disk_partitions()
    result = []
    for p in partitions:
        try:
            usage = psutil.disk_usage(p.mountpoint)
            result.append(
                {
                    "path": p.mountpoint,
                    "device": p.device,
                    "fstype": p.fstype,
                    "total_bytes": usage.total,
                    "used_bytes": usage.used,
                    "free_bytes": usage.free,
                    "percent_used": usage.percent,
                }
            )
        except (PermissionError, OSError):
            continue
    return {"disks": result}


@router.get("/processes")
async def get_processes():
    """Top processes by CPU usage."""
    procs = []
    for p in psutil.process_iter(["pid", "name", "cpu_percent", "memory_info", "status"]):
        try:
            info = p.info
            procs.append(
                {
                    "pid": info["pid"],
                    "name": info["name"],
                    "cpu_percent": info["cpu_percent"] or 0,
                    "memory_mb": round((info["memory_info"].rss if info["memory_info"] else 0) / 1024 / 1024, 1),
                    "status": info["status"],
                }
            )
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    procs.sort(key=lambda x: x["cpu_percent"], reverse=True)
    return {"processes": procs[:20]}


@router.get("/network")
async def get_network():
    """Network interface statistics."""
    counters = psutil.net_io_counters(pernic=True)
    result = []
    for name, stats in counters.items():
        if name == "lo":
            continue
        result.append(
            {
                "interface": name,
                "bytes_sent": stats.bytes_sent,
                "bytes_recv": stats.bytes_recv,
                "packets_sent": stats.packets_sent,
                "packets_recv": stats.packets_recv,
                "errin": stats.errin,
                "errout": stats.errout,
            }
        )
    return {"interfaces": result}


@router.get("/containers")
async def get_containers():
    """Docker container statuses."""
    result = []
    for name in MANAGED_CONTAINERS:
        try:
            container = docker_client.containers.get(name)
            state = container.attrs.get("State", {})
            result.append(
                {
                    "name": name,
                    "status": container.status,
                    "image": container.image.tags[0] if container.image.tags else str(container.image.id)[:12],
                    "started_at": state.get("StartedAt"),
                    "health": state.get("Health", {}).get("Status"),
                }
            )
        except docker.errors.NotFound:
            result.append({"name": name, "status": "not_found", "image": None, "started_at": None, "health": None})
        except Exception as e:
            result.append({"name": name, "status": "error", "error": str(e)})
    return {"containers": result}
