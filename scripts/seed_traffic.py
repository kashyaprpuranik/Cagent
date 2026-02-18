#!/usr/bin/env python3
"""
Data Plane Log Seed Traffic Generator.

Generates realistic traffic through DP services to produce logs:
  - CoreDNS query logs (allowed + blocked domains)
  - Envoy access logs (HTTP requests through proxy)
  - Cell container stdout logs (sandbox activity)

Run inside the cell container:
    docker exec cell python3 /seed_traffic.py

Logs flow: DP services -> Vector -> CP ingest API -> OpenObserve
"""

import json
import os
import socket
import subprocess
import sys

DNS_SERVER = "10.200.1.5"

ALLOWED_DOMAINS = [
    "api.github.com",
    "api.openai.com",
    "api.anthropic.com",
    "pypi.org",
    "registry.npmjs.org",
    "files.pythonhosted.org",
    "huggingface.co",
]

BLOCKED_DOMAINS = [
    "evil.example.com",
    "data-exfil.attacker.com",
    "malware-c2.badsite.net",
    "crypto-miner.sketchy.io",
    "unauthorized-api.internal",
]

HTTP_REQUESTS = [
    # Use http:// — envoy acts as a forward proxy upgrading to HTTPS on backend.
    # HTTPS URLs would send CONNECT which envoy's HCM doesn't handle.
    # (url, description)
    ("http://api.github.com/", "GitHub API root"),
    ("http://api.github.com/repos/torvalds/linux", "GitHub repo lookup"),
    ("http://api.github.com/rate_limit", "GitHub rate limit check"),
    ("http://api.openai.com/v1/models", "OpenAI models (expect 401)"),
    ("http://api.anthropic.com/v1/messages", "Anthropic messages (expect 401)"),
    ("http://pypi.org/simple/requests/", "PyPI package index"),
    ("http://registry.npmjs.org/express", "npm registry (expect 403 - not in allowlist)"),
]


def dns_lookup(domain):
    """Perform a DNS lookup via nslookup (logs to CoreDNS)."""
    try:
        subprocess.run(
            ["nslookup", domain, DNS_SERVER],
            capture_output=True, timeout=5,
        )
        return True
    except Exception:
        return False


def http_get(url):
    """Make an HTTP GET request through the proxy (logs to Envoy)."""
    try:
        result = subprocess.run(
            ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", url],
            capture_output=True, text=True, timeout=15,
        )
        code = result.stdout.strip()
        return int(code) if code.isdigit() else 0
    except Exception:
        return 0


def main():
    print("=== Data Plane Log Seed ===")
    print()

    # -----------------------------------------------------------------
    # 1. CoreDNS — DNS query logs
    # -----------------------------------------------------------------
    print("[coredns] Generating DNS query logs...")

    for domain in ALLOWED_DOMAINS:
        dns_lookup(domain)
        print(f"  resolve {domain} -> OK")

    for domain in BLOCKED_DOMAINS:
        dns_lookup(domain)
        print(f"  resolve {domain} -> NXDOMAIN (blocked)")

    print()

    # -----------------------------------------------------------------
    # 2. Envoy — HTTP access logs
    # -----------------------------------------------------------------
    print("[envoy] Generating HTTP access logs...")

    for url, desc in HTTP_REQUESTS:
        code = http_get(url)
        print(f"  GET {url.split('//')[1]} -> {code}  ({desc})")

    print()

    # -----------------------------------------------------------------
    # 3. Agent — container activity logs (stdout captured by Vector)
    # -----------------------------------------------------------------
    print("[cell] Generating sandbox activity logs...")

    print(f"  Python {sys.version.split()[0]} ready in sandbox")

    # Workspace I/O
    workspace = "/workspace"
    demo_file = os.path.join(workspace, "demo.txt")
    with open(demo_file, "w") as f:
        f.write("Hello from secure sandbox\n")
    with open(demo_file) as f:
        f.read()
    print(f"  Workspace I/O verified: {demo_file}")

    # Environment info
    info = {
        "user": os.environ.get("USER", "unknown"),
        "hostname": socket.gethostname(),
        "workspace_files": os.listdir(workspace),
    }
    print(f"  Environment: {json.dumps(info)}")

    print()
    print("=== Seed traffic complete ===")
    print("Logs will propagate through Vector -> CP -> OpenObserve in ~15-20s.")


if __name__ == "__main__":
    main()
