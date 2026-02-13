#!/usr/bin/env python3
"""
Post-seed: create dev resources via the API after uvicorn is running.

This script reads the admin token written by seed.py and calls the API
to create domain policies and IP ACLs. Because it goes through the API,
all actions are automatically audit-logged.

Pre-seed (seed.py) creates tenants and tokens — things the API needs to
function. This script creates everything else.

Run from dev_up.sh after the health check passes:
    docker exec backend python post_seed.py
"""

import json
import os
import sys
import urllib.request
import urllib.error

API_BASE = "http://localhost:8000/api/v1"
SEED_TOKEN_FILE = "/tmp/seed-token"


def api_call(method, path, token, body=None, params=None):
    """Make an API call. Returns (status_code, response_body)."""
    url = f"{API_BASE}{path}"
    if params:
        url += "?" + "&".join(f"{k}={v}" for k, v in params.items())

    data = json.dumps(body).encode() if body else None
    req = urllib.request.Request(
        url,
        data=data,
        method=method,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as e:
        body_text = e.read().decode()
        try:
            return e.code, json.loads(body_text)
        except json.JSONDecodeError:
            return e.code, {"detail": body_text}


def get_tenant_id(token, slug):
    """Get a tenant's ID by slug."""
    status, data = api_call("GET", "/tenants", token)
    if status != 200:
        print(f"ERROR: Failed to list tenants: {data}")
        sys.exit(1)
    # Handle both paginated {"items": [...]} and flat list responses
    tenants = data.get("items", data) if isinstance(data, dict) else data
    for tenant in tenants:
        if tenant.get("slug") == slug:
            return tenant["id"]
    print(f"ERROR: Tenant '{slug}' not found")
    sys.exit(1)


def create_policies(token, tenant_id, tenant_name, policies, created, skipped):
    """Create domain policies for a tenant."""
    for policy in policies:
        status, data = api_call(
            "POST", "/domain-policies", token,
            body=policy,
            params={"tenant_id": str(tenant_id)},
        )
        label = f"[{tenant_name}] Domain policy '{policy['domain']}'"
        if policy.get("agent_id"):
            label += f" (agent: {policy['agent_id']})"
        if status == 200:
            created.append(label)
        elif status == 400 and "already exists" in data.get("detail", ""):
            skipped.append(f"{label} (exists)")
        else:
            print(f"WARNING: Failed to create {label}: {data}")


def create_email_policies(token, tenant_id, tenant_name, policies, created, skipped):
    """Create email policies for a tenant."""
    for policy in policies:
        status, data = api_call(
            "POST", "/email-policies", token,
            body=policy,
            params={"tenant_id": str(tenant_id)},
        )
        label = f"[{tenant_name}] Email policy '{policy['name']}'"
        if status == 200:
            created.append(label)
        elif status == 400 and "already exists" in data.get("detail", ""):
            skipped.append(f"{label} (exists)")
        else:
            print(f"WARNING: Failed to create {label}: {data}")


def create_ip_acls(token, tenant_id, tenant_name, acls, created, skipped):
    """Create IP ACLs for a tenant."""
    for acl in acls:
        status, data = api_call(
            "POST", f"/tenants/{tenant_id}/ip-acls", token,
            body=acl,
        )
        label = f"[{tenant_name}] IP ACL '{acl['cidr']}'"
        if status == 200:
            created.append(label)
        elif status == 400 and "already exists" in data.get("detail", ""):
            skipped.append(f"{label} (exists)")
        else:
            print(f"WARNING: Failed to create {label}: {data}")


def post_seed():
    # Read admin token
    if not os.path.exists(SEED_TOKEN_FILE):
        print("No seed token file found — skipping post-seed (already done or not a fresh seed)")
        return

    with open(SEED_TOKEN_FILE) as f:
        token = f.read().strip()

    if not token:
        print("ERROR: Seed token file is empty")
        sys.exit(1)

    default_tenant_id = get_tenant_id(token, "default")
    acme_tenant_id = get_tenant_id(token, "acme")
    created = []
    skipped = []

    # =========================================================================
    # 1. Default tenant — global domain policies
    # =========================================================================
    default_policies = [
        {
            "domain": "api.openai.com",
            "alias": "openai",
            "description": "OpenAI API - ChatGPT, GPT-4, embeddings",
            "timeout": "120s",
            "requests_per_minute": 60,
            "burst_size": 10,
            "allowed_paths": ["/v1/chat/*", "/v1/completions", "/v1/embeddings", "/v1/models"],
        },
        {
            "domain": "api.anthropic.com",
            "alias": "anthropic",
            "description": "Anthropic API - Claude models",
            "timeout": "120s",
            "requests_per_minute": 60,
            "burst_size": 10,
            "allowed_paths": ["/v1/messages", "/v1/complete"],
        },
        {
            "domain": "github.com",
            "description": "GitHub web",
        },
        {
            "domain": "api.github.com",
            "alias": "github",
            "description": "GitHub API - repos, issues, PRs",
            "timeout": "30s",
            "requests_per_minute": 100,
            "burst_size": 20,
        },
        {
            "domain": "raw.githubusercontent.com",
            "description": "GitHub raw content",
        },
        {
            "domain": "objects.githubusercontent.com",
            "description": "GitHub objects",
        },
        {
            "domain": "gist.githubusercontent.com",
            "description": "GitHub gist content",
        },
        {
            "domain": "codeload.github.com",
            "description": "GitHub code downloads",
        },
        {
            "domain": "pypi.org",
            "description": "Python Package Index",
            "read_only": True,
        },
        {
            "domain": "files.pythonhosted.org",
            "description": "Python package downloads",
            "read_only": True,
        },
        {
            "domain": "registry.npmjs.org",
            "description": "NPM Registry",
            "read_only": True,
        },
        {
            "domain": "registry.yarnpkg.com",
            "description": "Yarn Registry",
            "read_only": True,
        },
    ]

    create_policies(token, default_tenant_id, "default", default_policies, created, skipped)

    # =========================================================================
    # 2. Default tenant — agent-specific policies for test-agent
    # =========================================================================
    default_agent_policies = [
        {
            "domain": "huggingface.co",
            "alias": "huggingface",
            "description": "HuggingFace - test-agent only",
            "timeout": "300s",
            "requests_per_minute": 30,
            "burst_size": 5,
            "agent_id": "test-agent",
            "credential": {
                "header": "Authorization",
                "format": "Bearer {value}",
                "value": "hf_dummy_token_for_testing",
            },
        },
        {
            "domain": "cdn-lfs.huggingface.co",
            "description": "HuggingFace LFS - large model downloads",
            "timeout": "600s",
            "agent_id": "test-agent",
        },
        {
            "domain": "*.aws.amazon.com",
            "description": "AWS APIs - test-agent only",
            "agent_id": "test-agent",
        },
    ]

    create_policies(token, default_tenant_id, "default", default_agent_policies, created, skipped)

    # =========================================================================
    # 3. Acme Corp tenant — domain policies
    # =========================================================================
    acme_policies = [
        {
            "domain": "api.openai.com",
            "alias": "openai",
            "description": "OpenAI API",
        },
        {
            "domain": "api.stripe.com",
            "alias": "stripe",
            "description": "Stripe Payments API",
        },
        {
            "domain": "api.twilio.com",
            "alias": "twilio",
            "description": "Twilio Communications API",
        },
    ]

    create_policies(token, acme_tenant_id, "acme", acme_policies, created, skipped)

    # =========================================================================
    # 4. Email policies — default tenant
    # =========================================================================
    default_email_policies = [
        {
            "name": "team-gmail",
            "provider": "gmail",
            "email": "agent@company.com",
            "allowed_recipients": ["*@company.com"],
            "allowed_senders": ["*"],
            "sends_per_hour": 50,
            "reads_per_hour": 200,
        },
    ]

    create_email_policies(token, default_tenant_id, "default", default_email_policies, created, skipped)

    # =========================================================================
    # 5. Email policies — acme tenant
    # =========================================================================
    acme_email_policies = [
        {
            "name": "acme-corp",
            "provider": "outlook",
            "email": "agent@acme-corp.com",
            "allowed_recipients": ["*@acme-corp.com"],
            "allowed_senders": ["*"],
            "sends_per_hour": 30,
            "reads_per_hour": 100,
        },
    ]

    create_email_policies(token, acme_tenant_id, "acme", acme_email_policies, created, skipped)

    # =========================================================================
    # 6. IP ACLs — allow all IPs for development (both tenants)
    # =========================================================================
    dev_acls = [
        {
            "cidr": "0.0.0.0/0",
            "description": "Allow all IPv4 addresses (development default)",
        },
    ]

    create_ip_acls(token, default_tenant_id, "default", dev_acls, created, skipped)
    create_ip_acls(token, acme_tenant_id, "acme", dev_acls, created, skipped)

    # Additional sample ACLs for default tenant
    sample_acls = [
        {
            "cidr": "10.0.0.0/8",
            "description": "Internal network",
        },
        {
            "cidr": "203.0.113.50/32",
            "description": "VPN egress",
        },
    ]

    create_ip_acls(token, default_tenant_id, "default", sample_acls, created, skipped)

    # =========================================================================
    # Done — clean up token file
    # =========================================================================
    os.remove(SEED_TOKEN_FILE)

    print("\n" + "=" * 50)
    print("Post-seed complete!")
    print("=" * 50)

    if created:
        print("\nCreated (audit-logged):")
        for item in created:
            print(f"  - {item}")

    if skipped:
        print("\nSkipped (already exist):")
        for item in skipped:
            print(f"  - {item}")

    print(f"\nAudit logs: {len(created)} entries created")
    print("View at: Admin UI > Audit Logs")


if __name__ == "__main__":
    post_seed()
