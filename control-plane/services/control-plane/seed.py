#!/usr/bin/env python3
"""
Database seeder for Cagent Control Plane.

Creates default data for development and testing:
- A default admin token
- A test agent (approved, for UI testing)
- Sample domain policies (allowlist, rate limits, credentials)

Usage:
    python seed.py              # Seed with defaults
    python seed.py --reset      # Clear all data first, then seed
    python seed.py --show-token # Show the generated admin token

Environment:
    DATABASE_URL: PostgreSQL connection string (defaults to docker-compose setup)
    ENCRYPTION_KEY: Fernet key for secret encryption
"""

import os
import sys
import argparse
import hashlib
import secrets
from datetime import datetime

# Ensure we can import main
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from cryptography.fernet import Fernet

# Set encryption key if not present
if not os.environ.get('ENCRYPTION_KEY'):
    os.environ['ENCRYPTION_KEY'] = Fernet.generate_key().decode()

from main import (
    engine, SessionLocal, Base,
    Tenant, ApiToken, AgentState, DomainPolicy,
    encrypt_secret
)


def hash_token(token: str) -> str:
    """Hash a token using SHA-256."""
    return hashlib.sha256(token.encode()).hexdigest()


def generate_token() -> str:
    """Generate a secure random token."""
    return secrets.token_urlsafe(32)


def seed_database(reset: bool = False, show_token: bool = False):
    """Seed the database with default data."""

    # Create tables
    Base.metadata.create_all(bind=engine)

    db = SessionLocal()

    try:
        if reset:
            print("Resetting database...")
            db.query(ApiToken).delete()
            db.query(AgentState).delete()
            db.query(DomainPolicy).delete()
            db.query(Tenant).delete()
            db.commit()
            print("Database cleared.")

        # Track what we create
        created = []
        admin_token_value = None

        # 0. Create default tenant (if not exists)
        existing_tenant = db.query(Tenant).filter(Tenant.slug == "default").first()
        if not existing_tenant:
            default_tenant = Tenant(
                name="Default Tenant",
                slug="default"
            )
            db.add(default_tenant)
            db.commit()
            db.refresh(default_tenant)
            created.append("Tenant 'Default Tenant' (slug: default)")

            # Create __default__ agent for tenant-global config
            default_agent = AgentState(
                agent_id="__default__",
                tenant_id=default_tenant.id,
                status="virtual",
                approved=True,
                approved_at=datetime.utcnow(),
                approved_by="seed-script"
            )
            db.add(default_agent)
            created.append("Agent '__default__' (tenant-global config)")
        else:
            default_tenant = existing_tenant
            print("Default tenant already exists")

        # 1. Create default admin token (super admin, if not exists)
        existing_admin = db.query(ApiToken).filter(ApiToken.name == "default-admin").first()
        if not existing_admin:
            admin_token_value = generate_token()
            admin_token = ApiToken(
                name="default-admin",
                token_hash=hash_token(admin_token_value),
                token_type="admin",
                is_super_admin=True,  # Super admin for backwards compat
                enabled=True
            )
            db.add(admin_token)
            created.append("Admin token 'default-admin' (super admin)")
        else:
            print("Admin token 'default-admin' already exists")

        # 2. Create test agent (approved, for UI testing)
        existing_agent = db.query(AgentState).filter(AgentState.agent_id == "test-agent").first()
        if not existing_agent:
            test_agent = AgentState(
                agent_id="test-agent",
                tenant_id=default_tenant.id,
                status="running",
                approved=True,
                approved_at=datetime.utcnow(),
                approved_by="seed-script",
                last_heartbeat=datetime.utcnow(),
                uptime_seconds=3600,
                cpu_percent=15,
                memory_mb=256,
                memory_limit_mb=1024
            )
            db.add(test_agent)
            created.append("Test agent 'test-agent' (approved)")
        else:
            print("Test agent 'test-agent' already exists")

        # 3. Create a pending agent (for testing approval flow)
        existing_pending = db.query(AgentState).filter(AgentState.agent_id == "pending-agent").first()
        if not existing_pending:
            pending_agent = AgentState(
                agent_id="pending-agent",
                tenant_id=default_tenant.id,
                status="running",
                approved=False,
                last_heartbeat=datetime.utcnow(),
            )
            db.add(pending_agent)
            created.append("Pending agent 'pending-agent' (not approved)")
        else:
            print("Pending agent 'pending-agent' already exists")

        # 4. Create agent token for test-agent
        existing_agent_token = db.query(ApiToken).filter(ApiToken.name == "test-agent-token").first()
        agent_token_value = None
        if not existing_agent_token:
            agent_token_value = generate_token()
            agent_token = ApiToken(
                name="test-agent-token",
                token_hash=hash_token(agent_token_value),
                token_type="agent",
                agent_id="test-agent",
                tenant_id=default_tenant.id,
                enabled=True
            )
            db.add(agent_token)
            created.append("Agent token 'test-agent-token' for test-agent")
        else:
            print("Agent token 'test-agent-token' already exists")

        # 5. Create sample domain policies (global)
        sample_policies = [
            {
                "domain": "api.openai.com",
                "alias": "openai",
                "description": "OpenAI API - ChatGPT, GPT-4, embeddings",
                "requests_per_minute": 60,
                "burst_size": 10,
                "allowed_paths": ["/v1/chat/*", "/v1/completions", "/v1/embeddings", "/v1/models"],
            },
            {
                "domain": "api.anthropic.com",
                "alias": "anthropic",
                "description": "Anthropic API - Claude models",
                "requests_per_minute": 60,
                "burst_size": 10,
                "allowed_paths": ["/v1/messages", "/v1/complete"],
            },
            {
                "domain": "api.github.com",
                "alias": "github",
                "description": "GitHub API - repos, issues, PRs",
                "requests_per_minute": 100,
                "burst_size": 20,
            },
            {
                "domain": "pypi.org",
                "description": "Python Package Index - no auth required",
            },
            {
                "domain": "files.pythonhosted.org",
                "description": "Python package downloads",
            },
            {
                "domain": "registry.npmjs.org",
                "description": "NPM Registry - no auth required",
            },
        ]
        for policy_data in sample_policies:
            existing = db.query(DomainPolicy).filter(
                DomainPolicy.domain == policy_data["domain"],
                DomainPolicy.agent_id.is_(None)
            ).first()
            if not existing:
                policy = DomainPolicy(
                    domain=policy_data["domain"],
                    alias=policy_data.get("alias"),
                    description=policy_data.get("description"),
                    requests_per_minute=policy_data.get("requests_per_minute"),
                    burst_size=policy_data.get("burst_size"),
                    allowed_paths=policy_data.get("allowed_paths", []),
                    enabled=True
                )
                db.add(policy)
                created.append(f"Domain policy '{policy_data['domain']}'")

        # 6. Create agent-specific domain policies for test-agent
        test_agent_policies = [
            {
                "domain": "huggingface.co",
                "alias": "huggingface",
                "description": "HuggingFace - test-agent only",
                "requests_per_minute": 30,
                "burst_size": 5,
                "agent_id": "test-agent",
                # With credential
                "credential_header": "Authorization",
                "credential_format": "Bearer {value}",
                "credential_value": "hf_dummy_token_for_testing",
            },
            {
                "domain": "*.aws.amazon.com",
                "description": "AWS APIs - test-agent only",
                "agent_id": "test-agent",
            },
        ]
        for policy_data in test_agent_policies:
            existing = db.query(DomainPolicy).filter(
                DomainPolicy.domain == policy_data["domain"],
                DomainPolicy.agent_id == policy_data.get("agent_id")
            ).first()
            if not existing:
                policy = DomainPolicy(
                    domain=policy_data["domain"],
                    alias=policy_data.get("alias"),
                    description=policy_data.get("description"),
                    requests_per_minute=policy_data.get("requests_per_minute"),
                    burst_size=policy_data.get("burst_size"),
                    allowed_paths=policy_data.get("allowed_paths", []),
                    agent_id=policy_data.get("agent_id"),
                    enabled=True
                )
                # Handle credential if present
                if policy_data.get("credential_value"):
                    policy.credential_header = policy_data.get("credential_header")
                    policy.credential_format = policy_data.get("credential_format")
                    policy.credential_value_encrypted = encrypt_secret(policy_data["credential_value"])
                db.add(policy)
                created.append(f"Domain policy '{policy_data['domain']}' ({policy_data.get('agent_id', 'global')})")

        db.commit()

        # Print summary
        print("\n" + "="*50)
        print("Database seeding complete!")
        print("="*50)

        if created:
            print("\nCreated:")
            for item in created:
                print(f"  - {item}")
        else:
            print("\nNo new data created (already exists)")

        if admin_token_value and show_token:
            print("\n" + "="*50)
            print("SAVE THIS TOKEN - IT WILL NOT BE SHOWN AGAIN!")
            print("="*50)
            print(f"\nAdmin Token: {admin_token_value}")
            print("\nUse in .env or docker-compose:")
            print(f"  ADMIN_TOKEN={admin_token_value}")
            print("\nOr in Authorization header:")
            print(f"  Authorization: Bearer {admin_token_value}")

        if agent_token_value and show_token:
            print(f"\nAgent Token (for test-agent): {agent_token_value}")

        print("\n" + "="*50)
        print("Quick start:")
        print("="*50)
        print("\n1. Legacy tokens still work (from API_TOKENS env var):")
        print("   curl -H 'Authorization: Bearer dev-token' http://localhost:8002/api/v1/agents")
        print("\n2. Access the Admin UI at: http://localhost:9080")
        print("   Default token: dev-token")
        print("\n3. Test agents in UI:")
        print("   - 'test-agent' is approved and ready")
        print("   - 'pending-agent' needs approval (test the approval flow)")
        print("\n4. Domain Policies:")
        print("   - Unified policies for allowlist, rate limits, egress, and credentials")
        print("   - Global policies: api.openai.com, api.anthropic.com, pypi.org, etc.")
        print("   - 'test-agent' has agent-specific policy for huggingface.co with credential")
        print("   - Agent-specific policies take precedence over global policies")
        print("\n5. Multi-tenancy:")
        print("   - Default tenant created with slug 'default'")
        print("   - All test agents belong to the default tenant")
        print("   - default-admin token is a super admin (can manage all tenants)")

    finally:
        db.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Seed the control plane database")
    parser.add_argument("--reset", action="store_true", help="Clear all data before seeding")
    parser.add_argument("--show-token", action="store_true", help="Show the generated admin token")
    args = parser.parse_args()

    seed_database(reset=args.reset, show_token=args.show_token)
