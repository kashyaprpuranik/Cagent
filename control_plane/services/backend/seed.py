#!/usr/bin/env python3
"""
Pre-seed: bootstrap auth infrastructure before uvicorn starts.

Creates tenants, tokens, and agent registrations directly in the DB.
These don't need audit logs. Domain policies and IP ACLs are created
by post_seed.py via the API after uvicorn is up.

Usage:
    python seed.py              # Seed with defaults
    python seed.py --reset      # Clear all data first, then seed
    python seed.py --show-token # Show the generated admin token
"""

import os
import sys
import argparse
import hashlib
import secrets
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from cryptography.fernet import Fernet

if not os.environ.get('ENCRYPTION_KEY'):
    os.environ['ENCRYPTION_KEY'] = Fernet.generate_key().decode()

from main import (
    engine, SessionLocal, Base,
    Tenant, ApiToken, AgentState,
)

SEED_TOKEN_FILE = "/tmp/seed-token"
SEED_AGENT_TOKEN = "seed-agent-token-do-not-use-in-production"


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def generate_token() -> str:
    return secrets.token_urlsafe(32)


def seed_database(reset: bool = False, show_token: bool = False):
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()

    try:
        if reset:
            print("Resetting database...")
            db.query(ApiToken).delete()
            db.query(AgentState).delete()
            db.query(Tenant).delete()
            db.commit()
            print("Database cleared.")

        created = []
        admin_token_value = None

        # 1. Default tenant
        existing_tenant = db.query(Tenant).filter(Tenant.slug == "default").first()
        if not existing_tenant:
            default_tenant = Tenant(name="Default Tenant", slug="default")
            db.add(default_tenant)
            db.commit()
            db.refresh(default_tenant)
            created.append("Tenant 'Default Tenant' (slug: default)")

            default_agent = AgentState(
                agent_id="__default__",
                tenant_id=default_tenant.id,
                status="virtual",
                approved=True,
                approved_at=datetime.now(timezone.utc),
                approved_by="seed-script"
            )
            db.add(default_agent)
            created.append("Agent '__default__' (tenant-global config)")
        else:
            default_tenant = existing_tenant
            print("Default tenant already exists")

        # 2. Super-admin token
        existing_admin = db.query(ApiToken).filter(ApiToken.name == "default-admin").first()
        if not existing_admin:
            admin_token_value = generate_token()
            admin_token = ApiToken(
                name="default-admin",
                token_hash=hash_token(admin_token_value),
                token_type="admin",
                is_super_admin=True,
                enabled=True
            )
            db.add(admin_token)
            created.append("Admin token 'default-admin' (super admin)")
        else:
            print("Admin token 'default-admin' already exists")

        # 3. Test agent (registered and active)
        existing_agent = db.query(AgentState).filter(AgentState.agent_id == "agent-group-0").first()
        if not existing_agent:
            test_agent = AgentState(
                agent_id="agent-group-0",
                tenant_id=default_tenant.id,
                status="running",
                approved=True,
                approved_at=datetime.now(timezone.utc),
                approved_by="seed-script",
                last_heartbeat=datetime.now(timezone.utc),
                uptime_seconds=3600,
                cpu_percent=15,
                memory_mb=256,
                memory_limit_mb=1024
            )
            db.add(test_agent)
            created.append("Test agent 'agent-group-0' (registered)")
        else:
            print("Test agent 'agent-group-0' already exists")

        # 4. Agent token for agent-group-0 (used by data plane heartbeat)
        existing_agent_token = db.query(ApiToken).filter(ApiToken.name == "agent-group-0-token").first()
        agent_token_value = None
        if not existing_agent_token:
            agent_token_value = SEED_AGENT_TOKEN
            agent_token = ApiToken(
                name="agent-group-0-token",
                token_hash=hash_token(agent_token_value),
                token_type="agent",
                agent_id="agent-group-0",
                tenant_id=default_tenant.id,
                enabled=True
            )
            db.add(agent_token)
            created.append("Agent token 'agent-group-0-token' for agent-group-0")
        else:
            print("Agent token 'agent-group-0-token' already exists")

        db.commit()

        # Write admin token to file for post_seed.py
        if admin_token_value:
            with open(SEED_TOKEN_FILE, "w") as f:
                f.write(admin_token_value)
            print(f"Admin token written to {SEED_TOKEN_FILE}")

        # Summary
        print("\n" + "=" * 50)
        print("Pre-seed complete!")
        print("=" * 50)

        if created:
            print("\nCreated:")
            for item in created:
                print(f"  - {item}")
        else:
            print("\nNo new data created (already exists)")

        if admin_token_value and show_token:
            print(f"\nAdmin Token: {admin_token_value}")

        if agent_token_value and show_token:
            print(f"Agent Token (for agent-group-0): {agent_token_value}")

    finally:
        db.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Pre-seed the control plane database")
    parser.add_argument("--reset", action="store_true", help="Clear all data before seeding")
    parser.add_argument("--show-token", action="store_true", help="Show the generated admin token")
    args = parser.parse_args()

    seed_database(reset=args.reset, show_token=args.show_token)
