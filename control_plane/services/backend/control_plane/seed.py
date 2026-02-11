import logging

from sqlalchemy.orm import Session

from control_plane.models import Tenant, ApiToken
from control_plane.crypto import hash_token

logger = logging.getLogger(__name__)

SUPER_ADMIN_TOKEN_VALUE = "super-admin-test-token-do-not-use-in-production"


def seed_bootstrap(db: Session):
    """Bootstrap minimum required data. Always runs on startup.

    Creates a single super-admin token for initial API access.
    Everything else is created by post_seed.py via the API so that
    audit logging happens naturally.

    Idempotent — skips if already exists.
    """
    existing = db.query(ApiToken).filter(ApiToken.name == "super-admin-token").first()
    if not existing:
        db_token = ApiToken(
            name="super-admin-token",
            token_hash=hash_token(SUPER_ADMIN_TOKEN_VALUE),
            token_type="admin",
            roles="admin",
            is_super_admin=True,
            tenant_id=None,
        )
        db.add(db_token)
        logger.info("Created super-admin-token — change this in production!")
        logger.info(f"  Token value: {SUPER_ADMIN_TOKEN_VALUE}")

    db.commit()


def seed_test_data(db: Session):
    """Seed tenants and tokens for development/testing.

    Only runs when SEED_TOKENS=true. These must be direct DB inserts
    because test tokens need deterministic values (the API generates
    random tokens). Tenants are here because tokens reference their IDs.

    Domain policies, IP ACLs, and everything else is created by
    post_seed.py via the API.

    Idempotent — skips anything that already exists.
    """
    # Create or get default tenant
    default_tenant = db.query(Tenant).filter(
        Tenant.slug == "default",
        Tenant.deleted_at.is_(None)
    ).first()

    if not default_tenant:
        default_tenant = Tenant(name="Default", slug="default")
        db.add(default_tenant)
        db.flush()
        logger.info("Seeded default tenant")

    default_tenant_id = default_tenant.id

    # Create or get Acme Corp tenant (for testing multi-tenancy)
    acme_tenant = db.query(Tenant).filter(
        Tenant.slug == "acme",
        Tenant.deleted_at.is_(None)
    ).first()

    if not acme_tenant:
        acme_tenant = Tenant(name="Acme Corp", slug="acme")
        db.add(acme_tenant)
        db.flush()
        logger.info("Seeded Acme Corp tenant")

    acme_tenant_id = acme_tenant.id

    # Test tokens with deterministic values (used by tests and dev scripts)
    test_tokens = [
        {
            "name": "admin-token",
            "raw_token": "admin-test-token-do-not-use-in-production",
            "token_type": "admin",
            "roles": "admin,developer",
            "is_super_admin": False,
            "tenant_id": default_tenant_id,
        },
        {
            "name": "dev-token",
            "raw_token": "dev-test-token-do-not-use-in-production",
            "token_type": "admin",
            "roles": "developer",
            "is_super_admin": False,
            "tenant_id": default_tenant_id,
        },
        {
            "name": "acme-admin-token",
            "raw_token": "acme-admin-test-token-do-not-use-in-production",
            "token_type": "admin",
            "roles": "admin",
            "is_super_admin": False,
            "tenant_id": acme_tenant_id,
        },
    ]

    for token_def in test_tokens:
        existing = db.query(ApiToken).filter(ApiToken.name == token_def["name"]).first()
        if not existing:
            db_token = ApiToken(
                name=token_def["name"],
                token_hash=hash_token(token_def["raw_token"]),
                token_type=token_def["token_type"],
                roles=token_def["roles"],
                is_super_admin=token_def["is_super_admin"],
                tenant_id=token_def["tenant_id"],
            )
            db.add(db_token)
            logger.info(f"Seeded token: {token_def['name']} (roles: {token_def['roles']})")

    db.commit()
