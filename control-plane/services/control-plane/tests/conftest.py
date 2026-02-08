"""
Pytest fixtures for control-plane integration tests.

Supports two modes:
- SQLite (default): Fast, no Docker required
- Postgres via testcontainers: Set USE_TESTCONTAINERS=1
"""

import os
import sys
import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# Set test encryption key before importing main (must be valid Fernet key)
os.environ["ENCRYPTION_KEY"] = Fernet.generate_key().decode()
os.environ["API_TOKENS"] = "test-token,admin-token"
# Use shared in-memory SQLite for tests (must be shared so all connections see the same DB)
os.environ["DATABASE_URL"] = "sqlite:///file::memory:?cache=shared"

# Add parent directory to path so we can import main
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

USE_TESTCONTAINERS = os.environ.get("USE_TESTCONTAINERS", "").lower() in ("1", "true")


@pytest.fixture(scope="session")
def database_url():
    """Get database URL - either from testcontainers or SQLite."""
    if USE_TESTCONTAINERS:
        from testcontainers.postgres import PostgresContainer
        with PostgresContainer("postgres:16-alpine") as postgres:
            yield postgres.get_connection_url()
    else:
        # Use shared in-memory SQLite (same as DATABASE_URL set above)
        yield "sqlite:///file::memory:?cache=shared"


@pytest.fixture(scope="session")
def engine(database_url):
    """Create SQLAlchemy engine connected to test database."""
    if "sqlite" in database_url:
        return create_engine(database_url, connect_args={"check_same_thread": False})
    return create_engine(database_url)


@pytest.fixture(scope="function")
def db_session(engine):
    """Create a new database session for each test."""
    import main

    # Create all tables
    main.Base.metadata.create_all(bind=engine)

    Session = sessionmaker(bind=engine)
    session = Session()

    yield session

    session.close()

    # Clean up tables after each test
    main.Base.metadata.drop_all(bind=engine)


@pytest.fixture(scope="function")
def client(engine, db_session):
    """Create FastAPI test client with test database."""
    import main

    # Override the get_db dependency to use our test session
    def override_get_db():
        try:
            yield db_session
        finally:
            pass

    main.app.dependency_overrides[main.get_db] = override_get_db

    with TestClient(main.app) as test_client:
        yield test_client

    main.app.dependency_overrides.clear()


@pytest.fixture
def auth_headers():
    """Return authorization headers for admin API requests (default tenant)."""
    # Use seeded admin token with proper tenant_id
    return {"Authorization": "Bearer admin-test-token-do-not-use-in-production"}


@pytest.fixture
def admin_headers():
    """Return admin authorization headers (default tenant)."""
    # Use seeded admin token with proper tenant_id
    return {"Authorization": "Bearer admin-test-token-do-not-use-in-production"}


@pytest.fixture
def super_admin_headers():
    """Return super admin authorization headers (cross-tenant)."""
    return {"Authorization": "Bearer super-admin-test-token-do-not-use-in-production"}


@pytest.fixture
def acme_admin_headers():
    """Return admin authorization headers for Acme Corp tenant."""
    return {"Authorization": "Bearer acme-admin-test-token-do-not-use-in-production"}
