"""
Pytest fixtures for control-plane integration tests.

Supports two modes:
- SQLite (default): Fast, no Docker required
- Postgres via testcontainers: Set USE_TESTCONTAINERS=1

Parallel execution via pytest-xdist (-n auto):
- Each xdist worker gets its own temp-file SQLite DB
- DATABASE_URL is set at module level (before any config imports)
"""

import os
import sys
import tempfile
import atexit
import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# Set test encryption key before importing main (must be valid Fernet key)
os.environ["ENCRYPTION_KEY"] = Fernet.generate_key().decode()
# Enable full test data seeding for tests
os.environ["SEED_TOKENS"] = "true"
# Disable multi-tenant by default in tests (individual tests opt in)
os.environ["OPENOBSERVE_MULTI_TENANT"] = "false"

# Per-worker SQLite file. Must be set at module level so config.py (which reads
# DATABASE_URL on import) sees the correct value even when test files import
# control_plane modules at module level (e.g., test_redis_client.py).
# PYTEST_XDIST_WORKER is set by xdist to "gw0", "gw1", etc.
_WORKER_ID = os.environ.get("PYTEST_XDIST_WORKER", "master")
_DB_FILE = tempfile.NamedTemporaryFile(
    prefix=f"cagent_test_{_WORKER_ID}_", suffix=".db", delete=False
)
_DB_FILE.close()
_TEST_DB_URL = f"sqlite:///{_DB_FILE.name}"
os.environ["DATABASE_URL"] = _TEST_DB_URL

# Clean up temp DB file on process exit
atexit.register(lambda: os.unlink(_DB_FILE.name) if os.path.exists(_DB_FILE.name) else None)

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
        yield _TEST_DB_URL


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
    from control_plane.rate_limit import limiter
    from control_plane.auth import clear_token_cache

    # Disable rate limiting in tests
    limiter.enabled = False

    # Clear token verification cache so stale entries from a previous test
    # (whose DB tables have been dropped) don't bleed over.
    clear_token_cache()

    # Override the get_db dependency to use our test session
    def override_get_db():
        try:
            yield db_session
        finally:
            pass

    main.app.dependency_overrides[main.get_db] = override_get_db

    # Ensure routes use the DB-only fallback path (no Redis in tests)
    main.app.state.redis = None

    with TestClient(main.app) as test_client:
        yield test_client

    main.app.dependency_overrides.clear()
    clear_token_cache()
    limiter.enabled = True


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
def dev_headers():
    """Return developer authorization headers (default tenant)."""
    return {"Authorization": "Bearer dev-test-token-do-not-use-in-production"}


@pytest.fixture
def acme_admin_headers():
    """Return admin authorization headers for Acme Corp tenant."""
    return {"Authorization": "Bearer acme-admin-test-token-do-not-use-in-production"}


@pytest.fixture
def mock_openobserve():
    """Mock httpx.AsyncClient for OpenObserve HTTP calls.

    Captures and validates requests without real network.
    Returns a mock that records all POST/DELETE calls.
    """
    calls = []

    class FakeResponse:
        def __init__(self, status_code=200, json_data=None, text=""):
            self.status_code = status_code
            self._json_data = json_data or {}
            self.text = text

        def json(self):
            return self._json_data

    class FakeClient:
        async def post(self, url, **kwargs):
            calls.append({"method": "POST", "url": url, **kwargs})
            # Return search results for query endpoints
            if "/_search" in url:
                return FakeResponse(200, {"hits": []})
            return FakeResponse(200)

        async def delete(self, url, **kwargs):
            calls.append({"method": "DELETE", "url": url, **kwargs})
            return FakeResponse(200)

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            pass

    fake_client = FakeClient()

    # Patch both the constructor (for openobserve.py provisioning) and the
    # shared app-state client (used by log/analytics routes).
    import main
    original_http_client = getattr(main.app.state, "http_client", None)
    main.app.state.http_client = fake_client

    with patch("httpx.AsyncClient", return_value=fake_client):
        yield calls

    # Restore original client
    if original_http_client is not None:
        main.app.state.http_client = original_http_client
