import sys
import os
import shutil
import pytest
from pathlib import Path
from fastapi.testclient import TestClient
import importlib

# Add services/warden to path
REPO_ROOT = Path(__file__).parent.parent
WARDEN_PATH = REPO_ROOT / "services" / "warden"
sys.path.insert(0, str(WARDEN_PATH))

# Path to frontend dist
FRONTEND_DIST = WARDEN_PATH / "frontend" / "dist"
ASSETS_DIR = FRONTEND_DIST / "assets"

@pytest.fixture(scope="module")
def app_with_frontend():
    # Setup: Create frontend/dist if not exists
    created_dist = False
    if not FRONTEND_DIST.exists():
        FRONTEND_DIST.mkdir(parents=True, exist_ok=True)
        ASSETS_DIR.mkdir(exist_ok=True)
        (FRONTEND_DIST / "index.html").write_text("<html>index</html>")
        created_dist = True

    # Import main.py
    # If it was already imported, reload it to pick up the existence of FRONTEND_DIST
    # (because the route registration is conditional on FRONTEND_DIST.exists())
    import main
    importlib.reload(main)

    yield main.app

    # Teardown
    if created_dist:
        shutil.rmtree(FRONTEND_DIST, ignore_errors=True)

def test_path_traversal(app_with_frontend):
    client = TestClient(app_with_frontend)

    # Create a dummy secret file in the warden directory (one level up from frontend/dist parent)
    # Structure:
    # services/warden/
    #   main.py
    #   secret.txt
    #   frontend/
    #     dist/
    #       index.html

    # We want to access ../../secret.txt from inside frontend/dist
    # Wait, frontend/dist is services/warden/frontend/dist.
    # So ../../ is services/warden.

    secret_file = WARDEN_PATH / "secret.txt"
    secret_file.write_text("SUPER_SECRET_DATA")

    try:
        # Attempt traversal
        # The path parameter in FastAPI captures the path.
        # We try to escape the static file directory.
        # We use URL encoding to bypass client-side normalization
        response = client.get("/%2e%2e/%2e%2e/secret.txt")

        # If vulnerable, we get the secret
        if response.status_code == 200 and "SUPER_SECRET_DATA" in response.text:
            pytest.fail("Vulnerability confirmed: Path traversal allowed access to secret.txt")

        # If fixed, we should probably get index.html (fallback) or 403
        # The current fallback logic returns index.html if file not found OR (with fix) if access denied
        assert "SUPER_SECRET_DATA" not in response.text

    finally:
        if secret_file.exists():
            secret_file.unlink()

def test_serve_valid_file(app_with_frontend):
    client = TestClient(app_with_frontend)
    response = client.get("/index.html")
    assert response.status_code == 200
    assert "<html>index</html>" in response.text
