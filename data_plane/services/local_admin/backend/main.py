"""
Local Admin API - Lightweight management API for standalone data plane.

Provides:
- Config management (read/write cagent.yaml)
- Container status and control
- Log streaming
- No authentication (localhost only)
"""

from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

from .routers import health, config, containers, logs, terminal, ssh_tunnel

app = FastAPI(
    title="Cagent Local Admin",
    description="Local management API for standalone data plane",
    version="1.0.0"
)

# CORS for local development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:5173", "http://127.0.0.1:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(health.router, prefix="/api", tags=["health"])
app.include_router(config.router, prefix="/api", tags=["config"])
app.include_router(containers.router, prefix="/api", tags=["containers"])
app.include_router(logs.router, prefix="/api", tags=["logs"])
app.include_router(terminal.router, prefix="/api", tags=["terminal"])
app.include_router(ssh_tunnel.router, prefix="/api", tags=["ssh-tunnel"])

# =============================================================================
# Static files (frontend)
# =============================================================================

# Serve frontend static files in production
FRONTEND_DIR = Path(__file__).parent.parent / "frontend" / "dist"
if FRONTEND_DIR.exists():
    app.mount("/assets", StaticFiles(directory=FRONTEND_DIR / "assets"), name="assets")

    @app.get("/{path:path}")
    async def serve_frontend(path: str):
        """Serve frontend for all non-API routes."""
        if path.startswith("api/"):
            raise HTTPException(404)

        file_path = FRONTEND_DIR / path
        if file_path.exists() and file_path.is_file():
            return FileResponse(file_path)
        return FileResponse(FRONTEND_DIR / "index.html")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)
