from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from slowapi.errors import RateLimitExceeded
from slowapi import _rate_limit_exceeded_handler

from control_plane.lifespan import lifespan
from control_plane.rate_limit import limiter
from control_plane.config import CORS_ORIGINS
from control_plane.database import Base, engine
from control_plane.models import (  # noqa: F401 - ensure models are registered
    Tenant, TenantIpAcl, AuditTrail, DomainPolicy,
    AgentState, TerminalSession, ApiToken, WebSocketTicket,
)
from control_plane.routes import health, logs, domain_policies, agents, terminal, tenants, ip_acls, tokens

# Create tables
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="AI Devbox Control Plane",
    description="Management API for Secure AI Devbox",
    version="1.0.0",
    lifespan=lifespan,
    openapi_url="/openapi.json",
    docs_url="/docs",
    redoc_url="/redoc"
)

# Register rate limiter with app
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

if CORS_ORIGINS:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=CORS_ORIGINS,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

# Include routers
app.include_router(health.router)
app.include_router(logs.router)
app.include_router(domain_policies.router)
app.include_router(agents.router)
app.include_router(terminal.router)
app.include_router(tenants.router)
app.include_router(ip_acls.router)
app.include_router(tokens.router)
