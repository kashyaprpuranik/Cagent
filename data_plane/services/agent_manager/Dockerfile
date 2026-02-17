# =============================================================================
# Agent Manager - Unified data plane service
# Multi-stage build: Node (frontend) + Python (backend)
# =============================================================================

# Stage 1: Build frontend (only in admin profile)
FROM node:20-alpine AS frontend-builder

WORKDIR /app

# Copy workspace root package files
COPY package.json package-lock.json* ./

# Copy shared-ui package
COPY packages/shared-ui/ packages/shared-ui/

# Copy frontend package files
COPY data_plane/services/local_admin/frontend/package.json data_plane/services/local_admin/frontend/

# Install dependencies (workspace-aware)
RUN npm ci --workspace=data_plane/services/local_admin/frontend --workspace=packages/shared-ui --include-workspace-root

# Copy frontend source
COPY data_plane/services/local_admin/frontend/ data_plane/services/local_admin/frontend/

# Build
RUN cd data_plane/services/local_admin/frontend && npm run build

# Stage 2: Production image
FROM python:3.11-slim

WORKDIR /app

# Install Python dependencies
RUN pip install --no-cache-dir \
    fastapi==0.109.0 \
    "uvicorn[standard]==0.27.0" \
    docker==7.1.0 \
    "requests>=2.32.0,<3" \
    pyyaml==6.0.1 \
    websockets==12.0 \
    pydantic>=2.0.0

# Copy agent-manager code
COPY data_plane/services/agent_manager/ /app/

# Copy built frontend (may not exist in managed-only builds)
COPY --from=frontend-builder /app/data_plane/services/local_admin/frontend/dist ./frontend/dist

ENV PYTHONUNBUFFERED=1

EXPOSE 8080

CMD ["python", "-m", "uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8080"]
