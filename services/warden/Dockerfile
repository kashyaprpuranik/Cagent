# =============================================================================
# Warden - Unified data plane service
# Multi-stage build: Node (frontend) + Python (backend)
# =============================================================================

# Stage 1: Build frontend (only in admin profile)
FROM node:20-alpine AS frontend-builder

RUN apk add --no-cache git

WORKDIR /app

# Copy workspace root package files
COPY package.json package-lock.json* ./

# Copy frontend package files
COPY services/warden/frontend/package.json services/warden/frontend/

# Install dependencies (workspace-aware)
RUN npm ci --workspace=services/warden/frontend --include-workspace-root

# Copy frontend source
COPY services/warden/frontend/ services/warden/frontend/

# Build
RUN cd services/warden/frontend && npm run build

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
    pydantic>=2.0.0 \
    psutil>=5.9.0

# Copy warden code
COPY services/warden/ /app/

# Copy built frontend (may not exist in managed-only builds)
COPY --from=frontend-builder /app/services/warden/frontend/dist ./frontend/dist

ENV PYTHONUNBUFFERED=1

EXPOSE 8080

CMD ["python", "-m", "uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8080"]
