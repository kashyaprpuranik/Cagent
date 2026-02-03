FROM python:3.11-slim

WORKDIR /app

# Install curl for healthcheck
RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*

# Install dependencies
RUN pip install --no-cache-dir \
    fastapi==0.109.0 \
    uvicorn[standard]==0.27.0 \
    sqlalchemy==2.0.25 \
    cryptography==42.0.0 \
    pydantic==2.5.3 \
    python-multipart==0.0.6 \
    psycopg2-binary==2.9.9 \
    httpx==0.26.0 \
    slowapi==0.1.9 \
    redis==5.0.1 \
    paramiko==3.4.0 \
    websockets==12.0

# Copy application
COPY main.py seed.py entrypoint.sh /app/

# Create non-root user and set permissions
RUN useradd -m -u 1000 appuser && \
    mkdir -p /app/data && \
    chmod +x /app/entrypoint.sh && \
    chown -R appuser:appuser /app

USER appuser

ENV PYTHONUNBUFFERED=1

EXPOSE 8000

CMD ["/app/entrypoint.sh"]
