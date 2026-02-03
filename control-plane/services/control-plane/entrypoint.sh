#!/bin/bash
set -e

# Generate ENCRYPTION_KEY if not provided
if [ -z "$ENCRYPTION_KEY" ]; then
    echo "ENCRYPTION_KEY not set, generating one for this session..."
    export ENCRYPTION_KEY=$(python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())")
    echo "WARNING: ENCRYPTION_KEY was auto-generated. Secrets will be lost on container restart!"
    echo "For production, set ENCRYPTION_KEY in your environment or .env file."
fi

# Run database migrations and seeding
echo "Running database migrations..."
python -c "
import os
import sys
sys.path.insert(0, '/app')

from sqlalchemy import text
from main import engine, SessionLocal, Base, AgentState

# Create tables if they don't exist
Base.metadata.create_all(bind=engine)

# Run migrations for new columns (idempotent)
with engine.connect() as conn:
    # Add stcp_secret_key column to agent_state if missing
    result = conn.execute(text(\"\"\"
        SELECT column_name FROM information_schema.columns
        WHERE table_name = 'agent_state' AND column_name = 'stcp_secret_key'
    \"\"\"))
    if not result.fetchone():
        print('Adding stcp_secret_key column to agent_state...')
        conn.execute(text('ALTER TABLE agent_state ADD COLUMN stcp_secret_key VARCHAR(256)'))
        conn.commit()

    # Add roles column to api_tokens if missing (RBAC)
    result = conn.execute(text(\"\"\"
        SELECT column_name FROM information_schema.columns
        WHERE table_name = 'api_tokens' AND column_name = 'roles'
    \"\"\"))
    if not result.fetchone():
        print('Adding roles column to api_tokens...')
        conn.execute(text(\"ALTER TABLE api_tokens ADD COLUMN roles VARCHAR(100) DEFAULT 'admin'\"))
        conn.commit()

    # Create terminal_sessions table if missing
    result = conn.execute(text(\"\"\"
        SELECT table_name FROM information_schema.tables
        WHERE table_name = 'terminal_sessions'
    \"\"\"))
    if not result.fetchone():
        print('Creating terminal_sessions table...')
        conn.execute(text('''
            CREATE TABLE terminal_sessions (
                id SERIAL PRIMARY KEY,
                session_id VARCHAR(36) UNIQUE NOT NULL,
                agent_id VARCHAR(100) NOT NULL,
                \"user\" VARCHAR(100) NOT NULL,
                started_at TIMESTAMP NOT NULL,
                ended_at TIMESTAMP,
                duration_seconds INTEGER,
                bytes_sent INTEGER DEFAULT 0,
                bytes_received INTEGER DEFAULT 0,
                client_ip VARCHAR(45)
            )
        '''))
        conn.execute(text('CREATE INDEX ix_terminal_sessions_agent_id ON terminal_sessions(agent_id)'))
        conn.commit()

print('Database migrations complete.')

# Check if seeding needed
db = SessionLocal()
try:
    agent_count = db.query(AgentState).count()
    if agent_count == 0:
        print('Database is empty, seeding...')
        db.close()
        # Import and run seeder
        from seed import seed_database
        seed_database(reset=False, show_token=True)
    else:
        print(f'Database already has {agent_count} agent(s), skipping seed.')
finally:
    db.close()
"

# Start the application
echo "Starting control plane API..."
exec uvicorn main:app --host 0.0.0.0 --port 8000
