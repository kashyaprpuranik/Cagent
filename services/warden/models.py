from typing import Optional

from pydantic import BaseModel


class DomainEntry(BaseModel):
    domain: str
    alias: Optional[str] = None
    timeout: Optional[str] = None
    read_only: Optional[bool] = None
    rate_limit: Optional[dict] = None
    credential: Optional[dict] = None


class EmailCredential(BaseModel):
    client_id_env: Optional[str] = None
    client_secret_env: Optional[str] = None
    refresh_token_env: Optional[str] = None
    password_env: Optional[str] = None


class EmailPolicy(BaseModel):
    allowed_recipients: Optional[list[str]] = None
    allowed_senders: Optional[list[str]] = None
    sends_per_hour: Optional[int] = None
    reads_per_hour: Optional[int] = None


class EmailAccount(BaseModel):
    name: str
    provider: str  # gmail, outlook, generic
    email: str
    imap_server: Optional[str] = None
    imap_port: Optional[int] = None
    smtp_server: Optional[str] = None
    smtp_port: Optional[int] = None
    credential: Optional[EmailCredential] = None
    policy: Optional[EmailPolicy] = None


class ConfigUpdate(BaseModel):
    domains: Optional[list[DomainEntry]] = None
    dns: Optional[dict] = None
    rate_limits: Optional[dict] = None
    mode: Optional[str] = None
    email: Optional[dict] = None
    security: Optional[dict] = None


class ContainerAction(BaseModel):
    action: str  # start, stop, restart
