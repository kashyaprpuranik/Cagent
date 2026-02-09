from typing import Optional

from pydantic import BaseModel


class DomainEntry(BaseModel):
    domain: str
    alias: Optional[str] = None
    timeout: Optional[str] = None
    read_only: Optional[bool] = None
    rate_limit: Optional[dict] = None
    credential: Optional[dict] = None


class ConfigUpdate(BaseModel):
    domains: Optional[list[DomainEntry]] = None
    dns: Optional[dict] = None
    rate_limits: Optional[dict] = None
    mode: Optional[str] = None


class ContainerAction(BaseModel):
    action: str  # start, stop, restart


class SshTunnelConfig(BaseModel):
    frp_server_addr: str
    frp_server_port: int = 7000
    frp_auth_token: str
    stcp_proxy_name: str
    stcp_secret_key: Optional[str] = None  # Auto-generated if not provided


class SshTunnelStatus(BaseModel):
    enabled: bool
    connected: bool
    stcp_proxy_name: Optional[str] = None
    frp_server: Optional[str] = None
    container_status: Optional[str] = None
    stcp_secret_key: Optional[str] = None
