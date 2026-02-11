const API_BASE = '/api';

async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, {
    headers: {
      'Content-Type': 'application/json',
      ...options?.headers,
    },
    ...options,
  });

  if (!response.ok) {
    const error = await response.json().catch(() => ({ detail: response.statusText }));
    throw new Error(error.detail || 'Request failed');
  }

  return response.json();
}

// Health & Info
export const getHealth = () => request<{ status: string }>('/health');
export const getInfo = () => request<{
  mode: string;
  config_path: string;
  features?: string[];
  containers: Record<string, string>;
}>('/info');

export interface HealthCheck {
  status: 'healthy' | 'unhealthy' | 'missing' | 'error';
  container_status?: string;
  uptime?: string;
  error?: string;
  reason?: string;
  test?: string;
}

export interface DetailedHealth {
  status: 'healthy' | 'degraded';
  timestamp: string;
  checks: Record<string, HealthCheck>;
}

export const getDetailedHealth = () => request<DetailedHealth>('/health/detailed');

// Terminal
export const createTerminal = (containerName: string): WebSocket => {
  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  const host = window.location.host;
  return new WebSocket(`${protocol}//${host}/api/terminal/${containerName}`);
};

// Config
export interface DomainEntry {
  domain: string;
  alias?: string;
  timeout?: string;
  read_only?: boolean;
  rate_limit?: { requests_per_minute: number; burst_size: number };
  credential?: { header: string; format: string; env: string };
}

export interface EmailCredential {
  client_id_env?: string;
  client_secret_env?: string;
  refresh_token_env?: string;
  password_env?: string;
}

export interface EmailPolicy {
  allowed_recipients?: string[];
  allowed_senders?: string[];
  sends_per_hour?: number;
  reads_per_hour?: number;
}

export interface EmailAccount {
  name: string;
  provider: 'gmail' | 'outlook' | 'generic';
  email: string;
  imap_server?: string;
  imap_port?: number;
  smtp_server?: string;
  smtp_port?: number;
  credential?: EmailCredential;
  policy?: EmailPolicy;
}

export interface Config {
  mode?: string;
  dns?: { upstream: string[]; cache_ttl: number };
  rate_limits?: { default: { requests_per_minute: number; burst_size: number } };
  domains?: DomainEntry[];
  email?: { accounts?: EmailAccount[] };
  internal_services?: string[];
}

export interface ConfigResponse {
  config: Config;
  raw: string;
  path: string;
  modified: string;
  read_only: boolean;
}

export const getConfig = () => request<ConfigResponse>('/config');
export const updateConfigRaw = (content: string) =>
  request<{ status: string }>('/config/raw', {
    method: 'PUT',
    body: JSON.stringify({ content }),
  });
export const reloadConfig = () =>
  request<{ status: string; results: Record<string, string> }>('/config/reload', {
    method: 'POST',
  });

// Containers
export interface ContainerInfo {
  name: string;
  status: string;
  id?: string;
  image?: string;
  created?: string;
  started_at?: string;
  cpu_percent?: number;
  memory_mb?: number;
  memory_limit_mb?: number;
  error?: string;
}

export const getContainers = () =>
  request<{ containers: Record<string, ContainerInfo> }>('/containers');
export const getContainer = (name: string) => request<ContainerInfo>(`/containers/${name}`);
export const controlContainer = (name: string, action: 'start' | 'stop' | 'restart') =>
  request<{ status: string }>(`/containers/${name}`, {
    method: 'POST',
    body: JSON.stringify({ action }),
  });

// Logs
export interface LogsResponse {
  container: string;
  lines: string[];
  count: number;
}

export const getContainerLogs = (name: string, tail = 100) =>
  request<LogsResponse>(`/containers/${name}/logs?tail=${tail}`);

export const createLogStream = (name: string): WebSocket => {
  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  const host = window.location.host;
  return new WebSocket(`${protocol}//${host}/api/containers/${name}/logs/stream`);
};

// SSH Tunnel
export interface SshTunnelStatus {
  enabled: boolean;
  connected: boolean;
  stcp_proxy_name?: string;
  frp_server?: string;
  frp_server_port?: string;
  container_status?: string;
  stcp_secret_key?: string;
  configured: boolean;
}

export interface SshTunnelConfig {
  frp_server_addr: string;
  frp_server_port: number;
  frp_auth_token: string;
  stcp_proxy_name?: string;
  stcp_secret_key?: string;
}

export interface SshConnectInfo {
  stcp_proxy_name: string;
  frp_server: string;
  frp_port: string;
  stcp_secret_key: string;
  ssh_command: string;
  visitor_config: string;
}

// Analytics
export interface BlockedDomainEntry {
  domain: string;
  count: number;
  last_seen: string;
}

export interface BlockedDomainsResponse {
  blocked_domains: BlockedDomainEntry[];
  window_hours: number;
}

export const getBlockedDomains = (hours?: number) =>
  request<BlockedDomainsResponse>(`/analytics/blocked-domains?hours=${hours || 1}`);

export const getSshTunnelStatus = () => request<SshTunnelStatus>('/ssh-tunnel');

export const generateStcpKey = () =>
  request<{ stcp_secret_key: string }>('/ssh-tunnel/generate-key', { method: 'POST' });

export const configureSshTunnel = (config: SshTunnelConfig) =>
  request<{ status: string; stcp_proxy_name: string; stcp_secret_key: string; message: string }>(
    '/ssh-tunnel/configure',
    {
      method: 'POST',
      body: JSON.stringify(config),
    }
  );

export const startSshTunnel = () =>
  request<{ status: string; message: string }>('/ssh-tunnel/start', { method: 'POST' });

export const stopSshTunnel = () =>
  request<{ status: string; message: string }>('/ssh-tunnel/stop', { method: 'POST' });

export const getSshConnectInfo = () => request<SshConnectInfo>('/ssh-tunnel/connect-info');
