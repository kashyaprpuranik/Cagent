export interface HealthStatus {
  status: string;
  version?: string;
  uptime?: number;
}

export interface DataPlane {
  agent_id: string;
  status: string;
  online: boolean;
  tenant_id?: number;
  last_heartbeat?: string;
}

export interface AuditTrailEntry {
  id: number;
  timestamp: string;
  event_type: string;
  user?: string;
  container_id?: string;
  action: string;
  severity: string;
  details?: string;
}

export interface AuditTrailFilters {
  tenant_id?: number;
  event_type?: string;
  search?: string;
  user?: string;
  severity?: string;
  start_time?: string;
  end_time?: string;
  limit?: number;
  offset?: number;
}

export interface ApiResponse<T> {
  data: T;
  message?: string;
  error?: string;
}

export interface PaginatedResponse<T> {
  items: T[];
  total: number;
  limit: number;
  offset: number;
}

export interface AgentStatus {
  agent_id: string;
  status: string;
  container_id?: string;
  uptime_seconds?: number;
  cpu_percent?: number;
  memory_mb?: number;
  memory_limit_mb?: number;
  last_heartbeat?: string;
  pending_command?: string;
  last_command?: string;
  last_command_result?: string;
  last_command_at?: string;
  online: boolean;
}

export interface AgentCommandResponse {
  status: string;
  command: string;
  message: string;
}

// API Tokens
export interface ApiToken {
  id: number;
  name: string;
  token_type: 'admin' | 'agent';
  agent_id?: string;
  tenant_id?: number;
  is_super_admin: boolean;
  roles?: string;  // Comma-separated: "admin", "developer", "admin,developer"
  created_at: string;
  expires_at?: string;
  last_used_at?: string;
  enabled: boolean;
}

export interface ApiTokenCreated extends Omit<ApiToken, 'last_used_at' | 'enabled'> {
  token: string;  // Only returned once on creation!
  roles: string;
}

export interface CreateApiTokenRequest {
  name: string;
  token_type: 'admin' | 'agent';
  agent_id?: string;
  tenant_id?: number;
  is_super_admin?: boolean;
  roles?: string;  // Comma-separated: "admin", "developer", "admin,developer"
  expires_in_days?: number;
}

// Tenants
export interface Tenant {
  id: number;
  name: string;
  slug: string;
  created_at: string;
  agent_count: number;
}

export interface CreateTenantRequest {
  name: string;
  slug: string;
}

// IP ACLs
export interface TenantIpAcl {
  id: number;
  tenant_id: number;
  cidr: string;
  description?: string;
  enabled: boolean;
  created_at: string;
  created_by?: string;
  updated_at: string;
}

export interface CreateTenantIpAclRequest {
  cidr: string;
  description?: string;
}

export interface UpdateTenantIpAclRequest {
  description?: string;
  enabled?: boolean;
}

// Log query response types (OpenObserve)
export interface LogQueryResponse {
  status: string;
  data: {
    resultType: string;
    result: LogHit[];
  };
}

// Terminal session types
export interface TerminalSession {
  session_id: string;
  agent_id: string;
  user: string;
  started_at: string;
  ended_at?: string;
  duration_seconds?: number;
  bytes_sent: number;
  bytes_received: number;
}

export interface STCPConfig {
  server_addr: string;
  server_port: number;
  proxy_name: string;
  secret_key: string;
}

export interface STCPSecretResponse {
  agent_id: string;
  secret_key: string;
  message: string;
}

export interface LogHit {
  _timestamp: number;
  message: string;
  source: string;
  agent_id: string;
  log_type: string;
  level?: string;
  method?: string;
  path?: string;
  upstream_host?: string;
  response_code?: number;
  duration_ms?: number;
  syscall?: string;
  syscall_result?: string;
  [key: string]: unknown;
}

// Email Policies - API route: /email-policies
export interface EmailPolicy {
  id: number;
  name: string;
  provider: 'gmail' | 'outlook' | 'generic';
  email: string;
  enabled: boolean;
  agent_id?: string;
  imap_server?: string;
  imap_port?: number;
  smtp_server?: string;
  smtp_port?: number;
  allowed_recipients: string[];
  allowed_senders: string[];
  sends_per_hour?: number;
  reads_per_hour?: number;
  has_credential: boolean;
  credential_type?: string;
  created_at: string;
  updated_at: string;
}

export interface EmailPolicyCredential {
  client_id?: string;
  client_secret?: string;
  refresh_token?: string;
  password?: string;
}

export interface CreateEmailPolicyRequest {
  name: string;
  provider: 'gmail' | 'outlook' | 'generic';
  email: string;
  agent_id?: string;
  imap_server?: string;
  imap_port?: number;
  smtp_server?: string;
  smtp_port?: number;
  allowed_recipients?: string[];
  allowed_senders?: string[];
  sends_per_hour?: number;
  reads_per_hour?: number;
  credential?: EmailPolicyCredential;
}

export interface UpdateEmailPolicyRequest {
  enabled?: boolean;
  imap_server?: string;
  imap_port?: number;
  smtp_server?: string;
  smtp_port?: number;
  allowed_recipients?: string[];
  allowed_senders?: string[];
  sends_per_hour?: number;
  reads_per_hour?: number;
  credential?: EmailPolicyCredential;
  clear_credential?: boolean;
}

// Egress Policies (Unified) - API route: /domain-policies
export interface DomainPolicy {
  id: number;
  domain: string;
  alias?: string;
  description?: string;
  enabled: boolean;
  agent_id?: string;
  allowed_paths: string[];
  requests_per_minute?: number;
  burst_size?: number;
  bytes_per_hour?: number;
  timeout?: string;
  read_only?: boolean;
  expires_at?: string;
  has_credential: boolean;
  credential_header?: string;
  credential_format?: string;
  credential_rotated_at?: string;
  created_at: string;
  updated_at: string;
}

export interface DomainPolicyCredential {
  header: string;
  format: string;
  value: string;
}

export interface CreateDomainPolicyRequest {
  domain: string;
  alias?: string;
  description?: string;
  agent_id?: string;
  allowed_paths?: string[];
  requests_per_minute?: number;
  burst_size?: number;
  bytes_per_hour?: number;
  timeout?: string;
  read_only?: boolean;
  expires_at?: string;
  credential?: DomainPolicyCredential;
}

export interface UpdateDomainPolicyRequest {
  alias?: string;
  description?: string;
  enabled?: boolean;
  allowed_paths?: string[];
  requests_per_minute?: number;
  burst_size?: number;
  bytes_per_hour?: number;
  timeout?: string;
  read_only?: boolean;
  credential?: DomainPolicyCredential;
  clear_credential?: boolean;
}
