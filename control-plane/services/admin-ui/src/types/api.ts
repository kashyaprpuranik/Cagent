export interface HealthStatus {
  status: string;
  version?: string;
  uptime?: number;
}

export interface DataPlane {
  agent_id: string;
  status: string;
  online: boolean;
  approved: boolean;
  tenant_id?: number;
  last_heartbeat?: string;
}

export interface Secret {
  id: number;
  name: string;
  domain_pattern?: string;
  alias?: string;  // e.g., "openai" -> openai.devbox.local
  header_name?: string;
  header_format?: string;
  description?: string;
  agent_id?: string;
  created_at: string;
  last_rotated?: string;
  rotation_days: number;
  needs_rotation: boolean;
}

export interface CreateSecretRequest {
  name: string;
  value: string;
  domain_pattern: string;
  alias?: string;  // e.g., "openai" -> openai.devbox.local
  header_name?: string;
  header_format?: string;
  description?: string;
  rotation_days?: number;
  agent_id?: string;
}

export interface AllowlistEntry {
  id: number;
  entry_type: 'domain' | 'ip' | 'command';
  value: string;
  enabled: boolean;
  description?: string;
  agent_id?: string;
  created_at: string;
  created_by?: string;
}

export interface CreateAllowlistEntryRequest {
  entry_type: 'domain' | 'ip' | 'command';
  value: string;
  description?: string;
  enabled?: boolean;
  agent_id?: string;
}

export interface AuditLog {
  id: string;
  timestamp: string;
  event_type: string;
  user?: string;
  resource?: string;
  action: string;
  severity: 'info' | 'warning' | 'error' | 'critical';
  details?: Record<string, unknown>;
  ip_address?: string;
}

export interface AuditLogFilters {
  event_type?: string;
  user?: string;
  severity?: string;
  start_date?: string;
  end_date?: string;
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

export interface RateLimit {
  id: number;
  domain_pattern: string;
  requests_per_minute: number;
  burst_size: number;
  description?: string;
  agent_id?: string;
  enabled: boolean;
  created_at: string;
  updated_at: string;
}

export interface CreateRateLimitRequest {
  domain_pattern: string;
  requests_per_minute?: number;
  burst_size?: number;
  description?: string;
  agent_id?: string;
}

export interface UpdateRateLimitRequest {
  requests_per_minute?: number;
  burst_size?: number;
  description?: string;
  enabled?: boolean;
}

// API Tokens
export interface ApiToken {
  id: number;
  name: string;
  token_type: 'admin' | 'agent';
  agent_id?: string;
  tenant_id?: number;
  is_super_admin: boolean;
  created_at: string;
  expires_at?: string;
  last_used_at?: string;
  enabled: boolean;
}

export interface ApiTokenCreated extends Omit<ApiToken, 'last_used_at' | 'enabled'> {
  token: string;  // Only returned once on creation!
}

export interface CreateApiTokenRequest {
  name: string;
  token_type: 'admin' | 'agent';
  agent_id?: string;
  tenant_id?: number;
  is_super_admin?: boolean;
  expires_in_days?: number;
}

export interface AgentApprovalResponse {
  status: string;
  agent_id: string;
  approved_at?: string;
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
