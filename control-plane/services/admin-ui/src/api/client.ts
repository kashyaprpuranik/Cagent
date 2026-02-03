import type {
  HealthStatus,
  DataPlane,
  Secret,
  CreateSecretRequest,
  AllowlistEntry,
  CreateAllowlistEntryRequest,
  AuditLog,
  AuditLogFilters,
  PaginatedResponse,
  AgentStatus,
  AgentCommandResponse,
  RateLimit,
  CreateRateLimitRequest,
  UpdateRateLimitRequest,
  ApiToken,
  ApiTokenCreated,
  CreateApiTokenRequest,
  AgentApprovalResponse,
  Tenant,
  CreateTenantRequest,
  LogQueryResponse,
} from '../types/api';

const API_BASE = './api/v1';

class ApiError extends Error {
  constructor(
    public status: number,
    message: string
  ) {
    super(message);
    this.name = 'ApiError';
  }
}

function getAuthHeaders(): HeadersInit {
  const token = localStorage.getItem('api_token');
  const headers: HeadersInit = {
    'Content-Type': 'application/json',
  };
  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }
  return headers;
}

async function handleResponse<T>(response: Response): Promise<T> {
  if (response.status === 401 || response.status === 403) {
    localStorage.removeItem('api_token');
    window.location.href = '/login';
    throw new ApiError(response.status, 'Unauthorized');
  }

  if (!response.ok) {
    const error = await response.text();
    throw new ApiError(response.status, error || response.statusText);
  }

  const text = await response.text();
  if (!text) {
    return {} as T;
  }
  return JSON.parse(text);
}

export const api = {
  // Auth
  setToken: (token: string) => {
    localStorage.setItem('api_token', token);
  },

  getToken: () => {
    return localStorage.getItem('api_token');
  },

  clearToken: () => {
    localStorage.removeItem('api_token');
  },

  // Current user info
  getCurrentUser: async (): Promise<{
    token_type: string;
    agent_id: string | null;
    tenant_id: number | null;
    is_super_admin: boolean;
    roles: string[];
  }> => {
    const response = await fetch(`${API_BASE}/auth/me`, {
      headers: getAuthHeaders(),
    });
    return handleResponse(response);
  },

  // Health
  getHealth: async (): Promise<HealthStatus> => {
    const response = await fetch('./health', {
      headers: getAuthHeaders(),
    });
    return handleResponse<HealthStatus>(response);
  },

  // Data Planes (Agents)
  getDataPlanes: async (): Promise<DataPlane[]> => {
    const response = await fetch(`${API_BASE}/agents`, {
      headers: getAuthHeaders(),
    });
    return handleResponse<DataPlane[]>(response);
  },

  // Secrets
  getSecrets: async (): Promise<Secret[]> => {
    const response = await fetch(`${API_BASE}/secrets`, {
      headers: getAuthHeaders(),
    });
    return handleResponse<Secret[]>(response);
  },

  createSecret: async (data: CreateSecretRequest): Promise<Secret> => {
    const response = await fetch(`${API_BASE}/secrets`, {
      method: 'POST',
      headers: getAuthHeaders(),
      body: JSON.stringify(data),
    });
    return handleResponse<Secret>(response);
  },

  rotateSecret: async (name: string, newValue: string): Promise<Secret> => {
    const response = await fetch(
      `${API_BASE}/secrets/${encodeURIComponent(name)}/rotate`,
      {
        method: 'POST',
        headers: getAuthHeaders(),
        body: JSON.stringify({ new_value: newValue }),
      }
    );
    return handleResponse<Secret>(response);
  },

  deleteSecret: async (name: string): Promise<void> => {
    const response = await fetch(
      `${API_BASE}/secrets/${encodeURIComponent(name)}`,
      {
        method: 'DELETE',
        headers: getAuthHeaders(),
      }
    );
    return handleResponse<void>(response);
  },

  // Allowlist
  getAllowlist: async (type?: string): Promise<AllowlistEntry[]> => {
    const url = type
      ? `${API_BASE}/allowlist?entry_type=${type}`
      : `${API_BASE}/allowlist`;
    const response = await fetch(url, {
      headers: getAuthHeaders(),
    });
    return handleResponse<AllowlistEntry[]>(response);
  },

  addAllowlistEntry: async (
    data: CreateAllowlistEntryRequest
  ): Promise<AllowlistEntry> => {
    const response = await fetch(`${API_BASE}/allowlist`, {
      method: 'POST',
      headers: getAuthHeaders(),
      body: JSON.stringify(data),
    });
    return handleResponse<AllowlistEntry>(response);
  },

  updateAllowlistEntry: async (
    id: number,
    data: Partial<CreateAllowlistEntryRequest>
  ): Promise<AllowlistEntry> => {
    const response = await fetch(`${API_BASE}/allowlist/${id}`, {
      method: 'PATCH',
      headers: getAuthHeaders(),
      body: JSON.stringify(data),
    });
    return handleResponse<AllowlistEntry>(response);
  },

  deleteAllowlistEntry: async (id: number): Promise<void> => {
    const response = await fetch(`${API_BASE}/allowlist/${id}`, {
      method: 'DELETE',
      headers: getAuthHeaders(),
    });
    return handleResponse<void>(response);
  },

  // Audit Logs (Admin/CP logs from Postgres)
  getAuditLogs: async (
    params: AuditLogFilters = {}
  ): Promise<PaginatedResponse<AuditLog>> => {
    const searchParams = new URLSearchParams();
    Object.entries(params).forEach(([key, value]) => {
      if (value !== undefined && value !== '') {
        searchParams.append(key, String(value));
      }
    });
    const response = await fetch(`${API_BASE}/audit-logs?${searchParams}`, {
      headers: getAuthHeaders(),
    });
    return handleResponse<PaginatedResponse<AuditLog>>(response);
  },

  // Agent Logs (DP logs from OpenObserve)
  queryAgentLogs: async (params: {
    query?: string;
    source?: string;
    agent_id?: string;
    limit?: number;
    start?: string;
    end?: string;
  }): Promise<LogQueryResponse> => {
    const searchParams = new URLSearchParams();
    if (params.query) searchParams.append('query', params.query);
    if (params.source) searchParams.append('source', params.source);
    if (params.agent_id) searchParams.append('agent_id', params.agent_id);
    if (params.limit) searchParams.append('limit', String(params.limit));
    if (params.start) searchParams.append('start', params.start);
    if (params.end) searchParams.append('end', params.end);
    const response = await fetch(`${API_BASE}/logs/query?${searchParams}`, {
      headers: getAuthHeaders(),
    });
    return handleResponse<LogQueryResponse>(response);
  },

  // Agent Management (per data plane)
  getAgentStatus: async (agentId: string): Promise<AgentStatus> => {
    const response = await fetch(`${API_BASE}/agents/${encodeURIComponent(agentId)}/status`, {
      headers: getAuthHeaders(),
    });
    return handleResponse<AgentStatus>(response);
  },

  wipeAgent: async (agentId: string, wipeWorkspace: boolean = false): Promise<AgentCommandResponse> => {
    const response = await fetch(`${API_BASE}/agents/${encodeURIComponent(agentId)}/wipe`, {
      method: 'POST',
      headers: getAuthHeaders(),
      body: JSON.stringify({ wipe_workspace: wipeWorkspace }),
    });
    return handleResponse<AgentCommandResponse>(response);
  },

  restartAgent: async (agentId: string): Promise<AgentCommandResponse> => {
    const response = await fetch(`${API_BASE}/agents/${encodeURIComponent(agentId)}/restart`, {
      method: 'POST',
      headers: getAuthHeaders(),
    });
    return handleResponse<AgentCommandResponse>(response);
  },

  stopAgent: async (agentId: string): Promise<AgentCommandResponse> => {
    const response = await fetch(`${API_BASE}/agents/${encodeURIComponent(agentId)}/stop`, {
      method: 'POST',
      headers: getAuthHeaders(),
    });
    return handleResponse<AgentCommandResponse>(response);
  },

  startAgent: async (agentId: string): Promise<AgentCommandResponse> => {
    const response = await fetch(`${API_BASE}/agents/${encodeURIComponent(agentId)}/start`, {
      method: 'POST',
      headers: getAuthHeaders(),
    });
    return handleResponse<AgentCommandResponse>(response);
  },

  // Rate Limits
  getRateLimits: async (): Promise<RateLimit[]> => {
    const response = await fetch(`${API_BASE}/rate-limits`, {
      headers: getAuthHeaders(),
    });
    return handleResponse<RateLimit[]>(response);
  },

  createRateLimit: async (data: CreateRateLimitRequest): Promise<RateLimit> => {
    const response = await fetch(`${API_BASE}/rate-limits`, {
      method: 'POST',
      headers: getAuthHeaders(),
      body: JSON.stringify(data),
    });
    return handleResponse<RateLimit>(response);
  },

  updateRateLimit: async (id: number, data: UpdateRateLimitRequest): Promise<RateLimit> => {
    const response = await fetch(`${API_BASE}/rate-limits/${id}`, {
      method: 'PUT',
      headers: getAuthHeaders(),
      body: JSON.stringify(data),
    });
    return handleResponse<RateLimit>(response);
  },

  deleteRateLimit: async (id: number): Promise<void> => {
    const response = await fetch(`${API_BASE}/rate-limits/${id}`, {
      method: 'DELETE',
      headers: getAuthHeaders(),
    });
    return handleResponse<void>(response);
  },

  // API Tokens
  getTokens: async (): Promise<ApiToken[]> => {
    const response = await fetch(`${API_BASE}/tokens`, {
      headers: getAuthHeaders(),
    });
    return handleResponse<ApiToken[]>(response);
  },

  createToken: async (data: CreateApiTokenRequest): Promise<ApiTokenCreated> => {
    const response = await fetch(`${API_BASE}/tokens`, {
      method: 'POST',
      headers: getAuthHeaders(),
      body: JSON.stringify(data),
    });
    return handleResponse<ApiTokenCreated>(response);
  },

  deleteToken: async (id: number): Promise<void> => {
    const response = await fetch(`${API_BASE}/tokens/${id}`, {
      method: 'DELETE',
      headers: getAuthHeaders(),
    });
    return handleResponse<void>(response);
  },

  updateToken: async (id: number, enabled: boolean): Promise<ApiToken> => {
    const response = await fetch(`${API_BASE}/tokens/${id}?enabled=${enabled}`, {
      method: 'PATCH',
      headers: getAuthHeaders(),
    });
    return handleResponse<ApiToken>(response);
  },

  // Agent Approval
  approveAgent: async (agentId: string): Promise<AgentApprovalResponse> => {
    const response = await fetch(`${API_BASE}/agents/${encodeURIComponent(agentId)}/approve`, {
      method: 'POST',
      headers: getAuthHeaders(),
    });
    return handleResponse<AgentApprovalResponse>(response);
  },

  rejectAgent: async (agentId: string): Promise<AgentApprovalResponse> => {
    const response = await fetch(`${API_BASE}/agents/${encodeURIComponent(agentId)}/reject`, {
      method: 'POST',
      headers: getAuthHeaders(),
    });
    return handleResponse<AgentApprovalResponse>(response);
  },

  revokeAgent: async (agentId: string): Promise<AgentApprovalResponse> => {
    const response = await fetch(`${API_BASE}/agents/${encodeURIComponent(agentId)}/revoke`, {
      method: 'POST',
      headers: getAuthHeaders(),
    });
    return handleResponse<AgentApprovalResponse>(response);
  },

  // Tenants
  getTenants: async (): Promise<Tenant[]> => {
    const response = await fetch(`${API_BASE}/tenants`, {
      headers: getAuthHeaders(),
    });
    return handleResponse<Tenant[]>(response);
  },

  createTenant: async (data: CreateTenantRequest): Promise<Tenant> => {
    const response = await fetch(`${API_BASE}/tenants`, {
      method: 'POST',
      headers: getAuthHeaders(),
      body: JSON.stringify(data),
    });
    return handleResponse<Tenant>(response);
  },

  deleteTenant: async (id: number): Promise<void> => {
    const response = await fetch(`${API_BASE}/tenants/${id}`, {
      method: 'DELETE',
      headers: getAuthHeaders(),
    });
    return handleResponse<void>(response);
  },
};

export { ApiError };
