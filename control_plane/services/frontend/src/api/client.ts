import type {
  HealthStatus,
  DataPlane,
  AuditTrailEntry,
  AuditTrailFilters,
  PaginatedResponse,
  AgentStatus,
  AgentCommandResponse,
  ApiToken,
  ApiTokenCreated,
  CreateApiTokenRequest,
  Tenant,
  CreateTenantRequest,
  TenantIpAcl,
  CreateTenantIpAclRequest,
  UpdateTenantIpAclRequest,
  LogQueryResponse,
  DomainPolicy,
  CreateDomainPolicyRequest,
  UpdateDomainPolicyRequest,
  DomainPolicyCredential,
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
  // Only logout on 401 (Unauthorized), not 403 (Forbidden)
  // 401 = not authenticated, 403 = authenticated but lacking permission
  if (response.status === 401) {
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
    tenant_name: string | null;
    tenant_slug: string | null;
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
  getDataPlanes: async (tenantId?: number): Promise<DataPlane[]> => {
    const url = tenantId !== undefined
      ? `${API_BASE}/agents?tenant_id=${tenantId}`
      : `${API_BASE}/agents`;
    const response = await fetch(url, {
      headers: getAuthHeaders(),
    });
    return handleResponse<DataPlane[]>(response);
  },

  // Audit Trail (transactional entries from Postgres)
  getAuditTrail: async (
    params: AuditTrailFilters = {}
  ): Promise<PaginatedResponse<AuditTrailEntry>> => {
    const searchParams = new URLSearchParams();
    Object.entries(params).forEach(([key, value]) => {
      if (value !== undefined && value !== '') {
        searchParams.append(key, String(value));
      }
    });
    const response = await fetch(`${API_BASE}/audit-trail?${searchParams}`, {
      headers: getAuthHeaders(),
    });
    return handleResponse<PaginatedResponse<AuditTrailEntry>>(response);
  },

  // Agent Logs (DP logs from OpenObserve)
  queryAgentLogs: async (params: {
    query?: string;
    source?: string;
    agent_id?: string;
    tenant_id?: number;
    limit?: number;
    start?: string;
    end?: string;
  }): Promise<LogQueryResponse> => {
    const searchParams = new URLSearchParams();
    if (params.query) searchParams.append('query', params.query);
    if (params.source) searchParams.append('source', params.source);
    if (params.agent_id) searchParams.append('agent_id', params.agent_id);
    if (params.tenant_id !== undefined) searchParams.append('tenant_id', String(params.tenant_id));
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

  // API Tokens
  getTokens: async (tenantId?: number): Promise<ApiToken[]> => {
    const url = tenantId !== undefined
      ? `${API_BASE}/tokens?tenant_id=${tenantId}`
      : `${API_BASE}/tokens`;
    const response = await fetch(url, {
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

  // IP ACLs
  getTenantIpAcls: async (tenantId: number): Promise<TenantIpAcl[]> => {
    const response = await fetch(`${API_BASE}/tenants/${tenantId}/ip-acls`, {
      headers: getAuthHeaders(),
    });
    return handleResponse<TenantIpAcl[]>(response);
  },

  createTenantIpAcl: async (
    tenantId: number,
    data: CreateTenantIpAclRequest
  ): Promise<TenantIpAcl> => {
    const response = await fetch(`${API_BASE}/tenants/${tenantId}/ip-acls`, {
      method: 'POST',
      headers: getAuthHeaders(),
      body: JSON.stringify(data),
    });
    return handleResponse<TenantIpAcl>(response);
  },

  updateTenantIpAcl: async (
    tenantId: number,
    aclId: number,
    data: UpdateTenantIpAclRequest
  ): Promise<TenantIpAcl> => {
    const response = await fetch(
      `${API_BASE}/tenants/${tenantId}/ip-acls/${aclId}`,
      {
        method: 'PATCH',
        headers: getAuthHeaders(),
        body: JSON.stringify(data),
      }
    );
    return handleResponse<TenantIpAcl>(response);
  },

  deleteTenantIpAcl: async (tenantId: number, aclId: number): Promise<void> => {
    const response = await fetch(
      `${API_BASE}/tenants/${tenantId}/ip-acls/${aclId}`,
      {
        method: 'DELETE',
        headers: getAuthHeaders(),
      }
    );
    return handleResponse<void>(response);
  },

  // Domain Policies
  getDomainPolicies: async (params?: { agentId?: string; tenantId?: number }): Promise<DomainPolicy[]> => {
    const searchParams = new URLSearchParams();
    if (params?.agentId) {
      searchParams.append('agent_id', params.agentId);
    }
    if (params?.tenantId !== undefined) {
      searchParams.append('tenant_id', String(params.tenantId));
    }
    const queryString = searchParams.toString();
    const url = queryString ? `${API_BASE}/domain-policies?${queryString}` : `${API_BASE}/domain-policies`;
    const response = await fetch(url, {
      headers: getAuthHeaders(),
    });
    return handleResponse<DomainPolicy[]>(response);
  },

  createDomainPolicy: async (data: CreateDomainPolicyRequest, tenantId?: number): Promise<DomainPolicy> => {
    const url = tenantId !== undefined
      ? `${API_BASE}/domain-policies?tenant_id=${tenantId}`
      : `${API_BASE}/domain-policies`;
    const response = await fetch(url, {
      method: 'POST',
      headers: getAuthHeaders(),
      body: JSON.stringify(data),
    });
    return handleResponse<DomainPolicy>(response);
  },

  updateDomainPolicy: async (id: number, data: UpdateDomainPolicyRequest): Promise<DomainPolicy> => {
    const response = await fetch(`${API_BASE}/domain-policies/${id}`, {
      method: 'PUT',
      headers: getAuthHeaders(),
      body: JSON.stringify(data),
    });
    return handleResponse<DomainPolicy>(response);
  },

  deleteDomainPolicy: async (id: number): Promise<void> => {
    const response = await fetch(`${API_BASE}/domain-policies/${id}`, {
      method: 'DELETE',
      headers: getAuthHeaders(),
    });
    return handleResponse<void>(response);
  },

  // Terminal Tickets
  getTerminalTicket: async (agentId: string): Promise<{ ticket: string; expires_in_seconds: number }> => {
    const response = await fetch(`${API_BASE}/terminal/${encodeURIComponent(agentId)}/ticket`, {
      method: 'POST',
      headers: getAuthHeaders(),
    });
    return handleResponse<{ ticket: string; expires_in_seconds: number }>(response);
  },

  rotateDomainPolicyCredential: async (id: number, credential: DomainPolicyCredential): Promise<DomainPolicy> => {
    const response = await fetch(`${API_BASE}/domain-policies/${id}/rotate-credential`, {
      method: 'POST',
      headers: getAuthHeaders(),
      body: JSON.stringify(credential),
    });
    return handleResponse<DomainPolicy>(response);
  },
};

export { ApiError };
