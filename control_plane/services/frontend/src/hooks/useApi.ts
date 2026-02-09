import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { api } from '../api/client';
import type {
  AuditTrailFilters,
  CreateApiTokenRequest,
  CreateTenantRequest,
  CreateTenantIpAclRequest,
  UpdateTenantIpAclRequest,
  CreateDomainPolicyRequest,
  UpdateDomainPolicyRequest,
  DomainPolicyCredential,
} from '../types/api';

// Health
export function useHealth() {
  return useQuery({
    queryKey: ['health'],
    queryFn: api.getHealth,
    refetchInterval: 30000,
  });
}

// Data Planes / Agents
export function useDataPlanes(tenantId?: number | null) {
  return useQuery({
    queryKey: ['dataPlanes', tenantId],
    queryFn: () => api.getDataPlanes(tenantId ?? undefined),
    refetchInterval: 10000,
    enabled: tenantId !== null, // Wait for tenant to be set if using tenant filter
  });
}

// Alias for useDataPlanes - for use in forms/dropdowns
export const useAgents = useDataPlanes;

// Audit Trail
export function useAuditTrail(filters: AuditTrailFilters = {}) {
  return useQuery({
    queryKey: ['auditTrail', filters],
    queryFn: () => api.getAuditTrail(filters),
  });
}

// Agent Management (per data plane)
export function useAgentStatus(agentId: string | null) {
  return useQuery({
    queryKey: ['agentStatus', agentId],
    queryFn: () => api.getAgentStatus(agentId!),
    enabled: !!agentId,
    refetchInterval: 10000,
  });
}

export function useWipeAgent() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ agentId, wipeWorkspace }: { agentId: string; wipeWorkspace: boolean }) =>
      api.wipeAgent(agentId, wipeWorkspace),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['agentStatus'] });
      queryClient.invalidateQueries({ queryKey: ['dataPlanes'] });
    },
  });
}

export function useRestartAgent() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (agentId: string) => api.restartAgent(agentId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['agentStatus'] });
      queryClient.invalidateQueries({ queryKey: ['dataPlanes'] });
    },
  });
}

export function useStopAgent() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (agentId: string) => api.stopAgent(agentId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['agentStatus'] });
      queryClient.invalidateQueries({ queryKey: ['dataPlanes'] });
    },
  });
}

export function useStartAgent() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (agentId: string) => api.startAgent(agentId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['agentStatus'] });
      queryClient.invalidateQueries({ queryKey: ['dataPlanes'] });
    },
  });
}

// API Tokens
export function useTokens(tenantId?: number | null) {
  return useQuery({
    queryKey: ['tokens', tenantId],
    queryFn: () => api.getTokens(tenantId ?? undefined),
    enabled: tenantId !== null, // Wait for tenant to be set if using tenant filter
  });
}

export function useCreateToken() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (data: CreateApiTokenRequest) => api.createToken(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['tokens'] });
    },
  });
}

export function useDeleteToken() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (id: number) => api.deleteToken(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['tokens'] });
    },
  });
}

export function useUpdateToken() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ id, enabled }: { id: number; enabled: boolean }) =>
      api.updateToken(id, enabled),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['tokens'] });
    },
  });
}

// Tenants
export function useTenants(enabled: boolean = true) {
  return useQuery({
    queryKey: ['tenants'],
    queryFn: api.getTenants,
    enabled,
  });
}

export function useCreateTenant() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (data: CreateTenantRequest) => api.createTenant(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['tenants'] });
    },
  });
}

export function useDeleteTenant() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (id: number) => api.deleteTenant(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['tenants'] });
    },
  });
}

// IP ACLs
export function useTenantIpAcls(tenantId: number | null) {
  return useQuery({
    queryKey: ['tenantIpAcls', tenantId],
    queryFn: () => api.getTenantIpAcls(tenantId!),
    enabled: !!tenantId,
  });
}

export function useCreateTenantIpAcl() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({
      tenantId,
      data,
    }: {
      tenantId: number;
      data: CreateTenantIpAclRequest;
    }) => api.createTenantIpAcl(tenantId, data),
    onSuccess: (_, { tenantId }) => {
      queryClient.invalidateQueries({ queryKey: ['tenantIpAcls', tenantId] });
    },
  });
}

export function useUpdateTenantIpAcl() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({
      tenantId,
      aclId,
      data,
    }: {
      tenantId: number;
      aclId: number;
      data: UpdateTenantIpAclRequest;
    }) => api.updateTenantIpAcl(tenantId, aclId, data),
    onSuccess: (_, { tenantId }) => {
      queryClient.invalidateQueries({ queryKey: ['tenantIpAcls', tenantId] });
    },
  });
}

export function useDeleteTenantIpAcl() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ tenantId, aclId }: { tenantId: number; aclId: number }) =>
      api.deleteTenantIpAcl(tenantId, aclId),
    onSuccess: (_, { tenantId }) => {
      queryClient.invalidateQueries({ queryKey: ['tenantIpAcls', tenantId] });
    },
  });
}

// Domain Policies
export function useDomainPolicies(params?: { agentId?: string; tenantId?: number | null }) {
  return useQuery({
    queryKey: ['domainPolicies', params?.agentId, params?.tenantId],
    queryFn: () => api.getDomainPolicies({
      agentId: params?.agentId,
      tenantId: params?.tenantId ?? undefined,
    }),
    enabled: params?.tenantId !== null, // Wait for tenant to be set if using tenant filter
  });
}

export function useCreateDomainPolicy() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ data, tenantId }: { data: CreateDomainPolicyRequest; tenantId?: number }) =>
      api.createDomainPolicy(data, tenantId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['domainPolicies'] });
    },
  });
}

export function useUpdateDomainPolicy() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ id, data }: { id: number; data: UpdateDomainPolicyRequest }) =>
      api.updateDomainPolicy(id, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['domainPolicies'] });
    },
  });
}

export function useDeleteDomainPolicy() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (id: number) => api.deleteDomainPolicy(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['domainPolicies'] });
    },
  });
}

export function useRotateDomainPolicyCredential() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ id, credential }: { id: number; credential: DomainPolicyCredential }) =>
      api.rotateDomainPolicyCredential(id, credential),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['domainPolicies'] });
    },
  });
}
