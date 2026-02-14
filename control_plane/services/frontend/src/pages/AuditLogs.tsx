import { useState, useEffect, useMemo } from 'react';
import { Search, ChevronLeft, ChevronRight } from 'lucide-react';
import { Card, Table, Input, Select, Badge } from '@cagent/shared-ui';
import { useAuditTrail } from '../hooks/useApi';
import { useTenant } from '../contexts/TenantContext';
import { useAuth } from '../contexts/AuthContext';
import type { AuditTrailEntry, AuditTrailFilters } from '../types/api';

const EVENT_TYPE_OPTIONS = [
  { value: '', label: 'All Events' },
  { value: 'egress_policy_created', label: 'Egress Policy Created' },
  { value: 'egress_policy_updated', label: 'Egress Policy Updated' },
  { value: 'egress_policy_deleted', label: 'Egress Policy Deleted' },
  { value: 'security_profile_created', label: 'Security Profile Created' },
  { value: 'security_profile_updated', label: 'Security Profile Updated' },
  { value: 'security_profile_deleted', label: 'Security Profile Deleted' },
  { value: 'agent_profile_assigned', label: 'Agent Group Profile Assigned' },
  { value: 'agent_profile_unassigned', label: 'Agent Group Profile Unassigned' },
  { value: 'ip_acl_created', label: 'IP ACL Created' },
  { value: 'ip_acl_updated', label: 'IP ACL Updated' },
  { value: 'ip_acl_deleted', label: 'IP ACL Deleted' },
  { value: 'agent_wipe_requested', label: 'Agent Group Wipe' },
  { value: 'token_created', label: 'Token Created' },
  { value: 'token_deleted', label: 'Token Deleted' },
  { value: 'terminal_session_start', label: 'Terminal Start' },
  { value: 'terminal_session_end', label: 'Terminal End' },
  { value: 'stcp_secret_generated', label: 'STCP Secret Generated' },
];

const SUPER_ADMIN_EVENT_TYPE_OPTIONS = [
  { value: 'tenant_created', label: 'Tenant Created' },
  { value: 'tenant_deleted', label: 'Tenant Deleted' },
];

export function AuditTrail() {
  const { user } = useAuth();
  const { selectedTenantId } = useTenant();
  const eventTypeOptions = useMemo(
    () => user?.is_super_admin
      ? [...EVENT_TYPE_OPTIONS, ...SUPER_ADMIN_EVENT_TYPE_OPTIONS]
      : EVENT_TYPE_OPTIONS,
    [user?.is_super_admin],
  );
  const [filters, setFilters] = useState<AuditTrailFilters>({
    limit: 25,
    offset: 0,
  });

  // Update filters when tenant changes
  useEffect(() => {
    if (selectedTenantId !== null) {
      setFilters(prev => ({ ...prev, tenant_id: selectedTenantId, offset: 0 }));
    }
  }, [selectedTenantId]);

  const { data, isLoading } = useAuditTrail(selectedTenantId !== null ? { ...filters, tenant_id: selectedTenantId } : filters);
  const logs = data?.items || [];
  const total = data?.total || 0;

  const updateFilter = (key: keyof AuditTrailFilters, value: string | number) => {
    setFilters((prev) => ({
      ...prev,
      [key]: value,
      offset: key !== 'offset' ? 0 : (value as number), // Reset offset on filter change
    }));
  };

  const getSeverityBadge = (severity: string) => {
    switch (severity?.toLowerCase()) {
      case 'critical':
        return <Badge variant="error">Critical</Badge>;
      case 'error':
        return <Badge variant="error">Error</Badge>;
      case 'warning':
        return <Badge variant="warning">Warning</Badge>;
      case 'info':
      default:
        return <Badge variant="info">Info</Badge>;
    }
  };

  const columns = [
    {
      key: 'timestamp',
      header: 'Time',
      render: (log: AuditTrailEntry) => (
        <span className="text-dark-400 text-sm whitespace-nowrap">
          {new Date(log.timestamp + 'Z').toLocaleString()}
        </span>
      ),
    },
    {
      key: 'severity',
      header: 'Severity',
      render: (log: AuditTrailEntry) => getSeverityBadge(log.severity),
    },
    {
      key: 'event_type',
      header: 'Event',
      render: (log: AuditTrailEntry) => (
        <span className="font-medium text-dark-200">{log.event_type}</span>
      ),
    },
    {
      key: 'user',
      header: 'User',
      render: (log: AuditTrailEntry) => (
        <span className="text-dark-300">{log.user || '-'}</span>
      ),
    },
    {
      key: 'action',
      header: 'Action',
      render: (log: AuditTrailEntry) => (
        <code className="bg-dark-900 px-2 py-0.5 rounded text-xs">
          {log.action}
        </code>
      ),
    },
    {
      key: 'details',
      header: 'Details',
      render: (log: AuditTrailEntry) => {
        if (!log.details) return <span className="text-dark-500">-</span>;
        try {
          const parsed = typeof log.details === 'string' ? JSON.parse(log.details) : log.details;
          return (
            <span className="text-dark-400 text-xs truncate max-w-xs block" title={JSON.stringify(parsed, null, 2)}>
              {Object.entries(parsed).map(([k, v]) => `${k}: ${v}`).join(', ')}
            </span>
          );
        } catch {
          return <span className="text-dark-400 text-xs">{String(log.details)}</span>;
        }
      },
    },
  ];

  const currentPage = Math.floor((filters.offset || 0) / (filters.limit || 25)) + 1;
  const totalPages = Math.ceil(total / (filters.limit || 25));

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-dark-100">Audit Trail</h1>
        <span className="text-dark-500">{total} total entries</span>
      </div>

      <Card>
        {/* Filters - Row 1 */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-4">
          <Select
            value={filters.event_type || ''}
            onChange={(e) => updateFilter('event_type', e.target.value)}
            options={eventTypeOptions}
          />
          <Input
            placeholder="Filter by user"
            value={filters.user || ''}
            onChange={(e) => updateFilter('user', e.target.value)}
          />
          <Select
            value={filters.severity || ''}
            onChange={(e) => updateFilter('severity', e.target.value)}
            options={[
              { value: '', label: 'All Severities' },
              { value: 'critical', label: 'Critical' },
              { value: 'error', label: 'Error' },
              { value: 'warning', label: 'Warning' },
              { value: 'info', label: 'Info' },
            ]}
          />
          <div className="relative">
            <Search
              size={16}
              className="absolute left-3 top-1/2 -translate-y-1/2 text-dark-500"
            />
            <Input
              placeholder="Search actions & details..."
              className="pl-9"
              value={filters.search || ''}
              onChange={(e) => updateFilter('search', e.target.value)}
            />
          </div>
        </div>
        {/* Filters - Row 2: Date range */}
        <div className="flex items-center gap-4 mb-4">
          <span className="text-dark-500 text-sm whitespace-nowrap">Date range:</span>
          <Input
            type="date"
            value={filters.start_time ? filters.start_time.split('T')[0] : ''}
            onChange={(e) => updateFilter('start_time', e.target.value ? `${e.target.value}T00:00:00` : '')}
            className="w-40"
          />
          <span className="text-dark-500 text-sm">to</span>
          <Input
            type="date"
            value={filters.end_time ? filters.end_time.split('T')[0] : ''}
            onChange={(e) => updateFilter('end_time', e.target.value ? `${e.target.value}T23:59:59` : '')}
            className="w-40"
          />
        </div>

        <Table
          columns={columns}
          data={logs}
          keyExtractor={(log) => log.id}
          isLoading={isLoading}
          emptyMessage="No audit trail entries found"
        />

        {/* Pagination */}
        {total > 0 && (
          <div className="flex items-center justify-between mt-4 pt-4 border-t border-dark-700">
            <div className="flex items-center gap-2">
              <span className="text-dark-500 text-sm">Rows per page:</span>
              <Select
                value={String(filters.limit || 25)}
                onChange={(e) => updateFilter('limit', Number(e.target.value))}
                options={[
                  { value: '10', label: '10' },
                  { value: '25', label: '25' },
                  { value: '50', label: '50' },
                  { value: '100', label: '100' },
                ]}
                className="w-20"
              />
            </div>
            <div className="flex items-center gap-4">
              <span className="text-dark-500 text-sm">
                Page {currentPage} of {totalPages}
              </span>
              <div className="flex gap-1">
                <button
                  onClick={() =>
                    updateFilter('offset', (filters.offset || 0) - (filters.limit || 25))
                  }
                  disabled={currentPage === 1}
                  className="p-1 rounded hover:bg-dark-700 disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  <ChevronLeft size={20} className="text-dark-400" />
                </button>
                <button
                  onClick={() =>
                    updateFilter('offset', (filters.offset || 0) + (filters.limit || 25))
                  }
                  disabled={currentPage === totalPages}
                  className="p-1 rounded hover:bg-dark-700 disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  <ChevronRight size={20} className="text-dark-400" />
                </button>
              </div>
            </div>
          </div>
        )}
      </Card>
    </div>
  );
}
