import { useState, useEffect } from 'react';
import { Search, ChevronLeft, ChevronRight } from 'lucide-react';
import { Card, Table, Input, Select, Badge } from '../components/common';
import { useAuditLogs } from '../hooks/useApi';
import { useTenant } from '../contexts/TenantContext';
import type { AuditLog, AuditLogFilters } from '../types/api';

export function AuditLogs() {
  const { selectedTenantId } = useTenant();
  const [filters, setFilters] = useState<AuditLogFilters>({
    limit: 25,
    offset: 0,
  });

  // Update filters when tenant changes
  useEffect(() => {
    if (selectedTenantId !== null) {
      setFilters(prev => ({ ...prev, tenant_id: selectedTenantId, offset: 0 }));
    }
  }, [selectedTenantId]);

  const { data, isLoading } = useAuditLogs(selectedTenantId !== null ? { ...filters, tenant_id: selectedTenantId } : filters);
  const logs = data?.items || [];
  const total = data?.total || 0;

  const updateFilter = (key: keyof AuditLogFilters, value: string | number) => {
    setFilters((prev) => ({
      ...prev,
      [key]: value,
      offset: key !== 'offset' ? 0 : (value as number), // Reset offset on filter change
    }));
  };

  const getSeverityBadge = (severity: AuditLog['severity']) => {
    switch (severity) {
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
      render: (log: AuditLog) => (
        <span className="text-dark-400 text-sm whitespace-nowrap">
          {new Date(log.timestamp).toLocaleString()}
        </span>
      ),
    },
    {
      key: 'severity',
      header: 'Severity',
      render: (log: AuditLog) => getSeverityBadge(log.severity),
    },
    {
      key: 'event_type',
      header: 'Event',
      render: (log: AuditLog) => (
        <span className="font-medium text-dark-200">{log.event_type}</span>
      ),
    },
    {
      key: 'user',
      header: 'User',
      render: (log: AuditLog) => (
        <span className="text-dark-300">{log.user || '-'}</span>
      ),
    },
    {
      key: 'resource',
      header: 'Resource',
      render: (log: AuditLog) => (
        <span className="text-dark-400">{log.resource || '-'}</span>
      ),
    },
    {
      key: 'action',
      header: 'Action',
      render: (log: AuditLog) => (
        <code className="bg-dark-900 px-2 py-0.5 rounded text-xs">
          {log.action}
        </code>
      ),
    },
    {
      key: 'ip_address',
      header: 'IP',
      render: (log: AuditLog) => (
        <span className="text-dark-500 text-sm">{log.ip_address || '-'}</span>
      ),
    },
  ];

  const currentPage = Math.floor((filters.offset || 0) / (filters.limit || 25)) + 1;
  const totalPages = Math.ceil(total / (filters.limit || 25));

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-dark-100">Admin Audit Logs</h1>
        <span className="text-dark-500">{total} total entries</span>
      </div>

      <Card>
        {/* Filters */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-4">
          <div className="relative">
            <Search
              size={16}
              className="absolute left-3 top-1/2 -translate-y-1/2 text-dark-500"
            />
            <Input
              placeholder="Search events..."
              className="pl-9"
              value={filters.event_type || ''}
              onChange={(e) => updateFilter('event_type', e.target.value)}
            />
          </div>
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
          <div className="flex gap-2">
            <Input
              type="date"
              value={filters.start_date || ''}
              onChange={(e) => updateFilter('start_date', e.target.value)}
            />
            <Input
              type="date"
              value={filters.end_date || ''}
              onChange={(e) => updateFilter('end_date', e.target.value)}
            />
          </div>
        </div>

        <Table
          columns={columns}
          data={logs}
          keyExtractor={(log) => log.id}
          isLoading={isLoading}
          emptyMessage="No audit logs found"
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
