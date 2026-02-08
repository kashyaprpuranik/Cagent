import { useState } from 'react';
import { Search, RefreshCw } from 'lucide-react';
import { Card, Table, Input, Select, Button, Badge } from '../components/common';
import { useAgents } from '../hooks/useApi';
import { useTenant } from '../contexts/TenantContext';
import { api } from '../api/client';
import { useQuery } from '@tanstack/react-query';

interface LogEntry {
  id: string;
  timestamp: string;
  message: string;
  source: string;
  agent_id: string;
  log_type: string;
  level?: string;
  method?: string;
  path?: string;
  response_code?: number;
  syscall?: string;
  syscall_result?: string;
}

export function AgentLogs() {
  const { selectedTenantId } = useTenant();
  // Filter agents by selected tenant
  const { data: agents = [] } = useAgents(selectedTenantId);
  const [selectedAgent, setSelectedAgent] = useState<string>('');
  const [logSource, setLogSource] = useState<string>('');
  const [searchText, setSearchText] = useState<string>('');
  const [limit, setLimit] = useState<number>(100);

  const { data: logsData, isLoading, refetch } = useQuery({
    queryKey: ['agentLogs', selectedTenantId, selectedAgent, logSource, searchText, limit],
    queryFn: () => api.queryAgentLogs({
      query: searchText,
      source: logSource || undefined,
      agent_id: selectedAgent || undefined,
      tenant_id: selectedTenantId ?? undefined,
      limit,
    }),
    enabled: selectedTenantId !== null,  // Wait for tenant to be selected
    refetchInterval: false,
  });

  // Transform OpenObserve response to log entries
  const logs: LogEntry[] = [];
  if (logsData?.data?.result) {
    logsData.data.result.forEach((hit: Record<string, unknown>, idx: number) => {
      logs.push({
        id: `${hit._timestamp || idx}-${idx}`,
        timestamp: hit._timestamp
          ? new Date(Number(hit._timestamp) / 1000).toISOString()
          : new Date().toISOString(),
        message: String(hit.message || ''),
        source: String(hit.source || 'unknown'),
        agent_id: String(hit.agent_id || '-'),
        log_type: String(hit.log_type || 'stdout'),
        level: hit.level ? String(hit.level) : undefined,
        method: hit.method ? String(hit.method) : undefined,
        path: hit.path ? String(hit.path) : undefined,
        response_code: hit.response_code ? Number(hit.response_code) : undefined,
        syscall: hit.syscall ? String(hit.syscall) : undefined,
        syscall_result: hit.syscall_result ? String(hit.syscall_result) : undefined,
      });
    });
  }

  const agentOptions = [
    { value: '', label: 'All Agents' },
    ...agents.map((agent) => ({
      value: agent.agent_id,
      label: agent.agent_id,
    })),
  ];

  const sourceOptions = [
    { value: '', label: 'All Sources' },
    { value: 'envoy', label: 'Envoy Proxy' },
    { value: 'agent', label: 'Agent Container' },
    { value: 'coredns', label: 'CoreDNS' },
    { value: 'gvisor', label: 'gVisor (Security)' },
    { value: 'agent-manager', label: 'Agent Manager' },
  ];

  const getBadgeVariant = (log: LogEntry) => {
    if (log.source === 'gvisor' && log.syscall_result === 'denied') {
      return 'error';
    }
    if (log.log_type === 'stderr' || log.level === 'error') {
      return 'warning';
    }
    if (log.source === 'envoy') {
      return 'info';
    }
    return 'default';
  };

  const columns = [
    {
      key: 'timestamp',
      header: 'Time',
      render: (log: LogEntry) => (
        <span className="text-dark-400 text-sm whitespace-nowrap font-mono">
          {new Date(log.timestamp).toLocaleString()}
        </span>
      ),
    },
    {
      key: 'source',
      header: 'Source',
      render: (log: LogEntry) => (
        <Badge variant={getBadgeVariant(log)}>{log.source}</Badge>
      ),
    },
    {
      key: 'agent',
      header: 'Agent',
      render: (log: LogEntry) => (
        <span className="text-dark-300 text-sm">{log.agent_id}</span>
      ),
    },
    {
      key: 'message',
      header: 'Log',
      render: (log: LogEntry) => (
        <div>
          {/* Show syscall info for gVisor logs */}
          {log.syscall && (
            <span className={`text-xs mr-2 ${log.syscall_result === 'denied' ? 'text-red-400' : 'text-dark-500'}`}>
              [{log.syscall}: {log.syscall_result}]
            </span>
          )}
          {/* Show HTTP info for Envoy access logs */}
          {log.method && (
            <span className="text-xs text-dark-500 mr-2">
              {log.method} {log.path} → {log.response_code}
            </span>
          )}
          <code className="text-dark-200 text-xs break-all whitespace-pre-wrap font-mono">
            {log.message}
          </code>
        </div>
      ),
    },
  ];

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-dark-100">Agent Logs</h1>
          <p className="text-dark-400 text-sm mt-1">
            Logs from data plane components (Envoy, CoreDNS, gVisor, containers)
          </p>
        </div>
        <Button variant="secondary" onClick={() => refetch()}>
          <RefreshCw size={16} className="mr-2" />
          Refresh
        </Button>
      </div>

      <Card>
        {/* Filters */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-4">
          <Select
            value={selectedAgent}
            onChange={(e) => setSelectedAgent(e.target.value)}
            options={agentOptions}
          />
          <Select
            value={logSource}
            onChange={(e) => setLogSource(e.target.value)}
            options={sourceOptions}
          />
          <div className="relative">
            <Search
              size={16}
              className="absolute left-3 top-1/2 -translate-y-1/2 text-dark-500"
            />
            <Input
              placeholder="Search logs..."
              className="pl-9"
              value={searchText}
              onChange={(e) => setSearchText(e.target.value)}
            />
          </div>
          <Select
            value={String(limit)}
            onChange={(e) => setLimit(Number(e.target.value))}
            options={[
              { value: '50', label: '50 lines' },
              { value: '100', label: '100 lines' },
              { value: '250', label: '250 lines' },
              { value: '500', label: '500 lines' },
            ]}
          />
        </div>

        <Table
          columns={columns}
          data={logs}
          keyExtractor={(log) => log.id}
          isLoading={isLoading || selectedTenantId === null}
          emptyMessage={
            selectedTenantId === null
              ? "Select a tenant to view agent logs"
              : "No logs found. Try adjusting filters or check if agents are running."
          }
        />

        {logs.length > 0 && (
          <div className="mt-4 pt-4 border-t border-dark-700">
            <span className="text-dark-500 text-sm">
              Showing {logs.length} log entries
            </span>
          </div>
        )}
      </Card>
    </div>
  );
}
