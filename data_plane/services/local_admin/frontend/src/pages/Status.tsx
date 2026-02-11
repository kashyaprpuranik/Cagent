import { useMemo } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { useNavigate } from 'react-router-dom';
import {
  RefreshCw,
  Play,
  Square,
  RotateCw,
  Cpu,
  HardDrive,
  CheckCircle,
  XCircle,
  AlertTriangle,
  Activity,
  Server,
  Globe,
  Shield,
  Mail,
} from 'lucide-react';
import { BlockedDomainsWidget } from '@cagent/shared-ui';
import {
  getContainers,
  controlContainer,
  getDetailedHealth,
  getBlockedDomains,
  getConfig,
  getInfo,
  ContainerInfo,
  HealthCheck,
} from '../api/client';

function HealthStatus({ check, label }: { check: HealthCheck; label: string }) {
  const statusConfig = {
    healthy: { icon: CheckCircle, color: 'text-green-400', bg: 'bg-green-900/30' },
    unhealthy: { icon: XCircle, color: 'text-red-400', bg: 'bg-red-900/30' },
    missing: { icon: AlertTriangle, color: 'text-yellow-400', bg: 'bg-yellow-900/30' },
    error: { icon: AlertTriangle, color: 'text-red-400', bg: 'bg-red-900/30' },
  };

  const config = statusConfig[check.status] || statusConfig.error;
  const Icon = config.icon;

  return (
    <div className={`flex items-center justify-between p-3 rounded-lg ${config.bg}`}>
      <div className="flex items-center gap-2">
        <Icon className={`w-4 h-4 ${config.color}`} />
        <span className="text-gray-200">{label}</span>
      </div>
      <span className={`text-sm ${config.color} capitalize`}>{check.status}</span>
    </div>
  );
}

function HealthPanel() {
  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ['health-detailed'],
    queryFn: getDetailedHealth,
    refetchInterval: 10000,
  });

  if (isLoading) {
    return (
      <div className="bg-gray-800 rounded-lg p-4 border border-gray-700">
        <div className="animate-pulse">Loading health checks...</div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="bg-red-900/50 border border-red-700 text-red-300 p-4 rounded-lg">
        Health check failed: {(error as Error).message}
      </div>
    );
  }

  const overallStatus = data?.status === 'healthy';

  return (
    <div className="bg-gray-800 rounded-lg p-4 border border-gray-700">
      <div className="flex items-center justify-between mb-4">
        <h2 className="text-lg font-semibold text-white flex items-center gap-2">
          <Activity className="w-5 h-5 text-blue-400" />
          Health Status
        </h2>
        <div className="flex items-center gap-2">
          {overallStatus ? (
            <span className="flex items-center gap-1 text-green-400 text-sm">
              <CheckCircle className="w-4 h-4" />
              All Systems Operational
            </span>
          ) : (
            <span className="flex items-center gap-1 text-yellow-400 text-sm">
              <AlertTriangle className="w-4 h-4" />
              Degraded
            </span>
          )}
          <button
            onClick={() => refetch()}
            className="p-1.5 text-gray-400 hover:text-white hover:bg-gray-700 rounded"
          >
            <RefreshCw className="w-4 h-4" />
          </button>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
        {data?.checks && (
          <>
            <HealthStatus check={data.checks.agent || { status: 'missing' }} label="Agent Container" />
            <HealthStatus check={data.checks['dns-filter'] || { status: 'missing' }} label="DNS Filter" />
            <HealthStatus check={data.checks['http-proxy'] || { status: 'missing' }} label="HTTP Proxy" />
            {data.checks['email-proxy'] && (
              <HealthStatus check={data.checks['email-proxy']} label="Email Proxy" />
            )}
            <HealthStatus check={data.checks.dns_resolution || { status: 'missing' }} label="DNS Resolution" />
            <HealthStatus check={data.checks.envoy_ready || { status: 'missing' }} label="HTTP Proxy Ready" />
          </>
        )}
      </div>
    </div>
  );
}

function ContainerCard({ container }: { container: ContainerInfo }) {
  const queryClient = useQueryClient();

  const mutation = useMutation({
    mutationFn: ({ name, action }: { name: string; action: 'start' | 'stop' | 'restart' }) =>
      controlContainer(name, action),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['containers'] });
      queryClient.invalidateQueries({ queryKey: ['health-detailed'] });
    },
  });

  const isRunning = container.status === 'running';
  const statusColor = isRunning ? 'text-green-400' : 'text-red-400';

  // Icon based on container name
  const getIcon = () => {
    if (container.name.includes('email')) return Mail;
    if (container.name.includes('agent')) return Server;
    if (container.name.includes('dns')) return Globe;
    if (container.name.includes('proxy')) return Shield;
    return Server;
  };
  const Icon = getIcon();

  return (
    <div className="bg-gray-800 rounded-lg p-4 border border-gray-700">
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-2">
          <Icon className="w-5 h-5 text-blue-400" />
          <h3 className="font-medium text-white">{container.name}</h3>
        </div>
        <div className="flex items-center gap-2">
          <span className={`w-2 h-2 rounded-full ${isRunning ? 'bg-green-400' : 'bg-red-400'}`} />
          <span className={`text-sm font-medium ${statusColor}`}>{container.status}</span>
        </div>
      </div>

      {container.id && <p className="text-xs text-gray-500 mb-2">ID: {container.id}</p>}

      {isRunning && (
        <div className="grid grid-cols-2 gap-4 mb-4 text-sm">
          {container.cpu_percent !== undefined && (
            <div className="flex items-center gap-2 text-gray-300">
              <Cpu className="w-4 h-4 text-blue-400" />
              <div className="flex-1">
                <div className="flex justify-between">
                  <span>CPU</span>
                  <span>{container.cpu_percent}%</span>
                </div>
                <div className="w-full bg-gray-700 rounded-full h-1 mt-1">
                  <div
                    className="bg-blue-500 h-1 rounded-full"
                    style={{ width: `${Math.min(container.cpu_percent, 100)}%` }}
                  />
                </div>
              </div>
            </div>
          )}
          {container.memory_mb !== undefined && container.memory_limit_mb && (
            <div className="flex items-center gap-2 text-gray-300">
              <HardDrive className="w-4 h-4 text-purple-400" />
              <div className="flex-1">
                <div className="flex justify-between">
                  <span>Memory</span>
                  <span>
                    {container.memory_mb} / {container.memory_limit_mb} MB
                  </span>
                </div>
                <div className="w-full bg-gray-700 rounded-full h-1 mt-1">
                  <div
                    className="bg-purple-500 h-1 rounded-full"
                    style={{
                      width: `${Math.min((container.memory_mb / container.memory_limit_mb) * 100, 100)}%`,
                    }}
                  />
                </div>
              </div>
            </div>
          )}
        </div>
      )}

      <div className="flex gap-2">
        {!isRunning && (
          <button
            onClick={() => mutation.mutate({ name: container.name, action: 'start' })}
            disabled={mutation.isPending}
            className="flex items-center gap-1 px-3 py-1.5 bg-green-600 hover:bg-green-700 text-white text-sm rounded disabled:opacity-50"
          >
            <Play className="w-3 h-3" />
            Start
          </button>
        )}
        {isRunning && (
          <>
            <button
              onClick={() => mutation.mutate({ name: container.name, action: 'stop' })}
              disabled={mutation.isPending}
              className="flex items-center gap-1 px-3 py-1.5 bg-red-600 hover:bg-red-700 text-white text-sm rounded disabled:opacity-50"
            >
              <Square className="w-3 h-3" />
              Stop
            </button>
            <button
              onClick={() => mutation.mutate({ name: container.name, action: 'restart' })}
              disabled={mutation.isPending}
              className="flex items-center gap-1 px-3 py-1.5 bg-yellow-600 hover:bg-yellow-700 text-white text-sm rounded disabled:opacity-50"
            >
              <RotateCw className="w-3 h-3" />
              Restart
            </button>
          </>
        )}
      </div>
    </div>
  );
}

export default function StatusPage() {
  const navigate = useNavigate();
  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ['containers'],
    queryFn: getContainers,
    refetchInterval: 5000,
  });

  const { data: blockedData, isLoading: blockedLoading } = useQuery({
    queryKey: ['blocked-domains'],
    queryFn: () => getBlockedDomains(),
    refetchInterval: 30_000,
  });

  const { data: configData } = useQuery({
    queryKey: ['config'],
    queryFn: getConfig,
  });

  const { data: infoData } = useQuery({
    queryKey: ['info'],
    queryFn: getInfo,
  });

  const allowlisted = useMemo(() => {
    const domains = configData?.config?.domains?.map((d) => d.domain) || [];
    return new Set(domains);
  }, [configData]);

  const isConnected = infoData?.mode === 'connected';

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-white">System Status</h1>
        <button
          onClick={() => refetch()}
          className="flex items-center gap-2 px-4 py-2 bg-gray-700 hover:bg-gray-600 text-white rounded-lg"
        >
          <RefreshCw className="w-4 h-4" />
          Refresh
        </button>
      </div>

      {/* Health Panel */}
      <HealthPanel />

      {/* Blocked Domains Widget */}
      <BlockedDomainsWidget
        domains={blockedData?.blocked_domains || []}
        allowlisted={allowlisted}
        onAdd={(domain) => navigate(`/config?add-domain=${encodeURIComponent(domain)}`)}
        isLoading={blockedLoading}
        readOnly={isConnected}
        windowHours={blockedData?.window_hours}
      />

      {/* Containers */}
      <div>
        <h2 className="text-lg font-semibold text-white mb-4">Containers</h2>

        {isLoading && <div className="text-gray-400">Loading containers...</div>}

        {error && (
          <div className="bg-red-900/50 border border-red-700 text-red-300 p-4 rounded-lg">
            Error: {(error as Error).message}
          </div>
        )}

        {data && (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {Object.values(data.containers).map((container) => (
              <ContainerCard key={container.name} container={container} />
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
