import { useState, useEffect, useRef, useMemo } from 'react';
import { useQuery } from '@tanstack/react-query';
import {
  RefreshCw,
  Download,
  Trash2,
  Radio,
  Search,
  BarChart3,
  Globe,
  AlertTriangle,
  Clock,
  ArrowUpRight,
} from 'lucide-react';
import { getContainerLogs, getContainers, getInfo, createLogStream } from '../api/client';

interface EnvoyLogEntry {
  timestamp: string;
  authority: string;
  path: string;
  method: string;
  response_code: number;
  duration_ms: number;
  bytes_received: number;
  bytes_sent: number;
  upstream_cluster: string;
  rate_limited?: string;
  credential_injected?: string;
}

interface TrafficStats {
  totalRequests: number;
  successCount: number;
  errorCount: number;
  rateLimitedCount: number;
  blockedCount: number;
  avgDuration: number;
  topDomains: { domain: string; count: number; bytes: number }[];
  recentErrors: { domain: string; code: number; time: string }[];
}

function parseEnvoyLog(line: string): EnvoyLogEntry | null {
  try {
    // Envoy outputs JSON logs
    const match = line.match(/\{.*\}/);
    if (match) {
      return JSON.parse(match[0]);
    }
  } catch {
    // Not JSON, skip
  }
  return null;
}

function computeTrafficStats(logs: string[]): TrafficStats {
  const entries: EnvoyLogEntry[] = [];
  const domainStats: Record<string, { count: number; bytes: number }> = {};
  const errors: { domain: string; code: number; time: string }[] = [];

  let successCount = 0;
  let errorCount = 0;
  let rateLimitedCount = 0;
  let blockedCount = 0;
  let totalDuration = 0;

  for (const line of logs) {
    const entry = parseEnvoyLog(line);
    if (!entry) continue;

    entries.push(entry);
    const domain = entry.authority || 'unknown';

    // Aggregate domain stats
    if (!domainStats[domain]) {
      domainStats[domain] = { count: 0, bytes: 0 };
    }
    domainStats[domain].count++;
    domainStats[domain].bytes += (entry.bytes_sent || 0) + (entry.bytes_received || 0);

    // Count by status
    if (entry.response_code >= 200 && entry.response_code < 400) {
      successCount++;
    } else if (entry.response_code === 429) {
      rateLimitedCount++;
      errorCount++;
    } else if (entry.response_code === 403) {
      blockedCount++;
      errorCount++;
      errors.push({ domain, code: entry.response_code, time: entry.timestamp });
    } else if (entry.response_code >= 400) {
      errorCount++;
      errors.push({ domain, code: entry.response_code, time: entry.timestamp });
    }

    totalDuration += entry.duration_ms || 0;
  }

  // Sort domains by count
  const topDomains = Object.entries(domainStats)
    .map(([domain, stats]) => ({ domain, ...stats }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 10);

  return {
    totalRequests: entries.length,
    successCount,
    errorCount,
    rateLimitedCount,
    blockedCount,
    avgDuration: entries.length > 0 ? totalDuration / entries.length : 0,
    topDomains,
    recentErrors: errors.slice(-5).reverse(),
  };
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function StatCard({
  label,
  value,
  icon: Icon,
  color = 'blue',
}: {
  label: string;
  value: string | number;
  icon: React.ElementType;
  color?: string;
}) {
  const colors: Record<string, string> = {
    blue: 'bg-blue-600/20 text-blue-400',
    green: 'bg-green-600/20 text-green-400',
    red: 'bg-red-600/20 text-red-400',
    yellow: 'bg-yellow-600/20 text-yellow-400',
    purple: 'bg-purple-600/20 text-purple-400',
  };

  return (
    <div className="bg-gray-800 rounded-lg p-4 border border-gray-700">
      <div className="flex items-center gap-3">
        <div className={`p-2 rounded-lg ${colors[color]}`}>
          <Icon className="w-5 h-5" />
        </div>
        <div>
          <p className="text-2xl font-bold text-white">{value}</p>
          <p className="text-xs text-gray-400">{label}</p>
        </div>
      </div>
    </div>
  );
}

export default function LogsPage() {
  const { data: infoData } = useQuery({ queryKey: ['info'], queryFn: getInfo });
  const emailEnabled = infoData?.features?.includes('email');
  const { data: containersData } = useQuery({
    queryKey: ['containers'],
    queryFn: getContainers,
    staleTime: 30_000,
  });

  const INFRA_NAMES = useMemo(() => new Set(['dns-filter', 'http-proxy', 'email-proxy', 'warden']), []);

  const containers = useMemo(() => {
    // Discover agent containers dynamically, keep infra containers static
    const allContainers = containersData
      ? Object.values(containersData.containers)
      : [];
    const agentNames = allContainers
      .filter((c) => !INFRA_NAMES.has(c.name))
      .map((c) => c.name);
    const hasWarden = allContainers.some((c) => c.name === 'warden');
    return [
      'http-proxy', 'dns-filter',
      ...agentNames,
      ...(hasWarden ? ['warden'] : []),
      ...(emailEnabled ? ['email-proxy'] : []),
    ];
  }, [containersData, emailEnabled, INFRA_NAMES]);
  const [selectedContainer, setSelectedContainer] = useState('http-proxy');
  const [logs, setLogs] = useState<string[]>([]);
  const [streaming, setStreaming] = useState(false);
  const [autoScroll, setAutoScroll] = useState(true);
  const [searchQuery, setSearchQuery] = useState('');
  const [levelFilter, setLevelFilter] = useState<string>('all');
  const [showStats, setShowStats] = useState(true);
  const wsRef = useRef<WebSocket | null>(null);
  const logsEndRef = useRef<HTMLDivElement>(null);

  // Get initial logs
  const { data, isLoading, refetch } = useQuery({
    queryKey: ['logs', selectedContainer],
    queryFn: () => getContainerLogs(selectedContainer, 500),
    enabled: !streaming,
  });

  // Update logs when data changes
  useEffect(() => {
    if (data?.lines && !streaming) {
      setLogs(data.lines);
    }
  }, [data, streaming]);

  // Auto-scroll to bottom
  useEffect(() => {
    if (autoScroll && logsEndRef.current) {
      logsEndRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [logs, autoScroll]);

  // Cleanup WebSocket on unmount
  useEffect(() => {
    return () => {
      if (wsRef.current) {
        wsRef.current.close();
      }
    };
  }, []);

  // Compute traffic stats for Envoy logs
  const trafficStats = useMemo(() => {
    if (selectedContainer === 'http-proxy') {
      return computeTrafficStats(logs);
    }
    return null;
  }, [logs, selectedContainer]);

  // Filter logs
  const filteredLogs = useMemo(() => {
    return logs.filter((line) => {
      // Search filter
      if (searchQuery && !line.toLowerCase().includes(searchQuery.toLowerCase())) {
        return false;
      }
      // Level filter
      if (levelFilter !== 'all') {
        const hasError = line.includes('ERROR') || line.includes('error') || line.includes('"response_code":5') || line.includes('"response_code":4');
        const hasWarn = line.includes('WARN') || line.includes('warning') || line.includes('"response_code":429');
        if (levelFilter === 'error' && !hasError) return false;
        if (levelFilter === 'warn' && !hasWarn && !hasError) return false;
      }
      return true;
    });
  }, [logs, searchQuery, levelFilter]);

  const startStreaming = () => {
    if (wsRef.current) {
      wsRef.current.close();
    }

    const ws = createLogStream(selectedContainer);
    wsRef.current = ws;

    ws.onopen = () => {
      setStreaming(true);
      setLogs([]);
    };

    ws.onmessage = (event) => {
      setLogs((prev) => [...prev.slice(-999), event.data]);
    };

    ws.onerror = () => setStreaming(false);
    ws.onclose = () => setStreaming(false);
  };

  const stopStreaming = () => {
    if (wsRef.current) {
      wsRef.current.close();
      wsRef.current = null;
    }
    setStreaming(false);
    refetch();
  };

  const handleContainerChange = (container: string) => {
    if (streaming) stopStreaming();
    setSelectedContainer(container);
    setLogs([]);
  };

  const downloadLogs = () => {
    const content = filteredLogs.join('\n');
    const blob = new Blob([content], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${selectedContainer}-logs-${new Date().toISOString()}.txt`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const getLineClass = (line: string) => {
    if (line.includes('ERROR') || line.includes('error') || line.includes('"response_code":5')) {
      return 'text-red-400';
    }
    if (line.includes('WARN') || line.includes('warning') || line.includes('"response_code":429')) {
      return 'text-yellow-400';
    }
    if (line.includes('"response_code":403')) {
      return 'text-orange-400';
    }
    return 'text-gray-300';
  };

  return (
    <div className="h-full flex flex-col gap-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-4">
          <h1 className="text-2xl font-bold text-white">Logs & Traffic</h1>

          <select
            value={selectedContainer}
            onChange={(e) => handleContainerChange(e.target.value)}
            className="bg-gray-800 border border-gray-700 text-white px-3 py-2 rounded-lg focus:outline-none focus:border-blue-500"
          >
            {containers.map((c) => (
              <option key={c} value={c}>{c}</option>
            ))}
          </select>

          {selectedContainer === 'http-proxy' && (
            <button
              onClick={() => setShowStats(!showStats)}
              className={`flex items-center gap-2 px-3 py-2 rounded-lg border ${
                showStats ? 'bg-blue-600/20 border-blue-500 text-blue-400' : 'bg-gray-800 border-gray-700 text-gray-400'
              }`}
            >
              <BarChart3 className="w-4 h-4" />
              Stats
            </button>
          )}
        </div>

        <div className="flex items-center gap-2">
          {streaming ? (
            <button
              onClick={stopStreaming}
              className="flex items-center gap-2 px-4 py-2 bg-red-600 hover:bg-red-700 text-white rounded-lg"
            >
              <Radio className="w-4 h-4 animate-pulse" />
              Stop
            </button>
          ) : (
            <button
              onClick={startStreaming}
              className="flex items-center gap-2 px-4 py-2 bg-green-600 hover:bg-green-700 text-white rounded-lg"
            >
              <Radio className="w-4 h-4" />
              Stream
            </button>
          )}

          <button
            onClick={() => refetch()}
            disabled={streaming || isLoading}
            className="flex items-center gap-2 px-4 py-2 bg-gray-700 hover:bg-gray-600 text-white rounded-lg disabled:opacity-50"
          >
            <RefreshCw className={`w-4 h-4 ${isLoading ? 'animate-spin' : ''}`} />
          </button>

          <button
            onClick={downloadLogs}
            disabled={filteredLogs.length === 0}
            className="p-2 bg-gray-700 hover:bg-gray-600 text-white rounded-lg disabled:opacity-50"
          >
            <Download className="w-4 h-4" />
          </button>

          <button
            onClick={() => setLogs([])}
            disabled={logs.length === 0}
            className="p-2 bg-gray-700 hover:bg-gray-600 text-white rounded-lg disabled:opacity-50"
          >
            <Trash2 className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Traffic Stats (Envoy only) */}
      {selectedContainer === 'http-proxy' && showStats && trafficStats && (
        <div className="space-y-4">
          <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-3">
            <StatCard label="Total Requests" value={trafficStats.totalRequests} icon={Globe} color="blue" />
            <StatCard label="Success (2xx/3xx)" value={trafficStats.successCount} icon={ArrowUpRight} color="green" />
            <StatCard label="Errors (4xx/5xx)" value={trafficStats.errorCount} icon={AlertTriangle} color="red" />
            <StatCard label="Rate Limited" value={trafficStats.rateLimitedCount} icon={Clock} color="yellow" />
            <StatCard label="Blocked (403)" value={trafficStats.blockedCount} icon={AlertTriangle} color="red" />
            <StatCard label="Avg Latency" value={`${trafficStats.avgDuration.toFixed(0)}ms`} icon={Clock} color="purple" />
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            {/* Top Domains */}
            <div className="bg-gray-800 rounded-lg p-4 border border-gray-700">
              <h3 className="text-sm font-medium text-gray-300 mb-3 flex items-center gap-2">
                <Globe className="w-4 h-4" />
                Top Domains
              </h3>
              <div className="space-y-2">
                {trafficStats.topDomains.length === 0 ? (
                  <p className="text-gray-500 text-sm">No traffic data</p>
                ) : (
                  trafficStats.topDomains.slice(0, 5).map((d) => (
                    <div key={d.domain} className="flex items-center justify-between text-sm">
                      <span className="text-gray-300 truncate flex-1">{d.domain}</span>
                      <span className="text-gray-500 ml-2">{d.count} req</span>
                      <span className="text-gray-500 ml-2 w-20 text-right">{formatBytes(d.bytes)}</span>
                    </div>
                  ))
                )}
              </div>
            </div>

            {/* Recent Errors */}
            <div className="bg-gray-800 rounded-lg p-4 border border-gray-700">
              <h3 className="text-sm font-medium text-gray-300 mb-3 flex items-center gap-2">
                <AlertTriangle className="w-4 h-4 text-red-400" />
                Recent Errors
              </h3>
              <div className="space-y-2">
                {trafficStats.recentErrors.length === 0 ? (
                  <p className="text-gray-500 text-sm">No errors</p>
                ) : (
                  trafficStats.recentErrors.map((e, i) => (
                    <div key={i} className="flex items-center justify-between text-sm">
                      <span className="text-gray-300 truncate flex-1">{e.domain}</span>
                      <span className={`ml-2 px-2 py-0.5 rounded text-xs ${
                        e.code === 429 ? 'bg-yellow-600/20 text-yellow-400' :
                        e.code === 403 ? 'bg-orange-600/20 text-orange-400' :
                        'bg-red-600/20 text-red-400'
                      }`}>
                        {e.code}
                      </span>
                    </div>
                  ))
                )}
              </div>
            </div>
          </div>

          {/* Request count */}
          <div className="text-sm text-gray-400">
            {trafficStats.totalRequests} requests
          </div>
        </div>
      )}

      {/* Search and Filter */}
      <div className="flex items-center gap-3">
        <div className="relative flex-1 max-w-md">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500" />
          <input
            type="text"
            placeholder="Search logs..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full bg-gray-800 border border-gray-700 text-white pl-10 pr-4 py-2 rounded-lg focus:outline-none focus:border-blue-500"
          />
        </div>

        <select
          value={levelFilter}
          onChange={(e) => setLevelFilter(e.target.value)}
          className="bg-gray-800 border border-gray-700 text-white px-3 py-2 rounded-lg focus:outline-none focus:border-blue-500"
        >
          <option value="all">All Levels</option>
          <option value="error">Errors Only</option>
          <option value="warn">Warnings & Errors</option>
        </select>

        <label className="flex items-center gap-2 text-sm text-gray-400">
          <input
            type="checkbox"
            checked={autoScroll}
            onChange={(e) => setAutoScroll(e.target.checked)}
            className="rounded bg-gray-700 border-gray-600"
          />
          Auto-scroll
        </label>

        <span className="text-xs text-gray-500">
          {filteredLogs.length} / {logs.length} lines
        </span>
      </div>

      {streaming && (
        <div className="flex items-center gap-2 text-sm text-green-400">
          <Radio className="w-4 h-4 animate-pulse" />
          Streaming live logs...
        </div>
      )}

      {/* Log Viewer */}
      <div className="flex-1 bg-gray-900 border border-gray-700 rounded-lg overflow-auto font-mono text-sm min-h-0">
        {isLoading && !streaming && (
          <div className="p-4 text-gray-500">Loading logs...</div>
        )}

        {filteredLogs.length === 0 && !isLoading && (
          <div className="p-4 text-gray-500">
            {logs.length === 0 ? 'No logs available' : 'No logs match your filter'}
          </div>
        )}

        <div className="p-2">
          {filteredLogs.map((line, i) => (
            <div
              key={i}
              className={`py-0.5 px-2 hover:bg-gray-800 whitespace-pre-wrap break-all ${getLineClass(line)}`}
            >
              {line}
            </div>
          ))}
          <div ref={logsEndRef} />
        </div>
      </div>
    </div>
  );
}
