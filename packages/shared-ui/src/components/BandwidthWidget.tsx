import { Card } from './Card';

export interface BandwidthEntry {
  domain: string;
  bytes_sent: number;
  bytes_received: number;
  total_bytes: number;
  request_count: number;
}

interface BandwidthWidgetProps {
  domains: BandwidthEntry[];
  isLoading?: boolean;
  windowHours?: number;
}

export function BandwidthWidget({ domains, isLoading, windowHours = 1 }: BandwidthWidgetProps) {
  const windowLabel = windowHours === 1 ? 'last hour' : `last ${windowHours}h`;
  const maxRequests = Math.max(...domains.map((d) => d.request_count), 1);

  return (
    <Card
      title="Requests by Domain"
      action={<span className="text-xs text-surface-400">{windowLabel}</span>}
    >
      {isLoading ? (
        <div className="text-surface-400 text-sm animate-pulse">Loading traffic...</div>
      ) : domains.length === 0 ? (
        <div className="text-surface-500 text-sm text-center py-4">No traffic recorded</div>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-surface-500 text-xs text-left">
                <th className="pb-2 pr-4">Domain</th>
                <th className="pb-2 text-right">Requests</th>
              </tr>
            </thead>
            <tbody>
              {domains.map((entry) => {
                const pct = (entry.request_count / maxRequests) * 100;
                return (
                  <tr key={entry.domain} className="relative">
                    <td className="py-1.5 pr-4 relative">
                      {/* Background bar */}
                      <div
                        className="absolute inset-0 bg-blue-500/10 rounded"
                        style={{ width: `${pct}%` }}
                      />
                      <span className="relative text-surface-100 font-mono truncate block max-w-[200px]">
                        {entry.domain}
                      </span>
                    </td>
                    <td className="py-1.5 text-right text-surface-400">{entry.request_count}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </Card>
  );
}
