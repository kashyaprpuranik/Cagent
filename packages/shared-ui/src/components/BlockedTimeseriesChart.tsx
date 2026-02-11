import { Card } from './Card';

export interface TimeseriesBucket {
  start: string;
  end: string;
  count: number;
}

interface BlockedTimeseriesChartProps {
  buckets: TimeseriesBucket[];
  isLoading?: boolean;
}

function formatTime(isoStr: string): string {
  const d = new Date(isoStr);
  return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
}

export function BlockedTimeseriesChart({ buckets, isLoading }: BlockedTimeseriesChartProps) {
  const maxCount = Math.max(...buckets.map((b) => b.count), 1);

  return (
    <Card title="Blocked Requests Over Time">
      {isLoading ? (
        <div className="text-surface-400 text-sm animate-pulse">Loading chart...</div>
      ) : buckets.length === 0 ? (
        <div className="text-surface-500 text-sm text-center py-4">No data</div>
      ) : (
        <div>
          <div className="flex items-end gap-1" style={{ height: 120 }}>
            {buckets.map((bucket, i) => {
              const pct = (bucket.count / maxCount) * 100;
              return (
                <div
                  key={i}
                  className="flex-1 group relative flex flex-col justify-end"
                  style={{ height: '100%' }}
                >
                  <div
                    className="bg-red-500/70 hover:bg-red-400/80 rounded-t transition-colors min-h-[2px]"
                    style={{ height: `${Math.max(pct, 2)}%` }}
                  />
                  {/* Tooltip */}
                  <div className="absolute bottom-full left-1/2 -translate-x-1/2 mb-1 hidden group-hover:block z-10">
                    <div className="bg-surface-900 border border-surface-600 rounded px-2 py-1 text-xs text-surface-200 whitespace-nowrap shadow-lg">
                      <div>{formatTime(bucket.start)} - {formatTime(bucket.end)}</div>
                      <div className="text-red-400 font-medium">{bucket.count} blocked</div>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
          {/* X-axis labels */}
          <div className="flex justify-between mt-1">
            <span className="text-[10px] text-surface-500">{formatTime(buckets[0].start)}</span>
            {buckets.length > 2 && (
              <span className="text-[10px] text-surface-500">
                {formatTime(buckets[Math.floor(buckets.length / 2)].start)}
              </span>
            )}
            <span className="text-[10px] text-surface-500">
              {formatTime(buckets[buckets.length - 1].end)}
            </span>
          </div>
        </div>
      )}
    </Card>
  );
}
