import { Card } from './Card';
import { Badge } from './Badge';
import { Button } from './Button';

export interface BlockedDomain {
  domain: string;
  count: number;
  last_seen: string;
}

interface BlockedDomainsWidgetProps {
  domains: BlockedDomain[];
  allowlisted: Set<string>;
  onAdd: (domain: string) => void;
  isLoading?: boolean;
  readOnly?: boolean;
  windowHours?: number;
}

function timeAgo(dateStr: string): string {
  const now = Date.now();
  const then = new Date(dateStr).getTime();
  const diffSec = Math.floor((now - then) / 1000);
  if (diffSec < 60) return `${diffSec}s ago`;
  const diffMin = Math.floor(diffSec / 60);
  if (diffMin < 60) return `${diffMin}m ago`;
  const diffHr = Math.floor(diffMin / 60);
  return `${diffHr}h ago`;
}

export function BlockedDomainsWidget({
  domains,
  allowlisted,
  onAdd,
  isLoading,
  readOnly,
  windowHours = 1,
}: BlockedDomainsWidgetProps) {
  const windowLabel = windowHours === 1 ? 'last hour' : `last ${windowHours}h`;

  return (
    <Card
      title="Top Blocked Domains"
      action={
        <span className="text-xs text-surface-400">{windowLabel}</span>
      }
    >
      {isLoading ? (
        <div className="text-surface-400 text-sm animate-pulse">Loading blocked domains...</div>
      ) : domains.length === 0 ? (
        <div className="text-surface-500 text-sm text-center py-4">No blocked requests</div>
      ) : (
        <div className="space-y-2">
          {domains.slice(0, 10).map((entry) => {
            const isAllowlisted = allowlisted.has(entry.domain);
            return (
              <div
                key={entry.domain}
                className="flex items-center justify-between gap-3 py-1.5 px-2 rounded hover:bg-surface-700/50"
              >
                <div className="flex items-center gap-3 min-w-0 flex-1">
                  <span className="text-surface-100 text-sm font-mono truncate">{entry.domain}</span>
                  <Badge variant="error">{entry.count}</Badge>
                </div>
                <div className="flex items-center gap-2 flex-shrink-0">
                  <span className="text-surface-500 text-xs">{timeAgo(entry.last_seen)}</span>
                  {!readOnly && (
                    isAllowlisted ? (
                      <span className="text-green-400 text-sm" title="Already allowlisted">&#10003;</span>
                    ) : (
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => onAdd(entry.domain)}
                        title="Add to allowlist"
                        className="px-1.5 py-0.5 text-xs"
                      >
                        +
                      </Button>
                    )
                  )}
                </div>
              </div>
            );
          })}
        </div>
      )}
    </Card>
  );
}
