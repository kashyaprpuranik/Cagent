import { useState, useRef, useEffect } from 'react';
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
  onBulkAdd?: (domains: string[]) => void;
  onAddWithTTL?: (domain: string, ttlHours: number) => void;
  onDiagnose?: (domain: string) => void;
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

const TTL_OPTIONS = [
  { label: 'Allow for 1h', hours: 1 },
  { label: 'Allow for 24h', hours: 24 },
  { label: 'Allow for 7d', hours: 168 },
];

function TTLDropdown({
  domain,
  onAdd,
  onAddWithTTL,
}: {
  domain: string;
  onAdd: (domain: string) => void;
  onAddWithTTL: (domain: string, ttlHours: number) => void;
}) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    const handler = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, [open]);

  return (
    <div className="relative" ref={ref}>
      <div className="flex items-center">
        <Button
          variant="ghost"
          size="sm"
          onClick={() => onAdd(domain)}
          title="Add to allowlist permanently"
          className="px-1.5 py-0.5 text-xs rounded-r-none"
        >
          +
        </Button>
        <button
          onClick={() => setOpen(!open)}
          className="px-1 py-0.5 text-xs text-surface-400 hover:text-surface-100 hover:bg-surface-700 rounded-r"
          title="Add with time limit"
        >
          &#9662;
        </button>
      </div>
      {open && (
        <div className="absolute right-0 top-full mt-1 bg-surface-800 border border-surface-600 rounded-lg shadow-lg z-20 min-w-[140px]">
          <button
            onClick={() => { onAdd(domain); setOpen(false); }}
            className="w-full text-left px-3 py-1.5 text-xs text-surface-200 hover:bg-surface-700 rounded-t-lg"
          >
            Add permanently
          </button>
          {TTL_OPTIONS.map((opt) => (
            <button
              key={opt.hours}
              onClick={() => { onAddWithTTL(domain, opt.hours); setOpen(false); }}
              className="w-full text-left px-3 py-1.5 text-xs text-surface-200 hover:bg-surface-700 last:rounded-b-lg"
            >
              {opt.label}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}

export function BlockedDomainsWidget({
  domains,
  allowlisted,
  onAdd,
  onBulkAdd,
  onAddWithTTL,
  onDiagnose,
  isLoading,
  readOnly,
  windowHours = 1,
}: BlockedDomainsWidgetProps) {
  const [selectedDomains, setSelectedDomains] = useState<Set<string>>(new Set());
  const windowLabel = windowHours === 1 ? 'last hour' : `last ${windowHours}h`;

  const selectableDomains = domains.slice(0, 10).filter(
    (entry) => !allowlisted.has(entry.domain)
  );
  const showCheckboxes = !readOnly && onBulkAdd && selectableDomains.length > 0;

  const toggleDomain = (domain: string) => {
    setSelectedDomains((prev) => {
      const next = new Set(prev);
      if (next.has(domain)) next.delete(domain);
      else next.add(domain);
      return next;
    });
  };

  const handleBulkAdd = () => {
    if (onBulkAdd && selectedDomains.size > 0) {
      onBulkAdd(Array.from(selectedDomains));
      setSelectedDomains(new Set());
    }
  };

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
            const isSelected = selectedDomains.has(entry.domain);
            return (
              <div
                key={entry.domain}
                className="flex items-center justify-between gap-3 py-1.5 px-2 rounded hover:bg-surface-700/50"
              >
                <div className="flex items-center gap-3 min-w-0 flex-1">
                  {showCheckboxes && !isAllowlisted && (
                    <input
                      type="checkbox"
                      checked={isSelected}
                      onChange={() => toggleDomain(entry.domain)}
                      className="w-3.5 h-3.5 rounded bg-surface-900 border-surface-600 flex-shrink-0"
                    />
                  )}
                  {onDiagnose ? (
                    <button
                      onClick={() => onDiagnose(entry.domain)}
                      className="text-surface-100 text-sm font-mono truncate hover:underline hover:text-blue-400 text-left"
                      title="Diagnose why this domain was blocked"
                    >
                      {entry.domain}
                    </button>
                  ) : (
                    <span className="text-surface-100 text-sm font-mono truncate">{entry.domain}</span>
                  )}
                  <Badge variant="error">{entry.count}</Badge>
                </div>
                <div className="flex items-center gap-2 flex-shrink-0">
                  <span className="text-surface-500 text-xs">{timeAgo(entry.last_seen)}</span>
                  {!readOnly && (
                    isAllowlisted ? (
                      <span className="text-green-400 text-sm" title="Already allowlisted">&#10003;</span>
                    ) : onAddWithTTL ? (
                      <TTLDropdown domain={entry.domain} onAdd={onAdd} onAddWithTTL={onAddWithTTL} />
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

      {/* Bulk action bar */}
      {selectedDomains.size > 0 && onBulkAdd && (
        <div className="mt-3 pt-3 border-t border-surface-700 flex items-center justify-between">
          <span className="text-xs text-surface-400">
            {selectedDomains.size} domain{selectedDomains.size > 1 ? 's' : ''} selected
          </span>
          <div className="flex items-center gap-2">
            <button
              onClick={() => setSelectedDomains(new Set())}
              className="text-xs text-surface-500 hover:text-surface-300"
            >
              Clear
            </button>
            <Button size="sm" onClick={handleBulkAdd}>
              Add {selectedDomains.size} domain{selectedDomains.size > 1 ? 's' : ''}
            </Button>
          </div>
        </div>
      )}
    </Card>
  );
}
