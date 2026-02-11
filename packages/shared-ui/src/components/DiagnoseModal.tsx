import { Modal } from './Modal';
import { Button } from './Button';

export interface DiagnoseRequest {
  timestamp: string;
  method: string;
  path: string;
  response_code: number;
  response_flags: string;
  duration_ms: number;
}

export interface DiagnoseResult {
  domain: string;
  in_allowlist: boolean;
  dns_result?: string;
  recent_requests: DiagnoseRequest[];
  diagnosis: string;
}

interface DiagnoseModalProps {
  domain: string;
  result: DiagnoseResult | null;
  isLoading: boolean;
  onClose: () => void;
  onAdd?: (domain: string) => void;
}

function StatusIcon({ ok }: { ok: boolean }) {
  return ok ? (
    <span className="text-green-400 text-lg">&#10003;</span>
  ) : (
    <span className="text-red-400 text-lg">&#10007;</span>
  );
}

function formatTime(isoStr: string): string {
  return new Date(isoStr).toLocaleTimeString([], {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  });
}

export function DiagnoseModal({ domain, result, isLoading, onClose, onAdd }: DiagnoseModalProps) {
  return (
    <Modal isOpen={true} onClose={onClose} title={`Diagnose: ${domain}`} size="lg">
      {isLoading ? (
        <div className="text-surface-400 text-sm animate-pulse py-8 text-center">
          Analyzing request path...
        </div>
      ) : !result ? (
        <div className="text-surface-500 text-sm text-center py-8">
          No diagnostic data available
        </div>
      ) : (
        <div className="space-y-4">
          {/* Diagnosis summary */}
          <div className="bg-surface-900 border border-surface-600 rounded-lg p-3">
            <p className="text-surface-200 text-sm">{result.diagnosis}</p>
          </div>

          {/* Step-by-step chain */}
          <div className="space-y-3">
            <div className="flex items-center gap-3 px-3 py-2 rounded bg-surface-800">
              <StatusIcon ok={result.in_allowlist} />
              <div>
                <div className="text-surface-200 text-sm font-medium">Allowlist check</div>
                <div className="text-surface-400 text-xs">
                  {result.in_allowlist ? 'Domain is in the allowlist' : 'Domain is not in the allowlist'}
                </div>
              </div>
            </div>

            {result.dns_result !== undefined && (
              <div className="flex items-center gap-3 px-3 py-2 rounded bg-surface-800">
                <StatusIcon ok={result.dns_result !== 'NXDOMAIN'} />
                <div>
                  <div className="text-surface-200 text-sm font-medium">DNS resolution</div>
                  <div className="text-surface-400 text-xs">
                    {result.dns_result === 'NXDOMAIN'
                      ? 'NXDOMAIN (blocked by CoreDNS)'
                      : `Resolved: ${result.dns_result}`}
                  </div>
                </div>
              </div>
            )}

            {result.recent_requests.length > 0 && (
              <div className="flex items-center gap-3 px-3 py-2 rounded bg-surface-800">
                <StatusIcon ok={result.recent_requests[0].response_code < 400} />
                <div>
                  <div className="text-surface-200 text-sm font-medium">Proxy decision</div>
                  <div className="text-surface-400 text-xs">
                    HTTP {result.recent_requests[0].response_code}
                    {result.recent_requests[0].response_flags && (
                      <> (flags: {result.recent_requests[0].response_flags})</>
                    )}
                  </div>
                </div>
              </div>
            )}
          </div>

          {/* Recent requests table */}
          {result.recent_requests.length > 0 && (
            <div>
              <h4 className="text-surface-300 text-xs font-medium mb-2">Recent Requests</h4>
              <div className="overflow-x-auto">
                <table className="w-full text-xs">
                  <thead>
                    <tr className="text-surface-500 text-left">
                      <th className="pb-1 pr-3">Time</th>
                      <th className="pb-1 pr-3">Method</th>
                      <th className="pb-1 pr-3">Path</th>
                      <th className="pb-1 pr-3">Code</th>
                      <th className="pb-1 pr-3">Flags</th>
                      <th className="pb-1">Duration</th>
                    </tr>
                  </thead>
                  <tbody>
                    {result.recent_requests.map((req, i) => (
                      <tr key={i} className="text-surface-300">
                        <td className="py-1 pr-3 font-mono">{formatTime(req.timestamp)}</td>
                        <td className="py-1 pr-3">{req.method}</td>
                        <td className="py-1 pr-3 font-mono truncate max-w-[150px]">{req.path}</td>
                        <td className={`py-1 pr-3 font-medium ${req.response_code >= 400 ? 'text-red-400' : 'text-green-400'}`}>
                          {req.response_code}
                        </td>
                        <td className="py-1 pr-3 text-surface-500">{req.response_flags || '-'}</td>
                        <td className="py-1 text-surface-500">{req.duration_ms}ms</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* Actions */}
          <div className="flex justify-end gap-2 pt-2 border-t border-surface-700">
            <Button variant="secondary" onClick={onClose}>Close</Button>
            {onAdd && !result.in_allowlist && (
              <Button onClick={() => { onAdd(domain); onClose(); }}>
                Add to allowlist
              </Button>
            )}
          </div>
        </div>
      )}
    </Modal>
  );
}
