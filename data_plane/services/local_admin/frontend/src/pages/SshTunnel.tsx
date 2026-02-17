import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  Terminal,
  Play,
  Square,
  Copy,
  CheckCircle,
  AlertCircle,
  Server,
  Shield,
} from 'lucide-react';
import {
  getSshTunnelStatus,
  configureSshTunnel,
  startSshTunnel,
  stopSshTunnel,
  getSshConnectInfo,
  SshTunnelConfig,
} from '../api/client';

export default function SshTunnelPage() {
  const queryClient = useQueryClient();
  const [showConfig, setShowConfig] = useState(false);
  const [showConnectInfo, setShowConnectInfo] = useState(false);
  const [copied, setCopied] = useState<string | null>(null);
  const [message, setMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null);

  // Form state
  const [formData, setFormData] = useState<SshTunnelConfig>({
    frp_auth_token: '',
    frp_server_addr: '',
    frp_server_port: 7000,
  });

  const { data: status, isLoading } = useQuery({
    queryKey: ['ssh-tunnel-status'],
    queryFn: getSshTunnelStatus,
    refetchInterval: 5000,
  });

  const { data: connectInfo } = useQuery({
    queryKey: ['ssh-connect-info'],
    queryFn: getSshConnectInfo,
    enabled: status?.configured ?? false,
  });

  const configureMutation = useMutation({
    mutationFn: configureSshTunnel,
    onSuccess: (result) => {
      queryClient.invalidateQueries({ queryKey: ['ssh-tunnel-status'] });
      setMessage({ type: 'success', text: result.message });
      setShowConfig(false);
      setTimeout(() => setMessage(null), 5000);
    },
    onError: (err) => {
      setMessage({ type: 'error', text: (err as Error).message });
    },
  });

  const startMutation = useMutation({
    mutationFn: startSshTunnel,
    onSuccess: (result) => {
      queryClient.invalidateQueries({ queryKey: ['ssh-tunnel-status'] });
      queryClient.invalidateQueries({ queryKey: ['ssh-connect-info'] });
      setMessage({ type: 'success', text: result.message });
      setTimeout(() => setMessage(null), 3000);
    },
    onError: (err) => {
      setMessage({ type: 'error', text: (err as Error).message });
    },
  });

  const stopMutation = useMutation({
    mutationFn: stopSshTunnel,
    onSuccess: (result) => {
      queryClient.invalidateQueries({ queryKey: ['ssh-tunnel-status'] });
      setMessage({ type: 'success', text: result.message });
      setTimeout(() => setMessage(null), 3000);
    },
    onError: (err) => {
      setMessage({ type: 'error', text: (err as Error).message });
    },
  });

  const copyToClipboard = (text: string, label: string) => {
    navigator.clipboard.writeText(text);
    setCopied(label);
    setTimeout(() => setCopied(null), 2000);
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    configureMutation.mutate(formData);
  };

  if (isLoading) {
    return <div className="text-gray-400">Loading SSH tunnel status...</div>;
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <Terminal className="w-6 h-6 text-blue-400" />
            SSH Tunnel
          </h1>
          <p className="text-sm text-gray-400 mt-1">
            Self-bootstrapping STCP tunnel for secure SSH access via FRP
          </p>
        </div>
      </div>

      {message && (
        <div
          className={`flex items-center gap-2 p-3 rounded-lg ${
            message.type === 'success'
              ? 'bg-green-900/50 border border-green-700 text-green-300'
              : 'bg-red-900/50 border border-red-700 text-red-300'
          }`}
        >
          {message.type === 'success' ? (
            <CheckCircle className="w-4 h-4" />
          ) : (
            <AlertCircle className="w-4 h-4" />
          )}
          {message.text}
        </div>
      )}

      {/* Status Card */}
      <div className="bg-gray-800 border border-gray-700 rounded-lg p-6">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-lg font-semibold text-white">Tunnel Status</h2>
          <div className="flex items-center gap-2">
            {status?.connected ? (
              <span className="flex items-center gap-2 text-green-400">
                <span className="w-2 h-2 bg-green-400 rounded-full animate-pulse" />
                Connected
              </span>
            ) : status?.configured ? (
              <span className="flex items-center gap-2 text-yellow-400">
                <span className="w-2 h-2 bg-yellow-400 rounded-full" />
                Configured (Stopped)
              </span>
            ) : (
              <span className="flex items-center gap-2 text-gray-400">
                <span className="w-2 h-2 bg-gray-400 rounded-full" />
                Not Configured
              </span>
            )}
          </div>
        </div>

        <div className="grid grid-cols-2 gap-4 mb-6">
          <div>
            <span className="text-gray-400 text-sm">FRP Server</span>
            <p className="text-white">
              {status?.frp_server ? `${status.frp_server}:${status.frp_server_port}` : '-'}
            </p>
          </div>
          <div>
            <span className="text-gray-400 text-sm">Container Status</span>
            <p className="text-white capitalize">{status?.container_status || '-'}</p>
          </div>
          <div>
            <span className="text-gray-400 text-sm">Control Plane</span>
            <p className="text-white text-sm truncate">
              {status?.control_plane_url || '-'}
            </p>
          </div>
          <div>
            <span className="text-gray-400 text-sm">Credentials</span>
            <p className="text-white text-sm">
              {status?.configured ? (
                <span className="text-green-400">Auto-provisioned from CP</span>
              ) : (
                <span className="text-gray-500">
                  {!status?.has_cp_token && 'Missing CP token. '}
                  {!status?.has_frp_token && 'Missing FRP token.'}
                  {status?.has_cp_token && status?.has_frp_token && 'Missing CP URL.'}
                </span>
              )}
            </p>
          </div>
        </div>

        <div className="flex gap-2">
          {status?.connected ? (
            <button
              onClick={() => stopMutation.mutate()}
              disabled={stopMutation.isPending}
              className="flex items-center gap-2 px-4 py-2 bg-red-600 hover:bg-red-700 text-white rounded-lg disabled:opacity-50"
            >
              <Square className="w-4 h-4" />
              Stop Tunnel
            </button>
          ) : status?.configured ? (
            <button
              onClick={() => startMutation.mutate()}
              disabled={startMutation.isPending}
              className="flex items-center gap-2 px-4 py-2 bg-green-600 hover:bg-green-700 text-white rounded-lg disabled:opacity-50"
            >
              <Play className="w-4 h-4" />
              Start Tunnel
            </button>
          ) : null}

          <button
            onClick={() => {
              if (status) {
                setFormData({
                  frp_auth_token: '',
                  frp_server_addr: status.frp_server || '',
                  frp_server_port: parseInt(status.frp_server_port || '7000'),
                });
              }
              setShowConfig(true);
            }}
            className="flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg"
          >
            <Server className="w-4 h-4" />
            {status?.configured ? 'Reconfigure' : 'Configure'}
          </button>

          {status?.configured && (
            <button
              onClick={() => setShowConnectInfo(!showConnectInfo)}
              className="flex items-center gap-2 px-4 py-2 bg-gray-600 hover:bg-gray-700 text-white rounded-lg"
            >
              <Shield className="w-4 h-4" />
              Connection Info
            </button>
          )}
        </div>
      </div>

      {/* Connection Info */}
      {showConnectInfo && connectInfo && (
        <div className="bg-gray-800 border border-gray-700 rounded-lg p-6">
          <h2 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
            <Shield className="w-5 h-5 text-green-400" />
            Connection Information
          </h2>

          <p className="text-gray-400 text-sm mb-4">
            To connect to this agent via SSH, run an FRP visitor on your local machine with the config below.
          </p>

          <div className="space-y-4">
            <div>
              <div className="flex items-center justify-between">
                <span className="text-gray-400 text-sm">Visitor Config (frpc-visitor.toml)</span>
                <button
                  onClick={() => copyToClipboard(connectInfo.visitor_config, 'config')}
                  className="text-blue-400 hover:text-blue-300 flex items-center gap-1 text-sm"
                >
                  {copied === 'config' ? (
                    <CheckCircle className="w-3 h-3" />
                  ) : (
                    <Copy className="w-3 h-3" />
                  )}
                  Copy
                </button>
              </div>
              <pre className="font-mono text-xs text-gray-300 bg-gray-900 p-3 rounded mt-1 overflow-x-auto">
                {connectInfo.visitor_config}
              </pre>
            </div>

            <div>
              <span className="text-gray-400 text-sm">SSH Command (after starting visitor)</span>
              <div className="flex items-center gap-2 mt-1">
                <code className="font-mono text-sm text-green-400 bg-gray-900 p-2 rounded flex-1">
                  {connectInfo.ssh_command}
                </code>
                <button
                  onClick={() => copyToClipboard('ssh -p 2222 agent@127.0.0.1', 'ssh')}
                  className="text-blue-400 hover:text-blue-300"
                >
                  {copied === 'ssh' ? (
                    <CheckCircle className="w-4 h-4" />
                  ) : (
                    <Copy className="w-4 h-4" />
                  )}
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Configuration Modal */}
      {showConfig && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div className="bg-gray-800 border border-gray-700 rounded-lg p-6 w-full max-w-lg">
            <h2 className="text-lg font-semibold text-white mb-2">Configure SSH Tunnel</h2>
            <p className="text-sm text-gray-400 mb-4">
              STCP credentials are auto-provisioned from the control plane.
              Only FRP server settings are needed here.
            </p>

            <form onSubmit={handleSubmit} className="space-y-4">
              <div>
                <label className="block text-sm text-gray-400 mb-1">FRP Auth Token</label>
                <input
                  type="password"
                  value={formData.frp_auth_token}
                  onChange={(e) =>
                    setFormData((prev) => ({ ...prev, frp_auth_token: e.target.value }))
                  }
                  placeholder="Must match frps.toml on control plane"
                  className="w-full bg-gray-900 border border-gray-600 rounded px-3 py-2 text-white focus:border-blue-500 focus:outline-none"
                  required
                />
              </div>

              <div>
                <label className="block text-sm text-gray-400 mb-1">
                  FRP Server Address
                  <span className="text-gray-500 ml-1">(optional, derived from CP URL)</span>
                </label>
                <input
                  type="text"
                  value={formData.frp_server_addr}
                  onChange={(e) =>
                    setFormData((prev) => ({ ...prev, frp_server_addr: e.target.value }))
                  }
                  placeholder="Leave empty to use control plane host"
                  className="w-full bg-gray-900 border border-gray-600 rounded px-3 py-2 text-white focus:border-blue-500 focus:outline-none"
                />
              </div>

              <div>
                <label className="block text-sm text-gray-400 mb-1">FRP Server Port</label>
                <input
                  type="number"
                  value={formData.frp_server_port}
                  onChange={(e) =>
                    setFormData((prev) => ({ ...prev, frp_server_port: parseInt(e.target.value) }))
                  }
                  className="w-full bg-gray-900 border border-gray-600 rounded px-3 py-2 text-white focus:border-blue-500 focus:outline-none"
                  required
                />
              </div>

              <div className="flex justify-end gap-2 pt-4">
                <button
                  type="button"
                  onClick={() => setShowConfig(false)}
                  className="px-4 py-2 bg-gray-700 hover:bg-gray-600 text-white rounded"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={configureMutation.isPending}
                  className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded disabled:opacity-50"
                >
                  {configureMutation.isPending ? 'Saving...' : 'Save Configuration'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
