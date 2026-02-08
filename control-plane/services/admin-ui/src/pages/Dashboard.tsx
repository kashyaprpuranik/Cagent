import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Server,
  RefreshCw,
  Trash2,
  Play,
  Square,
  ChevronDown,
  Circle,
  AlertCircle,
  X,
  CheckCircle,
  XCircle,
  ShieldOff,
  Terminal,
} from 'lucide-react';
import { Card, Badge, Button, Modal } from '../components/common';
import { useAuth } from '../contexts/AuthContext';
import { useTenant } from '../contexts/TenantContext';
import {
  useHealth,
  useDataPlanes,
  useAgentStatus,
  useWipeAgent,
  useRestartAgent,
  useStopAgent,
  useStartAgent,
  useApproveAgent,
  useRejectAgent,
  useRevokeAgent,
} from '../hooks/useApi';

export function Dashboard() {
  const { user } = useAuth();
  const { selectedTenantId } = useTenant();
  const navigate = useNavigate();
  const { data: health } = useHealth();
  // Pass tenant filter - super admins see agents for selected tenant, others see their tenant's agents
  const { data: dataPlanes, refetch: refetchDataPlanes } = useDataPlanes(selectedTenantId);

  // Check if user has developer role for terminal access
  const hasDeveloperRole = user?.roles?.includes('developer') || user?.is_super_admin;

  const [selectedAgentId, setSelectedAgentId] = useState<string | null>(null);
  const [dropdownOpen, setDropdownOpen] = useState(false);

  const { data: agentStatus, refetch: refetchAgent } = useAgentStatus(selectedAgentId);

  const wipeAgent = useWipeAgent();
  const restartAgent = useRestartAgent();
  const stopAgent = useStopAgent();
  const startAgent = useStartAgent();
  const approveAgent = useApproveAgent();
  const rejectAgent = useRejectAgent();
  const revokeAgent = useRevokeAgent();

  const [wipeModal, setWipeModal] = useState(false);
  const [wipeWorkspace, setWipeWorkspace] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [rejectModal, setRejectModal] = useState<string | null>(null);
  const [revokeModal, setRevokeModal] = useState<string | null>(null);

  // Auto-select first data plane when list loads
  useEffect(() => {
    if (dataPlanes && dataPlanes.length > 0 && !selectedAgentId) {
      setSelectedAgentId(dataPlanes[0].agent_id);
    }
  }, [dataPlanes, selectedAgentId]);

  const selectedDataPlane = dataPlanes?.find(dp => dp.agent_id === selectedAgentId);

  const handleWipe = async () => {
    if (!selectedAgentId) return;
    setError(null);
    try {
      await wipeAgent.mutateAsync({ agentId: selectedAgentId, wipeWorkspace });
      setWipeModal(false);
      setWipeWorkspace(false);
    } catch (e) {
      setError(`Wipe failed: ${e instanceof Error ? e.message : 'Unknown error'}`);
    }
  };

  const handleRestart = async () => {
    if (!selectedAgentId) return;
    setError(null);
    try {
      await restartAgent.mutateAsync(selectedAgentId);
    } catch (e) {
      setError(`Restart failed: ${e instanceof Error ? e.message : 'Unknown error'}`);
    }
  };

  const handleStop = async () => {
    if (!selectedAgentId) return;
    setError(null);
    try {
      await stopAgent.mutateAsync(selectedAgentId);
    } catch (e) {
      setError(`Stop failed: ${e instanceof Error ? e.message : 'Unknown error'}`);
    }
  };

  const handleStart = async () => {
    if (!selectedAgentId) return;
    setError(null);
    try {
      await startAgent.mutateAsync(selectedAgentId);
    } catch (e) {
      setError(`Start failed: ${e instanceof Error ? e.message : 'Unknown error'}`);
    }
  };

  const handleApprove = async (agentId: string) => {
    setError(null);
    try {
      await approveAgent.mutateAsync(agentId);
    } catch (e) {
      setError(`Approve failed: ${e instanceof Error ? e.message : 'Unknown error'}`);
    }
  };

  const handleReject = async (agentId: string) => {
    setError(null);
    try {
      await rejectAgent.mutateAsync(agentId);
      setRejectModal(null);
    } catch (e) {
      setError(`Reject failed: ${e instanceof Error ? e.message : 'Unknown error'}`);
    }
  };

  const handleRevoke = async (agentId: string) => {
    setError(null);
    try {
      await revokeAgent.mutateAsync(agentId);
      setRevokeModal(null);
    } catch (e) {
      setError(`Revoke failed: ${e instanceof Error ? e.message : 'Unknown error'}`);
    }
  };

  const pendingAgents = dataPlanes?.filter(dp => !dp.approved) || [];

  const getAgentStatusBadge = () => {
    if (!agentStatus) return <Badge>Unknown</Badge>;
    switch (agentStatus.status) {
      case 'running':
        return <Badge variant="success">Running</Badge>;
      case 'exited':
      case 'stopped':
        return <Badge variant="default">Stopped</Badge>;
      case 'not_found':
        return <Badge variant="warning">Not Found</Badge>;
      default:
        return <Badge>{agentStatus.status}</Badge>;
    }
  };

  const isAgentRunning = agentStatus?.status === 'running';
  const isAgentStopped = agentStatus?.status === 'stopped' || agentStatus?.status === 'exited';

  return (
    <div className="space-y-6">
      {/* Error Toast */}
      {error && (
        <div className="flex items-center gap-3 p-4 bg-red-900/50 border border-red-700 rounded-lg text-red-200">
          <AlertCircle size={20} className="flex-shrink-0" />
          <span className="flex-1">{error}</span>
          <button onClick={() => setError(null)} className="text-red-400 hover:text-red-200">
            <X size={18} />
          </button>
        </div>
      )}

      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-dark-100">Dashboard</h1>
        <div className="flex items-center gap-4">
          {/* Data Plane Selector */}
          <div className="relative">
            <button
              onClick={() => dataPlanes && dataPlanes.length > 0 && setDropdownOpen(!dropdownOpen)}
              className={`flex items-center gap-2 px-3 py-2 bg-dark-800 border border-dark-600 rounded-lg text-dark-200 transition-colors min-w-[200px] ${
                dataPlanes && dataPlanes.length > 0 ? 'hover:bg-dark-700 cursor-pointer' : 'cursor-default opacity-75'
              }`}
            >
              <Server size={16} className="text-dark-400" />
              <span className="flex-1 text-left truncate">
                {selectedAgentId || (dataPlanes && dataPlanes.length > 0 ? 'Select Data Plane' : 'No Data Planes')}
              </span>
              {selectedDataPlane && (
                <Circle
                  size={8}
                  className={selectedDataPlane.online ? 'text-green-500 fill-green-500' : 'text-red-500 fill-red-500'}
                />
              )}
              {dataPlanes && dataPlanes.length > 0 && <ChevronDown size={16} className="text-dark-400" />}
            </button>
            {dropdownOpen && (
              <div className="absolute top-full left-0 right-0 mt-1 bg-dark-800 border border-dark-600 rounded-lg shadow-lg z-10 max-h-64 overflow-y-auto">
                {dataPlanes && dataPlanes.length > 0 ? (
                  dataPlanes.map((dp) => (
                    <button
                      key={dp.agent_id}
                      onClick={() => {
                        setSelectedAgentId(dp.agent_id);
                        setDropdownOpen(false);
                      }}
                      className={`w-full flex items-center gap-2 px-3 py-2 text-left hover:bg-dark-700 transition-colors ${
                        dp.agent_id === selectedAgentId ? 'bg-dark-700' : ''
                      }`}
                    >
                      <Circle
                        size={8}
                        className={dp.online ? 'text-green-500 fill-green-500' : 'text-red-500 fill-red-500'}
                      />
                      <span className="text-dark-200 truncate">{dp.agent_id}</span>
                      {!dp.approved && (
                        <span className="text-yellow-400 text-xs">(pending)</span>
                      )}
                      <span className="text-dark-500 text-xs ml-auto">{dp.status}</span>
                    </button>
                  ))
                ) : (
                  <div className="px-3 py-2 text-dark-400 text-sm">No data planes connected</div>
                )}
              </div>
            )}
          </div>

          {/* System Health Indicator */}
          <div className="flex items-center gap-2" title={`API ${health?.status || 'unknown'}`}>
            <span
              className={`w-3 h-3 rounded-full ${
                health?.status === 'healthy' ? 'bg-green-500' : 'bg-red-500'
              }`}
            />
          </div>
        </div>
      </div>

      {/* Agent Management Card */}
      {selectedAgentId ? (
        <Card
          title={`Data Plane: ${selectedAgentId}`}
          action={
            <Button variant="ghost" size="sm" onClick={() => {
              refetchAgent();
              refetchDataPlanes();
            }}>
              <RefreshCw size={14} />
            </Button>
          }
        >
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-4">
                <div className="p-3 bg-purple-600/20 rounded-lg">
                  <Server className="text-purple-400" size={24} />
                </div>
                <div>
                  <div className="flex items-center gap-2">
                    <span className="font-medium text-dark-100">
                      {agentStatus?.agent_id || selectedAgentId}
                    </span>
                    {getAgentStatusBadge()}
                    {selectedDataPlane?.approved ? (
                      <Badge variant="success">Approved</Badge>
                    ) : (
                      <Badge variant="warning">Pending</Badge>
                    )}
                    {agentStatus?.online !== undefined && (
                      <span className={`text-xs ${agentStatus.online ? 'text-green-400' : 'text-red-400'}`}>
                        {agentStatus.online ? 'Online' : 'Offline'}
                      </span>
                    )}
                  </div>
                  {agentStatus?.container_id && (
                    <p className="text-dark-500 text-sm font-mono">
                      {agentStatus.container_id.substring(0, 12)}
                    </p>
                  )}
                  {agentStatus?.last_heartbeat && (
                    <p className="text-dark-500 text-xs">
                      Last heartbeat: {new Date(agentStatus.last_heartbeat).toLocaleString()}
                    </p>
                  )}
                </div>
              </div>
              <div className="flex items-center gap-2">
                {/* Approval controls */}
                {selectedDataPlane && !selectedDataPlane.approved && (
                  <>
                    <Button
                      variant="secondary"
                      size="sm"
                      onClick={() => handleApprove(selectedAgentId!)}
                      disabled={approveAgent.isPending}
                      className="bg-green-600/20 hover:bg-green-600/30 text-green-400"
                    >
                      <CheckCircle size={14} className="mr-1" />
                      {approveAgent.isPending ? 'Approving...' : 'Approve'}
                    </Button>
                    <Button
                      variant="danger"
                      size="sm"
                      onClick={() => setRejectModal(selectedAgentId)}
                    >
                      <XCircle size={14} className="mr-1" />
                      Reject
                    </Button>
                  </>
                )}
                {selectedDataPlane?.approved && (
                  <Button
                    variant="secondary"
                    size="sm"
                    onClick={() => setRevokeModal(selectedAgentId)}
                    className="text-yellow-400"
                  >
                    <ShieldOff size={14} className="mr-1" />
                    Revoke
                  </Button>
                )}
                {/* Container controls - only for approved agents */}
                {selectedDataPlane?.approved && (
                  <>
                    {isAgentStopped && (
                      <Button
                        variant="secondary"
                        size="sm"
                        onClick={handleStart}
                        disabled={startAgent.isPending}
                      >
                        <Play size={14} className="mr-1" />
                        {startAgent.isPending ? 'Starting...' : 'Start'}
                      </Button>
                    )}
                    {isAgentRunning && (
                      <Button
                        variant="secondary"
                        size="sm"
                        onClick={handleStop}
                        disabled={stopAgent.isPending}
                      >
                        <Square size={14} className="mr-1" />
                        {stopAgent.isPending ? 'Stopping...' : 'Stop'}
                      </Button>
                    )}
                    <Button
                      variant="secondary"
                      size="sm"
                      onClick={handleRestart}
                      disabled={restartAgent.isPending || agentStatus?.status === 'not_found'}
                    >
                      <RefreshCw size={14} className={`mr-1 ${restartAgent.isPending ? 'animate-spin' : ''}`} />
                      Restart
                    </Button>
                    <Button
                      variant="danger"
                      size="sm"
                      onClick={() => setWipeModal(true)}
                      disabled={agentStatus?.status === 'not_found'}
                    >
                      <Trash2 size={14} className="mr-1" />
                      Wipe
                    </Button>
                    {/* Terminal button - requires developer role */}
                    {hasDeveloperRole && (
                      <Button
                        variant="secondary"
                        size="sm"
                        onClick={() => navigate(`/terminal/${selectedAgentId}`)}
                        disabled={!agentStatus?.online || agentStatus?.status !== 'running'}
                        title={
                          !agentStatus?.online
                            ? 'Agent must be online'
                            : agentStatus?.status !== 'running'
                            ? 'Agent must be running'
                            : 'Open Web Terminal'
                        }
                      >
                        <Terminal size={14} className="mr-1" />
                        Terminal
                      </Button>
                    )}
                  </>
                )}
              </div>
            </div>

            {/* Agent Details */}
            {agentStatus && (
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4 pt-4 border-t border-dark-700">
                {agentStatus.uptime_seconds !== undefined && (
                  <div>
                    <p className="text-dark-500 text-xs">Uptime</p>
                    <p className="text-dark-200 text-sm">
                      {Math.floor(agentStatus.uptime_seconds / 3600)}h {Math.floor((agentStatus.uptime_seconds % 3600) / 60)}m
                    </p>
                  </div>
                )}
                {agentStatus.cpu_percent !== undefined && (
                  <div>
                    <p className="text-dark-500 text-xs">CPU</p>
                    <p className="text-dark-200 text-sm">{agentStatus.cpu_percent}%</p>
                  </div>
                )}
                {agentStatus.memory_mb !== undefined && (
                  <div>
                    <p className="text-dark-500 text-xs">Memory</p>
                    <p className="text-dark-200 text-sm">
                      {agentStatus.memory_mb} MB
                      {agentStatus.memory_limit_mb && ` / ${agentStatus.memory_limit_mb} MB`}
                    </p>
                  </div>
                )}
                {agentStatus.pending_command && (
                  <div>
                    <p className="text-dark-500 text-xs">Pending Command</p>
                    <p className="text-yellow-400 text-sm">{agentStatus.pending_command}</p>
                  </div>
                )}
                {agentStatus.last_command && (
                  <div>
                    <p className="text-dark-500 text-xs">Last Command</p>
                    <p className="text-dark-200 text-sm">
                      {agentStatus.last_command}
                      {agentStatus.last_command_result && (
                        <span className={agentStatus.last_command_result === 'success' ? 'text-green-400' : 'text-red-400'}>
                          {' '}({agentStatus.last_command_result})
                        </span>
                      )}
                    </p>
                  </div>
                )}
              </div>
            )}
          </div>
        </Card>
      ) : (
        <Card>
          <div className="text-center py-8 text-dark-400">
            <Server size={48} className="mx-auto mb-4 opacity-50" />
            <p>No data planes connected</p>
            <p className="text-sm mt-2">Data planes will appear here when they connect to the control plane</p>
          </div>
        </Card>
      )}

      {/* Pending Agents Alert */}
      {pendingAgents.length > 0 && (
        <Card title="Pending Agent Approvals" className="border-yellow-600/50">
          <div className="space-y-2">
            {pendingAgents.map((agent) => (
              <div
                key={agent.agent_id}
                className="flex items-center justify-between p-3 bg-yellow-900/20 border border-yellow-700/50 rounded-lg"
              >
                <div className="flex items-center gap-3">
                  <Server size={20} className="text-yellow-400" />
                  <div>
                    <span className="text-dark-100 font-medium">{agent.agent_id}</span>
                    <div className="flex items-center gap-2 text-xs text-dark-400">
                      <Circle
                        size={6}
                        className={agent.online ? 'text-green-500 fill-green-500' : 'text-red-500 fill-red-500'}
                      />
                      <span>{agent.online ? 'Online' : 'Offline'}</span>
                      {agent.last_heartbeat && (
                        <span>- Last seen: {new Date(agent.last_heartbeat).toLocaleString()}</span>
                      )}
                    </div>
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  <Button
                    size="sm"
                    onClick={() => handleApprove(agent.agent_id)}
                    disabled={approveAgent.isPending}
                    className="bg-green-600 hover:bg-green-700"
                  >
                    <CheckCircle size={14} className="mr-1" />
                    Approve
                  </Button>
                  <Button
                    variant="danger"
                    size="sm"
                    onClick={() => setRejectModal(agent.agent_id)}
                  >
                    <XCircle size={14} className="mr-1" />
                    Reject
                  </Button>
                </div>
              </div>
            ))}
          </div>
        </Card>
      )}


      {/* Wipe Confirmation Modal */}
      <Modal
        isOpen={wipeModal}
        onClose={() => setWipeModal(false)}
        title="Wipe Agent Container"
      >
        <div className="space-y-4">
          <p className="text-dark-300">
            This will stop and remove the agent container on <strong>{selectedAgentId}</strong>. It will be recreated automatically.
          </p>

          <label className="flex items-center gap-2 cursor-pointer">
            <input
              type="checkbox"
              checked={wipeWorkspace}
              onChange={(e) => setWipeWorkspace(e.target.checked)}
              className="w-4 h-4 rounded border-dark-600 bg-dark-900 text-blue-600 focus:ring-blue-500"
            />
            <span className="text-dark-200">Also wipe workspace volume</span>
          </label>

          {wipeWorkspace && (
            <p className="text-yellow-400 text-sm">
              Warning: This will delete all files in the agent workspace.
            </p>
          )}

          <div className="flex justify-end gap-2 pt-4">
            <Button variant="secondary" onClick={() => setWipeModal(false)}>
              Cancel
            </Button>
            <Button
              variant="danger"
              onClick={handleWipe}
              disabled={wipeAgent.isPending}
            >
              {wipeAgent.isPending ? 'Wiping...' : 'Wipe Agent'}
            </Button>
          </div>
        </div>
      </Modal>

      {/* Reject Agent Confirmation Modal */}
      <Modal
        isOpen={rejectModal !== null}
        onClose={() => setRejectModal(null)}
        title="Reject Agent"
      >
        <div className="space-y-4">
          <p className="text-dark-300">
            Are you sure you want to reject <strong>{rejectModal}</strong>? This will remove the agent from the system.
          </p>
          <p className="text-yellow-400 text-sm">
            The agent will need to be re-registered if you want to add it later.
          </p>
          <div className="flex justify-end gap-2 pt-4">
            <Button variant="secondary" onClick={() => setRejectModal(null)}>
              Cancel
            </Button>
            <Button
              variant="danger"
              onClick={() => rejectModal && handleReject(rejectModal)}
              disabled={rejectAgent.isPending}
            >
              {rejectAgent.isPending ? 'Rejecting...' : 'Reject Agent'}
            </Button>
          </div>
        </div>
      </Modal>

      {/* Revoke Agent Confirmation Modal */}
      <Modal
        isOpen={revokeModal !== null}
        onClose={() => setRevokeModal(null)}
        title="Revoke Agent Approval"
      >
        <div className="space-y-4">
          <p className="text-dark-300">
            Are you sure you want to revoke approval for <strong>{revokeModal}</strong>?
          </p>
          <p className="text-yellow-400 text-sm">
            The agent will no longer receive commands and will need to be re-approved.
          </p>
          <div className="flex justify-end gap-2 pt-4">
            <Button variant="secondary" onClick={() => setRevokeModal(null)}>
              Cancel
            </Button>
            <Button
              variant="danger"
              onClick={() => revokeModal && handleRevoke(revokeModal)}
              disabled={revokeAgent.isPending}
            >
              {revokeAgent.isPending ? 'Revoking...' : 'Revoke Approval'}
            </Button>
          </div>
        </div>
      </Modal>
    </div>
  );
}
