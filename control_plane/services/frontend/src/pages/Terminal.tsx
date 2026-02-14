import { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { Terminal as TerminalIcon, X, Maximize2, Minimize2, RefreshCw } from 'lucide-react';
import { Card, Button, Badge } from '@cagent/shared-ui';
import { useTerminal } from '../hooks/useTerminal';
import { useAgentStatus } from '../hooks/useApi';
import { useAuth } from '../contexts/AuthContext';
import '@xterm/xterm/css/xterm.css';

export function Terminal() {
  const { agentId } = useParams<{ agentId: string }>();
  const navigate = useNavigate();
  const { user } = useAuth();

  const [connected, setConnected] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [fullscreen, setFullscreen] = useState(false);

  const { data: agentStatus, isLoading: statusLoading } = useAgentStatus(agentId || null);

  const { containerRef, connect, disconnect } = useTerminal({
    agentId: agentId || '',
    onConnect: () => {
      setConnected(true);
      setError(null);
    },
    onDisconnect: () => setConnected(false),
    onError: setError,
  });

  // Check if user has developer role
  const hasDeveloperRole = user?.roles?.includes('developer') || user?.is_super_admin;

  // Auto-connect when agent is online and running
  useEffect(() => {
    if (agentId && agentStatus?.online && agentStatus?.status === 'running' && hasDeveloperRole) {
      const cleanup = connect();
      return cleanup;
    }
  }, [agentId, agentStatus?.online, agentStatus?.status, hasDeveloperRole, connect]);

  // Handle fullscreen toggle
  useEffect(() => {
    const handleEsc = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && fullscreen) {
        setFullscreen(false);
      }
    };
    window.addEventListener('keydown', handleEsc);
    return () => window.removeEventListener('keydown', handleEsc);
  }, [fullscreen]);

  if (!agentId) {
    return (
      <div className="space-y-6">
        <h1 className="text-2xl font-bold text-dark-100">Web Terminal</h1>
        <Card>
          <div className="text-center py-12 text-dark-400">
            <TerminalIcon size={48} className="mx-auto mb-4 opacity-50" />
            <p className="text-lg">No agent group selected</p>
            <p className="text-sm mt-2">
              Select an agent group from the dashboard to open a terminal session.
            </p>
            <Button
              variant="secondary"
              className="mt-4"
              onClick={() => navigate('/')}
            >
              Go to Dashboard
            </Button>
          </div>
        </Card>
      </div>
    );
  }

  if (!hasDeveloperRole) {
    return (
      <div className="space-y-6">
        <h1 className="text-2xl font-bold text-dark-100">Web Terminal</h1>
        <Card>
          <div className="text-center py-12 text-dark-400">
            <TerminalIcon size={48} className="mx-auto mb-4 opacity-50" />
            <p className="text-lg">Access Denied</p>
            <p className="text-sm mt-2">
              Developer role is required to access the web terminal.
            </p>
          </div>
        </Card>
      </div>
    );
  }

  const isAgentAvailable = agentStatus?.online && agentStatus?.status === 'running';

  return (
    <div className={fullscreen ? 'fixed inset-0 z-50 bg-dark-950 flex flex-col' : 'space-y-4'}>
      {/* Header */}
      <div className={`flex items-center justify-between ${fullscreen ? 'p-4 bg-dark-900 border-b border-dark-700' : ''}`}>
        <div className="flex items-center gap-3">
          <TerminalIcon className="text-dark-400" size={24} />
          <div>
            <h1 className="text-xl font-bold text-dark-100">
              Terminal: {agentId}
            </h1>
            {!fullscreen && (
              <p className="text-sm text-dark-400">
                Secure shell access to the agent group container
              </p>
            )}
          </div>
          <Badge variant={connected ? 'success' : isAgentAvailable ? 'default' : 'error'}>
            {connected ? 'Connected' : isAgentAvailable ? 'Ready' : 'Unavailable'}
          </Badge>
        </div>

        <div className="flex items-center gap-2">
          {connected && (
            <Button
              variant="ghost"
              size="sm"
              onClick={() => {
                disconnect();
                setTimeout(connect, 100);
              }}
              title="Reconnect"
            >
              <RefreshCw size={18} />
            </Button>
          )}
          <Button
            variant="ghost"
            size="sm"
            onClick={() => setFullscreen(!fullscreen)}
            title={fullscreen ? 'Exit fullscreen' : 'Fullscreen'}
          >
            {fullscreen ? <Minimize2 size={18} /> : <Maximize2 size={18} />}
          </Button>
          <Button
            variant="ghost"
            size="sm"
            onClick={() => navigate('/')}
            title="Close"
          >
            <X size={18} />
          </Button>
        </div>
      </div>

      {/* Error message */}
      {error && (
        <div className={`${fullscreen ? 'mx-4' : ''} p-3 bg-red-900/50 border border-red-700 rounded-lg text-red-200 flex items-center justify-between`}>
          <span>{error}</span>
          <button
            onClick={() => setError(null)}
            className="text-red-300 hover:text-red-100"
          >
            <X size={16} />
          </button>
        </div>
      )}

      {/* Terminal or unavailable message */}
      {statusLoading ? (
        <Card>
          <div className="text-center py-12 text-dark-400">
            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-dark-400 mx-auto mb-4" />
            <p>Loading agent group status...</p>
          </div>
        </Card>
      ) : !isAgentAvailable ? (
        <Card>
          <div className="text-center py-12 text-dark-400">
            <TerminalIcon size={48} className="mx-auto mb-4 opacity-50" />
            <p className="text-lg">Agent Group Unavailable</p>
            <p className="text-sm mt-2">
              {!agentStatus?.online
                ? 'The agent group is offline. Start the agent group to access the terminal.'
                : 'The agent group is not running. Start the agent group container to access the terminal.'}
            </p>
            <div className="mt-4 text-xs text-dark-500">
              Status: {agentStatus?.status || 'unknown'} | Online: {agentStatus?.online ? 'Yes' : 'No'}
            </div>
          </div>
        </Card>
      ) : (
        <div
          ref={containerRef}
          className={`bg-dark-950 rounded-lg border border-dark-700 p-1 ${
            fullscreen ? 'flex-1 mx-4 mb-4' : 'h-[600px]'
          }`}
          style={{ minHeight: fullscreen ? 0 : '600px' }}
        />
      )}

      {/* Help text */}
      {!fullscreen && isAgentAvailable && (
        <div className="text-xs text-dark-500 flex items-center gap-4">
          <span>Press <kbd className="px-1 py-0.5 bg-dark-800 rounded">Esc</kbd> to exit fullscreen</span>
          <span>|</span>
          <span>Session is logged for audit purposes</span>
        </div>
      )}
    </div>
  );
}
