import { useEffect, useRef, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Terminal as TerminalIcon, RefreshCw, X, ChevronDown } from 'lucide-react';
import { Terminal } from '@xterm/xterm';
import { FitAddon } from '@xterm/addon-fit';
import { createTerminal, getContainers } from '../api/client';
import '@xterm/xterm/css/xterm.css';

const INFRA_CONTAINERS = new Set([
  'dns-filter', 'http-proxy', 'email-proxy', 'tunnel-client', 'warden',
]);

export default function TerminalPage() {
  const terminalRef = useRef<HTMLDivElement>(null);
  const xtermRef = useRef<Terminal | null>(null);
  const wsRef = useRef<WebSocket | null>(null);
  const fitAddonRef = useRef<FitAddon | null>(null);

  const [selectedContainer, setSelectedContainer] = useState<string | null>(null);
  const [isConnected, setIsConnected] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Fetch containers to discover agent containers dynamically
  const { data: containersData } = useQuery({
    queryKey: ['containers'],
    queryFn: getContainers,
    refetchInterval: 10000,
  });

  // Extract agent containers (anything not infrastructure)
  const agentContainers = containersData
    ? Object.values(containersData.containers)
        .filter((c) => !INFRA_CONTAINERS.has(c.name) && c.status === 'running')
        .map((c) => c.name)
    : [];

  // Auto-select first agent container
  useEffect(() => {
    if (!selectedContainer && agentContainers.length > 0) {
      setSelectedContainer(agentContainers[0]);
    }
  }, [agentContainers, selectedContainer]);

  const connect = () => {
    if (!terminalRef.current || !selectedContainer) return;

    // Clean up previous connection
    disconnect();

    // Create terminal
    const term = new Terminal({
      cursorBlink: true,
      fontSize: 14,
      fontFamily: 'Menlo, Monaco, "Courier New", monospace',
      theme: {
        background: '#1a1a2e',
        foreground: '#eaeaea',
        cursor: '#eaeaea',
        cursorAccent: '#1a1a2e',
        selectionBackground: '#3d3d5c',
        black: '#1a1a2e',
        red: '#ff6b6b',
        green: '#4ecdc4',
        yellow: '#ffe66d',
        blue: '#4dabf7',
        magenta: '#da77f2',
        cyan: '#66d9ef',
        white: '#eaeaea',
        brightBlack: '#4a4a6a',
        brightRed: '#ff8787',
        brightGreen: '#69dbcf',
        brightYellow: '#fff078',
        brightBlue: '#74c0fc',
        brightMagenta: '#e599f7',
        brightCyan: '#81e6f2',
        brightWhite: '#ffffff',
      },
    });

    const fitAddon = new FitAddon();
    term.loadAddon(fitAddon);

    term.open(terminalRef.current);
    fitAddon.fit();

    xtermRef.current = term;
    fitAddonRef.current = fitAddon;

    // Connect WebSocket to the selected container
    const ws = createTerminal(selectedContainer);
    wsRef.current = ws;

    ws.onopen = () => {
      setIsConnected(true);
      setError(null);
      term.write(`\r\n\x1b[32mConnected to ${selectedContainer}\x1b[0m\r\n\r\n`);
    };

    ws.onmessage = (event) => {
      term.write(event.data);
    };

    ws.onerror = () => {
      setError('WebSocket connection error');
      setIsConnected(false);
    };

    ws.onclose = () => {
      setIsConnected(false);
      term.write('\r\n\x1b[31mConnection closed\x1b[0m\r\n');
    };

    // Send input to WebSocket
    term.onData((data) => {
      if (ws.readyState === WebSocket.OPEN) {
        ws.send(data);
      }
    });

    // Handle resize
    const handleResize = () => {
      if (fitAddonRef.current) {
        fitAddonRef.current.fit();
      }
    };

    window.addEventListener('resize', handleResize);

    return () => {
      window.removeEventListener('resize', handleResize);
    };
  };

  const disconnect = () => {
    if (wsRef.current) {
      wsRef.current.close();
      wsRef.current = null;
    }
    if (xtermRef.current) {
      xtermRef.current.dispose();
      xtermRef.current = null;
    }
    setIsConnected(false);
  };

  useEffect(() => {
    return () => {
      disconnect();
    };
  }, []);

  return (
    <div className="h-full flex flex-col">
      <div className="flex items-center justify-between mb-4">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <TerminalIcon className="w-6 h-6 text-green-400" />
            Web Terminal
          </h1>
          <p className="text-sm text-gray-400 mt-1">
            Interactive shell access to agent containers
          </p>
        </div>

        <div className="flex items-center gap-2">
          {/* Container Selector */}
          <div className="relative">
            <select
              value={selectedContainer || ''}
              onChange={(e) => {
                const newContainer = e.target.value || null;
                if (isConnected) disconnect();
                setSelectedContainer(newContainer);
              }}
              className="appearance-none bg-gray-800 border border-gray-600 rounded-lg px-3 py-2 pr-8 text-sm text-gray-200 focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
            >
              {agentContainers.length === 0 && (
                <option value="">No agent containers</option>
              )}
              {agentContainers.map((name) => (
                <option key={name} value={name}>
                  {name}
                </option>
              ))}
            </select>
            <ChevronDown
              size={16}
              className="absolute right-2 top-1/2 -translate-y-1/2 text-gray-400 pointer-events-none"
            />
          </div>

          {!isConnected ? (
            <button
              onClick={connect}
              disabled={!selectedContainer}
              className="flex items-center gap-2 px-4 py-2 bg-green-600 hover:bg-green-700 text-white rounded-lg disabled:opacity-50 disabled:cursor-not-allowed"
            >
              <TerminalIcon className="w-4 h-4" />
              Connect
            </button>
          ) : (
            <button
              onClick={disconnect}
              className="flex items-center gap-2 px-4 py-2 bg-red-600 hover:bg-red-700 text-white rounded-lg"
            >
              <X className="w-4 h-4" />
              Disconnect
            </button>
          )}

          {isConnected && (
            <button
              onClick={() => {
                disconnect();
                setTimeout(connect, 100);
              }}
              className="flex items-center gap-2 px-4 py-2 bg-gray-600 hover:bg-gray-700 text-white rounded-lg"
            >
              <RefreshCw className="w-4 h-4" />
              Reconnect
            </button>
          )}
        </div>
      </div>

      {error && (
        <div className="bg-red-900/50 border border-red-700 text-red-300 p-3 rounded-lg mb-4">
          {error}
        </div>
      )}

      <div className="flex items-center gap-2 mb-2">
        <span
          className={`w-2 h-2 rounded-full ${isConnected ? 'bg-green-400' : 'bg-gray-500'}`}
        />
        <span className="text-sm text-gray-400">
          {isConnected ? `Connected to ${selectedContainer}` : 'Disconnected'}
        </span>
      </div>

      <div
        ref={terminalRef}
        className="flex-1 bg-[#1a1a2e] rounded-lg border border-gray-700 p-2 min-h-[400px]"
      />
    </div>
  );
}
