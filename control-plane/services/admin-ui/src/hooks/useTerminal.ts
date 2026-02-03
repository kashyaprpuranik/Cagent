import { useRef, useCallback, useEffect } from 'react';
import { Terminal } from '@xterm/xterm';
import { FitAddon } from '@xterm/addon-fit';
import { WebLinksAddon } from '@xterm/addon-web-links';
import { api } from '../api/client';

interface UseTerminalOptions {
  agentId: string;
  onConnect?: () => void;
  onDisconnect?: () => void;
  onError?: (error: string) => void;
}

interface UseTerminalReturn {
  containerRef: React.RefObject<HTMLDivElement>;
  connect: () => (() => void) | undefined;
  disconnect: () => void;
  isConnected: boolean;
}

export function useTerminal({
  agentId,
  onConnect,
  onDisconnect,
  onError,
}: UseTerminalOptions): UseTerminalReturn {
  const terminalRef = useRef<Terminal | null>(null);
  const socketRef = useRef<WebSocket | null>(null);
  const fitAddonRef = useRef<FitAddon | null>(null);
  const containerRef = useRef<HTMLDivElement>(null);
  const isConnectedRef = useRef(false);

  const disconnect = useCallback(() => {
    if (socketRef.current) {
      socketRef.current.close();
      socketRef.current = null;
    }
    if (terminalRef.current) {
      terminalRef.current.dispose();
      terminalRef.current = null;
    }
    isConnectedRef.current = false;
  }, []);

  const connect = useCallback(() => {
    if (!containerRef.current || !agentId) return;

    // Clean up any existing connection
    disconnect();

    // Initialize terminal with dark theme matching admin UI
    const terminal = new Terminal({
      cursorBlink: true,
      fontSize: 14,
      fontFamily: '"JetBrains Mono", "Fira Code", "Consolas", "Monaco", monospace',
      theme: {
        background: '#111112', // dark-950
        foreground: '#ececf1', // dark-100
        cursor: '#ececf1',
        cursorAccent: '#111112',
        selectionBackground: 'rgba(255, 255, 255, 0.3)',
        black: '#000000',
        red: '#ef4444',
        green: '#22c55e',
        yellow: '#eab308',
        blue: '#3b82f6',
        magenta: '#a855f7',
        cyan: '#06b6d4',
        white: '#d4d4d8',
        brightBlack: '#71717a',
        brightRed: '#f87171',
        brightGreen: '#4ade80',
        brightYellow: '#facc15',
        brightBlue: '#60a5fa',
        brightMagenta: '#c084fc',
        brightCyan: '#22d3ee',
        brightWhite: '#fafafa',
      },
      allowProposedApi: true,
      scrollback: 5000,
    });

    // Add addons
    const fitAddon = new FitAddon();
    const webLinksAddon = new WebLinksAddon();

    terminal.loadAddon(fitAddon);
    terminal.loadAddon(webLinksAddon);

    // Mount terminal
    terminal.open(containerRef.current);
    fitAddon.fit();

    terminalRef.current = terminal;
    fitAddonRef.current = fitAddon;

    // Build WebSocket URL
    const token = api.getToken();
    if (!token) {
      terminal.write('\r\n\x1b[31mError: Not authenticated\x1b[0m\r\n');
      onError?.('Not authenticated');
      return;
    }

    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}/api/v1/terminal/${encodeURIComponent(agentId)}/ws?token=${encodeURIComponent(token)}`;

    terminal.write(`\x1b[90mConnecting to agent ${agentId}...\x1b[0m\r\n`);

    // Connect WebSocket
    const socket = new WebSocket(wsUrl);
    socket.binaryType = 'arraybuffer';

    socket.onopen = () => {
      terminal.write('\x1b[32mConnected!\x1b[0m\r\n\r\n');
      isConnectedRef.current = true;
      onConnect?.();

      // Send initial terminal size
      const { cols, rows } = terminal;
      socket.send(JSON.stringify({ type: 'resize', cols, rows }));
    };

    socket.onmessage = (event) => {
      if (event.data instanceof ArrayBuffer) {
        terminal.write(new Uint8Array(event.data));
      } else if (typeof event.data === 'string') {
        try {
          const msg = JSON.parse(event.data);
          if (msg.type === 'connected') {
            terminal.write(`\x1b[90mSession: ${msg.session_id}\x1b[0m\r\n`);
          } else if (msg.type === 'error') {
            terminal.write(`\r\n\x1b[31mError: ${msg.message}\x1b[0m\r\n`);
          }
        } catch {
          // Plain text message
          terminal.write(event.data);
        }
      }
    };

    socket.onclose = (event) => {
      isConnectedRef.current = false;
      const reason = event.reason || 'Connection closed';
      terminal.write(`\r\n\x1b[31mDisconnected: ${reason}\x1b[0m\r\n`);
      terminal.write('\x1b[90mPress any key to reconnect...\x1b[0m');
      onDisconnect?.();
    };

    socket.onerror = () => {
      onError?.('WebSocket connection error');
    };

    socketRef.current = socket;

    // Handle terminal input
    terminal.onData((data) => {
      if (socket.readyState === WebSocket.OPEN) {
        // Send as binary
        socket.send(new TextEncoder().encode(data));
      } else if (socket.readyState === WebSocket.CLOSED) {
        // Reconnect on keypress after disconnect
        connect();
      }
    });

    // Handle resize
    const handleResize = () => {
      if (fitAddonRef.current && terminalRef.current) {
        fitAddonRef.current.fit();
        const { cols, rows } = terminalRef.current;
        if (socketRef.current?.readyState === WebSocket.OPEN) {
          socketRef.current.send(JSON.stringify({ type: 'resize', cols, rows }));
        }
      }
    };

    window.addEventListener('resize', handleResize);

    // Cleanup function
    return () => {
      window.removeEventListener('resize', handleResize);
      disconnect();
    };
  }, [agentId, onConnect, onDisconnect, onError, disconnect]);

  // Cleanup on unmount
  useEffect(() => {
    return () => {
      disconnect();
    };
  }, [disconnect]);

  return {
    containerRef,
    connect,
    disconnect,
    isConnected: isConnectedRef.current,
  };
}
