import { Routes, Route, NavLink, Navigate } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { Settings, Container, FileText, Activity, Terminal, MonitorUp, Lock } from 'lucide-react';
import { getInfo } from './api/client';
import ConfigPage from './pages/Config';
import StatusPage from './pages/Status';
import LogsPage from './pages/Logs';
import SshTunnelPage from './pages/SshTunnel';
import TerminalPage from './pages/Terminal';

interface NavItem {
  to: string;
  icon: React.ComponentType<{ className?: string }>;
  label: string;
  badge?: string;
}

function Sidebar() {
  const { data: info } = useQuery({
    queryKey: ['info'],
    queryFn: getInfo,
  });

  const isConnected = info?.mode === 'connected';
  const sshTunnelEnabled = info?.features?.includes('ssh-tunnel');

  const navItems: NavItem[] = [
    { to: '/', icon: Activity, label: 'Status' },
    // Config only shown in standalone mode — in connected mode the CP owns the config
    ...(!isConnected ? [{ to: '/config', icon: Settings, label: 'Config' }] : []),
    { to: '/logs', icon: FileText, label: 'Logs' },
    { to: '/terminal', icon: MonitorUp, label: 'Terminal' },
    ...(sshTunnelEnabled ? [{ to: '/ssh-tunnel', icon: Terminal, label: 'SSH Tunnel', badge: 'Beta' }] : []),
  ];

  return (
    <aside className="w-56 bg-gray-800 border-r border-gray-700 flex flex-col">
      <div className="p-4 border-b border-gray-700">
        <NavLink to="/" className="text-lg font-bold text-white flex items-center gap-2 hover:text-blue-300 transition-colors">
          <Container className="w-5 h-5 text-blue-400" />
          Cagent
        </NavLink>
        <p className="text-xs text-gray-400 mt-1">Local Admin</p>
      </div>

      <nav className="flex-1 p-2">
        {navItems.map(({ to, icon: Icon, label, badge }) => (
          <NavLink
            key={to}
            to={to}
            className={({ isActive }) =>
              `flex items-center gap-3 px-3 py-2 rounded-lg transition-colors ${
                isActive
                  ? 'bg-blue-600 text-white'
                  : 'text-gray-300 hover:bg-gray-700'
              }`
            }
          >
            <Icon className="w-4 h-4" />
            {label}
            {badge && (
              <span className="text-[10px] font-medium bg-blue-600/20 text-blue-400 px-1.5 py-0.5 rounded">
                {badge}
              </span>
            )}
          </NavLink>
        ))}
      </nav>

      <div className="p-4 border-t border-gray-700 text-xs text-gray-500">
        {isConnected ? (
          <span className="flex items-center gap-1.5 text-yellow-400">
            <Lock className="w-3 h-3" />
            Connected (Read-Only)
          </span>
        ) : (
          'Standalone Mode'
        )}
      </div>
    </aside>
  );
}

function Layout({ children }: { children: React.ReactNode }) {
  return (
    <div className="flex h-screen">
      <Sidebar />
      <main className="flex-1 overflow-auto p-6">{children}</main>
    </div>
  );
}

export default function App() {
  const { data: info } = useQuery({
    queryKey: ['info'],
    queryFn: getInfo,
  });

  const isConnected = info?.mode === 'connected';
  const sshTunnelEnabled = info?.features?.includes('ssh-tunnel');

  return (
    <Layout>
      <Routes>
        <Route path="/" element={<StatusPage />} />
        {/* Config only available in standalone — in connected mode the CP owns the config */}
        <Route path="/config" element={isConnected ? <Navigate to="/" replace /> : <ConfigPage />} />
        <Route path="/logs" element={<LogsPage />} />
        <Route path="/terminal" element={<TerminalPage />} />
        <Route path="/ssh-tunnel" element={sshTunnelEnabled ? <SshTunnelPage /> : <Navigate to="/" replace />} />
      </Routes>
    </Layout>
  );
}
