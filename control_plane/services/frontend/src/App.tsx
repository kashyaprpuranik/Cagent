import { Routes, Route, Navigate } from 'react-router-dom';
import { Layout } from './components/Layout';
import { Dashboard } from './pages/Dashboard';
import { DomainPolicies } from './pages/DomainPolicies';
import { IpAcls } from './pages/IpAcls';
import { AuditTrail } from './pages/AuditLogs';
import { AgentLogs } from './pages/AgentLogs';
import { Tokens } from './pages/Tokens';
import { Tenants } from './pages/Tenants';
import { Settings } from './pages/Settings';
import { Login } from './pages/Login';
import { Terminal } from './pages/Terminal';
import { api } from './api/client';
import { useAuth } from './contexts/AuthContext';

// Protected route wrapper - redirects to login if not authenticated
function ProtectedRoute({ children }: { children: React.ReactNode }) {
  const { user, loading } = useAuth();

  if (loading) {
    return (
      <div className="min-h-screen bg-dark-950 flex items-center justify-center">
        <div className="text-dark-400">Loading...</div>
      </div>
    );
  }

  if (!user || !api.getToken()) {
    return <Navigate to="/login" replace />;
  }

  return <>{children}</>;
}

function App() {
  return (
    <Routes>
      <Route path="/login" element={<Login />} />
      <Route
        path="/"
        element={
          <ProtectedRoute>
            <Layout />
          </ProtectedRoute>
        }
      >
        <Route index element={<Dashboard />} />
        <Route path="domain-policies" element={<DomainPolicies />} />
        <Route path="ip-acls" element={<IpAcls />} />
        <Route path="audit-trail" element={<AuditTrail />} />
        <Route path="agent-logs" element={<AgentLogs />} />
        <Route path="tokens" element={<Tokens />} />
        <Route path="tenants" element={<Tenants />} />
        <Route path="settings" element={<Settings />} />
        <Route path="terminal/:agentId" element={<Terminal />} />
      </Route>
      {/* Redirects for legacy routes */}
      <Route path="/secrets" element={<Navigate to="/domain-policies" replace />} />
      <Route path="/allowlist" element={<Navigate to="/domain-policies" replace />} />
      <Route path="/rate-limits" element={<Navigate to="/domain-policies" replace />} />
      <Route path="/audit-logs" element={<Navigate to="/audit-trail" replace />} />
      <Route path="/admin-logs" element={<Navigate to="/audit-trail" replace />} />
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}

export default App;
