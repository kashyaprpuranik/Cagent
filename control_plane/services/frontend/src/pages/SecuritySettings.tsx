import { useState, useEffect } from 'react';
import { ChevronDown, AlertTriangle, CheckCircle } from 'lucide-react';
import { Card } from '@cagent/shared-ui';
import { useAuth } from '../contexts/AuthContext';
import { useTenant } from '../contexts/TenantContext';
import { useDataPlanes, useSecuritySettings, useUpdateSecuritySettings } from '../hooks/useApi';
import type { SeccompProfile } from '../types/api';

const PROFILE_INFO: Record<SeccompProfile, { label: string; description: string; variant: 'default' | 'warning' | 'success' }> = {
  standard: {
    label: 'Standard',
    description: 'Blocks all syscalls by default, explicitly allows ~150 needed for normal operation. Includes mount, ptrace, and unshare. Recommended for development.',
    variant: 'default',
  },
  hardened: {
    label: 'Hardened',
    description: 'Standard profile minus dangerous syscalls: mount, umount2, ptrace, personality, setns, unshare, pivot_root, chroot, sethostname, setdomainname, reboot, init_module, delete_module, finit_module. Recommended for production.',
    variant: 'success',
  },
  permissive: {
    label: 'Permissive',
    description: 'Allows all syscalls except raw socket creation. Use only for debugging when the standard profile blocks required operations.',
    variant: 'warning',
  },
};

export function SecuritySettings() {
  const { user } = useAuth();
  const { selectedTenantId } = useTenant();
  const { data: dataPlanes } = useDataPlanes(selectedTenantId);

  const hasAdminRole = user?.roles?.includes('admin') || user?.is_super_admin;

  const [selectedAgentId, setSelectedAgentId] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const agentList = dataPlanes ?? [];

  // Auto-select first agent
  useEffect(() => {
    if (!selectedAgentId && agentList.length > 0) {
      setSelectedAgentId(agentList[0].agent_id);
    }
  }, [agentList, selectedAgentId]);

  // Reset selection when tenant changes
  useEffect(() => {
    setSelectedAgentId(null);
  }, [selectedTenantId]);

  const { data: settings, isLoading } = useSecuritySettings(selectedAgentId);
  const updateSettings = useUpdateSecuritySettings();

  const handleProfileChange = (profile: SeccompProfile) => {
    if (!selectedAgentId || !hasAdminRole) return;
    setError(null);
    setSuccess(null);

    updateSettings.mutate(
      { agentId: selectedAgentId, data: { seccomp_profile: profile } },
      {
        onSuccess: () => {
          setSuccess('Profile updated. Change will take effect on next heartbeat cycle (~30s).');
          setTimeout(() => setSuccess(null), 5000);
        },
        onError: (err) => {
          setError((err as Error).message || 'Failed to update security settings');
        },
      }
    );
  };

  const currentProfile = (settings?.seccomp_profile || 'standard') as SeccompProfile;

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-dark-100">Security Settings</h1>
        <p className="text-sm text-dark-400 mt-1">
          Configure seccomp profiles to control syscall access for agent containers
        </p>
      </div>

      {/* Agent Selector */}
      <div>
        <label className="block text-sm font-medium text-dark-300 mb-2">
          Agent
        </label>
        <div className="relative w-72">
          <select
            value={selectedAgentId || ''}
            onChange={(e) => {
              setSelectedAgentId(e.target.value || null);
              setSuccess(null);
              setError(null);
            }}
            className="w-full appearance-none bg-dark-800 border border-dark-600 rounded-lg px-3 py-2 pr-8 text-sm text-dark-100 focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
          >
            {agentList.length === 0 && (
              <option value="">No agents connected</option>
            )}
            {agentList.map((agent: { agent_id: string }) => (
              <option key={agent.agent_id} value={agent.agent_id}>
                {agent.agent_id}
              </option>
            ))}
          </select>
          <ChevronDown
            size={16}
            className="absolute right-2 top-1/2 -translate-y-1/2 text-dark-400 pointer-events-none"
          />
        </div>
      </div>

      {/* Messages */}
      {success && (
        <div className="flex items-center gap-2 p-3 rounded-lg bg-green-900/30 border border-green-700 text-green-300 text-sm">
          <CheckCircle size={16} />
          {success}
        </div>
      )}
      {error && (
        <div className="flex items-center gap-2 p-3 rounded-lg bg-red-900/30 border border-red-700 text-red-300 text-sm">
          <AlertTriangle size={16} />
          {error}
        </div>
      )}

      {/* Profile Selection */}
      {selectedAgentId && (
        <Card title="Seccomp Profile">
          {isLoading ? (
            <p className="text-dark-400">Loading...</p>
          ) : (
            <div className="space-y-4">
              <p className="text-sm text-dark-400">
                Select the syscall filtering profile for this agent&apos;s container.
                Changes require a container recreation and take effect on the next heartbeat cycle.
              </p>

              <div className="space-y-3">
                {(Object.entries(PROFILE_INFO) as [SeccompProfile, typeof PROFILE_INFO['standard']][]).map(
                  ([key, info]) => (
                    <label
                      key={key}
                      className={`flex items-start gap-3 p-4 rounded-lg border cursor-pointer transition-colors ${
                        currentProfile === key
                          ? 'border-blue-500 bg-blue-900/20'
                          : 'border-dark-600 hover:border-dark-500 bg-dark-800'
                      } ${!hasAdminRole ? 'opacity-60 cursor-not-allowed' : ''}`}
                    >
                      <input
                        type="radio"
                        name="seccomp_profile"
                        value={key}
                        checked={currentProfile === key}
                        onChange={() => handleProfileChange(key)}
                        disabled={!hasAdminRole || updateSettings.isPending}
                        className="mt-1 w-4 h-4 text-blue-600 bg-dark-800 border-dark-600"
                      />
                      <div className="flex-1">
                        <div className="flex items-center gap-2">
                          <span className="font-medium text-dark-100">{info.label}</span>
                          {info.variant === 'success' && (
                            <span className="text-[10px] font-medium bg-green-600/20 text-green-400 px-1.5 py-0.5 rounded">
                              Production
                            </span>
                          )}
                          {info.variant === 'warning' && (
                            <span className="text-[10px] font-medium bg-yellow-600/20 text-yellow-400 px-1.5 py-0.5 rounded">
                              Debug only
                            </span>
                          )}
                          {key === 'standard' && (
                            <span className="text-[10px] font-medium bg-blue-600/20 text-blue-400 px-1.5 py-0.5 rounded">
                              Default
                            </span>
                          )}
                        </div>
                        <p className="text-sm text-dark-400 mt-1">{info.description}</p>
                      </div>
                    </label>
                  )
                )}
              </div>

              {currentProfile === 'permissive' && (
                <div className="flex items-center gap-2 p-3 rounded-lg bg-yellow-900/30 border border-yellow-700 text-yellow-300 text-sm">
                  <AlertTriangle size={16} className="flex-shrink-0" />
                  <span>
                    Permissive mode significantly reduces container security.
                    Use only for temporary debugging and switch back when done.
                  </span>
                </div>
              )}

              {!hasAdminRole && (
                <p className="text-sm text-dark-500">
                  Admin role required to change security settings.
                </p>
              )}
            </div>
          )}
        </Card>
      )}
    </div>
  );
}
