import { useState, useMemo } from 'react';
import { Plus, Pencil, Trash2, ShieldCheck, AlertTriangle, CheckCircle, X, Users } from 'lucide-react';
import { Card } from '@cagent/shared-ui';
import { useTenant } from '../contexts/TenantContext';
import {
  useSecurityProfiles,
  useCreateSecurityProfile,
  useUpdateSecurityProfile,
  useDeleteSecurityProfile,
  useDataPlanes,
  useBulkAssignAgentProfile,
} from '../hooks/useApi';
import type { SecurityProfile, CreateSecurityProfileRequest, UpdateSecurityProfileRequest } from '../types/api';

interface ProfileModalProps {
  profile?: SecurityProfile;
  onClose: () => void;
  onSave: (data: CreateSecurityProfileRequest | UpdateSecurityProfileRequest) => void;
  isPending: boolean;
}

function ProfileModal({ profile, onClose, onSave, isPending }: ProfileModalProps) {
  const [name, setName] = useState(profile?.name || '');
  const [description, setDescription] = useState(profile?.description || '');

  const isDefault = profile?.name === 'default';

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!name.trim()) return;
    const data: CreateSecurityProfileRequest = {
      name: name.trim(),
      description: description.trim() || undefined,
    };
    onSave(data);
  };

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
      <div className="bg-dark-800 rounded-xl border border-dark-600 p-6 w-full max-w-lg">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-lg font-semibold text-dark-100">
            {profile ? 'Edit Profile' : 'Create Profile'}
          </h2>
          <button onClick={onClose} className="text-dark-400 hover:text-dark-200">
            <X size={20} />
          </button>
        </div>

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-dark-300 mb-1">Name</label>
            <input
              type="text"
              value={name}
              onChange={(e) => setName(e.target.value)}
              className="w-full bg-dark-900 border border-dark-600 rounded-lg px-3 py-2 text-sm text-dark-100 focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
              placeholder="e.g., production-strict"
              required
              disabled={isDefault}
            />
            {isDefault && (
              <p className="text-xs text-dark-500 mt-1">The default profile name cannot be changed.</p>
            )}
          </div>

          <div>
            <label className="block text-sm font-medium text-dark-300 mb-1">Description</label>
            <textarea
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              rows={2}
              className="w-full bg-dark-900 border border-dark-600 rounded-lg px-3 py-2 text-sm text-dark-100 focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
              placeholder="Optional description"
            />
          </div>

          <div className="flex justify-end gap-3 pt-2">
            <button
              type="button"
              onClick={onClose}
              className="px-4 py-2 text-sm text-dark-300 hover:text-dark-100 transition-colors"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={isPending || !name.trim()}
              className="px-4 py-2 text-sm bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50 transition-colors"
            >
              {isPending ? 'Saving...' : profile ? 'Update' : 'Create'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

export function SecurityProfiles() {
  const { selectedTenantId } = useTenant();
  const { data: profiles, isLoading } = useSecurityProfiles(selectedTenantId);
  const { data: agents } = useDataPlanes(selectedTenantId);
  const createProfile = useCreateSecurityProfile();
  const updateProfile = useUpdateSecurityProfile();
  const deleteProfile = useDeleteSecurityProfile();
  const bulkAssign = useBulkAssignAgentProfile();

  const [showModal, setShowModal] = useState(false);
  const [editingProfile, setEditingProfile] = useState<SecurityProfile | undefined>();
  const [success, setSuccess] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  // Bulk assignment state
  const [selectedAgentIds, setSelectedAgentIds] = useState<Set<string>>(new Set());
  const [bulkProfileId, setBulkProfileId] = useState('');

  const agentIds = useMemo(() => agents?.map((a) => a.agent_id) ?? [], [agents]);
  const allSelected = agentIds.length > 0 && selectedAgentIds.size === agentIds.length;

  const toggleAgent = (agentId: string) => {
    setSelectedAgentIds((prev) => {
      const next = new Set(prev);
      if (next.has(agentId)) {
        next.delete(agentId);
      } else {
        next.add(agentId);
      }
      return next;
    });
  };

  const toggleAll = () => {
    if (allSelected) {
      setSelectedAgentIds(new Set());
    } else {
      setSelectedAgentIds(new Set(agentIds));
    }
  };

  const handleCreate = (data: CreateSecurityProfileRequest | UpdateSecurityProfileRequest) => {
    setError(null);
    createProfile.mutate(
      { data: data as CreateSecurityProfileRequest },
      {
        onSuccess: () => {
          setShowModal(false);
          setSuccess('Profile created successfully');
          setTimeout(() => setSuccess(null), 3000);
        },
        onError: (err) => setError((err as Error).message),
      }
    );
  };

  const handleUpdate = (data: CreateSecurityProfileRequest | UpdateSecurityProfileRequest) => {
    if (!editingProfile) return;
    setError(null);
    updateProfile.mutate(
      { id: editingProfile.id, data: data as UpdateSecurityProfileRequest },
      {
        onSuccess: () => {
          setEditingProfile(undefined);
          setSuccess('Profile updated successfully');
          setTimeout(() => setSuccess(null), 3000);
        },
        onError: (err) => setError((err as Error).message),
      }
    );
  };

  const handleDelete = (profile: SecurityProfile) => {
    if (!confirm(`Delete profile "${profile.name}"?`)) return;
    setError(null);
    deleteProfile.mutate(profile.id, {
      onSuccess: () => {
        setSuccess('Profile deleted');
        setTimeout(() => setSuccess(null), 3000);
      },
      onError: (err) => setError((err as Error).message),
    });
  };

  const handleBulkAssign = () => {
    if (selectedAgentIds.size === 0 || !bulkProfileId) return;
    setError(null);
    bulkAssign.mutate(
      { agent_ids: Array.from(selectedAgentIds), profile_id: Number(bulkProfileId) },
      {
        onSuccess: (data) => {
          setSelectedAgentIds(new Set());
          setSuccess(`Profile assigned to ${data.updated.length} agent(s)`);
          setTimeout(() => setSuccess(null), 3000);
        },
        onError: (err) => setError((err as Error).message),
      }
    );
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-dark-100">Profiles</h1>
          <p className="text-sm text-dark-400 mt-1">
            Named policy bundles combining egress rules, runtime settings, and resource limits
          </p>
        </div>
        <button
          onClick={() => { setShowModal(true); setError(null); }}
          className="flex items-center gap-2 px-4 py-2 bg-blue-600 text-white text-sm rounded-lg hover:bg-blue-700 transition-colors"
        >
          <Plus size={16} />
          New Profile
        </button>
      </div>

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

      {/* Profiles Table */}
      <Card title="Profiles">
        {isLoading ? (
          <p className="text-dark-400">Loading...</p>
        ) : !profiles?.length ? (
          <p className="text-dark-400">No profiles created yet.</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-left text-dark-400 border-b border-dark-700">
                  <th className="pb-2 font-medium">Name</th>
                  <th className="pb-2 font-medium">Seccomp</th>
                  <th className="pb-2 font-medium">Resources</th>
                  <th className="pb-2 font-medium">Agents</th>
                  <th className="pb-2 font-medium">Policies</th>
                  <th className="pb-2 font-medium">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-dark-700">
                {profiles.map((profile) => (
                  <tr key={profile.id} className="text-dark-200">
                    <td className="py-3">
                      <div className="flex items-center gap-2">
                        <ShieldCheck size={16} className="text-blue-400" />
                        <span className="font-medium">{profile.name}</span>
                      </div>
                      {profile.description && (
                        <p className="text-xs text-dark-400 mt-0.5 ml-6">{profile.description}</p>
                      )}
                    </td>
                    <td className="py-3">
                      <span className={`text-xs px-2 py-0.5 rounded ${
                        profile.seccomp_profile === 'hardened'
                          ? 'bg-green-600/20 text-green-400'
                          : profile.seccomp_profile === 'permissive'
                            ? 'bg-yellow-600/20 text-yellow-400'
                            : 'bg-dark-600 text-dark-300'
                      }`}>
                        {profile.seccomp_profile}
                      </span>
                    </td>
                    <td className="py-3">
                      {profile.cpu_limit || profile.memory_limit_mb || profile.pids_limit ? (
                        <div className="text-xs text-dark-300 space-y-0.5">
                          {profile.cpu_limit && <div>CPU: {profile.cpu_limit} cores</div>}
                          {profile.memory_limit_mb && <div>Mem: {profile.memory_limit_mb} MB</div>}
                          {profile.pids_limit && <div>PIDs: {profile.pids_limit}</div>}
                        </div>
                      ) : (
                        <span className="text-xs text-dark-500">Default</span>
                      )}
                    </td>
                    <td className="py-3 text-dark-300">{profile.agent_count}</td>
                    <td className="py-3 text-dark-300">{profile.policy_count}</td>
                    <td className="py-3">
                      <div className="flex items-center gap-2">
                        <button
                          onClick={() => { setEditingProfile(profile); setError(null); }}
                          className="text-dark-400 hover:text-blue-400 transition-colors"
                          title="Edit"
                        >
                          <Pencil size={16} />
                        </button>
                        {profile.name !== 'default' && (
                          <button
                            onClick={() => handleDelete(profile)}
                            className="text-dark-400 hover:text-red-400 transition-colors"
                            title="Delete"
                          >
                            <Trash2 size={16} />
                          </button>
                        )}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      {/* Agent Assignment */}
      <Card title="Agent Assignment">
        <div className="space-y-4">
          <p className="text-sm text-dark-400">
            Select agents and assign or unassign a profile in bulk. Each agent will use its assigned profile&apos;s egress policies, runtime settings, and resource limits.
          </p>

          {/* Action bar */}
          <div className="flex items-end gap-4 flex-wrap">
            <div>
              <label className="block text-sm font-medium text-dark-300 mb-1">Profile</label>
              <select
                value={bulkProfileId}
                onChange={(e) => setBulkProfileId(e.target.value)}
                className="bg-dark-900 border border-dark-600 rounded-lg px-3 py-2 text-sm text-dark-100 focus:border-blue-500 min-w-[200px]"
              >
                <option value="">Select profile...</option>
                {profiles?.map((p) => (
                  <option key={p.id} value={p.id}>{p.name}</option>
                ))}
              </select>
            </div>

            <button
              onClick={handleBulkAssign}
              disabled={selectedAgentIds.size === 0 || !bulkProfileId || bulkAssign.isPending}
              className="flex items-center gap-2 px-4 py-2 bg-blue-600 text-white text-sm rounded-lg hover:bg-blue-700 disabled:opacity-50 transition-colors"
            >
              <Users size={16} />
              Assign Selected ({selectedAgentIds.size})
            </button>
          </div>

          {/* Agent table */}
          {!agents?.length ? (
            <p className="text-dark-400 text-sm">No agents connected.</p>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="text-left text-dark-400 border-b border-dark-700">
                    <th className="pb-2 pr-3 font-medium w-8">
                      <input
                        type="checkbox"
                        checked={allSelected}
                        onChange={toggleAll}
                        className="rounded border-dark-600 bg-dark-900 text-blue-600 focus:ring-blue-500"
                      />
                    </th>
                    <th className="pb-2 font-medium">Agent ID</th>
                    <th className="pb-2 font-medium">Status</th>
                    <th className="pb-2 font-medium">Current Profile</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-dark-700">
                  {agents.map((agent) => (
                    <tr key={agent.agent_id} className="text-dark-200">
                      <td className="py-2 pr-3">
                        <input
                          type="checkbox"
                          checked={selectedAgentIds.has(agent.agent_id)}
                          onChange={() => toggleAgent(agent.agent_id)}
                          className="rounded border-dark-600 bg-dark-900 text-blue-600 focus:ring-blue-500"
                        />
                      </td>
                      <td className="py-2 font-medium">{agent.agent_id}</td>
                      <td className="py-2">
                        <span className={`inline-flex items-center gap-1 text-xs px-2 py-0.5 rounded ${
                          agent.online
                            ? 'bg-green-600/20 text-green-400'
                            : 'bg-dark-600 text-dark-400'
                        }`}>
                          <span className={`w-1.5 h-1.5 rounded-full ${agent.online ? 'bg-green-400' : 'bg-dark-500'}`} />
                          {agent.online ? 'Online' : 'Offline'}
                        </span>
                      </td>
                      <td className="py-2">
                        <span className="text-dark-200">{agent.security_profile_name || 'default'}</span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </Card>

      {/* Create Modal */}
      {showModal && (
        <ProfileModal
          onClose={() => setShowModal(false)}
          onSave={handleCreate}
          isPending={createProfile.isPending}
        />
      )}

      {/* Edit Modal */}
      {editingProfile && (
        <ProfileModal
          profile={editingProfile}
          onClose={() => setEditingProfile(undefined)}
          onSave={handleUpdate}
          isPending={updateProfile.isPending}
        />
      )}
    </div>
  );
}
