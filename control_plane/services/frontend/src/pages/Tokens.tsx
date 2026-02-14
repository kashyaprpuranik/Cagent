import { useState } from 'react';
import {
  Key,
  Plus,
  Trash2,
  Copy,
  Check,
  AlertCircle,
  X,
  Shield,
  Server,
  Crown,
  Building2,
} from 'lucide-react';
import { Card, Badge, Button, Modal } from '@cagent/shared-ui';
import {
  useTokens,
  useCreateToken,
  useDeleteToken,
  useUpdateToken,
  useTenants,
} from '../hooks/useApi';
import { useAuth } from '../contexts/AuthContext';
import { useTenant } from '../contexts/TenantContext';
import type { CreateApiTokenRequest, ApiTokenCreated } from '../types/api';

export function Tokens() {
  const { user } = useAuth();
  const { selectedTenantId } = useTenant();
  // Pass tenant filter - super admins see tokens for selected tenant, others see their tenant's tokens
  const { data: tokens, isLoading } = useTokens(selectedTenantId);
  // Only super admins can see tenants list (for tenant dropdown in create modal)
  const { data: tenants } = useTenants(user?.is_super_admin === true);
  const createToken = useCreateToken();
  const deleteToken = useDeleteToken();
  const updateToken = useUpdateToken();

  const [showCreateModal, setShowCreateModal] = useState(false);
  const [showDeleteModal, setShowDeleteModal] = useState<number | null>(null);
  const [newToken, setNewToken] = useState<ApiTokenCreated | null>(null);
  const [copied, setCopied] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [form, setForm] = useState<CreateApiTokenRequest>({
    name: '',
    token_type: 'admin',
    agent_id: '',
    tenant_id: undefined,
    is_super_admin: false,
    expires_in_days: undefined,
  });

  // Helper to get tenant name by ID
  const getTenantName = (tenantId?: number) => {
    if (!tenantId) return '-';
    const tenant = tenants?.find(t => t.id === tenantId);
    return tenant?.name || `Tenant #${tenantId}`;
  };

  const handleCreate = async () => {
    setError(null);
    try {
      const data: CreateApiTokenRequest = {
        name: form.name,
        token_type: form.token_type,
      };
      if (form.token_type === 'agent' && form.agent_id) {
        data.agent_id = form.agent_id;
      }
      if (form.token_type === 'admin') {
        if (form.is_super_admin) {
          data.is_super_admin = true;
        } else if (form.tenant_id) {
          data.tenant_id = form.tenant_id;
        }
      }
      if (form.expires_in_days) {
        data.expires_in_days = form.expires_in_days;
      }
      const result = await createToken.mutateAsync(data);
      setNewToken(result);
      setForm({ name: '', token_type: 'admin', agent_id: '', tenant_id: undefined, is_super_admin: false, expires_in_days: undefined });
    } catch (e) {
      setError(`Failed to create token: ${e instanceof Error ? e.message : 'Unknown error'}`);
    }
  };

  const handleDelete = async (id: number) => {
    setError(null);
    try {
      await deleteToken.mutateAsync(id);
      setShowDeleteModal(null);
    } catch (e) {
      setError(`Failed to delete token: ${e instanceof Error ? e.message : 'Unknown error'}`);
    }
  };

  const handleToggleEnabled = async (id: number, currentEnabled: boolean) => {
    setError(null);
    try {
      await updateToken.mutateAsync({ id, enabled: !currentEnabled });
    } catch (e) {
      setError(`Failed to update token: ${e instanceof Error ? e.message : 'Unknown error'}`);
    }
  };

  const copyToken = () => {
    if (newToken?.token) {
      navigator.clipboard.writeText(newToken.token);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  const closeNewTokenModal = () => {
    setNewToken(null);
    setShowCreateModal(false);
  };

  const formatDate = (dateStr?: string) => {
    if (!dateStr) return 'Never';
    return new Date(dateStr).toLocaleString();
  };

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
        <h1 className="text-2xl font-bold text-dark-100">API Tokens</h1>
        <Button onClick={() => setShowCreateModal(true)}>
          <Plus size={16} className="mr-2" />
          Create Token
        </Button>
      </div>

      <Card>
        {isLoading ? (
          <div className="text-center py-8 text-dark-400">Loading tokens...</div>
        ) : !tokens || tokens.length === 0 ? (
          <div className="text-center py-8 text-dark-400">
            <Key size={48} className="mx-auto mb-4 opacity-50" />
            <p>No API tokens configured</p>
            <p className="text-sm mt-2">Create tokens to authenticate with the API</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="text-left text-dark-400 border-b border-dark-700">
                  <th className="pb-3 font-medium">Name</th>
                  <th className="pb-3 font-medium">Type</th>
                  <th className="pb-3 font-medium">Scope</th>
                  <th className="pb-3 font-medium">Created</th>
                  <th className="pb-3 font-medium">Expires</th>
                  <th className="pb-3 font-medium">Last Used</th>
                  <th className="pb-3 font-medium">Status</th>
                  <th className="pb-3 font-medium text-right">Actions</th>
                </tr>
              </thead>
              <tbody>
                {tokens.map((token) => (
                  <tr key={token.id} className="border-b border-dark-700/50 last:border-0">
                    <td className="py-4">
                      <div className="flex items-center gap-2">
                        {token.is_super_admin ? (
                          <Crown size={16} className="text-yellow-400" />
                        ) : token.token_type === 'admin' ? (
                          <Shield size={16} className="text-purple-400" />
                        ) : (
                          <Server size={16} className="text-blue-400" />
                        )}
                        <span className="font-medium text-dark-100">{token.name}</span>
                      </div>
                    </td>
                    <td className="py-4">
                      {token.is_super_admin ? (
                        <Badge variant="warning">super admin</Badge>
                      ) : (
                        <Badge variant={token.token_type === 'admin' ? 'default' : 'success'}>
                          {token.token_type}
                        </Badge>
                      )}
                    </td>
                    <td className="py-4 text-dark-300">
                      <div className="flex items-center gap-1">
                        {token.is_super_admin ? (
                          <span className="text-yellow-400">All tenants</span>
                        ) : token.token_type === 'agent' ? (
                          <>
                            <Server size={12} className="text-dark-500" />
                            <span>{token.agent_id || '-'}</span>
                          </>
                        ) : (
                          <>
                            <Building2 size={12} className="text-dark-500" />
                            <span>{getTenantName(token.tenant_id)}</span>
                          </>
                        )}
                      </div>
                    </td>
                    <td className="py-4 text-dark-400 text-sm">
                      {formatDate(token.created_at)}
                    </td>
                    <td className="py-4 text-dark-400 text-sm">
                      {token.expires_at ? formatDate(token.expires_at) : 'Never'}
                    </td>
                    <td className="py-4 text-dark-400 text-sm">
                      {formatDate(token.last_used_at)}
                    </td>
                    <td className="py-4">
                      <button
                        onClick={() => handleToggleEnabled(token.id, token.enabled)}
                        className={`px-2 py-1 rounded text-xs font-medium transition-colors ${
                          token.enabled
                            ? 'bg-green-600/20 text-green-400 hover:bg-green-600/30'
                            : 'bg-red-600/20 text-red-400 hover:bg-red-600/30'
                        }`}
                      >
                        {token.enabled ? 'Enabled' : 'Disabled'}
                      </button>
                    </td>
                    <td className="py-4 text-right">
                      <Button
                        variant="danger"
                        size="sm"
                        onClick={() => setShowDeleteModal(token.id)}
                      >
                        <Trash2 size={14} />
                      </Button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      {/* Create Token Modal */}
      <Modal
        isOpen={showCreateModal && !newToken}
        onClose={() => setShowCreateModal(false)}
        title="Create API Token"
      >
        <div className="space-y-4">
          <div>
            <label className="block text-sm text-dark-300 mb-1">Token Name</label>
            <input
              type="text"
              value={form.name}
              onChange={(e) => setForm({ ...form, name: e.target.value })}
              placeholder="e.g., admin-ui, agent-prod-01"
              className="w-full px-3 py-2 bg-dark-900 border border-dark-600 rounded-lg text-dark-100 focus:outline-none focus:border-blue-500"
            />
          </div>

          <div>
            <label className="block text-sm text-dark-300 mb-1">Token Type</label>
            <select
              value={form.token_type}
              onChange={(e) => setForm({ ...form, token_type: e.target.value as 'admin' | 'agent' })}
              className="w-full px-3 py-2 bg-dark-900 border border-dark-600 rounded-lg text-dark-100 focus:outline-none focus:border-blue-500"
            >
              <option value="admin">Admin (full management access)</option>
              <option value="agent">Agent Group (data plane operations only)</option>
            </select>
          </div>

          {form.token_type === 'agent' && (
            <div>
              <label className="block text-sm text-dark-300 mb-1">Agent Group ID</label>
              <input
                type="text"
                value={form.agent_id}
                onChange={(e) => setForm({ ...form, agent_id: e.target.value })}
                placeholder="e.g., agent-group-prod-01"
                className="w-full px-3 py-2 bg-dark-900 border border-dark-600 rounded-lg text-dark-100 focus:outline-none focus:border-blue-500"
              />
              <p className="text-xs text-dark-500 mt-1">
                Token will only work for this specific agent group
              </p>
            </div>
          )}

          {form.token_type === 'admin' && (
            <>
              <div className="flex items-center gap-2">
                <input
                  type="checkbox"
                  id="is_super_admin"
                  checked={form.is_super_admin}
                  onChange={(e) => setForm({ ...form, is_super_admin: e.target.checked, tenant_id: undefined })}
                  className="w-4 h-4 rounded border-dark-600 bg-dark-900 text-blue-500 focus:ring-blue-500"
                />
                <label htmlFor="is_super_admin" className="text-sm text-dark-300">
                  Super Admin (access to all tenants)
                </label>
              </div>

              {!form.is_super_admin && (
                <div>
                  <label className="block text-sm text-dark-300 mb-1">Tenant</label>
                  <select
                    value={form.tenant_id || ''}
                    onChange={(e) => setForm({ ...form, tenant_id: e.target.value ? parseInt(e.target.value) : undefined })}
                    className="w-full px-3 py-2 bg-dark-900 border border-dark-600 rounded-lg text-dark-100 focus:outline-none focus:border-blue-500"
                  >
                    <option value="">Select a tenant...</option>
                    {tenants?.map((tenant) => (
                      <option key={tenant.id} value={tenant.id}>
                        {tenant.name} ({tenant.slug})
                      </option>
                    ))}
                  </select>
                  <p className="text-xs text-dark-500 mt-1">
                    Token will only have access to resources in this tenant
                  </p>
                </div>
              )}
            </>
          )}

          <div>
            <label className="block text-sm text-dark-300 mb-1">Expires In (days)</label>
            <input
              type="number"
              value={form.expires_in_days || ''}
              onChange={(e) => setForm({ ...form, expires_in_days: e.target.value ? parseInt(e.target.value) : undefined })}
              placeholder="Leave empty for no expiration"
              className="w-full px-3 py-2 bg-dark-900 border border-dark-600 rounded-lg text-dark-100 focus:outline-none focus:border-blue-500"
            />
          </div>

          <div className="flex justify-end gap-2 pt-4">
            <Button variant="secondary" onClick={() => setShowCreateModal(false)}>
              Cancel
            </Button>
            <Button
              onClick={handleCreate}
              disabled={
                !form.name ||
                (form.token_type === 'agent' && !form.agent_id) ||
                (form.token_type === 'admin' && !form.is_super_admin && !form.tenant_id) ||
                createToken.isPending
              }
            >
              {createToken.isPending ? 'Creating...' : 'Create Token'}
            </Button>
          </div>
        </div>
      </Modal>

      {/* New Token Display Modal */}
      <Modal
        isOpen={!!newToken}
        onClose={closeNewTokenModal}
        title="Token Created Successfully"
      >
        <div className="space-y-4">
          <div className="p-4 bg-yellow-900/30 border border-yellow-700 rounded-lg">
            <div className="flex items-center gap-2 text-yellow-400 mb-2">
              <AlertCircle size={20} />
              <span className="font-medium">Save this token now!</span>
            </div>
            <p className="text-yellow-200 text-sm">
              This token will only be shown once. Copy it and store it securely.
            </p>
          </div>

          <div>
            <label className="block text-sm text-dark-300 mb-1">Token</label>
            <div className="flex gap-2">
              <input
                type="text"
                value={newToken?.token || ''}
                readOnly
                className="flex-1 px-3 py-2 bg-dark-900 border border-dark-600 rounded-lg text-dark-100 font-mono text-sm"
              />
              <Button onClick={copyToken}>
                {copied ? <Check size={16} /> : <Copy size={16} />}
              </Button>
            </div>
          </div>

          <div className="text-sm text-dark-400">
            <p><strong>Name:</strong> {newToken?.name}</p>
            <p><strong>Type:</strong> {newToken?.is_super_admin ? 'Super Admin' : newToken?.token_type}</p>
            {newToken?.agent_id && <p><strong>Agent Group ID:</strong> {newToken.agent_id}</p>}
            {newToken?.tenant_id && !newToken?.is_super_admin && (
              <p><strong>Tenant:</strong> {getTenantName(newToken.tenant_id)}</p>
            )}
            {newToken?.is_super_admin && <p><strong>Scope:</strong> All tenants</p>}
            {newToken?.expires_at && <p><strong>Expires:</strong> {formatDate(newToken.expires_at)}</p>}
          </div>

          <div className="flex justify-end pt-4">
            <Button onClick={closeNewTokenModal}>Done</Button>
          </div>
        </div>
      </Modal>

      {/* Delete Confirmation Modal */}
      <Modal
        isOpen={showDeleteModal !== null}
        onClose={() => setShowDeleteModal(null)}
        title="Delete Token"
      >
        <div className="space-y-4">
          <p className="text-dark-300">
            Are you sure you want to delete this token? Any applications using this token will lose access.
          </p>
          <div className="flex justify-end gap-2 pt-4">
            <Button variant="secondary" onClick={() => setShowDeleteModal(null)}>
              Cancel
            </Button>
            <Button
              variant="danger"
              onClick={() => showDeleteModal && handleDelete(showDeleteModal)}
              disabled={deleteToken.isPending}
            >
              {deleteToken.isPending ? 'Deleting...' : 'Delete Token'}
            </Button>
          </div>
        </div>
      </Modal>
    </div>
  );
}
