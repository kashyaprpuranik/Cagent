import { useState, useMemo, useEffect } from 'react';
import { Plus, Edit2, Trash2, RefreshCw, Mail, Search, ChevronDown } from 'lucide-react';
import { Card, Table, Button, Modal, Input, Select, Badge } from '@cagent/shared-ui';
import {
  useEmailPolicies,
  useCreateEmailPolicy,
  useUpdateEmailPolicy,
  useDeleteEmailPolicy,
  useAgents,
  useSecurityProfiles,
} from '../hooks/useApi';
import { useTenant } from '../contexts/TenantContext';
import type { EmailPolicy, DataPlane, CreateEmailPolicyRequest, UpdateEmailPolicyRequest } from '../types/api';

interface FormData {
  name: string;
  provider: string;
  email: string;
  agent_id: string;
  imap_server: string;
  imap_port: string;
  smtp_server: string;
  smtp_port: string;
  allowed_recipients: string;
  allowed_senders: string;
  sends_per_hour: string;
  reads_per_hour: string;
  enable_credential: boolean;
  // OAuth2
  client_id: string;
  client_secret: string;
  refresh_token: string;
  // Generic
  password: string;
}

const emptyFormData: FormData = {
  name: '',
  provider: 'gmail',
  email: '',
  agent_id: '',
  imap_server: '',
  imap_port: '',
  smtp_server: '',
  smtp_port: '',
  allowed_recipients: '',
  allowed_senders: '*',
  sends_per_hour: '',
  reads_per_hour: '',
  enable_credential: false,
  client_id: '',
  client_secret: '',
  refresh_token: '',
  password: '',
};

export function EmailPolicies() {
  const { selectedTenantId } = useTenant();
  const { data: profiles } = useSecurityProfiles(selectedTenantId);
  const [selectedProfileId, setSelectedProfileId] = useState<number | undefined>(undefined);

  // Auto-select the first profile (usually "default") when profiles load
  useEffect(() => {
    if (profiles?.length && selectedProfileId === undefined) {
      const defaultProfile = profiles.find(p => p.name === 'default');
      setSelectedProfileId(defaultProfile?.id ?? profiles[0].id);
    }
  }, [profiles, selectedProfileId]);

  // Reset profile selection when tenant changes
  useEffect(() => {
    setSelectedProfileId(undefined);
  }, [selectedTenantId]);

  const { data: policies = [], isLoading, refetch } = useEmailPolicies({
    profileId: selectedProfileId,
    tenantId: selectedTenantId,
  });
  const { data: agents = [] } = useAgents();
  const createPolicy = useCreateEmailPolicy();
  const updatePolicy = useUpdateEmailPolicy();
  const deletePolicy = useDeleteEmailPolicy();

  const [createModal, setCreateModal] = useState(false);
  const [editModal, setEditModal] = useState<EmailPolicy | null>(null);
  const [deleteModal, setDeleteModal] = useState<EmailPolicy | null>(null);
  const [filter, setFilter] = useState('');
  const [formData, setFormData] = useState<FormData>(emptyFormData);

  const agentOptions = [
    { value: '', label: 'Global (all agent groups)' },
    ...agents.map((agent: DataPlane) => ({
      value: agent.agent_id,
      label: agent.agent_id,
    })),
  ];

  const providerOptions = [
    { value: 'gmail', label: 'Gmail (OAuth2)' },
    { value: 'outlook', label: 'Outlook/M365 (OAuth2)' },
    { value: 'generic', label: 'Generic (Password)' },
  ];

  const filteredPolicies = useMemo(() => {
    if (!filter) return policies;
    const q = filter.toLowerCase();
    return policies.filter((p: EmailPolicy) =>
      p.name.toLowerCase().includes(q) ||
      p.email.toLowerCase().includes(q) ||
      p.provider.toLowerCase().includes(q) ||
      (p.agent_id && p.agent_id.toLowerCase().includes(q))
    );
  }, [policies, filter]);

  const resetForm = () => setFormData(emptyFormData);

  const openEditModal = (policy: EmailPolicy) => {
    setFormData({
      name: policy.name,
      provider: policy.provider,
      email: policy.email,
      agent_id: policy.agent_id || '',
      imap_server: policy.imap_server || '',
      imap_port: policy.imap_port?.toString() || '',
      smtp_server: policy.smtp_server || '',
      smtp_port: policy.smtp_port?.toString() || '',
      allowed_recipients: (policy.allowed_recipients || []).join('\n'),
      allowed_senders: (policy.allowed_senders || []).join('\n'),
      sends_per_hour: policy.sends_per_hour?.toString() || '',
      reads_per_hour: policy.reads_per_hour?.toString() || '',
      enable_credential: policy.has_credential || false,
      client_id: '',
      client_secret: '',
      refresh_token: '',
      password: '',
    });
    setEditModal(policy);
  };

  const buildCredential = () => {
    if (!formData.enable_credential) return undefined;
    if (formData.provider === 'generic') {
      return formData.password ? { password: formData.password } : undefined;
    }
    if (formData.client_id || formData.client_secret || formData.refresh_token) {
      return {
        client_id: formData.client_id || undefined,
        client_secret: formData.client_secret || undefined,
        refresh_token: formData.refresh_token || undefined,
      };
    }
    return undefined;
  };

  const handleCreate = async () => {
    const data: CreateEmailPolicyRequest = {
      name: formData.name,
      provider: formData.provider as 'gmail' | 'outlook' | 'generic',
      email: formData.email,
      profile_id: selectedProfileId,
      agent_id: formData.agent_id || undefined,
      imap_server: formData.imap_server || undefined,
      imap_port: formData.imap_port ? parseInt(formData.imap_port) : undefined,
      smtp_server: formData.smtp_server || undefined,
      smtp_port: formData.smtp_port ? parseInt(formData.smtp_port) : undefined,
      allowed_recipients: formData.allowed_recipients.split('\n').map(s => s.trim()).filter(Boolean),
      allowed_senders: formData.allowed_senders.split('\n').map(s => s.trim()).filter(Boolean),
      sends_per_hour: formData.sends_per_hour ? parseInt(formData.sends_per_hour) : undefined,
      reads_per_hour: formData.reads_per_hour ? parseInt(formData.reads_per_hour) : undefined,
      credential: buildCredential(),
    };

    try {
      await createPolicy.mutateAsync({ data, tenantId: selectedTenantId ?? undefined });
      setCreateModal(false);
      resetForm();
    } catch {
      // Error handled by mutation
    }
  };

  const handleUpdate = async () => {
    if (!editModal) return;

    const data: UpdateEmailPolicyRequest = {
      imap_server: formData.imap_server || undefined,
      imap_port: formData.imap_port ? parseInt(formData.imap_port) : undefined,
      smtp_server: formData.smtp_server || undefined,
      smtp_port: formData.smtp_port ? parseInt(formData.smtp_port) : undefined,
      allowed_recipients: formData.allowed_recipients.split('\n').map(s => s.trim()).filter(Boolean),
      allowed_senders: formData.allowed_senders.split('\n').map(s => s.trim()).filter(Boolean),
      sends_per_hour: formData.sends_per_hour ? parseInt(formData.sends_per_hour) : undefined,
      reads_per_hour: formData.reads_per_hour ? parseInt(formData.reads_per_hour) : undefined,
      credential: buildCredential(),
    };

    try {
      await updatePolicy.mutateAsync({ id: editModal.id, data });
      setEditModal(null);
      resetForm();
    } catch {
      // Error handled by mutation
    }
  };

  const handleToggle = async (policy: EmailPolicy) => {
    try {
      await updatePolicy.mutateAsync({
        id: policy.id,
        data: { enabled: !policy.enabled },
      });
    } catch {
      // Error handled by mutation
    }
  };

  const handleDelete = async () => {
    if (!deleteModal) return;
    try {
      await deletePolicy.mutateAsync(deleteModal.id);
      setDeleteModal(null);
    } catch {
      // Error handled by mutation
    }
  };

  const columns = [
    {
      key: 'name',
      header: 'Account',
      render: (policy: EmailPolicy) => (
        <div>
          <code className="text-sm text-blue-400">{policy.name}</code>
          <p className="text-xs text-dark-500 mt-1">{policy.email}</p>
        </div>
      ),
    },
    {
      key: 'provider',
      header: 'Provider',
      render: (policy: EmailPolicy) => (
        <Badge variant={
          policy.provider === 'gmail' ? 'error' :
          policy.provider === 'outlook' ? 'info' : 'default'
        }>
          {policy.provider}
        </Badge>
      ),
    },
    {
      key: 'policy',
      header: 'Policy',
      render: (policy: EmailPolicy) => (
        <div className="space-y-1">
          {policy.sends_per_hour && (
            <span className="text-sm text-dark-300">{policy.sends_per_hour} sends/hr</span>
          )}
          {policy.sends_per_hour && policy.reads_per_hour && <span className="text-dark-500 mx-1">/</span>}
          {policy.reads_per_hour && (
            <span className="text-sm text-dark-300">{policy.reads_per_hour} reads/hr</span>
          )}
          {!policy.sends_per_hour && !policy.reads_per_hour && (
            <span className="text-dark-500 text-sm">No limits</span>
          )}
        </div>
      ),
    },
    {
      key: 'recipients',
      header: 'Recipients',
      render: (policy: EmailPolicy) => {
        const recipients = policy.allowed_recipients || [];
        if (recipients.length === 0) return <span className="text-dark-500 text-sm">None</span>;
        return (
          <span className="text-sm text-dark-300">
            {recipients.length} {recipients.length === 1 ? 'pattern' : 'patterns'}
          </span>
        );
      },
    },
    {
      key: 'credential',
      header: 'Credential',
      render: (policy: EmailPolicy) =>
        policy.has_credential ? (
          <Badge variant="success">
            {policy.credential_type === 'oauth2' ? 'OAuth2' : 'Password'}
          </Badge>
        ) : (
          <span className="text-dark-500 text-sm">None</span>
        ),
    },
    {
      key: 'agent',
      header: 'Agent Group',
      render: (policy: EmailPolicy) =>
        policy.agent_id ? (
          <Badge variant="info">{policy.agent_id}</Badge>
        ) : (
          <span className="text-dark-500 text-sm">Global</span>
        ),
    },
    {
      key: 'status',
      header: 'Status',
      render: (policy: EmailPolicy) => (
        <button onClick={() => handleToggle(policy)}>
          <Badge variant={policy.enabled ? 'success' : 'default'}>
            {policy.enabled ? 'Enabled' : 'Disabled'}
          </Badge>
        </button>
      ),
    },
    {
      key: 'actions',
      header: '',
      className: 'text-right',
      render: (policy: EmailPolicy) => (
        <div className="flex items-center justify-end gap-2">
          <Button variant="ghost" size="sm" onClick={() => openEditModal(policy)}>
            <Edit2 size={14} />
          </Button>
          <Button variant="ghost" size="sm" onClick={() => setDeleteModal(policy)}>
            <Trash2 size={14} className="text-red-400" />
          </Button>
        </div>
      ),
    },
  ];

  const renderFormFields = (isEdit: boolean) => (
    <div className="space-y-6">
      {/* Basic Settings */}
      <div>
        <h3 className="text-sm font-medium text-dark-200 mb-3">Account Settings</h3>
        <div className="space-y-4">
          <div className="grid grid-cols-2 gap-4">
            <Input
              label="Account Name"
              placeholder="work-gmail"
              value={formData.name}
              onChange={(e) => setFormData({ ...formData, name: e.target.value })}
              disabled={isEdit}
            />
            <Select
              label="Provider"
              options={providerOptions}
              value={formData.provider}
              onChange={(e) => setFormData({ ...formData, provider: e.target.value })}
              disabled={isEdit}
            />
          </div>
          <div className="grid grid-cols-2 gap-4">
            <Input
              label="Email Address"
              placeholder="agent@company.com"
              value={formData.email}
              onChange={(e) => setFormData({ ...formData, email: e.target.value })}
              disabled={isEdit}
            />
            <Select
              label="Agent Group (optional)"
              options={agentOptions}
              value={formData.agent_id}
              onChange={(e) => setFormData({ ...formData, agent_id: e.target.value })}
              disabled={isEdit}
            />
          </div>
        </div>
      </div>

      {/* Server Overrides */}
      <div>
        <h3 className="text-sm font-medium text-dark-200 mb-3">Server Settings (optional)</h3>
        <div className="grid grid-cols-2 gap-4">
          <Input
            label="IMAP Server"
            placeholder={formData.provider === 'gmail' ? 'imap.gmail.com' : formData.provider === 'outlook' ? 'outlook.office365.com' : 'mail.example.com'}
            value={formData.imap_server}
            onChange={(e) => setFormData({ ...formData, imap_server: e.target.value })}
          />
          <Input
            label="IMAP Port"
            type="number"
            placeholder="993"
            value={formData.imap_port}
            onChange={(e) => setFormData({ ...formData, imap_port: e.target.value })}
          />
          <Input
            label="SMTP Server"
            placeholder={formData.provider === 'gmail' ? 'smtp.gmail.com' : formData.provider === 'outlook' ? 'smtp.office365.com' : 'mail.example.com'}
            value={formData.smtp_server}
            onChange={(e) => setFormData({ ...formData, smtp_server: e.target.value })}
          />
          <Input
            label="SMTP Port"
            type="number"
            placeholder="587"
            value={formData.smtp_port}
            onChange={(e) => setFormData({ ...formData, smtp_port: e.target.value })}
          />
        </div>
      </div>

      {/* Recipient / Sender Allowlists */}
      <div>
        <h3 className="text-sm font-medium text-dark-200 mb-3">Allowlists</h3>
        <div className="space-y-4">
          <div>
            <label className="block text-sm text-dark-400 mb-1">Allowed Recipients (one per line)</label>
            <textarea
              className="w-full px-3 py-2 bg-dark-900 border border-dark-600 rounded-lg text-dark-100 focus:border-blue-500 focus:ring-1 focus:ring-blue-500 font-mono text-sm"
              rows={3}
              placeholder="*@company.com&#10;partner@external.com"
              value={formData.allowed_recipients}
              onChange={(e) => setFormData({ ...formData, allowed_recipients: e.target.value })}
            />
            <p className="text-xs text-dark-500 mt-1">
              Use *@domain.com for wildcards. Leave empty to block all sends.
            </p>
          </div>
          <div>
            <label className="block text-sm text-dark-400 mb-1">Allowed Senders (inbox filter, one per line)</label>
            <textarea
              className="w-full px-3 py-2 bg-dark-900 border border-dark-600 rounded-lg text-dark-100 focus:border-blue-500 focus:ring-1 focus:ring-blue-500 font-mono text-sm"
              rows={2}
              placeholder="*"
              value={formData.allowed_senders}
              onChange={(e) => setFormData({ ...formData, allowed_senders: e.target.value })}
            />
          </div>
        </div>
      </div>

      {/* Rate Limits */}
      <div>
        <h3 className="text-sm font-medium text-dark-200 mb-3">Rate Limits (optional)</h3>
        <div className="grid grid-cols-2 gap-4">
          <Input
            label="Sends per Hour"
            type="number"
            placeholder="50"
            value={formData.sends_per_hour}
            onChange={(e) => setFormData({ ...formData, sends_per_hour: e.target.value })}
          />
          <Input
            label="Reads per Hour"
            type="number"
            placeholder="200"
            value={formData.reads_per_hour}
            onChange={(e) => setFormData({ ...formData, reads_per_hour: e.target.value })}
          />
        </div>
      </div>

      {/* Credentials */}
      <div>
        <div className="flex items-center justify-between mb-3">
          <h3 className="text-sm font-medium text-dark-200">Credentials</h3>
          <label className="flex items-center gap-2 cursor-pointer">
            <input
              type="checkbox"
              checked={formData.enable_credential}
              onChange={(e) => setFormData({ ...formData, enable_credential: e.target.checked })}
              className="w-4 h-4 rounded border-dark-600 bg-dark-900 text-blue-500 focus:ring-blue-500 focus:ring-offset-dark-800"
            />
            <span className="text-sm text-dark-400">Enable</span>
          </label>
        </div>
        {formData.enable_credential && (
          <div className="space-y-4 p-4 bg-dark-900/50 rounded-lg border border-dark-700">
            {formData.provider === 'generic' ? (
              <Input
                label="Password"
                type="password"
                placeholder={isEdit && editModal?.has_credential ? '(unchanged)' : 'Enter password'}
                value={formData.password}
                onChange={(e) => setFormData({ ...formData, password: e.target.value })}
              />
            ) : (
              <>
                <Input
                  label="OAuth2 Client ID"
                  type="password"
                  placeholder={isEdit && editModal?.has_credential ? '(unchanged)' : 'Client ID'}
                  value={formData.client_id}
                  onChange={(e) => setFormData({ ...formData, client_id: e.target.value })}
                />
                <Input
                  label="OAuth2 Client Secret"
                  type="password"
                  placeholder={isEdit && editModal?.has_credential ? '(unchanged)' : 'Client Secret'}
                  value={formData.client_secret}
                  onChange={(e) => setFormData({ ...formData, client_secret: e.target.value })}
                />
                <Input
                  label="OAuth2 Refresh Token"
                  type="password"
                  placeholder={isEdit && editModal?.has_credential ? '(unchanged)' : 'Refresh Token'}
                  value={formData.refresh_token}
                  onChange={(e) => setFormData({ ...formData, refresh_token: e.target.value })}
                />
              </>
            )}
            <p className="text-xs text-dark-500">
              Credentials are encrypted at rest.
              {isEdit && editModal?.has_credential && ' Leave empty to keep current credentials.'}
            </p>
          </div>
        )}
      </div>
    </div>
  );

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-purple-600/20 rounded-lg">
            <Mail className="text-purple-400" size={24} />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-2xl font-bold text-dark-100">Email Policies</h1>
              <span className="text-xs font-medium bg-blue-600/20 text-blue-400 px-2 py-0.5 rounded">Beta</span>
            </div>
            <p className="text-dark-400 text-sm mt-1">
              Configure email accounts, allowlists, and rate limits for agents
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="secondary" onClick={() => refetch()}>
            <RefreshCw size={16} className="mr-2" />
            Refresh
          </Button>
          <Button onClick={() => setCreateModal(true)} disabled={!selectedTenantId}>
            <Plus size={16} className="mr-2" />
            New Account
          </Button>
        </div>
      </div>

      {/* Profile Selector */}
      <div>
        <label className="block text-sm font-medium text-dark-300 mb-2">
          Profile
        </label>
        <div className="relative w-72">
          <select
            value={selectedProfileId ?? ''}
            onChange={(e) => setSelectedProfileId(Number(e.target.value))}
            className="w-full appearance-none bg-dark-800 border border-dark-600 rounded-lg px-3 py-2 pr-8 text-sm text-dark-100 focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
          >
            {!profiles?.length && (
              <option value="">No profiles available</option>
            )}
            {profiles?.map((p) => (
              <option key={p.id} value={p.id}>{p.name}</option>
            ))}
          </select>
          <ChevronDown
            size={16}
            className="absolute right-2 top-1/2 -translate-y-1/2 text-dark-400 pointer-events-none"
          />
        </div>
      </div>

      <Card>
        {policies.length > 0 && (
          <div className="mb-4">
            <div className="relative max-w-sm">
              <Search size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-dark-500" />
              <Input
                placeholder="Filter by name, email, or provider..."
                className="pl-9"
                value={filter}
                onChange={(e) => setFilter(e.target.value)}
              />
            </div>
          </div>
        )}
        {isLoading || !selectedTenantId ? (
          <div className="text-center py-8 text-dark-400">
            {selectedTenantId ? 'Loading...' : 'Select a tenant to view email policies'}
          </div>
        ) : filteredPolicies.length > 0 ? (
          <Table
            columns={columns}
            data={filteredPolicies}
            keyExtractor={(p) => p.id.toString()}
          />
        ) : policies.length > 0 ? (
          <div className="text-center py-8 text-dark-400">
            No policies match &ldquo;{filter}&rdquo;
          </div>
        ) : (
          <div className="text-center py-8 text-dark-400">
            <Mail size={48} className="mx-auto mb-4 opacity-50" />
            <p>No email policies configured</p>
            <p className="text-sm mt-2">
              Add email accounts to control agent group email access with allowlists and rate limits.
            </p>
          </div>
        )}
      </Card>

      {/* Create Modal */}
      <Modal
        isOpen={createModal}
        onClose={() => { setCreateModal(false); resetForm(); }}
        title="Create Email Policy"
        size="lg"
      >
        {renderFormFields(false)}
        <div className="flex justify-end gap-2 pt-6">
          <Button variant="secondary" onClick={() => { setCreateModal(false); resetForm(); }}>
            Cancel
          </Button>
          <Button
            onClick={handleCreate}
            disabled={!formData.name || !formData.email || createPolicy.isPending}
          >
            {createPolicy.isPending ? 'Creating...' : 'Create'}
          </Button>
        </div>
      </Modal>

      {/* Edit Modal */}
      <Modal
        isOpen={!!editModal}
        onClose={() => { setEditModal(null); resetForm(); }}
        title="Edit Email Policy"
        size="lg"
      >
        {renderFormFields(true)}
        <div className="flex justify-end gap-2 pt-6">
          <Button variant="secondary" onClick={() => { setEditModal(null); resetForm(); }}>
            Cancel
          </Button>
          <Button onClick={handleUpdate} disabled={updatePolicy.isPending}>
            {updatePolicy.isPending ? 'Saving...' : 'Save Changes'}
          </Button>
        </div>
      </Modal>

      {/* Delete Modal */}
      <Modal
        isOpen={!!deleteModal}
        onClose={() => setDeleteModal(null)}
        title="Delete Email Policy"
      >
        <div className="space-y-4">
          <p className="text-dark-300">
            Are you sure you want to delete the email policy{' '}
            <code className="text-blue-400">{deleteModal?.name}</code> ({deleteModal?.email})?
            This action cannot be undone.
          </p>
          <div className="flex justify-end gap-2 pt-4">
            <Button variant="secondary" onClick={() => setDeleteModal(null)}>
              Cancel
            </Button>
            <Button variant="danger" onClick={handleDelete} disabled={deletePolicy.isPending}>
              {deletePolicy.isPending ? 'Deleting...' : 'Delete'}
            </Button>
          </div>
        </div>
      </Modal>
    </div>
  );
}
