import { useState } from 'react';
import { Plus, Edit2, Trash2, RefreshCw, RotateCcw, Globe } from 'lucide-react';
import { Card, Table, Button, Modal, Input, Select, Badge } from '../components/common';
import {
  useDomainPolicies,
  useCreateDomainPolicy,
  useUpdateDomainPolicy,
  useDeleteDomainPolicy,
  useRotateDomainPolicyCredential,
  useAgents,
} from '../hooks/useApi';
import { useTenant } from '../contexts/TenantContext';
import type { DomainPolicy, DataPlane, CreateDomainPolicyRequest, UpdateDomainPolicyRequest } from '../types/api';

interface FormData {
  domain: string;
  alias: string;
  description: string;
  agent_id: string;
  allowed_paths: string;
  requests_per_minute: string;
  burst_size: string;
  bytes_per_hour: string;
  enable_credential: boolean;
  credential_header: string;
  credential_format: string;
  credential_value: string;
}

const emptyFormData: FormData = {
  domain: '',
  alias: '',
  description: '',
  agent_id: '',
  allowed_paths: '',
  requests_per_minute: '',
  burst_size: '',
  bytes_per_hour: '',
  enable_credential: false,
  credential_header: 'Authorization',
  credential_format: 'Bearer {value}',
  credential_value: '',
};

export function DomainPolicies() {
  const { selectedTenantId } = useTenant();

  const { data: policies = [], isLoading, refetch } = useDomainPolicies({ tenantId: selectedTenantId });
  const { data: agents = [] } = useAgents();
  const createPolicy = useCreateDomainPolicy();
  const updatePolicy = useUpdateDomainPolicy();
  const deletePolicy = useDeleteDomainPolicy();
  const rotateCredential = useRotateDomainPolicyCredential();

  const [createModal, setCreateModal] = useState(false);
  const [editModal, setEditModal] = useState<DomainPolicy | null>(null);
  const [deleteModal, setDeleteModal] = useState<DomainPolicy | null>(null);
  const [rotateModal, setRotateModal] = useState<DomainPolicy | null>(null);

  const [formData, setFormData] = useState<FormData>(emptyFormData);
  const [rotateData, setRotateData] = useState({
    header: 'Authorization',
    format: 'Bearer {value}',
    value: '',
  });

  const agentOptions = [
    { value: '', label: 'Global (all agents)' },
    ...agents.map((agent: DataPlane) => ({
      value: agent.agent_id,
      label: agent.agent_id,
    })),
  ];

  const resetForm = () => {
    setFormData(emptyFormData);
  };

  const openEditModal = (policy: DomainPolicy) => {
    setFormData({
      domain: policy.domain,
      alias: policy.alias || '',
      description: policy.description || '',
      agent_id: policy.agent_id || '',
      allowed_paths: (policy.allowed_paths || []).join('\n'),
      requests_per_minute: policy.requests_per_minute?.toString() || '',
      burst_size: policy.burst_size?.toString() || '',
      bytes_per_hour: policy.bytes_per_hour?.toString() || '',
      enable_credential: policy.has_credential || false,
      credential_header: policy.credential_header || 'Authorization',
      credential_format: policy.credential_format || 'Bearer {value}',
      credential_value: '',
    });
    setEditModal(policy);
  };

  const handleCreate = async () => {
    const paths = formData.allowed_paths
      .split('\n')
      .map((p) => p.trim())
      .filter((p) => p);

    const data: CreateDomainPolicyRequest = {
      domain: formData.domain,
      alias: formData.alias || undefined,
      description: formData.description || undefined,
      agent_id: formData.agent_id || undefined,
      allowed_paths: paths.length > 0 ? paths : undefined,
      requests_per_minute: formData.requests_per_minute ? parseInt(formData.requests_per_minute) : undefined,
      burst_size: formData.burst_size ? parseInt(formData.burst_size) : undefined,
      bytes_per_hour: formData.bytes_per_hour ? parseInt(formData.bytes_per_hour) : undefined,
    };

    if (formData.enable_credential && formData.credential_value) {
      data.credential = {
        header: formData.credential_header,
        format: formData.credential_format,
        value: formData.credential_value,
      };
    }

    try {
      await createPolicy.mutateAsync({
        data,
        tenantId: selectedTenantId ?? undefined,
      });
      setCreateModal(false);
      resetForm();
    } catch {
      // Error handled by mutation
    }
  };

  const handleUpdate = async () => {
    if (!editModal) return;

    const paths = formData.allowed_paths
      .split('\n')
      .map((p) => p.trim())
      .filter((p) => p);

    const data: UpdateDomainPolicyRequest = {
      alias: formData.alias || undefined,
      description: formData.description || undefined,
      allowed_paths: paths,
      requests_per_minute: formData.requests_per_minute ? parseInt(formData.requests_per_minute) : undefined,
      burst_size: formData.burst_size ? parseInt(formData.burst_size) : undefined,
      bytes_per_hour: formData.bytes_per_hour ? parseInt(formData.bytes_per_hour) : undefined,
    };

    if (formData.enable_credential && formData.credential_value) {
      data.credential = {
        header: formData.credential_header,
        format: formData.credential_format,
        value: formData.credential_value,
      };
    }

    try {
      await updatePolicy.mutateAsync({ id: editModal.id, data });
      setEditModal(null);
      resetForm();
    } catch {
      // Error handled by mutation
    }
  };

  const handleToggle = async (policy: DomainPolicy) => {
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

  const handleRotate = async () => {
    if (!rotateModal) return;
    try {
      await rotateCredential.mutateAsync({
        id: rotateModal.id,
        credential: {
          header: rotateData.header,
          format: rotateData.format,
          value: rotateData.value,
        },
      });
      setRotateModal(null);
      setRotateData({ header: 'Authorization', format: 'Bearer {value}', value: '' });
    } catch {
      // Error handled by mutation
    }
  };

  const openRotateModal = (policy: DomainPolicy) => {
    setRotateData({
      header: policy.credential_header || 'Authorization',
      format: policy.credential_format || 'Bearer {value}',
      value: '',
    });
    setRotateModal(policy);
  };

  const columns = [
    {
      key: 'domain',
      header: 'Domain',
      render: (policy: DomainPolicy) => (
        <div>
          <code className="text-sm text-blue-400">{policy.domain}</code>
          {policy.alias && (
            <p className="text-xs text-dark-500">{policy.alias}.devbox.local</p>
          )}
          {policy.description && (
            <p className="text-xs text-dark-500 mt-1">{policy.description}</p>
          )}
        </div>
      ),
    },
    {
      key: 'paths',
      header: 'Paths',
      render: (policy: DomainPolicy) => {
        const paths = policy.allowed_paths || [];
        if (paths.length === 0) {
          return <span className="text-dark-500 text-sm">All paths</span>;
        }
        return (
          <span className="text-sm text-dark-300">
            {paths.length} {paths.length === 1 ? 'path' : 'paths'}
          </span>
        );
      },
    },
    {
      key: 'rate_limit',
      header: 'Rate Limit',
      render: (policy: DomainPolicy) =>
        policy.requests_per_minute ? (
          <span className="text-sm text-dark-300">
            {policy.requests_per_minute}/min (burst: {policy.burst_size || '-'})
          </span>
        ) : (
          <span className="text-dark-500 text-sm">Default</span>
        ),
    },
    {
      key: 'egress',
      header: 'Egress',
      render: (policy: DomainPolicy) =>
        policy.bytes_per_hour ? (
          <span className="text-sm text-dark-300">
            {(policy.bytes_per_hour / 1048576).toFixed(0)} MB/hr
          </span>
        ) : (
          <span className="text-dark-500 text-sm">Default</span>
        ),
    },
    {
      key: 'credential',
      header: 'Credential',
      render: (policy: DomainPolicy) =>
        policy.has_credential ? (
          <div>
            <Badge variant="success">Configured</Badge>
            {policy.credential_rotated_at && (
              <p className="text-xs text-dark-500 mt-1">
                Rotated: {new Date(policy.credential_rotated_at).toLocaleDateString()}
              </p>
            )}
          </div>
        ) : (
          <span className="text-dark-500 text-sm">None</span>
        ),
    },
    {
      key: 'agent',
      header: 'Agent',
      render: (policy: DomainPolicy) =>
        policy.agent_id ? (
          <Badge variant="info">{policy.agent_id}</Badge>
        ) : (
          <span className="text-dark-500 text-sm">Global</span>
        ),
    },
    {
      key: 'status',
      header: 'Status',
      render: (policy: DomainPolicy) => (
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
      render: (policy: DomainPolicy) => (
        <div className="flex items-center justify-end gap-2">
          {policy.has_credential && (
            <Button variant="ghost" size="sm" onClick={() => openRotateModal(policy)}>
              <RotateCcw size={14} className="mr-1" />
              Rotate
            </Button>
          )}
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
        <h3 className="text-sm font-medium text-dark-200 mb-3">Basic Settings</h3>
        <div className="space-y-4">
          <Input
            label="Domain"
            placeholder="api.openai.com or *.github.com"
            value={formData.domain}
            onChange={(e) => setFormData({ ...formData, domain: e.target.value })}
            disabled={isEdit}
          />
          <div className="grid grid-cols-2 gap-4">
            <Input
              label="Alias (optional)"
              placeholder="openai"
              value={formData.alias}
              onChange={(e) => setFormData({ ...formData, alias: e.target.value })}
            />
            <Select
              label="Agent (optional)"
              options={agentOptions}
              value={formData.agent_id}
              onChange={(e) => setFormData({ ...formData, agent_id: e.target.value })}
              disabled={isEdit}
            />
          </div>
          {formData.alias && (
            <p className="text-xs text-dark-500">
              Alias creates a shortcut: <code className="text-blue-400">{formData.alias}.devbox.local</code> → {formData.domain || 'domain'}
            </p>
          )}
          <Input
            label="Description (optional)"
            placeholder="OpenAI API access"
            value={formData.description}
            onChange={(e) => setFormData({ ...formData, description: e.target.value })}
          />
        </div>
      </div>

      {/* Path Restrictions */}
      <div>
        <h3 className="text-sm font-medium text-dark-200 mb-3">Path Restrictions (optional)</h3>
        <div className="space-y-2">
          <textarea
            className="w-full px-3 py-2 bg-dark-900 border border-dark-600 rounded-lg text-dark-100 focus:border-blue-500 focus:ring-1 focus:ring-blue-500 font-mono text-sm"
            rows={3}
            placeholder="/v1/chat/*&#10;/v1/models&#10;/api/v2/users/*"
            value={formData.allowed_paths}
            onChange={(e) => setFormData({ ...formData, allowed_paths: e.target.value })}
          />
          <p className="text-xs text-dark-500">
            One path pattern per line. Use * as wildcard. Leave empty to allow all paths.
          </p>
        </div>
      </div>

      {/* Rate Limiting */}
      <div>
        <h3 className="text-sm font-medium text-dark-200 mb-3">Rate Limiting (optional)</h3>
        <div className="grid grid-cols-2 gap-4">
          <Input
            label="Requests per Minute"
            type="number"
            placeholder="60"
            value={formData.requests_per_minute}
            onChange={(e) => setFormData({ ...formData, requests_per_minute: e.target.value })}
          />
          <Input
            label="Burst Size"
            type="number"
            placeholder="10"
            value={formData.burst_size}
            onChange={(e) => setFormData({ ...formData, burst_size: e.target.value })}
          />
        </div>
        <p className="text-xs text-dark-500 mt-2">
          Leave empty to use default rate limits.
        </p>
      </div>

      {/* Egress Limiting */}
      <div>
        <h3 className="text-sm font-medium text-dark-200 mb-3">Egress Limiting (optional)</h3>
        <Input
          label="Bytes per Hour"
          type="number"
          placeholder="104857600"
          value={formData.bytes_per_hour}
          onChange={(e) => setFormData({ ...formData, bytes_per_hour: e.target.value })}
        />
        <p className="text-xs text-dark-500 mt-2">
          Maximum bytes allowed per hour. 104857600 = 100MB. Leave empty for default.
        </p>
      </div>

      {/* Credential */}
      <div>
        <div className="flex items-center justify-between mb-3">
          <h3 className="text-sm font-medium text-dark-200">Credential Injection</h3>
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
            <div className="grid grid-cols-2 gap-4">
              <Input
                label="Header Name"
                placeholder="Authorization"
                value={formData.credential_header}
                onChange={(e) => setFormData({ ...formData, credential_header: e.target.value })}
              />
              <Input
                label="Header Format"
                placeholder="Bearer {value}"
                value={formData.credential_format}
                onChange={(e) => setFormData({ ...formData, credential_format: e.target.value })}
              />
            </div>
            <Input
              label="Credential Value"
              type="password"
              placeholder={isEdit && editModal?.has_credential ? '(unchanged)' : 'sk-...'}
              value={formData.credential_value}
              onChange={(e) => setFormData({ ...formData, credential_value: e.target.value })}
            />
            <p className="text-xs text-dark-500">
              Use {'{value}'} in header format to insert the credential.
              {isEdit && editModal?.has_credential && ' Leave value empty to keep current credential.'}
            </p>
          </div>
        )}
        {!formData.enable_credential && (
          <p className="text-xs text-dark-500">
            Enable to automatically inject credentials into requests to this domain.
          </p>
        )}
      </div>
    </div>
  );

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-blue-600/20 rounded-lg">
            <Globe className="text-blue-400" size={24} />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-dark-100">Domain Policies</h1>
            <p className="text-dark-400 text-sm mt-1">
              Configure access, rate limits, and credentials for external domains
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
            New Policy
          </Button>
        </div>
      </div>

      <Card>
        {isLoading || !selectedTenantId ? (
          <div className="text-center py-8 text-dark-400">
            {selectedTenantId ? 'Loading...' : 'Select a tenant to view domain policies'}
          </div>
        ) : policies.length > 0 ? (
          <Table
            columns={columns}
            data={policies}
            keyExtractor={(p) => p.id.toString()}
          />
        ) : (
          <div className="text-center py-8 text-dark-400">
            <Globe size={48} className="mx-auto mb-4 opacity-50" />
            <p>No domain policies configured</p>
            <p className="text-sm mt-2">
              Add policies to control access, rate limits, and credentials for external domains.
            </p>
          </div>
        )}
      </Card>

      {/* Create Modal */}
      <Modal
        isOpen={createModal}
        onClose={() => {
          setCreateModal(false);
          resetForm();
        }}
        title="Create Domain Policy"
        size="lg"
      >
        {renderFormFields(false)}
        <div className="flex justify-end gap-2 pt-6">
          <Button
            variant="secondary"
            onClick={() => {
              setCreateModal(false);
              resetForm();
            }}
          >
            Cancel
          </Button>
          <Button
            onClick={handleCreate}
            disabled={!formData.domain || createPolicy.isPending}
          >
            {createPolicy.isPending ? 'Creating...' : 'Create'}
          </Button>
        </div>
      </Modal>

      {/* Edit Modal */}
      <Modal
        isOpen={!!editModal}
        onClose={() => {
          setEditModal(null);
          resetForm();
        }}
        title="Edit Domain Policy"
        size="lg"
      >
        {renderFormFields(true)}
        <div className="flex justify-end gap-2 pt-6">
          <Button
            variant="secondary"
            onClick={() => {
              setEditModal(null);
              resetForm();
            }}
          >
            Cancel
          </Button>
          <Button onClick={handleUpdate} disabled={updatePolicy.isPending}>
            {updatePolicy.isPending ? 'Saving...' : 'Save Changes'}
          </Button>
        </div>
      </Modal>

      {/* Rotate Credential Modal */}
      <Modal
        isOpen={!!rotateModal}
        onClose={() => setRotateModal(null)}
        title="Rotate Credential"
      >
        <div className="space-y-4">
          <p className="text-dark-300">
            Rotating credential for:{' '}
            <code className="text-blue-400">{rotateModal?.domain}</code>
          </p>
          <div className="grid grid-cols-2 gap-4">
            <Input
              label="Header Name"
              placeholder="Authorization"
              value={rotateData.header}
              onChange={(e) => setRotateData({ ...rotateData, header: e.target.value })}
            />
            <Input
              label="Header Format"
              placeholder="Bearer {value}"
              value={rotateData.format}
              onChange={(e) => setRotateData({ ...rotateData, format: e.target.value })}
            />
          </div>
          <Input
            label="New Credential Value"
            type="password"
            placeholder="Enter new credential value"
            value={rotateData.value}
            onChange={(e) => setRotateData({ ...rotateData, value: e.target.value })}
          />
          <div className="flex justify-end gap-2 pt-4">
            <Button variant="secondary" onClick={() => setRotateModal(null)}>
              Cancel
            </Button>
            <Button
              onClick={handleRotate}
              disabled={!rotateData.value || rotateCredential.isPending}
            >
              {rotateCredential.isPending ? 'Rotating...' : 'Rotate'}
            </Button>
          </div>
        </div>
      </Modal>

      {/* Delete Confirmation Modal */}
      <Modal
        isOpen={!!deleteModal}
        onClose={() => setDeleteModal(null)}
        title="Delete Domain Policy"
      >
        <div className="space-y-4">
          <p className="text-dark-300">
            Are you sure you want to delete the policy for{' '}
            <code className="text-blue-400">{deleteModal?.domain}</code>?
            This action cannot be undone.
          </p>
          <div className="flex justify-end gap-2 pt-4">
            <Button variant="secondary" onClick={() => setDeleteModal(null)}>
              Cancel
            </Button>
            <Button
              variant="danger"
              onClick={handleDelete}
              disabled={deletePolicy.isPending}
            >
              {deletePolicy.isPending ? 'Deleting...' : 'Delete'}
            </Button>
          </div>
        </div>
      </Modal>
    </div>
  );
}
