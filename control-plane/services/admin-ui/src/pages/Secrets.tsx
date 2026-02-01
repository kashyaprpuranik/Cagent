import { useState } from 'react';
import { Plus, RefreshCw, RotateCcw, Trash2, ExternalLink } from 'lucide-react';
import { Card, Table, Button, Modal, Input, Select, Badge } from '../components/common';
import {
  useSecrets,
  useCreateSecret,
  useRotateSecret,
  useDeleteSecret,
  useAgents,
} from '../hooks/useApi';
import type { Secret, DataPlane } from '../types/api';

export function Secrets() {
  const { data: secrets = [], isLoading, refetch } = useSecrets();
  const { data: agents = [] } = useAgents();
  const createSecret = useCreateSecret();
  const rotateSecret = useRotateSecret();
  const deleteSecret = useDeleteSecret();

  const [createModal, setCreateModal] = useState(false);
  const [rotateModal, setRotateModal] = useState<Secret | null>(null);
  const [deleteModal, setDeleteModal] = useState<Secret | null>(null);

  const [newName, setNewName] = useState('');
  const [newValue, setNewValue] = useState('');
  const [newDomainPattern, setNewDomainPattern] = useState('');
  const [newHeaderName, setNewHeaderName] = useState('Authorization');
  const [newHeaderFormat, setNewHeaderFormat] = useState('Bearer {value}');
  const [newDescription, setNewDescription] = useState('');
  const [newAgentId, setNewAgentId] = useState('');
  const [newAlias, setNewAlias] = useState('');
  const [rotateValue, setRotateValue] = useState('');

  // Build agent options for the Select dropdown
  const agentOptions = [
    { value: '', label: 'Global (all agents)' },
    ...agents.map((agent: DataPlane) => ({
      value: agent.agent_id,
      label: agent.agent_id,
    })),
  ];

  const handleCreate = async () => {
    try {
      await createSecret.mutateAsync({
        name: newName,
        value: newValue,
        domain_pattern: newDomainPattern,
        alias: newAlias || undefined,
        header_name: newHeaderName,
        header_format: newHeaderFormat,
        description: newDescription || undefined,
        agent_id: newAgentId || undefined,
      });
      setCreateModal(false);
      setNewName('');
      setNewValue('');
      setNewDomainPattern('');
      setNewAlias('');
      setNewHeaderName('Authorization');
      setNewHeaderFormat('Bearer {value}');
      setNewDescription('');
      setNewAgentId('');
    } catch {
      // Error handled by mutation
    }
  };

  const handleRotate = async () => {
    if (!rotateModal) return;
    try {
      await rotateSecret.mutateAsync({
        name: rotateModal.name,
        newValue: rotateValue,
      });
      setRotateModal(null);
      setRotateValue('');
    } catch {
      // Error handled by mutation
    }
  };

  const handleDelete = async () => {
    if (!deleteModal) return;
    try {
      await deleteSecret.mutateAsync(deleteModal.name);
      setDeleteModal(null);
    } catch {
      // Error handled by mutation
    }
  };

  const getRotationBadge = (needsRotation: boolean) => {
    return needsRotation
      ? <Badge variant="warning">Needs Rotation</Badge>
      : <Badge variant="success">Current</Badge>;
  };

  const columns = [
    {
      key: 'name',
      header: 'Name',
      render: (secret: Secret) => (
        <div>
          <span className="font-medium text-dark-100">{secret.name}</span>
          {secret.description && (
            <p className="text-xs text-dark-500">{secret.description}</p>
          )}
        </div>
      ),
    },
    {
      key: 'domain_pattern',
      header: 'Domain',
      render: (secret: Secret) => (
        <div>
          <code className="text-sm text-blue-400">{secret.domain_pattern || '-'}</code>
          {secret.alias && (
            <p className="text-xs text-dark-500">{secret.alias}.devbox.local</p>
          )}
        </div>
      ),
    },
    {
      key: 'agent_id',
      header: 'Agent',
      render: (secret: Secret) => (
        secret.agent_id
          ? <Badge variant="info">{secret.agent_id}</Badge>
          : <span className="text-sm text-dark-500">Global</span>
      ),
    },
    {
      key: 'header',
      header: 'Header',
      render: (secret: Secret) => (
        <span className="text-sm text-dark-400">{secret.header_name || '-'}</span>
      ),
    },
    {
      key: 'status',
      header: 'Status',
      render: (secret: Secret) => getRotationBadge(secret.needs_rotation),
    },
    {
      key: 'last_rotated',
      header: 'Last Rotated',
      render: (secret: Secret) =>
        secret.last_rotated
          ? new Date(secret.last_rotated).toLocaleDateString()
          : 'Never',
    },
    {
      key: 'actions',
      header: '',
      className: 'text-right',
      render: (secret: Secret) => (
        <div className="flex items-center justify-end gap-2">
          <Button
            variant="ghost"
            size="sm"
            onClick={() => setRotateModal(secret)}
          >
            <RotateCcw size={14} className="mr-1" />
            Rotate
          </Button>
          <Button
            variant="ghost"
            size="sm"
            onClick={() => setDeleteModal(secret)}
          >
            <Trash2 size={14} />
          </Button>
        </div>
      ),
    },
  ];

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-dark-100">Secrets</h1>
        <div className="flex items-center gap-2">
          <a
            href="/grafana/d/vault-secrets"
            target="_blank"
            rel="noopener noreferrer"
            className="flex items-center gap-1 text-sm text-dark-400 hover:text-dark-200"
          >
            <ExternalLink size={14} />
            Grafana Metrics
          </a>
          <Button variant="secondary" onClick={() => refetch()}>
            <RefreshCw size={16} className="mr-2" />
            Refresh
          </Button>
          <Button onClick={() => setCreateModal(true)}>
            <Plus size={16} className="mr-2" />
            New Secret
          </Button>
        </div>
      </div>

      <Card>
        <Table
          columns={columns}
          data={secrets}
          keyExtractor={(s) => s.name}
          isLoading={isLoading}
          emptyMessage="No secrets found"
        />
      </Card>

      {/* Create Modal */}
      <Modal
        isOpen={createModal}
        onClose={() => setCreateModal(false)}
        title="Create Secret"
      >
        <div className="space-y-4">
          <Input
            label="Secret Name"
            placeholder="OPENAI_API_KEY"
            value={newName}
            onChange={(e) => setNewName(e.target.value)}
          />
          <Input
            label="Secret Value"
            type="password"
            placeholder="sk-..."
            value={newValue}
            onChange={(e) => setNewValue(e.target.value)}
          />
          <Input
            label="Domain Pattern"
            placeholder="api.openai.com or *.github.com"
            value={newDomainPattern}
            onChange={(e) => setNewDomainPattern(e.target.value)}
          />
          <Input
            label="Alias (optional)"
            placeholder="openai"
            value={newAlias}
            onChange={(e) => setNewAlias(e.target.value)}
          />
          <p className="text-xs text-dark-500">
            Alias creates a shortcut: <code className="text-blue-400">{newAlias || 'alias'}.devbox.local</code> → {newDomainPattern || 'domain'}
          </p>
          <div className="grid grid-cols-2 gap-4">
            <Input
              label="Header Name"
              placeholder="Authorization"
              value={newHeaderName}
              onChange={(e) => setNewHeaderName(e.target.value)}
            />
            <Input
              label="Header Format"
              placeholder="Bearer {value}"
              value={newHeaderFormat}
              onChange={(e) => setNewHeaderFormat(e.target.value)}
            />
          </div>
          <Input
            label="Description (optional)"
            placeholder="OpenAI API key for completions"
            value={newDescription}
            onChange={(e) => setNewDescription(e.target.value)}
          />
          <Select
            label="Agent (optional)"
            options={agentOptions}
            value={newAgentId}
            onChange={(e) => setNewAgentId(e.target.value)}
          />
          <p className="text-xs text-dark-500">
            The credential will be injected as the specified header when requests match the domain pattern.
            Use {'{value}'} in the header format to insert the secret value.
            Select an agent to scope this secret to that agent only, or leave as "Global" to apply to all agents.
            If an alias is set, agents can use <code className="text-blue-400">alias.devbox.local</code> instead of the real domain.
          </p>
          <div className="flex justify-end gap-2 pt-4">
            <Button variant="secondary" onClick={() => setCreateModal(false)}>
              Cancel
            </Button>
            <Button
              onClick={handleCreate}
              disabled={!newName || !newValue || !newDomainPattern || createSecret.isPending}
            >
              {createSecret.isPending ? 'Creating...' : 'Create'}
            </Button>
          </div>
        </div>
      </Modal>

      {/* Rotate Modal */}
      <Modal
        isOpen={!!rotateModal}
        onClose={() => setRotateModal(null)}
        title="Rotate Secret"
      >
        <div className="space-y-4">
          <p className="text-dark-300">
            Rotating secret:{' '}
            <span className="font-medium text-dark-100">
              {rotateModal?.name}
            </span>
          </p>
          <Input
            label="New Value"
            type="password"
            placeholder="Enter new secret value"
            value={rotateValue}
            onChange={(e) => setRotateValue(e.target.value)}
          />
          <div className="flex justify-end gap-2 pt-4">
            <Button variant="secondary" onClick={() => setRotateModal(null)}>
              Cancel
            </Button>
            <Button
              onClick={handleRotate}
              disabled={!rotateValue || rotateSecret.isPending}
            >
              {rotateSecret.isPending ? 'Rotating...' : 'Rotate'}
            </Button>
          </div>
        </div>
      </Modal>

      {/* Delete Confirmation Modal */}
      <Modal
        isOpen={!!deleteModal}
        onClose={() => setDeleteModal(null)}
        title="Delete Secret"
      >
        <div className="space-y-4">
          <p className="text-dark-300">
            Are you sure you want to delete the secret{' '}
            <span className="font-medium text-dark-100">
              {deleteModal?.name}
            </span>
            ? This action cannot be undone.
          </p>
          <div className="flex justify-end gap-2 pt-4">
            <Button variant="secondary" onClick={() => setDeleteModal(null)}>
              Cancel
            </Button>
            <Button
              variant="danger"
              onClick={handleDelete}
              disabled={deleteSecret.isPending}
            >
              {deleteSecret.isPending ? 'Deleting...' : 'Delete'}
            </Button>
          </div>
        </div>
      </Modal>
    </div>
  );
}
