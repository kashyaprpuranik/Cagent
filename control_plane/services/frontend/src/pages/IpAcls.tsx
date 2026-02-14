import { useState } from 'react';
import { Plus, Trash2, ToggleLeft, ToggleRight, Network } from 'lucide-react';
import { Card, Table, Button, Modal, Input, Badge } from '@cagent/shared-ui';
import {
  useTenantIpAcls,
  useCreateTenantIpAcl,
  useUpdateTenantIpAcl,
  useDeleteTenantIpAcl,
} from '../hooks/useApi';
import { useTenant } from '../contexts/TenantContext';
import type { TenantIpAcl } from '../types/api';

export function IpAcls() {
  const { selectedTenantId } = useTenant();

  const { data: ipAcls = [], isLoading } = useTenantIpAcls(selectedTenantId);
  const createAcl = useCreateTenantIpAcl();
  const updateAcl = useUpdateTenantIpAcl();
  const deleteAcl = useDeleteTenantIpAcl();

  const [addModal, setAddModal] = useState(false);
  const [deleteModal, setDeleteModal] = useState<TenantIpAcl | null>(null);

  const [newCidr, setNewCidr] = useState('');
  const [newDescription, setNewDescription] = useState('');
  const [cidrError, setCidrError] = useState('');

  // Validate CIDR format
  const validateCidr = (cidr: string): boolean => {
    // Basic CIDR validation regex
    const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$/;
    const ipv6Regex = /^([0-9a-fA-F:]+)\/\d{1,3}$/;
    return ipv4Regex.test(cidr) || ipv6Regex.test(cidr);
  };

  const handleCidrChange = (value: string) => {
    setNewCidr(value);
    if (value && !validateCidr(value)) {
      setCidrError('Invalid CIDR format. Example: 192.168.1.0/24 or 10.0.0.0/8');
    } else {
      setCidrError('');
    }
  };

  const handleAdd = async () => {
    if (!selectedTenantId || !newCidr || cidrError) return;
    try {
      await createAcl.mutateAsync({
        tenantId: selectedTenantId,
        data: {
          cidr: newCidr,
          description: newDescription || undefined,
        },
      });
      setAddModal(false);
      setNewCidr('');
      setNewDescription('');
      setCidrError('');
    } catch {
      // Error handled by mutation
    }
  };

  const handleToggle = async (acl: TenantIpAcl) => {
    if (!selectedTenantId) return;
    try {
      await updateAcl.mutateAsync({
        tenantId: selectedTenantId,
        aclId: acl.id,
        data: { enabled: !acl.enabled },
      });
    } catch {
      // Error handled by mutation
    }
  };

  const handleDelete = async () => {
    if (!deleteModal || !selectedTenantId) return;
    try {
      await deleteAcl.mutateAsync({
        tenantId: selectedTenantId,
        aclId: deleteModal.id,
      });
      setDeleteModal(null);
    } catch {
      // Error handled by mutation
    }
  };

  const columns = [
    {
      key: 'cidr',
      header: 'CIDR Range',
      render: (acl: TenantIpAcl) => (
        <code className="bg-dark-900 px-2 py-1 rounded text-sm font-mono">
          {acl.cidr}
        </code>
      ),
    },
    {
      key: 'description',
      header: 'Description',
      render: (acl: TenantIpAcl) => (
        <span className="text-dark-400">{acl.description || '-'}</span>
      ),
    },
    {
      key: 'enabled',
      header: 'Status',
      render: (acl: TenantIpAcl) =>
        acl.enabled ? (
          <Badge variant="success">Enabled</Badge>
        ) : (
          <Badge variant="default">Disabled</Badge>
        ),
    },
    {
      key: 'created_by',
      header: 'Created By',
      render: (acl: TenantIpAcl) => (
        <span className="text-dark-400 text-sm">{acl.created_by || '-'}</span>
      ),
    },
    {
      key: 'created_at',
      header: 'Created',
      render: (acl: TenantIpAcl) =>
        new Date(acl.created_at).toLocaleDateString(),
    },
    {
      key: 'actions',
      header: '',
      className: 'text-right',
      render: (acl: TenantIpAcl) => (
        <div className="flex items-center justify-end gap-2">
          <Button
            variant="ghost"
            size="sm"
            onClick={() => handleToggle(acl)}
            title={acl.enabled ? 'Disable' : 'Enable'}
          >
            {acl.enabled ? (
              <ToggleRight size={18} className="text-green-500" />
            ) : (
              <ToggleLeft size={18} className="text-dark-500" />
            )}
          </Button>
          <Button
            variant="ghost"
            size="sm"
            onClick={() => setDeleteModal(acl)}
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
        <div className="flex items-center gap-3">
          <div className="p-2 bg-blue-600/20 rounded-lg">
            <Network className="text-blue-400" size={24} />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-dark-100">IP Access Control</h1>
            <p className="text-dark-400 text-sm mt-1">
              Restrict control plane access to specific IP ranges per tenant
            </p>
          </div>
        </div>
        <Button onClick={() => setAddModal(true)} disabled={!selectedTenantId}>
          <Plus size={16} className="mr-2" />
          Add IP Range
        </Button>
      </div>

      <Card>
        <Table
          columns={columns}
          data={ipAcls}
          keyExtractor={(acl) => acl.id}
          isLoading={isLoading || !selectedTenantId}
          emptyMessage={
            selectedTenantId
              ? "No IP ACLs configured. All IPs are allowed."
              : "Select a tenant to view IP ACLs"
          }
        />
      </Card>

      <Card className="bg-dark-800/50">
        <div className="text-sm text-dark-400 space-y-2">
          <p className="font-medium text-dark-300">How IP ACLs Work:</p>
          <ul className="list-disc list-inside space-y-1">
            <li>If no IP ACLs are configured, all IP addresses are allowed (default behavior)</li>
            <li>Once any IP ACL is added, only matching IPs can access the control plane</li>
            <li>Agent group tokens (used by data planes) are not affected by IP ACLs</li>
            <li>Use CIDR notation: single IP as x.x.x.x/32, subnet as x.x.x.0/24</li>
          </ul>
        </div>
      </Card>

      {/* Add Modal */}
      <Modal
        isOpen={addModal}
        onClose={() => {
          setAddModal(false);
          setNewCidr('');
          setNewDescription('');
          setCidrError('');
        }}
        title="Add IP Range"
      >
        <div className="space-y-4">
          <Input
            label="CIDR Range"
            placeholder="192.168.1.0/24 or 10.0.0.0/8"
            value={newCidr}
            onChange={(e) => handleCidrChange(e.target.value)}
            error={cidrError}
          />
          <p className="text-xs text-dark-500">
            Examples: 192.168.1.0/24 (subnet), 10.0.0.5/32 (single IP), 0.0.0.0/0 (all IPv4)
          </p>
          <Input
            label="Description (optional)"
            placeholder="e.g., Office network, VPN, etc."
            value={newDescription}
            onChange={(e) => setNewDescription(e.target.value)}
          />
          <div className="flex justify-end gap-2 pt-4">
            <Button
              variant="secondary"
              onClick={() => {
                setAddModal(false);
                setNewCidr('');
                setNewDescription('');
                setCidrError('');
              }}
            >
              Cancel
            </Button>
            <Button
              onClick={handleAdd}
              disabled={!newCidr || !!cidrError || createAcl.isPending}
            >
              {createAcl.isPending ? 'Adding...' : 'Add IP Range'}
            </Button>
          </div>
        </div>
      </Modal>

      {/* Delete Confirmation Modal */}
      <Modal
        isOpen={!!deleteModal}
        onClose={() => setDeleteModal(null)}
        title="Delete IP Range"
      >
        <div className="space-y-4">
          <p className="text-dark-300">
            Are you sure you want to delete this IP range?
          </p>
          <code className="block bg-dark-900 px-3 py-2 rounded text-sm font-mono">
            {deleteModal?.cidr}
          </code>
          {deleteModal?.description && (
            <p className="text-dark-400 text-sm">{deleteModal.description}</p>
          )}
          <div className="bg-yellow-500/10 border border-yellow-500/20 rounded-lg p-3">
            <p className="text-yellow-400 text-sm">
              Warning: If this is the only IP range for the tenant, all IPs will be allowed after deletion.
            </p>
          </div>
          <div className="flex justify-end gap-2 pt-4">
            <Button variant="secondary" onClick={() => setDeleteModal(null)}>
              Cancel
            </Button>
            <Button
              variant="danger"
              onClick={handleDelete}
              disabled={deleteAcl.isPending}
            >
              {deleteAcl.isPending ? 'Deleting...' : 'Delete'}
            </Button>
          </div>
        </div>
      </Modal>
    </div>
  );
}
