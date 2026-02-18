import { useState, useEffect } from 'react';
import { useSearchParams } from 'react-router-dom';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  Save,
  RefreshCw,
  AlertCircle,
  CheckCircle,
  Plus,
  Trash2,
  Edit2,
  Globe,
  Code,
  Shield,
  Clock,
  Gauge,
  Key,
  Mail,
  Lock,
} from 'lucide-react';
import { Modal, Input, Select, Button, Badge } from '@cagent/ui';
import { getConfig, getInfo, updateConfigRaw, reloadConfig, Config, DomainEntry, EmailAccount } from '../api/client';

type Tab = 'domains' | 'email' | 'settings' | 'raw';

interface ValidationError {
  field: string;
  message: string;
}

// Validation functions
function validateDomain(domain: string): string | null {
  if (!domain) return 'Domain is required';
  // Allow wildcards like *.example.com or plain domains
  const pattern = /^(\*\.)?([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$/;
  if (!pattern.test(domain)) {
    return 'Invalid domain format (e.g., example.com or *.example.com)';
  }
  return null;
}

function validateAlias(alias: string): string | null {
  if (!alias) return null; // Optional
  const pattern = /^[a-zA-Z0-9-]+$/;
  if (!pattern.test(alias)) {
    return 'Alias must be alphanumeric with hyphens only';
  }
  return null;
}

function validateTimeout(timeout: string): string | null {
  if (!timeout) return null; // Optional
  const pattern = /^\d+[smh]?$/;
  if (!pattern.test(timeout)) {
    return 'Invalid timeout (e.g., 30s, 5m, 1h)';
  }
  return null;
}

function validatePositiveInt(value: number | undefined, fieldName: string): string | null {
  if (value === undefined) return null;
  if (!Number.isInteger(value) || value <= 0) {
    return `${fieldName} must be a positive integer`;
  }
  return null;
}

// Domain Editor Modal
function DomainModal({
  domain,
  onSave,
  onClose,
  existingDomains,
}: {
  domain: DomainEntry | null;
  onSave: (domain: DomainEntry) => void;
  onClose: () => void;
  existingDomains: string[];
}) {
  const [form, setForm] = useState<DomainEntry>(
    domain || { domain: '' }
  );
  const [errors, setErrors] = useState<ValidationError[]>([]);
  const [showCredential, setShowCredential] = useState(!!domain?.credential);
  const [showRateLimit, setShowRateLimit] = useState(!!domain?.rate_limit);

  const validate = (): boolean => {
    const newErrors: ValidationError[] = [];

    const domainErr = validateDomain(form.domain);
    if (domainErr) newErrors.push({ field: 'domain', message: domainErr });

    // Check for duplicate domain (only if adding new or changing domain name)
    if (!domain || domain.domain !== form.domain) {
      if (existingDomains.includes(form.domain)) {
        newErrors.push({ field: 'domain', message: 'Domain already exists' });
      }
    }

    const aliasErr = validateAlias(form.alias || '');
    if (aliasErr) newErrors.push({ field: 'alias', message: aliasErr });

    const timeoutErr = validateTimeout(form.timeout || '');
    if (timeoutErr) newErrors.push({ field: 'timeout', message: timeoutErr });

    if (showRateLimit && form.rate_limit) {
      const rpmErr = validatePositiveInt(form.rate_limit.requests_per_minute, 'Requests/min');
      if (rpmErr) newErrors.push({ field: 'rate_limit.requests_per_minute', message: rpmErr });

      const burstErr = validatePositiveInt(form.rate_limit.burst_size, 'Burst size');
      if (burstErr) newErrors.push({ field: 'rate_limit.burst_size', message: burstErr });
    }

    if (showCredential && form.credential) {
      if (!form.credential.header) {
        newErrors.push({ field: 'credential.header', message: 'Header name is required' });
      }
      if (!form.credential.env) {
        newErrors.push({ field: 'credential.env', message: 'Environment variable is required' });
      }
    }

    setErrors(newErrors);
    return newErrors.length === 0;
  };

  const handleSave = () => {
    if (!validate()) return;

    const cleanedForm: DomainEntry = { domain: form.domain };

    if (form.alias) cleanedForm.alias = form.alias;
    if (form.timeout) cleanedForm.timeout = form.timeout;
    if (form.read_only) cleanedForm.read_only = form.read_only;

    if (showRateLimit && form.rate_limit?.requests_per_minute) {
      cleanedForm.rate_limit = {
        requests_per_minute: form.rate_limit.requests_per_minute,
        burst_size: form.rate_limit.burst_size || 10,
      };
    }

    if (showCredential && form.credential?.header && form.credential?.env) {
      cleanedForm.credential = {
        header: form.credential.header,
        format: form.credential.format || '{value}',
        env: form.credential.env,
      };
    }

    onSave(cleanedForm);
  };

  const getError = (field: string) => errors.find((e) => e.field === field)?.message;

  return (
    <Modal isOpen={true} onClose={onClose} title={domain ? 'Edit Egress Policy' : 'Add Egress Policy'} size="lg">
      <div className="space-y-4">
        {/* Domain */}
        <Input
          label="Domain *"
          value={form.domain}
          onChange={(e) => setForm({ ...form, domain: e.target.value })}
          placeholder="api.example.com or *.example.com"
          error={getError('domain')}
        />

        {/* Alias */}
        <div className="space-y-1">
          <label className="block text-sm font-medium text-surface-300">
            Alias <span className="text-surface-500">(optional)</span>
          </label>
          <div className="flex items-center gap-2">
            <input
              type="text"
              value={form.alias || ''}
              onChange={(e) => setForm({ ...form, alias: e.target.value || undefined })}
              placeholder="shortname"
              className={`flex-1 px-3 py-2 bg-surface-900 border rounded-lg text-surface-100 focus:outline-none ${
                getError('alias') ? 'border-red-500' : 'border-surface-600 focus:border-blue-500'
              }`}
            />
            <span className="text-surface-500 text-sm">.devbox.local</span>
          </div>
          {getError('alias') && (
            <p className="text-sm text-red-500">{getError('alias')}</p>
          )}
        </div>

        {/* Timeout */}
        <Input
          label="Timeout (optional)"
          value={form.timeout || ''}
          onChange={(e) => setForm({ ...form, timeout: e.target.value || undefined })}
          placeholder="30s"
          error={getError('timeout')}
        />

        {/* Read Only */}
        <div className="flex items-center gap-2">
          <input
            type="checkbox"
            id="read_only"
            checked={form.read_only || false}
            onChange={(e) => setForm({ ...form, read_only: e.target.checked || undefined })}
            className="w-4 h-4 rounded bg-surface-900 border-surface-600"
          />
          <label htmlFor="read_only" className="text-sm text-surface-300">
            Read-only (block POST/PUT/DELETE)
          </label>
        </div>

        {/* Rate Limit Toggle */}
        <div className="border-t border-surface-700 pt-4">
          <div className="flex items-center justify-between mb-2">
            <label className="text-sm text-surface-300 flex items-center gap-2">
              <Gauge className="w-4 h-4" />
              Rate Limit
            </label>
            <button
              type="button"
              onClick={() => {
                setShowRateLimit(!showRateLimit);
                if (!showRateLimit) {
                  setForm({
                    ...form,
                    rate_limit: { requests_per_minute: 60, burst_size: 10 },
                  });
                } else {
                  setForm({ ...form, rate_limit: undefined });
                }
              }}
              className={`px-2 py-1 text-xs rounded ${
                showRateLimit ? 'bg-blue-600 text-white' : 'bg-surface-700 text-surface-400'
              }`}
            >
              {showRateLimit ? 'Enabled' : 'Disabled'}
            </button>
          </div>

          {showRateLimit && (
            <div className="grid grid-cols-2 gap-3 mt-2">
              <Input
                label="Requests/min"
                type="number"
                value={form.rate_limit?.requests_per_minute || ''}
                onChange={(e) =>
                  setForm({
                    ...form,
                    rate_limit: {
                      ...form.rate_limit,
                      requests_per_minute: parseInt(e.target.value) || 0,
                      burst_size: form.rate_limit?.burst_size || 10,
                    },
                  })
                }
                error={getError('rate_limit.requests_per_minute')}
              />
              <Input
                label="Burst size"
                type="number"
                value={form.rate_limit?.burst_size || ''}
                onChange={(e) =>
                  setForm({
                    ...form,
                    rate_limit: {
                      ...form.rate_limit,
                      requests_per_minute: form.rate_limit?.requests_per_minute || 60,
                      burst_size: parseInt(e.target.value) || 0,
                    },
                  })
                }
                error={getError('rate_limit.burst_size')}
              />
            </div>
          )}
        </div>

        {/* Credential Toggle */}
        <div className="border-t border-surface-700 pt-4">
          <div className="flex items-center justify-between mb-2">
            <label className="text-sm text-surface-300 flex items-center gap-2">
              <Key className="w-4 h-4" />
              Credential Injection
            </label>
            <button
              type="button"
              onClick={() => {
                setShowCredential(!showCredential);
                if (!showCredential) {
                  setForm({
                    ...form,
                    credential: { header: 'Authorization', format: 'Bearer {value}', env: '' },
                  });
                } else {
                  setForm({ ...form, credential: undefined });
                }
              }}
              className={`px-2 py-1 text-xs rounded ${
                showCredential ? 'bg-blue-600 text-white' : 'bg-surface-700 text-surface-400'
              }`}
            >
              {showCredential ? 'Enabled' : 'Disabled'}
            </button>
          </div>

          {showCredential && (
            <div className="space-y-3 mt-2">
              <Input
                label="Header Name"
                value={form.credential?.header || ''}
                onChange={(e) =>
                  setForm({
                    ...form,
                    credential: { ...form.credential!, header: e.target.value },
                  })
                }
                placeholder="Authorization"
                error={getError('credential.header')}
              />
              <div className="space-y-1">
                <Input
                  label="Format"
                  value={form.credential?.format || ''}
                  onChange={(e) =>
                    setForm({
                      ...form,
                      credential: { ...form.credential!, format: e.target.value },
                    })
                  }
                  placeholder="Bearer {value}"
                />
                <p className="text-xs text-surface-500">Use {'{value}'} as placeholder</p>
              </div>
              <Input
                label="Environment Variable"
                value={form.credential?.env || ''}
                onChange={(e) =>
                  setForm({
                    ...form,
                    credential: { ...form.credential!, env: e.target.value },
                  })
                }
                placeholder="API_KEY"
                error={getError('credential.env')}
              />
            </div>
          )}
        </div>
      </div>

      <div className="flex justify-end gap-2 mt-4 pt-4 border-t border-surface-700">
        <Button variant="secondary" onClick={onClose}>Cancel</Button>
        <Button onClick={handleSave}>{domain ? 'Update' : 'Add'} Policy</Button>
      </div>
    </Modal>
  );
}

// Email Account Editor Modal
function EmailAccountModal({
  account,
  onSave,
  onClose,
  existingNames,
}: {
  account: EmailAccount | null;
  onSave: (account: EmailAccount) => void;
  onClose: () => void;
  existingNames: string[];
}) {
  const [form, setForm] = useState<EmailAccount>(
    account || { name: '', provider: 'gmail', email: '' }
  );
  const [error, setError] = useState<string | null>(null);

  const handleSave = () => {
    if (!form.name) { setError('Account name is required'); return; }
    if (!form.email) { setError('Email address is required'); return; }
    if (!account && existingNames.includes(form.name)) { setError('Account name already exists'); return; }

    const cleaned: EmailAccount = {
      name: form.name,
      provider: form.provider,
      email: form.email,
    };

    if (form.imap_server) cleaned.imap_server = form.imap_server;
    if (form.imap_port) cleaned.imap_port = form.imap_port;
    if (form.smtp_server) cleaned.smtp_server = form.smtp_server;
    if (form.smtp_port) cleaned.smtp_port = form.smtp_port;

    // Credential
    if (form.provider === 'generic') {
      if (form.credential?.password_env) {
        cleaned.credential = { password_env: form.credential.password_env };
      }
    } else {
      if (form.credential?.client_id_env || form.credential?.client_secret_env || form.credential?.refresh_token_env) {
        cleaned.credential = {
          client_id_env: form.credential?.client_id_env || undefined,
          client_secret_env: form.credential?.client_secret_env || undefined,
          refresh_token_env: form.credential?.refresh_token_env || undefined,
        };
      }
    }

    // Policy
    const policy = form.policy;
    if (policy?.allowed_recipients?.length || policy?.allowed_senders?.length || policy?.sends_per_hour || policy?.reads_per_hour) {
      cleaned.policy = {};
      if (policy?.allowed_recipients?.length) cleaned.policy.allowed_recipients = policy.allowed_recipients;
      if (policy?.allowed_senders?.length) cleaned.policy.allowed_senders = policy.allowed_senders;
      if (policy?.sends_per_hour) cleaned.policy.sends_per_hour = policy.sends_per_hour;
      if (policy?.reads_per_hour) cleaned.policy.reads_per_hour = policy.reads_per_hour;
    }

    onSave(cleaned);
  };

  return (
    <Modal isOpen={true} onClose={onClose} title={account ? 'Edit Email Account' : 'Add Email Account'} size="lg">
      <div className="space-y-4">
        {error && (
          <div className="bg-red-900/50 border border-red-700 text-red-300 p-2 rounded text-sm">
            {error}
          </div>
        )}

        {/* Name */}
        <Input
          label="Account Name *"
          value={form.name}
          onChange={(e) => { setForm({ ...form, name: e.target.value }); setError(null); }}
          placeholder="work-gmail"
          disabled={!!account}
        />

        {/* Provider + Email */}
        <div className="grid grid-cols-2 gap-3">
          <Select
            label="Provider"
            value={form.provider}
            onChange={(e) => setForm({ ...form, provider: e.target.value as EmailAccount['provider'] })}
            options={[
              { value: 'gmail', label: 'Gmail (OAuth2)' },
              { value: 'outlook', label: 'Outlook/M365 (OAuth2)' },
              { value: 'generic', label: 'Generic (Password)' },
            ]}
          />
          <Input
            label="Email *"
            type="email"
            value={form.email}
            onChange={(e) => { setForm({ ...form, email: e.target.value }); setError(null); }}
            placeholder="agent@company.com"
          />
        </div>

        {/* Server overrides */}
        <div className="border-t border-surface-700 pt-4">
          <label className="text-sm text-surface-300 mb-2 block">Server Settings (optional overrides)</label>
          <div className="grid grid-cols-2 gap-3">
            <Input
              label="IMAP Server"
              value={form.imap_server || ''}
              onChange={(e) => setForm({ ...form, imap_server: e.target.value || undefined })}
              placeholder={form.provider === 'gmail' ? 'imap.gmail.com' : form.provider === 'outlook' ? 'outlook.office365.com' : 'mail.example.com'}
            />
            <Input
              label="IMAP Port"
              type="number"
              value={form.imap_port || ''}
              onChange={(e) => setForm({ ...form, imap_port: parseInt(e.target.value) || undefined })}
              placeholder="993"
            />
            <Input
              label="SMTP Server"
              value={form.smtp_server || ''}
              onChange={(e) => setForm({ ...form, smtp_server: e.target.value || undefined })}
              placeholder={form.provider === 'gmail' ? 'smtp.gmail.com' : form.provider === 'outlook' ? 'smtp.office365.com' : 'mail.example.com'}
            />
            <Input
              label="SMTP Port"
              type="number"
              value={form.smtp_port || ''}
              onChange={(e) => setForm({ ...form, smtp_port: parseInt(e.target.value) || undefined })}
              placeholder="587"
            />
          </div>
        </div>

        {/* Credentials */}
        <div className="border-t border-surface-700 pt-4">
          <label className="text-sm text-surface-300 flex items-center gap-2 mb-2">
            <Key className="w-4 h-4" />
            Credentials (environment variable names)
          </label>
          {form.provider === 'generic' ? (
            <Input
              label="Password Env Var"
              value={form.credential?.password_env || ''}
              onChange={(e) => setForm({ ...form, credential: { ...form.credential, password_env: e.target.value || undefined } })}
              placeholder="MAIL_PASSWORD"
            />
          ) : (
            <div className="space-y-3">
              <Input
                label="Client ID Env Var"
                value={form.credential?.client_id_env || ''}
                onChange={(e) => setForm({ ...form, credential: { ...form.credential, client_id_env: e.target.value || undefined } })}
                placeholder={form.provider === 'gmail' ? 'GMAIL_CLIENT_ID' : 'OUTLOOK_CLIENT_ID'}
              />
              <Input
                label="Client Secret Env Var"
                value={form.credential?.client_secret_env || ''}
                onChange={(e) => setForm({ ...form, credential: { ...form.credential, client_secret_env: e.target.value || undefined } })}
                placeholder={form.provider === 'gmail' ? 'GMAIL_CLIENT_SECRET' : 'OUTLOOK_CLIENT_SECRET'}
              />
              <Input
                label="Refresh Token Env Var"
                value={form.credential?.refresh_token_env || ''}
                onChange={(e) => setForm({ ...form, credential: { ...form.credential, refresh_token_env: e.target.value || undefined } })}
                placeholder={form.provider === 'gmail' ? 'GMAIL_REFRESH_TOKEN' : 'OUTLOOK_REFRESH_TOKEN'}
              />
            </div>
          )}
        </div>

        {/* Policy */}
        <div className="border-t border-surface-700 pt-4">
          <label className="text-sm text-surface-300 flex items-center gap-2 mb-2">
            <Shield className="w-4 h-4" />
            Policy
          </label>
          <div className="space-y-3">
            <div>
              <label className="block text-xs text-surface-500 mb-1">Allowed Recipients (one per line, supports *@domain.com)</label>
              <textarea
                value={form.policy?.allowed_recipients?.join('\n') || ''}
                onChange={(e) => setForm({
                  ...form,
                  policy: {
                    ...form.policy,
                    allowed_recipients: e.target.value ? e.target.value.split('\n').map(s => s.trim()).filter(Boolean) : undefined,
                  },
                })}
                rows={3}
                placeholder="*@company.com&#10;partner@external.com"
                className="w-full bg-surface-900 border border-surface-600 rounded-lg px-3 py-2 text-surface-100 text-sm font-mono focus:outline-none focus:border-blue-500"
              />
            </div>
            <div>
              <label className="block text-xs text-surface-500 mb-1">Allowed Senders (filter inbox, one per line)</label>
              <textarea
                value={form.policy?.allowed_senders?.join('\n') || ''}
                onChange={(e) => setForm({
                  ...form,
                  policy: {
                    ...form.policy,
                    allowed_senders: e.target.value ? e.target.value.split('\n').map(s => s.trim()).filter(Boolean) : undefined,
                  },
                })}
                rows={2}
                placeholder="*"
                className="w-full bg-surface-900 border border-surface-600 rounded-lg px-3 py-2 text-surface-100 text-sm font-mono focus:outline-none focus:border-blue-500"
              />
            </div>
            <div className="grid grid-cols-2 gap-3">
              <Input
                label="Sends per Hour"
                type="number"
                value={form.policy?.sends_per_hour || ''}
                onChange={(e) => setForm({
                  ...form,
                  policy: { ...form.policy, sends_per_hour: parseInt(e.target.value) || undefined },
                })}
                placeholder="50"
              />
              <Input
                label="Reads per Hour"
                type="number"
                value={form.policy?.reads_per_hour || ''}
                onChange={(e) => setForm({
                  ...form,
                  policy: { ...form.policy, reads_per_hour: parseInt(e.target.value) || undefined },
                })}
                placeholder="200"
              />
            </div>
          </div>
        </div>
      </div>

      <div className="flex justify-end gap-2 mt-4 pt-4 border-t border-surface-700">
        <Button variant="secondary" onClick={onClose}>Cancel</Button>
        <Button onClick={handleSave}>{account ? 'Update' : 'Add'} Account</Button>
      </div>
    </Modal>
  );
}

// Runtime Settings Editor
function SettingsEditor({
  config,
  onChange,
  isReadOnly,
}: {
  config: Config;
  onChange: (config: Config) => void;
  isReadOnly: boolean;
}) {
  return (
    <div className="space-y-6">
      {/* Security */}
      <div className="bg-gray-800 border border-gray-700 rounded-lg p-4">
        <h3 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
          <Shield className="w-5 h-5 text-green-400" />
          Security
        </h3>

        <div>
          <label className="block text-sm text-gray-400 mb-1">Seccomp Profile</label>
          <select
            value={config.security?.seccomp_profile || 'hardened'}
            onChange={(e) =>
              onChange({
                ...config,
                security: { ...config.security, seccomp_profile: e.target.value },
              })
            }
            className="w-full bg-gray-900 border border-gray-600 rounded px-3 py-2 text-white disabled:opacity-50"
            disabled={isReadOnly}
          >
            <option value="standard">Standard (default - blocks all, allows ~150)</option>
            <option value="hardened">Hardened (no mount, ptrace, unshare - production)</option>
            <option value="permissive">Permissive (allows all, blocks raw sockets - debug only)</option>
          </select>
          {config.security?.seccomp_profile === 'permissive' && (
            <p className="text-xs text-yellow-400 mt-2">
              Permissive mode reduces container security. Use only for temporary debugging.
            </p>
          )}
          <p className="text-xs text-gray-500 mt-1">
            Controls which syscalls the agent container can use. Changes take effect on next container recreation.
          </p>
        </div>
      </div>
    </div>
  );
}

export default function ConfigPage() {
  const queryClient = useQueryClient();
  const [searchParams, setSearchParams] = useSearchParams();
  const [activeTab, setActiveTab] = useState<Tab>('domains');
  const [rawContent, setRawContent] = useState('');
  const [config, setConfig] = useState<Config>({});
  const [hasChanges, setHasChanges] = useState(false);
  const [isReadOnly, setIsReadOnly] = useState(false);
  const [saveMessage, setSaveMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null);
  const [editingDomain, setEditingDomain] = useState<DomainEntry | null>(null);
  const [showDomainModal, setShowDomainModal] = useState(false);
  const [editingEmail, setEditingEmail] = useState<EmailAccount | null>(null);
  const [showEmailModal, setShowEmailModal] = useState(false);

  const { data: infoData } = useQuery({ queryKey: ['info'], queryFn: getInfo });
  const emailEnabled = infoData?.features?.includes('email');

  const { data, isLoading, error } = useQuery({
    queryKey: ['config'],
    queryFn: getConfig,
  });

  useEffect(() => {
    if (data) {
      setRawContent(data.raw);
      setConfig(data.config);
      setIsReadOnly(data.read_only);
      setHasChanges(false);
    }
  }, [data]);

  // Handle add-domain URL param from BlockedDomainsWidget
  useEffect(() => {
    const addDomain = searchParams.get('add-domain');
    if (addDomain && !isReadOnly) {
      setEditingDomain({ domain: addDomain });
      setShowDomainModal(true);
      setActiveTab('domains');
      searchParams.delete('add-domain');
      setSearchParams(searchParams, { replace: true });
    }
  }, [searchParams, isReadOnly, setSearchParams]);

  // Handle add-domains (plural) URL param from bulk allowlist
  useEffect(() => {
    const addDomains = searchParams.get('add-domains');
    if (addDomains && !isReadOnly && config.domains !== undefined) {
      const newDomains = addDomains.split(',').map(decodeURIComponent).filter(Boolean);
      const existingDomainNames = (config.domains || []).map((d) => d.domain);
      const toAdd = newDomains.filter((d) => !existingDomainNames.includes(d));
      if (toAdd.length > 0) {
        const entries = toAdd.map((domain) => ({ domain }));
        setConfig({
          ...config,
          domains: [...(config.domains || []), ...entries],
        });
        setHasChanges(true);
        setActiveTab('domains');
        setSaveMessage({
          type: 'success',
          text: `Added ${toAdd.length} domain${toAdd.length > 1 ? 's' : ''} to config. Click Save to persist.`,
        });
      }
      searchParams.delete('add-domains');
      setSearchParams(searchParams, { replace: true });
    }
  }, [searchParams, isReadOnly, config.domains, setSearchParams]);

  const saveMutation = useMutation({
    mutationFn: updateConfigRaw,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['config'] });
      setHasChanges(false);
      setSaveMessage({ type: 'success', text: 'Configuration saved' });
      setTimeout(() => setSaveMessage(null), 3000);
    },
    onError: (err) => {
      setSaveMessage({ type: 'error', text: (err as Error).message });
    },
  });

  const reloadMutation = useMutation({
    mutationFn: reloadConfig,
    onSuccess: (result) => {
      setSaveMessage({
        type: 'success',
        text: `Config reloaded: ${Object.entries(result.results)
          .map(([k, v]) => `${k}: ${v}`)
          .join(', ')}`,
      });
      setTimeout(() => setSaveMessage(null), 5000);
    },
    onError: (err) => {
      setSaveMessage({ type: 'error', text: (err as Error).message });
    },
  });

  // Convert config to YAML-like string for saving
  const configToYaml = (cfg: Config): string => {
    const lines: string[] = [
      '# Cagent Data Plane Configuration',
      '',
      `mode: ${cfg.mode || 'standalone'}`,
      '',
      'dns:',
      '  upstream:',
      ...(cfg.dns?.upstream || ['8.8.8.8', '8.8.4.4']).map((s) => `    - ${s}`),
      `  cache_ttl: ${cfg.dns?.cache_ttl || 300}`,
      '',
      'rate_limits:',
      '  default:',
      `    requests_per_minute: ${cfg.rate_limits?.default?.requests_per_minute || 120}`,
      `    burst_size: ${cfg.rate_limits?.default?.burst_size || 20}`,
      '',
      'security:',
      `  seccomp_profile: ${cfg.security?.seccomp_profile || 'hardened'}`,
      '',
      'domains:',
    ];

    for (const domain of cfg.domains || []) {
      lines.push(`  - domain: ${domain.domain}`);
      if (domain.alias) lines.push(`    alias: ${domain.alias}`);
      if (domain.timeout) lines.push(`    timeout: ${domain.timeout}`);
      if (domain.read_only) lines.push(`    read_only: true`);
      if (domain.rate_limit) {
        lines.push('    rate_limit:');
        lines.push(`      requests_per_minute: ${domain.rate_limit.requests_per_minute}`);
        lines.push(`      burst_size: ${domain.rate_limit.burst_size}`);
      }
      if (domain.credential) {
        lines.push('    credential:');
        lines.push(`      header: ${domain.credential.header}`);
        lines.push(`      format: "${domain.credential.format}"`);
        lines.push(`      env: ${domain.credential.env}`);
      }
    }

    if (cfg.email?.accounts?.length) {
      lines.push('');
      lines.push('email:');
      lines.push('  accounts:');
      for (const acct of cfg.email.accounts) {
        lines.push(`    - name: ${acct.name}`);
        lines.push(`      provider: ${acct.provider}`);
        lines.push(`      email: ${acct.email}`);
        if (acct.imap_server) lines.push(`      imap_server: ${acct.imap_server}`);
        if (acct.imap_port) lines.push(`      imap_port: ${acct.imap_port}`);
        if (acct.smtp_server) lines.push(`      smtp_server: ${acct.smtp_server}`);
        if (acct.smtp_port) lines.push(`      smtp_port: ${acct.smtp_port}`);
        if (acct.credential) {
          lines.push('      credential:');
          if (acct.credential.client_id_env) lines.push(`        client_id_env: ${acct.credential.client_id_env}`);
          if (acct.credential.client_secret_env) lines.push(`        client_secret_env: ${acct.credential.client_secret_env}`);
          if (acct.credential.refresh_token_env) lines.push(`        refresh_token_env: ${acct.credential.refresh_token_env}`);
          if (acct.credential.password_env) lines.push(`        password_env: ${acct.credential.password_env}`);
        }
        if (acct.policy) {
          lines.push('      policy:');
          if (acct.policy.allowed_recipients?.length) {
            lines.push('        allowed_recipients:');
            for (const r of acct.policy.allowed_recipients) lines.push(`          - "${r}"`);
          }
          if (acct.policy.allowed_senders?.length) {
            lines.push('        allowed_senders:');
            for (const s of acct.policy.allowed_senders) lines.push(`          - "${s}"`);
          }
          if (acct.policy.sends_per_hour) lines.push(`        sends_per_hour: ${acct.policy.sends_per_hour}`);
          if (acct.policy.reads_per_hour) lines.push(`        reads_per_hour: ${acct.policy.reads_per_hour}`);
        }
      }
    }

    if (cfg.internal_services?.length) {
      lines.push('');
      lines.push('internal_services:');
      for (const svc of cfg.internal_services) {
        lines.push(`  - ${svc}`);
      }
    }

    return lines.join('\n') + '\n';
  };

  const handleSave = () => {
    if (activeTab === 'raw') {
      saveMutation.mutate(rawContent);
    } else {
      const yaml = configToYaml(config);
      saveMutation.mutate(yaml);
    }
  };

  const handleAddDomain = (domain: DomainEntry) => {
    if (editingDomain && config.domains?.some((d) => d.domain === editingDomain.domain)) {
      // Update existing
      setConfig({
        ...config,
        domains: config.domains?.map((d) =>
          d.domain === editingDomain.domain ? domain : d
        ),
      });
    } else {
      // Add new
      setConfig({
        ...config,
        domains: [...(config.domains || []), domain],
      });
    }
    setHasChanges(true);
    setShowDomainModal(false);
    setEditingDomain(null);
  };

  const handleDeleteDomain = (domainName: string) => {
    if (!confirm(`Delete domain "${domainName}"?`)) return;
    setConfig({
      ...config,
      domains: config.domains?.filter((d) => d.domain !== domainName),
    });
    setHasChanges(true);
  };

  const handleSettingsChange = (newConfig: Config) => {
    setConfig(newConfig);
    setHasChanges(true);
  };

  const handleAddEmail = (account: EmailAccount) => {
    const accounts = config.email?.accounts || [];
    if (editingEmail) {
      setConfig({
        ...config,
        email: { accounts: accounts.map((a) => a.name === editingEmail.name ? account : a) },
      });
    } else {
      setConfig({
        ...config,
        email: { accounts: [...accounts, account] },
      });
    }
    setHasChanges(true);
    setShowEmailModal(false);
    setEditingEmail(null);
  };

  const handleDeleteEmail = (name: string) => {
    if (!confirm(`Delete email account "${name}"?`)) return;
    setConfig({
      ...config,
      email: { accounts: (config.email?.accounts || []).filter((a) => a.name !== name) },
    });
    setHasChanges(true);
  };

  const handleRawChange = (e: React.ChangeEvent<HTMLTextAreaElement>) => {
    setRawContent(e.target.value);
    setHasChanges(e.target.value !== data?.raw);
    setSaveMessage(null);
  };

  if (isLoading) {
    return <div className="text-gray-400">Loading configuration...</div>;
  }

  if (error) {
    return (
      <div className="bg-red-900/50 border border-red-700 text-red-300 p-4 rounded-lg">
        Error loading config: {(error as Error).message}
      </div>
    );
  }

  const tabs = [
    { id: 'domains' as Tab, label: 'Egress Policies', icon: Globe, count: config.domains?.length },
    ...(emailEnabled ? [{ id: 'email' as Tab, label: 'Email', icon: Mail, count: config.email?.accounts?.length, badge: 'Beta' }] : []),
    ...(!isReadOnly ? [{ id: 'settings' as Tab, label: 'Runtime Settings', icon: Shield }] : []),
    { id: 'raw' as Tab, label: 'Raw YAML', icon: Code },
  ];

  return (
    <div className="h-full flex flex-col">
      <div className="flex items-center justify-between mb-4">
        <div>
          <h1 className="text-2xl font-bold text-white">Configuration</h1>
          <p className="text-sm text-gray-400 mt-1">
            {data?.path} • Last modified:{' '}
            {data?.modified ? new Date(data.modified).toLocaleString() : 'unknown'}
          </p>
        </div>

        {!isReadOnly && (
          <div className="flex items-center gap-2">
            <button
              onClick={() => reloadMutation.mutate()}
              disabled={reloadMutation.isPending}
              className="flex items-center gap-2 px-4 py-2 bg-yellow-600 hover:bg-yellow-700 text-white rounded-lg disabled:opacity-50"
            >
              <RefreshCw className={`w-4 h-4 ${reloadMutation.isPending ? 'animate-spin' : ''}`} />
              Apply & Reload
            </button>
            <button
              onClick={handleSave}
              disabled={!hasChanges || saveMutation.isPending}
              className="flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg disabled:opacity-50"
            >
              <Save className="w-4 h-4" />
              Save
            </button>
          </div>
        )}
      </div>

      {/* Read-only banner */}
      {isReadOnly && (
        <div className="flex items-center gap-2 p-3 rounded-lg mb-4 bg-yellow-900/50 border border-yellow-700 text-yellow-300">
          <Lock className="w-4 h-4" />
          Configuration is managed by the control plane. Changes must be made in the control plane admin UI.
        </div>
      )}

      {saveMessage && (
        <div
          className={`flex items-center gap-2 p-3 rounded-lg mb-4 ${
            saveMessage.type === 'success'
              ? 'bg-green-900/50 border border-green-700 text-green-300'
              : 'bg-red-900/50 border border-red-700 text-red-300'
          }`}
        >
          {saveMessage.type === 'success' ? (
            <CheckCircle className="w-4 h-4" />
          ) : (
            <AlertCircle className="w-4 h-4" />
          )}
          {saveMessage.text}
        </div>
      )}

      {/* Tabs */}
      <div className="flex gap-1 mb-4 border-b border-gray-700">
        {tabs.map(({ id, label, icon: Icon, count, badge }) => (
          <button
            key={id}
            onClick={() => setActiveTab(id)}
            className={`flex items-center gap-2 px-4 py-2 border-b-2 transition-colors ${
              activeTab === id
                ? 'border-blue-500 text-white'
                : 'border-transparent text-gray-400 hover:text-gray-200'
            }`}
          >
            <Icon className="w-4 h-4" />
            {label}
            {badge && (
              <span className="text-[10px] font-medium bg-blue-600/20 text-blue-400 px-1.5 py-0.5 rounded">{badge}</span>
            )}
            {count !== undefined && (
              <span className="text-xs bg-gray-700 px-1.5 py-0.5 rounded">{count}</span>
            )}
          </button>
        ))}
      </div>

      {!isReadOnly && hasChanges && (
        <div className="mb-4 text-sm text-yellow-400 flex items-center gap-2">
          <AlertCircle className="w-4 h-4" />
          You have unsaved changes
        </div>
      )}

      {/* Tab Content */}
      <div className="flex-1 min-h-0 overflow-auto">
        {activeTab === 'domains' && (
          <div>
            <div className="flex justify-between items-center mb-4">
              <p className="text-gray-400 text-sm">
                Egress policies controlling agent access through the proxy
              </p>
              {!isReadOnly && (
                <button
                  onClick={() => {
                    setEditingDomain(null);
                    setShowDomainModal(true);
                  }}
                  className="flex items-center gap-2 px-3 py-2 bg-green-600 hover:bg-green-700 text-white rounded-lg text-sm"
                >
                  <Plus className="w-4 h-4" />
                  Add Policy
                </button>
              )}
            </div>

            <div className="bg-gray-800 border border-gray-700 rounded-lg overflow-hidden">
              <table className="w-full">
                <thead>
                  <tr className="border-b border-gray-700 text-left text-sm text-gray-400">
                    <th className="px-4 py-3">Domain</th>
                    <th className="px-4 py-3">Alias</th>
                    <th className="px-4 py-3">Options</th>
                    {!isReadOnly && <th className="px-4 py-3 w-24">Actions</th>}
                  </tr>
                </thead>
                <tbody>
                  {(config.domains || []).map((domain) => (
                    <tr
                      key={domain.domain}
                      className="border-b border-gray-700/50 hover:bg-gray-700/30"
                    >
                      <td className="px-4 py-3">
                        <span className="text-white font-mono text-sm">{domain.domain}</span>
                      </td>
                      <td className="px-4 py-3">
                        {domain.alias && (
                          <span className="text-blue-400 text-sm">
                            {domain.alias}.devbox.local
                          </span>
                        )}
                      </td>
                      <td className="px-4 py-3">
                        <div className="flex gap-2 flex-wrap">
                          {domain.read_only && (
                            <Badge variant="warning">
                              <span className="flex items-center gap-1">
                                <Shield className="w-3 h-3" />
                                Read-only
                              </span>
                            </Badge>
                          )}
                          {domain.timeout && (
                            <Badge>
                              <span className="flex items-center gap-1">
                                <Clock className="w-3 h-3" />
                                {domain.timeout}
                              </span>
                            </Badge>
                          )}
                          {domain.rate_limit && (
                            <Badge variant="info">
                              <span className="flex items-center gap-1">
                                <Gauge className="w-3 h-3" />
                                {domain.rate_limit.requests_per_minute}/min
                              </span>
                            </Badge>
                          )}
                          {domain.credential && (
                            <Badge variant="success">
                              <span className="flex items-center gap-1">
                                <Key className="w-3 h-3" />
                                {domain.credential.env}
                              </span>
                            </Badge>
                          )}
                        </div>
                      </td>
                      {!isReadOnly && (
                        <td className="px-4 py-3">
                          <div className="flex gap-1">
                            <button
                              onClick={() => {
                                setEditingDomain(domain);
                                setShowDomainModal(true);
                              }}
                              className="p-1.5 text-gray-400 hover:text-white hover:bg-gray-700 rounded"
                              title="Edit"
                            >
                              <Edit2 className="w-4 h-4" />
                            </button>
                            <button
                              onClick={() => handleDeleteDomain(domain.domain)}
                              className="p-1.5 text-gray-400 hover:text-red-400 hover:bg-gray-700 rounded"
                              title="Delete"
                            >
                              <Trash2 className="w-4 h-4" />
                            </button>
                          </div>
                        </td>
                      )}
                    </tr>
                  ))}
                  {(!config.domains || config.domains.length === 0) && (
                    <tr>
                      <td colSpan={isReadOnly ? 3 : 4} className="px-4 py-8 text-center text-gray-500">
                        No egress policies configured. {!isReadOnly && 'Click "Add Policy" to get started.'}
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {activeTab === 'email' && (
          <div>
            <div className="flex justify-between items-center mb-4">
              <p className="text-gray-400 text-sm">
                Email accounts the agent can use to send and read email (Beta)
              </p>
              {!isReadOnly && (
                <button
                  onClick={() => {
                    setEditingEmail(null);
                    setShowEmailModal(true);
                  }}
                  className="flex items-center gap-2 px-3 py-2 bg-green-600 hover:bg-green-700 text-white rounded-lg text-sm"
                >
                  <Plus className="w-4 h-4" />
                  Add Account
                </button>
              )}
            </div>

            <div className="bg-gray-800 border border-gray-700 rounded-lg overflow-hidden">
              <table className="w-full">
                <thead>
                  <tr className="border-b border-gray-700 text-left text-sm text-gray-400">
                    <th className="px-4 py-3">Account</th>
                    <th className="px-4 py-3">Provider</th>
                    <th className="px-4 py-3">Email</th>
                    <th className="px-4 py-3">Recipients</th>
                    <th className="px-4 py-3">Credential</th>
                    <th className="px-4 py-3">Policy</th>
                    {!isReadOnly && <th className="px-4 py-3 w-24">Actions</th>}
                  </tr>
                </thead>
                <tbody>
                  {(config.email?.accounts || []).map((account) => (
                    <tr
                      key={account.name}
                      className="border-b border-gray-700/50 hover:bg-gray-700/30"
                    >
                      <td className="px-4 py-3">
                        <span className="text-white font-mono text-sm">{account.name}</span>
                      </td>
                      <td className="px-4 py-3">
                        <span className={`text-xs px-2 py-0.5 rounded ${
                          account.provider === 'gmail' ? 'bg-red-900/50 text-red-400' :
                          account.provider === 'outlook' ? 'bg-blue-900/50 text-blue-400' :
                          'bg-gray-700 text-gray-300'
                        }`}>
                          {account.provider}
                        </span>
                      </td>
                      <td className="px-4 py-3">
                        <span className="text-gray-300 text-sm">{account.email}</span>
                      </td>
                      <td className="px-4 py-3">
                        {account.policy?.allowed_recipients?.length ? (
                          <Badge variant="warning">
                            {account.policy.allowed_recipients.length} recipients
                          </Badge>
                        ) : (
                          <span className="text-gray-500 text-sm">Any</span>
                        )}
                      </td>
                      <td className="px-4 py-3">
                        {account.credential ? (
                          <Badge variant="success">
                            {account.credential.password_env ? 'Password' : 'OAuth2'}
                          </Badge>
                        ) : (
                          <span className="text-gray-500 text-sm">None</span>
                        )}
                      </td>
                      <td className="px-4 py-3">
                        <div className="flex gap-2 flex-wrap">
                          {account.policy?.sends_per_hour && (
                            <Badge variant="info">
                              {account.policy.sends_per_hour} sends/hr
                            </Badge>
                          )}
                          {account.policy?.reads_per_hour && (
                            <Badge variant="success">
                              {account.policy.reads_per_hour} reads/hr
                            </Badge>
                          )}
                        </div>
                      </td>
                      {!isReadOnly && (
                        <td className="px-4 py-3">
                          <div className="flex gap-1">
                            <button
                              onClick={() => {
                                setEditingEmail(account);
                                setShowEmailModal(true);
                              }}
                              className="p-1.5 text-gray-400 hover:text-white hover:bg-gray-700 rounded"
                              title="Edit"
                            >
                              <Edit2 className="w-4 h-4" />
                            </button>
                            <button
                              onClick={() => handleDeleteEmail(account.name)}
                              className="p-1.5 text-gray-400 hover:text-red-400 hover:bg-gray-700 rounded"
                              title="Delete"
                            >
                              <Trash2 className="w-4 h-4" />
                            </button>
                          </div>
                        </td>
                      )}
                    </tr>
                  ))}
                  {(!config.email?.accounts || config.email.accounts.length === 0) && (
                    <tr>
                      <td colSpan={isReadOnly ? 6 : 7} className="px-4 py-8 text-center text-gray-500">
                        No email accounts configured. {!isReadOnly && 'Click "Add Account" to get started.'}
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {activeTab === 'settings' && !isReadOnly && (
          <SettingsEditor config={config} onChange={handleSettingsChange} isReadOnly={isReadOnly} />
        )}

        {activeTab === 'raw' && (
          <textarea
            value={rawContent}
            onChange={handleRawChange}
            readOnly={isReadOnly}
            className="yaml-editor w-full h-full min-h-[500px] bg-gray-800 border border-gray-700 rounded-lg p-4 text-gray-100 font-mono text-sm focus:outline-none focus:border-blue-500 resize-none disabled:opacity-50"
            spellCheck={false}
          />
        )}
      </div>

      {/* Domain Modal */}
      {showDomainModal && !isReadOnly && (
        <DomainModal
          domain={editingDomain}
          onSave={handleAddDomain}
          onClose={() => {
            setShowDomainModal(false);
            setEditingDomain(null);
          }}
          existingDomains={(config.domains || []).map((d) => d.domain)}
        />
      )}

      {/* Email Account Modal */}
      {showEmailModal && !isReadOnly && (
        <EmailAccountModal
          account={editingEmail}
          onSave={handleAddEmail}
          onClose={() => {
            setShowEmailModal(false);
            setEditingEmail(null);
          }}
          existingNames={(config.email?.accounts || []).map((a) => a.name)}
        />
      )}
    </div>
  );
}
