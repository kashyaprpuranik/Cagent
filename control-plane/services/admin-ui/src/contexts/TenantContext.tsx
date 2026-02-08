import { createContext, useContext, useState, useEffect, ReactNode } from 'react';
import { useAuth } from './AuthContext';
import { useTenants } from '../hooks/useApi';
import type { Tenant } from '../types/api';

interface TenantContextType {
  /** Currently selected tenant (null if not yet loaded) */
  selectedTenant: Tenant | null;
  /** Currently selected tenant ID (null if not yet loaded) */
  selectedTenantId: number | null;
  /** All available tenants (only populated for super admins) */
  tenants: Tenant[];
  /** Whether tenants are still loading */
  loading: boolean;
  /** Whether the current user can switch tenants (super admin only) */
  canSwitch: boolean;
  /** Change the selected tenant (super admin only) */
  setSelectedTenantId: (id: number) => void;
}

const TenantContext = createContext<TenantContextType | undefined>(undefined);

export function TenantProvider({ children }: { children: ReactNode }) {
  const { user, loading: authLoading } = useAuth();
  const [selectedTenantId, setSelectedTenantId] = useState<number | null>(null);

  // Only fetch tenants list for super admins
  const { data: tenants = [], isLoading: tenantsLoading } = useTenants(
    user?.is_super_admin === true
  );

  // Determine if user can switch tenants
  const canSwitch = user?.is_super_admin === true;

  // Auto-select tenant based on user type
  useEffect(() => {
    if (authLoading) return;

    if (user?.is_super_admin) {
      // Super admin: select first tenant when list loads (if none selected)
      if (tenants.length > 0 && selectedTenantId === null) {
        setSelectedTenantId(tenants[0].id);
      }
    } else if (user?.tenant_id) {
      // Regular user: use their assigned tenant
      setSelectedTenantId(user.tenant_id);
    }
  }, [user, tenants, selectedTenantId, authLoading]);

  // Find the full tenant object for the selected ID
  const selectedTenant = tenants.find((t) => t.id === selectedTenantId) || null;

  // For non-super-admins, create a placeholder tenant object using info from auth
  const effectiveSelectedTenant: Tenant | null =
    selectedTenant ||
    (user?.tenant_id && !user.is_super_admin
      ? {
          id: user.tenant_id,
          name: user.tenant_name || 'Unknown',
          slug: user.tenant_slug || '',
          created_at: '',
          agent_count: 0,
        }
      : null);

  const loading = authLoading || (user?.is_super_admin === true && tenantsLoading);

  return (
    <TenantContext.Provider
      value={{
        selectedTenant: effectiveSelectedTenant,
        selectedTenantId,
        tenants,
        loading,
        canSwitch,
        setSelectedTenantId,
      }}
    >
      {children}
    </TenantContext.Provider>
  );
}

export function useTenant() {
  const context = useContext(TenantContext);
  if (context === undefined) {
    throw new Error('useTenant must be used within a TenantProvider');
  }
  return context;
}
