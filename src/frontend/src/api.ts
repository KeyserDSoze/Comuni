export interface OrganizationContext {
  organizationId: string;
  organizationName: string;
  roles: string[];
  modules: string[];
}

export interface AdminModule {
  key: string;
  enabled: boolean;
}

export interface ProtocolRecord {
  id: string;
  subject: string;
  registeredAt: string;
}

async function request<T>(path: string, token: string, options?: RequestInit): Promise<T> {
  const response = await fetch(path, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${token}`,
      ...options?.headers,
    },
  });
  if (!response.ok) throw new Error(`API ${response.status}`);
  return (await response.json()) as T;
}

export const getContext = (token: string) => request<OrganizationContext>('/api/v1/context', token);
export const getRecords = (token: string) => request<ProtocolRecord[]>('/api/v1/protocol/records', token);
export const registerRecord = (token: string, subject: string) =>
  request<ProtocolRecord>('/api/v1/protocol/records', token, {
    method: 'POST', body: JSON.stringify({ subject }),
  });

export const getAdminModules = (token: string) =>
  request<AdminModule[]>('/api/v1/admin/modules', token);

export const setAdminModule = (token: string, key: string, enabled: boolean) =>
  request<AdminModule>(`/api/v1/admin/modules/${encodeURIComponent(key)}`, token, {
    method: 'PUT', body: JSON.stringify({ enabled }),
  });

export interface AdminMembership {
  subject: string;
  role: 'Admin' | 'Reader' | 'Officer';
  enabled: boolean;
  issuer?: string | null;
}

export const getAdminMemberships = (token: string) =>
  request<AdminMembership[]>('/api/v1/admin/memberships', token);

export const setAdminMembership = (
  token: string, role: 'Reader' | 'Officer', subject: string, enabled: boolean
) => request<AdminMembership>(`/api/v1/admin/memberships/${role}`, token, {
  method: 'PUT', body: JSON.stringify({ subject, enabled })
});


/** A platform OIDC session has no tenant context or operator roster details.
 * Never infer this privilege from a decoded JWT role or from municipal context.
 */
export interface PlatformSession { role: 'Superadmin' }

export async function getPlatformSession(token: string): Promise<PlatformSession> {
  const response = await fetch('/api/v1/platform/session', {
    method: 'GET', credentials: 'omit', cache: 'no-store', redirect: 'error',
    headers: { Accept: 'application/json', Authorization: `Bearer ${token}` }
  });
  if (!response.ok) throw new Error(`Platform API ${response.status}`);
  const result: unknown = await response.json();
  if (!result || typeof result !== 'object' || Array.isArray(result) ||
      Object.keys(result).length !== 1 ||
      !('role' in result) || result.role !== 'Superadmin') {
    throw new Error('Invalid platform session response');
  }
  return { role: 'Superadmin' };
}
