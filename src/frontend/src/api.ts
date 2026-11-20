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

/** Code-owned municipal service catalog; planned modules are never writable. */
export interface AdminModuleCatalogItem {
  key: string;
  name: string;
  status: 'available' | 'planned';
  enabled: boolean;
  configurable: boolean;
  dependsOn: string[];
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

export const getAdminModuleCatalog = (token: string) =>
  request<AdminModuleCatalogItem[]>('/api/v1/admin/modules/catalog', token);

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


/** Metadata-only platform inventory. Never uses or accepts organization context. */
export interface PlatformOrganization {
  id: string;
  name: string;
  isSuspended: boolean;
  protocolEnabled: boolean;
  lifecycleStatus: 'created' | 'active' | 'suspended';
}

export interface PlatformOrganizationsPage {
  organizations: PlatformOrganization[];
  nextCursor: string | null;
}

export class PlatformInventoryHttpError extends Error {
  constructor(readonly status: number) {
    super('Platform inventory API ' + status);
  }
}

const guidD = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export async function getPlatformOrganizations(
  token: string, after?: string, limit = 10
): Promise<PlatformOrganizationsPage> {
  if (!Number.isInteger(limit) || limit < 1 || limit > 25 ||
      (after !== undefined && !guidD.test(after))) {
    throw new Error('Invalid inventory pagination');
  }
  const url = '/api/v1/platform/organizations?limit=' + limit +
    (after === undefined ? '' : '&after=' + encodeURIComponent(after));
  const response = await fetch(url, {
    method: 'GET', credentials: 'omit', cache: 'no-store', redirect: 'error',
    headers: { Accept: 'application/json', Authorization: `Bearer ${token}` }
  });
  if (!response.ok) throw new PlatformInventoryHttpError(response.status);
  const result: unknown = await response.json();
  if (typeof result !== 'object' || result === null || Array.isArray(result) ||
      Object.keys(result).length !== 2 ||
      !('organizations' in result) || !Array.isArray(result.organizations) ||
      result.organizations.length > limit ||
      !('nextCursor' in result) ||
      !(result.nextCursor === null ||
        (typeof result.nextCursor === 'string' && guidD.test(result.nextCursor)))) {
    throw new Error('Invalid platform inventory response');
  }
  const items: PlatformOrganization[] = [];
  for (const item of result.organizations) {
    if (typeof item !== 'object' || item === null || Array.isArray(item) ||
        Object.keys(item).length !== 5 ||
        !('id' in item) || typeof item.id !== 'string' || !guidD.test(item.id) ||
        !('name' in item) || typeof item.name !== 'string' ||
        item.name.length < 1 || item.name.length > 200 ||
        !('isSuspended' in item) || typeof item.isSuspended !== 'boolean' ||
        !('protocolEnabled' in item) || typeof item.protocolEnabled !== 'boolean' ||
        !('lifecycleStatus' in item) ||
        !(item.lifecycleStatus === 'created' || item.lifecycleStatus === 'active' ||
          item.lifecycleStatus === 'suspended') ||
        item.isSuspended !== (item.lifecycleStatus !== 'active')) {
      throw new Error('Invalid municipality metadata');
    }
    items.push({ id: item.id, name: item.name,
      isSuspended: item.isSuspended, protocolEnabled: item.protocolEnabled,
      lifecycleStatus: item.lifecycleStatus });
  }
  return { organizations: items, nextCursor: result.nextCursor };
}


/** Strictly minimised and bounded municipal audit. No actor, tenant selector,
 * resource ID, correlation ID or unbounded paging is exposed to the browser.
 * Authorization comes exclusively from server-side Admin membership + RLS.
 */
export interface MunicipalAuditEntry {
  id: string;
  action: string;
  resourceType: string;
  occurredAt: string;
}

export async function getMunicipalAudit(token: string): Promise<MunicipalAuditEntry[]> {
  const response = await fetch('/api/v1/admin/audit', {
    method: 'GET', credentials: 'omit', cache: 'no-store', redirect: 'error',
    headers: { Accept: 'application/json', Authorization: `Bearer ${token}` }
  });
  if (!response.ok) throw new Error('Municipal audit denied');
  const raw: unknown = await response.json();
  if (!Array.isArray(raw) || raw.length > 25) throw new Error('Invalid audit response');
  const items: MunicipalAuditEntry[] = [];
  for (const row of raw) {
    if (!row || typeof row !== 'object' || Array.isArray(row) ||
        Object.keys(row).length !== 4 ||
        !('id' in row) || typeof row.id !== 'string' || !guidD.test(row.id) ||
        !('action' in row) || typeof row.action !== 'string' ||
        row.action.length === 0 || row.action.length > 120 ||
        !('resourceType' in row) || typeof row.resourceType !== 'string' ||
        row.resourceType.length === 0 || row.resourceType.length > 100 ||
        !('occurredAt' in row) || typeof row.occurredAt !== 'string' ||
        !Number.isFinite(Date.parse(row.occurredAt))) {
      throw new Error('Invalid municipal audit metadata');
    }
    items.push({
      id: row.id, action: row.action,
      resourceType: row.resourceType, occurredAt: row.occurredAt
    });
  }
  return items;
}
