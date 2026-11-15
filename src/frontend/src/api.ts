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
