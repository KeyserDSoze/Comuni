/** Browser OIDC client for ONE configured public provider.
 * Access tokens are held by App state only. Session storage holds ONLY a short-lived
 * PKCE verifier / CSRF state across the full-page authorization redirect.
 */
export interface BrowserOidcConfig {
  mode: 'Oidc' | 'DevelopmentJwt';
  enabled: boolean;
  issuer: string | null;
  clientId: string | null;
  authorizationEndpoint: string | null;
  tokenEndpoint: string | null;
  scope: string | null;
}

export interface OidcAccessToken { accessToken: string; expiresAt: number }
export interface OidcCallback {
  code: string | null;
  state: string | null;
  error: string | null;
  issuer: string | null;
  malformed: boolean;
}

const pendingKey = 'comuni:oidc:pending';
const maxPendingMs = 5 * 60 * 1000;

interface PendingAuthorization {
  state: string;
  verifier: string;
  redirectUri: string;
  created: number;
}

export async function loadBrowserOidc(): Promise<BrowserOidcConfig> {
  const response = await fetch('/api/v1/auth/browser', {
    credentials: 'same-origin', cache: 'no-store', redirect: 'error',
    headers: { Accept: 'application/json' }
  });
  if (!response.ok) throw new Error('Browser OIDC configuration unavailable');
  const config = (await response.json()) as BrowserOidcConfig;
  if (config.mode !== 'Oidc' && config.mode !== 'DevelopmentJwt') {
    throw new Error('Invalid browser auth mode');
  }
  if (config.mode !== 'Oidc' && config.enabled) throw new Error('Demo mode cannot advertise OIDC');
  if (config.enabled) validateOidcConfig(config);
  return config;
}

function validateOidcConfig(config: BrowserOidcConfig): asserts config is BrowserOidcConfig & {
  issuer: string; clientId: string; authorizationEndpoint: string; tokenEndpoint: string; scope: string;
} {
  if (config.mode !== 'Oidc' || !config.issuer || !config.clientId ||
      !config.authorizationEndpoint || !config.tokenEndpoint || !config.scope) {
    throw new Error('Incomplete public OIDC configuration');
  }
  const issuer = new URL(config.issuer);
  const authorize = new URL(config.authorizationEndpoint);
  const token = new URL(config.tokenEndpoint);
  if (issuer.protocol !== 'https:' || authorize.protocol !== 'https:' ||
      token.protocol !== 'https:' || authorize.origin !== issuer.origin ||
      token.origin !== issuer.origin || authorize.username || token.username ||
      authorize.password || token.password || authorize.search || token.search ||
      authorize.hash || token.hash || !config.scope.split(' ').includes('openid')) {
    throw new Error('Unsafe public OIDC configuration');
  }
}

function redirectUri(): string {
  if (window.location.protocol !== 'https:' &&
      !['localhost', '127.0.0.1'].includes(window.location.hostname)) {
    throw new Error('PKCE requires HTTPS or local development');
  }
  return window.location.origin + '/';
}

function randomUrlSafe(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  return base64url(bytes);
}

function base64url(bytes: Uint8Array): string {
  return btoa(Array.from(bytes, byte => String.fromCharCode(byte)).join(''))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function pendingFromSession(): PendingAuthorization | null {
  const stored = sessionStorage.getItem(pendingKey);
  if (!stored) return null;
  try {
    const value = JSON.parse(stored) as PendingAuthorization;
    if (typeof value.state !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(value.state) ||
        typeof value.verifier !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(value.verifier) ||
        typeof value.redirectUri !== 'string' || !Number.isFinite(value.created)) {
      return null;
    }
    return value;
  } catch { return null; }
}

export function clearPendingOidc(): void {
  sessionStorage.removeItem(pendingKey);
}

export async function beginOidcLogin(config: BrowserOidcConfig): Promise<void> {
  validateOidcConfig(config);
  const verifier = randomUrlSafe();
  const state = randomUrlSafe();
  const redirect = redirectUri();
  const challenge = base64url(new Uint8Array(await crypto.subtle.digest('SHA-256',
    new TextEncoder().encode(verifier))));
  const pending: PendingAuthorization = { state, verifier, redirectUri: redirect, created: Date.now() };
  sessionStorage.setItem(pendingKey, JSON.stringify(pending));
  const authorize = new URL(config.authorizationEndpoint);
  authorize.searchParams.set('client_id', config.clientId);
  authorize.searchParams.set('redirect_uri', redirect);
  authorize.searchParams.set('response_type', 'code');
  authorize.searchParams.set('scope', config.scope);
  authorize.searchParams.set('state', state);
  authorize.searchParams.set('code_challenge', challenge);
  authorize.searchParams.set('code_challenge_method', 'S256');
  window.location.assign(authorize.toString());
}

/** Scrub the authorization response from the browser URL before network requests. */
export function captureOidcCallback(): OidcCallback | null {
  const params = new URLSearchParams(window.location.search);
  if (!['code', 'state', 'error'].some(key => params.has(key))) return null;
  const result: OidcCallback = {
    code: params.get('code'), state: params.get('state'),
    error: params.get('error'), issuer: params.get('iss'),
    malformed: ['code', 'state', 'error', 'iss'].some(key => params.getAll(key).length > 1)
  };
  window.history.replaceState(window.history.state, '', window.location.pathname);
  return result;
}

export async function completeOidcLogin(
  config: BrowserOidcConfig, callback: OidcCallback | null
): Promise<OidcAccessToken | null> {
  if (!callback) return null;
  const pending = pendingFromSession();
  // State and verifier are single-use even when exchange fails or a forged redirect arrives.
  clearPendingOidc();
  validateOidcConfig(config);
  if (callback.malformed || callback.error || !callback.code || !callback.state ||
      !/^[\w.~-]{1,2048}$/.test(callback.code) ||
      !pending || pending.state !== callback.state ||
      pending.redirectUri !== redirectUri() ||
      pending.created > Date.now() || Date.now() - pending.created > maxPendingMs ||
      (callback.issuer !== null && callback.issuer !== config.issuer)) {
    throw new Error('Invalid authorization response or expired PKCE state');
  }
  const form = new URLSearchParams({
    grant_type: 'authorization_code',
    code: callback.code,
    client_id: config.clientId,
    redirect_uri: pending.redirectUri,
    code_verifier: pending.verifier
  });
  const response = await fetch(config.tokenEndpoint, {
    method: 'POST', body: form,
    mode: 'cors', credentials: 'omit', redirect: 'error', cache: 'no-store',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' }
  });
  if (!response.ok) throw new Error('Authorization code exchange failed');
  const result = (await response.json()) as {
    token_type?: unknown; access_token?: unknown; expires_in?: unknown;
  };
  if (result.token_type !== 'Bearer' || typeof result.access_token !== 'string' ||
      !result.access_token || result.access_token.length > 16384 ||
      /\s/.test(result.access_token) || typeof result.expires_in !== 'number' ||
      !Number.isFinite(result.expires_in) || result.expires_in < 30 ||
      result.expires_in > 86400) {
    throw new Error('Invalid API access token response');
  }
  // Deliberately ignore id_token/refresh_token and never persist access tokens in storage.
  return { accessToken: result.access_token, expiresAt: Date.now() + result.expires_in * 1000 };
}
