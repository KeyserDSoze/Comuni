import { test, expect, type Page } from '@playwright/test';

const origin = 'http://127.0.0.1:5173';
const provider = 'https://identity.example.test';
const config = {
  mode: 'Oidc', enabled: true, issuer: provider + '/tenant/v2.0',
  clientId: 'comuni-platform-ui-test',
  authorizationEndpoint: provider + '/oauth2/v2.0/authorize',
  tokenEndpoint: provider + '/oauth2/v2.0/token',
  scope: 'openid profile api://comuni-api/access_as_user'
};

type PlatformResponse = { status: number; payload?: unknown };
const municipal = {
  organizationId: '11111111-1111-1111-1111-111111111111',
  organizationName: 'Comune Riservato', roles: ['Admin'], modules: ['protocol']
};

async function loginOidc(
  page: Page, platform: () => PlatformResponse,
  contextStatus = 403, tokenValue = 'platform-only-test-access-token'
) {
  await page.route('**/api/v1/auth/browser', route => route.fulfill({
    status: 200, contentType: 'application/json', body: JSON.stringify(config)
  }));
  let platformCalls = 0;
  const authHeaders: string[] = [];
  await page.route('**/api/v1/platform/session', route => {
    platformCalls++;
    authHeaders.push(route.request().headers()['authorization'] ?? '');
    const response = platform();
    return route.fulfill({
      status: response.status, contentType: 'application/json',
      body: JSON.stringify(response.payload ?? { role: 'Superadmin' })
    });
  });
  await page.route('**/api/v1/context', route => route.fulfill({
    status: contextStatus, contentType: 'application/json',
    body: JSON.stringify(contextStatus === 200 ? municipal : { error: 'forbidden' })
  }));
  await page.route(provider + '/oauth2/v2.0/authorize**', route => route.fulfill({
    status: 200, contentType: 'text/html',
    body: '<!doctype html><html><body>OIDC mock provider</body></html>'
  }));
  await page.goto('/');
  await page.getByRole('button', { name: 'Accedi con identità digitale' }).click();
  await page.waitForURL('**/oauth2/v2.0/authorize?**');
  const state = new URL(page.url()).searchParams.get('state');
  expect(state).toBeTruthy();
  await page.route(provider + '/oauth2/v2.0/token', route => route.fulfill({
    status: 200,
    headers: {
      'Access-Control-Allow-Origin': origin,
      'Access-Control-Allow-Headers': 'content-type',
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      access_token: tokenValue, token_type: 'Bearer', expires_in: 300
    })
  }));
  await page.goto('/?code=platform-mocked-code&state=' + encodeURIComponent(state!));
  return { calls: () => platformCalls, authHeaders };
}

test('operatore OIDC platform vede esclusivamente una area Superadmin read-only e non il Comune', async ({ page }) => {
  const auth = await loginOidc(page, () => ({ status: 200 }), 403);
  await expect(page.getByRole('navigation').getByRole('button', { name: 'Superadmin' })).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Area Superadmin' })).toBeVisible();
  await expect(page.getByText('Solo consultazione del proprio accesso piattaforma.')).toBeVisible();
  await expect(page.getByText('Comune Riservato')).toHaveCount(0);
  await expect(page.getByText('Membri del Comune')).toHaveCount(0);
  await expect(page.getByRole('navigation').getByText('Protocollo')).toHaveCount(0);
  await expect(page.getByRole('navigation').getByText('Amministrazione')).toHaveCount(0);
  await expect(page.getByRole('button', { name: /Impersona|Disabilita Protocollo|Crea Comune/ })).toHaveCount(0);
  expect(auth.calls()).toBeGreaterThan(0);
  expect(auth.authHeaders).toContain('Bearer platform-only-test-access-token');
  await expect(page).not.toHaveURL(/access_token|platform-only-test-access-token/);

  await page.getByRole('button', { name: 'Lingua' }).click();
  await expect(page.getByRole('heading', { name: 'Superadmin area' })).toBeVisible();
  await page.getByRole('button', { name: 'Theme' }).click();
  await expect(page.locator('html')).toHaveClass(/dark/);
  await page.getByRole('navigation').getByRole('button', { name: 'Superadmin' }).click();
  await expect(page).toHaveURL(/\/platform$/);
});

test('Admin comunale non ottiene menu Superadmin nemmeno se il JWT dichiara quel ruolo', async ({ page }) => {
  await loginOidc(page, () => ({ status: 403 }), 200, 'role-superadmin-forged-in-token');
  await expect(page.locator('header').getByText('Comune Riservato')).toBeVisible();
  await expect(page.getByRole('navigation').getByRole('button', { name: 'Superadmin' })).toHaveCount(0);
  await expect(page.getByRole('heading', { name: 'Area Superadmin' })).toHaveCount(0);
  await expect(page.getByRole('navigation').getByText('Amministrazione')).toBeVisible();
});

test('OIDC non autorizzato e payload inatteso 200 non aprono la console', async ({ page }) => {
  let reply: PlatformResponse = { status: 403 };
  await loginOidc(page, () => reply);
  await expect(page.getByRole('heading', { name: 'Area Superadmin' })).toHaveCount(0);
  await expect(page.getByRole('navigation').getByRole('button', { name: 'Superadmin' })).toHaveCount(0);
  // A 200 body with fabricated tenant fields cannot be treated as valid session.
  reply = { status: 200, payload: { role: 'Superadmin', organizations: ['private-tenant'] } };
  await page.reload();
  await expect(page.getByRole('heading', { name: 'Area Superadmin' })).toHaveCount(0);
});

test('revoca 403 durante la sessione nasconde subito la console su focus', async ({ page }) => {
  let allowed = true;
  const auth = await loginOidc(page, () => ({ status: allowed ? 200 : 403 }));
  await expect(page.getByRole('heading', { name: 'Area Superadmin' })).toBeVisible();
  const previous = auth.calls();
  allowed = false;
  await page.evaluate(() => window.dispatchEvent(new Event('focus')));
  await expect.poll(() => auth.calls()).toBeGreaterThan(previous);
  await expect(page.getByRole('heading', { name: 'Area Superadmin' })).toHaveCount(0);
  await expect(page.getByRole('navigation').getByRole('button', { name: 'Superadmin' })).toHaveCount(0);
});

test('logout e reload cancellano il contesto platform: token solo nella memoria', async ({ page }) => {
  await loginOidc(page, () => ({ status: 200 }));
  await expect(page.getByRole('heading', { name: 'Area Superadmin' })).toBeVisible();
  const persisted = await page.evaluate(() => ({
    local: JSON.stringify(localStorage), session: JSON.stringify(sessionStorage)
  }));
  expect(persisted.local).not.toContain('platform-only-test-access-token');
  expect(persisted.session).not.toContain('platform-only-test-access-token');
  await page.getByRole('button', { name: 'Esci' }).click();
  await expect(page.getByRole('heading', { name: 'Area Superadmin' })).toHaveCount(0);
  await page.reload();
  await expect(page.getByRole('heading', { name: 'Area Superadmin' })).toHaveCount(0);
});

test('deep link /platform senza autenticazione e token demo non bypassano il server', async ({ page }) => {
  let platformCalls = 0;
  await page.route('**/api/v1/auth/browser', route => route.fulfill({
    status: 200, contentType: 'application/json',
    body: JSON.stringify({ mode: 'DevelopmentJwt', enabled: false })
  }));
  await page.route('**/api/v1/context', route => route.fulfill({
    status: 403, contentType: 'application/json', body: '{}'
  }));
  await page.route('**/api/v1/platform/session', route => {
    platformCalls++;
    return route.fulfill({ status: 200, contentType: 'application/json', body: '{"role":"Superadmin"}' });
  });
  await page.goto('/platform');
  await expect(page.getByRole('heading', { name: 'Area Superadmin' })).toHaveCount(0);
  await page.getByLabel('Token JWT di sviluppo').fill('pretend-superadmin-token');
  await page.getByRole('button', { name: 'Usa token' }).click();
  await expect(page.getByRole('heading', { name: 'Area Superadmin' })).toHaveCount(0);
  expect(platformCalls).toBe(0);
});
