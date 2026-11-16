import { test, expect, type Page } from '@playwright/test';

const origin = 'http://127.0.0.1:5173';
const provider = 'https://identity.example.test';
const oidc = {
  mode: 'Oidc', enabled: true, issuer: provider + '/tenant/v2.0',
  clientId: 'comuni-platform-list-test',
  authorizationEndpoint: provider + '/oauth2/v2.0/authorize',
  tokenEndpoint: provider + '/oauth2/v2.0/token',
  scope: 'openid profile api://comuni-api/access_as_user'
};
const alpha = { id: '11111111-1111-1111-1111-111111111111', name: 'Comune Alfa',
  isSuspended: false, protocolEnabled: true, lifecycleStatus: 'active' };
const beta = { id: '22222222-2222-2222-2222-222222222222', name: 'Comune Beta',
  isSuspended: true, protocolEnabled: false, lifecycleStatus: 'suspended' };
const gamma = { id: '33333333-3333-3333-3333-333333333333', name: 'Comune Gamma',
  isSuspended: true, protocolEnabled: false, lifecycleStatus: 'created' };

async function login(page: Page, municipal = false,
  listStatus: () => number = () => 200) {
  const requests: string[] = [];
  await page.route('**/api/v1/auth/browser', route => route.fulfill({
    status: 200, contentType: 'application/json', body: JSON.stringify(oidc)
  }));
  await page.route('**/api/v1/context', route => route.fulfill({
    status: municipal ? 200 : 403, contentType: 'application/json',
    body: JSON.stringify(municipal ? {
      organizationId: alpha.id, organizationName: 'Comune Alfa',
      roles: ['Admin'], modules: ['protocol']
    } : { title: 'Forbidden' })
  }));
  await page.route('**/api/v1/platform/session', route => route.fulfill({
    status: municipal ? 403 : 200, contentType: 'application/json',
    body: JSON.stringify({ role: 'Superadmin' })
  }));
  await page.route('**/api/v1/platform/organizations?**', route => {
    requests.push(route.request().url());
    const status = listStatus();
    if (status !== 200) return route.fulfill({ status, body: '{}' });
    const cursor = new URL(route.request().url()).searchParams.get('after');
    const body = cursor
      ? { organizations: [beta, gamma], nextCursor: null }
      : { organizations: [alpha], nextCursor: alpha.id };
    return route.fulfill({ status: 200, contentType: 'application/json',
      body: JSON.stringify(body) });
  });
  await page.route(provider + '/oauth2/v2.0/authorize**', route => route.fulfill({
    status: 200, contentType: 'text/html',
    body: '<!doctype html><html><body>OIDC mock provider</body></html>'
  }));
  await page.goto('/');
  await page.getByRole('button', { name: 'Accedi con identità digitale' }).click();
  await page.waitForURL('**/oauth2/v2.0/authorize?**');
  const state = new URL(page.url()).searchParams.get('state')!;
  await page.route(provider + '/oauth2/v2.0/token', route => route.fulfill({
    status: 200, headers: {
      'Access-Control-Allow-Origin': origin,
      'Access-Control-Allow-Headers': 'content-type',
      'Content-Type': 'application/json'
    }, body: JSON.stringify({ access_token: 'in-memory-platform-test-token',
      token_type: 'Bearer', expires_in: 300 })
  }));
  await page.goto('/?code=inventory-mock-code&state=' + encodeURIComponent(state));
  return { requests };
}

test('Superadmin visualizza solamente metadata minimali con paginazione', async ({ page }) => {
  const trace = await login(page);
  await expect(page.getByRole('heading', { name: 'Comuni registrati' })).toBeVisible();
  const table = page.getByRole('table', { name: 'Comuni registrati' });
  await expect(table.getByText('Comune Alfa')).toBeVisible();
  await expect(table.getByText('Comune Beta')).toHaveCount(0);
  await expect(table.getByText(alpha.id)).toBeVisible();
  await expect(table.getByText('Attivo', { exact: true }).first()).toBeVisible();
  await expect(page.getByRole('button', { name: 'Carica altri Comuni' })).toBeVisible();
  await page.getByRole('button', { name: 'Carica altri Comuni' }).click();
  await expect(table.getByText('Comune Beta')).toBeVisible();
  await expect(table.getByText('Comune Gamma')).toBeVisible();
  await expect(table.getByText('Sospeso', { exact: true })).toBeVisible();
  await expect(table.getByText('Creato', { exact: true })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Carica altri Comuni' })).toHaveCount(0);
  expect(trace.requests).toHaveLength(2);
  expect(trace.requests[0]).toContain('limit=10');
  expect(trace.requests[1]).toContain('after=' + alpha.id);
  await expect(page.getByText('Membri del Comune')).toHaveCount(0);
  await expect(page.getByRole('button', { name: /Impersona|Modifica Comune|Disabilita/ })).toHaveCount(0);
});

test('Admin comunale o ruolo JWT inventato non richiedono inventario globale', async ({ page }) => {
  const trace = await login(page, true);
  await expect(page.locator('header').getByText('Comune Alfa')).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Comuni registrati' })).toHaveCount(0);
  expect(trace.requests).toHaveLength(0);
});

test('errore 503 mostra errore senza dati comunali e permette nuovo tentativo', async ({ page }) => {
  let status = 503;
  await login(page, false, () => status);
  await expect(page.getByRole('heading', { name: 'Comuni registrati' })).toBeVisible();
  await expect(page.getByRole('alert')).toBeVisible();
  await expect(page.getByRole('table', { name: 'Comuni registrati' })).toHaveCount(0);
  status = 200;
  await page.getByRole('button', { name: 'Riprova inventario' }).click();
  await expect(page.getByRole('table', { name: 'Comuni registrati' }).getByText('Comune Alfa')).toBeVisible();
});

test('revoca inventario 403 pulisce dati già visibili e sessione platform', async ({ page }) => {
  let status = 200;
  await login(page, false, () => status);
  await expect(page.getByRole('table', { name: 'Comuni registrati' }).getByText('Comune Alfa')).toBeVisible();
  status = 403;
  await page.getByRole('button', { name: 'Carica altri Comuni' }).click();
  await expect(page.getByRole('heading', { name: 'Comuni registrati' })).toHaveCount(0);
  await expect(page.getByRole('table')).toHaveCount(0);
  await expect(page.getByRole('navigation').getByRole('button', { name: 'Superadmin' })).toHaveCount(0);
});

test('lingua e tema della vista elenco restano quelli della PWA unica', async ({ page }) => {
  await login(page);
  await expect(page.getByRole('heading', { name: 'Comuni registrati' })).toBeVisible();
  await page.getByRole('button', { name: 'Lingua' }).click();
  await expect(page.getByRole('heading', { name: 'Registered municipalities' })).toBeVisible();
  await page.getByRole('button', { name: 'Load more municipalities' }).click();
  await expect(page.getByRole('table', { name: 'Registered municipalities' }).getByText('Created', { exact: true })).toBeVisible();
  await expect(page.getByRole('table', { name: 'Registered municipalities' }).getByText('Suspended', { exact: true })).toBeVisible();
  await page.getByRole('button', { name: 'Theme' }).click();
  await expect(page.locator('html')).toHaveClass(/dark/);
});

test('payload inventario incoerente non viene mostrato', async ({ page }) => {
  await login(page);
  await expect(page.getByRole('table', { name: 'Comuni registrati' }).getByText('Comune Alfa')).toBeVisible();
  await page.route('**/api/v1/platform/organizations?**', route => route.fulfill({
    status: 200, contentType: 'application/json',
    body: JSON.stringify({ organizations: [{ ...beta, lifecycleStatus: 'active' }], nextCursor: null })
  }));
  await page.getByRole('button', { name: 'Carica altri Comuni' }).click();
  await expect(page.getByRole('alert')).toBeVisible();
  await expect(page.getByRole('table', { name: 'Comuni registrati' })).toHaveCount(0);
});
