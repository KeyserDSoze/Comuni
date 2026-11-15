import { test, expect } from '@playwright/test';
import { createHash } from 'node:crypto';

const org = '11111111-1111-1111-1111-111111111111';
const origin = 'http://127.0.0.1:5173';
const provider = 'https://identity.example.test';
const oidc = {
  mode: 'Oidc', enabled: true,
  issuer: provider + '/tenant/v2.0',
  clientId: 'comuni-spa-test',
  authorizationEndpoint: provider + '/oauth2/v2.0/authorize',
  tokenEndpoint: provider + '/oauth2/v2.0/token',
  scope: 'openid profile api://comuni-api/access_as_user'
};

async function setup(page: import('@playwright/test').Page, config: object = oidc) {
  await page.route('**/api/v1/auth/browser', route => route.fulfill({
    status: 200, contentType: 'application/json', body: JSON.stringify(config)
  }));
  await page.route('**/api/v1/context', route => route.fulfill({
    status: 200, contentType: 'application/json',
    body: JSON.stringify({ organizationId: org, organizationName: 'Comune Aurora',
      roles: ['Reader'], modules: ['protocol'] })
  }));
  await page.route(provider + '/oauth2/v2.0/authorize**', route => route.fulfill({
    status: 200, contentType: 'text/html', body: '<!doctype html><html><body>Identity provider mock</body></html>'
  }));
  await page.goto('/');
}

test('OIDC login usa authorization code PKCE S256 con state e il solo access token per API', async ({ page }) => {
  await setup(page);
  await expect(page.getByLabel('Token JWT di sviluppo')).toHaveCount(0);
  const button = page.getByRole('button', { name: 'Accedi con identità digitale' });
  await expect(button).toBeVisible();
  await button.click();
  await page.waitForURL('**/oauth2/v2.0/authorize?**');
  const url = new URL(page.url());
  expect(url.searchParams.get('response_type')).toBe('code');
  expect(url.searchParams.get('code_challenge_method')).toBe('S256');
  expect(url.searchParams.get('redirect_uri')).toBe(origin + '/');
  expect(url.searchParams.get('client_id')).toBe('comuni-spa-test');
  const state = url.searchParams.get('state')!;
  const challenge = url.searchParams.get('code_challenge')!;
  expect(state.length).toBeGreaterThanOrEqual(40);
  expect(challenge.length).toBeGreaterThanOrEqual(40);
  let body: URLSearchParams | null = null;
  let apiAuthorization: string | null = null;
  await page.route('**/api/v1/context', route => {
    apiAuthorization = route.request().headers()['authorization'] ?? null;
    return route.fulfill({
      status: 200, contentType: 'application/json',
      body: JSON.stringify({ organizationId: org, organizationName: 'Comune Aurora',
        roles: ['Reader'], modules: ['protocol'] })
    });
  });
  await page.route(provider + '/oauth2/v2.0/token', route => {
    body = new URLSearchParams(route.request().postData() || '');
    return route.fulfill({
      status: 200,
      headers: { 'Access-Control-Allow-Origin': origin,
                 'Access-Control-Allow-Headers': 'content-type',
                 'Content-Type': 'application/json' },
      body: JSON.stringify({ access_token: 'access-for-api', token_type: 'Bearer', expires_in: 300,
                             id_token: 'not-an-api-access-token', refresh_token: 'discarded' })
    });
  });
  await page.goto('/?code=mock-authorization-code&state=' + encodeURIComponent(state));
  await expect(page.locator('header').getByText('Comune Aurora')).toBeVisible();
  expect(apiAuthorization).toBe('Bearer access-for-api');
  expect(body).not.toBeNull();
  const exchanged = body!;
  expect(exchanged.get('grant_type')).toBe('authorization_code');
  expect(exchanged.get('code')).toBe('mock-authorization-code');
  const verifier = exchanged.get('code_verifier')!;
  expect(createHash('sha256').update(verifier).digest('base64url')).toBe(challenge);
  expect(exchanged.has('client_secret')).toBe(false);
  expect(page.url()).toBe(origin + '/');
  const requests = await page.evaluate(() => Object.keys(sessionStorage));
  expect(requests).toHaveLength(0);
  await page.getByRole('button', { name: 'Esci' }).click();
  await expect(page.locator('header').getByText('Comune Aurora')).toHaveCount(0);
  await page.reload();
  await expect(page.locator('header').getByText('Comune Aurora')).toHaveCount(0);
});

test('callback state manomesso è rifiutato senza invocare token endpoint', async ({ page }) => {
  await setup(page);
  await page.getByRole('button', { name: 'Accedi con identità digitale' }).click();
  await page.waitForURL('**/oauth2/v2.0/authorize?**');
  let exchanges = 0;
  await page.route(provider + '/oauth2/v2.0/token', route => {
    exchanges += 1;
    return route.fulfill({ status: 500 });
  });
  await page.goto('/?code=bad-code&state=forged-state');
  await expect(page.getByRole('alert')).toBeVisible();
  expect(exchanges).toBe(0);
  expect(page.url()).toBe(origin + '/');
  await page.reload();
  await expect(page.getByRole('button', { name: 'Accedi con identità digitale' })).toBeVisible();
});

test('un ID token senza API access token è rifiutato, senza aprire la dashboard', async ({ page }) => {
  await setup(page);
  await page.getByRole('button', { name: 'Accedi con identità digitale' }).click();
  await page.waitForURL('**/oauth2/v2.0/authorize?**');
  const state = new URL(page.url()).searchParams.get('state')!;
  await page.route(provider + '/oauth2/v2.0/token', route => route.fulfill({
    status: 200,
    headers: { 'Access-Control-Allow-Origin': origin,
      'Access-Control-Allow-Headers': 'content-type',
      'Content-Type': 'application/json' },
    body: JSON.stringify({ id_token: 'id-is-not-api-access', token_type: 'Bearer', expires_in: 300 })
  }));
  await page.goto('/?code=mock-authorization-code&state=' + encodeURIComponent(state));
  await expect(page.getByRole('alert')).toBeVisible();
  await expect(page.locator('header').getByText('Comune Aurora')).toHaveCount(0);
  expect(page.url()).toBe(origin + '/');
});

test('quando OIDC non è configurato la pagina non permette di incollare token', async ({ page }) => {
  await setup(page, { mode: 'Oidc', enabled: false });
  await expect(page.getByLabel('Token JWT di sviluppo')).toHaveCount(0);
  await expect(page.getByRole('button', { name: 'Accedi con identità digitale' })).toHaveCount(0);
  await expect(page.getByText('Accesso OIDC non configurato')).toBeVisible();
});
