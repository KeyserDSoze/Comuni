import { test, expect, type Page } from '@playwright/test';

const org = '11111111-1111-1111-1111-111111111111';
const events = [
  { id: 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb',
    action: 'platform.module.protocol.disabled', resourceType: 'platform.module',
    occurredAt: '2026-11-16T10:00:00Z' },
  { id: 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',
    action: 'platform.membership.reader.activated', resourceType: 'platform.membership',
    occurredAt: '2026-11-16T09:00:00Z' }
];
async function open(page: Page, role: 'Admin' | 'Reader' = 'Admin') {
  let status = 200;
  let hits = 0;
  await page.route('**/api/v1/auth/browser', route => route.fulfill({
    status: 200, contentType: 'application/json',
    body: JSON.stringify({ mode: 'DevelopmentJwt', enabled: false })
  }));
  await page.route('**/api/v1/context', route => route.fulfill({
    status: 200, contentType: 'application/json',
    body: JSON.stringify({
      organizationId: org, organizationName: 'Comune Audit', roles: [role],
      modules: ['protocol']
    })
  }));
  await page.route('**/api/v1/admin/modules', route => route.fulfill({
    status: 200, contentType: 'application/json',
    body: JSON.stringify([{ key: 'protocol', enabled: true }])
  }));
  await page.route('**/api/v1/admin/memberships', route => route.fulfill({
    status: 200, contentType: 'application/json', body: '[]'
  }));
  await page.route('**/api/v1/admin/audit', route => {
    hits++;
    return route.fulfill({
      status, contentType: 'application/json', body: JSON.stringify(status === 200 ? events : { error: 'denied' })
    });
  });
  await page.goto('/');
  await page.getByLabel('Token JWT di sviluppo').fill('synthetic-test-token');
  await page.getByRole('button', { name: 'Usa token' }).click();
  await expect(page.locator('header').getByText('Comune Audit')).toBeVisible();
  return { count: () => hits, setStatus: (next: number) => { status = next; } };
}

test('Admin vede soltanto metadati di audit in una sezione nella propria amministrazione', async ({ page }) => {
  const trace = await open(page);
  await page.getByRole('navigation').getByRole('button', { name: 'Amministrazione' }).click();
  await expect(page.getByRole('heading', { name: 'Attività recenti del Comune' })).toBeVisible();
  const table = page.getByRole('table', { name: 'Attività recenti del Comune' });
  await expect(table.getByText('platform.module.protocol.disabled')).toBeVisible();
  await expect(table.getByText('platform.membership.reader.activated')).toBeVisible();
  await expect(table.getByText('platform.module', { exact: true })).toBeVisible();
  expect(trace.count()).toBeGreaterThan(0);
  await expect(page.getByText('hidden-actor-identifiable')).toHaveCount(0);
  await expect(page.getByText('hidden-correlation-identifiable')).toHaveCount(0);
  await expect(page.getByRole('button', { name: /Esporta audit|Elimina audit|Impersona/ })).toHaveCount(0);
  await page.getByRole('button', { name: 'Lingua' }).click();
  await expect(page.getByRole('heading', { name: 'Recent municipal activity' })).toBeVisible();
  await page.getByRole('button', { name: 'Theme' }).click();
  await expect(page.locator('html')).toHaveClass(/dark/);
});

test('Reader non vede la sezione e non richiede audit', async ({ page }) => {
  const trace = await open(page, 'Reader');
  await expect(page.getByRole('navigation').getByRole('button', { name: 'Amministrazione' })).toHaveCount(0);
  await expect(page.getByRole('heading', { name: 'Attività recenti del Comune' })).toHaveCount(0);
  expect(trace.count()).toBe(0);
});

test('Audit fallito non mostra righe precedenti e offre un retry manuale', async ({ page }) => {
  const trace = await open(page);
  trace.setStatus(503);
  await page.getByRole('navigation').getByRole('button', { name: 'Amministrazione' }).click();
  await expect(page.getByRole('button', { name: 'Riprova attività' })).toBeVisible();
  await expect(page.getByRole('table', { name: 'Attività recenti del Comune' })).toHaveCount(0);
  trace.setStatus(200);
  await page.getByRole('button', { name: 'Riprova attività' }).click();
  await expect(page.getByRole('table', { name: 'Attività recenti del Comune' }).getByText(events[0].action)).toBeVisible();
  await page.getByRole('button', { name: 'Esci' }).click();
  await expect(page.getByRole('heading', { name: 'Attività recenti del Comune' })).toHaveCount(0);
});


test('Admin vede una comunicazione chiara sulla tracciatura della consultazione senza identità o token', async ({ page }) => {
  await open(page);
  await page.getByRole('navigation').getByRole('button', { name: 'Amministrazione' }).click();
  await expect(page.getByText('Le consultazioni del registro sono registrate per sicurezza.')).toBeVisible();
  await page.getByRole('button', { name: 'Lingua' }).click();
  await expect(page.getByText('Audit register consultations are logged for security.')).toBeVisible();
  await expect(page.getByText('audit-admin')).toHaveCount(0);
  await expect(page.getByText('synthetic-test-token')).toHaveCount(0);
});
