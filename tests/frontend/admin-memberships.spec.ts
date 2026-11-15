import { expect, test, type Page } from '@playwright/test';

const org = '11111111-1111-1111-1111-111111111111';
type Member = { subject: string; role: string; enabled: boolean; issuer?: string | null };

async function openAdministration(page: Page, admin: boolean) {
  const members: Member[] = [
    { subject: 'test-admin', role: 'Admin', enabled: true },
    { subject: 'test-reader', role: 'Reader', enabled: true, issuer: 'https://issuer.comuni.test/' }
  ];
  let failUpdates = false;
  await page.route('**/api/v1/auth/browser', route => route.fulfill({
    status: 200, contentType: 'application/json',
    body: JSON.stringify({ mode: 'DevelopmentJwt', enabled: false })
  }));
  await page.route('**/api/v1/context', route => route.fulfill({
    status: 200, contentType: 'application/json',
    body: JSON.stringify({ organizationId: org, organizationName: 'Comune Aurora',
      roles: admin ? ['Admin'] : ['Reader'], modules: ['protocol'] })
  }));
  await page.route('**/api/v1/admin/modules', route => route.fulfill({
    status: 200, contentType: 'application/json',
    body: JSON.stringify([{ key: 'protocol', enabled: true }])
  }));
  await page.route('**/api/v1/admin/memberships', route => route.fulfill({
    status: 200, contentType: 'application/json', body: JSON.stringify(members)
  }));
  await page.route('**/api/v1/admin/memberships/*', route => {
    if (failUpdates) return route.fulfill({ status: 500, body: 'Unavailable' });
    const body = route.request().postDataJSON() as { subject: string; enabled: boolean };
    const role = route.request().url().split('/').pop()!;
    const existing = members.find(x => x.subject === body.subject && x.role === role);
    if (existing) existing.enabled = body.enabled;
    else members.push({ subject: body.subject, role, enabled: body.enabled });
    return route.fulfill({ status: 200, contentType: 'application/json',
      body: JSON.stringify({ subject: body.subject, role, enabled: body.enabled }) });
  });
  await page.goto('/');
  await page.getByLabel('Token JWT di sviluppo').fill('unit-test-token');
  await page.getByRole('button', { name: 'Usa token' }).click();
  await expect(page.locator('header').getByText('Comune Aurora')).toBeVisible();
  return { setFailure: () => { failUpdates = true; } };
}

test('un Reader non vede amministrazione né gestione membership', async ({ page }) => {
  await openAdministration(page, false);
  await expect(page.getByRole('navigation').getByText('Amministrazione')).toHaveCount(0);
  await expect(page.getByText('Membri del Comune')).toHaveCount(0);
});

test('Admin assegna e disattiva un Officer senza poter gestire Admin', async ({ page }) => {
  await openAdministration(page, true);
  await page.getByRole('navigation').getByText('Amministrazione').click();
  await expect(page.getByText('Membri del Comune')).toBeVisible();
  await expect(page.getByText('test-admin')).toBeVisible();
  await expect(page.getByText('https://issuer.comuni.test/')).toBeVisible();
  await expect(page.getByLabel('Issuer da modificare')).toHaveCount(0);
  await expect(page.getByRole('button', { name: 'Disattiva Admin per test-admin' })).toHaveCount(0);

  await page.getByLabel('Identificativo soggetto IdP').fill('idp-new-officer');
  await page.getByLabel('Ruolo da assegnare').selectOption('Officer');
  await page.getByRole('button', { name: 'Assegna ruolo' }).click();
  await expect(page.getByText('idp-new-officer')).toBeVisible();
  await page.getByRole('button', { name: 'Disattiva Officer per idp-new-officer' }).click();
  await expect(page.getByRole('button', { name: 'Riattiva Officer per idp-new-officer' })).toBeVisible();
});

test('errore backend mantiene stato precedente e mostra feedback', async ({ page }) => {
  const operations = await openAdministration(page, true);
  await page.getByRole('navigation').getByText('Amministrazione').click();
  operations.setFailure();
  await page.getByRole('button', { name: 'Disattiva Reader per test-reader' }).click();
  await expect(page.getByRole('alert')).toBeVisible();
  await expect(page.getByRole('button', { name: 'Disattiva Reader per test-reader' })).toBeVisible();
});
