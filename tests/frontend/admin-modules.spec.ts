import { test, expect } from '@playwright/test';

const organizationId = '11111111-1111-1111-1111-111111111111';

async function openDashboard(page: import('@playwright/test').Page, roles: string[]) {
  let enabled = true;
  let failUpdate = false;
  await page.route('**/api/v1/auth/browser', route => route.fulfill({
    status: 200, contentType: 'application/json',
    body: JSON.stringify({ mode: 'DevelopmentJwt', enabled: false })
  }));
  await page.route('**/api/v1/context', route => route.fulfill({
    status: 200, contentType: 'application/json',
    body: JSON.stringify({
      organizationId, organizationName: 'Comune Aurora', roles,
      modules: enabled ? ['protocol'] : []
    }),
  }));
  await page.route('**/api/v1/admin/modules', route => route.fulfill({
    status: 200, contentType: 'application/json',
    body: JSON.stringify([{ key: 'protocol', enabled }]),
  }));
  await page.route('**/api/v1/admin/modules/protocol', route => {
    if (failUpdate) return route.fulfill({ status: 500, body: 'Error' });
    enabled = (route.request().postDataJSON() as { enabled: boolean }).enabled;
    return route.fulfill({ status: 200, contentType: 'application/json',
      body: JSON.stringify({ key: 'protocol', enabled }) });
  });
  await page.goto('/');
  await page.getByLabel('Token JWT di sviluppo').fill('test-token');
  await page.getByRole('button', { name: 'Usa token' }).click();
  await expect(page.locator('header').getByText('Comune Aurora')).toBeVisible();
  return { setFailure: () => { failUpdate = true; } };
}

test('solo Admin vede la navigazione Amministrazione', async ({ page }) => {
  await openDashboard(page, ['Reader']);
  await expect(page.getByRole('navigation').getByText('Amministrazione')).toHaveCount(0);
});

test('Admin disabilita Protocollo e il menu viene aggiornato', async ({ page }) => {
  await openDashboard(page, ['Admin']);
  await page.getByRole('navigation').getByText('Amministrazione').click();
  await expect(page.getByRole('button', { name: 'Disabilita Protocollo' })).toBeVisible();
  await page.getByRole('button', { name: 'Disabilita Protocollo' }).click();
  await expect(page.getByRole('button', { name: 'Abilita Protocollo' })).toBeVisible();
  await expect(page.getByRole('navigation').getByText('Protocollo')).toHaveCount(0);
});

test('fallimento aggiornamento mostra errore e non cambia menu', async ({ page }) => {
  const control = await openDashboard(page, ['Admin']);
  control.setFailure();
  await page.getByRole('navigation').getByText('Amministrazione').click();
  await page.getByRole('button', { name: 'Disabilita Protocollo' }).click();
  await expect(page.getByRole('alert')).toBeVisible();
  await expect(page.getByRole('navigation').getByText('Protocollo')).toBeVisible();
});
