import { test, expect } from '@playwright/test';

const aurora = '11111111-1111-1111-1111-111111111111';

async function enterWithContext(page: import('@playwright/test').Page, roles: string[], modules: string[]) {
  await page.route('**/api/v1/context', route => route.fulfill({
    status: 200,
    contentType: 'application/json',
    body: JSON.stringify({ organizationId: aurora, organizationName: 'Comune Aurora', roles, modules }),
  }));
  await page.route('**/api/v1/protocol/records', route => route.fulfill({
    status: 200, contentType: 'application/json', body: JSON.stringify([]),
  }));
  await page.goto('/');
  await page.getByLabel('Token JWT di sviluppo').fill('test-token');
  await page.getByRole('button', { name: 'Usa token' }).click();
}

test('nasconde il modulo non abilitato', async ({ page }) => {
  await enterWithContext(page, ['Admin'], []);
  await expect(page.getByRole('navigation').getByText('Protocollo')).toHaveCount(0);
  await expect(page.locator('header').getByText('Comune Aurora')).toBeVisible();
});

test('un Reader non vede la creazione nel modulo attivo', async ({ page }) => {
  await enterWithContext(page, ['Reader'], ['protocol']);
  await page.getByRole('navigation').getByText('Protocollo').click();
  await expect(page.getByRole('button', { name: 'Registra documento' })).toHaveCount(0);
});

test('un Officer può aprire la registrazione', async ({ page }) => {
  await enterWithContext(page, ['Officer'], ['protocol']);
  await page.getByRole('navigation').getByText('Protocollo').click();
  await expect(page.getByRole('button', { name: 'Registra documento' })).toBeVisible();
});
