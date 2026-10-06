import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { expect, test } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';

test('real operator workflow keeps secrets out of reviews and adapts to its viewport', async ({
  page,
}, info) => {
  test.setTimeout(90000);
  const errors: string[] = [];
  page.on('pageerror', (error) => errors.push(error.message));
  const response = await page.goto('/');
  expect(response?.headers()['content-security-policy']).toContain("script-src 'self'");
  await expect(page.getByRole('button', { name: 'Open vault', exact: true })).toBeEnabled();
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark');
  const selectedTab = page.getByRole('button', { name: 'Credentials', exact: true });
  await selectedTab.focus();
  await expect(selectedTab).toHaveCSS('outline-offset', '-2px');
  await expect(selectedTab).toHaveCSS('outline-width', '2px');
  const inactiveTab = page.getByRole('button', { name: 'Permissions', exact: true });
  await inactiveTab.hover();
  await expect(inactiveTab).toHaveCSS('background-color', 'rgb(33, 33, 33)');
  await expect(selectedTab).toHaveCSS('background-color', 'rgb(23, 23, 23)');
  await page.mouse.move(0, 0);
  await expect(page.getByRole('button', { name: 'Add credential', exact: true })).toBeDisabled();
  await page.getByLabel('Vault passphrase').fill('synthetic-preview-passphrase');
  await page.getByRole('button', { name: 'Open vault', exact: true }).click();
  await expect(page.getByRole('button', { name: 'Sign out' })).toBeVisible();
  await page.getByRole('button', { name: /example\/build/ }).click();
  await expect(page.getByRole('heading', { name: 'example/build' })).toBeVisible();
  await page.screenshot({
    path: join(process.env['AV_WEB_CAPTURE_ROOT'] ?? tmpdir(), `av-${info.project.name}-final.png`),
    fullPage: true,
  });
  expect((await new AxeBuilder({ page }).analyze()).violations).toEqual([]);
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(
    true,
  );
  await page.getByRole('button', { name: 'Switch to light mode' }).click();
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
  await expect(page.locator('button[aria-current="page"]')).toHaveCSS('color', 'rgb(28, 28, 32)');
  await expect(page.locator('.heading-actions .primary')).toHaveCSS(
    'background-color',
    'rgb(24, 24, 27)',
  );
  expect((await new AxeBuilder({ page }).analyze()).violations).toEqual([]);
  await page.getByRole('button', { name: 'Switch to dark mode' }).click();
  await page.getByRole('button', { name: 'Add credential', exact: true }).click();
  const name = `test/${info.project.name}_${String(Date.now())}`;
  await page.getByLabel('Credential name', { exact: true }).fill(name);
  await page.getByLabel('Allowed host', { exact: true }).fill('api.test.example.test');
  await page.getByLabel('Credential value', { exact: true }).fill('av-synthetic-browser-only');
  await page.getByRole('button', { name: 'Save credential' }).click();
  await expect(page.getByRole('button', { name: new RegExp(name) })).toBeVisible();
  await page.getByRole('button', { name: new RegExp(name) }).click();
  await expect(page.getByRole('heading', { name })).toBeVisible();
  expect(await page.locator('body').textContent()).not.toContain('av-synthetic-browser-only');
  await page.getByRole('button', { name: 'Rotate credential' }).click();
  await page.getByLabel('New credential value').fill('av-synthetic-rotated-browser-only');
  await page.getByRole('button', { name: 'Replace credential' }).click();
  await page.getByRole('button', { name: new RegExp(name) }).click();
  await expect(page.getByText('v2', { exact: true })).toBeVisible();
  const ca = process.env['AV_MCP_TEST_CA'];
  if (!ca) throw new Error('Set AV_MCP_TEST_CA to the disposable test server CA');
  await page.getByRole('button', { name: 'Actions', exact: true }).click();
  await page.getByLabel('Credential', { exact: true }).selectOption(name);
  await expect(page.locator('.task-destination strong')).toHaveText('api.test.example.test');
  for (const tab of await page.locator('.segmented-nav button').all()) {
    const bounds = await tab.boundingBox();
    expect(bounds).not.toBeNull();
    if (bounds)
      expect(bounds.x + bounds.width).toBeLessThanOrEqual(page.viewportSize()?.width ?? 0);
  }
  await page.getByLabel('Executable', { exact: true }).fill('/usr/bin/true');
  await page.getByLabel('Maximum seconds').fill('25');
  await page.getByLabel('Maximum requests').fill('4');
  await page.getByLabel('Maximum connections').fill('2');
  const destination = page.locator('details.task-transport');
  if ((await destination.getAttribute('open')) === null)
    await destination.getByText('Test destination', { exact: true }).click();
  await page.getByLabel('Local server address').fill('127.0.0.1:19443');
  await page.getByLabel('Server CA file').fill(ca);
  await page.getByRole('button', { name: /^(Create action|Save action)$/u }).click();
  await expect(
    page.getByText('Action saved. Grant its credential permission before enabling actions.'),
  ).toBeVisible();
  expect((await new AxeBuilder({ page }).analyze()).violations).toEqual([]);
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(
    true,
  );
  const capture = process.env['AV_WEB_CAPTURE_ROOT'];
  if (capture)
    await page.screenshot({
      path: join(capture, `task-editor-${info.project.name}.png`),
      fullPage: true,
    });
  await page.getByRole('button', { name: 'Permissions', exact: true }).click();
  await page.getByRole('button', { name: new RegExp(name) }).click();
  await page.getByRole('button', { name: 'Edit permissions', exact: true }).click();
  await page.getByRole('button', { name: 'Grant configured action', exact: true }).click();
  await expect(
    page.getByText('Configured action granted. Each run requires approval.'),
  ).toBeVisible();
  await page.getByRole('button', { name: 'Actions', exact: true }).click();
  await page.getByLabel('Maximum requests').fill('5');
  await page.getByRole('button', { name: 'Save action', exact: true }).click();
  await expect(
    page.getByText('Action saved. Grant its credential permission before enabling actions.'),
  ).toBeVisible();
  await page.getByRole('button', { name: 'Credentials', exact: true }).click();
  await page.getByRole('button', { name: new RegExp(name) }).click();
  await expect(page.getByText('No access granted', { exact: true })).toBeVisible();
  await page.getByRole('button', { name: 'Disconnect credential', exact: true }).click();
  await page.getByRole('button', { name: 'Confirm disconnect', exact: true }).click();
  await page.getByRole('button', { name: 'Approvals', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'No requests to review' })).toBeVisible();
  await page.getByRole('button', { name: 'Sign out' }).click();
  await expect(page.getByRole('button', { name: 'Open vault', exact: true })).toBeVisible();
  await page.getByRole('button', { name: 'Credentials', exact: true }).click();
  await expect(page.getByRole('button', { name: 'Add credential', exact: true })).toBeDisabled();
  expect(errors).toEqual([]);
});
