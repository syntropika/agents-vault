import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { defineConfig, devices } from '@playwright/test';

export default defineConfig({
  testDir: './tests',
  fullyParallel: false,
  workers: 1,
  forbidOnly: true,
  retries: 0,
  reporter: 'list',
  outputDir: process.env['AV_WEB_TEST_OUTPUT'] ?? join(tmpdir(), 'av-web-browser-results'),
  use: {
    baseURL: 'http://127.0.0.1:14323',
    trace: 'off',
    screenshot: 'off',
    launchOptions: {
      ...(process.env['AV_WEB_BROWSER'] ? { executablePath: process.env['AV_WEB_BROWSER'] } : {}),
    },
  },
  projects: [
    {
      name: 'desktop',
      use: { ...devices['Desktop Chrome'], viewport: { width: 1505, height: 1045 } },
    },
    { name: 'mobile', use: { ...devices['iPhone 13'], defaultBrowserType: 'chromium' } },
  ],
});
