import { defineConfig, devices } from '@playwright/test';

export default defineConfig({
  testDir: './e2e',
  testMatch: '*.spec.ts',
  fullyParallel: false,
  workers: 1,
  timeout: 45_000,
  expect: { timeout: 10_000 },
  use: {
    baseURL: 'http://127.0.0.1:4179',
    trace: 'retain-on-failure',
    ...devices['Desktop Chrome']
  },
  webServer: {
    command: 'npm run build && cd .. && go run ./frontend/e2e/server',
    env: { PUBLIC_SECURL_API_BASE_URL: '' },
    url: 'http://127.0.0.1:4179/healthz',
    reuseExistingServer: false,
    timeout: 120_000
  }
});
