import { expect, test, type Page } from '@playwright/test';
import { create, fromBinary, toBinary } from '@bufbuild/protobuf';
import {
  CreateEnvelopeRequestSchema,
  SafeBrowsingFullHashSchema,
  SafeBrowsingLookupResponseSchema
} from '../src/lib/gen/securl/v1/api_pb.js';
import { hashSafeBrowsingUrl } from '../src/lib/safe-browsing/url-hash.js';

declare global {
  interface Window {
    __solveCaptcha: () => void;
    __failCaptcha: () => void;
    __expireCaptcha: () => void;
    __captchaRenderCount: number;
  }
}

const safeLookupPattern = '**/api/v1/safe-browsing/lookup';
const turnstileScriptPattern = 'https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit';

function lookupResponse(fullHashes: Uint8Array[] = []): Buffer {
  const response = create(SafeBrowsingLookupResponseSchema, {
    fullHashes: fullHashes.map((fullHash) =>
      create(SafeBrowsingFullHashSchema, {
        fullHash,
        threatType: 'SOCIAL_ENGINEERING',
        attributes: [],
        cacheSeconds: 60
      })
    )
  });
  return Buffer.from(toBinary(SafeBrowsingLookupResponseSchema, response));
}

async function createProtectedLink(
  page: Page,
  destination: string,
  options: { password?: string; captcha?: boolean; burn?: boolean; ttl?: number } = {}
): Promise<{ link: string; requestBody: Buffer }> {
  let requestBody = Buffer.alloc(0);
  page.on('request', (request) => {
    if (request.method() === 'POST' && request.url().endsWith('/api/v1/envelopes')) {
      requestBody = request.postDataBuffer() ?? Buffer.alloc(0);
    }
  });
  await mockTurnstile(page);
  await page.goto('/');
  await page.getByLabel('Destination URL').fill(destination);
  if (options.password !== undefined) {
    await page.getByRole('checkbox', { name: /Password/ }).check();
    await page.getByLabel('Password', { exact: true }).fill(options.password);
  }
  if (options.captcha) await page.getByRole('checkbox', { name: /CAPTCHA/ }).check();
  if (options.burn) await page.getByRole('checkbox', { name: /Burn after reading/ }).check();
  if (options.ttl !== undefined) await page.getByLabel('Time to live').selectOption(String(options.ttl));
  await page.getByRole('button', { name: 'Create protected link' }).click();
  await expect(page.getByRole('heading', { name: 'Protected link ready' })).toBeVisible();
  return { link: (await page.locator('code').textContent())!, requestBody };
}

function turnstileMockScript(autoSolve = true): string {
  return `window.turnstile={render:function(_,options){window.__captchaRenderCount=(window.__captchaRenderCount||0)+1;window.__solveCaptcha=function(){options.callback('e2e-token')};window.__failCaptcha=function(){options['error-callback']()};window.__expireCaptcha=function(){options['expired-callback']()};${autoSolve ? 'setTimeout(window.__solveCaptcha,0);' : ''}return 'e2e-widget'},remove:function(){}};`;
}

async function mockTurnstile(page: Page, autoSolve = true): Promise<void> {
  await page.route(turnstileScriptPattern, async (route) => {
    await route.fulfill({
      status: 200,
      contentType: 'application/javascript',
      body: turnstileMockScript(autoSolve)
    });
  });
}

test('creator CAPTCHA blocks submission until the challenge is solved', async ({ page }) => {
  await mockTurnstile(page, false);
  await page.goto('/');
  await page.getByLabel('Destination URL').fill('https://example.com/creator-captcha');
  const createButton = page.getByRole('button', { name: 'Create protected link' });
  await expect(createButton).toBeDisabled();
  await page.waitForFunction(() => typeof window.__solveCaptcha === 'function');
  await page.evaluate(() => window.__solveCaptcha());
  await expect(createButton).toBeEnabled();
  await createButton.click();
  await expect(page.getByRole('heading', { name: 'Protected link ready' })).toBeVisible();
});

for (const scenario of [
  { name: 'provider error', trigger: 'error', message: 'Verification failed. Try again.' },
  { name: 'expiry', trigger: 'expired', message: 'Verification expired. Complete it again.' }
] as const) {
  test(`creator CAPTCHA recovers from ${scenario.name}`, async ({ page }) => {
    await mockTurnstile(page, false);
    await page.goto('/');
    await page.getByLabel('Destination URL').fill(`https://example.com/captcha-${scenario.trigger}`);
    await page.waitForFunction(() => window.__captchaRenderCount === 1);
    await page.evaluate((trigger) => {
      if (trigger === 'error') window.__failCaptcha();
      else window.__expireCaptcha();
    }, scenario.trigger);

    const createButton = page.getByRole('button', { name: 'Create protected link' });
    await expect(page.getByRole('alert')).toHaveText(scenario.message);
    await expect(createButton).toBeDisabled();
    await page.getByRole('button', { name: 'Try verification again' }).click();
    await page.waitForFunction(() => window.__captchaRenderCount === 2);
    await page.evaluate(() => window.__solveCaptcha());
    await expect(createButton).toBeEnabled();
    await createButton.click();
    await expect(page.getByRole('heading', { name: 'Protected link ready' })).toBeVisible();
  });
}

test('creator CAPTCHA retries after the provider script fails to load', async ({ page }) => {
  let scriptRequests = 0;
  await page.route(turnstileScriptPattern, async (route) => {
    scriptRequests += 1;
    if (scriptRequests === 1) {
      await route.abort('failed');
      return;
    }
    await route.fulfill({
      status: 200,
      contentType: 'application/javascript',
      body: turnstileMockScript(false)
    });
  });
  await page.goto('/');
  await page.getByLabel('Destination URL').fill('https://example.com/captcha-script-retry');
  await expect(page.getByRole('alert')).toHaveText('Verification couldn’t load.');
  const createButton = page.getByRole('button', { name: 'Create protected link' });
  await expect(createButton).toBeDisabled();
  await page.getByRole('button', { name: 'Try verification again' }).click();
  await page.waitForFunction(() => window.__captchaRenderCount === 1);
  await page.evaluate(() => window.__solveCaptcha());
  await expect(createButton).toBeEnabled();
  await createButton.click();
  await expect(page.getByRole('heading', { name: 'Protected link ready' })).toBeVisible();
});

test('clean lookup redirects only after the five-second gate and leaks no fragment or plaintext', async ({
  page,
  context
}) => {
  const destinationInput = 'example.com/clean?a=1';
  const destination = 'https://example.com/clean?a=1';
  const { link, requestBody } = await createProtectedLink(page, destinationInput);
  const match = link.match(/\/#([0-9A-Za-z]{11})$/);
  expect(match).not.toBeNull();
  const fragment = match![1];
  expect(requestBody.includes(Buffer.from(fragment))).toBe(false);
  expect(requestBody.includes(Buffer.from(destination))).toBe(false);
  expect(requestBody.includes(Buffer.from(destinationInput))).toBe(false);
  const createRequest = fromBinary(CreateEnvelopeRequestSchema, requestBody);
  expect(createRequest.storageKey).toHaveLength(32);
  expect(createRequest.envelope?.ciphertext.length).toBeGreaterThan(16);
  expect(createRequest.captchaToken).toBe('e2e-token');

  const openPage = await context.newPage();
  let scanCompletedAt = 0;
  let destinationRequestedAt = 0;
  await openPage.route(safeLookupPattern, async (route) => {
    scanCompletedAt = Date.now();
    await route.fulfill({ status: 200, contentType: 'application/x-protobuf', body: lookupResponse() });
  });
  await openPage.route(destination, async (route) => {
    destinationRequestedAt = Date.now();
    await route.fulfill({ status: 200, contentType: 'text/html', body: '<title>clean destination</title>' });
  });
  await openPage.goto(link);
  await expect(openPage.getByRole('heading', { name: 'Checking destination safety' })).toBeVisible();
  await openPage.waitForTimeout(4500);
  expect(openPage.url()).toBe(link);
  await expect(openPage).toHaveURL(destination, { timeout: 3000 });
  expect(destinationRequestedAt - scanCompletedAt).toBeGreaterThanOrEqual(4800);
});

test('New link leaves the open-link state and returns to the creator', async ({ page, context }) => {
  const destination = 'https://example.com/new-link-navigation';
  const password = 'new-link-navigation';
  const { link } = await createProtectedLink(page, destination, { password });
  const openPage = await context.newPage();

  await openPage.goto(link);
  await expect(openPage.getByRole('heading', { name: 'Password required' })).toBeVisible();
  await openPage.getByRole('link', { name: 'New link' }).click();

  await expect(openPage).toHaveURL('/');
  await expect(openPage.getByRole('heading', { name: 'Create a protected link' })).toBeVisible();
  await expect(openPage.getByRole('heading', { name: 'Open a protected link' })).toHaveCount(0);
});


test('forever TTL is encoded as zero and creates a non-expiring link', async ({ page }) => {
  const { requestBody } = await createProtectedLink(page, 'https://example.com/forever', { ttl: 0 });
  const createRequest = fromBinary(CreateEnvelopeRequestSchema, requestBody);
  expect(createRequest.envelope?.metadata?.ttlSeconds).toBe(0);
  await expect(page.getByRole('heading', { name: 'Protected link ready' })).toBeVisible();
});

test('manual choice skips the delay but still waits for a clean safety check', async ({ page, context }) => {
  const destination = 'https://example.com/clean?a=1';
  const { link } = await createProtectedLink(page, destination);
  const openPage = await context.newPage();
  const lookup = Promise.withResolvers<void>();
  await openPage.route(safeLookupPattern, async (route) => {
    await lookup.promise;
    await route.fulfill({ status: 200, contentType: 'application/x-protobuf', body: lookupResponse() });
  });
  await openPage.route(destination, (route) =>
    route.fulfill({ status: 200, contentType: 'text/html', body: '<title>manual destination</title>' })
  );
  await openPage.goto(link);
  await expect(openPage.getByRole('heading', { name: 'Checking destination safety' })).toBeVisible();
  const startedAt = Date.now();
  await openPage.getByRole('button', { name: 'Check now and open' }).click();
  await openPage.waitForTimeout(300);
  expect(openPage.url()).toBe(link);
  lookup.resolve();
  await expect(openPage).toHaveURL(destination);
  expect(Date.now() - startedAt).toBeLessThan(2000);
});

test('threat response blocks every redirect', async ({ page, context }) => {
  const destination = 'https://example.com/clean?a=1';
  const { link } = await createProtectedLink(page, destination);
  const hashes = await hashSafeBrowsingUrl(destination);
  const openPage = await context.newPage();
  let destinationRequests = 0;
  await openPage.route(safeLookupPattern, (route) =>
    route.fulfill({
      status: 200,
      contentType: 'application/x-protobuf',
      body: lookupResponse([hashes[0].fullHash])
    })
  );
  await openPage.route(destination, async (route) => {
    destinationRequests++;
    await route.abort();
  });
  await openPage.goto(link);
  await expect(openPage.getByRole('heading', { name: 'Deceptive site ahead' })).toBeVisible();
  await openPage.waitForTimeout(5500);
  expect(openPage.url()).toBe(link);
  expect(destinationRequests).toBe(0);
});

test('503 remains gated until explicit unscanned choice', async ({ page, context }) => {
  const destination = 'https://example.com/clean?a=1';
  const { link } = await createProtectedLink(page, destination);
  const openPage = await context.newPage();
  await openPage.route(safeLookupPattern, (route) =>
    route.fulfill({ status: 503, contentType: 'application/x-protobuf', body: Buffer.alloc(0) })
  );
  await openPage.route(destination, (route) =>
    route.fulfill({ status: 200, contentType: 'text/html', body: '<title>unscanned destination</title>' })
  );
  await openPage.goto(link);
  await expect(openPage.getByRole('heading', { name: 'Safety check unavailable' })).toBeVisible();
  await openPage.waitForTimeout(5200);
  expect(openPage.url()).toBe(link);
  await openPage.getByRole('button', { name: 'Open without safety check' }).click();
  await expect(openPage).toHaveURL(destination);
});

test('password, CAPTCHA mock, and burn consume the link exactly once', async ({ page, context }) => {
  const destination = 'https://example.com/protected';
  const password = 'correct horse battery staple';
  const { link } = await createProtectedLink(page, destination, {
    password,
    captcha: true,
    burn: true
  });
  const openPage = await context.newPage();
  await mockTurnstile(openPage);
  await openPage.route(safeLookupPattern, (route) =>
    route.fulfill({ status: 200, contentType: 'application/x-protobuf', body: lookupResponse() })
  );
  await openPage.goto(link);
  await expect(openPage.getByRole('heading', { name: 'Password required' })).toBeVisible();
  await openPage.getByLabel('Password', { exact: true }).fill(password);
  await openPage.getByRole('button', { name: 'Continue' }).click();
  await expect(openPage.getByRole('heading', { name: 'Checking destination safety' })).toBeVisible({
    timeout: 20_000
  });

  const missingMetadata = openPage.waitForResponse(
    (response) => response.url().includes('/metadata') && response.status() === 404
  );
  await openPage.reload();
  await missingMetadata;
  await expect(openPage.getByText('This link is no longer available.')).toBeVisible();
});
