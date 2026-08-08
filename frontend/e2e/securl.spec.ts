import { expect, test, type Page } from '@playwright/test';
import { create, fromBinary, toBinary } from '@bufbuild/protobuf';
import {
  CreateEnvelopeRequestSchema,
  SafeBrowsingFullHashSchema,
  SafeBrowsingLookupResponseSchema
} from '../src/lib/gen/securl/v1/api_pb.js';
import { hashSafeBrowsingUrl } from '../src/lib/safe-browsing/url-hash.js';

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

async function mockTurnstile(page: Page): Promise<void> {
  await page.route(turnstileScriptPattern, async (route) => {
    await route.fulfill({
      status: 200,
      contentType: 'application/javascript',
      body: `window.turnstile={render:function(_,options){setTimeout(function(){options.callback('e2e-token')},0);return 'e2e-widget'},remove:function(){}};`
    });
  });
}

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
  await expect(openPage.getByText('Envelope not found.')).toBeVisible();
});
