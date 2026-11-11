import { randomBytes, randomUUID } from 'node:crypto';
import { eq } from 'drizzle-orm';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { deriveSiteKey, hashSiteKey, REPORT_MAX_BYTES, REPORTS_PATH, sha256Hex, signRequest, type InsideReport } from '@shc/companion';
import { sampleInsideReport } from '@shc/companion/testing';
import { auditEvents, pluginKeys, pluginReports, scans, sites } from '@shc/db';
import { createTestContext, del, FakeOwnership, FakeQueue, get, post, resetState, signedInUser, type TestContext } from './helpers';

const SECRET = 'test-plugin-key-secret-0123456789abcdef';
const REPORTS_PER_HOUR = 3;
const queue = new FakeQueue();
let ctx: TestContext;
let alice: string;
let siteId: string;
let keyId: string;
let key: string;

const ownership = new FakeOwnership();

beforeAll(async () => {
  ctx = await createTestContext({ ownership, scanQueue: queue, plugin: { keySecret: SECRET, reportsPerHour: REPORTS_PER_HOUR } });
});
afterAll(async () => {
  await ctx.close();
});
beforeEach(async () => {
  await resetState(ctx);
  queue.enqueued = [];
  ownership.next = { ok: true, detail: 'TXT record found at _shc-verify.example.com' };
  alice = await signedInUser(ctx, 'alice@example.com');
  expect((await post(ctx, '/api/billing/upgrade', { plan: 'pro' }, alice)).statusCode).toBe(200);
  siteId = (await post(ctx, '/api/sites', { domain: 'example.com' }, alice)).json().site.id;
  await ctx.db.update(sites).set({ verifiedAt: new Date(), verificationMethod: 'dns_txt' }).where(eq(sites.id, siteId));
  const { code } = (await post(ctx, `/api/sites/${siteId}/plugin/pairing-code`, {}, alice)).json().pairing;
  const paired = await ctx.app.inject({ method: 'POST', url: '/api/plugin/pair', payload: { code, homeUrl: 'https://example.com', pluginVersion: '0.1.0' } });
  ({ keyId, key } = paired.json());
});

interface SendOptions {
  report?: InsideReport;
  /** Sent instead of the JSON of `report`. */
  body?: string;
  /** Signed instead of the body actually sent. */
  signedBody?: string;
  keyId?: string;
  key?: string;
  timestamp?: number;
  nonce?: string;
  headers?: Record<string, string | undefined>;
}

const freshNonce = () => randomBytes(16).toString('base64url');

/** Signs and sends a report the way the plugin does: from the server, without an Origin header. */
function send(options: SendOptions = {}) {
  const body = options.body ?? JSON.stringify(options.report ?? sampleInsideReport());
  const timestamp = options.timestamp ?? Math.floor(Date.now() / 1000);
  const nonce = options.nonce ?? freshNonce();
  const signature = signRequest(options.key ?? key, { method: 'POST', path: REPORTS_PATH, timestamp, nonce, body: options.signedBody ?? body });
  const headers: Record<string, string> = {
    'content-type': 'application/json',
    'x-shc-key-id': options.keyId ?? keyId,
    'x-shc-timestamp': String(timestamp),
    'x-shc-nonce': nonce,
    'x-shc-signature': signature,
  };
  for (const [name, value] of Object.entries(options.headers ?? {})) {
    if (value === undefined) delete headers[name];
    else headers[name] = value;
  }
  return ctx.app.inject({ method: 'POST', url: '/api/plugin/reports', headers, payload: body });
}

async function expectRefused(res: Awaited<ReturnType<typeof send>>, status: number, error: string) {
  expect(res.statusCode, res.body).toBe(status);
  expect(res.json().error).toBe(error);
}

describe('signed reports', () => {
  it('stores the report with logins masked again and queues an inside scan', async () => {
    const report = sampleInsideReport();
    report.admins = [{ login: 'shc-admin', roles: ['administrator'] }];
    const body = JSON.stringify(report);
    const res = await send({ body });
    expect(res.statusCode).toBe(202);
    const { reportId, scanId } = res.json();

    const [scan] = await ctx.db.select().from(scans).where(eq(scans.id, scanId));
    expect(scan).toMatchObject({ siteId, kind: 'inside', trigger: 'plugin', status: 'queued' });
    expect(queue.enqueued).toEqual([scanId]);

    const [stored] = await ctx.db.select().from(pluginReports).where(eq(pluginReports.id, reportId));
    expect(stored).toMatchObject({ siteId, pluginKeyId: keyId, scanId, pluginVersion: '0.1.0', payloadSha256: sha256Hex(body) });
    expect((stored!.payload as InsideReport).admins).toEqual([{ login: 's******n', roles: ['administrator'] }]);
    expect(JSON.stringify(stored!.payload)).not.toContain('shc-admin');

    const [usedKey] = await ctx.db.select().from(pluginKeys).where(eq(pluginKeys.id, keyId));
    expect(usedKey!.lastUsedAt).toBeInstanceOf(Date);
    expect((await ctx.db.select().from(auditEvents)).map((e) => e.event)).toContain('plugin_report_received');
    expect((await get(ctx, `/api/sites/${siteId}/plugin`, alice)).json().plugin).toMatchObject({
      status: 'connected',
      lastReportAt: expect.any(String),
      lastScanId: scanId,
      pluginVersion: '0.1.0',
    });
  });

  it('keeps the Origin check: the plugin sends none, a browser on another site is refused', async () => {
    await expectRefused(await send({ headers: { origin: 'https://evil.example' } }), 403, 'forbidden_origin');
    expect((await send()).statusCode).toBe(202);
  });

  it('takes reports larger than the API-wide body limit, up to 512 KB', async () => {
    const big = sampleInsideReport();
    big.plugins = Array.from({ length: 700 }, (_, i) => ({ slug: `plugin-${i}`, file: `plugin-${i}/plugin-${i}.php`, name: `Plugin number ${i}`, version: '1.0.0', active: true, autoUpdate: false }));
    const body = JSON.stringify(big);
    expect(body.length).toBeGreaterThan(64 * 1024);
    expect((await send({ body })).statusCode).toBe(202);
    await expectRefused(await send({ body: `${body}${' '.repeat(REPORT_MAX_BYTES)}` }), 413, 'payload_too_large');
  });

  it('refuses missing or malformed signing headers', async () => {
    await expectRefused(await send({ headers: { 'x-shc-signature': undefined } }), 401, 'invalid_signature');
    await expectRefused(await send({ headers: { 'x-shc-key-id': keyId.toUpperCase() } }), 401, 'invalid_signature');
    await expectRefused(await send({ nonce: 'too-short' }), 401, 'invalid_signature');
    await expectRefused(await send({ headers: { 'x-shc-timestamp': 'yesterday' } }), 401, 'invalid_signature');
  });

  it('refuses a timestamp more than five minutes off', async () => {
    const now = Math.floor(Date.now() / 1000);
    await expectRefused(await send({ timestamp: now - 301 }), 401, 'stale_request');
    await expectRefused(await send({ timestamp: now + 301 }), 401, 'stale_request');
  });

  it('refuses unknown, revoked and expired keys', async () => {
    const unknown = randomUUID();
    await expectRefused(await send({ keyId: unknown, key: deriveSiteKey(SECRET, unknown) }), 401, 'invalid_key');

    await ctx.db.update(pluginKeys).set({ expiresAt: new Date(Date.now() - 1000) });
    await expectRefused(await send(), 401, 'key_expired');

    expect((await del(ctx, `/api/sites/${siteId}/plugin`, alice)).statusCode).toBe(200);
    await expectRefused(await send(), 401, 'invalid_key');
  });

  it('refuses a key that another server secret issued', async () => {
    const otherSecret = 'another-plugin-key-secret-0123456789abcd';
    await ctx.db.update(pluginKeys).set({ keyHash: hashSiteKey(deriveSiteKey(otherSecret, keyId)) });
    await expectRefused(await send({ key: deriveSiteKey(otherSecret, keyId) }), 401, 'invalid_key');
  });

  it('refuses a wrong signature and a body changed after signing', async () => {
    await expectRefused(await send({ key: deriveSiteKey(SECRET, randomUUID()) }), 401, 'invalid_signature');
    const report = sampleInsideReport();
    const signedBody = JSON.stringify(report);
    report.uploadsPhp.scanned = 13;
    await expectRefused(await send({ body: JSON.stringify(report), signedBody }), 401, 'invalid_signature');
    expect(await ctx.db.select().from(pluginReports)).toEqual([]);
  });

  it('refuses a replayed nonce without creating another scan', async () => {
    const nonce = freshNonce();
    const timestamp = Math.floor(Date.now() / 1000);
    expect((await send({ nonce, timestamp })).statusCode).toBe(202);
    await expectRefused(await send({ nonce, timestamp }), 409, 'replayed');
    expect(await ctx.db.select().from(scans)).toHaveLength(1);
    expect(queue.enqueued).toHaveLength(1);
  });

  it('limits each site per hour, counting only correctly signed requests, and re-pairing does not reset it', async () => {
    for (let i = 0; i < 5; i++) await expectRefused(await send({ key: deriveSiteKey(SECRET, randomUUID()) }), 401, 'invalid_signature');
    for (let i = 0; i < REPORTS_PER_HOUR; i++) expect((await send()).statusCode).toBe(202);
    await expectRefused(await send(), 429, 'rate_limited');

    const { code } = (await post(ctx, `/api/sites/${siteId}/plugin/pairing-code`, {}, alice)).json().pairing;
    const repaired = (await ctx.app.inject({ method: 'POST', url: '/api/plugin/pair', payload: { code, homeUrl: 'https://example.com', pluginVersion: '0.1.0' } })).json();
    await expectRefused(await send({ keyId: repaired.keyId, key: repaired.key }), 429, 'rate_limited');
  });

  it('refuses reports once the owner is no longer on Pro', async () => {
    expect((await post(ctx, '/api/billing/cancel', {}, alice)).statusCode).toBe(200);
    await expectRefused(await send(), 403, 'upgrade_required');
  });

  it('refuses reports once ownership can no longer be confirmed', async () => {
    await ctx.db.update(sites).set({ verifiedAt: new Date(Date.now() - 25 * 60 * 60 * 1000) }).where(eq(sites.id, siteId));
    ownership.next = { ok: false, reason: 'The TXT record is gone.' };
    await expectRefused(await send(), 403, 'not_verified');
    expect(await ctx.db.select().from(scans)).toHaveLength(0);
  });

  it('refuses a body that is not a valid report, saying why', async () => {
    await expectRefused(await send({ body: '{"schema": 1,' }), 400, 'invalid_report');
    const extra = { ...sampleInsideReport(), passwords: ['hunter2'] };
    const res = await send({ body: JSON.stringify(extra) });
    await expectRefused(res, 400, 'invalid_report');
    expect(res.json().details.length).toBeGreaterThan(0);
    expect(res.json().details.length).toBeLessThanOrEqual(10);
  });

  it('refuses a report from a different site', async () => {
    const report = sampleInsideReport();
    report.site.homeUrl = 'https://other.example.org';
    await expectRefused(await send({ report }), 400, 'site_mismatch');
    report.site.homeUrl = 'https://www.example.com';
    expect((await send({ report })).statusCode).toBe(202);
  });

  it('checks in the documented order', async () => {
    const now = Math.floor(Date.now() / 1000);
    const unknown = randomUUID();
    // A stale request is refused before its key is looked up.
    await expectRefused(await send({ keyId: unknown, timestamp: now - 600 }), 401, 'stale_request');
    // Payload problems are only reported to a correctly signed request from a Pro owner.
    await expectRefused(await send({ body: 'not json', key: deriveSiteKey(SECRET, unknown) }), 401, 'invalid_signature');
    expect((await post(ctx, '/api/billing/cancel', {}, alice)).statusCode).toBe(200);
    await expectRefused(await send({ body: 'not json' }), 403, 'upgrade_required');
  });
});

describe('without PLUGIN_KEY_SECRET', () => {
  let off: TestContext;
  beforeAll(async () => {
    off = await createTestContext();
  });
  afterAll(async () => {
    await off.close();
  });

  it('refuses reports as unavailable', async () => {
    const res = await off.app.inject({ method: 'POST', url: '/api/plugin/reports', headers: { 'content-type': 'application/json' }, payload: '{}' });
    expect(res.statusCode).toBe(503);
    expect(res.json().error).toBe('plugin_unavailable');
  });
});
