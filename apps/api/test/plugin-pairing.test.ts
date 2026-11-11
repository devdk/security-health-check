import { eq } from 'drizzle-orm';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { deriveSiteKey, hashSiteKey } from '@shc/companion';
import { auditEvents, pluginKeys, pluginPairingCodes, sites } from '@shc/db';
import { createTestContext, del, FakeOwnership, get, ORIGIN, post, resetState, signedInUser, type TestContext } from './helpers';

const SECRET = 'test-plugin-key-secret-0123456789abcdef';
const ownership = new FakeOwnership();
let ctx: TestContext;
let alice: string;
let siteId: string;

beforeAll(async () => {
  ctx = await createTestContext({ ownership, plugin: { keySecret: SECRET } });
});
afterAll(async () => {
  await ctx.close();
});
beforeEach(async () => {
  await resetState(ctx);
  ownership.next = { ok: true, detail: 'ok' };
  alice = await signedInUser(ctx, 'alice@example.com');
  siteId = await verifiedSite(alice, 'example.com');
});

async function verifiedSite(cookie: string, domain: string): Promise<string> {
  const id = (await post(ctx, '/api/sites', { domain }, cookie)).json().site.id as string;
  await ctx.db.update(sites).set({ verifiedAt: new Date(), verificationMethod: 'dns_txt' }).where(eq(sites.id, id));
  return id;
}

const upgrade = async (cookie = alice) => expect((await post(ctx, '/api/billing/upgrade', { plan: 'pro' }, cookie)).statusCode).toBe(200);
const status = async (id = siteId) => (await get(ctx, `/api/sites/${id}/plugin`, alice)).json().plugin;
const createCode = (id = siteId, cookie = alice) => post(ctx, `/api/sites/${id}/plugin/pairing-code`, {}, cookie);
async function code(id = siteId): Promise<string> {
  const res = await createCode(id);
  expect(res.statusCode).toBe(201);
  return res.json().pairing.code;
}
/** The plugin calls from the WordPress server: no session and no Origin header. */
const pair = (body: { code: string; homeUrl?: string; pluginVersion?: string }) =>
  ctx.app.inject({ method: 'POST', url: '/api/plugin/pair', payload: { homeUrl: 'https://example.com', pluginVersion: '0.1.0', ...body } });
const events = async () => (await ctx.db.select().from(auditEvents)).map((e) => e.event);

describe('pairing codes', () => {
  it('creates a one-time code for a verified Pro site and stores only its hash', async () => {
    await upgrade();
    const res = await createCode();
    expect(res.statusCode).toBe(201);
    const { pairing } = res.json();
    expect(pairing.code).toMatch(/^[0-9A-HJKMNP-TV-Z]{5}-[0-9A-HJKMNP-TV-Z]{5}$/);
    expect(pairing.serviceUrl).toBe(ORIGIN);
    const minutes = (Date.parse(pairing.expiresAt) - Date.now()) / 60_000;
    expect(minutes).toBeGreaterThan(14);
    expect(minutes).toBeLessThanOrEqual(15);

    const rows = await ctx.db.select().from(pluginPairingCodes);
    expect(rows).toHaveLength(1);
    expect(JSON.stringify(rows)).not.toContain(pairing.code.replace('-', ''));
    expect(await events()).toContain('plugin_code_created');
  });

  it('replaces the unused code when a new one is created', async () => {
    await upgrade();
    const first = await code();
    const second = await code();
    expect((await pair({ code: first })).json().error).toBe('invalid_code');
    expect((await pair({ code: second })).statusCode).toBe(201);
  });

  it('needs Pro and a verified site', async () => {
    const free = await createCode();
    expect(free.statusCode).toBe(403);
    expect(free.json().error).toBe('upgrade_required');

    await upgrade();
    await ctx.db.update(sites).set({ verifiedAt: null, verificationMethod: null }).where(eq(sites.id, siteId));
    const unverified = await createCode();
    expect(unverified.statusCode).toBe(403);
    expect(unverified.json().error).toBe('not_verified');
    expect(await ctx.db.select().from(pluginPairingCodes)).toEqual([]);
  });

  it("can't be created for another user's site", async () => {
    const bob = await signedInUser(ctx, 'bob@example.com');
    await upgrade(bob);
    expect((await createCode(siteId, bob)).statusCode).toBe(404);
    expect((await get(ctx, `/api/sites/${siteId}/plugin`, bob)).statusCode).toBe(404);
  });
});

describe('pairing', () => {
  beforeEach(async () => {
    await upgrade();
  });

  it('trades a valid code for a site key that is returned once and never stored', async () => {
    expect(await status()).toEqual({ available: true, status: 'not_connected', connectedAt: null, expiresAt: null, lastReportAt: null, lastScanId: null, pluginVersion: null });

    const res = await pair({ code: await code() });
    expect(res.statusCode).toBe(201);
    const { keyId, key, expiresAt } = res.json();
    expect(keyId).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[0-9a-f]{4}-[0-9a-f]{12}$/);
    expect(key).toBe(deriveSiteKey(SECRET, keyId));
    expect((Date.parse(expiresAt) - Date.now()) / 86_400_000).toBeCloseTo(365, 0);

    const [row] = await ctx.db.select().from(pluginKeys);
    expect(row).toMatchObject({ id: keyId, siteId, keyHash: hashSiteKey(key), revokedAt: null });
    expect(JSON.stringify(row)).not.toContain(key);
    expect(await status()).toMatchObject({ status: 'connected', expiresAt, connectedAt: expect.any(String) });
    expect(await events()).toContain('plugin_paired');
  });

  it('answers unknown, used, expired and malformed codes the same way', async () => {
    const used = await code();
    expect((await pair({ code: used })).statusCode).toBe(201);
    const expired = await code();
    await ctx.db.update(pluginPairingCodes).set({ expiresAt: new Date(Date.now() - 1000) });

    const answers = await Promise.all(['ABCDE-FGHJK', used, expired, 'not a code'].map(async (c) => pair({ code: c })));
    for (const res of answers) {
      expect(res.statusCode).toBe(400);
      expect(res.json()).toEqual(answers[0]!.json());
    }
    expect(answers[0]!.json().error).toBe('invalid_code');
  });

  it('accepts a code typed in lower case or with a space', async () => {
    const typed = (await code()).toLowerCase().replace('-', ' ');
    expect((await pair({ code: typed })).statusCode).toBe(201);
  });

  it("accepts the site's www twin and refuses every other host", async () => {
    const shared = await code();
    for (const homeUrl of ['https://evil.example.org', 'https://shop.example.com', 'https://example.com.evil.org', 'not a url']) {
      const res = await pair({ code: shared, homeUrl });
      expect(res.statusCode, homeUrl).toBe(400);
      expect(res.json().error, homeUrl).toBe('site_mismatch');
    }
    expect((await pair({ code: shared, homeUrl: 'https://www.example.com/blog' })).statusCode).toBe(201);

    const wwwSite = await verifiedSite(alice, 'www.example.net');
    expect((await pair({ code: await code(wwwSite), homeUrl: 'http://example.net' })).statusCode).toBe(201);
  });

  it('refuses when the owner left Pro or the site is no longer verified', async () => {
    const pending = await code();
    expect((await post(ctx, '/api/billing/cancel', {}, alice)).statusCode).toBe(200);
    const free = await pair({ code: pending });
    expect(free.statusCode).toBe(403);
    expect(free.json().error).toBe('upgrade_required');

    await upgrade();
    await ctx.db.update(sites).set({ verifiedAt: new Date(Date.now() - 48 * 3_600_000) }).where(eq(sites.id, siteId));
    ownership.next = { ok: false, reason: 'TXT record removed' };
    const stale = await pair({ code: pending });
    expect(stale.statusCode).toBe(403);
    expect(stale.json().error).toBe('not_verified');
    expect(await ctx.db.select().from(pluginKeys)).toEqual([]);
  });

  it('revokes the previous key when the site pairs again', async () => {
    const first = (await pair({ code: await code() })).json();
    const second = (await pair({ code: await code() })).json();
    const keys = await ctx.db.select().from(pluginKeys);
    expect(keys.find((k) => k.id === first.keyId)?.revokedAt).toBeInstanceOf(Date);
    expect(keys.find((k) => k.id === second.keyId)?.revokedAt).toBeNull();
    expect(await status()).toMatchObject({ status: 'connected', expiresAt: second.expiresAt });
  });

  it('reports an expired key as expired', async () => {
    await pair({ code: await code() });
    await ctx.db.update(pluginKeys).set({ expiresAt: new Date(Date.now() - 1000) });
    expect((await status()).status).toBe('expired');
  });

  it('disconnects by revoking every key and withdrawing unused codes', async () => {
    await pair({ code: await code() });
    const pending = await code();
    const res = await del(ctx, `/api/sites/${siteId}/plugin`, alice);
    expect(res.statusCode).toBe(200);
    expect(res.json().plugin).toMatchObject({ available: true, status: 'not_connected', expiresAt: null });
    expect((await ctx.db.select().from(pluginKeys)).every((k) => k.revokedAt !== null)).toBe(true);
    expect((await pair({ code: pending })).json().error).toBe('invalid_code');
    expect(await events()).toContain('plugin_disconnected');
  });
});

describe('without PLUGIN_KEY_SECRET', () => {
  let off: TestContext;
  beforeAll(async () => {
    off = await createTestContext({ ownership });
  });
  afterAll(async () => {
    await off.close();
  });

  it('switches pairing off', async () => {
    const cookie = await signedInUser(off, 'carol@example.com');
    expect((await post(off, '/api/billing/upgrade', { plan: 'pro' }, cookie)).statusCode).toBe(200);
    const id = (await post(off, '/api/sites', { domain: 'example.org' }, cookie)).json().site.id;
    await off.db.update(sites).set({ verifiedAt: new Date(), verificationMethod: 'dns_txt' }).where(eq(sites.id, id));

    const created = await post(off, `/api/sites/${id}/plugin/pairing-code`, {}, cookie);
    expect(created.statusCode).toBe(503);
    expect(created.json().error).toBe('plugin_unavailable');
    const paired = await off.app.inject({ method: 'POST', url: '/api/plugin/pair', payload: { code: 'ABCDE-FGHJK', homeUrl: 'https://example.org', pluginVersion: '0.1.0' } });
    expect(paired.statusCode).toBe(503);
    expect((await get(off, `/api/sites/${id}/plugin`, cookie)).json().plugin).toMatchObject({ available: false, status: 'not_connected' });
  });
});
