import { eq } from 'drizzle-orm';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { ensureFreshVerification } from '@shc/core';
import { auditEvents, sites, subscriptions } from '@shc/db';
import { SITE_LIMITS } from '@shc/shared';
import { createTestContext, del, FakeOwnership, get, post, resetState, signedInUser, type TestContext } from './helpers';

const ownership = new FakeOwnership();
let ctx: TestContext;
let alice: string;

beforeAll(async () => {
  ctx = await createTestContext({ ownership });
});
afterAll(async () => {
  await ctx.close();
});
beforeEach(async () => {
  await resetState(ctx);
  ownership.calls = [];
  ownership.next = { ok: true, detail: 'TXT record found at _shc-verify.example.com' };
  alice = await signedInUser(ctx, 'alice@example.com');
});

async function addSite(cookie: string, domain = 'example.com') {
  const res = await post(ctx, '/api/sites', { domain }, cookie);
  expect(res.statusCode).toBe(201);
  return res.json().site as { id: string; domain: string; status: string; instructions: { dns: { name: string; value: string }; file: { url: string } } };
}

const events = async () => (await ctx.db.select().from(auditEvents)).map((e) => e.event);

describe('site management', () => {
  it('requires a signed-in user', async () => {
    expect((await get(ctx, '/api/sites')).statusCode).toBe(401);
    expect((await post(ctx, '/api/sites', { domain: 'example.com' })).statusCode).toBe(401);
  });

  it('normalises the domain and returns verification instructions', async () => {
    const site = await addSite(alice, 'https://WWW.Example.com/blog/');
    expect(site.domain).toBe('www.example.com');
    expect(site.status).toBe('unverified');
    expect(site.instructions.dns.name).toBe('_shc-verify.www.example.com');
    expect(site.instructions.dns.value).toMatch(/^shc-verify=[0-9a-f]{32}$/);
    expect(site.instructions.file.url).toMatch(/^https:\/\/www\.example\.com\/shc-verify-[0-9a-f]{32}\.txt$/);

    const list = await get(ctx, '/api/sites', alice);
    expect(list.json().sites.map((s: { domain: string }) => s.domain)).toEqual(['www.example.com']);
    expect(await events()).toContain('site_added');
  });

  it.each(['10.0.0.1', 'localhost', 'example.com:8080', 'intranet.local', 'not a domain'])('rejects %s with a clear reason', async (domain) => {
    const res = await post(ctx, '/api/sites', { domain }, alice);
    expect(res.statusCode).toBe(400);
    expect(res.json().error).toBe('invalid_domain');
    expect(res.json().message.length).toBeGreaterThan(10);
  });

  it('refuses the same domain twice for one owner', async () => {
    await addSite(alice);
    const again = await post(ctx, '/api/sites', { domain: 'EXAMPLE.com' }, alice);
    expect(again.statusCode).toBe(409);
    expect(again.json().error).toBe('site_exists');
  });

  it('lets two different owners each add (and separately verify) the same domain', async () => {
    const bob = await signedInUser(ctx, 'bob@example.com');
    const a = await addSite(alice);
    const b = await addSite(bob);
    expect(a.id).not.toBe(b.id);
    expect(a.instructions.dns.value).not.toBe(b.instructions.dns.value);
  });

  it(`enforces the free plan limit of ${SITE_LIMITS.free} sites`, async () => {
    for (let i = 0; i < SITE_LIMITS.free; i++) await addSite(alice, `site${i}.example.com`);
    const over = await post(ctx, '/api/sites', { domain: 'one-too-many.example.com' }, alice);
    expect(over.statusCode).toBe(403);
    expect(over.json().error).toBe('site_limit_reached');
  });

  it('applies the higher limit to active paid plans', async () => {
    const [user] = await ctx.db.select().from(subscriptions);
    await ctx.db.update(subscriptions).set({ plan: 'pro', status: 'active' }).where(eq(subscriptions.id, user!.id));
    for (let i = 0; i <= SITE_LIMITS.free; i++) await addSite(alice, `site${i}.example.com`);
  });

  it('deletes a site', async () => {
    const site = await addSite(alice);
    expect((await del(ctx, `/api/sites/${site.id}`, alice)).statusCode).toBe(204);
    expect((await get(ctx, `/api/sites/${site.id}`, alice)).statusCode).toBe(404);
    expect(await events()).toContain('site_deleted');
  });

  it('validates site ids', async () => {
    expect((await get(ctx, '/api/sites/not-a-uuid', alice)).statusCode).toBe(400);
  });
});

describe('isolation between accounts', () => {
  it("hides another owner's site completely", async () => {
    const site = await addSite(alice);
    const bob = await signedInUser(ctx, 'bob@example.com');

    expect((await get(ctx, '/api/sites', bob)).json().sites).toEqual([]);
    expect((await get(ctx, `/api/sites/${site.id}`, bob)).statusCode).toBe(404);
    expect((await post(ctx, `/api/sites/${site.id}/verify`, { method: 'dns_txt' }, bob)).statusCode).toBe(404);
    expect((await del(ctx, `/api/sites/${site.id}`, bob)).statusCode).toBe(404);
    expect(ownership.calls).toHaveLength(0);
    expect(await ctx.db.select().from(sites)).toHaveLength(1);
  });
});

describe('ownership verification', () => {
  it('marks the site verified when the check passes', async () => {
    const site = await addSite(alice);
    const res = await post(ctx, `/api/sites/${site.id}/verify`, { method: 'dns_txt' }, alice);
    expect(res.statusCode).toBe(200);
    const body = res.json();
    expect(body.verified).toBe(true);
    expect(body.site.status).toBe('verified');
    expect(body.site.verificationMethod).toBe('dns_txt');
    expect(body.site.lastVerifyError).toBeNull();

    const [row] = await ctx.db.select().from(sites);
    expect(ownership.calls).toEqual([{ method: 'dns_txt', domain: 'example.com', token: row!.verificationToken }]);
    expect(await events()).toContain('site_verified');
  });

  it('records the reason when the check fails', async () => {
    const site = await addSite(alice);
    ownership.next = { ok: false, reason: 'No matching TXT record at _shc-verify.example.com yet.' };
    const res = await post(ctx, `/api/sites/${site.id}/verify`, { method: 'file' }, alice);
    expect(res.json()).toMatchObject({
      verified: false,
      message: 'No matching TXT record at _shc-verify.example.com yet.',
      site: { status: 'unverified', verificationMethod: null, lastVerifyError: 'No matching TXT record at _shc-verify.example.com yet.' },
    });
    expect(await events()).toContain('site_verify_failed');
  });

  it('keeps an earlier success when a later attempt fails', async () => {
    const site = await addSite(alice);
    await post(ctx, `/api/sites/${site.id}/verify`, { method: 'dns_txt' }, alice);
    ownership.next = { ok: false, reason: 'file missing' };
    const res = await post(ctx, `/api/sites/${site.id}/verify`, { method: 'file' }, alice);
    expect(res.json().site).toMatchObject({ status: 'verified', verificationMethod: 'dns_txt', lastVerifyError: 'file missing' });
  });

  it('only accepts the two supported methods', async () => {
    const site = await addSite(alice);
    const res = await post(ctx, `/api/sites/${site.id}/verify`, { method: 'email' }, alice);
    expect(res.statusCode).toBe(400);
  });

  it('rate-limits verification attempts per user', async () => {
    const site = await addSite(alice);
    const statuses: number[] = [];
    for (let i = 0; i < 11; i++) statuses.push((await post(ctx, `/api/sites/${site.id}/verify`, { method: 'dns_txt' }, alice)).statusCode);
    expect(statuses.slice(0, 10).every((s) => s === 200)).toBe(true);
    expect(statuses[10]).toBe(429);
  });
});

describe('re-verification before scans (rule 1)', () => {
  async function verifiedSite(hoursAgo: number) {
    const site = await addSite(alice);
    await ctx.db
      .update(sites)
      .set({ verifiedAt: new Date(Date.now() - hoursAgo * 3600_000), verificationMethod: 'dns_txt' })
      .where(eq(sites.id, site.id));
    ownership.calls = [];
    return site.id;
  }

  it('refuses a site that was never verified, without checking', async () => {
    const site = await addSite(alice);
    const res = await ensureFreshVerification(ctx.db, ownership, site.id);
    expect(res.ok).toBe(false);
    expect(ownership.calls).toHaveLength(0);
  });

  it('accepts a check from the last 24 hours without re-checking', async () => {
    const id = await verifiedSite(2);
    const res = await ensureFreshVerification(ctx.db, ownership, id);
    expect(res).toMatchObject({ ok: true, rechecked: false });
    expect(ownership.calls).toHaveLength(0);
  });

  it('re-checks with the stored method once 24 hours have passed', async () => {
    const id = await verifiedSite(25);
    const res = await ensureFreshVerification(ctx.db, ownership, id);
    expect(res).toMatchObject({ ok: true, rechecked: true });
    expect(ownership.calls.map((c) => c.method)).toEqual(['dns_txt']);
    const [row] = await ctx.db.select().from(sites).where(eq(sites.id, id));
    expect(Date.now() - row!.verifiedAt!.getTime()).toBeLessThan(60_000);
    expect(await events()).toContain('site_reverified');
  });

  it('blocks the scan when the re-check fails', async () => {
    const id = await verifiedSite(25);
    ownership.next = { ok: false, reason: 'TXT record removed' };
    const res = await ensureFreshVerification(ctx.db, ownership, id);
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.reason).toMatch(/TXT record removed/);
    expect(await events()).toContain('site_reverify_failed');
  });
});
