import { eq } from 'drizzle-orm';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { auditEvents, findings, scans, siteComponents, sites } from '@shc/db';
import { createTestContext, FakeOwnership, FakeQueue, get, post, resetState, signedInUser, type TestContext } from './helpers';

const ownership = new FakeOwnership();
const queue = new FakeQueue();
let ctx: TestContext;
let alice: string;
let siteId: string;

beforeAll(async () => {
  ctx = await createTestContext({ ownership, scanQueue: queue });
});
afterAll(async () => {
  await ctx.close();
});
beforeEach(async () => {
  await resetState(ctx);
  ownership.calls = [];
  ownership.next = { ok: true, detail: 'ok' };
  queue.enqueued = [];
  alice = await signedInUser(ctx, 'alice@example.com');
  siteId = (await post(ctx, '/api/sites', { domain: 'example.com' }, alice)).json().site.id;
});

async function verify(hoursAgo = 0) {
  await ctx.db
    .update(sites)
    .set({ verifiedAt: new Date(Date.now() - hoursAgo * 3600_000), verificationMethod: 'dns_txt' })
    .where(eq(sites.id, siteId));
}

const startScan = (cookie = alice) => post(ctx, `/api/sites/${siteId}/scans`, {}, cookie);

describe('starting a scan', () => {
  it('refuses until ownership is verified, without queueing anything', async () => {
    const res = await startScan();
    expect(res.statusCode).toBe(403);
    expect(res.json().error).toBe('ownership_not_verified');
    expect(queue.enqueued).toEqual([]);
    expect(await ctx.db.select().from(scans)).toEqual([]);
  });

  it('queues a scan for a verified site', async () => {
    await verify();
    const res = await startScan();
    expect(res.statusCode).toBe(202);
    const scan = res.json().scan;
    expect(scan).toMatchObject({ siteId, status: 'queued', trigger: 'manual', requestCount: 0 });
    expect(queue.enqueued).toEqual([scan.id]);
    expect((await ctx.db.select().from(auditEvents)).map((e) => e.event)).toContain('scan_requested');
  });

  it('re-verifies ownership older than 24 hours before queueing', async () => {
    await verify(30);
    expect((await startScan()).statusCode).toBe(202);
    expect(ownership.calls).toHaveLength(1);

    ownership.calls = [];
    await ctx.db.delete(scans);
    await verify(30);
    ownership.next = { ok: false, reason: 'TXT record removed' };
    const refused = await startScan();
    expect(refused.statusCode).toBe(403);
    expect(refused.json().message).toMatch(/TXT record removed/);
  });

  it('allows only one active scan per site', async () => {
    await verify();
    await startScan();
    const second = await startScan();
    expect(second.statusCode).toBe(409);
    expect(second.json().error).toBe('scan_in_progress');
    expect(queue.enqueued).toHaveLength(1);
  });

  it('enforces a cooldown between scans and says when to retry', async () => {
    await verify();
    const first = (await startScan()).json().scan;
    await ctx.db.update(scans).set({ status: 'completed' }).where(eq(scans.id, first.id));
    const again = await startScan();
    expect(again.statusCode).toBe(429);
    expect(again.json().error).toBe('scan_cooldown');
    expect(Number(again.headers['retry-after'])).toBeGreaterThan(0);
  });

  it('does not count failed scans towards the cooldown', async () => {
    await verify();
    const first = (await startScan()).json().scan;
    await ctx.db.update(scans).set({ status: 'failed' }).where(eq(scans.id, first.id));
    expect((await startScan()).statusCode).toBe(202);
  });

  it('marks the scan failed if it cannot be queued', async () => {
    await verify();
    queue.failNext = true;
    const res = await startScan();
    expect(res.statusCode).toBe(503);
    const [row] = await ctx.db.select().from(scans);
    expect(row!.status).toBe('failed');
  });

  it("does not let one user scan another user's site", async () => {
    await verify();
    const bob = await signedInUser(ctx, 'bob@example.com');
    expect((await startScan(bob)).statusCode).toBe(404);
    expect(queue.enqueued).toEqual([]);
  });
});

describe('reading scans', () => {
  async function completedScan() {
    await verify();
    const scanId = (await startScan()).json().scan.id as string;
    await ctx.db
      .update(scans)
      .set({
        status: 'completed',
        requestCount: 7,
        baseUrl: 'https://example.com',
        moduleResults: [{ module: 'wp-detect', status: 'ok', durationMs: 120, requests: 2, findings: 1 }],
      })
      .where(eq(scans.id, scanId));
    const [component] = await ctx.db
      .insert(siteComponents)
      .values({ scanId, siteId, softwareType: 'core', slug: 'wordpress', name: 'WordPress', version: '6.4.2', versionConfidence: 'confirmed' })
      .returning();
    const base = { scanId, checkId: 'x.y', explanation: 'e', fixSteps: 'f', componentId: component!.id };
    await ctx.db.insert(findings).values([
      { ...base, conceptId: 'exposure/known-vulnerable-component', severity: 'critical', title: 'Secret detail A' },
      { ...base, conceptId: 'exposure/wordpress-version-disclosed', severity: 'low', title: 'Secret detail B' },
      { ...base, conceptId: 'exposure/component-versions-disclosed', severity: 'low', title: 'Secret detail C' },
    ]);
    return scanId;
  }

  it('lists scans for a site with counts by severity', async () => {
    const scanId = await completedScan();
    const res = await get(ctx, `/api/sites/${siteId}/scans`, alice);
    expect(res.statusCode).toBe(200);
    expect(res.json().scans).toEqual([
      expect.objectContaining({ id: scanId, status: 'completed', findingCounts: { critical: 1, high: 0, medium: 0, low: 2, info: 0 } }),
    ]);
  });

  it('says which kind of scan each one is', async () => {
    await ctx.db.update(sites).set({ verifiedAt: new Date(), verificationMethod: 'dns_txt' }).where(eq(sites.id, siteId));
    await post(ctx, '/api/billing/upgrade', { plan: 'pro' }, alice);
    const external = (await startScan()).json().scan;
    expect(external.kind).toBe('external');
    const [inside] = await ctx.db.insert(scans).values({ siteId, kind: 'inside', trigger: 'plugin', status: 'queued' }).returning();
    const listed = (await get(ctx, `/api/sites/${siteId}/scans`, alice)).json().scans;
    expect(listed.map((s: { id: string; kind: string; trigger: string }) => [s.id, s.kind, s.trigger])).toEqual([
      [inside!.id, 'inside', 'plugin'],
      [external.id, 'external', 'manual'],
    ]);
  });

  it('shows scan details with detected software, without exposing finding details yet', async () => {
    const scanId = await completedScan();
    const res = await get(ctx, `/api/scans/${scanId}`, alice);
    expect(res.statusCode).toBe(200);
    const scan = res.json().scan;
    expect(scan).toMatchObject({
      domain: 'example.com',
      requestCount: 7,
      components: [{ type: 'core', slug: 'wordpress', name: 'WordPress', version: '6.4.2', versionConfidence: 'confirmed' }],
      modules: [expect.objectContaining({ module: 'wp-detect', status: 'ok' })],
    });
    // Finding titles and details arrive with the report phase's free/paid rules.
    expect(res.body).not.toContain('Secret detail');
  });

  it("hides other users' scans", async () => {
    const scanId = await completedScan();
    const bob = await signedInUser(ctx, 'bob@example.com');
    expect((await get(ctx, `/api/scans/${scanId}`, bob)).statusCode).toBe(404);
    expect((await get(ctx, `/api/sites/${siteId}/scans`, bob)).statusCode).toBe(404);
  });
});
