import { eq, sql } from 'drizzle-orm';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import type { ScanQueue } from '@shc/core';
import { createDb, scans, sites, subscriptions, users, type DbHandle } from '@shc/db';
import type { OwnershipChecker, OwnershipResult } from '@shc/net';
import { scheduleDueScans } from '../src/weekly-scans';
import { workerTestDbUrl } from './global-setup';

let handle: DbHandle;
const enqueued: string[] = [];
const queue: ScanQueue = { enqueue: async (id) => void enqueued.push(id), close: async () => {} };
let ownershipResult: OwnershipResult = { ok: true, detail: 'ok' };
const ownership: OwnershipChecker = { check: async () => ownershipResult };

async function site(opts: { plan: 'free' | 'pro'; dueHoursAgo?: number; verifiedHoursAgo?: number }) {
  const [user] = await handle.db.insert(users).values({ email: `u${Math.random()}@example.com`, passwordHash: 'x' }).returning();
  await handle.db.insert(subscriptions).values({ userId: user!.id, plan: opts.plan, status: 'active' });
  const [s] = await handle.db
    .insert(sites)
    .values({
      ownerId: user!.id,
      domain: 'example.com',
      verificationToken: 't'.repeat(32),
      verificationMethod: 'dns_txt',
      verifiedAt: new Date(Date.now() - (opts.verifiedHoursAgo ?? 1) * 3600_000),
      weeklyScan: true,
      nextScanAt: new Date(Date.now() - (opts.dueHoursAgo ?? 1) * 3600_000),
    })
    .returning();
  return s!;
}

const reload = async (id: string) => (await handle.db.select().from(sites).where(eq(sites.id, id)))[0]!;
const run = () => scheduleDueScans(handle.db, { ownership, queue, cooldownMinutes: 15 });

beforeAll(() => {
  handle = createDb(workerTestDbUrl(), { max: 3 });
});
afterAll(async () => {
  await handle.close();
});
beforeEach(async () => {
  await handle.db.execute(sql`truncate table users restart identity cascade`);
  enqueued.length = 0;
  ownershipResult = { ok: true, detail: 'ok' };
});

describe('scheduleDueScans', () => {
  it('queues due weekly scans for Pro sites and books the next one a week out', async () => {
    const s = await site({ plan: 'pro' });
    expect(await run()).toEqual({ queued: 1, skipped: 0, disabled: 0 });
    const [scan] = await handle.db.select().from(scans).where(eq(scans.siteId, s.id));
    expect(scan).toMatchObject({ trigger: 'scheduled', status: 'queued', requestedBy: s.ownerId });
    expect(enqueued).toEqual([scan!.id]);
    const next = (await reload(s.id)).nextScanAt!.getTime();
    expect((next - Date.now()) / 86_400_000).toBeGreaterThan(6.9);
  });

  it('leaves sites alone until they are due', async () => {
    await site({ plan: 'pro', dueHoursAgo: -5 });
    expect(await run()).toEqual({ queued: 0, skipped: 0, disabled: 0 });
  });

  it('switches weekly scans off when the owner is no longer on Pro', async () => {
    const s = await site({ plan: 'free' });
    expect(await run()).toMatchObject({ disabled: 1 });
    expect(await reload(s.id)).toMatchObject({ weeklyScan: false, nextScanAt: null });
    expect(enqueued).toEqual([]);
  });

  it('still re-verifies ownership, and retries tomorrow if it fails', async () => {
    const s = await site({ plan: 'pro', verifiedHoursAgo: 30 });
    ownershipResult = { ok: false, reason: 'record removed' };
    expect(await run()).toMatchObject({ skipped: 1, queued: 0 });
    const hours = ((await reload(s.id)).nextScanAt!.getTime() - Date.now()) / 3600_000;
    expect(hours).toBeGreaterThan(23);
    expect(hours).toBeLessThan(25);
  });

  it('retries in an hour when a scan is already running', async () => {
    const s = await site({ plan: 'pro' });
    await handle.db.insert(scans).values({ siteId: s.id, kind: 'external', trigger: 'manual', status: 'running' });
    expect(await run()).toMatchObject({ skipped: 1 });
    const minutes = ((await reload(s.id)).nextScanAt!.getTime() - Date.now()) / 60_000;
    expect(minutes).toBeGreaterThan(55);
    expect(minutes).toBeLessThan(65);
  });
});
