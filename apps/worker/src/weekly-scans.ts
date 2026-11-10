import { Queue, Worker, type ConnectionOptions } from 'bullmq';
import { and, eq, lte, sql } from 'drizzle-orm';
import { audit, createScanRequest, type ScanQueue } from '@shc/core';
import { sites, subscriptions, type Database } from '@shc/db';
import type { OwnershipChecker } from '@shc/net';
import { effectivePlan } from '@shc/shared';

export const SCHEDULE_QUEUE = 'schedules';
const WEEK = "interval '7 days'";

export interface WeeklyResult {
  queued: number;
  skipped: number;
  disabled: number;
}

/**
 * Queues the weekly scans that are due. Every rule of a manual scan still applies:
 * ownership is re-verified, one scan at a time per site, and the cooldown holds.
 * Sites whose owner is no longer on Pro have weekly scans switched off.
 */
export async function scheduleDueScans(
  db: Database,
  deps: { ownership: OwnershipChecker; queue: ScanQueue; cooldownMinutes: number; limit?: number },
): Promise<WeeklyResult> {
  const due = await db
    .select({ id: sites.id, ownerId: sites.ownerId, plan: subscriptions.plan, status: subscriptions.status })
    .from(sites)
    .innerJoin(subscriptions, eq(subscriptions.userId, sites.ownerId))
    .where(and(eq(sites.weeklyScan, true), lte(sites.nextScanAt, sql`now()`)))
    .orderBy(sites.nextScanAt)
    .limit(deps.limit ?? 50);

  const result: WeeklyResult = { queued: 0, skipped: 0, disabled: 0 };
  for (const site of due) {
    if (effectivePlan(site.plan, site.status) !== 'pro') {
      await db.update(sites).set({ weeklyScan: false, nextScanAt: null }).where(eq(sites.id, site.id));
      await audit(db, { event: 'weekly_scan_changed', userId: site.ownerId, siteId: site.id, meta: { enabled: false, reason: 'plan' } });
      result.disabled++;
      continue;
    }

    const request = await createScanRequest(db, deps.ownership, {
      siteId: site.id,
      requestedBy: site.ownerId,
      trigger: 'scheduled',
      cooldownMinutes: deps.cooldownMinutes,
    });
    let next = sql.raw(`now() + ${WEEK}`);
    if (request.ok) {
      await deps.queue.enqueue(request.scan.id);
      result.queued++;
    } else {
      // Busy or cooling down: try again in an hour. Ownership failed: try again tomorrow.
      next = sql.raw(request.code === 'not_verified' ? "now() + interval '1 day'" : "now() + interval '1 hour'");
      await audit(db, { event: 'scheduled_scan_skipped', userId: site.ownerId, siteId: site.id, meta: { reason: request.code } });
      result.skipped++;
    }
    await db.update(sites).set({ nextScanAt: next }).where(eq(sites.id, site.id));
  }
  return result;
}

/** Checks for due weekly scans every 10 minutes; BullMQ makes sure only one worker runs each check. */
export async function startWeeklyScans(opts: {
  db: Database;
  connection: ConnectionOptions;
  ownership: OwnershipChecker;
  queue: ScanQueue;
  cooldownMinutes: number;
  log: { info(o: object, m?: string): void; error(o: object, m?: string): void };
}) {
  const queue = new Queue(SCHEDULE_QUEUE, { connection: opts.connection });
  await queue.upsertJobScheduler('weekly-scans', { every: 10 * 60_000 }, { name: 'weekly-scans', data: {}, opts: { removeOnComplete: 20, removeOnFail: 20 } });
  const worker = new Worker(
    SCHEDULE_QUEUE,
    async () => {
      const result = await scheduleDueScans(opts.db, opts);
      if (result.queued + result.skipped + result.disabled > 0) opts.log.info({ result }, 'weekly scans checked');
      return result;
    },
    { connection: opts.connection, concurrency: 1 },
  );
  worker.on('failed', (job, err) => opts.log.error({ jobId: job?.id, err }, 'weekly scan check failed'));
  return {
    close: async () => {
      await worker.close();
      await queue.close();
    },
  };
}
