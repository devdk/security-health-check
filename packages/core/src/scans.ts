import { and, desc, eq, inArray, ne } from 'drizzle-orm';
import { Queue, type ConnectionOptions } from 'bullmq';
import { scans, type Database } from '@shc/db';
import type { OwnershipChecker } from '@shc/net';
import type { ScanTrigger } from '@shc/shared';
import { audit } from './audit';
import { ensureFreshVerification } from './verification';

export const SCAN_QUEUE = 'scans';

export interface ScanJobData {
  scanId: string;
}

/** Hands a scan to the workers. The API never scans directly. */
export interface ScanQueue {
  enqueue(scanId: string): Promise<void>;
  close(): Promise<void>;
}

export class BullScanQueue implements ScanQueue {
  private readonly queue: Queue<ScanJobData>;

  constructor(connection: ConnectionOptions) {
    this.queue = new Queue<ScanJobData>(SCAN_QUEUE, { connection });
  }

  async enqueue(scanId: string): Promise<void> {
    // jobId = scanId makes a duplicate enqueue a no-op. Scans are not retried
    // automatically: a retry would hit the customer's site again without being asked.
    await this.queue.add('scan', { scanId }, { jobId: scanId, attempts: 1, removeOnComplete: 1000, removeOnFail: 1000 });
  }

  close(): Promise<void> {
    return this.queue.close();
  }
}

type ScanRow = typeof scans.$inferSelect;

export type ScanRequestResult =
  | { ok: true; scan: ScanRow }
  | { ok: false; code: 'not_verified' | 'in_progress' | 'cooldown'; message: string; retryAfterSeconds?: number };

function isUniqueViolation(err: unknown): boolean {
  const e = err as { code?: string; cause?: { code?: string } };
  return e?.code === '23505' || e?.cause?.code === '23505';
}

/**
 * Creates a queued scan if, and only if, the product's rules allow it:
 * 1. ownership is verified, re-checked when older than 24 hours;
 * 2. no other scan of the site is queued or running;
 * 3. the previous scan was at least `cooldownMinutes` ago, so we never hammer a site.
 */
export async function createScanRequest(
  db: Database,
  checker: OwnershipChecker,
  input: { siteId: string; requestedBy: string | null; trigger: ScanTrigger; cooldownMinutes: number; ip?: string | null },
): Promise<ScanRequestResult> {
  const fresh = await ensureFreshVerification(db, checker, input.siteId);
  if (!fresh.ok) return { ok: false, code: 'not_verified', message: fresh.reason };

  const external = and(eq(scans.siteId, input.siteId), eq(scans.kind, 'external'));
  const [active] = await db
    .select({ id: scans.id })
    .from(scans)
    .where(and(external, inArray(scans.status, ['queued', 'running'])))
    .limit(1);
  if (active) return { ok: false, code: 'in_progress', message: 'A scan of this site is already running.' };

  if (input.cooldownMinutes > 0) {
    const [last] = await db
      .select({ createdAt: scans.createdAt })
      .from(scans)
      .where(and(external, ne(scans.status, 'failed')))
      .orderBy(desc(scans.createdAt))
      .limit(1);
    if (last) {
      const readyAt = last.createdAt.getTime() + input.cooldownMinutes * 60_000;
      const wait = Math.ceil((readyAt - Date.now()) / 1000);
      if (wait > 0) {
        return {
          ok: false,
          code: 'cooldown',
          retryAfterSeconds: wait,
          message: `To keep scans gentle on your site, you can scan again in ${Math.ceil(wait / 60)} minute${wait > 60 ? 's' : ''}.`,
        };
      }
    }
  }

  try {
    const [scan] = await db
      .insert(scans)
      .values({ siteId: input.siteId, requestedBy: input.requestedBy, kind: 'external', trigger: input.trigger, status: 'queued' })
      .returning();
    await audit(db, { event: 'scan_requested', userId: input.requestedBy, siteId: input.siteId, ip: input.ip, meta: { scanId: scan!.id, trigger: input.trigger } });
    return { ok: true, scan: scan! };
  } catch (err) {
    if (isUniqueViolation(err)) return { ok: false, code: 'in_progress', message: 'A scan of this site is already running.' };
    throw err;
  }
}

export async function markScanFailed(db: Database, scanId: string, reason: string): Promise<void> {
  await db
    .update(scans)
    .set({ status: 'failed', error: reason.slice(0, 500), finishedAt: new Date() })
    .where(and(eq(scans.id, scanId), inArray(scans.status, ['queued', 'running'])));
}

/** Turns a redis:// URL into BullMQ connection options. */
export function redisConnection(url: string): ConnectionOptions {
  const u = new URL(url);
  const db = u.pathname.length > 1 ? Number(u.pathname.slice(1)) : 0;
  return {
    host: u.hostname,
    port: u.port ? Number(u.port) : 6379,
    username: u.username ? decodeURIComponent(u.username) : undefined,
    password: u.password ? decodeURIComponent(u.password) : undefined,
    db: Number.isInteger(db) ? db : 0,
    ...(u.protocol === 'rediss:' ? { tls: {} } : {}),
    maxRetriesPerRequest: null,
  };
}
