import { Queue, Worker, type ConnectionOptions } from 'bullmq';
import { and, eq, gt, sql } from 'drizzle-orm';
import type { Config } from '@shc/config';
import { softwareReleases, vulnSyncRuns, type Database } from '@shc/db';
import { NvdAdapter, OsvAdapter, runIntelRefresh, WordfenceAdapter, type IntelLogger, type VulnSourceAdapter } from '@shc/intel';

export const INTEL_QUEUE = 'intel';

export function intelAdapters(config: Config): VulnSourceAdapter[] {
  return [
    new WordfenceAdapter({ apiKey: config.intel.wordfenceApiKey ?? undefined }),
    new NvdAdapter({ apiKey: config.intel.nvdApiKey ?? undefined }),
    new OsvAdapter(),
  ];
}

/** True when the cache is empty or older than a day, so a fresh install doesn't wait for 03:17. */
async function needsRefresh(db: Database): Promise<boolean> {
  const dayAgo = sql`now() - interval '1 day'`;
  const [core] = await db
    .select({ n: sql<number>`count(*)::int` })
    .from(softwareReleases)
    .where(and(eq(softwareReleases.softwareType, 'core'), gt(softwareReleases.fetchedAt, dayAgo)));
  const [runs] = await db
    .select({ n: sql<number>`count(*)::int` })
    .from(vulnSyncRuns)
    .where(and(eq(vulnSyncRuns.status, 'ok'), gt(vulnSyncRuns.startedAt, dayAgo)));
  return (core?.n ?? 0) === 0 || (runs?.n ?? 0) === 0;
}

/**
 * Daily intelligence refresh as a BullMQ job scheduler, so exactly one run happens per
 * day however many workers are running.
 */
export async function startIntelJobs(opts: { db: Database; config: Config; connection: ConnectionOptions; log: IntelLogger & { error(o: object, m?: string): void } }) {
  const { db, config, connection, log } = opts;
  const queue = new Queue(INTEL_QUEUE, { connection });
  await queue.upsertJobScheduler(
    'daily-intel-refresh',
    { pattern: config.intel.refreshCron, tz: 'UTC' },
    { name: 'refresh', data: {}, opts: { removeOnComplete: 50, removeOnFail: 50 } },
  );

  const adapters = intelAdapters(config);
  const worker = new Worker(
    INTEL_QUEUE,
    async () => {
      const result = await runIntelRefresh(db, adapters, { log });
      log.info({ result }, 'intel refresh finished');
      return result;
    },
    { connection, concurrency: 1 },
  );
  worker.on('failed', (job, err) => log.error({ jobId: job?.id, err }, 'intel refresh failed'));

  if (await needsRefresh(db)) {
    await queue.add('refresh', {}, { jobId: `intel-startup-${new Date().toISOString().slice(0, 10)}`, removeOnComplete: 50, removeOnFail: 50 });
    log.info({}, 'intel cache is stale or empty; refresh queued');
  }

  return {
    close: async () => {
      await worker.close();
      await queue.close();
    },
  };
}
