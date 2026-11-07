import { Worker } from 'bullmq';
import { sql } from 'drizzle-orm';
import { Redis } from 'ioredis';
import { pino } from 'pino';
import { ConfigError, loadConfig } from '@shc/config';
import { markScanFailed, redisConnection, SCAN_QUEUE, type ScanJobData } from '@shc/core';
import { createDb } from '@shc/db';
import { DbReleaseLookup, DbVulnLookup } from '@shc/intel';
import { createTxtResolver, OwnershipVerifier, SafeFetcher, TlsProber } from '@shc/net';
import { RedisRateLimiter } from '@shc/scanner';
import { startIntelJobs } from './intel-jobs';
import { failStuckScans, processScan, type ProcessDeps } from './process-scan';

async function main(): Promise<void> {
  const config = loadConfig();
  const log = pino({ level: config.logLevel, base: { service: 'worker' } });
  const dbHandle = createDb(config.databaseUrl, { max: config.scan.concurrency + 2 });
  const redis = new Redis(config.redisUrl, { maxRetriesPerRequest: null });

  await dbHandle.db.execute(sql`select 1`);
  await redis.ping();

  const fetcher = new SafeFetcher({ userAgent: config.scanner.userAgent, allowPrivateHosts: config.scanner.allowPrivateHosts });
  const deps: ProcessDeps = {
    db: dbHandle.db,
    ownership: new OwnershipVerifier({ fetcher, resolveTxt: createTxtResolver({ servers: config.scanner.dnsResolvers }) }),
    fetcher,
    // Shared through Redis, so all workers together stay under the per-site limit. The
    // 50 ms margin absorbs network jitter so the target never sees more than the promise.
    limiter: new RedisRateLimiter(redis, Math.ceil(1000 / config.scan.ratePerSecond) + 50),
    vulns: new DbVulnLookup(dbHandle.db),
    releases: new DbReleaseLookup(dbHandle.db),
    // Same SSRF policy as HTTP: only vetted public addresses, pinned for the handshake.
    tlsProbe: new TlsProber(fetcher),
    scan: config.scan,
    log,
  };

  const intel = await startIntelJobs({ db: dbHandle.db, config, connection: redisConnection(config.redisUrl), log });

  const worker = new Worker<ScanJobData>(SCAN_QUEUE, async (job) => processScan(job.data.scanId, deps), {
    connection: redisConnection(config.redisUrl),
    concurrency: config.scan.concurrency,
  });
  worker.on('failed', (job, err) => {
    log.error({ jobId: job?.id, err }, 'scan job failed');
    if (job) void markScanFailed(dbHandle.db, job.data.scanId, 'The scan stopped because of an internal error. Please try again later.');
  });
  worker.on('error', (err) => log.error({ err }, 'worker error'));

  // Clean up after crashed workers: anything running well past the time limit is dead.
  const sweep = async () => {
    try {
      const n = await failStuckScans(dbHandle.db, { runningMinutes: Math.ceil(config.scan.timeoutSeconds / 60) + 5, queuedMinutes: 60 });
      if (n > 0) log.warn({ count: n }, 'failed stuck scans');
    } catch (err) {
      log.error({ err }, 'sweep failed');
    }
  };
  await sweep();
  const sweeper = setInterval(() => void sweep(), 2 * 60_000);

  log.info({ concurrency: config.scan.concurrency, ratePerSecond: config.scan.ratePerSecond, maxRequests: config.scan.maxRequests }, 'worker ready');

  const shutdown = async (signal: string) => {
    log.info({ signal }, 'shutting down');
    clearInterval(sweeper);
    await worker.close().catch(() => undefined);
    await intel.close().catch(() => undefined);
    await redis.quit().catch(() => undefined);
    await dbHandle.close().catch(() => undefined);
    process.exit(0);
  };
  process.once('SIGTERM', () => void shutdown('SIGTERM'));
  process.once('SIGINT', () => void shutdown('SIGINT'));
}

main().catch((err) => {
  console.error(err instanceof ConfigError ? err.message : err);
  process.exit(1);
});
