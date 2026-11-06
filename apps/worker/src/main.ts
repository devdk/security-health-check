import { sql } from 'drizzle-orm';
import { Redis } from 'ioredis';
import { pino } from 'pino';
import { ConfigError, loadConfig } from '@shc/config';
import { createDb } from '@shc/db';

/**
 * Phase 1 skeleton: proves the worker can boot with validated config and reach Postgres
 * and Redis. Queues, the rate-limited HTTP client and check modules arrive in Phase 3.
 */
async function main(): Promise<void> {
  const config = loadConfig();
  const log = pino({ level: config.logLevel, base: { service: 'worker' } });
  const dbHandle = createDb(config.databaseUrl, { max: 5 });
  const redis = new Redis(config.redisUrl, { maxRetriesPerRequest: null });

  await dbHandle.db.execute(sql`select 1`);
  await redis.ping();
  log.info('worker ready (no job processors registered yet)');

  const shutdown = async (signal: string) => {
    log.info({ signal }, 'shutting down');
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
