import { Redis } from 'ioredis';
import { ConfigError, loadConfig } from '@shc/config';
import { createDb } from '@shc/db';
import { buildApp } from './app';

async function main(): Promise<void> {
  const config = loadConfig();
  const dbHandle = createDb(config.databaseUrl);
  const redis = new Redis(config.redisUrl, { maxRetriesPerRequest: 3 });

  const app = await buildApp({ config, db: dbHandle.db, redis });

  const shutdown = async (signal: string) => {
    app.log.info({ signal }, 'shutting down');
    try {
      await app.close();
      await redis.quit();
      await dbHandle.close();
      process.exit(0);
    } catch (err) {
      app.log.error({ err }, 'error during shutdown');
      process.exit(1);
    }
  };
  process.once('SIGTERM', () => void shutdown('SIGTERM'));
  process.once('SIGINT', () => void shutdown('SIGINT'));

  await app.listen({ host: config.api.host, port: config.api.port });
}

main().catch((err) => {
  console.error(err instanceof ConfigError ? err.message : err);
  process.exit(1);
});
