import { pino } from 'pino';
import { ConfigError, loadConfig } from '@shc/config';
import { createDb } from '@shc/db';
import { runIntelRefresh } from '@shc/intel';
import { intelAdapters } from './intel-jobs';

// npm run intel:sync -w @shc/worker : run the daily refresh once, now.
try {
  const config = loadConfig();
  const log = pino({ level: config.logLevel, base: { service: 'intel-sync' } });
  const handle = createDb(config.databaseUrl, { max: 2 });
  const result = await runIntelRefresh(handle.db, intelAdapters(config), { log });
  await handle.close();
  console.log(`\nWordPress core: ${result.core}`);
  for (const s of result.sources) console.log(`${s.source.padEnd(10)} ${s.status.padEnd(8)} ${s.rows} rows${s.removed ? `, ${s.removed} removed` : ''}${s.note ? `  (${s.note})` : ''}`);
  process.exit(result.sources.some((s) => s.status === 'failed') ? 1 : 0);
} catch (err) {
  console.error(err instanceof ConfigError ? err.message : err);
  process.exit(1);
}
