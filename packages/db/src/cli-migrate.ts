import { loadConfig } from '@shc/config';
import { runMigrations } from './migrate';

// Entry point for `npm run db:migrate` and the `migrate` container.
try {
  const config = loadConfig();
  await runMigrations(config.databaseUrl);
  console.log('Migrations applied.');
} catch (err) {
  console.error(err instanceof Error ? err.message : err);
  process.exit(1);
}
