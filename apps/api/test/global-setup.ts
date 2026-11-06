import pg from 'pg';
import { runMigrations } from '@shc/db';

/** Recreates the test database from scratch and applies all migrations. */
export default async function setup(): Promise<void> {
  const url = process.env.TEST_DATABASE_URL;
  if (!url) {
    throw new Error('TEST_DATABASE_URL is not set. Run `npm run setup:env` and `docker compose up -d postgres redis` first.');
  }
  if (!process.env.TEST_REDIS_URL) throw new Error('TEST_REDIS_URL is not set.');

  const dbName = new URL(url).pathname.slice(1);
  // Safety net: never drop anything that isn't clearly a test database.
  if (!/^[a-z0-9_]+_test$/.test(dbName)) throw new Error(`Refusing to reset "${dbName}": test database names must end in _test`);

  const adminUrl = new URL(url);
  adminUrl.pathname = '/postgres';
  const admin = new pg.Client({ connectionString: adminUrl.toString() });
  await admin.connect();
  try {
    await admin.query(`DROP DATABASE IF EXISTS "${dbName}" WITH (FORCE)`);
    await admin.query(`CREATE DATABASE "${dbName}"`);
  } finally {
    await admin.end();
  }

  await runMigrations(url);
}
