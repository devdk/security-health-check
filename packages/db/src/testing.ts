import pg from 'pg';
import { runMigrations } from './migrate';

/** Same server and credentials, different database name. */
export function withDatabaseName(url: string, name: string): string {
  const u = new URL(url);
  u.pathname = `/${name}`;
  return u.toString();
}

/**
 * Drops and recreates a test database, then applies every migration. Refuses any name
 * that doesn't end in _test, so it can never wipe a real database by mistake.
 */
export async function recreateTestDatabase(url: string): Promise<void> {
  const name = new URL(url).pathname.slice(1);
  if (!/^[a-z0-9_]+_test$/.test(name)) throw new Error(`Refusing to reset "${name}": test database names must end in _test`);

  const admin = new pg.Client({ connectionString: withDatabaseName(url, 'postgres') });
  await admin.connect();
  try {
    await admin.query(`DROP DATABASE IF EXISTS "${name}" WITH (FORCE)`);
    await admin.query(`CREATE DATABASE "${name}"`);
  } finally {
    await admin.end();
  }
  await runMigrations(url);
}
