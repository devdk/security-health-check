import { recreateTestDatabase } from '@shc/db/testing';

/** Recreates the API test database from scratch and applies all migrations. */
export default async function setup(): Promise<void> {
  const url = process.env.TEST_DATABASE_URL;
  if (!url) {
    throw new Error('TEST_DATABASE_URL is not set. Run `npm run setup:env` and `docker compose up -d postgres redis` first.');
  }
  if (!process.env.TEST_REDIS_URL) throw new Error('TEST_REDIS_URL is not set.');
  await recreateTestDatabase(url);
}
