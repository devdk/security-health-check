import { recreateTestDatabase, withDatabaseName } from '@shc/db/testing';

/** The worker gets its own test database so it can run alongside the API tests. */
export const workerTestDbUrl = () => withDatabaseName(process.env.TEST_DATABASE_URL!, 'shc_worker_test');

export default async function setup(): Promise<void> {
  if (!process.env.TEST_DATABASE_URL) {
    throw new Error('TEST_DATABASE_URL is not set. Run `npm run setup:env` and `docker compose up -d postgres redis` first.');
  }
  await recreateTestDatabase(workerTestDbUrl());
}
