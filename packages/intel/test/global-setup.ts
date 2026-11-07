import { recreateTestDatabase, withDatabaseName } from '@shc/db/testing';

export const intelTestDbUrl = () => withDatabaseName(process.env.TEST_DATABASE_URL!, 'shc_intel_test');

export default async function setup(): Promise<void> {
  if (!process.env.TEST_DATABASE_URL) {
    throw new Error('TEST_DATABASE_URL is not set. Run `npm run setup:env` and `docker compose up -d postgres redis` first.');
  }
  await recreateTestDatabase(intelTestDbUrl());
}
