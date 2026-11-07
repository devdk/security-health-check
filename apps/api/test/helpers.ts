import { sql } from 'drizzle-orm';
import { Redis } from 'ioredis';
import { expect } from 'vitest';
import { loadConfig, type Config } from '@shc/config';
import { createDb, type Database } from '@shc/db';
import type { ScanQueue } from '@shc/core';
import type { OwnershipChecker, OwnershipResult } from '@shc/net';
import type { VerifyMethod } from '@shc/shared';
import { buildApp, type App } from '../src/app';
import { MemoryMailer } from '../src/lib/mailer';

export const ORIGIN = 'http://localhost:5173';

export interface TestContext {
  app: App;
  db: Database;
  redis: Redis;
  mailer: MemoryMailer;
  config: Config;
  close: () => Promise<void>;
}

/** Ownership checker that never touches the network; tests set the next answer. */
export class FakeOwnership implements OwnershipChecker {
  calls: Array<{ method: VerifyMethod; domain: string; token: string }> = [];
  next: OwnershipResult = { ok: true, detail: 'TXT record found at _shc-verify.example.com' };

  async check(method: VerifyMethod, domain: string, token: string): Promise<OwnershipResult> {
    this.calls.push({ method, domain, token });
    return this.next;
  }
}

/** Records enqueued scans instead of talking to BullMQ. */
export class FakeQueue implements ScanQueue {
  enqueued: string[] = [];
  failNext = false;

  async enqueue(scanId: string): Promise<void> {
    if (this.failNext) {
      this.failNext = false;
      throw new Error('redis down');
    }
    this.enqueued.push(scanId);
  }

  async close(): Promise<void> {}
}

export async function createTestContext(
  options: { rateLimit?: Partial<Config['rateLimit']>; ownership?: OwnershipChecker; scanQueue?: ScanQueue } = {},
): Promise<TestContext> {
  const rateLimit = options.rateLimit ?? {};
  const base = loadConfig({
    NODE_ENV: 'test',
    LOG_LEVEL: 'silent',
    DATABASE_URL: process.env.TEST_DATABASE_URL,
    REDIS_URL: process.env.TEST_REDIS_URL,
    WEB_BASE_URL: ORIGIN,
    RATE_LIMIT_GLOBAL_PER_MINUTE: '10000',
    RATE_LIMIT_AUTH_PER_MINUTE: '10000',
  });
  const config: Config = { ...base, rateLimit: { ...base.rateLimit, ...rateLimit } };

  const dbHandle = createDb(config.databaseUrl, { max: 4 });
  const redis = new Redis(config.redisUrl, { maxRetriesPerRequest: 3 });
  const mailer = new MemoryMailer();
  const app = await buildApp({
    config,
    db: dbHandle.db,
    redis,
    mailer,
    ownership: options.ownership ?? new FakeOwnership(),
    scanQueue: options.scanQueue ?? new FakeQueue(),
    logger: false,
  });
  await app.ready();

  return {
    app,
    db: dbHandle.db,
    redis,
    mailer,
    config,
    close: async () => {
      await app.close();
      await redis.quit();
      await dbHandle.close();
    },
  };
}

/** Wipes all rows and rate-limit counters between tests. */
export async function resetState(ctx: TestContext): Promise<void> {
  await ctx.db.execute(sql`truncate table users, vuln_cache, vuln_sync_runs restart identity cascade`);
  await ctx.redis.flushdb();
  ctx.mailer.sent.length = 0;
}

export function tokenFromMail(text: string | undefined): string {
  const match = /#token=([A-Za-z0-9_-]{43})/.exec(text ?? '');
  expect(match, 'expected a token link in the email').not.toBeNull();
  return match![1]!;
}

export async function post(ctx: TestContext, url: string, payload: unknown, cookie?: string) {
  return ctx.app.inject({
    method: 'POST',
    url,
    payload: payload as Record<string, unknown>,
    headers: { origin: ORIGIN, ...(cookie ? { cookie } : {}) },
  });
}

export async function get(ctx: TestContext, url: string, cookie?: string) {
  return ctx.app.inject({ method: 'GET', url, headers: cookie ? { cookie } : {} });
}

export async function del(ctx: TestContext, url: string, cookie?: string) {
  return ctx.app.inject({ method: 'DELETE', url, headers: { origin: ORIGIN, ...(cookie ? { cookie } : {}) } });
}

/** Registers, verifies and signs in a user; returns their cookie header. */
export async function signedInUser(ctx: TestContext, email: string, password = 'a long enough passphrase'): Promise<string> {
  await registerAndVerify(ctx, email, password);
  return login(ctx, email, password);
}

export async function registerAndVerify(ctx: TestContext, email: string, password: string): Promise<void> {
  const reg = await post(ctx, '/api/auth/register', { email, password });
  expect(reg.statusCode).toBe(202);
  const token = tokenFromMail(ctx.mailer.lastTo(email.trim().toLowerCase())?.text);
  const ver = await post(ctx, '/api/auth/verify-email', { token });
  expect(ver.statusCode).toBe(200);
}

/** Logs in and returns a `cookie` header value for follow-up requests. */
export async function login(ctx: TestContext, email: string, password: string): Promise<string> {
  const res = await post(ctx, '/api/auth/login', { email, password });
  expect(res.statusCode).toBe(200);
  const session = res.cookies.find((c) => c.name === ctx.config.session.cookieName);
  expect(session).toBeDefined();
  return `${session!.name}=${session!.value}`;
}
