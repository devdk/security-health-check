import { Redis } from 'ioredis';
import { afterAll, describe, expect, it } from 'vitest';
import { InMemoryRateLimiter, RedisRateLimiter } from '../src/rate-limit';

async function timed(fn: () => Promise<unknown>): Promise<number> {
  const started = Date.now();
  await fn();
  return Date.now() - started;
}

describe('InMemoryRateLimiter', () => {
  it('spaces calls for the same key and leaves other keys alone', async () => {
    const limiter = new InMemoryRateLimiter(100);
    const same = await timed(() => Promise.all([1, 2, 3].map(() => limiter.acquire('a'))));
    expect(same).toBeGreaterThanOrEqual(180);
    const other = await timed(() => limiter.acquire('b'));
    expect(other).toBeLessThan(50);
  });

  it('can be aborted while waiting', async () => {
    const limiter = new InMemoryRateLimiter(10_000);
    await limiter.acquire('k');
    const controller = new AbortController();
    const waiting = limiter.acquire('k', controller.signal);
    controller.abort(new Error('scan cancelled'));
    await expect(waiting).rejects.toThrow('scan cancelled');
  });
});

// Shared limiter across worker processes; needs the Valkey container. Uses its own
// logical database (2) because the API tests flush database 1 between tests.
const redisUrl = process.env.TEST_REDIS_URL?.replace(/\/\d+$/, '/2');
describe.skipIf(!redisUrl)('RedisRateLimiter', () => {
  const redis = new Redis(redisUrl ?? 'redis://localhost', { lazyConnect: true, maxRetriesPerRequest: 1 });
  afterAll(async () => {
    await redis.quit().catch(() => undefined);
  });

  it('keeps two independent limiters (two workers) to one shared pace', async () => {
    await redis.connect().catch(() => undefined);
    if (redis.status !== 'ready') return; // Valkey not running: nothing to test against
    const key = `test-${Date.now()}`;
    const workerA = new RedisRateLimiter(redis, 100);
    const workerB = new RedisRateLimiter(redis, 100);
    const elapsed = await timed(() => Promise.all([workerA, workerB, workerA, workerB].map((l) => l.acquire(key))));
    expect(elapsed).toBeGreaterThanOrEqual(280);
  });
});
