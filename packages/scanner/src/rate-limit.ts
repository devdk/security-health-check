import type { Redis } from 'ioredis';

/** Waits until the caller may send the next request to `key` (one target site). */
export interface RateLimiter {
  acquire(key: string, signal?: AbortSignal): Promise<void>;
}

const sleep = (ms: number, signal?: AbortSignal) =>
  new Promise<void>((resolve, reject) => {
    if (ms <= 0) return resolve();
    const timer = setTimeout(resolve, ms);
    signal?.addEventListener(
      'abort',
      () => {
        clearTimeout(timer);
        reject(signal.reason ?? new Error('aborted'));
      },
      { once: true },
    );
  });

/** Spaces requests at least `intervalMs` apart per key, within one process. */
export class InMemoryRateLimiter implements RateLimiter {
  private readonly next = new Map<string, number>();

  constructor(private readonly intervalMs: number) {}

  async acquire(key: string, signal?: AbortSignal): Promise<void> {
    const now = Date.now();
    const slot = Math.max(now, this.next.get(key) ?? 0);
    this.next.set(key, slot + this.intervalMs);
    await sleep(slot - now, signal);
  }
}

/**
 * Reserves time slots in Redis so that every worker process together stays under the
 * per-target limit. Uses the Redis server clock, so worker clock drift doesn't matter.
 * Returns the number of milliseconds the caller must wait for its slot.
 */
const RESERVE_SLOT = `
local t = redis.call('TIME')
local now = tonumber(t[1]) * 1000 + math.floor(tonumber(t[2]) / 1000)
local interval = tonumber(ARGV[1])
local nextFree = tonumber(redis.call('GET', KEYS[1]) or '0')
local slot = math.max(now, nextFree)
redis.call('SET', KEYS[1], tostring(slot + interval), 'PX', interval * 20 + 60000)
return slot - now
`;

export class RedisRateLimiter implements RateLimiter {
  constructor(
    private readonly redis: Redis,
    private readonly intervalMs: number,
    private readonly prefix = 'shc:target-rl:',
  ) {}

  async acquire(key: string, signal?: AbortSignal): Promise<void> {
    const wait = Number(await this.redis.eval(RESERVE_SLOT, 1, `${this.prefix}${key}`, String(this.intervalMs)));
    await sleep(wait, signal);
  }
}

/** For unit tests of check modules: no waiting. */
export const noRateLimit: RateLimiter = { acquire: async () => {} };
