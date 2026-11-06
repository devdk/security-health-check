import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { createTestContext, ORIGIN, post, resetState, type TestContext } from './helpers';

let ctx: TestContext;

beforeAll(async () => {
  ctx = await createTestContext();
});
afterAll(async () => {
  await ctx.close();
});
beforeEach(async () => {
  await resetState(ctx);
});

describe('request hardening', () => {
  it('rejects state-changing requests from a foreign origin', async () => {
    const res = await ctx.app.inject({
      method: 'POST',
      url: '/api/auth/login',
      headers: { origin: 'https://evil.example' },
      payload: { email: 'a@example.com', password: 'whatever password' },
    });
    expect(res.statusCode).toBe(403);
    expect(res.json().error).toBe('forbidden_origin');
  });

  it('rejects cross-site requests that omit the Origin header', async () => {
    const res = await ctx.app.inject({
      method: 'POST',
      url: '/api/auth/login',
      headers: { 'sec-fetch-site': 'cross-site' },
      payload: { email: 'a@example.com', password: 'whatever password' },
    });
    expect(res.statusCode).toBe(403);
  });

  it('only accepts JSON bodies, so plain HTML forms cannot post', async () => {
    const res = await ctx.app.inject({
      method: 'POST',
      url: '/api/auth/login',
      headers: { origin: ORIGIN, 'content-type': 'text/plain' },
      payload: '{"email":"a@example.com","password":"whatever password"}',
    });
    expect(res.statusCode).toBe(415);
  });

  it('validates input and does not echo internals', async () => {
    const res = await post(ctx, '/api/auth/register', { email: 'not-an-email', password: 'short' });
    expect(res.statusCode).toBe(400);
    const body = res.json();
    expect(body.error).toBe('invalid_request');
    expect(JSON.stringify(body)).not.toMatch(/stack|node_modules/);
  });

  it('rejects oversized passwords before hashing', async () => {
    const res = await post(ctx, '/api/auth/login', { email: 'a@example.com', password: 'x'.repeat(5000) });
    expect(res.statusCode).toBe(400);
  });

  it('sets security headers and disables caching on API responses', async () => {
    const res = await ctx.app.inject({ method: 'GET', url: '/api/health' });
    expect(res.statusCode).toBe(200);
    expect(res.headers['x-content-type-options']).toBe('nosniff');
    expect(res.headers['content-security-policy']).toContain("default-src 'none'");
    expect(res.headers['referrer-policy']).toBe('no-referrer');
    expect(res.headers['cache-control']).toBe('no-store');
    expect(res.headers['x-powered-by']).toBeUndefined();
  });

  it('returns 401 for missing or forged session cookies and clears the bad cookie', async () => {
    const none = await ctx.app.inject({ method: 'GET', url: '/api/auth/me' });
    expect(none.statusCode).toBe(401);

    const forged = await ctx.app.inject({
      method: 'GET',
      url: '/api/auth/me',
      headers: { cookie: `shc_session=${'A'.repeat(43)}` },
    });
    expect(forged.statusCode).toBe(401);
    const cleared = forged.cookies.find((c) => c.name === 'shc_session');
    expect(cleared?.value).toBe('');
  });

  it('returns JSON 404s', async () => {
    const res = await ctx.app.inject({ method: 'GET', url: '/api/does-not-exist' });
    expect(res.statusCode).toBe(404);
    expect(res.json().error).toBe('not_found');
  });
});

describe('rate limiting', () => {
  let limited: TestContext;

  beforeAll(async () => {
    limited = await createTestContext({ authPerMinute: 3 });
  });
  afterAll(async () => {
    await limited.close();
  });

  it('throttles repeated sign-in attempts per IP', async () => {
    await limited.redis.flushdb();
    const statuses: number[] = [];
    for (let i = 0; i < 4; i++) {
      const res = await post(limited, '/api/auth/login', { email: 'a@example.com', password: 'whatever password' });
      statuses.push(res.statusCode);
    }
    expect(statuses.slice(0, 3)).toEqual([401, 401, 401]);
    expect(statuses[3]).toBe(429);
  });
});
