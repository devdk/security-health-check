import { describe, expect, it } from 'vitest';
import { BudgetExhaustedError, OutOfScopeError, PoliteClient } from '../src/polite-client';
import { InMemoryRateLimiter, noRateLimit } from '../src/rate-limit';
import { FixtureFetcher } from '../src/testing';

const routes = {
  'https://example.com/': { body: 'home' },
  'https://example.com/a': { body: 'a' },
  'https://example.com/old': { status: 301, headers: { location: '/new' } },
  'https://example.com/new': { status: 301, headers: { location: 'https://www.example.com/final' } },
  'https://www.example.com/final': { body: 'final' },
  'https://example.com/away': { status: 302, headers: { location: 'https://evil.example/' } },
};

function client(maxRequests = 50, limiter = noRateLimit) {
  const fetcher = new FixtureFetcher(routes);
  return { fetcher, http: PoliteClient.create({ fetcher, limiter, domain: 'example.com', maxRequests }) };
}

describe('PoliteClient', () => {
  it('only talks to the verified domain and its www twin', async () => {
    const { http, fetcher } = client();
    await expect(http.get('https://other.example/')).rejects.toBeInstanceOf(OutOfScopeError);
    await expect(http.get('https://sub.example.com/')).rejects.toBeInstanceOf(OutOfScopeError);
    await expect(http.get('ftp://example.com/')).rejects.toBeInstanceOf(OutOfScopeError);
    expect((await http.get('https://www.example.com/final')).status).toBe(200);
    expect(fetcher.requested).toEqual(['GET https://www.example.com/final']);
  });

  it('stops at the per-scan request cap', async () => {
    const { http } = client(2);
    await http.get('https://example.com/');
    await http.head('https://example.com/a');
    await expect(http.head('https://example.com/a')).rejects.toBeInstanceOf(BudgetExhaustedError);
    expect(http.requestCount).toBe(2);
    expect(http.remaining).toBe(0);
  });

  it('serves repeated GETs from the scan cache', async () => {
    const { http, fetcher } = client();
    const [a, b] = await Promise.all([http.get('https://example.com/'), http.get('https://example.com/')]);
    expect(a.body.toString()).toBe('home');
    expect(b.body.toString()).toBe('home');
    expect(fetcher.requested).toHaveLength(1);
    expect(http.requestCount).toBe(1);
  });

  it('follows on-site redirects, counting every hop', async () => {
    const { http } = client();
    const res = await http.get('https://example.com/old', { followRedirects: true });
    expect(res.body.toString()).toBe('final');
    expect(res.redirects).toEqual(['https://example.com/new', 'https://www.example.com/final']);
    expect(http.requestCount).toBe(3);
  });

  it('does not follow redirects off the verified site', async () => {
    const { http, fetcher } = client();
    const res = await http.get('https://example.com/away', { followRedirects: true });
    expect(res.status).toBe(302);
    expect(res.redirectedOffSite).toBe(true);
    expect(fetcher.requested).toEqual(['GET https://example.com/away']);
  });

  it('attributes requests to modules', async () => {
    const { http } = client();
    await http.forModule('one').get('https://example.com/');
    await http.forModule('two').head('https://example.com/a');
    await http.forModule('two').head('https://example.com/a');
    expect(http.requestsBy('one')).toBe(1);
    expect(http.requestsBy('two')).toBe(2);
  });

  it('spaces requests to the same site through the rate limiter', async () => {
    const { http } = client(50, new InMemoryRateLimiter(100));
    const started = Date.now();
    await Promise.all(['/', '/a', '/old', '/new'].map((p) => http.head(`https://example.com${p}`)));
    // Four requests at 100 ms spacing: the last one waits at least ~300 ms.
    expect(Date.now() - started).toBeGreaterThanOrEqual(280);
  });
});
