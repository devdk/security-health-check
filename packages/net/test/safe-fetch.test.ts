import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import type { ResolvedAddress } from '../src/dns';
import { NetError } from '../src/errors';
import { SafeFetcher } from '../src/safe-fetch';

// A local server stands in for websites; a fake DNS table decides where names point.
let server: http.Server;
let port = 0;
const hits: Array<{ url: string; host: string; ua: string }> = [];

const DNS: Record<string, string[]> = {
  'site.test': ['127.0.0.1'],
  'www.site.test': ['127.0.0.1'],
  'other.test': ['127.0.0.1'],
  'pinned.test': ['127.0.0.1'],
  'evil.test': ['10.0.0.7'],
  'meta.test': ['169.254.169.254'],
  'mixed.test': ['93.184.216.34', '127.0.0.1'],
};
let lookups: string[] = [];
const resolveHost = async (host: string): Promise<ResolvedAddress[]> => {
  lookups.push(host);
  const addrs = DNS[host];
  if (!addrs) throw Object.assign(new Error('ENOTFOUND'), { code: 'ENOTFOUND' });
  return addrs.map((address) => ({ address, family: 4 as const }));
};

const UA = 'SecurityHealthCheck/test (+http://localhost/scanner)';
let fetcher: SafeFetcher; // trusts the *.test names that point at the local server
let strict: SafeFetcher; // no private allowances at all

beforeAll(async () => {
  server = http.createServer((req, res) => {
    hits.push({ url: req.url ?? '', host: req.headers.host ?? '', ua: req.headers['user-agent'] ?? '' });
    const at = (host: string, path: string) => `http://${host}:${port}${path}`;
    switch (req.url) {
      case '/ok':
        return res.end('hello');
      case '/big':
        return res.end('x'.repeat(10_000));
      case '/redirect-same':
        res.writeHead(302, { location: '/ok' });
        return res.end();
      case '/redirect-www':
        res.writeHead(301, { location: at('www.site.test', '/ok') });
        return res.end();
      case '/redirect-other':
        res.writeHead(302, { location: at('other.test', '/ok') });
        return res.end();
      case '/redirect-scheme':
        res.writeHead(302, { location: 'file:///etc/passwd' });
        return res.end();
      case '/redirect-loop':
        res.writeHead(302, { location: '/redirect-loop' });
        return res.end();
      case '/slow':
        return setTimeout(() => res.end('late'), 3000);
      default:
        res.statusCode = 404;
        return res.end('not found');
    }
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  port = (server.address() as AddressInfo).port;

  fetcher = new SafeFetcher({
    userAgent: UA,
    allowPrivateHosts: ['site.test', 'www.site.test', 'other.test', 'pinned.test'],
    allowedPorts: [port],
    resolveHost,
  });
  strict = new SafeFetcher({ userAgent: UA, allowedPorts: [80, 443, port], resolveHost });
});

afterAll(async () => {
  server.closeAllConnections();
  await new Promise((resolve) => server.close(resolve));
});

beforeEach(() => {
  hits.length = 0;
  lookups = [];
});

const url = (host: string, path: string) => `http://${host}:${port}${path}`;

async function expectNetError(promise: Promise<unknown>, code: NetError['code']) {
  await expect(promise).rejects.toSatisfy((err) => err instanceof NetError && err.code === code);
}

describe('SafeFetcher', () => {
  it('fetches with an honest User-Agent and the real Host header', async () => {
    const res = await fetcher.fetch(url('site.test', '/ok'));
    expect(res.status).toBe(200);
    expect(res.body.toString()).toBe('hello');
    expect(hits[0]).toEqual({ url: '/ok', host: `site.test:${port}`, ua: UA });
  });

  it('cannot be talked out of its User-Agent', async () => {
    await fetcher.fetch(url('site.test', '/ok'), { headers: { 'user-agent': 'Mozilla/5.0' } });
    expect(hits[0]?.ua).toBe(UA);
  });

  it('connects to the address it vetted rather than resolving again', async () => {
    // The OS can't resolve "pinned.test"; success proves the socket used our vetted IP.
    const res = await fetcher.fetch(url('pinned.test', '/ok'));
    expect(res.status).toBe(200);
    expect(res.remoteAddress).toBe('127.0.0.1');
    expect(lookups).toEqual(['pinned.test']);
  });

  it('takes the rate-limit slot after DNS, right before sending, and starts the timeout then', async () => {
    const order: string[] = [];
    const f = new SafeFetcher({
      userAgent: UA,
      allowPrivateHosts: ['site.test'],
      allowedPorts: [port],
      resolveHost: async (h) => {
        order.push('dns');
        return resolveHost(h);
      },
    });
    const res = await f.fetch(url('site.test', '/ok'), {
      timeoutMs: 200,
      beforeSend: async () => {
        order.push('slot');
        await new Promise((r) => setTimeout(r, 400)); // longer than the timeout
      },
    });
    expect(res.status).toBe(200);
    expect(order).toEqual(['dns', 'slot']);
    expect(hits).toHaveLength(1);
  });

  describe('SSRF protection', () => {
    it('refuses names that resolve to private addresses, before connecting', async () => {
      await expectNetError(strict.fetch(url('evil.test', '/ok')), 'blocked_address');
      await expectNetError(strict.fetch(url('site.test', '/ok')), 'blocked_address');
      expect(hits).toHaveLength(0);
    });

    it('refuses cloud metadata addresses, by name or literal', async () => {
      await expectNetError(strict.fetch('http://meta.test/latest/meta-data/'), 'blocked_address');
      await expectNetError(strict.fetch('http://169.254.169.254/latest/meta-data/'), 'blocked_address');
      await expectNetError(strict.fetch('http://[::ffff:a9fe:a9fe]/'), 'blocked_address');
    });

    it('refuses a name if any of its addresses is private', async () => {
      await expectNetError(strict.fetch('http://mixed.test/'), 'blocked_address');
    });

    it('refuses other schemes, credentials and ports', async () => {
      await expectNetError(fetcher.fetch('file:///etc/passwd'), 'blocked_scheme');
      await expectNetError(fetcher.fetch('gopher://site.test/'), 'blocked_scheme');
      await expectNetError(fetcher.fetch(`http://user:pass@site.test:${port}/ok`), 'invalid_url');
      await expectNetError(fetcher.fetch('http://site.test:6379/'), 'blocked_port');
      await expectNetError(fetcher.fetch('not a url'), 'invalid_url');
    });

    it('reports unknown names as DNS failures', async () => {
      await expectNetError(fetcher.fetch(url('nowhere.test', '/')), 'dns_failed');
    });
  });

  describe('redirects', () => {
    it('does not follow redirects unless asked', async () => {
      const res = await fetcher.fetch(url('site.test', '/redirect-same'));
      expect(res.status).toBe(302);
      expect(hits).toHaveLength(1);
    });

    it('follows same-host redirects and records them', async () => {
      const res = await fetcher.fetch(url('site.test', '/redirect-same'), { redirect: 'same-host' });
      expect(res.status).toBe(200);
      expect(res.redirects).toEqual([url('site.test', '/ok')]);
    });

    it('allows www/apex hops only with the same-site policy', async () => {
      await expectNetError(fetcher.fetch(url('site.test', '/redirect-www'), { redirect: 'same-host' }), 'redirect_blocked');
      const res = await fetcher.fetch(url('site.test', '/redirect-www'), { redirect: 'same-site' });
      expect(res.status).toBe(200);
    });

    it('never follows a redirect to another domain', async () => {
      await expectNetError(fetcher.fetch(url('site.test', '/redirect-other'), { redirect: 'same-site' }), 'redirect_blocked');
      expect(hits.map((h) => h.url)).toEqual(['/redirect-other']);
    });

    it('refuses redirects to other schemes', async () => {
      await expectNetError(fetcher.fetch(url('site.test', '/redirect-scheme'), { redirect: 'same-site' }), 'redirect_blocked');
    });

    it('stops redirect loops', async () => {
      await expectNetError(fetcher.fetch(url('site.test', '/redirect-loop'), { redirect: 'same-host', maxRedirects: 3 }), 'too_many_redirects');
      expect(hits).toHaveLength(4);
    });
  });

  describe('limits', () => {
    it('stops reading after maxBytes', async () => {
      const res = await fetcher.fetch(url('site.test', '/big'), { maxBytes: 100 });
      expect(res.body.length).toBe(100);
      expect(res.truncated).toBe(true);
    });

    it('does not mark an exact-size body as truncated', async () => {
      const res = await fetcher.fetch(url('site.test', '/ok'), { maxBytes: 5 });
      expect(res.body.toString()).toBe('hello');
      expect(res.truncated).toBe(false);
    });

    it('gives up after the time budget', async () => {
      const started = Date.now();
      await expectNetError(fetcher.fetch(url('site.test', '/slow'), { timeoutMs: 300 }), 'timeout');
      expect(Date.now() - started).toBeLessThan(2000);
    });

    it('supports HEAD without reading a body', async () => {
      const res = await fetcher.fetch(url('site.test', '/ok'), { method: 'HEAD' });
      expect(res.status).toBe(200);
      expect(res.body.length).toBe(0);
    });
  });
});
