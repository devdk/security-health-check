/**
 * Records HTTP fixtures from the local test WordPress (docker compose --profile testwp).
 * Development only: it talks to 127.0.0.1:<TESTWP_HOST_PORT> and nothing else.
 *
 *   npm run record-fixtures -w @shc/scanner
 *
 * Runs a real scan through a recording fetcher, then writes every response it saw to
 * test/fixtures/testwp-recorded/, so module tests replay genuine WordPress output.
 */
import http from 'node:http';
import { mkdirSync, rmSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { NetError, type FetchOptions, type Fetcher, type SafeResponse } from '@shc/net';
import { InMemoryRateLimiter } from '../src/rate-limit';
import { runScan } from '../src/engine';
import { noVulns } from '../src/testing';

const PORT = Number(process.env.TESTWP_HOST_PORT ?? 8081);
const DOMAIN = 'wordpress.test';
const UA = 'SecurityHealthCheck/0.1 (fixture recorder)';
const KEEP_HEADERS = ['content-type', 'link', 'location', 'x-pingback', 'server', 'x-powered-by'];
const out = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../test/fixtures/testwp-recorded');

interface Recorded {
  status?: number;
  headers?: Record<string, string>;
  bodyFile?: string;
  error?: string;
}
const recorded = new Map<string, Recorded & { body?: Buffer }>();

class RecordingFetcher implements Fetcher {
  async fetch(url: string, options: FetchOptions = {}): Promise<SafeResponse> {
    const u = new URL(url);
    if (u.hostname !== DOMAIN && u.hostname !== `www.${DOMAIN}`) throw new Error(`recorder refuses ${url}`);
    if (u.protocol === 'https:') {
      recorded.set(url, { error: 'connect_failed' });
      throw new NetError('connect_failed', 'test site has no TLS', url);
    }
    const maxBytes = options.maxBytes ?? 256 * 1024;
    const res = await new Promise<{ status: number; headers: http.IncomingHttpHeaders; body: Buffer }>((resolve, reject) => {
      const req = http.request(
        { host: '127.0.0.1', port: PORT, path: `${u.pathname}${u.search}`, method: options.method ?? 'GET', headers: { host: u.host, 'user-agent': UA } },
        (r) => {
          const chunks: Buffer[] = [];
          r.on('data', (c: Buffer) => chunks.push(c));
          r.on('end', () => resolve({ status: r.statusCode ?? 0, headers: r.headers, body: Buffer.concat(chunks).subarray(0, maxBytes) }));
        },
      );
      req.on('error', reject);
      req.end();
    });
    const headers = Object.fromEntries(KEEP_HEADERS.filter((h) => typeof res.headers[h] === 'string').map((h) => [h, res.headers[h] as string]));
    recorded.set(url, { status: res.status, headers, body: res.body });
    return { url, status: res.status, headers, body: res.body, truncated: false, remoteAddress: '127.0.0.1', redirects: [] };
  }
}

const outcome = await runScan({
  domain: DOMAIN,
  fetcher: new RecordingFetcher(),
  limiter: new InMemoryRateLimiter(500),
  vulns: noVulns,
  maxRequests: 150,
  timeoutMs: 120_000,
});

rmSync(out, { recursive: true, force: true });
mkdirSync(out, { recursive: true });
const routes: Record<string, Recorded> = {};
let n = 0;
for (const [url, r] of recorded) {
  const entry: Recorded = r.error ? { error: r.error } : { status: r.status, headers: r.headers };
  if (r.body && r.body.length > 0) {
    const name = `${String(++n).padStart(2, '0')}-${new URL(url).pathname.replace(/[^a-z0-9]+/gi, '-').replace(/^-|-$/g, '') || 'home'}.txt`;
    writeFileSync(path.join(out, name), r.body);
    entry.bodyFile = name;
  }
  routes[url] = entry;
}
writeFileSync(
  path.join(out, 'fixture.json'),
  `${JSON.stringify({ description: `Recorded ${new Date().toISOString().slice(0, 10)} from the local test WordPress (docker compose --profile testwp).`, origin: `http://${DOMAIN}`, routes }, null, 2)}\n`,
);
console.log(`Recorded ${recorded.size} responses (${outcome.requestCount} requests) to ${path.relative(process.cwd(), out)}`);
for (const c of outcome.components) console.log(`  ${c.type} ${c.slug} ${c.version ?? '?'} (${c.versionConfidence ?? 'n/a'})`);
