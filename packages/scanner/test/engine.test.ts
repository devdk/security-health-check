import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { ScanError, runScan } from '../src/engine';
import { noRateLimit } from '../src/rate-limit';
import { pluginsThemes, vulnMatch, wpDetect } from '../src/modules';
import { FakeTlsProbe, FixtureFetcher, goodTls, loadFixture, memoryReleases, memoryVulns, noVulns } from '../src/testing';
import type { CheckModule } from '../src/types';

const wpClassic = loadFixture(path.join(import.meta.dirname, 'fixtures', 'wp-classic')).routes;
const base = { limiter: noRateLimit, vulns: noVulns, maxRequests: 150, timeoutMs: 10_000 };

describe('runScan', () => {
  it('runs the first three modules and shares one request budget', async () => {
    const fetcher = new FixtureFetcher(wpClassic);
    const vulns = memoryVulns({
      'plugin:contact-form-7': [
        { source: 'wordfence', sourceId: 'x', title: 'Unrestricted File Upload', cveIds: ['CVE-2020-35489'], cvssScore: null, severity: 'critical', affected: [{ to: '5.3.1' }], fixedIn: '5.3.2', references: [] },
      ],
    });
    const outcome = await runScan({ ...base, domain: 'example.com', fetcher, vulns, modules: [wpDetect, pluginsThemes, vulnMatch] });

    expect(outcome.baseUrl).toBe('https://example.com');
    expect(outcome.ontologyVersion).toMatch(/^\d{4}\./);
    expect(outcome.modules.map((m) => [m.module, m.status])).toEqual([
      ['plugins-themes', 'ok'],
      ['vuln-match', 'ok'],
      ['wp-detect', 'ok'],
    ]);
    expect(outcome.findings.map((f) => f.conceptId).sort()).toEqual([
      'exposure/component-versions-disclosed',
      'exposure/known-vulnerable-component',
      'exposure/wordpress-version-disclosed',
    ]);
    // home page fetched once and shared: home + feed + 3 readmes + 2 style.css
    expect(outcome.requestCount).toBe(7);
    expect(new Set(fetcher.requested).size).toBe(fetcher.requested.length);
    expect(outcome.components).toHaveLength(6);
  });

  it('runs all twelve checks within the request cap', async () => {
    const fetcher = new FixtureFetcher(wpClassic);
    const outcome = await runScan({
      ...base,
      domain: 'example.com',
      fetcher,
      tlsProbe: new FakeTlsProbe({ 'example.com': { inspection: goodTls('example.com', 10) } }),
      releases: memoryReleases({ core: { status: 'insecure', latest: '7.1.4' }, latest: { 'plugin:woocommerce': '9.0.0' } }),
    });
    expect(outcome.modules).toHaveLength(12);
    expect(outcome.modules.filter((m) => m.status !== 'ok')).toEqual([]);
    expect(outcome.requestCount).toBeLessThanOrEqual(150);
    const concepts = new Set(outcome.findings.map((f) => f.conceptId));
    for (const c of [
      'exposure/wordpress-version-disclosed',
      'exposure/wordpress-core-outdated',
      'exposure/plugin-outdated',
      'exposure/tls-certificate-expiring-soon',
      'exposure/hsts-missing',
    ] as const) {
      expect(concepts, c).toContain(c);
    }
    // Nobody requested the same thing twice.
    expect(new Set(fetcher.requested).size).toBe(fetcher.requested.length);
  });

  it('follows the site to its canonical origin', async () => {
    const routes = {
      'https://example.com/': { status: 301, headers: { location: 'https://www.example.com/' } },
      'https://www.example.com/': { body: '<html><meta name="generator" content="WordPress 6.5"></html>' },
    };
    const outcome = await runScan({ ...base, domain: 'example.com', fetcher: new FixtureFetcher(routes) });
    expect(outcome.baseUrl).toBe('https://www.example.com');
  });

  it('falls back to plain HTTP when HTTPS is unreachable', async () => {
    const routes = {
      'https://example.com/': { error: 'tls_failed' as const },
      'http://example.com/': { body: '<html>plain</html>' },
    };
    const outcome = await runScan({ ...base, domain: 'example.com', fetcher: new FixtureFetcher(routes) });
    expect(outcome.baseUrl).toBe('http://example.com');
  });

  it('fails clearly when the site cannot be reached at all', async () => {
    const routes = { 'https://example.com/': { error: 'connect_failed' as const }, 'http://example.com/': { error: 'connect_failed' as const } };
    await expect(runScan({ ...base, domain: 'example.com', fetcher: new FixtureFetcher(routes) })).rejects.toSatisfy(
      (err) => err instanceof ScanError && err.code === 'unreachable' && /couldn't reach example\.com/.test(err.message),
    );
  });

  it('records budget exhaustion without losing other modules', async () => {
    const outcome = await runScan({ ...base, domain: 'example.com', fetcher: new FixtureFetcher(wpClassic), maxRequests: 3, modules: [wpDetect, pluginsThemes, vulnMatch] });
    expect(outcome.requestCount).toBe(3);
    expect(outcome.modules.some((m) => m.status === 'budget_exhausted')).toBe(true);
    expect(outcome.modules.find((m) => m.module === 'vuln-match')?.status).toBe('ok');
  });

  it('isolates a crashing module and drops malformed findings', async () => {
    const broken: CheckModule = { id: 'broken', title: 'Broken', stage: 1, run: async () => Promise.reject(new Error('boom')) };
    const sloppy: CheckModule = {
      id: 'sloppy',
      title: 'Sloppy',
      stage: 1,
      run: async () => [
        { checkId: 'sloppy.ok', conceptId: 'exposure/xmlrpc-enabled', severity: 'medium', title: 'ok', confidence: 'confirmed', evidence: {} },
        { checkId: 'sloppy.bad', conceptId: 'exposure/not-real' as never, severity: 'medium', title: 'bad', confidence: 'confirmed', evidence: {} },
        { checkId: 'someone-else.x', conceptId: 'exposure/xmlrpc-enabled', severity: 'medium', title: 'spoofed', confidence: 'confirmed', evidence: {} },
      ],
    };
    const outcome = await runScan({ ...base, domain: 'example.com', fetcher: new FixtureFetcher(wpClassic), modules: [broken, sloppy] });
    expect(outcome.modules).toEqual([
      expect.objectContaining({ module: 'broken', status: 'failed', note: 'Check failed unexpectedly' }),
      expect.objectContaining({ module: 'sloppy', status: 'ok', findings: 1 }),
    ]);
    expect(outcome.findings.map((f) => f.checkId)).toEqual(['sloppy.ok']);
  });
});
