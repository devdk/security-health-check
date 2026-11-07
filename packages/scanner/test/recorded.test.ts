import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { runScan } from '../src/engine';
import { noRateLimit } from '../src/rate-limit';
import { FakeTlsProbe, FixtureFetcher, loadFixture, memoryReleases, memoryVulns } from '../src/testing';

// Genuine responses recorded from the local test WordPress (docker compose --profile testwp):
// WordPress 6.4.2, Contact Form 7 5.3.1, PHP 8.1.27, a leftover wp-config.php.bak and a
// public debug.log. Re-record with `npm run record-fixtures -w @shc/scanner`.
const { routes } = loadFixture(path.join(import.meta.dirname, 'fixtures', 'testwp-recorded'));

describe('full scan replayed from a real WordPress install', () => {
  it('finds what a careful attacker would, using only GET/HEAD within the request cap', async () => {
    const fetcher = new FixtureFetcher(routes);
    const outcome = await runScan({
      domain: 'wordpress.test',
      fetcher,
      limiter: noRateLimit,
      tlsProbe: new FakeTlsProbe({}), // the test site has no HTTPS
      vulns: memoryVulns({
        'plugin:contact-form-7': [
          { source: 'nvd', sourceId: 'CVE-2020-35489', title: 'Unrestricted file upload', cveIds: ['CVE-2020-35489'], cvssScore: null, severity: 'critical', affected: [{ to: '5.3.1' }], fixedIn: '5.3.2', references: [] },
        ],
      }),
      releases: memoryReleases({ core: { status: 'insecure', latest: '7.1.4' }, latest: { 'plugin:contact-form-7': '6.1.2', 'theme:twentytwentyone': '2.7' } }),
      maxRequests: 150,
      timeoutMs: 10_000,
    });

    expect(outcome.baseUrl).toBe('http://wordpress.test');
    expect(outcome.modules.every((m) => m.status === 'ok')).toBe(true);
    expect(outcome.requestCount).toBe(52);
    expect(fetcher.requested.every((r) => r.startsWith('GET ') || r.startsWith('HEAD '))).toBe(true);

    const versions = Object.fromEntries(outcome.components.map((c) => [`${c.type}:${c.slug}`, c.version]));
    expect(versions).toEqual({
      'core:wordpress': '6.4.2',
      'plugin:contact-form-7': '5.3.1',
      'theme:twentytwentyone': '2.0',
      'php:php': '8.1.27',
      'web_server:apache': '2.4.57',
    });

    expect(outcome.findings.map((f) => `${f.severity} ${f.conceptId}`).sort()).toEqual([
      'critical exposure/config-backup-exposed',
      'critical exposure/known-vulnerable-component',
      'high exposure/debug-log-exposed',
      'high exposure/https-not-enforced',
      'high exposure/php-unsupported',
      'high exposure/wordpress-core-outdated',
      'info exposure/component-versions-disclosed',
      'info exposure/mime-sniffing-protection-missing',
      'info exposure/permissions-policy-missing',
      'info exposure/referrer-policy-missing',
      'low exposure/clickjacking-protection-missing',
      'low exposure/csp-missing',
      'low exposure/php-version-disclosed',
      'low exposure/theme-outdated',
      'low exposure/wordpress-version-disclosed',
      'medium exposure/login-unprotected',
      'medium exposure/plugin-outdated',
      'medium exposure/usernames-via-author-archives',
      'medium exposure/usernames-via-rest-api',
      'medium exposure/xmlrpc-enabled',
    ]);

    // Secrets and usernames from the site never end up in stored evidence.
    const stored = JSON.stringify(outcome.findings);
    expect(stored).not.toContain('not-a-real-password');
    expect(stored).not.toContain('shc-admin');
  });
});
